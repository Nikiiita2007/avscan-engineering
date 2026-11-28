//! Named-pipe transport for modules that an external host drives itself.
//!
//! The host connects to a pipe created here and speaks the module protocol
//! (hello, start, ping, command, stop) directly with the module. The
//! orchestrator only spawns the module process and copies bytes between the
//! pipe and the module's stdio, so the frames are never parsed here. The
//! relay is generic over the streams and is tested without Windows; only
//! creating the pipe needs Windows.

use std::io;

use tokio::io::{copy_bidirectional, join, AsyncRead, AsyncWrite};

/// Prefix of every local named-pipe path.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Default pipe of a module: `\\.\pipe\avscan.<module id>`.
pub fn default_pipe_name(module_id: &str) -> String {
    format!("{PIPE_PREFIX}avscan.{module_id}")
}

/// Whether `name` is a local named-pipe path (`\\.\pipe\<name>`, no further separators).
pub fn is_valid_pipe_name(name: &str) -> bool {
    match name.strip_prefix(PIPE_PREFIX) {
        Some(rest) => !rest.is_empty() && !rest.contains(['\\', '/']),
        None => false,
    }
}

/// Copies bytes between the host's pipe and the module's stdio until both
/// directions have ended. When one side closes, the other side is shut down
/// too, so the module sees end of input and the host sees end of output.
/// Returns the byte counts (host to module, module to host).
pub async fn relay<P, R, W>(pipe: P, module_out: R, module_in: W) -> io::Result<(u64, u64)>
where
    P: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut pipe = pipe;
    let mut module = join(module_out, module_in);
    copy_bidirectional(&mut pipe, &mut module).await
}

#[cfg(windows)]
pub mod windows {
    //! Creating the pipe (Windows only).

    use std::io;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    /// Creates the only instance of the pipe `name`; remote clients are refused.
    pub fn create(name: &str) -> io::Result<NamedPipeServer> {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn default_names_follow_the_module_id() {
        assert_eq!(default_pipe_name("log_hunter"), r"\\.\pipe\avscan.log_hunter");
        assert!(is_valid_pipe_name(&default_pipe_name("log_hunter")));
    }

    #[test]
    fn only_local_pipe_paths_are_valid() {
        assert!(is_valid_pipe_name(r"\\.\pipe\avscan"));
        assert!(!is_valid_pipe_name(r"\\.\pipe\"));
        assert!(!is_valid_pipe_name(r"\\server\pipe\avscan"));
        assert!(!is_valid_pipe_name(r"\\.\pipe\a\b"));
        assert!(!is_valid_pipe_name(r"\\.\pipe\a/b"));
        assert!(!is_valid_pipe_name("avscan"));
        assert!(!is_valid_pipe_name(""));
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_closing_ends_the_relay() {
        let (mut host, pipe_end) = duplex(1024);
        let (mut module_writes, module_out) = duplex(1024);
        let (module_in, mut module_reads) = duplex(1024);
        let relay = tokio::spawn(relay(pipe_end, module_out, module_in));

        host.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        module_reads.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        module_writes.write_all(b"pong").await.unwrap();
        host.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop(host);
        let mut rest = Vec::new();
        module_reads.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        drop(module_writes);
        let counts = relay.await.unwrap().unwrap();
        assert_eq!(counts, (4, 4));
    }

    #[tokio::test]
    async fn a_module_that_exits_closes_the_host_side() {
        let (mut host, pipe_end) = duplex(1024);
        let (module_writes, module_out) = duplex(1024);
        let (module_in, module_reads) = duplex(1024);
        let relay = tokio::spawn(relay(pipe_end, module_out, module_in));

        drop(module_writes);
        let mut rest = Vec::new();
        host.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        drop(host);
        drop(module_reads);
        relay.await.unwrap().unwrap();
    }
}

#pragma once
// Transport of the module host over a byte stream, plus the Windows named-pipe client under it.
// The Rust orchestrator creates one pipe per module ("pipes" in its configuration), starts the module and
// relays the bytes, so the frames of protocol.hpp travel unchanged between this host and the module.
// Not thread-safe, like ModuleHost: use one transport from a single thread.
#include "module_host.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace av::host {

// Byte stream under a StreamTransport.
struct ByteStream {
    enum class Read { Data, Timeout, Closed };
    virtual ~ByteStream() = default;
    // Writes all `n` bytes or fails.
    virtual bool write(const void* data, std::size_t n) = 0;
    // Waits up to `timeout` for at least one byte, then reads at most `cap` bytes into `buf`.
    // A zero timeout polls once. Data means got > 0; Closed means the peer is gone.
    virtual Read read(void* buf, std::size_t cap, std::size_t& got, std::chrono::milliseconds timeout) = 0;
    virtual void close() = 0;
};

// Frames (protocol.hpp) over a ByteStream. Any stream error, a closed stream or a malformed frame drops the
// stream for good: later calls fail at once. Frames that were already received stay readable.
class StreamTransport : public Transport {
public:
    explicit StreamTransport(std::unique_ptr<ByteStream> stream) : s_(std::move(stream)) {}

    bool connected() const { return s_ != nullptr; }
    // Why the incoming frames were rejected (empty when they were not).
    const std::string& error() const { return reader_.error(); }

    bool send(const Message& m) override {
        if (!s_) return false;
        const std::optional<std::string> frame = encodeFrame(m);
        if (!frame) return false;  // over the frame limit: the message is refused, the stream is fine
        if (!s_->write(frame->data(), frame->size())) {
            drop();
            return false;
        }
        return true;
    }

    std::optional<Message> receive(std::chrono::milliseconds timeout) override {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        Message m;
        for (;;) {
            switch (reader_.next(m)) {
            case FrameReader::Status::Frame: return m;
            case FrameReader::Status::Error: drop(); return std::nullopt;
            case FrameReader::Status::NeedMore: break;
            }
            if (!s_) return std::nullopt;
            const auto now = std::chrono::steady_clock::now();
            const auto left = now >= deadline ? std::chrono::milliseconds(0)
                                              : std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            char buf[4096];
            std::size_t got = 0;
            switch (s_->read(buf, sizeof buf, got, left)) {
            case ByteStream::Read::Data:
                if (got == 0 || got > sizeof buf) {
                    drop();
                    return std::nullopt;
                }
                reader_.feed(buf, got);
                break;
            case ByteStream::Read::Timeout: return std::nullopt;
            case ByteStream::Read::Closed: drop(); return std::nullopt;
            }
        }
    }

    // Drops the connection. The orchestrator sees the pipe close and ends the module's input.
    void terminate() override { drop(); }

private:
    void drop() {
        if (!s_) return;
        s_->close();
        s_.reset();
    }

    std::unique_ptr<ByteStream> s_;
    FrameReader reader_;
};

#ifdef _WIN32

inline std::wstring widenUtf8(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// Client end of a named pipe. The handle is synchronous; reads poll PeekNamedPipe so they never block
// past their timeout. A write blocks while the pipe buffer is full, i.e. while the module does not read.
class PipeStream : public ByteStream {
public:
    explicit PipeStream(HANDLE h) : h_(h) {}
    PipeStream(const PipeStream&) = delete;
    PipeStream& operator=(const PipeStream&) = delete;
    ~PipeStream() override { close(); }

    bool write(const void* data, std::size_t n) override {
        const char* p = static_cast<const char*>(data);
        while (n > 0) {
            if (h_ == INVALID_HANDLE_VALUE) return false;
            const DWORD chunk = static_cast<DWORD>(n < 65536 ? n : 65536);
            DWORD done = 0;
            if (!WriteFile(h_, p, chunk, &done, nullptr) || done == 0) return false;
            p += done;
            n -= done;
        }
        return true;
    }

    Read read(void* buf, std::size_t cap, std::size_t& got, std::chrono::milliseconds timeout) override {
        got = 0;
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            if (h_ == INVALID_HANDLE_VALUE) return Read::Closed;
            DWORD avail = 0;
            if (!PeekNamedPipe(h_, nullptr, 0, nullptr, &avail, nullptr)) return Read::Closed;
            if (avail > 0) {
                const DWORD want = static_cast<DWORD>(cap < avail ? cap : avail);
                DWORD done = 0;
                if (!ReadFile(h_, buf, want, &done, nullptr) || done == 0) return Read::Closed;
                got = done;
                return Read::Data;
            }
            if (std::chrono::steady_clock::now() >= deadline) return Read::Timeout;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    void close() override {
        if (h_ == INVALID_HANDLE_VALUE) return;
        CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_;
};

// Connects to a pipe that the orchestrator creates. It makes the pipe just before it starts the module, so
// the connection is retried until `timeout`. The pipe is opened with an identification-level security
// context, so the server cannot impersonate this process.
inline std::unique_ptr<StreamTransport> connectPipeTransport(const std::string& pipeName,
                                                             std::chrono::milliseconds timeout, std::string& error) {
    const std::wstring name = widenUtf8(pipeName);
    if (name.empty()) {
        error = "invalid pipe name";
        return nullptr;
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    DWORD last = ERROR_FILE_NOT_FOUND;
    for (;;) {
        HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
            return std::make_unique<StreamTransport>(std::make_unique<PipeStream>(h));
        }
        last = GetLastError();
        if (last != ERROR_FILE_NOT_FOUND && last != ERROR_PIPE_BUSY) break;
        if (std::chrono::steady_clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    error = "cannot connect to the pipe '" + pipeName + "' (Windows error " + std::to_string(last) + ")";
    return nullptr;
}

#else

// Named pipes exist only on Windows; the stream transport itself works everywhere.
inline std::unique_ptr<StreamTransport> connectPipeTransport(const std::string&, std::chrono::milliseconds,
                                                             std::string& error) {
    error = "named pipes are available only on Windows";
    return nullptr;
}

#endif

} // namespace av::host

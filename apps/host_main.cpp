// avhost: a small module host for the command line. It connects to the named pipe of a module that the Rust
// orchestrator has started ("pipes" in the orchestrator configuration), runs the handshake, optionally sends one
// command, prints the events and logs of the module, and stops it.
#include "pipe_transport.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

using namespace av;
using namespace av::host;

namespace {

void usage() {
    std::cout << R"(avhost: drives one module over the named pipe that the Rust orchestrator created for it.

Usage: avhost --pipe NAME --manifest FILE [--command NAME] [--args JSON] [--seconds N]

  --pipe NAME       pipe of the module, as in the pipes section of the orchestrator configuration
  --manifest FILE   the module.json of the module
  --command NAME    send this capability as a command and wait for its result
  --args JSON       arguments of the command, a JSON object (default {})
  --seconds N       wait at most N seconds for the result, or listen for N seconds without a command (default 10)
  -h, --help        this help

Exit codes: 0 - ok, 1 - the command failed, 2 - bad arguments, 3 - connection, manifest or handshake error.
)";
}

bool parseSeconds(const std::string& text, int& out) {
    try {
        std::size_t used = 0;
        const int n = std::stoi(text, &used);
        if (used != text.size() || n < 1 || n > 3600) return false;
        out = n;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::string pipeName, manifestPath, command, argsText = "{}";
    int seconds = 10;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](std::string& dst) {
            if (i + 1 >= argc) return false;
            dst = argv[++i];
            return true;
        };
        bool ok = true;
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "--pipe") {
            ok = value(pipeName);
        } else if (a == "--manifest") {
            ok = value(manifestPath);
        } else if (a == "--command") {
            ok = value(command);
        } else if (a == "--args") {
            ok = value(argsText);
        } else if (a == "--seconds") {
            std::string n;
            ok = value(n) && parseSeconds(n, seconds);
        } else {
            ok = false;
        }
        if (!ok) {
            std::cerr << "bad argument near '" << a << "'\n";
            usage();
            return 2;
        }
    }
    if (pipeName.empty() || manifestPath.empty()) {
        usage();
        return 2;
    }

    json::Value commandArgs = json::Value::object();
    if (!command.empty()) {
        const json::ParseResult parsed = json::parse(argsText);
        if (!parsed.value || !parsed.value->isObject()) {
            std::cerr << "--args must be a JSON object" << (parsed.error.empty() ? "" : ": " + parsed.error) << '\n';
            return 2;
        }
        commandArgs = *parsed.value;
    }

    std::ifstream in(manifestPath, std::ios::binary);
    if (!in) {
        std::cerr << "cannot read " << manifestPath << '\n';
        return 3;
    }
    std::ostringstream text;
    text << in.rdbuf();
    const ManifestResult manifest = parseManifest(text.str());
    if (!manifest.value) {
        for (const auto& e : manifest.errors) std::cerr << "manifest: " << e << '\n';
        return 3;
    }

    std::string error;
    auto transport = connectPipeTransport(pipeName, std::chrono::seconds(10), error);
    if (!transport) {
        std::cerr << error << '\n';
        return 3;
    }

    EventBus bus;
    ModuleHost host(*manifest.value, *transport, bus);
    host.setLogSink([](const std::string& line) { std::cout << "log " << line << '\n'; });
    for (const auto& pattern : manifest.value->publishes)
        bus.subscribe(pattern, [](const std::string& topic, const json::Value& data, const std::string& source) {
            std::cout << "event " << source << ' ' << topic << ' ' << json::dump(data) << '\n';
        });

    if (!host.start()) {
        std::cerr << "handshake failed: " << host.error() << '\n';
        return 3;
    }
    std::cout << "module " << manifest.value->id << ' ' << manifest.value->version << " is running\n";

    int exitCode = 0;
    bool done = false;
    const bool waitForResult = !command.empty();
    if (waitForResult) {
        host.sendCommand(command, commandArgs, [&](const CommandOutcome& outcome) {
            done = true;
            if (outcome.ok) {
                std::cout << "command " << command << " ok\n";
            } else {
                std::cerr << "command " << command << " failed: " << outcome.error << '\n';
                exitCode = 1;
            }
        });
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while ((!waitForResult || !done) && host.state() == ModuleState::Running &&
           std::chrono::steady_clock::now() < deadline) {
        host.pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (waitForResult && !done) {
        std::cerr << "no result of '" << command << "' within " << seconds << " s\n";
        exitCode = 1;
    }
    if (host.state() == ModuleState::Failed) {
        std::cerr << "module failed: " << host.error() << '\n';
        if (exitCode == 0) exitCode = 3;
    }

    host.stop();
    if (host.forcedStop()) std::cerr << "the module did not stop in time; the connection was dropped\n";
    return exitCode;
}

#pragma once
// Shared CLI parsing for the console monitor and the Windows service.
#ifdef _WIN32
#include "monitor.hpp"
#include "config_file.hpp"
#include <stdexcept>
#include <string>
#include <vector>

namespace av {
// Parses monitor options; throws std::runtime_error on invalid input.
// Returns false when --help was requested (options filled as far as parsed).
// --config FILE loads a configuration file at that position; arguments after it override the file.
inline bool parseMonitorArgs(const std::vector<std::wstring>& args, MonitorOptions& o) {
    bool help = false;
    for (size_t i = 0; i < args.size(); ++i) {
        std::wstring a = args[i];
        auto value = [&]() {
            if (++i >= args.size()) throw std::runtime_error("missing value");
            return args[i];
        };
        if (a == L"--watch") o.roots.emplace_back(value());
        else if (a == L"--exclude") o.excludes.emplace_back(value());
        else if (a == L"--priority") o.priority.emplace_back(value());
        else if (a == L"--db") o.db = value();
        else if (a == L"--quarantine") o.quarantine = value();
        else if (a == L"--threads") {
            auto x = std::stoul(value());
            if (x < 1 || x > 32) throw std::runtime_error("threads: 1..32");
            o.threads = unsigned(x);
        } else if (a == L"--etw") o.etw = true;
        else if (a == L"--block-exec") o.blockExec = true;
        else if (a == L"--auto-quarantine") o.autoQuarantine = true;
        else if (a == L"--config") loadMonitorConfig(std::filesystem::path(value()), o);
        else if (a == L"--events") {
            const std::wstring v = value();
            if (v == L"jsonl") o.jsonl = true;
            else if (v == L"text") o.jsonl = false;
            else throw std::runtime_error("events: text or jsonl");
        }
        else if (a == L"--help") help = true;
        else throw std::runtime_error("unknown option");
    }
    if (o.roots.empty()) o.roots = o.priority;
    return !help;
}
}
#endif

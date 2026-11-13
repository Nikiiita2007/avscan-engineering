#pragma once
// Plain "key = value" configuration for avmonitor (format: docs/CONFIG.md).
// Portable: no Windows API, so it is unit-tested on every platform.
#include "monitor.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace av {
namespace cfgdetail {

inline std::string trim(std::string_view s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

inline std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

[[noreturn]] inline void fail(int line, const std::string& message) {
    throw std::runtime_error("config line " + std::to_string(line) + ": " + message);
}

inline bool parseBool(int line, const std::string& key, const std::string& v) {
    const std::string s = lower(v);
    if (s == "true" || s == "1" || s == "yes" || s == "on") return true;
    if (s == "false" || s == "0" || s == "no" || s == "off") return false;
    fail(line, key + ": expected true or false, got '" + v + "'");
}

inline unsigned long long parseUInt(int line, const std::string& key, const std::string& v,
                                    unsigned long long lo, unsigned long long hi) {
    if (v.empty() || v.size() > 18) fail(line, key + ": expected a number");
    for (char c : v)
        if (c < '0' || c > '9') fail(line, key + ": expected a number, got '" + v + "'");
    const unsigned long long x = std::stoull(v);
    if (x < lo || x > hi)
        fail(line, key + ": must be in the range " + std::to_string(lo) + ".." + std::to_string(hi));
    return x;
}

} // namespace cfgdetail

// Applies configuration text to o. List keys (watch, exclude, priority) accumulate; other keys overwrite.
// Throws std::runtime_error with a "config line N: ..." message on any problem (unknown keys are errors).
inline void applyMonitorConfig(const std::string& text, MonitorOptions& o) {
    using namespace cfgdetail;
    std::istringstream in(text);
    std::string raw;
    int line = 0;
    while (std::getline(in, raw)) {
        ++line;
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        if (line == 1 && raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
            static_cast<unsigned char>(raw[1]) == 0xBB && static_cast<unsigned char>(raw[2]) == 0xBF)
            raw.erase(0, 3); // UTF-8 BOM
        const std::string s = trim(raw);
        if (s.empty() || s[0] == '#' || s[0] == ';') continue;
        if (s.front() == '[') {
            if (lower(s) != "[monitor]") fail(line, "unknown section " + s + " (only [monitor] is supported)");
            continue;
        }
        const auto eq = s.find('=');
        if (eq == std::string::npos) fail(line, "expected key = value");
        const std::string key = lower(trim(std::string_view(s).substr(0, eq)));
        std::string value = trim(std::string_view(s).substr(eq + 1));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
        if (key.empty()) fail(line, "empty key");

        if (key == "watch") o.roots.push_back(pathFromUtf8(value));
        else if (key == "exclude") o.excludes.push_back(pathFromUtf8(value));
        else if (key == "priority") o.priority.push_back(pathFromUtf8(value));
        else if (key == "db") o.db = pathFromUtf8(value);
        else if (key == "quarantine") o.quarantine = pathFromUtf8(value);
        else if (key == "threads") o.threads = static_cast<unsigned>(parseUInt(line, key, value, 1, 32));
        else if (key == "debounce_ms") o.debounceMs = static_cast<unsigned>(parseUInt(line, key, value, 0, 60000));
        else if (key == "stable_ms") o.stableMs = static_cast<unsigned>(parseUInt(line, key, value, 100, 60000));
        else if (key == "max_size_mb") o.maxSize = parseUInt(line, key, value, 1, 1048576) << 20;
        else if (key == "queue_limit") o.queueLimit = static_cast<std::size_t>(parseUInt(line, key, value, 1, 10000000));
        else if (key == "etw") o.etw = parseBool(line, key, value);
        else if (key == "block_exec") o.blockExec = parseBool(line, key, value);
        else if (key == "auto_quarantine") o.autoQuarantine = parseBool(line, key, value);
        else if (key == "events") {
            const std::string v = lower(value);
            if (v == "jsonl") o.jsonl = true;
            else if (v == "text") o.jsonl = false;
            else fail(line, "events: expected text or jsonl, got '" + value + "'");
        } else fail(line, "unknown key '" + key + "'");
    }
}

inline void loadMonitorConfig(const std::filesystem::path& file, MonitorOptions& o) {
    std::ifstream f(file, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open config file: " + pathUtf8(file));
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    applyMonitorConfig(text, o);
}

} // namespace av

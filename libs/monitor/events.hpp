#pragma once
// JSON Lines output for avmonitor: one compact JSON object per line (format: docs/CONFIG.md).
// Portable and header-only; the monitor itself is unchanged, only the console log callback uses it.
#include <chrono>
#include <cstdio>
#include <string>

namespace av {

// ISO-8601 UTC timestamp for a Unix time in milliseconds (no platform time functions, so it behaves the same everywhere).
inline std::string utcTimestampAt(long long unixMs) {
    long long secs = unixMs / 1000;
    int msPart = static_cast<int>(unixMs % 1000);
    if (msPart < 0) { msPart += 1000; --secs; }
    long long days = secs / 86400;
    long long rem = secs % 86400;
    if (rem < 0) { rem += 86400; --days; }
    // Civil date from day count (H. Hinnant's algorithm).
    days += 719468;
    const long long era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long y = static_cast<long long>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) ++y;
    char buf[96];
    std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02d:%02d:%02d.%03dZ", y, m, d, static_cast<int>(rem / 3600),
                  static_cast<int>(rem % 3600 / 60), static_cast<int>(rem % 60), msPart);
    return buf;
}

inline std::string utcTimestamp() {
    using namespace std::chrono;
    return utcTimestampAt(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

inline std::string jsonEscape(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else o.push_back(static_cast<char>(c));
        }
    }
    return o;
}

// Removes whitespace outside of string literals, so a pretty-printed object becomes a single line.
inline std::string compactJson(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    bool inString = false, escape = false;
    for (char c : s) {
        if (inString) {
            o.push_back(c);
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') inString = false;
        } else if (c == '"') {
            inString = true;
            o.push_back(c);
        } else if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
            o.push_back(c);
        }
    }
    return o;
}

inline bool startsWith(const std::string& s, const char* prefix) { return s.rfind(prefix, 0) == 0; }

// A diagnostic text line becomes {"v":1,"ts":...,"event":...,"level":...,"message":...}.
inline std::string logEventJson(const std::string& line) {
    const char* event = "log";
    const char* level = "info";
    if (startsWith(line, "Error")) level = "error";
    else if (startsWith(line, "Warning")) level = "warning";
    else if (startsWith(line, "Skipped")) level = "warning";
    else if (startsWith(line, "Blocked:")) event = "blocked";
    else if (startsWith(line, "Quarantined:")) event = "quarantined";
    return std::string("{\"v\":1,\"ts\":\"") + utcTimestamp() + "\",\"event\":\"" + event + "\",\"level\":\"" + level +
           "\",\"message\":\"" + jsonEscape(line) + "\"}";
}

// True if s is a single {...} value with balanced braces/brackets and closed strings (a cheap sanity check).
inline bool looksLikeObject(const std::string& s) {
    if (s.size() < 2 || s.front() != '{' || s.back() != '}') return false;
    int depth = 0;
    bool inString = false, escape = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (inString) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if (c == '"') inString = false;
        } else if (c == '"') {
            inString = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
            if (depth == 0 && i + 1 != s.size()) return false;
        }
    }
    return depth == 0 && !inString;
}

// A pretty-printed scan result object becomes {"v":1,"ts":...,"event":"scan",<scan fields>} on one line.
// The envelope key is "event" (not "type") because the scan result has its own "type" field (the file type).
// Anything that is not a well-formed object is wrapped as a log event instead.
inline std::string scanEventJson(const std::string& prettyJson) {
    const std::string c = compactJson(prettyJson);
    if (!looksLikeObject(c) || c == "{}") return logEventJson(prettyJson);
    return std::string("{\"v\":1,\"ts\":\"") + utcTimestamp() + "\",\"event\":\"scan\"," + c.substr(1);
}

// The console log callback: text mode returns the line unchanged.
inline std::string toEventLine(const std::string& s, bool jsonl) {
    if (!jsonl) return s;
    if (!s.empty() && s.front() == '{') return scanEventJson(s);
    return logEventJson(s);
}

} // namespace av

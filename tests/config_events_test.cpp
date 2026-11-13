// Unit tests for libs/monitor/config_file.hpp and libs/monitor/events.hpp (portable, no Windows API).
#include "config_file.hpp"
#include "events.hpp"

#include <iostream>
#include <string>

namespace {

int fails = 0;
void check(bool ok, const char* what) {
    std::cout << (ok ? "PASS " : "FAIL ") << what << '\n';
    if (!ok) ++fails;
}

std::size_t countOf(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (std::size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size())) ++n;
    return n;
}

// Strict recursive-descent JSON validator (enough to prove that emitted lines are valid JSON).
struct Validator {
    const std::string& s;
    std::size_t i = 0;
    explicit Validator(const std::string& text) : s(text) {}
    void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i; }
    bool lit(const char* w) {
        std::size_t n = std::string(w).size();
        if (s.compare(i, n, w) != 0) return false;
        i += n;
        return true;
    }
    bool str() {
        if (i >= s.size() || s[i] != '"') return false;
        ++i;
        while (i < s.size()) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c == '"') { ++i; return true; }
            if (c < 0x20) return false;
            if (c == '\\') {
                ++i;
                if (i >= s.size()) return false;
                if (s[i] == 'u') {
                    for (int k = 1; k <= 4; ++k)
                        if (i + k >= s.size() || !std::isxdigit(static_cast<unsigned char>(s[i + k]))) return false;
                    i += 4;
                } else if (std::string("\"\\/bfnrt").find(s[i]) == std::string::npos) return false;
            }
            ++i;
        }
        return false;
    }
    bool num() {
        std::size_t b = i;
        if (i < s.size() && s[i] == '-') ++i;
        while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.' || s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) ++i;
        return i > b;
    }
    bool val() {
        ws();
        if (i >= s.size()) return false;
        if (s[i] == '{') {
            ++i; ws();
            if (i < s.size() && s[i] == '}') { ++i; return true; }
            for (;;) {
                ws(); if (!str()) return false; ws();
                if (i >= s.size() || s[i] != ':') return false;
                ++i; if (!val()) return false; ws();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == '}') { ++i; return true; }
                return false;
            }
        }
        if (s[i] == '[') {
            ++i; ws();
            if (i < s.size() && s[i] == ']') { ++i; return true; }
            for (;;) {
                if (!val()) return false;
                ws();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == ']') { ++i; return true; }
                return false;
            }
        }
        if (s[i] == '"') return str();
        if (lit("true") || lit("false") || lit("null")) return true;
        return num();
    }
    bool valid() { if (!val()) return false; ws(); return i == s.size(); }
};

bool validJson(const std::string& s) { Validator v(s); return v.valid(); }

std::string configError(const std::string& text) {
    av::MonitorOptions o;
    try {
        av::applyMonitorConfig(text, o);
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

} // namespace

int main() {
    using namespace av;

    // ---- config: full example ----
    {
        MonitorOptions o;
        applyMonitorConfig(
            "\xEF\xBB\xBF# comment\r\n"
            "; another comment\r\n"
            "[monitor]\r\n"
            "watch = D:\\Incoming\r\n"
            "watch = \"D:\\With Space\"\r\n"
            "exclude = D:\\Incoming\\Trusted\r\n"
            "priority = D:\\Priority\r\n"
            "db = D:\\av\\signatures.db\r\n"
            "quarantine = D:\\Evidence\r\n"
            "THREADS = 4\r\n"
            "debounce_ms = 500\r\n"
            "stable_ms = 2000\r\n"
            "max_size_mb = 256\r\n"
            "queue_limit = 1000\r\n"
            "etw = yes\r\n"
            "block_exec = false\r\n"
            "auto_quarantine = ON\r\n"
            "events = JSONL\r\n",
            o);
        check(o.roots.size() == 2 && o.roots[0] == pathFromUtf8("D:\\Incoming") && o.roots[1] == pathFromUtf8("D:\\With Space"), "config: watch list and quoted value");
        check(o.excludes.size() == 1 && o.priority.size() == 1, "config: exclude and priority");
        check(o.db == pathFromUtf8("D:\\av\\signatures.db") && o.quarantine == pathFromUtf8("D:\\Evidence"), "config: db and quarantine");
        check(o.threads == 4 && o.debounceMs == 500 && o.stableMs == 2000, "config: numbers");
        check(o.maxSize == (256ull << 20) && o.queueLimit == 1000, "config: max_size_mb and queue_limit");
        check(o.etw && !o.blockExec && o.autoQuarantine && o.jsonl, "config: booleans and events");
    }
    // ---- config: defaults untouched by empty config ----
    {
        MonitorOptions def, o;
        applyMonitorConfig("# nothing\n\n", o);
        check(o.threads == def.threads && o.stableMs == def.stableMs && o.maxSize == def.maxSize && !o.jsonl, "config: empty config keeps defaults");
    }
    // ---- config: errors ----
    check(configError("bogus = 1").find("config line 1") == 0 && configError("bogus = 1").find("unknown key") != std::string::npos, "config error: unknown key with line number");
    check(configError("\n\nthreads = 0").find("config line 3") == 0, "config error: threads below range, line 3");
    check(!configError("threads = 33").empty(), "config error: threads above range");
    check(!configError("threads = abc").empty(), "config error: not a number");
    check(!configError("stable_ms = 50").empty(), "config error: stable_ms too small");
    check(!configError("etw = maybe").empty(), "config error: bad boolean");
    check(!configError("events = xml").empty(), "config error: bad events value");
    check(!configError("[service]\nthreads = 2").empty(), "config error: unknown section");
    check(!configError("just text").empty(), "config error: missing =");
    check(!configError("max_size_mb = 99999999999999999999").empty(), "config error: huge number");
    check(configError("[monitor]\nthreads = 2").empty(), "config: [monitor] section accepted");

    // ---- config: file loading ----
    {
        MonitorOptions o;
        bool threw = false;
        try { loadMonitorConfig("definitely/missing/config.conf", o); } catch (const std::exception&) { threw = true; }
        check(threw, "config: missing file throws");
    }

    // ---- events ----
    {
        const std::string pretty =
            "{\n  \"path\": \"c:\\\\a b\\\\file {x}.txt\",\n  \"status\": \"Infected\",\n  \"message\": \"say \\\"hi\\\"\",\n"
            "  \"size\": 12,\n  \"type\": \"pe\",\n  \"detections\": [{\"kind\": \"signature\", \"name\": \"X Y\", \"malware\": true}],\n  \"children\": []\n}";
        const std::string compact = compactJson(pretty);
        check(compact.find('\n') == std::string::npos && validJson(compact), "events: compactJson gives one valid line");
        check(compact.find("file {x}.txt") != std::string::npos && compact.find("X Y") != std::string::npos, "events: spaces inside strings are kept");
        check(compact.find("say \\\"hi\\\"") != std::string::npos, "events: escaped quotes are kept");

        const std::string scan = toEventLine(pretty, true);
        check(scan.find('\n') == std::string::npos && validJson(scan), "events: scan line is valid single-line JSON");
        check(scan.rfind("{\"v\":1,\"ts\":\"", 0) == 0 && scan.find("\"event\":\"scan\",\"path\":") != std::string::npos, "events: scan envelope fields");
        check(scan.find("\"status\":\"Infected\"") != std::string::npos, "events: scan keeps original fields");
        check(countOf(scan, "\"type\":") == 1 && scan.find("\"type\":\"pe\"") != std::string::npos && countOf(scan, "\"event\":") == 1, "events: no duplicate keys (file type kept, event key separate)");

        const std::string logLine = toEventLine("Warning: directory events lost; full rescan scheduled", true);
        check(validJson(logLine) && logLine.find("\"level\":\"warning\"") != std::string::npos && logLine.find("\"event\":\"log\"") != std::string::npos, "events: warning log line");
        check(toEventLine("Error ETW unavailable", true).find("\"level\":\"error\"") != std::string::npos, "events: error level");
        check(toEventLine("Quarantined: record 1 from C:\\x", true).find("\"event\":\"quarantined\"") != std::string::npos, "events: quarantined event");
        check(toEventLine("Blocked: terminated pid=5", true).find("\"event\":\"blocked\"") != std::string::npos, "events: blocked event");

        const std::string weird = std::string("Error: bad \"path\" \\ with tab\t and ctrl ") + char(1) + " and \xD1\x82\xD0\xB5\xD1\x81\xD1\x82";
        const std::string weirdJson = toEventLine(weird, true);
        check(validJson(weirdJson) && weirdJson.find("\\u0001") != std::string::npos && weirdJson.find("\xD1\x82\xD0\xB5\xD1\x81\xD1\x82") != std::string::npos, "events: control characters escaped, UTF-8 kept");

        check(toEventLine(pretty, false) == pretty && toEventLine("plain", false) == "plain", "events: text mode is a passthrough");

        check(utcTimestampAt(0) == "1970-01-01T00:00:00.000Z", "events: timestamp epoch");
        check(utcTimestampAt(1700000000123LL) == "2023-11-14T22:13:20.123Z", "events: timestamp 2023-11-14");
        check(utcTimestampAt(951782400000LL) == "2000-02-29T00:00:00.000Z", "events: timestamp leap day 2000");
        check(utcTimestampAt(4102444800999LL) == "2100-01-01T00:00:00.999Z", "events: timestamp 2100-01-01");
        const std::string ts = utcTimestamp();
        check(ts.size() == 24 && ts[4] == '-' && ts[10] == 'T' && ts[19] == '.' && ts.back() == 'Z', "events: timestamp format");
        check(toEventLine("{broken", true).find("\"event\":") != std::string::npos && validJson(toEventLine("{broken", true)), "events: malformed object still yields valid JSON");
    }
    return fails ? 1 : 0;
}

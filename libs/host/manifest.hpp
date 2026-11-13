#pragma once
// Module manifest (module.json): parsing and strict validation. Spec: docs/MODULES.md.
#include "json.hpp"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace av::host {

constexpr int kHostApiVersion = 1;

struct Manifest {
    std::string id, name, version, description;
    int apiVersion = 0;
    std::string exe;                 // relative path inside the module directory
    std::vector<std::string> args;
    std::vector<std::string> capabilities;   // what the module can do (informational contract)
    std::vector<std::string> permissions;    // what the module asks the host to allow
    std::vector<std::string> publishes;      // event topic patterns the module may publish
    std::vector<std::string> subscribes;     // event topic patterns the module wants to receive
    std::string restartPolicy = "never";     // never | on_failure
    int maxRestarts = 0;
    json::Value config = json::Value::object();
    std::filesystem::path root;              // module directory, set by the registry
};

struct ManifestResult {
    std::optional<Manifest> value;
    std::vector<std::string> errors;  // all problems found; empty on success
};

namespace detail {

inline bool isLower(char c) { return c >= 'a' && c <= 'z'; }
inline bool isDigit(char c) { return c >= '0' && c <= '9'; }

// id segment: [a-z][a-z0-9_]{0,31}; id: 1..8 segments separated by '.', total length 3..64
inline bool validId(const std::string& s) {
    if (s.size() < 3 || s.size() > 64) return false;
    std::size_t segLen = 0;
    int segments = 0;
    bool start = true;
    for (char c : s) {
        if (c == '.') {
            if (start) return false;
            start = true;
            segLen = 0;
            continue;
        }
        if (start) {
            if (!isLower(c)) return false;
            start = false;
            ++segments;
            segLen = 1;
            continue;
        }
        if (!(isLower(c) || isDigit(c) || c == '_')) return false;
        if (++segLen > 32) return false;
    }
    return !start && segments >= 1 && segments <= 8;
}

// topic / capability: [a-z][a-z0-9_]*(.[a-z0-9_]+)*, up to 64 characters
inline bool validName(const std::string& s) {
    if (s.empty() || s.size() > 64 || !isLower(s[0])) return false;
    char prev = 0;
    for (char c : s) {
        if (c == '.') {
            if (prev == '.') return false;
        } else if (!(isLower(c) || isDigit(c) || c == '_')) {
            return false;
        }
        prev = c;
    }
    return prev != '.';
}

inline bool endsWithStar(const std::string& s) { return s.size() >= 3 && s.compare(s.size() - 2, 2, ".*") == 0; }

// pattern: a name, optionally followed by ".*"
inline bool validPattern(const std::string& s) { return endsWithStar(s) ? validName(s.substr(0, s.size() - 2)) : validName(s); }

inline std::string patternBase(const std::string& s) { return endsWithStar(s) ? s.substr(0, s.size() - 2) : s; }

inline bool validVersion(const std::string& s) {
    int parts = 0;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t j = i;
        while (j < s.size() && isDigit(s[j])) ++j;
        const std::size_t len = j - i;
        if (len == 0 || len > 9 || (len > 1 && s[i] == '0')) return false;
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
    }
    return parts == 3;
}

inline bool noControl(const std::string& s) {
    return std::none_of(s.begin(), s.end(), [](unsigned char c) { return c < 0x20 || c == 0x7F; });
}

// Relative executable path: segments separated by / or \, no "..", ".", drive letters, empty segments,
// reserved characters, or segments ending in '.' or ' ' (Windows treats those specially).
inline bool validExe(const std::string& s) {
    if (s.empty() || s.size() > 200 || !noControl(s)) return false;
    if (s.find(':') != std::string::npos || s.front() == '/' || s.front() == '\\') return false;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t j = i;
        while (j < s.size() && s[j] != '/' && s[j] != '\\') ++j;
        const std::string seg = s.substr(i, j - i);
        if (seg.empty() || seg == "." || seg == ".." || seg.back() == '.' || seg.back() == ' ') return false;
        if (seg.find_first_of("<>\"|?*") != std::string::npos) return false;
        if (j == s.size()) break;
        i = j + 1;
    }
    return true;
}

inline bool allowedPermission(const std::string& p) {
    static const char* const kAllowed[] = {"fs.read", "fs.write", "net.local", "net.outbound", "net.capture", "process.spawn", "admin", "etw"};
    return std::any_of(std::begin(kAllowed), std::end(kAllowed), [&](const char* a) { return p == a; });
}

} // namespace detail

// Parses and validates a manifest. hostApi is the module API version the host implements.
inline ManifestResult parseManifest(std::string_view text, int hostApi = kHostApiVersion) {
    ManifestResult r;
    auto& errs = r.errors;
    const json::ParseResult pr = json::parse(text, 256 * 1024);
    if (!pr.value) { errs.push_back("invalid JSON: " + pr.error); return r; }
    const json::Value& j = *pr.value;
    if (!j.isObject()) { errs.push_back("manifest must be a JSON object"); return r; }

    static const char* const kTop[] = {"id", "name", "version", "api_version", "description", "entry", "capabilities", "permissions", "events", "restart", "config"};
    for (const auto& k : j.keys)
        if (std::none_of(std::begin(kTop), std::end(kTop), [&](const char* a) { return k == a; })) errs.push_back("unknown field '" + k + "'");

    Manifest m;
    auto needString = [&](const char* key, std::string& dst, bool required) {
        const json::Value* v = j.find(key);
        if (!v) { if (required) errs.push_back(std::string(key) + ": required"); return false; }
        if (!v->isString()) { errs.push_back(std::string(key) + ": must be a string"); return false; }
        dst = v->s;
        return true;
    };
    auto stringList = [&](const json::Value* v, const char* what, std::vector<std::string>& dst, std::size_t maxItems) {
        if (!v) return;
        if (!v->isArray()) { errs.push_back(std::string(what) + ": must be an array of strings"); return; }
        if (v->items.size() > maxItems) { errs.push_back(std::string(what) + ": too many entries"); return; }
        for (const auto& it : v->items) {
            if (!it.isString()) { errs.push_back(std::string(what) + ": entries must be strings"); return; }
            dst.push_back(it.s);
        }
    };

    if (needString("id", m.id, true) && !detail::validId(m.id)) errs.push_back("id: must look like 'antivirus' or 'net.analyzer' (lowercase letters, digits, '_', '.'; 3..64 characters)");
    if (needString("name", m.name, true) && (m.name.empty() || m.name.size() > 100 || !detail::noControl(m.name))) errs.push_back("name: 1..100 printable characters required");
    if (needString("version", m.version, true) && !detail::validVersion(m.version)) errs.push_back("version: must be MAJOR.MINOR.PATCH (numbers)");
    if (needString("description", m.description, false) && (m.description.size() > 500 || !detail::noControl(m.description))) errs.push_back("description: at most 500 printable characters");

    if (const json::Value* a = j.find("api_version")) {
        if (!a->isNumber() || !a->isInt) errs.push_back("api_version: must be an integer");
        else if (a->i != hostApi) errs.push_back("api_version: module needs " + std::to_string(a->i) + " but the host implements " + std::to_string(hostApi));
        else m.apiVersion = static_cast<int>(a->i);
    } else {
        errs.push_back("api_version: required");
    }

    if (const json::Value* e = j.find("entry")) {
        if (!e->isObject()) {
            errs.push_back("entry: must be an object");
        } else {
            for (const auto& k : e->keys)
                if (k != "exe" && k != "args") errs.push_back("entry: unknown field '" + k + "'");
            const json::Value* exe = e->find("exe");
            if (!exe || !exe->isString()) errs.push_back("entry.exe: required string");
            else if (!detail::validExe(exe->s)) errs.push_back("entry.exe: must be a relative path inside the module directory (no '..', drive letters or reserved characters)");
            else m.exe = exe->s;
            stringList(e->find("args"), "entry.args", m.args, 32);
            for (const auto& a : m.args)
                if (a.size() > 260 || !detail::noControl(a)) { errs.push_back("entry.args: arguments must be printable and at most 260 characters"); break; }
        }
    } else {
        errs.push_back("entry: required");
    }

    stringList(j.find("capabilities"), "capabilities", m.capabilities, 64);
    for (const auto& c : m.capabilities)
        if (!detail::validName(c)) errs.push_back("capabilities: invalid name '" + c + "'");
    stringList(j.find("permissions"), "permissions", m.permissions, 16);
    for (const auto& p : m.permissions)
        if (!detail::allowedPermission(p)) errs.push_back("permissions: unknown permission '" + p + "'");

    if (const json::Value* ev = j.find("events")) {
        if (!ev->isObject()) {
            errs.push_back("events: must be an object");
        } else {
            for (const auto& k : ev->keys)
                if (k != "publishes" && k != "subscribes") errs.push_back("events: unknown field '" + k + "'");
            stringList(ev->find("publishes"), "events.publishes", m.publishes, 64);
            stringList(ev->find("subscribes"), "events.subscribes", m.subscribes, 64);
            for (const auto& p : m.publishes) {
                if (!detail::validPattern(p)) { errs.push_back("events.publishes: invalid topic '" + p + "'"); continue; }
                const std::string base = detail::patternBase(p);
                if (base != m.id && base.compare(0, m.id.size() + 1, m.id + ".") != 0)
                    errs.push_back("events.publishes: topic '" + p + "' must start with the module id '" + m.id + "' (a module cannot publish in another module's namespace)");
            }
            for (const auto& s : m.subscribes)
                if (!detail::validPattern(s)) errs.push_back("events.subscribes: invalid topic '" + s + "'");
        }
    }

    auto hasDuplicates = [](std::vector<std::string> v) {
        std::sort(v.begin(), v.end());
        return std::adjacent_find(v.begin(), v.end()) != v.end();
    };
    if (hasDuplicates(m.capabilities)) errs.push_back("capabilities: duplicate entries");
    if (hasDuplicates(m.permissions)) errs.push_back("permissions: duplicate entries");
    if (hasDuplicates(m.publishes)) errs.push_back("events.publishes: duplicate entries");
    if (hasDuplicates(m.subscribes)) errs.push_back("events.subscribes: duplicate entries");

    if (const json::Value* rs = j.find("restart")) {
        if (!rs->isObject()) {
            errs.push_back("restart: must be an object");
        } else {
            for (const auto& k : rs->keys)
                if (k != "policy" && k != "max_restarts") errs.push_back("restart: unknown field '" + k + "'");
            if (const json::Value* p = rs->find("policy")) {
                if (!p->isString() || (p->s != "never" && p->s != "on_failure")) errs.push_back("restart.policy: must be 'never' or 'on_failure'");
                else m.restartPolicy = p->s;
            }
            if (const json::Value* n = rs->find("max_restarts")) {
                if (!n->isNumber() || !n->isInt || n->i < 0 || n->i > 10) errs.push_back("restart.max_restarts: integer 0..10 required");
                else m.maxRestarts = static_cast<int>(n->i);
            }
        }
    }

    if (const json::Value* c = j.find("config")) {
        if (!c->isObject()) errs.push_back("config: must be an object");
        else m.config = *c;
    }

    if (errs.empty()) r.value = std::move(m);
    return r;
}

} // namespace av::host

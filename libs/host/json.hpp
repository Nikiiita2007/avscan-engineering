#pragma once
// Minimal strict JSON (RFC 8259) value, parser and serializer for the module host.
// Strictness is deliberate: duplicate object keys, lone surrogates, invalid UTF-8, trailing garbage,
// NaN/Infinity and nesting deeper than 64 levels are all rejected, so every accepted document has exactly one meaning.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace av::json {

struct Value {
    enum class Kind { Null, Bool, Number, String, Array, Object };
    Kind kind = Kind::Null;
    bool b = false;
    bool isInt = false;      // number written without fraction/exponent and fitting in int64
    long long i = 0;         // valid when isInt
    double num = 0;          // always valid for numbers
    std::string s;
    std::vector<Value> items;               // array elements, or object values
    std::vector<std::string> keys;          // object keys (parallel to items), in document order

    static Value null() { return Value{}; }
    static Value boolean(bool v) { Value x; x.kind = Kind::Bool; x.b = v; return x; }
    static Value integer(long long v) { Value x; x.kind = Kind::Number; x.isInt = true; x.i = v; x.num = static_cast<double>(v); return x; }
    static Value number(double v) { Value x; x.kind = Kind::Number; x.num = v; return x; }
    static Value string(std::string v) { Value x; x.kind = Kind::String; x.s = std::move(v); return x; }
    static Value array() { Value x; x.kind = Kind::Array; return x; }
    static Value object() { Value x; x.kind = Kind::Object; return x; }

    bool isNull() const { return kind == Kind::Null; }
    bool isBool() const { return kind == Kind::Bool; }
    bool isNumber() const { return kind == Kind::Number; }
    bool isString() const { return kind == Kind::String; }
    bool isArray() const { return kind == Kind::Array; }
    bool isObject() const { return kind == Kind::Object; }

    // Object access. find() returns nullptr when the key is missing or this is not an object.
    const Value* find(std::string_view key) const {
        if (kind != Kind::Object) return nullptr;
        for (std::size_t n = 0; n < keys.size(); ++n)
            if (keys[n] == key) return &items[n];
        return nullptr;
    }
    // Sets (inserts or replaces) a key; turns a Null value into an object.
    Value& set(std::string key, Value v) {
        if (kind == Kind::Null) kind = Kind::Object;
        for (std::size_t n = 0; n < keys.size(); ++n)
            if (keys[n] == key) { items[n] = std::move(v); return items[n]; }
        keys.push_back(std::move(key));
        items.push_back(std::move(v));
        return items.back();
    }
    void push(Value v) {
        if (kind == Kind::Null) kind = Kind::Array;
        items.push_back(std::move(v));
    }
    // Convenience getters with defaults.
    std::string getString(std::string_view key, std::string def = "") const {
        const Value* v = find(key);
        return (v && v->isString()) ? v->s : def;
    }
    long long getInt(std::string_view key, long long def = 0) const {
        const Value* v = find(key);
        return (v && v->isNumber() && v->isInt) ? v->i : def;
    }
};

struct ParseResult {
    std::optional<Value> value;
    std::string error;  // empty on success; otherwise "message at offset N"
};

namespace detail {

struct Parser {
    std::string_view t;
    std::size_t p = 0;
    std::string err;
    static constexpr int kMaxDepth = 64;

    bool fail(const char* m) {
        if (err.empty()) err = std::string(m) + " at offset " + std::to_string(p);
        return false;
    }
    void ws() { while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) ++p; }
    bool lit(const char* w) {
        const std::string_view sv(w);
        if (t.compare(p, sv.size(), sv) != 0) return false;
        p += sv.size();
        return true;
    }
    static void appendUtf8(std::string& o, unsigned cp) {
        if (cp < 0x80) o.push_back(static_cast<char>(cp));
        else if (cp < 0x800) { o.push_back(static_cast<char>(0xC0 | (cp >> 6))); o.push_back(static_cast<char>(0x80 | (cp & 0x3F))); }
        else if (cp < 0x10000) {
            o.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            o.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            o.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            o.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            o.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            o.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    bool hex4(unsigned& out) {
        if (p + 4 > t.size()) return fail("truncated \\u escape");
        out = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = t[p + static_cast<std::size_t>(k)];
            unsigned d;
            if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A' + 10);
            else return fail("bad hex digit in \\u escape");
            out = out * 16 + d;
        }
        p += 4;
        return true;
    }
    // Validates one multi-byte UTF-8 sequence starting at lead byte t[p] and appends it.
    bool utf8(std::string& o) {
        const unsigned char c = static_cast<unsigned char>(t[p]);
        std::size_t n;
        unsigned cp;
        if (c >= 0xC2 && c <= 0xDF) { n = 2; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { n = 3; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { n = 4; cp = c & 0x07; }
        else return fail("invalid UTF-8 lead byte");
        if (p + n > t.size()) return fail("truncated UTF-8 sequence");
        for (std::size_t k = 1; k < n; ++k) {
            const unsigned char cc = static_cast<unsigned char>(t[p + k]);
            if ((cc & 0xC0) != 0x80) return fail("invalid UTF-8 continuation byte");
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return fail("invalid UTF-8 code point");
        o.append(t.substr(p, n));
        p += n;
        return true;
    }
    bool str(std::string& o) {
        ++p;  // opening quote
        while (p < t.size()) {
            const unsigned char c = static_cast<unsigned char>(t[p]);
            if (c == '"') { ++p; return true; }
            if (c < 0x20) return fail("control character in string");
            if (c == '\\') {
                ++p;
                if (p >= t.size()) return fail("truncated escape");
                const char e = t[p++];
                switch (e) {
                    case '"': o.push_back('"'); break;
                    case '\\': o.push_back('\\'); break;
                    case '/': o.push_back('/'); break;
                    case 'b': o.push_back('\b'); break;
                    case 'f': o.push_back('\f'); break;
                    case 'n': o.push_back('\n'); break;
                    case 'r': o.push_back('\r'); break;
                    case 't': o.push_back('\t'); break;
                    case 'u': {
                        unsigned cp;
                        if (!hex4(cp)) return false;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (t.compare(p, 2, "\\u") != 0) return fail("lone high surrogate");
                            p += 2;
                            unsigned lo;
                            if (!hex4(lo)) return false;
                            if (lo < 0xDC00 || lo > 0xDFFF) return fail("invalid low surrogate");
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return fail("lone low surrogate");
                        }
                        appendUtf8(o, cp);
                        break;
                    }
                    default: return fail("invalid escape");
                }
            } else if (c < 0x80) {
                o.push_back(static_cast<char>(c));
                ++p;
            } else if (!utf8(o)) {
                return false;
            }
        }
        return fail("unterminated string");
    }
    bool number(Value& v) {
        const std::size_t b = p;
        if (p < t.size() && t[p] == '-') ++p;
        if (p >= t.size()) return fail("invalid number");
        if (t[p] == '0') ++p;
        else if (t[p] >= '1' && t[p] <= '9') { while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p; }
        else return fail("invalid number");
        bool integral = true;
        if (p < t.size() && t[p] == '.') {
            integral = false;
            ++p;
            if (p >= t.size() || t[p] < '0' || t[p] > '9') return fail("invalid fraction");
            while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
        }
        if (p < t.size() && (t[p] == 'e' || t[p] == 'E')) {
            integral = false;
            ++p;
            if (p < t.size() && (t[p] == '+' || t[p] == '-')) ++p;
            if (p >= t.size() || t[p] < '0' || t[p] > '9') return fail("invalid exponent");
            while (p < t.size() && t[p] >= '0' && t[p] <= '9') ++p;
        }
        const std::string text(t.substr(b, p - b));
        const double d = std::strtod(text.c_str(), nullptr);
        if (!std::isfinite(d)) { p = b; return fail("number out of range"); }
        v.kind = Value::Kind::Number;
        v.num = d;
        if (integral && text.size() <= 18) { v.isInt = true; v.i = std::strtoll(text.c_str(), nullptr, 10); }
        return true;
    }
    bool value(Value& v, int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        ws();
        if (p >= t.size()) return fail("unexpected end");
        const char c = t[p];
        if (c == '{') {
            ++p;
            v = Value::object();
            ws();
            if (p < t.size() && t[p] == '}') { ++p; return true; }
            for (;;) {
                ws();
                if (p >= t.size() || t[p] != '"') return fail("expected object key");
                std::string key;
                if (!str(key)) return false;
                if (v.find(key)) return fail("duplicate object key");
                ws();
                if (p >= t.size() || t[p] != ':') return fail("expected ':'");
                ++p;
                Value child;
                if (!value(child, depth + 1)) return false;
                v.keys.push_back(std::move(key));
                v.items.push_back(std::move(child));
                ws();
                if (p < t.size() && t[p] == ',') { ++p; continue; }
                if (p < t.size() && t[p] == '}') { ++p; return true; }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++p;
            v = Value::array();
            ws();
            if (p < t.size() && t[p] == ']') { ++p; return true; }
            for (;;) {
                Value child;
                if (!value(child, depth + 1)) return false;
                v.items.push_back(std::move(child));
                ws();
                if (p < t.size() && t[p] == ',') { ++p; continue; }
                if (p < t.size() && t[p] == ']') { ++p; return true; }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') { std::string s; if (!str(s)) return false; v = Value::string(std::move(s)); return true; }
        if (lit("true")) { v = Value::boolean(true); return true; }
        if (lit("false")) { v = Value::boolean(false); return true; }
        if (lit("null")) { v = Value::null(); return true; }
        if (c == '-' || (c >= '0' && c <= '9')) return number(v);
        return fail("unexpected character");
    }
};

inline void escapeInto(std::string& o, const std::string& s) {
    o.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o.push_back(static_cast<char>(c));
        }
    }
    o.push_back('"');
}

inline void dumpInto(std::string& o, const Value& v) {
    switch (v.kind) {
        case Value::Kind::Null: o += "null"; break;
        case Value::Kind::Bool: o += v.b ? "true" : "false"; break;
        case Value::Kind::Number:
            if (v.isInt) o += std::to_string(v.i);
            else { char b[40]; std::snprintf(b, sizeof b, "%.17g", v.num); o += b; }
            break;
        case Value::Kind::String: escapeInto(o, v.s); break;
        case Value::Kind::Array:
            o.push_back('[');
            for (std::size_t n = 0; n < v.items.size(); ++n) { if (n) o.push_back(','); dumpInto(o, v.items[n]); }
            o.push_back(']');
            break;
        case Value::Kind::Object:
            o.push_back('{');
            for (std::size_t n = 0; n < v.keys.size(); ++n) {
                if (n) o.push_back(',');
                escapeInto(o, v.keys[n]);
                o.push_back(':');
                dumpInto(o, v.items[n]);
            }
            o.push_back('}');
            break;
    }
}

} // namespace detail

// Parses a complete JSON document. maxBytes protects against oversized input (default 1 MiB).
inline ParseResult parse(std::string_view text, std::size_t maxBytes = 1u << 20) {
    ParseResult r;
    if (text.size() > maxBytes) { r.error = "document too large"; return r; }
    detail::Parser ps;
    ps.t = text;
    Value v;
    if (!ps.value(v, 0)) { r.error = ps.err; return r; }
    ps.ws();
    if (ps.p != text.size()) { ps.fail("trailing characters"); r.error = ps.err; return r; }
    r.value = std::move(v);
    return r;
}

// Compact serialization (no whitespace).
inline std::string dump(const Value& v) {
    std::string o;
    detail::dumpInto(o, v);
    return o;
}

} // namespace av::json

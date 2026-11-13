#pragma once
// Message envelope and framing between the module host and a module process (spec: docs/MODULES.md).
// Wire format: 4-byte little-endian payload length, then that many bytes of UTF-8 JSON (one Message).
#include "json.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace av::host {

constexpr int kProtocolVersion = 1;
constexpr std::size_t kMaxFrameBytes = 1u << 20;  // 1 MiB

struct Message {
    int v = kProtocolVersion;
    std::string type;     // hello, hello_ack, start, started, stop, stopped, ping, pong, event, log, error
    std::string id;       // optional correlation id (ping/pong)
    std::string module;   // module id; required on messages that come from a module
    json::Value payload = json::Value::object();
};

inline json::Value toJson(const Message& m) {
    json::Value o = json::Value::object();
    o.set("v", json::Value::integer(m.v));
    o.set("type", json::Value::string(m.type));
    if (!m.id.empty()) o.set("id", json::Value::string(m.id));
    if (!m.module.empty()) o.set("module", json::Value::string(m.module));
    o.set("payload", m.payload.isObject() ? m.payload : json::Value::object());
    return o;
}

inline bool validMessageType(const std::string& t) {
    if (t.empty() || t.size() > 32) return false;
    for (char c : t)
        if (!((c >= 'a' && c <= 'z') || c == '_')) return false;
    return true;
}

// Strict envelope validation: unknown keys, wrong types and wrong protocol version are all errors.
inline bool fromJson(const json::Value& j, Message& out, std::string& err) {
    if (!j.isObject()) { err = "message must be a JSON object"; return false; }
    for (const auto& k : j.keys)
        if (k != "v" && k != "type" && k != "id" && k != "module" && k != "payload") { err = "unknown message field '" + k + "'"; return false; }
    const json::Value* v = j.find("v");
    if (!v || !v->isNumber() || !v->isInt || v->i != kProtocolVersion) { err = "unsupported or missing protocol version 'v'"; return false; }
    const json::Value* t = j.find("type");
    if (!t || !t->isString() || !validMessageType(t->s)) { err = "invalid or missing 'type'"; return false; }
    Message m;
    m.v = kProtocolVersion;
    m.type = t->s;
    if (const json::Value* id = j.find("id")) {
        if (!id->isString() || id->s.size() > 64) { err = "invalid 'id'"; return false; }
        m.id = id->s;
    }
    if (const json::Value* mod = j.find("module")) {
        if (!mod->isString() || mod->s.size() > 64) { err = "invalid 'module'"; return false; }
        m.module = mod->s;
    }
    if (const json::Value* p = j.find("payload")) {
        if (!p->isObject()) { err = "'payload' must be an object"; return false; }
        m.payload = *p;
    }
    out = std::move(m);
    return true;
}

// Serializes a message into one frame. Returns nullopt if it would exceed the frame limit.
inline std::optional<std::string> encodeFrame(const Message& m) {
    const std::string body = json::dump(toJson(m));
    if (body.empty() || body.size() > kMaxFrameBytes) return std::nullopt;
    std::string f;
    f.reserve(body.size() + 4);
    const std::uint32_t n = static_cast<std::uint32_t>(body.size());
    for (int k = 0; k < 4; ++k) f.push_back(static_cast<char>((n >> (8 * k)) & 0xFF));
    f += body;
    return f;
}

// Incremental decoder: feed it bytes as they arrive, then call next() until it stops returning Frame.
// After the first Error the reader stays in the Error state; the connection must be dropped.
class FrameReader {
public:
    enum class Status { NeedMore, Frame, Error };

    explicit FrameReader(std::size_t maxFrame = kMaxFrameBytes) : max_(maxFrame) {}

    void feed(const void* data, std::size_t n) {
        if (bad_ || n == 0) return;
        buf_.append(static_cast<const char*>(data), n);
    }

    Status next(Message& out) {
        if (bad_) return Status::Error;
        if (buf_.size() < 4) return Status::NeedMore;
        std::uint32_t len = 0;
        for (int k = 0; k < 4; ++k) len |= static_cast<std::uint32_t>(static_cast<unsigned char>(buf_[static_cast<std::size_t>(k)])) << (8 * k);
        if (len == 0 || len > max_) return fail("invalid frame length");
        if (buf_.size() < 4u + len) return Status::NeedMore;
        const json::ParseResult pr = json::parse(std::string_view(buf_).substr(4, len), max_);
        if (!pr.value) return fail("invalid JSON in frame: " + pr.error);
        std::string e;
        if (!fromJson(*pr.value, out, e)) return fail(e);
        buf_.erase(0, 4u + len);
        return Status::Frame;
    }

    const std::string& error() const { return err_; }

private:
    Status fail(std::string e) {
        bad_ = true;
        err_ = std::move(e);
        buf_.clear();
        return Status::Error;
    }
    std::string buf_;
    std::size_t max_;
    std::string err_;
    bool bad_ = false;
};

} // namespace av::host

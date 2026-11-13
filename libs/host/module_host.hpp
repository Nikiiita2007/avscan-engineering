#pragma once
// Module lifecycle and event routing, independent of the OS transport (named pipes will implement Transport).
// Not thread-safe: drive one ModuleHost from a single thread (call pump() regularly from the host loop).
#include "manifest.hpp"
#include "protocol.hpp"

#include <algorithm>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace av::host {

// Connection to one module process. Implemented over named pipes on Windows; faked in tests.
struct Transport {
    virtual ~Transport() = default;
    virtual bool send(const Message& m) = 0;
    // Blocks up to `timeout`. Returns nullopt when the timeout elapsed or the connection is closed.
    virtual std::optional<Message> receive(std::chrono::milliseconds timeout) = 0;
    virtual void terminate() = 0;  // kill the process / drop the connection
};

// Does `pattern` ("a.b" or "a.b.*") match `topic`? "a.*" matches "a" and everything below "a.".
inline bool topicMatches(const std::string& pattern, const std::string& topic) {
    if (detail::endsWithStar(pattern)) {
        const std::string base = detail::patternBase(pattern);
        return topic == base || topic.compare(0, base.size() + 1, base + ".") == 0;
    }
    return pattern == topic;
}

inline bool topicAllowed(const std::vector<std::string>& patterns, const std::string& topic) {
    return std::any_of(patterns.begin(), patterns.end(), [&](const std::string& p) { return topicMatches(p, topic); });
}

class EventBus {
public:
    using Handler = std::function<void(const std::string& topic, const json::Value& data, const std::string& source)>;

    int subscribe(std::string pattern, Handler h) {
        subs_.push_back(Sub{next_, std::move(pattern), std::move(h)});
        return next_++;
    }
    void unsubscribe(int id) {
        subs_.erase(std::remove_if(subs_.begin(), subs_.end(), [&](const Sub& s) { return s.id == id; }), subs_.end());
    }
    // Returns the number of handlers that received the event.
    std::size_t publish(const std::string& topic, const json::Value& data, const std::string& source) {
        const std::vector<Sub> copy = subs_;  // handlers may (un)subscribe while we deliver
        std::size_t n = 0;
        for (const auto& s : copy)
            if (topicMatches(s.pattern, topic)) { s.handler(topic, data, source); ++n; }
        return n;
    }

private:
    struct Sub {
        int id;
        std::string pattern;
        Handler handler;
    };
    std::vector<Sub> subs_;
    int next_ = 1;
};

enum class ModuleState { Created, Handshaking, Starting, Running, Stopping, Stopped, Failed };

struct HostTimeouts {
    std::chrono::milliseconds hello{5000}, start{10000}, stop{5000}, ping{2000};
};

class ModuleHost {
public:
    ModuleHost(Manifest manifest, Transport& transport, EventBus& bus, HostTimeouts timeouts = {})
        : m_(std::move(manifest)), t_(transport), bus_(bus), to_(timeouts) {}
    ModuleHost(const ModuleHost&) = delete;
    ModuleHost& operator=(const ModuleHost&) = delete;
    ~ModuleHost() { unsubscribeAll(); }

    ModuleState state() const { return state_; }
    const std::string& error() const { return error_; }
    bool forcedStop() const { return forced_; }
    unsigned droppedEvents() const { return dropped_; }
    const Manifest& manifest() const { return m_; }
    void setLogSink(std::function<void(const std::string&)> sink) { logSink_ = std::move(sink); }

    // Handshake and start. configOverride keys replace the manifest's default config keys.
    bool start(const json::Value& configOverride = json::Value::object()) {
        if (state_ != ModuleState::Created) return fail("start() called in the wrong state");
        state_ = ModuleState::Handshaking;
        Message hello = base("hello");
        hello.payload.set("host_api", json::Value::integer(kHostApiVersion));
        if (!t_.send(hello)) return fail("cannot send hello");
        auto ack = expect("hello_ack", to_.hello, true);
        if (!ack) return false;
        if (!checkAck(*ack)) return false;

        state_ = ModuleState::Starting;
        json::Value cfg = m_.config;
        for (std::size_t n = 0; n < configOverride.keys.size(); ++n) cfg.set(configOverride.keys[n], configOverride.items[n]);
        Message st = base("start");
        st.payload.set("config", cfg);
        if (!t_.send(st)) return fail("cannot send start");
        if (!expect("started", to_.start, true)) return false;

        state_ = ModuleState::Running;
        for (const auto& pattern : m_.subscribes) {
            subIds_.push_back(bus_.subscribe(pattern, [this](const std::string& topic, const json::Value& data, const std::string& source) {
                if (state_ != ModuleState::Running || source == m_.id) return;
                Message ev = base("event");
                ev.payload.set("topic", json::Value::string(topic));
                ev.payload.set("data", data);
                ev.payload.set("source", json::Value::string(source));
                t_.send(ev);
            }));
        }
        return true;
    }

    // Processes everything the module has already sent, without blocking.
    void pump() {
        while (state_ == ModuleState::Running) {
            auto m = t_.receive(std::chrono::milliseconds(0));
            if (!m) return;
            if (!checkEnvelope(*m)) return;
            if (m->type == "event") handleEvent(*m);
            else if (m->type == "log") handleLog(*m);
            else if (m->type == "error") { error_ = "module reported: " + m->payload.getString("message", "(no message)"); }
            else if (m->type == "stopped") { fail("module stopped on its own"); return; }
            else if (m->type == "pong") continue;
            else { fail("unexpected message '" + m->type + "' from module"); return; }
        }
    }

    // Liveness check: ping/pong with a correlation id.
    bool ping() {
        if (state_ != ModuleState::Running) return false;
        Message p = base("ping");
        p.id = "ping-" + std::to_string(++pingSeq_);
        if (!t_.send(p)) return fail("cannot send ping");
        auto pong = expect("pong", to_.ping, true);
        if (!pong) return false;
        if (pong->id != p.id) return fail("pong carries the wrong id");
        return true;
    }

    // Graceful stop; if the module does not answer in time its process is terminated (forcedStop() == true).
    void stop() {
        if (state_ == ModuleState::Created) { state_ = ModuleState::Stopped; return; }
        if (state_ != ModuleState::Running) return;  // Failed / Stopped stay as they are
        state_ = ModuleState::Stopping;
        unsubscribeAll();
        t_.send(base("stop"));
        auto stopped = expect("stopped", to_.stop, false);
        if (!stopped) {
            forced_ = true;
            t_.terminate();
        }
        state_ = ModuleState::Stopped;
    }

private:
    Message base(const char* type) const {
        Message m;
        m.type = type;
        m.module = m_.id;
        return m;
    }

    bool fail(std::string msg) {
        error_ = std::move(msg);
        state_ = ModuleState::Failed;
        unsubscribeAll();
        t_.terminate();
        return false;
    }

    void unsubscribeAll() {
        for (int id : subIds_) bus_.unsubscribe(id);
        subIds_.clear();
    }

    bool checkEnvelope(const Message& m) {
        if (m.module != m_.id) return fail("message from module '" + m.module + "' on the connection of '" + m_.id + "'");
        return true;
    }

    bool checkAck(const Message& ack) {
        const json::Value& p = ack.payload;
        if (p.getInt("api_version", -1) != m_.apiVersion) return fail("module reports a different api_version than its manifest");
        if (p.getString("module_version") != m_.version) return fail("module version '" + p.getString("module_version") + "' does not match the manifest version '" + m_.version + "'");
        const json::Value* caps = p.find("capabilities");
        if (!caps || !caps->isArray()) return fail("hello_ack must list capabilities");
        for (const auto& c : caps->items) {
            if (!c.isString()) return fail("capabilities must be strings");
            if (std::find(m_.capabilities.begin(), m_.capabilities.end(), c.s) == m_.capabilities.end())
                return fail("module claims capability '" + c.s + "' that its manifest does not declare");
        }
        return true;
    }

    void handleLog(const Message& m) {
        if (logSink_) logSink_(m_.id + ": " + m.payload.getString("message"));
    }

    void handleEvent(const Message& m) {
        const std::string topic = m.payload.getString("topic");
        if (topic.empty() || !topicAllowed(m_.publishes, topic)) {
            ++dropped_;
            error_ = "dropped event with undeclared topic '" + topic + "'";
            return;
        }
        const json::Value* data = m.payload.find("data");
        bus_.publish(topic, data ? *data : json::Value::object(), m_.id);
    }

    // Waits for a message of the given type. Events and logs that arrive meanwhile are processed.
    std::optional<Message> expect(const char* type, std::chrono::milliseconds timeout, bool failOnTimeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            const auto left = now >= deadline ? std::chrono::milliseconds(0) : std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            auto m = t_.receive(left);
            if (!m) {
                if (failOnTimeout) fail(std::string("no '") + type + "' from module (timeout or connection closed)");
                return std::nullopt;
            }
            if (!checkEnvelope(*m)) return std::nullopt;
            if (m->type == type) return m;
            if (m->type == "log") { handleLog(*m); continue; }
            if (m->type == "event") { if (state_ == ModuleState::Running || state_ == ModuleState::Stopping) handleEvent(*m); continue; }
            if (failOnTimeout) fail("unexpected message '" + m->type + "' while waiting for '" + type + "'");
            else continue;  // while stopping, ignore stragglers and keep waiting for "stopped"
            return std::nullopt;
        }
    }

    Manifest m_;
    Transport& t_;
    EventBus& bus_;
    HostTimeouts to_;
    ModuleState state_ = ModuleState::Created;
    std::string error_;
    bool forced_ = false;
    unsigned dropped_ = 0;
    unsigned pingSeq_ = 0;
    std::vector<int> subIds_;
    std::function<void(const std::string&)> logSink_;
};

} // namespace av::host

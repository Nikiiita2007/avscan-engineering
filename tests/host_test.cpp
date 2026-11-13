// Tests for the module host core (libs/host): JSON, protocol framing, manifests, registry, lifecycle, events.
#include "module_host.hpp"
#include "registry.hpp"

#include <chrono>
#include <deque>
#include <fstream>
#include <iostream>
#include <string>

using namespace av;
using namespace av::host;

namespace {

int fails = 0;
void check(bool ok, const char* what) {
    std::cout << (ok ? "PASS " : "FAIL ") << what << '\n';
    if (!ok) ++fails;
}

bool parses(const std::string& s) { return json::parse(s).value.has_value(); }

// ---------- a scripted module on the other end of the transport ----------
struct FakeTransport : Transport {
    std::deque<Message> inbox;
    std::vector<Message> sent;
    bool terminated = false;
    std::function<void(const Message&, FakeTransport&)> onSend;

    bool send(const Message& m) override {
        sent.push_back(m);
        if (onSend) onSend(m, *this);
        return true;
    }
    std::optional<Message> receive(std::chrono::milliseconds) override {
        if (inbox.empty()) return std::nullopt;
        Message m = inbox.front();
        inbox.pop_front();
        return m;
    }
    void terminate() override { terminated = true; }
    bool sentType(const char* t) const {
        for (const auto& m : sent)
            if (m.type == t) return true;
        return false;
    }
};

Manifest sampleManifest() {
    const char* text = R"({
      "id": "antivirus", "name": "AV", "version": "0.4.0", "api_version": 1,
      "entry": {"exe": "m.exe"},
      "capabilities": ["scan.file", "scan.buffer"],
      "permissions": ["fs.read"],
      "events": {"publishes": ["antivirus.threat", "antivirus.stats.*"], "subscribes": ["host.shutdown", "other.*"]},
      "config": {"threads": 2, "db": "a.db"}
    })";
    auto r = parseManifest(text);
    if (!r.value) { std::cerr << "sample manifest invalid\n"; std::exit(3); }
    return *r.value;
}

Message fromModule(const char* type, const std::string& module = "antivirus") {
    Message m;
    m.type = type;
    m.module = module;
    return m;
}

Message goodAck() {
    Message a = fromModule("hello_ack");
    a.payload.set("api_version", json::Value::integer(1));
    a.payload.set("module_version", json::Value::string("0.4.0"));
    json::Value caps = json::Value::array();
    caps.push(json::Value::string("scan.file"));
    a.payload.set("capabilities", caps);
    return a;
}

// A well-behaved module: answers hello/start/stop/ping automatically.
void wellBehaved(FakeTransport& t) {
    t.onSend = [](const Message& m, FakeTransport& tr) {
        if (m.type == "hello") tr.inbox.push_back(goodAck());
        else if (m.type == "start") tr.inbox.push_back(fromModule("started"));
        else if (m.type == "stop") tr.inbox.push_back(fromModule("stopped"));
        else if (m.type == "ping") { Message p = fromModule("pong"); p.id = m.id; tr.inbox.push_back(p); }
    };
}

Message eventFrom(const std::string& topic, const std::string& module = "antivirus") {
    Message e = fromModule("event", module);
    e.payload.set("topic", json::Value::string(topic));
    json::Value d = json::Value::object();
    d.set("n", json::Value::integer(7));
    e.payload.set("data", d);
    return e;
}

bool hasError(const ManifestResult& r, const char* part) {
    for (const auto& e : r.errors)
        if (e.find(part) != std::string::npos) return true;
    return false;
}

std::string withField(const std::string& key, const std::string& valueJson) {
    // base manifest with one top-level field replaced/added
    json::Value base = json::parse(R"({"id":"antivirus","name":"AV","version":"1.2.3","api_version":1,"entry":{"exe":"m.exe"}})").value.value();
    json::Value v = json::parse(valueJson).value.value();
    base.set(key, v);
    return json::dump(base);
}

} // namespace

int main(int argc, char** argv) {
    // ======== JSON ========
    {
        auto r = json::parse(R"({"a":[1,2.5,true,null,"x\u00e9\ud83d\ude00"],"b":{"c":-0}})");
        check(r.value && r.value->find("a") && r.value->find("a")->items.size() == 5, "json: parses nested document");
        check(r.value && r.value->find("a")->items[0].isInt && r.value->find("a")->items[0].i == 1, "json: integers keep int64");
        check(r.value && r.value->find("a")->items[4].s == "x\xC3\xA9\xF0\x9F\x98\x80", "json: \\u escapes and surrogate pairs become UTF-8");
        check(r.value && json::parse(json::dump(*r.value)).value && json::dump(*json::parse(json::dump(*r.value)).value) == json::dump(*r.value), "json: dump/parse round trip is stable");
        check(!parses(""), "json: empty input rejected");
        check(!parses("{\"a\":1,\"a\":2}"), "json: duplicate keys rejected");
        check(!parses("[1,]") && !parses("{\"a\":1,}"), "json: trailing commas rejected");
        check(!parses("[NaN]") && !parses("[Infinity]") && !parses("1e999"), "json: NaN, Infinity and out-of-range numbers rejected");
        check(!parses("\"\\ud800\"") && !parses("\"\\udc00\""), "json: lone surrogates rejected");
        check(!parses("\"\xff\"") && !parses("\"\xc0\x80\"") && !parses("\"\xed\xa0\x80\""), "json: invalid UTF-8 rejected");
        check(!parses("\"a\nb\""), "json: raw control character in string rejected");
        check(!parses("[1] x") && !parses("[1][2]"), "json: trailing garbage rejected");
        check(!parses("[01]") && !parses("[1.]") && !parses("[.5]") && !parses("[+1]"), "json: malformed numbers rejected");
        check(parses(std::string(60, '[') + std::string(60, ']')), "json: 60 nested arrays accepted");
        check(!parses(std::string(200, '[') + std::string(200, ']')), "json: 200 nested arrays rejected");
        check(!json::parse("[1]", 2).value.has_value(), "json: size limit enforced");
    }

    // ======== protocol ========
    {
        Message m;
        m.type = "ping";
        m.id = "p1";
        m.module = "antivirus";
        auto frame = encodeFrame(m);
        check(frame && frame->size() > 4, "protocol: frame encoded");
        FrameReader fr;
        Message out;
        check(fr.next(out) == FrameReader::Status::NeedMore, "protocol: empty reader needs more");
        bool gotFrame = false;
        for (std::size_t k = 0; k < frame->size(); ++k) {
            fr.feed(frame->data() + k, 1);
            const auto st = fr.next(out);
            if (k + 1 < frame->size()) { if (st != FrameReader::Status::NeedMore) gotFrame = false; }
            else gotFrame = (st == FrameReader::Status::Frame);
        }
        check(gotFrame && out.type == "ping" && out.id == "p1" && out.module == "antivirus", "protocol: frame fed byte by byte decodes correctly");

        std::string two = *frame + *frame;
        FrameReader fr2;
        fr2.feed(two.data(), two.size());
        check(fr2.next(out) == FrameReader::Status::Frame && fr2.next(out) == FrameReader::Status::Frame && fr2.next(out) == FrameReader::Status::NeedMore, "protocol: two frames in one buffer");

        const char zero[4] = {0, 0, 0, 0};
        FrameReader fr3;
        fr3.feed(zero, 4);
        check(fr3.next(out) == FrameReader::Status::Error && fr3.next(out) == FrameReader::Status::Error, "protocol: zero length is a sticky error");

        FrameReader small(64);
        std::string big = *frame;
        big[0] = 100;  // length 100 > max 64
        small.feed(big.data(), big.size());
        check(small.next(out) == FrameReader::Status::Error, "protocol: oversize length rejected before buffering the body");

        auto frameOf = [](const std::string& body) {
            std::string f(4, '\0');
            for (int k = 0; k < 4; ++k) f[static_cast<std::size_t>(k)] = static_cast<char>((body.size() >> (8 * k)) & 0xFF);
            return f + body;
        };
        auto decodes = [&](const std::string& body) {
            FrameReader r;
            const std::string f = frameOf(body);
            r.feed(f.data(), f.size());
            Message o;
            return r.next(o) == FrameReader::Status::Frame;
        };
        check(decodes(R"({"v":1,"type":"ping"})"), "protocol: minimal envelope accepted");
        check(!decodes(R"({"v":2,"type":"ping"})"), "protocol: wrong version rejected");
        check(!decodes(R"({"v":1})"), "protocol: missing type rejected");
        check(!decodes(R"({"v":1,"type":"Ping"})"), "protocol: bad type characters rejected");
        check(!decodes(R"({"v":1,"type":"ping","extra":1})"), "protocol: unknown envelope field rejected");
        check(!decodes(R"({"v":1,"type":"ping","payload":[]})"), "protocol: non-object payload rejected");
        check(!decodes("not json"), "protocol: invalid JSON rejected");
        check(!decodes(R"([1,2])"), "protocol: non-object message rejected");
    }

    // ======== manifest ========
    {
        auto ok = parseManifest(withField("description", "\"d\""));
        check(ok.value && ok.errors.empty(), "manifest: minimal manifest accepted");
        check(!parseManifest("{").value && !parseManifest("[]").value, "manifest: non-object / invalid JSON rejected");
        check(hasError(parseManifest(withField("bogus", "1")), "unknown field"), "manifest: unknown top-level field rejected");
        check(hasError(parseManifest(withField("id", "\"Bad-Id\"")), "id:"), "manifest: bad id rejected");
        check(hasError(parseManifest(withField("id", "\"ab\"")), "id:"), "manifest: too short id rejected");
        check(hasError(parseManifest(withField("version", "\"1.2\"")), "version"), "manifest: bad version rejected");
        check(hasError(parseManifest(withField("version", "\"01.2.3\"")), "version"), "manifest: leading zero in version rejected");
        check(hasError(parseManifest(withField("api_version", "2")), "api_version"), "manifest: unsupported api_version rejected");
        check(hasError(parseManifest(withField("entry", R"({"exe":"..\\evil.exe"})")), "entry.exe"), "manifest: exe with .. rejected");
        check(hasError(parseManifest(withField("entry", R"({"exe":"C:\\x.exe"})")), "entry.exe"), "manifest: exe with drive letter rejected");
        check(hasError(parseManifest(withField("entry", R"({"exe":"/etc/x"})")), "entry.exe"), "manifest: absolute exe rejected");
        check(hasError(parseManifest(withField("entry", R"({"exe":"a//b.exe"})")), "entry.exe"), "manifest: empty path segment rejected");
        check(hasError(parseManifest(withField("entry", R"({"exe":"a.exe.","args":[]})")), "entry.exe"), "manifest: trailing dot rejected");
        check(parseManifest(withField("entry", R"({"exe":"bin\\m.exe","args":["--module"]})")).value.has_value(), "manifest: nested relative exe accepted");
        check(hasError(parseManifest(withField("permissions", R"(["fs.read","root"])")), "unknown permission"), "manifest: unknown permission rejected");
        check(hasError(parseManifest(withField("permissions", R"(["fs.read","fs.read"])")), "duplicate"), "manifest: duplicate permission rejected");
        check(hasError(parseManifest(withField("capabilities", R"(["Scan"])")), "capabilities"), "manifest: bad capability name rejected");
        check(hasError(parseManifest(withField("events", R"({"publishes":["other.topic"]})")), "must start with the module id"), "manifest: cannot publish in another module's namespace");
        check(parseManifest(withField("events", R"({"publishes":["antivirus","antivirus.a.*"],"subscribes":["x.*"]})")).value.has_value(), "manifest: own-namespace topics and patterns accepted");
        check(hasError(parseManifest(withField("events", R"({"publishes":["antivirus.BAD"]})")), "invalid topic"), "manifest: invalid topic rejected");
        check(hasError(parseManifest(withField("restart", R"({"policy":"always"})")), "restart.policy"), "manifest: bad restart policy rejected");
        check(hasError(parseManifest(withField("restart", R"({"max_restarts":99})")), "max_restarts"), "manifest: restart count limit");
        check(hasError(parseManifest(withField("config", "[]")), "config"), "manifest: config must be an object");
        check(parseManifest(withField("restart", R"({"policy":"on_failure","max_restarts":3})")).value->maxRestarts == 3, "manifest: restart values parsed");
    }

    // ======== topics and bus ========
    {
        check(topicMatches("a.b", "a.b") && !topicMatches("a.b", "a.b.c"), "topics: exact match");
        check(topicMatches("a.*", "a") && topicMatches("a.*", "a.b.c") && !topicMatches("a.*", "ab"), "topics: wildcard matches the base and everything below");
        EventBus bus;
        int got = 0;
        std::string lastSource;
        const int id = bus.subscribe("x.*", [&](const std::string&, const json::Value&, const std::string& src) { ++got; lastSource = src; });
        check(bus.publish("x.y", json::Value::object(), "mod") == 1 && got == 1 && lastSource == "mod", "bus: delivers matching events");
        check(bus.publish("z", json::Value::object(), "mod") == 0 && got == 1, "bus: ignores non-matching events");
        bus.unsubscribe(id);
        check(bus.publish("x.y", json::Value::object(), "mod") == 0, "bus: unsubscribe stops delivery");
    }

    // ======== lifecycle ========
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        check(h.start(), "host: handshake and start succeed");
        check(h.state() == ModuleState::Running && t.sentType("hello") && t.sentType("start"), "host: state Running after hello and start");
        const json::Value* cfg = nullptr;
        for (const auto& m : t.sent) if (m.type == "start") cfg = m.payload.find("config");
        check(cfg && cfg->getInt("threads") == 2, "host: default config from manifest sent in start");
        check(h.ping(), "host: ping gets matching pong");
        h.stop();
        check(h.state() == ModuleState::Stopped && !h.forcedStop() && !t.terminated && t.sentType("stop"), "host: graceful stop");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        json::Value over = json::Value::object();
        over.set("threads", json::Value::integer(8));
        check(h.start(over), "host: start with config override");
        const json::Value* cfg = nullptr;
        for (const auto& m : t.sent) if (m.type == "start") cfg = m.payload.find("config");
        check(cfg && cfg->getInt("threads") == 8 && cfg->getString("db") == "a.db", "host: override replaces only the given keys");
    }
    {
        FakeTransport t; EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);  // nobody answers
        check(!h.start() && h.state() == ModuleState::Failed && t.terminated, "host: no hello_ack -> Failed and process terminated");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "hello") tr.inbox.push_back(fromModule("hello_ack", "intruder")); };
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.error().find("intruder") != std::string::npos, "host: ack from a different module id rejected");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "hello") { Message a = goodAck(); a.payload.set("api_version", json::Value::integer(2)); tr.inbox.push_back(a); } };
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.error().find("api_version") != std::string::npos, "host: api_version mismatch rejected");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "hello") { Message a = goodAck(); a.payload.set("module_version", json::Value::string("9.9.9")); tr.inbox.push_back(a); } };
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.error().find("version") != std::string::npos, "host: module version must match the manifest");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) {
            if (m.type == "hello") { Message a = goodAck(); json::Value caps = json::Value::array(); caps.push(json::Value::string("scan.file")); caps.push(json::Value::string("spawn.anything")); a.payload.set("capabilities", caps); tr.inbox.push_back(a); }
        };
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.error().find("spawn.anything") != std::string::npos, "host: undeclared capability rejected");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "hello") tr.inbox.push_back(goodAck()); };  // never says "started"
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.state() == ModuleState::Failed, "host: no 'started' -> Failed");
    }
    {
        FakeTransport t; EventBus bus;
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "hello") tr.inbox.push_back(fromModule("stopped")); };
        ModuleHost h(sampleManifest(), t, bus);
        check(!h.start() && h.error().find("unexpected message") != std::string::npos, "host: unexpected message during handshake rejected");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        t.onSend = [](const Message&, FakeTransport&) {};  // module hangs: ignores "stop"
        h.stop();
        check(h.state() == ModuleState::Stopped && h.forcedStop() && t.terminated, "host: module ignoring stop is terminated");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        t.onSend = [](const Message&, FakeTransport&) {};
        check(!h.ping() && h.state() == ModuleState::Failed && t.terminated, "host: missing pong -> Failed");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        t.onSend = [](const Message& m, FakeTransport& tr) { if (m.type == "ping") { Message p = fromModule("pong"); p.id = "wrong"; tr.inbox.push_back(p); } };
        check(!h.ping(), "host: pong with wrong id -> failure");
    }
    {
        FakeTransport t; EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.stop();
        check(h.state() == ModuleState::Stopped, "host: stop before start is harmless");
        check(!h.start(), "host: cannot start after stop");
    }

    // ======== events through the host ========
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        std::vector<std::string> topics;
        bus.subscribe("antivirus.*", [&](const std::string& topic, const json::Value& d, const std::string& src) { topics.push_back(topic + "|" + src + "|" + std::to_string(d.getInt("n"))); });
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        t.inbox.push_back(eventFrom("antivirus.threat"));
        t.inbox.push_back(eventFrom("antivirus.stats.cpu"));
        t.inbox.push_back(eventFrom("net_analyzer.alert"));  // not declared in publishes: must be dropped
        t.inbox.push_back(eventFrom("antivirus.unknown"));    // inside the namespace but not declared: dropped
        h.pump();
        check(topics.size() == 2 && topics[0] == "antivirus.threat|antivirus|7" && topics[1] == "antivirus.stats.cpu|antivirus|7", "events: declared topics are published with the module as source");
        check(h.droppedEvents() == 2 && h.state() == ModuleState::Running, "events: undeclared topics are dropped without killing the module");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        bus.publish("host.shutdown", json::Value::object(), "host");
        bus.publish("unrelated.topic", json::Value::object(), "host");
        bus.publish("other.thing", json::Value::object(), "host");
        int events = 0;
        for (const auto& m : t.sent) if (m.type == "event") ++events;
        check(events == 2, "events: module receives only the topics it subscribed to");
        bus.publish("host.shutdown", json::Value::object(), "antivirus");
        int after = 0;
        for (const auto& m : t.sent) if (m.type == "event") ++after;
        check(after == 2, "events: a module does not receive its own events back");
        h.stop();
        bus.publish("host.shutdown", json::Value::object(), "host");
        int afterStop = 0;
        for (const auto& m : t.sent) if (m.type == "event") ++afterStop;
        check(afterStop == 2, "events: no delivery after stop");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        std::vector<std::string> logs;
        h.setLogSink([&](const std::string& s) { logs.push_back(s); });
        h.start();
        Message l = fromModule("log");
        l.payload.set("message", json::Value::string("hello"));
        t.inbox.push_back(l);
        t.inbox.push_back(fromModule("pong", "someone_else"));
        h.pump();
        check(logs.size() == 1 && logs[0] == "antivirus: hello", "events: module log lines reach the sink");
        check(h.state() == ModuleState::Failed && t.terminated, "events: message from a foreign module id kills the connection");
    }
    {
        FakeTransport t; wellBehaved(t); EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        h.start();
        t.inbox.push_back(fromModule("stopped"));
        h.pump();
        check(h.state() == ModuleState::Failed, "events: unrequested 'stopped' marks the module Failed");
    }

    // ======== registry ========
    {
        namespace fs = std::filesystem;
        const fs::path root = fs::temp_directory_path() / ("avhost-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        auto write = [&](const std::string& rel, const std::string& text) {
            const fs::path p = root / rel;
            fs::create_directories(p.parent_path());
            std::ofstream(p, std::ios::binary) << text;
        };
        const std::string good = R"({"id":"alpha","name":"A","version":"1.0.0","api_version":1,"entry":{"exe":"a.exe"}})";
        write("alpha/module.json", good);
        write("beta/module.json", good);  // directory name != id
        write("gamma/module.json", "{ nope");
        write("empty_dir/readme.txt", "no manifest here");
        write("zeta/module.json", R"({"id":"zeta","name":"Z","version":"1.0.0","api_version":1,"entry":{"exe":"z.exe"}})");
        write("stray.txt", "x");
        auto d = discoverModules(root);
        check(d.modules.size() == 2 && d.modules[0].id == "alpha" && d.modules[1].id == "zeta", "registry: valid modules found and sorted");
        check(d.errors.size() == 2, "registry: bad modules reported, non-module entries ignored");
        check(!d.modules.empty() && d.modules[0].root == root / "alpha", "registry: module root recorded");
        auto d2 = discoverModules(root, true);
        check(d2.modules.empty() && d2.errors.size() >= 4, "registry: requireExecutable reports missing executables");
        write("alpha/a.exe", "MZ");
        auto d3 = discoverModules(root, true);
        check(d3.modules.size() == 1 && d3.modules[0].id == "alpha", "registry: module with existing executable accepted");
        check(!discoverModules(root / "does_not_exist").errors.empty(), "registry: missing modules directory reported");
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    // ======== sample modules shipped with the repository ========
    if (argc > 1) {
        auto d = discoverModules(argv[1]);
        std::string all;
        for (const auto& e : d.errors) all += e + "; ";
        if (!all.empty()) std::cout << "sample module errors: " << all << '\n';
        check(d.errors.empty() && d.modules.size() == 3, "samples: antivirus, net_analyzer and vuln_parser manifests are valid");
        if (d.modules.size() == 3) check(d.modules[0].id == "antivirus" && d.modules[1].id == "net_analyzer" && d.modules[2].id == "vuln_parser", "samples: expected ids");
    }
    return fails ? 1 : 0;
}

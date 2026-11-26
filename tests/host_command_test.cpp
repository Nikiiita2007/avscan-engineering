// Tests for command / command_result in the module host core (libs/host/module_host.hpp).
#include "module_host.hpp"

#include <chrono>
#include <deque>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace av;
using namespace av::host;

namespace {

int fails = 0;
void check(bool ok, const char* what) {
    std::cout << (ok ? "PASS " : "FAIL ") << what << '\n';
    if (!ok) ++fails;
}

// A scripted module on the other end of the transport.
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
    int countSent(const char* type) const {
        int n = 0;
        for (const auto& m : sent)
            if (m.type == type) ++n;
        return n;
    }
};

Manifest sampleManifest() {
    const char* text = R"({
      "id": "antivirus", "name": "AV", "version": "0.4.0", "api_version": 1,
      "entry": {"exe": "m.exe"},
      "capabilities": ["scan.file"]
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

Message commandResult(const std::string& id, bool ok, const std::string& error = "") {
    Message m = fromModule("command_result");
    m.id = id;
    m.payload.set("ok", json::Value::boolean(ok));
    if (!error.empty()) m.payload.set("error", json::Value::string(error));
    return m;
}

// A well-behaved module: answers hello, start, stop and ping. It never answers commands by itself.
void wellBehaved(FakeTransport& t) {
    t.onSend = [](const Message& m, FakeTransport& tr) {
        if (m.type == "hello") tr.inbox.push_back(goodAck());
        else if (m.type == "start") tr.inbox.push_back(fromModule("started"));
        else if (m.type == "stop") tr.inbox.push_back(fromModule("stopped"));
        else if (m.type == "ping") { Message p = fromModule("pong"); p.id = m.id; tr.inbox.push_back(p); }
    };
}

using Outcomes = std::vector<CommandOutcome>;

CommandCallback collect(Outcomes& out) {
    return [&out](const CommandOutcome& o) { out.push_back(o); };
}

const Message* lastCommand(const FakeTransport& t) {
    const Message* found = nullptr;
    for (const auto& m : t.sent)
        if (m.type == "command") found = &m;
    return found;
}

// A running module behind a fake transport.
struct Running {
    FakeTransport t;
    EventBus bus;
    ModuleHost h;
    Running() : h(sampleManifest(), t, bus) {
        wellBehaved(t);
        h.start();
    }
};

} // namespace

int main() {
    {
        Running r;
        Outcomes got;
        json::Value args = json::Value::object();
        args.set("path", json::Value::string("/tmp/x"));
        check(r.h.sendCommand("scan.file", args, collect(got)), "commands: a declared capability is sent");
        const Message* cmd = lastCommand(r.t);
        check(cmd && cmd->id == "cmd-1" && cmd->module == "antivirus" && cmd->payload.getString("name") == "scan.file",
              "commands: the message carries id, module and name");
        const json::Value* sentArgs = cmd ? cmd->payload.find("args") : nullptr;
        check(sentArgs && sentArgs->getString("path") == "/tmp/x", "commands: the message carries the arguments");
        check(got.empty(), "commands: the callback waits for command_result");
        r.t.inbox.push_back(commandResult("cmd-1", true));
        r.h.pump();
        check(got.size() == 1 && got[0].ok && got[0].error.empty(), "commands: command_result completes the callback");
        check(r.h.state() == ModuleState::Running, "commands: the module keeps running after a result");
        r.t.inbox.push_back(commandResult("cmd-1", true));
        r.h.pump();
        check(r.h.state() == ModuleState::Failed && got.size() == 1, "commands: a second result for the same id is a violation");
    }
    {
        Running r;
        Outcomes got;
        r.h.sendCommand("scan.file", json::Value::object(), collect(got));
        r.t.inbox.push_back(commandResult("cmd-1", false, "boom"));
        r.h.pump();
        check(got.size() == 1 && !got[0].ok && got[0].error == "boom", "commands: a failed result keeps the module's error text");
    }
    {
        Running r;
        Outcomes got;
        const bool sent = r.h.sendCommand("evil", json::Value::object(), collect(got));
        check(!sent && got.size() == 1 && !got[0].ok && got[0].error.find("evil") != std::string::npos,
              "commands: an undeclared capability is rejected at once");
        check(r.t.countSent("command") == 0 && r.h.state() == ModuleState::Running, "commands: a rejected command is not sent");
    }
    {
        FakeTransport t;
        EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        Outcomes got;
        const bool sent = h.sendCommand("scan.file", json::Value::object(), collect(got));
        check(!sent && got.size() == 1 && !got[0].ok && t.countSent("command") == 0, "commands: nothing is sent before the module runs");
    }
    {
        Running r;
        Outcomes got;
        r.h.sendCommand("scan.file", json::Value::string("not an object"), collect(got));
        const Message* cmd = lastCommand(r.t);
        const json::Value* sentArgs = cmd ? cmd->payload.find("args") : nullptr;
        check(sentArgs && sentArgs->isObject(), "commands: non-object arguments are replaced by an empty object");
    }
    {
        Running r;
        Outcomes got;
        r.t.inbox.push_back(commandResult("cmd-77", true));
        r.h.pump();
        check(r.h.state() == ModuleState::Failed && r.t.terminated && r.h.error().find("unknown id") != std::string::npos,
              "commands: a result with an unknown id fails the module");
    }
    {
        Running r;
        Outcomes got;
        r.h.sendCommand("scan.file", json::Value::object(), collect(got));
        r.h.stop();
        check(r.h.state() == ModuleState::Stopped && got.size() == 1 && !got[0].ok && got[0].error.find("stopped") != std::string::npos,
              "commands: stop completes waiting commands with a failure");
    }
    {
        Running r;
        Outcomes got;
        r.h.sendCommand("scan.file", json::Value::object(), collect(got));
        r.t.inbox.push_back(fromModule("pong", "someone_else"));
        r.h.pump();
        check(r.h.state() == ModuleState::Failed && got.size() == 1 && !got[0].ok && got[0].error.find("failed") != std::string::npos,
              "commands: a failing module completes waiting commands with a failure");
    }
    {
        Running r;
        Outcomes got;
        int accepted = 0;
        for (std::size_t n = 0; n < kMaxPendingCommands; ++n)
            if (r.h.sendCommand("scan.file", json::Value::object(), collect(got))) ++accepted;
        check(accepted == static_cast<int>(kMaxPendingCommands) && got.empty(), "commands: up to the limit may wait");
        const bool extra = r.h.sendCommand("scan.file", json::Value::object(), collect(got));
        check(!extra && got.size() == 1 && !got[0].ok, "commands: a command over the limit is rejected");
        check(r.t.countSent("command") == static_cast<int>(kMaxPendingCommands), "commands: the rejected command is not sent");
    }
    {
        Running r;
        Outcomes got;
        r.h.sendCommand("scan.file", json::Value::object(), collect(got));
        r.t.onSend = [](const Message& m, FakeTransport& tr) {
            if (m.type != "ping") return;
            tr.inbox.push_back(commandResult("cmd-1", true));
            Message p = fromModule("pong");
            p.id = m.id;
            tr.inbox.push_back(p);
        };
        check(r.h.ping(), "commands: a result that arrives while waiting for a pong is not an error");
        check(got.size() == 1 && got[0].ok, "commands: that result still completes its command");
    }
    return fails ? 1 : 0;
}

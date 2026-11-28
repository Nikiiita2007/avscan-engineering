// Tests for the stream transport and the named-pipe client (libs/host/pipe_transport.hpp).
#include "pipe_transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

using namespace av;
using namespace av::host;

namespace {

int fails = 0;
void check(bool ok, const char* what) {
    std::cout << (ok ? "PASS " : "FAIL ") << what << '\n';
    if (!ok) ++fails;
}

const std::chrono::milliseconds kNow(0);

// A scripted peer: `chunks` is what it sends, `written` is what the host wrote to it.
struct FakeStream : ByteStream {
    std::deque<std::string> chunks;
    std::string written;
    bool closed = false;  // once the chunks are used up, reads report Closed instead of Timeout
    bool failWrites = false;
    int closeCalls = 0;

    bool write(const void* d, std::size_t n) override {
        if (failWrites) return false;
        written.append(static_cast<const char*>(d), n);
        return true;
    }
    Read read(void* buf, std::size_t cap, std::size_t& got, std::chrono::milliseconds) override {
        got = 0;
        if (chunks.empty()) return closed ? Read::Closed : Read::Timeout;
        std::string& c = chunks.front();
        got = std::min(cap, c.size());
        std::memcpy(buf, c.data(), got);
        c.erase(0, got);
        if (c.empty()) chunks.pop_front();
        return Read::Data;
    }
    void close() override { ++closeCalls; }
};

std::string frameOf(const char* type, const std::string& id = "") {
    Message m;
    m.type = type;
    m.module = "m";
    m.id = id;
    return *encodeFrame(m);
}

using Rig = std::pair<std::unique_ptr<StreamTransport>, FakeStream*>;

Rig makeRig() {
    auto s = std::make_unique<FakeStream>();
    FakeStream* raw = s.get();
    return Rig{std::make_unique<StreamTransport>(std::move(s)), raw};
}

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

// A module on the far end of the stream: it decodes the frames it receives and answers like a good module.
struct ScriptedModule : ByteStream {
    FrameReader in;
    std::string out;

    bool write(const void* d, std::size_t n) override {
        in.feed(d, n);
        Message m;
        while (in.next(m) == FrameReader::Status::Frame) reply(m);
        return true;
    }
    Read read(void* buf, std::size_t cap, std::size_t& got, std::chrono::milliseconds) override {
        got = std::min(cap, out.size());
        if (got == 0) return Read::Timeout;
        std::memcpy(buf, out.data(), got);
        out.erase(0, got);
        return Read::Data;
    }
    void close() override {}

    void reply(const Message& m) {
        Message r;
        r.module = "antivirus";
        if (m.type == "hello") {
            r.type = "hello_ack";
            r.payload.set("api_version", json::Value::integer(1));
            r.payload.set("module_version", json::Value::string("0.4.0"));
            json::Value caps = json::Value::array();
            caps.push(json::Value::string("scan.file"));
            r.payload.set("capabilities", caps);
        } else if (m.type == "start") {
            r.type = "started";
        } else if (m.type == "stop") {
            r.type = "stopped";
        } else if (m.type == "ping") {
            r.type = "pong";
            r.id = m.id;
        } else {
            return;
        }
        out += *encodeFrame(r);
    }
};

#ifdef _WIN32
void windowsPipeRoundTrip() {
    const std::string name = std::string(R"(\\.\pipe\avscan-host-test-)") + std::to_string(GetCurrentProcessId());
    const std::wstring wname(name.begin(), name.end());
    HANDLE server = CreateNamedPipeW(wname.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
                                     65536, 65536, 0, nullptr);
    check(server != INVALID_HANDLE_VALUE, "pipe: the test server pipe is created");
    if (server == INVALID_HANDLE_VALUE) return;
    std::string error;
    auto t = connectPipeTransport(name, std::chrono::milliseconds(2000), error);
    check(t != nullptr, "pipe: the client connects");
    if (!t) {
        CloseHandle(server);
        return;
    }
    ConnectNamedPipe(server, nullptr);  // ERROR_PIPE_CONNECTED is fine: the client came first

    const std::string pong = frameOf("pong", "7");
    DWORD done = 0;
    WriteFile(server, pong.data(), static_cast<DWORD>(pong.size()), &done, nullptr);
    auto got = t->receive(std::chrono::milliseconds(2000));
    check(got && got->type == "pong" && got->id == "7", "pipe: a frame written by the server is received");
    check(!t->receive(std::chrono::milliseconds(50)) && t->connected(), "pipe: an idle pipe times out and stays connected");

    Message hello;
    hello.type = "hello";
    hello.module = "m";
    check(t->send(hello), "pipe: a frame is sent");
    char buf[256];
    DWORD n = 0;
    ReadFile(server, buf, sizeof buf, &n, nullptr);
    FrameReader reader;
    reader.feed(buf, n);
    Message back;
    check(reader.next(back) == FrameReader::Status::Frame && back.type == "hello", "pipe: the server reads the frame");

    CloseHandle(server);
    check(!t->receive(std::chrono::milliseconds(500)) && !t->connected(), "pipe: a closed server ends the connection");

    std::string missing;
    auto none = connectPipeTransport(name, std::chrono::milliseconds(100), missing);
    check(!none && !missing.empty(), "pipe: a pipe that does not exist is reported");
}
#endif

} // namespace

int main() {
    {
        auto [t, raw] = makeRig();
        Message hello;
        hello.type = "hello";
        hello.module = "m";
        check(t->send(hello) && raw->written == *encodeFrame(hello), "stream: send writes exactly one encoded frame");
    }
    {
        auto [t, raw] = makeRig();
        raw->chunks.push_back(frameOf("pong", "7"));
        auto m = t->receive(kNow);
        check(m && m->type == "pong" && m->id == "7" && m->module == "m", "stream: a whole frame is received");
    }
    {
        auto [t, raw] = makeRig();
        for (char c : frameOf("pong")) raw->chunks.push_back(std::string(1, c));
        auto m = t->receive(kNow);
        check(m && m->type == "pong", "stream: a frame that arrives byte by byte is reassembled");
    }
    {
        auto [t, raw] = makeRig();
        raw->chunks.push_back(frameOf("started") + frameOf("pong"));
        auto a = t->receive(kNow);
        auto b = t->receive(kNow);
        auto c = t->receive(kNow);
        check(a && a->type == "started" && b && b->type == "pong" && !c, "stream: two frames in one chunk come out one by one");
        check(t->connected(), "stream: running out of data is not an error");
    }
    {
        auto [t, raw] = makeRig();
        check(!t->receive(kNow) && t->connected(), "stream: a timeout keeps the connection");
        raw->chunks.push_back(frameOf("pong"));
        check(t->receive(kNow).has_value(), "stream: data that comes after a timeout is received");
    }
    {
        auto [t, raw] = makeRig();
        raw->closed = true;
        Message hello;
        hello.type = "hello";
        hello.module = "m";
        check(!t->receive(kNow) && !t->connected() && raw->closeCalls == 1, "stream: a closed peer drops the stream");
        check(!t->send(hello) && raw->written.empty(), "stream: nothing is sent after the drop");
    }
    {
        auto [t, raw] = makeRig();
        raw->closed = true;
        raw->chunks.push_back(frameOf("pong"));
        auto first = t->receive(kNow);
        auto second = t->receive(kNow);
        check(first && first->type == "pong" && !second && !t->connected(), "stream: a frame received before the close is not lost");
    }
    {
        auto [t, raw] = makeRig();
        raw->chunks.push_back(std::string(4, '\0'));
        check(!t->receive(kNow) && !t->connected() && !t->error().empty(), "stream: a malformed frame drops the stream");
    }
    {
        auto [t, raw] = makeRig();
        Message big;
        big.type = "event";
        big.module = "m";
        big.payload.set("blob", json::Value::string(std::string(kMaxFrameBytes + 1, 'x')));
        check(!t->send(big) && raw->written.empty() && t->connected(), "stream: an oversized message is refused without dropping the stream");
    }
    {
        auto [t, raw] = makeRig();
        raw->failWrites = true;
        Message hello;
        hello.type = "hello";
        hello.module = "m";
        check(!t->send(hello) && !t->connected(), "stream: a failed write drops the stream");
    }
    {
        auto [t, raw] = makeRig();
        t->terminate();
        t->terminate();
        check(!t->connected() && raw->closeCalls == 1, "stream: terminate closes the stream once");
    }
    {
        StreamTransport t(std::make_unique<ScriptedModule>());
        EventBus bus;
        ModuleHost h(sampleManifest(), t, bus);
        check(h.start(), "host: the handshake works over the stream transport");
        check(h.state() == ModuleState::Running, "host: the module is running");
        check(h.ping(), "host: ping and pong work over the stream transport");
        h.stop();
        check(h.state() == ModuleState::Stopped && !h.forcedStop(), "host: a graceful stop works over the stream transport");
    }
    {
        std::string error;
        auto t = connectPipeTransport("", std::chrono::milliseconds(0), error);
        check(!t && !error.empty(), "pipe: an empty pipe name is refused");
    }
#ifdef _WIN32
    windowsPipeRoundTrip();
#endif
    return fails ? 1 : 0;
}

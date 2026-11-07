#pragma once
// База сигнатур + автомат Ахо–Корасик.
// Формат строки (разделитель '|'):
//   version|2026.11.07
//   sig|Имя|malware|pe|[@смещение:]HEX_с_??  &&  [@смещение:]"ascii"
//   sig|Имя|suspicious|script|"powershell -enc"
//   sha256|<64 hex>|Имя
//   fuzzy|<ssdeep-подобный хэш>|Имя семейства
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include "modern.hpp"
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include "types.hpp"

namespace av {

struct Pattern {
    std::vector<std::uint8_t> bytes; // уже применена маска
    std::vector<std::uint8_t> mask;  // 0xFF точно, 0x00 любой байт (??)
    std::optional<std::uint64_t> offset; // абсолютное смещение от начала файла
    std::size_t anchorPos = 0, anchorLen = 0;
};

struct Signature {
    std::string name;
    bool malware = true;
    std::optional<FileType> type; // нет => любой тип
    std::vector<Pattern> patterns; // все должны совпасть (AND)
};

class AhoCorasick {
public:
    AhoCorasick() { nodes_.emplace_back(); nodes_.back().fill(-1); out_.emplace_back(); }
    void add(const std::uint8_t* w, std::size_t n, std::uint32_t id) {
        int s = 0;
        for (std::size_t i = 0; i < n; ++i) {
            int& nx = nodes_[s][w[i]];
            if (nx < 0) { nx = int(nodes_.size()); nodes_.emplace_back(); nodes_.back().fill(-1); out_.emplace_back(); }
            s = nodes_[s][w[i]];
        }
        out_[s].push_back(id);
    }
    void build() {
        std::vector<int> fail(nodes_.size(), 0);
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            int& nx = nodes_[0][c];
            if (nx < 0) nx = 0; else { fail[nx] = 0; q.push(nx); }
        }
        while (!q.empty()) {
            int u = q.front(); q.pop();
            for (auto id : out_[fail[u]]) out_[u].push_back(id);
            for (int c = 0; c < 256; ++c) {
                int v = nodes_[u][c];
                if (v < 0) nodes_[u][c] = nodes_[fail[u]][c];
                else { fail[v] = nodes_[fail[u]][c]; q.push(v); }
            }
        }
    }
    int next(int s, std::uint8_t c) const { return nodes_[s][c]; }
    const std::vector<std::uint32_t>& out(int s) const { return out_[s]; }
private:
    std::vector<std::array<int, 256>> nodes_;
    std::vector<std::vector<std::uint32_t>> out_;
};

struct PatRef { std::uint32_t sig, pat; };

class SigDb {
public:
    std::string version = "none";
    std::vector<Signature> sigs;
    std::unordered_map<std::string, std::string> sha256;       // hash -> имя
    std::vector<std::pair<std::string, std::string>> fuzzy;    // (хэш, семейство)
    std::vector<std::string> warnings;
    AhoCorasick ac;
    std::vector<PatRef> refs;
    std::size_t maxPatLen = 1;

    bool load(const std::string& path) {
        std::ifstream in(pathFromUtf8(path));
        if (!in) { warnings.push_back("не удалось открыть базу: " + path); return false; }
        std::string line;
        int ln = 0;
        while (std::getline(in, line)) {
            ++ln;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto t = trim(line);
            if (t.empty() || t[0] == '#') continue;
            auto f = splitBar(t);
            auto warn = [&](const std::string& m) { warnings.push_back(path + ":" + std::to_string(ln) + ": " + m); };
            if (f[0] == "version" && f.size() >= 2) version = trim(f[1]);
            else if (f[0] == "sha256" && f.size() >= 3) sha256[lower(trim(f[1]))] = trim(f[2]);
            else if (f[0] == "fuzzy" && f.size() >= 3) fuzzy.emplace_back(trim(f[1]), trim(f[2]));
            else if (f[0] == "sig" && f.size() >= 5) {
                Signature s; s.name = trim(f[1]);
                auto cls = trim(f[2]);
                if (cls == "malware") s.malware = true;
                else if (cls == "suspicious") s.malware = false;
                else { warn("класс должен быть malware|suspicious"); continue; }
                auto ty = trim(f[3]);
                if (ty != "any") {
                    auto ft = parseType(ty);
                    if (!ft) { warn("неизвестный тип файла: " + ty); continue; }
                    s.type = ft;
                }
                bool ok = true;
                for (auto& ps : splitAnd(f[4])) {
                    Pattern p; std::string err;
                    if (!parsePattern(ps, p, err)) { warn(err); ok = false; break; }
                    s.patterns.push_back(std::move(p));
                }
                if (ok && !s.patterns.empty()) sigs.push_back(std::move(s));
            } else warn("нераспознанная строка");
        }
        finalize();
        return true;
    }

    void finalize() {
        ac = AhoCorasick();
        refs.clear();
        maxPatLen = 1;
        for (std::uint32_t i = 0; i < sigs.size(); ++i)
            for (std::uint32_t j = 0; j < sigs[i].patterns.size(); ++j) {
                auto& p = sigs[i].patterns[j];
                ac.add(p.bytes.data() + p.anchorPos, p.anchorLen, std::uint32_t(refs.size()));
                refs.push_back({i, j});
                maxPatLen = std::max(maxPatLen, p.bytes.size());
            }
        ac.build();
    }

    static std::optional<FileType> parseType(const std::string& s) {
        if (s == "pe") return FileType::PE;
        if (s == "elf") return FileType::ELF;
        if (s == "script") return FileType::Script;
        if (s == "zip") return FileType::Zip;
        if (s == "7z") return FileType::SevenZip;
        if (s == "rar") return FileType::Rar;
        if (s == "jpeg") return FileType::Jpeg;
        return std::nullopt;
    }

    static bool parsePattern(std::string s, Pattern& p, std::string& err) {
        s = trim(s);
        if (s.size() > 1 && s[0] == '@') {
            auto c = s.find(':');
            if (c == std::string::npos) { err = "смещение без ':'"; return false; }
            try { p.offset = std::stoull(s.substr(1, c - 1), nullptr, 0); } catch (...) { err = "плохое смещение"; return false; }
            s = trim(s.substr(c + 1));
        }
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            for (std::size_t i = 1; i + 1 < s.size(); ++i) { p.bytes.push_back(std::uint8_t(s[i])); p.mask.push_back(0xFF); }
        } else {
            std::size_t i = 0;
            while (i < s.size()) {
                if (std::isspace(static_cast<unsigned char>(s[i]))) { ++i; continue; }
                if (i + 1 >= s.size()) { err = "нечётное число hex-символов"; return false; }
                if (s[i] == '?' && s[i+1] == '?') { p.bytes.push_back(0); p.mask.push_back(0); }
                else {
                    int a = hexv(s[i]), b = hexv(s[i+1]);
                    if (a < 0 || b < 0) { err = "некорректный hex: " + s.substr(i, 2); return false; }
                    p.bytes.push_back(std::uint8_t(a * 16 + b)); p.mask.push_back(0xFF);
                }
                i += 2;
            }
        }
        std::size_t best = 0, run = 0, start = 0;
        for (std::size_t i = 0; i < p.mask.size(); ++i) {
            if (p.mask[i]) { if (run++ == 0) start = i; if (run > best) { best = run; p.anchorPos = start; } }
            else run = 0;
        }
        p.anchorLen = best;
        if (best < 2) { err = "в шаблоне должно быть минимум 2 подряд идущих точных байта"; return false; }
        return true;
    }

    static std::string trim(const std::string& s) {
        std::size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
        return a == std::string::npos ? "" : s.substr(a, b - a + 1);
    }
    static std::string lower(std::string s) { for (auto& c : s) c = char(std::tolower(static_cast<unsigned char>(c))); return s; }

private:
    static int hexv(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }
    static std::vector<std::string> splitBar(const std::string& s) {
        std::vector<std::string> r; std::string cur;
        for (char c : s) { if (c == '|' && r.size() < 4) { r.push_back(cur); cur.clear(); } else cur.push_back(c); }
        r.push_back(cur); return r;
    }
    static std::vector<std::string> splitAnd(const std::string& s) {
        std::vector<std::string> r; std::size_t pos = 0;
        bool inq = false; std::string cur;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '"') inq = !inq;
            if (!inq && s[i] == '&' && i + 1 < s.size() && s[i+1] == '&') { r.push_back(cur); cur.clear(); ++i; }
            else cur.push_back(s[i]);
        }
        (void)pos; r.push_back(cur); return r;
    }
};

} // namespace av

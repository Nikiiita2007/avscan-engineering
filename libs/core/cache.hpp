#pragma once
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include "types.hpp"

namespace av {

// Ключ: путь + размер + время изменения + версия базы. Хранится в TSV.
class Cache {
public:
    explicit Cache(std::string path) : path_(std::move(path)) {
        std::ifstream in(path_);
        std::string line;
        while (std::getline(in, line)) {
            std::vector<std::string> f;
            std::stringstream ss(line);
            std::string x;
            while (std::getline(ss, x, '\t')) f.push_back(x);
            if (f.size() < 7) continue;
            Entry e;
            e.status = static_cast<Status>(std::stoi(f[1]));
            e.score = std::stoi(f[2]);
            e.sha256 = f[3]; e.fuzzy = f[4]; e.type = f[5]; e.names = f[6];
            map_[f[0]] = e;
        }
    }
    static std::string key(const std::string& path, std::uint64_t size, long long mtime, const std::string& dbver) {
        return path + "|" + std::to_string(size) + "|" + std::to_string(mtime) + "|" + dbver;
    }
    bool get(const std::string& k, ScanResult& r) const {
        auto it = map_.find(k);
        if (it == map_.end()) return false;
        r.status = it->second.status; r.score = it->second.score;
        r.sha256 = it->second.sha256; r.fuzzy = it->second.fuzzy;
        r.message = "из кэша (типы/детали не хранятся; --no-cache для полного отчёта); тип: " + it->second.type;
        if (!it->second.names.empty() && it->second.names != "-") {
            std::stringstream ss(it->second.names); std::string n;
            while (std::getline(ss, n, ',')) r.detections.push_back({"cached", n, "", true});
        }
        r.fromCache = true;
        return true;
    }
    void put(const std::string& k, const ScanResult& r) {
        Entry e{r.status, r.score, r.sha256, r.fuzzy, toString(r.type), ""};
        for (auto& d : r.detections) e.names += (e.names.empty() ? "" : ",") + d.name;
        if (e.names.empty()) e.names = "-";
        map_[k] = e; dirty_ = true;
    }
    void flush() {
        if (!dirty_) return;
        std::ofstream out(path_, std::ios::trunc);
        for (auto& [k, e] : map_)
            out << k << '\t' << int(e.status) << '\t' << e.score << '\t' << e.sha256 << '\t' << e.fuzzy << '\t' << e.type << '\t' << e.names << '\n';
        dirty_ = false;
    }
private:
    struct Entry { Status status; int score; std::string sha256, fuzzy, type, names; };
    std::string path_;
    std::unordered_map<std::string, Entry> map_;
    bool dirty_ = false;
};

} // namespace av

#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>
#include "sigdb.hpp"
#include "source.hpp"
#include "types.hpp"

namespace av {

struct Limits {
    std::uint64_t maxFileSize = 2ull << 30;        // 2 ГиБ
    int maxDepth = 3;                               // вложенность архивов
    std::uint64_t maxEntries = 10000;               // файлов в архиве (суммарно)
    std::uint64_t maxEntrySize = 256ull << 20;      // один распакованный файл
    std::uint64_t maxTotalUnpacked = 1ull << 30;    // всё распакованное за один скан
    double maxRatio = 1000.0;                       // распаковано / размер корневого файла
};

struct Config {
    Limits limits;
    int suspiciousThreshold = 40;
    int infectedThreshold = 150;
    bool useCache = true;
    std::string cachePath = ".avscan_cache.tsv";
};

// Общий бюджет распаковки на один корневой скан (защита от zip-бомб).
struct Budget {
    std::uint64_t unpacked = 0, entries = 0, rootSize = 0;
};

class Cache;

class Scanner {
public:
    Scanner(SigDb db, Config cfg);
    ~Scanner();
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
    Scanner(Scanner&&) = delete;
    Scanner& operator=(Scanner&&) = delete;
    ScanResult scanPath(const std::string& path);
    ScanResult scanMemory(std::span<const std::uint8_t> data, const std::string& name, int depth, Budget& b);
    const SigDb& db() const { return db_; }
    const Config& config() const { return cfg_; }
    void flushCache();

private:
    ScanResult scanSource(Source& src, const std::string& name, std::uint64_t size, int depth, Budget& b,
                          const std::string* realPath, std::span<const std::uint8_t> mem);
    void finalize(ScanResult& r);

    SigDb db_;
    Config cfg_;
    Cache* cache_ = nullptr;
};

// Реализуется в archive.cpp.
bool archiveSupportFor(FileType t);
void scanArchive(Scanner& sc, const std::string* path, std::span<const std::uint8_t> mem, FileType t,
                 ScanResult& parent, int depth, Budget& b);

Status worst(Status a, Status b);
FileType detectType(std::span<const std::uint8_t> head);
double entropyOf(const std::array<std::uint64_t, 256>& h, std::uint64_t total);

} // namespace av

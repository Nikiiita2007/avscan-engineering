#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "report.hpp"
#include "scanner.hpp"
#include "selftest.hpp"
#ifdef _WIN32
#include <windows.h>
#endif

using namespace av;
namespace fs = std::filesystem;

static void usage() {
    std::cout <<
R"(avscan — учебный антивирусный сканер (C++20)

Использование: avscan [опции] <файл|каталог>...

  --db FILE            база сигнатур (по умолчанию db/signatures.db рядом с exe или в текущем каталоге)
  -r, --recursive      сканировать каталоги рекурсивно
  -v, --verbose        подробный отчёт: каждый балл, за что получен/не получен
  --json               вывод в JSON
  --no-cache           не использовать кэш результатов
  --cache FILE         файл кэша (по умолчанию .avscan_cache.tsv)
  --max-size MB        лимит размера файла (по умолчанию 2048)
  --max-depth N        глубина вложенных архивов (по умолчанию 3)
  --max-unpacked MB    лимит суммарно распакованного (по умолчанию 1024)
  --max-entry MB       лимит одного распакованного файла (по умолчанию 256)
  --max-entries N      лимит файлов в архивах (по умолчанию 10000)
  --max-ratio N        лимит степени сжатия (по умолчанию 1000)
  --suspicious N       порог Suspicious (по умолчанию 40)
  --infected N         порог Infected по баллам (по умолчанию 150)
  --selftest           встроенные тесты ядра
  -h, --help           справка

Коды возврата: 0 — чисто, 1 — Infected, 2 — Suspicious, 3 — Error, 4 — ошибка аргументов.
)";
}

static std::string findDb(const char* argv0) {
    std::vector<fs::path> c{"db/signatures.db"};
    std::error_code ec;
    auto exe = fs::absolute(argv0, ec).parent_path();
    c.push_back(exe / "db/signatures.db");
    c.push_back(exe / "../db/signatures.db");
    for (auto& p : c) if (fs::exists(p, ec)) return p.string();
    return "db/signatures.db";
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    Config cfg;
    std::string dbPath, fuzzy;
    bool recursive = false, verbose = false, json = false, selftest = false;
    std::vector<std::string> targets;
    auto num = [&](int& i) -> long long {
        if (i + 1 >= argc) { std::cerr << "нужен аргумент после " << argv[i] << "\n"; std::exit(4); }
        try { return std::stoll(argv[++i]); } catch (...) { std::cerr << "ожидалось число: " << argv[i] << "\n"; std::exit(4); }
    };
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (a == "-r" || a == "--recursive") recursive = true;
        else if (a == "-v" || a == "--verbose") verbose = true;
        else if (a == "--json") json = true;
        else if (a == "--no-cache") cfg.useCache = false;
        else if (a == "--selftest") selftest = true;
        else if (a == "--db" && i + 1 < argc) dbPath = argv[++i];
        else if (a == "--cache" && i + 1 < argc) cfg.cachePath = argv[++i];
        else if (a == "--max-size") cfg.limits.maxFileSize = std::uint64_t(num(i)) << 20;
        else if (a == "--max-depth") cfg.limits.maxDepth = int(num(i));
        else if (a == "--max-unpacked") cfg.limits.maxTotalUnpacked = std::uint64_t(num(i)) << 20;
        else if (a == "--max-entry") cfg.limits.maxEntrySize = std::uint64_t(num(i)) << 20;
        else if (a == "--max-entries") cfg.limits.maxEntries = std::uint64_t(num(i));
        else if (a == "--max-ratio") cfg.limits.maxRatio = double(num(i));
        else if (a == "--suspicious") cfg.suspiciousThreshold = int(num(i));
        else if (a == "--infected") cfg.infectedThreshold = int(num(i));
        else if (!a.empty() && a[0] == '-') { std::cerr << "неизвестная опция: " << a << "\n"; usage(); return 4; }
        else targets.push_back(a);
    }
    if (selftest) return runSelfTest();
    if (targets.empty()) { usage(); return 4; }

    SigDb db;
    if (dbPath.empty()) dbPath = findDb(argv[0]);
    if (!db.load(dbPath)) { std::cerr << "ОШИБКА: " << db.warnings.back() << "\n"; return 3; }
    for (auto& w : db.warnings) std::cerr << "предупреждение: " << w << "\n";
    if (!json)
        std::cout << "База: " << dbPath << " (версия " << db.version << ", сигнатур " << db.sigs.size()
                  << ", хэшей " << db.sha256.size() << ", fuzzy " << db.fuzzy.size() << ")\n\n";

    Scanner sc(std::move(db), cfg);
    std::vector<std::string> files;
    std::vector<ScanResult> pre;
    for (auto& t : targets) {
        std::error_code ec;
        if (fs::is_directory(t, ec)) {
            if (!recursive) { ScanResult r; r.path = t; r.status = Status::Skipped; r.message = "каталог (используйте -r)"; pre.push_back(r); continue; }
            fs::recursive_directory_iterator it(t, fs::directory_options::skip_permission_denied, ec), end;
            if (ec) { ScanResult r; r.path = t; r.status = Status::Error; r.message = "не удалось открыть каталог: " + ec.message(); pre.push_back(r); continue; }
            for (; it != end; it.increment(ec)) {
                if (ec) { ScanResult r; r.path = t; r.status = Status::Error; r.message = "ошибка обхода: " + ec.message(); pre.push_back(r); break; }
                if (it->is_regular_file(ec) && !it->is_symlink(ec)) files.push_back(it->path().string());
            }
        } else files.push_back(t);
    }

    int counts[5] = {};
    Status overall = Status::Clean;
    bool first = true;
    if (json) std::cout << "[\n";
    auto emit = [&](const ScanResult& r) {
        ++counts[int(r.status)];
        overall = worst(overall, r.status);
        if (json) { if (!first) std::cout << ",\n"; printJson(std::cout, r); }
        else { printResult(std::cout, r, verbose); std::cout << "\n"; }
        first = false;
    };
    for (auto& r : pre) emit(r);
    for (auto& f : files) emit(sc.scanPath(f));
    sc.flushCache();
    if (json) std::cout << "\n]\n";
    else {
        std::cout << "=== Итого ===\n";
        for (Status s : {Status::Clean, Status::Infected, Status::Suspicious, Status::Error, Status::Skipped})
            std::cout << "  " << toString(s) << ": " << counts[int(s)] << "\n";
    }
    switch (overall) {
        case Status::Infected: return 1;
        case Status::Suspicious: return 2;
        case Status::Error: return 3;
        default: return 0;
    }
}

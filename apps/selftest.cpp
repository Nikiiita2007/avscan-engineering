#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "scanner.hpp"
#include "selftest.hpp"

namespace av {
namespace {
using Bytes = std::vector<std::uint8_t>;

Bytes bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

void put16(Bytes& b, std::size_t o, std::uint16_t v) { b[o] = v & 255; b[o+1] = v >> 8; }
void put32(Bytes& b, std::size_t o, std::uint32_t v) { for (int i = 0; i < 4; ++i) b[o+i] = (v >> (8*i)) & 255; }

// Искусственный «упакованный» PE: секции UPX0 (RWX, пустая) и UPX1 (случайные данные), EP в последней секции, нет импортов.
Bytes fakePackedPe() {
    Bytes b(0x400 + 0x2000, 0);
    b[0] = 'M'; b[1] = 'Z'; put32(b, 0x3C, 0x40);
    std::memcpy(&b[0x40], "PE\0\0", 4);
    put16(b, 0x44, 0x14c); put16(b, 0x46, 2); put16(b, 0x54, 224); put16(b, 0x56, 0x102);
    std::size_t opt = 0x58;
    put16(b, opt, 0x10B); put32(b, opt + 16, 0x11000); put32(b, opt + 92, 16);
    std::size_t sh = opt + 224;
    std::memcpy(&b[sh], "UPX0", 4); put32(b, sh + 8, 0x10000); put32(b, sh + 12, 0x1000); put32(b, sh + 36, 0xE0000080u);
    sh += 40;
    std::memcpy(&b[sh], "UPX1", 4); put32(b, sh + 8, 0x2000); put32(b, sh + 12, 0x11000);
    put32(b, sh + 16, 0x2000); put32(b, sh + 20, 0x400); put32(b, sh + 36, 0xE0000020u);
    std::uint32_t x = 12345;
    for (std::size_t i = 0x400; i < b.size(); ++i) { x = x * 1664525u + 1013904223u; b[i] = std::uint8_t(x >> 24); }
    return b;
}
} // namespace

int runSelfTest() {
    namespace fs = std::filesystem;
    auto tmp = (fs::temp_directory_path() / "avscan_selftest.db").string();
    {
        std::ofstream o(tmp);
        o << "version|selftest\n"
             "sig|T.Eicar|malware|any|\"X5O!P%@AP[4\\PZX54(P^)7CC)7}$\" && \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\"\n"
             "sig|T.JpegOnlyForPE|malware|pe|FF D8 FF E0\n"
             "sig|T.MzOnlyForElf|malware|elf|4D 5A 90 00\n"
             "sig|T.Wildcard|malware|any|41 56 ?? 45 53 54\n"
             "sig|T.Offset8|malware|any|@8:\"ABCD\"\n"
             "sig|T.Boundary|malware|any|\"BOUNDARYTEST\"\n";
    }
    SigDb db;
    db.load(tmp);
    fs::remove(tmp);
    Config cfg; cfg.useCache = false;
    Scanner sc(std::move(db), cfg);

    int fails = 0;
    auto check = [&](const char* name, const Bytes& data, Status want) {
        Budget b; b.rootSize = std::max<std::size_t>(data.size(), 1);
        auto r = sc.scanMemory(data, name, 0, b);
        bool ok = r.status == want;
        std::printf("  [%s] %-44s ожидалось %-10s получено %-10s баллы=%d\n", ok ? "OK" : "FAIL", name, toString(want), toString(r.status), r.score);
        if (!ok) ++fails;
    };
    std::string e1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$", e2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!";
    std::printf("Самопроверка ядра:\n");
    check("EICAR (2 условия)", bytes(e1 + e2 + "$H+H*"), Status::Infected);
    check("только половина EICAR (AND не выполнен)", bytes(e2), Status::Clean);
    check("JPEG-заголовок (сигнатура только для PE)", bytes(std::string("\xFF\xD8\xFF\xE0", 4) + std::string(100, 'x')), Status::Clean);
    check("голый MZ-заголовок (сигнатура только для ELF)", bytes(std::string("MZ\x90\x00\x03", 5) + std::string(100, 'x')), Status::Clean);
    check("битый ZIP (не подтвердить чистоту => Skipped)", bytes(std::string("PK\x03\x04", 4) + std::string(40, '\0')), Status::Skipped);
    check("маска ?? (AV?EST)", bytes("hello AVZEST world"), Status::Infected);
    check("смещение 8: совпало", bytes("01234567ABCD"), Status::Infected);
    check("смещение 8: сдвиг на 1 — не совпало", bytes("0123456ABCD"), Status::Clean);
    {
        Bytes d(65536 - 5, 'z'); auto t = bytes("BOUNDARYTEST"); d.insert(d.end(), t.begin(), t.end()); d.insert(d.end(), 100, 'z');
        check("сигнатура на границе блоков 64 КБ", d, Status::Infected);
    }
    check("искусственный упакованный PE (эвристика)", fakePackedPe(), Status::Suspicious);
    {
        auto r = sc.scanPath("/nonexistent/path/file.bin");
        bool ok = r.status == Status::Error;
        std::printf("  [%s] %-44s ожидалось %-10s получено %-10s\n", ok ? "OK" : "FAIL", "нечитаемый файл ≠ Clean", "Error", toString(r.status));
        if (!ok) ++fails;
    }
    std::printf(fails ? "РЕЗУЛЬТАТ: провалено %d\n" : "РЕЗУЛЬТАТ: все тесты пройдены\n", fails);
    return fails ? 1 : 0;
}

} // namespace av

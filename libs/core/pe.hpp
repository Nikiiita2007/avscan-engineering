#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "source.hpp"

namespace av {

struct PeSection {
    std::string name;
    std::uint32_t vsize = 0, vaddr = 0, rawsize = 0, rawptr = 0, chars = 0;
};

struct PeInfo {
    bool valid = false;
    std::string error;
    bool is64 = false;
    std::uint32_t entryRva = 0;
    int entrySection = -1; // -1: точка входа вне секций
    std::vector<PeSection> sections;
    std::vector<std::string> dlls, funcs;
    bool importsParsed = false;
};

namespace pe_detail {
inline std::uint32_t rd32(std::span<const std::uint8_t> d, std::size_t o, bool& ok) {
    if (o + 4 > d.size()) { ok = false; return 0; }
    return d[o] | (d[o+1] << 8) | (d[o+2] << 16) | (std::uint32_t(d[o+3]) << 24);
}
inline std::uint16_t rd16(std::span<const std::uint8_t> d, std::size_t o, bool& ok) {
    if (o + 2 > d.size()) { ok = false; return 0; }
    return std::uint16_t(d[o] | (d[o+1] << 8));
}
} // namespace pe_detail

inline std::optional<std::uint64_t> peRvaToOffset(const PeInfo& pe, std::uint32_t rva) {
    for (auto& s : pe.sections) {
        std::uint32_t span = std::max(s.vsize, s.rawsize);
        if (rva >= s.vaddr && rva - s.vaddr < span) return std::uint64_t(s.rawptr) + (rva - s.vaddr);
    }
    if (pe.sections.empty() || rva < pe.sections.front().vaddr) return rva; // область заголовков
    return std::nullopt;
}

// head — первый блок файла (уже прочитан сканером). Импорты читаются точечно через src.readAt.
inline PeInfo parsePe(Source& src, std::span<const std::uint8_t> head, std::uint64_t fileSize) {
    using namespace pe_detail;
    PeInfo pe;
    bool ok = true;
    if (head.size() < 0x40) { pe.error = "файл короче DOS-заголовка"; return pe; }
    std::uint32_t lfanew = rd32(head, 0x3C, ok);
    if (!ok || lfanew > head.size() || lfanew + 24 > head.size()) { pe.error = "e_lfanew вне первого блока"; return pe; }
    if (std::memcmp(head.data() + lfanew, "PE\0\0", 4) != 0) { pe.error = "нет сигнатуры PE"; return pe; }
    std::size_t coff = lfanew + 4;
    std::uint16_t nsec = rd16(head, coff + 2, ok);
    std::uint16_t optSize = rd16(head, coff + 16, ok);
    std::size_t opt = coff + 20;
    std::uint16_t magic = rd16(head, opt, ok);
    if (!ok || (magic != 0x10B && magic != 0x20B)) { pe.error = "неизвестный Optional Header"; return pe; }
    pe.is64 = (magic == 0x20B);
    pe.entryRva = rd32(head, opt + 16, ok);
    std::size_t ddOff = opt + (pe.is64 ? 112 : 96);
    std::uint32_t nrva = rd32(head, ddOff - 4, ok);
    if (nsec > 96) { pe.error = "слишком много секций"; return pe; }
    std::size_t st = opt + optSize;
    for (unsigned i = 0; i < nsec; ++i) {
        std::size_t o = st + i * 40;
        if (o + 40 > head.size()) { pe.error = "таблица секций вне первого блока"; return pe; }
        PeSection s;
        s.name.assign(reinterpret_cast<const char*>(head.data() + o), 8);
        s.name = s.name.substr(0, s.name.find('\0'));
        s.vsize = rd32(head, o + 8, ok); s.vaddr = rd32(head, o + 12, ok);
        s.rawsize = rd32(head, o + 16, ok); s.rawptr = rd32(head, o + 20, ok);
        s.chars = rd32(head, o + 36, ok);
        pe.sections.push_back(std::move(s));
    }
    if (!ok) { pe.error = "обрезанный заголовок"; return pe; }
    for (unsigned i = 0; i < pe.sections.size(); ++i) {
        auto& s = pe.sections[i];
        if (pe.entryRva >= s.vaddr && pe.entryRva - s.vaddr < std::max(s.vsize, s.rawsize)) { pe.entrySection = int(i); break; }
    }
    pe.valid = true;

    // --- импорты (точечные чтения, небольшой объём) ---
    if (nrva >= 2 && ddOff + 16 <= head.size()) {
        std::uint32_t impRva = rd32(head, ddOff + 8, ok);
        auto readBuf = [&](std::uint64_t off, std::size_t n) -> std::optional<std::vector<std::uint8_t>> {
            if (off > fileSize || n > fileSize - off) n = off < fileSize ? std::size_t(fileSize - off) : 0;
            if (n == 0) return std::nullopt;
            std::vector<std::uint8_t> b(n);
            if (!src.readAt(off, b.data(), n)) return std::nullopt;
            return b;
        };
        auto cstr = [&](std::uint32_t rva) -> std::string {
            auto o = peRvaToOffset(pe, rva);
            if (!o) return {};
            auto b = readBuf(*o, 256);
            if (!b) return {};
            std::string s;
            for (auto c : *b) { if (!c) break; s.push_back(char(c)); }
            return s;
        };
        if (impRva) {
            pe.importsParsed = true;
            if (auto base = peRvaToOffset(pe, impRva)) {
                for (unsigned i = 0; i < 256; ++i) {
                    auto d = readBuf(*base + i * 20, 20);
                    if (!d || d->size() < 20) break;
                    bool k = true;
                    std::span<const std::uint8_t> ds(*d);
                    std::uint32_t oft = rd32(ds, 0, k), nameRva = rd32(ds, 12, k), ft = rd32(ds, 16, k);
                    if (!oft && !nameRva && !ft) break;
                    pe.dlls.push_back(cstr(nameRva));
                    std::uint32_t thunk = oft ? oft : ft;
                    auto to = peRvaToOffset(pe, thunk);
                    if (!to) continue;
                    unsigned esz = pe.is64 ? 8 : 4;
                    for (unsigned j = 0; j < 2048 && pe.funcs.size() < 8192; ++j) {
                        auto t = readBuf(*to + j * esz, esz);
                        if (!t || t->size() < esz) break;
                        std::uint64_t v = 0;
                        for (unsigned b = 0; b < esz; ++b) v |= std::uint64_t((*t)[b]) << (8 * b);
                        if (!v) break;
                        bool ord = pe.is64 ? (v >> 63) & 1 : (v >> 31) & 1;
                        if (ord) pe.funcs.push_back("ord#" + std::to_string(v & 0xFFFF));
                        else pe.funcs.push_back(cstr(std::uint32_t(v & 0x7FFFFFFF) + 2));
                    }
                }
            }
        }
    }
    return pe;
}

} // namespace av

#include "report.hpp"

#include <cstdio>
#include <iomanip>
#include <ostream>

namespace av {
namespace {
std::string pad(int n) { return std::string(std::size_t(n), ' '); }

std::string jesc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o.push_back(char(c));
        }
    }
    return o;
}
} // namespace

void printResult(std::ostream& os, const ScanResult& r, bool verbose, int ind) {
    auto p = pad(ind);
    os << p << "Файл:    " << r.path << "\n";
    os << p << "Статус:  " << toString(r.status) << (r.fromCache ? "  (кэш)" : "") << "\n";
    if (!r.message.empty()) os << p << "Причина: " << r.message << "\n";
    if (r.status == Status::Error || r.status == Status::Skipped) {
        if (r.sha256.empty()) return;
    }
    os << p << "Размер:  " << r.size << " байт" << (r.fromCache ? std::string() : std::string(", тип: ") + toString(r.type)) << "\n";
    if (!r.sha256.empty()) os << p << "SHA-256: " << r.sha256 << "\n";
    if (!r.fuzzy.empty() && !r.fromCache) os << p << "Fuzzy:   " << r.fuzzy << "\n";
    if (!r.fromCache) { char b[32]; std::snprintf(b, sizeof b, "%.3f", r.entropy); os << p << "Энтропия файла: " << b << " / 8\n"; }
    os << p << "Баллы:   " << r.score << "\n";
    for (auto& d : r.detections)
        os << p << "  ! [" << d.kind << (d.malware ? ", malware" : ", suspicious") << "] " << d.name
           << (d.detail.empty() ? "" : "  — " + d.detail) << "\n";
    if (verbose) {
        if (!r.sections.empty()) {
            os << p << "Секции PE:\n";
            for (auto& s : r.sections) {
                char b[160];
                std::snprintf(b, sizeof b, "  %-10s raw=%-9u virt=%-9u flags=0x%08X entropy=%.2f", s.name.c_str(), s.rawsize, s.vsize, s.chars, s.entropy);
                os << p << b << "\n";
            }
        }
        if (!r.indicators.empty()) {
            os << p << "Подробный отчёт по баллам:\n";
            int skippedPe = 0;
            for (auto& i : r.indicators) {
                if (!i.applicable && i.id.rfind("PE_", 0) == 0 && r.type != FileType::PE) { ++skippedPe; continue; }
                char b[48];
                if (!i.applicable) std::snprintf(b, sizeof b, "[ n/a ]");
                else std::snprintf(b, sizeof b, "[+%2d/%2d]", i.points, i.maxPoints);
                os << p << "  " << b << " " << i.id << " — " << i.title << "\n";
                os << p << "           " << (i.applicable ? (i.points > 0 ? "ПОЛУЧЕНО: " : "НЕ ПОЛУЧЕНО: ") : "НЕПРИМЕНИМО: ") << i.explanation << "\n";
            }
            if (skippedPe) os << p << "  [ n/a ] PE_* (" << skippedPe << " проверок) — НЕПРИМЕНИМО: файл не является PE\n";
            os << p << "  Итого: " << r.score << " баллов (Suspicious ≥ --suspicious, Infected ≥ --infected; malware-сигнатура/хэш = Infected сразу)\n";
        }
    }
    for (auto& n : r.notes) os << p << "  · " << n << "\n";
    for (auto& c : r.children) { os << p << "  ── вложенный объект ──\n"; printResult(os, c, verbose, ind + 4); }
}

void printJson(std::ostream& os, const ScanResult& r, int ind) {
    auto p = pad(ind), q = pad(ind + 2);
    os << p << "{\n";
    os << q << "\"path\": \"" << jesc(r.path) << "\",\n";
    os << q << "\"status\": \"" << toString(r.status) << "\",\n";
    os << q << "\"message\": \"" << jesc(r.message) << "\",\n";
    os << q << "\"size\": " << r.size << ",\n";
    os << q << "\"type\": \"" << toString(r.type) << "\",\n";
    os << q << "\"sha256\": \"" << r.sha256 << "\",\n";
    os << q << "\"fuzzy\": \"" << jesc(r.fuzzy) << "\",\n";
    os << q << "\"entropy\": " << r.entropy << ",\n";
    os << q << "\"score\": " << r.score << ",\n";
    os << q << "\"from_cache\": " << (r.fromCache ? "true" : "false") << ",\n";
    os << q << "\"partial\": " << (r.partial ? "true" : "false") << ",\n";
    os << q << "\"detections\": [";
    for (std::size_t i = 0; i < r.detections.size(); ++i)
        os << (i ? ", " : "") << "{\"kind\": \"" << jesc(r.detections[i].kind) << "\", \"name\": \"" << jesc(r.detections[i].name)
           << "\", \"malware\": " << (r.detections[i].malware ? "true" : "false") << "}";
    os << "],\n" << q << "\"indicators\": [";
    for (std::size_t i = 0; i < r.indicators.size(); ++i) {
        auto& x = r.indicators[i];
        os << (i ? ", " : "") << "{\"id\": \"" << jesc(x.id) << "\", \"points\": " << x.points << ", \"max\": " << x.maxPoints
           << ", \"applicable\": " << (x.applicable ? "true" : "false") << ", \"explanation\": \"" << jesc(x.explanation) << "\"}";
    }
    os << "],\n" << q << "\"notes\": [";
    for (std::size_t i = 0; i < r.notes.size(); ++i) os << (i ? ", " : "") << "\"" << jesc(r.notes[i]) << "\"";
    os << "],\n" << q << "\"children\": [";
    if (!r.children.empty()) {
        os << "\n";
        for (std::size_t i = 0; i < r.children.size(); ++i) { printJson(os, r.children[i], ind + 4); os << (i + 1 < r.children.size() ? ",\n" : "\n"); }
        os << q;
    }
    os << "]\n" << p << "}";
}

} // namespace av

#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace av {

// Порядок важен: больший = «хуже». Ошибка чтения никогда не равна Clean.
enum class Status { Clean = 0, Skipped = 1, Error = 2, Suspicious = 3, Infected = 4 };

enum class FileType { Unknown, PE, ELF, Script, Zip, SevenZip, Rar, Jpeg };

inline const char* toString(Status s) {
    switch (s) {
        case Status::Clean: return "Clean";
        case Status::Infected: return "Infected";
        case Status::Suspicious: return "Suspicious";
        case Status::Error: return "Error";
        case Status::Skipped: return "Skipped";
    }
    return "?";
}
inline const char* toString(FileType t) {
    switch (t) {
        case FileType::PE: return "pe";
        case FileType::ELF: return "elf";
        case FileType::Script: return "script";
        case FileType::Zip: return "zip";
        case FileType::SevenZip: return "7z";
        case FileType::Rar: return "rar";
        case FileType::Jpeg: return "jpeg";
        default: return "unknown";
    }
}
inline bool isArchive(FileType t) {
    return t == FileType::Zip || t == FileType::SevenZip || t == FileType::Rar;
}

struct Detection {
    std::string kind;    // signature | hash | fuzzy
    std::string name;
    std::string detail;
    bool malware = true; // true => сразу Infected, false => только баллы
};

// Один пункт эвристики: всегда попадает в подробный отчёт, сработал он или нет.
struct Indicator {
    std::string id;
    std::string title;
    int maxPoints = 0;
    int points = 0;
    bool applicable = true;
    std::string explanation;
};

struct SectionInfo {
    std::string name;
    std::uint32_t vsize = 0, rawsize = 0, chars = 0;
    double entropy = 0;
};

struct ScanResult {
    std::string path;
    Status status = Status::Clean;
    std::string message;
    std::uint64_t size = 0;
    FileType type = FileType::Unknown;
    std::string sha256, fuzzy;
    double entropy = 0;
    int score = 0;
    bool fromCache = false;
    bool partial = false; // часть содержимого не проверена (лимиты, шифрование, нет поддержки)
    std::vector<Detection> detections;
    std::vector<Indicator> indicators;
    std::vector<SectionInfo> sections;
    std::vector<std::string> notes;
    std::vector<ScanResult> children;
};

} // namespace av

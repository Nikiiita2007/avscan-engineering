#pragma once
#include <cstdint>
#include <cstring>
#include <fstream>
#include "modern.hpp"
#include <span>
#include <stdexcept>
#include <string>

namespace av {

// Источник байтов: последовательное чтение + точечное чтение (для заголовков PE).
class Source {
public:
    virtual ~Source() = default;
    // Возвращает 0 на EOF. При ошибке ввода-вывода бросает std::runtime_error.
    virtual std::size_t read(std::uint8_t* dst, std::size_t n) = 0;
    virtual bool readAt(std::uint64_t off, std::uint8_t* dst, std::size_t n) = 0;
};

class FileSource final : public Source {
public:
    explicit FileSource(const std::string& path) : path_(path), in_(pathFromUtf8(path), std::ios::binary) {
        if (!in_) throw std::runtime_error("не удалось открыть файл");
    }
    std::size_t read(std::uint8_t* dst, std::size_t n) override {
        in_.read(reinterpret_cast<char*>(dst), std::streamsize(n));
        if (in_.bad()) throw std::runtime_error("ошибка чтения файла");
        return std::size_t(in_.gcount());
    }
    bool readAt(std::uint64_t off, std::uint8_t* dst, std::size_t n) override {
        if (!rnd_.is_open()) rnd_.open(pathFromUtf8(path_), std::ios::binary);
        if (!rnd_) return false;
        rnd_.clear();
        rnd_.seekg(std::streamoff(off));
        rnd_.read(reinterpret_cast<char*>(dst), std::streamsize(n));
        return std::size_t(rnd_.gcount()) == n;
    }
private:
    std::string path_;
    std::ifstream in_, rnd_;
};

class MemSource final : public Source {
public:
    explicit MemSource(std::span<const std::uint8_t> d) : d_(d) {}
    std::size_t read(std::uint8_t* dst, std::size_t n) override {
        std::size_t k = std::min(n, d_.size() - pos_);
        if (k) std::memcpy(dst, d_.data() + pos_, k);
        pos_ += k;
        return k;
    }
    bool readAt(std::uint64_t off, std::uint8_t* dst, std::size_t n) override {
        if (off > d_.size() || n > d_.size() - off) return false;
        if (n) std::memcpy(dst, d_.data() + off, n);
        return true;
    }
private:
    std::span<const std::uint8_t> d_;
    std::size_t pos_ = 0;
};

} // namespace av

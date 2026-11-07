#pragma once
// Нечёткий хэш в стиле ssdeep (spamsum / CTPH). Формат: "blocksize:sig1:sig2".
// Потоковый: update() вызывается блоками, размер файла нужен заранее.
#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace av {

class FuzzyHasher {
public:
    explicit FuzzyHasher(std::uint64_t totalSize) {
        bs_ = 3;
        while (bs_ * 64 < totalSize) bs_ *= 2;
    }
    void update(std::span<const std::uint8_t> d) {
        for (std::uint8_t c : d) {
            roll(c);
            s1_ = (s1_ * 0x01000193u) ^ c;
            s2_ = (s2_ * 0x01000193u) ^ c;
            const std::uint32_t r = rollSum();
            if (r % bs_ == bs_ - 1) {
                if (d1_.size() < 63) { d1_.push_back(b64(s1_)); s1_ = kInit; }
                if (r % (bs_ * 2) == bs_ * 2 - 1 && d2_.size() < 31) { d2_.push_back(b64(s2_)); s2_ = kInit; }
            }
        }
    }
    std::string digest() const {
        std::string a = d1_, b = d2_;
        if (rollSum() != 0) { a.push_back(b64(s1_)); b.push_back(b64(s2_)); }
        return std::to_string(bs_) + ":" + a + ":" + b;
    }

    static int compare(const std::string& x, const std::string& y) {
        auto px = split(x), py = split(y);
        if (!px.ok || !py.ok) return 0;
        if (px.bs == py.bs) return std::max(score(px.s1, py.s1), score(px.s2, py.s2));
        if (px.bs == py.bs * 2) return score(px.s1, py.s2);
        if (py.bs == px.bs * 2) return score(px.s2, py.s1);
        return 0;
    }

private:
    static constexpr std::uint32_t kInit = 0x28021967u;
    static char b64(std::uint32_t v) {
        static constexpr char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        return t[v & 63];
    }
    void roll(std::uint8_t c) {
        h2_ = h2_ - h1_ + 7u * c;
        h1_ = h1_ + c - win_[n_ % 7];
        win_[n_ % 7] = c;
        ++n_;
        h3_ = (h3_ << 5) ^ c;
    }
    std::uint32_t rollSum() const { return h1_ + h2_ + h3_; }

    struct Parts { bool ok = false; std::uint64_t bs = 0; std::string s1, s2; };
    static Parts split(const std::string& s) {
        Parts p;
        auto a = s.find(':');
        if (a == std::string::npos) return p;
        auto b = s.find(':', a + 1);
        if (b == std::string::npos) return p;
        try { p.bs = std::stoull(s.substr(0, a)); } catch (...) { return p; }
        p.s1 = s.substr(a + 1, b - a - 1);
        p.s2 = s.substr(b + 1);
        p.ok = p.bs > 0;
        return p;
    }
    static bool commonSub7(const std::string& a, const std::string& b) {
        if (a.size() < 7 || b.size() < 7) return false;
        for (std::size_t i = 0; i + 7 <= a.size(); ++i)
            if (b.find(a.substr(i, 7)) != std::string::npos) return true;
        return false;
    }
    static int score(const std::string& a, const std::string& b) {
        if (!commonSub7(a, b)) return 0;
        const std::size_t n = a.size(), m = b.size();
        std::vector<int> prev(m + 1), cur(m + 1);
        for (std::size_t j = 0; j <= m; ++j) prev[j] = int(j);
        for (std::size_t i = 1; i <= n; ++i) {
            cur[0] = int(i);
            for (std::size_t j = 1; j <= m; ++j) {
                int sub = prev[j-1] + (a[i-1] == b[j-1] ? 0 : 2);
                cur[j] = std::min({prev[j] + 1, cur[j-1] + 1, sub});
            }
            std::swap(prev, cur);
        }
        int dist = prev[m];
        int s = dist * 64 / int(n + m);
        s = 100 * s / 64;
        return std::clamp(100 - s, 0, 100);
    }

    std::uint64_t bs_;
    std::uint32_t s1_ = kInit, s2_ = kInit;
    std::uint32_t h1_ = 0, h2_ = 0, h3_ = 0, n_ = 0;
    std::uint8_t win_[7] = {};
    std::string d1_, d2_;
};

} // namespace av

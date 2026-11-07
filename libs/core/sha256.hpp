#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace av {

class Sha256 {
public:
    Sha256() { reset(); }
    void reset() {
        h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        total_ = 0;
        fill_ = 0;
    }
    void update(std::span<const std::uint8_t> d) {
        total_ += d.size();
        std::size_t i = 0;
        if (fill_ > 0) {
            while (i < d.size() && fill_ < 64) buf_[fill_++] = d[i++];
            if (fill_ == 64) { block(buf_.data()); fill_ = 0; }
        }
        for (; i + 64 <= d.size(); i += 64) block(d.data() + i);
        while (i < d.size()) buf_[fill_++] = d[i++];
    }
    std::string hexdigest() {
        std::uint64_t bits = total_ * 8;
        std::uint8_t pad[72] = {0x80};
        std::size_t padLen = (fill_ < 56) ? 56 - fill_ : 120 - fill_;
        std::uint8_t len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        std::uint64_t saved = total_;
        update({pad, padLen});
        update({len, 8});
        total_ = saved;
        static constexpr char hx[] = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (auto v : h_)
            for (int s = 28; s >= 0; s -= 4) out.push_back(hx[(v >> s) & 0xF]);
        return out;
    }

private:
    static constexpr std::array<std::uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

    void block(const std::uint8_t* p) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(p[4*i]) << 24) | (std::uint32_t(p[4*i+1]) << 16) |
                   (std::uint32_t(p[4*i+2]) << 8) | std::uint32_t(p[4*i+3]);
        for (int i = 16; i < 64; ++i) {
            auto s0 = std::rotr(w[i-15], 7) ^ std::rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            auto s1 = std::rotr(w[i-2], 17) ^ std::rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        auto [a,b,c,d,e,f,g,h] = h_;
        for (int i = 0; i < 64; ++i) {
            auto S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            auto ch = (e & f) ^ (~e & g);
            auto t1 = h + S1 + ch + K[i] + w[i];
            auto S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            auto mj = (a & b) ^ (a & c) ^ (b & c);
            auto t2 = S0 + mj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
    }

    std::array<std::uint32_t, 8> h_{};
    std::array<std::uint8_t, 64> buf_{};
    std::size_t fill_ = 0;
    std::uint64_t total_ = 0;
};

} // namespace av

#pragma once
#include <concepts>
#include <span>
#include <ranges>
#include <filesystem>
#include <string>
#include <cstdint>
namespace av {
inline std::filesystem::path pathFromUtf8(const std::string& s){
 std::u8string u;for(unsigned char c:s)u.push_back(static_cast<char8_t>(c));return std::filesystem::path(u);
}
inline std::string pathUtf8(const std::filesystem::path& p){auto u=p.u8string();return {u.begin(),u.end()};}
template<class R> concept ByteRange=std::ranges::contiguous_range<R> && std::ranges::sized_range<R> && std::same_as<std::ranges::range_value_t<R>,std::uint8_t>;
template<class H> concept StreamHasher=requires(H h,std::span<const std::uint8_t> b){h.update(b);};
template<StreamHasher H,ByteRange R> void feed(H& h,const R& r){h.update(std::span<const std::uint8_t>(std::ranges::data(r),std::ranges::size(r)));}
}

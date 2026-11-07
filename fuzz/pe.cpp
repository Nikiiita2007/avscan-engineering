#include "pe.hpp"
#include "scanner.hpp"
#include <algorithm>
#include <span>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* d,std::size_t n){
 std::span<const std::uint8_t> s(d,n);av::MemSource src(s);
 auto h=s.first(std::min(n,std::size_t(65536)));
 (void)av::detectType(h);(void)av::parsePe(src,h,n);return 0;
}

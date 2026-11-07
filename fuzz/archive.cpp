#include "scanner.hpp"
#include <algorithm>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* d,std::size_t n){
 static av::Scanner scanner([]{av::SigDb db;db.finalize();return db;}(),[]{
  av::Config c;c.useCache=false;c.limits.maxDepth=2;c.limits.maxEntrySize=1<<20;c.limits.maxTotalUnpacked=2<<20;c.limits.maxEntries=32;return c;}());
 av::Budget budget;budget.rootSize=std::max(n,std::size_t(1));
 (void)scanner.scanMemory({d,n},"fuzz",0,budget);return 0;
}

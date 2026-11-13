#pragma once
#include "engine.hpp"
#include <functional>
#include <stop_token>

namespace av {
struct MonitorOptions {
 std::vector<std::filesystem::path> roots,excludes,priority;
 std::filesystem::path db="db/signatures.db",quarantine="quarantine";
 unsigned threads=2,debounceMs=750,stableMs=1000;
 std::size_t queueLimit=50000;
 std::uint64_t maxSize=512ull<<20;
 bool etw=false;
 // Event response (not just detection): on an ETW process-start scan marked Infected,
 // terminate that process; optionally store an encrypted quarantine copy of the sample.
 // This is post-start termination, NOT pre-execution blocking (that needs a minifilter driver).
 bool blockExec=false,autoQuarantine=false;
 // Console output format: false = text (default), true = one JSON object per line (see events.hpp).
 bool jsonl=false;
};
using Log=std::function<void(const std::string&)>;
Result<int> monitor(const MonitorOptions&,std::stop_token,Log);
}

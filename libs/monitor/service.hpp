#pragma once
// Windows service wrapper for the monitor: auto-start "AVScanMonitor" (LocalSystem),
// arguments configured in HKLM\Software\AVScan\Monitor (REG_SZ "Args"),
// logging to %ProgramData%\AVScan\monitor.log.
#ifdef _WIN32
#include "monitor.hpp"

namespace av {
Result<void> installService(const std::wstring& serviceArgs); // create auto-start service
Result<void> removeService();                                  // delete service
Result<void> setServiceArgs(const std::wstring& args);         // write HKLM Args value
int runService();                                               // block in SCM dispatch loop
}
#endif

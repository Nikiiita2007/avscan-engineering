#pragma once
#ifdef _WIN32
#include "monitor.hpp"
#include <windows.h>
#include <memory>
namespace av {
class Etw {
 struct Impl;std::unique_ptr<Impl> p;
public:
 // submit(path, pid): pid != 0 marks a process-start event (executable image of that pid).
 Etw(std::function<void(std::filesystem::path,DWORD pid)> submit,Log log);
 ~Etw();bool start();void stop();
};
}
#endif

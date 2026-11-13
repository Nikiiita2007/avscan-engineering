#include "monitor.hpp"
#include <iostream>
#ifdef _WIN32
#include "monitor_cli.hpp"
#include "events.hpp"
#include "service.hpp"
#include "unique_handle.hpp"
#include <shlobj.h>

namespace {std::stop_source stop;
BOOL WINAPI control(DWORD c){if(c==CTRL_C_EVENT||c==CTRL_BREAK_EVENT){stop.request_stop();return TRUE;}return FALSE;}}
int wmain(int argc,wchar_t** argv){SetConsoleOutputCP(CP_UTF8);SetConsoleCtrlHandler(control,TRUE);
 try {
  // Service management commands (no console monitor run).
  for(int i=1;i<argc;++i){
   std::wstring a=argv[i];
   if(a==L"--service")return av::runService();
   if(a==L"--install-service"){std::wstring args;for(int j=i+1;j<argc;++j){if(!args.empty())args+=L' ';args+=argv[j];}
    auto r=av::installService(args);if(!r){std::cerr<<r.error().message<<'\n';return 3;}
    std::cout<<"service installed (auto start, LocalSystem). args: "<<av::pathUtf8(std::filesystem::path(args))<<'\n';return 0;}
   if(a==L"--remove-service"){auto r=av::removeService();if(!r){std::cerr<<r.error().message<<'\n';return 3;}
    std::cout<<"service removed\n";return 0;}
   if(a==L"--service-args"){if(i+1>=argc)throw std::runtime_error("--service-args requires a quoted string");
    auto r=av::setServiceArgs(argv[i+1]);if(!r){std::cerr<<r.error().message<<'\n';return 3;}
    std::cout<<"service args updated\n";return 0;}
  }
  av::MonitorOptions o;wchar_t temp[32768];DWORD n=GetTempPathW(32768,temp);if(n&&n<32768)o.priority.emplace_back(temp);
  PWSTR d=nullptr;if(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads,0,nullptr,&d))){o.priority.emplace_back(d);CoTaskMemFree(d);}
  if(!av::parseMonitorArgs(std::vector<std::wstring>(argv+1,argv+argc),o)){
   std::cout<<"avmonitor [--watch DIR] [--exclude DIR] [--priority DIR] [--quarantine DIR] [--db FILE] [--threads N]\n"
     "  [--etw] [--block-exec] [--auto-quarantine]   (console)\n"
     "  [--config FILE] [--events text|jsonl]          (config file; JSON Lines output)\n"
     "  --service                                      (run as Windows service, used by SCM)\n"
     "  --install-service [--watch ... --etw ...]      (admin: install auto-start service)\n"
     "  --remove-service                               (admin: remove service)\n"
     "  --service-args \"--watch D:\\In --etw\"           (admin: change service arguments)\n";
   return 0;}
  const bool jsonl=o.jsonl;
  auto r=av::monitor(o,stop.get_token(),[jsonl](const std::string& s){std::cout<<av::toEventLine(s,jsonl)<<std::endl;});if(!r){std::cerr<<r.error().message<<'\n';return 3;}return *r;
 }catch(std::exception& e){std::cerr<<e.what()<<'\n';return 4;}}
#else
int main(){std::cerr<<"avmonitor requires Windows\n";return 3;}
#endif

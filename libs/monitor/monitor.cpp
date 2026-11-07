#include "monitor.hpp"
#include "unique_handle.hpp"
#include "report.hpp"
#include "etw.hpp"
#include "quarantine.hpp"
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>
#include <cwctype>
#include <cstring>
namespace av {
#ifdef _WIN32
namespace {
namespace fs=std::filesystem;
using Clock=std::chrono::steady_clock;
fs::path norm(fs::path p){std::error_code ec;auto a=fs::absolute(p,ec);if(!ec)p=a;auto s=p.lexically_normal().wstring();for(auto& c:s)c=wchar_t(towlower(c));while(s.size()>3&&s.back()==L'\\')s.pop_back();return s;}
bool under(const fs::path& p,const fs::path& base){auto a=p.begin();for(auto b=base.begin();b!=base.end();++b,++a)if(a==p.end()||*a!=*b)return false;return true;}
struct Job{fs::path p;Clock::time_point due;uintmax_t size=0;fs::file_time_type time{};unsigned tries=0;int priority=0;bool sampled=false;DWORD pid=0;};
struct Watch{UniqueHandle dir;OVERLAPPED ov{};std::vector<DWORD> buf=std::vector<DWORD>(16384);fs::path root;bool pending=false;
 bool arm(){ov={};pending=ReadDirectoryChangesW(dir.get(),buf.data(),65536,TRUE,FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE,nullptr,&ov,nullptr)!=FALSE;return pending;}};
}
#endif
Result<int> monitor(const MonitorOptions& o,std::stop_token stop,Log log){
#ifndef _WIN32
 (void)o;(void)stop;(void)log;return failure("IOCP/ETW monitor requires Windows");
#else
 if(o.roots.empty()||!o.threads||o.threads>32||!o.queueLimit)return failure("Invalid monitor configuration");
 Config cfg;cfg.useCache=false;cfg.limits.maxFileSize=o.maxSize;
 auto probe=makeEngine(o.db,cfg);if(!probe)return failure(probe.error().message);
 std::mutex mu,out;std::condition_variable_any cv;std::map<fs::path,Job> jobs;std::set<fs::path> active;
 std::atomic<bool> rescan=true;
 auto emit=[&](const std::string& s){std::lock_guard l(out);log(s);};
 std::vector<fs::path> excludes=o.excludes;excludes.push_back(o.quarantine);for(auto& p:excludes)p=norm(p);
 auto excluded=[&](const fs::path& p){for(auto& x:excludes)if(under(p,x))return true;return false;};
 auto submit=[&](fs::path p,int pr,DWORD pid=0){p=norm(p);if(excluded(p)||stop.stop_requested())return;
  for(auto& x:o.priority)if(under(p,norm(x)))pr=std::max(pr,2);
  std::lock_guard l(mu);if(!jobs.contains(p)&&jobs.size()>=o.queueLimit){rescan=true;return;}
  auto it=jobs.find(p);if(it!=jobs.end()){pr=std::max(pr,it->second.priority);if(!pid)pid=it->second.pid;}
  jobs[p]=Job{p,Clock::now()+std::chrono::milliseconds(o.debounceMs),0,{},0,pr,false,pid};cv.notify_all();};
 UniqueHandle port(CreateIoCompletionPort(INVALID_HANDLE_VALUE,nullptr,0,1));if(!port)return failure("CreateIoCompletionPort failed");
 std::vector<std::unique_ptr<Watch>> watches;
 for(auto p:o.roots){auto w=std::make_unique<Watch>();w->root=norm(p);
  w->dir.reset(CreateFileW(w->root.c_str(),FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED,nullptr));
  if(!w->dir||!CreateIoCompletionPort(w->dir.get(),port.get(),reinterpret_cast<ULONG_PTR>(w.get()),0)||!w->arm()){emit("Error: watch unavailable "+pathUtf8(p));continue;}watches.push_back(std::move(w));}
 if(watches.empty())return failure("No active watch roots");
 // Scope guard keeps OVERLAPPED buffers alive until cancellation completions are drained, also on exceptions.
 struct Drain {
  HANDLE port;std::vector<std::unique_ptr<Watch>>& watches;
  ~Drain(){size_t count=0;for(auto& w:watches)if(w->pending){++count;CancelIoEx(w->dir.get(),&w->ov);}
   while(count){DWORD n;ULONG_PTR k;OVERLAPPED* ov=nullptr;GetQueuedCompletionStatus(port,&n,&k,&ov,INFINITE);
    if(ov){auto* w=reinterpret_cast<Watch*>(k);if(w->pending){w->pending=false;--count;}}}}
 } drain{port.get(),watches};
 std::vector<std::jthread> workers;
 for(unsigned i=0;i<o.threads;++i)workers.emplace_back([&](std::stop_token st){
  auto engine=makeEngine(o.db,cfg);if(!engine){emit("Error: worker DB");return;}
  while(!st.stop_requested()&&!stop.stop_requested()){
   Job j;
   {std::unique_lock l(mu);auto pick=[&](){auto best=jobs.end();for(auto it=jobs.begin();it!=jobs.end();++it)
      if(it->second.due<=Clock::now()&&!active.contains(it->first)&&(best==jobs.end()||it->second.priority>best->second.priority||(it->second.priority==best->second.priority&&it->second.due<best->second.due)))best=it;return best;};
    auto it=pick();if(it==jobs.end()){cv.wait_for(l,st,std::chrono::milliseconds(100),[&]{return stop.stop_requested();});continue;}
    j=it->second;active.insert(j.p);jobs.erase(it);}
   bool retry=false;std::error_code ec;auto attr=GetFileAttributesW(j.p.c_str());
   if(attr!=INVALID_FILE_ATTRIBUTES&&!(attr&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))){
    auto size=fs::file_size(j.p,ec);auto time=fs::last_write_time(j.p,ec);
    if(ec)retry=true;
    else if(size>o.maxSize)emit("Skipped size limit: "+pathUtf8(j.p));
    else if(!j.sampled||j.size!=size||j.time!=time){j.size=size;j.time=time;j.sampled=true;retry=true;}
    else {auto r=(*engine)->scanPath(pathUtf8(j.p));auto after=fs::file_size(j.p,ec);auto stamp=fs::last_write_time(j.p,ec);
     if(ec||after!=size||stamp!=time||r.status==Status::Error)retry=true;
     else {std::ostringstream s;printJson(s,r);emit(s.str());
      // Event response: ETW process-start detection -> terminate + optional quarantine.
      if(r.status==Status::Infected){
       if(o.blockExec&&j.pid){UniqueHandle h(OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,j.pid));
        if(h&&TerminateProcess(h.get(),1))emit("Blocked: terminated pid="+std::to_string(j.pid)+" image="+pathUtf8(j.p));
        else emit("Warning: could not terminate pid="+std::to_string(j.pid)+" (already exited or access denied)");}
       if(o.autoQuarantine){Quarantine q(o.quarantine);auto st=q.store(j.p);
        if(st)emit("Quarantined: record "+*st+" from "+pathUtf8(j.p));
        else emit("Warning: quarantine store failed: "+st.error().message);}
      }}}
   }else if(attr==INVALID_FILE_ATTRIBUTES&&GetLastError()!=ERROR_FILE_NOT_FOUND&&GetLastError()!=ERROR_PATH_NOT_FOUND)retry=true;
   {std::lock_guard l(mu);active.erase(j.p);if(retry&&!jobs.contains(j.p)&&!st.stop_requested()){
     if(++j.tries<=20){j.due=Clock::now()+std::chrono::milliseconds(o.stableMs);jobs.emplace(j.p,std::move(j));}
     else emit("Error unstable/unreadable: "+pathUtf8(j.p));}}cv.notify_all();
  }
 });
 std::jthread walker([&](std::stop_token st){while(!st.stop_requested()&&!stop.stop_requested()){
  if(rescan.exchange(false))for(auto& w:watches){std::error_code ec;fs::recursive_directory_iterator it(w->root,ec),end;
   if(ec)emit("Error enumerate: "+ec.message());
   while(it!=end&&!st.stop_requested()&&!stop.stop_requested()){
    auto p=it->path();DWORD attr=GetFileAttributesW(p.c_str());
    if(excluded(norm(p))||attr==INVALID_FILE_ATTRIBUTES||(attr&FILE_ATTRIBUTE_REPARSE_POINT))it.disable_recursion_pending();
    else if(!(attr&FILE_ATTRIBUTE_DIRECTORY))submit(p,-1);
    it.increment(ec);if(ec){emit("Error enumerate: "+ec.message());break;}}
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
 }});
 Etw etw([&](fs::path p,DWORD pid){submit(p,3,pid);},emit);if(o.etw&&!etw.start())emit("Error ETW unavailable; directory monitor continues");
 bool broken=false;
 while(!stop.stop_requested()&&!broken){DWORD n=0;ULONG_PTR key=0;OVERLAPPED* ov=nullptr;
  BOOL ok=GetQueuedCompletionStatus(port.get(),&n,&key,&ov,200);if(!ov)continue;
  auto& w=*reinterpret_cast<Watch*>(key);w.pending=false;
  if(!ok||!n){emit("Warning: directory events lost; full rescan scheduled");rescan=true;if(!w.arm())broken=true;continue;}
  std::vector<DWORD> copy((n+3)/4);std::memcpy(copy.data(),w.buf.data(),n);if(!w.arm())broken=true;
  size_t offset=0;while(offset+offsetof(FILE_NOTIFY_INFORMATION,FileName)<=n){
   auto* e=reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(reinterpret_cast<const char*>(copy.data())+offset);
   size_t h=offsetof(FILE_NOTIFY_INFORMATION,FileName);
   if(e->FileNameLength%2||e->FileNameLength>n-offset-h){rescan=true;break;}
   auto p=w.root/std::wstring(e->FileName,e->FileNameLength/2);
   if(e->Action==FILE_ACTION_ADDED||e->Action==FILE_ACTION_MODIFIED||e->Action==FILE_ACTION_RENAMED_NEW_NAME){auto a=GetFileAttributesW(p.c_str());if(a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_DIRECTORY))rescan=true;else submit(p,0);}
   if(!e->NextEntryOffset)break;
   if(e->NextEntryOffset<h||e->NextEntryOffset%4||e->NextEntryOffset>n-offset){rescan=true;break;}offset+=e->NextEntryOffset;
  }
 }
 etw.stop();walker.request_stop();walker.join();for(auto& t:workers)t.request_stop();cv.notify_all();workers.clear();
 return broken?Result<int>(failure("Watcher could not rearm")):Result<int>(0);
#endif
}
}

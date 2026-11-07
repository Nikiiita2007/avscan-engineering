#include "etw.hpp"
#ifdef _WIN32
#include "unique_handle.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <thread>
#include <cstring>
namespace av {
namespace {
const GUID systemGuid={0x9e814aad,0x3204,0x11d2,{0x9a,0x82,0,0x60,8,0xa8,0x69,0x39}};
const GUID procGuid={0x3d6fa8d0,0xfe05,0x11d0,{0x9d,0xda,0,0xc0,0x4f,0xd7,0xba,0x7c}};
const GUID imageGuid={0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0,0xa0,0xc9,0x11,0xf5,0x18}};
std::vector<BYTE> prop(EVENT_RECORD* e,const wchar_t* name){
 PROPERTY_DATA_DESCRIPTOR d{};d.PropertyName=reinterpret_cast<ULONGLONG>(name);d.ArrayIndex=ULONG(-1);
 ULONG n=0;if(TdhGetPropertySize(e,0,nullptr,1,&d,&n)||n>65536)return {};
 std::vector<BYTE> b(n);if(TdhGetProperty(e,0,nullptr,1,&d,n,b.data()))return {};return b;
}
std::filesystem::path resolve(std::wstring s){
 if(s.rfind(L"\\??\\",0)==0)s.erase(0,4);
 if(s.rfind(L"\\SystemRoot\\",0)==0){wchar_t buf[MAX_PATH];GetWindowsDirectoryW(buf,MAX_PATH);s=std::wstring(buf)+s.substr(11);}
 if(s.rfind(L"\\Device\\",0)==0)for(wchar_t c=L'A';c<=L'Z';++c){
  wchar_t drive[]={c,L':',0},buf[32768];if(QueryDosDeviceW(drive,buf,32768)){
   std::wstring d(buf);if(s.size()>d.size()&&s.compare(0,d.size(),d)==0&&s[d.size()]==L'\\')return std::wstring(drive)+s.substr(d.size());}}
 return s;
}
}
struct Etw::Impl {
 std::function<void(std::filesystem::path,DWORD)> submit;Log log;
 TRACEHANDLE session=0,consumer=INVALID_PROCESSTRACE_HANDLE;std::wstring name;
 std::vector<BYTE> storage;std::jthread worker;
 EVENT_TRACE_PROPERTIES* props(){return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(storage.data());}
 static void WINAPI event(EVENT_RECORD* e){auto* self=static_cast<Impl*>(e->UserContext);try{
  auto& g=e->EventHeader.ProviderId;auto op=e->EventHeader.EventDescriptor.Opcode;
  if(IsEqualGUID(g,procGuid)&&op==EVENT_TRACE_TYPE_START){
   DWORD pid=0;auto b=prop(e,L"ProcessId");if(b.size()>=4)std::memcpy(&pid,b.data(),4);
   self->log("ETW process-start pid="+std::to_string(pid));
   UniqueHandle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));
   wchar_t buf[32768];DWORD n=32768;if(h&&QueryFullProcessImageNameW(h.get(),0,buf,&n))self->submit(std::wstring(buf,n),pid);
   else self->log("ETW process path unavailable");
  }else if(IsEqualGUID(g,imageGuid)&&op==EVENT_TRACE_TYPE_LOAD){
   auto b=prop(e,L"FileName");std::wstring s;
   for(size_t i=0;i+1<b.size();i+=2){wchar_t c=wchar_t(b[i]|(unsigned(b[i+1])<<8));if(!c)break;s+=c;}
   auto p=resolve(s);if(p.is_absolute()){self->log("ETW image-load "+pathUtf8(p));self->submit(p,0);}
  }
 }catch(...){self->log("ETW callback error");}}
 static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* l){if(l->EventsLost)static_cast<Impl*>(l->Context)->log("Error: ETW events lost; historical process events cannot be recovered");return TRUE;}
};
Etw::Etw(std::function<void(std::filesystem::path,DWORD)> s,Log l):p(std::make_unique<Impl>()){p->submit=std::move(s);p->log=std::move(l);}
Etw::~Etw(){stop();}
bool Etw::start(){
 HANDLE raw=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&raw))return false;
 UniqueHandle token(raw);TOKEN_PRIVILEGES tp{};tp.PrivilegeCount=1;
 if(!LookupPrivilegeValueW(nullptr,SE_SYSTEM_PROFILE_NAME,&tp.Privileges[0].Luid))return false;
 tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(0);
 if(!AdjustTokenPrivileges(token.get(),FALSE,&tp,0,nullptr,nullptr)||GetLastError()!=ERROR_SUCCESS)return false;
 p->name=L"AVScan-"+std::to_wstring(GetCurrentProcessId());p->storage.resize(sizeof(EVENT_TRACE_PROPERTIES)+(p->name.size()+1)*2);
 auto* v=p->props();v->Wnode.BufferSize=ULONG(p->storage.size());v->Wnode.Guid=systemGuid;v->Wnode.Flags=WNODE_FLAG_TRACED_GUID;v->Wnode.ClientContext=1;
 v->LoggerNameOffset=sizeof(*v);v->LogFileMode=EVENT_TRACE_REAL_TIME_MODE|EVENT_TRACE_SYSTEM_LOGGER_MODE;
 v->EnableFlags=EVENT_TRACE_FLAG_PROCESS|EVENT_TRACE_FLAG_IMAGE_LOAD;v->BufferSize=64;v->MinimumBuffers=16;v->MaximumBuffers=128;v->FlushTimer=1;
 auto rc=StartTraceW(&p->session,p->name.c_str(),v);if(rc){p->session=0;p->log("StartTrace failed "+std::to_string(rc));return false;}
 EVENT_TRACE_LOGFILEW l{};l.LoggerName=p->name.data();l.Context=p.get();l.EventRecordCallback=Impl::event;l.BufferCallback=Impl::buffer;
 l.ProcessTraceMode=PROCESS_TRACE_MODE_REAL_TIME|PROCESS_TRACE_MODE_EVENT_RECORD;p->consumer=OpenTraceW(&l);
 if(p->consumer==INVALID_PROCESSTRACE_HANDLE){stop();return false;}
 auto h=p->consumer;p->worker=std::jthread([this,h](std::stop_token)mutable{auto rc=ProcessTrace(&h,1,nullptr,nullptr);if(rc&&rc!=ERROR_CANCELLED)p->log("ProcessTrace error "+std::to_string(rc));});return true;
}
void Etw::stop(){
 if(p->session){ControlTraceW(p->session,p->name.c_str(),p->props(),EVENT_TRACE_CONTROL_STOP);p->session=0;}
 if(p->consumer!=INVALID_PROCESSTRACE_HANDLE){CloseTrace(p->consumer);p->consumer=INVALID_PROCESSTRACE_HANDLE;}
 if(p->worker.joinable())p->worker.join();
}
}
#endif

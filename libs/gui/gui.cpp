#include "gui.hpp"
#include "engine.hpp"
#include "report.hpp"
#ifdef _WIN32
#include "unique_handle.hpp"
#include <commdlg.h>
#include <thread>
#include <sstream>
namespace av {
namespace {
struct State{std::jthread worker;HWND output=nullptr;};
std::wstring wide(const std::string& s){int n=MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),nullptr,0);std::wstring w(n,0);MultiByteToWideChar(CP_UTF8,0,s.data(),int(s.size()),w.data(),n);return w;}
LRESULT CALLBACK proc(HWND win,UINT msg,WPARAM wp,LPARAM lp){auto* s=reinterpret_cast<State*>(GetWindowLongPtrW(win,GWLP_USERDATA));
 if(msg==WM_CREATE){s=static_cast<State*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);SetWindowLongPtrW(win,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(s));
  CreateWindowW(L"BUTTON",L"Choose and scan file",WS_CHILD|WS_VISIBLE,10,10,200,32,win,reinterpret_cast<HMENU>(1),nullptr,nullptr);
  s->output=CreateWindowW(L"EDIT",L"",WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY,10,52,760,480,win,nullptr,nullptr,nullptr);return 0;}
 if(msg==WM_COMMAND&&LOWORD(wp)==1){
  if(s->worker.joinable())s->worker.join();wchar_t file[32768]{};OPENFILENAMEW o{};o.lStructSize=sizeof(o);o.hwndOwner=win;o.lpstrFile=file;o.nMaxFile=32768;o.Flags=OFN_FILEMUSTEXIST|OFN_NOCHANGEDIR;
  if(GetOpenFileNameW(&o)){EnableWindow(GetDlgItem(win,1),FALSE);SetWindowTextW(s->output,L"Scanning...");
   s->worker=std::jthread([win,p=std::filesystem::path(file)](std::stop_token st){
    Config c;c.useCache=false;auto engine=makeEngine("db/signatures.db",c);std::ostringstream out;
    if(!engine)out<<engine.error().message;else printResult(out,(*engine)->scanPath(pathUtf8(p)),true);
    auto text=std::make_unique<std::wstring>(wide(out.str()));if(!st.stop_requested()&&PostMessageW(win,WM_APP+1,0,reinterpret_cast<LPARAM>(text.get())))text.release();
   });}return 0;}
 if(msg==WM_APP+1){std::unique_ptr<std::wstring> text(reinterpret_cast<std::wstring*>(lp));SetWindowTextW(s->output,text->c_str());EnableWindow(GetDlgItem(win,1),TRUE);return 0;}
 if(msg==WM_CLOSE){if(s->worker.joinable()){s->worker.request_stop();s->worker.join();}MSG queued;while(PeekMessageW(&queued,win,WM_APP+1,WM_APP+1,PM_REMOVE))delete reinterpret_cast<std::wstring*>(queued.lParam);DestroyWindow(win);return 0;}
 if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(win,msg,wp,lp);
}
}
int runGui(){State state;WNDCLASSW c{};c.lpfnWndProc=proc;c.hInstance=GetModuleHandleW(nullptr);c.lpszClassName=L"AVScanEngineering";c.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&c);
 auto win=CreateWindowW(c.lpszClassName,L"AVScan — manual scanner",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,810,600,nullptr,nullptr,c.hInstance,&state);if(!win)return 3;
 ShowWindow(win,SW_SHOW);MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}return 0;}
}
#else
namespace av{int runGui(){return 3;}}
#endif

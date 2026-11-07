#pragma once
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <utility>
namespace av {
class UniqueHandle {
 HANDLE h=nullptr;
public:
 UniqueHandle()=default;explicit UniqueHandle(HANDLE v):h(v){}
 ~UniqueHandle(){reset();}
 UniqueHandle(const UniqueHandle&)=delete;UniqueHandle& operator=(const UniqueHandle&)=delete;
 UniqueHandle(UniqueHandle&& o)noexcept:h(o.release()){}
 UniqueHandle& operator=(UniqueHandle&& o)noexcept{if(this!=&o)reset(o.release());return *this;}
 HANDLE get()const noexcept{return h;}
 explicit operator bool()const noexcept{return h&&h!=INVALID_HANDLE_VALUE;}
 HANDLE release()noexcept{return std::exchange(h,nullptr);}
 void reset(HANDLE v=nullptr)noexcept{if(*this)CloseHandle(h);h=v;}
};
}
#endif

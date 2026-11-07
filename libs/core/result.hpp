#pragma once
#include <string>
#include <utility>
#ifdef AV_USE_TL_EXPECTED
#include <tl/expected.hpp>
#else
#include <variant>
#endif
namespace av {
struct Failure { std::string message; };
#ifdef AV_USE_TL_EXPECTED
template<class T> using Result=tl::expected<T,Failure>;
inline auto failure(std::string s){return tl::make_unexpected(Failure{std::move(s)});}
#else
// Offline-only fallback, explicitly NOT tl::expected. Full vcpkg build uses real tl::expected.
struct Unexpected {Failure value;};
inline Unexpected failure(std::string s){return {{std::move(s)}};}
template<class T> class Result {
 std::variant<T,Failure> v;
public:
 Result(T t):v(std::in_place_index<0>,std::move(t)){}
 Result(Unexpected e):v(std::in_place_index<1>,std::move(e.value)){}
 explicit operator bool()const{return v.index()==0;}
 T& operator*(){return std::get<0>(v);} const T& operator*()const{return std::get<0>(v);}
 T* operator->(){return &std::get<0>(v);}
 const Failure& error()const{return std::get<1>(v);}
};
template<> class Result<void> {
 std::variant<std::monostate,Failure> v;
public:
 Result():v(std::in_place_index<0>){}
 Result(Unexpected e):v(std::in_place_index<1>,std::move(e.value)){}
 explicit operator bool()const{return v.index()==0;}
 const Failure& error()const{return std::get<1>(v);}
};
#endif
}

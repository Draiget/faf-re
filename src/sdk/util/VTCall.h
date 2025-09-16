#pragma once
#include <cstdint>
#include <type_traits>

// NOTE: This helper never relies on the compiler-generated vtable layout.
// We index into the real vtable of the game object and cast to a __thiscall fn pointer.

template<class T>
static inline void** GetVTable(T* p) {
    return *reinterpret_cast<void***>(p);
}

template<int Slot, class Fn, class T, class... Args>
static inline auto VCall(T* p, Args... args)
-> typename std::invoke_result<Fn, T*, Args...>::type
{
    // Make sure Fn is a __thiscall pointer
#if defined(_MSC_VER) && !defined(_M_X64)
    // nothing: MSVC x86 supports __thiscall
#else
    static_assert(false, "__thiscall required and only meaningful on MSVC x86");
#endif
    auto raw = GetVTable(p)[Slot];
    auto f = reinterpret_cast<Fn>(raw);
    return f(p, std::forward<Args>(args)...);
}

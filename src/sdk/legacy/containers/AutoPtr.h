#pragma once

// Minimal MSVC8-era auto_ptr clone.
// - Copying transfers ownership.
// - Single pointer data member (4 bytes on x86).
// - No array support; intended for single objects only.

namespace msvc8
{
    template<class T>
    struct auto_ptr_ref
    {
        T* ptr;
        explicit auto_ptr_ref(T* p) : ptr(p) {}
    };

    template<class T>
    class auto_ptr
    {
    public:
        typedef T element_type;

        // constructors
        /**
         * Address: 0x00875210 (FUN_00875210) - `auto_ptr<Moho::CMovieManager>`,
         * the movie manager's static (moho/misc/StartupHelpers.cpp) with
         * `this` folded to 0x010C4AF0: stores the null default and returns
         * `this`. A linker-retained copy; the static itself is zero-initialised.
         * Address: 0x008CB410 (FUN_008CB410) - `auto_ptr<Moho::CUserPrefs>`
         * (StartupHelpers.cpp), `this` in EAX and `p` in ECX: `mov [eax], ecx`.
         * A linker-retained copy; `USER_LoadPreferences` inlines it.
         */
        explicit auto_ptr(T* p = 0) : px_(p) {}

        auto_ptr(auto_ptr& r) : px_(r.release()) {}

        template<class U>
        auto_ptr(auto_ptr<U>& r) : px_(r.release()) {}

        auto_ptr(auto_ptr_ref<T> r) : px_(r.ptr) {}

        template<class U>
        auto_ptr(auto_ptr_ref<U> r) : px_(static_cast<T*>(r.ptr)) {}

        // destructor
        /**
         * Address: 0x00C07B40 (FUN_00C07B40) - `auto_ptr<Moho::CMovieManager>`,
         * the movie manager static's `atexit` destructor (0x00BE6C80 registers
         * it): `if (p) delete p;` through the manager's scalar deleting
         * destructor 0x00875290.
         * Address: 0x00C08890 (FUN_00C08890) - `auto_ptr<Moho::IUserPrefs>`,
         * the preferences static's `atexit` destructor (0x00BE8B40 registers
         * it): `if (p) delete p;` through vtable slot 0 with flag 1.
         * Address: 0x008CB450 (FUN_008CB450) - `auto_ptr<Moho::CUserPrefs>`,
         * `this` in EAX: `USER_LoadPreferences`' local, reached from its EH
         * unwind funclet (`jmp` at 0x00BBE524).
         */
        ~auto_ptr() { delete px_; }

        auto_ptr& operator=(T* p)
        {
            reset(p);
            return *this;
        }

        // assignments
        auto_ptr& operator=(auto_ptr& r)
        {
            if (this != &r)
                reset(r.release());
            return *this;
        }

        /**
         * Address: 0x008CB420 (FUN_008CB420) - `auto_ptr<Moho::IUserPrefs>` =
         * `auto_ptr<Moho::CUserPrefs>&` for the preferences static, `this`
         * folded, `r` in EAX: `r.px` taken and cleared, then `reset`.
         * `USER_LoadPreferences` (0x008C90D1) carries it inline.
         */
        template<class U>
        auto_ptr& operator=(auto_ptr<U>& r)
        {
            reset(r.release());
            return *this;
        }

        auto_ptr& operator=(auto_ptr_ref<T> r)
        {
            reset(r.ptr);
            return *this;
        }

        template<class U>
        auto_ptr& operator=(auto_ptr_ref<U> r)
        {
            reset(static_cast<T*>(r.ptr));
            return *this;
        }

        // observers
        T& operator*() const { return *px_; }
        T* operator->() const { return px_; }

        /**
         * Address: 0x00875230 (FUN_00875230)
         * Address: 0x00875240 (FUN_00875240)
         * Address: 0x008752E0 (FUN_008752E0)
         *
         * `auto_ptr<Moho::CMovieManager>`'s `get`, `operator->` and
         * `operator*` for the movie manager static, `this` folded: each is
         * `mov eax, [0x010C4AF0]; ret`, so which address is which of the three
         * cannot be told apart. Linker-retained copies; every caller inlines.
         * Address: 0x008CB470 (FUN_008CB470) - the same for the preferences
         * static `auto_ptr<Moho::IUserPrefs>` (`mov eax, [0x010C6258]; ret`).
         * Address: 0x008CB460 (FUN_008CB460) - `auto_ptr<Moho::CUserPrefs>`,
         * `this` in EAX: `mov eax, [eax]; ret`.
         */
        T* get() const { return px_; }

        // modifiers
        T* release()
        {
            T* p = px_;
            px_ = 0;
            return p;
        }

        /**
         * Address: 0x00875250 (FUN_00875250) - `auto_ptr<Moho::CMovieManager>`
         * for the movie manager static: `if (p != px && px) delete px;` then
         * the store. `SetupBasicMovieManager` (0x00874C20) and
         * `DestroyMovieManagerSingleton` (0x00874CA0) carry it inline.
         *
         * VC8's shape: the old object is destroyed before the new pointer is
         * stored, and the store is unconditional.
         * Address: 0x008CB480 (FUN_008CB480) - `auto_ptr<Moho::IUserPrefs>` for
         * the preferences static, `p` in ESI; `USER_GetPreferences` (0x008C916B)
         * carries it inline.
         */
        void reset(T* p = 0)
        {
            if (p != px_)
                delete px_;
            px_ = p;
        }

        void swap(auto_ptr& other)
        {
            T* tmp = px_;
            px_ = other.px_;
            other.px_ = tmp;
        }

        // proxy conversion enables: ap = auto_ptr<Derived>(new Derived);
        operator auto_ptr_ref<T>() { return auto_ptr_ref<T>(release()); }

        template<class U>
        operator auto_ptr_ref<U>() { return auto_ptr_ref<U>(release()); }

        // logical tests
        bool operator!() const { return px_ == 0; }

#if defined(__cpp_explicit_bool) || (defined(_MSC_VER) && _MSC_VER >= 1600) || (__cplusplus >= 201103L)
        explicit operator bool() const { return px_ != 0; }
#endif

        // equality with another auto_ptr
        bool operator==(const auto_ptr& r) const { return get() == r.get(); }
        bool operator!=(const auto_ptr& r) const { return get() != r.get(); }

        // equality with raw pointer (enables: ap == nullptr / ap != nullptr)
        bool operator==(const T* p) const { return get() == p; }
        bool operator!=(const T* p) const { return get() != p; }

    private:
        T* px_;
    };

    // free swap
    template<class T>
    inline void swap(auto_ptr<T>& a, auto_ptr<T>& b) { a.swap(b); }

    template<class T>
    inline bool operator==(const T* p, const auto_ptr<T>& a) { return p == a.get(); }

    template<class T>
    inline bool operator!=(const T* p, const auto_ptr<T>& a) { return p != a.get(); }

    // nullptr_t symmetric overloads (for C++11+ toolchains)
#if (defined(_MSC_VER) && _MSC_VER >= 1600) || (__cplusplus >= 201103L)
    template<class T>
    inline bool operator==(std::nullptr_t, const auto_ptr<T>& a) { return a.get() == nullptr; }

    template<class T>
    inline bool operator!=(std::nullptr_t, const auto_ptr<T>& a) { return a.get() != nullptr; }

    template<class T>
    inline bool operator==(const auto_ptr<T>& a, std::nullptr_t) { return a.get() == nullptr; }

    template<class T>
    inline bool operator!=(const auto_ptr<T>& a, std::nullptr_t) { return a.get() != nullptr; }
#endif

} // namespace msvc8

// Size check for 32-bit builds (x86). Will intentionally fail on x64.
#if defined(_M_IX86) || defined(__i386__)
typedef char msvc8_auto_ptr_size_check[(sizeof(msvc8::auto_ptr<int>) == 4) ? 1 : -1];
#endif

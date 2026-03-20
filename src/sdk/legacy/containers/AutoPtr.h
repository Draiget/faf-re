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
        explicit auto_ptr(T* p = 0) : px_(p) {}

        auto_ptr(auto_ptr& r) : px_(r.release()) {}

        template<class U>
        auto_ptr(auto_ptr<U>& r) : px_(r.release()) {}

        auto_ptr(auto_ptr_ref<T> r) : px_(r.ptr) {}

        template<class U>
        auto_ptr(auto_ptr_ref<U> r) : px_(static_cast<T*>(r.ptr)) {}

        // destructor
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
        T* get() const { return px_; }

        // modifiers
        T* release()
        {
            T* p = px_;
            px_ = 0;
            return p;
        }

        void reset(T* p = 0)
        {
            if (px_ != p) {
                delete px_;
                px_ = p;
            }
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

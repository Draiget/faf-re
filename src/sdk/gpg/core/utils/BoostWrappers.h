#pragma once
#include <type_traits>
#include <utility>
#include <cstdint>
#include <typeinfo>

#include "boost/shared_ptr.h"

namespace boost
{
	namespace detail
	{
		// Old-Boost style: use std::type_info and compare via operator==
        using sp_typeinfo = std::type_info;

        // Consistent comparison helper (keeps call sites simple)
        inline bool sp_typeinfo_equal(sp_typeinfo const& a,
            sp_typeinfo const& b) noexcept
        {
            return a == b;
        }

#ifndef BOOST_SP_TYPEID
        // Mirror BOOST_SP_TYPEID from Boost: wraps typeid(T)
#define BOOST_SP_TYPEID(T) typeid(T)
#endif
	}

    // Raw layout of boost::shared_ptr<T> used by VC8-era Boost on x86:
	// two pointers: px (T*), pi (control block*). We never mutate refcounts.
    template <class T>
    struct SharedPtrRaw {
        T* px;  // pointer to T
        detail::sp_counted_base* pi;  // boost::detail::sp_counted_base*

        /**
         * Construct empty raw shared_ptr (nullptr/null control block)
         */
        SharedPtrRaw() noexcept : px(nullptr), pi(nullptr) {}

        /**
         * Construct raw shared_ptr from pointer only (no control block).
         * Useful for borrowing; no ownership semantics.
         */
        explicit SharedPtrRaw(T* p) noexcept : px(p), pi(nullptr) {}

        /**
         * Construct raw shared_ptr with a custom deleter, e.g.:
         *     SharedPtrRaw<char> r(buf, &free);
         * This allocates a VC8-like control block that will call the deleter.
         */
        template <class Deleter>
        SharedPtrRaw(T* p, Deleter d)
            : px(p)
            , pi(nullptr)
        {
            if (!p) {
                // Mirror common shared_ptr semantics: empty pointer => no control block.
                // (Old Boost could allocate it anyway; we choose lean behavior.)
                return;
            }

            // Local control block that mimics Boost's sp_counted_impl_pd<T,D> shape:
            struct ControlBlock final : boost::detail::sp_counted_base {
                T* p_;
                Deleter d_;
                ControlBlock(T* p_, Deleter d_) noexcept
                    : p_(p_), d_(std::move(d_)) {
                }

                // Called when use_count_ drops to zero
                void dispose() noexcept override {
                    // Call user-supplied deleter with the stored pointer
                    d_(p_);
                }

                // Called when weak_count_ drops to zero after dispose
                void destroy() noexcept override {
                    delete this;
                }

                // Expose deleter by type; compatible with Boost's ABI expectations
                void* get_deleter(detail::sp_typeinfo const& ti) noexcept override {
                    // Compare requested type with our stored deleter type
                    return detail::sp_typeinfo_equal(ti, BOOST_SP_TYPEID(Deleter)) ? &d_ : nullptr;
                }
            };

            // sp_counted_base ctor sets use_count_=1, weak_count_=1 (old-Boost behavior).
            // That matches a just-constructed shared_ptr owning one strong ref.
            pi = new ControlBlock(p, std::move(d));
        }

        /**
         * Helper factory that deduces T from pointer and deleter.
         * Usage: auto r = SharedPtrRaw<char>::with_deleter(buf, &free);
         */
        template <class Deleter>
        static SharedPtrRaw with_deleter(T* p, Deleter d) {
            return SharedPtrRaw(p, std::move(d));
        }
    };

    // Detection: is T iterable (has member begin()/end())?
    template <class U, class = void>
    struct is_iterable : std::false_type {};
    template <class U>
    struct is_iterable<U, std::void_t<
        decltype(std::declval<U&>().begin()),
        decltype(std::declval<U&>().end())
        >> : std::true_type {};

    // BorrowedSharedPtr<T> is a non-owning, read-only view over a raw Boost shared_ptr layout.
    // It does NOT change reference counts. Safe to pass by value (just copies the two pointers).
    template <class T>
    class BorrowedSharedPtr {
    public:
        using element_type = T;

        // ctors
        BorrowedSharedPtr() noexcept : px_(nullptr), pi_(nullptr) {}
        BorrowedSharedPtr(T* px, void* pi) noexcept : px_(px), pi_(pi) {}
        explicit BorrowedSharedPtr(const SharedPtrRaw<T>& raw) noexcept : px_(raw.px), pi_(raw.pi) {}

        // pointer interface
        T* get()       noexcept { return px_; }
        const T* get() const noexcept { return px_; }
        T& operator*() { return *px_; }
        const T& operator*()  const { return *px_; }
        T* operator->() { return px_; }
        const T* operator->() const { return px_; }
        explicit operator bool() const noexcept { return px_ != nullptr; }

        // raw accessors (debug/interop)
        T* px_raw() const noexcept { return px_; }
        void* pi_raw() const noexcept { return pi_; }

        // reset view (does not touch refcounts)
        void reset() noexcept { px_ = nullptr; pi_ = nullptr; }

        // Iteration passthrough if T is iterable: enables range-for over the wrapper.
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto begin() { return px_->begin(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto end() { return px_->end(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto begin()  const { return px_->begin(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto end()    const { return px_->end(); }

    private:
        T* px_;
        void* pi_;
    };
}

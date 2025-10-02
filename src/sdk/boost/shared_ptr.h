#pragma once
#include <cstddef>
#include <utility>
#include <typeinfo>
#include <exception>

#include "platform/Platform.h"

namespace boost {

    template<class T> class shared_ptr;                 // forward for prototypes below
    template<class T> class enable_shared_from_this;    // forward (no include!)

    namespace detail {

        // Two overloads selected when Y derives from enable_shared_from_this<Y>.
        template<class X, class Y>
        void sp_enable_shared_from_this(shared_ptr<X> const* /*ppx*/, Y* /*p*/, enable_shared_from_this<Y>* /*pe*/);

        template<class X, class Y>
        void sp_enable_shared_from_this(shared_ptr<X> const* /*ppx*/, Y* /*p*/, enable_shared_from_this<Y> const* /*pe*/);

        // Fallback when Y does not derive from enable_shared_from_this<Y>.
        inline void sp_enable_shared_from_this(...) { /* no-op */ }

    }
}

namespace boost
{

    template<class T> class shared_ptr;
    template<class T> class weak_ptr;

    namespace detail
    {
        /** Non-throwing lock tag (as in early Boost). */
        struct sp_nothrow_tag {};

        /** Alias for old Boost's sp_typeinfo. */
        using sp_typeinfo = std::type_info;

        /** Interlocked counter primitive, 32-bit, compatible with MSVC8 era. */
        class atomic_long
        {
        public:
            atomic_long() noexcept : v_(0) {}
            explicit atomic_long(long v) noexcept : v_(v) {}

            long load() const noexcept
            {
#if defined(_WIN32)
                return v_;
#else
                return v_.load();
#endif
            }

            long increment() noexcept
            {
#if defined(_WIN32)
                return InterlockedIncrement(&v_);
#else
                return ++v_;
#endif
            }

            long decrement() noexcept
            {
#if defined(_WIN32)
                return InterlockedDecrement(&v_);
#else
                return --v_;
#endif
            }

            /** CAS: if (*this == expected) *this = desired; returns previous value. */
            long compare_exchange(long expected, long desired) noexcept
            {
#if defined(_WIN32)
                return InterlockedCompareExchange(&v_, desired, expected);
#else
                v_.compare_exchange_strong(expected, desired);
                return expected; // return old
#endif
            }

        private:
#if defined(_WIN32)
            long v_;
#else
            std::atomic<long> v_;
#endif
        };

        /**
         * Reference-count control block interface (subset of Boost 1.33/1.34).
         * Layout: two 32-bit counters (use_ and weak_), plus vptr.
         */
        class sp_counted_base
        {
        public:
            sp_counted_base() noexcept
                : use_count_(1)     // one shared owner on creation
                , weak_count_(1)    // and one weak ref held by the control block itself
            {
            }

            virtual ~sp_counted_base() {}

            /** Destroy the managed object (but not the control block). */
            virtual void dispose() noexcept = 0;

            /** Destroy this control block. */
            virtual void destroy() noexcept
            {
                delete this;
            }

            /** Optional deleter query (type-erased). Default: not present. */
            virtual void* get_deleter(detail::sp_typeinfo const&) noexcept
            {
                return nullptr;
            }

            /** Shared: add one reference (copy). */
            void add_ref_copy() noexcept
            {
                use_count_.increment();
            }

            /**
             * Shared: try to add one reference only if use_count_ > 0.
             * Returns true on success.
             */
            bool add_ref_lock() noexcept
            {
                for (;;)
                {
                    long c = use_count_.load();
                    if (c == 0) return false;
                    if (use_count_.compare_exchange(c, c + 1) == c) return true;
                }
            }

            /** Shared: release one reference; dispose when reaching zero; then release weak ref. */
            void release() noexcept
            {
                if (use_count_.decrement() == 0)
                {
                    dispose();       // delete managed object
                    weak_release();  // drop control block's implicit weak ref from shared side
                }
            }

            /** Weak: add one weak reference. */
            void weak_add_ref() noexcept
            {
                weak_count_.increment();
            }

            /** Weak: release one; destroy control block when reaching zero. */
            void weak_release() noexcept
            {
                if (weak_count_.decrement() == 0)
                {
                    destroy();
                }
            }

            /** Current number of shared owners. */
            long use_count() const noexcept
            {
                return use_count_.load();
            }

        private:
            atomic_long use_count_;
            atomic_long weak_count_;

            // non-copyable
            sp_counted_base(sp_counted_base const&) = delete;
            sp_counted_base& operator=(sp_counted_base const&) = delete;
        };

        /** Default deleter (single object). */
        template<class T>
        struct default_delete
        {
            void operator()(T* p) const noexcept { delete p; }
        };

        /**
         * Control block for pointer + default deletion.
         */
        template<class P>
        class sp_counted_impl_p final : public sp_counted_base
        {
        public:
            explicit sp_counted_impl_p(P p) noexcept : p_(p) {}

            /** Destroy managed object via delete. */
            void dispose() noexcept override
            {
                default_delete<typename std::remove_pointer<P>::type>()(p_);
            }

            void* get_deleter(detail::sp_typeinfo const&) noexcept override
            {
                return nullptr;
            }

        private:
            P p_;
        };

        /**
         * Control block for pointer + custom deleter.
         */
        template<class P, class D>
        class sp_counted_impl_pd final : public sp_counted_base
        {
        public:
            sp_counted_impl_pd(P p, D d) noexcept
                : p_(p), d_(std::move(d))
            {
            }

            void dispose() noexcept override
            {
                d_(p_);
            }

            void* get_deleter(detail::sp_typeinfo const& ti) noexcept override
            {
                // Compare type_info addresses to avoid operator== issues
                return (&ti == &typeid(D)) ? static_cast<void*>(&d_) : nullptr;
            }

        private:
            P p_;
            D d_;
        };

        /**
         * Weak-count holder matching Boost's detail::weak_count semantics.
         * Provides a "from_shared" helper to take weak_add_ref() on construction from a shared control block.
         */
        class weak_count
        {
        public:
            weak_count() noexcept : pi_(nullptr) {}

            explicit weak_count(sp_counted_base* p) noexcept : pi_(p) {}

            static weak_count from_shared(sp_counted_base* p) noexcept
            {
                weak_count w;
                w.pi_ = p;
                if (w.pi_) w.pi_->weak_add_ref();
                return w;
            }

            weak_count(weak_count const& r) noexcept : pi_(r.pi_)
            {
                if (pi_) pi_->weak_add_ref();
            }

            weak_count(weak_count&& r) noexcept : pi_(r.pi_) { r.pi_ = nullptr; }

            ~weak_count()
            {
                if (pi_) pi_->weak_release();
            }

            weak_count& operator=(weak_count const& r) noexcept
            {
                weak_count(r).swap(*this);
                return *this;
            }

            weak_count& operator=(weak_count&& r) noexcept
            {
                if (this != &r)
                {
                    if (pi_) pi_->weak_release();
                    pi_ = r.pi_;
                    r.pi_ = nullptr;
                }
                return *this;
            }

            void swap(weak_count& other) noexcept
            {
                std::swap(pi_, other.pi_);
            }

            long use_count() const noexcept
            {
                return pi_ ? pi_->use_count() : 0;
            }

            bool empty() const noexcept { return pi_ == nullptr; }

            sp_counted_base* lock() const noexcept
            {
                if (pi_ && pi_->add_ref_lock()) return pi_;
                return nullptr;
            }

            sp_counted_base* get() const noexcept { return pi_; }

        private:
            sp_counted_base* pi_;
        };

        /** Exception type matching std::bad_weak_ptr spirit (name preserved). */
        class bad_weak_ptr : public std::exception
        {
        public:
            const char* what() const noexcept override { return "bad_weak_ptr"; }
        };

    } // namespace detail


    /**
     * Shared ownership smart pointer (Boost 1.33/1.34 style).
     */
    template<class T>
    class shared_ptr
    {
    public:
        using element_type = T;

        /** Default: empty shared_ptr. */
        shared_ptr() noexcept : px_(nullptr), pi_(nullptr) {}

        /** Construct from raw pointer, default deletion. */
        explicit shared_ptr(T* p)
            : px_(p)
            , pi_(nullptr)
        {
            try_construct_default_(p);
            detail::sp_enable_shared_from_this(this, p, p);
        }

        /** Construct from raw pointer + deleter. D must be callable as D(T*). */
        template<class D>
        shared_ptr(T* p, D d)
            : px_(p)
            , pi_(nullptr)
        {
            try_construct_deleter_(p, std::move(d));
            detail::sp_enable_shared_from_this(this, p, p);
        }

        /** Aliasing constructor: shares ownership with r but holds pointer p. */
        template<class U>
        shared_ptr(shared_ptr<U> const& r, T* p) noexcept
            : px_(p)
            , pi_(r.pi_)
        {
            if (pi_) pi_->add_ref_copy();
            detail::sp_enable_shared_from_this(this, p, r.get());
        }

        /** Copy-construct from convertible shared_ptr<U>. */
        template<class U,
            class = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
        shared_ptr(shared_ptr<U> const& r) noexcept
            : px_(r.px_)
            , pi_(r.pi_)
        {
            if (pi_) pi_->add_ref_copy();
        }

        /** Copy-construct same type. */
        shared_ptr(shared_ptr const& r) noexcept
            : px_(r.px_)
            , pi_(r.pi_)
        {
            if (pi_) pi_->add_ref_copy();
        }

        /** Move-construct. */
        shared_ptr(shared_ptr&& r) noexcept
            : px_(r.px_), pi_(r.pi_)
        {
            r.px_ = nullptr; r.pi_ = nullptr;
        }

        /** Construct from weak_ptr (throwing on expired). */
        template<class U>
        explicit shared_ptr(weak_ptr<U> const& r)
            : px_(nullptr)
            , pi_(nullptr)
        {
            acquire_from_weak_throw_(r);
        }

        /** Construct from weak_ptr (non-throwing tag). */
        template<class U>
        shared_ptr(weak_ptr<U> const& r, detail::sp_nothrow_tag) noexcept
            : px_(nullptr)
            , pi_(nullptr)
        {
            acquire_from_weak_nothrow_(r);
        }

        /** Destructor: release one shared owner. */
        ~shared_ptr()
        {
            if (pi_) pi_->release();
        }

        /** Copy-assign. */
        shared_ptr& operator=(shared_ptr const& r) noexcept
        {
            shared_ptr(r).swap(*this);
            return *this;
        }

        /** Templated copy-assign. */
        template<class U>
        shared_ptr& operator=(shared_ptr<U> const& r) noexcept
        {
            shared_ptr(r).swap(*this);
            return *this;
        }

        /** Move-assign. */
        shared_ptr& operator=(shared_ptr&& r) noexcept
        {
            if (this != &r)
            {
                shared_ptr(std::move(r)).swap(*this);
            }
            return *this;
        }

        /** Reset to empty. */
        void reset() noexcept
        {
            shared_ptr().swap(*this);
        }

        /** Reset from raw pointer (default delete). */
        void reset(T* p)
        {
            shared_ptr(p).swap(*this);
        }

        /** Reset from raw pointer + deleter. */
        template<class D>
        void reset(T* p, D d)
        {
            shared_ptr(p, std::move(d)).swap(*this);
        }

        /** Swap with another shared_ptr. */
        void swap(shared_ptr& r) noexcept
        {
            std::swap(px_, r.px_);
            std::swap(pi_, r.pi_);
        }

        /** Observers. */
        T* get() const noexcept { return px_; }
        T& operator*() const noexcept { return *px_; }
        T* operator->() const noexcept { return px_; }
        explicit operator bool() const noexcept { return px_ != nullptr; }

        long use_count() const noexcept { return pi_ ? pi_->use_count() : 0; }
        bool unique() const noexcept { return use_count() == 1; }

        /** Owner-based strict weak ordering (control-block identity). */
        template<class U>
        bool owner_before(shared_ptr<U> const& r) const noexcept
        {
            return pi_ < r.pi_;
        }

        template<class U>
        bool owner_before(weak_ptr<U> const& r) const noexcept
        {
            return pi_ < r.pn_.get();
        }

    private:
        T* px_;
        detail::sp_counted_base* pi_;

        /** Construct control block for default delete. */
        void try_construct_default_(T* p)
        {
            if (!p) { pi_ = nullptr; return; }
            pi_ = new detail::sp_counted_impl_p<T*>(p);
        }

        /** Construct control block for custom deleter. */
        template<class D>
        void try_construct_deleter_(T* p, D d)
        {
            if (!p)
            {
                pi_ = nullptr;
                return;
            }
            pi_ = new detail::sp_counted_impl_pd<T*, D>(p, std::move(d));
        }

        /** Acquire from weak_ptr throwing on failure. */
        template<class U>
        void acquire_from_weak_throw_(weak_ptr<U> const& r)
        {
            detail::sp_counted_base* cb = r.pn_.lock();
            if (!cb) throw detail::bad_weak_ptr();
            pi_ = cb;
            px_ = r.px_;
        }

        /** Acquire from weak_ptr non-throwing. */
        template<class U>
        void acquire_from_weak_nothrow_(weak_ptr<U> const& r) noexcept
        {
            detail::sp_counted_base* cb = r.pn_.lock();
            if (!cb)
            {
                pi_ = nullptr;
                px_ = nullptr;
            } else
            {
                pi_ = cb;
                px_ = r.px_;
            }
        }

        template<class U> friend class shared_ptr;
        template<class U> friend class weak_ptr;
    };

} // namespace boost

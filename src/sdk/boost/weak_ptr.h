#pragma once

#include <type_traits>
#include "sp_counted_base.h"

namespace boost
{
    /**
     * Weak non-owning reference (paired with shared_ptr).
     */
    template<class T>
    class weak_ptr
    {
    public:
        using element_type = T;

        weak_ptr() noexcept : px_(nullptr), pn_() {}

        /** From shared_ptr<U> (increments weak ref). */
        template<class U,
            class = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
        weak_ptr(shared_ptr<U> const& r) noexcept
            : px_(r.px_)
            , pn_(detail::weak_count::from_shared(r.pi_))
        {
        }

        /** Copy-construct. */
        weak_ptr(weak_ptr const& r) noexcept : px_(r.px_), pn_(r.pn_) {}

        /** Templated copy-construct. */
        template<class U,
            class = typename std::enable_if<std::is_convertible<U*, T*>::value>::type>
        weak_ptr(weak_ptr<U> const& r) noexcept : px_(r.px_), pn_(r.pn_) {}

        /** Move-construct. */
        weak_ptr(weak_ptr&& r) noexcept : px_(r.px_), pn_(std::move(r.pn_))
        {
            r.px_ = nullptr;
        }

        /** Destructor. */
        ~weak_ptr() = default;

        /** Assignments. */
        weak_ptr& operator=(weak_ptr const& r) noexcept
        {
            weak_ptr(r).swap(*this);
            return *this;
        }

        template<class U>
        weak_ptr& operator=(weak_ptr<U> const& r) noexcept
        {
            weak_ptr(r).swap(*this);
            return *this;
        }

        template<class U>
        weak_ptr& operator=(shared_ptr<U> const& r) noexcept
        {
            weak_ptr(r).swap(*this);
            return *this;
        }

        /** Reset to empty. */
        void reset() noexcept { weak_ptr().swap(*this); }

        /** Swap. */
        void swap(weak_ptr& r) noexcept
        {
            std::swap(px_, r.px_);
            pn_.swap(r.pn_);
        }

        /** Observers. */
        long use_count() const noexcept { return pn_.use_count(); }
        bool expired() const noexcept { return use_count() == 0; }

        /** Non-throwing promotion to shared_ptr. */
        shared_ptr<T> lock() const noexcept
        {
            return shared_ptr<T>(*this, detail::sp_nothrow_tag{});
        }

        /** Owner-based ordering. */
        template<class U>
        bool owner_before(weak_ptr<U> const& r) const noexcept
        {
            return pn_.get() < r.pn_.get();
        }

        template<class U>
        bool owner_before(shared_ptr<U> const& r) const noexcept
        {
            return pn_.get() < r.pi_;
        }

    private:
        T* px_;
        detail::weak_count pn_;

        template<class U> friend class shared_ptr;
        template<class U> friend class weak_ptr;
    };


    /** ADL swap helpers. */
    template<class T>
    inline void swap(shared_ptr<T>& a, shared_ptr<T>& b) noexcept { a.swap(b); }

    template<class T>
    inline void swap(weak_ptr<T>& a, weak_ptr<T>& b) noexcept { a.swap(b); }


    /**
     * get_deleter<D>(shared_ptr<T> const&) — Boost-like deleter query.
     */
    template<class D, class T>
    inline D* get_deleter(shared_ptr<T> const& p) noexcept
    {
        if (!p.pi_) return nullptr;
        void* q = p.pi_->get_deleter(typeid(D));
        return static_cast<D*>(q);
    }
}

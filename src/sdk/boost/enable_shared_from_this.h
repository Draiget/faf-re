#pragma once
#include "shared_ptr.h"  // one-way include

namespace boost {

    template<class T>
    class enable_shared_from_this
    {
    protected:
        mutable weak_ptr<T> weak_this_;

    public:
        shared_ptr<T> shared_from_this() {
            shared_ptr<T> sp(weak_this_); // may throw if expired (your shared_ptr should emulate bad_weak_ptr)
            return sp;
        }

        shared_ptr<T const> shared_from_this() const {
            shared_ptr<T const> sp(weak_this_);
            return sp;
        }

        weak_ptr<T> weak_from_this() { return weak_this_; }
        weak_ptr<T const> weak_from_this() const { return weak_ptr<T const>(weak_this_); }

    protected:
        template<class X>
        void _internal_accept_owner(shared_ptr<X> const& owner, T* p) const {
            if (weak_this_.expired()) {
                // Bind to owner's control block but keep exact T* (subobject-friendly).
                weak_this_ = shared_ptr<T>(owner, p);
            }
        }

        ~enable_shared_from_this() {}

        // Friends reference declarations that already exist in shared_ptr.h
        template<class X, class Y>
        friend void detail::sp_enable_shared_from_this(shared_ptr<X> const*, Y*, enable_shared_from_this<Y>*);

        template<class X, class Y>
        friend void detail::sp_enable_shared_from_this(shared_ptr<X> const*, Y*, enable_shared_from_this<Y> const*);
    };

    // Provide the definitions now (declarations were in shared_ptr.h)
    namespace detail {

        template<class X, class Y>
        inline void sp_enable_shared_from_this(shared_ptr<X> const* ppx, Y* p, enable_shared_from_this<Y>* pe) {
            if (pe) { pe->_internal_accept_owner(*ppx, p); }
        }

        template<class X, class Y>
        inline void sp_enable_shared_from_this(shared_ptr<X> const* ppx, Y* p, enable_shared_from_this<Y> const* pe) {
            if (pe) { pe->_internal_accept_owner(*ppx, p); }
        }

    } // namespace detail

} // namespace boost

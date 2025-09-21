#pragma once
#include <new>
#include <typeinfo>
#include <type_traits>
#include <utility>
#include <exception>
#include <cstring>

//
// Minimal, modern reimplementation of boost::function<R(Args...)>
// - Small buffer optimization (SBO) for small callables
// - Type erasure with per-type vtable
// - target<T>(), target_type(), clear(), swap(), operator bool
// - Throws bad_function_call on invoking empty function
// - No allocators/bind placeholders or function_equal support
//
// Namespace kept as 'boost' for drop-in compatibility.
//
namespace boost
{
    /**
     * \brief Exception thrown when invoking an empty function.
     */
    struct bad_function_call : std::exception
    {
        /** \brief Message string. */
        const char* what() const noexcept override { return "bad_function_call"; }
    };

    /** Legacy-compatible: keep Alloc parameter but ignore it. */
    template<class Signature, class Alloc = void>
    class function;

    /**
     * \brief Type-erased function wrapper compatible with old boost::function.
     *
     * Notes:
     * - SBO size is 3 pointers (like many std::function impls).
     * - target<T>() returns pointer to stored callable if exact T matches.
     * - Construction from null function pointer makes it empty.
     */
    template<class R, class... Args, class Alloc>
    class function<R(Args...), Alloc>
    {
    public:
        using result_type = R;
        using allocator_type = Alloc;

        /** \brief Default-construct empty function. */
        function() noexcept = default;

        /** \brief Construct empty from nullptr. */
        function(std::nullptr_t) noexcept {}

        /**
         * \brief Construct from any callable F where F(Args...) is invocable and returns R (or convertible to R).
         */
        template<class F,
            class DF = std::decay_t<F>,
            std::enable_if_t<!std::is_same_v<DF, function>, int> = 0,
            std::enable_if_t<std::is_invocable_r_v<R, DF&, Args...>, int> = 0>
        function(F&& f) {
            assign(std::forward<F>(f));
        }

        /** \brief Copy constructor. */
        function(const function& other) {
            if (other.vtable_) {
                vtable_ = other.vtable_;
                vtable_->copy(&storage_, &other.storage_);
            }
        }

        /** \brief Move constructor. */
        function(function&& other) noexcept {
            if (other.vtable_) {
                vtable_ = other.vtable_;
                vtable_->move(&storage_, &other.storage_);
                other.vtable_ = nullptr;
            }
        }

        /** \brief Destructor. */
        ~function() {
            reset();
        }

        /** \brief Assign nullptr -> empty. */
        function& operator=(std::nullptr_t) noexcept {
            reset();
            return *this;
        }

        /** \brief Copy assignment. */
        function& operator=(const function& other) {
            if (this == &other) return *this;
            function tmp(other);
            swap(tmp);
            return *this;
        }

        /** \brief Move assignment. */
        function& operator=(function&& other) noexcept {
            if (this == &other) return *this;
            reset();
            if (other.vtable_) {
                vtable_ = other.vtable_;
                vtable_->move(&storage_, &other.storage_);
                other.vtable_ = nullptr;
            }
            return *this;
        }

        /** \brief Templated assignment from callable. */
        template<class F,
            class DF = std::decay_t<F>,
            std::enable_if_t<!std::is_same_v<DF, function>, int> = 0,
            std::enable_if_t<std::is_invocable_r_v<R, DF&, Args...>, int> = 0>
        function& operator=(F&& f) {
            function tmp(std::forward<F>(f));
            swap(tmp);
            return *this;
        }

        /**
         * \brief Invoke the stored callable.
         * \throws bad_function_call if empty.
         */
        R operator()(Args... args) const {
            if (!vtable_) throw bad_function_call{};
            return vtable_->call(&storage_, std::forward<Args>(args)...);
        }

        /** \brief True if not empty. */
        explicit operator bool() const noexcept { return vtable_ != nullptr; }

        /** \brief Is empty. */
        bool empty() const noexcept { return vtable_ == nullptr; }

        /** \brief Clear to empty. */
        void clear() noexcept { reset(); }

        /** \brief Swap with another function. */
        void swap(function& other) noexcept {
            if (this == &other) return;

            alignas(max_align_t) unsigned char tmp[sbo_size];
            const vtable_t* vt_tmp = vtable_;

            if (vtable_ && other.vtable_) {
                // Both non-empty: move this -> tmp, other -> this, tmp -> other
                vtable_->move(&tmp, &storage_);
                other.vtable_->move(&storage_, &other.storage_);
                vt_tmp->move(&other.storage_, &tmp);
            } else if (vtable_ && !other.vtable_) {
                // this non-empty, other empty
                vtable_->move(&other.storage_, &storage_);
                other.vtable_ = vtable_;
                vtable_ = nullptr;
            } else if (!vtable_ && other.vtable_) {
                // this empty, other non-empty
                other.vtable_->move(&storage_, &other.storage_);
                vtable_ = other.vtable_;
                other.vtable_ = nullptr;
            } // else both empty: nothing
        }

        /** \brief C++17-friendly ADL swap. */
        friend void swap(function& a, function& b) noexcept { a.swap(b); }

        /** \brief Type info of the stored callable (or typeid(void) if empty). */
        const std::type_info& target_type() const noexcept {
            return vtable_ ? vtable_->type() : typeid(void);
        }

        /**
         * \brief Get pointer to stored callable if it is exactly T, else nullptr.
         */
        template<class T>
        T* target() noexcept {
            if (!vtable_) return nullptr;
            return static_cast<T*>(vtable_->target(&storage_, typeid(T)));
        }

        /** \brief Const overload of target<T>(). */
        template<class T>
        const T* target() const noexcept {
            if (!vtable_) return nullptr;
            return static_cast<const T*>(vtable_->target(const_cast<void*>(static_cast<const void*>(&storage_)),
                typeid(T)));
        }

    private:
        /** \brief SBO config: tune if you want more room for captures. */
        static constexpr std::size_t sbo_size = sizeof(void*) * 3;
        static constexpr std::size_t sbo_align = alignof(std::max_align_t);

        using storage_t = std::aligned_storage_t<sbo_size, sbo_align>;

        /** \brief Per-type vtable. */
        struct vtable_t
        {
            /** \brief Invoke callable stored in storage_. */
            R(*call)(const void*, Args&&...);

            /** \brief Copy from src storage to dst storage. */
            void (*copy)(void* dst, const void* src);

            /** \brief Move from src storage to dst storage (leaves src empty). */
            void (*move)(void* dst, void* src);

            /** \brief Destroy callable in storage. */
            void (*destroy)(void*);

            /** \brief Return type_info of the stored callable. */
            const std::type_info& (*type)();

            /** \brief Return pointer to T if type matches; else nullptr. */
            void* (*target)(void*, const std::type_info&);
        };

        /** \brief Storage and vtable pointer. */
        storage_t storage_{};
        const vtable_t* vtable_{ nullptr };

        /** \brief Reset to empty, destroying current target if any. */
        void reset() noexcept {
            if (vtable_) {
                vtable_->destroy(&storage_);
                vtable_ = nullptr;
            }
        }

        /** \brief Implementation for small/heap storage per T. */
        template<class T>
        static constexpr bool is_small() {
            return sizeof(T) <= sbo_size &&
                alignof(T) <= sbo_align &&
                std::is_nothrow_move_constructible_v<T>;
        }

        template<class T, bool Small>
        struct ops
        {
            /** \brief Call. */
            static R call(const void* obj, Args&&... a) {
                if constexpr (Small) {
                    const T* t = reinterpret_cast<const T*>(obj);
                    if constexpr (std::is_void_v<R>) { (*t)(std::forward<Args>(a)...); return; } else { return (*t)(std::forward<Args>(a)...); }
                } else {
                    T* const* pp = reinterpret_cast<T* const*>(obj);
                    if constexpr (std::is_void_v<R>) { (**pp)(std::forward<Args>(a)...); return; } else { return (**pp)(std::forward<Args>(a)...); }
                }
            }

            /** \brief Copy construct into dst. */
            static void copy(void* dst, const void* src) {
                if constexpr (Small) {
                    const T* s = reinterpret_cast<const T*>(src);
                    ::new (dst) T(*s);
                } else {
                    T* const* ps = reinterpret_cast<T* const*>(src);
                    T* d = new T(**ps);
                    std::memcpy(dst, &d, sizeof(T*));
                }
            }

            /** \brief Move construct into dst; src becomes empty for heap. */
            static void move(void* dst, void* src) {
                if constexpr (Small) {
                    T* s = reinterpret_cast<T*>(src);
                    ::new (dst) T(std::move(*s));
                    s->~T();
                } else {
                    T** ps = reinterpret_cast<T**>(src);
                    std::memcpy(dst, ps, sizeof(T*));  // steal pointer
                    *ps = nullptr;
                }
            }

            /** \brief Destroy stored callable. */
            static void destroy(void* obj) {
                if constexpr (Small) {
                    T* t = reinterpret_cast<T*>(obj);
                    t->~T();
                } else {
                    T** pp = reinterpret_cast<T**>(obj);
                    if (*pp) { delete* pp; *pp = nullptr; }
                }
            }

            /** \brief Stored callable type. */
            static const std::type_info& type() { return typeid(T); }

            /** \brief Return pointer to T if type matches, otherwise nullptr. */
            static void* target(void* obj, const std::type_info& ti) {
                if (ti != typeid(T)) return nullptr;
                if constexpr (Small) {
                    return obj;
                } else {
                    T** pp = reinterpret_cast<T**>(obj);
                    return *pp;
                }
            }

            /** \brief Static vtable instance for given T/Small. */
            inline static const vtable_t vt = {
                &ops::call,
                &ops::copy,
                &ops::move,
                &ops::destroy,
                &ops::type,
                &ops::target
            };
        };

        /** \brief Assign any callable (handles null function pointers). */
        template<class F>
        void assign(F&& f) {
            using DF = std::decay_t<F>;

            // Null function pointer -> empty
            if constexpr (std::is_pointer_v<DF> && std::is_function_v<std::remove_pointer_t<DF>>) {
                if (f == nullptr) { reset(); return; }
            }

            reset();

            if constexpr (is_small<DF>()) {
                ::new (&storage_) DF(std::forward<F>(f));
                vtable_ = &ops<DF, true>::vt;
            } else {
                DF* heap = new DF(std::forward<F>(f));
                std::memcpy(&storage_, &heap, sizeof(DF*));
                vtable_ = &ops<DF, false>::vt;
            }
        }
    };
} // namespace boost

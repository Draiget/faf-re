#pragma once
#include <memory>
#include <ranges>
#include <unordered_map>

namespace gpg::core
{
    /**
     * Small type-erased deleter to store in registry.
     */
    struct ErasedDeleter
	{
        using Fn = void(*)(void*) noexcept;
        Fn fn{};
        constexpr ErasedDeleter() = default;
        constexpr explicit ErasedDeleter(Fn f) : fn(f) {}
        void operator()(void* p) const noexcept { if (fn && p) fn(p); }
        explicit operator bool() const noexcept { return fn != nullptr; }
    };

    /**
     * Per-thread registry of values keyed by owner address
     */
    struct TLRegistry
	{
        // owner -> (ptr, deleter)
        std::unordered_map<const void*, std::pair<void*, ErasedDeleter>> map;

        ~TLRegistry() noexcept {
            // Delete all remaining per-thread values on thread exit
            for (auto& val : map | std::views::values) {
                auto& [fst, snd] = val;
                snd(fst);
                fst = nullptr;
            }
            map.clear();
        }

        void* get_raw(const void* owner) const noexcept {
            auto it = map.find(owner);
            return it == map.end() ? nullptr : it->second.first;
        }
        void set_raw(const void* owner, void* ptr, ErasedDeleter d) {
            map[owner] = std::make_pair(ptr, d);
        }
        std::pair<void*, ErasedDeleter> extract(const void* owner) {
	        const auto it = map.find(owner);
            if (it == map.end()) {
                return { nullptr, ErasedDeleter{} };
            }
	        const auto val = it->second;
            map.erase(it);
            return val;
        }
        void reset_and_delete(const void* owner, void* replacement, ErasedDeleter d) {
	        const auto it = map.find(owner);
            if (it != map.end()) {
                auto& pair = it->second;
                pair.second(pair.first); // delete old
                pair = std::make_pair(replacement, d);
            } else {
                map.emplace(owner, std::make_pair(replacement, d));
            }
        }
    };

    // One registry per thread
    inline thread_local TLRegistry gTlsRegistry{};

    template<class T, class Deleter = std::default_delete<T>>
    class TssPtr
	{
    public:
        using element_type = T;
        using deleter_type = Deleter;

        /**
         * Empty, unique owner key is 'this'.
         */
        constexpr TssPtr() noexcept = default;

        /**
         * Delete current-thread value (if any) and remove the entry for this owner.
         */
        ~TssPtr() noexcept {
            auto [ptr, del] = gTlsRegistry.extract(this);
            (void)del; // deleter isn't needed here; we delete explicitly below to be precise
            if (ptr) {
                // Use our own deleter to match the stored type exactly
                deleter_type{}(static_cast<T*>(ptr));
            }
        }

        TssPtr(const TssPtr&) = delete;
        TssPtr& operator=(const TssPtr&) = delete;

        /**
         * Get value for current thread (may be null).
         */
        T* get() const noexcept {
            return static_cast<T*>(gTlsRegistry.get_raw(this));
        }

        /**
         * Replace value without deleting the previous one (use carefully).
         */
        void set_no_delete(T* p) noexcept {
            gTlsRegistry.set_raw(this, p, erased_deleter());
        }

        /**
         * Replace value and delete the previous one with Deleter.
         */
        void reset(T* p = nullptr) noexcept {
            gTlsRegistry.reset_and_delete(this, p, erased_deleter());
        }

        /**
         * Release current value without deleting it and remove from registry.
         */
        T* release() noexcept {
            auto [ptr, _] = gTlsRegistry.extract(this);
            return static_cast<T*>(ptr);
        }

        /**
         * Get or create via factory if null; returns reference to value.
         */
        template<class Factory>
        T& get_or_create(Factory&& f) {
            T* cur = get();
            if (!cur) {
                T* created = std::forward<Factory>(f)();
                reset(created);
                return *created;
            }
            return *cur;
        }

        T& operator*()  const { return *get(); }
        T* operator->() const { return  get(); }

    private:
        static ErasedDeleter erased_deleter() noexcept {
            return ErasedDeleter{
            	[](void* p) noexcept {
	                Deleter{}(static_cast<T*>(p));
	            }
            };
        }
    };
}

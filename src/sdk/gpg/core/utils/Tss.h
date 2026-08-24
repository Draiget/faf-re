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

        /**
         * Deletes every per-thread value but leaves this registry usable.
         *
         * This is deliberately not a destructor. Objects that outlive thread
         * storage still consult the registry while they unwind - gpg::LogContext
         * does it from its own destructor, which for the main thread runs out of
         * an atexit handler, after thread_local destructors have already gone.
         * Draining leaves an empty map that answers nullptr, which every caller
         * here already handles; destroying it left find() walking freed bucket
         * storage.
         */
        void drain() noexcept {
            for (auto& val : map | std::views::values) {
                auto& [fst, snd] = val;
                if (fst != nullptr && snd) {
                    snd(fst);
                }
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

    // One registry per thread, allocated on first use and never destroyed, so
    // that anything unwinding after thread storage is gone still finds a valid
    // (if empty) map. A separate guard drains the values when the thread ends.
    inline TLRegistry& TlsRegistry() noexcept
    {
        static thread_local TLRegistry* const registry = new TLRegistry();
        return *registry;
    }

    struct TLRegistryDrainGuard final
    {
        ~TLRegistryDrainGuard() noexcept { TlsRegistry().drain(); }
    };

    inline thread_local TLRegistryDrainGuard gTlsRegistryDrainGuard{};

    /**
     * Supersedes the binary's `boost::thread_specific_ptr<T>` construction
     * machinery for `LogContext::tss` (`ContextStack` in the original boost
     * naming): `boost::detail::tss_adapter_ContextStack::tss_adapter_ContextStack`
     * (0x00936B30), `boost::function1_ContextStack` (0x00937950, the cleanup-
     * function wrapper boost's tss_adapter stores), and `boost::
     * thread_specific_ptr_ContextStack::thread_specific_ptr_ContextStack`
     * (0x009379F0) are all real, compiled-in boost template instantiations
     * for this exact slot, but none has a corresponding call here: this
     * registry-based design (a `thread_local` `TLRegistry` keyed by owner
     * address) deliberately replaces boost's TLS-slot-allocation approach
     * entirely rather than porting it line-for-line, matching this project's
     * documented "keep behaviour, not exact function count" modernization
     * philosophy for compiler/library-generated machinery. `TssPtr`'s own
     * trivial `constexpr` default constructor is the modern equivalent of
     * what those three addresses did in the original binary; the boost
     * cleanup callback they registered is superseded by `ThreadStateTssDeleter`
     * (`Logging.h`), already cited against the matching runtime addresses
     * there (0x00936CC0/0x00936FD0).
     */
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
            auto [ptr, del] = TlsRegistry().extract(this);
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
            return static_cast<T*>(TlsRegistry().get_raw(this));
        }

        /**
         * Replace value without deleting the previous one (use carefully).
         */
        void set_no_delete(T* p) noexcept {
            TlsRegistry().set_raw(this, p, erased_deleter());
        }

        /**
         * Replace value and delete the previous one with Deleter.
         */
        void reset(T* p = nullptr) noexcept {
            TlsRegistry().reset_and_delete(this, p, erased_deleter());
        }

        /**
         * Release current value without deleting it and remove from registry.
         */
        T* release() noexcept {
            auto [ptr, _] = TlsRegistry().extract(this);
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

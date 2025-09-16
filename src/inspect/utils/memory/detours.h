#pragma once
#include <cstdint>
#include <string>
#include <memory>
#include <mutex>
#include <vector>
#include "detours_sigscan.h"
#include "detours_memory.h"
#include "asm_utils.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace detours {

    template<typename TFunc>
    class Detour {
    public:
        using Func = TFunc;

        /** Create detour by compiled IDA pattern + HMODULE. */
        static std::unique_ptr<Detour> create_ida(std::string name,
            HMODULE module,
            const detours::sigscan::Compiled& pattern,
            Func callback)
        {
            auto ptr = std::unique_ptr<Detour>(new Detour(std::move(name), "", "", reinterpret_cast<void*>(callback)));
            if (!module) return nullptr;

            void* target = detours::sigscan::find_ida(module, pattern, /*require_unique=*/true);
            if (!target || target == detours::sigscan::invalid_ptr) return nullptr;
            if (!ptr->init_common(target)) return nullptr;
            ptr->enable();
            return ptr;
        }

        /** Create detour by compiled IDA pattern + module name (wide). */
        static std::unique_ptr<Detour> create_ida(std::string name,
            std::wstring_view module_name_w,
            const detours::sigscan::Compiled& pattern,
            Func callback)
        {
            auto ptr = std::unique_ptr<Detour>(new Detour(std::move(name), "", "", reinterpret_cast<void*>(callback)));
            if (module_name_w.empty()) return nullptr;

            void* target = detours::sigscan::find_ida(module_name_w, pattern, /*require_unique=*/true);
            if (!target || target == detours::sigscan::invalid_ptr) return nullptr;
            if (!ptr->init_common(target)) return nullptr;
            ptr->enable();
            return ptr;
        }

        /** Optional: bridge overloads that take raw IDA string (compile then forward). */
        static std::unique_ptr<Detour> create_ida(std::string name,
            HMODULE module,
            std::string ida_signature,
            Func callback)
        {
            if (!module) return nullptr;
            if (auto cp = detours::sigscan::compile_ida(ida_signature)) {
                return create_ida(std::move(name), module, *cp, callback);
            }
            return nullptr;
        }

        static std::unique_ptr<Detour> create_ida(std::string name,
            std::wstring_view module_name_w,
            std::string ida_signature,
            Func callback)
        {
            if (module_name_w.empty()) return nullptr;
            if (auto cp = detours::sigscan::compile_ida(ida_signature)) {
                return create_ida(std::move(name), module_name_w, *cp, callback);
            }
            return nullptr;
        }

        /** Create detour at fixed address (unchanged). */
        static std::unique_ptr<Detour> create_at(std::string name,
            void* target,
            Func callback)
        {
            auto ptr = std::unique_ptr<Detour>(new Detour(std::move(name), "", "", reinterpret_cast<void*>(callback)));
            if (!ptr->init_common(target)) return nullptr;
            ptr->enable();
            return ptr;
        }

        ~Detour() { disable(); }

        Detour(const Detour&) = delete;
        Detour& operator=(const Detour&) = delete;
        Detour(Detour&&) = delete;
        Detour& operator=(Detour&&) = delete;

        [[nodiscard]] bool enabled() const noexcept { return enabled_ && detoured_; }
        [[nodiscard]] Func original() const noexcept { return reinterpret_cast<Func>(trampoline_); }
        [[nodiscard]] void* target_address() const noexcept { return target_; }

        void enable() {
#if defined(_WIN32)
            std::scoped_lock lk(mu_);
            if (!enabled_ || detoured_) return;

            MemProtectGuard guard(target_, patch_len_, PAGE_EXECUTE_READWRITE);
            if (!guard.ok()) return;

            // Write E9 rel32 to hook entry
            asm_utils::inject_jump(target_, reinterpret_cast<std::uint8_t*>(callback_ptr_));

            // NOP pad the rest of stolen block (prevents half-instruction tails)
            auto* p = static_cast<std::uint8_t*>(target_);
            for (std::size_t i = asm_utils::kOpJmpRel32Size; i < patch_len_; ++i) p[i] = asm_utils::kOpNop;

            FlushInstructionCache(::GetCurrentProcess(), target_, patch_len_);
            detoured_ = true;
#endif
        }

        void disable() {
#if defined(_WIN32)
            std::scoped_lock lk(mu_);
            if (!enabled_ || !detoured_) return;

            MemProtectGuard guard(target_, patch_len_, PAGE_EXECUTE_READWRITE);
            if (!guard.ok()) return;

            auto* p = static_cast<std::uint8_t*>(target_);
            for (std::size_t i = 0; i < original_.size(); ++i) p[i] = original_[i];

            FlushInstructionCache(::GetCurrentProcess(), target_, patch_len_);
            detoured_ = false;
#endif
        }

    private:
        Detour(std::string name, std::string module, std::string sig, void* callback)
            : name_(std::move(name)), module_(std::move(module)), ida_sig_(std::move(sig)),
            callback_ptr_(callback), target_(nullptr), trampoline_(nullptr),
            patch_len_(0), enabled_(false), detoured_(false) {
        }

        bool init_common(void* target) {
#if !defined(_WIN32)
            (void)target; return false;
#else
            if (!target) return false;
            target_ = target;

            auto* entry = static_cast<std::uint8_t*>(target_);
            // 1) Decide stolen count so we fully cover SEH prologue
            const auto need = asm_utils::compute_stolen_len_covering_seh(entry);
            patch_len_ = need;

            // 2) Save original bytes for disable()
            original_.assign(entry, entry + need);

            // 3) Build trampoline: [decoded+fixed stolen bytes] + [E9 back to entry+need]
            const std::size_t tramp_size = need + 1 + sizeof(std::uint32_t);
            trampoline_ = ::VirtualAlloc(nullptr, tramp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!trampoline_) return false;

            auto* w = static_cast<std::uint8_t*>(trampoline_);
            asm_utils::decode_copy_bytes(entry, w, need); // relocation-aware copy
            w += need;

            *w++ = asm_utils::kOpJmp; // E9
            const auto back_rel = reinterpret_cast<std::uintptr_t>(entry + need)
                - (reinterpret_cast<std::uintptr_t>(w) + sizeof(std::uint32_t));
            *reinterpret_cast<std::uint32_t*>(w) = static_cast<std::uint32_t>(back_rel);

            enabled_ = true;
            return true;
#endif
        }

    private:
        std::string name_;
        std::string module_;
        std::string ida_sig_;
        void* callback_ptr_;

        void* target_;
        void* trampoline_;
        std::vector<std::uint8_t> original_;
        std::size_t patch_len_;

        bool enabled_;
        bool detoured_;
        std::mutex mu_;
    };

} // namespace detours

#pragma once

// Modern signature scanner for x86 Windows PE modules (IDA-style patterns).
// Keeps compatibility with IDA-like signatures: "55 8B EC ?? ?? 83 EC 1C".
// Wildcards are "?" or "??".
//
// All code comments are in English per project convention.
// This header intentionally contains no Windows headers; implementation hides them.
//
// Usage:
//   auto addr = detours2::sigscan::find_unique_ida("gamedata.dll", "55 8B EC ?? ?? 83 EC 1C");
//   if (!addr || addr == detours2::sigscan::invalid_ptr) { /* handle error */ }
//
// Notes:
// - Returns invalid_ptr if more than one match is found (same semantics as the legacy code).
// - Returns nullptr if nothing found.
// - Thread-safe and exception-safe.

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#endif

namespace detours::sigscan
{
    // Special "multiple matches" marker (mirrors legacy INVALID_POINTER behavior).
    inline const auto invalid_ptr =
        reinterpret_cast<void*>(static_cast<intptr_t>(-1));

    struct Compiled {
        // Full pattern
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> mask; // 0xFF = exact, 0x00 = wildcard

        // Anchor (longest solid literal run)
        std::size_t anchor_off = 0;     // offset inside full pattern
        std::size_t anchor_len = 0;     // length of anchor
        std::vector<int> bmh_shift;     // 256-element shift table for anchor's last byte
    };

    // Parse IDA string into Compiled pattern with precomputed anchor + BMH shifts.
    [[nodiscard]] std::optional<Compiled> compile_ida(std::string_view ida);

    // Find using module handle (fast path; no Toolhelp).
    [[nodiscard]] void* find_ida(HMODULE mod, const Compiled& pat, bool require_unique);

    // Convenience: from module name. Uses GetModuleHandleExW once.
    [[nodiscard]] void* find_ida(std::wstring_view module_name_w,
        const Compiled& pat,
        bool require_unique);

    // One-shot helper (parse + find). Same semantics as before.
    [[nodiscard]] inline void* find_ida(std::wstring_view module_name_w,
        std::string_view ida_signature,
        bool require_unique)
    {
        if (auto cp = compile_ida(ida_signature)) {
            return find_ida(module_name_w, *cp, require_unique);
        }
        return nullptr;
    }

    [[nodiscard]] inline void* find_unique_ida(std::wstring_view module_name_w,
        std::string_view ida_signature)
    {
        return find_ida(module_name_w, ida_signature, true);
    }
}

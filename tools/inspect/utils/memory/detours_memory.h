
#pragma once

// Simple RAII VirtualProtect guard for setting PAGE_EXECUTE_READWRITE temporarily.
// Only meaningful on Windows. On other platforms it compiles to a no-op.

#include <cstdint>
#include <cstddef>

namespace detours
{
    class MemProtectGuard {
    public:
        MemProtectGuard(void* address, std::size_t size, std::uint32_t newProtection) noexcept;
        ~MemProtectGuard();

        MemProtectGuard(const MemProtectGuard&) = delete;
        MemProtectGuard& operator=(const MemProtectGuard&) = delete;

        MemProtectGuard(MemProtectGuard&&) = delete;
        MemProtectGuard& operator=(MemProtectGuard&&) = delete;

        [[nodiscard]] bool ok() const noexcept { return ok_; }

    private:
        void* address_;
        std::size_t size_;
        std::uint32_t old_;
        bool ok_;
    };
}

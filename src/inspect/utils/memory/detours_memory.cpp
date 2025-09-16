#include "detours_memory.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace detours
{
    MemProtectGuard::MemProtectGuard(void* address, const std::size_t size, const std::uint32_t newProtection) noexcept
        : address_(address), size_(size), old_(0), ok_(false)
    {
#if defined(_WIN32)
        DWORD oldProtect = 0;
        ok_ = VirtualProtect(
            address_, 
            size_, 
            newProtection, 
            &oldProtect) != 0;

        old_ = static_cast<std::uint32_t>(oldProtect);
#else
        (void)newProtection;
        ok_ = true;
#endif
    }

    MemProtectGuard::~MemProtectGuard() {
#if defined(_WIN32)
        if (ok_) {
            DWORD tmp;
            VirtualProtect(address_, size_, old_, &tmp);
        }
#endif
    }
}

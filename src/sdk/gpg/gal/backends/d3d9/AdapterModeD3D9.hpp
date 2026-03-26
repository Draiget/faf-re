#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D423A4
     * COL:     0x00E50804
     */
    class AdapterModeD3D9
    {
    public:
        /**
         * Address: 0x008E8E40 (FUN_008E8E40)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for AdapterModeD3D9 instances.
         */
        virtual ~AdapterModeD3D9();

    public:
        std::uint32_t width_ = 0;       // +0x04
        std::uint32_t height_ = 0;      // +0x08
        std::uint32_t refreshRate_ = 0; // +0x0C
    };

    static_assert(offsetof(AdapterModeD3D9, width_) == 0x04, "AdapterModeD3D9::width_ offset must be 0x04");
    static_assert(offsetof(AdapterModeD3D9, height_) == 0x08, "AdapterModeD3D9::height_ offset must be 0x08");
    static_assert(
        offsetof(AdapterModeD3D9, refreshRate_) == 0x0C,
        "AdapterModeD3D9::refreshRate_ offset must be 0x0C"
    );
    static_assert(sizeof(AdapterModeD3D9) == 0x10, "AdapterModeD3D9 size must be 0x10");
}

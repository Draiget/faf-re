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
         * Address: 0x00940990 (FUN_00940990, ??0AdapterModeD3D9@gal@gpg@@QAE@@Z)
         *
         * What it does:
         * Initializes one adapter-mode lane with width/height/refresh-rate
         * scalar values.
         */
        AdapterModeD3D9(std::uint32_t width, std::uint32_t height, std::uint32_t refreshRate);

        /**
         * Address: 0x008E8E10 (FUN_008E8E10)
         *
         * What it does:
         * Copy-constructs one adapter-mode lane by cloning width/height/
         * refresh-rate scalar values.
         */
        AdapterModeD3D9(const AdapterModeD3D9& other);

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

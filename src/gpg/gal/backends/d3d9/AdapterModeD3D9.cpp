#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x00940990 (FUN_00940990, ??0AdapterModeD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Initializes one adapter-mode lane with width/height/refresh-rate scalar values.
     */
    AdapterModeD3D9::AdapterModeD3D9(
        const std::uint32_t widthValue,
        const std::uint32_t heightValue,
        const std::uint32_t refreshRateValue
    )
        : width_(widthValue)
        , height_(heightValue)
        , refreshRate_(refreshRateValue)
    {
    }

    /**
     * Address: 0x008E8E10 (FUN_008E8E10)
     *
     * What it does:
     * Copy-constructs one adapter-mode lane by cloning width/height/
     * refresh-rate scalar values.
     */
    AdapterModeD3D9::AdapterModeD3D9(const AdapterModeD3D9& other)
        : width_(other.width_)
        , height_(other.height_)
        , refreshRate_(other.refreshRate_)
    {
    }

    /**
     * Address: 0x009409B0 (FUN_009409B0, ??1AdapterModeD3D9@gal@gpg@@QAE@@Z)
     * Address: 0x008E8E40 (FUN_008E8E40, the scalar-deleting wrapper for the
     * destructor above)
     *
     * What it does:
     * Restores AdapterModeD3D9 vftable ownership; deleting-thunk lanes route
     * through this destructor body.
     */
    AdapterModeD3D9::~AdapterModeD3D9() = default;
}


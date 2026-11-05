#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x00941040 (FUN_00941040, gpg::gal::AdapterD3D9::AdapterD3D9)
     * Mangled: ??0AdapterD3D9@gal@gpg@@QAE@@Z
     *
     * What it does:
     * Initializes one empty adapter descriptor with zeroed identifiers,
     * empty strings, and an empty mode vector.
     */
    AdapterD3D9::AdapterD3D9()
        : vendorId(0U)
        , deviceId(0U)
        , driver()
        , deviceName()
        , description()
        , modes()
    {
    }

    /**
     * Address: 0x009410A0 (FUN_009410A0, gpg::gal::AdapterD3D9::AdapterD3D9)
     * Mangled: ??0AdapterD3D9@gal@gpg@@QAE@@Z
     *
     * What it does:
     * Initializes adapter identifier lanes and copies driver/device/description
     * strings into this adapter instance.
     */
    AdapterD3D9::AdapterD3D9(
        const std::uint32_t vendorIdValue,
        const std::uint32_t deviceIdValue,
        const fa::string& driverName,
        const fa::string& deviceNameText,
        const fa::string& descriptionText
    )
        : vendorId(vendorIdValue)
        , deviceId(deviceIdValue)
        , driver()
        , deviceName()
        , description()
        , modes()
    {
        driver.assign(driverName, 0U, fa::string::npos);
        deviceName.assign(deviceNameText, 0U, fa::string::npos);
        description.assign(descriptionText, 0U, fa::string::npos);
    }

    /**
     * Address: 0x008EFF80 (FUN_008EFF80, gpg::gal::AdapterD3D9::AdapterD3D9 copy)
     *
     * What it does:
     * Memberwise copy: the two ids, the three strings, then `modes` through the
     * vector's copy constructor (0x008EFB60, called at 0x008F0020). The
     * recovered body default-constructed `modes` and assigned it afterwards,
     * which runs `operator=` (0x008EF870) instead.
     */
    AdapterD3D9::AdapterD3D9(const AdapterD3D9&) = default;

    /**
     * Address: 0x00940C90 (FUN_00940C90)
     * Address: 0x008F0040 (FUN_008F0040, the scalar-deleting wrapper for the
     * destructor above)
     *
     * What it does:
     * Destroys adapter mode list and all descriptive string lanes.
     */
    AdapterD3D9::~AdapterD3D9() = default;

    /**
     * Address: 0x009411D0 (FUN_009411D0)
     *
     * What it does:
     * `modes.push_back(mode)`. The body is `add ecx, 60h` and a jump into the
     * vector's `push_back` (0x00941160); `CollectAllAdapters` calls it once per
     * enumerated display mode (0x008F1EDF).
     */
    void AdapterD3D9::AddMode(const AdapterModeD3D9& mode)
    {
        modes.push_back(mode);
    }
}


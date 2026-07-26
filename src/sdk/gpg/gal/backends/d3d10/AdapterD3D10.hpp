#pragma once

#include <cstddef>
#include <cstdint>

#include <dxgi.h>

#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    struct AdapterModeD3D10
    {
        std::uint32_t format_ = 0U;              // +0x00 (DXGI_FORMAT)
        void* output_ = nullptr;                 // +0x04 (IDXGIOutput*)
        DXGI_OUTPUT_DESC outputDesc_{};          // +0x08 (0x5C bytes)
        msvc8::vector<DXGI_MODE_DESC> modes_{};  // +0x64
    };

    static_assert(offsetof(AdapterModeD3D10, format_) == 0x00, "AdapterModeD3D10::format_ offset must be 0x00");
    static_assert(offsetof(AdapterModeD3D10, output_) == 0x04, "AdapterModeD3D10::output_ offset must be 0x04");
    static_assert(offsetof(AdapterModeD3D10, outputDesc_) == 0x08, "AdapterModeD3D10::outputDesc_ offset must be 0x08");
    /**
     * `modes_` starts at +0x64, not +0x68: the word at +0x64 is the legacy
     * vector's own `myProxy_` lane, not a descriptor pad.
     *
     * Proof, both from `AppendAdapterModeEntry`'s binary body (FUN_008F7C50):
     * the element stride is `add esi, 74h` at 0x008F7CBC, and the count divide
     * is the `imul 8D3DCB09h` / `add edx, ecx` / `sar edx, 6` reciprocal triple
     * at 0x008F7C66-0x008F7C6F — the signed divide-by-116 sequence. And in
     * `AdapterD3D10::ProbeOutputsAndModes` (FUN_008F7CF0) the entry base is
     * `esp+0x44` (0x008F7E7A) while the three zeroed vector lanes are
     * `esp+0xAC/0xB0/0xB4` (0x008F7D94-0x008F7DA2) and the buffer freed at
     * 0x008F7EA1 is read from `esp+0xAC` — i.e. `first_` sits at entry+0x68,
     * so the vector object itself begins one word earlier.
     */
    static_assert(offsetof(AdapterModeD3D10, modes_) == 0x64, "AdapterModeD3D10::modes_ offset must be 0x64");
    static_assert(sizeof(AdapterModeD3D10) == 0x74, "AdapterModeD3D10 size must be 0x74");

    /**
     * VFTABLE: 0x00D42FF8
     * COL:     0x00E50B54
     */
    class AdapterD3D10
    {
    public:
        /**
         * Address: 0x008F7AC0 (FUN_008F7AC0)
         *
         * IDXGIAdapter *
         *
         * What it does:
         * Initializes one adapter wrapper from one DXGI adapter pointer and
         * captures the adapter descriptor payload.
         */
        explicit AdapterD3D10(void* dxgiAdapter);

        /**
         * Address: 0x008FF450 (FUN_008FF450)
         *
         * What it does:
         * Copy-constructs one adapter wrapper by cloning descriptor payload and
         * deep-copying cached mode vectors from `other`.
         */
        AdapterD3D10(const AdapterD3D10& other);

        /**
         * Address: 0x008FF2F0 (FUN_008FF2F0)
         *
         * What it does:
         * Copy-assigns adapter pointer/descriptor lanes and deep-copies the
         * cached mode-vector lane from `other`.
         */
        AdapterD3D10& operator=(const AdapterD3D10& other);

        /**
         * Address: 0x008F7CF0 (FUN_008F7CF0, sub_8F7CF0)
         *
         * What it does:
         * Enumerates outputs and cached display-mode lists for the recovered DXGI
         * format probe set into the local mode cache.
         */
        int ProbeOutputsAndModes();

        /**
         * Address: 0x008F7BF0 (FUN_008F7BF0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk and releases retained
         * adapter-mode heap storage.
         */
        virtual ~AdapterD3D10();

    public:
        IDXGIAdapter* dxgiAdapter_ = nullptr;        // +0x04
        DXGI_ADAPTER_DESC description_{};            // +0x08
        msvc8::vector<AdapterModeD3D10> modes_{};    // +0x12C
    };

    static_assert(offsetof(AdapterD3D10, dxgiAdapter_) == 0x04, "AdapterD3D10::dxgiAdapter_ offset must be 0x04");
    static_assert(offsetof(AdapterD3D10, description_) == 0x08, "AdapterD3D10::description_ offset must be 0x08");
    static_assert(offsetof(AdapterD3D10, modes_) == 0x12C, "AdapterD3D10::modes_ offset must be 0x12C");
    static_assert(sizeof(AdapterD3D10) == 0x13C, "AdapterD3D10 size must be 0x13C");
}

#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/Head.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    /**
     * The graphics API a device context asks for, stored as the dword at
     * `DeviceContext` +0x04. `Device::Create` builds a `DeviceD3D9` for
     * `Direct3D9` and a `DeviceD3D10` for `Direct3D10` and throws "unknown API
     * requested" for anything else; `GetHardwareVertexFormatter` picks its
     * formatter table by the same value. Each backend's own context starts out
     * `Unset` (both constructors push 0) until `Setup` copies the requested one
     * in.
     */
    enum class DeviceApi : std::int32_t
    {
        Unset = 0,
        Direct3D9 = 1,
        Direct3D10 = 2,
        // FAF addition, not in the shipped binary: the Direct3D 11 backend
        // (`DeviceD3D11`, selected with /d3d11).
        Direct3D11 = 3,
        // FAF additions: the Direct3D 12 (`DeviceD3D12`, /d3d12) and Vulkan
        // (`DeviceVulkan`, /vulkan) backends.
        Direct3D12 = 4,
        Vulkan = 5,
    };

    /**
     * FAF addition, not in the shipped binary.
     *
     * True for the APIs whose effects are written in the D3D10 dialect -
     * d3d10states.compat, `technique10`, shader model 4 - and whose mesh
     * formatters are the D3D10 ones. Direct3D 11 runs the D3D10 effect path
     * unchanged, and Direct3D 12 and Vulkan run it through the FAF effect
     * layer, so every engine branch on "is this D3D10" asks this instead.
     */
    [[nodiscard]] constexpr bool UsesD3D10EffectDialect(const DeviceApi api) noexcept
    {
        return api == DeviceApi::Direct3D10 || api == DeviceApi::Direct3D11 || api == DeviceApi::Direct3D12 ||
            api == DeviceApi::Vulkan;
    }

    /**
     * VFTABLE: 0x00D420B4
     * COL:     0x00E5EAEC
     */
    class DeviceContext
    {
    public:
        /**
         * Address: 0x008E6D40 (FUN_008E6D40)
         *
         * What it does:
         * Initializes one device-context record and records requested backend type.
         */
        explicit DeviceContext(DeviceApi deviceType = DeviceApi::Direct3D9);

        /**
         * Address: 0x00430480 (FUN_00430480)
         *
         * DeviceContext const &
         *
         * What it does:
         * Copies one device-context payload, including all configured heads.
         */
        DeviceContext(const DeviceContext& other);

        /**
         * Address: 0x008D1D00 (FUN_008D1D00, func_CpyDeviceContext)
         *
         * What it does:
         * Copies all scalar capability lanes and head-descriptor vector state
         * from one context into this context.
         */
        DeviceContext& operator=(const DeviceContext& other);

        /**
         * Address: 0x008E69B0 (FUN_008E69B0, gpg::gal::DeviceContext::~DeviceContext)
         * Address: 0x00430570 (FUN_00430570, scalar deleting destructor thunk)
         *
         * What it does:
         * Tears down one device-context base lane; deleting-thunk dispatch uses
         * the same canonical destructor body.
         */
        virtual ~DeviceContext();

        /**
         * Address: 0x008E66E0 (FUN_008E66E0)
         *
         * What it does:
         * Returns the current number of configured head descriptors.
         */
        int GetHeadCount() const;

        /**
         * Address: 0x008E69C0 (FUN_008E69C0)
         *
         * What it does:
         * Returns one validated head descriptor by index.
         */
        const Head& GetHead(std::uint32_t index) const;

        /**
         * Address: 0x008E6A90 (FUN_008E6A90)
         *
         * What it does:
         * Returns one validated mutable head descriptor by index.
         */
        Head& GetHead(std::uint32_t index);

        /**
         * Address: 0x008E7530 (FUN_008E7530)
         *
         * What it does:
         * Appends one head descriptor to the context head list.
         */
        void AddHead(const Head& head);

    public:
        DeviceApi mDeviceType = DeviceApi::Unset; // +0x04
        bool mValidate = false;              // +0x08
        std::uint8_t padding0x09_[3]{};      // +0x09
        std::int32_t mAdapter = 0;           // +0x0C
        bool mVSync = false;                 // +0x10
        bool mHWBasedInstancing = false;     // +0x11
        bool mSupportsFloat16 = false;       // +0x12
        std::uint8_t padding0x13_ = 0;       // +0x13
        std::int32_t mVertexShaderProfile = 0; // +0x14
        std::int32_t mPixelShaderProfile = 0;  // +0x18
        std::uint32_t mMaxPrimitiveCount = 0;  // +0x1C
        std::uint32_t mMaxVertexCount = 0;     // +0x20
        msvc8::vector<Head> mHeads{};        // +0x24
    };

    static_assert(offsetof(DeviceContext, mDeviceType) == 0x04, "DeviceContext::mDeviceType offset must be 0x04");
    static_assert(offsetof(DeviceContext, mValidate) == 0x08, "DeviceContext::mValidate offset must be 0x08");
    static_assert(offsetof(DeviceContext, mAdapter) == 0x0C, "DeviceContext::mAdapter offset must be 0x0C");
    static_assert(offsetof(DeviceContext, mVSync) == 0x10, "DeviceContext::mVSync offset must be 0x10");
    static_assert(
        offsetof(DeviceContext, mHWBasedInstancing) == 0x11,
        "DeviceContext::mHWBasedInstancing offset must be 0x11"
    );
    static_assert(
        offsetof(DeviceContext, mSupportsFloat16) == 0x12,
        "DeviceContext::mSupportsFloat16 offset must be 0x12"
    );
    static_assert(
        offsetof(DeviceContext, mVertexShaderProfile) == 0x14,
        "DeviceContext::mVertexShaderProfile offset must be 0x14"
    );
    static_assert(
        offsetof(DeviceContext, mPixelShaderProfile) == 0x18,
        "DeviceContext::mPixelShaderProfile offset must be 0x18"
    );
    static_assert(
        offsetof(DeviceContext, mMaxPrimitiveCount) == 0x1C,
        "DeviceContext::mMaxPrimitiveCount offset must be 0x1C"
    );
    static_assert(
        offsetof(DeviceContext, mMaxVertexCount) == 0x20,
        "DeviceContext::mMaxVertexCount offset must be 0x20"
    );
    static_assert(offsetof(DeviceContext, mHeads) == 0x24, "DeviceContext::mHeads offset must be 0x24");
    static_assert(sizeof(DeviceContext) == 0x34, "DeviceContext size must be 0x34");
}

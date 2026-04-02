#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/Head.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
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
        explicit DeviceContext(std::int32_t deviceType = 1);

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
         * Address: 0x00430570 (FUN_00430570)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for device-context interface instances.
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
         * Address family:
         * - 0x008E69C0 (const)
         * - 0x008D0496 / 0x008D0529 call-site mutable lane
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
        std::int32_t mDeviceType = 0;        // +0x04
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

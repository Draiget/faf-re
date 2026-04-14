#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  class Shadow
  {
  public:
    /**
     * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes shadow-renderer fidelity/size flags, constructs the embedded
     * camera at `+0x18`, and clears runtime state lanes.
     */
    Shadow();

    virtual ~Shadow() = default;

  public:
    std::int32_t mUninitializedLane04;   // +0x04
    std::int32_t mShadowFidelity;        // +0x08
    bool mShadowBlurEnabled;             // +0x0C
    std::uint8_t mPadding0D_0F[0x03];    // +0x0D
    std::int32_t mShadowSize;            // +0x10
    bool mUnknown14;                     // +0x14
    std::uint8_t mPadding15_17[0x03];    // +0x15
    GeomCamera3 mCamera;                 // +0x18
    std::int32_t mRuntimeLanes[14];      // +0x2E0
  };

  static_assert(offsetof(Shadow, mShadowFidelity) == 0x08, "Shadow::mShadowFidelity offset must be 0x08");
  static_assert(offsetof(Shadow, mShadowBlurEnabled) == 0x0C, "Shadow::mShadowBlurEnabled offset must be 0x0C");
  static_assert(offsetof(Shadow, mShadowSize) == 0x10, "Shadow::mShadowSize offset must be 0x10");
  static_assert(offsetof(Shadow, mCamera) == 0x18, "Shadow::mCamera offset must be 0x18");
  static_assert(offsetof(Shadow, mRuntimeLanes) == 0x2E0, "Shadow::mRuntimeLanes offset must be 0x2E0");
  static_assert(sizeof(Shadow) == 0x318, "Shadow size must be 0x318");
} // namespace moho

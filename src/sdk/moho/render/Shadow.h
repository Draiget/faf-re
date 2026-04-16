#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  struct ShadowRuntimeSharedRef;

  struct ShadowRuntimeLane
  {
    std::int32_t mState;               // +0x00
    ShadowRuntimeSharedRef* mResource; // +0x04
  };

  static_assert(sizeof(ShadowRuntimeLane) == 0x08, "ShadowRuntimeLane size must be 0x8");
  static_assert(offsetof(ShadowRuntimeLane, mState) == 0x00, "ShadowRuntimeLane::mState offset must be 0x0");
  static_assert(offsetof(ShadowRuntimeLane, mResource) == 0x04, "ShadowRuntimeLane::mResource offset must be 0x4");

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

    /**
     * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
     *
     * What it does:
     * Runs non-deleting teardown for one shadow runtime object.
     */
    virtual ~Shadow();

  public:
    std::int32_t mUninitializedLane04;   // +0x04
    std::int32_t mShadowFidelity;        // +0x08
    bool mShadowBlurEnabled;             // +0x0C
    std::uint8_t mPadding0D_0F[0x03];    // +0x0D
    std::int32_t mShadowSize;            // +0x10
    bool mUnknown14;                     // +0x14
    std::uint8_t mPadding15_17[0x03];    // +0x15
    GeomCamera3 mCamera;                 // +0x18
    ShadowRuntimeLane mRuntimeLanes[7];  // +0x2E0
  };

  static_assert(offsetof(Shadow, mShadowFidelity) == 0x08, "Shadow::mShadowFidelity offset must be 0x08");
  static_assert(offsetof(Shadow, mShadowBlurEnabled) == 0x0C, "Shadow::mShadowBlurEnabled offset must be 0x0C");
  static_assert(offsetof(Shadow, mShadowSize) == 0x10, "Shadow::mShadowSize offset must be 0x10");
  static_assert(offsetof(Shadow, mCamera) == 0x18, "Shadow::mCamera offset must be 0x18");
  static_assert(offsetof(Shadow, mRuntimeLanes) == 0x2E0, "Shadow::mRuntimeLanes offset must be 0x2E0");
  static_assert(sizeof(Shadow) == 0x318, "Shadow size must be 0x318");
} // namespace moho

#include "moho/render/Shadow.h"

namespace moho
{
  /**
   * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes shadow-renderer fidelity/size flags, constructs the embedded
   * camera at `+0x18`, and clears runtime state lanes.
   */
  Shadow::Shadow()
    : mShadowFidelity(0)
    , mShadowBlurEnabled(false)
    , mShadowSize(0)
    , mUnknown14(false)
    , mCamera()
    , mRuntimeLanes{}
  {}
} // namespace moho


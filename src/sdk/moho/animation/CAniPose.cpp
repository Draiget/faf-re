#include "CAniPose.h"

namespace moho
{
  /**
   * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
   *
   * What it does:
   * Stores pose skeleton handle + source scale and zeros trailing runtime bytes.
   */
  CAniPose::CAniPose(const boost::shared_ptr<const CAniSkel> skeleton, const float scale)
    : mSkeleton(skeleton)
    , mScale(scale)
  {}
} // namespace moho

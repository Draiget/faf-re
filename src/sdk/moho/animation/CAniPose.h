#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  class CAniSkel;

  class CAniPose
  {
  public:
    /**
     * Address: 0x0054AF00 (FUN_0054AF00, ??0CAniPose@Moho@@QAE@V?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@M@Z)
     *
     * What it does:
     * Initializes animation-pose state from skeleton + scalar pose factor.
     */
    CAniPose(boost::shared_ptr<const CAniSkel> skeleton, float scale);

    ~CAniPose() = default;

    /**
     * Address: 0x005E3B10 (FUN_005E3B10, ?GetSkeleton@CAniPose@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns a retained copy of this pose's skeleton shared handle.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

  public:
    boost::shared_ptr<const CAniSkel> mSkeleton; // +0x00
    float mScale;                                // +0x08
    std::uint8_t pad_0C_8F[0x84]{};
  };

  static_assert(offsetof(CAniPose, mSkeleton) == 0x00, "CAniPose::mSkeleton offset must be 0x00");
  static_assert(offsetof(CAniPose, mScale) == 0x08, "CAniPose::mScale offset must be 0x08");
  static_assert(sizeof(CAniPose) == 0x90, "CAniPose size must be 0x90");
} // namespace moho

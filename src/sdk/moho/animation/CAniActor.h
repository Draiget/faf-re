#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class CAniPose;
  class CAniSkel;
  class IAniManipulator;

  class CAniActor
  {
  public:
    /**
     * Address: 0x005E3CF0 (FUN_005E3CF0, ?GetSkeleton@CAniActor@Moho@@QBE?AV?$shared_ptr@$$CBVCAniSkel@Moho@@@boost@@XZ)
     *
     * What it does:
     * Returns the current skeleton handle from the actor-owned pose object.
     */
    [[nodiscard]]
    boost::shared_ptr<const CAniSkel> GetSkeleton() const;

  public:
    boost::SharedPtrRaw<CAniPose> mPose;                     // +0x00
    std::uint8_t mReserved08_0F[0x08]{};                     // +0x08
    TDatList<IAniManipulator, void> mManipulatorsByPrecedence; // +0x10
  };

  static_assert(offsetof(CAniActor, mPose) == 0x00, "CAniActor::mPose offset must be 0x00");
  static_assert(
    offsetof(CAniActor, mManipulatorsByPrecedence) == 0x10,
    "CAniActor::mManipulatorsByPrecedence offset must be 0x10"
  );
} // namespace moho

#pragma once

#include "gpg/core/reflection/RSharedPointerType.h"

namespace moho
{
  class CAniPose;
}

namespace gpg
{
  static_assert(
    sizeof(RSharedPointerType<moho::CAniPose>) == 0x68,
    "RSharedPointerType<moho::CAniPose> size must be 0x68"
  );

  /**
   * Address: 0x0055EA20 (FUN_0055EA20, preregister_SharedPtrCAniPoseTypeStartup)
   * Address: 0x00BF5540 (FUN_00BF5540, its atexit destructor)
   *
   * What it does:
   * Builds the `RSharedPointerType<moho::CAniPose>` object (0x01104D30), whose
   * constructor preregisters it for `boost::shared_ptr<moho::CAniPose>`.
   */
  [[nodiscard]] gpg::RType* preregister_SharedPtrCAniPoseTypeStartup();
} // namespace gpg

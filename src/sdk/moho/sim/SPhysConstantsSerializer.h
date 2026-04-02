#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class SPhysConstantsSerializer
  {
  public:
    /**
     * Address: 0x00699C10 (FUN_00699C10, Moho::SPhysConstantsSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `mGravity` vector for `SPhysConstants`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00699C50 (FUN_00699C50, Moho::SPhysConstantsSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `mGravity` vector for `SPhysConstants`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds `SPhysConstants` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SPhysConstantsSerializer, mHelperNext) == 0x04,
    "SPhysConstantsSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SPhysConstantsSerializer, mHelperPrev) == 0x08,
    "SPhysConstantsSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SPhysConstantsSerializer, mDeserialize) == 0x0C,
    "SPhysConstantsSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SPhysConstantsSerializer, mSerialize) == 0x10,
    "SPhysConstantsSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SPhysConstantsSerializer) == 0x14, "SPhysConstantsSerializer size must be 0x14");

  /**
   * Address: 0x00BFD460 (FUN_00BFD460, cleanup_SPhysConstantsSerializer)
   *
   * What it does:
   * Unlinks `SPhysConstantsSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SPhysConstantsSerializer();

  /**
   * Address: 0x00BD6050 (FUN_00BD6050, register_SPhysConstantsSerializer)
   *
   * What it does:
   * Initializes `SPhysConstants` serializer callbacks and schedules exit cleanup.
   */
  int register_SPhysConstantsSerializer();
} // namespace moho

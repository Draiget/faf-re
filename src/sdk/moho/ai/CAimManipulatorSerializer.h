#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E21420
   * COL:  0x00E7AA9C
   */
  class CAimManipulatorSerializer
  {
  public:
    /**
     * Address: 0x00630030 (FUN_00630030, Moho::CAimManipulatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAimManipulator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00630040 (FUN_00630040, Moho::CAimManipulatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAimManipulator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00632D80 (FUN_00632D80)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAimManipulator RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(
    offsetof(CAimManipulatorSerializer, mHelperNext) == 0x04,
    "CAimManipulatorSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAimManipulatorSerializer, mHelperPrev) == 0x08,
    "CAimManipulatorSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAimManipulatorSerializer, mDeserialize) == 0x0C,
    "CAimManipulatorSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CAimManipulatorSerializer, mSerialize) == 0x10,
    "CAimManipulatorSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CAimManipulatorSerializer) == 0x14, "CAimManipulatorSerializer size must be 0x14");

  /**
   * Address: 0x00BD2290 (FUN_00BD2290, register_CAimManipulatorSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `CAimManipulator` and installs
   * process-exit cleanup.
   */
  void register_CAimManipulatorSerializer();
} // namespace moho

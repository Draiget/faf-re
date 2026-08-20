#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection serializer helper for `CBuilderArmManipulator`.
   *
   * VFTABLE: 0x00E217C4
   * COL:  0x00E7B130
   *
   * Layout evidence: the startup thunk at 0x00635B20 constructs the process
   * global at 0x010B24BC, writes `mDeserialize` at +0x0C (0x010B24C8) and
   * `mSerialize` at +0x10 (0x010B24CC), then installs the class vftable at
   * +0x00 - so the `gpg::SerHelperBase` link pair occupies +0x04/+0x08 and the
   * complete object is 0x14 bytes.
   */
  class CBuilderArmManipulatorSerializer
  {
  public:
    /**
     * Address: 0x00635AF0 (FUN_00635AF0, Moho::CBuilderArmManipulatorSerializer::Deserialize)
     *
     * IDA signature:
     * int __cdecl Moho::CBuilderArmManipulatorSerializer::Deserialize(gpg::ReadArchive *a1, int a2);
     *
     * What it does:
     * Reflection `load_func_t` adapter: moves the archive into `esi` and the
     * reflected object into `eax` (0x00635AF0/0x00635AF5) and tail-calls the
     * member loader at 0x00637510. The trailing `version`/`ownerRef` callback
     * parameters are never read.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00635B00 (FUN_00635B00, Moho::CBuilderArmManipulatorSerializer::Serialize)
     *
     * IDA signature:
     * int __cdecl Moho::CBuilderArmManipulatorSerializer::Serialize(BinaryWriteArchive *a1, int a2);
     *
     * What it does:
     * Reflection `save_func_t` adapter: moves the archive into `esi` and the
     * reflected object into `edi` (0x00635B01/0x00635B06) and tail-calls the
     * member saver at 0x00637640. The trailing `version`/`ownerRef` callback
     * parameters are never read.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00636F80 (FUN_00636F80)
     * Slot: 0
     *
     * What it does:
     * Binds this helper's load/save callbacks into the `CBuilderArmManipulator`
     * type descriptor once reflection has resolved it.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;      // +0x04
    gpg::SerHelperBase* mHelperPrev;      // +0x08
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CBuilderArmManipulatorSerializer, mHelperNext) == 0x04,
    "CBuilderArmManipulatorSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CBuilderArmManipulatorSerializer, mHelperPrev) == 0x08,
    "CBuilderArmManipulatorSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CBuilderArmManipulatorSerializer, mDeserialize) == 0x0C,
    "CBuilderArmManipulatorSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CBuilderArmManipulatorSerializer, mSerialize) == 0x10,
    "CBuilderArmManipulatorSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(CBuilderArmManipulatorSerializer) == 0x14, "CBuilderArmManipulatorSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BD25B0 (FUN_00BD25B0, register_CBuilderArmManipulatorSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `CBuilderArmManipulator` and installs
   * process-exit cleanup.
   */
  void register_CBuilderArmManipulatorSerializer();
} // namespace moho

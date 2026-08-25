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
   */
  class CBuilderArmManipulatorSerializer : public gpg::SerHelperBase
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
     * Address: 0x00BD25B0 (FUN_00BD25B0, dynamic initializer for the global
     * `CBuilderArmManipulatorSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CBuilderArmManipulatorSerializer@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    CBuilderArmManipulatorSerializer();

    /**
     * Address: 0x00BFAAC0 (FUN_00BFAAC0, Moho::CBuilderArmManipulatorSerializer::~CBuilderArmManipulatorSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CBuilderArmManipulatorSerializer();

    /**
     * Address: 0x00636F80 (FUN_00636F80)
     * Slot: 0
     *
     * What it does:
     * Lazily resolves `CBuilderArmManipulator` RTTI and installs this
     * helper's load/save callbacks into the type descriptor. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
} // namespace moho

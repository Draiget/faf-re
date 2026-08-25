#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E148
   * COL:  0x00E74D1C
   */
  class CAiSteeringImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005D3B70 (FUN_005D3B70, Moho::CAiSteeringImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiSteeringImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005D3B80 (FUN_005D3B80, Moho::CAiSteeringImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiSteeringImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCE4A0 (FUN_00BCE4A0, dynamic initializer for the global
     * `CAiSteeringImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CAiSteeringImplSerializer@Moho@@6B@` -- no eager
     * `Init()` call exists here, and this class has no user-declared
     * destructor (the real binary explicitly registers
     * `atexit(&sub_BF8190)` instead).
     *
     * This helper had never been wired up at all in the previously-recovered
     * source: `Deserialize`/`Serialize` were undeclared, no
     * `register_CAiSteeringImplSerializer` existed anywhere, and no global
     * instance existed anywhere, leaving `Init()` (formerly
     * `RegisterSerializeFunctions`) a dead, uncalled orphan on a class that
     * used raw untyped `void* mNext`/`void* mPrev` link fields instead of
     * the real `gpg::SerHelperBase` base.
     */
    CAiSteeringImplSerializer();

    /**
     * Address: 0x005D3EB0 (FUN_005D3EB0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiSteeringImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper
     * is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  static_assert(offsetof(CAiSteeringImplSerializer, mSerLoadFunc) == 0x0C, "CAiSteeringImplSerializer::mSerLoadFunc offset must be 0x0C");
  static_assert(offsetof(CAiSteeringImplSerializer, mSerSaveFunc) == 0x10, "CAiSteeringImplSerializer::mSerSaveFunc offset must be 0x10");
  static_assert(sizeof(CAiSteeringImplSerializer) == 0x14, "CAiSteeringImplSerializer size must be 0x14");
} // namespace moho

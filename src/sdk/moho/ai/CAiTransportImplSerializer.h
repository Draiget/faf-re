#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F4BC
   * COL:  0x00E764B8
   */
  class CAiTransportImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005E8590 (FUN_005E8590, Moho::CAiTransportImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiTransportImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E85A0 (FUN_005E85A0, Moho::CAiTransportImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiTransportImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCEF50 (FUN_00BCEF50, dynamic initializer for the global
     * `CAiTransportImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiTransportImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here, and this class has no user-declared destructor (the real
     * binary explicitly registers `atexit(&sub_BF8C70)` instead).
     */
    CAiTransportImplSerializer();

    /**
     * Address: 0x005E9C30 (FUN_005E9C30)
     *
     * What it does:
     * Lazily resolves CAiTransportImpl RTTI and installs load/save callbacks
     * from this helper object into the type descriptor. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiTransportImplSerializer, mLoadCallback) == 0x0C,
    "CAiTransportImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTransportImplSerializer, mSaveCallback) == 0x10,
    "CAiTransportImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTransportImplSerializer) == 0x14, "CAiTransportImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCEF50 caller lane (`IAiTransport.cpp`'s reflection
   * bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAiTransportImplSerializer` singleton from an explicit registration
   * sequence. `gCAiTransportImplSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
   * sequence does not need editing.
   */
  void register_CAiTransportImplSerializer();
} // namespace moho

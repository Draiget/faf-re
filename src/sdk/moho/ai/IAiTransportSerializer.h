#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F3B8
   * COL:  0x00E766B0
   */
  class IAiTransportSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCEEB0 (FUN_00BCEEB0, dynamic initializer for the global
     * `IAiTransportSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7IAiTransportSerializer@Moho@@6B@` -- no eager
     * `Init()` call exists here.
     */
    IAiTransportSerializer();

    /**
     * Address: 0x005E4880 (FUN_005E4880, IAiTransportSerializer::Deserialize)
     *
     * What it does:
     * Loads `IAiTransport` broadcaster event-list lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E4890 (FUN_005E4890, IAiTransportSerializer::Serialize)
     *
     * What it does:
     * Saves `IAiTransport` broadcaster event-list lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E9530 (FUN_005E9530, gpg::SerSaveLoadHelper_IAiTransport::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiTransport RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiTransportSerializer, mLoadCallback) == 0x0C,
    "IAiTransportSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiTransportSerializer, mSaveCallback) == 0x10,
    "IAiTransportSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiTransportSerializer) == 0x14, "IAiTransportSerializer size must be 0x14");

  /**
   * Compatibility no-op: `IAiTransport.cpp`'s reflection bootstrap sequence
   * still calls this by name. See the definition in
   * IAiTransportSerializer.cpp for why it no longer needs to do anything.
   */
  int register_IAiTransportSerializer();
} // namespace moho

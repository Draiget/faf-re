#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F378
   */
  class STransportPickUpInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005E4660 (FUN_005E4660, STransportPickUpInfoSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `STransportPickUpInfo` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E4670 (FUN_005E4670, STransportPickUpInfoSerializer::Serialize)
     *
     * What it does:
     * Serializes one `STransportPickUpInfo` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCEE50 (FUN_00BCEE50, dynamic initializer for the global
     * `STransportPickUpInfoSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7STransportPickUpInfoSerializer@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    STransportPickUpInfoSerializer();

    /**
     * Address: 0x00BF8B20 (FUN_00BF8B20, ??1STransportPickUpInfoSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~STransportPickUpInfoSerializer();

    /**
     * What it does:
     * Binds load/save serializer callbacks into `STransportPickUpInfo` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(STransportPickUpInfoSerializer, mLoadCallback) == 0x0C,
    "STransportPickUpInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(STransportPickUpInfoSerializer, mSaveCallback) == 0x10,
    "STransportPickUpInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(STransportPickUpInfoSerializer) == 0x14, "STransportPickUpInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BCEE50 caller lane (`IAiTransport.cpp`'s reflection
   * bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `STransportPickUpInfoSerializer` singleton from an explicit registration
   * sequence. `gSTransportPickUpInfoSerializer` is now a genuine
   * namespace-scope global, so its constructor already runs unconditionally
   * at static-init time; this call is kept only so `IAiTransport.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  int register_STransportPickUpInfoSerializer();
} // namespace moho

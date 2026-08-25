#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F270
   * COL:  0x00E76A74
   */
  class SAiReservedTransportBoneSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005E40A0 (FUN_005E40A0, SAiReservedTransportBoneSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `SAiReservedTransportBone` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E40B0 (FUN_005E40B0, SAiReservedTransportBoneSerializer::Serialize)
     *
     * What it does:
     * Serializes one `SAiReservedTransportBone` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCED90 (FUN_00BCED90, dynamic initializer for the global
     * `SAiReservedTransportBoneSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SAiReservedTransportBoneSerializer@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    SAiReservedTransportBoneSerializer();

    /**
     * Address: 0x00BF8A00 (FUN_00BF8A00, ??1SAiReservedTransportBoneSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SAiReservedTransportBoneSerializer();

    /**
     * Address: 0x005E8F70 (FUN_005E8F70)
     *
     * What it does:
     * Binds load/save serializer callbacks into SAiReservedTransportBone RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mLoadCallback) == 0x0C,
    "SAiReservedTransportBoneSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mSaveCallback) == 0x10,
    "SAiReservedTransportBoneSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SAiReservedTransportBoneSerializer) == 0x14,
    "SAiReservedTransportBoneSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCED90 caller lane (`IAiTransport.cpp`'s reflection
   * bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `SAiReservedTransportBoneSerializer` singleton from an explicit
   * registration sequence. `gSAiReservedTransportBoneSerializer` is now a
   * genuine namespace-scope global, so its constructor already runs
   * unconditionally at static-init time; this call is kept only so
   * `IAiTransport.cpp`'s existing bootstrap sequence does not need editing.
   */
  int register_SAiReservedTransportBoneSerializer();
} // namespace moho

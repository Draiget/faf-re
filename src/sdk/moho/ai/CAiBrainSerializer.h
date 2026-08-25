#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E19A58
   * COL:  0x00E6E5D4
   */
  class CAiBrainSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCB430 (FUN_00BCB430, dynamic initializer for the global
     * `CAiBrainSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiBrainSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here.
     */
    CAiBrainSerializer();

    /**
     * Address: 0x00BF62F0 (FUN_00BF62F0, Moho::CAiBrainSerializer::~CAiBrainSerializer)
     * Address: 0x00579DE0 (FUN_00579DE0), Address: 0x00579E10 (FUN_00579E10)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCB430) as the global's `atexit` teardown.
     */
    ~CAiBrainSerializer();

    /**
     * Address: 0x00579D90 (FUN_00579D90, Moho::CAiBrainSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiBrain::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00579DA0 (FUN_00579DA0, Moho::CAiBrainSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiBrain::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0057E460 (FUN_0057E460)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiBrain RTTI. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CAiBrainSerializer, mLoadCallback) == 0x0C, "CAiBrainSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiBrainSerializer, mSaveCallback) == 0x10, "CAiBrainSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiBrainSerializer) == 0x14, "CAiBrainSerializer size must be 0x14");
} // namespace moho

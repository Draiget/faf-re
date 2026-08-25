// Reconstructed from FA binary evidence (vtable + callsites + decomp).
#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E19134
   *
   * Serializer helper for `CFormationInstance`. Same shape as
   * `CAiBrainSerializer`: an intrusive node in the global serializer chain plus
   * the load/save callbacks that `Init` installs into the reflected type.
   */
  class CFormationInstanceSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x0056A860 (FUN_0056A860, Moho::CFormationInstanceSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CFormationInstance::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0056A870 (FUN_0056A870, Moho::CFormationInstanceSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CFormationInstance::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCAC40 (FUN_00BCAC40, dynamic initializer for the global
     * `CFormationInstanceSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CFormationInstanceSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CFormationInstanceSerializer();

    /**
     * Address: 0x00BF5AA0 (FUN_00BF5AA0, ??1CFormationInstanceSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks the helper node from the intrusive serializer chain and
     * re-points both links at itself, leaving a valid one-element ring.
     */
    ~CFormationInstanceSerializer();

    /**
     * What it does:
     * Binds this helper's load/save callbacks into the `CFormationInstance`
     * type descriptor. Dispatched by `gpg::SerHelperBase::InitNewHelpers`
     * when this helper is drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    // Serializer callbacks consumed by the reflection registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CFormationInstanceSerializer, mLoadCallback) == 0x0C,
    "CFormationInstanceSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CFormationInstanceSerializer, mSaveCallback) == 0x10,
    "CFormationInstanceSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(CFormationInstanceSerializer) == 0x14, "CFormationInstanceSerializer size must be 0x14"
  );
} // namespace moho

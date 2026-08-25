#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1C89C
   * COL:  0x00E72578
   */
  class SContinueInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005B2290 (FUN_005B2290, Moho::SContinueInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SContinueInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B22A0 (FUN_005B22A0, Moho::SContinueInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SContinueInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCD2F0 (FUN_00BCD2F0, dynamic initializer for the global
     * `SContinueInfoSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SContinueInfoSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    SContinueInfoSerializer();

    /**
     * Address: 0x00BF74B0 (FUN_00BF74B0, ??1SContinueInfoSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SContinueInfoSerializer();

    /**
     * Address: 0x005B4820 (FUN_005B4820)
     *
     * What it does:
     * Binds load/save callbacks into reflected `SContinueInfo` metadata.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(SContinueInfoSerializer, mLoadCallback) == 0x0C,
    "SContinueInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SContinueInfoSerializer, mSaveCallback) == 0x10,
    "SContinueInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SContinueInfoSerializer) == 0x14, "SContinueInfoSerializer size must be 0x14");
} // namespace moho

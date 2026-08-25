#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E31298
   */
  class CArmyStatsSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA210 (FUN_00BDA210, register_CArmyStatsSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CArmyStatsSerializer@Moho@@6B@` -- no eager
     * `Init()` call exists here.
     */
    CArmyStatsSerializer();

    /**
     * Address: 0x00BFF850 (FUN_00BFF850, Moho::CArmyStatsSerializer::~CArmyStatsSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CArmyStatsSerializer();

    /**
     * Address: 0x0070E1F0 (FUN_0070E1F0, Moho::CArmyStatsSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback that deserializes `CArmyStats` fields.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070E200 (FUN_0070E200, Moho::CArmyStatsSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback that serializes `CArmyStats` fields.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0070F5E0 (FUN_0070F5E0, gpg::SerSaveLoadHelper_CArmyStats::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CArmyStats RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CArmyStatsSerializer, mLoadCallback) == 0x0C, "CArmyStatsSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CArmyStatsSerializer, mSaveCallback) == 0x10, "CArmyStatsSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CArmyStatsSerializer) == 0x14, "CArmyStatsSerializer size must be 0x14");
} // namespace moho

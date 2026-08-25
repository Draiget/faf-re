#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1D99C
   * COL:  0x00E74204
   */
  class SPerArmyReconInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDBD0 (FUN_00BCDBD0, register_SPerArmyReconInfoSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SPerArmyReconInfoSerializer();

    /**
     * Address: 0x00BF7840 (FUN_00BF7840, Moho::SPerArmyReconInfoSerializer::~SPerArmyReconInfoSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SPerArmyReconInfoSerializer();

    /**
     * Address: 0x005BE4C0 (FUN_005BE4C0, Moho::SPerArmyReconInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SPerArmyReconInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005BE4E0 (FUN_005BE4E0, Moho::SPerArmyReconInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SPerArmyReconInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C3DE0 (FUN_005C3DE0, Moho::SPerArmyReconInfoSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SPerArmyReconInfo` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SPerArmyReconInfoSerializer, mLoadCallback) == 0x0C,
    "SPerArmyReconInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SPerArmyReconInfoSerializer, mSaveCallback) == 0x10,
    "SPerArmyReconInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SPerArmyReconInfoSerializer) == 0x14, "SPerArmyReconInfoSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E1DA64
   * COL:  0x00E73E98
   */
  class ReconBlipSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDCE0 (FUN_00BCDCE0, register_ReconBlipSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields, then registers `cleanup_ReconBlipSerializer`
     * (0x00BF7930, a plain free function -- not a mangled destructor) as
     * the explicit atexit teardown.
     */
    ReconBlipSerializer();

    /**
     * Address: 0x005BFC90 (FUN_005BFC90, Moho::ReconBlipSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback that deserializes `ReconBlip` fields.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005BFCA0 (FUN_005BFCA0, Moho::ReconBlipSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback that serializes `ReconBlip` fields.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C43B0 (FUN_005C43B0, gpg::SerSaveLoadHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into ReconBlip RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(ReconBlipSerializer, mLoadCallback) == 0x0C, "ReconBlipSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipSerializer, mSaveCallback) == 0x10, "ReconBlipSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipSerializer) == 0x14, "ReconBlipSerializer size must be 0x14");
} // namespace moho

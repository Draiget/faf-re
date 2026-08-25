#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3195C
   * COL: 0x00E8E5B4
   */
  class COGridSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDAAB0 (FUN_00BDAAB0, dynamic initializer for the global
     * `COGridSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    COGridSerializer();

    /**
     * Address: 0x00C003E0 (FUN_00C003E0, ??1COGridSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~COGridSerializer();

    /**
     * Address: 0x00722CC0 (FUN_00722CC0, Moho::COGridSerializer::Deserialize)
     *
     * What it does:
     * Registers one pre-created `COGrid` pointer instance in read-archive tracking.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00722D00 (FUN_00722D00, Moho::COGridSerializer::Serialize)
     *
     * What it does:
     * Publishes one pre-created `COGrid` pointer instance into write-archive tracking.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00722F90 (FUN_00722F90, gpg::SerSaveLoadHelper_COGrid::Init)
     *
     * What it does:
     * Resolves `COGrid` RTTI and installs serializer load/save callback lanes.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(COGridSerializer, mLoadCallback) == 0x0C, "COGridSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(COGridSerializer, mSaveCallback) == 0x10, "COGridSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(COGridSerializer) == 0x14, "COGridSerializer size must be 0x14");
} // namespace moho

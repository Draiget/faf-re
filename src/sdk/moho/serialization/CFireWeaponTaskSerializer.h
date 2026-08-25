#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFireWeaponTask;

  /**
   * VFTABLE: 0x00E2E2EC (`??_7CFireWeaponTaskSerializer@Moho@@6B@`)
   */
  class CFireWeaponTaskSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8890 (FUN_00BD8890, dynamic initializer for the global
     * `CFireWeaponTaskSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CFireWeaponTaskSerializer();

    /**
     * Address: 0x00BFE710 (FUN_00BFE710, Moho::CFireWeaponTaskSerializer::~CFireWeaponTaskSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CFireWeaponTaskSerializer();

    /**
     * Address: 0x006D3EF0 (FUN_006D3EF0, Moho::CFireWeaponTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CFireWeaponTask::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D3F00 (FUN_006D3F00, Moho::CFireWeaponTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CFireWeaponTask::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB850 (FUN_006DB850, Moho::CFireWeaponTaskSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `CFireWeaponTask` load/save callbacks into reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(CFireWeaponTaskSerializer, mDeserialize) == 0x0C, "CFireWeaponTaskSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CFireWeaponTaskSerializer, mSerialize) == 0x10, "CFireWeaponTaskSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CFireWeaponTaskSerializer) == 0x14, "CFireWeaponTaskSerializer size must be 0x14");
} // namespace moho

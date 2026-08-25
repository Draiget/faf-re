#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTeleport;

  class CUnitCallTeleportSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCFD20 (FUN_00BCFD20, register_CUnitCallTeleportSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCallTeleportSerializer();

    /**
     * Address: 0x00BF9740 (FUN_00BF9740, Moho::CUnitCallTeleportSerializer::~CUnitCallTeleportSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CUnitCallTeleportSerializer();

    /**
     * Address: 0x006011F0 (FUN_006011F0, Moho::CUnitCallTeleportSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitCallTeleport::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00601200 (FUN_00601200, Moho::CUnitCallTeleportSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitCallTeleport::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00602530 (FUN_00602530)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallTeleport` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCallTeleportSerializer, mDeserialize) == 0x0C,
    "CUnitCallTeleportSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallTeleportSerializer, mSerialize) == 0x10,
    "CUnitCallTeleportSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCallTeleportSerializer) == 0x14, "CUnitCallTeleportSerializer size must be 0x14");
} // namespace moho

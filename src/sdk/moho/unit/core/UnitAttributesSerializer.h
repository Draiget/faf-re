#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct UnitAttributes;

  /**
   * VFTABLE: 0x00E187DC
   * COL: 0x00E73800
   */
  class UnitAttributesSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCA5E0 (FUN_00BCA5E0, register_UnitAttributesSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    UnitAttributesSerializer();

    /**
     * Address: 0x00BF5390 (FUN_00BF5390, Moho::UnitAttributesSerializer::~UnitAttributesSerializer)
     *
     * What it does:
     * Unlinks the serializer helper node and restores self-links.
     */
    ~UnitAttributesSerializer();

    /**
     * Address: 0x0055C350 (FUN_0055C350, Moho::UnitAttributesSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `UnitAttributes::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055C360 (FUN_0055C360, Moho::UnitAttributesSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `UnitAttributes::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055CAE0 (FUN_0055CAE0, gpg::SerSaveLoadHelper<Moho::UnitAttributes>::Init lane)
     *
     * What it does:
     * Binds serializer load/save callbacks into `UnitAttributes` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(UnitAttributesSerializer, mDeserialize) == 0x0C,
    "UnitAttributesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(UnitAttributesSerializer, mSerialize) == 0x10,
    "UnitAttributesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(UnitAttributesSerializer) == 0x14, "UnitAttributesSerializer size must be 0x14");
} // namespace moho

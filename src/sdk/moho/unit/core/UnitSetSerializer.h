#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7EC
   * COL: 0x00E87028
   */
  class UnitSetSerializer
  {
  public:
    /**
     * Address: 0x006D2A00 (FUN_006D2A00, sub_6D2A00)
     *
     * What it does:
     * Deserializes one `EntitySetTemplate<Unit>` payload using `EntitySetBase` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2A40 (FUN_006D2A40, sub_6D2A40)
     *
     * What it does:
     * Serializes one `EntitySetTemplate<Unit>` payload using `EntitySetBase` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2D90 (FUN_006D2D90, sub_6D2D90)
     *
     * What it does:
     * Binds `EntitySetTemplate<Unit>` RTTI serializer callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(UnitSetSerializer, mHelperNext) == 0x04, "UnitSetSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitSetSerializer, mHelperPrev) == 0x08, "UnitSetSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(UnitSetSerializer, mDeserialize) == 0x0C, "UnitSetSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(UnitSetSerializer, mSerialize) == 0x10, "UnitSetSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UnitSetSerializer) == 0x14, "UnitSetSerializer size must be 0x14");

  /**
   * Address: 0x00BFE450 (FUN_00BFE450, sub_BFE450)
   *
   * What it does:
   * Unlinks `UnitSetSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitSetSerializer();

  /**
   * Address: 0x00BD8480 (FUN_00BD8480, sub_BD8480)
   *
   * What it does:
   * Initializes `UnitSetSerializer`, binds callbacks, and registers exit cleanup.
   */
  int register_UnitSetSerializer();
} // namespace moho

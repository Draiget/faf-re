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
   * VFTABLE: 0x00E2D82C
   * COL: 0x00E86F2C
   */
  class WeakUnitSetSerializer
  {
  public:
    /**
     * Address: 0x006D2C50 (FUN_006D2C50, sub_6D2C50)
     *
     * What it does:
     * Deserializes one weak unit-set payload through `EntitySetTemplate<Unit>` RTTI.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2C90 (FUN_006D2C90, sub_6D2C90)
     *
     * What it does:
     * Serializes one weak unit-set payload through `EntitySetTemplate<Unit>` RTTI.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D2E30 (FUN_006D2E30, sub_6D2E30)
     *
     * What it does:
     * Binds `WeakEntitySetTemplate<Unit>` RTTI serializer callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(WeakUnitSetSerializer, mHelperNext) == 0x04, "WeakUnitSetSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(WeakUnitSetSerializer, mHelperPrev) == 0x08, "WeakUnitSetSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(WeakUnitSetSerializer, mDeserialize) == 0x0C, "WeakUnitSetSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(WeakUnitSetSerializer, mSerialize) == 0x10, "WeakUnitSetSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(WeakUnitSetSerializer) == 0x14, "WeakUnitSetSerializer size must be 0x14");

  /**
   * Address: 0x00BFE4E0 (FUN_00BFE4E0, sub_BFE4E0)
   *
   * What it does:
   * Unlinks `WeakUnitSetSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_WeakUnitSetSerializer();

  /**
   * Address: 0x00BD84E0 (FUN_00BD84E0, sub_BD84E0)
   *
   * What it does:
   * Initializes `WeakUnitSetSerializer`, binds callbacks, and registers exit cleanup.
   */
  int register_WeakUnitSetSerializer();
} // namespace moho

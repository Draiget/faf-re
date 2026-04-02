#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
  class SerConstructResult;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E1C0F0
   * COL:  0x00E7162C
   */
  class CAiNavigatorLandConstruct
  {
  public:
    /**
     * Address: 0x005A4730 (FUN_005A4730, construct callback)
     *
     * What it does:
     * Allocates one `CAiNavigatorLand` and publishes it as unowned construct
     * result payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005A7DF0 (FUN_005A7DF0, delete callback)
     *
     * What it does:
     * Deletes one constructed `CAiNavigatorLand` object when present.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005A73B0 (FUN_005A73B0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiNavigatorLand RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiNavigatorLandConstruct, mHelperNext) == 0x04,
    "CAiNavigatorLandConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mHelperPrev) == 0x08,
    "CAiNavigatorLandConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mConstructCallback) == 0x0C,
    "CAiNavigatorLandConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mDeleteCallback) == 0x10,
    "CAiNavigatorLandConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorLandConstruct) == 0x14, "CAiNavigatorLandConstruct size must be 0x14");

  /**
   * Address: 0x00BCC7A0 (FUN_00BCC7A0, register_CAiNavigatorLandConstruct)
   *
   * What it does:
   * Initializes the global CAiNavigatorLand construct helper callbacks and
   * installs process-exit cleanup.
   */
  int register_CAiNavigatorLandConstruct();
} // namespace moho

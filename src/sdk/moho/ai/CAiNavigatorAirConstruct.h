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
   * VFTABLE: 0x00E1C140
   * COL:  0x00E71484
   */
  class CAiNavigatorAirConstruct
  {
  public:
    /**
      * Alias of FUN_005A5630 (non-canonical helper lane).
     *
     * What it does:
     * Allocates one `CAiNavigatorAir` and publishes it as unowned construct
     * result payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005A7ED0 (FUN_005A7ED0, delete callback)
     *
     * What it does:
     * Deletes one constructed `CAiNavigatorAir` object when present.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005A74D0 (FUN_005A74D0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiNavigatorAir RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiNavigatorAirConstruct, mHelperNext) == 0x04,
    "CAiNavigatorAirConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorAirConstruct, mHelperPrev) == 0x08,
    "CAiNavigatorAirConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorAirConstruct, mConstructCallback) == 0x0C,
    "CAiNavigatorAirConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorAirConstruct, mDeleteCallback) == 0x10,
    "CAiNavigatorAirConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorAirConstruct) == 0x14, "CAiNavigatorAirConstruct size must be 0x14");

  /**
   * Address: 0x00BCC840 (FUN_00BCC840, register_CAiNavigatorAirConstruct)
   *
   * What it does:
   * Initializes the global CAiNavigatorAir construct helper callbacks and
   * installs process-exit cleanup.
   */
  int register_CAiNavigatorAirConstruct();
} // namespace moho


#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class SerConstructResult;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1B7FC
   * COL:  0x00E70D48
   */
  class CAiBuilderImplConstruct
  {
  public:
    /**
     * Address: 0x0059FD80 (FUN_0059FD80, construct callback)
     *
     * What it does:
     * Allocates one `CAiBuilderImpl` and publishes it as unowned construct
     * result payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005A1C80 (FUN_005A1C80, delete callback)
     *
     * What it does:
     * Releases one `CAiBuilderImpl` object created by construct callback
     * lanes.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005A0650 (FUN_005A0650)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiBuilderImpl RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiBuilderImplConstruct, mHelperNext) == 0x04, "CAiBuilderImplConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiBuilderImplConstruct, mHelperPrev) == 0x08, "CAiBuilderImplConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiBuilderImplConstruct, mConstructCallback) == 0x0C,
    "CAiBuilderImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiBuilderImplConstruct, mDeleteCallback) == 0x10,
    "CAiBuilderImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiBuilderImplConstruct) == 0x14, "CAiBuilderImplConstruct size must be 0x14");

  /**
   * Address: 0x00BCC2E0 (FUN_00BCC2E0)
   *
   * What it does:
   * Initializes the global CAiBuilderImpl construct helper callbacks and
   * installs process-exit cleanup.
   */
  int register_CAiBuilderImplConstruct();
} // namespace moho

#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1EAD4
   * COL: 0x00E75858
   */
  class CAiAttackerImplConstruct
  {
  public:
    /**
     * Address: 0x005D8390 (FUN_005D8390)
     *
     * What it does:
     * Constructs a recovered `CAiAttackerImpl` object for archive loading.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005DEB50 (FUN_005DEB50)
     *
     * What it does:
     * Deletes one recovered `CAiAttackerImpl` object.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005DC050 (FUN_005DC050)
     *
     * What it does:
     * Binds construct/delete callbacks into `CAiAttackerImpl` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(CAiAttackerImplConstruct, mHelperNext) == 0x04, "CAiAttackerImplConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(CAiAttackerImplConstruct, mHelperPrev) == 0x08, "CAiAttackerImplConstruct::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CAiAttackerImplConstruct, mConstructCallback) == 0x0C, "CAiAttackerImplConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CAiAttackerImplConstruct, mDeleteCallback) == 0x10, "CAiAttackerImplConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(CAiAttackerImplConstruct) == 0x14, "CAiAttackerImplConstruct size must be 0x14");

  /**
   * Address: 0x00BCE890 (FUN_00BCE890, register_CAiAttackerImplConstruct)
   *
   * What it does:
   * Constructs the recovered `CAiAttackerImpl` construct helper and installs
   * process-exit cleanup.
   */
  int register_CAiAttackerImplConstruct();
} // namespace moho

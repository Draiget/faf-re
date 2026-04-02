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
   * VFTABLE: 0x00E1B3F8
   * COL:  0x00E70430
   */
  class IAiCommandDispatchImplConstruct
  {
  public:
    /**
     * Address: 0x00599320 (FUN_00599320, Moho::IAiCommandDispatchImplConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback arguments into
     * `IAiCommandDispatchImpl::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005999D0 (FUN_005999D0, Moho::IAiCommandDispatchImplConstruct::Deconstruct)
     *
     * What it does:
     * Deletes one recovered command-dispatch object through its deleting
     * destructor lane.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x00599650 (FUN_00599650)
     *
     * What it does:
     * Binds construct/delete callbacks into IAiCommandDispatchImpl RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;             // +0x04
    gpg::SerHelperBase* mHelperPrev;             // +0x08
    gpg::RType::construct_func_t mConstructFunc; // +0x0C
    gpg::RType::delete_func_t mDeleteFunc;       // +0x10
  };

  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mHelperNext) == 0x04,
    "IAiCommandDispatchImplConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mHelperPrev) == 0x08,
    "IAiCommandDispatchImplConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mConstructFunc) == 0x0C,
    "IAiCommandDispatchImplConstruct::mConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplConstruct, mDeleteFunc) == 0x10,
    "IAiCommandDispatchImplConstruct::mDeleteFunc offset must be 0x10"
  );
  static_assert(sizeof(IAiCommandDispatchImplConstruct) == 0x14, "IAiCommandDispatchImplConstruct size must be 0x14");

  /**
   * Address: 0x00BCBEC0 (FUN_00BCBEC0, register_IAiCommandDispatchImplConstruct)
   *
   * What it does:
   * Initializes recovered construct helper storage/callback lanes and installs
   * process-exit unlink cleanup.
   */
  void register_IAiCommandDispatchImplConstruct();
} // namespace moho

#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1DE38
   * COL:  0x00E748A4
   */
  class CAiSiloBuildImplConstruct
  {
  public:
    /**
     * Address: 0x005CF840 (FUN_005CF840, Moho::CAiSiloBuildImplConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `CAiSiloBuildImpl::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005D0870 (FUN_005D0870, Moho::CAiSiloBuildImplConstruct::Deconstruct)
     *
     * What it does:
     * Deletes one constructed `CAiSiloBuildImpl` object.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x005CFEB0 (FUN_005CFEB0)
     *
     * void ()
     *
     * IDA signature:
     * int __thiscall sub_5CFEB0(_DWORD *this);
     *
     * What it does:
     * Binds construct/delete callbacks into CAiSiloBuildImpl RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;             // +0x04
    gpg::SerHelperBase* mHelperPrev;             // +0x08
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;   // +0x10
  };

  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mHelperNext) == 0x04,
    "CAiSiloBuildImplConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mHelperPrev) == 0x08,
    "CAiSiloBuildImplConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mConstructCallback) == 0x0C,
    "CAiSiloBuildImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiSiloBuildImplConstruct, mDeleteCallback) == 0x10,
    "CAiSiloBuildImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiSiloBuildImplConstruct) == 0x14, "CAiSiloBuildImplConstruct size must be 0x14");

  /**
   * Address: 0x00BCE110 (FUN_00BCE110, register_CAiSiloBuildImplConstruct)
   *
   * What it does:
   * Registers construct/delete callbacks for `CAiSiloBuildImpl` and installs
   * process-exit cleanup.
   */
  int register_CAiSiloBuildImplConstruct();
} // namespace moho

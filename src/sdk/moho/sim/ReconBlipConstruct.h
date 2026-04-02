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
   * VFTABLE: 0x00E1DA54
   * COL:  0x00E73F44
   */
  class ReconBlipConstruct
  {
  public:
    /**
     * Address: 0x005BFBC0 (FUN_005BFBC0, Moho::ReconBlipConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `ReconBlip::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into ReconBlip RTTI.
     */
    virtual void RegisterConstructFunction();

    /**
     * Address: 0x005C9070 (FUN_005C9070, Moho::ReconBlipConstruct::Deconstruct)
     *
     * What it does:
     * Releases one constructed object through its deleting-destructor vtable
     * entry when the pointer is non-null.
     */
    static void DeleteConstructedObject(void* objectPtr);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(ReconBlipConstruct, mHelperNext) == 0x04, "ReconBlipConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mHelperPrev) == 0x08, "ReconBlipConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mConstructCallback) == 0x0C,
    "ReconBlipConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mDeleteCallback) == 0x10, "ReconBlipConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipConstruct) == 0x14, "ReconBlipConstruct size must be 0x14");

  /**
   * Address: 0x00BCDCA0 (FUN_00BCDCA0, register_ReconBlipConstruct)
   *
   * What it does:
   * Initializes ReconBlip construct helper callback lanes, binds them into
   * reflected RTTI, and installs process-exit cleanup.
   */
  void register_ReconBlipConstruct();
} // namespace moho

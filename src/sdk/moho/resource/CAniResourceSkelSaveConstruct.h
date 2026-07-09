#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RRef;
  struct SerHelperBase;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAniResourceSkel;

  /**
   * VFTABLE: 0x00E16340
   * COL: 0x00E6A95C
   */
  class CAniResourceSkelSaveConstruct
  {
  public:
    /**
     * Address: 0x005386F0 (FUN_005386F0, Moho::CAniResourceSkelSaveConstruct::Construct)
     *
     * What it does:
     * Save-construct-args callback: writes the resource's mounted model path
     * into the archive and marks the result payload as shared.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      CAniResourceSkel* resource,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00539500 (FUN_00539500, gpg::SerSaveConstructHelper_CAniResourceSkel::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CAniResourceSkel` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  /**
   * Address: 0x00BC9080 (FUN_00BC9080, register_CAniResourceSkelSaveConstruct)
   *
   * What it does:
   * Initializes the global save-construct helper node, installs `&Construct`
   * as the save-construct-args callback, and schedules helper-node teardown at
   * process exit.
   */
  void register_CAniResourceSkelSaveConstruct();

  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mHelperNext) == 0x04,
    "CAniResourceSkelSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mHelperPrev) == 0x08,
    "CAniResourceSkelSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CAniResourceSkelSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CAniResourceSkelSaveConstruct) == 0x10, "CAniResourceSkelSaveConstruct size must be 0x10");
} // namespace moho

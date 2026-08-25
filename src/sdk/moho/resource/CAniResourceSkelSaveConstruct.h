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
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CAniResourceSkelSaveConstruct@Moho'`): `FUN_00BC9080`
   * (real, sole writer, `__xc_a`-reachable). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds
   * `mSerSaveConstructArgsFunc` to `FUN_005386F0`, installs the
   * `CAniResourceSkelSaveConstruct` vtable, and pushes the real mangled
   * destructor `??1CAniResourceSkelSaveConstruct@Moho@@QAE@@Z`
   * (`FUN_00BF3B80`, confirmed unlink-then-self-link shape matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- no eager
   * `RegisterSaveConstructArgsFunction`/`Init()` call exists in the real
   * ctor; that call was fabricated in the previous recovery's
   * `register_CAniResourceSkelSaveConstruct()` free function (its own
   * comment admitted the deviation: "the binary splits this into a
   * separate helper... invoking it here keeps the callback installed").
   * Removed; `Init()` is dispatched normally via `SerHelperBase::
   * InitNewHelpers()`. Two zero-xref duplicate emissions of the unlink
   * logic (`FUN_00538710`, `FUN_00538740`, formerly
   * `CleanupCAniResourceSkelSaveConstructHelperNodePrimary/Secondary`) are
   * dead ICF twins, sha256-identical to the real destructor.
   */
  class CAniResourceSkelSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9080 (FUN_00BC9080, dynamic initializer for the global
     * `CAniResourceSkelSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    CAniResourceSkelSaveConstruct();

    /**
     * Address: 0x00BF3B80 (FUN_00BF3B80, Moho::CAniResourceSkelSaveConstruct::~CAniResourceSkelSaveConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CAniResourceSkelSaveConstruct();

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
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc; // +0x0C
  };

  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CAniResourceSkelSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CAniResourceSkelSaveConstruct) == 0x10, "CAniResourceSkelSaveConstruct size must be 0x10");
} // namespace moho

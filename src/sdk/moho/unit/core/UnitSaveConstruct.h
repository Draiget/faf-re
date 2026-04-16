#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class Unit;

  /**
   * Reflection helper node used to bind `moho::Unit` save-construct-args
   * behavior into RTTI.
   *
   * Size evidence:
   * - The startup lane at `0x00BD6AF0` writes two intrusive helper links plus
   *   one callback pointer.
   */
  class UnitSaveConstruct
  {
  public:
    /**
     * Address: 0x006AE920 (FUN_006AE920, Moho::UnitSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * Binds the `moho::Unit` save-construct-args callback into RTTI using
     * `typeid(moho::Unit)`.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(offsetof(UnitSaveConstruct, mHelperNext) == 0x04, "UnitSaveConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitSaveConstruct, mHelperPrev) == 0x08, "UnitSaveConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(UnitSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "UnitSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(UnitSaveConstruct) == 0x10, "UnitSaveConstruct size must be 0x10");

  /**
   * Address: 0x00BFD9D0 (FUN_00BFD9D0, cleanup_UnitSaveConstruct)
   *
   * What it does:
   * Unlinks the `UnitSaveConstruct` helper node from the intrusive list and
   * restores self-links.
  */
  gpg::SerHelperBase* cleanup_UnitSaveConstruct();

  /**
   * Address: 0x00BD6AF0 (FUN_00BD6AF0, register_UnitSaveConstruct)
   *
   * What it does:
   * Initializes the `UnitSaveConstruct` helper node and registers its callback
   * lane during startup.
   */
  void register_UnitSaveConstruct();
} // namespace moho

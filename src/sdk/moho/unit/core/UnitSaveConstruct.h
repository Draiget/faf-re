#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class Unit;

  /**
   * Reflection helper singleton that binds `moho::Unit` save-construct-args
   * behavior into RTTI.
   *
   * RTTI Class Hierarchy Descriptor shows this class's base chain running
   * through `.?AU?$SerSaveConstructHelper@VUnit@Moho@@@gpg@@` before
   * `gpg::SerHelperBase` -- a different template family than
   * `SerSaveLoadHelper`/`PrimitiveSerHelper` (construct-args callback
   * instead of load/save), with only this one confirmed instantiation.
   * Not worth introducing a new one-instantiation template for; kept as a
   * concrete `SerHelperBase`-derived class, matching the
   * `CUnitCommandConstruct` precedent for the sibling construct/delete
   * template family.
   */
  class UnitSaveConstruct final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6AF0 (FUN_00BD6AF0, register_UnitSaveConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    UnitSaveConstruct();

    /**
     * Address: 0x00BFD9D0 (FUN_00BFD9D0, cleanup_UnitSaveConstruct)
     *
     * What it does:
     * Unlinks the `UnitSaveConstruct` helper node from the intrusive list and
     * restores self-links.
     */
    ~UnitSaveConstruct();

    /**
     * Address: 0x006AE920 (FUN_006AE920, Moho::UnitSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * Binds the `moho::Unit` save-construct-args callback into RTTI using
     * `typeid(moho::Unit)`.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(UnitSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "UnitSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(UnitSaveConstruct) == 0x10, "UnitSaveConstruct size must be 0x10");
} // namespace moho

#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class WriteArchive;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E26F74
   * COL: 0x00E994DC
   */
  class CollisionBeamEntitySaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4C60 (FUN_00BD4C60, dynamic initializer for the global
     * `CollisionBeamEntitySaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the save-construct-args callback field.
     */
    CollisionBeamEntitySaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CollisionBeamEntitySaveConstruct();

    /**
     * Address: 0x006738A0 (FUN_006738A0, CollisionBeamEntity save-construct args callback)
     *
     * What it does:
     * Serializes owning `Sim` pointer as unowned save-construct argument.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00674EE0 (FUN_00674EE0, gpg::SerSaveConstructHelper_CollisionBeamEntity::Init)
     *
     * What it does:
     * Binds save-construct-args callback lane into `CollisionBeamEntity` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CollisionBeamEntitySaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CollisionBeamEntitySaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(
    sizeof(CollisionBeamEntitySaveConstruct) == 0x10,
    "CollisionBeamEntitySaveConstruct size must be 0x10"
  );
} // namespace moho

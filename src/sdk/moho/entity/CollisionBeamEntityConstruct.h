#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E26F84
   * COL: 0x00E994B8
   */
  class CollisionBeamEntityConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4C90 (FUN_00BD4C90, dynamic initializer for the global
     * `CollisionBeamEntityConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the construct/delete callback fields.
     */
    CollisionBeamEntityConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CollisionBeamEntityConstruct();

    /**
     * Address: 0x00673A30 (FUN_00673A30, Moho::CollisionBeamEntityConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `CollisionBeamEntity::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00675570 (FUN_00675570, Moho::CollisionBeamEntityConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `CollisionBeamEntity`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00674F60 (FUN_00674F60, gpg::SerConstructHelper_CollisionBeamEntity::Init)
     *
     * What it does:
     * Asserts `CollisionBeamEntity`'s reflected construct callback is not
     * already bound, then installs the construct/delete callback lanes into
     * `CollisionBeamEntity` RTTI. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(CollisionBeamEntityConstruct, mConstructCallback) == 0x0C,
    "CollisionBeamEntityConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CollisionBeamEntityConstruct, mDeleteCallback) == 0x10,
    "CollisionBeamEntityConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CollisionBeamEntityConstruct) == 0x14, "CollisionBeamEntityConstruct size must be 0x14");
} // namespace moho

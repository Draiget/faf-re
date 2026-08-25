#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CollisionBeamEntity;

  /**
   * VFTABLE: 0x00E26F94
   * COL: 0x00E99494
   */
  class CollisionBeamEntitySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4CD0 (FUN_00BD4CD0, dynamic initializer for the global
     * `CollisionBeamEntitySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields.
     */
    CollisionBeamEntitySerializer();

    /**
     * Address: 0x00BFC3A0 (FUN_00BFC3A0, Moho::CollisionBeamEntitySerializer::~CollisionBeamEntitySerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CollisionBeamEntitySerializer();

    /**
     * Address: 0x00673B00 (FUN_00673B00, Moho::CollisionBeamEntitySerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load into `CollisionBeamEntity::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00673B10 (FUN_00673B10, Moho::CollisionBeamEntitySerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save into `CollisionBeamEntity::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00674FE0 (FUN_00674FE0, gpg::SerSaveLoadHelper_CollisionBeamEntity::Init)
     *
     * What it does:
     * Binds `CollisionBeamEntity` RTTI load/save callback lanes. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CollisionBeamEntitySerializer, mDeserialize) == 0x0C,
    "CollisionBeamEntitySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CollisionBeamEntitySerializer, mSerialize) == 0x10,
    "CollisionBeamEntitySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CollisionBeamEntitySerializer) == 0x14, "CollisionBeamEntitySerializer size must be 0x14");
} // namespace moho

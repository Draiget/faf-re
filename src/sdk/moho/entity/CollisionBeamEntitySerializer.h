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
  class CollisionBeamEntitySerializer
  {
  public:
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
     * Binds `CollisionBeamEntity` RTTI load/save callback lanes.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CollisionBeamEntitySerializer, mHelperLinks) == 0x04,
    "CollisionBeamEntitySerializer::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CollisionBeamEntitySerializer, mDeserialize) == 0x0C,
    "CollisionBeamEntitySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CollisionBeamEntitySerializer, mSerialize) == 0x10,
    "CollisionBeamEntitySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CollisionBeamEntitySerializer) == 0x14, "CollisionBeamEntitySerializer size must be 0x14");

  /**
   * Address: 0x00BFC3A0 (FUN_00BFC3A0, Moho::CollisionBeamEntitySerializer::~CollisionBeamEntitySerializer)
   *
   * What it does:
   * Unlinks the startup serializer helper-node lane and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySerializer();

  /**
   * Address: 0x00BD4CD0 (FUN_00BD4CD0, register_CollisionBeamEntitySerializer)
   *
   * What it does:
   * Initializes startup serializer helper and callback lanes for
   * `CollisionBeamEntity`.
   */
  void register_CollisionBeamEntitySerializer();
} // namespace moho

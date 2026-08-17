// Reconstructed from FA binary evidence (vtable + callsites + decomp).
#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * Serializer helper for `Entity`. Same `SerHelperBase` shape as
   * `CAiBrainSerializer` and `CFormationInstanceSerializer`: an intrusive node
   * in the global serializer chain plus the load/save callbacks that
   * `RegisterSerializeFunctions` installs into the reflected type.
   */
  class EntitySerializer
  {
  public:
    /**
     * Address: 0x0067B630 (FUN_0067B630, Moho::EntitySerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `Entity::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0067B640 (FUN_0067B640, Moho::EntitySerializer::Serialize)
     * Address: 0x006807A0 (FUN_006807A0)
     * Address: 0x0067F640 (FUN_0067F640)
     *
     * What it does:
     * Forwards archive saving into `Entity::MemberSerialize`. The three
     * addresses are byte-identical emissions of this one adapter.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds this helper's load/save callbacks into the `Entity` type
     * descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by the reflection registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(EntitySerializer, mHelperNext) == 0x04, "EntitySerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(EntitySerializer, mHelperPrev) == 0x08, "EntitySerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(EntitySerializer, mLoadCallback) == 0x0C, "EntitySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EntitySerializer, mSaveCallback) == 0x10, "EntitySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(EntitySerializer) == 0x14, "EntitySerializer size must be 0x14");

  /**
   * Address: 0x00BD5050 (FUN_00BD5050, register_EntitySerializer)
   *
   * What it does:
   * Initializes the global `Entity` serializer helper, binds its load/save
   * callbacks, and installs process-exit cleanup.
   */
  void register_EntitySerializer();
} // namespace moho

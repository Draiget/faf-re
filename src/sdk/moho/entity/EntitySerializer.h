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
   * Serializer helper for `Entity`.
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='EntitySerializer@Moho'`): `FUN_00BD5050`
   * (`__xc_a`-reachable, plain unlink atexit target `FUN_00BFC870`,
   * modeled as the compiler's implicit static-destructor registration).
   * The real `Init()` body (`FUN_0067C600`, found via the class's own
   * vtable slot-0 data xref) demangles as `gpg::SerSaveLoadHelper_Entity::
   * Init` and is ICF-shared with `gpg::SerSaveLoadHelper<Moho::Entity>`'s
   * own vtable slot -- it was previously duplicated (uncalled, orphaned)
   * in `Entity.cpp` as `InstallEntitySerializerCallbacks`, reached through
   * a generic `SerSaveLoadHelperInitRuntimeView*` reach-in parameter
   * instead of `this`.
   */
  class EntitySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD5050 (FUN_00BD5050, dynamic initializer for the global
     * `EntitySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    EntitySerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~EntitySerializer();

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
     * Address: 0x0067C600 (FUN_0067C600, gpg::SerSaveLoadHelper_Entity::Init)
     *
     * What it does:
     * Binds this helper's load/save callbacks into the `Entity` type
     * descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(EntitySerializer, mLoadCallback) == 0x0C, "EntitySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EntitySerializer, mSaveCallback) == 0x10, "EntitySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(EntitySerializer) == 0x14, "EntitySerializer size must be 0x14");
} // namespace moho

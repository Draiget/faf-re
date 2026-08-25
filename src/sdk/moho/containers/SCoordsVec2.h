#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SCoordsVec2
  {
    static gpg::RType* sType;

    float x;
    float z;
  };

  /**
   * Owns reflected metadata for `SCoordsVec2`.
   */
  class SCoordsVec2TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050BBD0 (FUN_0050BBD0, Moho::SCoordsVec2TypeInfo::SCoordsVec2TypeInfo)
     *
     * What it does:
     * Preregisters the `SCoordsVec2` RTTI descriptor with the reflection map.
     */
    SCoordsVec2TypeInfo();

    /**
     * Address: 0x00BF20B0 (FUN_00BF20B0, Moho::SCoordsVec2TypeInfo::dtr)
     *
     * What it does:
     * Releases the reflected field and base vector storage.
     */
    ~SCoordsVec2TypeInfo() override;

    /**
     * Address: 0x0050BC50 (FUN_0050BC50, Moho::SCoordsVec2TypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SCoordsVec2`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BC30 (FUN_0050BC30, Moho::SCoordsVec2TypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size and finalizes the type.
     */
    void Init() override;
  };

  /**
   * Serializer helper for `SCoordsVec2` archive lanes.
   *
   * RTTI (`dumps/rtti_dump_all.hpp`) shows the real inheritance chain as
   * `SerHelperBase -> SerSaveLoadHelper<SCoordsVec2> -> SCoordsVec2Serializer`
   * (every base at `mdisp=0`, single inheritance) -- but `SCoordsVec2` has
   * no `MemberDeserialize`/`MemberSerialize` of its own, so this class fully
   * overrides `Init()`/`Deserialize`/`Serialize` rather than using the
   * generic template bodies. Modeled as directly inheriting `SerHelperBase`
   * (same prior-art judgment call as `Rect2iSerializer`/`Rect2fSerializer`
   * in Reflection.h): the intermediate template level adds zero data or
   * behavior this class doesn't already fully override.
   */
  class SCoordsVec2Serializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC7CE0 (FUN_00BC7CE0, dynamic initializer for the global
     * `SCoordsVec2Serializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SCoordsVec2Serializer();

    /**
     * Address: 0x00BF2110 (FUN_00BF2110, Moho::SCoordsVec2Serializer::~SCoordsVec2Serializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The real ctor
     * pushes this mangled destructor symbol as its atexit target.
     */
    ~SCoordsVec2Serializer();

    /**
     * Address: 0x0050BD10 (FUN_0050BD10, Moho::SCoordsVec2Serializer::Deserialize)
     *
     * What it does:
     * Loads the 2D coordinate lanes from archive storage in binary order.
     */
    static void Deserialize(gpg::ReadArchive* archive, SCoordsVec2* coords);

    /**
     * Address: 0x0050BD40 (FUN_0050BD40, Moho::SCoordsVec2Serializer::Serialize)
     *
     * What it does:
     * Stores the 2D coordinate lanes to archive storage in binary order.
     */
    static void Serialize(gpg::WriteArchive* archive, SCoordsVec2* coords);

    /**
     * Address: 0x0050C730 (FUN_0050C730) -- shared vtable slot 0 target for
     * both `??_7SCoordsVec2Serializer@Moho@@6B@` and the
     * `SerSaveLoadHelper<SCoordsVec2>` intermediate vtable (confirmed via
     * `data_refs` on both vtable heads).
     *
     * What it does:
     * Lazily resolves `SCoordsVec2`'s RTTI onto `SCoordsVec2::sType`, then
     * installs this helper's load/save callbacks onto that type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(offsetof(SCoordsVec2Serializer, mDeserialize) == 0x0C, "SCoordsVec2Serializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SCoordsVec2Serializer, mSerialize) == 0x10, "SCoordsVec2Serializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SCoordsVec2Serializer) == 0x14, "SCoordsVec2Serializer size must be 0x14");
  static_assert(sizeof(SCoordsVec2TypeInfo) == 0x64, "SCoordsVec2TypeInfo size must be 0x64");
  static_assert(sizeof(SCoordsVec2) == 0x08, "SCoordsVec2 size must be 0x08");
  static_assert(offsetof(SCoordsVec2, x) == 0x00, "SCoordsVec2::x offset must be 0x00");
  static_assert(offsetof(SCoordsVec2, z) == 0x04, "SCoordsVec2::z offset must be 0x04");

  /**
   * Address: 0x00BC7CC0 (FUN_00BC7CC0, register_SCoordsVec2TypeInfo)
   *
   * What it does:
   * Installs the static `SCoordsVec2TypeInfo` instance and its shutdown hook.
   */
  void register_SCoordsVec2TypeInfo();
} // namespace moho

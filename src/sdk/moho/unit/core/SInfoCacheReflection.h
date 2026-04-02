#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E2D7BC
   * COL: 0x00E870C0
   */
  class SInfoCacheTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006A4E60 (FUN_006A4E60, sub_6A4E60)
     *
     * What it does:
     * Constructs and preregisters RTTI metadata for `SInfoCache`.
     */
    SInfoCacheTypeInfo();

    /**
     * Address: 0x006A4EF0 (FUN_006A4EF0, sub_6A4EF0)
     *
     * What it does:
     * Releases reflected `SInfoCacheTypeInfo` field/base vectors and restores the
     * base `RObject` vtable lane during teardown.
     */
    ~SInfoCacheTypeInfo() override;

    /**
     * Address: 0x006A4EC0 (FUN_006A4EC0, Moho::SInfoCacheTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size metadata for `SInfoCache` and finalizes the type.
     */
    void Init() override;

    /**
     * Address: 0x006A4EE0 (FUN_006A4EE0, Moho::SInfoCacheTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflection type-name literal for `SInfoCache`.
     */
    [[nodiscard]] const char* GetName() const override;
  };

  static_assert(sizeof(SInfoCacheTypeInfo) == 0x64, "SInfoCacheTypeInfo size must be 0x64");

  /**
   * Address: 0x006A4E60 (FUN_006A4E60, sub_6A4E60)
   *
   * What it does:
   * Ensures the global `SInfoCacheTypeInfo` singleton is constructed and preregistered.
   */
  [[nodiscard]] gpg::RType* construct_SInfoCacheTypeInfo();

  /**
   * Address: 0x00BFD8E0 (FUN_00BFD8E0, sub_BFD8E0)
   *
   * What it does:
   * Releases reflected `SInfoCacheTypeInfo` field/base vectors at exit.
   */
  void cleanup_SInfoCacheTypeInfo();

  /**
   * Address: 0x00BD6A70 (FUN_00BD6A70, register_SInfoCacheTypeInfo)
   *
   * What it does:
   * Forces `SInfoCacheTypeInfo` construction and schedules exit cleanup.
   */
  int register_SInfoCacheTypeInfo();

  /**
   * VFTABLE: 0x00E2D7F8
   * COL: 0x00E870E8
   */
  class SInfoCacheSerializer final
  {
  public:
    /**
     * Address: 0x006B04B0 (FUN_006B04B0, Moho::SInfoCacheSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `SInfoCache` pointer lanes and scalar/vector payload.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006B0580 (FUN_006B0580, Moho::SInfoCacheSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `SInfoCache` pointer lanes and scalar/vector payload.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BD6A90 (FUN_00BD6A90, register_SInfoCacheSerializer)
     *
     * What it does:
     * Binds `SInfoCache` load/save callbacks into its RTTI descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(SInfoCacheSerializer, mHelperNext) == 0x04, "SInfoCacheSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SInfoCacheSerializer, mHelperPrev) == 0x08, "SInfoCacheSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SInfoCacheSerializer, mDeserialize) == 0x0C, "SInfoCacheSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SInfoCacheSerializer, mSerialize) == 0x10, "SInfoCacheSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SInfoCacheSerializer) == 0x14, "SInfoCacheSerializer size must be 0x14");

  /**
   * Address: 0x00BFD940 (FUN_00BFD940, sub_BFD940)
   *
   * What it does:
   * Unlinks `SInfoCacheSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SInfoCacheSerializer();

  /**
   * Address: 0x00BD6A90 (FUN_00BD6A90, register_SInfoCacheSerializer)
   *
   * What it does:
   * Initializes and registers `SInfoCache` serializer callbacks.
   */
  void register_SInfoCacheSerializer();
} // namespace moho

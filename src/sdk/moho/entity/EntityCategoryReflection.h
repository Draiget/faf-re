#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/BVSet.h"

namespace moho
{
  class RBlueprint;

  /**
   * Reflection helper value serialized ahead of category bitset payload.
   *
   * Address: 0x0052B780 (FUN_0052B780, EntityCategoryHelperTypeInfo::Init)
   */
  struct EntityCategoryHelper
  {
    static gpg::RType* sType;

    std::uint32_t mWordUniverseHandle{0}; // +0x00

    /**
     * Address family:
     * - 0x005563D2/0x00556870/0x005567F0 callsites (lazy cache usage)
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();
  };
  static_assert(sizeof(EntityCategoryHelper) == 0x04, "EntityCategoryHelper size must be 0x04");

  using EntityCategorySet = BVSet<const RBlueprint*, EntityCategoryHelper>;
  static_assert(sizeof(EntityCategorySet) == 0x28, "EntityCategorySet size must be 0x28");

  /**
   * Address family:
   * - 0x005567F0 (FUN_005567F0, SerSave)
   * - 0x00556870 (FUN_00556870, SerLoad)
   */
  class EntityCategory
  {
  public:
    /**
     * Address: 0x005567F0 (FUN_005567F0, Moho::EntityCategory::SerSave)
     *
     * What it does:
     * Serializes helper dword (+0x00) and BVIntSet payload (+0x08).
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);

    /**
     * Address: 0x00556870 (FUN_00556870, Moho::EntityCategory::SerLoad)
     *
     * What it does:
     * Deserializes helper dword (+0x00) and BVIntSet payload (+0x08).
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);
  };

  /**
   * VFTABLE: 0x00E16294
   * COL: 0x00E6A070
   */
  class EntityCategoryHelperTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0052B7B0 (FUN_0052B7B0, deleting dtor thunk)
     * Slot: 2
     */
    ~EntityCategoryHelperTypeInfo() override;

    /**
     * Address: 0x0052B7A0 (FUN_0052B7A0, Moho::EntityCategoryHelperTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0052B780 (FUN_0052B780, Moho::EntityCategoryHelperTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };
  static_assert(sizeof(EntityCategoryHelperTypeInfo) == 0x64, "EntityCategoryHelperTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E162C4
   * COL: 0x00E69FD8
   */
  class EntityCategoryHelperSerializer
  {
  public:
    /**
     * Address: 0x0052C8E0 (FUN_0052C8E0, gpg::SerSaveLoadHelper_EntityCategoryHelper::Init)
     *
     * What it does:
     * Registers helper load/save callbacks on `EntityCategoryHelper` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };
  static_assert(sizeof(EntityCategoryHelperSerializer) == 0x14, "EntityCategoryHelperSerializer size must be 0x14");
} // namespace moho

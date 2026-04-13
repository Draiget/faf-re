#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EntityCategoryTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00555E90 (FUN_00555E90, ??0EntityCategoryTypeInfo@Moho@@QAE@@Z)
     */
    EntityCategoryTypeInfo();

    /**
     * Address: 0x00555F50 (FUN_00555F50, scalar deleting thunk)
     */
    ~EntityCategoryTypeInfo() override;

    /**
     * Address: 0x00555F40 (FUN_00555F40, Moho::EntityCategoryTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00555EF0 (FUN_00555EF0, Moho::EntityCategoryTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x00556A90 (FUN_00556A90, Moho::EntityCategoryTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00556AF0 (FUN_00556AF0, Moho::EntityCategoryTypeInfo::CpyRef)
     */
    static gpg::RRef CpyRef(gpg::RRef* sourceRef);

    /**
     * Address: 0x00556B90 (FUN_00556B90, Moho::EntityCategoryTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00556BD0 (FUN_00556BD0, Moho::EntityCategoryTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00556C20 (FUN_00556C20, Moho::EntityCategoryTypeInfo::MovRef)
     */
    static gpg::RRef MovRef(void* objectStorage, gpg::RRef* sourceRef);

    /**
     * Address: 0x00556CB0 (FUN_00556CB0, Moho::EntityCategoryTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(EntityCategoryTypeInfo) == 0x64, "EntityCategoryTypeInfo size must be 0x64");

  /** Address: 0x00BC9ED0 (FUN_00BC9ED0) */
  void register_EntityCategoryTypeInfoStartup();
} // namespace moho

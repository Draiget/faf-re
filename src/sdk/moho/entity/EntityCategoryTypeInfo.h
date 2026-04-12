#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class EntityCategoryTypeInfo final : public gpg::RType
  {
  public:
    /** Address: 0x00555E90 (FUN_00555E90) */
    EntityCategoryTypeInfo();
    /** Address: 0x00555F50 (FUN_00555F50) */
    ~EntityCategoryTypeInfo() override;
    /** Address: 0x00555F40 (FUN_00555F40) */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x00555EF0 (FUN_00555EF0) */
    void Init() override;
  };

  static_assert(sizeof(EntityCategoryTypeInfo) == 0x64, "EntityCategoryTypeInfo size must be 0x64");

  /** Address: 0x00BC9ED0 (FUN_00BC9ED0) */
  void register_EntityCategoryTypeInfoStartup();
} // namespace moho

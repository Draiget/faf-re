#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/entity/EntityCategoryReflection.h"

namespace moho
{
  struct RBlueprint;

  template <class T, class U>
  class BVSetRType;

  /**
   * VFTABLE: 0x00E17CE0
   * COL: 0x00E6C898
   */
  template <>
  class BVSetRType<const RBlueprint*, EntityCategoryHelper> final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00556510 (FUN_00556510, deleting dtor thunk)
     * Slot: 2
     */
    ~BVSetRType() override;

    /**
     * Address: 0x005563A0 (FUN_005563A0, Moho::BVSetRType_RBlueprintP_EntityCategoryHelper::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005564B0 (FUN_005564B0, Moho::BVSetRType_RBlueprintP_EntityCategoryHelper::Init)
     * Slot: 9
     */
    void Init() override;

  private:
    static msvc8::string sName;
    static std::uint32_t sNameInitGuard;
  };

  static_assert(
    sizeof(BVSetRType<const RBlueprint*, EntityCategoryHelper>) == 0x64,
    "BVSetRType<const RBlueprint*,EntityCategoryHelper> size must be 0x64"
  );
} // namespace moho

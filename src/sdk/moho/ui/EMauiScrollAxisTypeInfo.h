#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EMauiScrollAxis : std::int32_t
  {
    MSA_Vert = 0,
    MSA_Horz = 1,
  };

  static_assert(sizeof(EMauiScrollAxis) == 0x4, "EMauiScrollAxis size must be 0x4");

  class EMauiScrollAxisTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x007865F0 (FUN_007865F0, Moho::EMauiScrollAxisTypeInfo::dtr)
     */
    ~EMauiScrollAxisTypeInfo() override;

    /**
     * Address: 0x007865E0 (FUN_007865E0, Moho::EMauiScrollAxisTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00786590 (FUN_00786590, Moho::EMauiScrollAxisTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00786620 (FUN_00786620, Moho::EMauiScrollAxisTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EMauiScrollAxisTypeInfo) == 0x78, "EMauiScrollAxisTypeInfo size must be 0x78");
} // namespace moho


#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EResourceType : std::int32_t
  {
    RESTYPE_None = 0,
    RESTYPE_Mass = 1,
    RESTYPE_Hydrocarbon = 2,
    RESTYPE_Max = 3,
  };

  static_assert(sizeof(EResourceType) == 0x4, "EResourceType size must be 0x4");

  class EResourceTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00545AE0 (FUN_00545AE0, Moho::EResourceTypeTypeInfo::dtr)
     */
    ~EResourceTypeTypeInfo() override;

    /**
     * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EResourceTypeTypeInfo) == 0x78, "EResourceTypeTypeInfo size must be 0x78");
} // namespace moho

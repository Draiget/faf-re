#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EScrollType : std::int32_t
  {
    SCROLLTYPE_None = 0,
    SCROLLTYPE_PingPong = 1,
    SCROLLTYPE_Manual = 2,
    SCROLLTYPE_MotionDerived = 3,
  };

  static_assert(sizeof(EScrollType) == 0x4, "EScrollType size must be 0x4");

  class EScrollTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x007771B0 (FUN_007771B0, Moho::EScrollTypeTypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EScrollType` enum metadata.
     */
    EScrollTypeTypeInfo();

    /**
     * Address: 0x00777240 (FUN_00777240, Moho::EScrollTypeTypeInfo::dtr)
     */
    ~EScrollTypeTypeInfo() override;

    /**
     * Address: 0x00777230 (FUN_00777230, Moho::EScrollTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00777210 (FUN_00777210, Moho::EScrollTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00777270 (FUN_00777270, Moho::EScrollTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EScrollTypeTypeInfo) == 0x78, "EScrollTypeTypeInfo size must be 0x78");
} // namespace moho

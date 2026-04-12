#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiFrameTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00796060 (Moho::CMauiFrameTypeInfo::CMauiFrameTypeInfo)
     */
    CMauiFrameTypeInfo();

    /**
     * Address: 0x00796100 (scalar deleting thunk)
     */
    ~CMauiFrameTypeInfo() override;

    /**
     * Address: 0x007960F0 (Moho::CMauiFrameTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007960C0 (Moho::CMauiFrameTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CMauiFrameTypeInfo) == 0x64, "CMauiFrameTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDE5B0 (register_CMauiFrameTypeInfo)
   */
  void register_CMauiFrameTypeInfoStartup();
} // namespace moho

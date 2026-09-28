#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiTextTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007A2A90 (FUN_007A2A90, Moho::CMauiTextTypeInfo::CMauiTextTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiText` descriptor.
     */
    CMauiTextTypeInfo();

    /**
     * Address: 0x007A2B30 (FUN_007A2B30, Moho::CMauiTextTypeInfo::dtr)
     */
    ~CMauiTextTypeInfo() override;

    /**
     * Address: 0x007A2B20 (FUN_007A2B20, Moho::CMauiTextTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007A2AF0 (FUN_007A2AF0, Moho::CMauiTextTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BDEFE0 (FUN_00BDEFE0, register_CMauiTextTypeInfoStartup)
   *
   * What it does:
   * Constructs the `CMauiText` type-info object.
   */
  void register_CMauiTextTypeInfoStartup();
} // namespace moho

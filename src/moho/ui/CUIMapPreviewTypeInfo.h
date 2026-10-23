#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUIMapPreviewTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00850620 (FUN_00850620, Moho::CUIMapPreviewTypeInfo::CUIMapPreviewTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CUIMapPreview` descriptor.
     */
    CUIMapPreviewTypeInfo();

    /**
     * Address: 0x008506C0 (FUN_008506C0, Moho::CUIMapPreviewTypeInfo::dtr)
     */
    ~CUIMapPreviewTypeInfo() override;

    /**
     * Address: 0x008506B0 (FUN_008506B0, Moho::CUIMapPreviewTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00850680 (FUN_00850680, Moho::CUIMapPreviewTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BE4F40 (FUN_00BE4F40, register_CUIMapPreviewTypeInfoStartup)
   *
   * What it does:
   * Constructs the `CUIMapPreview` type-info object.
   */
  void register_CUIMapPreviewTypeInfoStartup();
} // namespace moho

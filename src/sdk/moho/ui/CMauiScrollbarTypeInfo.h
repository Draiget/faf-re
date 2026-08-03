#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CMauiScrollbarTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007A0360 (FUN_007A0360, Moho::CMauiScrollbarTypeInfo::CMauiScrollbarTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CMauiScrollbar` descriptor.
     */
    CMauiScrollbarTypeInfo();

    /**
     * Address: 0x007A0400 (FUN_007A0400, Moho::CMauiScrollbarTypeInfo::dtr)
     */
    ~CMauiScrollbarTypeInfo() override;

    /**
     * Address: 0x007A03F0 (FUN_007A03F0, Moho::CMauiScrollbarTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007A03C0 (FUN_007A03C0, Moho::CMauiScrollbarTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CMauiScrollbarTypeInfoStartup();
} // namespace moho

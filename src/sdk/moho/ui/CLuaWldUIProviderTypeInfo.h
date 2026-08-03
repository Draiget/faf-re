#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CLuaWldUIProviderTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0086A3E0 (FUN_0086A3E0, Moho::CLuaWldUIProviderTypeInfo::CLuaWldUIProviderTypeInfo)
     *
     * What it does:
     * Pre-registers the reflected `CLuaWldUIProvider` descriptor.
     */
    CLuaWldUIProviderTypeInfo();

    /**
     * Address: 0x0086A480 (FUN_0086A480, Moho::CLuaWldUIProviderTypeInfo::dtr)
     */
    ~CLuaWldUIProviderTypeInfo() override;

    /**
     * Address: 0x0086A470 (FUN_0086A470, Moho::CLuaWldUIProviderTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0086A440 (FUN_0086A440, Moho::CLuaWldUIProviderTypeInfo::Init)
     */
    void Init() override;
  };

  void register_CLuaWldUIProviderTypeInfoStartup();
} // namespace moho

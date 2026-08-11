#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflected descriptor for `moho::CUIWorldView`.
   *
   * Without it `gpg::LookupRType` cannot name the class, so every
   * `SCR_FromLua_CUIWorldView` in the world-view binder family fails to resolve
   * the control Lua hands it and raises out of the binding - the same failure
   * that kept `CMauiLuaDragger` from ever running a button's `OnClick`.
   */
  class CUIWorldViewTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0086DCA0 (FUN_0086DCA0, sub_86DCA0)
     *
     * What it does:
     * Pre-registers the reflected `CUIWorldView` descriptor.
     */
    CUIWorldViewTypeInfo();

    /**
     * Address: 0x0086DD40 (FUN_0086DD40, Moho::CUIWorldViewTypeInfo::dtr)
     */
    ~CUIWorldViewTypeInfo() override;

    /**
     * Address: 0x0086DD30 (FUN_0086DD30, Moho::CUIWorldViewTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0086DD00 (FUN_0086DD00, Moho::CUIWorldViewTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BE6920 (FUN_00BE6920, sub_BE6920)
   */
  void register_CUIWorldViewTypeInfoStartup();
} // namespace moho

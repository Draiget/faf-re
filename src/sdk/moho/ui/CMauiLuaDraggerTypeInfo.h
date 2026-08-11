#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflected descriptor for `moho::CMauiLuaDragger`.
   *
   * Without it `gpg::LookupRType`/`gpg::REF_FindTypeNamed` cannot name the
   * class, so `SCR_FromLua_CMauiLuaDragger` fails to resolve the dragger Lua
   * hands to `PostDragger` and raises out of the binder. That kills the
   * `ButtonPress` handler in `lua/maui/button.lua` on its last statement, which
   * is why a front-end button lit up and depressed but its `OnClick` never ran.
   */
  class CMauiLuaDraggerTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0078DC70 (FUN_0078DC70, sub_78DC70)
     *
     * What it does:
     * Pre-registers the reflected `CMauiLuaDragger` descriptor.
     */
    CMauiLuaDraggerTypeInfo();

    /**
     * Address: 0x0078DD10 (FUN_0078DD10, Moho::CMauiLuaDraggerTypeInfo::dtr)
     */
    ~CMauiLuaDraggerTypeInfo() override;

    /**
     * Address: 0x0078DD00 (FUN_0078DD00, Moho::CMauiLuaDraggerTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0078DCD0 (FUN_0078DCD0, Moho::CMauiLuaDraggerTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BDE120 (FUN_00BDE120, sub_BDE120)
   */
  void register_CMauiLuaDraggerTypeInfoStartup();
} // namespace moho

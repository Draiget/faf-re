#include "moho/debug/CPathDebugger.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  gpg::RType* CPathDebugger::sType = nullptr;

  /**
   * Address: 0x007B5C90 (FUN_007B5C90)
   */
  CPathDebugger::CPathDebugger(const LuaPlus::LuaObject& luaObject)
  {
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x007B5C50 (FUN_007B5C50, Moho::CPathDebugger::GetClass)
   */
  gpg::RType* CPathDebugger::GetClass() const
  {
    return debug_reflection::ResolveObjectType<CPathDebugger>(sType);
  }

  /**
   * Address: 0x007B5C70 (FUN_007B5C70, Moho::CPathDebugger::GetDerivedObjectRef)
   */
  gpg::RRef CPathDebugger::GetDerivedObjectRef()
  {
    return debug_reflection::MakeRef(this, GetClass());
  }

  /**
   * Address: 0x007B5CE0 (FUN_007B5CE0, Moho::CPathDebugger::dtr)
   */
  CPathDebugger::~CPathDebugger() = default;
} // namespace moho

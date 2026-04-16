#include "moho/debug/CPathDebuggerTypeInfo.h"

#include <typeinfo>

#include "moho/debug/CPathDebugger.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x007B5DB0 (FUN_007B5DB0, Moho::CPathDebuggerTypeInfo::dtr)
   */
  CPathDebuggerTypeInfo::~CPathDebuggerTypeInfo() = default;

  /**
   * Address: 0x007B5DA0 (FUN_007B5DA0, Moho::CPathDebuggerTypeInfo::GetName)
   */
  const char* CPathDebuggerTypeInfo::GetName() const
  {
    return "CPathDebugger";
  }

  /**
   * Address: 0x007B5D70 (FUN_007B5D70, Moho::CPathDebuggerTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CPathDebuggerTypeInfo::Init(gpg::RType* this);
   */
  void CPathDebuggerTypeInfo::Init()
  {
    size_ = sizeof(CPathDebugger);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x007B5D10 (FUN_007B5D10, preregister_CPathDebuggerTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::CPathDebugger`.
   */
  [[nodiscard]] gpg::RType* preregister_CPathDebuggerTypeInfo()
  {
    static CPathDebuggerTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(CPathDebugger), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x007B6260 (FUN_007B6260, Moho::CPathDebuggerTypeInfo::AddBase_CScriptObject)
   */
  void CPathDebuggerTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseCScriptObject(typeInfo);
  }
} // namespace moho

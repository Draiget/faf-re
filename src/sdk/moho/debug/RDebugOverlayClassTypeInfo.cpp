#include "moho/debug/RDebugOverlayClassTypeInfo.h"

#include "moho/debug/RDebugOverlayClass.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00651870 (FUN_00651870, Moho::RDebugOverlayClassTypeInfo::dtr)
   */
  RDebugOverlayClassTypeInfo::~RDebugOverlayClassTypeInfo() = default;

  /**
   * Address: 0x00651860 (FUN_00651860, Moho::RDebugOverlayClassTypeInfo::GetName)
   */
  const char* RDebugOverlayClassTypeInfo::GetName() const
  {
    return "RDebugOverlayClass";
  }

  /**
   * Address: 0x00651830 (FUN_00651830, Moho::RDebugOverlayClassTypeInfo::Init)
   */
  void RDebugOverlayClassTypeInfo::Init()
  {
    size_ = sizeof(RDebugOverlayClass);
    AddBase_RType(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006526F0 (FUN_006526F0, Moho::RDebugOverlayClassTypeInfo::AddBase_RType)
   */
  void RDebugOverlayClassTypeInfo::AddBase_RType(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRType(typeInfo);
  }
} // namespace moho

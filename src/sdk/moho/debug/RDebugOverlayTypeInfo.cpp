#include "moho/debug/RDebugOverlayTypeInfo.h"

#include "moho/debug/RDebugOverlay.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00651AA0 (FUN_00651AA0, Moho::RDebugOverlayTypeInfo::dtr)
   */
  RDebugOverlayTypeInfo::~RDebugOverlayTypeInfo() = default;

  /**
   * Address: 0x00651AC0 (FUN_00651AC0)
   *
   * What it does:
   * Deleting-destructor thunk lane that forwards into
   * `RDebugOverlayTypeInfo` non-deleting destructor body.
   */
  [[maybe_unused]] RDebugOverlayTypeInfo* DestroyRDebugOverlayTypeInfoThunk(RDebugOverlayTypeInfo* const object)
  {
    object->~RDebugOverlayTypeInfo();
    return object;
  }

  /**
   * Address: 0x00651A90 (FUN_00651A90, Moho::RDebugOverlayTypeInfo::GetName)
   */
  const char* RDebugOverlayTypeInfo::GetName() const
  {
    return "RDebugOverlay";
  }

  /**
   * Address: 0x00651A60 (FUN_00651A60, Moho::RDebugOverlayTypeInfo::Init)
   */
  void RDebugOverlayTypeInfo::Init()
  {
    size_ = sizeof(RDebugOverlay);
    AddBase_RObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00652750 (FUN_00652750, Moho::RDebugOverlayTypeInfo::AddBase_RObject)
   */
  void RDebugOverlayTypeInfo::AddBase_RObject(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRObject(typeInfo);
  }
} // namespace moho

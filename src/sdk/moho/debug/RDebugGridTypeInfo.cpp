#include "moho/debug/RDebugGridTypeInfo.h"

#include "moho/debug/RDebugGrid.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x0064D150 (FUN_0064D150, Moho::RDebugGridTypeInfo::dtr)
   */
  RDebugGridTypeInfo::~RDebugGridTypeInfo() = default;

  /**
   * Address: 0x0064D140 (FUN_0064D140, Moho::RDebugGridTypeInfo::GetName)
   */
  const char* RDebugGridTypeInfo::GetName() const
  {
    return "RDebugGrid";
  }

  /**
   * Address: 0x0064D0F0 (FUN_0064D0F0, Moho::RDebugGridTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugGridTypeInfo::Init(gpg::RDbgOverlayType *this);
   */
  void RDebugGridTypeInfo::Init()
  {
    size_ = sizeof(RDebugGrid);
    newRefFunc_ = &RDebugGridTypeInfo::NewRef;
    ctorRefFunc_ = &RDebugGridTypeInfo::CtrRef;
    deleteFunc_ = &RDebugGridTypeInfo::Delete;
    dtrFunc_ = &RDebugGridTypeInfo::Destruct;
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterOverlayClass("Display the world grid", "Grid");
    Finish();
  }

  /**
   * Address: 0x0064EA70 (FUN_0064EA70, Moho::RDebugGridTypeInfo::NewRef)
   */
  gpg::RRef RDebugGridTypeInfo::NewRef()
  {
    return debug_reflection::NewRef<RDebugGrid>(RDebugGrid::sType);
  }

  /**
   * Address: 0x0064EAE0 (FUN_0064EAE0, Moho::RDebugGridTypeInfo::CtrRef)
   */
  gpg::RRef RDebugGridTypeInfo::CtrRef(void* const objectStorage)
  {
    return debug_reflection::CtrRef<RDebugGrid>(objectStorage, RDebugGrid::sType);
  }

  /**
   * Address: 0x0064EAC0 (FUN_0064EAC0, Moho::RDebugGridTypeInfo::Delete)
   */
  void RDebugGridTypeInfo::Delete(void* const objectStorage)
  {
    debug_reflection::Delete<RDebugGrid>(objectStorage);
  }

  /**
   * Address: 0x0064EB20 (FUN_0064EB20, Moho::RDebugGridTypeInfo::Destruct)
   */
  void RDebugGridTypeInfo::Destruct(void* const objectStorage)
  {
    debug_reflection::Destruct<RDebugGrid>(objectStorage);
  }

  /**
   * Address: 0x0064F030 (FUN_0064F030, Moho::RDebugGridTypeInfo::AddBase_RDebugOverlay)
   */
  void RDebugGridTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRDebugOverlay(typeInfo);
  }
} // namespace moho

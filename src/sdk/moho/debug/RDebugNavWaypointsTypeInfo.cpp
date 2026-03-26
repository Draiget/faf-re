#include "moho/debug/RDebugNavWaypointsTypeInfo.h"

#include "moho/debug/RDebugNavWaypoints.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00650860 (FUN_00650860, Moho::RDebugNavWaypointsTypeInfo::dtr)
   */
  RDebugNavWaypointsTypeInfo::~RDebugNavWaypointsTypeInfo() = default;

  /**
   * Address: 0x00650850 (FUN_00650850, Moho::RDebugNavWaypointsTypeInfo::GetName)
   */
  const char* RDebugNavWaypointsTypeInfo::GetName() const
  {
    return "RDebugNavWaypoints";
  }

  /**
   * Address: 0x00650800 (FUN_00650800, Moho::RDebugNavWaypointsTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugNavWaypointsTypeInfo::Init(gpg::RDbgOverlayType *this);
   */
  void RDebugNavWaypointsTypeInfo::Init()
  {
    size_ = sizeof(RDebugNavWaypoints);
    newRefFunc_ = &RDebugNavWaypointsTypeInfo::NewRef;
    ctorRefFunc_ = &RDebugNavWaypointsTypeInfo::CtrRef;
    deleteFunc_ = &RDebugNavWaypointsTypeInfo::Delete;
    dtrFunc_ = &RDebugNavWaypointsTypeInfo::Destruct;
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterOverlayClass("Display the navigator waypoints", "NavWaypoints");
    Finish();
  }

  /**
   * Address: 0x00650D50 (FUN_00650D50, Moho::RDebugNavWaypointsTypeInfo::NewRef)
   */
  gpg::RRef RDebugNavWaypointsTypeInfo::NewRef()
  {
    return debug_reflection::NewRef<RDebugNavWaypoints>(RDebugNavWaypoints::sType);
  }

  /**
   * Address: 0x00650DC0 (FUN_00650DC0, Moho::RDebugNavWaypointsTypeInfo::CtrRef)
   */
  gpg::RRef RDebugNavWaypointsTypeInfo::CtrRef(void* const objectStorage)
  {
    return debug_reflection::CtrRef<RDebugNavWaypoints>(objectStorage, RDebugNavWaypoints::sType);
  }

  /**
   * Address: 0x00650DA0 (FUN_00650DA0, Moho::RDebugNavWaypointsTypeInfo::Delete)
   */
  void RDebugNavWaypointsTypeInfo::Delete(void* const objectStorage)
  {
    debug_reflection::Delete<RDebugNavWaypoints>(objectStorage);
  }

  /**
   * Address: 0x00650E00 (FUN_00650E00, Moho::RDebugNavWaypointsTypeInfo::Destruct)
   */
  void RDebugNavWaypointsTypeInfo::Destruct(void* const objectStorage)
  {
    debug_reflection::Destruct<RDebugNavWaypoints>(objectStorage);
  }

  /**
   * Address: 0x006510B0 (FUN_006510B0, Moho::RDebugNavWaypoints::AddBase_RDebugOverlay)
   */
  void RDebugNavWaypointsTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRDebugOverlay(typeInfo);
  }
} // namespace moho

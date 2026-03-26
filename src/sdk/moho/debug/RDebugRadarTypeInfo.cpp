#include "moho/debug/RDebugRadarTypeInfo.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/debug/RDebugRadar.h"

namespace moho
{
  /**
   * Address: 0x0064D9B0 (FUN_0064D9B0, Moho::RDebugRadarTypeInfo::dtr)
   */
  RDebugRadarTypeInfo::~RDebugRadarTypeInfo() = default;

  /**
   * Address: 0x0064D9A0 (FUN_0064D9A0, Moho::RDebugRadarTypeInfo::GetName)
   */
  const char* RDebugRadarTypeInfo::GetName() const
  {
    return "RDebugRadar";
  }

  /**
   * Address: 0x0064D950 (FUN_0064D950, Moho::RDebugRadarTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugRadarTypeInfo::Init(gpg::RDbgOverlayType *this);
   */
  void RDebugRadarTypeInfo::Init()
  {
    size_ = sizeof(RDebugRadar);
    newRefFunc_ = &RDebugRadarTypeInfo::NewRef;
    ctorRefFunc_ = &RDebugRadarTypeInfo::CtrRef;
    deleteFunc_ = &RDebugRadarTypeInfo::Delete;
    dtrFunc_ = &RDebugRadarTypeInfo::Destruct;
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterOverlayClass("Display the world radar", "Radar");
    Finish();
  }

  /**
   * Address: 0x0064EB30 (FUN_0064EB30, Moho::RDebugRadarTypeInfo::NewRef)
   */
  gpg::RRef RDebugRadarTypeInfo::NewRef()
  {
    return debug_reflection::NewRef<RDebugRadar>(RDebugRadar::sType);
  }

  /**
   * Address: 0x0064EBA0 (FUN_0064EBA0, Moho::RDebugRadarTypeInfo::CtrRef)
   */
  gpg::RRef RDebugRadarTypeInfo::CtrRef(void* const objectStorage)
  {
    return debug_reflection::CtrRef<RDebugRadar>(objectStorage, RDebugRadar::sType);
  }

  /**
   * Address: 0x0064EB80 (FUN_0064EB80, Moho::RDebugRadarTypeInfo::Delete)
   */
  void RDebugRadarTypeInfo::Delete(void* const objectStorage)
  {
    debug_reflection::Delete<RDebugRadar>(objectStorage);
  }

  /**
   * Address: 0x0064EBE0 (FUN_0064EBE0, Moho::RDebugRadarTypeInfo::Destruct)
   */
  void RDebugRadarTypeInfo::Destruct(void* const objectStorage)
  {
    debug_reflection::Destruct<RDebugRadar>(objectStorage);
  }

  /**
   * Address: 0x0064F3A0 (FUN_0064F3A0, Moho::RDebugRadarTypeInfo::AddBase_RDebugOverlay)
   */
  void RDebugRadarTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRDebugOverlay(typeInfo);
  }
} // namespace moho

#include "moho/debug/RDebugRadarTypeInfo.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/debug/RDebugRadar.h"

#include <cstdint>

namespace
{
  /**
   * Address: 0x0064D9E0 (FUN_0064D9E0)
   *
   * What it does:
   * Registers one debug-overlay descriptor pair for world-radar rendering.
   */
  void RegisterRDebugRadarOverlayClass(moho::RDebugOverlayClass* const typeInfo)
  {
    typeInfo->RegisterOverlayClass("Display the world radar", "Radar");
  }

  /**
   * Address: 0x0064EBF0 (FUN_0064EBF0)
   *
   * What it does:
   * Stores one `*base + index * 72` address lane into caller output storage.
   */
  [[maybe_unused]] std::uintptr_t* StoreStride72BaseAddressByIndex(
    std::uintptr_t* const outAddress,
    const std::uintptr_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outAddress = *baseAddress + (static_cast<std::uintptr_t>(index) * 72u);
    return outAddress;
  }
} // namespace

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
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &RDebugRadarTypeInfo::NewRef,
      &RDebugRadarTypeInfo::CtrRef,
      &RDebugRadarTypeInfo::Delete,
      &RDebugRadarTypeInfo::Destruct
    );
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterRDebugRadarOverlayClass(this);
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

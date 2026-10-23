#include "moho/unit/core/RDebugWeaponsTypeInfo.h"

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/unit/core/RDebugWeapons.h"

namespace
{
  /**
   * Address: 0x00652DF0 (FUN_00652DF0)
   *
   * What it does:
   * Registers one debug-overlay descriptor pair for weapon-range rendering.
   */
  void RegisterRDebugWeaponsOverlayClass(moho::RDebugOverlayClass* const typeInfo)
  {
    typeInfo->RegisterOverlayClass("Display weapon ranges", "Weapons");
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00652DC0 (FUN_00652DC0, Moho::RDebugWeaponsTypeInfo::dtr)
   */
  RDebugWeaponsTypeInfo::~RDebugWeaponsTypeInfo() = default;

  /**
   * Address: 0x00652DE0 (FUN_00652DE0)
   *
   * What it does:
   * Deleting-destructor thunk lane that forwards into
   * `RDebugOverlayClass` non-deleting destructor body.
   */
  [[maybe_unused]] RDebugOverlayClass* DestroyRDebugWeaponsTypeInfoThunk(RDebugOverlayClass* const object)
  {
    object->~RDebugOverlayClass();
    return object;
  }

  /**
   * Address: 0x00652DB0 (FUN_00652DB0, Moho::RDebugWeaponsTypeInfo::GetName)
   */
  const char* RDebugWeaponsTypeInfo::GetName() const
  {
    return "RDebugWeapons";
  }

  /**
   * Address: 0x00652D60 (FUN_00652D60, Moho::RDebugWeaponsTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugWeaponsTypeInfo::Init(gpg::RDbgOverlayType *this);
   */
  void RDebugWeaponsTypeInfo::Init()
  {
    size_ = sizeof(RDebugWeapons);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &RDebugWeaponsTypeInfo::NewRef,
      &RDebugWeaponsTypeInfo::CtrRef,
      &RDebugWeaponsTypeInfo::Delete,
      &RDebugWeaponsTypeInfo::Destruct
    );
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterRDebugWeaponsOverlayClass(this);
    Finish();
  }

  /**
   * Address: 0x006536A0 (FUN_006536A0, Moho::RDebugWeaponsTypeInfo::NewRef)
   */
  gpg::RRef RDebugWeaponsTypeInfo::NewRef()
  {
    return debug_reflection::NewRef<RDebugWeapons>(RDebugWeapons::sType);
  }

  /**
   * Address: 0x00653710 (FUN_00653710, Moho::RDebugWeaponsTypeInfo::CtrRef)
   */
  gpg::RRef RDebugWeaponsTypeInfo::CtrRef(void* const objectStorage)
  {
    return debug_reflection::CtrRef<RDebugWeapons>(objectStorage, RDebugWeapons::sType);
  }

  /**
   * Address: 0x006536F0 (FUN_006536F0, Moho::RDebugWeaponsTypeInfo::Delete)
   */
  void RDebugWeaponsTypeInfo::Delete(void* const objectStorage)
  {
    debug_reflection::Delete<RDebugWeapons>(objectStorage);
  }

  /**
   * Address: 0x00653750 (FUN_00653750, Moho::RDebugWeaponsTypeInfo::Destruct)
   */
  void RDebugWeaponsTypeInfo::Destruct(void* const objectStorage)
  {
    debug_reflection::Destruct<RDebugWeapons>(objectStorage);
  }

  /**
   * Address: 0x00653960 (FUN_00653960, Moho::RDebugWeapons::AddBase_RDebugOverlay)
   */
  void RDebugWeaponsTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRDebugOverlay(typeInfo);
  }
} // namespace moho

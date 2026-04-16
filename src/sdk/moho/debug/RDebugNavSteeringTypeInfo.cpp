#include "moho/debug/RDebugNavSteeringTypeInfo.h"

#include "moho/debug/RDebugNavSteering.h"
#include "moho/debug/RDebugOverlayReflectionHelpers.h"

namespace
{
  /**
   * Address: 0x00650A90 (FUN_00650A90)
   *
   * What it does:
   * Registers one debug-overlay descriptor pair for navigator-steering
   * rendering.
   */
  void RegisterRDebugNavSteeringOverlayClass(moho::RDebugOverlayClass* const typeInfo)
  {
    typeInfo->RegisterOverlayClass("Display the navigator steering", "NavSteering");
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00650A60 (FUN_00650A60, Moho::RDebugNavSteeringTypeInfo::dtr)
   */
  RDebugNavSteeringTypeInfo::~RDebugNavSteeringTypeInfo() = default;

  /**
   * Address: 0x00650A80 (FUN_00650A80)
   *
   * What it does:
   * Deleting-destructor thunk lane that forwards into
   * `RDebugOverlayClass` non-deleting destructor body.
   */
  [[maybe_unused]] RDebugOverlayClass* DestroyRDebugNavSteeringTypeInfoThunk(RDebugOverlayClass* const object)
  {
    object->~RDebugOverlayClass();
    return object;
  }

  /**
   * Address: 0x00650A50 (FUN_00650A50, Moho::RDebugNavSteeringTypeInfo::GetName)
   */
  const char* RDebugNavSteeringTypeInfo::GetName() const
  {
    return "RDebugNavSteering";
  }

  /**
   * Address: 0x00650A00 (FUN_00650A00, Moho::RDebugNavSteeringTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugNavSteeringTypeInfo::Init(gpg::RDbgOverlayType *this);
   */
  void RDebugNavSteeringTypeInfo::Init()
  {
    size_ = sizeof(RDebugNavSteering);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &RDebugNavSteeringTypeInfo::NewRef,
      &RDebugNavSteeringTypeInfo::CtrRef,
      &RDebugNavSteeringTypeInfo::Delete,
      &RDebugNavSteeringTypeInfo::Destruct
    );
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();
    RegisterRDebugNavSteeringOverlayClass(this);
    Finish();
  }

  /**
   * Address: 0x00650E10 (FUN_00650E10, Moho::RDebugNavSteeringTypeInfo::NewRef)
   */
  gpg::RRef RDebugNavSteeringTypeInfo::NewRef()
  {
    return debug_reflection::NewRef<RDebugNavSteering>(RDebugNavSteering::sType);
  }

  /**
   * Address: 0x00650E80 (FUN_00650E80, Moho::RDebugNavSteeringTypeInfo::CtrRef)
   */
  gpg::RRef RDebugNavSteeringTypeInfo::CtrRef(void* const objectStorage)
  {
    return debug_reflection::CtrRef<RDebugNavSteering>(objectStorage, RDebugNavSteering::sType);
  }

  /**
   * Address: 0x00650E60 (FUN_00650E60, Moho::RDebugNavSteeringTypeInfo::Delete)
   */
  void RDebugNavSteeringTypeInfo::Delete(void* const objectStorage)
  {
    debug_reflection::Delete<RDebugNavSteering>(objectStorage);
  }

  /**
   * Address: 0x00650EC0 (FUN_00650EC0, Moho::RDebugNavSteeringTypeInfo::Destruct)
   */
  void RDebugNavSteeringTypeInfo::Destruct(void* const objectStorage)
  {
    debug_reflection::Destruct<RDebugNavSteering>(objectStorage);
  }

  /**
   * Address: 0x00651110 (FUN_00651110, Moho::RDebugNavSteering::AddBase_RDebugOverlay)
   */
  void RDebugNavSteeringTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    debug_reflection::AddBaseRDebugOverlay(typeInfo);
  }
} // namespace moho

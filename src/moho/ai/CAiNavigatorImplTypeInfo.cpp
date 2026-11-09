#include "moho/ai/CAiNavigatorImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorImpl.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6D50 (FUN_00BF6D50, atexit destructor of the CAiNavigatorImplTypeInfo object)
   */
  [[nodiscard]] CAiNavigatorImplTypeInfo* AcquireCAiNavigatorImplTypeInfo()
  {
    static CAiNavigatorImplTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005A7C20 (FUN_005A7C20)
   *
   * What it does:
   * Adds the reflected `IAiNavigator` base entry to the navigator impl RTTI
   * node.
   */
  void AddIAiNavigatorBase(gpg::RType& typeInfo)
  {
    gpg::AddReflectedBase<IAiNavigator>(&typeInfo);
  }

  /**
   * Address: 0x005A7C80 (FUN_005A7C80)
   *
   * What it does:
   * Adds the reflected `CTask` base entry to the navigator impl RTTI node.
   */
  void AddCTaskBase(gpg::RType& typeInfo)
  {
    gpg::AddReflectedBase<CTask>(&typeInfo, gpg::BaseSubobjectOffset<CAiNavigatorImpl, CTask>());
  }

  /**
   * Address: 0x005A7CE0 (FUN_005A7CE0)
   *
   * What it does:
   * Adds the reflected `CScriptObject` base entry to the navigator impl RTTI
   * node.
   */
  void AddCScriptObjectBase(gpg::RType& typeInfo)
  {
    gpg::AddReflectedBase<CScriptObject>(&typeInfo, gpg::BaseSubobjectOffset<CAiNavigatorImpl, CScriptObject>());
  }

} // namespace

/**
 * Address: 0x005A3880 (FUN_005A3880, ctor)
 *
 * What it does:
 * Preregisters `CAiNavigatorImpl` RTTI so lookup resolves to this type helper.
 */
CAiNavigatorImplTypeInfo::CAiNavigatorImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiNavigatorImpl), this);
}

/**
 * Address: 0x005A3930 (FUN_005A3930, scalar deleting thunk)
 */
CAiNavigatorImplTypeInfo::~CAiNavigatorImplTypeInfo() = default;

/**
 * Address: 0x005A3920 (FUN_005A3920, ?GetName@CAiNavigatorImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorImplTypeInfo::GetName() const
{
  return "CAiNavigatorImpl";
}

/**
 * Address: 0x005A38E0 (FUN_005A38E0, ?Init@CAiNavigatorImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorImplTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorImpl);
  Version(1);
  gpg::RType::Init();

  AddIAiNavigatorBase(*this);
  AddCTaskBase(*this);
  AddCScriptObjectBase(*this);

  Finish();
}

/**
 * Address: 0x00BCC700 (FUN_00BCC700, register_CAiNavigatorImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiNavigatorImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiNavigatorImplTypeInfo()
{
  (void)AcquireCAiNavigatorImplTypeInfo();
}

namespace
{
  struct CAiNavigatorImplTypeInfoBootstrap
  {
    CAiNavigatorImplTypeInfoBootstrap()
    {
      (void)moho::register_CAiNavigatorImplTypeInfo();
    }
  };

  [[maybe_unused]] CAiNavigatorImplTypeInfoBootstrap gCAiNavigatorImplTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiNavigatorImplTypeInfo_015f1a, moho::register_CAiNavigatorImplTypeInfo)

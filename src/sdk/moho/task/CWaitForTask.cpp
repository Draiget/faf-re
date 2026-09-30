#include "CWaitForTask.h"

#include <cstddef>
#include <cstdlib>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{

  /**
   * Address: 0x004CA330 (FUN_004CA330, CWaitForTask startup type-info pre-registration)
   * Address: 0x00BF0BB0 (FUN_00BF0BB0, atexit destructor of the CWaitForTaskTypeInfo object)
   *
   * What it does:
   * Materializes the startup `CWaitForTaskTypeInfo` object and pre-registers
   * reflected metadata for `typeid(CWaitForTask)`.
   */
  [[nodiscard]] gpg::RType* PreRegisterCWaitForTaskTypeInfo()
  {
    static moho::CWaitForTaskTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(CWaitForTask), &sInstance);
    return &sInstance;
  }

  gpg::RType* CachedCWaitForTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CWaitForTask));
    }
    return cached;
  }

  gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  /**
   * Address: 0x004CB920 (FUN_004CB920, CWaitForTaskTypeInfo::AddBase_CTask)
   *
   * What it does:
   * Adds reflected `CTask` base metadata at subobject offset `0x00`.
   */
  void AddCTaskBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const taskType = CachedCTaskType();
    gpg::RField baseField{};
    baseField.mName = taskType->GetName();
    baseField.mType = taskType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

} // namespace

/**
 * Address: 0x004CA470 (FUN_004CA470, sub_4CA470)
 */
CWaitForTask::CWaitForTask()
  : CTask(nullptr, false)
  , mEventLinkRef()
  , mEventObject()
{
}

/**
 * Address: 0x004CA520 (FUN_004CA520, ??0CWaitForTask@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
 */
CWaitForTask::CWaitForTask(const LuaPlus::LuaObject& payload)
  : CTask(nullptr, false)
  , mEventLinkRef()
  , mEventObject(payload)
{
}

/**
 * Address: 0x004CA5B0 (FUN_004CA5B0, sub_4CA5B0)
 *
 * What it does:
 * Releases active event linkage (if any), then clears this task's weak-link
 * node from owner chains before base task teardown.
 */
CWaitForTask::~CWaitForTask()
{
  if (mEventLinkRef.HasValue()) {
    STaskEventLinkage* const linkage = mEventLinkRef.GetObjectPtr();
    if (linkage != nullptr) {
      delete linkage;
    }
  }

  mEventLinkRef.ResetFromObject(nullptr);
}

/**
 * Address: 0x004CA660 (FUN_004CA660, ?Execute@CWaitForTask@Moho@@UAEHXZ)
 */
int CWaitForTask::Execute()
{
  CScriptEvent* const event = SCR_GetScriptEventFromLuaObject(mEventObject);
  if (event) {
    STaskEventLinkage* const linkage = event->EventWait(mOwnerThread);
    mEventLinkRef.ResetFromObject(linkage);
    if (mEventLinkRef.HasValue()) {
      return 0;
    }
  } else {
    static int n = 0;
    if (n < 20) {
      ++n;
      gpg::Warnf("[WAITTASK] no event resolved from lua object");
    }
  }

  return -1;
}

/**
 * Address: 0x004CC3B0 (FUN_004CC3B0, Moho::CWaitForTask::MemberSerialize in export label)
 */
void CWaitForTask::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
  if (!luaObjectType) {
    luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    LuaPlus::LuaObject::sType = luaObjectType;
  }

  gpg::RRef ownerRef{};
  moho::ReadCTaskBase(archive, this, ownerRef);
  WeakPtr_STaskEventLinkage::Read(archive, &mEventLinkRef, ownerRef);
  archive->Read(luaObjectType, &mEventObject, ownerRef);
}

/**
 * Address: 0x004CC460 (FUN_004CC460, Moho::CWaitForTask::MemberDeserialize in export label)
 */
void CWaitForTask::MemberSerialize(gpg::WriteArchive* const archive) const{
  gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
  if (!luaObjectType) {
    luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    LuaPlus::LuaObject::sType = luaObjectType;
  }

  gpg::RRef ownerRef{};
  moho::WriteCTaskBase(archive, this, ownerRef);
  WeakPtr_STaskEventLinkage::Write(archive, &mEventLinkRef, ownerRef);
  archive->Write(luaObjectType, &mEventObject, ownerRef);
}

/**
 * Address: 0x00BC6280 (FUN_00BC6280, CWaitForTask startup type-info registration)
 *
 * What it does:
 * Pre-registers `CWaitForTask` reflected type descriptor.
 */
void moho::register_CWaitForTaskTypeInfo()
{
  (void)PreRegisterCWaitForTaskTypeInfo();
}

/**
 * Address: 0x004CA3C0 (FUN_004CA3C0, scalar deleting destructor thunk)
 */
CWaitForTaskTypeInfo::~CWaitForTaskTypeInfo() = default;

/**
 * Address: 0x004CA3B0 (FUN_004CA3B0, ?GetName@CWaitForTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CWaitForTaskTypeInfo::GetName() const
{
  return "CWaitForTask";
}

/**
 * Address: 0x004CA390 (FUN_004CA390, ?Init@CWaitForTaskTypeInfo@Moho@@UAEXXZ)
 */
void CWaitForTaskTypeInfo::Init()
{
  size_ = sizeof(CWaitForTask);
  gpg::RType::Init();
  AddCTaskBaseToTypeInfo(this);
  Finish();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CWaitForTaskTypeInfo_30426d, moho::register_CWaitForTaskTypeInfo)

GPG_PREREGISTER_INIT(PreRegisterCWaitForTaskTypeInfo_30426d, PreRegisterCWaitForTaskTypeInfo)

namespace moho
{
  /**
   * Address: 0x004CA750 (FUN_004CA750)
   */
  void CWaitForTask::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CWaitForTask()), 0u);
  }

  /**
   * `gpg::SerConstructHelper<CWaitForTask>`, vtable 0x00E09A14.
   *
   * Address: 0x00BC62A0 (FUN_00BC62A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0C10 (FUN_00BF0C10 -- the global's destructor.)
   * Address: 0x004CB1B0 (FUN_004CB1B0 -- `Init`.)
   * Address: 0x004CA740 (FUN_004CA740 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x004CB9E0 (FUN_004CB9E0 -- `Delete`.)
   */
  struct CWaitForTaskConstruct : gpg::SerConstructHelper<CWaitForTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8D2C -- process-global `CWaitForTaskConstruct` singleton.
  moho::CWaitForTaskConstruct gCWaitForTaskConstruct;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CWaitForTask>`, vtable 0x00E09A24.
   *
   * Address: 0x00BC62E0 (FUN_00BC62E0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0C40 (FUN_00BF0C40 -- the global's destructor.)
   * Address: 0x004CB230 (FUN_004CB230 -- `Init`.)
   * Address: 0x004CA7E0 (FUN_004CA7E0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x004CA7F0 (FUN_004CA7F0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CWaitForTaskSerializer : gpg::SerSaveLoadHelper<CWaitForTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8D40 -- process-global `CWaitForTaskSerializer` singleton.
  moho::CWaitForTaskSerializer gCWaitForTaskSerializer;
} // namespace

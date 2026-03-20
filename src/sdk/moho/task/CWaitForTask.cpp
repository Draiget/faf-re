#include "CWaitForTask.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/script/CScriptEvent.h"

using namespace moho;

namespace
{
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

  gpg::RType* CachedWeakPtrSTaskEventLinkageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakPtr<STaskEventLinkage>));
    }
    return cached;
  }

  gpg::RType* CachedLuaObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    }
    return cached;
  }

  void AddCTaskBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const taskType = CachedCTaskType();
    gpg::RField baseField{};
    baseField.mName = taskType->GetName();
    baseField.mType = taskType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x004CA7E0 (FUN_004CA7E0, CWaitForTaskSerializer::Deserialize callback)
   * Chain:   0x004CC3B0 (FUN_004CC3B0)
   */
  void DeserializeCWaitForTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);

    gpg::RType* const baseTaskType = CachedCTaskType();
    GPG_ASSERT(baseTaskType && baseTaskType->serLoadFunc_);
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    baseTaskType->serLoadFunc_(archive, objectPtr, baseTaskType->version_, &owner);

    gpg::RType* const weakLinkType = CachedWeakPtrSTaskEventLinkageType();
    GPG_ASSERT(weakLinkType && weakLinkType->serLoadFunc_);
    weakLinkType->serLoadFunc_(archive, reinterpret_cast<int>(&task->mEventLinkRef), weakLinkType->version_, &owner);

    gpg::RType* const luaObjectType = CachedLuaObjectType();
    GPG_ASSERT(luaObjectType && luaObjectType->serLoadFunc_);
    luaObjectType->serLoadFunc_(archive, reinterpret_cast<int>(&task->mEventObject), luaObjectType->version_, &owner);
  }

  /**
   * Address: 0x004CA7F0 (FUN_004CA7F0, CWaitForTaskSerializer::Serialize callback)
   * Chain:   0x004CC460 (FUN_004CC460)
   */
  void SerializeCWaitForTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RType* const baseTaskType = CachedCTaskType();
    GPG_ASSERT(baseTaskType && baseTaskType->serSaveFunc_);
    baseTaskType->serSaveFunc_(archive, objectPtr, baseTaskType->version_, &owner);

    gpg::RType* const weakLinkType = CachedWeakPtrSTaskEventLinkageType();
    GPG_ASSERT(weakLinkType && weakLinkType->serSaveFunc_);
    weakLinkType->serSaveFunc_(archive, reinterpret_cast<int>(&task->mEventLinkRef), weakLinkType->version_, &owner);

    gpg::RType* const luaObjectType = CachedLuaObjectType();
    GPG_ASSERT(luaObjectType && luaObjectType->serSaveFunc_);
    luaObjectType->serSaveFunc_(archive, reinterpret_cast<int>(&task->mEventObject), luaObjectType->version_, &owner);
  }
} // namespace

/**
 * Address: 0x004CA470 (FUN_004CA470, sub_4CA470)
 */
CWaitForTask::CWaitForTask()
  : CTask(nullptr, false)
  , mEventLinkRef{nullptr, nullptr}
  , mEventObject()
{}

/**
 * Address: 0x004CA520 (FUN_004CA520, ??0CWaitForTask@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
 */
CWaitForTask::CWaitForTask(const LuaPlus::LuaObject& payload)
  : CTask(nullptr, false)
  , mEventLinkRef{nullptr, nullptr}
  , mEventObject(payload)
{}

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
  }

  return -1;
}

/**
 * Address: 0x004CB1B0 (FUN_004CB1B0, sub_4CB1B0)
 */
void CWaitForTaskConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCWaitForTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x004CB230 (FUN_004CB230, sub_4CB230)
 */
void CWaitForTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCWaitForTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCWaitForTask;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCWaitForTask;
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

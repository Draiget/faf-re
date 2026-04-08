#include "CWaitForTask.h"

#include <cstdlib>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"

using namespace moho;

namespace
{
  moho::CWaitForTaskSerializer gCWaitForTaskSerializer{};

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mNext);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    auto* const next = static_cast<gpg::SerHelperBase*>(serializer.mNext);
    auto* const prev = static_cast<gpg::SerHelperBase*>(serializer.mPrev);
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mPrev = self;
    serializer.mNext = self;
    return self;
  }

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mNext == nullptr || serializer.mPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mPrev = self;
      serializer.mNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
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
  void DeserializeCWaitForTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004CA7F0 (FUN_004CA7F0, CWaitForTaskSerializer::Serialize callback)
   * Chain:   0x004CC460 (FUN_004CC460)
   */
  void SerializeCWaitForTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    task->MemberSerialize(archive);
  }

  void InitializeCWaitForTaskSerializer()
  {
    ResetSerializerNode(gCWaitForTaskSerializer);
    gCWaitForTaskSerializer.mSerLoadFunc = &DeserializeCWaitForTask;
    gCWaitForTaskSerializer.mSerSaveFunc = &SerializeCWaitForTask;
  }

  void CleanupCWaitForTaskSerializerAtExit()
  {
    (void)moho::cleanup_CWaitForTaskSerializer();
  }
} // namespace

/**
 * Address: 0x004CB460 (FUN_004CB460, Moho::InstanceCounter<Moho::CWaitForTask>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CWaitForTask
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CWaitForTask>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CWaitForTask).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

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
 * Address: 0x004CC3B0 (FUN_004CC3B0, Moho::CWaitForTask::MemberSerialize in export label)
 */
void CWaitForTask::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  gpg::RType* weakLinkType = WeakPtr<STaskEventLinkage>::sType;
  if (!weakLinkType) {
    weakLinkType = gpg::LookupRType(typeid(WeakPtr<STaskEventLinkage>));
    WeakPtr<STaskEventLinkage>::sType = weakLinkType;
  }

  gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
  if (!luaObjectType) {
    luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    LuaPlus::LuaObject::sType = luaObjectType;
  }

  gpg::RRef ownerRef{};
  archive->Read(taskType, this, ownerRef);
  archive->Read(weakLinkType, &mEventLinkRef, ownerRef);
  archive->Read(luaObjectType, &mEventObject, ownerRef);
}

/**
 * Address: 0x004CC460 (FUN_004CC460, Moho::CWaitForTask::MemberDeserialize in export label)
 */
void CWaitForTask::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  gpg::RType* weakLinkType = WeakPtr<STaskEventLinkage>::sType;
  if (!weakLinkType) {
    weakLinkType = gpg::LookupRType(typeid(WeakPtr<STaskEventLinkage>));
    WeakPtr<STaskEventLinkage>::sType = weakLinkType;
  }

  gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
  if (!luaObjectType) {
    luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    LuaPlus::LuaObject::sType = luaObjectType;
  }

  gpg::RRef ownerRef{};
  archive->Write(taskType, this, ownerRef);
  archive->Write(weakLinkType, &mEventLinkRef, ownerRef);
  archive->Write(luaObjectType, &mEventObject, ownerRef);
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

gpg::SerHelperBase* moho::cleanup_CWaitForTaskSerializer()
{
  return UnlinkSerializerNode(gCWaitForTaskSerializer);
}

/**
 * Address: 0x00BC62E0 (FUN_00BC62E0, register_CWaitForTaskSerializer)
 *
 * What it does:
 * Initializes startup serializer callback lanes for `CWaitForTask` and
 * schedules intrusive helper cleanup at process exit.
 */
void moho::register_CWaitForTaskSerializer()
{
  InitializeCWaitForTaskSerializer();
  (void)std::atexit(&CleanupCWaitForTaskSerializerAtExit);
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

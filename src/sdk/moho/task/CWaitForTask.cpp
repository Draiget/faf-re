#include "CWaitForTask.h"

#include <cstddef>
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
  alignas(moho::CWaitForTaskTypeInfo) std::byte gCWaitForTaskTypeInfoStorage[sizeof(moho::CWaitForTaskTypeInfo)]{};
  bool gCWaitForTaskTypeInfoConstructed = false;
  alignas(moho::CWaitForTaskConstruct) std::byte gCWaitForTaskConstructStorage[sizeof(moho::CWaitForTaskConstruct)]{};
  bool gCWaitForTaskConstructInitialized = false;
  moho::CWaitForTaskSerializer gCWaitForTaskSerializer{};

  [[nodiscard]] moho::CWaitForTaskTypeInfo& CWaitForTaskTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CWaitForTaskTypeInfo*>(gCWaitForTaskTypeInfoStorage);
  }

  [[nodiscard]] moho::CWaitForTaskConstruct& CWaitForTaskConstructSlot()
  {
    return *reinterpret_cast<moho::CWaitForTaskConstruct*>(gCWaitForTaskConstructStorage);
  }

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

  /**
   * Address: 0x004CA330 (FUN_004CA330, CWaitForTask startup type-info pre-registration)
   *
   * What it does:
   * Materializes one startup `CWaitForTaskTypeInfo` storage lane and
   * pre-registers reflected metadata for `typeid(CWaitForTask)`.
   */
  [[nodiscard]] gpg::RType* PreRegisterCWaitForTaskTypeInfo()
  {
    if (!gCWaitForTaskTypeInfoConstructed) {
      ::new (static_cast<void*>(&CWaitForTaskTypeInfoSlot())) moho::CWaitForTaskTypeInfo();
      gCWaitForTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CWaitForTask), &CWaitForTaskTypeInfoSlot());
    return &CWaitForTaskTypeInfoSlot();
  }

  /**
   * Address: 0x00BF0BB0 (FUN_00BF0BB0, CWaitForTask type-info cleanup at exit)
   *
   * What it does:
   * Releases dynamic field/base arrays from startup CWaitForTask type-info
   * storage and tears down placement-constructed type metadata.
   */
  void CleanupCWaitForTaskTypeInfoAtExit()
  {
    if (!gCWaitForTaskTypeInfoConstructed) {
      return;
    }

    CWaitForTaskTypeInfoSlot().fields_ = msvc8::vector<gpg::RField>{};
    CWaitForTaskTypeInfoSlot().bases_ = msvc8::vector<gpg::RField>{};
    CWaitForTaskTypeInfoSlot().~CWaitForTaskTypeInfo();
    gCWaitForTaskTypeInfoConstructed = false;
  }

  /**
   * Address: 0x004CBA10 (FUN_004CBA10, CWaitForTask reflected ref store helper)
   *
   * What it does:
   * Writes one `gpg::RRef` lane for a CWaitForTask pointer into
   * caller-provided output storage.
   */
  [[maybe_unused]] gpg::RRef* StoreCWaitForTaskRef(gpg::RRef* const outRef, CWaitForTask* const task)
  {
    return gpg::RRef_CWaitForTask(outRef, task);
  }

  /**
   * Address: 0x004CA750 (FUN_004CA750, CWaitForTask construct callback body)
   *
   * What it does:
   * Placement-constructs one CWaitForTask object in caller-provided storage
   * for reflection construct-function registration.
   */
  void ConstructCWaitForTaskInPlace(void* const objectStorage)
  {
    if (objectStorage != nullptr) {
      (void)::new (objectStorage) CWaitForTask();
    }
  }

  /**
   * Address: 0x004CB9E0 (FUN_004CB9E0, CWaitForTask construct delete callback)
   *
   * What it does:
   * Deletes one construct-path CWaitForTask object through its virtual
   * deleting destructor.
   */
  void DeleteConstructedCWaitForTask(void* const objectStorage)
  {
    auto* const task = static_cast<CWaitForTask*>(objectStorage);
    if (!task) {
      return;
    }
    delete task;
  }

  /**
   * Address: 0x00BF0C10 (FUN_00BF0C10, CWaitForTask construct cleanup primary)
   *
   * What it does:
   * Unlinks startup CWaitForTask construct helper node from the intrusive
   * helper chain and restores self-links.
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCWaitForTaskConstructVariantPrimary()
  {
    return UnlinkSerializerNode(CWaitForTaskConstructSlot());
  }

  /**
   * Address: 0x004CA6E0 (FUN_004CA6E0, CWaitForTask construct cleanup alias A)
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCWaitForTaskConstructVariantAliasA()
  {
    return CleanupCWaitForTaskConstructVariantPrimary();
  }

  /**
   * Address: 0x004CA710 (FUN_004CA710, CWaitForTask construct cleanup alias B)
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCWaitForTaskConstructVariantAliasB()
  {
    return CleanupCWaitForTaskConstructVariantPrimary();
  }

  /**
    * Alias of FUN_004CA830 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCWaitForTaskSerializerVariantAliasA()
  {
    return UnlinkSerializerNode(gCWaitForTaskSerializer);
  }

  /**
    * Alias of FUN_004CA860 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCWaitForTaskSerializerVariantAliasB()
  {
    return UnlinkSerializerNode(gCWaitForTaskSerializer);
  }

  void InitializeCWaitForTaskConstructHelper()
  {
    if (!gCWaitForTaskConstructInitialized) {
      ::new (static_cast<void*>(&CWaitForTaskConstructSlot())) moho::CWaitForTaskConstruct();
      gCWaitForTaskConstructInitialized = true;
    }

    auto& constructHelper = CWaitForTaskConstructSlot();
    ResetSerializerNode(constructHelper);
    constructHelper.mSerConstructFunc = &ConstructCWaitForTaskInPlace;
    constructHelper.mDeleteFunc = &DeleteConstructedCWaitForTask;
  }

  void CleanupCWaitForTaskConstructAtExit()
  {
    (void)CleanupCWaitForTaskConstructVariantPrimary();
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
void CWaitForTask::MemberSerialize(gpg::WriteArchive* const archive)
{
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
 * Address: 0x00BC6280 (FUN_00BC6280, CWaitForTask startup type-info registration)
 *
 * What it does:
 * Pre-registers `CWaitForTask` reflected type descriptor and schedules
 * teardown of startup type-info storage at process exit.
 */
void moho::register_CWaitForTaskTypeInfo()
{
  static const bool kRegistered = []() {
    (void)PreRegisterCWaitForTaskTypeInfo();
    (void)std::atexit(&CleanupCWaitForTaskTypeInfoAtExit);
    return true;
  }();
  (void)kRegistered;
}

/**
 * Address: 0x00BC62A0 (FUN_00BC62A0, CWaitForTask startup construct registration)
 *
 * What it does:
 * Initializes construct helper callbacks for CWaitForTask reflected serializer
 * construction and schedules intrusive helper cleanup at process exit.
 */
void moho::register_CWaitForTaskConstruct()
{
  static const bool kRegistered = []() {
    InitializeCWaitForTaskConstructHelper();
    CWaitForTaskConstructSlot().RegisterConstructFunction();
    (void)std::atexit(&CleanupCWaitForTaskConstructAtExit);
    return true;
  }();
  (void)kRegistered;
}

/**
 * Address: 0x004CA830 (FUN_004CA830, serializer cleanup alias A)
 * Address: 0x004CA860 (FUN_004CA860, serializer cleanup alias B)
 *
 * What it does:
 * Unlinks static CWaitForTask serializer helper node from the intrusive
 * helper list and restores self-links.
 */
gpg::SerHelperBase* moho::cleanup_CWaitForTaskSerializer()
{
  return CleanupCWaitForTaskSerializerVariantAliasA();
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

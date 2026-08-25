#include "CWaitForTask.h"

#include <cstddef>
#include <cstdlib>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

using namespace moho;

namespace
{
  alignas(moho::CWaitForTaskTypeInfo) std::byte gCWaitForTaskTypeInfoStorage[sizeof(moho::CWaitForTaskTypeInfo)]{};
  bool gCWaitForTaskTypeInfoConstructed = false;
  moho::CWaitForTaskConstruct gCWaitForTaskConstruct{};
  moho::CWaitForTaskSerializer gCWaitForTaskSerializer{};

  [[nodiscard]] moho::CWaitForTaskTypeInfo& CWaitForTaskTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CWaitForTaskTypeInfo*>(gCWaitForTaskTypeInfoStorage);
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
   * Address: 0x004CA750 (FUN_004CA750, allocate + default-construct + SetUnowned body)
   *
   * What it does:
   * Allocates raw `CWaitForTask` storage, default-constructs it via
   * `CWaitForTask::CWaitForTask()`, builds an unowned reflected reference
   * for the new object, and reports it through the serializer construct
   * result. This is the real callback body -- it allocates its own storage
   * rather than using any caller-provided `objectStorage`.
   */
  void ConstructCWaitForTaskForSerializer(gpg::SerConstructResult* const result)
  {
    void* const storage = ::operator new(sizeof(moho::CWaitForTask), std::nothrow);
    moho::CWaitForTask* task = nullptr;
    if (storage) {
      task = ::new (storage) moho::CWaitForTask();
    }

    gpg::RRef taskRef{};
    (void)gpg::RRef_CWaitForTask(&taskRef, task);
    result->SetUnowned(taskRef, 0u);
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

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
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
{
  AddStatCounter(InstanceCounter<CWaitForTask>::GetStatItem(), 1L);
}

/**
 * Address: 0x004CA520 (FUN_004CA520, ??0CWaitForTask@Moho@@QAE@ABVLuaObject@LuaPlus@@@Z)
 */
CWaitForTask::CWaitForTask(const LuaPlus::LuaObject& payload)
  : CTask(nullptr, false)
  , mEventLinkRef{nullptr, nullptr}
  , mEventObject(payload)
{
  AddStatCounter(InstanceCounter<CWaitForTask>::GetStatItem(), 1L);
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

  // Decrement the CWaitForTask instance-count stat (binary FUN_004CA5B0). Both
  // ctors (FUN_004CA470, FUN_004CA520) increment it by 1; the recovered code had
  // dropped the whole InstanceCounter<CWaitForTask> tracking (GetStatItem defined
  // but never called), so the stat was never maintained.
  AddStatCounter(InstanceCounter<CWaitForTask>::GetStatItem(), -1L);
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
 * Address: 0x00BC62A0 (FUN_00BC62A0, dynamic initializer for the global
 * `CWaitForTaskConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base and binds the
 * construct/delete callback fields.
 */
CWaitForTaskConstruct::CWaitForTaskConstruct()
  : mSerConstructFunc(reinterpret_cast<gpg::RType::construct_func_t>(&CWaitForTaskConstruct::Construct))
  , mDeleteFunc(&CWaitForTaskConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF0C10 (FUN_00BF0C10, Moho::CWaitForTaskConstruct::~CWaitForTaskConstruct)
 *
 * What it does:
 * Plain (unmangled) implicit-dtor-style unlink body -- functionally
 * identical to `ResetLinks()`. Two zero-incoming-xref duplicate emissions
 * of this same unlink shape also exist (0x004CA6E0, 0x004CA710); neither is
 * reachable from anywhere in the binary.
 */
CWaitForTaskConstruct::~CWaitForTaskConstruct()
{
  ResetLinks();
}

/**
 * Address: 0x004CA740 (FUN_004CA740, Moho::CWaitForTaskConstruct::Construct)
 *
 * What it does:
 * Thin reflection-dispatcher thunk: ignores the archive/objectStorage/
 * version parameters and forwards only `result` to the allocate +
 * default-construct + `SetUnowned` body.
 */
void CWaitForTaskConstruct::Construct(
  void* /*archive*/, void* /*objectStorage*/, int /*version*/, gpg::SerConstructResult* const result
)
{
  ConstructCWaitForTaskForSerializer(result);
}

/**
 * Address: 0x004CB9E0 (FUN_004CB9E0, CWaitForTask construct delete callback)
 *
 * What it does:
 * Deletes one construct-path CWaitForTask object through its virtual
 * deleting destructor.
 */
void CWaitForTaskConstruct::Deconstruct(void* const object)
{
  auto* const task = static_cast<CWaitForTask*>(object);
  if (!task) {
    return;
  }
  delete task;
}

/**
 * Address: 0x004CB1B0 (FUN_004CB1B0, sub_4CB1B0)
 */
void CWaitForTaskConstruct::Init()
{
  gpg::RType* const type = CachedCWaitForTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x00BC62E0 (FUN_00BC62E0, dynamic initializer for the global
 * `CWaitForTaskSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base and binds the load/save
 * callback fields.
 */
CWaitForTaskSerializer::CWaitForTaskSerializer()
  : mSerLoadFunc(&CWaitForTaskSerializer::Deserialize)
  , mSerSaveFunc(&CWaitForTaskSerializer::Serialize)
{}

/**
 * Address: 0x00BF0C40 (FUN_00BF0C40, Moho::CWaitForTaskSerializer::~CWaitForTaskSerializer)
 *
 * What it does:
 * Mangled `??1CWaitForTaskSerializer@Moho@@QAE@@Z` dtor calling the shared
 * unlink body. Two zero-incoming-xref duplicate emissions of this same
 * unlink shape also exist (0x004CA830, 0x004CA860); neither is reachable
 * from anywhere in the binary.
 */
CWaitForTaskSerializer::~CWaitForTaskSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x004CA7E0 (FUN_004CA7E0, CWaitForTaskSerializer::Deserialize callback)
 * Chain:   0x004CC3B0 (FUN_004CC3B0)
 */
void CWaitForTaskSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
  GPG_ASSERT(task != nullptr);
  task->MemberDeserialize(archive);
}

/**
 * Address: 0x004CA7F0 (FUN_004CA7F0, CWaitForTaskSerializer::Serialize callback)
 * Chain:   0x004CC460 (FUN_004CC460)
 */
void CWaitForTaskSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
)
{
  auto* const task = reinterpret_cast<CWaitForTask*>(objectPtr);
  GPG_ASSERT(task != nullptr);
  task->MemberSerialize(archive);
}

/**
 * Address: 0x004CB230 (FUN_004CB230, sub_4CB230)
 */
void CWaitForTaskSerializer::Init()
{
  gpg::RType* const type = CachedCWaitForTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
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

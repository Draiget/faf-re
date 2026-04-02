#include "ScrDiskWatcherTask.h"

#include <cstdlib>
#include <exception>
#include <string>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StatItem.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  moho::ScrDiskWatcherTaskTypeInfo gScrDiskWatcherTaskTypeInfo;
  moho::ScrDiskWatcherTaskSaveConstruct gScrDiskWatcherTaskSaveConstruct;
  moho::ScrDiskWatcherTaskConstruct gScrDiskWatcherTaskConstruct;

  gpg::RType* CachedScrDiskWatcherTaskType()
  {
    if (!ScrDiskWatcherTask::sType) {
      ScrDiskWatcherTask::sType = gpg::LookupRType(typeid(ScrDiskWatcherTask));
    }
    return ScrDiskWatcherTask::sType;
  }

  gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
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

  std::uint32_t InitializeReservedAndTrackScrDiskWatcherTask() noexcept
  {
    AddInstanceCounterDelta(moho::InstanceCounter<moho::ScrDiskWatcherTask>::GetStatItem(), 1);
    return 0;
  }

  /**
   * Address: 0x004C1370 (FUN_004C1370, gpg::RRef_ScrDiskWatcherTask)
   *
   * What it does:
   * Packs one `ScrDiskWatcherTask*` into reflection lanes, preserving dynamic
   * owner type when the pointer references a derived runtime type.
   */
  [[nodiscard]] gpg::RRef MakeScrDiskWatcherTaskRefImpl(ScrDiskWatcherTask* task)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedScrDiskWatcherTaskType();
    if (!task) {
      return out;
    }

    gpg::RType* dynamicType = CachedScrDiskWatcherTaskType();
    try {
      dynamicType = gpg::LookupRType(typeid(*task));
    } catch (...) {
      dynamicType = CachedScrDiskWatcherTaskType();
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(CachedScrDiskWatcherTaskType(), &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = task;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(
      reinterpret_cast<std::uintptr_t>(task) - static_cast<std::uintptr_t>(baseOffset)
    );
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x004C1230 (FUN_004C1230, RRef store wrapper)
   *
   * What it does:
   * Stores one reflected `ScrDiskWatcherTask` reference into caller-provided
   * output storage.
   */
  gpg::RRef* StoreScrDiskWatcherTaskRef(ScrDiskWatcherTask* task, gpg::RRef* outRef)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    *outRef = MakeScrDiskWatcherTaskRefImpl(task);
    return outRef;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x004C0980 (FUN_004C0980)
   *
   * What it does:
   * Unlinks the ScrDiskWatcherTask save-construct helper node.
   */
  gpg::SerHelperBase* CleanupScrDiskWatcherTaskSaveConstructVariant1()
  {
    return UnlinkHelperNode(gScrDiskWatcherTaskSaveConstruct);
  }

  /**
   * Address: 0x004C09B0 (FUN_004C09B0)
   *
   * What it does:
   * Duplicate lane of save-construct helper unlink/reset.
   */
  gpg::SerHelperBase* CleanupScrDiskWatcherTaskSaveConstructVariant2()
  {
    return UnlinkHelperNode(gScrDiskWatcherTaskSaveConstruct);
  }

  /**
   * Address: 0x004C0A50 (FUN_004C0A50)
   *
   * What it does:
   * Unlinks the ScrDiskWatcherTask construct helper node.
   */
  gpg::SerHelperBase* CleanupScrDiskWatcherTaskConstructVariant1()
  {
    return UnlinkHelperNode(gScrDiskWatcherTaskConstruct);
  }

  /**
   * Address: 0x004C0A80 (FUN_004C0A80)
   *
   * What it does:
   * Duplicate lane of construct helper unlink/reset.
   */
  gpg::SerHelperBase* CleanupScrDiskWatcherTaskConstructVariant2()
  {
    return UnlinkHelperNode(gScrDiskWatcherTaskConstruct);
  }

  void CleanupScrDiskWatcherTaskTypeInfo() noexcept
  {
    gScrDiskWatcherTaskTypeInfo.fields_ = msvc8::vector<gpg::RField>{};
    gScrDiskWatcherTaskTypeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  void CleanupScrDiskWatcherTaskSaveConstructAtexit()
  {
    (void)CleanupScrDiskWatcherTaskSaveConstructVariant1();
  }

  void CleanupScrDiskWatcherTaskConstructAtexit()
  {
    (void)CleanupScrDiskWatcherTaskConstructVariant1();
  }

  /**
   * Address: 0x004C07D0 (FUN_004C07D0)
   *
   * What it does:
   * Pre-registers the `ScrDiskWatcherTask` runtime type descriptor.
   */
  gpg::RType* RegisterScrDiskWatcherTaskTypeInfo()
  {
    gpg::PreRegisterRType(typeid(ScrDiskWatcherTask), &gScrDiskWatcherTaskTypeInfo);
    return &gScrDiskWatcherTaskTypeInfo;
  }

  void RegisterScrDiskWatcherTaskSaveConstruct()
  {
    InitializeHelperNode(gScrDiskWatcherTaskSaveConstruct);
    gScrDiskWatcherTaskSaveConstruct.mSerSaveConstructArgsFunc =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&moho::ScrDiskWatcherTask::SaveConstructArgs);
    gScrDiskWatcherTaskSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupScrDiskWatcherTaskSaveConstructAtexit);
  }

  void RegisterScrDiskWatcherTaskConstruct()
  {
    InitializeHelperNode(gScrDiskWatcherTaskConstruct);
    gScrDiskWatcherTaskConstruct.mSerConstructFunc =
      reinterpret_cast<gpg::RType::construct_func_t>(&moho::ScrDiskWatcherTask::Construct);
    gScrDiskWatcherTaskConstruct.mDeleteFunc = &moho::ScrDiskWatcherTask::Delete;
    gScrDiskWatcherTaskConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupScrDiskWatcherTaskConstructAtexit);
  }

  void ResolvePathForLua(const SDiskWatchEvent& event, msvc8::string& normalizedPath)
  {
    normalizedPath = event.mPath;
    (void)FILE_ToMountedPath(&normalizedPath, normalizedPath.c_str());
  }

  /**
   * Address: 0x004C1260 (FUN_004C1260, func_LuaCallStrInt)
   *
   * What it does:
   * Calls Lua callback with `(path, actionCode)` and restores stack top.
   */
  void LuaCallStrInt(const LuaPlus::LuaObject& callback, const msvc8::string& path, const int actionCode)
  {
    lua_State* const activeState = callback.GetActiveCState();
    const int savedTop = lua_gettop(activeState);
    callback.PushStack(activeState);
    lua_pushlstring(activeState, path.c_str(), static_cast<size_t>(path.size()));
    lua_pushnumber(activeState, static_cast<lua_Number>(actionCode));
    lua_call(activeState, 2, 1);
    lua_settop(activeState, savedTop);
  }

  struct ScrDiskWatcherTaskReflectionBootstrap
  {
    ScrDiskWatcherTaskReflectionBootstrap()
    {
      (void)RegisterScrDiskWatcherTaskTypeInfo();
      RegisterScrDiskWatcherTaskSaveConstruct();
      RegisterScrDiskWatcherTaskConstruct();
      (void)std::atexit(&CleanupScrDiskWatcherTaskTypeInfo);
    }
  };

  ScrDiskWatcherTaskReflectionBootstrap gScrDiskWatcherTaskReflectionBootstrap{};
} // namespace

gpg::RType* ScrDiskWatcherTask::sType = nullptr;

/**
 * Address: 0x004C1060 (FUN_004C1060, Moho::InstanceCounter<Moho::ScrDiskWatcherTask>::GetStatItem)
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::ScrDiskWatcherTask>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem != nullptr) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (engineStats == nullptr) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::ScrDiskWatcherTask).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x004C0B60 (FUN_004C0B60, ??0ScrDiskWatcher@Moho@@QAE@@Z)
 */
ScrDiskWatcherTask::ScrDiskWatcherTask(LuaPlus::LuaState* const luaState)
  : CTask(nullptr, false)
  , mReserved18(InitializeReservedAndTrackScrDiskWatcherTask())
  , mLuaState(luaState)
  , mListener(nullptr)
{
  DISK_AddWatchListener(&mListener);
}

/**
 * Address: 0x004C0C20 (FUN_004C0C20, scalar deleting thunk)
 * Address: 0x004C0C40 (FUN_004C0C40, non-deleting body)
 */
ScrDiskWatcherTask::~ScrDiskWatcherTask()
{
  AddInstanceCounterDelta(InstanceCounter<ScrDiskWatcherTask>::GetStatItem(), -1);
}

/**
 * Address: 0x004C0CB0 (FUN_004C0CB0, ?Execute@ScrDiskWatcherTask@Moho@@UAEHXZ)
 */
int ScrDiskWatcherTask::Execute()
{
  if (!mListener.AnyChangesPending()) {
    return 1;
  }

  LuaPlus::LuaObject watchCallbacks = mLuaState->GetGlobal("__diskwatch");
  if (!watchCallbacks) {
    return 1;
  }

  msvc8::vector<SDiskWatchEvent> pendingEvents;
  mListener.CopyAndClearPendingChanges(pendingEvents);

  for (const SDiskWatchEvent& event : pendingEvents) {
    msvc8::string normalizedPath;
    ResolvePathForLua(event, normalizedPath);

    LuaPlus::LuaTableIterator iter(&watchCallbacks, 1);
    while (!iter.m_isDone) {
      LuaPlus::LuaObject callback = iter.GetValue();

      try {
        lua_State* const activeState = callback.GetActiveCState();
        if (!activeState) {
          iter.Next();
          continue;
        }

        const int savedTop = lua_gettop(activeState);
        callback.PushStack(activeState);
        const bool isFunction = lua_isfunction(activeState, -1) != 0;
        lua_settop(activeState, savedTop);

        if (!isFunction) {
          throw std::runtime_error("call");
        }

        LuaCallStrInt(callback, normalizedPath, event.mActionCode);
      } catch (const std::exception& ex) {
        gpg::Warnf("Error handling disk changes: %s", ex.what());
      } catch (...) {
        gpg::Warnf("Error handling disk changes: %s", "unknown exception");
      }

      iter.Next();
    }
  }

  return 1;
}

/**
 * Address: 0x004C0940 (FUN_004C0940, ScrDiskWatcherTask save-construct callback)
 */
void ScrDiskWatcherTask::SaveConstructArgs(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::SerSaveConstructArgsResult* const result
)
{
  (void)version;
  if (archive == nullptr || result == nullptr) {
    return;
  }

  auto* const task = reinterpret_cast<ScrDiskWatcherTask*>(objectPtr);
  gpg::RRef luaStateRef{};
  (void)gpg::RRef_LuaState(&luaStateRef, task != nullptr ? task->mLuaState : nullptr);
  gpg::WriteRawPointer(archive, luaStateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  result->SetUnowned(1u);
}

/**
 * Address: 0x004C0AB0 (FUN_004C0AB0, ScrDiskWatcherTask construct callback)
 */
void ScrDiskWatcherTask::Construct(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::SerConstructResult* const result
)
{
  (void)objectPtr;
  (void)version;
  if (archive == nullptr || result == nullptr) {
    return;
  }

  LuaPlus::LuaState* luaState = nullptr;
  (void)archive->ReadPointer_LuaState(&luaState, nullptr);
  ScrDiskWatcherTask* const task = new ScrDiskWatcherTask(luaState);

  gpg::RRef taskRef{};
  (void)StoreScrDiskWatcherTaskRef(task, &taskRef);
  result->SetUnowned(taskRef, 1u);
}

/**
 * Address: 0x004C11F0 (FUN_004C11F0, ScrDiskWatcherTask delete callback)
 */
void ScrDiskWatcherTask::Delete(void* const objectPtr)
{
  delete static_cast<ScrDiskWatcherTask*>(objectPtr);
}

/**
 * Address: 0x004C0F90 (FUN_004C0F90, sub_4C0F90)
 */
void ScrDiskWatcherTaskSaveConstruct::RegisterSaveConstructArgsFunction()
{
  gpg::RType* const type = CachedScrDiskWatcherTaskType();
  GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSerSaveConstructArgsFunc);
  type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
}

/**
 * Address: 0x004C1010 (FUN_004C1010, sub_4C1010)
 */
void ScrDiskWatcherTaskConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedScrDiskWatcherTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mSerConstructFunc);
  GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteFunc);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x004C0860 (FUN_004C0860, scalar deleting destructor thunk)
 */
ScrDiskWatcherTaskTypeInfo::~ScrDiskWatcherTaskTypeInfo() = default;

/**
 * Address: 0x004C0850 (FUN_004C0850, ?GetName@ScrDiskWatcherTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* ScrDiskWatcherTaskTypeInfo::GetName() const
{
  return "ScrDiskWatcherTask";
}

/**
 * Address: 0x004C1150 (FUN_004C1150, Moho::ScrDiskWatcherTaskTypeInfo::AddBase_CTask)
 */
void ScrDiskWatcherTaskTypeInfo::AddBase_CTask(gpg::RType* const typeInfo)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = CachedCTaskType();
    CTask::sType = taskType;
  }

  gpg::RField baseField{};
  baseField.mName = taskType->GetName();
  baseField.mType = taskType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x004C0830 (FUN_004C0830, ?Init@ScrDiskWatcherTaskTypeInfo@Moho@@UAEXXZ)
 */
void ScrDiskWatcherTaskTypeInfo::Init()
{
  size_ = sizeof(ScrDiskWatcherTask);
  gpg::RType::Init();
  AddBase_CTask(this);
  Finish();
}

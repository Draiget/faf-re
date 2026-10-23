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
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
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

  /**
   * Address: 0x004C07D0 (FUN_004C07D0)
   * Address: 0x00BF0800 (FUN_00BF0800, atexit destructor of the ScrDiskWatcherTaskTypeInfo object)
   *
   * What it does:
   * Constructs and pre-registers the `ScrDiskWatcherTask` runtime type
   * descriptor.
   */
  gpg::RType* RegisterScrDiskWatcherTaskTypeInfo()
  {
    static moho::ScrDiskWatcherTaskTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(ScrDiskWatcherTask), &sInstance);
    return &sInstance;
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
      moho::register_ScrDiskWatcherTaskTypeInfo();
    }
  };

  ScrDiskWatcherTaskReflectionBootstrap gScrDiskWatcherTaskReflectionBootstrap{};

} // namespace

/**
 * Address: 0x00BC5F60 (FUN_00BC5F60, ScrDiskWatcherTask startup type-info registration)
 *
 * What it does:
 * Registers `ScrDiskWatcherTask` reflected type descriptor.
 */
void moho::register_ScrDiskWatcherTaskTypeInfo()
{
  (void)RegisterScrDiskWatcherTaskTypeInfo();
}

gpg::RType* ScrDiskWatcherTask::sType = nullptr;

/**
 * Address: 0x004C0B60 (FUN_004C0B60, ??0ScrDiskWatcher@Moho@@QAE@@Z)
 */
ScrDiskWatcherTask::ScrDiskWatcherTask(LuaPlus::LuaState* const luaState)
  : CTask(nullptr, false)
  , mReserved18(0)
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

void ScrDiskWatcherTask::MemberSaveConstructArgs(
  gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
  archive.WritePointer(mLuaState, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  result.SetUnowned(1u);
}

void ScrDiskWatcherTask::MemberConstruct(
  gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result
)
{
  // 0x004C0ACE: the owner is an empty reference on the stack.
  LuaPlus::LuaState* luaState = nullptr;
  const gpg::RRef owner{};
  archive.ReadPointer(&luaState, &owner);

  gpg::RRef taskRef{};
  (void)StoreScrDiskWatcherTaskRef(new ScrDiskWatcherTask(luaState), &taskRef);
  result.SetUnowned(taskRef, 1u);
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
  baseField.mFlags = 0;
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ScrDiskWatcherTaskTypeInfo_1d07fe, moho::register_ScrDiskWatcherTaskTypeInfo)

GPG_PREREGISTER_INIT(RegisterScrDiskWatcherTaskTypeInfo_1d07fe, RegisterScrDiskWatcherTaskTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveConstructHelper<ScrDiskWatcherTask>`, vtable 0x00E08B94.
   *
   * Address: 0x00BC5F80 (FUN_00BC5F80 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0860 (FUN_00BF0860 -- the global's destructor.)
   * Address: 0x004C0F90 (FUN_004C0F90 -- `Init`.)
   * Address: 0x004C0940 (FUN_004C0940 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
   */
  struct ScrDiskWatcherTaskSaveConstruct : gpg::SerSaveConstructHelper<ScrDiskWatcherTask>
  {};

  /**
   * `gpg::SerConstructHelper<ScrDiskWatcherTask>`, vtable 0x00E08BA4.
   *
   * Address: 0x00BC5FB0 (FUN_00BC5FB0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF0890 (FUN_00BF0890 -- the global's destructor.)
   * Address: 0x004C1010 (FUN_004C1010 -- `Init`.)
   * Address: 0x004C0AB0 (FUN_004C0AB0 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x004C11F0 (FUN_004C11F0 -- `Delete`.)
   */
  struct ScrDiskWatcherTaskConstruct : gpg::SerConstructHelper<ScrDiskWatcherTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8A9C -- process-global `ScrDiskWatcherTaskSaveConstruct` singleton.
  moho::ScrDiskWatcherTaskSaveConstruct gScrDiskWatcherTaskSaveConstruct;

  // Address: 0x010A8A88 -- process-global `ScrDiskWatcherTaskConstruct` singleton.
  moho::ScrDiskWatcherTaskConstruct gScrDiskWatcherTaskConstruct;
} // namespace

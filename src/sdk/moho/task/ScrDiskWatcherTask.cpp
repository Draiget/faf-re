#include "ScrDiskWatcherTask.h"

#include <cstdlib>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/CVirtualFileSystem.h"

using namespace moho;

namespace
{
  struct CFileWaitHandleSet
  {
    std::uint8_t mOpaque00[0x4C];
    CVirtualFileSystem* mVirtualFileSystem;
  };

  // +0x4C CVirtualFileSystem* slot exists in the original set object.
  CFileWaitHandleSet gFileWaitHandleStorage{};
  CFileWaitHandleSet* gFileWaitHandleSet = nullptr;
  std::once_flag gFileWaitHandleSetInitOnce;

  void ResetFileCWaitHandleSet()
  {
    gFileWaitHandleSet = nullptr;
  }

  /**
   * Address: 0x00457F90 (FUN_00457F90, func_EnsureFileCWaitHandleSet)
   *
   * What it does:
   * Lazily initializes the process-wide file wait-handle set pointer and
   * publishes it to diskwatch code paths.
   */
  void EnsureFileCWaitHandleSet()
  {
    std::call_once(gFileWaitHandleSetInitOnce, [] {
      // Recovery note:
      // `func_InitFileCWaitHandleSet` and its full object wiring are still a
      // tracked dependency. We preserve one-time publication semantics and keep
      // a stable storage object for downstream users.
      gFileWaitHandleSet = &gFileWaitHandleStorage;
      std::atexit(&ResetFileCWaitHandleSet);
    });

    if (!gFileWaitHandleSet) {
      gFileWaitHandleSet = &gFileWaitHandleStorage;
    }
  }

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

  void ResolvePathForLua(const SDiskWatchEvent& event, msvc8::string& normalizedPath)
  {
    EnsureFileCWaitHandleSet();
    normalizedPath = event.mPath;

    if (gFileWaitHandleSet && gFileWaitHandleSet->mVirtualFileSystem) {
      gFileWaitHandleSet->mVirtualFileSystem->ResolvePath(&normalizedPath, normalizedPath.c_str());
    }
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
} // namespace

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
 * Address: 0x004C0C40 (FUN_004C0C40, non-deleting body)
 */
ScrDiskWatcherTask::~ScrDiskWatcherTask() = default;

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
 * Address: 0x004C0F90 (FUN_004C0F90, sub_4C0F90)
 */
void ScrDiskWatcherTaskSaveConstruct::RegisterSaveConstructArgsFunction()
{
  gpg::RType* const type = CachedScrDiskWatcherTaskType();
  GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
  type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
}

/**
 * Address: 0x004C1010 (FUN_004C1010, sub_4C1010)
 */
void ScrDiskWatcherTaskConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedScrDiskWatcherTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
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
 * Address: 0x004C0830 (FUN_004C0830, ?Init@ScrDiskWatcherTaskTypeInfo@Moho@@UAEXXZ)
 */
void ScrDiskWatcherTaskTypeInfo::Init()
{
  size_ = sizeof(ScrDiskWatcherTask);
  gpg::RType::Init();
  AddCTaskBaseToTypeInfo(this);
  Finish();
}

#include "CLuaTask.h"

#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"

extern "C" {
void lua_traceback(lua_State* L, const char* message);
}

using namespace moho;

namespace gpg
{
  enum class TrackedPointerState : int
  {
    Unowned = 1,
    Owned = 2,
  };

  struct TrackedPointerInfo
  {
    void* object;
    gpg::RType* type;
  };

  TrackedPointerInfo ReadRawPointer(ReadArchive* archive, const gpg::RRef& ownerRef);
  void WriteRawPointer(
    WriteArchive* archive, const gpg::RRef& objectRef, TrackedPointerState state, const gpg::RRef& ownerRef
  );
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
} // namespace gpg

namespace
{
  gpg::RType* CachedCLuaTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CLuaTask));
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

  gpg::RType* CachedLuaStateType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaState));
    }
    return cached;
  }

  gpg::RRef MakeLuaStateRef(LuaPlus::LuaState* state)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedLuaStateType();
    if (!state) {
      return out;
    }

    gpg::RType* dynamicType = CachedLuaStateType();
    try {
      dynamicType = gpg::LookupRType(typeid(*state));
    } catch (...) {
      dynamicType = CachedLuaStateType();
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(CachedLuaStateType(), &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = state;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(state) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  LuaPlus::LuaState* ReadLuaStatePointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedLuaStateType());
    if (upcast.mObj) {
      return static_cast<LuaPlus::LuaState*>(upcast.mObj);
    }

    const char* const expected = CachedLuaStateType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "LuaState",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
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

  const char* LuaErrorString(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return "<no lua state>";
    }

    const char* const text = lua_tostring(state->m_state, -1);
    return text ? text : "<non-string lua error>";
  }

  /**
   * Address: 0x004C9C40 (FUN_004C9C40, CLuaTaskSerializer::Deserialize callback)
   * Chain:   0x004CC2B0 (FUN_004CC2B0)
   */
  void DeserializeCLuaTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);

    gpg::RType* const baseTaskType = CachedCTaskType();
    GPG_ASSERT(baseTaskType && baseTaskType->serLoadFunc_);
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    baseTaskType->serLoadFunc_(archive, objectPtr, baseTaskType->version_, &owner);

    task->mLuaState = ReadLuaStatePointer(archive, owner);
    archive->ReadInt(&task->mResumeArgCount);

    if (task->mLuaState) {
      task->mLuaState->m_luaTask = task;
    }
  }

  /**
   * Address: 0x004C9C50 (FUN_004C9C50, CLuaTaskSerializer::Serialize callback)
   * Chain:   0x004CC320 (FUN_004CC320)
   */
  void SerializeCLuaTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);

    gpg::RType* const baseTaskType = CachedCTaskType();
    GPG_ASSERT(baseTaskType && baseTaskType->serSaveFunc_);
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    baseTaskType->serSaveFunc_(archive, objectPtr, baseTaskType->version_, &owner);
    const gpg::RRef stateRef = MakeLuaStateRef(task->mLuaState);
    gpg::WriteRawPointer(archive, stateRef, gpg::TrackedPointerState::Owned, owner);
    archive->WriteInt(task->mResumeArgCount);

    if (task->mLuaState) {
      task->mLuaState->m_luaTask = task;
    }
  }
} // namespace

/**
 * Address: 0x004D33A0 (FUN_004D33A0,
 * ?SCR_Traceback@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
 *
 * LuaPlus::LuaState *, gpg::StrArg
 *
 * What it does:
 * Pushes lua traceback text for the provided message and returns it as string.
 */
msvc8::string moho::SCR_Traceback(LuaPlus::LuaState* const state, const gpg::StrArg message)
{
  if (!state || !state->m_state) {
    return msvc8::string(message ? message : "");
  }

  lua_traceback(state->m_state, message);
  const char* const traceback = lua_tostring(state->m_state, -1);
  msvc8::string out(traceback ? traceback : "<non-string traceback>");
  lua_settop(state->m_state, -2);
  return out;
}

/**
 * Address: 0x004C9610 (FUN_004C9610, non-deleting body)
 *
 * What it does:
 * Handles running-execute guard race, releases owned LuaState when safe, then
 * tears down base task state.
 */
CLuaTask::~CLuaTask()
{
  if (mExecuteDestroyedFlag != nullptr) {
    if (mLuaState != nullptr) {
      mLuaState->m_luaTask = nullptr;
    }
    *mExecuteDestroyedFlag = true;
  } else {
    delete mLuaState;
  }
}

/**
 * Address: 0x004C9700 (FUN_004C9700, ?Execute@CLuaTask@Moho@@UAEHXZ)
 */
int CLuaTask::Execute()
{
  LuaPlus::LuaState* const state = mLuaState;
  if (!state || !state->m_state) {
    return -1;
  }

  bool destroyedByDtor = false;
  mExecuteDestroyedFlag = &destroyedByDtor;

  try {
    const int resumeResult = lua_resume(state->m_state, mResumeArgCount);

    if (destroyedByDtor) {
      if (resumeResult != 0) {
        gpg::Warnf("Error running lua script from destroyed thread: %s", LuaErrorString(state));
      }

      delete state;
      return 1;
    }

    mExecuteDestroyedFlag = nullptr;

    if (resumeResult != 0) {
      gpg::Warnf("Error running lua script: %s", LuaErrorString(state));
      return -1;
    }

    mResumeArgCount = 0;

    if (lua_type(state->m_state, 1) == LUA_TNONE) {
      return -1;
    }

    if (lua_type(state->m_state, 1) == LUA_TNUMBER) {
      const int ticks = static_cast<int>(lua_tonumber(state->m_state, 1));
      if (ticks >= 0) {
        return ticks;
      }

      const msvc8::string traceback = SCR_Traceback(state, "Invalid args to yield(); tick count must be >=0");
      gpg::Warnf("%s", traceback.c_str());
      return -1;
    }

    const msvc8::string traceback = SCR_Traceback(state, "Invalid args to yield(); expected tick count");
    gpg::Warnf("%s", traceback.c_str());
    return -1;
  } catch (...) {
    if (destroyedByDtor) {
      delete state;
    } else {
      mExecuteDestroyedFlag = nullptr;
    }
    throw;
  }
}

/**
 * Address: 0x004CAF60 (FUN_004CAF60, sub_4CAF60)
 */
void CLuaTaskConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCLuaTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x004CAFE0 (FUN_004CAFE0, sub_4CAFE0)
 */
void CLuaTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCLuaTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCLuaTask;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCLuaTask;
}

/**
 * Address: 0x004C9A60 (FUN_004C9A60, scalar deleting destructor thunk)
 */
CLuaTaskTypeInfo::~CLuaTaskTypeInfo() = default;

/**
 * Address: 0x004C9A50 (FUN_004C9A50, ?GetName@CLuaTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CLuaTaskTypeInfo::GetName() const
{
  return "CLuaTask";
}

/**
 * Address: 0x004C9A30 (FUN_004C9A30, ?Init@CLuaTaskTypeInfo@Moho@@UAEXXZ)
 */
void CLuaTaskTypeInfo::Init()
{
  size_ = sizeof(CLuaTask);
  gpg::RType::Init();
  AddCTaskBaseToTypeInfo(this);
  Finish();
}

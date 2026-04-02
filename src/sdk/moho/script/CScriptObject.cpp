#include "CScriptObject.h"

#include <cstdint>
#include <exception>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"

using namespace moho;

gpg::RType* CScriptObject::sType = nullptr;
gpg::RType* CScriptObject::sPointerType = nullptr;

namespace
{
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

  gpg::RRef MakeCScriptObjectPointerRef(CScriptObject* scriptObject)
  {
    gpg::RRef ref{};
    ref.mObj = scriptObject;
    ref.mType = CScriptObject::GetPointerType();
    return ref;
  }

  [[nodiscard]]
  LuaPlus::LuaObject GetTableFieldByName(const LuaPlus::LuaObject& tableObject, const char* const fieldName)
  {
    LuaPlus::LuaObject out;
    if (!tableObject.IsTable()) {
      return out;
    }

    LuaPlus::LuaState* const state = tableObject.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const lstate = state->GetCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(tableObject).PushStack(lstate);
    lua_pushstring(lstate, fieldName ? fieldName : "");
    lua_gettable(lstate, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = GetTableFieldByName(payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CScriptObject::GetPointerType());
    return static_cast<CScriptObject**>(upcast.mObj);
  }

  void ClearWeakObjectChain(WeakObject& weakObject) noexcept
  {
    auto* cursor = reinterpret_cast<WeakObject::WeakLinkNodeView**>(weakObject.WeakLinkHeadSlot());
    while (cursor && *cursor) {
      WeakObject::WeakLinkNodeView* const node = *cursor;
      *cursor = node->nextInOwner;
      node->ownerLinkSlot = nullptr;
      node->nextInOwner = nullptr;
    }
  }

  gpg::RType* CachedLuaObjectType()
  {
    gpg::RType* cached = LuaPlus::LuaObject::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = cached;
    }
    return cached;
  }

  LuaPlus::LuaObject GetScriptObjectMetatable(LuaPlus::LuaState* state)
  {
    return CScrLuaMetatableFactory<CScriptObject*>::Instance().Get(state);
  }

  [[nodiscard]] bool LuaValueToBool(const LuaPlus::LuaObject& value) noexcept
  {
    if (!value) {
      return false;
    }
    if (value.IsBoolean()) {
      return value.GetBoolean();
    }
    if (value.IsNumber()) {
      return value.GetNumber() != 0.0;
    }
    return false;
  }

  /**
   * Address: 0x006B0940 (FUN_006B0940) guard prologue/epilogue pattern
   *
   * Mirrors the weak-object intrusive guard chain used by callback wrappers.
   * Shared guard mechanics live in WeakObject so callback helpers do not
   * duplicate owner-link traversal logic.
   */
  class CallbackWeakGuard final
  {
  public:
    explicit CallbackWeakGuard(CScriptObject* obj) : m_guard(static_cast<WeakObject*>(obj)) {}

    [[nodiscard]]
    CScriptObject* ResolveObjectForWarning() const
    {
      const WeakObject::WeakLinkSlot* const ownerLinkSlot = m_guard.OwnerLinkSlotAddress();
      if (!ownerLinkSlot) {
        return nullptr;
      }
      return WeakPtr<CScriptObject>::DecodeOwnerObject(
        reinterpret_cast<void*>(const_cast<WeakObject::WeakLinkSlot*>(ownerLinkSlot))
      );
    }

  private:
    WeakObject::ScopedWeakLinkGuard m_guard;
  };
} // namespace

/**
 * Address: 0x004C7DC0 (FUN_004C7DC0, Moho::InstanceCounter<Moho::CScriptObject>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CScriptObject
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CScriptObject>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CScriptObject).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x004C6F70 (??0CScriptObject@Moho@@IAE@XZ)
 *
 * What it does:
 * Initializes weak-link storage and tracks CScriptObject instance count.
 */
CScriptObject::CScriptObject()
{
  weakLinkHead_ = 0u;
  AddStatCounter(InstanceCounter<CScriptObject>::GetStatItem(), 1);
}

/**
 * Address: 0x004C7010 (??0CScriptObject@Moho@@IAE@ABVLuaObject@LuaPlus@@000@Z)
 *
 * What it does:
 * Initializes base storage then creates/attaches Lua object state.
 */
CScriptObject::CScriptObject(
  const LuaPlus::LuaObject& metaOrFactory,
  const LuaPlus::LuaObject& arg1,
  const LuaPlus::LuaObject& arg2,
  const LuaPlus::LuaObject& arg3
)
  : CScriptObject()
{
  CreateLuaObject(metaOrFactory, arg1, arg2, arg3);
}

/**
 * Address: 0x004C7340 (FUN_004C7340, Moho::CScriptObject::~CScriptObject)
 *
 * What it does:
 * Clears Lua `_c_object` back-reference, decrements tracked instance count,
 * and unlinks all intrusive weak-reference nodes owned by this object.
 */
CScriptObject::~CScriptObject()
{
  if (cObject.m_state) {
    CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(cObject);
    if (scriptObjectSlot) {
      *scriptObjectSlot = nullptr;
    }
  }

  AddStatCounter(InstanceCounter<CScriptObject>::GetStatItem(), -1);
  ClearWeakObjectChain(*static_cast<WeakObject*>(this));
}

gpg::RType* CScriptObject::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CScriptObject));
  }
  return sType;
}

/**
 * Address: 0x004C8530 (FUN_004C8530, Moho::CScriptObject::GetPointerType)
 */
gpg::RType* CScriptObject::GetPointerType()
{
  gpg::RType* cached = sPointerType;
  if (!cached) {
    cached = gpg::LookupRType(typeid(CScriptObject*));
    sPointerType = cached;
  }
  return cached;
}

/**
 * Address: 0x004C8DC0 (FUN_004C8DC0, Moho::CScriptObject::MemberDeserialize)
 */
void CScriptObject::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef ownerRef{};
  gpg::RType* luaObjectType = CachedLuaObjectType();
  archive->Read(luaObjectType, &cObject, ownerRef);

  luaObjectType = CachedLuaObjectType();
  archive->Read(luaObjectType, &mLuaObj, ownerRef);
}

/**
 * Address: 0x004C8E40 (FUN_004C8E40, Moho::CScriptObject::MemberSerialize)
 */
void CScriptObject::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RRef ownerRef{};
  gpg::RType* luaObjectType = CachedLuaObjectType();
  archive->Write(luaObjectType, &cObject, ownerRef);

  luaObjectType = CachedLuaObjectType();
  archive->Write(luaObjectType, &mLuaObj, ownerRef);
}

/**
 * Address: 0x004C70A0
 */
msvc8::string CScriptObject::GetErrorDescription()
{
  return gpg::STR_Printf("CScriptObject at %08x", reinterpret_cast<uintptr_t>(this));
}

/**
 * Address: 0x004C70D0
 */
void CScriptObject::CreateLuaObject(
  const LuaPlus::LuaObject& metaOrFactory,
  const LuaPlus::LuaObject& arg1,
  const LuaPlus::LuaObject& arg2,
  const LuaPlus::LuaObject& arg3
)
{
  LuaPlus::LuaState* state = metaOrFactory.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  LuaPlus::LuaObject callObject;
  metaOrFactory.PushStack(lstate);
  if (lua_getmetatable(lstate, -1) != 0) {
    lua_pushstring(lstate, "__call");
    lua_gettable(lstate, -2);
    callObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
  }
  lua_settop(lstate, stackTop);

  LuaPlus::LuaObject created;
  if (callObject.IsNil()) {
    created.AssignNewTable(state, 0, 1);
    created.SetMetaTable(metaOrFactory);
  } else {
    callObject.PushStack(lstate);
    const int funcTop = lua_gettop(lstate);

    metaOrFactory.PushStack(lstate);
    if (arg1.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg1).PushStack(lstate);
    }
    if (arg2.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg2).PushStack(lstate);
    }
    if (arg3.m_state) {
      const_cast<LuaPlus::LuaObject&>(arg3).PushStack(lstate);
    }

    const int nargs = lua_gettop(lstate) - funcTop;
    if (lua_pcall(lstate, nargs, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      gpg::Warnf("Error in lua: %s", err.GetString());
      lua_settop(lstate, stackTop);
      return;
    }

    created = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(lstate, stackTop);
  }

  SetLuaObject(created);
}

/**
 * Address: 0x004C72D0
 */
void CScriptObject::SetLuaObject(const LuaPlus::LuaObject& obj)
{
  LuaPlus::LuaState* state = obj.GetActiveState();
  if (!state || obj.IsNil()) {
    return;
  }

  mLuaObj = obj;
  const gpg::RRef ptrRef = MakeCScriptObjectPointerRef(this);
  cObject.AssignNewUserData(state, ptrRef);

  // sub_100BA410: apply metatable from CScrLuaMetatableFactory<CScriptObject*>.
  LuaPlus::LuaObject meta = GetScriptObjectMetatable(state);
  if (meta) {
    cObject.SetMetaTable(meta);
  }
  mLuaObj.SetObject("_c_object", cObject);
}

/**
 * Address: 0x004C7410
 */
void CScriptObject::LogScriptWarning(CScriptObject* obj, const char* which, const char* message)
{
  const char* where = "<deleted object>";
  msvc8::string description;
  if (obj) {
    description = obj->GetErrorDescription();
    where = description.c_str();
  }

  gpg::Warnf("Error running %s script in %s: %s", which ? which : "<unknown>", where, message ? message : "");
}

/**
 * Address: 0x004C74B0
 */
LuaPlus::LuaObject CScriptObject::FindScript(LuaPlus::LuaObject* dest, const char* name)
{
  if (!dest) {
    return {};
  }

  *dest = LuaPlus::LuaObject{};

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return *dest;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  mLuaObj.PushStack(lstate);
  lua_pushstring(lstate, name ? name : "");
  lua_gettable(lstate, -2);

  *dest = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
  lua_settop(lstate, stackTop);
  return *dest;
}

/**
 * Address: 0x004C7580
 */
bool CScriptObject::RunScriptMultiRet(
  const char* funcName,
  gpg::core::FastVector<LuaPlus::LuaObject>& out,
  LuaPlus::LuaObject arg1,
  LuaPlus::LuaObject arg2,
  LuaPlus::LuaObject arg3,
  LuaPlus::LuaObject arg4,
  LuaPlus::LuaObject arg5
)
{
  out.Clear();

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return false;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  mLuaObj.PushStack(lstate);
  const int tableIndex = lua_gettop(lstate);
  lua_pushstring(lstate, funcName ? funcName : "");
  lua_gettable(lstate, -2);
  if (lua_isnil(lstate, -1)) {
    lua_settop(lstate, stackTop);
    return false;
  }

  const int funcTop = lua_gettop(lstate);
  mLuaObj.PushStack(lstate);
  if (arg1.m_state) {
    arg1.PushStack(lstate);
  }
  if (arg2.m_state) {
    arg2.PushStack(lstate);
  }
  if (arg3.m_state) {
    arg3.PushStack(lstate);
  }
  if (arg4.m_state) {
    arg4.PushStack(lstate);
  }
  if (arg5.m_state) {
    arg5.PushStack(lstate);
  }

  const int nargs = lua_gettop(lstate) - funcTop;
  if (lua_pcall(lstate, nargs, LUA_MULTRET, 0) != 0) {
    const LuaPlus::LuaStackObject err(state, -1);
    LogScriptWarning(this, funcName ? funcName : "<unknown>", err.GetString());
    out.Clear();
    lua_settop(lstate, stackTop);
    return false;
  }

  const int retCount = lua_gettop(lstate) - tableIndex;
  if (retCount > 0) {
    out.Reserve(static_cast<size_t>(retCount));
    for (int i = -retCount; i <= -1; ++i) {
      LuaPlus::LuaObject value{LuaPlus::LuaStackObject(state, i)};
      out.PushBack(value);
    }
  }

  lua_settop(lstate, stackTop);
  return true;
}

/**
 * Address: 0x00623F10 (FUN_00623F10, Moho::CScriptObject::TaskTick)
 */
int CScriptObject::TaskTick()
{
  LuaPlus::LuaObject taskTickCallback;
  FindScript(&taskTickCallback, "TaskTick");
  if (!taskTickCallback) {
    return 0;
  }

  LuaPlus::LuaFunction<int> taskTick{taskTickCallback};
  return taskTick(mLuaObj);
}

/**
 * Address: 0x00581AA0
 */
void CScriptObject::CallbackStr(const char* callback)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);

    if (lua_pcall(lstate, 1, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005FCFE0
 */
void CScriptObject::CallbackStr(const char* callback, const char** arg0)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (arg0 && *arg0) ? *arg0 : nullptr);

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x0067F450
 */
void CScriptObject::CallbackStr(const char* callback, const char** arg0, const char** arg1)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (arg0 && *arg0) ? *arg0 : nullptr);
    lua_pushstring(lstate, (arg1 && *arg1) ? *arg1 : nullptr);

    if (lua_pcall(lstate, 3, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x006B0940
 */
void CScriptObject::CallbackInt(const char* callback, const int value)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, callback);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushnumber(lstate, static_cast<lua_Number>(value));

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", err.GetString());
      lua_settop(lstate, stackTop);
      return;
    }

    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), callback ? callback : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x006753A0
 */
void CScriptObject::LuaPCall(const char* scriptName, const char* const* args, LuaPlus::LuaObject* obj)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    lua_pushstring(lstate, (args && *args) ? *args : nullptr);
    LuaPush(lstate, obj);

    if (lua_pcall(lstate, 3, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005EBED0 (FUN_005EBED0, Moho::CScriptObject::RunScript_Unit_Bool)
 */
bool CScriptObject::RunScriptUnitBool(const char* const scriptName, Unit* const unitArg)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, scriptName);
  if (!script) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<LuaPlus::LuaObject> fn{script};
    const LuaPlus::LuaObject result = fn(mLuaObj, unitArg);
    return LuaValueToBool(result);
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), scriptName ? scriptName : "<unknown>", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x00581930
 */
void CScriptObject::LuaCall(const char* fileName, LuaPlus::LuaObject* obj)
{
  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, fileName);
  if (!script) {
    return;
  }

  LuaPlus::LuaState* state = mLuaObj.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  try {
    script.PushStack(lstate);
    mLuaObj.PushStack(lstate);
    LuaPush(lstate, obj);

    if (lua_pcall(lstate, 2, 1, 0) != 0) {
      const LuaPlus::LuaStackObject err(state, -1);
      LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", err.GetString());
    }
    lua_settop(lstate, stackTop);
  } catch (const std::exception& ex) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", ex.what());
  } catch (...) {
    lua_settop(lstate, stackTop);
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), fileName ? fileName : "<unknown>", "unknown exception");
  }
}

/**
 * Address: 0x005EC040 (FUN_005EC040, Moho::CScriptObject::RunScript_UnitOnDamage)
 */
void CScriptObject::RunScriptUnitOnDamage(Unit* const sourceUnit, const int amount, const bool canTakeDamageFlag)
{
  constexpr const char* kOnDamage = "OnDamage";

  CallbackWeakGuard weakGuard(this);

  LuaPlus::LuaObject script;
  FindScript(&script, kOnDamage);
  if (!script) {
    return;
  }

  try {
    LuaPlus::LuaFunction<void> fn{script};
    fn(mLuaObj, sourceUnit, amount, canTakeDamageFlag, "Damage");
  } catch (const std::exception& ex) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, ex.what());
  } catch (...) {
    LogScriptWarning(weakGuard.ResolveObjectForWarning(), kOnDamage, "unknown exception");
  }
}

/**
 * Address: 0x007CB940
 */
void CScriptObject::RunScriptObj(LuaPlus::LuaObject& out, const char* name)
{
  out = LuaPlus::LuaObject{};

  gpg::core::FastVector<LuaPlus::LuaObject> returns;
  if (!RunScriptMultiRet(
        name,
        returns,
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{},
        LuaPlus::LuaObject{}
      )) {
    return;
  }

  if (!returns.Empty()) {
    out = returns[0];
  }
}

/**
 * Address: 0x00675CF0
 */
void CScriptObject::LuaInvoke3_DiscardReturn(
  LuaPlus::LuaObject& func, LuaPlus::LuaObject& selfObj, const char* stringArg, LuaPlus::LuaObject& payloadObj
)
{
  LuaPlus::LuaState* state = func.GetActiveState();
  if (!state) {
    return;
  }

  lua_State* lstate = state->GetCState();
  const int stackTop = lua_gettop(lstate);

  func.PushStack(lstate);
  selfObj.PushStack(lstate);
  lua_pushstring(lstate, stringArg ? stringArg : "");
  payloadObj.PushStack(lstate);

  lua_call(lstate, 3, 1);
  lua_settop(lstate, stackTop);
}

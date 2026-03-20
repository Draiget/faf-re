#include "CScriptObject.h"

#include <cstdint>
#include <exception>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaObjectFactory.h"

using namespace moho;

namespace
{
  gpg::RType* GetCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject*));
    }
    return cached;
  }

  gpg::RRef MakeCScriptObjectPointerRef(CScriptObject* scriptObject)
  {
    gpg::RRef ref{};
    ref.mObj = scriptObject;
    ref.mType = GetCScriptObjectPointerType();
    return ref;
  }

  LuaPlus::LuaObject GetScriptObjectMetatable(LuaPlus::LuaState* state)
  {
    return CScrLuaMetatableFactory<CScriptObject*>::Instance().Get(state);
  }

  /**
   * Address: 0x006B0940 (FUN_006B0940) guard prologue/epilogue pattern
   *
   * Mirrors the weak-object intrusive guard chain used by callback wrappers:
   * - inserts stack marker into owner link slot at (this + 0x04),
   * - restores the link by searching for that marker on function exit.
   */
  class CallbackWeakGuard final
  {
  public:
    explicit CallbackWeakGuard(CScriptObject* obj)
    {
      if (!obj) {
        return;
      }

      m_ownerLinkSlot = reinterpret_cast<void***>(reinterpret_cast<uint8_t*>(obj) + 0x04u);
      m_prev = *m_ownerLinkSlot;
      *m_ownerLinkSlot = Marker();
    }

    ~CallbackWeakGuard()
    {
      Restore();
    }

    [[nodiscard]]
    CScriptObject* ResolveObjectForWarning() const
    {
      if (!m_ownerLinkSlot) {
        return nullptr;
      }
      return reinterpret_cast<CScriptObject*>(reinterpret_cast<uint8_t*>(m_ownerLinkSlot) - 0x04u);
    }

  private:
    [[nodiscard]]
    void** Marker() const
    {
      return reinterpret_cast<void**>(const_cast<void****>(&m_ownerLinkSlot));
    }

    void Restore()
    {
      if (!m_ownerLinkSlot) {
        return;
      }

      void*** cursor = m_ownerLinkSlot;
      while (*cursor != Marker()) {
        cursor = reinterpret_cast<void***>(reinterpret_cast<uint8_t*>(*cursor) + 0x04u);
      }
      *cursor = m_prev;
    }

  private:
    void*** m_ownerLinkSlot = nullptr;
    void** m_prev = nullptr;
  };
} // namespace

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

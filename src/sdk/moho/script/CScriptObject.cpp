#include "CScriptObject.h"

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

msvc8::string CScriptObject::GetErrorDescription() {
	return gpg::STR_Printf("CScriptObject at %08x", reinterpret_cast<uintptr_t>(this));
}

void CScriptObject::CreateLuaObject(
	const LuaPlus::LuaObject& metaOrFactory,
	const LuaPlus::LuaObject& arg1,
	const LuaPlus::LuaObject& arg2,
	const LuaPlus::LuaObject& arg3)
{
    /*
    LuaPlus::LuaState* S = metaOrFactory.GetActiveState();
    if (!S) return;

    LuaPlus::LuaObject meta = metaOrFactory.GetMetaTable();
    LuaPlus::LuaObject call = meta.GetByName("__call");

    LuaPlus::LuaObject result; // a2a в дизасме

    if (call.IsNil()) {
        // No __call: create empty table and set metatable to metaOrFactory
        result.AssignNewTable(S, 0, 1); // S, narray, nrec
        result.SetMetaTable(metaOrFactory);
    } else {
	    LuaPlus::lua_State* L = S->m_state;
        LuaTopGuard top{ L };

        // Push __call function and arguments
        call.PushStack(S);
        const int funcTop = lua_gettop(L); // v9 in asm

        metaOrFactory.PushStack(S);        // first argument to __call (the "self")
        if (arg1.GetActiveState()) arg1.PushStack(S);
        if (arg2.GetActiveState()) arg2.PushStack(S);
        if (arg3.GetActiveState()) arg3.PushStack(S);

        const int afterPush = lua_gettop(L);
        const int nargs = afterPush - funcTop;

        // lua_call(..., 1)
        // L, nargs, nresults, errfunc
        if (lua_pcall(L, nargs, 1, 0)) {
            // Error path: warn with error string on top
            LuaPlus::LuaStackObject err{ S, -1 };
            gpg::Warnf("Error in lua: %s", err.GetString());
            // LuaTopGuard restores stack
            return;
        }

        // Assign result from top of stack
        LuaPlus::LuaStackObject topObj{ S, -1 };
        result = topObj;
        // LuaTopGuard restores stack to previous
    }

    // Wire result into this object
    SetLuaObject(result);
	*/
}

void CScriptObject::SetLuaObject(const LuaPlus::LuaObject& obj) {
    /*
    LuaPlus::LuaState* S = obj.GetActiveState();
    if (!S || obj.IsNil()) return;

    // Assign table itself
    Table = obj;

    // Create C++ back-reference userdata (binary used func_CreateLuaScriptObject)
    // Emulate via a small helper: store 'this' as lightuserdata or proper userdata.
    // Here we pretend LuaPlus can wrap a pointer:
    UserData.AssignUserData(this);            // <-- implement in your LuaPlus shim
    Table.SetObject(kCObjectKey, UserData);   // table["_c_object"] = userdata(this)
    */
}

void CScriptObject::LogScriptWarning(CScriptObject* obj, const char* which, const char* message) {
    /*
	const char* where = "<deleted object>";
    std::string tmp;
    if (obj) {
        obj->GetErrorDescription(tmp);
        where = tmp.c_str();
    }
    gpg::Warnf("Error running %s script in %s: %s", which, where, message);
    */
}

LuaPlus::LuaObject CScriptObject::FindScript(LuaPlus::LuaObject* dest, const char* name) {
    /*
    LuaPlus::LuaObject out;
    LuaPlus::LuaState* S = Table.GetActiveState();
    if (!S) { out.AssignNil(); return out; }

    lua_State* L = S->m_state;
    LuaTopGuard guard{L};

    Table.PushStack(S);
    lua_pushstring(L, name);
    lua_gettable(L, -2); // table[name]

    LuaPlus::LuaStackObject topObj{S, -1};
    out = topObj;
    return out;
     */
    return LuaPlus::LuaObject{};
}

bool CScriptObject::RunScriptMultiRet(
    const char* funcName, 
    gpg::core::FastVector<LuaPlus::LuaObject>& out,
	LuaPlus::LuaObject arg1, 
    LuaPlus::LuaObject arg2, 
    LuaPlus::LuaObject arg3, 
    LuaPlus::LuaObject arg4,
	LuaPlus::LuaObject arg5)
{
    /*
    LuaPlus::LuaState* S = Table.GetActiveState();
    if (!S) { out.clear(); return false; }

    lua_State* L = S->m_state;
    LuaTopGuard guard{L};

    // fn = Table[funcName]
    Table.PushStack(S);
    lua_pushstring(L, funcName);
    const int keyTop = lua_gettop(L);
    lua_gettable(L, -2); // pops key, pushes value
    if (lua_type(L, keyTop) == LUA_TNIL || lua_isnil(L, -1)) {
        out.clear();
        return false;
    }

    const int callTop = lua_gettop(L);
    // We'll use count relative to (callTop - 1) as sentinel like in asm.
    // Push self (Table) as first argument
    Table.PushStack(S);

    auto push_if = [&](const LuaPlus::LuaObject& o) {
        if (o.GetActiveState()) o.PushStack(S);
    };
    push_if(a1); push_if(a2); push_if(a3); push_if(a4); push_if(a5);

    ScriptCallGuard stayAlive{this}; // mirrors the list link/unlink in asm

    const int nargs = lua_gettop(L) - callTop; // args excluding function itself
    if (lua_pcall(L, nargs, LUA_MULTRET, 0)) {
        // Error: format object name and log warning
        LuaPlus::LuaStackObject err{S, -1};
        LogScriptWarning(this, funcName, err.GetString());
        out.clear();
        return false;
    }

    // Success: collect multiple returns
    const int rets = lua_gettop(L) - guard.top;
    out.clear();
    out.reserve(static_cast<size_t>(rets));
    for (int i = -rets; i <= -1; ++i) {
        LuaPlus::LuaStackObject so{S, i};
        LuaPlus::LuaObject tmp{so};
        out.push_back(tmp);
    }
     */

    return true;
}

void CScriptObject::CallbackStr(const char* callback, const char** arg0) {
}

void CScriptObject::CallbackStr(const char* callback, const char** arg0, const char** arg1) {
}

void CScriptObject::LuaPCall(const char* fileName, const char** data, LuaPlus::LuaObject* obj) {
}

void CScriptObject::LuaCall(const char* fileName, LuaPlus::LuaObject* obj) {
}

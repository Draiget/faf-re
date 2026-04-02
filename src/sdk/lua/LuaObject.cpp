#include "LuaObject.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include "LuaAssertion.h"
#include "LuaTableIterator.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace LuaPlus;

namespace
{
	extern "C"
	{
		const TObject* luaH_get(Table* t, const TObject* key);
		const TObject* luaH_getnum(Table* t, int key);
		Table* luaH_new(lua_State* L, int narray, int nhash);
		int luaO_log2(unsigned int x);
		void luaG_typeerror(lua_State* L, const TObject* o, const char* op);
	}

	[[noreturn]] void LuaAssertFail(const char* message)
	{
		throw std::runtime_error(message ? message : "Lua assertion failed");
	}

	void Ensure(bool cond, const char* message)
	{
		if (!cond) {
			LuaAssertFail(message);
		}
	}

	/**
	 * Address: 0x0090A8C0 (FUN_0090A8C0, LS_LOG)
	 *
	 * What it does:
	 * Implements Lua `LOG`/`_ALERT` by applying `tostring` to each argument,
	 * joining with tab separators, and forwarding the final text to gpg logging.
	 */
	[[maybe_unused]] int LS_LOG(lua_State* const state)
	{
		Ensure(state != nullptr, "state");

		const int argumentCount = lua_gettop(state);
		lua_pushstring(state, "tostring");
		lua_gettable(state, LUA_GLOBALSINDEX);

		std::ostringstream messageBuilder{};
		for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
			lua_pushvalue(state, -1);
			lua_pushvalue(state, argumentIndex);
			lua_call(state, 1, 1);

			const char* const convertedText = lua_tostring(state, -1);
			if (convertedText == nullptr) {
				luaL_error(state, "`tostring' must return a string to `print'");
				return 0;
			}

			if (argumentIndex > 1) {
				messageBuilder << '\t';
			}
			messageBuilder << convertedText;

			lua_settop(state, -2);
		}

		msvc8::string message{};
		message.assign_owned(messageBuilder.str());
		gpg::LogMessage(gpg::LogSeverity::Info, message);
		return 0;
	}

	unsigned int HashLuaString(const char* key, const unsigned int length)
	{
		unsigned int hash = length;
		const unsigned int step = (hash >> 5U) + 1U;
		for (unsigned int i = length; i >= step; i -= step) {
			hash ^= (hash >> 2U) + (hash << 5U) + static_cast<unsigned char>(key[i - 1U]);
		}
		return hash;
	}

	const TString* FindInternedString(lua_State* state, const char* key)
	{
		Ensure(state != nullptr && state->l_G != nullptr, "state != nullptr && state->l_G != nullptr");
		Ensure(key != nullptr, "key");

		const stringtable& strings = state->l_G->strt;
		if (strings.hash == nullptr || strings.size <= 0) {
			return nullptr;
		}

		const unsigned int keyLength = static_cast<unsigned int>(std::strlen(key));
		const unsigned int hash = HashLuaString(key, keyLength);
		GCObject* current = strings.hash[hash & static_cast<unsigned int>(strings.size - 1)];
		while (current != nullptr) {
			if (current->gch.tt == LUA_TSTRING) {
				const auto* candidate = reinterpret_cast<const TString*>(current);
				if (candidate->len == static_cast<size_t>(keyLength)
					&& std::memcmp(candidate->str, key, static_cast<size_t>(keyLength)) == 0) {
					return candidate;
				}
			}
			current = current->gch.next;
		}

		return nullptr;
	}

	TObject CaptureStackValue(lua_State* state, const int index)
	{
		lua_pushvalue(state, index);
		const TObject value = *(state->top - 1);
		lua_pop(state, 1);
		return value;
	}

	void PushTObject(lua_State* state, const TObject& object)
	{
		switch (object.tt) {
			case LUA_TNIL:
				lua_pushnil(state);
				return;
			case LUA_TBOOLEAN:
				lua_pushboolean(state, object.value.b ? 1 : 0);
				return;
			case LUA_TNUMBER:
				lua_pushnumber(state, object.value.n);
				return;
			case LUA_TSTRING: {
				const auto* str = static_cast<const TString*>(object.value.p);
				lua_pushstring(state, str ? str->str : "");
				return;
			}
			default:
				break;
		}

		*state->top = object;
		if (state->top >= state->ci->top) {
			lua_checkstack(state, 1);
		}
		state->top += 1;
	}

	void RebindToState(LuaObject& object, LuaState* state)
	{
		Ensure(state != nullptr, "state");
		const LuaState* root = state->m_rootState ? state->m_rootState : state;
		if (root == object.m_state) {
			return;
		}

		if (object.m_state) {
			*object.m_prev = object.m_next;
			object.m_next->m_prev = object.m_prev;
			object.m_object.tt = LUA_TNIL;
		}

		object.AddToUsedList(state);
	}
}

/**
 * Address: 0x009072A0 (FUN_009072A0, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty LuaObject with null list links/state and NIL payload.
 */
LuaObject::LuaObject()
	: m_next(nullptr),
	  m_prev(nullptr),
	  m_state(nullptr),
	  m_object()
{
}

LuaObject::LuaObject(LuaState* state)
	: LuaObject()
{
	AddToUsedList(state);
	m_object.tt = LUA_TNIL;
}

LuaObject::LuaObject(LuaState* state, const int32_t stackIndex)
	: LuaObject()
{
	Ensure(state != nullptr, "state");
	const TObject stackObject = CaptureStackValue(state->GetCState(), stackIndex);
	AddToUsedObjectList(state, const_cast<TObject*>(&stackObject));
}

LuaObject::LuaObject(const LuaStackObject& stackObject)
	: LuaObject()
{
	if (!stackObject.m_state) {
		return;
	}

	const TObject stackValue = CaptureStackValue(
		stackObject.m_state->GetCState(),
		stackObject.m_stackIndex);
	AddToUsedObjectList(stackObject.m_state, const_cast<TObject*>(&stackValue));
}

/**
 * Address: 0x00908A40 (FUN_00908A40, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty object, then mirrors the source LuaObject by
 * linking into the same root-state used-object list when bound.
 */
LuaObject::LuaObject(const LuaObject& other)
	: LuaObject()
{
	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	}
}

/**
 * Address: 0x00908AB0 (FUN_00908AB0, LuaPlus::LuaObject::operator=)
 *
 * What it does:
 * Unlinks current state-list ownership (when bound), then binds to `other`
 * by re-inserting this object into the source state's used-object list.
 */
LuaObject& LuaObject::operator=(const LuaObject& other)
{
	if (this == &other) {
		return *this;
	}

	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}

	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	} else {
		m_state = nullptr;
		m_next = nullptr;
		m_prev = nullptr;
	}
	return *this;
}

LuaObject::~LuaObject()
{
	Reset();
}

/**
 * Address: 0x0090A520 (FUN_0090A520, LuaPlus::LuaState::LuaState)
 *
 * What it does:
 * Creates one coroutine thread state under the provided root wrapper, captures
 * the pushed thread object into `m_threadObj`, then binds `stateUserData`.
 */
LuaState::LuaState(LuaState* const parentState)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_pad9{0, 0, 0},
	  m_threadObj(),
	  m_rootState(parentState ? parentState->m_rootState : nullptr),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{
	Ensure(parentState != nullptr, "parentState");
	Ensure(m_rootState != nullptr, "parentState->m_rootState");
	Ensure(m_rootState->m_state != nullptr, "parentState->m_rootState->m_state");

	m_state = lua_newthread(m_rootState->m_state);
	Ensure(m_state != nullptr, "lua_newthread");

	const LuaStackObject threadStackObject(m_rootState, lua_gettop(m_rootState->m_state));
	m_threadObj = LuaObject(threadStackObject);
	lua_settop(m_rootState->m_state, -2);

	m_state->stateUserData = this;
}

/**
 * Address: 0x0090A600 (FUN_0090A600, LuaPlus::LuaState::~LuaState)
 *
 * What it does:
 * Clears root-owned live objects, detaches Lua state userdata, closes owned
 * C-state when required, then lets member destructors run.
 */
LuaState::~LuaState()
{
	if (m_rootState == this) {
		const auto* const tail = reinterpret_cast<const LuaObject*>(&m_tailObject);
		while (m_headObject.m_next != tail) {
			LuaObject* const live = m_headObject.m_next;
			Ensure(live != nullptr, "live");
			live->Reset();
		}
	}

	if (m_state != nullptr) {
		m_state->stateUserData = nullptr;
		if (m_ownState != 0) {
			lua_close(m_state);
		}
	}
}

LuaState* LuaState::GetActiveState()
{
	if (!m_state || !m_state->l_G || !m_state->l_G->lstate) {
		return nullptr;
	}
	return m_state->l_G->lstate->stateUserData;
}

lua_State* LuaState::GetActiveCState()
{
	if (!m_state || !m_state->l_G) {
		return nullptr;
	}
	return m_state->l_G->lstate;
}

lua_State* LuaState::GetCState() const
{
	return m_state;
}

/**
 * Address: 0x1000A4A0 (?GetGlobals@LuaState@LuaPlus@@QAE?AVLuaObject@2@XZ)
 */
LuaObject LuaState::GetGlobals()
{
	if (!m_state) {
		return {};
	}

	return LuaObject(this, LUA_GLOBALSINDEX);
}

/**
 * Address: 0x10008F20 (?GetGlobal@LuaState@LuaPlus@@QAE?AVLuaObject@2@PBD@Z)
 */
LuaObject LuaState::GetGlobal(const char* name)
{
	LuaObject globals = GetGlobals();
	return globals[name ? name : ""];
}

LuaState* LuaState::GetRootState()
{
	return m_rootState;
}

const LuaState* LuaState::GetRootState() const
{
	return m_rootState;
}

const LuaObject* LuaState::GetThreadObject() const
{
	return &m_threadObj;
}

LuaStackObject LuaState::Stack(const int32_t index)
{
	return LuaStackObject(this, index);
}

int32_t LuaState::GetTop() const
{
	return m_state ? lua_gettop(m_state) : 0;
}

bool LuaState::IsRootState() const
{
	return m_rootState == this;
}

bool LuaState::IsSuspended() const
{
	// lua_suspended() is not surfaced in this SDK build yet.
	return false;
}

void LuaState::Error(LuaState* const state, const char* const format, ...)
{
	if (state == nullptr || state->m_state == nullptr) {
		throw std::runtime_error("LuaState::Error called with null state");
	}

	va_list args;
	va_start(args, format);
	lua_pushvfstring(state->m_state, format ? format : "", args);
	va_end(args);
	lua_error(state->m_state);
}

/**
 * Address: 0x00415490 (FUN_00415490, LuaPlus::LuaStackObject::LuaStackObject)
 */
LuaStackObject::LuaStackObject(LuaState* state, const int32_t stackIndex)
	: m_state(state),
	  m_stackIndex(stackIndex)
{
}

/**
 * Address: 0x00456AE0 (FUN_00456AE0, sub_456AE0)
 *
 * LuaState *,char const *
 *
 * What it does:
 * Pushes one C-string onto the Lua state stack and returns a stack-object
 * view for the pushed slot.
 */
LuaStackObject LuaPlus::PushStringAndCaptureStackObject(LuaState* const state, const char* const value)
{
	lua_pushstring(state->m_state, value);
	return LuaStackObject(state, lua_gettop(state->m_state));
}

bool LuaStackObject::IsNil() const
{
	return !m_state || !m_state->GetCState() || lua_type(m_state->GetCState(), m_stackIndex) == LUA_TNIL;
}

/**
 * Address: 0x004154B0 (FUN_004154B0, LuaPlus::LuaStackObject::TypeError)
 *
 * What it does:
 * Raises the standard Lua bad-argument error for the current stack slot.
 */
void LuaStackObject::TypeError(const char* const expectedType) const
{
	luaL_argerror(m_state->GetCState(), m_stackIndex, expectedType ? expectedType : "value");
}

void LuaStackObject::TypeError(const char* const expectedType, const int32_t) const
{
	TypeError(expectedType);
}

void LuaStackObject::TypeError(LuaStackObject* const self, const char* const expectedType)
{
	if (self != nullptr) {
		self->TypeError(expectedType);
	}
}

/**
 * Address: 0x00415530 (FUN_00415530, LuaPlus::LuaStackObject::GetString)
 *
 * What it does:
 * Returns the string view for the current stack slot, coercing via Lua and
 * raising a type error when conversion fails.
 */
const char* LuaStackObject::GetString() const
{
	const char* const str = lua_tostring(m_state->GetCState(), m_stackIndex);
	if (!str) {
		TypeError("string");
	}
	return str;
}

/**
 * Address: 0x0041B520 (FUN_0041B520, LuaPlus::LuaStackObject::GetInteger)
 *
 * What it does:
 * Reads one integer lane from the current Lua stack slot and raises a type
 * error when the slot is not numeric.
 */
int32_t LuaStackObject::GetInteger() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("integer");
	}
	return static_cast<int32_t>(lua_tonumber(cState, m_stackIndex));
}

double LuaStackObject::ToNumber() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("number");
	}
	return lua_tonumber(cState, m_stackIndex);
}

/**
 * Address: 0x00415560 (FUN_00415560, LuaPlus::LuaStackObject::GetBoolean)
 *
 * What it does:
 * Reads the current stack slot as a Lua boolean, allowing nil as false and
 * raising a type error for other non-boolean values.
 */
bool LuaStackObject::GetBoolean() const
{
	const int type = lua_type(m_state->GetCState(), m_stackIndex);
	if (type != LUA_TBOOLEAN && type != LUA_TNIL) {
		TypeError("boolean");
	}
	return lua_toboolean(m_state->GetCState(), m_stackIndex) != 0;
}

LuaState* LuaObject::GetActiveState() const
{
	if (!m_state || !m_state->m_state || !m_state->m_state->l_G || !m_state->m_state->l_G->lstate) {
		return nullptr;
	}

	return m_state->m_state->l_G->lstate->stateUserData;
}

/**
 * Address: 0x009072C0 (FUN_009072C0, LuaPlus::LuaObject::GetActiveCState)
 *
 * What it does:
 * Returns the active C-state pointer through this object's bound root
 * wrapper lane.
 */
lua_State* LuaObject::GetActiveCState() const
{
	return m_state->m_state->l_G->lstate;
}

void LuaObject::AddToUsedObjectList(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");

	LuaState* root = state->m_rootState ? state->m_rootState : state;
	m_state = root;

	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	if (m_next) {
		m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	}
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);

	if (object) {
		m_object = *object;
	} else {
		m_object.tt = LUA_TNIL;
	}
}

void LuaObject::AddToUsedList(LuaState* state)
{
	Ensure(state != nullptr, "state");

	LuaState* root = state->m_rootState ? state->m_rootState : state;
	m_state = root;

	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	if (m_next) {
		m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	}
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
}

void LuaObject::Reset()
{
	if (!m_state) {
		return;
	}

	if (m_prev && m_next) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
	}
	m_object.tt = LUA_TNIL;
	m_state = nullptr;
	m_next = nullptr;
	m_prev = nullptr;
}

LuaObject::operator bool() const noexcept
{
	if (!m_state) {
		return false;
	}

	if (m_object.tt == LUA_TNIL) {
		return false;
	}

	if (m_object.tt == LUA_TBOOLEAN) {
		return m_object.value.b != 0;
	}

	return true;
}

/**
 * Address: 0x0128BF90 (FUN_0128BF90, LuaPlus::LuaObject::IsFunction)
 *
 * What it does:
 * Validates state ownership, then checks the wrapped tagged value against
 * `LUA_TFUNCTION`.
 */
bool LuaObject::IsFunction() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TFUNCTION;
}

/**
 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
 *
 * What it does:
 * Raises one Lua-object operation type error for the current tagged value.
 */
void LuaObject::TypeError(const char* const operation) const
{
	lua_State* const cState = GetActiveCState();
	const char* const valueType = cState != nullptr ? lua_typename(cState, m_object.tt) : "unknown";
	const char* const opText = operation != nullptr ? operation : "operate on";

	std::string message("attempt to ");
	message += opText;
	message += " a ";
	message += valueType != nullptr ? valueType : "unknown";
	message += " value";
	throw std::runtime_error(message);
}

void LuaObject::SetTableHelper(const char* key, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	PushTObject(lstate, *object);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

void LuaObject::SetTableHelper(const int32_t index, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushnumber(lstate, static_cast<lua_Number>(index));
	PushTObject(lstate, *object);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00907D10 (FUN_00907D10)
 * Mangled: ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z
 *
 * What it does:
 * Validates that both objects share the same Lua global-state root, pushes this
 * object's raw `TObject` payload onto `state->top`, extends stack space when
 * needed, then advances the stack top by one slot.
 */
StkId LuaObject::PushStack(lua_State* state) const
{
	if (state == nullptr || m_state == nullptr || m_state->m_state == nullptr) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}
	if (state->l_G != m_state->m_state->l_G) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}

	StkId const slot = state->top;
	*slot = m_object;

	if (slot >= state->ci->top) {
		lua_checkstack(state, 1);
	}
	state->top = slot + 1;
	return slot;
}

StkId LuaObject::PushStack(LuaState* state) const
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState == m_state, "state->m_rootState == m_state");
	return PushStack(state->GetCState());
}

void LuaObject::AssignNewTable(LuaState* state, const int32_t nArray, const uint32_t lnHash)
{
	RebindToState(*this, state);

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	// Address: 0x00909940 (FUN_00909940)
	// Binary path creates a table directly via luaH_new using requested array/hash sizing.
	const int hashBits = luaO_log2(lnHash);
	Table* const table = luaH_new(lstate, nArray, hashBits + 1);
	Ensure(table != nullptr, "luaH_new returned null");
	m_object.tt = table->tt;
	m_object.value.p = table;
}

void LuaObject::AssignNumber(LuaState* state, const double number)
{
	RebindToState(*this, state);
	m_object.value.n = static_cast<float>(number);
	m_object.tt = LUA_TNUMBER;
}

void LuaObject::AssignNil(LuaState* state)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TNIL;
	m_object.value.p = nullptr;
}

void LuaObject::AssignBoolean(LuaState* state, const bool value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TBOOLEAN;
	m_object.value.b = value ? 1 : 0;
}

void LuaObject::AssignString(LuaState* state, const char* value)
{
	RebindToState(*this, state);
	if (!value) {
		m_object.tt = LUA_TNIL;
		m_object.value.p = nullptr;
		return;
	}

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	lua_pushstring(lstate, value);
	m_object = *(lstate->top - 1);
	lua_settop(lstate, oldTop);
}

void LuaObject::AssignLightUserData(LuaState* state, void* value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TLIGHTUSERDATA;
	m_object.value.p = value;
}

gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RRef& value)
{
	RebindToState(*this, state);

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	void* storage = lua_newuserdata(lstate, sizeof(gpg::RRef));
	auto* storedRef = reinterpret_cast<gpg::RRef*>(storage);
	*storedRef = value;

	m_object = *(lstate->top - 1);
	lua_settop(lstate, oldTop);

	gpg::RRef out{};
	out.mObj = storedRef;
	out.mType = value.mType;
	return out;
}

void LuaObject::SetString(const int32_t index, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushnumber(lstate, static_cast<lua_Number>(index));
	if (value) {
		lua_pushstring(lstate, value);
	} else {
		lua_pushnil(lstate);
	}
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

void LuaObject::SetString(const char* key, const char* value)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	if (value) {
		lua_pushstring(lstate, value);
	} else {
		lua_pushnil(lstate);
	}
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

void LuaObject::SetNumber(const char* key, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TNUMBER;
	object.value.n = value;
	SetTableHelper(key, &object);
}

void LuaObject::SetNumber(const int32_t index, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TNUMBER;
	object.value.n = value;
	SetTableHelper(index, &object);
}

void LuaObject::SetInteger(const char* key, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");
	SetNumber(key, static_cast<float>(value));
}

void LuaObject::SetBoolean(const char* key, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TBOOLEAN;
	object.value.b = value ? 1 : 0;
	SetTableHelper(key, &object);
}

void LuaObject::SetObject(const char* key, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(key, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const char* key, LuaObject* value)
{
	if (value) {
		SetObject(key, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(key, &nilValue);
}

void LuaObject::SetObject(const LuaObject& key, const LuaObject& value)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state == key.m_state && m_state == value.m_state, "m_state == key.m_state && m_state == value.m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	const_cast<LuaObject&>(key).PushStack(lstate);
	const_cast<LuaObject&>(value).PushStack(lstate);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

void LuaObject::SetObject(const int32_t index, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(index, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const int32_t index, LuaObject* value)
{
	if (value) {
		SetObject(index, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(index, &nilValue);
}

void LuaObject::SetMetaTable(const LuaObject& valueObj)
{
	Ensure(m_state && m_state == valueObj.m_state, "m_state && m_state == valueObj.m_state");

	lua_State* lstate = m_state->GetCState();
	Ensure(lstate != nullptr, "m_state->GetCState() != nullptr");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	const_cast<LuaObject&>(valueObj).PushStack(lstate);
	lua_setmetatable(lstate, -2);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Calls `table.insert(this, key, obj)` in the active Lua state and restores
 * the original stack top after the call.
 */
void LuaObject::Insert(const int32_t key, const LuaObject& obj) const
{
	if (m_state != obj.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject insertFunction = tableObject["insert"];
		insertFunction.PushStack(activeState);

		const_cast<LuaObject*>(this)->PushStack(activeState);
		lua_pushnumber(lstate, static_cast<lua_Number>(key));
		const_cast<LuaObject&>(obj).PushStack(activeState);
		lua_call(lstate, 3, LUA_MULTRET);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 */
LuaObject LuaObject::GetByIndex(const int32_t index) const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
	lua_pushnumber(lstate, static_cast<lua_Number>(index));
	lua_gettable(lstate, -2);
	LuaObject value{ LuaStackObject(m_state, -1) };
	lua_settop(lstate, oldTop);
	return value;
}

LuaObject LuaObject::GetByName(const char* name) const
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(name != nullptr, "name");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
	lua_pushstring(lstate, name);
	lua_gettable(lstate, -2);
	LuaObject value{LuaStackObject(m_state, -1)};
	lua_settop(lstate, oldTop);
	return value;
}

/**
 * Address: 0x00908F60 (FUN_00908F60, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates table indexing, resolves an already-interned string key from the
 * VM string table, and returns the raw table slot value.
 */
LuaObject LuaObject::operator[](const char* const name) const
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(name != nullptr, "name");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	const TString* const internedKey = FindInternedString(lstate, name);
	if (internedKey == nullptr) {
		LuaObject nilValue;
		nilValue.AddToUsedList(m_state);
		nilValue.m_object.tt = LUA_TNIL;
		return nilValue;
	}

	TObject keyObject;
	keyObject.tt = internedKey->tt;
	keyObject.value.p = const_cast<TString*>(internedKey);

	const TObject* const rawValue = luaH_get(reinterpret_cast<Table*>(m_object.value.p), &keyObject);
	Ensure(rawValue != nullptr, "obj");

	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009091E0 (FUN_009091E0, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates state + table type for integer indexing, then fetches the raw
 * numeric-key slot directly from Lua's table storage.
 */
LuaObject LuaObject::operator[](const int32_t index) const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
		if (m_object.tt != LUA_TTABLE) {
			throw LuaAssertion("(((o)->tt) == LUA_TTABLE)");
		}
	}

	const TObject* const rawValue = luaH_getnum(reinterpret_cast<Table*>(m_object.value.p), index);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

LuaObject LuaObject::Lookup(const char* const path) const
{
	if (!path || !*path) {
		return *this;
	}

	LuaObject current = *this;
	const char* segmentStart = path;
	while (segmentStart && *segmentStart) {
		const char* const dot = std::strchr(segmentStart, '.');
		const std::size_t segmentLength = dot ? static_cast<std::size_t>(dot - segmentStart) : std::strlen(segmentStart);
		if (segmentLength == 0) {
			return {};
		}

		msvc8::string segment(segmentStart, segmentLength);
		current = current.GetByName(segment.c_str());
		if (current.IsNil()) {
			return current;
		}

		segmentStart = dot ? (dot + 1) : nullptr;
	}

	return current;
}

int32_t LuaObject::GetN() const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
#if defined(lua_rawlen)
	const int32_t count = static_cast<int32_t>(lua_rawlen(lstate, -1));
#elif defined(lua_objlen)
	const int32_t count = static_cast<int32_t>(lua_objlen(lstate, -1));
#else
	const int32_t count = luaL_getn(lstate, -1);
#endif
	lua_settop(lstate, oldTop);
	return count;
}

void LuaObject::Register(const char* key, CFunction value, const int32_t tagMethod)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(value != nullptr, "value");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	lua_pushcfunction(lstate, value);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);

	(void)tagMethod;
}

/**
 * Address: 0x004D2A40 (FUN_004D2A40, Moho::SCR_FromByteStream)
 *
 * What it does:
 * Deserializes one tagged Lua payload from a binary stream and recursively
 * rebuilds nested table key/value pairs.
 */
void LuaObject::SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader)
{
	Ensure(state != nullptr, "state");
	Ensure(reader != nullptr, "reader");

	LuaObject result;
	int8_t luaType = 0;
	reader->ReadExact(luaType);

	switch (luaType) {
		case 0: {
			float number = 0.0f;
			reader->ReadExact(number);
			result.AssignNumber(state, number);
			break;
		}
		case 1: {
			msvc8::string string;
			reader->ReadString(&string);
			result.AssignString(state, string.c_str());
			break;
		}
		case 2:
			result.AssignNil(state);
			break;
		case 3: {
			int8_t byteValue = 0;
			reader->ReadExact(byteValue);
			result.AssignBoolean(state, byteValue != 0);
			break;
		}
		case 4: {
			result.AssignNewTable(state, 0, 0);
			gpg::Stream* stream = const_cast<gpg::Stream*>(reader->stream());
			if (!stream) {
				gpg::Warnf("Error deserializing lua table: no stream.");
				result.AssignNil(state);
				break;
			}

			while (true) {
				const int8_t nextType = stream->GetByte();
				if (nextType == -1) {
					gpg::Warnf("Error deserializing lua table: unexpected EOF.");
					result.AssignNil(state);
					break;
				}

				stream->VirtUnGetByte(nextType);
				if (nextType == 5) {
					(void)stream->GetByte();
					break;
				}

				LuaObject key;
				SCR_FromByteStream(key, state, reader);
				if (key.IsNil()) {
					gpg::Die("Deserialized nil table key.");
				}

				LuaObject value;
				SCR_FromByteStream(value, state, reader);
				if (value.IsNil()) {
					gpg::Die("Deserialized nil table value.");
				}

				result.SetObject(key, value);
			}
			break;
		}
		case 5:
			gpg::Warnf("Error deseralizing lua object: unexpected end-of-table marker encountered.");
			result.AssignNil(state);
			break;
		default:
			gpg::Warnf("Attempt to deserialize unknown lua data.");
			result.AssignNil(state);
			break;
	}

	out = result;
}

/**
 * Address: 0x00907A90 (FUN_00907A90, LuaPlus::LuaObject::GetString)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-string values, and returns the underlying interned string buffer.
 */
const char* LuaObject::GetString() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TSTRING) {
		luaG_typeerror(lstate, &m_object, "get as string");
	}

	const auto* ts = static_cast<const TString*>(m_object.value.p);
	return ts->str;
}

const char* LuaObject::ToString() const
{
	if (IsString()) {
		return GetString();
	}

	if (IsNil()) {
		return "nil";
	}

	if (IsBoolean()) {
		return GetBoolean() ? "true" : "false";
	}

	thread_local std::string scratch;
	if (IsNumber()) {
		scratch = std::to_string(GetNumber());
		return scratch.c_str();
	}

	lua_State* const state = GetActiveCState();
	return state ? lua_typename(state, m_object.tt) : "unknown";
}

int32_t LuaObject::GetInteger() const noexcept
{
	if (IsNumber()) {
		return static_cast<int32_t>(GetNumber());
	}

	if (IsBoolean()) {
		return GetBoolean() ? 1 : 0;
	}

	if (IsString()) {
		const char* const str = GetString();
		return str ? std::atoi(str) : 0;
	}

	return 0;
}

/**
 * Address: 0x004D2C80 (FUN_004D2C80, ?SCR_ToByteStream@Moho@@YA_NABVLuaObject@LuaPlus@@AAVStream@gpg@@@Z)
 *
 * What it does:
 * Encodes one LuaObject value into the SCR tagged stream format and recursively
 * serializes table keys/values while warning on userdata/unsupported lanes.
 */
bool LuaObject::ToByteStream(gpg::Stream& stream)
{
	char typeTag;
	bool success = true;

	if (!m_state || IsNil()) {
		typeTag = 2;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsBoolean()) {
		typeTag = 3;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}

		const bool boolValue = GetBoolean();
		typeTag = boolValue ? 1 : 0;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsNumber()) {
		typeTag = 0;
		stream.Write(typeTag);
		const float number = static_cast<float>(GetNumber());
		stream.Write(number);
		return true;
	}

	if (IsString()) {
		typeTag = 1;
		stream.Write(typeTag);
		const char* str = GetString();
		stream.Write(str ? str : "");
		return true;
	}

	if (IsTable()) {
		typeTag = 4;
		stream.Write(typeTag);

		LuaTableIterator iter(this, 1);
		while (!iter.m_isDone) {
			LuaObject key = iter.GetKey();
			if (!key.ToByteStream(stream)) {
				success = false;
			}

			LuaObject value = iter.GetValue();
			if (!value.ToByteStream(stream)) {
				success = false;
			}

			iter.Next();
		}

		typeTag = 5;
		stream.Write(typeTag);
		return success;
	}

	if (IsUserData()) {
		gpg::Warnf("Attempt to serialize lua user data.");
		typeTag = 2;
		stream.Write(typeTag);
		return false;
	}

	gpg::Warnf("Attempt to serialize unsupported lua value.");
	typeTag = 2;
	stream.Write(typeTag);
	return false;
}

#include "LuaObject.h"

#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include "LuaTableIterator.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace LuaPlus;

namespace
{
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

LuaObject::LuaObject(const LuaObject& other)
	: LuaObject()
{
	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	}
}

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
	if (!m_state) {
		return {};
	}

	lua_State* lstate = GetCState();
	Ensure(lstate != nullptr, "state->GetCState()");

	const int oldTop = lua_gettop(lstate);
	lua_pushstring(lstate, name ? name : "");
	lua_gettable(lstate, LUA_GLOBALSINDEX);
	LuaObject result{ LuaStackObject(this, -1) };
	lua_settop(lstate, oldTop);
	return result;
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

LuaStackObject::LuaStackObject(LuaState* state, const int32_t stackIndex)
	: m_state(state),
	  m_stackIndex(stackIndex)
{
}

bool LuaStackObject::IsNil() const
{
	return !m_state || !m_state->GetCState() || lua_type(m_state->GetCState(), m_stackIndex) == LUA_TNIL;
}

const char* LuaStackObject::GetString() const
{
	if (!m_state || !m_state->GetCState()) {
		return "";
	}

	const char* str = lua_tostring(m_state->GetCState(), m_stackIndex);
	return str ? str : "";
}

LuaState* LuaObject::GetActiveState() const
{
	if (!m_state || !m_state->m_state || !m_state->m_state->l_G || !m_state->m_state->l_G->lstate) {
		return nullptr;
	}

	return m_state->m_state->l_G->lstate->stateUserData;
}

lua_State* LuaObject::GetActiveCState() const
{
	if (!m_state || !m_state->m_state || !m_state->m_state->l_G) {
		return nullptr;
	}
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

StkId LuaObject::PushStack(lua_State* state) const
{
	Ensure(state && m_state && m_state->m_state, "state->l_G == m_state->m_state->l_G");
	if (state->l_G != m_state->m_state->l_G) {
		LuaAssertFail("state->l_G == m_state->m_state->l_G");
	}

	StkId slot = state->top;
	*slot = m_object;

	if (state->top >= state->ci->top) {
		lua_checkstack(state, 1);
	}
	state->top += 1;
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

	(void)nArray;
	(void)lnHash;
	const int oldTop = lua_gettop(lstate);
	lua_newtable(lstate);
	m_object = *(lstate->top - 1);
	lua_settop(lstate, oldTop);
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

LuaObject LuaObject::operator[](const char* const name) const
{
	return GetByName(name);
}

LuaObject LuaObject::operator[](const int32_t index) const
{
	return GetByIndex(index);
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
					gpg::Warnf("Deserialized nil table key.");
					result.AssignNil(state);
					break;
				}

				LuaObject value;
				SCR_FromByteStream(value, state, reader);
				if (value.IsNil()) {
					gpg::Warnf("Deserialized nil table value.");
					result.AssignNil(state);
					break;
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

const char* LuaObject::GetString() const noexcept
{
	if (!m_state || m_object.tt != LUA_TSTRING) {
		return nullptr;
	}

	const auto* ts = static_cast<const TString*>(m_object.value.p);
	return ts ? ts->str : nullptr;
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

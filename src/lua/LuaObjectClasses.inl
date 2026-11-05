// Part of LuaObject.cpp, included there: the LuaState, LuaStackObject and LuaObject methods.

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

LuaObject LuaState::GetTableSizes()
{
	getsizes(m_state);
	LuaObject sizes(this, -1);
	lua_settop(m_state, -2);
	return sizes;
}

/**
 * Address: 0x0090A510 (FUN_0090A510, LuaPlus::LuaState::CastState)
 *
 * What it does:
 * Returns the C++ wrapper pointer stored in `lua_State::stateUserData`.
 */
LuaState* LuaState::CastState(lua_State* const state)
{
	return state->stateUserData;
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

// The two bridges below are x86 register/stack adapters written in inline
// assembly; x64 has neither inline asm nor those conventions.
#if defined(_M_IX86)
/**
 * Address: 0x004CCA70 (FUN_004CCA70)
 *
 * What it does:
 * Bridges one `lua_State*` slot in `ECX` into `lua_call(L, nargs, nresults)`,
 * preserving the original thiscall adapter stack shape.
 */
__declspec(naked) void __stdcall LuaStateSlotCallBridge(
	const int /*nargs*/,
	const int /*nresults*/
)
{
	__asm
	{
		mov     eax, [esp+8]
		mov     edx, [esp+4]
		push    eax
		mov     eax, [ecx]
		push    edx
		push    eax
		call    lua_call
		add     esp, 0Ch
		retn    8
	}
}

/**
 * Address: 0x004CCA90 (FUN_004CCA90)
 *
 * What it does:
 * Bridges register/stack lanes into `luaL_loadbuffer(*slot, buff, size, name)`
 * using the original stdcall adapter sequence.
 */
__declspec(naked) void __stdcall LuaStateSlotLoadBufferBridge(lua_State** /*stateSlot*/)
{
	__asm
	{
		push    eax
		mov     eax, [esp+8]
		push    ecx
		mov     ecx, [eax]
		push    edx
		push    ecx
		call    luaL_loadbuffer
		add     esp, 10h
		retn    4
	}
}
#endif // _M_IX86

/**
 * Address: 0x004CCAB0 (FUN_004CCAB0)
 *
 * What it does:
 * Pops one value from a Lua stack slot by rebasing top to `-2`.
 */
[[maybe_unused]] static void LuaStateSlotPopOne(lua_State** const stateSlot)
{
	lua_settop(*stateSlot, -2);
}

/**
 * Address: 0x004CCA10 (FUN_004CCA10, LuaPlus::LuaState::PushNil)
 *
 * What it does:
 * Pushes nil to this state's Lua stack and returns a stack-object view for
 * the pushed value.
 */
LuaStackObject LuaState::PushNil()
{
	lua_pushnil(m_state);
	return LuaStackObject(this, lua_gettop(m_state));
}

/**
 * Address: 0x004CCA30 (FUN_004CCA30, LuaPlus::LuaState::PushNumber)
 *
 * What it does:
 * Pushes one numeric value to this state's Lua stack and returns a stack view
 * for the pushed value.
 */
LuaStackObject LuaState::PushNumber(const float n)
{
	lua_pushnumber(m_state, n);
	return LuaStackObject(this, lua_gettop(m_state));
}

LuaStackObject LuaState::Stack(const int32_t index)
{
	return LuaStackObject(this, index);
}

/**
 * Address: 0x0090BFB0 (FUN_0090BFB0, LuaPlus::LuaState::CheckString)
 *
 * What it does:
 * Validates stack slot `index` as string/coercible and returns Lua's internal
 * string pointer + optional byte length.
 */
const char* LuaState::CheckString(const int32_t index, size_t* const lengthOut)
{
	return luaL_checklstring(m_state, index, lengthOut);
}

/**
 * Address: 0x0090C170 (FUN_0090C170, LuaPlus::LuaState::CheckAny)
 *
 * What it does:
 * Raises a Lua argument error when stack slot `index` is missing.
 */
void LuaState::CheckAny(const int32_t index)
{
	luaL_checkany(m_state, index);
}

/**
 * Address: 0x0090BF90 (FUN_0090BF90)
 *
 * What it does:
 * Raises one Lua argument error for argument lane `narg`.
 */
int LuaState::ArgError(const int narg, char* const extraMessage)
{
	return luaL_argerror(m_state, narg, extraMessage);
}

/**
 * Address: 0x0090BFD0 (FUN_0090BFD0)
 *
 * What it does:
 * Returns optional string argument `narg` or `defaultValue`, and writes string
 * byte length when `lengthOut` is non-null.
 */
const char* LuaState::OptString(const int narg, char* const defaultValue, size_t* const lengthOut)
{
	return luaL_optlstring(m_state, narg, defaultValue, lengthOut);
}

/**
 * Address: 0x0090BFF0 (FUN_0090BFF0)
 *
 * What it does:
 * Validates numeric argument `index` and returns its number lane.
 */
lua_Number LuaState::CheckNumber(const int index)
{
	return luaL_checknumber(m_state, index);
}

/**
 * Address: 0x0090C010 (FUN_0090C010)
 *
 * What it does:
 * Returns optional numeric argument `index` or `defaultValue`.
 */
lua_Number LuaState::OptNumber(const int index, const lua_Number defaultValue)
{
	return luaL_optnumber(m_state, index, defaultValue);
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

/**
 * Address: 0x0090C1D0 (FUN_0090C1D0, ?Error@LuaState@LuaPlus@@QAAHPBDZZ)
 *
 * What it does:
 * Formats one varargs error string on the Lua stack and raises `lua_error`.
 */
void LuaState::Error(LuaState* const state, const char* const format, ...)
{
	va_list args;
	va_start(args, format);
	lua_pushvfstring(state->m_state, format, args);
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
 * Copies the stack slot into a LuaObject (0x00908A70) and raises its type error
 * (LuaObject::TypeError, 0x009072D0), e.g. "integer expected but got nil".
 */
void LuaStackObject::TypeError(const char* const expectedType) const
{
	const LuaObject value(*this);
	value.TypeError(expectedType);
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
	// 0x0041B553: tail call to `__ftol2_sse`, so NaN reads as 0x80000000 --
	// `WaitTicks(NaN)` is then a negative tick count and ends the thread.
	return fa::TruncateToInt(lua_tonumber(cState, m_stackIndex));
}

/**
 * Address: 0x004CCB00 (FUN_004CCB00, LuaPlus::LuaStackObject::ToNumber)
 *
 * What it does:
 * Validates that the current stack lane is numeric and returns one Lua number
 * payload; raises `TypeError(\"number\")` for non-numeric values.
 */
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

/**
 * Address: 0x00528140 (FUN_00528140, LuaPlus::LuaStackObject::GetByName)
 *
 * What it does:
 * Pushes `name`, performs one raw lookup against this stack slot, and returns
 * a stack-object view of the lookup result.
 */
LuaStackObject LuaStackObject::GetByName(const char* const name) const
{
	lua_State* const cState = m_state->GetCState();
	lua_pushstring(cState, name);
	lua_rawget(cState, m_stackIndex);
	return LuaStackObject(m_state, lua_gettop(cState));
}


/**
 * Address: 0x009072B0 (FUN_009072B0, LuaPlus::LuaObject::GetActiveState)
 *
 * What it does:
 * Returns the active Lua wrapper state (`stateUserData`) from this object's
 * bound root C-state lane.
 */
LuaState* LuaObject::GetActiveState() const
{
	// An unbound LuaObject answers null rather than faulting. Every caller in
	// this tree already treats null as "no script state": CScriptObject::
	// FindScript reads this straight into `state` and returns early on null,
	// which only means anything if null is reachable. Unit::Unit reaches it that
	// way -- SetAutoMode -> CallbackStr -> FindScript runs at Unit.cpp:13518,
	// before the unit's own Lua object exists -- and without this the read of
	// `m_state->m_state` faulted on address 0.
	if (m_state == nullptr || m_state->m_state == nullptr) {
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

/**
 * Address: 0x0091E200 (FUN_0091E200, func_SerializeLuaObjectName)
 *
 * What it does:
 * Resolves one serialized-name lookup lane from globals key
 * `"__serialize_object_for_name"` and returns the matching table entry for
 * `key`, or Lua's canonical nil object lane when the globals slot is not a
 * table.
 */
[[maybe_unused, nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* const state, TString* const key)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_object_for_name", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt == LUA_TTABLE) {
		return luaH_getstr(static_cast<Table*>(serializeMapObject->value.p), key);
	}

	return &luaO_nilobject;
}

/**
 * Address: 0x0090B990 (FUN_0090B990, LuaPlus::LuaObject::MemberSerialize)
 *
 * What it does:
 * Serializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberSerialize(gpg::WriteArchive* const archive)
{
	Ensure(archive != nullptr, "archive");

	archive->WritePointer<LuaPlus::LuaState>(m_state, gpg::TrackedPointerState::Unowned, gpg::RRef{});

	if (m_state != nullptr) {
		gpg::RRef ownerRef{};
		ownerRef = gpg::MakeRRef<lua_State>(m_state->m_state);
		archive->Write(CachedType<TObject>(gLuaTObjectType), &m_object, ownerRef);
	}
}

/**
 * Address: 0x0090BDD0 (FUN_0090BDD0, LuaPlus::LuaObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	LuaState* state = nullptr;
	(void)archive->ReadPointer(&state, &ownerRef);
	if (state != nullptr) {
		AssignNil(state);

		gpg::RRef stateOwner{};
		stateOwner = gpg::MakeRRef<lua_State>(m_state->m_state);
		archive->Read(CachedType<TObject>(gLuaTObjectType), &m_object, stateOwner);
		return;
	}

	*this = LuaObject{};
}

/**
 * Address: 0x009088E0 (FUN_009088E0, LuaPlus::LuaObject::AddToUsedObjectList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state` and
 * copies the caller-provided raw payload into `m_object`.
 */
void LuaObject::AddToUsedObjectList(LuaState* state, TObject* object)
{
	MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");
	Ensure(object != nullptr, "obj");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
	m_object = *object;
}

/**
 * Address: 0x009099B0 (FUN_009099B0, LuaPlus::LuaObject::AssignTObject)
 *
 * What it does:
 * Rebinds this object to the target root list only when the owner root
 * changes, then copies one caller-provided raw `TObject` payload.
 */
void LuaObject::AssignTObject(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");
	Ensure(object != nullptr, "obj");

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object = *object;
}

/**
 * Address: 0x00908890 (FUN_00908890, LuaPlus::LuaObject::AddToUsedList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state`,
 * preserving the current payload lane.
 */
void LuaObject::AddToUsedList(LuaState* state)
{
	MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
}

/**
 * Address: 0x009096F0 (FUN_009096F0, LuaPlus::LuaObject::AssignThread)
 *
 * What it does:
 * Rebinds this object to one thread `lua_State` payload and enforces root
 * ownership transition semantics for the intrusive used-object list.
 */
void LuaObject::AssignThread(LuaState* const state)
{
	if (state->m_rootState == state) {
		LuaState* const activeState = state->GetActiveState();
		luaG_runerror(activeState->m_state, "attempt to use main lua state as a thread");
	}

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.p = state->m_state;
	m_object.tt = state->m_state->tt;
}

/**
 * Address: 0x009075F0 (FUN_009075F0, LuaPlus::LuaObject::Reset)
 *
 * What it does:
 * Unlinks this object from the owning state intrusive list (when bound),
 * resets the tagged value to nil, and clears state ownership.
 */
void LuaObject::Reset()
{
	if (!m_state) {
		return;
	}

	MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
	if (m_prev && m_next) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
	}
	m_object.tt = LUA_TNIL;
	m_state = nullptr;
	m_next = nullptr;
	m_prev = nullptr;
}

/**
 * Address: 0x00907440 (FUN_00907440, LuaPlus::LuaObject::operator bool)
 *
 * What it does:
 * Applies Lua truthiness rules for this bound object:
 * nil is false, booleans return stored value, everything else is true.
 */
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
 * Address: 0x0090BF00 (FUN_0090BF00)
 *
 * What it does:
 * Performs Lua semantic equality on this value and `other` after matching
 * type tags.
 */
bool LuaObject::operator==(const LuaObject& other) const
{
	if (m_object.tt != other.m_object.tt) {
		return false;
	}

	return luaV_equalval(m_state->m_state, &m_object, &other.m_object) != 0;
}

/**
 * Address: 0x0090BF40 (FUN_0090BF40)
 *
 * What it does:
 * Performs Lua semantic less-than comparison between this value and `other`.
 */
bool LuaObject::operator<(const LuaObject& other) const
{
	return luaV_lessthan(m_state->m_state, &m_object, &other.m_object) != 0;
}

/**
 * Address: 0x009072F0 (FUN_009072F0, LuaPlus::LuaObject::IsNil)
 *
 * What it does:
 * Returns true only for state-bound objects tagged as nil.
 */
bool LuaObject::IsNil() const noexcept
{
	return m_state != nullptr && m_object.tt == LUA_TNIL;
}

/**
 * Address: 0x00907850 (FUN_00907850, LuaPlus::LuaObject::IsNone)
 *
 * What it does:
 * Asserts state binding and returns whether this object carries Lua's
 * `LUA_TNONE` sentinel tag.
 */
bool LuaObject::IsNone() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TNONE;
}

/**
 * Address: 0x009078D0 (FUN_009078D0, LuaPlus::LuaObject::IsBoolean)
 *
 * What it does:
 * Asserts state binding and returns whether this value is a boolean tag.
 */
bool LuaObject::IsBoolean() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TBOOLEAN;
}

/**
 * Address: 0x00907350 (FUN_00907350, LuaPlus::LuaObject::IsNumber)
 *
 * What it does:
 * Returns whether this value carries a numeric Lua tag.
 */
bool LuaObject::IsNumber() const noexcept
{
	return m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x0077F680 (FUN_0077F680, LuaObject::j_IsNumber2 thunk)
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::IsNumber`.
 */
bool LuaObjectIsNumberThunk2(const LuaObject* const object)
{
	return object->IsNumber();
}

/**
 * Address: 0x00907370 (FUN_00907370, LuaPlus::LuaObject::IsString)
 *
 * What it does:
 * Returns whether this value carries a string Lua tag.
 */
bool LuaObject::IsString() const noexcept
{
	return m_object.tt == LUA_TSTRING;
}

/**
 * Address: 0x00907890 (FUN_00907890, LuaPlus::LuaObject::IsLightUserData)
 *
 * What it does:
 * Asserts state binding and returns whether this value carries a light-
 * userdata tag.
 */
bool LuaObject::IsLightUserData() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TLIGHTUSERDATA;
}

/**
 * Address: 0x00907320 (FUN_00907320, LuaPlus::LuaObject::IsUserData)
 *
 * What it does:
 * Returns true for both full userdata and light userdata tags.
 */
bool LuaObject::IsUserData() const noexcept
{
	return m_object.tt == LUA_TUSERDATA || m_object.tt == LUA_TLIGHTUSERDATA;
}

/**
 * Address: 0x00907BC0 (FUN_00907BC0, LuaPlus::LuaObject::GetUserData)
 * Mangled: ?GetUserData@LuaObject@LuaPlus@@QBE?AVRRef@gpg@@XZ
 *
 * IDA signature:
 * gpg::RRef *__thiscall LuaPlus::LuaObject::GetUserData(
 *     LuaPlus::LuaObject *this, gpg::RRef *dest);
 *
 * What it does:
 * Builds the reflection reference a full userdata stands for.
 *
 * Only the full-userdata tag is accepted here - the light-userdata one that
 * `IsUserData` also answers to has no header to read a type out of, so it
 * takes the type-error path.
 *
 * The two loads are the whole contract, and they are worth stating because
 * both hand-rolled copies of this in the tree had them wrong:
 *
 *     lea edx, [ecx+10h]   ; mObj  = the object, laid out after the header
 *     mov ecx, [ecx+0Ch]   ; mType = Udata::len, reinterpreted as RType*
 *
 * This fork reuses `Udata::len` to carry the `gpg::RType*` rather than a
 * byte count, so the reference is assembled from the header and the payload
 * pointer. It is not a `gpg::RRef` stored inside the payload, and the type
 * does not sit inside the payload either.
 */
gpg::RRef LuaObject::GetUserData() const
{
	Ensure(m_state != nullptr, "m_state");

	if (m_object.tt != LUA_TUSERDATA) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as UserData");
	}

	auto* const userdata = static_cast<Udata*>(m_object.value.p);

	gpg::RRef out{};
	out.mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
	out.mType = reinterpret_cast<gpg::RType*>(userdata->len);
	return out;
}

/**
 * Address: 0x00907810 (FUN_00907810, LuaPlus::LuaObject::IsFunction)
 *
 * What it does:
 * Validates state ownership, then treats both Lua closure and C-function
 * tags as callable by checking `(tt | 1) == LUA_TFUNCTION`.
 */
bool LuaObject::IsFunction() const
{
	if (m_state == nullptr) {
		throw LuaAssertion("m_state");
	}

	return (m_object.tt | 1) == LUA_TFUNCTION;
}

/**
 * Address: 0x00907700 (FUN_00907700, LuaPlus::LuaObject::IsConvertibleToInteger)
 *
 * What it does:
 * Returns true when this value is already numeric or can be converted to one
 * via `luaV_tonumber`.
 */
bool LuaObject::IsConvertibleToInteger() const
{
	Ensure(m_state != nullptr, "m_state");

	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER) {
		return true;
	}

	return luaV_tonumber(&m_object, &numericValue) != 0;
}

/**
 * Address: 0x00907760 (FUN_00907760, LuaPlus::LuaObject::IsConvertibleToNumber)
 *
 * What it does:
 * Returns true when this value is already numeric or can be converted to one
 * via `luaV_tonumber`.
 */
bool LuaObject::IsConvertibleToNumber() const
{
	Ensure(m_state != nullptr, "m_state");

	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER) {
		return true;
	}

	return luaV_tonumber(&m_object, &numericValue) != 0;
}

/**
 * Address: 0x009077C0 (FUN_009077C0, LuaPlus::LuaObject::IsConvertibleToString)
 *
 * What it does:
 * Returns true when this value is already string or numeric.
 */
bool LuaObject::IsConvertibleToString() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TSTRING || m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
 *
 * What it does:
 * Raises one Lua type error for the current tagged value on the active thread:
 * `luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, operation)`. The
 * object is never on that thread's stack, so the message is always the plain
 * "<operation> expected but got <type>" (FA-Binary-Patches LuaMessages wording).
 */
void LuaObject::TypeError(const char* const operation) const
{
	luaG_typeerror(GetActiveCState(), &m_object, operation != nullptr ? operation : "value");
}

/**
 * Address: 0x009076D0 (FUN_009076D0, LuaPlus::LuaObject::Type)
 *
 * What it does:
 * Returns this object's raw Lua type tag.
 */
int LuaObject::Type() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt;
}

/**
 * Address: 0x00908B50 (FUN_00908B50, LuaPlus::LuaObject::TypeName)
 *
 * What it does:
 * Returns `"no value"` for `LUA_TNONE`; otherwise returns Lua's typename for
 * this object's current type tag.
 */
const char* LuaObject::TypeName() const
{
	Ensure(m_state != nullptr, "m_state");

	const int type = m_object.tt;
	if (type == LUA_TNONE) {
		return "no value";
	}
	return luaT_typenames[type];
}

/**
 * Address: 0x009074B0 (FUN_009074B0)
 *
 * What it does:
 * Interns `key` and writes `object` into this table through `luaV_settable`. It stays off the Lua
 * stack, so no collection can start here: a string value made by `SetString` is on no stack yet, and
 * a collection would free it.
 */
void LuaObject::SetTableHelper(const char* key, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TString* const interned = luaS_newlstr(lstate, key, std::strlen(key));
	TObject keyObject{};
	keyObject.tt = interned->tt;
	keyObject.value.p = interned;
	luaV_settable(lstate, &m_object, &keyObject, object);
}

/**
 * Address: 0x00907510 (FUN_00907510)
 *
 * What it does:
 * Builds one numeric-key TValue and writes `valueSlot` into this object's
 * table lane using `luaV_settable`.
 */
void LuaObject::SetTableHelperRaw(const int32_t index, const StkId valueSlot)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(valueSlot != nullptr, "valueSlot");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);
	luaV_settable(lstate, &m_object, &key, valueSlot);
}

/**
 * Address: 0x00907550 (FUN_00907550)
 *
 * What it does:
 * Writes one table entry by Lua-object key through `luaV_settable` using one
 * caller-provided value slot.
 */
void LuaObject::SetTableHelperRaw(const LuaObject& key, const StkId valueSlot)
{
	lua_State* const lstate = GetActiveCState();
	luaV_settable(lstate, &m_object, const_cast<TObject*>(&key.m_object), valueSlot);
}

void LuaObject::SetTableHelper(const int32_t index, TObject* object)
{
	SetTableHelperRaw(index, object);
}

/**
 * Address: 0x00907ED0 (FUN_00907ED0, LuaPlus::LuaObject::SetN)
 *
 * What it does:
 * Writes Lua array-length metadata (`n`) for this table object.
 */
void LuaObject::SetN(const int32_t n)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	luaL_setn(lstate, -1, n);
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

	return PushRawLuaObjectToStack(&m_object, state);
}

// Convenience overload with no counterpart in the binary, which exports only
// ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z (0x00907D10). That one
// guards on the two objects sharing a `global_State` and nothing more, so this
// forwarder must not add a stricter test: demanding the same *root* LuaState
// rejects pushes between the sim and UI roots, which are distinct roots over
// one global_State, and that rejection is what was failing every
// cfunc_GetPreference call at startup.
StkId LuaObject::PushStack(LuaState* state) const
{
	Ensure(state != nullptr, "state");
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

/**
 * Address: 0x00909900 (FUN_00909900, LuaPlus::LuaObject::AssignObject)
 *
 * What it does:
 * Copies one source LuaObject tagged payload into this object after enforcing
 * shared-state ownership.
 */
void LuaObject::AssignObject(
	LuaState* const state,
	const LuaObject& value
)
{
	(void)state;
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	m_object.tt = value.m_object.tt;
	m_object.value = value.m_object.value;
}

/**
 * Address: 0x00909650 (FUN_00909650, LuaPlus::LuaObject::AssignInteger)
 *
 * What it does:
 * Rebinds this object to `state` root ownership lane when needed, then stores
 * one integer payload converted to Lua number format.
 */
void LuaObject::AssignInteger(LuaState* state, const int32_t value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.n = static_cast<float>(value);
	m_object.tt = LUA_TNUMBER;
}

/**
 * Address: 0x009096A0 (FUN_009096A0, LuaPlus::LuaObject::AssignNumber)
 *
 * What it does:
 * Rebinds this object to `state` root ownership (when needed) and stores one
 * numeric payload lane.
 */
void LuaObject::AssignNumber(LuaState* state, const double number)
{
	RebindToState(*this, state);
	m_object.value.n = static_cast<float>(number);
	m_object.tt = LUA_TNUMBER;
}

/**
 * Address: 0x009095C0 (FUN_009095C0, LuaPlus::LuaObject::AssignNil)
 *
 * IDA signature:
 * void __thiscall LuaPlus::LuaObject::AssignNil(
 *     LuaPlus::LuaObject *this, LuaPlus::LuaState *state);
 *
 * What it does:
 * Rebinds this object to `state` and sets its payload to nil. The unlink from
 * the previous state's used-object chain lives in RebindToState, which is what
 * the binary open-codes here before writing the tag.
 */
void LuaObject::AssignNil(LuaState* state)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TNIL;
	m_object.value.p = nullptr;
}

/**
 * Address: 0x00909600 (FUN_00909600, LuaPlus::LuaObject::AssignBoolean)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * boolean payload lane (`LUA_TBOOLEAN`).
 */
void LuaObject::AssignBoolean(LuaState* state, const bool value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object.value.b = value ? 1u : 0u;
	*reinterpret_cast<std::uint32_t*>(&m_object.tt) = LUA_TBOOLEAN;
}

/**
 * Address: 0x00909750 (FUN_00909750, LuaPlus::LuaObject::AssignString)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * interned string payload or marks this object as `LUA_TNIL` for null input.
 */
void LuaObject::AssignString(LuaState* state, const char* value)
{
	RebindToState(*this, state);
	if (value == nullptr) {
		m_object.tt = LUA_TNIL;
		return;
	}

	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
	m_object.tt = interned->tt;
	m_object.value.p = interned;
}

void LuaObject::AssignLightUserData(LuaState* state, void* value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TLIGHTUSERDATA;
	SetLightPointer(m_object.value, value);
}

/**
 * Address: 0x009097D0 (FUN_009097D0, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, allocates one default-
 * constructed userdata payload for `type`, and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RType* type)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	Ensure(type != nullptr, "type");

	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = luaS_newudata(lstate, const_cast<gpg::RType*>(type));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x00909840 (FUN_00909840, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, then materializes one
 * reflected userdata lane from `value` and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RRef& value)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = CreateRefUserdata(lstate, const_cast<gpg::RRef*>(&value));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x009084E0 (FUN_009084E0, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by integer index using a string-or-nil payload.
 */
void LuaObject::SetString(const int32_t index, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	TObject keyObject{};
	keyObject.value.n = static_cast<float>(index);
	keyObject.tt = LUA_TNUMBER;
	luaV_settable(lstate, &m_object, &keyObject, &valueObject);
}

/**
 * Address: 0x00908450 (FUN_00908450, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by string key using a string-or-nil payload.
 */
void LuaObject::SetString(const char* key, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	SetTableHelper(key, &valueObject);
}

/**
 * Address: 0x00908590 (FUN_00908590, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by LuaObject key using a string-or-nil payload after
 * enforcing shared-state ownership with `key`.
 */
void LuaObject::SetString(const LuaObject& key, const char* value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
	}

	SetTableHelperRaw(key, &valueObject);
}

/**
 * Address: 0x00908630 (FUN_00908630, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by string key.
 */
void LuaObject::SetLightUserData(const char* const key, void* const value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TLIGHTUSERDATA;
	SetLightPointer(object.value, value);
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908680 (FUN_00908680, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by integer key.
 */
void LuaObject::SetLightUserData(const int32_t index, void* const value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject val{};
	SetLightPointer(val.value, value);
	val.tt = LUA_TLIGHTUSERDATA;

	TObject key{};
	key.value.n = static_cast<float>(index);
	key.tt = LUA_TNUMBER;

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009086F0 (FUN_009086F0, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by LuaObject key after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetLightUserData(const LuaObject& key, void* const value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	SetLightPointer(val.value, value);
	val.tt = LUA_TLIGHTUSERDATA;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00907FF0 (FUN_00907FF0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by string key.
 */
void LuaObject::SetNil(const char* const key)
{
	Ensure(m_state != nullptr, "m_state");

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;
	SetTableHelper(key, &nilObject);
}

/**
 * Address: 0x00907FA0 (FUN_00907FA0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by integer key.
 */
void LuaObject::SetNil(const int32_t index)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;

	luaV_settable(lstate, &m_object, &keyObject, &nilObject);
}

/**
 * Address: 0x00908060 (FUN_00908060, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes one nil payload to this table by LuaObject key after validating
 * shared-state ownership with `key`.
 */
void LuaObject::SetNil(const LuaObject& key)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;

	SetTableHelperRaw(key, &nilObject);
}

/**
 * Address: 0x00908320 (FUN_00908320, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by string key using a numeric payload.
 */
void LuaObject::SetNumber(const char* key, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TNUMBER;
	object.value.n = value;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908370 (FUN_00908370, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by integer key using a numeric payload.
 */
void LuaObject::SetNumber(const int32_t index, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = value;

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009083E0 (FUN_009083E0, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by LuaObject key using a numeric payload after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetNumber(const LuaObject& key, const float value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = value;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00908240 (FUN_00908240, ?SetInteger@LuaObject@LuaPlus@@QBEXHH@Z)
 *
 * What it does:
 * Writes one table entry by integer key using an integer payload.
 */
void LuaObject::SetInteger(const int32_t index, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = static_cast<float>(value);

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009081F0 (FUN_009081F0, ?SetInteger@LuaObject@LuaPlus@@QBEXPBDH@Z)
 *
 * What it does:
 * Writes one table entry by string key using an integer payload lane.
 */
void LuaObject::SetInteger(const char* key, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TNUMBER;
	object.value.n = static_cast<float>(value);
	SetTableHelper(key, &object);
}

/**
 * Address: 0x009082B0 (FUN_009082B0, LuaPlus::LuaObject::SetInteger)
 *
 * What it does:
 * Writes one table entry by LuaObject key using an integer payload lane after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetInteger(const LuaObject& key, const int32_t value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = static_cast<float>(value);

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x009080C0 (FUN_009080C0, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by string key.
 */
void LuaObject::SetBoolean(const char* key, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TBOOLEAN;
	object.value.b = value ? 1 : 0;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908110 (FUN_00908110, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by integer key.
 */
void LuaObject::SetBoolean(const int32_t index, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject val{};
	val.value.b = value ? 1 : 0;
	val.tt = LUA_TBOOLEAN;

	TObject key{};
	key.value.n = static_cast<float>(index);
	key.tt = LUA_TNUMBER;

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x00908180 (FUN_00908180, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by LuaObject key after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetBoolean(const LuaObject& key, const bool value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.value.b = value ? 1 : 0;
	val.tt = LUA_TBOOLEAN;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00908760 (FUN_00908760, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table field by string key after enforcing shared-state ownership
 * with the source Lua object value.
 */
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

/**
 * Address: 0x00908810 (FUN_00908810, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table entry by LuaObject key/value lanes after validating shared
 * state ownership.
 */
void LuaObject::SetObject(const LuaObject& key, const LuaObject& value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");
	Ensure(m_state == value.m_state, "m_state == value.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	SetTableHelperRaw(key, const_cast<TObject*>(&value.m_object));
}

/**
 * Address: 0x009087A0 (FUN_009087A0, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one object value into this table by integer key after enforcing
 * shared Lua-state ownership with `value`.
 */
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

namespace
{
	struct OwnerWordLaneAt68
	{
		std::byte pad00[68];
		std::uint32_t lane44;
	};
	static_assert(offsetof(OwnerWordLaneAt68, lane44) == 68, "OwnerWordLaneAt68::lane44 offset must be 68");

	struct OwnerWordWritePair
	{
		OwnerWordLaneAt68* owner;
		std::uint32_t value;
	};
	static_assert(sizeof(OwnerWordWritePair) == 0x08, "OwnerWordWritePair size must be 0x08");

	/**
	 * Address: 0x00929BE0 (FUN_00929BE0)
	 *
	 * What it does:
	 * Stores one 32-bit value into owner field `+0x44` (`+0x68` bytes) and
	 * returns the owner pointer lane.
	 */
	[[maybe_unused]] OwnerWordLaneAt68* StoreOwnerWordLaneAt68(
		OwnerWordWritePair* const writePair
	)
	{
		if (writePair == nullptr || writePair->owner == nullptr) {
			return nullptr;
		}

		writePair->owner->lane44 = writePair->value;
		return writePair->owner;
	}

	/**
	 * Address: 0x009284D0 (FUN_009284D0)
	 *
	 * IDA signature:
	 * void __cdecl sub_9284D0(lua_State *L, TObject *o, GCObject *mt);
	 *
	 * What it does:
	 * Assigns one metatable object to a tagged Lua value:
	 * table/userdata instances store direct metatable pointers while all other
	 * tag lanes update `global_State::_defaultmetatypes[tt]`. The binary
	 * dispatches on the tag alone - it validates neither the pointers nor the
	 * tag range, so neither does this.
	 */
	void AssignMetatableByTaggedValueType(
		lua_State* const state,
		LuaPlus::TObject* const object,
		GCObject* const metatableObject
	)
	{
		if (object->tt == LUA_TTABLE) {
			static_cast<Table*>(object->value.p)->metatable = reinterpret_cast<Table*>(metatableObject);
			return;
		}

		if (object->tt == LUA_TUSERDATA) {
			static_cast<Udata*>(object->value.p)->metatable = reinterpret_cast<Table*>(metatableObject);
			return;
		}

		TObject& slot = state->l_G->_defaultmetatypes[object->tt];
		slot.tt = static_cast<int>(metatableObject->gch.tt);
		slot.value.p = metatableObject;
	}
}

/**
 * Address: 0x00907E00 (FUN_00907E00, LuaPlus::LuaObject::SetMetaTable)
 *
 * What it does:
 * Validates that both objects share one Lua state and applies `valueObj` as
 * this object's runtime metatable.
 */
void LuaObject::SetMetaTable(const LuaObject& valueObj)
{
	Ensure(m_state && m_state == valueObj.m_state, "m_state && m_state == valueObj.m_state");

	AssignMetatableByTaggedValueType(
		m_state->GetCState(),
		&m_object,
		static_cast<GCObject*>(valueObj.m_object.value.p)
	);
}

/**
 * Address: 0x00908BA0 (FUN_00908BA0, LuaPlus::LuaObject::GetMetaTable)
 *
 * What it does:
 * Fetches this object's runtime metatable and returns it as a bound LuaObject.
 */
LuaObject LuaObject::GetMetaTable() const
{
	Ensure(m_state != nullptr, "m_state");

	Table* const metatable = luaT_getmetatable(m_state->m_state, &m_object);

	LuaObject out(m_state);
	out.m_object.value.p = metatable;
	out.m_object.tt = metatable->tt;
	return out;
}

/**
 * Address: 0x00908C10 (FUN_00908C10, LuaPlus::LuaObject::CreateTable)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at string key `key`.
 */
LuaObject LuaObject::CreateTable(const char* const key, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;
	SetTableHelper(key, &out.m_object);
	return out;
}

/**
 * Address: 0x00908CA0 (FUN_00908CA0, LuaPlus::LuaObject::CreateTable_Array)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at integer key
 * `index`.
 */
LuaObject LuaObject::CreateTable(const int32_t index, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);
	luaV_settable(lstate, &m_object, &keyObject, &out.m_object);
	return out;
}

/**
 * Address: 0x00908D50 (FUN_00908D50, LuaPlus::LuaObject::CreateTable)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table under LuaObject key
 * `key`.
 */
LuaObject LuaObject::CreateTable(
	const LuaObject& key,
	const int32_t narray,
	const int32_t lnhash
)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.tt = table->tt;
	out.m_object.value.p = table;

	SetTableHelperRaw(key, &out.m_object);
	return out;
}

// Reopen the same unnamed namespace that houses LuaCall and the
// three recovered frame primitives so we can build a typed `table.method()`
// driver on top of them without duplicating their layout.
namespace
{
	// Intent-first typed frame wrapper used by LuaObject::Insert / Remove / Sort.
	// Delegates to the recovered 2007 primitives from earlier in this TU:
	//   ConstructLuaCallFrame            (0x00909A00, FUN_00909A00)
	//   InvokeLuaCallFrame               (0x00907270, FUN_00907270)
	//   PushLuaObjectArgumentToCallFrame (0x00908940, FUN_00908940)
	void RunLuaTableMethodCallFrame(
		LuaState* const activeState,
		LuaObject& methodFunction,
		LuaObject* const arg0 = nullptr,
		const bool pushNumericArg = false,
		const lua_Number numericArg = 0.0,
		LuaObject* const arg2 = nullptr
	)
	{
		(void)activeState;

		LuaCall frame{};
		(void)ConstructLuaCallFrame(&frame, &methodFunction);

		if (arg0 != nullptr) {
			(void)PushLuaObjectArgumentToCallFrame(&frame, arg0);
		}

		if (pushNumericArg) {
			// 0x00909D9E: `lua_pushnumber(state->m_state, (float)key)` -- the
			// number goes on the FRAME's thread, the same one every other
			// argument and `lua_call` use, never on the caller's wrapper.
			lua_pushnumber(frame.m_state->m_state, numericArg);
			++frame.m_numArgs;
		}

		if (arg2 != nullptr) {
			(void)PushLuaObjectArgumentToCallFrame(&frame, arg2);
		}

		LuaStackObject result(activeState, 0);
		const int multret = LUA_MULTRET;
		(void)InvokeLuaCallFrame(&frame, &result, &multret);
	}
} // namespace

/**
 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Runs `table.insert(this, key, obj)` by constructing one Lua call-frame
 * view (FUN_00909A00) over the resolved `table.insert` function, pushing
 * `this`, the numeric key, and the value `obj` as arguments onto it,
 * invoking the frame, and restoring the original Lua stack top.
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

		LuaObject thisCopy(*this);
		LuaObject objCopy(obj);
		RunLuaTableMethodCallFrame(
			activeState,
			insertFunction,
			&thisCopy,
			true,
			static_cast<lua_Number>(key),
			&objCopy
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00909AF0 (FUN_00909AF0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Runs `table.insert(this, obj)` (no explicit index -- appends at the end)
 * by constructing one Lua call-frame view (FUN_00909A00) over the resolved
 * `table.insert` function, pushing `this` and the value `obj` as arguments
 * onto it, invoking the frame, and restoring the original Lua stack top.
 * Same shape as the two-argument overload above with the numeric-key push
 * omitted.
 */
void LuaObject::Insert(const LuaObject& obj) const
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

		LuaObject thisCopy(*this);
		LuaObject objCopy(obj);
		RunLuaTableMethodCallFrame(
			activeState,
			insertFunction,
			&thisCopy,
			false,
			0.0,
			&objCopy
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00909EB0 (FUN_00909EB0, LuaPlus::LuaObject::Remove)
 *
 * What it does:
 * Runs `table.remove(this, index)` by constructing one Lua call-frame view
 * (FUN_00909A00) over `table.remove`, pushing `this` and the numeric index
 * as arguments, invoking the frame, and restoring the original Lua stack
 * top.
 */
void LuaObject::Remove(const int32_t index) const
{
	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject removeFunction = tableObject["remove"];

		LuaObject thisCopy(*this);
		RunLuaTableMethodCallFrame(
			activeState,
			removeFunction,
			&thisCopy,
			true,
			static_cast<lua_Number>(index),
			nullptr
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x0090A020 (FUN_0090A020, LuaPlus::LuaObject::Sort)
 *
 * What it does:
 * Runs `table.sort(this)` by constructing one Lua call-frame view
 * (FUN_00909A00) over `table.sort`, pushing `this` as the single argument,
 * invoking the frame, and restoring the original Lua stack top.
 */
void LuaObject::Sort() const
{
	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject sortFunction = tableObject["sort"];

		LuaObject thisCopy(*this);
		RunLuaTableMethodCallFrame(
			activeState,
			sortFunction,
			&thisCopy,
			false,
			0.0,
			nullptr
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 * Address: 0x00908DF0 (FUN_00908DF0, __imp_?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 *
 * IDA signature:
 * LuaPlus::LuaObject *__thiscall GetByIndex(LuaObject *this, LuaObject *dest, int index);
 *
 * What it does:
 * Reads one entry out of this object's own tagged value by numeric key. The
 * lookup runs straight through `luaV_gettable` on `m_object` - the sibling of
 * `GetByObject` - and the resolved slot is bound into a fresh LuaObject on the
 * same root state.
 *
 * The Lua stack is deliberately not involved. Routing this through
 * `PushStack`/`lua_gettable` and then reading slot -1 back through a
 * `LuaStackObject` bound to `m_state` mixes two different threads: the push
 * lands on `l_G->lstate` (whichever coroutine is running) while the read
 * indexes `m_state->m_state` (the root). Inside a sim coroutine those are
 * different stacks, so every lookup returned whatever the root happened to
 * have on top - typically a stale error string. That is how class metatables
 * fetched out of `__factory_objects` turned into `TString`s.
 */
LuaObject LuaObject::GetByIndex(const int32_t index) const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject key{};
	key.value.n = static_cast<lua_Number>(index);
	key.tt = LUA_TNUMBER;

	const TObject* const rawValue = luaV_gettable(lstate, &m_object, &key, 0);
	return LuaObject(m_state, const_cast<TObject*>(rawValue));
}

/**
 * Address: 0x00908E70 (FUN_00908E70, LuaPlus::LuaObject::GetByObject)
 *
 * What it does:
 * Looks up this table using a LuaObject key and returns the raw slot value.
 */
LuaObject LuaObject::GetByObject(const LuaObject& key) const
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const TObject* const rawValue = luaV_gettable(lstate, &m_object, &key.m_object, 0);
	LuaObject out;
	out.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return out;
}

/**
 * Address: 0x00908EE0 (FUN_00908EE0, LuaPlus::LuaObject::GetByObject)
 *
 * What it does:
 * Looks up this table using one `LuaStackObject` key lane and returns the
 * resolved raw slot value as a bound LuaObject.
 */
LuaObject LuaObject::GetByObject(const LuaStackObject& obj) const
{
	Ensure(m_state == obj.m_state->m_rootState, "m_state == obj.m_state->m_rootState");

	lua_State* const lstate = GetActiveCState();
	TObject* const keyObject = luaA_index(lstate, obj.m_stackIndex);
	const TObject* const rawValue = luaV_gettable(lstate, &m_object, keyObject, 0);
	return LuaObject(m_state, const_cast<TObject*>(rawValue));
}

/**
 * Address: 0x0090A160 (FUN_0090A160, LuaPlus::LuaObject::GetByName)
 * Mangled: ?GetByName@LuaObject@LuaPlus@@QBE?AV12@PBD@Z
 *
 * IDA signature:
 * LuaPlus::LuaObject *__userpurge LuaPlus::LuaObject::GetByName@<eax>(
 *     LuaPlus::LuaObject *this@<ecx>, LuaPlus::LuaObject *dest, const char *name);
 *
 * What it does:
 * Forwards straight to operator[](const char*), which reads the table slot
 * with luaH_get. The lookup is therefore raw: no __index metamethod runs, and
 * a key the table does not hold itself comes back nil rather than escalating
 * to whatever the module's environment chain would do with it.
 */
LuaObject LuaObject::GetByName(const char* name) const
{
	return (*this)[name];
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

	const TObject* const rawValue = luaH_get(static_cast<Table*>(m_object.value.p), &keyObject);
	Ensure(rawValue != nullptr, "obj");

	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x00909280 (FUN_00909280, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates state + table type for LuaObject-key indexing, then fetches the
 * raw keyed slot directly from Lua's table storage.
 */
LuaObject LuaObject::operator[](const LuaObject& key) const
{
	if (m_state != key.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	const TObject* const rawValue = luaH_get(static_cast<Table*>(m_object.value.p), &key.m_object);
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

	const TObject* const rawValue = luaH_getnum(static_cast<Table*>(m_object.value.p), index);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x00909310 (FUN_00909310, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates root-state compatibility for LuaStackObject-key indexing, then
 * resolves the stack key and fetches the raw keyed table slot.
 */
LuaObject LuaObject::operator[](const LuaStackObject& key) const
{
	const LuaState* const rootState = m_state;
	const LuaState* const keyRootState = (key.m_state != nullptr) ? key.m_state->m_rootState : nullptr;
	if (rootState != keyRootState) {
		throw LuaAssertion("m_state == obj.m_state->m_rootState");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	TObject* const stackKey = luaA_index(lstate, key.m_stackIndex);
	const TObject* const rawValue = luaH_get(static_cast<Table*>(m_object.value.p), stackKey);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009093B0 (FUN_009093B0, LuaPlus::LuaObject::Lookup)
 *
 * What it does:
 * Traverses a dotted path and alternates string-key vs numeric-index lookup
 * based on each segment's parse result.
 */
LuaObject LuaObject::Lookup(const char* const path) const
{
	if (path == nullptr || *path == '\0') {
		return *this;
	}

	auto tryParseIndex = [](const char* const text, int32_t* const outIndex) -> bool
	{
		if (text == nullptr || *text == '\0' || outIndex == nullptr) {
			return false;
		}

		char* parseEnd = nullptr;
		const double parsedValue = std::strtod(text, &parseEnd);
		if (parseEnd == text || parseEnd == nullptr || *parseEnd != '\0') {
			return false;
		}

		const double minValue = static_cast<double>(std::numeric_limits<int32_t>::min());
		const double maxValue = static_cast<double>(std::numeric_limits<int32_t>::max());
		if (parsedValue < minValue || parsedValue > maxValue) {
			return false;
		}

		*outIndex = static_cast<int32_t>(parsedValue);
		return true;
	};

	LuaObject current = *this;
	std::string mutablePath(path);
	char* segment = mutablePath.data();
	char* dot = std::strchr(segment, '.');

	while (dot != nullptr) {
		*dot = '\0';
		if (*segment == '\0') {
			return {};
		}

		int32_t numericIndex = 0;
		current = tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
		if (current.IsNil()) {
			return current;
		}

		segment = dot + 1;
		dot = std::strchr(segment, '.');
	}

	if (*segment == '\0') {
		return {};
	}

	int32_t numericIndex = 0;
	return tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
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

/**
 * Address: 0x00907F50 (FUN_00907F50, LuaPlus::LuaObject::GetCount)
 *
 * What it does:
 * Pushes this object to the active Lua stack, reads Lua table length via
 * `lua_getn`, then restores stack top and returns that element count.
 */
int32_t LuaObject::GetCount() const
{
	Ensure(m_state != nullptr, "m_state");

	LuaState* const activeState = GetActiveState();
	Ensure(activeState != nullptr, "active state");
	Ensure(activeState->m_state != nullptr, "active lua state");

	const int oldTop = lua_gettop(activeState->m_state);
	const_cast<LuaObject*>(this)->PushStack(activeState);
	const int stackIndex = lua_gettop(activeState->m_state);
	const int32_t count = static_cast<int32_t>(lua_getn(activeState->m_state, stackIndex));
	lua_settop(activeState->m_state, oldTop);
	return count;
}

/**
 * Address: 0x0090A410 (FUN_0090A410, LuaPlus::LuaObject::GetTableCount)
 *
 * What it does:
 * Iterates all table entries and returns the number of key/value pairs.
 */
int32_t LuaObject::GetTableCount() const
{
	int32_t count = 0;
	LuaTableIterator iter(*this, 1);
	while (!iter.m_isDone) {
		++count;
		iter.Next();
	}
	return count;
}

/**
 * Address: 0x00907630 (FUN_00907630, LuaPlus::LuaObject::Register)
 *
 * What it does:
 * Creates one C closure with `tagMethod` upvalues from the Lua root-state
 * stack, then assigns it into this table object under `key`.
 */
void LuaObject::Register(const char* const key, CFunction const value, const int32_t tagMethod)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state->m_state != nullptr, "lua state");
	Ensure(m_state->m_state->l_G != nullptr, "lua global state");
	Ensure(key != nullptr, "key");
	Ensure(value != nullptr, "value");

	lua_State* const closureState = m_state->m_state->l_G->lstate;
	Ensure(closureState != nullptr, "closure state");

	Closure* const closure = luaF_newCclosure(closureState, tagMethod);
	closure->c.f = value;
	closureState->top -= tagMethod;

	for (int upvalueIndex = tagMethod - 1; upvalueIndex >= 0; --upvalueIndex) {
		closure->c.upvalue[upvalueIndex] = closureState->top[upvalueIndex];
		closureState->top[upvalueIndex].tt = 0;
	}

	TObject closureObject{};
	closureObject.value.p = closure;
	closureObject.tt = static_cast<int>(closure->c.tt);
	SetTableHelper(key, &closureObject);
}

namespace
{
	// Wire tags of the SCR byte-stream format, written by LuaObject::ToByteStream.
	constexpr int8_t kScrTagNumber = 0;
	constexpr int8_t kScrTagString = 1;
	constexpr int8_t kScrTagNil = 2;
	constexpr int8_t kScrTagBoolean = 3;
	constexpr int8_t kScrTagTableBegin = 4;
	constexpr int8_t kScrTagTableEnd = 5;

	// Deepest table nesting the decoder rebuilds. Each nested table is one
	// recursion, and a 64 KB lobby message or sim callback holds 65535
	// table-begin tags, enough to overflow any thread's stack. Nothing the
	// engine or the game's Lua sends nests within an order of magnitude of it.
	// Tables below this depth are skipped, not refused: FAF's lobby relays what
	// a player sent a few levels deeper (a joiner's player options end up in
	// the host's Launch message), so refusing would let one player's deep table
	// stop everyone else's launch.
	constexpr int kScrMaxTableDepth = 256;

	// The stream comes off the network (lobby data, sim callbacks, chat), so a
	// malformed one is the sender's fault: it fails the decode like a short
	// read (BinaryReader::PrematureEOF) does, and the caller drops it.
	[[noreturn]] void ThrowMalformedScrStream(const char* const reason)
	{
		throw std::runtime_error(std::string("Malformed lua byte stream: ") + reason);
	}

	bool ReadScrValue(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader, int tablesLeft);
} // namespace

/**
 * Address: 0x004D2A40 (FUN_004D2A40, Moho::SCR_FromByteStream)
 *
 * What it does:
 * Deserializes one tagged Lua payload from a binary stream and recursively
 * rebuilds nested table key/value pairs.
 *
 * A malformed stream (truncated, or a table entry whose key or value is nil
 * or whose key is NaN) throws a std::runtime_error; the shipped body called
 * gpg::Die for a nil key or value and recursed without bound, so any peer
 * could end the process. A table entry whose key or value nests deeper than
 * kScrMaxTableDepth is skipped without recursion and left out.
 */
void LuaObject::SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader)
{
	Ensure(state != nullptr, "state");
	Ensure(reader != nullptr, "reader");

	ReadScrValue(out, state, reader, kScrMaxTableDepth);
}

/**
 * Engine addition, not in the binary: see the declaration. The stream was
 * written by ToByteStream in this process, which recursed as deep as this
 * decode will, so the nesting cap guards nothing here.
 */
void LuaObject::SCR_FromLocalByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader)
{
	Ensure(state != nullptr, "state");
	Ensure(reader != nullptr, "reader");

	ReadScrValue(out, state, reader, std::numeric_limits<int>::max());
}

namespace
{
	/**
	 * What it does:
	 * Consumes the rest of a table whose begin tag has been read, nested
	 * tables included, with a counter instead of recursion.
	 */
	void SkipScrTable(const gpg::BinaryReader* const reader)
	{
		std::size_t openTables = 1;
		while (openTables != 0) {
			int8_t luaType = 0;
			reader->ReadExact(luaType);
			switch (luaType) {
				case kScrTagNumber: {
					float number = 0.0f;
					reader->ReadExact(number);
					break;
				}
				case kScrTagString: {
					fa::string string;
					reader->ReadString(&string);
					break;
				}
				case kScrTagBoolean: {
					int8_t byteValue = 0;
					reader->ReadExact(byteValue);
					break;
				}
				case kScrTagTableBegin:
					++openTables;
					break;
				case kScrTagTableEnd:
					--openTables;
					break;
				default:
					break;
			}
		}
	}

	/**
	 * What it does:
	 * The body of SCR_FromByteStream, one tagged value at a time;
	 * `tablesLeft` is how many more levels of table nesting may be opened.
	 * Returns false for a table past that depth, which is skipped instead.
	 */
	bool ReadScrValue(LuaObject& out, LuaState* const state, const gpg::BinaryReader* const reader, const int tablesLeft)
	{
		LuaObject result;
		int8_t luaType = 0;
		reader->ReadExact(luaType);

		switch (luaType) {
			case kScrTagNumber: {
				float number = 0.0f;
				reader->ReadExact(number);
				result.AssignNumber(state, number);
				break;
			}
			case kScrTagString: {
				fa::string string;
				reader->ReadString(&string);
				result.AssignString(state, string.c_str());
				break;
			}
			case kScrTagNil:
				result.AssignNil(state);
				break;
			case kScrTagBoolean: {
				int8_t byteValue = 0;
				reader->ReadExact(byteValue);
				result.AssignBoolean(state, byteValue != 0);
				break;
			}
			case kScrTagTableBegin: {
				if (tablesLeft <= 0) {
					SkipScrTable(reader);
					return false;
				}
				result.AssignNewTable(state, 0, 0);

				// Peek the next tag through Stream::CheckByte: it reads one byte and
				// rewinds the read window by one. Reaching for the virtual unget
				// directly instead skips that rewind, and MemBufferStream's override
				// throws unconditionally - which made every table fail to load.
				gpg::Stream& stream = *const_cast<gpg::Stream*>(reader->stream());
				while (stream.CheckByte() != kScrTagTableEnd) {
					LuaObject key;
					const bool haveKey = ReadScrValue(key, state, reader, tablesLeft - 1);
					if (haveKey && key.IsNil()) {
						ThrowMalformedScrStream("nil table key");
					}
					// A NaN key makes luaH_set raise a Lua error, which unwinds with
					// the error message still pushed on the Lua stack.
					if (haveKey && key.IsNumber() && key.GetNumber() != key.GetNumber()) {
						ThrowMalformedScrStream("NaN table key");
					}

					LuaObject value;
					const bool haveValue = ReadScrValue(value, state, reader, tablesLeft - 1);
					if (haveValue && value.IsNil()) {
						ThrowMalformedScrStream("nil table value");
					}

					// An entry with a key or value nested too deeply is left out.
					if (haveKey && haveValue) {
						result.SetObject(key, value);
					}
				}

				// Consume the end-of-table tag the peek left in place.
				(void)reader->ReadChar();
				break;
			}
			case kScrTagTableEnd:
				gpg::Warnf("Error deseralizing lua object: unexpected end-of-table marker encountered.");
				result.AssignNil(state);
				break;
			default:
				gpg::Warnf("Attempt to deserialize unknown lua data.");
				result.AssignNil(state);
				break;
		}

		out = result;
		return true;
	}
} // namespace

/**
 * Address: 0x00907C90 (FUN_00907C90, LuaPlus::LuaObject::GetBoolean)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-nil/non-boolean values, and returns Lua truthiness for boolean lanes.
 */
bool LuaObject::GetBoolean() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TNIL && m_object.tt != LUA_TBOOLEAN) {
		luaG_typeerror(lstate, &m_object, "get as boolean");
	}

	return m_object.tt != LUA_TNIL && (m_object.tt != LUA_TBOOLEAN || m_object.value.b != 0);
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

/**
 * Address: 0x00907410 (FUN_00907410, LuaPlus::LuaObject::ToStrLen)
 *
 * What it does:
 * Returns current string length when already string, otherwise tries Lua's
 * number-to-string conversion and returns resulting length on success.
 */
int32_t LuaObject::ToStrLen()
{
	if (m_object.tt == LUA_TSTRING) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	if (luaV_tostring(m_state->m_state, &m_object) != 0) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	return 0;
}

/**
 * Address: 0x00907380 (FUN_00907380)
 *
 * What it does:
 * Returns one integer truncation of this value when numeric/coercible,
 * otherwise returns `0`.
 */
int32_t LuaObject::ToInteger() const
{
	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER || luaV_tonumber(&m_object, &numericValue) != 0) {
		return static_cast<int32_t>(m_object.value.n);
	}
	return 0;
}

/**
 * Address: 0x009073B0 (FUN_009073B0, LuaPlus::LuaObject::ToNumber)
 *
 * What it does:
 * Returns numeric payload when already numeric, otherwise attempts Lua numeric
 * coercion and returns `0` on conversion failure.
 */
double LuaObject::ToNumber() const
{
	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER || luaV_tonumber(&m_object, &numericValue) != 0) {
		return static_cast<double>(m_object.value.n);
	}
	return 0.0;
}

/**
 * Address: 0x009073E0 (FUN_009073E0, LuaPlus::LuaObject::ToString)
 *
 * What it does:
 * Returns the current interned string buffer when this object is already a
 * string, otherwise attempts in-place Lua coercion via `luaV_tostring` and
 * returns `nullptr` when conversion fails.
 */
const char* LuaObject::ToString() const
{
	if (m_object.tt == LUA_TSTRING) {
		return static_cast<const GCObject*>(m_object.value.p)->ts.str;
	}

	TObject* const object = const_cast<TObject*>(&m_object);
	if (luaV_tostring(m_state->m_state, object) != 0) {
		return static_cast<const GCObject*>(object->value.p)->ts.str;
	}

	return nullptr;
}

/**
 * Address: 0x00907970 (FUN_00907970, LuaPlus::LuaObject::GetNumber)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns numeric payload.
 */
double LuaObject::GetNumber() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as number");
	}
	return static_cast<double>(m_object.value.n);
}

/**
 * Address: 0x009079D0 (FUN_009079D0)
 *
 * What it does:
 * Validates LuaObject state/type and returns the numeric payload as one float
 * lane (`Value::n`), raising Lua's type-error lane for non-numeric values.
 */
float LuaObjectGetNumberAsFloat(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as number");
	}
	return object->m_object.value.n;
}

/**
 * Address: 0x00907AF0 (FUN_00907AF0)
 *
 * What it does:
 * Validates LuaObject state/type and returns one interned Lua string buffer,
 * raising Lua's typed-operation error lane on non-string values.
 */
const char* LuaObjectGetStringChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TSTRING) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "string");
	}

	const auto* const text = static_cast<const TString*>(object->m_object.value.p);
	return text->str;
}

/**
 * Address: 0x00907B50 (FUN_00907B50)
 *
 * What it does:
 * Validates LuaObject state/type for function access and returns one C closure
 * entrypoint pointer, or `nullptr` if Lua still reports a non-function lane.
 */
CFunction LuaObjectGetCFunctionChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");

	bool isFunctionType = object->m_object.tt == LUA_TFUNCTION;
	if (!isFunctionType) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as C function");
		isFunctionType = object->m_object.tt == LUA_TFUNCTION;
	}

	if (!isFunctionType) {
		return nullptr;
	}

	const auto* const closure = static_cast<const CClosure*>(object->m_object.value.p);
	return closure != nullptr ? closure->f : nullptr;
}

/**
 * Address: 0x00907C30 (FUN_00907C30)
 *
 * What it does:
 * Validates LuaObject state/type and returns the raw light-userdata pointer
 * payload (`Value::p`) from this tagged object.
 */
void* LuaObjectGetLightUserDataChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TLIGHTUSERDATA) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as light userdata");
	}

	return LightPointer(object->m_object.value);
}

/**
 * Address: 0x009166B0 (FUN_009166B0)
 *
 * What it does:
 * Fetches one boolean field from the date-table lane at stack index `-2` and
 * returns the converted truth-value while restoring the original stack top.
 */
bool LuaDateGetBooleanField(
	const char* const fieldName,
	lua_State* const  state
)
{
	Ensure(state != nullptr, "state");
	Ensure(fieldName != nullptr, "fieldName");

	lua_pushstring(state, fieldName);
	lua_gettable(state, -2);
	const bool value = lua_toboolean(state, -1) != 0;
	lua_settop(state, -2);
	return value;
}

/**
 * Address: 0x009166E0 (FUN_009166E0)
 *
 * What it does:
 * Fetches one numeric field from the date-table lane at stack index `-2`;
 * returns `defaultValue` on non-number fields and raises when required.
 */
int LuaDateGetNumericFieldOrDefault(
	int               defaultValue,
	const char* const fieldName,
	lua_State* const  state
)
{
	Ensure(state != nullptr, "state");
	Ensure(fieldName != nullptr, "fieldName");

	lua_pushstring(state, fieldName);
	lua_gettable(state, -2);

	if (lua_isnumber(state, -1)) {
		defaultValue = static_cast<int>(lua_tonumber(state, -1));
	} else if (defaultValue == -2) {
		luaL_error(state, "field `%s' missing in date table", fieldName);
	}

	lua_settop(state, -2);
	return defaultValue;
}

/**
 * Address: 0x0077F660 (FUN_0077F660, LuaObject::j_GetNumber2 thunk)
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::GetNumber`.
 */
double LuaObjectGetNumberThunk2(const LuaObject* const object)
{
	return object->GetNumber();
}

/**
 * Address: 0x00907910 (FUN_00907910, LuaPlus::LuaObject::GetInteger)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns int-truncated payload.
 */
int32_t LuaObject::GetInteger() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as int");
	}
	return static_cast<int32_t>(m_object.value.n);
}

namespace
{
	// Deepest table nesting the encoder writes; past it an entry is left out.
	// Each level is one recursion on the calling thread (the sim's for Sync),
	// and a table that contains itself would otherwise recurse until the stack
	// ran out. Well above anything real: remote data arrives capped at 256
	// levels (kScrMaxTableDepth) and the sim adds a few on top.
	constexpr std::size_t kScrMaxEncodeDepth = 1024;

	// Values the SCR format carries inside a table.
	[[nodiscard]] bool IsScrEncodable(const LuaObject& value) noexcept
	{
		return value.IsBoolean() || value.IsNumber() || value.IsString() || value.IsTable();
	}

	bool WriteScrValue(LuaObject& value, gpg::Stream& stream, std::vector<const void*>& openTables);
} // namespace

/**
 * Address: 0x004D2C80 (FUN_004D2C80, ?SCR_ToByteStream@Moho@@YA_NABVLuaObject@LuaPlus@@AAVStream@gpg@@@Z)
 *
 * What it does:
 * Encodes one LuaObject value into the SCR tagged stream format and recursively
 * serializes table keys/values while warning on userdata/unsupported lanes.
 *
 * Engine addition: inside a table, an entry the format cannot carry (a
 * function or userdata key or value), a table already being written (a
 * cycle) or one nested past kScrMaxEncodeDepth is left out instead of being
 * written as nil or recursed into, and the call returns false as before. The
 * binary wrote nil there, which every decoder refuses as a table value, so the
 * whole stream became unreadable; and it recursed into cycles until the stack
 * overflowed.
 */
bool LuaObject::ToByteStream(gpg::Stream& stream)
{
	std::vector<const void*> openTables;
	return WriteScrValue(*this, stream, openTables);
}

namespace
{
	/**
	 * What it does:
	 * The body of LuaObject::ToByteStream; `openTables` holds the tables
	 * enclosing `value`, outermost first.
	 */
	bool WriteScrValue(LuaObject& value, gpg::Stream& stream, std::vector<const void*>& openTables)
	{
		char typeTag;
		bool success = true;

		const auto skipEntry = [&openTables](const LuaObject& entry) {
			if (!IsScrEncodable(entry)) {
				gpg::Warnf(
					entry.IsUserData() ? "Attempt to serialize lua user data." : "Attempt to serialize unsupported lua value."
				);
				return true;
			}
			if (entry.IsTable()) {
				const void* const table = entry.m_object.value.p;
				if (std::find(openTables.begin(), openTables.end(), table) != openTables.end()) {
					gpg::Warnf("Attempt to serialize a lua table that contains itself.");
					return true;
				}
				if (openTables.size() >= kScrMaxEncodeDepth) {
					gpg::Warnf("Attempt to serialize lua tables nested more than %u deep.", static_cast<unsigned>(kScrMaxEncodeDepth));
					return true;
				}
			}
			return false;
		};

		if (!value.m_state || value.IsNil()) {
			typeTag = 2;
			if (stream.mWriteEnd != stream.mWriteHead) {
				*stream.mWriteHead = typeTag;
				++stream.mWriteHead;
			} else {
				stream.VirtWrite(&typeTag, 1);
			}
			return true;
		}

		if (value.IsBoolean()) {
			typeTag = 3;
			if (stream.mWriteEnd != stream.mWriteHead) {
				*stream.mWriteHead = typeTag;
				++stream.mWriteHead;
			} else {
				stream.VirtWrite(&typeTag, 1);
			}

			const bool boolValue = value.GetBoolean();
			typeTag = boolValue ? 1 : 0;
			if (stream.mWriteEnd != stream.mWriteHead) {
				*stream.mWriteHead = typeTag;
				++stream.mWriteHead;
			} else {
				stream.VirtWrite(&typeTag, 1);
			}
			return true;
		}

		if (value.IsNumber()) {
			typeTag = 0;
			stream.Write(typeTag);
			const float number = static_cast<float>(value.GetNumber());
			stream.Write(number);
			return true;
		}

		if (value.IsString()) {
			typeTag = 1;
			stream.Write(typeTag);
			const char* str = value.GetString();
			stream.Write(str ? str : "");
			return true;
		}

		if (value.IsTable()) {
			typeTag = 4;
			stream.Write(typeTag);

			openTables.push_back(value.m_object.value.p);
			LuaTableIterator iter(value, 1);
			while (!iter.m_isDone) {
				LuaObject entryKey = iter.GetKey();
				LuaObject entryValue = iter.GetValue();
				if (skipEntry(entryKey) || skipEntry(entryValue)) {
					success = false;
				} else {
					if (!WriteScrValue(entryKey, stream, openTables)) {
						success = false;
					}
					if (!WriteScrValue(entryValue, stream, openTables)) {
						success = false;
					}
				}

				iter.Next();
			}
			openTables.pop_back();

			typeTag = 5;
			stream.Write(typeTag);
			return success;
		}

		if (value.IsUserData()) {
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
} // namespace

namespace gpg
{
	/**
	 * Address: 0x00916E60 (FUN_00916E60, gpg::RRef_WrapFile)
	 *
	 * IDA signature:
	 * gpg::RRef *__cdecl gpg::RRef_WrapFile(gpg::RRef *out, char *object);
	 *
	 * What it does:
	 * Builds a reflected reference for one `WrapFile` payload (internal
	 * LuaObject.cpp userdata type) using the cached RTTI lookup and the
	 * 3-slot TLS derived-type normalization helper. `WrapFile` is a
	 * non-polymorphic struct so the runtime-type compare-equal fast path
	 * always fires and the derived-type TLS-cache lanes are dead code in
	 * this instantiation; the effective behavior is
	 * `(out->mObj = object; out->mType = CachedType<WrapFile>())`.
	 */
	gpg::RRef* RRef_WrapFile(gpg::RRef* const out, void* const object)
	{
		return RRefWrapFileImpl(out, static_cast<WrapFile*>(object));
	}
}

/**
 * `gpg::SerSaveLoadHelper<Table>`, vtable 0x00D47030.
 *
 * Address: 0x00BEA380 (FUN_00BEA380 -- constructs the global and registers its destructor.)
 * Address: 0x00C09AF0 (FUN_00C09AF0 -- the global's destructor.)
 * Address: 0x0091FBC0 (FUN_0091FBC0 -- `Init`.)
 * Address: 0x009233A0 (FUN_009233A0 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x00920A50 (FUN_00920A50 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct TableSerializer : gpg::SerSaveLoadHelper<Table>
{};

namespace
{
	// Address: 0x00F8E72C -- process-global `TableSerializer` singleton.
	TableSerializer gTableSerializer;
} // namespace

/**
 * `gpg::SerSaveLoadHelper<LClosure>`, vtable 0x00D47038.
 *
 * Address: 0x00BEA490 (FUN_00BEA490 -- constructs the global and registers its destructor.)
 * Address: 0x00C09B80 (FUN_00C09B80 -- the global's destructor.)
 * Address: 0x0091FD50 (FUN_0091FD50 -- `Init`.)
 * Address: 0x00923430 (FUN_00923430 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x00921370 (FUN_00921370 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct LClosureSerializer : gpg::SerSaveLoadHelper<LClosure>
{};

namespace
{
	// Address: 0x00F8E768 -- process-global `LClosureSerializer` singleton.
	LClosureSerializer gLClosureSerializer;
} // namespace

/**
 * `gpg::SerSaveLoadHelper<Proto>`, vtable 0x00D47040.
 *
 * Address: 0x00BEA6B0 (FUN_00BEA6B0 -- constructs the global and registers its destructor.)
 * Address: 0x00C09CA0 (FUN_00C09CA0 -- the global's destructor.)
 * Address: 0x00920070 (FUN_00920070 -- `Init`.)
 * Address: 0x00923520 (FUN_00923520 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x009213C0 (FUN_009213C0 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct ProtoSerializer : gpg::SerSaveLoadHelper<Proto>
{};

namespace
{
	// Address: 0x00F8E77C -- process-global `ProtoSerializer` singleton.
	ProtoSerializer gProtoSerializer;
} // namespace

/**
 * `gpg::SerSaveLoadHelper<lua_State>`, vtable 0x00D47050.
 *
 * Address: 0x00BEA7C0 (FUN_00BEA7C0 -- constructs the global and registers its destructor.)
 * Address: 0x00C09D30 (FUN_00C09D30 -- the global's destructor.)
 * Address: 0x00920200 (FUN_00920200 -- `Init`.)
 * Address: 0x009235D0 (FUN_009235D0 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x009213F0 (FUN_009213F0 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct lua_StateSerializer : gpg::SerSaveLoadHelper<lua_State>
{};

namespace
{
	// Address: 0x00F8EAAC -- process-global `lua_StateSerializer` singleton.
	lua_StateSerializer glua_StateSerializer;
} // namespace

/**
 * `gpg::SerSaveLoadHelper<TObject>`, vtable 0x00D47010.
 *
 * Address: 0x00BEA160 (FUN_00BEA160 -- constructs the global and registers its destructor.)
 * Address: 0x00C09DF0 (FUN_00C09DF0 -- the global's destructor.)
 * Address: 0x0091F8A0 (FUN_0091F8A0 -- `Init`.)
 * Address: 0x00923250 (FUN_00923250 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x00921FC0 (FUN_00921FC0 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct TObjectSerializer : gpg::SerSaveLoadHelper<TObject>
{};

namespace
{
	// Address: 0x00F8E8AC -- process-global `TObjectSerializer` singleton.
	TObjectSerializer gTObjectSerializer;
} // namespace

/**
 * `gpg::SerSaveLoadHelper<Udata>`, vtable 0x00D47058.
 *
 * Address: 0x00BEA8D0 (FUN_00BEA8D0 -- constructs the global and registers its destructor.)
 * Address: 0x00C09DC0 (FUN_00C09DC0 -- the global's destructor.)
 * Address: 0x00920390 (FUN_00920390 -- `Init`.)
 * Address: 0x00923660 (FUN_00923660 -- `Deserialize`, a forward to `MemberDeserialize`.)
 * Address: 0x00920D90 (FUN_00920D90 -- `Serialize`, a forward to `MemberSerialize`.)
 */
struct UdataSerializer : gpg::SerSaveLoadHelper<Udata>
{};

namespace
{
	// Address: 0x00F8E6F0 -- process-global `UdataSerializer` singleton.
	UdataSerializer gUdataSerializer;
} // namespace

namespace LuaPlus
{
	/**
	 * `gpg::SerSaveLoadHelper<LuaObject>`, vtable 0x00D44F5C.
	 *
	 * Address: 0x00BE9F50 (FUN_00BE9F50 -- constructs the global and registers its destructor.)
	 * Address: 0x00C098B0 (FUN_00C098B0 -- the global's destructor.)
	 * Address: 0x0090B560 (FUN_0090B560 -- `Init`.)
	 * Address: 0x0090BE70 (FUN_0090BE70 -- `Deserialize`, a forward to `MemberDeserialize`.)
	 * Address: 0x0090BA10 (FUN_0090BA10 -- `Serialize`, a forward to `MemberSerialize`.)
	 */
	struct LuaObjectSerializer : gpg::SerSaveLoadHelper<LuaObject>
	{};
} // namespace LuaPlus

namespace
{
	// Address: 0x00F8E5AC -- process-global `LuaObjectSerializer` singleton.
	LuaPlus::LuaObjectSerializer gLuaObjectSerializer;
} // namespace

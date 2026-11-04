// Part of LuaObject.cpp, included there: LuaState setup and object serialization.

/**
 * Address: 0x0090AAD0 (FUN_0090AAD0, LuaPlus::LuaState::Init)
 *
 * What it does:
 * Initializes selected standard libraries and script helper globals, then
 * always registers `LOG` and `_ALERT` on the global table.
 */
void LuaState::Init(const StandardLibraries initStandardLibrary)
{
	if (initStandardLibrary != LIB_NONE) {
		lua_State* const state = m_state;
		const int previousTop = lua_gettop(state);

		luaopen_base(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo below. The
		// vendored ltablib was compiled with stock tag numbering, where
		// LUA_TFUNCTION is 6; in this fork 6 is the C-function tag, so its
		// table.sort turned away every Lua comparator with "cfunction
		// expected, got function". FAF hot-patch: this call (0x0090AB1F) goes
		// to 0x0128C1DE in .exxt, which also registers table.getsize/empty/
		// unpack/clone - see LuaOpenTable.
		LuaOpenTable(state);
		if (initStandardLibrary == LIB_OSIO) {
			// Ours, not the prebuilt lib's. The vendored liolib walks a
			// lua_State this tree builds and asserts in its debug
			// lua_newuserdata; this one is the binary's own 0x00917BC0.
			LuaOpenIo(state);
		}
		luaopen_serialize(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
		LuaOpenString(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
		LuaOpenMath(state);
		luaopen_debug(state);
		if (initStandardLibrary == LIB_OSIO) {
			// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
			LuaOpenLoadLib(state);
		}

		ScriptFunctionsRegister(this);
		if (initStandardLibrary != LIB_OSIO) {
			// Engine addition: game states read files through the mounted file
			// system only (luaB_loadfile_mounted). The start-up state, which runs
			// the user's own init file with real paths, keeps the stock ones.
			LuaObject globals = GetGlobals();
			globals.Register("loadfile", luaB_loadfile_mounted, 0);
			globals.Register("dofile", luaB_dofile_mounted, 0);
		}
		lua_settop(state, previousTop);
	}

	LuaObject globals = GetGlobals();
	globals.Register("LOG", LS_LOG, 0);

	LuaObject alertGlobals = GetGlobals();
	alertGlobals.Register("_ALERT", LS_LOG, 0);
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
 * Address: 0x0090A5D0 (FUN_0090A5D0)
 *
 * What it does:
 * Zeroes every binding and default-constructs `m_threadObj`; the argument
 * only selects this overload.
 */
LuaState::LuaState(Unbound)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_threadObj(),
	  m_rootState(nullptr),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{}

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
		// `l_G->lstate` names the currently-executing thread, and it is the lane
		// every `LuaObject::GetActiveState()` resolves through
		// (0x009072B0: `m_state->m_state->l_G->lstate->stateUserData`). The
		// binary dereferences that result with no null check at all -- see
		// `CScriptObject::FindScript`, which calls `GetActiveState` at
		// 0x004C74DF and reads straight through the returned pointer at
		// 0x004C74E6 -- so the thread `lstate` names must always still own a
		// live wrapper.
		//
		// Clearing `stateUserData` below while `lstate` still names this thread
		// breaks exactly that, and it does so silently: `GetActiveState()` then
		// answers null for *every* object bound to this state root, not just
		// ones related to the thread being torn down, until the dead thread is
		// finally collected and `luaE_freethread` puts `lstate` back. Measured
		// window: a forked unit-script coroutine tearing down mid-beat left
		// `CScriptObject::FindScript` unable to find any script at all for the
		// next ~400 sim frames, so `RunScriptBool("CheckBuildRestriction")`
		// answered false, `IAiCommandDispatchImpl::DispatchTask` built no task
		// for `UNITCOMMAND_BuildMobile`, and `TaskTick` retired the command --
		// every structure queued on a commander during its warp-in vanished.
		//
		// Dropping back to the main thread restores the binary's invariant at
		// the point the wrapper dies, which is where the window opens; the same
		// correction in `luaE_freethread` only closes it again much later.
		global_State* const globalState = m_state->l_G;
		if (globalState != nullptr && globalState->lstate == m_state) {
			globalState->lstate = globalState->mainthread;
		}

		m_state->stateUserData = nullptr;
		if (m_ownState != 0) {
			lua_close(m_state);
		}
	}
}

/**
 * Address: 0x004C99B0 (FUN_004C99B0, LuaState scalar deleting destructor thunk)
 *
 * What it does:
 * Runs `LuaState` non-deleting destruction, then conditionally releases the
 * object storage when the scalar-delete flag bit is set.
 */
LuaState* DestroyLuaStateWithDeleteFlag(LuaState* const state, const std::uint8_t deleteFlag)
{
	state->~LuaState();
	if ((deleteFlag & 1u) != 0u) {
		::operator delete(state);
	}
	return state;
}

/**
 * Address: 0x0090A7D0 (FUN_0090A7D0, LuaPlus::LuaState::SetState)
 *
 * What it does:
 * Binds this wrapper to an existing C `lua_State`, sets root thread/sentinel
 * ownership for main-thread lanes, and updates `stateUserData`.
 */
void LuaState::SetState(lua_State* const state)
{
	if (m_state != nullptr || m_rootState != nullptr) {
		throw LuaAssertion("m_state==NULL && m_rootState==NULL");
	}

	if (state->stateUserData != nullptr) {
		throw LuaAssertion("L->stateUserData == NULL");
	}

	lua_State* const mainThread = state->l_G->mainthread;
	if (mainThread == state) {
		m_rootState = this;
		m_state = state;
		m_ownState = 1;
		m_headObject.m_prev = nullptr;
		m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
		m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
		m_tailObject.m_next = nullptr;
		m_state->l_G->userGCFunction = &LuaPlusGCFunction;
		m_state->stateUserData = this;
		return;
	}

	m_rootState = mainThread->stateUserData;
	if (m_rootState == nullptr) {
		throw LuaAssertion("m_rootState");
	}

	m_state = state;
	m_threadObj.AssignThread(this);
	m_state->stateUserData = this;
}

/**
 * Address: 0x00921480 (FUN_00921480, func_SerializeNameLuaObject)
 *
 * What it does:
 * Resolves optional object-name indirection from global table
 * `"__serialize_name_for_object"` and returns a TString pointer when present.
 */
[[nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* state, TString* key);

[[nodiscard]] TString* ResolveSerializedNameForLuaObject(lua_State* const state, const Value value)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_name_for_object", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt != LUA_TTABLE) {
		return nullptr;
	}

	const auto* const gcObject = static_cast<const GCObject*>(value.p);
	if (gcObject == nullptr) {
		return nullptr;
	}

	TObject lookupKey{};
	lookupKey.tt = static_cast<int>(gcObject->gch.tt);
	lookupKey.value = value;

	const TObject* const lookupResult = luaH_get(static_cast<Table*>(serializeMapObject->value.p), &lookupKey);
	if (lookupResult->tt == LUA_TNIL) {
		return nullptr;
	}

	if (lookupResult->tt != LUA_TSTRING) {
		throw gpg::SerializationError("__serialize_name_for_object table must contain only string values");
	}

	return static_cast<TString*>(lookupResult->value.p);
}

/**
 * Address: 0x009216D0 (FUN_009216D0, TObject::MemberSerialize)
 *
 * What it does:
 * Serializes one tagged Lua value lane with optional named-object indirection
 * and type-specific payload dispatch.
 */
void TObject::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	if (tt > LUA_TSTRING) {
		lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
		if (TString* const serializedName = ResolveSerializedNameForLuaObject(ownerState, value);
			serializedName != nullptr) {
			archive->WriteInt(-2);
			archive->WriteTString(serializedName, ownerRef);
			return;
		}
	}

	archive->WriteInt(tt);
	switch (tt) {
	case LUA_TBOOLEAN:
		archive->WriteInt(value.b);
		return;
	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");
	case LUA_TNUMBER:
		archive->WriteValue(&value, 0);
		return;
	case LUA_TSTRING:
		archive->WriteTString(static_cast<TString*>(value.p), ownerRef);
		return;
	case LUA_TTABLE:
		archive->WriteTTable(static_cast<Table*>(value.p), ownerRef);
		return;
	case LUA_CFUNCTION:
		archive->WriteCFunction(static_cast<CClosure*>(value.p), ownerRef);
		return;
	case LUA_TFUNCTION:
		archive->WriteFunction(static_cast<LClosure*>(value.p), ownerRef);
		return;
	case LUA_TUSERDATA:
		archive->WriteUserdata(static_cast<Udata*>(value.p), ownerRef);
		return;
	case LUA_TTHREAD:
		archive->WriteTThread(static_cast<lua_State*>(value.p), ownerRef);
		return;
	default:
		return;
	}
}

/**
 * Address: 0x009226F0 (FUN_009226F0, TObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes one tagged Lua value lane with named-object lookup support and
 * type-specific payload dispatch.
 */
void TObject::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	int typeCode = LUA_TNIL;
	archive->ReadInt(&typeCode);
	switch (typeCode) {
	case -2: {
		lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
		TString* serializedName = nullptr;
		(void)archive->ReadPointer(&serializedName, &ownerRef);

		const TObject* const resolvedObject = ResolveSerializedObjectNameEntry(ownerState, serializedName);
		if (resolvedObject->tt == LUA_TNIL) {
			throw gpg::SerializationError("Named script object not found");
		}

		*this = *resolvedObject;
		return;
	}

	case LUA_TNONE:
	case LUA_TNIL:
		tt = typeCode;
		value.p = nullptr;
		return;

	case LUA_TBOOLEAN: {
		int boolValue = 0;
		archive->ReadInt(&boolValue);
		tt = LUA_TBOOLEAN;
		value.b = boolValue;
		return;
	}

	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");

	case LUA_TNUMBER: {
		float numberValue = 0.0f;
		archive->ReadFloat(&numberValue);
		tt = LUA_TNUMBER;
		value.n = numberValue;
		return;
	}

	case LUA_TSTRING: {
		TString* stringValue = nullptr;
		(void)archive->ReadPointer(&stringValue, &ownerRef);
		tt = LUA_TSTRING;
		value.p = stringValue;
		return;
	}

	case LUA_TTABLE: {
		Table* tableValue = nullptr;
		(void)archive->ReadPointer(&tableValue, &ownerRef);
		tt = LUA_TTABLE;
		value.p = tableValue;
		return;
	}

	case LUA_CFUNCTION:
		throw gpg::SerializationError("C functions must be saved by name, not value");

	case LUA_TFUNCTION: {
		LClosure* functionValue = nullptr;
		(void)archive->ReadPointer(&functionValue, &ownerRef);
		tt = LUA_TFUNCTION;
		value.p = functionValue;
		return;
	}

	case LUA_TUSERDATA: {
		Udata* userdataValue = nullptr;
		(void)archive->ReadPointer(&userdataValue, &ownerRef);
		tt = LUA_TUSERDATA;
		value.p = userdataValue;
		return;
	}

	case LUA_TTHREAD: {
		lua_State* threadValue = nullptr;
		(void)archive->ReadPointer(&threadValue, &ownerRef);
		tt = LUA_TTHREAD;
		value.p = threadValue;
		return;
	}

	default:
		throw gpg::SerializationError("Unknown type code for lua value");
	}
}

/**
 * Address: 0x00920DA0 (FUN_00920DA0, LClosure::MemberSerialize)
 *
 * What it does:
 * Serializes one closure's proto pointer, global-object lane, and upvalue
 * pointer array lanes.
 */
void LClosure::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");


	archive->WritePointer<Proto>(p, gpg::TrackedPointerState::Unowned, ownerRef);

	archive->Write(CachedType<TObject>(gLuaTObjectType), &g, ownerRef);

	for (std::uint8_t upvalueIndex = 0; upvalueIndex < nupvalues; ++upvalueIndex) {
		archive->WritePointer<UpVal>(upvals[upvalueIndex], gpg::TrackedPointerState::Unowned, ownerRef);
	}
}

/**
 * Address: 0x00920E40 (FUN_00920E40, Proto::MemberSerialize)
 *
 * What it does:
 * Serializes proto scalar metadata, constants/code/nested-proto lanes, and
 * debug name/source pointer lanes.
 */
void Proto::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");


	archive->WriteInt(sizeupvalues);
	archive->WriteInt(sizek);
	archive->WriteInt(sizecode);
	archive->WriteInt(sizelineinfo);
	archive->WriteInt(sizep);
	archive->WriteInt(sizelocvars);
	archive->WriteInt(lineDefined);
	archive->WriteUByte(nups);
	archive->WriteUByte(numparams);
	archive->WriteUByte(is_vararg);
	archive->WriteUByte(maxstacksize);

	for (int index = 0; index < sizek; ++index) {
		archive->Write(CachedType<TObject>(gLuaTObjectType), &k[index], ownerRef);
	}

	archive->WriteBytes(reinterpret_cast<char*>(code), sizeof(Instruction) * static_cast<std::size_t>(sizecode));

	for (int index = 0; index < sizep; ++index) {
		archive->WritePointer<Proto>(p[index], gpg::TrackedPointerState::Unowned, ownerRef);
	}

	for (int index = 0; index < sizelineinfo; ++index) {
		archive->WriteInt(lineinfo[index]);
	}

	for (int index = 0; index < sizelocvars; ++index) {
		archive->WritePointer<TString>(locvars[index].varname, gpg::TrackedPointerState::Unowned, ownerRef);
		archive->WriteInt(locvars[index].startpc);
		archive->WriteInt(locvars[index].endpc);
	}

	for (int index = 0; index < nups; ++index) {
		archive->WritePointer<TString>(upvalues[index], gpg::TrackedPointerState::Unowned, ownerRef);
	}

	archive->WritePointer<TString>(source, gpg::TrackedPointerState::Unowned, ownerRef);
}

/**
 * Address: 0x00922B20 (FUN_00922B20, Proto::MemberDeserialize)
 *
 * What it does:
 * Deserializes proto scalar metadata, constants/code/nested-proto lanes, and
 * debug name/source pointer lanes, then validates bytecode consistency.
 */
void Proto::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");

	archive->ReadInt(&sizeupvalues);
	archive->ReadInt(&sizek);
	archive->ReadInt(&sizecode);
	archive->ReadInt(&sizelineinfo);
	archive->ReadInt(&sizep);
	archive->ReadInt(&sizelocvars);
	archive->ReadInt(&lineDefined);
	archive->ReadUByte(&nups);
	archive->ReadUByte(&numparams);
	archive->ReadUByte(&is_vararg);
	archive->ReadUByte(&maxstacksize);

	const gpg::RRef& owner = ownerRef;
	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);

	k = luaM_newvector<TObject>(ownerState, static_cast<lu_mem>(sizek));
	for (int index = 0; index < sizek; ++index) {
		archive->Read(tObjectType, &k[index], owner);
	}

	code = luaM_newvector<Instruction>(ownerState, static_cast<lu_mem>(sizecode));
	archive->ReadBytes(
		reinterpret_cast<char*>(code),
		sizeof(Instruction) * static_cast<std::size_t>(sizecode)
	);

	p = luaM_newvector<Proto*>(ownerState, static_cast<lu_mem>(sizep));
	for (int index = 0; index < sizep; ++index) {
		archive->ReadPointer(&p[index], &ownerRef);
	}

	lineinfo = luaM_newvector<int>(ownerState, static_cast<lu_mem>(sizelineinfo));
	for (int index = 0; index < sizelineinfo; ++index) {
		archive->ReadInt(&lineinfo[index]);
	}

	locvars = luaM_newvector<LocVar>(ownerState, static_cast<lu_mem>(sizelocvars));
	for (int index = 0; index < sizelocvars; ++index) {
		archive->ReadPointer(&locvars[index].varname, &ownerRef);
		archive->ReadInt(&locvars[index].startpc);
		archive->ReadInt(&locvars[index].endpc);
	}

	upvalues = luaM_newvector<TString*>(ownerState, static_cast<lu_mem>(nups));
	for (int index = 0; index < nups; ++index) {
		archive->ReadPointer(&upvalues[index], &ownerRef);
	}

	archive->ReadPointer(&source, &ownerRef);
	if (!luaG_checkcode(this)) {
		throw gpg::SerializationError("Consistency check failed: luaG_checkcode(&value)");
	}
}

/**
 * Address: 0x00920530 (FUN_00920530, Table::MemberSerialize)
 *
 * What it does:
 * Serializes table metatable pointer lane, dense array payload lanes, and
 * non-empty hash key/value lanes.
 */
void Table::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	archive->WritePointer<Table>(metatable, gpg::TrackedPointerState::Unowned, ownerRef);

	const int hashNodeCount = 1 << lsizenode;

	// Engine addition (replay keyframes): which slot a colliding key got depends on what was
	// inserted before it, and `next` walks the slots, so a table rebuilt by insertion can iterate in
	// another order; freed slots still count as taken until a rehash, so it also rehashes at another
	// time. A keyframe keeps the slots. A key hashed by address has no fixed slot in any other process,
	// so such a table is rebuilt by insertion, and lockstep cannot depend on its order anyway.
	if (moho::gSimExactArchive.load(std::memory_order_relaxed)) {
		bool hashedByAddress = false;
		for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
			const Node& slot = node[hashIndex];
			const int keyType = slot.KeyTag();
			hashedByAddress = hashedByAddress
				|| (slot.i_val.tt != LUA_TNIL && keyType != LUA_TBOOLEAN && keyType != LUA_TNUMBER && keyType != LUA_TSTRING);
		}
		archive->WriteBool(hashedByAddress);

		// A slot with a nil value keeps its key, and that key may already be collected: nothing can
		// be read through it. A string still alive is kept, because assigning that key again reuses
		// the slot. The strings alive are the string table's, gathered once per save.
		thread_local std::uint32_t tLiveStringsSave = 0u;
		thread_local std::unordered_set<const void*> tLiveStrings;
		const std::uint32_t currentSave = moho::gSimExactSaveCount.load(std::memory_order_relaxed);
		if (tLiveStringsSave != currentSave) {
			tLiveStringsSave = currentSave;
			tLiveStrings.clear();
			const global_State* const globalState = ownerRef.TryUpcastLuaThreadState()->l_G;
			for (int bucket = 0; bucket < globalState->strt.size; ++bucket) {
				for (const GCObject* string = globalState->strt.hash[bucket]; string != nullptr; string = string->gch.next) {
					tLiveStrings.insert(string);
				}
			}
		}

		if (!hashedByAddress) {
			gpg::RType* const exactType = CachedType<TObject>(gLuaTObjectType);
			archive->WriteInt(static_cast<int>(firstfree - node));
			for (int arrayIndex = 0; arrayIndex < sizearray; ++arrayIndex) {
				archive->Write(exactType, &array[arrayIndex], ownerRef);
			}
			for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
				const Node& slot = node[hashIndex];
				if (slot.KeyIs(LUA_TNIL)) {
					archive->WriteUByte(0u);
					continue;
				}

				const int keyType = slot.KeyTag();
				const bool keyReadable = slot.i_val.tt != LUA_TNIL || keyType == LUA_TBOOLEAN || keyType == LUA_TNUMBER
					|| (keyType == LUA_TSTRING && tLiveStrings.count(slot.KeyValue().p) != 0u);
				if (!keyReadable) {
					archive->WriteUByte(2u); // a dead key: takes its slot, holds nothing
				} else {
					archive->WriteUByte(1u);
					TObject key = slot.Key();
					archive->Write(exactType, &key, ownerRef);
					archive->Write(exactType, &slot.i_val, ownerRef);
				}
				archive->WriteInt(slot.Next() != nullptr ? static_cast<int>(slot.Next() - node) : -1);
			}
			return;
		}
	}

	int nonEmptyHashCount = 0;
	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		if (node[hashIndex].i_val.tt != LUA_TNIL) {
			++nonEmptyHashCount;
		}
	}
	archive->WriteInt(nonEmptyHashCount);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int arrayIndex = 0; arrayIndex < sizearray; ++arrayIndex) {
		archive->Write(tObjectType, &array[arrayIndex], ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		const Node& slot = node[hashIndex];
		if (slot.i_val.tt == LUA_TNIL) {
			continue;
		}

		const TObject slotKey = slot.Key();
		archive->Write(tObjectType, &slotKey, ownerRef);
		archive->Write(tObjectType, &slot.i_val, ownerRef);
	}
}

/**
 * Address: 0x00922950 (FUN_00922950, Table::MemberDeserialize)
 *
 * What it does:
 * Deserializes table metatable pointer lane, dense-array element lanes, and
 * hashed key/value lanes under owner GC traversal lock.
 */
void Table::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	Table* loadedMetatable = metatable;
	(void)archive->ReadPointer(&loadedMetatable, &ownerRef);
	metatable = loadedMetatable;

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);

	// Engine addition (replay keyframes): the slots as they were, see MemberSerialize.
	if (moho::gSimExactArchive.load(std::memory_order_relaxed)) {
		bool hashedByAddress = false;
		archive->ReadBool(&hashedByAddress);
		if (!hashedByAddress) {
			// A new table says it has no tag methods; luaH_set clears that, and these writes bypass it.
			flags = 0;
			int firstFreeIndex = 0;
			archive->ReadInt(&firstFreeIndex);
			for (int arrayIndex = 0; arrayIndex < sizearray; ++arrayIndex) {
				archive->Read(tObjectType, &array[arrayIndex], ownerRef);
			}

			const int hashNodeCount = 1 << lsizenode;
			for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
				lu_byte slotState = 0u;
				archive->ReadUByte(&slotState);
				if (slotState == 0u) {
					continue;
				}

				Node& slot = node[hashIndex];
				if (slotState == 1u) {
					TObject key{};
					archive->Read(tObjectType, &key, ownerRef);
					slot.SetKey(key);
					archive->Read(tObjectType, &slot.i_val, ownerRef);
				} else {
					slot.SetKeyTag(LUA_TNONE);
					slot.i_val.tt = LUA_TNIL;
				}

				int nextIndex = -1;
				archive->ReadInt(&nextIndex);
				slot.SetNext(nextIndex >= 0 ? &node[nextIndex] : nullptr);
			}
			firstfree = &node[firstFreeIndex];
			return;
		}
	}

	int hashEntryCount = 0;
	archive->ReadInt(&hashEntryCount);

	for (int arrayIndex = 1; arrayIndex <= sizearray; ++arrayIndex) {
		TObject* const destinationSlot = luaH_setnum(ownerState, this, arrayIndex);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashEntryCount; ++hashIndex) {
		TObject key{};
		archive->Read(tObjectType, &key, ownerRef);
		TObject* const destinationSlot = luaH_set(ownerState, this, &key);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}
}

/**
 * Address: 0x009207E0 (FUN_009207E0, Udata::MemberSerialize)
 *
 * What it does:
 * Uses the owner Lua-thread lane as serialization context, writes userdata
 * metatable pointer as unowned tracked reference, then serializes userdata
 * payload through the stored runtime `RType`.
 */
void Udata::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	archive->WritePointer<Table>(metatable, gpg::TrackedPointerState::Unowned, ownerRef);

	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(len);
	const void* const payload = reinterpret_cast<const std::uint8_t*>(this) + sizeof(Udata);
	archive->Write(payloadType, payload, ownerRef);
}

/**
 * Address: 0x00923170 (FUN_00923170, Udata::MemberDeserialize)
 *
 * What it does:
 * Deserializes userdata metatable pointer lane and typed payload bytes using
 * one owning Lua thread traversal lock lane from `ownerRef`.
 */
void Udata::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	(void)archive->ReadPointer(&metatable, &ownerRef);
	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(len);
	void* const payload = reinterpret_cast<std::uint8_t*>(this) + sizeof(Udata);
	archive->Read(payloadType, payload, ownerRef);
}

/**
 * Address: 0x00922AB0 (FUN_00922AB0, LClosure::MemberDeserialize)
 *
 * What it does:
 * Deserializes prototype/global-object/upvalue pointer lanes for one Lua
 * closure object.
 */
void LClosure::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	archive->ReadPointer(&p, &ownerRef);
	archive->Read(CachedType<TObject>(gLuaTObjectType), &g, ownerRef);

	UpVal** upvalueLane = upvals;
	for (std::uint8_t upvalueIndex = 0; upvalueIndex < nupvalues; ++upvalueIndex, ++upvalueLane) {
		archive->ReadPointer(upvalueLane, &ownerRef);
	}
}

namespace
{
	/**
	 * Address: 0x00915E20 (FUN_00915E20)
	 *
	 * What it does:
	 * Unlinks one `UpVal` from the global state's `rootgc` chain (`[L+0x10]+0xC`) and clears its
	 * `next` link. A corrupt archive can name one that is not there, which the binary does not test.
	 */
	void UnlinkUpvalueFromRootList(lua_State* const state, GCObject* const upvalue)
	{
		GCObject** link = &state->l_G->rootgc;
		while (*link != upvalue) {
			if (*link == nullptr) {
				throw gpg::SerializationError("Consistency check failed: u");
			}
			link = &(*link)->gch.next;
		}
		*link = upvalue->gch.next;
		upvalue->gch.next = nullptr;
	}
} // namespace

/**
 * Address: 0x00922DD0 (FUN_00922DD0, lua_State::MemberDeserialize)
 *
 * What it does:
 * Restores one Lua thread stack/callframe/global/upvalue lane set from a
 * serialized archive payload.
 */
void lua_State::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");

	int stackSize = 0;
	int topIndex = 0;
	int baseIndex = 0;
	archive->ReadInt(&stackSize);
	archive->ReadInt(&baseIndex);
	archive->ReadInt(&topIndex);

	if (baseIndex < 0 || baseIndex > topIndex || topIndex > stackSize) {
		throw gpg::SerializationError("Consistency check failed: 0 <= ibase && ibase <= itop && itop <= stacksize");
	}

	luaD_reallocstack(this, stackSize);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int stackIndex = 0; stackIndex < topIndex; ++stackIndex) {
		archive->Read(tObjectType, &stack[stackIndex], ownerRef);
	}

	TObject* const stackBase = stack;
	base = &stackBase[baseIndex];
	top = &stackBase[topIndex];

	std::uint16_t callInfoCapacity = 0u;
	archive->ReadUShort(&callInfoCapacity);
	luaD_reallocCI(this, static_cast<int>(callInfoCapacity));

	std::uint16_t currentCallInfoIndex = 0u;
	archive->ReadUShort(&currentCallInfoIndex);
	if (currentCallInfoIndex >= callInfoCapacity) {
		throw gpg::SerializationError("Consistency check failed: ici < size_ci");
	}

	ci = &base_ci[currentCallInfoIndex];

	for (std::uint16_t callInfoIndex = 0; callInfoIndex <= currentCallInfoIndex; ++callInfoIndex) {
		CallInfo* const callInfo = base_ci + callInfoIndex;

		int ciBaseByteOffset = 0;
		int ciTopByteOffset = 0;
		archive->ReadInt(&ciBaseByteOffset);
		archive->ReadInt(&ciTopByteOffset);

		if (ciBaseByteOffset < 0) {
			throw gpg::SerializationError("Consistency check failed: 0 <= cibase");
		}
		if (ciBaseByteOffset > ciTopByteOffset) {
			throw gpg::SerializationError("Consistency check failed: cibase <= citop");
		}
		if (ciTopByteOffset > static_cast<int>(sizeof(TObject) * static_cast<std::size_t>(stacksize))) {
			throw gpg::SerializationError("Consistency check failed: citop <= (int)(value.stacksize*sizeof(TObject))");
		}

		auto* const stackBytes = reinterpret_cast<std::uint8_t*>(stack);
		callInfo->base = reinterpret_cast<TObject*>(stackBytes + ciBaseByteOffset);
		callInfo->top = reinterpret_cast<TObject*>(stackBytes + ciTopByteOffset);

		archive->ReadInt(&callInfo->state);
		archive->ReadInt(&callInfo->tailcalls);

		if (callInfo->state < 3) {
			int savedProgramCounterIndex = 0;
			archive->ReadInt(&savedProgramCounterIndex);

			const TObject* const functionSlot = callInfo->base - 1;
			const auto* const closure = static_cast<const Closure*>(functionSlot->value.p);
			const Instruction* const codeBase = closure->l.p->code;
			callInfo->savedpc = codeBase + savedProgramCounterIndex;
		} else {
			callInfo->savedpc = nullptr;
		}
	}

	archive->Read(tObjectType, &_gt, ownerRef);

	int upvalueLastStackIndex = topIndex;
	GCObject** openUpvalueInsert = &openupval;

	int upvalueStackIndex = -1;
	archive->ReadInt(&upvalueStackIndex);
	while (upvalueStackIndex != -1) {
		if (upvalueStackIndex < 0 || upvalueStackIndex >= upvalueLastStackIndex) {
			throw gpg::SerializationError("Consistency check failed: 0 <= stackindex && stackindex < upval_last_stackindex");
		}

		UpVal* upvalue = nullptr;
		archive->ReadPointer(&upvalue, &ownerRef);
		if (upvalue == nullptr) {
			throw gpg::SerializationError("Consistency check failed: u");
		}
		if (upvalue->v != &upvalue->value) {
			throw gpg::SerializationError("Consistency check failed: u->v == &u->value");
		}

		// 0x0092303B: `call 0x915E20` moves it off the global list luaF_newupval put it on, so that its
		// next link can chain this thread's open upvalues.
		auto* const upvalueObject = reinterpret_cast<GCObject*>(upvalue);
		UnlinkUpvalueFromRootList(this, upvalueObject);

		upvalue->v = &stack[upvalueStackIndex];
		*openUpvalueInsert = upvalueObject;
		openUpvalueInsert = &upvalueObject->gch.next;

		upvalueLastStackIndex = upvalueStackIndex;
		archive->ReadInt(&upvalueStackIndex);
	}
}

/**
 * Address: 0x00921050 (FUN_00921050, lua_State::MemberSerialize)
 *
 * What it does:
 * Serializes raw lua_State stack/callframe/global/upvalue lanes for archive
 * persistence.
 */
void lua_State::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	Ensure(archive != nullptr, "archive");


	TObject* const stackBase = stack;
	const int baseIndex = static_cast<int>(base - stackBase);
	const int topIndex = static_cast<int>(top - stackBase);

	archive->WriteInt(stacksize);
	archive->WriteInt(baseIndex);
	archive->WriteInt(topIndex);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int index = 0; index < topIndex; ++index) {
		archive->Write(tObjectType, &stackBase[index], ownerRef);
	}

	archive->WriteUShort(size_ci);
	const std::uint16_t currentCallInfoIndex = static_cast<std::uint16_t>(ci - base_ci);
	archive->WriteUShort(currentCallInfoIndex);

	for (std::uint16_t callInfoIndex = 0; callInfoIndex <= currentCallInfoIndex; ++callInfoIndex) {
		CallInfo* const callInfo = base_ci + callInfoIndex;

		const int callInfoBaseByteOffset = static_cast<int>(
			reinterpret_cast<const std::uint8_t*>(callInfo->base) - reinterpret_cast<const std::uint8_t*>(stackBase)
		);
		const int callInfoTopByteOffset = static_cast<int>(
			reinterpret_cast<const std::uint8_t*>(callInfo->top) - reinterpret_cast<const std::uint8_t*>(stackBase)
		);

		archive->WriteInt(callInfoBaseByteOffset);
		archive->WriteInt(callInfoTopByteOffset);
		archive->WriteInt(callInfo->state);
		archive->WriteInt(callInfo->tailcalls);

		if (callInfo->state < 3) {
			const TObject* const functionSlot = callInfo->base - 1;
			const auto* const closure = static_cast<const Closure*>(functionSlot->value.p);
			const Instruction* const codeBase = closure->l.p->code;
			archive->WriteInt(static_cast<int>(callInfo->savedpc - codeBase));
		}
	}

	archive->Write(tObjectType, &_gt, ownerRef);

	for (GCObject* openUpval = openupval; openUpval != nullptr; openUpval = openUpval->gch.next) {
		UpVal* const upvalue = &openUpval->uv;
		archive->WriteInt(static_cast<int>(upvalue->v - stackBase));

		archive->WritePointer<UpVal>(upvalue, gpg::TrackedPointerState::Unowned, ownerRef);
	}

	archive->WriteInt(-1);
}

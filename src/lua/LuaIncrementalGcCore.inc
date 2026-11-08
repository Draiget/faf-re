// ---------------------------------------------------------------------------
// Lua 5.1-style incremental collector core.
//
// This file is included inside namespace LuaPlus from LuaObject.cpp. The
// object model is the fork's Lua 5.0.1 one, so the types and the root lists are
// the fork's; the collector mechanics below are ported from Lua 5.1.5 lgc.c
// (tri-colour invariant, gray / grayagain / weak lists, atomic remark, barrier
// functions, phased sweep and finalisation). Each function names its 5.1
// counterpart.
// ---------------------------------------------------------------------------

namespace
{
	using namespace moho::lua_incremental;

	// Ported from Lua 5.1.5 lgc.c: the GCS* cost constants.
	constexpr int kGcStepSize = 1024;
	constexpr int kGcSweepMax = 40;
	constexpr int kGcSweepCost = 10;
	constexpr int kGcFinalizeCost = 100;

	[[nodiscard]] inline bool IsCollectable(const TObject& value) noexcept
	{
		return value.tt >= LUA_TSTRING;
	}

	// Ported from Lua 5.1.5 lgc.c: makewhite().
	inline void IncrMakeWhite(SState& state, GCObject* const object) noexcept
	{
		object->gch.marked = static_cast<lu_byte>(
			(object->gch.marked & static_cast<lu_byte>(~kColorMask)) | White(state)
		);
	}

	// Ported from Lua 5.1.5 lgc.h: changewhite(x) -> marked ^= WHITEBITS.
	// Flips a dead object's white colour back to the current white so that
	// a stale interned string can be handed out again.
	inline void IncrChangeWhite(GCObject* const object) noexcept
	{
		object->gch.marked ^= kWhiteBits;
	}

	// Ported from Lua 5.1.5 lgc.c: white2gray().
	inline void IncrWhiteToGray(GCObject* const object) noexcept
	{
		object->gch.marked &= static_cast<lu_byte>(~kWhiteBits);
	}

	// Ported from Lua 5.1.5 lgc.c: gray2black().
	inline void IncrGrayToBlack(GCObject* const object) noexcept
	{
		object->gch.marked |= kBlackBit;
	}

	// Ported from Lua 5.1.5 lgc.c: black2gray().
	inline void IncrBlackToGray(GCObject* const object) noexcept
	{
		object->gch.marked &= static_cast<lu_byte>(~kBlackBit);
	}

	// Ported from Lua 5.1.5 lgc.c: stringmark().
	inline void IncrMarkString(TString* const string) noexcept
	{
		string->marked &= static_cast<lu_byte>(~kWhiteBits);
	}

	// Ported from Lua 5.1.5 lgc.c: markvalue().
	void IncrMarkValue(SState& state, const TObject& value);

	// Ported from Lua 5.1.5 lgc.c: markobject().
	void IncrMarkObject(SState& state, GCObject* object);

	// Ported from Lua 5.1.5 lgc.c: reallymarkobject().
	void IncrReallyMarkObject(SState& state, GCObject* const object)
	{
		if (!IsWhite(object)) {
			return;
		}

		IncrWhiteToGray(object);

		switch (object->gch.tt) {
			case LUA_TSTRING:
				// Strings are never put on the gray list; their gray colour is
				// enough to keep them through the sweep.
				return;

			case LUA_TUSERDATA: {
				auto* const userdata = reinterpret_cast<Udata*>(object);
				IncrGrayToBlack(object); // userdata are never gray
				if (userdata->metatable != nullptr) {
					IncrMarkObject(state, reinterpret_cast<GCObject*>(userdata->metatable));
				}
				return;
			}

			case LUA_TUPVALUE: {
				auto* const upvalue = reinterpret_cast<UpVal*>(object);
				IncrMarkValue(state, *upvalue->v);
				if (upvalue->v == &upvalue->value) {
					IncrGrayToBlack(object); // closed upvalues are black
				}
				// Open upvalues stay gray and are re-marked by remarkupvals().
				return;
			}

			case LUA_TTABLE:
				object->h.gclist = state.gray;
				state.gray = object;
				return;

			case LUA_TFUNCTION:
			case LUA_CFUNCTION:
				object->cl.c.gclist = state.gray;
				state.gray = object;
				return;

			case LUA_TTHREAD:
				object->th.gclist = state.gray;
				state.gray = object;
				return;

			case LUA_TPROTO:
				object->p.gclist = state.gray;
				state.gray = object;
				return;

			default:
				return;
		}
	}

	void IncrMarkObject(SState& state, GCObject* const object)
	{
		if (object != nullptr && IsWhite(object)) {
			IncrReallyMarkObject(state, object);
		}
	}

	void IncrMarkValue(SState& state, const TObject& value)
	{
		if (IsCollectable(value)) {
			IncrMarkObject(state, static_cast<GCObject*>(value.value.p));
		}
	}

	// Ported from Lua 5.1.5 lgc.c: traversetable().
	// Returns true when the table is weak and must stay gray until atomic().
	bool IncrTraverseTable(SState& state, Table* const table)
	{
		constexpr int kTagMethodMode = 2;

		Table* const metatable = table->metatable;
		IncrMarkObject(state, reinterpret_cast<GCObject*>(metatable));

		bool weakKey = false;
		bool weakValue = false;
		if (metatable != nullptr && (metatable->flags & (1 << kTagMethodMode)) == 0) {
			const TObject* const mode =
				luaT_gettm(metatable, kTagMethodMode, state.g->tmname[kTagMethodMode]);
			if (mode != nullptr && mode->tt == LUA_TSTRING) {
				const char* const modeText = static_cast<TString*>(mode->value.p)->str;
				weakKey = std::strchr(modeText, 'k') != nullptr;
				weakValue = std::strchr(modeText, 'v') != nullptr;
			}
		}

		if (weakKey || weakValue) {
			table->marked &= static_cast<lu_byte>(~(kKeyWeakBit | kValueWeakBit));
			if (weakKey) {
				table->marked |= kKeyWeakBit;
			}
			if (weakValue) {
				table->marked |= kValueWeakBit;
			}
			table->gclist = state.weak;
			state.weak = reinterpret_cast<GCObject*>(table);
		}

		if (weakKey && weakValue) {
			return true;
		}

		if (!weakValue) {
			for (int index = table->sizearray; index != 0; --index) {
				IncrMarkValue(state, table->array[index - 1]);
			}
		}

		const int nodeCount = 1 << table->lsizenode;
		for (int index = nodeCount; index != 0; --index) {
			Node& node = table->node[index - 1];
			if (node.i_val.tt == LUA_TNIL) {
				continue;
			}
			if (!weakKey) {
				IncrMarkValue(state, node.Key());
			}
			if (!weakValue) {
				IncrMarkValue(state, node.i_val);
			}
		}
		return weakKey || weakValue;
	}

	// Ported from Lua 5.1.5 lgc.c: traverseclosure().
	// This fork distinguishes C and Lua closures by GC tag, not by the
	// never-written CClosure::isC byte.
	void IncrTraverseClosure(SState& state, const Closure* const closure, const bool isC)
	{
		if (isC) {
			for (int index = 0; index < closure->c.nupvalues; ++index) {
				IncrMarkValue(state, closure->c.upvalue[index]);
			}
			return;
		}

		IncrMarkValue(state, closure->l.g);
		IncrMarkObject(state, reinterpret_cast<GCObject*>(closure->l.p));
		for (int index = 0; index < closure->l.nupvalues; ++index) {
			IncrMarkObject(state, reinterpret_cast<GCObject*>(closure->l.upvals[index]));
		}
	}

	// Ported from Lua 5.1.5 lgc.c: traverseproto().
	void IncrTraverseProto(SState& state, const Proto* const proto)
	{
		if (proto->source != nullptr) {
			IncrMarkString(proto->source);
		}
		for (int index = 0; index < proto->sizek; ++index) {
			IncrMarkValue(state, proto->k[index]);
		}
		for (int index = 0; index < proto->sizeupvalues; ++index) {
			if (proto->upvalues[index] != nullptr) {
				IncrMarkString(proto->upvalues[index]);
			}
		}
		for (int index = 0; index < proto->sizep; ++index) {
			IncrMarkObject(state, reinterpret_cast<GCObject*>(proto->p[index]));
		}
		for (int index = 0; index < proto->sizelocvars; ++index) {
			if (proto->locvars[index].varname != nullptr) {
				IncrMarkString(proto->locvars[index].varname);
			}
		}
	}

	// Ported from Lua 5.1.5 lgc.c: traversestack().
	void IncrTraverseStack(SState& state, lua_State* const thread)
	{
		IncrMarkValue(state, thread->_gt);

		TObject* limit = thread->top;
		for (CallInfo* ci = thread->base_ci; ci <= thread->ci; ++ci) {
			if (limit < ci->top) {
				limit = ci->top;
			}
		}

		for (TObject* slot = thread->stack; slot < thread->top; ++slot) {
			IncrMarkValue(state, *slot);
		}
		for (TObject* slot = thread->top; slot <= limit; ++slot) {
			slot->tt = LUA_TNIL;
			slot->value.p = nullptr;
		}

		// Lua 5.1.5 traversestack() never resizes the stack. Shrinking here
		// would move a live VM stack behind its ra/rb pointers.
		(void)limit;
	}

	// Ported from Lua 5.1.5 lgc.c: remarkupvals().
	// Open upvalues live on each thread's openupval list in this fork, not on
	// a process-global uvhead list.
	void IncrRemarkUpvalues(SState& state)
	{
		const auto remarkThread = [&state](lua_State* const thread) {
			for (GCObject* object = thread->openupval; object != nullptr; object = object->gch.next) {
				UpVal* const upvalue = &object->uv;
				// Lua 5.1.5 remarkupvals() tests the UpVal object itself.
				if (IsGray(object)) {
					IncrMarkValue(state, *upvalue->v);
				}
			}
		};

		remarkThread(state.g->mainthread);
		for (GCObject* object = state.g->rootgc1; object != nullptr; object = object->gch.next) {
			if (object->gch.tt == LUA_TTHREAD) {
				remarkThread(&object->th);
			}
		}
	}

	// Ported from Lua 5.1.5 lgc.c: propagatemark().
	// The fork stores one gclist offset per object shape; UpVal objects are
	// never gray-listed (they become black when closed and are remarked by
	// remarkupvals() while open), matching 5.1.
	size_t IncrPropagateMark(SState& state)
	{
		GCObject* const object = state.gray;
		if (object == nullptr) {
			return 0;
		}
		IncrGrayToBlack(object);

		switch (object->gch.tt) {
			case LUA_TTABLE: {
				Table* const table = &object->h;
				state.gray = table->gclist;
				if (IncrTraverseTable(state, table)) {
					IncrBlackToGray(object); // weak tables stay gray
				}
				return sizeof(Table) + sizeof(TObject) * static_cast<size_t>(table->sizearray) +
				       sizeof(Node) * (static_cast<size_t>(1) << table->lsizenode);
			}

			case LUA_CFUNCTION: {
				const Closure* const closure = &object->cl;
				state.gray = closure->c.gclist;
				IncrTraverseClosure(state, closure, true);
				return sizeof(CClosure) + sizeof(TObject) * static_cast<size_t>(closure->c.nupvalues);
			}

			case LUA_TFUNCTION: {
				const Closure* const closure = &object->cl;
				state.gray = closure->c.gclist;
				IncrTraverseClosure(state, closure, false);
				return sizeof(LClosure) + sizeof(UpVal*) * static_cast<size_t>(closure->l.nupvalues);
			}

			case LUA_TTHREAD: {
				lua_State* const thread = &object->th;
				state.gray = thread->gclist;
				thread->gclist = state.grayagain;
				state.grayagain = object;
				IncrBlackToGray(object); // threads are revisited at atomic()
				IncrTraverseStack(state, thread);
				return sizeof(lua_State) + sizeof(TObject) * static_cast<size_t>(thread->stacksize) +
				       sizeof(CallInfo) * static_cast<size_t>(thread->size_ci);
			}

			case LUA_TPROTO: {
				Proto* const proto = &object->p;
				state.gray = proto->gclist;
				IncrTraverseProto(state, proto);
				return sizeof(Proto) + sizeof(Instruction) * static_cast<size_t>(proto->sizecode) +
				       sizeof(Proto*) * static_cast<size_t>(proto->sizep) +
				       sizeof(TObject) * static_cast<size_t>(proto->sizek);
			}

			default:
				return 0;
		}
	}

	// Ported from Lua 5.1.5 lgc.c: propagateall().
	size_t IncrPropagateAll(SState& state)
	{
		size_t work = 0;
		while (state.gray != nullptr) {
			work += IncrPropagateMark(state);
		}
		return work;
	}

	// Ported from Lua 5.1.5 lgc.c: markroot().
	void IncrMarkRoot(lua_State* const state)
	{
		SState& incremental = Acquire(state->l_G);
		incremental.gray = nullptr;
		incremental.grayagain = nullptr;
		incremental.weak = nullptr;

		global_State* const globalState = state->l_G;
		// The main thread is not linked into any sweep list in this fork, so
		// nothing turns it white between cycles. 5.1's mainthread is a rootgc
		// object and gets makewhite() during sweep; do the equivalent here.
		IncrMakeWhite(incremental, reinterpret_cast<GCObject*>(globalState->mainthread));
		IncrMarkObject(incremental, reinterpret_cast<GCObject*>(globalState->mainthread));
		IncrMarkValue(incremental, globalState->mainthread->_gt);
		IncrMarkValue(incremental, globalState->_registry);
		IncrMarkValue(incremental, globalState->_defaultmeta);
		for (TObject& slot : globalState->_defaultmetatypes) {
			IncrMarkValue(incremental, slot);
		}
		if (state != globalState->mainthread) {
			IncrMarkObject(incremental, reinterpret_cast<GCObject*>(state));
		}

		incremental.state = EState::Propagate;

		// LuaPlus keeps live LuaObject payloads in an engine-side root list.
		if (globalState->userGCFunction != nullptr) {
			GCState hook{};
			hook.g = globalState;
			hook.L = globalState->mainthread;
			globalState->userGCFunction(&hook);
		}
	}

	// Ported from Lua 5.1.5 lgc.c: isfinalized() for userdata.
	//
	// Upstream 5.1 sets FINALIZEDBIT on a userdata while it is being taken
	// through finalisation (lgc.c:137/142, inside luaC_separateudata) and
	// never clears it, so `isfinalized' stays true for the rest of the
	// object's life. lgc.c:343 then drops such userdata from weak *values*
	// while keeping them in weak *keys*.
	//
	// This fork has no permanent "finalized" bit: mark bit 0x02 means
	// "wants finaliser", it is set at allocation (only for types with a
	// destructor) and it is cleared once the destructor has run. The
	// finalized state is therefore derived from the collector's own state:
	//   - a userdata that has been separated for finalisation sits on
	//     `tmudata' until its destructor runs, and
	//   - a userdata whose destructor already ran has a cleared 0x02 bit
	//     while its type still has a destructor.
	[[nodiscard]] bool IncrIsFinalizedUserdata(SState& state, const GCObject* const object)
	{
		if (object->gch.tt != LUA_TUSERDATA) {
			return false;
		}

		if ((object->gch.marked & kFinalizedBit) != 0) {
			// Still wants its finaliser: only the userdata that have already
			// been separated for finalisation count as finalized.
			for (GCObject* pending = state.g->tmudata; pending != nullptr; pending = pending->gch.next) {
				if (pending == object) {
					return true;
				}
			}
			return false;
		}

		// The "wants finaliser" bit is clear, so the destructor has run if the
		// type has one at all.
		const auto* const type = reinterpret_cast<const gpg::RType*>(object->u.len);
		return type != nullptr && type->dtrFunc_ != nullptr;
	}

	// Ported from Lua 5.1.5 lgc.c: iscleared().
	bool IncrIsCleared(SState& state, const TObject& value, const bool isKey)
	{
		if (!IsCollectable(value)) {
			return false;
		}
		if (value.tt == LUA_TSTRING) {
			// Strings behave as values in weak tables and are never collected
			// merely because they are weak entries.
			IncrMarkString(static_cast<TString*>(value.value.p));
			return false;
		}

		auto* const object = static_cast<GCObject*>(value.value.p);
		if (object == nullptr) {
			return false;
		}
		// This runs in atomic() before currentWhite is flipped. Upstream 5.1
		// uses iswhite() here, not isdead(): white means "not reached by this
		// mark", while isdead() would only become true after the flip.
		if (IsWhite(object) && !IsBlack(object)) {
			return true;
		}

		// Upstream: iswhite(o) || (ttisuserdata(o) && (!iskey && isfinalized(uvalue(o)))).
		// A finalized userdata is dropped from weak values but kept in weak
		// keys, so that the finaliser can still resurrect it.
		if (!isKey && value.tt == LUA_TUSERDATA && IncrIsFinalizedUserdata(state, object)) {
			return true;
		}

		return false;
	}

	// Ported from Lua 5.1.5 lgc.c: cleartable().
	void IncrClearWeakTables(SState& state)
	{
		for (GCObject* object = state.weak; object != nullptr;) {
			Table* const table = &object->h;
			GCObject* const next = table->gclist;
			const bool weakKey = (table->marked & kKeyWeakBit) != 0;
			const bool weakValue = (table->marked & kValueWeakBit) != 0;

			if (weakValue) {
				for (int index = table->sizearray; index != 0; --index) {
					TObject& value = table->array[index - 1];
					if (IncrIsCleared(state, value, false)) {
						value.tt = LUA_TNIL;
						value.value.p = nullptr;
					}
				}
			}

			const int nodeCount = 1 << table->lsizenode;
			for (int index = nodeCount; index != 0; --index) {
				Node& node = table->node[index - 1];
				if (node.i_val.tt == LUA_TNIL) {
					continue;
				}
				const LuaPlus::TObject nodeKey = node.Key();
				if (IncrIsCleared(state, nodeKey, true) || IncrIsCleared(state, node.i_val, false)) {
					node.i_val.tt = LUA_TNIL;
					node.i_val.value.p = nullptr;
					if (IsCollectable(nodeKey)) {
						node.SetKeyTag(LUA_TNONE);
					}
				}
			}
			(void)weakKey;
			object = next;
		}
		state.weak = nullptr;
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_separateudata().
	// The fork keeps userdata on rootudata and records "wants finaliser" in
	// mark bit 0x02 (the same bit 5.1 calls FINALIZEDBIT, but here it is set at
	// allocation and cleared after the destructor runs).
	size_t IncrSeparateUdata(SState& state, lua_State* const L)
	{
		constexpr lu_byte kWantsFinalizerBit = 0x02;

		GCObject** link = &state.g->rootudata;
		GCObject* moved = nullptr;
		GCObject** movedTail = &moved;
		size_t deadMemory = 0;

		while (*link != nullptr) {
			GCObject* const current = *link;
			// atomic() calls this before the white-bit flip; an unmarked object
			// is still white at this point. IsDead() is only valid after the flip.
			if (!IsWhite(current) || IsBlack(current) ||
				(current->gch.marked & kWantsFinalizerBit) == 0) {
				link = &current->gch.next;
				continue;
			}

			deadMemory += static_cast<size_t>(
				LuaX86PayloadSize(reinterpret_cast<gpg::RType*>(current->u.len))
			);
			*link = current->gch.next;
			current->gch.next = nullptr;
			*movedTail = current;
			movedTail = &current->gch.next;
		}

		*movedTail = state.g->tmudata;
		state.g->tmudata = moved;
		(void)L;
		return deadMemory;
	}

	// Ported from Lua 5.1.5 lgc.c: marktmu().
	void IncrMarkTMU(SState& state)
	{
		for (GCObject* object = state.g->tmudata; object != nullptr; object = object->gch.next) {
			IncrMakeWhite(state, object);
			IncrReallyMarkObject(state, object);
		}
	}

	// Ported from Lua 5.1.5 lgc.c: GCTM().
	bool IncrCallGCTMOne(SState& state, lua_State* const L)
	{
		constexpr lu_byte kWantsFinalizerBit = 0x02;

		GCObject* const object = state.g->tmudata;
		if (object == nullptr) {
			return false;
		}
		state.g->tmudata = object->gch.next;
		object->gch.next = state.g->rootudata;
		state.g->rootudata = object;

		IncrMakeWhite(state, object);
		object->gch.marked &= static_cast<lu_byte>(~kWantsFinalizerBit);

		++L->top;
		TObject* const slot = L->top - 1;
		slot->value.p = object;
		slot->tt = static_cast<int>(object->gch.tt);

		RunLuaCallGate(nullptr);
		auto* const type = reinterpret_cast<gpg::RType*>(object->u.len);
		if (type->dtrFunc_ != nullptr) {
			type->dtrFunc_(static_cast<void*>(&object->u + 1));
		}
		--L->top;
		return true;
	}

	// Ported from Lua 5.1.5 lgc.c: atomic().
	void IncrAtomic(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		global_State* const globalState = L->l_G;
		IncrRemarkUpvalues(state);
		IncrPropagateAll(state);

		// Re-mark weak tables and their metatables; weak tables were left gray
		// by traversetable() and are collected on the weak list.
		state.gray = state.weak;
		state.weak = nullptr;
		IncrMarkObject(state, reinterpret_cast<GCObject*>(L));
		IncrMarkObject(state, reinterpret_cast<GCObject*>(globalState->mainthread));
		IncrMarkObject(state, reinterpret_cast<GCObject*>(globalState->lstate));
		IncrMarkValue(state, globalState->mainthread->_gt);
		IncrMarkValue(state, globalState->_registry);
		IncrMarkValue(state, globalState->_defaultmeta);
		for (TObject& slot : globalState->_defaultmetatypes) {
			IncrMarkValue(state, slot);
		}
		if (globalState->userGCFunction != nullptr) {
			GCState hook{};
			hook.g = globalState;
			hook.L = globalState->mainthread;
			globalState->userGCFunction(&hook);
		}
		IncrPropagateAll(state);

		// Objects caught by write barriers since the last step.
		state.gray = state.grayagain;
		state.grayagain = nullptr;
		IncrPropagateAll(state);

		size_t deadMemory = IncrSeparateUdata(state, L);
		IncrMarkTMU(state);
		deadMemory += IncrPropagateAll(state);

		IncrClearWeakTables(state);

		// Flip the current white before sweeping. Objects allocated after this
		// point are born with the new white and are not considered dead.
		state.currentWhite ^= kWhiteBits;
		state.sweepStringBucket = 0;
		state.sweepLink = nullptr;
		state.state = EState::SweepString;
		state.estimate = (globalState->nblocks > deadMemory) ? (globalState->nblocks - deadMemory) : 0;
	}

	// Ported from Lua 5.1.5 lgc.c: freeobj() is the fork's existing function;
	// this is the incremental sweeplist() body around it.
	GCObject** IncrSweepList(lua_State* const L, GCObject** link, const int count, int& freed)
	{
		SState& state = Acquire(L->l_G);
		int remaining = count;
		while (*link != nullptr && remaining-- > 0) {
			GCObject* const current = *link;

			if (current->gch.tt == LUA_TTHREAD) {
				// Lua 5.1.5 lgc.c: sweeplist() first sweeps the thread's
				// openupval list. Dead open upvalues are unlinked and freed here;
				// live ones stay on the list and are made white. luaF_close()
				// still copies a live upvalue's value before any later stack/thread
				// teardown. Keeping every entry alive would retain dead upvalues
				// for the lifetime of a long-lived thread.
				int openFreed = 0;
				(void)IncrSweepList(
					L,
					&current->th.openupval,
					0x7FFFFFFF,
					openFreed
				);
				freed += openFreed;
			}

			if (!IsDead(state, current)) {
				IncrMakeWhite(state, current);
				link = &current->gch.next;
			} else {
				*link = current->gch.next;
				freeobj(current, L);
				++freed;
			}
		}
		return link;
	}

	// Ported from Lua 5.1.5 lgc.c: sweepwholelist() over one string bucket.
	int IncrSweepStringBucket(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		global_State* const globalState = L->l_G;
		int freed = 0;
		(void)IncrSweepList(L, &globalState->strt.hash[state.sweepStringBucket], 0x7FFFFFFF, freed);
		return freed;
	}

	// Ported from Lua 5.1.5 lgc.c: checkSizes().
	void IncrCheckSizes(lua_State* const L)
	{
		global_State* const globalState = L->l_G;
		if (globalState->strt.nuse < globalState->strt.size / 4 && globalState->strt.size > 64) {
			luaS_resize(L, globalState->strt.size / 2);
		}
		if (globalState->buff.buffsize > 64u) {
			const lu_mem oldSize = globalState->buff.buffsize;
			const lu_mem newSize = oldSize >> 1;
			globalState->buff.buffer =
				luaM_reallocvector<char>(L, globalState->buff.buffer, oldSize, newSize);
			globalState->buff.buffsize = newSize;
		}
	}

	// Ported from Lua 5.1.5 lgc.c: setthreshold().
	void IncrSetThreshold(SState& state)
	{
		state.estimate = state.g->nblocks;
		state.g->GCthreshold = (state.estimate / 100u) * static_cast<lu_mem>(state.gcPause);
	}

	// Ported from Lua 5.1.5 lgc.c: singlestep().
	int IncrSingleStep(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		switch (state.state) {
			case EState::Pause:
				IncrMarkRoot(L);
				return 0;

			case EState::Propagate:
				if (state.gray != nullptr) {
					return static_cast<int>(IncrPropagateMark(state));
				}
				IncrAtomic(L);
				return 0;

			case EState::SweepString: {
				const int freed = IncrSweepStringBucket(L);
				state.g->strt.nuse -= freed;
				++state.sweepStringBucket;
				if (state.sweepStringBucket >= state.g->strt.size) {
					state.state = EState::SweepUserdata;
					state.sweepLink = &state.g->rootudata;
				}
				return kGcSweepCost;
			}

			case EState::SweepUserdata:
			case EState::SweepThreads:
			case EState::SweepObjects: {
				int freed = 0;
				state.sweepLink = IncrSweepList(L, state.sweepLink, kGcSweepMax, freed);
				if (*state.sweepLink == nullptr) {
					if (state.state == EState::SweepUserdata) {
						state.state = EState::SweepThreads;
						state.sweepLink = &state.g->rootgc1;
					} else if (state.state == EState::SweepThreads) {
						state.state = EState::SweepObjects;
						state.sweepLink = &state.g->rootgc;
					} else {
						IncrCheckSizes(L);
						state.state = EState::Finalize;
					}
				}
				return kGcSweepCost * kGcSweepMax;
			}

			case EState::Finalize:
				if (IncrCallGCTMOne(state, L)) {
					return kGcFinalizeCost;
				}
				state.state = EState::Pause;
				state.gcdebt = 0;
				IncrSetThreshold(state);
				return 0;
		}
		return 0;
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_link().
	void IncrLink(lua_State* const L, GCObject* const object, const int typeTag)
	{
		SState& state = Acquire(L->l_G);
		object->gch.next = L->l_G->rootgc;
		L->l_G->rootgc = object;
		object->gch.marked = state.initialized ? White(state) : kWhite0Bit;
		object->gch.tt = static_cast<lu_byte>(typeTag);
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_linkupval().
	void IncrLinkUpVal(lua_State* const L, UpVal* const upvalue)
	{
		SState& state = Acquire(L->l_G);
		auto* const object = reinterpret_cast<GCObject*>(upvalue);
		object->gch.next = L->l_G->rootgc;
		L->l_G->rootgc = object;
		if (IsGray(object)) {
			if (state.state == EState::Propagate) {
				IncrGrayToBlack(object);
				if (upvalue->v != nullptr && IsCollectable(*upvalue->v)) {
					auto* const value = static_cast<GCObject*>(upvalue->v->value.p);
					if (value != nullptr && IsWhite(value)) {
						IncrReallyMarkObject(state, value);
					}
				}
			} else {
				IncrMakeWhite(state, object);
			}
		}
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_barrierf().
	void IncrBarrierF(lua_State* const L, GCObject* const object, GCObject* const value)
	{
		if (L == nullptr || L->l_G == nullptr) {
			return;
		}
		if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
			return;
		}
		SState& state = Acquire(L->l_G);
		if (!state.initialized || object == nullptr || value == nullptr) {
			return;
		}
		if (state.state == EState::Pause || state.state == EState::Finalize) {
			return;
		}
		if (!IsBlack(object) || !IsWhite(value) || IsDead(state, value) || IsDead(state, object)) {
			return;
		}
		if (state.state == EState::Propagate) {
			IncrReallyMarkObject(state, value);
		} else {
			IncrMakeWhite(state, object);
		}
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_barrierback().
	void IncrBarrierBack(lua_State* const L, Table* const table)
	{
		if (L == nullptr || L->l_G == nullptr) {
			return;
		}
		if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
			return;
		}
		SState& state = Acquire(L->l_G);
		if (!state.initialized || table == nullptr) {
			return;
		}
		if (state.state == EState::Pause || state.state == EState::Finalize) {
			return;
		}
		auto* const object = reinterpret_cast<GCObject*>(table);
		if (!IsBlack(object) || IsDead(state, object)) {
			return;
		}
		IncrBlackToGray(object);
		table->gclist = state.grayagain;
		state.grayagain = object;
	}

	// Ported from Lua 5.1.5 lgc.h: luaC_barrier() / luaC_barriert().
	void IncrBarrierValue(lua_State* const L, GCObject* const object, const TObject* const value)
	{
		if (L == nullptr || L->l_G == nullptr) {
			return;
		}
		if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
			return;
		}
		if (value == nullptr || !IsCollectable(*value)) {
			return;
		}
		auto* const valueObject = static_cast<GCObject*>(value->value.p);
		if (valueObject != nullptr) {
			IncrBarrierF(L, object, valueObject);
		}
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_step().
	void IncrStep(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		if (state.running) {
			return;
		}
		state.running = true;

		if (state.g->nblocks > state.g->GCthreshold) {
			state.gcdebt += state.g->nblocks - state.g->GCthreshold;
		}
		int limit = (kGcStepSize / 100) * state.gcStepMul;
		if (limit == 0) {
			limit = 0x7FFFFFFF;
		}
		do {
			limit -= IncrSingleStep(L);
			if (state.state == EState::Pause) {
				break;
			}
		} while (limit > 0);

		if (state.state != EState::Pause) {
			if (state.gcdebt < static_cast<lu_mem>(kGcStepSize)) {
				state.g->GCthreshold = state.g->nblocks + kGcStepSize;
			} else {
				state.gcdebt -= kGcStepSize;
				state.g->GCthreshold = state.g->nblocks;
			}
		} else {
			IncrSetThreshold(state);
		}
		state.running = false;
	}

	// Engine addition for the UI driver: 5.1's singlestep loop with an explicit
	// work budget instead of allocation debt.
	bool IncrSlice(lua_State* const L, const int workBudget, const bool forceStart)
	{
		SState& state = Acquire(L->l_G);
		if (state.running) {
			return state.state == EState::Pause;
		}
		state.frameDriven = true;
		// The UI asks every frame; do nothing until the allocation threshold
		// says a collection is due, otherwise a cycle would restart forever.
		if (state.state == EState::Pause && !forceStart && L->l_G->nblocks < L->l_G->GCthreshold) {
			return true;
		}
		state.running = true;
		int remaining = workBudget;
		do {
			remaining -= IncrSingleStep(L);
			if (state.state == EState::Pause) {
				break;
			}
		} while (remaining > 0);
		if (state.state == EState::Pause) {
			IncrSetThreshold(state);
		} else {
			// A cycle is still running. Do not pull the threshold down to
			// `nblocks + kGcStepSize` (1 KB): that would make every single
			// allocation look like a collection is due and would hand the
			// pacing over to the allocation path. The frame driver owns the
			// pacing of a frame-driven state, so keep the normal pause-based
			// threshold and never lower it below the current block count.
			const lu_mem normalThreshold =
				(state.g->nblocks / 100u) * static_cast<lu_mem>(state.gcPause);
			state.g->GCthreshold = (normalThreshold > state.g->nblocks)
				? normalThreshold
				: state.g->nblocks;
		}
		state.running = false;
		return state.state == EState::Pause;
	}

	// Ported from Lua 5.1.5 lgc.c: luaC_fullgc().
	void IncrFullGC(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		if (state.running) {
			return;
		}
		state.running = true;
		bool started = false;
		while (true) {
			if (state.state == EState::Pause) {
				if (started) {
					break;
				}
				started = true;
			}
			IncrSingleStep(L);
		}
		IncrSetThreshold(state);
		state.running = false;
	}

	// Engine addition: colour every pre-existing object before the first
	// incremental cycle. This is the one-time equivalent of 5.1's invariant
	// that every object is born with luaC_white().
	void IncrEnsure(lua_State* const L)
	{
		SState& state = Acquire(L->l_G);
		if (state.initialized) {
			return;
		}

		state.currentWhite = kWhite0Bit;
		state.state = EState::Pause;
		// The main thread is not linked into rootgc in this fork; 5.1 relies
		// on every object already carrying a white colour when markroot runs.
		IncrMakeWhite(state, reinterpret_cast<GCObject*>(L->l_G->mainthread));
		state.gray = nullptr;
		state.grayagain = nullptr;
		state.weak = nullptr;
		state.sweepStringBucket = 0;
		state.sweepLink = nullptr;

		const auto recolourList = [&state](GCObject* object) {
			for (; object != nullptr; object = object->gch.next) {
				IncrMakeWhite(state, object);
			}
		};
		recolourList(L->l_G->rootudata);
		recolourList(L->l_G->rootgc1);
		recolourList(L->l_G->rootgc);
		for (int bucket = 0; bucket < L->l_G->strt.size; ++bucket) {
			recolourList(L->l_G->strt.hash[bucket]);
		}

		const auto recolourThread = [&state](lua_State* const thread) {
			for (GCObject* object = thread->openupval; object != nullptr; object = object->gch.next) {
				IncrMakeWhite(state, object);
			}
		};
		recolourThread(L->l_G->mainthread);
		for (GCObject* object = L->l_G->rootgc1; object != nullptr; object = object->gch.next) {
			if (object->gch.tt == LUA_TTHREAD) {
				recolourThread(&object->th);
			}
		}

		state.initialized = true;
		IncrSetThreshold(state);
	}
	// Engine addition: finish and remove the incremental state when a Lua
	// state stops being the user VM (the sim installs its Sim* in
	// globalUserData). This keeps the shipped 5.0 collector's mark bytes clean.
	void IncrClearColors(global_State* const g)
	{
		const auto clearList = [](GCObject* object) {
			for (; object != nullptr; object = object->gch.next) {
				object->gch.marked &= static_cast<lu_byte>(~kColorMask);
			}
		};
		clearList(g->rootudata);
		clearList(g->rootgc1);
		clearList(g->rootgc);
		for (int bucket = 0; bucket < g->strt.size; ++bucket) {
			clearList(g->strt.hash[bucket]);
		}
		if (g->mainthread != nullptr) {
			g->mainthread->marked &= static_cast<lu_byte>(~kColorMask);
			clearList(g->mainthread->openupval);
		}
		for (GCObject* object = g->rootgc1; object != nullptr; object = object->gch.next) {
			if (object->gch.tt == LUA_TTHREAD) {
				clearList(object->th.openupval);
			}
		}
	}

	void IncrAbandon(global_State* const g)
	{
		SState* const state = Find(g);
		if (state == nullptr) {
			return;
		}
		if (state->state != EState::Pause && g->mainthread != nullptr) {
			IncrFullGC(g->mainthread);
		}
		IncrClearColors(g);
		Release(g);
		UnregisterIncrementalVm(g);
		g->GCthreshold = 0;
	}
} // namespace

extern "C" void faf_lua51_gc_abandon(global_State* const g)
{
	IncrAbandon(g);
}

extern "C" void faf_lua51_gc_register_vm(lua_State* const L, const int role)
{
	if (L == nullptr || L->l_G == nullptr) {
		return;
	}
	if (role != static_cast<int>(ELuaVmRole::FrontendUi) &&
		role != static_cast<int>(ELuaVmRole::SessionUi)) {
		return;
	}
	// Only a non-sim root may use the incremental collector. In particular,
	// never let a state that has installed a Sim* in globalUserData enter here.
	if (L->l_G->globalUserData != nullptr) {
		return;
	}
	RegisterIncrementalVm(L->l_G);
	// Engine addition: initialise the collector and its pause threshold at VM
	// creation. Without this a freshly registered session VM keeps the shipped
	// 5.0 default threshold (115000) while the heap is already tens of millions
	// of blocks, so every allocation passes the gate and the cycle is pushed
	// far too hard during session loading.
	if (UsesIncrementalGc(L->l_G)) {
		IncrEnsure(L);
	}
}

extern "C" void faf_lua51_gc_release(global_State* const g)
{
	if (g == nullptr) {
		return;
	}
	UnregisterIncrementalVm(g);
	// Never touch the shipped 5.0 mark bytes unless this state actually went
	// through the incremental path.
	if (Find(g) == nullptr) {
		return;
	}
	IncrClearColors(g);
	Release(g);
}

extern "C" void faf_lua51_gc_step(lua_State* const L)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return;
	}
	IncrEnsure(L);
	IncrStep(L);
}

extern "C" bool faf_lua51_gc_slice(lua_State* const L, const int workBudget, const bool forceStart)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return true;
	}
	IncrEnsure(L);
	return IncrSlice(L, workBudget, forceStart);
}

extern "C" void faf_lua51_gc_full(lua_State* const L)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return;
	}
	IncrEnsure(L);
	IncrFullGC(L);
}

extern "C" void faf_lua51_gc_link(lua_State* const L, GCObject* const object, const int typeTag)
{
	IncrLink(L, object, typeTag);
}

extern "C" void faf_lua51_gc_color_userdata(lua_State* const L, Udata* const userdata)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return;
	}
	SState& state = Acquire(L->l_G);
	const lu_byte colour = state.initialized ? White(state) : kWhite0Bit;
	userdata->marked = static_cast<lu_byte>(
		(userdata->marked & static_cast<lu_byte>(~kColorMask)) | colour
	);
}

extern "C" void faf_lua51_gc_color_thread(lua_State* const L, lua_State* const thread)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return;
	}
	SState& state = Acquire(L->l_G);
	const lu_byte colour = state.initialized ? White(state) : kWhite0Bit;
	thread->marked = static_cast<lu_byte>(
		(thread->marked & static_cast<lu_byte>(~kColorMask)) | colour
	);
}

extern "C" void faf_lua51_gc_link_upval(lua_State* const L, UpVal* const upvalue)
{
	IncrLinkUpVal(L, upvalue);
}

extern "C" void faf_lua51_gc_barrier_f(lua_State* const L, GCObject* const object, GCObject* const value)
{
	IncrBarrierF(L, object, value);
}

extern "C" void faf_lua51_gc_barrier_back(lua_State* const L, Table* const table)
{
	IncrBarrierBack(L, table);
}

extern "C" void faf_lua51_gc_barrier_value(
	lua_State* const L,
	GCObject* const object,
	const TObject* const value)
{
	IncrBarrierValue(L, object, value);
}

extern "C" bool faf_lua51_gc_is_active(global_State* const g)
{
	return Active(g);
}

extern "C" void faf_lua51_gc_mark_object(global_State* const g, GCObject* const object)
{
	if (!moho::lua_IncrementalGC || !IsUiState(g)) {
		return;
	}
	SState* const state = Find(g);
	if (state == nullptr || !state->initialized || state->state == EState::Pause ||
		state->state == EState::Finalize) {
		return;
	}
	IncrMarkObject(*state, object);
}

// Ported from Lua 5.1.5 lstring.c: luaS_resize() bails out while the
// collector is sweeping the string table.
extern "C" bool faf_lua51_gc_sweep_string_active(lua_State* const L)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return false;
	}
	const SState* const state = Find(L->l_G);
	return state != nullptr && state->state == EState::SweepString;
}

extern "C" void faf_lua51_gc_revive_string(lua_State* const L, GCObject* const object)
{
	if (!moho::lua_IncrementalGC || !IsUiState(L->l_G)) {
		return;
	}
	SState* const state = Find(L->l_G);
	if (state == nullptr || !state->initialized) {
		return;
	}
	if (!IsDead(*state, object)) {
		return;
	}
	// Lua 5.1.5 lstring.c: `if (isdead(G(L), o)) changewhite(o);`
	// A dead interned string that is still linked in the string table is
	// revived by flipping its white colour back to the current white.
	IncrChangeWhite(object);
}

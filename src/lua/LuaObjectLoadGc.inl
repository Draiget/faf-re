// Part of LuaObject.cpp, included there: chunk loading and the collector (lundump, lgc).

	/**
	 * Address: 0x009287A0 (FUN_009287A0, sub_9287A0)
	 *
	 * What it does:
	 * Reads one size-prefixed Lua chunk string payload and interns it (without
	 * trailing NUL) into the owner Lua state string table.
	 */
	[[nodiscard]] TString* LuaLoadTString(LoadState* const loadState)
	{
		std::uint32_t byteCount = 0u;
		LuaLoadBlock(4u, &byteCount, loadState);
		if (byteCount == 0u) {
			return nullptr;
		}

		char* const scratch = luaZ_openspace(loadState->state, loadState->scratchBuffer, byteCount);
		if (luaZ_read(loadState->stream, scratch, byteCount) != 0) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}

		return luaS_newlstr(loadState->state, scratch, static_cast<size_t>(byteCount - 1u));
	}

	/**
	 * Address: 0x00928810 (FUN_00928810, sub_928810)
	 *
	 * What it does:
	 * Reads proto bytecode instruction count, allocates `Proto::code`, and
	 * loads one contiguous instruction vector from chunk stream.
	 */
	void LuaLoadProtoCode(LoadState* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->code = luaM_newvector<Instruction>(loadState->state, static_cast<lu_mem>(count));
		proto->sizecode = count;
		LuaLoadElementArray(reinterpret_cast<char*>(proto->code), loadState, count, 4);
	}

	/**
	 * Address: 0x00928960 (FUN_00928960, sub_928960)
	 *
	 * What it does:
	 * Reads proto line-info count, allocates `Proto::lineinfo`, and loads one
	 * contiguous source-line map vector from chunk stream.
	 */
	void LuaLoadProtoLineInfo(LoadState* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->lineinfo = luaM_newvector<int>(loadState->state, static_cast<lu_mem>(count));
		proto->sizelineinfo = count;
		LuaLoadElementArray(reinterpret_cast<char*>(proto->lineinfo), loadState, count, 4);
	}

	/**
	 * Address: 0x00928540 (FUN_00928540, LoadByte)
	 *
	 * What it does:
	 * Reads one byte from the chunk stream via the `zgetc` fast path
	 * (`ReadZioByte`); raises "unexpected end of file in %s" when the
	 * stream is exhausted (EOZ, -1). Matches real Lua 5.0.2 lundump.c's
	 * `LoadByte(LoadState*)`.
	 *
	 * This address sat in an untokenized gap (0x00928512-0x009285C0,
	 * between the end of FUN_009284D0 and FUN_009285C0/LoadBlock) that
	 * IDA never carved into its own function - no .asm/.c export exists
	 * for it. Identified by manual Capstone disassembly against
	 * bin/2025.7.1/ForgedAlliance.exe (validated against a known-good
	 * tokenized function first) and cross-checked instruction-for-
	 * instruction against this pre-existing recovered body, which
	 * already matched exactly.
	 */
	[[nodiscard]] int LuaReadChunkByteOrThrow(LoadState* const loadState)
	{
		const int byteValue = ReadZioByte(loadState->stream);
		if (byteValue == -1) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}
		return byteValue;
	}

	// The recursive nested-proto loader has external linkage (defined in the
	// LuaPlus block below so LuaParser.cpp's luaU_undump can call it). Re-expose
	// it here so the constant/child-proto reader can recurse by simple name.
	using LuaPlus::LuaLoadProtoObject;

	/**
	 * Address: 0x00928870 (FUN_00928870, sub_928870)
	 *
	 * What it does:
	 * Reads local-variable debug lane count and fills one `Proto::locvars`
	 * array with `{name,startpc,endpc}` entries.
	 */
	void LuaLoadProtoLocalVariableDebugInfo(
		LoadState* const loadState,
		Proto* const proto
	)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->locvars = luaM_newvector<LocVar>(loadState->state, static_cast<lu_mem>(count));
		proto->sizelocvars = count;

		if (count <= 0) {
			return;
		}

		for (int index = 0; index < count; ++index) {
			LocVar& lane = proto->locvars[index];
			lane.varname = LuaLoadTString(loadState);

			int startPc = 0;
			LuaLoadBlock(4u, &startPc, loadState);
			if (startPc < 0) {
				luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
			}
			lane.startpc = startPc;

			int endPc = 0;
			LuaLoadBlock(4u, &endPc, loadState);
			if (endPc < 0) {
				luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
			}
			lane.endpc = endPc;
		}
	}

	/**
	 * Address: 0x009289C0 (FUN_009289C0, sub_9289C0)
	 *
	 * What it does:
	 * Reads upvalue-name count, validates it against `Proto::nups`, and fills
	 * one `Proto::upvalues` string-pointer lane array.
	 */
	void LuaLoadProtoUpvalueNames(LoadState* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		if (count != 0 && count != static_cast<int>(proto->nups)) {
			luaG_runerror(
				loadState->state,
				"bad nupvalues in %s: read %d; expected %d",
				loadState->chunkName,
				count,
				static_cast<int>(proto->nups)
			);
		}

		proto->upvalues = luaM_newvector<TString*>(loadState->state, static_cast<lu_mem>(count));
		proto->sizeupvalues = count;

		for (int index = 0; index < count; ++index) {
			proto->upvalues[index] = LuaLoadTString(loadState);
		}
	}

	/**
	 * Address: 0x00928A60 (FUN_00928A60, sub_928A60)
	 *
	 * What it does:
	 * Loads one proto constant table lane (`Proto::k`) followed by nested child
	 * proto pointers (`Proto::p`) from the chunk stream.
	 */
	void LuaLoadProtoConstantsAndNestedProtos(
		LoadState* const loadState,
		Proto* const proto
	)
	{
		int constantCount = 0;
		LuaLoadBlock(4u, &constantCount, loadState);
		if (constantCount < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->k = luaM_newvector<LuaPlus::TObject>(loadState->state, static_cast<lu_mem>(constantCount));
		proto->sizek = constantCount;

		for (int index = 0; index < constantCount; ++index) {
			LuaPlus::TObject& constantLane = proto->k[index];
			const int constantType = LuaReadChunkByteOrThrow(loadState);
			const unsigned int typeTag = static_cast<unsigned int>(static_cast<unsigned char>(constantType));

			if (typeTag == LUA_TNIL) {
				constantLane.tt = LUA_TNIL;
				continue;
			}

			if (typeTag == LUA_TNUMBER) {
				float numberValue = 0.0f;
				LuaLoadBlock(4u, &numberValue, loadState);
				constantLane.tt = LUA_TNUMBER;
				constantLane.value.n = numberValue;
				continue;
			}

			if (typeTag == LUA_TSTRING) {
				TString* const stringValue = LuaLoadTString(loadState);
				constantLane.tt = static_cast<int>(stringValue->tt);
				constantLane.value.p = stringValue;
				continue;
			}

			luaG_runerror(loadState->state, "bad constant type (%d) in %s", static_cast<int>(typeTag), loadState->chunkName);
		}

		int childCount = 0;
		LuaLoadBlock(4u, &childCount, loadState);
		if (childCount < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->p = luaM_newvector<Proto*>(loadState->state, static_cast<lu_mem>(childCount));
		proto->sizep = childCount;

		for (int index = 0; index < childCount; ++index) {
			proto->p[index] = LuaLoadProtoObject(loadState, proto->source);
		}
	}

	/**
	 * Address: 0x0090A780 (FUN_0090A780, LuaPlusGCFunction)
	 *
	 * What it does:
	 * Marks root-state live LuaObject payload GC nodes during Lua GC callback,
	 * skipping already-marked or non-GC-tag payload lanes.
	 */
	void LuaPlusGCFunction(GCState* const gcState)
	{
		if (gcState == nullptr || gcState->L == nullptr) {
			return;
		}

		auto* const state = static_cast<LuaState*>(gcState->L->stateUserData);
		if (state == nullptr || state != state->m_rootState) {
			return;
		}

		LuaObject* node = state->m_headObject.m_next;
		LuaObject* const tail = reinterpret_cast<LuaObject*>(&state->m_tailObject);
		while (node != tail) {
			if (node->m_object.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(node->m_object.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(gcState, object);
				}
			}
			node = node->m_next;
		}
	}

	/**
	 * Address: 0x009151E0 (FUN_009151E0, reallymarkobject)
	 *
	 * What it does:
	 * Marks one collectable GC object and links it into the appropriate gray
	 * propagation lane.
	 */
	extern "C" void reallymarkobject(GCState* const st, GCObject* const object)
	{
		GCObject* current = object;
		current->gch.marked |= 1u;

		while (true) {
			switch (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE)) {
			case 0:
				current->h.gclist = st->tmark;
				st->tmark = current;
				return;

			case 1:
			case 2:
				current->cl.c.gclist = st->tmark;
				st->tmark = current;
				return;

			case 3:
				current = reinterpret_cast<GCObject*>(current->u.metatable);
				if (current != nullptr && (current->gch.marked & 0x11u) == 0u) {
					current->gch.marked |= 1u;
					if (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE) <= 5u) {
						continue;
					}
				}
				return;

			case 4:
				current->th.gclist = st->tmark;
				st->tmark = current;
				return;

			case 5:
				current->p.gclist = st->tmark;
				st->tmark = current;
				return;

			default:
				return;
			}
		}
	}

	/// Engine fix, see `ForgetDeadRemovedKeys`: the nodes this thread's serial traversals found with a
	/// removed collectable key.
	static thread_local std::vector<Node*> tRemovedKeyNodes;

	/**
	 * Engine addition (replay keyframes): the VM whose collection in progress treats weak tables as
	 * strong (`lua_collectkeepingweaktables`). Workers mark too, so it is not per thread; the user VM
	 * may collect meanwhile, so it names the VM.
	 */
	static std::atomic<const global_State*> sKeepWeakTablesOf{nullptr};

	/**
	 * Address: 0x00915320 (FUN_00915320, traversetable)
	 *
	 * What it does:
	 * Marks the metatable, resolves weak-table mode, and traverses array/hash
	 * lanes while preserving weak key/value semantics.
	 */
	extern "C" void traversetable(GCState* const st, Table* const h)
	{
		// __mode is slot 2, not 3: luaT_init (FUN_009283C0) interns
		// luaT_eventname (0x00D47508) in the order __index, __newindex,
		// __mode, __eq, ..., and traversetable's own call site is
		// "mov edx,[ecx+64h]" / "push 2" - byte offset 0x64 into tmname at
		// 0x5C. The old value read the same byte offset only because tmname
		// was mismodelled as starting at 0x58.
		constexpr int kLuaTagMethodMode = 2;

		auto markCollectable = [st](const TObject& slot) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		};

		auto condMarkCollectable = [&markCollectable](const TObject& slot, const bool shouldMark) {
			if (shouldMark) {
				markCollectable(slot);
			}
		};

		Table* const metatable = h->metatable;
		bool weakkey = false;
		bool weakvalue = false;
		if ((metatable->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(metatable));
		}

		if ((metatable->flags & 4) == 0 && sKeepWeakTablesOf.load(std::memory_order_relaxed) != st->g) {
			const TObject* const mode = luaT_gettm(metatable, kLuaTagMethodMode, st->g->tmname[kLuaTagMethodMode]);
			if (mode != nullptr && mode->tt == LUA_TSTRING) {
				const char* const modeText = static_cast<TString*>(mode->value.p)->str;
				weakkey = std::strchr(modeText, 'k') != nullptr;
				weakvalue = std::strchr(modeText, 'v') != nullptr;
			}
		}

		if (weakkey || weakvalue) {
			h->marked &= static_cast<lu_byte>(~0x6u);
			if (weakkey) {
				h->marked |= 0x2u;
			}
			if (weakvalue) {
				h->marked |= 0x4u;
			}

			GCObject** const weaklist = weakkey ? (weakvalue ? &st->wkv : &st->wk) : &st->wv;
			h->gclist = *weaklist;
			*weaklist = reinterpret_cast<GCObject*>(h);
		}

		if (!weakvalue) {
			for (int index = h->sizearray; index != 0; --index) {
				markCollectable(h->array[index - 1]);
			}
		}

		for (int index = 1 << h->lsizenode; index != 0; --index) {
			Node* const node = &h->node[index - 1];
			if (node->i_val.tt != LUA_TNIL) {
				condMarkCollectable(node->Key(), !weakkey);
				condMarkCollectable(node->i_val, !weakvalue);
			} else if (node->KeyTag() >= LUA_TSTRING) {
				tRemovedKeyNodes.push_back(node);
			}
		}
	}

	/**
	 * Address: 0x009154A0 (FUN_009154A0, traverseproto)
	 *
	 * What it does:
	 * Marks one prototype's strings, upvalue names, nested protos, and local
	 * variable names.
	 */
	extern "C" void traverseproto(GCState* const st, Proto* const f)
	{
		f->source->marked |= 1u;
		for (int index = 0; index < f->sizek; ++index) {
			TObject& constant = f->k[index];
			if (constant.tt == LUA_TSTRING) {
				static_cast<TString*>(constant.value.p)->marked |= 1u;
			}
		}

		for (int index = 0; index < f->sizeupvalues; ++index) {
			f->upvalues[index]->marked |= 1u;
		}

		for (int index = 0; index < f->sizep; ++index) {
			Proto* const nested = f->p[index];
			if ((nested->marked & 0x11u) == 0u) {
				reallymarkobject(st, reinterpret_cast<GCObject*>(nested));
			}
		}

		for (int index = 0; index < f->sizelocvars; ++index) {
			TString* const varname = f->locvars[index].varname;
			const auto nameBits = reinterpret_cast<std::uintptr_t>(varname);
			if (nameBits < 0x00100000u || (nameBits & 3u) != 0u) {
				static int sBadNameBudget = 0;
				if (sBadNameBudget < 10) {
					++sBadNameBudget;
					char probe[512];
					sprintf_s(probe, sizeof(probe),
					          "[LOCVARBAD] proto=%p locvars=%p(%d) idx=%d varname=%p | code=%p(%d end=%p) k=%p(%d) p=%p(%d) lineinfo=%p(%d)\n",
					          static_cast<const void*>(f),
					          static_cast<const void*>(f->locvars),
					          f->sizelocvars, index, static_cast<const void*>(varname),
					          static_cast<const void*>(f->code),
					          f->sizecode,
					          reinterpret_cast<const void*>(reinterpret_cast<std::uintptr_t>(f->code) +
					                                sizeof(Instruction) * static_cast<std::size_t>(f->sizecode)),
					          static_cast<const void*>(f->k), f->sizek,
					          static_cast<const void*>(f->p), f->sizep,
					          static_cast<const void*>(f->lineinfo),
					          f->sizelineinfo);
					::OutputDebugStringA(probe);
				}
				continue;
			}
			varname->marked |= 1u;
		}
	}

	/**
	 * Address: 0x00915540 (FUN_00915540, traversecclosure)
	 *
	 * What it does:
	 * Marks one C closure's collectable upvalue lanes.
	 */
	extern "C" void traversecclosure(GCState* const st, CClosure* const cl)
	{
		for (int index = 0; index < cl->nupvalues; ++index) {
			TObject& upvalue = cl->upvalue[index];
			if (upvalue.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(upvalue.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}
	}

	/**
	 * Address: 0x00915580 (FUN_00915580, traverselclosure)
	 *
	 * What it does:
	 * Marks one Lua closure's environment, prototype, and nested upvalues.
	 */
	extern "C" void traverselclosure(GCState* const st, LClosure* const cl)
	{
		if (cl->g.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(cl->g.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		if (cl->p != nullptr && (cl->p->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(cl->p));
		}

		for (int index = 0; index < cl->nupvalues; ++index) {
			UpVal* const upvalue = cl->upvals[index];
			if (upvalue != nullptr && upvalue->marked == 0) {
				if (upvalue->value.tt >= LUA_TSTRING) {
					auto* const object = static_cast<GCObject*>(upvalue->value.value.p);
					if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
						reallymarkobject(st, object);
					}
				}
				upvalue->marked = 1u;
			}
		}
	}

	/**
	 * Address: 0x00915600 (FUN_00915600)
	 *
	 * What it does:
	 * Shrinks call-info and stack allocations when the live usage window is
	 * sparse enough to satisfy the legacy Lua GC compaction thresholds.
	 */
	void ShrinkThreadStacksIfSparse(
		TObject* const liveStackLimit,
		lua_State* const state
	)
	{
		const unsigned __int16 callInfoCapacity = state->size_ci;
		if (4 * (state->ci - state->base_ci) < callInfoCapacity && callInfoCapacity > 0x10u) {
			luaD_reallocCI(state, callInfoCapacity >> 1);
		}

		const int stackCapacity = state->stacksize;
		if (4 * (liveStackLimit - state->stack) < stackCapacity && stackCapacity > 90) {
			luaD_reallocstack(state, stackCapacity / 2);
		}
	}

	/**
	 * Address: 0x00915670 (FUN_00915670, traversestack)
	 *
	 * What it does:
	 * Marks the thread global table and live stack lanes, clears the unused tail
	 * to nil, then trims overgrown stack and call-info allocations.
	 */
	extern "C" void traversestack(lua_State* const L1, GCState* const st)
	{
		if (L1->_gt.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(L1->_gt.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		CallInfo* const baseCi = L1->base_ci;
		CallInfo* const currentCi = L1->ci;
		TObject* lim = L1->top;
		for (CallInfo* ci = baseCi; ci <= currentCi; ++ci) {
			if (lim < ci->top) {
				lim = ci->top;
			}
		}

		for (TObject* object = L1->stack; object < L1->top; ++object) {
			if (object->tt >= LUA_TSTRING) {
				auto* const gcObject = static_cast<GCObject*>(object->value.p);
				if (gcObject != nullptr && (gcObject->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, gcObject);
				}
			}
		}

		for (TObject* object = L1->top; object <= lim; ++object) {
			object->tt = LUA_TNIL;
			object->value.p = nullptr;
		}

		ShrinkThreadStacksIfSparse(lim, L1);
	}

	/**
	 * Address: 0x00915840 (FUN_00915840, cleartablekeys)
	 *
	 * What it does:
	 * Walks weak-key tables and clears hash nodes whose keys are collectable
	 * but were not marked alive in the current propagation pass.
	 */
	extern "C" void cleartablekeys(GCObject* tableList)
	{
		auto markStringKey = [](const LuaPlus::TObject& keySlot) {
			if (keySlot.tt == LUA_TSTRING && keySlot.value.p != nullptr) {
				static_cast<TString*>(keySlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(static_cast<GCObject*>(table->gclist))) {
			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				const LuaPlus::TObject keySlot = node.Key();
				markStringKey(keySlot);

				if (keySlot.tt >= LUA_TSTRING) {
					auto* const keyObject = static_cast<GCObject*>(keySlot.value.p);
					if (keyObject != nullptr && (keyObject->gch.marked & 1u) == 0u) {
						node.i_val.tt = LUA_TNIL;
						node.SetKeyTag(LUA_TNONE);
					}
				}
			}
		}
	}

	/**
	 * Address: 0x009158A0 (FUN_009158A0, cleartablevalues)
	 *
	 * What it does:
	 * Walks weak-value tables and clears array/hash value lanes whose
	 * collectable payloads were not marked alive in the current GC pass.
	 */
	extern "C" void cleartablevalues(GCObject* tableList)
	{
		auto markStringValue = [](LuaPlus::TObject& valueSlot) {
			if (valueSlot.tt == LUA_TSTRING && valueSlot.value.p != nullptr) {
				static_cast<TString*>(valueSlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(static_cast<GCObject*>(table->gclist))) {
			for (int arrayIndex = table->sizearray; arrayIndex != 0; --arrayIndex) {
				LuaPlus::TObject& valueSlot = table->array[arrayIndex - 1];
				markStringValue(valueSlot);
				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						valueSlot.tt = LUA_TNIL;
					}
				}
			}

			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				LuaPlus::TObject& valueSlot = node.i_val;
				markStringValue(valueSlot);

				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						const bool hasCollectableKey = node.KeyTag() >= LUA_TSTRING;
						valueSlot.tt = LUA_TNIL;
						if (hasCollectableKey) {
							node.SetKeyTag(LUA_TNONE);
						}
					}
				}
			}
		}
	}

	extern "C" void freeobj(GCObject* object, lua_State* state);
	extern "C" void luaF_freeproto(lua_State* L, Proto* proto);
	extern "C" void luaF_freeclosure(lua_State* L, Closure* closure);
	extern "C" void luaE_freethread(lua_State* L, lua_State* thread);

	/**
	 * Address: 0x00915530 (lgc.c::freeobj, file-local in original Lua)
	 *
	 * What it does:
	 * Dispatches one dead GC object to its type-specific free function:
	 * `LUA_TPROTO`/`LUA_TFUNCTION`/`LUA_TTABLE`/`LUA_TTHREAD` route to the
	 * corresponding `luaF_free*` / `luaH_free` / `luaE_freethread` helper;
	 * `LUA_TUPVALUE`/`LUA_TSTRING`/`LUA_TUSERDATA` are released through
	 * `luaM_realloc(..., 0)` with the appropriate variable-length size.
	 * Recovered as a free function here because `sweeplist` (recovered above)
	 * calls it across translation-unit boundaries.
	 */
	extern "C" void freeobj(GCObject* const object, lua_State* const state)
	{
		switch (object->gch.tt) {
			case LUA_TPROTO:
				luaF_freeproto(state, reinterpret_cast<Proto*>(object));
				break;
			case LUA_TFUNCTION:
				luaF_freeclosure(state, reinterpret_cast<Closure*>(object));
				break;
			case LUA_TUPVALUE:
				luaM_freelem<UpVal>(state, reinterpret_cast<UpVal*>(object));
				break;
			case LUA_TTABLE:
				luaH_free(state, reinterpret_cast<Table*>(object));
				break;
			case LUA_TTHREAD:
				luaE_freethread(state, reinterpret_cast<lua_State*>(object));
				break;
			case LUA_TSTRING: {
				// `len + 21` in the binary (0x00915950), which is exactly what
				// `newlstr` asks for: a 20-byte header plus the NUL. Charging
				// `sizeof(TString)` instead adds the four bytes C++ pads the
				// `char str[1]` tail to, so every string free refunded four
				// bytes that were never allocated and `nblocks` drifted below
				// the true total - eventually underflowing and leaving the
				// collector running against a bogus threshold.
				const auto* const ts = reinterpret_cast<const TString*>(object);
				(void)luaM_reallocblock(state, object, sizestring(ts->len), {0u, 0u});
				break;
			}
			case LUA_TUSERDATA: {
				// `Udata::len` carries the object's `gpg::RType*` in this fork, not a
				// byte count, so the payload size is the type's. Charging `ud->len`
				// refunded a pointer value - tens of megabytes - on every userdata
				// free, which underflowed `nblocks` and left it permanently above
				// `GCthreshold`, so `luaC_checkGC` ran a full collection on every
				// single allocation from then on. Must mirror the allocation in
				// `luaS_newudata` exactly.
				const auto* const ud = reinterpret_cast<const Udata*>(object);
				const auto* const type = reinterpret_cast<const gpg::RType*>(ud->len);
				(void)luaM_reallocblock(state, object, sizeudata(type), {0u, 0u});
				break;
			}
			default:
				break;
		}
	}

	/**
	 * Address: 0x00915A00 (FUN_00915A00, sweeplist)
	 *
	 * What it does:
	 * Walks one intrusive GC list lane until `tail`, keeping live nodes in-place
	 * (while clearing their dead-white bit) and unlinking/freeing dead nodes up
	 * to `limit`, returning the reclaimed object count.
	 */
	extern "C" int sweeplist(
		GCObject** const listHeadLink,
		GCObject* const tail,
		lua_State* const state,
		const int limit
	)
	{
		GCObject** currentLink = listHeadLink;
		GCObject* current = *currentLink;
		int reclaimedCount = 0;

		while (current != tail) {
			const lu_byte markByte = current->gch.marked;
			// FAF hot-patch (FA-Binary-Patches weakgcmarkerFix, #73): the stock binary
			// compared the whole byte (`mov cl, [eax+5]; movzx edx, cl; cmp edx, limit`),
			// so a table that kept only its weak-mode bits (1 and 2, which the sweep
			// below never clears) compared above 0 and was never collected - weak
			// tables, and everything they held, lived forever. The FAF exe masks those
			// two bits first (`and edx, 0FFFFFFF9h` at 0x00915A17), as stock Lua 5.0
			// does. A userdata's bit 1 ("finaliser pending") is masked too, which is
			// safe: an unreached userdata with a finaliser has already been moved to
			// `tmudata` and re-marked by `luaC_separateudata` before the sweep.
			const int colorClass = static_cast<int>(markByte & 0xF9u);

			if (colorClass > limit) {
				current->gch.marked = static_cast<lu_byte>(markByte & 0xFEu);
				currentLink = &current->gch.next;
			} else {
				*currentLink = current->gch.next;
				++reclaimedCount;
				freeobj(current, state);
			}

			current = *currentLink;
		}

		return reclaimedCount;
	}

	/**
	 * Address: 0x00915A50 (FUN_00915A50, sweepstrings)
	 *
	 * What it does:
	 * Sweeps every string-table bucket and decrements `nuse` by each bucket's
	 * reclaimed string count.
	 */
	void sweepstrings(lua_State* const state, const int all)
	{
		global_State* const globalState = state->l_G;
		for (int index = 0; index < globalState->strt.size; ++index) {
			globalState->strt.nuse -= sweeplist(&globalState->strt.hash[index], nullptr, state, all);
		}
	}

	/**
	 * Address: 0x00915AA0 (FUN_00915AA0, checkSizes)
	 *
	 * What it does:
	 * Shrinks oversized string/hash scratch storage and recomputes the next GC
	 * threshold after the current mark/sweep dead-memory estimate.
	 */
	void checkSizes(lua_State* const state, const size_t deadmem)
	{
		global_State* const globalState = state->l_G;
		if (globalState->strt.nuse < globalState->strt.size / 4) {
			const int stringTableSize = globalState->strt.size;
			if (stringTableSize > 64) {
				luaS_resize(state, stringTableSize / 2);
			}
		}

		if (globalState->buff.buffsize > 64u) {
			const lu_mem oldBufferSize = globalState->buff.buffsize;
			const lu_mem newBufferSize = oldBufferSize >> 1;
			globalState->buff.buffer = luaM_reallocvector<char>(state, globalState->buff.buffer, oldBufferSize, newBufferSize);
			globalState->buff.buffsize = newBufferSize;
		}

		// FAF hot-patch (FA-Binary-Patches HFix4GB): 0x00915B05 jumps to `add eax, eax; jge`
		// at 0x00915A92, so the base is twice the heap while that doubling does not overflow a
		// signed 32-bit value (heap below 2 GB), and heap + 256 MB from there up.
		const std::uint32_t nblocks = static_cast<std::uint32_t>(globalState->nblocks);
		const std::uint32_t thresholdBase =
			static_cast<std::int32_t>(nblocks) >= 0 ? nblocks + nblocks : nblocks + 0x10000000u;

		const std::uint32_t adjustedThreshold = thresholdBase - static_cast<std::uint32_t>(deadmem);
		globalState->GCthreshold = static_cast<lu_mem>(adjustedThreshold);
	}

	/**
	 * Address: 0x00915BF0 (FUN_00915BF0, markroot)
	 *
	 * What it does:
	 * Marks Lua GC roots for default metatable lanes, registry, and thread
	 * roots, then dispatches the optional engine GC callback hook.
	 */
	void markroot(GCState* const st, lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		global_State* const gcGlobals = st->g;

		if (globalState->_defaultmeta.tt >= LUA_TSTRING) {
			auto* const defaultMetaObject = static_cast<GCObject*>(globalState->_defaultmeta.value.p);
			if ((defaultMetaObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, defaultMetaObject);
			}
		}

		for (TObject& slot : globalState->_defaultmetatypes) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if ((object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}

		if (globalState->_registry.tt >= LUA_TSTRING) {
			auto* const registryObject = static_cast<GCObject*>(globalState->_registry.value.p);
			if ((registryObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, registryObject);
			}
		}

		traversestack(gcGlobals->mainthread, st);
		if (state != gcGlobals->mainthread && (state->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(state));
		}

		if (globalState->userGCFunction != nullptr) {
			st->L = gcGlobals->mainthread;
			globalState->userGCFunction(st);
		}
	}

	/**
	 * Address: 0x00915750 (FUN_00915750, propagatemarks)
	 *
	 * What it does:
	 * Drains the gray list by dispatching tables, closures, threads, and proto
	 * nodes through their specialized traversal lanes.
	 */
	extern "C" void propagatemarks(GCState* const st)
	{
		while (st->tmark != nullptr) {
			GCObject* const current = st->tmark;
			switch (current->gch.tt) {
			case LUA_TTABLE:
				st->tmark = current->h.gclist;
				traversetable(st, &current->h);
				break;

			case LUA_CFUNCTION:
				st->tmark = current->cl.c.gclist;
				traversecclosure(st, &current->cl.c);
				break;

			case LUA_TFUNCTION:
				st->tmark = current->cl.c.gclist;
				traverselclosure(st, &current->cl.l);
				break;

			case LUA_TTHREAD:
				st->tmark = current->th.gclist;
				traversestack(&current->th, st);
				if (current->th.l_G->userGCFunction != nullptr) {
					st->L = &current->th;
					current->th.l_G->userGCFunction(st);
				}
				break;

			case LUA_TPROTO:
				st->tmark = current->p.gclist;
				traverseproto(st, &current->p);
				break;

			default:
				break;
			}
		}
	}

	constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
	constexpr unsigned int kLuaOpcodeModeMask = 0x3u;
	constexpr unsigned int kLuaInstructionAFieldShift = 24u;
	constexpr unsigned int kLuaInstructionBFieldShift = 15u;
	constexpr unsigned int kLuaInstructionCFieldShift = 6u;
	constexpr unsigned int kLuaInstructionABxMask = 0x3FFFFu;
	constexpr unsigned int kLuaInstructionBOrCMask = 0x1FFu;
	constexpr int kLuaInstructionSignedBxBias = 0x1FFFF;

	constexpr unsigned char kLuaOpcodeModes[] = {
		0, 1, 0, 0, 0, 1, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
		0, 0, 2, 0, 2, 1, 1, 0, 1
	};

	constexpr const char* const kLuaOpcodeNames[] = {
		"MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL",
		"GETGLOBAL", "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE",
		"NEWTABLE", "SELF", "ADD", "SUB", "MUL",
		"DIV", "BAND", "BOR", "BSHL", "BSHR",
		"XOR", "UNM", "NOT", "CONCAT", "JMP",
		"EQ", "LT", "LE", "TEST", "CALL",
		"TAILCALL", "RETURN", "FORLOOP", "TFORLOOP", "TFORPREP",
		"SETLIST", "SETLISTO", "CLOSE", "CLOSURE"
	};
	static_assert(
		(sizeof(kLuaOpcodeModes) / sizeof(kLuaOpcodeModes[0]))
		== (sizeof(kLuaOpcodeNames) / sizeof(kLuaOpcodeNames[0])),
		"Lua opcode mode/name table sizes must match"
	);
	constexpr const char* kLuaDebugLevelOutOfRange = "level out of range";
	constexpr const char* kLuaDebugFunctionOrLevelExpected = "function or level expected";
	constexpr const char* kLuaDebugInvalidOption = "invalid option";

	/**
	 * Address: 0x009116B0 (FUN_009116B0, getinfo)
	 *
	 * What it does:
	 * Resolves debug info for either stack level arg-1 or function arg-1 and
	 * returns one table populated by requested option mask (`flnSu` by default).
	 */
	int LuaDebugGetInfo(lua_State* const state)
	{
		const char* optionMask = luaL_optlstring(state, 2, "flnSu", nullptr);
		::lua_Debug activationRecord{};

		if (lua_isnumber(state, 1) != 0) {
			const int level = static_cast<int>(lua_tonumber(state, 1));
			if (lua_getstack(state, level, &activationRecord) == 0) {
				lua_pushnil(state);
				return 1;
			}
		} else {
			const int firstArgumentType = lua_type(state, 1);
			if ((firstArgumentType | 1) != LUA_TFUNCTION) {
				luaL_argerror(state, 1, kLuaDebugFunctionOrLevelExpected);
			}

			lua_pushfstring(state, ">%s", optionMask);
			optionMask = lua_tostring(state, -1);
			lua_pushvalue(state, 1);
		}

		if (lua_getinfo(state, optionMask, &activationRecord) == 0) {
			return luaL_argerror(state, 2, kLuaDebugInvalidOption);
		}

		lua_newtable(state);
		for (const char* option = optionMask; *option != '\0'; ++option) {
			switch (*option) {
				case 'S':
					lua_pushstring(state, "source");
					lua_pushstring(state, activationRecord.source);
					lua_rawset(state, -3);

					lua_pushstring(state, "short_src");
					lua_pushstring(state, activationRecord.short_src);
					lua_rawset(state, -3);

					lua_pushstring(state, "linedefined");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.linedefined));
					lua_rawset(state, -3);

					lua_pushstring(state, "what");
					lua_pushstring(state, activationRecord.what);
					lua_rawset(state, -3);
					break;

				case 'f':
					lua_pushlstring(state, "func", 4);
					lua_pushvalue(state, -3);
					lua_rawset(state, -3);
					break;

				case 'l':
					lua_pushstring(state, "currentline");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.currentline));
					lua_rawset(state, -3);
					break;

				case 'n':
					lua_pushstring(state, "name");
					lua_pushstring(state, activationRecord.name);
					lua_rawset(state, -3);

					lua_pushstring(state, "namewhat");
					lua_pushstring(state, activationRecord.namewhat);
					lua_rawset(state, -3);
					break;

				case 'u':
					lua_pushstring(state, "nups");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.nups));
					lua_rawset(state, -3);
					break;

				default:
					break;
			}
		}

		return 1;
	}

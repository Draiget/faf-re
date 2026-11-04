// Part of LuaObject.cpp, included there: bytecode checks, runtime errors and calls (ldebug, ldo).

	[[nodiscard]] gpg::RRef BuildRefFromUserdata(Udata* const userdata)
	{
		gpg::RRef out{};
		out.mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
		out.mType = reinterpret_cast<gpg::RType*>(userdata->len);
		return out;
	}

	/**
	 * Address: 0x00912D30 (FUN_00912D30, kname)
	 *
	 * What it does:
	 * Resolves one proto constant-table slot name from a stack/register index
	 * by subtracting `MAXSTACK`; returns `"?"` when slot is out of range or not
	 * a Lua string constant.
	 */
	const char* kname(const int stackSlotIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		constexpr const char* kUnknownName = "?";

		const int constantIndex = stackSlotIndex - kLuaParserMaxStackSlots;
		if (constantIndex < 0 || proto == nullptr || proto->k == nullptr) {
			return kUnknownName;
		}

		const LuaPlus::TObject& constant = proto->k[constantIndex];
		if (constant.tt != LUA_TSTRING || constant.value.p == nullptr) {
			return kUnknownName;
		}

		return static_cast<const TString*>(constant.value.p)->str;
	}

	/**
	 * Address: 0x009127F0 (FUN_009127F0, travglobals)
	 *
	 * What it does:
	 * Scans the global table hash nodes for a value equal to `object` and
	 * returns the associated string-key name when found.
	 */
	const char* travglobals(lua_State* const state, const TObject* const object)
	{
		auto* const globalsTable = static_cast<Table*>(state->_gt.value.p);
		int remaining = 1 << globalsTable->lsizenode;
		if (remaining == 0) {
			return nullptr;
		}

		int nodeIndex = remaining;
		while (remaining > 0) {
			Node* const node = &globalsTable->node[--nodeIndex];
			--remaining;

			if (luaO_rawequalObj(object, &node->i_val) != 0 && node->KeyIs(LUA_TSTRING)) {
				return static_cast<const TString*>(node->KeyValue().p)->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x009128D0 (FUN_009128D0, checkopenop)
	 *
	 * What it does:
	 * Checks whether instruction `pc + 1` is an "open" opcode lane for
	 * symbolic execution (`OP_CALL`..`OP_RETURN` with open-result flag cleared,
	 * or `OP_SETLIST`).
	 */
	bool checkopenop(const Proto* const proto, const int pc)
	{
		constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
		constexpr unsigned int kLuaOpenOperandMask = 0x00FF8000u;
		constexpr unsigned int kOpCall = 0x1Du;
		constexpr unsigned int kOpReturn = 0x1Fu;
		constexpr unsigned int kOpSetList = 0x24u;

		const Instruction instruction = proto->code[pc + 1];
		const unsigned int opcode = static_cast<unsigned int>(instruction) & kLuaOpcodeMask;
		if (opcode >= kOpCall) {
			if (opcode <= kOpReturn) {
				return (static_cast<unsigned int>(instruction) & kLuaOpenOperandMask) == 0u;
			}

			if (opcode == kOpSetList) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Address: 0x00912530 (FUN_00912530, currentline)
	 *
	 * What it does:
	 * Returns one active source line for the current frame when `savedpc` maps
	 * into Lua bytecode; returns `-1` for non-Lua frames and `0` when lineinfo
	 * is absent.
	 */
	int currentline(CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		if (ci->state >= kCiSavedPc) {
			return -1;
		}

		const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
		const Proto* const proto = closure->l.p;
		const int instructionIndex = static_cast<int>(ci->savedpc - proto->code);
		if (instructionIndex < 0) {
			return -1;
		}

		if (proto->lineinfo != nullptr) {
			return proto->lineinfo[instructionIndex];
		}

		return 0;
	}

	/**
	 * Address: 0x00912910 (FUN_00912910, checkRK)
	 *
	 * What it does:
	 * Validates one RK operand lane against either register space
	 * (`< maxstacksize`) or constant-table space (`MAXSTACK + k`).
	 */
	bool checkRK(const int rkIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		return rkIndex < static_cast<int>(proto->maxstacksize)
			|| (rkIndex >= kLuaParserMaxStackSlots
				&& (rkIndex - kLuaParserMaxStackSlots) < proto->sizek);
	}

	/**
	 * Address: 0x00912E90 (FUN_00912E90, getfuncname)
	 *
	 * What it does:
	 * Resolves callee object-name metadata for call/tailcall opcodes in the
	 * previous Lua frame and returns the object-class string from `getobjname`.
	 */
	const char* getfuncname(const char** const nameOut, CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		constexpr int kOpCall = 29;
		constexpr int kOpTailCall = 30;

		if ((ci->state < kCiSavedPc && ci->tailcalls > 0) || (ci - 1)->state >= kCiSavedPc) {
			return nullptr;
		}

		CallInfo* const callerFrame = ci - 1;
		const auto* const callerClosure = static_cast<const Closure*>(callerFrame->base[-1].value.p);
		const Proto* const callerProto = callerClosure->l.p;

		int instructionIndex = -1;
		if (callerFrame->state < kCiSavedPc) {
			instructionIndex = static_cast<int>(callerFrame->savedpc - callerProto->code);
		}

		const Instruction instruction = callerProto->code[instructionIndex];
		const int opcode = static_cast<int>(instruction & 0x3Fu);
		if (opcode != kOpCall && opcode != kOpTailCall) {
			return nullptr;
		}

		return getobjname(static_cast<int>(instruction >> 24u), callerFrame, nameOut);
	}

	// ---- Lua 5.0 (LuaPlus 1081) bytecode instruction layout + opcode modes ----
	//
	// Field positions for the packed 32-bit Instruction word and the operand
	// range limits used by the symbolic executor below. Values match the
	// LuaPlus 1081 VM this build links.
	constexpr int kLuaMaxStack = 250;                 // MAXSTACK
	constexpr int kLuaNoReg = 255;                    // NO_REG (== MAXARG_A)
	constexpr unsigned kLuaMaxArgB = 0x1FFu;          // MAXARG_B / MAXARG_C
	constexpr unsigned kLuaMaxArgBx = 0x3FFFFu;       // MAXARG_Bx
	constexpr int kLuaMaxArgSBx = 0x1FFFF;            // MAXARG_sBx bias
	constexpr unsigned kLuaFieldsPerFlushM1 = 0x1Fu;  // LFIELDS_PER_FLUSH - 1
	constexpr unsigned kLuaOpJmp = 0x18u;             // OP_JMP opcode (24)
	constexpr unsigned kLuaOpReturn = 0x1Fu;          // OP_RETURN opcode (31)

	// Bits of a `luaP_opmodes` entry: (T<<7)|(A<<6)|(B<<4)|(C<<2)|opmode.
	enum LuaOpModeBits : unsigned char {
		kLuaOpModeMask = 0x03,   // low 2 bits: iABC=0 / iABx=1 / iAsBx=2
		kLuaOpModeBreg = 0x04,   // B is a register
		kLuaOpModeBrk  = 0x08,   // B is register-or-constant (RK)
		kLuaOpModeCrk  = 0x10,   // C is register-or-constant (RK)
		kLuaOpModeSetA = 0x20,   // instruction assigns register A
		kLuaOpModeK    = 0x40,   // Bx is a constant index
	};
	enum LuaOpMode : unsigned char { kLuaIABC = 0, kLuaIABx = 1, kLuaIAsBx = 2 };

	// luaP_opmodes[op] for LuaPlus 1081 — byte-verified from ForgedAlliance.exe
	// .rdata at VA 0x00D466F4. Do NOT edit; matches the shipped binary exactly.
	constexpr unsigned char kLuaOpModes[39] = {
		0x24, 0x61, 0x20, 0x24, 0x20, 0x61, 0x34, 0x41, 0x00, 0x18,
		0x20, 0x34, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
		0x38, 0x24, 0x24, 0x34, 0x02, 0x98, 0x98, 0x98, 0xA4, 0x00,
		0x00, 0x00, 0x02, 0x80, 0x02, 0x01, 0x01, 0x00, 0x21,
	};

	/**
	 * Address: 0x00912680 (FUN_00912680, lua_getlocal)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_getlocal(lua_State *L, const lua_Debug *ar, int n);
	 *
	 * What it does:
	 * Names local `n` of the frame `ar` refers to and, when it exists, pushes
	 * its current value. Returns null for C frames and out-of-range indices.
	 *
	 * The frame is `L->base_ci[ar->i_ci]`; 0x0091268C computes the index as
	 * `i_ci * 5` scaled by eight, which is the 0x28-byte CallInfo stride.
	 * `ci->state >= 3` is the C-frame test (0x00912698) and returns null
	 * immediately - a C frame has no Proto to name locals from. Otherwise the
	 * closure comes from `ci->base[-1]`, read as `[base - 4]` because the value
	 * word sits at +4 of an eight-byte TObject.
	 */
	extern "C" const char* lua_getlocal(lua_State* const state, const lua_Debug* const activationRecord, const int localIndex)
	{
		CallInfo* const frame = &state->base_ci[activationRecord->i_ci];
		if (frame->state >= 3) {
			return nullptr;
		}

		const auto* const closure = static_cast<const LClosure*>(frame->base[-1].value.p);
		Proto* const prototype = closure->p;
		if (prototype == nullptr) {
			return nullptr;
		}

		const int currentPc = static_cast<int>(frame->savedpc - prototype->code);
		const char* const localName = luaF_getlocalname(prototype, localIndex, currentPc);
		if (localName == nullptr) {
			return nullptr;
		}

		luaA_pushobject(state, &frame->base[localIndex - 1]);
		return localName;
	}

	/**
	 * Address: 0x009126F0 (FUN_009126F0, lua_setlocal)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_setlocal(lua_State *L, const lua_Debug *ar, int n);
	 *
	 * What it does:
	 * Pops the stack top into local `n` of the frame `ar` refers to and returns
	 * its name; returns null without storing when the local does not exist or is
	 * compiler-internal.
	 *
	 * Two details this fork gets right that a naive port would not. The pop at
	 * 0x0091271E happens **unconditionally**, before the name is even known, so
	 * the value is consumed whether or not the store lands - unlike
	 * `lua_setupvalue`, which pops only on success. And a name beginning with
	 * '(' (0x28, tested at 0x00912755) marks a compiler-internal local, which is
	 * reported as absent.
	 */
	extern "C" const char* lua_setlocal(lua_State* const state, const lua_Debug* const activationRecord, const int localIndex)
	{
		CallInfo* const frame = &state->base_ci[activationRecord->i_ci];

		Proto* prototype = nullptr;
		if (frame->state < 3) {
			prototype = static_cast<const LClosure*>(frame->base[-1].value.p)->p;
		}

		--state->top;

		if (prototype == nullptr) {
			return nullptr;
		}

		const int currentPc = (frame->state >= 3) ? -1 : static_cast<int>(frame->savedpc - prototype->code);
		const char* const localName = luaF_getlocalname(prototype, localIndex, currentPc);
		if (localName == nullptr || localName[0] == '(') {
			return nullptr;
		}

		frame->base[localIndex - 1] = *state->top;
		return localName;
	}

	/**
	 * Address: 0x00912940 (FUN_00912940, luaG_symbexec)
	 *
	 * IDA signature:
	 * Instruction __usercall luaG_symbexec@<eax>(const Proto *pt, int lastpc, int reg);
	 *
	 * What it does:
	 * Symbolically executes proto bytecode from pc 0 up to `lastpc`, validating
	 * every instruction's operands against the register window, constant table,
	 * upvalue count and nested-proto lanes, and returns the last instruction that
	 * assigned register `reg` (or 0 when `reg` is never written or the bytecode is
	 * malformed). File-local in the original ldebug.c; used by `getobjname` (name
	 * resolution) and `luaG_checkcode` (load-time verification).
	 *
	 * The exact early-return lattice and forward-jump tracking are preserved 1:1
	 * from the binary; a fully structured rewrite would obscure that lattice.
	 */
	Instruction luaG_symbexec(const Proto* const pt, const int lastpc, const int reg)
	{
		int last = pt->sizecode - 1;
		if (pt->maxstacksize > static_cast<unsigned char>(kLuaMaxStack)) {
			return 0;
		}
		if (pt->sizelineinfo != pt->sizecode && pt->sizelineinfo != 0) {
			return 0;
		}

		const Instruction* const code = pt->code;
		if ((code[pt->sizecode - 1] & 0x3Fu) != kLuaOpReturn) {
			return 0;
		}
		if (lastpc <= 0) {
			return code[last];
		}

		const int maxstack = pt->maxstacksize;
		int pc = 0;
		for (;;) {
			const Instruction instr = code[pc];
			const int op = static_cast<int>(instr & 0x3Fu);
			const int a = static_cast<int>((instr >> 24) & 0xFFu);
			int b = 0;
			int c = 0;
			if (a >= maxstack) {
				return 0;
			}

			const signed char mode = static_cast<signed char>(kLuaOpModes[op]);
			const int opmode = mode & kLuaOpModeMask;
			if (opmode == kLuaIABx) {
				b = static_cast<int>((instr >> 6) & kLuaMaxArgBx);
				if ((mode & kLuaOpModeK) != 0 && !(b < pt->sizek)) {
					return 0;
				}
			} else if (opmode == kLuaIAsBx) {
				b = static_cast<int>((instr >> 6) & kLuaMaxArgBx) - kLuaMaxArgSBx;
			} else {  // iABC: decode + validate B/C operands
				b = static_cast<int>((instr >> 15) & kLuaMaxArgB);
				c = static_cast<int>((instr >> 6) & kLuaMaxArgB);
				if ((mode & kLuaOpModeBreg) != 0) {
					if (b >= maxstack) {
						return 0;
					}
				} else if ((mode & kLuaOpModeBrk) != 0 && !checkRK(b, pt)) {
					return 0;
				}
				if ((mode & kLuaOpModeCrk) != 0 && c >= maxstack) {
					if (c < kLuaMaxStack) {
						return 0;
					}
					if (!((c - kLuaMaxStack) < pt->sizek)) {
						return 0;
					}
				}
			}

			if ((mode & kLuaOpModeSetA) != 0 && a == reg) {
				last = pc;
			}

			// A test operator must be immediately followed by an OP_JMP; any
			// other operator (mode >= 0, i.e. test bit clear) runs unconditionally.
			if (mode >= 0 ||
				(pc + 2 < pt->sizecode && (code[pc + 1] & 0x3Fu) == kLuaOpJmp)) {
				switch (op) {
				case 2:  // OP_LOADBOOL: skip-next requires a following instruction
					if (c != 0 && pc + 2 >= pt->sizecode) {
						return 0;
					}
					break;
				case 3:  // OP_LOADNIL: clears R(a..b)
					if (a <= reg && reg <= b) {
						last = pc;
					}
					break;
				case 4:  // OP_GETUPVAL
				case 8:  // OP_SETUPVAL
					if (b >= pt->nups) {
						return 0;
					}
					break;
				case 5:  // OP_GETGLOBAL
				case 7:  // OP_SETGLOBAL: Bx must name a string constant
					if (pt->k[b].tt != LUA_TSTRING) {
						return 0;
					}
					break;
				case 11:  // OP_SELF: writes R(a) and R(a+1)
					if (a + 1 >= maxstack) {
						return 0;
					}
					if (reg == a + 1) {
						last = pc;
					}
					break;
				case 23:  // OP_CONCAT: R(b..c)
					if (c >= kLuaMaxStack || b >= c) {
						return 0;
					}
					break;
				case 29:  // OP_CALL
				case 30:  // OP_TAILCALL
					if (b != 0 && b + a - 1 >= maxstack) {
						return 0;
					}
					if (--c == -1) {
						if (!checkopenop(pt, pc)) {
							return 0;
						}
					} else if (c != 0 && a + c - 1 >= maxstack) {
						return 0;
					}
					if (reg >= a) {
						last = pc;
					}
					break;
				case 31:  // OP_RETURN
					if (--b > 0 && b + a - 1 >= maxstack) {
						return 0;
					}
					break;
				case 35:  // OP_SETLIST
					if (static_cast<int>(b & kLuaFieldsPerFlushM1) + a + 1 >= maxstack) {
						return 0;
					}
					break;
				case 38:  // OP_CLOSURE: preceding MOVE/GETUPVAL pseudo-ops per upvalue
					if (b >= pt->sizep) {
						return 0;
					}
					{
						int upvalues = pt->p[b]->nups;
						if (upvalues + pc >= pt->sizecode) {
							return 0;
						}
						if (upvalues != 0) {
							const Instruction* pseudo = &code[upvalues + pc];
							for (;;) {
								const int pseudoOp = static_cast<int>(*pseudo & 0x3Fu);
								if (pseudoOp != 4 && pseudoOp != 0) {  // GETUPVAL / MOVE only
									return 0;
								}
								--upvalues;
								--pseudo;
								if (upvalues <= 0) {
									break;
								}
							}
						}
					}
					break;
				case 33:  // OP_TFORLOOP: writes control + loop vars, then falls to jump
					if (a + c + 5 >= maxstack) {
						return 0;
					}
					if (reg >= a) {
						last = pc;
					}
					[[fallthrough]];
				case 32:  // OP_FORLOOP: writes R(a+2), then falls to jump
					if (a + 2 >= maxstack) {
						return 0;
					}
					[[fallthrough]];
				case 24: {  // OP_JMP: validate/optionally follow the forward jump
					const int dest = b + pc + 1;
					if (dest < 0 || dest >= pt->sizecode) {
						return 0;
					}
					if (reg != kLuaNoReg && pc < dest && dest <= lastpc) {
						pc += b;
					}
					break;
				}
				default:
					break;
				}
			} else {
				return 0;
			}

			if (++pc >= lastpc) {
				return code[last];
			}
		}
	}

	/**
	 * Address: 0x00912D10 (FUN_00912D10, luaG_checkcode)
	 *
	 * IDA signature:
	 * int __cdecl luaG_checkcode(const Proto *pt);
	 *
	 * What it does:
	 * Validates a prototype's whole bytecode by symbolically executing it to the
	 * last instruction with no register of interest. Non-zero means the code
	 * verified.
	 *
	 * `pt->sizecode` is read from +0x2C and `NO_REG` is the literal 0xFF pushed
	 * at 0x00912D17 - the widest value a register operand can hold, so no real
	 * register ever matches it.
	 */
	extern "C" int luaG_checkcode(const Proto* const prototype)
	{
		return static_cast<int>(luaG_symbexec(prototype, prototype->sizecode, 0xFF));
	}

	/**
	 * Address: 0x00912D50 (FUN_00912D50, getobjname)
	 *
	 * IDA signature:
	 * const char* __usercall getobjname@<eax>(Instruction stackpos@<eax>, CallInfo *ci, const char **name);
	 *
	 * What it does:
	 * Resolves a human-readable name (and its kind: "local"/"upval"/"global"/
	 * "field"/"method") for the value in register `stackPos`, to enrich runtime
	 * error messages. First tries an active local name via `luaF_getlocalname`
	 * (skipping compiler-internal "(...)" names); otherwise symbolically executes
	 * the proto bytecode (`luaG_symbexec`) up to the current pc to find the
	 * producing opcode, following OP_MOVE chains to their source register.
	 */
	extern "C" const char* getobjname(int stackPos, CallInfo* const callInfo, const char** const nameOut)
	{
		constexpr int kCiSavedPc = 3;
		if (callInfo->state >= kCiSavedPc) {
			return nullptr;
		}

		for (;;) {
			const auto* const closure = static_cast<const Closure*>(callInfo->base[-1].value.p);
			const Proto* const proto = closure->l.p;
			const int instructionIndex = static_cast<int>(callInfo->savedpc - proto->code);

			// Prefer an active local-variable name. Compiler-internal locals begin
			// with '(' (e.g. "(for index)") and are skipped, matching the original.
			const char* const localName = luaF_getlocalname(proto, stackPos + 1, instructionIndex);
			*nameOut = localName;
			if (localName != nullptr && *localName != '(') {
				return "local";
			}

			// Otherwise symbolically execute up to this pc to find the instruction
			// that produced the value in register `stackPos`, and name it from that
			// opcode (global/field/method/upvalue) or follow a MOVE chain.
			const Instruction producer = luaG_symbexec(proto, instructionIndex, stackPos);
			switch (producer & 0x3Fu) {
			case 0:  // OP_MOVE: trace back to the source register, then re-resolve
				if (static_cast<int>((producer >> 15) & 0x1FFu) >=
					static_cast<int>((producer >> 24) & 0xFFu)) {
					return nullptr;
				}
				stackPos = static_cast<int>((producer >> 15) & 0x1FFu);
				if (callInfo->state >= kCiSavedPc) {
					return nullptr;
				}
				continue;
			case 4:  // OP_GETUPVAL
				*nameOut = proto->upvalues[(producer >> 15) & 0x1FFu]->str;
				return "upval";
			case 5:  // OP_GETGLOBAL
				*nameOut = static_cast<const TString*>(proto->k[(producer >> 6) & 0x3FFFFu].value.p)->str;
				return "global";
			case 6:  // OP_GETTABLE with a constant key
				*nameOut = kname(static_cast<int>((producer >> 6) & 0x1FFu), proto);
				return "field";
			case 11:  // OP_SELF (method-call sugar)
				*nameOut = kname(static_cast<int>((producer >> 6) & 0x1FFu), proto);
				return "method";
			default:
				return nullptr;
			}
		}
	}

	/**
	 * Address: 0x00912F30 (FUN_00912F30, addinfo)
	 *
	 * What it does:
	 * Prefixes one Lua error message with `chunk(line): ` when the active call
	 * frame is a Lua function and returns the formatted string lane.
	 */
	const char* addinfo(lua_State* const state, const char* const msg)
	{
		char buff[60]{};
		CallInfo* const ci = state->ci;
		if (ci->state < 3) {
			const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
			const Proto* const proto = closure->l.p;
			const int line = currentline(ci);
			luaO_chunkid(buff, proto->source->str, static_cast<int>(sizeof(buff)));
			return luaO_pushfstring(state, "%s(%d): %s", buff, line, msg);
		}

		return msg;
	}

	/**
	 * Address: 0x009133A0 (FUN_009133A0, luaG_typeerror)
	 *
	 * What it does:
	 * Resolves Lua operand provenance/name when possible and raises a typed
	 * operation error matching Lua's runtime wording.
	 */
	void luaG_typeerror(lua_State* const state, const TObject* const object, const char* const operation)
	{
		const char* const valueType = luaT_typenames[object->tt];
		CallInfo* const callInfo = state->ci;
		const char* objectName = nullptr;
		TObject* stackSlot = callInfo->base;
		const TObject* const stackTop = callInfo->top;

		while (stackSlot < stackTop) {
			if (stackSlot == object) {
				const int stackIndex = static_cast<int>(object - state->base);
				const char* const objectClass = getobjname(stackIndex, callInfo, &objectName);
				if (objectClass != nullptr) {
					luaG_runerror(
						state, "attempt to %s %s `%s' (a %s value)", operation, objectClass, objectName, valueType
					);
				}
				break;
			}
			++stackSlot;
		}

		luaG_runerror(state, "%s expected but got %s", operation, valueType);
	}

	/**
	 * Address: 0x00913420 (FUN_00913420, luaV_concat type-error helper)
	 *
	 * What it does:
	 * Selects the non-string operand lane from two concat candidates and raises
	 * `luaG_typeerror(..., "concatenate")`.
	 */
	[[noreturn]] void luaV_concat_raise_typeerror(
		lua_State* const state,
		TObject* const leftCandidate,
		TObject* const rightCandidate
	)
	{
		TObject* errorOperand = leftCandidate;
		if (leftCandidate != nullptr && leftCandidate->tt == LUA_TSTRING) {
			errorOperand = rightCandidate;
		}

		luaG_typeerror(state, errorOperand, "concatenate");
		std::abort();
	}

	/**
	 * Address: 0x00913440 (FUN_00913440, luaG_aritherror)
	 *
	 * What it does:
	 * Selects the non-numeric arithmetic operand (when present) and raises
	 * `luaG_typeerror(..., "perform arithmetic on")`.
	 */
	[[noreturn]] void luaG_aritherror(
		lua_State* const state,
		TObject* const leftOperand,
		TObject* const rightOperand
	)
	{
		TObject* errorOperand = leftOperand;
		if (leftOperand != nullptr && leftOperand->tt == LUA_TNUMBER) {
			errorOperand = rightOperand;
		}

		luaG_typeerror(state, errorOperand, "perform arithmetic on");
		std::abort();
	}

	/**
	 * Address: 0x00914240 (FUN_00914240, luaD_growCI)
	 *
	 * What it does:
	 * Doubles call-info capacity and raises runtime overflow errors for
	 * recursive error handling and post-growth stack-limit overrun.
	 */
	void luaD_growCI(lua_State* const state)
	{
		const std::uint16_t currentFrameCapacity = state->size_ci;
		if (currentFrameCapacity > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "error in Lua error handling");
		}

		luaD_reallocCI(state, static_cast<int>(currentFrameCapacity) * 2);
		if (state->size_ci > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "stack overflow");
		}
	}

	/**
	 * Address: 0x00914080 (FUN_00914080)
	 *
	 * What it does:
	 * Refreshes `stack_last` from the current stack allocation and clamps an
	 * oversized call-info arena back to `kLuaMaxCallInfoFrames` when active
	 * frames fit below that threshold.
	 */
	extern "C" TObject* luaD_refreshstacklimit(lua_State* const state)
	{
		TObject* const stackLast = &state->stack[state->stacksize - 1];
		state->stack_last = stackLast;

		if (state->size_ci > kLuaMaxCallInfoFrames) {
			const auto activeFrameCount = (state->ci - state->base_ci) + 1;
			if (activeFrameCount < static_cast<decltype(activeFrameCount)>(kLuaMaxCallInfoFrames)) {
				luaD_reallocCI(state, static_cast<int>(kLuaMaxCallInfoFrames));
			}
		}

		return stackLast;
	}

	/**
	 * Address: 0x00913850 (FUN_00913850, correctstack)
	 *
	 * What it does:
	 * Rebases stack-relative `top/base/callinfo/open-upvalue` pointers after one
	 * Lua stack reallocation from `oldStackBase` to `state->stack`.
	 */
	extern "C" void correctstack(lua_State* const state, TObject* const oldStackBase)
	{
		TObject* const newStackBase = state->stack;
		state->top = &newStackBase[state->top - oldStackBase];

		for (GCObject* openUpvalue = state->openupval; openUpvalue != nullptr; openUpvalue = openUpvalue->gch.next) {
			UpVal* const upvalue = &openUpvalue->uv;
			upvalue->v = &newStackBase[upvalue->v - oldStackBase];
		}

		for (CallInfo* frame = state->base_ci; frame <= state->ci; ++frame) {
			frame->top = &newStackBase[frame->top - oldStackBase];
			frame->base = &newStackBase[frame->base - oldStackBase];
		}

		state->base = state->ci->base;
	}

	/**
	 * Address: 0x00913990 (FUN_00913990, luaD_growstack)
	 *
	 * What it does:
	 * Reallocates Lua stack storage, grows by either `2x` or `n + EXTRA_STACK`,
	 * then rewrites stack-relative pointers through `correctstack`.
	 */
	extern "C" void luaD_growstack(lua_State* const state, const int n)
	{
		constexpr int kLuaExtraStackSlots = 5;
		const int currentStackSize = state->stacksize;
		TObject* const oldStackBase = state->stack;
		const int newStackSize =
			(n > currentStackSize) ? (currentStackSize + n + kLuaExtraStackSlots) : (currentStackSize * 2);
		TObject* const newStackBase = luaM_reallocvector<TObject>(
			state, oldStackBase, static_cast<lu_mem>(currentStackSize), static_cast<lu_mem>(newStackSize)
		);
		state->stack = newStackBase;
		state->stacksize = newStackSize;
		state->stack_last = &newStackBase[newStackSize - 6];
		correctstack(state, oldStackBase);
	}

	/**
	 * Address: 0x009292F0 (FUN_009292F0, callTM)
	 *
	 * What it does:
	 * Pushes one metamethod + three operands, performs a no-result Lua call,
	 * and preserves stack-growth behavior.
	 */
	void callTM(
		const TObject* const firstOperand,
		const TObject* const secondOperand,
		const TObject* const thirdOperand,
		lua_State* const state,
		const TObject* const metamethodFunction
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *firstOperand;
		top[2] = *secondOperand;
		top[3] = *thirdOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 32) {
			luaD_growstack(state, 4);
		}

		state->top += 4;
		(void)luaD_call(state, state->top - 4, 0);
	}

	/**
	 * Address: 0x009295A0 (FUN_009295A0, get_compTM)
	 *
	 * What it does:
	 * Resolves one comparison metamethod from both metatables and returns it
	 * only when both sides expose the same metamethod function.
	 */
	const TObject* get_compTM(
		Table* const leftMetatable,
		const int event,
		lua_State* const state,
		Table* const rightMetatable
	)
	{
		const lu_byte eventMask = static_cast<lu_byte>(1u << static_cast<unsigned int>(event));
		if ((leftMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const leftTagMethod = luaT_gettm(leftMetatable, event, state->l_G->tmname[event]);
		if (leftTagMethod == nullptr) {
			return nullptr;
		}

		if (leftMetatable == rightMetatable) {
			return leftTagMethod;
		}

		if ((rightMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const rightTagMethod = luaT_gettm(rightMetatable, event, state->l_G->tmname[event]);
		if (rightTagMethod == nullptr) {
			return nullptr;
		}

		return (luaO_rawequalObj(leftTagMethod, rightTagMethod) != 0) ? leftTagMethod : nullptr;
	}

	/**
	 * Address: 0x00929280 (FUN_00929280, callTMres)
	 *
	 * What it does:
	 * Pushes one metamethod function + two operands, executes one Lua call with
	 * a single expected result, then pops that result slot from the Lua stack.
	 */
	int callTMres(
		const TObject* const metamethodFunction,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		lua_State* const state
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *leftOperand;
		top[2] = *rightOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 24) {
			luaD_growstack(state, 3);
		}

		state->top += 3;
		const int callResult = luaD_call(state, state->top - 3, 1);
		--state->top;
		return callResult;
	}

	/**
	 * Address: 0x00929530 (FUN_00929530)
	 *
	 * What it does:
	 * Resolves one binary-operation metamethod across both operands, executes it
	 * when callable, and writes the result back to caller-selected stack slot.
	 */
	int call_binTM(
		lua_State* const state,
		const TObject* const firstOperand,
		const TObject* const secondOperand,
		StkId const resultSlot,
		const int event
	)
	{
		const auto resultStackOffset = resultSlot - state->stack;
		const TObject* metamethodFunction = luaT_gettmbyobj(state, firstOperand, event);
		if (metamethodFunction->tt == LUA_TNIL) {
			metamethodFunction = luaT_gettmbyobj(state, secondOperand, event);
		}

		if ((metamethodFunction->tt | 1) != 7) {
			return 0;
		}

		(void)callTMres(metamethodFunction, firstOperand, secondOperand, state);
		state->stack[resultStackOffset] = *state->top;
		return 1;
	}

	/**
	 * Address: 0x00929B90 (FUN_00929B90)
	 *
	 * What it does:
	 * Attempts one binary-arithmetic metamethod dispatch, then raises one
	 * arithmetic type error when no metamethod resolves.
	 */
	int CallBinTmOrRaiseArithmeticTypeError(
		const int event,
		TObject* const leftOperand,
		lua_State* const state,
		TObject* const rightOperand,
		const StkId resultSlot
	)
	{
		const int result = call_binTM(state, leftOperand, rightOperand, resultSlot, event);
		if (result == 0) {
			luaG_aritherror(state, leftOperand, rightOperand);
		}
		return result;
	}

	/**
	 * Address: 0x00929610 (FUN_00929610, call_orderTM)
	 *
	 * What it does:
	 * Resolves order metamethod on both operands, executes one shared metamethod
	 * call when both sides match, and returns Lua-truthiness of result.
	 */
	int call_orderTM(
		lua_State* const state,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		const int event
	)
	{
		const TObject* const rightMetamethod = luaT_gettmbyobj(state, rightOperand, event);
		if (rightMetamethod->tt == LUA_TNIL) {
			return -1;
		}

		const TObject* const leftMetamethod = luaT_gettmbyobj(state, leftOperand, event);
		if (luaO_rawequalObj(rightMetamethod, leftMetamethod) == 0) {
			return -1;
		}

		(void)callTMres(rightMetamethod, leftOperand, rightOperand, state);
		const TObject* const result = state->top;
		return (result->tt != LUA_TNIL && (result->tt != LUA_TBOOLEAN || result->value.b != 0)) ? 1 : 0;
	}

	/**
	 * Address: 0x00913AD0 (FUN_00913AD0, adjust_varargs)
	 *
	 * What it does:
	 * Pads missing fixed args with nil, collects extra args into one vararg
	 * table (`1..n` plus string key `"n"`), and pushes that table.
	 */
	void adjust_varargs(lua_State* const state, int fixedArgCount, StkId base)
	{
		int actualArgCount = static_cast<int>(state->top - base);
		if (actualArgCount < fixedArgCount) {
			int missingArgCount = fixedArgCount - actualArgCount;
			if ((state->stack_last - state->top) <= missingArgCount) {
				luaD_growstack(state, missingArgCount);
			}

			actualArgCount = fixedArgCount;
			while (missingArgCount-- > 0) {
				state->top->tt = LUA_TNIL;
				++state->top;
			}
		}

		actualArgCount -= fixedArgCount;
		Table* const varargTable = luaH_new(state, actualArgCount, 1);
		for (int index = 0; index < actualArgCount; ++index) {
			const TObject* const sourceSlot = state->top - actualArgCount + index;
			*luaH_setnum(state, varargTable, index + 1) = *sourceSlot;
		}

		TString* const internedCountKey = luaS_newlstr(state, "n", 1u);
		TObject keyN{};
		keyN.tt = static_cast<int>(internedCountKey->tt);
		keyN.value.p = internedCountKey;

		TObject* const countSlot = luaH_set(state, varargTable, &keyN);
		countSlot->tt = LUA_TNUMBER;
		countSlot->value.n = static_cast<float>(actualArgCount);

		state->top -= actualArgCount;
		state->top->tt = static_cast<int>(varargTable->tt);
		state->top->value.p = varargTable;

		if ((state->stack_last - state->top) <= 1) {
			const int currentStackSize = state->stacksize;
			TObject* const oldStackBase = state->stack;
			int newStackSize = currentStackSize * 2;
			if (currentStackSize < 1) {
				newStackSize = currentStackSize + 6;
			}

			TObject* const newStackBase = luaM_reallocvector<TObject>(
				state, oldStackBase, static_cast<lu_mem>(currentStackSize), static_cast<lu_mem>(newStackSize)
			);
			state->stack = newStackBase;
			state->stack_last = &newStackBase[newStackSize - 6];
			state->stacksize = newStackSize;
			correctstack(state, oldStackBase);
		}

		++state->top;
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
	 * Address: 0x00924020 (FUN_00924020, defaultFatalErrorFunc)
	 *
	 * What it does:
	 * Handles unrecoverable Lua VM fatal-error fallback by terminating the
	 * process with exit code `1`.
	 */
	[[noreturn]] void defaultFatalErrorFunc()
	{
		std::exit(1);
	}

	template <class TObjectType>
	[[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
	{
		if (slot == nullptr) {
			slot = gpg::LookupRType(typeid(TObjectType));
		}
		return slot;
	}

	gpg::RType* gLuaTObjectType = nullptr;
	gpg::RType* gWrapFileType = nullptr;

	struct WrapFile
	{
		std::FILE* stream;
		std::uint8_t closeEnabled;
		std::uint8_t reserved[3];
	};
	static_assert(sizeof(WrapFile) == 0x8, "WrapFile size must be 0x8");
	static_assert(offsetof(WrapFile, stream) == 0x0, "WrapFile::stream offset must be 0x0");
	static_assert(offsetof(WrapFile, closeEnabled) == 0x4, "WrapFile::closeEnabled offset must be 0x4");

	class WrapFileTypeInfo final : public gpg::RType
	{
	public:
		/**
		 * Address: 0x00917F80 (FUN_00917F80, WrapFileTypeInfo::WrapFileTypeInfo)
		 *
		 * What it does:
		 * Constructs the WrapFile runtime type descriptor and preregisters it
		 * with reflection registry using `typeid(WrapFile)`.
		 */
		WrapFileTypeInfo();

		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00917FE0 (FUN_00917FE0, WrapFileTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes WrapFile reflection size/callback lanes and finalizes the
		 * descriptor.
		 */
		void Init() override;
	};

	class TObjectTypeInfo final : public gpg::RType
	{
	public:
		/**
		 * Address: 0x00921EF0 (FUN_00921EF0, TObjectTypeInfo::TObjectTypeInfo)
		 *
		 * What it does:
		 * Constructs the TObject runtime type descriptor and preregisters it with
		 * reflection registry using `typeid(LuaPlus::TObject)`.
		 */
		TObjectTypeInfo();

		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00921F50 (FUN_00921F50, TObjectTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes TObject reflection size lane and finalizes the descriptor.
		 */
		void Init() override;
	};

	constexpr int kLuaRefUserdataTypeTag = LUA_TUSERDATA;
	constexpr int kLuaIoUpvalueEnvIndex = lua_upvalueindex(1);
	// The line-iterator closure carries three upvalues, and both places that
	// build it push them in the same order: the "FILE*" metatable first (held
	// only to keep it alive), then the file, then the close-on-eof flag. The
	// binary reads the file at -10003 and the flag at -10004, which is upvalues
	// 2 and 3 - reading them as 1 and 2 handed the metatable to
	// TryUpcast_WrapFile, and `for line in handle:lines()` threw BadRefCast
	// "can't convert null to WrapFile" on the first iteration.
	constexpr int kLuaIoReadlineFileUpvalueIndex = lua_upvalueindex(2);
	constexpr int kLuaIoReadlineCloseOnEofUpvalueIndex = lua_upvalueindex(3);
	constexpr std::size_t kLuaIoReadChunkSize = 0x200;
	constexpr const char* kLuaDebugHookRegistryKey = "h";
	constexpr const char* kLuaDebugExternalHookLabel = "external hook";
	constexpr const char* kLuaDebugPrompt = "lua_debug> ";
	constexpr const char* kLuaDebugContinueToken = "cont\n";
	constexpr int kLuaDebugInputBufferSize = 0xFC;
	constexpr int kLuaDebugReadLineLimit = 0xFA;
	constexpr int kLuaRegistryAllocationSizesKey = 3;
	constexpr const char* const kLuaDebugHookEventNames[] = {
		"call",
		"return",
		"line",
		"count",
		"tail return"
	};
	static_assert(
		(sizeof(kLuaDebugHookEventNames) / sizeof(kLuaDebugHookEventNames[0])) == 5,
		"kLuaDebugHookEventNames must match Lua hook event count"
	);

	/**
	 * Address: 0x0090CBB0 (FUN_0090CBB0, func_GetRRefFromUserdata)
	 *
	 * What it does:
	 * Reads one userdata stack lane, then materializes `{payload, rtype}` into
	 * a reflected `gpg::RRef`; non-userdata/out-of-range lanes return null ref.
	 */
	void GetRRefFromUserdata(gpg::RRef* const out, lua_State* const state, const int index)
	{
		if (out == nullptr) {
			return;
		}

		// The binary reads the slot itself rather than going through
		// lua_touserdata - `dest->mType = p->u.rtype` at +0x0C and
		// `dest->mObj = &p->th.l_G` at +0x10, which is the payload. Routing it
		// through lua_touserdata was worse than a detour: that function is not
		// defined anywhere in this tree, so it resolved to the prebuilt
		// LuaPlus copy, whose tag test is stock's LUA_TUSERDATA of 7 while this
		// fork numbers full userdata 8. It answered null for every reflected
		// object, and `handle:lines()` threw BadRefCast on the first call.
		const TObject* const object = luaA_indexAcceptable(state, index);
		if (object == nullptr || object->tt != kLuaRefUserdataTypeTag) {
			out->mObj = nullptr;
			out->mType = nullptr;
			return;
		}

		auto* const userdata = static_cast<Udata*>(object->value.p);
		out->mType = reinterpret_cast<gpg::RType*>(userdata->len);
		out->mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
	}

	bool IsWrapFileTypeName(const char* const typeName)
	{
		return typeName != nullptr && std::strstr(typeName, "WrapFile") != nullptr;
	}

	/**
	 * Address: 0x00917060 (FUN_00917060, gpg::RRef::TryUpcast_WrapFile)
	 *
	 * What it does:
	 * Validates reflected userdata carries one WrapFile-compatible type lane,
	 * then returns the wrapped file payload pointer; throws `BadRefCast` on
	 * mismatch to match runtime cast-failure behavior.
	 */
	WrapFile* TryUpcastWrapFile(gpg::RRef* const reference)
	{
		const char* sourceTypeName = "null";
		if (reference != nullptr && reference->mType != nullptr) {
			const char* const runtimeTypeName = reference->mType->GetName();
			sourceTypeName = runtimeTypeName != nullptr ? runtimeTypeName : "null";
		}

		if (reference == nullptr || reference->mObj == nullptr || !IsWrapFileTypeName(sourceTypeName)) {
			throw gpg::BadRefCast(nullptr, sourceTypeName, "WrapFile");
		}

		return static_cast<WrapFile*>(reference->mObj);
	}

	/**
	 * Address: 0x00917240 (FUN_00917240, aux_close)
	 *
	 * What it does:
	 * Closes one wrapped FILE lane only when close-enabled; prefers `_pclose`
	 * and falls back through `fclose` error path exactly as original control
	 * flow, then nulls the stored stream pointer.
	 */
	int AuxClose(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->closeEnabled == 0 || wrapFile->stream == nullptr) {
			return 0;
		}

		if (::_pclose(wrapFile->stream) == -1 && std::fclose(wrapFile->stream) != 0) {
			wrapFile->stream = nullptr;
			return 0;
		}

		wrapFile->stream = nullptr;
		return 1;
	}

	/**
	 * Address: 0x009172B0 (FUN_009172B0, lua::io_close)
	 *
	 * What it does:
	 * Resolves default `_output` file handle from io upvalue when arg-1 is
	 * missing, attempts wrapped close, and pushes Lua `(true)` or
	 * `(nil, strerror(errno), errno-number)` result lanes.
	 */
	int LuaIoClose(lua_State* const state)
	{
		if (lua_type(state, 1) == LUA_TNONE && lua_type(state, kLuaIoUpvalueEnvIndex) == LUA_TTABLE) {
			lua_pushstring(state, "_output");
			lua_rawget(state, kLuaIoUpvalueEnvIndex);
		}

		if (AuxClose(state)) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

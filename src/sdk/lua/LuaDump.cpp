#include "lua/LuaUndump.h"

#include <cstddef>

// The binary-chunk writer - upstream's `ldump.c`, and the exact mirror of the
// loader recovered in LuaObject.cpp. Every byte this file emits is read back
// by `LuaLoadChunkHeader` / `LuaLoadProtoObject` there, so the two must be
// read together: a change on one side is a format change on both.
//
// The whole family occupies one contiguous run, 0x00914850 through
// 0x00914E8B, wedged between a LuaError.cpp function at 0x00914780 and a
// LuaObject.cpp one at 0x00914E90. That island is what a separate translation
// unit looks like in the link order, which is why this is its own `.cpp`
// rather than more weight on LuaObject.cpp.
//
// Two divergences from the vendored LuaPlus Build 1081 `ldump.c` are visible
// in the disassembly and preserved here:
//
//   * the chunk header carries a **format** byte after the version byte
//     (`DumpByte(5)` then `DumpByte(1)` at 0x00914D1C / 0x00914D34), which
//     upstream 5.0 does not write. `LuaLoadChunkHeader` (LuaObject.cpp) reads
//     exactly those two bytes back and folds them into the 0x0501 it demands;
//   * there is no `DumpWString` and no `LUA_TWSTRING` case. The constant
//     dispatch at 0x00914B35 is a two-step compare chain - `sub eax,3` / `je`
//     then `sub eax,1` / `jne` - so only `LUA_TNUMBER` and `LUA_TSTRING` carry
//     a payload and every other tag falls through writing nothing.
//
// `lua_Number` is 4 bytes here (this fork builds with `LUA_NUMBER=float`),
// which the header self-test at 0x00914E1E confirms twice over: it declares
// `sizeof(lua_Number)` as 4 and then writes the probe value with a single
// `movss`.

namespace LuaPlus
{
	namespace
	{
		/**
		 * Everything the chunk writer threads through its sub-dumpers -
		 * upstream's `DumpState`, file-private in `ldump.c` there and here.
		 *
		 * `luaU_dump` (0x00914E50) builds one with `sub esp, 0xC` and three
		 * stores at +0x00/+0x04/+0x08, then hands its address to every
		 * sub-dumper in ESI; each reads `[esi]`, `[esi+4]` and `[esi+8]` as the
		 * thread, the sink callback and the sink's own context.
		 */
		struct DumpState
		{
			lua_State* state;      // +0x00  DumpState::L
			lua_Chunkwriter write; // +0x04  DumpState::write
			void* writerData;      // +0x08  DumpState::data
		};

		static_assert(offsetof(DumpState, state) == 0x00, "DumpState::state must be at +0x00");
		static_assert(offsetof(DumpState, write) == 0x04, "DumpState::write must be at +0x04");
		static_assert(offsetof(DumpState, writerData) == 0x08, "DumpState::writerData must be at +0x08");
		static_assert(sizeof(DumpState) == 0x0C, "DumpState size must be 0x0C");

		/// The four bytes every binary chunk opens with, and the same literal
		/// `LuaLoadSignature` (0x00928DE0) matches on the way back in. Lives at
		/// 0x00D45B84 in the image; `DumpHeader` pushes it with a length of 4
		/// set in EBX at 0x00914CFD.
		constexpr char kLuaChunkSignature[] = "\x1BLua";

		/// Version and format halves of the word `LuaLoadChunkHeader` rebuilds
		/// as `format | (version << 8)` and requires to equal 0x0501.
		constexpr int kLuaChunkVersion = 5;
		constexpr int kLuaChunkFormat = 1;

		/// Instruction field widths, checked byte for byte by the loader's
		/// `LuaTestTypeSize(6/8/9/9, ..., "OP"/"A"/"B"/"C")` calls.
		constexpr int kLuaInstructionSizeOp = 6;
		constexpr int kLuaInstructionSizeA = 8;
		constexpr int kLuaInstructionSizeB = 9;
		constexpr int kLuaInstructionSizeC = 9;

		/// Upstream's `TEST_NUMBER`: a multiple of pi big enough that a format
		/// mismatch cannot survive the round trip. Held at 0x00D45B80 and
		/// loaded with `movss` at 0x00914E1E; as a `float` it lands exactly on
		/// 31415926, which is the integer the loader compares against.
		constexpr lua_Number kLuaNumberFormatProbe = static_cast<lua_Number>(3.14159265358979323846e7);

		/**
		 * Upstream's `DumpBlock`. Inlined at every use in this build, so no
		 * `FUN_*` corresponds to it: each site loads `[esi]`, `[esi+4]` and
		 * `[esi+8]` and makes the indirect call itself.
		 *
		 * The sink's return value is discarded, exactly as the binary discards
		 * it - a writer that reports failure does not abort the dump, and
		 * `lua_dump` still reports success. `lua_unlock`/`lua_lock` bracket the
		 * call upstream and compile to nothing in this single-threaded build,
		 * which is why no lock traffic appears around the call sites.
		 */
		void LuaDumpBlock(const void* const block, const std::size_t size, DumpState* const dumpState)
		{
			(void)(*dumpState->write)(dumpState->state, block, size, dumpState->writerData);
		}

		/// Upstream's `DumpByte`; inlined everywhere (`push 1` plus a one-byte
		/// store into the scratch slot, e.g. 0x00914C09).
		void LuaDumpByte(const int value, DumpState* const dumpState)
		{
			const char byteValue = static_cast<char>(value);
			LuaDumpBlock(&byteValue, sizeof(byteValue), dumpState);
		}

		/// Upstream's `DumpInt`; inlined everywhere (`push 4` plus a dword
		/// store, e.g. 0x00914BEE).
		void LuaDumpInt(const int value, DumpState* const dumpState)
		{
			LuaDumpBlock(&value, sizeof(value), dumpState);
		}

		/// Upstream's `DumpSize`. Same four bytes as `LuaDumpInt` on this
		/// target, but kept distinct because the format declares `sizeof(int)`
		/// and `sizeof(size_t)` separately and the loader checks both.
		void LuaDumpSize(const std::size_t value, DumpState* const dumpState)
		{
			LuaDumpBlock(&value, sizeof(value), dumpState);
		}

		/// Upstream's `DumpNumber`; inlined as a `movss` into the scratch slot
		/// followed by a 4-byte block write (0x00914B5F, 0x00914E34).
		void LuaDumpNumber(const lua_Number value, DumpState* const dumpState)
		{
			LuaDumpBlock(&value, sizeof(value), dumpState);
		}

		/**
		 * Address: 0x00914850 (FUN_00914850, DumpString)
		 *
		 * IDA signature:
		 * void __usercall DumpString(TString *s@<eax>, DumpState *D@<esi>);
		 *
		 * What it does:
		 * Writes one interned string as a `size_t` byte count followed by that
		 * many bytes, the trailing NUL included; a null string writes a zero
		 * count and nothing else.
		 *
		 * Upstream also tests `getstr(s) == NULL`, and the binary does carry
		 * that test - `lea ebx,[eax+0x14]` / `test ebx,ebx` at 0x00914856 - but
		 * it can never fire. `str` is the object's flexible tail, so its
		 * address is the string's own address plus 0x14 and is null only when
		 * `s` is, which the preceding branch already caught. Writing it out
		 * would add a comparison the optimiser deletes and a warning nobody
		 * wants, so only the reachable half is spelled here.
		 */
		void LuaDumpString(const TString* const string, DumpState* const dumpState)
		{
			if (string == nullptr) {
				LuaDumpSize(0u, dumpState);
				return;
			}

			const std::size_t size = string->len + 1u; // the trailing NUL travels with it
			LuaDumpSize(size, dumpState);
			LuaDumpBlock(string->str, size, dumpState);
		}

		/**
		 * Address: 0x00914CAA (inlined into DumpFunction, FUN_00914BC0)
		 *
		 * What it does:
		 * Writes the bytecode stream: the instruction count, then that many
		 * 4-byte instructions verbatim.
		 *
		 * The binary has no out-of-line body for this one - `DumpFunction`
		 * inlines it, reading `sizecode` from +0x2C and `code` from +0x0C and
		 * folding `n * sizeof(Instruction)` into `add edx,edx` twice at
		 * 0x00914CD3.
		 */
		void LuaDumpCode(const Proto* const prototype, DumpState* const dumpState)
		{
			LuaDumpInt(prototype->sizecode, dumpState);
			LuaDumpBlock(
				prototype->code,
				static_cast<std::size_t>(prototype->sizecode) * sizeof(Instruction),
				dumpState
			);
		}

		/**
		 * Address: 0x009149F0 (DumpLines; also inlined at 0x00914C65)
		 *
		 * What it does:
		 * Writes the opcode-to-source-line map: the entry count, then that many
		 * 4-byte line numbers verbatim.
		 *
		 * This one the compiler emitted twice - an out-of-line body at
		 * 0x009149F0 taking the prototype in EDI, and an inlined copy inside
		 * `DumpFunction` at 0x00914C65. Both read `sizelineinfo` from +0x30 and
		 * `lineinfo` from +0x14, which is how the pair is told apart from
		 * `DumpCode`'s +0x2C/+0x0C.
		 */
		void LuaDumpLines(const Proto* const prototype, DumpState* const dumpState)
		{
			LuaDumpInt(prototype->sizelineinfo, dumpState);
			LuaDumpBlock(
				prototype->lineinfo,
				static_cast<std::size_t>(prototype->sizelineinfo) * sizeof(int),
				dumpState
			);
		}

		/**
		 * Address: 0x00914900 (FUN_00914900, DumpLocals)
		 *
		 * IDA signature:
		 * void __usercall DumpLocals(const Proto *f, DumpState *D@<esi>);
		 *
		 * What it does:
		 * Writes the local-variable debug table: the entry count, then each
		 * entry's name, first live pc and last live pc.
		 *
		 * `sizelocvars` comes from +0x38 and `locvars` from +0x18; the loop
		 * walks the array by adding 0xC per step (0x009149DB), which is the
		 * 12-byte `LocVar` stride. `DumpString` is inlined into the loop here
		 * rather than called.
		 */
		void LuaDumpLocals(const Proto* const prototype, DumpState* const dumpState)
		{
			const int count = prototype->sizelocvars;
			LuaDumpInt(count, dumpState);

			for (int index = 0; index < count; ++index) {
				const LocVar& local = prototype->locvars[index];
				LuaDumpString(local.varname, dumpState);
				LuaDumpInt(local.startpc, dumpState);
				LuaDumpInt(local.endpc, dumpState);
			}
		}

		/**
		 * Address: 0x00914A30 (FUN_00914A30, DumpUpvalues)
		 *
		 * IDA signature:
		 * void __usercall DumpUpvalues(const Proto *f, DumpState *D@<esi>);
		 *
		 * What it does:
		 * Writes the upvalue debug names: the count, then one string each.
		 *
		 * `sizeupvalues` comes from +0x24 and `upvalues` from +0x1C, indexed
		 * `[eax + ebp*4]` at 0x00914A68 for the pointer array. `DumpString` is
		 * inlined into the loop, same as in `DumpLocals`.
		 */
		void LuaDumpUpvalues(const Proto* const prototype, DumpState* const dumpState)
		{
			const int count = prototype->sizeupvalues;
			LuaDumpInt(count, dumpState);

			for (int index = 0; index < count; ++index) {
				LuaDumpString(prototype->upvalues[index], dumpState);
			}
		}

		void LuaDumpProtoObject(const Proto* prototype, const TString* parentSource, DumpState* dumpState);

		/**
		 * Address: 0x00914AE0 (FUN_00914AE0, DumpConstants)
		 *
		 * IDA signature:
		 * void __usercall DumpConstants(const Proto *f@<ebx>, DumpState *D@<eax>);
		 *
		 * What it does:
		 * Writes the constant pool - a tag byte per entry followed by its
		 * payload - and then, recursively, every prototype defined inside this
		 * one.
		 *
		 * `sizek` comes from +0x28 and `k` from +0x08, stepped `[ecx + ebp*8]`
		 * at 0x00914B16 for the 8-byte `TObject` stride; `sizep` from +0x34 and
		 * `p` from +0x10. Only two tags carry a payload: the dispatch at
		 * 0x00914B35 subtracts 3 and takes the number branch, then subtracts 1
		 * more and takes the string branch, so `LUA_TNUMBER` (3) writes four
		 * bytes of `float` and `LUA_TSTRING` (4) writes a string. Everything
		 * else - nil above all - is its tag byte and nothing more. The vendored
		 * `ldump.c` has a `LUA_TWSTRING` case here; this build does not.
		 */
		void LuaDumpConstants(const Proto* const prototype, DumpState* const dumpState)
		{
			const int constantCount = prototype->sizek;
			LuaDumpInt(constantCount, dumpState);

			for (int index = 0; index < constantCount; ++index) {
				const TObject& constant = prototype->k[index];
				LuaDumpByte(constant.tt, dumpState);
				switch (constant.tt) {
				case LUA_TNUMBER:
					LuaDumpNumber(constant.value.n, dumpState);
					break;
				case LUA_TSTRING:
					LuaDumpString(static_cast<const TString*>(constant.value.p), dumpState);
					break;
				default:
					break;
				}
			}

			const int nestedCount = prototype->sizep;
			LuaDumpInt(nestedCount, dumpState);

			for (int index = 0; index < nestedCount; ++index) {
				LuaDumpProtoObject(prototype->p[index], prototype->source, dumpState);
			}
		}

		/**
		 * Address: 0x00914BC0 (FUN_00914BC0, DumpFunction)
		 *
		 * IDA signature:
		 * void __cdecl DumpFunction(const Proto *f, const TString *p, DumpState *D);
		 *
		 * What it does:
		 * Writes one prototype whole: its chunk name, the line it was defined
		 * on, its four byte-sized counts, then the line map, locals, upvalue
		 * names, constants (which recurse into nested prototypes) and finally
		 * the bytecode.
		 *
		 * `parentSource` is what makes nested prototypes cheap: a child that
		 * came from the same chunk as its parent writes a null name instead of
		 * repeating it, and `LuaLoadProtoObject` substitutes the parent's on
		 * the way back. The binary computes that branchlessly at 0x00914BCA -
		 * `sub` / `neg` / `sbb` / `and` turns "are these the same pointer" into
		 * the mask it ANDs over `f->source`.
		 *
		 * Field offsets read here: source +0x20, lineDefined +0x3C, nups +0x44,
		 * numparams +0x45, is_vararg +0x46, maxstacksize +0x47.
		 */
		void LuaDumpProtoObject(
			const Proto* const prototype,
			const TString* const parentSource,
			DumpState* const dumpState
		)
		{
			LuaDumpString((prototype->source == parentSource) ? nullptr : prototype->source, dumpState);
			LuaDumpInt(prototype->lineDefined, dumpState);
			LuaDumpByte(prototype->nups, dumpState);
			LuaDumpByte(prototype->numparams, dumpState);
			LuaDumpByte(prototype->is_vararg, dumpState);
			LuaDumpByte(prototype->maxstacksize, dumpState);
			LuaDumpLines(prototype, dumpState);
			LuaDumpLocals(prototype, dumpState);
			LuaDumpUpvalues(prototype, dumpState);
			LuaDumpConstants(prototype, dumpState);
			LuaDumpCode(prototype, dumpState);
		}

		/**
		 * Address: 0x00914CF0 (FUN_00914CF0, DumpHeader)
		 *
		 * IDA signature:
		 * void __usercall DumpHeader(DumpState *D@<esi>);
		 *
		 * What it does:
		 * Writes the twelve-field chunk header: signature, version, format,
		 * endianness, the sizes of `int`, `size_t` and `Instruction`, the four
		 * instruction field widths, the size of `lua_Number`, and a probe value
		 * in that number format.
		 *
		 * `LuaLoadChunkHeader` (LuaObject.cpp, 0x00928ED0) reads this back
		 * field for field in the same order and rejects any disagreement, so
		 * the two functions are one specification written twice. EBX is pinned
		 * to 4 at 0x00914CFD and reused for the signature length and every
		 * 4-byte size byte.
		 */
		void LuaDumpChunkHeader(DumpState* const dumpState)
		{
			LuaDumpBlock(kLuaChunkSignature, sizeof(kLuaChunkSignature) - 1u, dumpState);
			LuaDumpByte(kLuaChunkVersion, dumpState);
			LuaDumpByte(kLuaChunkFormat, dumpState);
			LuaDumpByte(luaU_endianness(), dumpState);
			LuaDumpByte(static_cast<int>(sizeof(int)), dumpState);
			LuaDumpByte(static_cast<int>(sizeof(std::size_t)), dumpState);
			LuaDumpByte(static_cast<int>(sizeof(Instruction)), dumpState);
			LuaDumpByte(kLuaInstructionSizeOp, dumpState);
			LuaDumpByte(kLuaInstructionSizeA, dumpState);
			LuaDumpByte(kLuaInstructionSizeB, dumpState);
			LuaDumpByte(kLuaInstructionSizeC, dumpState);
			LuaDumpByte(static_cast<int>(sizeof(lua_Number)), dumpState);
			LuaDumpNumber(kLuaNumberFormatProbe, dumpState);
		}
	}

	/**
	 * Address: 0x00914E50 (FUN_00914E50, luaU_dump)
	 *
	 * IDA signature:
	 * void __cdecl luaU_dump(lua_State *L, const Proto *Main, lua_Chunkwriter w, void *data);
	 *
	 * What it does:
	 * Dumps one compiled chunk: the header, then the main prototype and
	 * everything nested inside it. The main prototype is written with a null
	 * parent chunk name, so its own name is always spelled out in full.
	 *
	 * Reports nothing. A sink that fails is not detected here and not detected
	 * by `lua_dump` either - the caller learns about a bad write from its own
	 * sink, which is how `LS_dump` (0x0090AFB0) and `str_dump` (0x00924FD0)
	 * both behave.
	 */
	void luaU_dump(
		lua_State* const state,
		const Proto* const mainPrototype,
		const lua_Chunkwriter writer,
		void* const writerData
	)
	{
		DumpState dumpState{};
		dumpState.state = state;
		dumpState.write = writer;
		dumpState.writerData = writerData;

		LuaDumpChunkHeader(&dumpState);
		LuaDumpProtoObject(mainPrototype, nullptr, &dumpState);
	}
}

#pragma once

#include <cstddef>
#include <cstdint>

#include "lua/LuaRuntimeTypes.h"

/**
 * Lua 5.0 parser and code-generator state, as this fork ships it.
 *
 * These are the structures `lparser.h` and `llex.h` declare upstream. They
 * are plain C aggregates at global scope, shared by the lexer (`luaX_*`), the
 * parser (`luaY_*`) and the code generator (`luaK_*`), whose bodies are split
 * across `LuaParser.cpp` and `LuaObject.cpp` in this tree - so the definition
 * has to be visible to both, and there has to be exactly one of it.
 *
 * Every offset below is asserted, and the ones the code generator actually
 * touches were read out of the shipped image rather than taken from upstream:
 *
 *   FuncState::f          +0x00  `mov esi, [ebx]`            (0x0091AE92, indexupvalue)
 *   FuncState::h          +0x04  `mov eax, [esi+4]`          (0x00910400, addk; -> luaH_get)
 *   FuncState::ls         +0x0C  `mov eax, [ebx+0xC]`        (0x0091AEC1, -> luaX_checklimit)
 *   FuncState::L          +0x10  `mov ecx, [ebx+0x10]`       (0x0091AEF8, -> luaM_growaux)
 *   FuncState::freereg    +0x24  `mov ebx, [esi+0x24]`       (0x00910A85, discharge2anyreg)
 *   FuncState::nk         +0x28  `mov ecx, [esi+0x28]`       (0x0091041E, addk)
 *   FuncState::upvalues   +0x38  `mov [ebx+edx*4+0x38], ecx` (0x0091AF23, indexupvalue)
 *   LexState::lastline    +0x08  `mov ecx, [eax+8]`          (0x009109D0, discharge2reg)
 *
 * `upvalues` stride is 0x14: indexupvalue walks it with `add ecx, 0x14`
 * (0x0091AEBA) and indexes it with `lea edx, [eax+eax*4]` / `[ebx+edx*4+0x38]`
 * - i.e. `index * 5 * 4`. The same site copies a whole `expdesc` as five
 * consecutive dwords (0x0091AF23..0x0091AF40), which fixes `expdesc` at 0x14
 * with `k`/`info` first.
 *
 * The remaining `FuncState` fields (`prev`, `bl`, `pc`, `lasttarget`, `jpc`,
 * `np`, `nlocvars`, `nactvar`, `actvar`) keep their upstream order; the total
 * closes exactly on the observed 0x5D8, which leaves them no room to move:
 * 0x38 + 32*0x14 = 0x2B8, and 0x2B8 + 200*4 = 0x5D8.
 */

/// Locals per function (upstream `MAXVARS`). Sets `FuncState::actvar`.
constexpr std::int32_t MAXVARS = 0xC8;

/// Upvalues per closure (upstream `MAXUPVALUES`). Sets `FuncState::upvalues`.
/// `indexupvalue` passes this same 0x20 to `luaX_checklimit` (`push 0x20`,
/// 0x0091AEC9).
constexpr std::int32_t MAXUPVALUES = 0x20;

/// Empty jump list / "no jump" sentinel (upstream `NO_JUMP`).
constexpr std::int32_t NO_JUMP = -1;

struct FuncState;
struct LexState;

/**
 * How an `expdesc` currently holds its value, and what `info`/`aux` mean.
 *
 * Stock Lua 5.0 numbering, unchanged by the fork - confirmed against the
 * code generator: `discharge2reg` (0x00910970) switches on `k-1` over a
 * 0..10 jump table and stamps `VNONRELOC` as the literal 0xB
 * (`mov dword ptr [ebx], 0xb`), and `discharge2anyreg` (0x00910A75) tests
 * `cmp dword ptr [ebp], 0xb` for the already-in-a-register case.
 */
enum expkind : std::int32_t
{
	VVOID = 0x00,      ///< no value
	VNIL = 0x01,       ///< the nil constant
	VTRUE = 0x02,      ///< the true constant
	VFALSE = 0x03,     ///< the false constant
	VK = 0x04,         ///< info = index of the constant in `f->k`
	VLOCAL = 0x05,     ///< info = local register
	VUPVAL = 0x06,     ///< info = index into `FuncState::upvalues`
	VGLOBAL = 0x07,    ///< info = table register; aux = index of the name in `f->k`
	VINDEXED = 0x08,   ///< info = table register; aux = index register (or constant)
	VJMP = 0x09,       ///< info = pc of the jump instruction
	VRELOCABLE = 0x0A, ///< info = pc of an instruction whose target register is unset
	VNONRELOC = 0x0B,  ///< info = the register already holding the value
	VCALL = 0x0C       ///< info = the register holding the call's first result
};

/**
 * One expression under construction, plus its two pending patch lists.
 *
 * `t` and `f` chain the jumps that leave the expression when it tests true or
 * false; both are `NO_JUMP` until a short-circuit operator links them.
 */
struct expdesc
{
	expkind k;          // +0x00
	std::int32_t info;  // +0x04
	std::int32_t aux;   // +0x08
	std::int32_t t;     // +0x0C patch list of `exit when true'
	std::int32_t f;     // +0x10 patch list of `exit when false'
};

static_assert(offsetof(expdesc, k) == 0x00, "expdesc::k offset must be 0x00");
static_assert(offsetof(expdesc, info) == 0x04, "expdesc::info offset must be 0x04");
static_assert(offsetof(expdesc, aux) == 0x08, "expdesc::aux offset must be 0x08");
static_assert(offsetof(expdesc, t) == 0x0C, "expdesc::t offset must be 0x0C");
static_assert(offsetof(expdesc, f) == 0x10, "expdesc::f offset must be 0x10");
static_assert(sizeof(expdesc) == 0x14, "expdesc size must be 0x14");

/**
 * One lexical block (loop or `do` body) on the parser's block chain.
 *
 * The fork adds `continuelist` beside stock's `breaklist`, which is why this
 * is 0x18 rather than upstream's 0x14.
 */
struct BlockCnt
{
	BlockCnt* previous;        // +0x00 enclosing block
	std::int32_t breaklist;    // +0x04 jumps out of this loop
	std::int32_t continuelist; // +0x08 jumps back to this loop's step
	std::int32_t nactvar;      // +0x0C actives outside the block
	std::int32_t upval;        // +0x10 some local here is used as an upvalue
	std::int32_t isbreakable;  // +0x14 block is a loop
};

static_assert(offsetof(BlockCnt, previous) == 0x00, "BlockCnt::previous offset must be 0x00");
static_assert(offsetof(BlockCnt, breaklist) == 0x04, "BlockCnt::breaklist offset must be 0x04");
static_assert(offsetof(BlockCnt, continuelist) == 0x08, "BlockCnt::continuelist offset must be 0x08");
static_assert(offsetof(BlockCnt, nactvar) == 0x0C, "BlockCnt::nactvar offset must be 0x0C");
static_assert(offsetof(BlockCnt, upval) == 0x10, "BlockCnt::upval offset must be 0x10");
static_assert(offsetof(BlockCnt, isbreakable) == 0x14, "BlockCnt::isbreakable offset must be 0x14");
static_assert(sizeof(BlockCnt) == 0x18, "BlockCnt size must be 0x18");

/// Semantic payload of a token: a number literal, or an interned string.
union SemInfo
{
	float r;
	TString* ts;
};

/// One lookahead-able token: its kind, plus whichever payload that kind carries.
struct Token
{
	std::int32_t token;  // +0x00
	SemInfo seminfo;     // +0x04
};

static_assert(offsetof(Token, token) == 0x00, "Token::token offset must be 0x00");
static_assert(offsetof(Token, seminfo) == 0x04, "Token::seminfo offset must be 0x04");
static_assert(sizeof(Token) == 0x08, "Token size must be 0x08");

/**
 * Lexer state: the character stream, the current and lookahead tokens, and
 * the back-pointer to the function currently being compiled.
 *
 * `z` is the `ZIO` the chunk is being read from and `buff` the `Mbuffer` the
 * lexer accumulates a token's text in. Both stay `void*` here because the
 * `luaX_*` bodies in `LuaParser.cpp` pass them straight through to the
 * reader helpers without ever dereferencing them at this type.
 */
struct LexState
{
	std::int32_t current;    // +0x00 current character
	std::int32_t linenumber; // +0x04 input line counter
	std::int32_t lastline;   // +0x08 line of the last token consumed
	Token t;                 // +0x0C current token
	Token lookahead;         // +0x14 lookahead token
	FuncState* fs;           // +0x1C function currently being compiled
	lua_State* L;            // +0x20
	void* z;                 // +0x24 input stream (ZIO)
	void* buff;              // +0x28 token-text accumulator (Mbuffer)
	TString* source;         // +0x2C chunk name, for error messages
	std::int32_t nestlevel;  // +0x30 nested non-terminal depth
};

static_assert(offsetof(LexState, current) == 0x00, "LexState::current offset must be 0x00");
static_assert(offsetof(LexState, linenumber) == 0x04, "LexState::linenumber offset must be 0x04");
static_assert(offsetof(LexState, lastline) == 0x08, "LexState::lastline offset must be 0x08");
static_assert(offsetof(LexState, t) == 0x0C, "LexState::t offset must be 0x0C");
static_assert(offsetof(LexState, lookahead) == 0x14, "LexState::lookahead offset must be 0x14");
static_assert(offsetof(LexState, fs) == 0x1C, "LexState::fs offset must be 0x1C");
static_assert(offsetof(LexState, L) == 0x20, "LexState::L offset must be 0x20");
static_assert(offsetof(LexState, z) == 0x24, "LexState::z offset must be 0x24");
static_assert(offsetof(LexState, buff) == 0x28, "LexState::buff offset must be 0x28");
static_assert(offsetof(LexState, source) == 0x2C, "LexState::source offset must be 0x2C");
static_assert(offsetof(LexState, nestlevel) == 0x30, "LexState::nestlevel offset must be 0x30");
static_assert(sizeof(LexState) == 0x34, "LexState size must be 0x34");

/**
 * Everything needed to generate code for one function body.
 *
 * `h` is the reverse index into `f->k`: it maps a constant back to the slot
 * already holding it, so `addk` (0x00910400) can reuse it instead of
 * appending a duplicate. `freereg` is the first register not currently
 * holding a live value, and `nk`/`np`/`nlocvars` are the live counts for the
 * `Proto` arrays that `luaM_growaux` grows in place.
 */
struct FuncState
{
	Proto* f;                      // +0x00   current function header
	Table* h;                      // +0x04   constant -> index of it in `f->k'
	FuncState* prev;               // +0x08   enclosing function
	LexState* ls;                  // +0x0C   lexical state
	lua_State* L;                  // +0x10   copy of the Lua state
	BlockCnt* bl;                  // +0x14   chain of current blocks
	std::int32_t pc;               // +0x18   next position to code
	std::int32_t lasttarget;       // +0x1C   `pc' of last `jump target'
	std::int32_t jpc;              // +0x20   list of pending jumps to `pc'
	std::int32_t freereg;          // +0x24   first free register
	std::int32_t nk;               // +0x28   number of elements in `f->k'
	std::int32_t np;               // +0x2C   number of elements in `f->p'
	std::int32_t nlocvars;         // +0x30   number of elements in `f->locvars'
	std::int32_t nactvar;          // +0x34   number of active local variables
	expdesc upvalues[MAXUPVALUES]; // +0x38   upvalues
	std::int32_t actvar[MAXVARS];  // +0x2B8  declared-variable stack
};

static_assert(offsetof(FuncState, f) == 0x00, "FuncState::f offset must be 0x00");
static_assert(offsetof(FuncState, h) == 0x04, "FuncState::h offset must be 0x04");
static_assert(offsetof(FuncState, prev) == 0x08, "FuncState::prev offset must be 0x08");
static_assert(offsetof(FuncState, ls) == 0x0C, "FuncState::ls offset must be 0x0C");
static_assert(offsetof(FuncState, L) == 0x10, "FuncState::L offset must be 0x10");
static_assert(offsetof(FuncState, bl) == 0x14, "FuncState::bl offset must be 0x14");
static_assert(offsetof(FuncState, pc) == 0x18, "FuncState::pc offset must be 0x18");
static_assert(offsetof(FuncState, lasttarget) == 0x1C, "FuncState::lasttarget offset must be 0x1C");
static_assert(offsetof(FuncState, jpc) == 0x20, "FuncState::jpc offset must be 0x20");
static_assert(offsetof(FuncState, freereg) == 0x24, "FuncState::freereg offset must be 0x24");
static_assert(offsetof(FuncState, nk) == 0x28, "FuncState::nk offset must be 0x28");
static_assert(offsetof(FuncState, np) == 0x2C, "FuncState::np offset must be 0x2C");
static_assert(offsetof(FuncState, nlocvars) == 0x30, "FuncState::nlocvars offset must be 0x30");
static_assert(offsetof(FuncState, nactvar) == 0x34, "FuncState::nactvar offset must be 0x34");
static_assert(offsetof(FuncState, upvalues) == 0x38, "FuncState::upvalues offset must be 0x38");
static_assert(offsetof(FuncState, actvar) == 0x2B8, "FuncState::actvar offset must be 0x2B8");
static_assert(sizeof(FuncState) == 0x5D8, "FuncState size must be 0x5D8");

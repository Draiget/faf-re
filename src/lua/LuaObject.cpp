#include "LuaObject.h"
#include "legacy/math/X87Math.h"
#include <Windows.h>
#include <array>
#include <unordered_set>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <xmmintrin.h>
#include <bit>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <clocale>
#include <cstddef>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <io.h>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>

#include "LuaAssertion.h"
#include "LuaCallGate.h"
#include "LuaCrashDump.h"
#include "LuaError.h"
#include "LuaGcEventLog.h"
#include "LuaIncrementalGc.h"
#include "LuaMemAccounting.h"
#include "LuaNumberText.h"
#include "gpg/core/diagnostics/ProbeWatch.h"
#include "gpg/core/profiling/ProfileNames.h"
#include "gpg/core/profiling/Profiler.h"
#include "LuaParser.h"
#include "LuaTableIterator.h"
#include "LuaUndump.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimBlockLane.h"
#include "moho/sim/SimThreadRole.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/console/CConCommand.h"

using namespace LuaPlus;

extern "C" int luaG_checkcode(const Proto* f);

/**
 * Legacy CRT `_iob[]` global array shim.
 *
 * The old MSVCRT exported `_iob` as `FILE _iob[_IOB_ENTRIES]` via
 * `__imp___iob`. UCRT removed the global in favor of `__acrt_iob_func()`,
 * but third-party .lib files compiled against the old CRT (e.g. LuaPlus's
 * `lauxlib.obj`, `lbaselib.obj`, `liolib.obj`) still reference
 * `__imp___iob`. Provide a private backing array so the link resolves; the
 * streams are not functional — callers that actually use them will route
 * through `__iob_func()` above which dispatches to UCRT at runtime.
 */
#if defined(_DLL)
// Linked statically (/MT), the CRT's own _file.obj defines `_iob`.
extern "C" __declspec(selectany) std::FILE _iob[20]{};
#endif

/**
 * Address: 0x00A89E54 (legacy CRT compat thunk)
 *
 * What it does:
 * Returns the base of the legacy `_iob[]` array. On UCRT, dispatches to
 * `__acrt_iob_func(0)` from `ucrtbase.dll` (the modern replacement) and
 * falls back to a static placeholder array if the symbol is unavailable.
 * Provided here because UCRT does not export `__iob_func` directly.
 */
extern "C" std::FILE* __cdecl __iob_func(
  void
)
{
  using AcrtIobFunc = std::FILE*(__cdecl*)(unsigned int);
  static AcrtIobFunc sAcrtIobFunc = []() noexcept -> AcrtIobFunc {
    HMODULE const ucrtModule = ::GetModuleHandleA("ucrtbase.dll");
    if (ucrtModule == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<AcrtIobFunc>(reinterpret_cast<void (*)()>(::GetProcAddress(ucrtModule, "__acrt_iob_func")));
  }();

  if (sAcrtIobFunc != nullptr) {
    return sAcrtIobFunc(0u);
  }

  static std::FILE sLegacyIobFallback[20]{};
  return sLegacyIobFallback;
}

// FUN_00923F20 / FUN_00923F40 are recovered once, further down this file, as
// the `extern "C"` pair that `luaHelper_Realloc` / `luaHelper_Free` point at.
// A second copy used to live here with the same two addresses and the wrong
// allocator - `std::realloc` and the CRT's `_free_crt` rather than the
// engine's `realloc_0` / `free_crt`. It was unreferenced, but it is exactly
// the pairing Global.cpp warns about, so it is gone rather than dormant.

gpg::RType* Table::sType = nullptr;
gpg::RType* Proto::sType = nullptr;
gpg::RType* Udata::sType = nullptr;
gpg::RType* LClosure::sType = nullptr;
gpg::RType* lua_State::sType = nullptr;

namespace
{
  /**
   * Engine addition (`lua_ParallelSweep`, see `parallel_sweep` further down): where the next
   * parallel sweep may split each GC list into chunks.
   *
   * A boundary is an object known to be on its list, in list order. Between two sweeps a list
   * only gains objects at its head and loses them only in the sweep (and, for userdata, to
   * `luaC_separateudata`), so the boundaries from one sweep, plus every Nth object linked at a
   * head since, stay valid until the next sweep. A serial sweep frees boundary objects, so it
   * forgets them all (`Forget`).
   */
  namespace sweep_boundaries
  {
    enum EList : int
    {
      kListUserdata = 0, // rootudata
      kListThreads = 1,  // rootgc1
      kListObjects = 2,  // rootgc
      kListCount = 3
    };

    constexpr std::size_t kObjectsPerBoundary = 4096u;

    struct HeapBoundaries
    {
      // Read by the link sites on any thread (the user Lua state links on the main thread);
      // every other member is touched only by the thread running the heap this names.
      std::atomic<const global_State*> g{nullptr};
      std::array<std::vector<GCObject*>, kListCount> survivors; // from the last sweep, in list order
      std::array<std::vector<GCObject*>, kListCount> linked;    // linked at the head since, oldest first
      std::array<std::size_t, kListCount> countdown{kObjectsPerBoundary, kObjectsPerBoundary, kObjectsPerBoundary};
    };

    HeapBoundaries sBoundaries[2];

    [[nodiscard]] inline HeapBoundaries* FindBoundaries(
      const global_State* const g
    ) noexcept
    {
      if (g == nullptr) {
        return nullptr;
      }
      if (sBoundaries[0].g.load(std::memory_order_relaxed) == g) {
        return &sBoundaries[0];
      }
      if (sBoundaries[1].g.load(std::memory_order_relaxed) == g) {
        return &sBoundaries[1];
      }
      return nullptr;
    }

    inline HeapBoundaries& AllocateBoundaries(
      const global_State* const g
    ) noexcept
    {
      const int idx = moho::IsSimThread() ? 0 : 1;
      sBoundaries[idx].g.store(g, std::memory_order_relaxed);
      return sBoundaries[idx];
    }

    void Forget(
      const global_State* const g
    ) noexcept
    {
      HeapBoundaries* const b = FindBoundaries(g);
      if (b == nullptr) {
        return;
      }
      b->g.store(nullptr, std::memory_order_relaxed);
      for (int list = 0; list < kListCount; ++list) {
        b->survivors[list].clear();
        b->linked[list].clear();
        b->countdown[list] = kObjectsPerBoundary;
      }
    }

    /// `object` was just linked at the head of `list`: remember every Nth one.
    void NoteLinked(
      const global_State* const g,
      const EList list,
      GCObject* const object
    )
    {
      HeapBoundaries* const b = FindBoundaries(g);
      if (b == nullptr) {
        return;
      }
      if (--b->countdown[list] == 0u) {
        b->countdown[list] = kObjectsPerBoundary;
        b->linked[list].push_back(object);
      }
    }
  } // namespace sweep_boundaries

  /// FAF_LUAGC_TIMING: charges the time since the previous call to a named sub-phase of the collection.
  class GcDetailLaps
  {
  public:
    GcDetailLaps() noexcept
      : mTimer(lua::GcTimer::Current())
      , mLast(mTimer != nullptr ? lua::GcTimer::Now() : 0)
    {}

    void operator()(
      const char* const name
    ) noexcept
    {
      if (mTimer != nullptr) {
        const long long now = lua::GcTimer::Now();
        mTimer->Detail(name, now - mLast);
        mLast = now;
      }
    }

  private:
    lua::GcTimer* mTimer;
    long long mLast;
  };
}

namespace
{
  /**
   * The metatable every fresh userdata starts with.
   *
   * `luaS_newudata` (0x00924A10) reads it as `mov edx, [ecx+118h]` off the
   * `global_State`, and 0x118 is `_defaultmetatypes[LUA_TUSERDATA].value`:
   * the array sits at G+0xD4 with an 8-byte stride (`lea eax, [ecx+eax*8+0D4h]`
   * in `luaT_gettmbyobj`, 0x00928450), and `TObject` is `{int tt; Value value;}`
   * - tt first - so slot 8's value half lands at 0xD4 + 8*8 + 4 = 0x118.
   */
  [[nodiscard]] inline Table* DefaultUserdataMetatable(
    global_State* const globalState
  ) noexcept
  {
    return static_cast<Table*>(globalState->_defaultmetatypes[LUA_TUSERDATA].value.p);
  }
  static_assert(
    offsetof(global_State, _defaultmetatypes) + LUA_TUSERDATA * sizeof(LuaPlus::TObject) +
        offsetof(LuaPlus::TObject, value) ==
      0x118,
    "default userdata metatable must live at global_State+0x118"
  );
  static_assert(offsetof(global_State, rootudata) == 0x14, "global_State::rootudata must be at +0x14");

  /**
   * The metatable every fresh table starts with - the same array one slot
   * down, at `_defaultmetatypes[LUA_TTABLE].value`.
   *
   * `luaH_new` (0x00927320) reads it as `[ecx+100h]`, and 0xD4 + 5*8 + 4 is
   * 0x100, which pins LUA_TTABLE at tag 5 - consistent with the fork having
   * split `cfunction` out of `function` ahead of userdata's tag 8.
   */
  [[nodiscard]] inline Table* DefaultTableMetatable(
    global_State* const globalState
  ) noexcept
  {
    return static_cast<Table*>(globalState->_defaultmetatypes[LUA_TTABLE].value.p);
  }
  static_assert(
    offsetof(global_State, _defaultmetatypes) + LUA_TTABLE * sizeof(LuaPlus::TObject) +
        offsetof(LuaPlus::TObject, value) ==
      0x100,
    "default table metatable must live at global_State+0x100"
  );
  static_assert(
    offsetof(global_State, allocationTrackingEnabled) == 0x150,
    "global_State::allocationTrackingEnabled must be at +0x150"
  );

#if INTPTR_MAX == INT32_MAX
  // Table's own offsets are asserted at its definition in LuaRuntimeTypes.h,
  // where each one cites the instruction it was read from. They used to be
  // asserted here as 0x0D/0x14/0x18/0x24, which matched the struct as written
  // rather than the binary.
  static_assert(sizeof(Node) == 0x14, "Node size must be 0x14 (x86)");
#endif

  [[nodiscard]] constexpr std::uint32_t LuaHashMask(
    const Table* const table
  )
  {
    return (1u << table->lsizenode) - 1u;
  }

  [[nodiscard]] constexpr std::uint32_t LuaHashOddModulus(
    const Table* const table
  )
  {
    return LuaHashMask(table) | 1u;
  }

  [[nodiscard]] std::uint32_t LuaFloatBitPattern(
    const float value
  )
  {
    return std::bit_cast<std::uint32_t>(value);
  }

  [[nodiscard]] constexpr int LuaInstructionSignedOffset(
    const Instruction instruction
  )
  {
    return static_cast<int>((instruction >> 6) & 0x3FFFFu) - 0x1FFFF;
  }

  Table* LuaDebugGetSizesTable(lua_State* const state);
}

extern "C" {
Udata* luaS_newudata(lua_State* L, gpg::RType* type);
void luaC_collectgarbage(lua_State* L);
void luaC_link(lua_State* L, GCObject* object, int typeTag);
int luaC_sweep(lua_State* L, int all);
void luaF_close(lua_State* L, StkId level);
Closure* luaF_newCclosure(lua_State* L, int nelems);
lua_State* luaE_newthread(lua_State* L);
void luaD_growstack(lua_State* L, int n);
void luaS_freeall(lua_State* L);
const char* luaO_pushvfstring(lua_State* L, const char* fmt, va_list argp);
int _errorfb(lua_State* L, int level);
void luaG_runerror(lua_State* L, const char* format, ...);
void luaV_concat(lua_State* L, int total, int last);
int luaV_tostring(lua_State* L, TObject* obj);
int luaV_equalval(lua_State* L, const TObject* left, const TObject* right);
int luaV_lessthan(lua_State* L, const TObject* left, const TObject* right);
Proto* luaF_newproto(lua_State* L);
void discharge2reg(expdesc* e, int reg, FuncState* fs);
int luaK_code(FuncState* fs, Instruction i, int line);
int luaK_codeABC(FuncState* fs, int o, int a, int b, int c);
void luaK_dischargevars(FuncState* fs, expdesc* e);
void luaK_nil(FuncState* fs, int from, int n);
void luaX_checklimit(LexState* ls, int v, int l, const char* what);
void luaX_syntaxerror(LexState* ls, const char* msg);
TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
// Lua nil sentinel TObject. The Lua VM core that originally owned this
// global is not part of the recovered link set, so it is defined here with
// external linkage (extern + initializer). A default-constructed TObject is
// the nil value (tt == LUA_TNIL, value.p == nullptr).
extern const TObject luaO_nilobject{};
int luaO_rawequalObj(const TObject* t1, const TObject* t2);
Node* luaH_mainposition(const Table* t, const TObject* key);
const TObject* luaH_getany(const TObject* key, Table* t);
const TObject* luaH_get(Table* t, const TObject* key);
const TObject* luaH_getstr(Table* t, TString* key);
const TObject* luaH_getnum(Table* t, int key);
int luaO_log2(unsigned int x);
const TObject* luaT_gettm(Table* events, int event, TString* ename);
void luaD_reallocstack(lua_State* L, int newsize);
TObject* newkey(lua_State* L, Table* t, const TObject* key);
void luaK_fixjump(int to, int from, FuncState* fs);
TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
TObject* luaH_setnum(lua_State* L, Table* t, int key);
TObject* negindex(lua_State* L, int idx);
Table* luaH_new(lua_State* L, int narray, int lnhash);
Table* luaT_getmetatable(lua_State* L, const TObject* o);
const TObject* luaV_tonumber(const TObject* obj, TObject* outNumber);
int luaV_lessthan(lua_State* L, const TObject* l, const TObject* r);
int luaH_next(lua_State* L, Table* table, TObject* key);
void luaG_errormsg(lua_State* L);

/**
 * Address: 0x00D474D8 (luaT_typenames)
 *
 * What it does:
 * Names each type tag for `lua_typename` and the `luaG_*error` messages.
 * Read straight out of the shipped image: twelve entries, ending where
 * luaT_eventname begins at 0x00D47508. The fork's split of "cfunction"
 * from "function" and its trailing proto/upval lanes are why this cannot
 * be left to resolve into the prebuilt LuaPlus lib, whose stock array is
 * both shorter and differently ordered.
 */
extern const char* luaT_typenames[]{
  "nil",       // LUA_TNIL            0
  "boolean",   // LUA_TBOOLEAN        1
  "userdata",  // LUA_TLIGHTUSERDATA  2
  "number",    // LUA_TNUMBER         3
  "string",    // LUA_TSTRING         4
  "table",     // LUA_TTABLE          5
  "cfunction", // LUA_CFUNCTION       6
  "function",  // LUA_TFUNCTION       7
  "userdata",  // LUA_TUSERDATA       8
  "thread",    // LUA_TTHREAD         9
  "proto",     // LUA_TPROTO         10
  "upval",     // LUA_TUPVALUE       11
};

// Sizes of the three interned-name tables the bootstrap walks, each taken
// from the loop bound in the function that fills it.
constexpr int kLuaTypeTagCount = 12;      // luaC_init:  0xA4 -> 0xD4 step 4
constexpr int kLuaTagMethodCount = 18;    // luaT_init:  0x5C -> 0xA4 step 4
constexpr int kLuaReservedWordCount = 22; // luaX_init:  "cmp ebx, 16h"

// GC mark bit that pins a string against collection; every interned name
// laid down during bootstrap gets it ("or byte ptr [eax+5], 10h").
constexpr lu_byte kLuaFixedStringMark = 0x10;

// Bucket count the string table opens with ("push 20h" -> luaS_resize).
constexpr int kLuaInitialStringTableSize = 32;

/**
 * `luaC_checkGC` was a macro in the 2007 sources, so the binary emits it
 * inline at every allocating API entry point rather than as a call. Kept
 * as one internal-linkage helper here so the gate is written once.
 */
static void luaC_checkGC(
  lua_State* const state
)
{
  global_State* const globalState = state->l_G;
  if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
    if (
      const moho::lua_incremental::SState* const incremental = moho::lua_incremental::Find(state->l_G);
      incremental != nullptr && incremental->frameDriven
    ) {
      return; // UI_ProcessIdleGC owns this state's pacing
    }
    if (globalState->nblocks >= globalState->GCthreshold && globalState->gcTraversalLockDepth == 0) {
      faf_lua51_gc_step(state); // Lua 5.1.5 lgc.c: luaC_checkGC()/luaC_step()
    }
    return;
  }
  if (LuaGcThresholdReached(globalState) && globalState->gcTraversalLockDepth == 0) {
    luaC_collectgarbage(state);
  }
}

/**
 * `api_incr_top`, likewise a macro: publish one freshly written stack slot,
 * growing the stack first when this frame has run out of room.
 */
static void api_incr_top(
  lua_State* const state
)
{
  if (state->top >= state->ci->top && state->stack_last - state->top <= 1) {
    luaD_growstack(state, 1);
  }

  ++state->top;
}
/**
 * Address: 0x009240C0 (FUN_009240C0, lua_stack_init)
 *
 * What it does:
 * Allocates one fresh Lua thread stack and call-info array, initializes the
 * first call frame, and seeds default stack/base/top lanes for execution.
 */
static void lua_stack_init(
  lua_State* const allocatorState,
  lua_State* const threadState
)
{
  constexpr int kInitialStackSlots = 45;
  constexpr int kStackGuardTailSlots = 6;
  constexpr int kInitialCallInfoSlots = 8;
  constexpr int kInitialCallFrameTopSpan = 20;

  TObject* const stackBase = luaM_newvector<TObject>(allocatorState, kInitialStackSlots);
  threadState->stack = stackBase;
  threadState->top = stackBase;
  threadState->stacksize = kInitialStackSlots;
  threadState->stack_last = stackBase + (kInitialStackSlots - kStackGuardTailSlots);

  CallInfo* const callInfoBase = luaM_newvector<CallInfo>(allocatorState, kInitialCallInfoSlots);
  threadState->ci = callInfoBase;
  threadState->base_ci = callInfoBase;
  callInfoBase->state = 5;
  callInfoBase->savedpc = nullptr;
  callInfoBase->tailcalls = 0;
  callInfoBase->pc = nullptr;
  callInfoBase->reserved0 = 0;
  callInfoBase->reserved1 = 0;
  callInfoBase->reserved2 = 0;

  threadState->top->tt = LUA_TNIL;
  CallInfo* const ci = threadState->ci;
  ci->base = ++threadState->top;
  threadState->base = ci->base;
  ci->top = threadState->top + kInitialCallFrameTopSpan;
  threadState->size_ci = static_cast<std::uint16_t>(kInitialCallInfoSlots);
  threadState->end_ci = threadState->base_ci + kInitialCallInfoSlots;
}

/**
 * Address: 0x00924210 (FUN_00924210, close_state)
 *
 * What it does:
 * Closes pending Lua upvalues, sweeps/frees GC and scratch-buffer lanes,
 * releases callinfo+stack arrays, then frees global and thread state using
 * allocator callbacks captured from `global_State`.
 */
static void close_state(
  lua_State* const state
)
{
  // Crash-report registry (deviation, documented): out first, so the
  // handler never walks a state that is being freed under it.
  lua::UnregisterLuaVm(state);

  luaF_close(state, state->stack);

  global_State* const globalState = state->l_G;
  lua_State allocatorState{};
  global_State allocatorGlobal{};
  allocatorState.l_G = &allocatorGlobal;
  allocatorGlobal.memData = globalState->memData;
  allocatorGlobal.reallocFunc = globalState->reallocFunc;
  allocatorGlobal.freeFunc = globalState->freeFunc;

  if (globalState != nullptr) {
    (void)luaC_sweep(state, 1);
    luaS_freeall(state);
    globalState->buff.buffer =
      luaM_reallocvector<char>(state, globalState->buff.buffer, globalState->buff.buffsize, 0u);
    globalState->buff.buffsize = 0u;
  }

  luaM_freearray<CallInfo>(state, state->base_ci, static_cast<lu_mem>(state->size_ci));
  luaM_freearray<TObject>(state, state->stack, static_cast<lu_mem>(state->stacksize));

  if (globalState != nullptr) {
    // x64 port test mode (plan 4.1a), not in the binary: FAF_LUAGC_LOG.
    lua::GcEventLogUnregisterState(globalState);
    luaM_freelem<global_State>(&allocatorState, globalState);
  }
  luaM_freelem<lua_State>(&allocatorState, state);
}

/**
 * Address: 0x00924080 (FUN_00924080, lua_setusergcfunction)
 *
 * What it does:
 * Stores one engine GC callback pointer in the shared global-state lane.
 */
void lua_setusergcfunction(
  lua_State* const state,
  void(__cdecl* userGCFunction)(void*)
)
{
  state->l_G->userGCFunction = reinterpret_cast<void(__cdecl*)(GCState*)>(userGCFunction);
}

/**
 * Address: 0x009240B0 (FUN_009240B0, lua_setstateuserdata)
 *
 * What it does:
 * Stores one LuaPlus wrapper pointer in `lua_State::stateUserData`.
 */
void lua_setstateuserdata(
  lua_State* const state,
  void* const stateUserData
)
{
  state->stateUserData = static_cast<LuaState*>(stateUserData);
}

/**
 * Address: 0x00924060 (FUN_00924060, lua_setglobaluserdata)
 *
 * What it does:
 * Stores engine global userdata pointer into `global_State::globalUserData`.
 */
void lua_setglobaluserdata(
  lua_State* const state,
  void* const globalUserData
)
{
  state->l_G->globalUserData = static_cast<moho::Sim*>(globalUserData);
  if (globalUserData != nullptr && moho::lua_IncrementalGC) {
    faf_lua51_gc_abandon(state->l_G);
  }
}

/**
 * Address: 0x00924050 (FUN_00924050, lua_getglobaluserdata)
 *
 * IDA signature:
 * Moho::Sim *__usercall lua_getglobaluserdata@<eax>(lua_State *L);
 *
 * What it does:
 * Reads back what lua_setglobaluserdata stored - the Sim every sim-side
 * Lua binding starts from.
 *
 * The setter above was recovered but this half never was, so it resolved
 * to the prebuilt LuaPlus library's copy, which reads the field at stock
 * global_State's offset rather than this fork's +0x148. Every binding that
 * asked for the Sim got a null back, and the first one to do so - the
 * initial-unit spawn - reported the ACU blueprint as unknown.
 */
// LuaPrimitives.h macros the name onto the typed inline wrapper for call
// sites; the definition itself has to be spelled without it.
#undef lua_getglobaluserdata
void* lua_getglobaluserdata(
  lua_State* const state
)
{
  return state->l_G->globalUserData;
}
#define lua_getglobaluserdata lua_getglobaluserdata_typed

/**
 * Address: 0x0090C530 (FUN_0090C530, lua_newthread)
 *
 * What it does:
 * Runs the Lua GC-threshold gate, creates one new coroutine state, pushes
 * that thread object to stack top, and preserves Lua stack growth guard.
 */
lua_State* lua_newthread(
  lua_State* const state
)
{
  luaC_checkGC(state);

  lua_State* const newThread = luaE_newthread(state);
  auto* const threadObject = reinterpret_cast<GCObject*>(newThread);
  TObject* const top = state->top;
  top->tt = static_cast<int>(threadObject->gch.tt);
  top->value.p = threadObject;

  if (top >= state->ci->top && state->stack_last - top <= 1) {
    luaD_growstack(state, 1);
  }

  ++state->top;
  return newThread;
}

#include "LuaObjectApi.inl"

#include "LuaObjectStringsTables.inl"

#include "LuaObjectCode.inl"

#include "LuaObjectDebugCall.inl"

#include "LuaObjectIoLib.inl"

#include "LuaObjectLoadGc.inl"

#include "LuaObjectDebugLib.inl"

#include "LuaObjectStringLib.inl"

#include "LuaObjectTableMathLib.inl"

#include "LuaObjectBaseLib.inl"

#include "LuaObjectPlusRefs.inl"

#include "LuaObjectAuxLib.inl"

#include "LuaObjectVm.inl"

#include "LuaObjectSerialize.inl"

#include "LuaObjectClasses.inl"

#include "lua/LuaCrashDump.h"

#include <Windows.h>

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "gpg/core/diagnostics/CrashReport.h"
#include "lua/LuaPrimitives.h"
#include "lua/LuaRuntimeTypes.h"

namespace
{

  // The registry is written from any thread (lua_open/lua_close) but only
  // appended/nulled under an interlocked swap, and read only on the crash
  // path. A torn entry (a state being destroyed mid-crash) is caught by the
  // sanity checks in DescribeVm.
  constexpr int kMaxLuaVms = 16;

  struct VmRegistry
  {
    void* volatile states[kMaxLuaVms] = {};
    DWORD threadIds[kMaxLuaVms] = {};
    volatile LONG activeCount = 0;
  };

  VmRegistry& VmRegistryInstance()
  {
    static VmRegistry registry;
    return registry;
  }

  // ------------------------------------------------------------------
  // Crash-safe primitives (no allocation: fixed buffers, plain fprintf)
  // ------------------------------------------------------------------

  void DumpLine(std::FILE* const sink, const char* const format, ...)
  {
    if (sink == nullptr) {
      return;
    }
    va_list args;
    va_start(args, format);
    std::vfprintf(sink, format, args);
    va_end(args);
    std::fputc('\n', sink);
    std::fflush(sink);
  }

  bool IsPlausiblePointer(const void* const p)
  {
    const auto address = reinterpret_cast<std::uintptr_t>(p);
    return address > 0x10000 && address < 0x7FFFFFFFFFFFULL;
  }

  const char* LuaTypeName(const int tt)
  {
    switch (tt) {
      case LUA_TNIL: return "nil";
      case LUA_TBOOLEAN: return "boolean";
      case LUA_TLIGHTUSERDATA: return "lightuserdata";
      case LUA_TNUMBER: return "number";
      case LUA_TSTRING: return "string";
      case LUA_TTABLE: return "table";
      case LUA_TFUNCTION: return "function";
      case LUA_TUSERDATA: return "userdata";
      case LUA_TTHREAD: return "thread";
      case LUA_TPROTO: return "proto";
      case LUA_TUPVALUE: return "upvalue";
      default: return "?";
    }
  }

  // Renders one TObject into a fixed buffer, allocation-free.
  void DescribeTObject(const LuaPlus::TObject& object, char* const out, const std::size_t outBytes)
  {
    switch (object.tt) {
      case LUA_TNIL:
        (void)std::snprintf(out, outBytes, "nil");
        break;
      case LUA_TBOOLEAN:
        (void)std::snprintf(out, outBytes, "%s", object.value.b ? "true" : "false");
        break;
      case LUA_TNUMBER:
        (void)std::snprintf(out, outBytes, "%g", static_cast<double>(object.value.n));
        break;
      case LUA_TSTRING: {
        const auto* const string = static_cast<const TString*>(object.value.p);
        if (!IsPlausiblePointer(string)) {
          (void)std::snprintf(out, outBytes, "string(<bad %p>)", object.value.p);
          break;
        }
        std::size_t length = string->len;
        if (length > 64) {
          length = 64; // preview only
        }
        (void)std::snprintf(out, outBytes, "\"%.*s\"", static_cast<int>(length), string->str);
        break;
      }
      default:
        (void)std::snprintf(out, outBytes, "%s(%p)", LuaTypeName(object.tt), object.value.p);
        break;
    }
  }

  // The frame's source chunk name, guarded (chunk names are TString*).
  void DescribeSource(const Proto* const proto, char* const out, const std::size_t outBytes)
  {
    out[0] = '\0';
    if (proto == nullptr || !IsPlausiblePointer(proto)) {
      (void)std::snprintf(out, outBytes, "(bad proto)");
      return;
    }
    const TString* const source = proto->source;
    if (!IsPlausiblePointer(source)) {
      (void)std::snprintf(out, outBytes, "(bad source)");
      return;
    }
    std::size_t length = source->len;
    if (length > 96) {
      length = 96;
    }
    (void)std::snprintf(out, outBytes, "%.*s", static_cast<int>(length), source->str);
  }

  // ------------------------------------------------------------------
  // Table corruption finders (FADeepProbe #3 parity, on typed layouts)
  // ------------------------------------------------------------------

  bool NodeKeyIsNil(const Node& node)
  {
    return node.i_key.tt == LUA_TNIL;
  }

  bool NodeValueIsNil(const Node& node)
  {
    return node.i_val.tt == LUA_TNIL;
  }

  void DumpSuspectTable(std::FILE* const sink, const Table* const table)
  {
    if (!IsPlausiblePointer(table)) {
      DumpLine(sink, "    suspect table: <bad pointer %p>", static_cast<const void*>(table));
      return;
    }

    const int nodeCount = (table->lsizenode > 0 && table->lsizenode < 20)
                            ? (1 << table->lsizenode)
                            : (table->lsizenode == 0 ? 0 : -1);
    DumpLine(
      sink, "    table %p: flags=%d lsizenode=%u nodes=%d array=%d sizearray=%d metatable=%p",
      static_cast<const void*>(table), static_cast<int>(table->flags), static_cast<unsigned>(table->lsizenode),
      nodeCount, static_cast<int>(table->array != nullptr), table->sizearray,
      static_cast<const void*>(table->metatable)
    );

    if (nodeCount <= 0 || !IsPlausiblePointer(table->node)) {
      return;
    }

    const int dumpNodes = (nodeCount < 32) ? nodeCount : 32;
    int nilKeyNodes = 0;
    for (int i = 0; i < dumpNodes; ++i) {
      const Node& node = table->node[i];
      if (NodeKeyIsNil(node) && !NodeValueIsNil(node)) {
        ++nilKeyNodes;
      }
      char keyText[96] = {};
      char valueText[96] = {};
      DescribeTObject(node.i_key, keyText, sizeof(keyText));
      DescribeTObject(node.i_val, valueText, sizeof(valueText));
      DumpLine(
        sink, "    node[%d] key=%s value=%s next=%p", i, keyText, valueText,
        static_cast<const void*>(node.next)
      );
    }
    if (nilKeyNodes != 0) {
      DumpLine(
        sink, "    !! %d node(s) with nil key and non-nil value - Lua never creates these; "
              "stray write signature",
        nilKeyNodes
      );
    }
    if (dumpNodes < nodeCount) {
      DumpLine(sink, "    (%d more nodes not dumped)", nodeCount - dumpNodes);
    }
  }

  // Is this frame executing inside the table code family? The report uses it
  // to decide whether to dump the table operands sitting in the frame's
  // registers. Exact opcode ranges are not needed: the crash handler only
  // sees the faulting native address, so the trigger is the table value
  // present in the frame's top slots (dumped below when found).
  void DumpTableOperandsInFrame(std::FILE* const sink, const lua_State* const state, const CallInfo* const ci)
  {
    if (state == nullptr || ci == nullptr || !IsPlausiblePointer(state->stack)) {
      return;
    }
    int dumped = 0;
    // Walk this frame's registers, bounded; dump only the first few tables.
    const LuaPlus::StkId base = ci->base;
    const LuaPlus::StkId top = ci->top;
    if (!IsPlausiblePointer(base) || !IsPlausiblePointer(top) || top <= base || (top - base) > 250) {
      return;
    }
    for (LuaPlus::StkId slot = base; slot < top && dumped < 3; ++slot) {
      if (slot->tt == LUA_TTABLE && IsPlausiblePointer(slot->value.p)) {
        DumpLine(sink, "    table operand in register %d:", static_cast<int>(slot - base));
        DumpSuspectTable(sink, static_cast<const Table*>(slot->value.p));
        ++dumped;
      }
    }
  }

  // ------------------------------------------------------------------
  // One VM
  // ------------------------------------------------------------------

  void DescribeVm(std::FILE* const sink, lua_State* const state, const int index)
  {
    if (!IsPlausiblePointer(state)) {
      DumpLine(sink, "VM %d: <bad pointer>", index);
      return;
    }

    DumpLine(sink, "VM %d: %p", index, static_cast<void*>(state));

    if (!IsPlausiblePointer(state->l_G) || !IsPlausiblePointer(state->stack)
        || !IsPlausiblePointer(state->base_ci)) {
      DumpLine(sink, "  VM %d: header sanity failed (partially destroyed?)", index);
      return;
    }

    // Which thread of this VM is running? luaV_execute sets G->lstate on
    // entry and restores it on every exit (ActiveThreadGuard), so a non-null
    // lstate != state is a coroutine mid-execution - dump that thread's chain
    // as well. It is also the validity signal for the live-pc pointer: once
    // luaV_execute has returned, ci->pc points into a dead frame.
    lua_State* const runningThread = state->l_G->lstate;
    if (IsPlausiblePointer(runningThread) && runningThread != state
        && runningThread->l_G == state->l_G) {
      DumpLine(sink, "  VM %d: running on coroutine thread %p", index, static_cast<void*>(runningThread));
      DescribeVm(sink, runningThread, index);
    }

    const bool livePcValid = (runningThread == state);

    // CallInfo chain: outermost first is more readable in a report.
    CallInfo* const baseCi = state->base_ci;
    CallInfo* const currentCi = state->ci;
    if (!IsPlausiblePointer(currentCi) || currentCi < baseCi) {
      DumpLine(sink, "  VM %d: bad ci %p (base %p)", index, static_cast<void*>(currentCi),
               static_cast<void*>(baseCi));
      return;
    }
    const std::ptrdiff_t frameCount = currentCi - baseCi;
    if (frameCount > 200) {
      DumpLine(sink, "  VM %d: ci chain implausible (%td frames); skipping", index,
               static_cast<long long>(frameCount));
      return;
    }

    DumpLine(sink, "  VM %d: %td frame(s)", index, static_cast<long long>(frameCount));

    // Print innermost 32 frames, innermost first (that is where the bug is).
    const std::ptrdiff_t printed = (frameCount < 32) ? frameCount : 32;
    for (std::ptrdiff_t f = 0; f < printed; ++f) {
      CallInfo* const ci = currentCi - f;
      if (!IsPlausiblePointer(ci->base)) {
        DumpLine(sink, "  VM %d frame %td: bad base", index, static_cast<long long>(f));
        continue;
      }

      const int frameState = ci->state;
      const Closure* const closure =
        (ci->base > state->stack) ? static_cast<const Closure*>(ci->base[-1].value.p) : nullptr;

      if (closure == nullptr || !IsPlausiblePointer(closure)) {
        DumpLine(sink, "  VM %d frame %td: <no closure> state=%d", index, static_cast<long long>(f), frameState);
        continue;
      }

      const Proto* const proto = closure->l.p;
      if (!IsPlausiblePointer(proto) || !IsPlausiblePointer(proto->code)) {
        DumpLine(sink, "  VM %d frame %td: <bad proto> state=%d", index, static_cast<long long>(f), frameState);
        continue;
      }

      char source[128] = {};
      DescribeSource(proto, source, sizeof(source));

      // Line resolution. The running frame's exact pc: luaV_execute stores
      // the address of its live `pc` variable into ci->pc at each dispatch
      // entry (see LuaObject.cpp); outer frames use savedpc, which points
      // just past the call.
      const Instruction* pc = nullptr;
      const char* pcKind = "savedpc";
      if (f == 0 && livePcValid && IsPlausiblePointer(ci->pc)) {
        pc = *(ci->pc);
        pcKind = "livepc";
      } else if (IsPlausiblePointer(ci->savedpc) && ci->savedpc >= proto->code) {
        pc = ci->savedpc - 1; // the call instruction
        pcKind = "savedpc";
      }

      int line = -1;
      if (pc != nullptr && pc >= proto->code && proto->lineinfo != nullptr) {
        const std::ptrdiff_t instructionIndex = pc - proto->code;
        const int sizecode = proto->sizecode;
        if (instructionIndex >= 0 && instructionIndex < sizecode) {
          line = proto->lineinfo[instructionIndex];
        }
      }

      if (frameState >= 3) { // C function / special frames have no Lua source
        DumpLine(
          sink, "  VM %d frame %td: <C or suspended> state=%d", index, static_cast<long long>(f), frameState
        );
      } else {
        DumpLine(
          sink, "  VM %d frame %td: %s:%d (lineDefined=%d, %s)", index, static_cast<long long>(f), source, line,
          proto->lineDefined, pcKind
        );
        if (f == 0) {
          DumpTableOperandsInFrame(sink, state, ci);
        }
      }
    }
    if (frameCount > printed) {
      DumpLine(sink, "  VM %d: ... %td outer frame(s) elided", index,
               static_cast<long long>(frameCount - printed));
    }

    // Top-of-stack preview (the innermost frame's registers).
    if (IsPlausiblePointer(currentCi->base) && IsPlausiblePointer(state->top)
        && state->top > currentCi->base && (state->top - currentCi->base) <= 250) {
      const int slots = static_cast<int>(state->top - currentCi->base);
      const int printedSlots = (slots < 16) ? slots : 16;
      DumpLine(sink, "  VM %d stack top: %d slot(s), first %d:", index, slots, printedSlots);
      for (int s = 0; s < printedSlots; ++s) {
        char valueText[96] = {};
        DescribeTObject(currentCi->base[s], valueText, sizeof(valueText));
        DumpLine(sink, "  VM %d   [%d] %s", index, s, valueText);
      }
    }
  }

} // namespace

namespace lua
{

  namespace
  {

    // Registers the Lua section with the crash reporter at load time, so any
    // fatal path after static init includes the Lua dump without an explicit
    // startup call in engine code.
    void WriteLuaCrashSectionAdapter(std::FILE* const sink, const gpg::diag::CrashSectionInfo& info)
    {
      WriteLuaCrashSection(sink, info.faultAddress, info.accessTarget);
    }

    const bool sLuaCrashSectionRegistered =
      (gpg::diag::AddCrashSection("Lua", &WriteLuaCrashSectionAdapter), true);

  } // namespace

  void RegisterLuaVm(lua_State* const state)
  {
    if (state == nullptr) {
      return;
    }
    VmRegistry& registry = VmRegistryInstance();
    const LONG count = registry.activeCount;
    for (LONG i = 0; i < count; ++i) {
      if (registry.states[i] == static_cast<void*>(state)) {
        return; // already registered
      }
    }
    if (count >= kMaxLuaVms) {
      return;
    }
    registry.states[count] = state;
    registry.threadIds[count] = ::GetCurrentThreadId();
    ::InterlockedIncrement(&registry.activeCount);
  }

  void UnregisterLuaVm(lua_State* const state)
  {
    if (state == nullptr) {
      return;
    }
    VmRegistry& registry = VmRegistryInstance();
    const LONG count = registry.activeCount;
    for (LONG i = 0; i < count; ++i) {
      if (registry.states[i] == static_cast<void*>(state)) {
        // Swap-with-last keeps the live prefix dense.
        registry.states[i] = registry.states[count - 1];
        registry.threadIds[i] = registry.threadIds[count - 1];
        registry.states[count - 1] = nullptr;
        registry.threadIds[count - 1] = 0;
        ::InterlockedDecrement(&registry.activeCount);
        return;
      }
    }
  }

  void SetThreadActiveLuaVm(lua_State* const)
  {
    // The per-thread active flag is folded into RegisterLuaVm's threadIds
    // for creation; the running-thread correlation is reported through
    // global_State::lstate, which luaV_execute already maintains and the
    // dump reads directly. Reserved for the Phase 4 watch/probe work.
  }

  void WriteLuaCrashSection(std::FILE* const sink, const void* const faultAddress, const void* const accessTarget)
  {
    VmRegistry& registry = VmRegistryInstance();
    const LONG count = registry.activeCount;
    DumpLine(sink, "registered VMs: %d", static_cast<int>(count));
    for (LONG i = 0; i < count && i < kMaxLuaVms; ++i) {
      if (registry.states[i] == nullptr) {
        continue;
      }
      DescribeVm(sink, static_cast<lua_State*>(registry.states[i]), static_cast<int>(i));
    }
    if (faultAddress != nullptr) {
      AnnotateLuaAddress(sink, faultAddress);
    }
    if (accessTarget != nullptr && accessTarget != faultAddress) {
      AnnotateLuaAddress(sink, accessTarget);
    }
  }

  void AnnotateLuaAddress(std::FILE* const sink, const void* const address)
  {
    if (sink == nullptr || address == nullptr) {
      return;
    }
    VmRegistry& registry = VmRegistryInstance();
    const LONG count = registry.activeCount;
    const auto target = reinterpret_cast<std::uintptr_t>(address);
    for (LONG i = 0; i < count && i < kMaxLuaVms; ++i) {
      const lua_State* const state = static_cast<const lua_State*>(registry.states[i]);
      if (state == nullptr || !IsPlausiblePointer(state->stack) || state->stacksize <= 0) {
        continue;
      }
      const auto stackBegin = reinterpret_cast<std::uintptr_t>(state->stack);
      const auto stackEnd = stackBegin + static_cast<std::uintptr_t>(state->stacksize) * sizeof(LuaPlus::TObject);
      if (target >= stackBegin && target < stackEnd) {
        const std::size_t slot = (target - stackBegin) / sizeof(LuaPlus::TObject);
        DumpLine(sink, "address %p is VM %d stack slot %llu", address, static_cast<int>(i),
                 static_cast<unsigned long long>(slot));
        return;
      }
    }
  }

} // namespace lua

// Retail call recorder: an x86 DLL loaded into the original ForgedAlliance.exe
// while it plays a replay. Each hooked function's entry jumps to a stub that
// saves every register and the whole FPU/SSE state (pushad, fxsave), records
// the arguments, and sends the call on to a trampoline (the function's first
// whole instructions, then a jump back into it) with its own return address
// swapped for a post-call stub. That stub records the result (eax, edx:eax, or
// st0 read from the fxsave image), restores everything and returns to the real
// caller, so the game computes exactly what it would without the recorder.
//
// Two modes, by environment:
//   RETAIL_RECORDER_SPEC=<spec.bin> (from spec.py): hooks every function in
//     the spec and keeps, per function, the call count and the sum of one
//     64-bit FNV-1a hash per call over its hashed arguments and its result
//     (order-independent, so sim worker threads do not change it). The table
//     ("va calls sum") is rewritten to RETAIL_RECORDER_OUT every 10 s.
//   RETAIL_RECORDER_SETS=<file> with a spec from spec_compare.py: instead of one
//     sum, keeps per function the set of per-call hashes (arguments and result)
//     and writes them to <file>, for compare_sets.py. The DLL is the same for the
//     original game and for our instrumented build (see README).
//   otherwise: the built-in kValueHooks, written call by call to
//     RETAIL_RECORDER_OUT in faf_math_dump's values format.
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{
  using u32 = std::uint32_t;
  using u64 = std::uint64_t;

  enum : std::uint8_t
  {
    kRetNone = 0,
    kRetEax = 1,
    kRetSt0Float = 2,
    kRetSt0Double = 3,
    kRetEdxEax = 4,
    kRetAl = 5,
    kRetAx = 6,
    kRetXmm0Float = 7,
    kRetEaxPointer = 8, // written to the R and P lines, never hashed: an address differs per run
  };

  struct ArgSpec
  {
    std::uint8_t location; // register index (eax ecx edx ebx esi edi ebp), or 0x80 | stack dword
    std::uint8_t words;
    std::uint8_t hashed;
    std::uint8_t isFloat;
  };

  // Sets mode: the distinct per-call hashes of one function. Past kMaxSetSize
  // it keeps only hashes whose top `level` bits are zero, so two runs compare
  // on the same sample whatever each one saw.
  constexpr u32 kFirstSetCapacity = 16u;
  constexpr u32 kMaxSetSize = 1u << 14;
  struct HashSet
  {
    volatile LONG lock = 0;
    u32 level = 0;
    u32 count = 0;
    u32 capacity = 0;
    u64* slots = nullptr;
  };

  struct Hook
  {
    u32 va = 0;
    u32 id = 0; // what the hash starts from: the retail address on both sides
    HashSet set;
    volatile LONG64 recorded = 0;
    int prologueBytes = 0;
    u32 popBytes = 0;
    std::uint8_t ret = kRetNone;
    std::vector<ArgSpec> args;
    const char* lineName = nullptr; // values mode: the difffuzz row name
    u32 recordAll = 0;
    u32 thenEvery = 1;
    // Spec mode: the spec's writes flag (1 = the function stores outside its
    // result and frame; its probe calls would change the game, so none run).
    std::uint8_t writes = 0;
    // Probe state: how many real calls still get extra edge-value calls, and
    // whether probing is disabled for this hook (the journal's skip list).
    u32 probeBudget = 0;
    volatile LONG probesDone = 0;
    LONG64 nextProbeCall = 0; // rounds spread over the game: each waits for 4x the calls
    volatile LONG faults = 0;
    bool probeEnabled = true;
    std::uint8_t* trampoline = nullptr;
    bool watched = false; // sets mode: each recorded call also goes to the watch file
    volatile LONG64 calls = 0;
    volatile LONG64 sum = 0;
  };

  // Values mode. atan2f 0x004E9DF0: push ebp; mov ebp, esp; and esp, -8 (6
  // bytes), cdecl [y x], fpatan, result in st0. Row "atan2f".
  struct ValueHookSpec
  {
    u32 va;
    int prologueBytes;
    const char* name;
    int stackWords;
    std::uint8_t ret;
    u32 recordAll;
    u32 thenEvery;
  };
  const ValueHookSpec kValueHooks[] = {
    {0x004E9DF0u, 6, "atan2f", 2, kRetSt0Float, 20000u, 1000u},
  };

  std::vector<Hook> gHooks;
  bool gSpecMode = false;
  bool gSetsMode = false;
  // Sets mode: only the sim thread records, known as the thread that first
  // enters this function (Sim::AdvanceBeat). The original game's other threads
  // draw, and their calls depend on frame timing; our headless has no such calls.
  u32 gSimEntryId = 0;
  // Sets mode: what a hash hides. Two runs' files line up call by call.
  std::FILE* gWatchOut = nullptr;
  int gWatchTextArg = -1;
  int gWatchWordArg = -1;
  volatile LONG gSimThreadId = 0;
  // Sets mode: recording stops once this many beats ran (0: never), so both games
  // record the same beats whichever plays further at the end of a replay.
  u64 gSimBeats = 0;
  bool gEndAtSimBeats = false;
  HANDLE gLastWriteWanted = nullptr;
  HANDLE gLastWriteDone = nullptr;
  volatile LONG gSetsFinal = 0;

  // pushad image, then the stack the stubs see above it.
  struct EntryFrame
  {
    u32 edi, esi, ebp, espAtPushad, ebx, edx, ecx, eax;
    u32 eflags;
    u32 slot;      // hook index on entry; the trampoline address on the way out
    u32 callerRet; // swapped for PostEntry
    u32 args[1];   // the stack arguments continue from here
  };
  struct ExitFrame
  {
    u32 edi, esi, ebp, espAtPushad, ebx, edx, ecx, eax;
    u32 eflags;
    u32 slot; // the caller's return address on the way out
  };

  constexpr int kMaxValueWords = 16;
  constexpr int kProbeStackWords = 16;
  // What a real call entered with, copied in OnEntry for the probes: the stub's
  // frame is gone by the exit (the registers lie below esp once the function
  // runs, and a `ret N` hands its arguments to PostEntry's pushes).
  struct CapturedCall
  {
    u32 regs[7]; // eax ecx edx ebx esi edi ebp (RegisterValue order)
    u32 args[kProbeStackWords];
    u32 fcw;
    u32 mxcsr;
  };
  struct PendingCall
  {
    int hook;
    u32 callerRet;
    u32 returnSlot; // address of the caller's return address: matches the exit even after an unwind
    CapturedCall captured; // filled only for a hook that still has probes to run
    bool record;
    u32 sequence;
    u64 hash;
    int valueCount;
    u32 values[kMaxValueWords];
    char text[128]; // watched call: the text at RETAIL_RECORDER_WATCH_TEXT_ARG
    u32 pointee; // watched call: the word at RETAIL_RECORDER_WATCH_WORD_ARG
  };
  constexpr int kMaxDepth = 512;
  __declspec(thread) PendingCall tPending[kMaxDepth];
  __declspec(thread) int tDepth = 0;

  CRITICAL_SECTION gWriterLock;
  std::FILE* gOut = nullptr;
  char gOutPath[MAX_PATH] = {};
  char gSetsPath[MAX_PATH] = {};
  unsigned gLinesSinceFlush = 0;


  extern "C" void CommonEntry();
  extern "C" void PostEntry();

  [[nodiscard]] u32 RegisterValue(const EntryFrame* f, const int index)
  {
    switch (index) {
      case 0: return f->eax;
      case 1: return f->ecx;
      case 2: return f->edx;
      case 3: return f->ebx;
      case 4: return f->esi;
      case 5: return f->edi;
      default: return f->ebp;
    }
  }

  // ---------------------------------------------------------------------
  // Probe mode: after a real call, re-call the same function on the same
  // objects with edge values in the plain-value arguments, recording the
  // argument words, the result and a snapshot of the bytes behind every
  // pointer argument. Only functions the spec marks probe-safe (writes
  // nothing outside their result and stack frame) are probed, so the extra
  // calls cannot change the game; a fault inside a probe is caught and
  // recorded as the result. A journal notes progress to disk: if the game
  // dies inside a probe (some errors kill the process past any handler), the
  // next run reads the journal and skips that function.
  // ---------------------------------------------------------------------
  bool gProbeMode = false;
  char gJournalPath[MAX_PATH] = {};
  constexpr u32 kProbeCallsPerFunction = 4; // real calls that get extra probes
  constexpr int kMaxProbesPerCall = 256; // edge variants per real call
  constexpr int kSnapshotWords = 16; // dwords captured per pointer argument

  // Probes run only on the sim thread. The map-loader and worker threads
  // call hooked functions too (the loader alone makes far more than 10,000
  // hooked calls during blueprint load, so a call-count threshold cannot
  // tell them apart), and re-entering a function while its objects are
  // mid-construction on those threads hangs the loader. A single "first
  // thread past 60s" claim is a lottery (probe10/11: a worker won it, the
  // sim never probed; probe13: relaxing to any thread froze the game).
  // The gate is a leader election instead: every thread counts its hooked
  // calls in TLS and the hottest thread globally is the sim - it makes
  // millions of calls over a replay while loader and worker bursts are
  // transient. Only the leader, and only past the grace period, probes.
  constexpr DWORD kSimGracePeriodMs = 60000;
  constexpr u32 kLeaderMinCalls = 100000; // the loader can burst early; the sim dominates over time
  ULONGLONG gLoadTick = 0;
  volatile LONG gLeaderThreadId = 0;
  volatile LONG64 gLeaderCalls = 0;
  __declspec(thread) u64 tThreadCalls = 0;

  // The edge values one plain argument word is replaced with, one per extra
  // call: every word goes through its whole list, picked by the spec's isFloat.
  constexpr u32 kEdgeFloats[] = {
    0x00000000u, // +0.0
    0x80000000u, // -0.0
    0x00000001u, // the smallest denormal
    0x80000001u, // a negative denormal
    0x007FFFFFu, // the largest denormal
    0x00800000u, // FLT_MIN (smallest normal)
    0x3F800000u, // 1.0f
    0xBF800000u, // -1.0f
    0x3F000000u, // 0.5f
    0x40000000u, // 2.0f
    0x40490FDBu, // pi
    0x2EC75305u, // 1e-10
    0x501502F9u, // 1e10
    0x4B7FFFFFu, // 2^24 - 1 (the float-exact int limit)
    0x4F000000u, // 2^31
    0x5F000000u, // 2^63
    0x7F7FFFFFu, // FLT_MAX
    0xFF7FFFFFu, // -FLT_MAX
    0x7F800000u, // +inf
    0xFF800000u, // -inf
    0x7FC00000u, // the default quiet NaN
    0xFFFFFFFFu, // a negative NaN
  };
  constexpr u32 kEdgeInts[] = {
    0x00000000u,
    0x00000001u,
    0x00000002u,
    0xFFFFFFFFu, // -1
    0xFFFFFFFEu, // -2
    0x0000007Fu,
    0x00000080u,
    0x000000FFu,
    0x00000100u,
    0x00007FFFu,
    0x00008000u,
    0x0000FFFFu,
    0x00010000u,
    0x7FFFFFFFu, // INT_MAX
    0x80000000u, // INT_MIN
    0x80000001u, // INT_MIN + 1
  };
  constexpr u64 kEdgeDoubles[] = {
    0x0000000000000000ull, // +0.0
    0x8000000000000000ull, // -0.0
    0x0000000000000001ull, // the smallest denormal
    0x3FF0000000000000ull, // 1.0
    0xBFF0000000000000ull, // -1.0
    0x3FE0000000000000ull, // 0.5
    0x400921FB54442D18ull, // pi
    0x7FEFFFFFFFFFFFFFull, // DBL_MAX
    0x7FF0000000000000ull, // +inf
    0xFFF0000000000000ull, // -inf
    0x7FF8000000000000ull, // the default quiet NaN
  };
  constexpr u64 kEdgeInt64s[] = {
    0x0000000000000000ull,
    0x0000000000000001ull,
    0xFFFFFFFFFFFFFFFFull,
    0x000000007FFFFFFFull,
    0x0000000080000000ull,
    0x7FFFFFFFFFFFFFFFull,
    0x8000000000000000ull,
  };

  void ProbeWrite(const char* text, const int length)
  {
    if (gOut == nullptr) {
      return;
    }
    EnterCriticalSection(&gWriterLock);
    std::fwrite(text, 1, static_cast<std::size_t>(length), gOut);
    // Flush eagerly: a probe that kills the process past its handler must
    // not lose the P lines already written (the journal skip-list alone
    // would hide what the faulting function produced).
    if (++gLinesSinceFlush >= 4u) {
      std::fflush(gOut);
      gLinesSinceFlush = 0;
    }
    LeaveCriticalSection(&gWriterLock);
  }

  // A pointer argument's snapshot: the first kSnapshotWords dwords behind
  // the pointer, best effort (an unreadable page yields FFFFFFFF words, the
  // same marker the x87 empty-st0 path uses).
  void SnapshotPointer(const u32 pointer, u32* words)
  {
    for (int w = 0; w < kSnapshotWords; ++w) {
      words[w] = 0xFFFFFFFFu;
    }
    if (pointer == 0u || pointer < 0x10000u || pointer >= 0x80000000u) {
      return;
    }
    __try {
      const volatile u32* src = reinterpret_cast<const volatile u32*>(pointer);
      for (int w = 0; w < kSnapshotWords; ++w) {
        words[w] = src[w];
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      // Partial snapshot; the untouched slots stay FFFFFFFF.
    }
  }

  // The frame one probe calls through: the real call's registers and stack
  // arguments with one argument replaced by an edge value. Lives on the probing
  // thread's stack. The offsets are the invoker's.
  struct ProbeFrame
  {
    u32 regs[7];    // +0: eax ecx edx ebx esi edi ebp (RegisterValue order)
    u32 target;     // +28: the hook's trampoline
    u32 retKind;    // +32: the spec's result kind
    u32 resultEdx;  // +36: filled by the invoker
    u32 resultEax;  // +40
    u32 resultSt0[2]; // +44: a float in [0], a double in [0..1]
    u32 stackArgs[kProbeStackWords]; // +52
    u32 savedEsp;   // +116
    u32 fcw;        // +120: the game's control word at the real call's entry
    u32 mxcsr;      // +124
  };
  static_assert(sizeof(ProbeFrame) == 128);

  extern "C" void ProbeInvoke(); // the naked invoker, defined below

  using ProbeFn = void(__cdecl*)(ProbeFrame*);
  ProbeFn gProbeInvoke = nullptr;

  // The frame of the probe running on this thread. No register survives the
  // callee for certain (retail's register conventions are its own, and every
  // register but esp is an input), so the invoker reads this after the call.
  __declspec(thread) ProbeFrame* tCurrentProbeFrame = nullptr;
  // Set while a probe runs: hooked callees it reaches are the probe's, not the
  // game's, so they leave the call table alone and start no probes themselves.
  __declspec(thread) bool tInProbe = false;

  // Journal: "<va> <probesDone> <state> <writes>" per line. State 1 = skip:
  // its probes were running when this was written (still 1 on disk means the
  // process died inside them), or re-calling it with its own arguments faulted.
  void JournalWrite()
  {
    if (gJournalPath[0] == '\0') {
      return;
    }
    EnterCriticalSection(&gWriterLock); // the journal thread writes this file too
    char tmp[MAX_PATH + 8];
    std::snprintf(tmp, sizeof(tmp), "%s.tmp", gJournalPath);
    std::FILE* f = std::fopen(tmp, "wb");
    if (f == nullptr) {
      LeaveCriticalSection(&gWriterLock);
      return;
    }
    for (const Hook& h : gHooks) {
      if (h.probeBudget == 0) {
        continue; // not probeable: never journalled
      }
      const int state = h.probeEnabled ? 0 : 1;
      std::fprintf(
        f, "0x%08X %ld %d %d\n", h.va, h.probesDone, state,
        static_cast<int>(h.writes)
      );
    }
    std::fclose(f);
    MoveFileExA(tmp, gJournalPath, MOVEFILE_REPLACE_EXISTING);
    LeaveCriticalSection(&gWriterLock);
  }

  void JournalRead()
  {
    if (gJournalPath[0] == '\0') {
      return;
    }
    std::FILE* f = std::fopen(gJournalPath, "rb");
    if (f == nullptr) {
      return;
    }
    char line[128];
    while (std::fgets(line, sizeof(line), f) != nullptr) {
      u32 va = 0;
      long done = 0;
      int state = 0;
      if (std::sscanf(line, "%x %ld %d", &va, &done, &state) != 3) {
        continue;
      }
      for (Hook& h : gHooks) {
        if (h.va == va) {
          h.probesDone = done;
          if (state != 0) {
            h.probeEnabled = false; // faulted or died last time: skip
          }
          break;
        }
      }
    }
    std::fclose(f);
  }

  [[nodiscard]] u32 CanonicalFloat(const u32 bits)
  {
    return ((bits & 0x7F800000u) == 0x7F800000u && (bits & 0x007FFFFFu) != 0u) ? 0x7FC00000u : bits;
  }

  void CanonicalDouble(u32* words)
  {
    if ((words[1] & 0x7FF00000u) == 0x7FF00000u && ((words[1] & 0x000FFFFFu) != 0u || words[0] != 0u)) {
      words[1] = 0x7FF80000u;
      words[0] = 0u;
    }
  }

  // One re-call under the guard. Returns the exception code, 0 when it returned.
  DWORD ProbeOnce(ProbeFrame* const pf)
  {
    const int depth = tDepth;
    tCurrentProbeFrame = pf;
    tInProbe = true;
    DWORD faultCode = 0;
    __try {
      gProbeInvoke(pf);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      faultCode = GetExceptionCode();
      tDepth = depth; // the hooked callees the fault unwound never reached their exits
      __asm fninit // PostEntry's fxrstor puts the game's state back
    }
    tInProbe = false;
    return faultCode;
  }

  // Appends the result of the frame's last call to a line.
  int AppendResult(char* out, const std::size_t size, int n, const Hook& hook, const ProbeFrame& pf)
  {
    u32 result[2] = {pf.resultEax, pf.resultEdx};
    int resultWords = 0;
    switch (hook.ret) {
      case kRetEax:
      case kRetEaxPointer: resultWords = 1; break;
      case kRetEdxEax: resultWords = 2; break;
      case kRetAl: result[0] &= 0xFFu; resultWords = 1; break;
      case kRetAx: result[0] &= 0xFFFFu; resultWords = 1; break;
      case kRetSt0Float:
      case kRetXmm0Float:
        result[0] = CanonicalFloat(pf.resultSt0[0]);
        resultWords = 1;
        break;
      case kRetSt0Double:
        result[0] = pf.resultSt0[0];
        result[1] = pf.resultSt0[1];
        CanonicalDouble(result);
        resultWords = 2;
        break;
      default: break;
    }
    for (int i = 0; i < resultWords; ++i) {
      n += std::snprintf(out + n, size - n, " %08X", result[i]);
    }
    return n;
  }

  int AppendArgs(char* out, const std::size_t size, int n, const Hook& hook, const ProbeFrame& pf)
  {
    for (const ArgSpec& a : hook.args) {
      for (int w = 0; w < a.words; ++w) {
        const u32 argWord = (a.location & 0x80u) != 0u
          ? pf.stackArgs[(a.location & 0x7Fu) + w]
          : pf.regs[a.location];
        n += std::snprintf(out + n, size - n, " %08X", argWord);
      }
    }
    return n;
  }

  [[nodiscard]] u32* ArgSlot(ProbeFrame& pf, const ArgSpec& a, const int word)
  {
    return (a.location & 0x80u) != 0u ? &pf.stackArgs[(a.location & 0x7Fu) + word] : &pf.regs[a.location];
  }

  // Runs on the sim thread inside OnExit, after the real call completed and
  // its result was recorded. The game's state is exactly what the real call
  // left, and the probes re-enter the function through its trampoline: once
  // with its own arguments (variant -1, which must return the real result, or
  // the re-call itself is wrong), then with each edge value in place of one
  // plain argument. Guarded per probe: a fault is recorded as the variant's
  // result instead of killing the run.
  void RunProbes(
    Hook& hook, const CapturedCall& captured, const u32 callIndex, const u32* realResult,
    const int realResultWords
  )
  {
    ProbeFrame frame{};
    ProbeFrame* const pf = &frame;
    std::memcpy(pf->regs, captured.regs, sizeof(pf->regs));
    std::memcpy(pf->stackArgs, captured.args, sizeof(pf->stackArgs));
    pf->target = reinterpret_cast<u32>(hook.trampoline);
    pf->retKind = hook.ret;
    pf->fcw = captured.fcw;
    pf->mxcsr = captured.mxcsr;

    // Snapshot every unhashed (pointer) argument before the probes.
    u32 preSnaps[4][kSnapshotWords];
    int snapIndex[4] = {0, 0, 0, 0};
    u32 snapPointer[4] = {0, 0, 0, 0};
    u32 snapCount = 0;
    for (std::size_t i = 0; i < hook.args.size(); ++i) {
      if (hook.args[i].hashed != 0u || snapCount >= 4) {
        continue;
      }
      snapPointer[snapCount] = *ArgSlot(*pf, hook.args[i], 0);
      snapIndex[snapCount] = static_cast<int>(i);
      SnapshotPointer(snapPointer[snapCount], preSnaps[snapCount]);
      ++snapCount;
    }

    char out[2048];
    int n = std::snprintf(out, sizeof(out), "R 0x%08X %u", hook.va, callIndex);
    n = AppendArgs(out, sizeof(out), n, hook, *pf);
    n += std::snprintf(out + n, sizeof(out) - n, " ->");
    for (int i = 0; i < realResultWords; ++i) {
      n += std::snprintf(out + n, sizeof(out) - n, " %08X", realResult[i]);
    }
    n += std::snprintf(out + n, sizeof(out) - n, "\n");
    ProbeWrite(out, n);

    // One variant: the frame as it stands.
    int variant = -1;
    const auto runVariant = [&]() -> DWORD {
      int m = std::snprintf(out, sizeof(out), "P 0x%08X %u %d", hook.va, callIndex, variant);
      m = AppendArgs(out, sizeof(out), m, hook, *pf);
      m += std::snprintf(out + m, sizeof(out) - m, " ->");
      const DWORD faultCode = ProbeOnce(pf);
      if (faultCode != 0) {
        InterlockedIncrement(&hook.faults);
        m += std::snprintf(out + m, sizeof(out) - m, " F%08lX", faultCode);
      } else {
        m = AppendResult(out, sizeof(out), m, hook, *pf);
      }
      m += std::snprintf(out + m, sizeof(out) - m, "\n");
      ProbeWrite(out, m);
      ++variant;
      return faultCode;
    };

    // The function's own arguments first. If that faults, an edge value
    // proves nothing and the function stays skipped.
    const bool baselineFaulted = runVariant() != 0;

    for (const ArgSpec& a : hook.args) {
      if (baselineFaulted || a.hashed == 0u || variant >= kMaxProbesPerCall) {
        continue;
      }
      if (a.words == 2) {
        u32* const low = ArgSlot(*pf, a, 0);
        u32* const high = ArgSlot(*pf, a, 1);
        const u32 savedLow = *low;
        const u32 savedHigh = *high;
        const u64* const list = a.isFloat != 0u ? kEdgeDoubles : kEdgeInt64s;
        const int count = a.isFloat != 0u ? static_cast<int>(sizeof(kEdgeDoubles) / sizeof(u64))
                                          : static_cast<int>(sizeof(kEdgeInt64s) / sizeof(u64));
        for (int e = 0; e < count && variant < kMaxProbesPerCall; ++e) {
          *low = static_cast<u32>(list[e]);
          *high = static_cast<u32>(list[e] >> 32);
          runVariant();
        }
        *low = savedLow;
        *high = savedHigh;
        continue;
      }
      u32* const slot = ArgSlot(*pf, a, 0);
      const u32 saved = *slot;
      const u32* const list = a.isFloat != 0u ? kEdgeFloats : kEdgeInts;
      const int count = a.isFloat != 0u ? static_cast<int>(sizeof(kEdgeFloats) / sizeof(u32))
                                        : static_cast<int>(sizeof(kEdgeInts) / sizeof(u32));
      for (int e = 0; e < count && variant < kMaxProbesPerCall; ++e) {
        *slot = list[e];
        runVariant();
      }
      *slot = saved;
    }
    if (baselineFaulted) {
      hook.probeEnabled = false;
    }

    // Snapshot after: for pointer arguments, the S line with pre and post.
    for (u32 s = 0; s < snapCount; ++s) {
      u32 post[kSnapshotWords];
      SnapshotPointer(snapPointer[s], post);
      n = std::snprintf(
        out, sizeof(out), "S 0x%08X %u %d %08X pre", hook.va, callIndex, snapIndex[s], snapPointer[s]
      );
      for (int w = 0; w < kSnapshotWords; ++w) {
        n += std::snprintf(out + n, sizeof(out) - n, " %08X", preSnaps[s][w]);
      }
      n += std::snprintf(out + n, sizeof(out) - n, " post");
      for (int w = 0; w < kSnapshotWords; ++w) {
        n += std::snprintf(out + n, sizeof(out) - n, " %08X", post[w]);
      }
      n += std::snprintf(out + n, sizeof(out) - n, "\n");
      ProbeWrite(out, n);
    }
  }

  extern "C" ProbeFrame* __cdecl ProbeCurrentFrame()
  {
    return tCurrentProbeFrame;
  }

  // ProbeInvoke(ProbeFrame* f), cdecl: save the caller's registers and FPU/SSE
  // state, run the callee under the game's control word and MXCSR with the x87
  // stack empty, load every register the real call entered with, call f->target,
  // read eax/edx/st0 into the frame, and put everything back. The callee may
  // leave any register changed and pop anything (`ret N`), so after it returns
  // the frame comes back from TLS, and the exit esp from the frame.
  extern "C" __declspec(naked) void ProbeInvoke()
  {
    __asm {
      mov eax, dword ptr [esp + 4]
      push ebp
      push esi
      push edi
      push ebx
      mov ebx, eax
      mov eax, esp                    ; the esp the exit path pops from
      sub esp, 528                    ; fxsave image (512) + one slot, then aligned
      and esp, 0FFFFFFF0h
      fxsave [esp]
      mov dword ptr [esp + 512], eax
      mov dword ptr [ebx + 116], esp
      fninit
      fldcw word ptr [ebx + 120]
      ldmxcsr dword ptr [ebx + 124]
      push dword ptr [ebx + 52 + 15*4]
      push dword ptr [ebx + 52 + 14*4]
      push dword ptr [ebx + 52 + 13*4]
      push dword ptr [ebx + 52 + 12*4]
      push dword ptr [ebx + 52 + 11*4]
      push dword ptr [ebx + 52 + 10*4]
      push dword ptr [ebx + 52 + 9*4]
      push dword ptr [ebx + 52 + 8*4]
      push dword ptr [ebx + 52 + 7*4]
      push dword ptr [ebx + 52 + 6*4]
      push dword ptr [ebx + 52 + 5*4]
      push dword ptr [ebx + 52 + 4*4]
      push dword ptr [ebx + 52 + 3*4]
      push dword ptr [ebx + 52 + 2*4]
      push dword ptr [ebx + 52 + 1*4]
      push dword ptr [ebx + 52 + 0*4]
      call load_and_enter
      push eax
      push edx
      call ProbeCurrentFrame          ; integer code only: st0 stays
      mov ebx, eax
      pop edx
      pop eax
      mov dword ptr [ebx + 36], edx
      mov dword ptr [ebx + 40], eax
      cmp dword ptr [ebx + 32], 2
      je store_float
      cmp dword ptr [ebx + 32], 7
      je store_xmm0
      cmp dword ptr [ebx + 32], 3
      jne restore
      fstp qword ptr [ebx + 44]
      jmp restore
store_xmm0:
      movss dword ptr [ebx + 44], xmm0
      jmp restore
store_float:
      fstp dword ptr [ebx + 44]
restore:
      mov esp, dword ptr [ebx + 116]
      fxrstor [esp]
      mov esp, dword ptr [esp + 512]
      pop ebx
      pop edi
      pop esi
      pop ebp
      ret
load_and_enter:
      push dword ptr [ebx + 28]       ; the target, reached by the ret below
      mov eax, dword ptr [ebx + 0]
      mov ecx, dword ptr [ebx + 4]
      mov edx, dword ptr [ebx + 8]
      mov esi, dword ptr [ebx + 16]
      mov edi, dword ptr [ebx + 20]
      mov ebp, dword ptr [ebx + 24]
      mov ebx, dword ptr [ebx + 12]
      ret
    }
  }

  void HashWord(u64& h, const u32 word)
  {
    for (int i = 0; i < 4; ++i) {
      h ^= (word >> (8 * i)) & 0xFFu;
      h *= 0x100000001B3ull;
    }
  }

  void SetLock(HashSet& set)
  {
    while (InterlockedExchange(&set.lock, 1) != 0) {
      SwitchToThread();
    }
  }

  void SetUnlock(HashSet& set)
  {
    InterlockedExchange(&set.lock, 0);
  }

  void SetPut(u64* const slots, const u32 capacity, const u64 hash)
  {
    u32 at = static_cast<u32>(hash) & (capacity - 1u);
    while (slots[at] != 0u) {
      at = (at + 1u) & (capacity - 1u);
    }
    slots[at] = hash;
  }

  [[nodiscard]] bool SetKeeps(const u32 level, const u64 hash)
  {
    return level == 0u || (hash >> (64u - level)) == 0u;
  }

  // Rebuilds the table with `capacity` slots, keeping what `level` keeps.
  void SetRebuild(HashSet& set, const u32 capacity, const u32 level)
  {
    auto* const slots = static_cast<u64*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity * sizeof(u64)));
    if (slots == nullptr) {
      return; // no memory: this set stops growing, and SetInsert raises its level instead
    }
    u32 count = 0;
    for (u32 i = 0; i < set.capacity; ++i) {
      if (set.slots[i] != 0u && SetKeeps(level, set.slots[i])) {
        SetPut(slots, capacity, set.slots[i]);
        ++count;
      }
    }
    if (set.slots != nullptr) {
      HeapFree(GetProcessHeap(), 0, set.slots);
    }
    set.slots = slots;
    set.capacity = capacity;
    set.level = level;
    set.count = count;
  }

  void SetInsert(HashSet& set, u64 hash)
  {
    hash = hash != 0u ? hash : 1u; // 0 marks an empty slot
    SetLock(set);
    if (set.capacity == 0u) {
      SetRebuild(set, kFirstSetCapacity, 0u);
    }
    if (set.capacity != 0u && SetKeeps(set.level, hash)) {
      u32 at = static_cast<u32>(hash) & (set.capacity - 1u);
      while (set.slots[at] != 0u && set.slots[at] != hash) {
        at = (at + 1u) & (set.capacity - 1u);
      }
      if (set.slots[at] == 0u) {
        set.slots[at] = hash;
        ++set.count;
        if (set.count * 2u >= set.capacity) {
          const u32 before = set.capacity;
          if (before < kMaxSetSize * 2u) {
            SetRebuild(set, before * 2u, set.level);
          }
          if (set.capacity == before) {
            while (set.count * 2u >= set.capacity && set.level < 63u) {
              SetRebuild(set, set.capacity, set.level + 1u);
            }
          }
        }
      }
    }
    SetUnlock(set);
  }

  // "RSET", then for each function with calls: id, level, count, calls, recorded
  // calls, and its hashes. Written whole and renamed into place.
  void WriteSets()
  {
    if (gSetsFinal != 0) {
      return;
    }
    char tmp[MAX_PATH + 8];
    std::snprintf(tmp, sizeof(tmp), "%s.tmp", gSetsPath);
    std::FILE* f = std::fopen(tmp, "wb");
    if (f == nullptr) {
      return;
    }
    std::fwrite("RSET", 1, 4, f);
    std::vector<u64> hashes;
    for (Hook& h : gHooks) {
      const LONG64 calls = h.calls;
      if (calls == 0) {
        continue;
      }
      SetLock(h.set);
      hashes.clear();
      for (u32 i = 0; i < h.set.capacity; ++i) {
        if (h.set.slots[i] != 0u) {
          hashes.push_back(h.set.slots[i]);
        }
      }
      const u32 head[3] = {h.id, h.set.level, static_cast<u32>(hashes.size())};
      SetUnlock(h.set);
      const LONG64 counts[2] = {calls, h.recorded};
      std::fwrite(head, sizeof(u32), 3, f);
      std::fwrite(counts, sizeof(LONG64), 2, f);
      if (!hashes.empty()) {
        std::fwrite(hashes.data(), sizeof(u64), hashes.size(), f);
      }
    }
    std::fclose(f);
    MoveFileExA(tmp, gSetsPath, MOVEFILE_REPLACE_EXISTING);
  }

  void ReadWatchText(const u32 address, char* const out, const int size)
  {
    int length = 0;
    __try {
      const char* const text = reinterpret_cast<const char*>(address);
      while (length < size - 1 && ((text[length] >= 0x20 && text[length] < 0x7F) || text[length] == '\n' || text[length] == '\t')) {
        out[length] = text[length] < 0x20 ? ' ' : text[length];
        ++length;
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      length = 0;
    }
    out[length] = '\0';
  }

  u32 ReadWatchWord(const u32 address)
  {
    __try {
      return *reinterpret_cast<const u32*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return 0xFFFFFFFFu;
    }
  }

  extern "C" void __cdecl OnEntry(EntryFrame* frame)
  {
    const int hookIndex = static_cast<int>(frame->slot);
    Hook& hook = gHooks[static_cast<std::size_t>(hookIndex)];
    PendingCall& pending = tPending[tDepth < kMaxDepth ? tDepth : kMaxDepth - 1];
    ++tDepth;
    // A hooked callee of a probe is not one of the game's calls.
    const u64 call = tInProbe ? 0u : static_cast<u64>(InterlockedIncrement64(&hook.calls)) - 1u;
    if (!tInProbe) {
      ++tThreadCalls;
    }
    pending.hook = hookIndex;
    pending.callerRet = frame->callerRet;
    pending.returnSlot = reinterpret_cast<u32>(&frame->callerRet);
    if (gProbeMode && !tInProbe && hook.probeBudget != 0u && hook.probesDone < static_cast<LONG>(hook.probeBudget)) {
      CapturedCall& captured = pending.captured;
      captured.regs[0] = frame->eax;
      captured.regs[1] = frame->ecx;
      captured.regs[2] = frame->edx;
      captured.regs[3] = frame->ebx;
      captured.regs[4] = frame->esi;
      captured.regs[5] = frame->edi;
      captured.regs[6] = frame->ebp;
      std::memcpy(captured.args, frame->args, sizeof(captured.args));
      // CommonEntry changed neither: these are the game's own.
      std::uint16_t fcw = 0;
      u32 mxcsr = 0;
      __asm {
        fnstcw fcw
        stmxcsr mxcsr
      }
      captured.fcw = fcw;
      captured.mxcsr = mxcsr;
    }
    pending.sequence = static_cast<u32>(call);
    pending.hash = 0xCBF29CE484222325ull;
    pending.valueCount = 0;
    if (!gSetsMode) {
      HashWord(pending.hash, hook.va);
    }
    pending.record = gSpecMode || call < hook.recordAll || (call - hook.recordAll) % hook.thenEvery == 0u;
    for (const ArgSpec& arg : hook.args) {
      for (int w = 0; w < arg.words; ++w) {
        u32 word = (arg.location & 0x80u) != 0u ? frame->args[(arg.location & 0x7Fu) + w]
                                                : RegisterValue(frame, arg.location);
        if (!arg.hashed) {
          continue;
        }
        if (arg.isFloat && arg.words == 1) {
          word = CanonicalFloat(word);
        }
        if (!gSetsMode) {
          HashWord(pending.hash, word);
        }
        if (pending.valueCount < kMaxValueWords) {
          pending.values[pending.valueCount++] = word;
        }
      }
    }
    if (gSetsMode) {
      // In sorted order: Hex-Rays lists a retail function's register arguments
      // in its own order, which can differ from ours.
      std::sort(pending.values, pending.values + pending.valueCount);
      HashWord(pending.hash, hook.id);
      for (int i = 0; i < pending.valueCount; ++i) {
        HashWord(pending.hash, pending.values[i]);
      }
    }
    if (gSetsMode) {
      const LONG self = static_cast<LONG>(GetCurrentThreadId());
      if (hook.id == gSimEntryId) {
        if (gSimThreadId == 0) {
          InterlockedCompareExchange(&gSimThreadId, self, 0);
        }
        if (gSimBeats != 0 && call == gSimBeats && gSimThreadId == self) {
          // The sim waits, so the last write holds exactly these beats.
          gSimThreadId = -1;
          SetEvent(gLastWriteWanted);
          WaitForSingleObject(gLastWriteDone, INFINITE);
        }
      }
      pending.record = gSimThreadId == self;
      if (hook.watched && pending.record) {
        pending.text[0] = '\0';
        if (gWatchTextArg >= 0) {
          ReadWatchText(frame->args[gWatchTextArg], pending.text, sizeof(pending.text));
        }
        if (gWatchWordArg >= 0) {
          pending.pointee = ReadWatchWord(frame->args[gWatchWordArg]);
        }
      }
    }
    frame->slot = reinterpret_cast<u32>(hook.trampoline);
    frame->callerRet = reinterpret_cast<u32>(&PostEntry);
  }

  void St0Bits(const std::uint8_t* fxsave, const bool asDouble, u32* dest)
  {
    const unsigned fsw = *reinterpret_cast<const std::uint16_t*>(fxsave + 2);
    const unsigned top = (fsw >> 11) & 7u;
    if ((fxsave[4] & (1u << top)) == 0u) {
      dest[0] = dest[1] = 0xFFFFFFFFu; // st0 empty: nothing was left on the x87 stack
      return;
    }
    const std::uint8_t* const st0 = fxsave + 32; // ST0 first, 16 bytes a register
    if (asDouble) {
      __asm {
        mov eax, st0
        fld tbyte ptr [eax]
        mov eax, dest
        fstp qword ptr [eax]
      }
      CanonicalDouble(dest);
    } else {
      __asm {
        mov eax, st0
        fld tbyte ptr [eax]
        mov eax, dest
        fstp dword ptr [eax]
      }
      dest[0] = CanonicalFloat(dest[0]);
    }
  }

  extern "C" void __cdecl OnExit(ExitFrame* frame, const std::uint8_t* fxsave)
  {
    // The call this return belongs to: entries above it were left by frames
    // that an exception or a longjmp unwound without returning.
    const u32 exitStack = reinterpret_cast<u32>(&frame->slot) + 4u;
    while (tDepth > 1) {
      const PendingCall& top = tPending[tDepth - 1 < kMaxDepth ? tDepth - 1 : kMaxDepth - 1];
      if (top.returnSlot + 4u + gHooks[static_cast<std::size_t>(top.hook)].popBytes >= exitStack) {
        break;
      }
      --tDepth;
    }
    --tDepth;
    PendingCall& pending = tPending[tDepth < kMaxDepth ? tDepth : kMaxDepth - 1];
    frame->slot = pending.callerRet;
    Hook& hook = gHooks[static_cast<std::size_t>(pending.hook)];

    u32 result[2] = {0, 0};
    int resultWords = 0;
    switch (hook.ret) {
      case kRetEax:
      case kRetEaxPointer: result[0] = frame->eax; resultWords = 1; break;
      case kRetEdxEax: result[0] = frame->eax; result[1] = frame->edx; resultWords = 2; break;
      case kRetAl: result[0] = frame->eax & 0xFFu; resultWords = 1; break;
      case kRetAx: result[0] = frame->eax & 0xFFFFu; resultWords = 1; break;
      case kRetXmm0Float:
        result[0] = CanonicalFloat(*reinterpret_cast<const u32*>(fxsave + 160)); // XMM0 in the image
        resultWords = 1;
        break;
      case kRetSt0Float: St0Bits(fxsave, false, result); resultWords = 1; break;
      case kRetSt0Double: St0Bits(fxsave, true, result); resultWords = 2; break;
      default: break;
    }

    if (gSetsMode) {
      if (pending.record) {
        for (int i = 0; i < resultWords; ++i) {
          HashWord(pending.hash, result[i]);
        }
        InterlockedIncrement64(&hook.recorded);
        SetInsert(hook.set, pending.hash);
        if (hook.watched) {
          std::fprintf(gWatchOut, "%08X", hook.id);
          for (int i = 0; i < pending.valueCount; ++i) {
            std::fprintf(gWatchOut, " %08X", pending.values[i]);
          }
          std::fputs(" ->", gWatchOut);
          for (int i = 0; i < resultWords; ++i) {
            std::fprintf(gWatchOut, " %08X", result[i]);
          }
          if (gWatchWordArg >= 0) {
            std::fprintf(gWatchOut, " *%08X", pending.pointee);
          }
          std::fprintf(gWatchOut, " %s\n", pending.text);
        }
      }
      return;
    }
    if (gSpecMode) {
      if (tInProbe) {
        return; // a probe's callee: neither in the table nor probed itself
      }
      for (int i = 0; hook.ret != kRetEaxPointer && i < resultWords; ++i) {
        HashWord(pending.hash, result[i]);
      }
      InterlockedExchangeAdd64(&hook.sum, static_cast<LONG64>(pending.hash));
      // The probes: a bounded number of real calls per function get extra
      // edge-value calls on the same objects, on the elected sim-thread
      // leader only, past the load grace period. The journal marks the
      // function skipped while they run, so a probe that kills the process
      // past the handler is not repeated by the next run.
      const DWORD selfId = GetCurrentThreadId();
      if (gLeaderThreadId == 0 && gProbeMode && tThreadCalls > kLeaderMinCalls
          && GetTickCount64() - gLoadTick > kSimGracePeriodMs) {
        // Claim the leadership if still open: the hottest thread reaches
        // this first, and a leader, once set, is never replaced.
        InterlockedCompareExchange(&gLeaderThreadId, static_cast<LONG>(selfId), 0);
      }
      if (gProbeMode && static_cast<DWORD>(gLeaderThreadId) == selfId && hook.probeEnabled
          && hook.probesDone < static_cast<LONG>(hook.probeBudget)
          && static_cast<LONG64>(pending.sequence) >= hook.nextProbeCall) {
        // Nested hooks reuse this pending slot during the probes.
        const CapturedCall captured = pending.captured;
        const u32 sequence = pending.sequence;
        hook.nextProbeCall = (static_cast<LONG64>(sequence) + 1) * 4;
        InterlockedIncrement(&hook.probesDone);
        hook.probeEnabled = false;
        JournalWrite();
        hook.probeEnabled = true;
        RunProbes(hook, captured, sequence, result, resultWords);
        JournalWrite();
      }
      return;
    }
    if (!pending.record || gOut == nullptr) {
      return;
    }
    char line[512];
    int n = std::snprintf(line, sizeof(line), "%s %u", hook.lineName, pending.sequence);
    for (int i = 0; i < pending.valueCount; ++i) {
      n += std::snprintf(line + n, sizeof(line) - n, " %08X", pending.values[i]);
    }
    n += std::snprintf(line + n, sizeof(line) - n, " ->");
    for (int i = 0; i < resultWords; ++i) {
      n += std::snprintf(line + n, sizeof(line) - n, " %08X", result[i]);
    }
    n += std::snprintf(line + n, sizeof(line) - n, "\n");
    EnterCriticalSection(&gWriterLock);
    std::fwrite(line, 1, static_cast<std::size_t>(n), gOut);
    if (++gLinesSinceFlush >= 2048u) {
      std::fflush(gOut);
      gLinesSinceFlush = 0;
    }
    LeaveCriticalSection(&gWriterLock);
  }

  // [esp] = hook index (pushed by the entry stub), [esp+4] = caller's return.
  extern "C" __declspec(naked) void CommonEntry()
  {
    __asm {
      pushfd
      pushad
      mov ebx, esp
      sub esp, 528
      and esp, 0FFFFFFF0h
      fxsave [esp]
      push ebx
      call OnEntry
      add esp, 4
      fxrstor [esp]
      mov esp, ebx
      popad
      popfd
      ret
    }
  }

  // Reached by the hooked function's own `ret`, with its results in place.
  extern "C" __declspec(naked) void PostEntry()
  {
    __asm {
      push 0
      pushfd
      pushad
      mov ebx, esp
      sub esp, 528
      and esp, 0FFFFFFF0h
      fxsave [esp]
      fninit // OnExit reads st0 from the image with fld; fxrstor puts the game's x87 state back
      mov eax, esp
      push eax
      push ebx
      call OnExit
      add esp, 8
      fxrstor [esp]
      mov esp, ebx
      popad
      popfd
      ret
    }
  }

  void WriteJump(std::uint8_t* at, const void* target)
  {
    at[0] = 0xE9;
    const std::int32_t rel = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(target) -
                                                       reinterpret_cast<std::intptr_t>(at + 5));
    std::memcpy(at + 1, &rel, 4);
  }

  bool LoadSpec(const char* path)
  {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
      return false;
    }
    char magic[4];
    u32 count = 0;
    const bool haveMagic = std::fread(magic, 1, 4, f) == 4;
    const bool rrs3 = haveMagic && std::memcmp(magic, "RRS3", 4) == 0;
    const bool rrs2 = rrs3 || (haveMagic && std::memcmp(magic, "RRS2", 4) == 0);
    const bool rrs1 = !rrs2 && std::memcmp(magic, "RRS1", 4) == 0;
    if ((!rrs1 && !rrs2) || std::fread(&count, 4, 1, f) != 1) {
      std::fclose(f);
      return false;
    }
    // RRS3: flags (bit 0: addresses are relative to the exe, which moves with
    // ASLR in our build), and each entry carries the id its hashes start from.
    u32 flags = 0;
    if (rrs3 && std::fread(&flags, 4, 1, f) != 1) {
      std::fclose(f);
      return false;
    }
    const u32 base = (flags & 1u) != 0u ? reinterpret_cast<u32>(GetModuleHandleW(nullptr)) : 0u;
    // Sanity: the spec generator emits a few thousand entries. A corrupt or
    // misparsed file once read count as millions, and the zero-va hook array
    // (hundreds of MB, then millions of failing installs) stalled the game's
    // loader for the whole run - reading as an unexplained hang.
    if (count == 0 || count > 20000u) {
      std::fclose(f);
      return false;
    }
    gHooks.resize(count);
    for (u32 i = 0; i < count; ++i) {
      std::uint8_t rec[9];
      if (std::fread(rec, 1, 9, f) != 9) {
        std::fclose(f);
        return false;
      }
      Hook& h = gHooks[i];
      std::memcpy(&h.va, rec, 4);
      std::uint16_t pop = 0;
      std::memcpy(&pop, rec + 4, 2);
      h.popBytes = pop;
      h.prologueBytes = rec[6];
      h.ret = rec[7];
      h.args.resize(rec[8]);
      if (rrs2 && std::fread(&h.writes, 1, 1, f) != 1) {
        std::fclose(f);
        return false;
      }
      h.id = h.va;
      h.va += base;
      if (rrs3 && std::fread(&h.id, 4, 1, f) != 1) {
        std::fclose(f);
        return false;
      }
      for (ArgSpec& a : h.args) {
        if (std::fread(&a, 1, 4, f) != 4) {
          std::fclose(f);
          return false;
        }
      }
    }
    std::fclose(f);
    return true;
  }

  void LoadValueHooks()
  {
    for (const ValueHookSpec& v : kValueHooks) {
      Hook h;
      h.va = v.va;
      h.prologueBytes = v.prologueBytes;
      h.ret = v.ret;
      h.lineName = v.name;
      h.recordAll = v.recordAll;
      h.thenEvery = v.thenEvery;
      for (int i = 0; i < v.stackWords; ++i) {
        h.args.push_back(ArgSpec{static_cast<std::uint8_t>(0x80u | i), 1, 1, 0});
      }
      gHooks.push_back(std::move(h));
    }
  }

  // Every other thread stops while the entries are rewritten, so none runs a
  // half-written jump. Nothing here may take a lock a stopped thread could hold
  // (no heap): the code buffer is allocated before.
  std::vector<HANDLE> SuspendOtherThreads()
  {
    std::vector<HANDLE> stopped;
    stopped.reserve(256);
    const DWORD self = GetCurrentThreadId();
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
      if (te.th32OwnerProcessID != pid || te.th32ThreadID == self || stopped.size() == stopped.capacity()) {
        continue;
      }
      HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
      if (t != nullptr && SuspendThread(t) != static_cast<DWORD>(-1)) {
        stopped.push_back(t);
      } else if (t != nullptr) {
        CloseHandle(t);
      }
    }
    CloseHandle(snap);
    return stopped;
  }

  bool InstallHooks()
  {
    const std::size_t count = gHooks.size();
    auto* const code = static_cast<std::uint8_t*>(
      VirtualAlloc(nullptr, 64 * count + 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    );
    if (code == nullptr) {
      return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
      Hook& hook = gHooks[i];
      auto* const target = reinterpret_cast<std::uint8_t*>(hook.va);
      std::uint8_t* const trampoline = code + 64 * i;
      std::uint8_t* const entryStub = trampoline + 32;
      std::memcpy(trampoline, target, static_cast<std::size_t>(hook.prologueBytes));
      WriteJump(trampoline + hook.prologueBytes, target + hook.prologueBytes);
      entryStub[0] = 0x68; // push imm32 (hook index)
      const u32 index = static_cast<u32>(i);
      std::memcpy(entryStub + 1, &index, 4);
      WriteJump(entryStub + 5, reinterpret_cast<const void*>(&CommonEntry));
      hook.trampoline = trampoline;
    }
    const std::vector<HANDLE> stopped = SuspendOtherThreads();
    // A stopped thread inside bytes about to be overwritten continues at the
    // same instruction in the trampoline instead.
    for (HANDLE t : stopped) {
      CONTEXT ctx{};
      ctx.ContextFlags = CONTEXT_CONTROL;
      if (!GetThreadContext(t, &ctx)) {
        continue;
      }
      for (std::size_t i = 0; i < count; ++i) {
        const Hook& hook = gHooks[i];
        if (ctx.Eip > hook.va && ctx.Eip < hook.va + static_cast<u32>(hook.prologueBytes)) {
          ctx.Eip = reinterpret_cast<u32>(hook.trampoline) + (ctx.Eip - hook.va);
          SetThreadContext(t, &ctx);
          break;
        }
      }
    }
    for (std::size_t i = 0; i < count; ++i) {
      const Hook& hook = gHooks[i];
      auto* const target = reinterpret_cast<std::uint8_t*>(hook.va);
      DWORD old = 0;
      if (VirtualProtect(target, static_cast<SIZE_T>(hook.prologueBytes), PAGE_EXECUTE_READWRITE, &old)) {
        WriteJump(target, code + 64 * i + 32);
        for (int b = 5; b < hook.prologueBytes; ++b) {
          target[b] = 0xCC; // the rest of the copied prologue is never executed in place
        }
        VirtualProtect(target, static_cast<SIZE_T>(hook.prologueBytes), old, &old);
      }
    }
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    for (HANDLE t : stopped) {
      ResumeThread(t);
      CloseHandle(t);
    }
    return true;
  }

  void WriteTable()
  {
    char tmp[MAX_PATH + 8];
    std::snprintf(tmp, sizeof(tmp), "%s.tmp", gOutPath);
    std::FILE* f = std::fopen(tmp, "wb");
    if (f == nullptr) {
      return;
    }
    std::fprintf(f, "# retail call recorder: va calls sum (FNV-1a 64 per call over hashed arguments and result)\n");
    for (const Hook& h : gHooks) {
      const LONG64 calls = h.calls;
      if (calls != 0) {
        std::fprintf(f, "0x%08X %lld %016llX\n", h.va, calls, static_cast<unsigned long long>(h.sum));
      }
    }
    std::fclose(f);
    MoveFileExA(tmp, gOutPath, MOVEFILE_REPLACE_EXISTING);
  }

  DWORD WINAPI TableWriter(void*)
  {
    for (;;) {
      Sleep(10000);
      WriteTable();
    }
  }

  // Our headless ends in TerminateProcess, which skips DLL_PROCESS_DETACH, so the
  // exe's import of it writes the sets first. Without this a run loses whatever
  // it did after the writer thread's last pass.
  using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
  TerminateProcessFn gRealTerminateProcess = nullptr;

  BOOL WINAPI TerminateProcessHook(HANDLE process, const UINT code)
  {
    if (process == GetCurrentProcess()) {
      WriteSets();
    }
    return gRealTerminateProcess(process, code);
  }

  void HookTerminateProcess()
  {
    auto* const base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
    const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0u) {
      return;
    }
    const void* const real = reinterpret_cast<const void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TerminateProcess")
    );
    const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name != 0u; ++desc) {
      auto* slot = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
      for (; slot->u1.Function != 0u; ++slot) {
        if (reinterpret_cast<const void*>(slot->u1.Function) != real) {
          continue;
        }
        gRealTerminateProcess = reinterpret_cast<TerminateProcessFn>(slot->u1.Function);
        DWORD old = 0;
        if (VirtualProtect(&slot->u1.Function, sizeof(slot->u1.Function), PAGE_READWRITE, &old)) {
          slot->u1.Function = reinterpret_cast<DWORD>(&TerminateProcessHook);
          VirtualProtect(&slot->u1.Function, sizeof(slot->u1.Function), old, &old);
        }
        return;
      }
    }
  }

  // The launcher ends the game from outside 12 s after the replay is over, which
  // HookTerminateProcess cannot see, so a longer period loses the replay's last calls.
  DWORD WINAPI SetsWriter(void*)
  {
    for (;;) {
      const bool last = WaitForSingleObject(gLastWriteWanted, 10000) == WAIT_OBJECT_0;
      WriteSets();
      if (last) {
        gSetsFinal = 1;
        if (gWatchOut != nullptr) {
          std::fflush(gWatchOut);
        }
        if (gEndAtSimBeats) {
          TerminateProcess(GetCurrentProcess(), 0);
        }
        SetEvent(gLastWriteDone);
        return 0;
      }
    }
  }

  DWORD WINAPI JournalWriter(void*)
  {
    for (;;) {
      Sleep(10000);
      JournalWrite();
    }
  }

  // Probe-mode startup, after LoadSpec succeeded.
  void ProbeStartup()
  {
    gLoadTick = GetTickCount64();
    GetEnvironmentVariableA("RETAIL_RECORDER_JOURNAL", gJournalPath, MAX_PATH);
    JournalRead();
    gProbeInvoke = reinterpret_cast<ProbeFn>(&ProbeInvoke);
    gOut = gOutPath[0] != '\0' ? std::fopen(gOutPath, "wb") : nullptr;
    if (gOut != nullptr) {
      std::fprintf(
        gOut,
        "# retail call recorder probe: real call then re-calls on the same objects\n"
        "# R <va> <call> <arg words> -> <result words> (the real call)\n"
        "# P <va> <call> <variant> <arg words> -> <result words or F<code>> (variant -1: its own arguments)\n"
        "# S <va> <call> <argIndex> <pointer> pre <words> post <words> (pointer-argument snapshots)\n"
      );
      std::fflush(gOut);
    }
    for (Hook& h : gHooks) {
      // Only probe-safe functions with placed arguments and a plain value
      // to replace get probes; the rest only record the table.
      if (h.writes == 0u && !h.args.empty() && h.probeEnabled) {
        bool anyHashed = false;
        for (const ArgSpec& a : h.args) {
          if (a.hashed != 0u) {
            anyHashed = true;
            break;
          }
        }
        h.probeBudget = anyHashed ? kProbeCallsPerFunction : 0;
      }
    }
  }
} // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
  if (reason == DLL_PROCESS_ATTACH) {
    InitializeCriticalSection(&gWriterLock);
    GetEnvironmentVariableA("RETAIL_RECORDER_OUT", gOutPath, MAX_PATH);
    char specPath[MAX_PATH] = {};
    gSpecMode = GetEnvironmentVariableA("RETAIL_RECORDER_SPEC", specPath, MAX_PATH) != 0;
    gSetsMode = gSpecMode && GetEnvironmentVariableA("RETAIL_RECORDER_SETS", gSetsPath, MAX_PATH) != 0;
    if (gSetsMode) {
      char simEntry[16] = {};
      GetEnvironmentVariableA("RETAIL_RECORDER_SIM_ENTRY", simEntry, sizeof(simEntry));
      gSimEntryId = std::strtoul(simEntry, nullptr, 16);
      char simBeats[16] = {};
      GetEnvironmentVariableA("RETAIL_RECORDER_SIM_BEATS", simBeats, sizeof(simBeats));
      gSimBeats = std::strtoull(simBeats, nullptr, 10);
      gEndAtSimBeats = GetEnvironmentVariableA("RETAIL_RECORDER_END_AT_SIM_BEATS", nullptr, 0) != 0;
      gLastWriteWanted = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      gLastWriteDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    if (gSpecMode) {
      if (!LoadSpec(specPath)) {
        return TRUE; // no hooks: the game runs as it is
      }
      gProbeMode = GetEnvironmentVariableA("RETAIL_RECORDER_PROBE", nullptr, 0) != 0;
      if (gProbeMode) {
        ProbeStartup();
      }
    } else {
      LoadValueHooks();
      if (gOutPath[0] != '\0') {
        gOut = std::fopen(gOutPath, "wb");
      }
      if (gOut != nullptr) {
        std::fprintf(gOut, "# retail call recorder: ForgedAlliance.exe calls, faf_math_dump values format\n");
        std::fflush(gOut);
      }
    }
    char watchPath[MAX_PATH] = {};
    if (gSetsMode && GetEnvironmentVariableA("RETAIL_RECORDER_WATCH", watchPath, MAX_PATH) != 0) {
      gWatchOut = std::fopen(watchPath, "w");
      char watchIds[256] = {};
      GetEnvironmentVariableA("RETAIL_RECORDER_WATCH_IDS", watchIds, sizeof(watchIds));
      char watchArg[16] = {};
      if (GetEnvironmentVariableA("RETAIL_RECORDER_WATCH_TEXT_ARG", watchArg, sizeof(watchArg)) != 0) {
        gWatchTextArg = std::atoi(watchArg);
      }
      if (GetEnvironmentVariableA("RETAIL_RECORDER_WATCH_WORD_ARG", watchArg, sizeof(watchArg)) != 0) {
        gWatchWordArg = std::atoi(watchArg);
      }
      for (const char* at = watchIds; *at != '\0';) {
        char* end = nullptr;
        const u32 id = std::strtoul(at, &end, 16);
        for (Hook& h : gHooks) {
          h.watched = h.watched || h.id == id;
        }
        at = *end == ',' ? end + 1 : end;
        if (end == at && *at != '\0') {
          break;
        }
      }
    }
    InstallHooks();
    if (gSetsMode) {
      HookTerminateProcess();
      CreateThread(nullptr, 0, &SetsWriter, nullptr, 0, nullptr);
    } else if (gSpecMode && gOutPath[0] != '\0') {
      CreateThread(nullptr, 0, &TableWriter, nullptr, 0, nullptr);
    }
    if (gProbeMode && gJournalPath[0] != '\0') {
      CreateThread(nullptr, 0, &JournalWriter, nullptr, 0, nullptr);
    }
  } else if (reason == DLL_PROCESS_DETACH) {
    if (gSetsMode) {
      WriteSets();
    } else if (gSpecMode && gOutPath[0] != '\0') {
      WriteTable();
    }
    if (gProbeMode) {
      JournalWrite();
      if (gOut != nullptr) {
        std::fflush(gOut);
      }
    } else if (gOut != nullptr) {
      std::fflush(gOut);
    }
  }
  return TRUE;
}

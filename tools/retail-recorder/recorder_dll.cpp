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
//   otherwise: the built-in kValueHooks, written call by call to
//     RETAIL_RECORDER_OUT in faf_math_dump's values format.
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
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
  };

  struct ArgSpec
  {
    std::uint8_t location; // register index (eax ecx edx ebx esi edi ebp), or 0x80 | stack dword
    std::uint8_t words;
    std::uint8_t hashed;
    std::uint8_t isFloat;
  };

  struct Hook
  {
    u32 va = 0;
    int prologueBytes = 0;
    u32 popBytes = 0;
    std::uint8_t ret = kRetNone;
    std::vector<ArgSpec> args;
    const char* lineName = nullptr; // values mode: the difffuzz row name
    u32 recordAll = 0;
    u32 thenEvery = 1;
    std::uint8_t* trampoline = nullptr;
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
  struct PendingCall
  {
    int hook;
    u32 callerRet;
    u32 returnSlot; // address of the caller's return address: matches the exit even after an unwind
    bool record;
    u32 sequence;
    u64 hash;
    int valueCount;
    u32 values[kMaxValueWords];
  };
  constexpr int kMaxDepth = 512;
  __declspec(thread) PendingCall tPending[kMaxDepth];
  __declspec(thread) int tDepth = 0;

  CRITICAL_SECTION gWriterLock;
  std::FILE* gOut = nullptr;
  char gOutPath[MAX_PATH] = {};
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

  [[nodiscard]] u32 CanonicalFloat(const u32 bits)
  {
    return ((bits & 0x7F800000u) == 0x7F800000u && (bits & 0x007FFFFFu) != 0u) ? 0x7FC00000u : bits;
  }

  void HashWord(u64& h, const u32 word)
  {
    for (int i = 0; i < 4; ++i) {
      h ^= (word >> (8 * i)) & 0xFFu;
      h *= 0x100000001B3ull;
    }
  }

  extern "C" void __cdecl OnEntry(EntryFrame* frame)
  {
    const int hookIndex = static_cast<int>(frame->slot);
    Hook& hook = gHooks[static_cast<std::size_t>(hookIndex)];
    PendingCall& pending = tPending[tDepth < kMaxDepth ? tDepth : kMaxDepth - 1];
    ++tDepth;
    const u64 call = static_cast<u64>(InterlockedIncrement64(&hook.calls)) - 1u;
    pending.hook = hookIndex;
    pending.callerRet = frame->callerRet;
    pending.returnSlot = reinterpret_cast<u32>(&frame->callerRet);
    pending.sequence = static_cast<u32>(call);
    pending.hash = 0xCBF29CE484222325ull;
    pending.valueCount = 0;
    HashWord(pending.hash, hook.va);
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
        HashWord(pending.hash, word);
        if (pending.valueCount < kMaxValueWords) {
          pending.values[pending.valueCount++] = word;
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
      if ((dest[1] & 0x7FF00000u) == 0x7FF00000u && ((dest[1] & 0x000FFFFFu) != 0u || dest[0] != 0u)) {
        dest[1] = 0x7FF80000u;
        dest[0] = 0u;
      }
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
      case kRetEax: result[0] = frame->eax; resultWords = 1; break;
      case kRetEdxEax: result[0] = frame->eax; result[1] = frame->edx; resultWords = 2; break;
      case kRetSt0Float: St0Bits(fxsave, false, result); resultWords = 1; break;
      case kRetSt0Double: St0Bits(fxsave, true, result); resultWords = 2; break;
      default: break;
    }

    if (gSpecMode) {
      for (int i = 0; i < resultWords; ++i) {
        HashWord(pending.hash, result[i]);
      }
      InterlockedExchangeAdd64(&hook.sum, static_cast<LONG64>(pending.hash));
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
    if (std::fread(magic, 1, 4, f) != 4 || std::memcmp(magic, "RRS1", 4) != 0 || std::fread(&count, 4, 1, f) != 1) {
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
} // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
  if (reason == DLL_PROCESS_ATTACH) {
    InitializeCriticalSection(&gWriterLock);
    GetEnvironmentVariableA("RETAIL_RECORDER_OUT", gOutPath, MAX_PATH);
    char specPath[MAX_PATH] = {};
    gSpecMode = GetEnvironmentVariableA("RETAIL_RECORDER_SPEC", specPath, MAX_PATH) != 0;
    if (gSpecMode) {
      if (!LoadSpec(specPath)) {
        return TRUE; // no hooks: the game runs as it is
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
    InstallHooks();
    if (gSpecMode && gOutPath[0] != '\0') {
      CreateThread(nullptr, 0, &TableWriter, nullptr, 0, nullptr);
    }
  } else if (reason == DLL_PROCESS_DETACH) {
    if (gSpecMode && gOutPath[0] != '\0') {
      WriteTable();
    } else if (gOut != nullptr) {
      std::fflush(gOut);
    }
  }
  return TRUE;
}

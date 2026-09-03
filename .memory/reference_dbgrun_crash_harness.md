---
name: reference-dbgrun-crash-harness
description: Programmatic crash harness - run the engine under dbgrun.exe to get registers, symbolised all-thread stacks and memory on any fault, with no engine rebuild and no debug prints.
metadata:
  type: reference
---

**Stop adding `gpg::Logf` probes and rebuilding.** The engine can be run under a
real debugger that dumps everything on a fault. Two rebuild+run cycles of
printf-chasing is strictly worse, and worse still: printing perturbs heap layout,
which hides the corruption bugs (proved - see
[[project-game-clock-and-verifychecksum-smash]], where replacing `operator new`
made the bug vanish).

## Use it

    <scratchpad>/dbgskirm.ps1 -Tag c1 -Map SCMP_009 -WaitSeconds 150

Writes the debugger report to `<scratchpad>/dbg_<Tag>.txt` and the ordinary game
log to `<scratchpad>/dbg_<Tag>.sclog`. Grep the report for `[EXCEPTION]`.

Underneath: `dbgrun.exe <exe> <workdir> [args...]` (source `dbgrun.cpp`, built by
`build_dbgrun.bat`). It is a real Win32 debugger loop - `DEBUG_PROCESS` +
`WaitForDebugEvent` - not a VEH inside the process, so it sees first-chance AND
second-chance faults and cannot be swallowed by the engine's own handler.

## What a fault report contains

    [EXCEPTION] ACCESS_VIOLATION (0xC0000005) 1st-chance at 00429C27  tid=84900
                read from address 00000035
                faulting instr: main!newlstr+0x97  [.../LuaObject.cpp:2641]
      --- registers (fault) ---
        eax=... ebx=... ecx=... edx=...   esi=... edi=... ebp=... esp=...
        eip=... eflags=... [ZF SF ...]    cs=.. ss=.. ds=.. es=.. fs=.. gs=..
        dr0..dr7 (only when a watchpoint is armed)
        at eip: <symbol + file:line>
        [mem eax/ebx/ecx/edx/esi/edi/ebp @ ..., 16 bytes]   <- only committed ones
      --- stack (fault) ---   full symbol + file:line via StackWalk64
      --- thread N ---        every OTHER thread's stack, on second chance
      [mem esp, 0x180]  [mem fault-addr]  [vq <addr>] region state/type/protect

The per-register memory rows are what identify the object an instruction was
walking - e.g. `edx=63657277` decoding to `"wrec"` proved the blueprint id
string was intact and moved the search to the string table instead.

## Other modes already in dbgrun.cpp

- `-watch <addr>` arms a DR0 write watchpoint and reports the writer's stack.
  There is a "poison" filter that only reports stores of non-heap pointers.
- Entry-point breakpoint + `InjectDll`, so a probe DLL can be loaded before the
  CRT runs any initializer.
- C++ throw reporting (`0xE06D7363`) with the throwing stack - useful for the
  "unhandled exception escaped to WinMain" class of bug.

## Added 2026-08-13

`DumpRegisters()` and `DumpAllThreadStacks()`. Before that the harness dumped a
stack and some memory but never the register file, which is why crashes kept
being chased with prints instead.

Related: [[project-startup-debugging-harness]].

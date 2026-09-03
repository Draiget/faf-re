---
name: project-game-clock-and-verifychecksum-smash
description: Game clock now runs (c0323ff publishes Sim::Sync's clock scalars). Still-open heap smash is reachable ONLY through the VerifyChecksum message path - full A/B evidence, the diagnostic harness that found it, and what is already ruled out.
metadata:
  type: project
---

**Landed `c0323ff` "Start the game clock".** Two changes:

1. `Sim::Sync` published only `mCurBeat`. Added `mCurTick`, `mAdvanced`
   (`= mAdvancedThisTick`) and `mFocusArmy` (`= mSyncFilter.focusArmy`), plus the
   beat retirement at 0x00748311..0x00748336 (`++mCurBeat`, `FlushLog()`,
   `mAdvancedThisTick = false`, `mGameOver = mGameEnded`).
2. `CClientBase::Process` appended to `mPipe` through the `Stream::Write` window
   fast path with no lock; routed through `VirtWrite` instead.

**The clock works.** `debug: Session time: ... Game time: ...` in the sclog is the
readout - grep it, do not guess. It only samples every ~10-30s, so a run that dies
at 31s shows one `00:00:00` line and that means "died early", NOT "frozen". A
surviving run reads `00:00:02` then `00:00:05`. `Sim::AdvanceBeat` ticks fine
(`curTick` 0->143); **`Sim::Logf` writes to `mLog` (a separate FILE*), not the
sclog**, so a missing `tick number` line proves nothing.

## CORRECTION (read before trusting the table below)

**`VerifyChecksum` is never actually called.** `mSimHashes` is *read* in exactly
three places in the whole tree and **written in none**, so `IsZeroDigest` is always
true and `FinalizeSyncDispatchLocked` always short-circuits. The "disable
VerifyChecksum -> corruption gone" row was a clean run by luck, not a fix - exactly
what [[project-include-order-static-init-landmine]] warns about ("runs are NOT
deterministic, never bisect on a single run"). Same for the "pipe fast path ->
VirtWrite" row: that fix is correct on its own merits but did NOT stop the smash
(clock1/clock2/guard1 all still crash with it in).

Two further exclusions, both solid:

- **Pipe chunks are innocent.** Backed every `PipeStreamBuffer` with a trailing
  `PAGE_NOACCESS` guard page (temporary `operator new`/`delete` using `VirtualAlloc`,
  object placed so `mData` ends exactly on the guard boundary). Ran to the usual
  crash: **the guard never faulted**, so nothing overruns a 4KB pipe chunk.
- **`Sim::AdvanceBeat` is complete.** Its tail (debug-overlay `OnTick` walk, the
  `mCurTick % 70` `lua_setgcthreshold(L, 0)` forced GC, `mDidProcess = true`) all
  matches FUN_00749F40. `Sim::UpdateChecksum` also matches FUN_0074A640 - the binary
  likewise never stores into `mSimHashes` from there.
- **`EntId` lexical warnings are faithful.** The 270+ `Invalid value for EntId ...:
  number 3` warnings from `SCR_LuaBuildObject` are NOT a bug: `Moho::EntIdTypeInfo`'s
  vtable in the RTTI dump has slot 4 `GetLexical` and slot 5 `SetLexical` pointing at
  the inherited `gpg::RType` bodies, and the base `SetLexical` returns false. Retail
  rejects these too. Do not "fix" this.

## SOLVED 2026-08-13: it is NOT a stale pointer. The packet block is ALIASED.

Two findings kill the stale-pointer theory outright.

**1. The smash bytes are Lua values.** `TObject` in this fork is `{int tt; Value
value;}` (tt FIRST - Lua 5.0 order, not 5.1), 8 bytes, and `LUA_TSTRING == 4`,
`LUA_TTABLE == 5`, `LUA_TNIL == 0` (`src/sdk/lua/LuaPrimitives.h:90`). So the
signature `{+0x10: 5, +0x14: ptr, +0x18: 4, +0x1C: ptr, +0x20: 0}` is three
TObjects - a table, a string, a nil - at packet-relative 8-byte alignment, i.e.
elements 2/3/4 of a `TObject[]`. It is a Lua stack or a Table array part.

**2. Nothing touches the packet after free.** Gave `SSyncData` a class
`operator new`/`operator delete` backed by `VirtualAlloc` (one 64K region each,
address NEVER reused, `PAGE_NOACCESS` on delete) plus a VEH logging
READ/WRITE/EIP on any fault. Result: **zero faults, and the smash disappeared.**
No stale writer (no WRITE fault) and no dangling reader on our side (no READ
fault). So do not go looking for who retains an `SSyncData*` - nobody does.

The only reading left: **the CRT heap handed `new SSyncData` a block that Lua
already owned.** Two owners, one block. The packet is an innocent victim; the
corruptor is whatever frees a still-live Lua allocation (or frees a pointer it
does not own). This is almost certainly the same defect as
[[project-resize-path-and-depth-stencil]]'s "GC wild write, 8 dead hypotheses".

**With the packet out of the CRT heap the game clock demonstrably runs**
(`sk_pkt3`/`sk_aud1`, 100s, 1034-1035 beats, zero crashes):

    Session 00:00:31  Game 00:00:00      Session 00:01:02  Game 00:00:51
    Session 00:00:42  Game 00:00:16      Session 00:01:31  Game 00:01:41

That arena is a DIAGNOSTIC, not a fix - it was reverted, not committed.

## Crash B SOLVED - `34464d9` (mouse move killed the process)

Separate from the packet smash, and the more frequent of the two. Chain:
mouse move -> `wxWindowMswRuntime::HandleMouseMove` -> `ProcessEvent` ->
`DispatchPushedEventHandlersForWindow` -> `CMauiWxEventMapperRuntime::OnMouseMove`
-> `CMauiControl::PostEvent` -> `HandleEvent` -> `CreateLuaEventObject`
(`UiRuntimeTypes.cpp:24601`) -> `AssignNewTable(nullptr,...)` -> `RebindToState`
-> `Ensure(state != nullptr)` throws -> nothing on the wx path catches ->
`WinMain`'s `catch (const std::exception&)` -> `gpg::Die`.

Root cause: `luaV_execute` stashes `G->lstate` on entry and writes it back at
each `return` (the binary, FUN_00929C60, does the same at +0x44) - but our Lua
raises script errors as **C++ exceptions**, and unwinding past that frame
skipped the write-back. `lstate` was then left pointing at the raising thread,
usually a coroutine, and a coroutine's `stateUserData` is null by construction
(`luaE_newthread` zeroes it; only a `LuaState` wrapper fills it). Every later
`LuaObject::GetActiveState()` returned null. The binary cannot hit this: its
errors are a longjmp to `luaD_rawrunprotected`, so there is no unwind path
through the frame at all. Fixed with a scope guard.

The trigger on SCMP_009 is the AI archetype loader raising
`HasBuilderList (a nil value)`. **Note for future triage:** `HasBuilderList`
(`builder-manager.lua:328`) and `SessionIsReplay` are NOT missing bindings -
`HasBuilderList` is pure Lua, and `func_SessionIsReplayUser_LuaFuncDef`
registers into `scr_UserInits` only, exactly as FUN_00897D90 does. Do not
"fix" either.

**Still open after this fix:** a Lua `table index is nil` escaping unprotected
to `WinMain` (~47s). `InvokeControlScriptObjectBool` *does* catch, so the
raising call is on some other, unprotected path - find it.

### The `0x1C` crash decoded exactly (do not re-derive this)

`CUserSoundManager::UpdateSoundRequests` reads `requests.start_[i].requestType`
(`CUserSoundManager.cpp:1517-1519`); `requestType` is at `SAudioRequest+0x18`.
The AV reads `0x0000001C`, so `start_ == 4`. `mAudioRequests` sits at
packet+0x18, so `start_` is packet+0x18 and `end_` is packet+0x1C - which is
exactly the smash signature's `{+0x18: 4, +0x1C: ptr}`. That `4` is
`tt == LUA_TSTRING` and the `ptr` is the `TString*`. So:

- the packet is **NOT** destroyed early (a destroyed `FastVectorN` has
  `start_ == nullptr`, because its dtor nulls all three - that theory is dead);
- `msvc8::auto_ptr` is **NOT** double-owning (`auto_ptr(auto_ptr&)` takes
  `r.release()`, and the rvalue call site routes through `auto_ptr_ref`, which
  also releases - single delete, verified);
- the packet is simply **overwritten in place by live Lua**.

**Caution about the arena:** because it never recycles an address, it masks a
double-free just as well as it masks aliasing. Do not read "arena -> clean" as
proof the packet is a passive victim; it only proves the packet's *address* is
what the two owners collide on.

### Separate latent bug, FIXED in `cf5d327` (was not the corruptor)

All four callers of the `SpatialDB_MeshInstance` collect family passed an
inline `fastvector_n` to an API taking the `gpg::fastvector<T>` base, whose
`Reserve` frees `start_` unconditionally - so overflowing the inline capacity
called `delete[]` on a **stack** address. `DoBeat`'s ticker lane (81 slots,
refilled every beat) crosses that at ~81 units. Fixed by giving those four
sites heap-backed vectors. It did **not** stop the smash (`sk_fix1`/`sk_fix2`
still die), because a 31s run never reaches 81 units - so this was latent, not
the cause. The faithful fix is to restore the per-vector-type templates the
binary has; see the commit message.

### BOTH Lua-allocator directions are now EXCLUDED (2026-08-13)

Instrumented `luaM_realloc` (`LuaObject.cpp:12962`) - the single choke point for
all Lua memory - with a live-packet registry published from `SSyncData`'s
ctor/dtor:

1. **Overlap at allocation.** For every Lua block returned, tested it against
   all live packets. **0 hits.** Lua is never handed memory a live packet owns.
2. **Packet on a freed Lua block.** Kept a 512-entry ring of freed blocks -
   both the explicit `size == 0` path AND the implicit free when a realloc
   *moves* a block (which is the path `luaH_resize` takes for a Table's array
   part, so a retained stale array pointer would show here and nowhere else).
   Tested every new packet against the ring. **0 hits.**

So the writer does not reach the packet through `luaM_realloc` in either
direction. Either the bytes are not Lua's after all (the `{5,ptr},{4,ptr},{0}`
= table/string/nil reading is strong but circumstantial), or the writer holds a
pointer obtained some other way. **Do not re-run these two experiments.**

Next angles, untried:
- The packet's own `operator new` is the CRT's. Log the packet address and dump
  the 20 bytes at +0x10 at the moment `DoBeat` sees `start_` small; then set a
  hardware watchpoint on packet+0x18 **for that specific packet** and let it
  run to the next beat. The earlier watchpoint attempt armed the wrong packet.
- Check non-Lua writers of `{small int, pointer}` pairs. `LuaObject` is
  `{m_next, m_prev, m_state, TObject}` = 0x14 - the same 20 bytes as the smash.
  A `LuaObject` constructed at packet+0x10 would give `m_prev == 5`, which is
  implausible, but a *pair* of engine structs might fit better than TObjects.
- `CUserSoundManager::UpdateSoundRequests` reads `requests.start_[i]` with
  `i < Size()`; consider logging the whole `mAudioRequests` head at push, pop
  and at DoBeat entry to bracket exactly which of the three the smash precedes.

### Original lead, still unproven: `FastVectorN` shadows the base non-virtually

`FastVectorN<T,N> : public FastVector<T>` (FastVector.h:584). The base dtor does
an unconditional `delete[] start_` (FastVector.h:275-277); `FastVectorN` shadows
the dtor, `Grow` and `Reserve` **non-virtually**, guarding on `originalVec_`.
So any site that destroys or grows a `FastVectorN` through a `FastVector<T>&`
or `FastVector<T>*` will `delete[]` the **inline buffer** - an interior pointer
of the enclosing object. That is precisely a "free a block you do not own" bug,
and it corrupts the CRT freelist in exactly the way needed to hand one block to
two owners. Audit base-typed non-const `fastvector<T>&`/`*` parameters and any
`delete` through a base pointer. (Const base refs, e.g.
`UpdateSoundRequests(const gpg::fastvector<SAudioRequest>&)`, are safe.)

### Second, intermittent crash (~1 run in 3, same family)

`Ensure(state != nullptr, "state")` thrown from `RebindToState`
(`LuaObject.cpp:12508`) escapes to `WinMain`'s `catch (const std::exception&)`
and calls `gpg::Die("Unhandled exception:\n\n%s")`, printing just `state`. That
is a `LuaPlus` rebind with a null `LuaState*`. Symbolise it by putting
`RtlCaptureStackBackTrace(0, 24, frames, nullptr)` + `moho::PLAT_GetSymbolInfo`
in `Ensure` (`LuaObject.cpp:5702`) - that recipe worked and is cheap to redo.
Did not reproduce in two later runs, so treat it as downstream of the aliasing
until proven otherwise.

## OPEN: heap smash, triggered by the clock scalars

`CSimDriver::FinalizeSyncDispatchLocked` calls
`mMarshaller->VerifyChecksum(mSim->mSimHashes[syncBeat & 0x7F], syncBeat)`. That
call was **unreachable before this commit** - it needs `syncBeat < currentBeat`,
and `mCurBeat` never moved. With it live, one queued `SSyncData` gets 20 bytes
smashed at +0x10..+0x23, and the run dies in `CUserSoundManager::UpdateSoundRequests`
reading `0x0000001C` (= `start_[0].requestType` off a `start_` of 4).

**A/B, each one build+run:**

| Config | corruption |
|---|---|
| scalars off | none, survives 75s, clock frozen |
| scalars on | push-BAD + pop-BAD, dies ~beat 120-150 |
| scalars on, `VerifyChecksum` call `#if 0`'d | **none** |
| scalars on, `SSyncData::operator delete` a no-op (leak, never recycle) | **none** |
| scalars on, pipe fast path -> `VirtWrite` | none in one run, reproduced in another |

Signature is always `{+0x10: 5, +0x14: ptr, +0x18: 4, +0x1C: ptr, +0x20: 0}` with
`originalVec_` (+0x24) usually still correct. Two `{small int, pointer}` pairs.

**Ruled out:** `SSyncDataQueue` push/pop (new/push/pop/dtor counts balance, no
double-free); `Sim::VerifyChecksum` itself (digest always matches, early-returns);
`CDecoder::DecodeVerifyChecksum` (handled, opcode 3, not an unknown-opcode throw);
`PipeStream::DoRead` freeing the write chunk (it only frees head when `head != tail`,
and `mWriteHead` is always in the tail); `SnapshotSyncReserveCounts` (writes
`Sim::mSyncReserveCounts`, a real `int32_t[5]` member at +0xA70); checksum cadence
(`sim_ChecksumPeriod` default really is 1); `CMessage` inline buffer (64 bytes, a
23-byte checksum message never grows it).

**Next suspect, unexamined:** `CMessage::Append` -> `FastVectorN<char,64>::InsertAt`.
VerifyChecksum is the only message that appends a 16-byte range; everything else
appends <= 4 bytes. Also unexamined: `BinaryReader::ReadBytes16`.

## Dead ends already walked for the stale-pointer hunt

`CUserSoundManager` does NOT retain the request vector (its only mention of
`fastvector<SAudioRequest>` is the `UpdateSoundRequests` parameter). `Sim` has no
`SSyncData*` member at all. `Entity::Sync`, `Unit::CreateInterface/SyncInterface`,
`CCommandDb::PublishSyncData` and `QueueCreateUnitParams` all take the packet as a
parameter and are never called by our partial `Sim::Sync`. So the retainer is not
any of those - keep looking, and prefer arming the watchpoint over more reading.

## The diagnostic harness (rebuild it, it works)

All temporary, all removed before the commit; re-add from this recipe.

- **Lifecycle log**: `gpg::Logf("PKTLIFE new/push/pop/dtor %p beat=%d")` in
  `Sim::Sync` after the `new`, in `FinalizeSyncDispatchLocked` before `PushBack`,
  in `GetSyncData` after the pop, and in `~SSyncData`. Grep one packet address to
  get its whole history.
- **Lane validity check** at push and pop: `lane.start_ != lane.originalVec_ ||
  lane.end_ != lane.start_`, plus a 4-row hex dump of the packet head. This is what
  localised the window to "between the ctor and the push".
- **Hardware write watchpoint**, `SimDriver.cpp` anon namespace: `AddVectoredExceptionHandler`
  + `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + per-thread `SuspendThread` /
  `GetThreadContext(CONTEXT_DEBUG_REGISTERS)` / `Dr0 = addr`,
  `Dr7 = (Dr7 & ~0xF0000F) | 1 | (1<<16) | (3<<18)` / `ResumeThread`. Handler tests
  `ExceptionCode == EXCEPTION_SINGLE_STEP && (Dr6 & 1)`, logs `ctx->Eip`, clears Dr6,
  returns `EXCEPTION_CONTINUE_EXECUTION`. It fires correctly - verified against the
  known ctor/dtor writes - but the corrupting packet was never the armed one.
  **Arm it on the packet address right after `new SSyncData{}`, not at a fixed beat.**

Related: [[project-dobeat-keystone-chain]], [[project-lua-gc-upvalue-corruption]]
(the same "one wild write, many symptoms" shape; that one was solved by allocator
instrumentation and the recipe is written up there).

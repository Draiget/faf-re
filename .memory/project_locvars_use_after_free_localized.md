---
name: project-locvars-use-after-free-localized
description: BREAKTHROUGH 2026-09-01 — the CreateUI corruptor is a USE-AFTER-FREE of a Proto's locvars block, localized to one prototype (enhancementqueue.lua line 67). Symptoms 1 and 3 are one bug.
metadata:
  type: project
---

# The corruptor is a locvars USE-AFTER-FREE, and it is localized

Caught live under dbgrun on `/map SCMP_009`, 2026-09-01. This supersedes the
"overrun" framing in [[project_createui_corruptor_ruled_out]] — every overrun
hypothesis in that file was correctly eliminated because **it is not an
overrun.**

## The fault

    ACCESS_VIOLATION reading 0x0005C05F
      traverseproto            LuaObject.cpp:8216   (f->locvars[i].varname->marked)
      propagatemarks
      mark / luaC_collectgarbage / luaC_checkGC
      lua_setgcthreshold
      CUIManager::UpdateFrameRate   CUIManager.cpp:368
      CScApp::Main

`f->locvars[i].varname` is garbage. **That is the same array `singlevaraux`
compares against when resolving a local**, which is why symptom (1)
("nonexistent global variable AttackMoveBehavior") and symptom (3) (this GC
fault) are almost certainly one bug, not two.

## The decisive evidence: it is FREED, not overwritten

A probe in `traverseproto` that validates `varname` instead of dereferencing it
(guard on null / low address / misalignment / `tt != LUA_TSTRING`, then
`OutputDebugStringA` and `continue`) reported:

    [LOCVARDIAG] bad varname: src=@...\lua.nx2\lua\ui\notify\enhancementqueue.lua
                 idx=0/41 ptr=490FBE00 tt=134 locvars=490FBA00 line=67

`locvars[0].varname == 0x490FBE00 == locvars + 0x400`. **A block pointing at
another block in its own size class is a free-list next pointer** — the engine
allocator writes one into the head of a freed block. Later indices hold
unrelated reused data (`0x05008000`, `0x09048003`, `0x0B043ECB`, …).

So the locvars block was **freed and partly reused while the Proto still points
at it**. Meanwhile `f->source` still prints correctly and `f->sizelocvars` is
still a sane 41, so the *Proto* block itself has not been reused yet (different
size class: Proto ~0x5C bytes vs locvars 41*12 = 492).

The most consistent reading: **the Proto was collected while still reachable
from the GC's gray list**, freeing its arrays; the GC then walks the corpse in
`propagatemarks`. Premature collection, not memory damage.

## It is localized — this is the best lead the hunt has had

Exactly **one** source file and one prototype across the whole run: 9 probe
hits, all `enhancementqueue.lua`, all the same proto (`line=67`,
`locvars=490FBA00`). Everything else in the process is clean. Start there.

## Ruled out on the way (all verified against ground truth)

`close_func` (0x0091B350) shrinks locvars correctly and does not null it;
`luaM_growaux` (0x0091A310), `luaM_realloc` (0x0091A240),
`luaHelper_ReallocFunction` (0x00923F20) and `realloc_0` (0x00957B00) are all
faithful — see the chain table in [[project_createui_corruptor_ruled_out]].
So the free is not coming from the growth/shrink path.

## Probe notes for the next pass

The probe lives in `traverseproto` (`LuaObject.cpp`), **uncommitted and marked
"TEMPORARY PROBE (do not commit)"**. Its address floor of `0x00010000` is too
low: `0x0005C05A` passes it and then faults on `->tt`. Raise the floor (or
`IsBadReadPtr`-style guard) before relying on it again.

## Two experiments run — both narrow it sharply

**1. `luaF_freeproto` is NOT the freer, and the Proto is never collected.**
Instrumented every `luaF_freeproto` call to log `proto/locvars/sizelocvars/
source`, cross-referenced against `[LOCVARDIAG]` in the same run:
**5198 calls, none freed the corrupted block, and none was for
`enhancementqueue.lua` at all.** So the Lua GC never collects this Proto, and
`luaC_link` / `rootgc` / weak-table clearing / sweep are all out of the path.
The "premature collection" reading above is **wrong** — something outside the
Lua GC freed a block it does not own.

**2. A DR0 watchpoint on the block never fires, yet the block still ends up
corrupt.** `close_func` publishes the finished locvars address as
`lane8=%08X` (dbgrun arms DR0 on any `lane8=` marker it sees); it armed at
`5BE41400` on 45 threads, `[LOCVARDIAG]` then reported that exact block corrupt
10 times — and there were **zero watchpoint hits**.

Nothing writes the block after `close_func`.

**3. ANSWERED: the array is already corrupt AT `close_func`.** The
`validAtClose` probe answered by faulting rather than printing — it read
`f->locvars[i].varname == 0x008000D8` and died dereferencing it:

    ACCESS_VIOLATION reading 0x008000DC
      close_func+0x25B   LuaParser.cpp:3763   (the probe loop)
      body / funcstat / statement / chunk / luaY_parser / f_parser
      luaD_protectedparser

So the corruption happens **during parsing**, before `close_func` ever runs.
That kills the whole "something frees it later" framing: there is no later. It
also explains the watchpoint silence (armed after close_func) and the
freeproto silence (the Proto is never collected). A probe that walks locvars
must NOT dereference `varname` — check pointer range and alignment only.

Next: bisect within parsing. A probe in `luaI_registerlocalvar` that, after
each write, scans the entries so far and reports the first implausible pointer
names the exact registration during which the block goes bad.

## 4. The allocator's own lane list is corrupt — same class as the solved bug

Once `moho.IEffect` was fixed (see
[[project_commander_spawn_initializearmies_nil_binding]]) the run gets far
enough to fault somewhere new and much more diagnostic:

    ACCESS_VIOLATION
      PopLaneNode+0x21              Global.cpp:281      <- engine allocator
      malloc_0+0x154                Global.cpp:1290
      realloc_0+0x59                Global.cpp:1438
      luaHelper_ReallocFunction     LuaObject.cpp:13386
      luaM_realloc / luaD_growstack / luaD_precall / luaV_execute / resume

`PopLaneNode` popping a bad node means **the allocator's per-size-class free
lane is corrupt**, which is precisely the failure mode recorded in
[[project_lua_gc_string_table_corruption]]: "left the 28-byte lane list shorter
than its own `count` - so `TrimThreadCache` popped a null and `PushHeapBlock`
read `[0+0x20]`". That bug was one object freeing a block it never owned.

This unifies the picture. A corrupt free lane hands the same block out twice,
which is exactly how a live `Proto`'s `locvars` ends up reused while still
referenced — so the locvars symptom and this are very likely one wild free, not
two bugs. It also explains why the locvars block looked freed while nothing
observable freed it.

## THE SHARPEST EVIDENCE: the ThreadHeapCache itself is used after free

With the poison in place (offset 4 onward, `next` preserved), the fault is:

    ACCESS_VIOLATION  read from address FBFBFBFB    ecx=FBFBFBFB
      PopLaneNode+0x21     Global.cpp:281
      malloc_0 <- realloc_0 <- luaHelper_ReallocFunction
      <- luaM_realloc <- luaD_growstack

`lane.head` **is the poison value**. The poison deliberately skips offset 0, so
a poisoned block sitting on a lane would still have a valid `next` — this is not
a poisoned lane node. `lane` lives inside `ThreadHeapCache` (`lanes[44]` then
`cachedBytes`), and `lanes[N].head` for N>=1 sits at offset >=12, inside the
poisoned region. Therefore:

**The `ThreadHeapCache` block is itself freed and poisoned while still live, and
later allocations read its lanes out of freed memory.**

That unifies every earlier symptom — a corrupt lane hands the same block out
twice, which is how a live `Proto`'s locvars, a Lua `Table`'s node chain, and
the allocator's own free list all end up damaged by "one" bug.

The cache is an ordinary small block (`GetOrCreateThreadHeapCache` ->
`AllocateSmallBlocksAmount(&request, GetSmallBlockIndex(0x214), 1, true)`), so
any stray free can release it.

Ruled out so far:

- **Same-thread free** (`ptr == gThreadHeapCache` checked in `free()`): never
  fires. Not released by `free()` on its own thread.
- **`FlushCurrentThreadHeapCache`** is correct — trims, pushes the block back,
  then sets `gThreadHeapCache = kThreadCacheDisabled`.
- `ThreadCacheTlsDetachBridge` is `[[maybe_unused]]` and ODR-used by nothing, so
  on threads where it is never instantiated the cache is *leaked*, not freed —
  a leak, not this crash.

Next probe (in flight): a global registry of live cache blocks checked in
`free()` from any thread, to catch a **cross-thread** free.

## THE TOOL: poison freed blocks to make stale readers fault at the read

The single most useful thing to come out of this hunt. In the engine allocator's
`free()` small-block path, right after `PushLaneNode`:

    if (blockSize > 4u) {
        std::memset(static_cast<std::uint8_t*>(ptr) + 4, 0xFB, blockSize - 4u);
    }

Skip the first 4 bytes — that word is the lane's own `next` link and must stay
valid. Correct code never reads a freed block, so this is **inert for correct
code**. A dangling reader, though, now sees `0xFBFBFBFB` instead of plausible
recycled data, so it faults **at the read**, with a clean stack naming the
culprit, instead of wandering on and corrupting something three subsystems away.

This is what surfaced `VisionDB::TryAdd`'s null quadtree root (fixed,
`0d4a51e1`) — a bug that had been hiding behind allocator-level symptoms.

Do not read "the crash moved / went away with poison" as masking. It means the
poison changed *which* latent bug bites first, which is exactly what makes it
useful: fix the one it names, re-run, get the next.

Ran the instrumentation. Results, in order:

- **Double-free walk** (before `PushLaneNode`, scan the lane for `ptr`):
  **zero hits.** The block reaches the free lane exactly once. Not a double
  free.
- **Poison + freer stamp** (on free: `_ReturnAddress()` at +4, magic at +8,
  0xFB from +12; on alloc: verify): **zero real hits.** Nothing *writes* to a
  freed block. NOTE: gate the check on a magic you wrote yourself — the first
  pass reported a flood of `freedBy=00000000` false positives, which were fresh
  `AllocateSmallBlocksAmount` refill blocks that had never been freed and so
  were never poisoned.
- **The clue: poisoning freed blocks MAKES THE CRASH GO AWAY.** With the poison
  in place the run stops faulting in `PopLaneNode`, gets dramatically further,
  and reaches live per-frame rendering. Revert the probe and the
  `traverseproto` fault (LuaObject.cpp:8216, `locvars[i].varname->marked`)
  comes straight back.

That combination — freed once, never written after freeing, but sensitive to
what the freed bytes contain — means this is a **stale READ of freed memory**,
not a wild free and not an overrun. Something holds a pointer to a block after
it is freed and reads it; with real recycled data it takes a bad path, with
0xFB fill it happens not to.

So the earlier "wild free / double handout" framing is wrong, and a sweep for
`delete[]`-on-a-borrowed-pointer is looking for the wrong thing. The question
is **who keeps reading a freed block** — and the `close_func` evidence in (3)
says the locvars array is already stale by the end of parsing, so the holder is
plausibly something that captured `f->locvars` (or a Proto) before a realloc
moved it.

Worth re-checking with that lens: `luaM_realloc`'s shrink path returns a NEW
pointer when `newsize <= msize(block)/2` (`realloc_0`, 0x00957B00) and frees the
old one. Every caller must store the returned pointer. `close_func` does — but
any other holder of the pre-shrink pointer would be left dangling, and that is
exactly the shape of what we are seeing.

## Host caveat that blocked the follow-up

The D3D9 adapter count is not just 0-or-1: it has been observed at **4**, and in
that state runs diverge long before UI modules load. Two consecutive runs died
via `SC_PrimaryAdapter` -> `DeviceD3D9::Clear` -> `ThrowGalErrorFromHresult`,
cascading to 3000 C++ throws and `gpg::Die` at WinMain.cpp:689 — which is
symptom (5) in the list above, now explained as **host state, not our code**.
`enhancementqueue.lua` was never even loaded in those runs.

So the "5 faces" are not all one bug: at least symptom (5) is the 4-adapter
environment. Check `d3dprobe` reports **1** adapter before trusting a run to be
representative.

## A hypothesis worth testing (faf-main-f7, static reasoning only, not verified live)

Checked `luaC_link` (new objects always link onto `rootgc`, `marked=0`,
correct) and confirmed `rootgc1` is a red herring — it's thread-only
(`luaE_newthread` links there), `luaF_newproto` uses the generic
`luaC_link` path like everything else. `enhancementqueue.lua` itself has
zero weak-table usage, so a weak-value-cleared-too-early bug isn't the
mechanism for *that* file specifically.

Symptom (1) (`orders.lua`'s `AttackMoveBehavior`) and symptom (3)
(`enhancementqueue.lua`'s GC fault) may still be the same underlying class
of bug without being literally the same memory event — worth
distinguishing before assuming one fix closes both:

- Symptom (1) corrupts `FuncState::actvar[]`/the in-progress `Proto::
  locvars` of a chunk **actively being parsed** — a `Proto` reachable only
  from a local C++ variable on the parser's C call stack
  (`luaY_parser`'s `funcstate`, `body`'s `new_fs`), already linked onto
  `rootgc` via `luaF_newproto` the moment parsing of that function starts,
  but *not yet* reachable from any of `markroot`'s roots (registry,
  metatables, `mainthread`'s Lua stack) because nothing has stored a
  closure referencing it anywhere yet. If a GC cycle fires **mid-parse**
  (plausible: `new_localvar`/`luaI_registerlocalvar`/`luaM_growaux` all
  allocate, and any allocation can cross `GCthreshold`), this Proto would
  be genuinely un-marked by `markroot`+`propagatemarks` and get swept —
  matching the symptom exactly, and explaining why it's deterministic
  (whether a GC threshold crossing happens to land mid-parse-of-this-
  specific-chunk is a function of allocation counts up to that point,
  which is identical every run for the same content).
- Symptom (3) is different in kind: `enhancementqueue.lua` is a
  **complete, already-loaded module** by the time `CUIManager::
  UpdateFrameRate` triggers the GC, its table entry reachable via the
  ordinary `_G -> __modules -> module -> ModifyBuildablesForACU -> Proto`
  chain, which `traversetable`/`traverselclosure` should walk normally.
  If the freed-Proto's owner is confirmed to be *this* closure (not some
  other Proto that only shares an unlucky heap address), the mid-parse
  theory does **not** explain it, and a shared root cause would have to
  be something else entirely (e.g. a bug in how `traverselclosure`/
  `traversetable` handles this *specific* shape of nesting, or in
  `close_func`'s locvars-shrink interacting badly with something).

If the watchpoint names the freer, checking whether it fires **during
active parsing of some chunk** (mid-parse GC, supporting the symptom-1
theory) vs. during an **ordinary frame-triggered sweep with no parse in
flight** (refuting it for symptom 3, or suggesting they're two separate
bugs that happen to share a symptom family) would settle this quickly.

## Wild-free candidate sweep (faf-main-f7, 2026-09-01) — clean, do not re-run without new evidence

After the watchpoint proved the GC never frees the corrupted block (5198
`luaF_freeproto` calls, none matching), swept every `delete[] <member>`
site in `src/sdk/**` outside the container homes (`FastVector.h`'s own
internal `this->start_` cleanup excluded — that's the container's own,
correct, teardown). Checked each site's full ownership story by hand, not
just the delete call:

- `STIMap.cpp`'s `CHeightFieldTier` cluster (`DestroyHeightFieldTierRangeVariant1`,
  `ResetHeightFieldTierVectorStorage`, `ReleaseHeightFieldTierVectorStorage`,
  `ResizeHeightFieldTierVectorWithZeroTemplate`, `InsertHeightFieldTierCopies`)
  — looked exactly like the UnitAttributes precedent at first glance
  (`CHeightFieldTier` has no explicit copy ctor/operator=, relies on the
  compiler default). Both apparent hits resolved clean: every real copy
  site routes through an explicit `CopyHeightFieldTierDeep` helper before
  `push_back` (so the implicit shallow copy only ever touches
  already-independently-owned pointers), and the one `delete[]
  zeroTemplate.data1/data2.data` site frees a template that
  `ZeroHeightFieldTier` explicitly nulled first (`delete[] nullptr`,
  a no-op).
- `IAniManipulator.cpp`'s `ReallocateWatchBoneStorageForInsert` — standard
  guarded inline-vs-heap growth (`if (storage->mBegin == storage->
  mInlineStorage) { ... } else { delete[] storage->mBegin; }`), correct.
- `SConditionTriggerTypes.cpp`'s `DestroySTriggerState` — same
  guarded-inline-vs-heap pattern for `STrigger::mConditions`, correct.
- `ScrDebugWindow.cpp`'s source-page teardown — plain single-owner
  destroy-then-null, correct, and this is debug-console-only code with no
  obvious path into per-frame/per-unit logic anyway.
- `WxRuntimeTypes.cpp`'s four `wxFileConfig` group/entry array
  grow/shrink sites — all copy *pointer values* into a freshly-sized
  array via `memcpy`/loop, not the pointed-to objects, so there's no
  aliasing to double-free; standard array-of-pointers resize, correct.
  (Also this is INI-style settings storage, not obviously on the
  Lua/GC/per-frame path the corruption lives on.)

None of these are the freer. This was a first-pass grep for literal
`delete[] <expr>-><member>`/`this-><member>` shapes — it does **not**
cover `operator delete` (non-array) on a member, a bare `free()` call, or
a shallow copy whose owning side doesn't even call `delete[]` visibly
(e.g. hidden inside a destructor the grep pattern didn't match text-wise).
If the watchpoint doesn't resolve it first, those are the next shapes to
widen the sweep to.

Runtime access is gated — see [[project_d3d9_zero_adapters_is_host_not_code]].

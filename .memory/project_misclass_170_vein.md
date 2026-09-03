---
name: project-misclass-170-vein
description: 125-token vein (of an original 170) reverted to blocked by a 2026-08-13 audit - real engine code wrongly flipped external_dependency->recovered with no source. 7 landed this session, all container/template-family citations (boost::shared_ptr release x2, RB-tree iterator x1, msvc8::vector::size x2, msvc8::vector::push_back x1); 46 register_*Serializer functions identified as a rich but harder sub-vein blocked on a vtable-assignment puzzle. Good next-target pool - keep pulling std::/boost::/msvc8::-named tokens and verifying against independently-confirmed struct layouts.
metadata:
  type: project
---

## Background

A 2026-05-07 "misclass batch" flipped 170 tokens from `external_dependency`
to `recovered` reasoning "engine code is not an external import" - correct
reasoning, wrong conclusion: 154 of them got the `recovered` status with
**no source written at all**. A 2026-08-13 audit caught this and reverted
them to `blocked`, leaving a detailed note on every affected token (search
`recovered_progress.json` for the substring `"misclass batch flipped 170"`,
125 of the 154 remain at this writing). This predates and independently
confirms [[project_fake_recovered_status_contamination]] - same root
failure mode (batch status writes with no source-level check), different
incident, caught by a different session. Two contamination waves, at least.

## Landed this session (5 tokens, all citation-only - no new functions)

- **`FUN_0043FB10`** (`Moho::WeakPtr_VertexBufferD3D9::Release`) - cited on
  `CD3DVertexStream::ReleaseBufferHandle`'s `mBuffer.reset()`
  (`src/sdk/moho/render/d3d/CD3DVertexStream.cpp`). Commit `473947d`.
- **`FUN_008F38E0`** (`Moho::WeakPtr_EffectD3D9::~WeakPtr_EffectD3D9`) -
  cited on `LockWeakEffectD3D9` in `D3D9Interfaces.cpp`. Commit `57e49cc`.
- **`FUN_006E2220`** (`std::map<uint,CUnitCommand*>::Iterator::inc`) - cited
  on the already-existing `TreeSuccessor` helper in `CCommandDb.cpp`.
  Commit `7f83442`.
- **`FUN_005DB5E0`** (decompiler-misnamed `std::vector_EntityCategory::Size`;
  actually `msvc8::vector<EntityCategorySet>::size()`, 40-byte element =
  `sizeof(EntityCategorySet)`) - cited on the generic `size()` template in
  `legacy/containers/Vector.h` alongside its 4 sibling instantiations;
  genuinely invoked at `weapon->mTargetPriorities.size()` in
  `CAiAttackerImpl.cpp:1356`. Commit `08723f1`.
- (`FUN_00779C30`, found while chasing an unrelated CDecalBuffer thread,
  reverted not landed - see [[project_cdecalbuffer_tree_chain]].)

**Pattern note**: 4 of 5 landings this pass were container/template-family
citations (boost::shared_ptr release x2, RB-tree iterator x1, vector::size
x1) rather than hand-written functions - this vein is unusually rich in
"the generic implementation already exists, just needs an address
citation" cases compared to typical blocked-list targets. Worth grepping
the remaining ~120 tokens' decompiler names for `std::`/`boost::`/
`msvc8::`-shaped names before assuming any of them need a new function.

## The recipe that worked (boost::shared_ptr release lanes)

Several of the 125 are per-T instantiations of
`boost::shared_ptr<T>::~shared_ptr()`'s internal release body:
```
if (pi && !_InterlockedExchangeAdd(&pi->use_count_, 0xFFFFFFFF)) {
  pi->dispose(pi);
  if (!_InterlockedExchangeAdd(&pi->weak_count_, 0xFFFFFFFF)) pi->destroy(pi);
}
```
This is template-emission, not a callable function - it's reached wherever
a `boost::shared_ptr<T>` (the REAL Boost type, confirmed by checking the
member's declared type resolves to `boost::shared_ptr<T>`, not this
project's own `boost::SharedPtrRaw<T>` mirror - they compile to visibly
different shapes, see the CIntelGrid dead-end below) goes out of scope.
**Recipe**: find the real caller list (many, scattered - it's shared across
every use of that specific `shared_ptr<T>` instantiation), pick ANY one
already-recovered site holding a member/local of that exact type, confirm
the type resolution, and add an `Address:` citation to the nearest existing
doxygen block explaining "reached implicitly, not called directly." Do NOT
write a new function.

**Untried but likely same pattern** (didn't get to these):
`FUN_007D1CD0` (`boost::shared_ptr_CD3DBatchTexture::~shared_ptr`),
`FUN_00873780` (`boost::shared_ptr_UICommandGraph::~shared_ptr`),
`FUN_00824060` (`Moho::WeakPtr_UICommandGraph::Release`) - all three
already have citation slots reserved in `BoostWrappers.h`'s
`SharedPtrRaw<T>::release()` doxygen (see next section), suggesting they
route through the project's `SharedPtrRaw<T>` wrapper rather than real
`boost::shared_ptr<T>` - check which shape matches before citing.

## `SharedPtrRaw<T>::release()` - the OTHER citation point (untried)

`src/sdk/gpg/core/utils/BoostWrappers.h` has a project-specific
`SharedPtrRaw<T>` mirroring real `boost::shared_ptr<T>`'s raw `(px,pi)`
layout, with a generic `release()` method (line ~235) that ALREADY carries
many address citations (0x00442BD0, 0x00442C40, 0x00442C90, 0x00442F20,
0x00442FA0, 0x007D1CD0, 0x00873780, 0x00824060, 0x0053ACA0, plus
`Moho::WeakPtr_AudioEngine::Release` at 0x004D7A20). **This is the SAME
kind of citation target as the real-boost case above, but for the OTHER
wrapper** - if a misclass-170 token's caller uses `SharedPtrRaw<T>` instead
of real `boost::shared_ptr<T>`, cite it here instead. Don't confuse the two:
`SharedPtrRaw<T>::release()`'s own body just does
`px=null; pi=null; if(pi) pi->release();` (delegates onward) - it does NOT
match the inline use_count/dispose/weak_count/destroy shape. A token with
that inline shape is the REAL boost type; a token matching the
delegate-onward shape belongs to `SharedPtrRaw<T>`.

## Dead end: `FUN_005CE460` (`boost::shared_ptr_CIntelGrid::release`)

Its only caller (`FUN_005CE220` = `gpg::ReadArchive::ReadPointerShared_CIntelGrid2`,
genuinely recovered, `ArchiveSerialization.cpp`) uses `ReleaseSharedCIntelGrid`,
which calls `SharedPtrRaw<CIntelGrid>::release()` - the delegate-onward
shape, NOT matching `FUN_005CE460`'s inline dispose/destroy shape. So
`FUN_005CE460` is a real `boost::shared_ptr<CIntelGrid>` instantiation from
some OTHER, not-yet-found call site, not `ReadPointerShared_CIntelGrid2`.
Did not find the real site before time ran out on this thread - grep for
`shared_ptr<.*CIntelGrid` / `shared_ptr<moho::CIntelGrid` across `src/sdk`
excluding `ArchiveSerialization.cpp`'s `SharedPtrRaw` usage.

## RB-tree template family (RbTree.h) - same trick as CDecalBuffer

`FUN_008D8E00`/`FUN_008D8E20` (`func_TreeDecendRight`/`Left`, `rb_max`/
`rb_min` for `std::map<type_info*, ...>`) and `FUN_006E2220` (landed, see
above) are all instantiations of the generic `msvc8::detail::rb_tree<Traits>`
family in `legacy/containers/RbTree.h` - same diagnosis technique as
[[project_cdecalbuffer_tree_chain]]. `FUN_008D8E00`/`FUN_008D8E20`'s only
caller, `FUN_008DBCB0` (`std::_Tree::erase` for the `type_info*`-keyed map -
almost certainly the `gpg::TypeInfoLess`-comparatored type-preregistration
map mentioned in `Reflection.h`), is itself `blocked` ("owner and typed node
payload unresolved") - would need paired bottom-up recovery of that eraser
first. Worth doing: find where the type-preregistration map's erase path
lives (search `Reflection.cpp` for a `std::map<type_info, ...>`-shaped
member being erased from) before attempting these two.

## Hard sub-vein: 46 `register_*Serializer` functions - vtable puzzle, NOT started

`FUN_00BD4310`+45 siblings (`register_CEfxEmitterSerializer`,
`register_CUnitPatrolTaskSerializer`, `register_CRotateManipulatorSerializer`,
etc. - full list: filter `recovered_progress.json` for
`status=blocked` and note substring `"misclass batch flipped 170"` and
name starting `register_`). Each is 9-10 instructions:
```cpp
gpg::SerHelperBase::SerHelperBase(&Moho::XxxSerializer);
Moho::XxxSerializer.mDeserialize = &Moho::XxxSerializer::Deserialize;
Moho::XxxSerializer.mSerialize = &Moho::XxxSerializer::Serialize;
Moho::XxxSerializer.__vftable = &Moho::XxxSerializer::`vftable';
atexit(Moho::XxxSerializer::~XxxSerializer);
```
Looks mechanical but has a real blocker: **the manual `__vftable` field
write**. `gpg::SerHelperBase` itself is only 8 bytes (`mNext`/`mPrev`, no
vtable - confirmed by reading `Reflection.h`), so `XxxSerializer`'s OWN
vtable pointer must come from virtual methods it declares itself, NOT
inherited. The global object is a raw memory blob (its C++ constructor
never runs automatically - that's why `SerHelperBase::SerHelperBase()` is
called MANUALLY inside `register_*`), so there's no automatic path to a
`&ClassName::vftable`-style symbol the way a normally-constructed C++
global gets one for free. Two already-recovered examples show BOTH sides
of this:
  - `moho::CUnitMobileBuildTaskSerializer` (`CUnitMobileBuildTaskSerializer.cpp`,
    `register_CUnitMobileBuildTaskSerializer` at `0x00BCF890`, ALREADY
    recovered) - a REAL derived C++ class, normally constructed, register_*
    does NOT touch `__vftable` at all (the compiler already did it).
  - `Moho::CEfxEmitterSerializer` (`CEfxEmitterSerializer.cpp`, EXISTS but
    only has `Unlink*` helpers, missing `register_*`/`Deserialize`/
    `Serialize`/`cleanup_*`/bootstrap) - uses a plain anonymous-namespace
    `CEfxEmitterSerializerRuntime` struct (`{mVftable, mHelperNext,
    mHelperPrev, mLoadCallback, mSaveCallback}`, sizeof 0x14, all offsets
    verified) - i.e. someone ALREADY correctly diagnosed this exact "manual
    construction, no automatic ctor" pattern for THIS type, but never
    finished wiring it.

**Before touching any of the 46**: resolve how to obtain the real vtable
symbol for a `SerHelperBase`-derived-but-manually-constructed type. Options
to investigate: (a) the RTTI/vtable dump for `??_7CEfxEmitterSerializer@Moho@@6B@`
might reveal the class's real virtual interface, letting you declare a
genuine (if never-normally-constructed) derived class and take its vtable
address the normal way; (b) an `extern "C"` symbol declaration matching the
mangled vtable name directly, written into the raw struct's `mVftable`
field. Whichever approach wins, it needs to work for all 46 - solve it
once, then the actual registration wiring per-type is genuinely mechanical
(each type X 4 sub-functions: register_X, X::Deserialize forwarding to
X::MemberDeserialize, X::Serialize forwarding to X::MemberSerialize,
~X unlinking the SerHelperBase list node - all trivial once the vtable
question is answered). **Also check each type's `Deserialize`/`Serialize`/
destructor addresses individually before trusting them** - `CEfxEmitterSerializer`'s
own three (`0x0065E140`/`0x0065E150`/`0x00BFBDB0`) were ALSO found
fake-recovered (blank entries) this session and had to be reverted first;
expect the same for other types in this list of 46.

## Landed 6th: `FUN_00599530`, and a self-correction worth recording

`FUN_00599530` (decompiler-named `std::vector_WeakPtr_CUnitCommand::size`)
- cited on `NormalizeWeakPtrVectorInsertIndex` in `WeakPtr.h` (reached via
`CUnitCommand::AddUnit`). Commit follows this doc update.

Getting there took a genuine wrong turn worth recording: first read of the
raw asm (`mov ecx,[eax+4] ; mov eax,[eax+8] ; sub eax,ecx ; sar eax,3`)
was mis-paired against Hexrays' own GNU-libstdc++-flavored field labels
(`_M_finish`/`_M_end_of_storage`), concluding this computed
`capacityEnd - end` (remaining free slots) rather than `end - begin`
(size) - i.e. trusted the decompiler's inferred field NAMES over the
actual offsets. Cross-checking against `WeakPtrVectorRuntimeView<T>`'s
own `static_assert`-verified layout (`begin@0x04, end@0x08,
capacityEnd@0x0C`, confirmed independently via `FUN_005A0740`'s
`resize()` write pattern to the same three offsets) proved field `+4` is
`begin` and `+8` is `end`, not `end`/`capacityEnd` - so the computation
really is `end - begin`, genuine size, and the original match was right.
**Lesson for the rest of this vein**: when a raw-asm read and a decompiler
field-name read disagree, re-derive the struct layout independently (from
an existing `static_assert`, or from a sibling function's write pattern
like `resize()` here) rather than trusting either the original hypothesis
or the "correction" on faith - both were checked against ground truth here,
and it went from right to (wrongly) reverted to right again. The other 13
unlanded tokens in the `std::`/`boost::`/`msvc8::`-named shortlist (see the
query in this file's history; `FUN_005A0740` itself, `resize`, is next in
line and its struct layout is now already confirmed above) are still
unchecked - verify each one's raw asm against an independently-confirmed
struct layout, not against Hexrays' inferred names alone.

## Open lead, not landed: `FUN_005A0740` (`std::vector_WeakPtr_CUnitCommand::resize`)

Only caller: `FUN_005FB910` = the already-recovered `ReplaceWithRouteCommandsIfAny`
(`CUnitFerryTask.cpp`), which calls `CopyWeakPtrCUnitCommandVector`
(`CUnitCommandWeakPtrReflection.cpp:413`), which calls
`destination.resize(sourceSize)` - the REAL `msvc8::vector<T>::resize()`
at `Vector.h:1579`. But `FUN_005A0740`'s own asm always sets
`begin==end` (`_Mylast = _Myfirst`) after allocating, regardless of the
target size, while `Vector.h:1579`'s `resize()` correctly advances `last_`
past the newly-constructed elements. **These don't match** - `FUN_005A0740`
looks like an internal allocate-only primitive (`_Buy`-shaped: reserve
storage for N elements, leave the logical range empty for the caller to
fill), not `resize()` itself. Did not find where this primitive's logic
actually lives in the recovered source before time ran out - check
`reallocate_to` (`Vector.h:2661`) and whatever it calls internally,
particularly for the specific case of growing from an empty vector.
Not cited, not landed - leave `FUN_005A0740` blocked until this is
resolved for real; don't force a citation onto `resize()` itself, it's
provably a different computation.

## Also unresolved: `FUN_0056AFE0` (`std::map<EntId,SUnitOffsetInfo>::find`)

All 8 callers point into `CAiFormationInstance.cpp` (currently being
concurrently edited by another session - expect to need the same
minimal-hunk `git apply --cached` isolation used for the D3D9Interfaces.cpp
commit above if landing anything here). Checked one caller
(`CFormationInstance::Func6`/`FUN_005669A0`) - it calls `LaneMapFindNode`,
but that operates on `SFormationLaneUnitMap`/`SFormationLaneUnitNode`
(keyed by bare `unitEntityId`, no `SUnitOffsetInfo` value) - a different
map from this token's real `EntId -> SUnitOffsetInfo` one. Whatever member
actually holds `SUnitOffsetInfo` values (likely something like
`mUnitOffsets`) wasn't located before time ran out. Same broader vein as
[[project_entity_serializer_layout_gate]] and the `SUnitOffsetInfoSerializer`
registrar mentioned in this file's register_* section - `SUnitOffsetInfo`
keeps surfacing as a not-fully-wired type across multiple independent
threads this session.

## How to apply

Pick up either: (1) more boost::shared_ptr release-lane citations (fast,
proven recipe, several candidates listed above), or (2) solve the vtable
puzzle once and clear a meaningful chunk of the 46 registrars in one
focused pass (bigger payoff, needs the RTTI/vtable-dump investigation
first). Either way, budget time to re-verify EVERY dependency address
individually - this vein has an unusually high rate of ALSO being
fake-recovered on top of being misclass-reverted (found 4 more fakes
chasing just the CEfxEmitterSerializer thread alone).

---
name: project_cmaui_control_hierarchy_missing_cscriptobject_base
description: FIXED 2026-09-01 (faf-main-f7) — CMauiControl and 10 concrete derived widget classes never inherited CScriptObject or overrode its 2 pure virtuals; both gaps landed, tucheck-clean. NOT the confirmed cause of peer's "603 controls tick, nothing draws" render bug — investigated and most likely ruled out, see the render-dispatch analysis below.
metadata:
  type: project
---

# CMauiControl's whole widget hierarchy was missing its real CScriptObject base

Triggered by peer `faf-main-2c` asking for a narrow check ("does `Frame` really
sit at real vtable slot 13 / `+0x34`, does `CMauiBitmap` override it at a
mismatched slot") to help interpret a stuck-loading-splash symptom. The narrow
check confirmed slot 13 is correct, but surfaced something much bigger.

## What was actually wrong

`dumps/rtti_dump_all.hpp:50517` — the real binary's `CMauiControl` has 6 bases
via its flattened RTTI Base Class Array, headed by `Moho::CScriptObject`
(mdisp=0, primary base). Our recovered `class CMauiControl { public: ... }`
(`UiRuntimeTypes.h`) had **zero** base classes. See
[[feedback_thin_fake_composition_bug_class]] instance 6 for the mechanism —
this file has the full fix narrative and the render-path investigation that
grew out of it.

**All 25 real vtable slots were independently confirmed correct** — every
single one of CMauiControl's own already-recovered virtual methods
(`DoInit`@4, `Destroy`@5, `DoRender`@6, `SetHidden`@7, `IsHidden`@8,
`HitTest`@9, `DisableHitTest`@10, `IsHitTestDisabled`@11, `HandleEvent`@12,
`Frame`@13, `AcquireKeyboardFocus`@14, `AbandonKeyboardFocus`@15,
`LosingKeyboardFocus`@16, `OnKeyboardFocusChange`@17, `IsScrollable`@18,
`GetScrollValues`@19, `ScrollLines`@20, `ScrollPages`@21, `ScrollSetTop`@22,
`OnMinimized`@23, `Dump`@24) matched a real slot address exactly. Two
declared-`virtual` methods, `ClearChildren` (0x786F60) and `Render`
(0x786FA0), matched **no** slot in the real 25-entry table — they are
non-virtual in the real binary. Not devirtualized this pass (see "Left
undone" below) since peer's own analysis concluded slot shape doesn't
functionally matter for a self-consistent recompile; flagging here so the
next pass doesn't have to re-derive it.

## Second, bigger discovery: 10 concrete widget classes never override the 2 pure virtuals

`CScriptObject::GetClass()`/`GetDerivedObjectRef()` are genuinely pure
(`= 0`, vtable slots 0/1 resolve to the real `purecall()` at `0xA82547` —
verified via `FUN_00A82547.c`) whenever a class doesn't override them.
`CMauiControl` itself is correctly abstract even in the real binary (matches
— its own slots 0/1 are also purecall). But **10 concrete leaf classes** —
`CMauiBitmap`, `CMauiFrame`, `CMauiEdit`, `CMauiGroup`, `CMauiHistogram`,
`CMauiMovie`, `CMauiScrollbar`, `CMauiText`, `CMauiItemList`,
`CUIMapPreview` — are directly `new`'d (via `cfunc_InternalCreateXxxL`
Lua-exposed factories in `UiRuntimeTypes.cpp`) and **none of them had
`GetClass`/`GetDerivedObjectRef` declared anywhere**, in the header or any
`CMauiXxxTypeInfo.cpp`. This was invisible before this fix because
`CMauiControl` had no real relationship to `CScriptObject` at all, so the
compiler never checked abstractness. Once real inheritance was added, all
10 became hard `error C2259: cannot instantiate abstract class` — this
wasn't optional cleanup, it blocked compilation entirely.

Fixed by adding, per class, the exact pattern already used correctly by 5
sibling classes in this same file (`CMauiMesh`, `CMauiBorder`,
`CMauiLuaDragger`, `CUIWorldView`, `CLuaWldUIProvider`) and confirmed
byte-for-byte against ground truth for all 10 (`FUN_<addr>.c` for every
slot-0/slot-1 pair, sourced from the RTTI dump's per-class vtable listing):

```cpp
// header, inside the class body
[[nodiscard]] gpg::RType* GetClass() const override;
gpg::RRef GetDerivedObjectRef() override;
static gpg::RType* sType;
```
```cpp
// .cpp
gpg::RType* moho::ClassName::GetClass() const
{
  if (!sType) { sType = gpg::LookupRType(typeid(ClassName)); }
  return sType;
}
gpg::RRef moho::ClassName::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}
```
Plus the out-of-line `gpg::RType* moho::ClassName::sType = nullptr;` in the
existing static-definition cluster (`UiRuntimeTypes.cpp` ~line 5194, right
after `CMauiMesh::sType`).

All 20 addresses (10 classes × 2 methods) verified against
`decomp/recovery/disasm/fa_full_2026_03_26/FUN_<addr>.c` before writing —
none guessed from pattern alone: CMauiBitmap 0x77F7A0/0x77F7C0, CMauiFrame
0x796000/0x796020, CMauiEdit 0x78EC80/0x78ECA0, CMauiGroup
0x7970F0/0x797110, CMauiHistogram 0x7975F0/0x797610, CMauiMovie
0x79EC90/0x79ECB0, CMauiScrollbar 0x7A0310/0x7A0330, CMauiText
0x7A29D0/0x7A29F0, CMauiItemList 0x799050/0x799070, CUIMapPreview
0x8505E0/0x850600.

## The fix (single commit, tucheck EXITCODE=0)

1. `class CMauiControl : public CScriptObject` (was base-less).
2. `mControlStateStorage` resized `[0x118]` → `[0xE8]` — it used to model
   bytes `+0x04..+0x11B` (past a bare, non-base vtable ptr); with a real
   0x34-byte CScriptObject base sub-object now occupying `+0x00..+0x33`,
   the class's own storage starts at `+0x34`. Total object size unchanged
   (`sizeof(CMauiControl) == 0x11C` still holds) — same bytes, just no
   longer double-counted. The 3 `CMauiControl*RuntimeView` overlay structs
   (2 in the header, 1 file-local pair in the .cpp —
   `CMauiControlHierarchyRuntimeView`/`CMauiControlScriptObjectRuntimeView`,
   worth noting for next time: **grep the .cpp, not just the header**, before
   concluding a referenced view type doesn't exist) needed zero changes:
   they `reinterpret_cast` the whole object regardless of its C++ base-class
   shape, and the byte offsets they assume didn't move.
3. Constructor: `: CScriptObject()` member-init (matches ground truth's
   `Moho::CScriptObject::CScriptObject((Moho::CScriptObject *)this);` as the
   literal first statement) instead of `reinterpret_cast<CScriptObject*>(this)`
   + manual placement-new of just `cObject`/`mLuaObj`. This is not just
   style: the real `CScriptObject::CScriptObject()` also does
   `weakLinkHead_ = 0u;` and bumps the instance-counter stat — neither ran
   before. `weakLinkHead_` left as uninitialized garbage matters because
   `WeakObject::ScopedWeakLinkGuard`/`DetachAllWeakReferences` treat it as
   a live intrusive pointer chain and write through it — every `RunScript*`
   call in this class (i.e. nearly every script callback) went through that
   guard on a never-zeroed field.
4. Destructor: deleted the explicit
   `reinterpret_cast<CScriptObject*>(this)->CScriptObject::~CScriptObject();`
   tail call (whose own comment already said *why* it was there: "this
   class does not derive from CScriptObject - it overlays one"). The
   compiler now auto-chains the base dtor, matching ground truth's
   `return Moho::CScriptObject::~CScriptObject((Moho::CScriptObject *)this);`
   tail-call rendering exactly.
5. Cleaned up all `reinterpret_cast<CScriptObject*>(this)` sites *within
   CMauiControl's own methods* (14 sites across `Frame`, `DoInit`,
   `Destroy`, `OnHide`, `GetIsScrollable`, `ScrollLines/Pages/SetTop`,
   `LosingKeyboardFocus`, `OnKeyboardFocusChange`, `GetScrollValues`) to
   plain `this`/unqualified calls, now that `this` is genuinely a
   `CScriptObject*`. Deliberately did **not** touch the same pattern in
   sibling classes (`CMauiCursor`, `CMauiBitmap`, `CMauiFrame`, `CMauiEdit`
   — confirmed present via grep, ~20 more sites) — those still work
   correctly as reinterpret_casts (single inheritance, offset 0, no
   behavior change), just not idiomatic. Follow-up, not required for this
   fix's correctness.
6. The 10-class `GetClass`/`GetDerivedObjectRef` + `sType` additions above.

## Left undone, deliberately, this pass

- **`ClearChildren`/`Render` not devirtualized.** Confirmed via the real
  25-slot vtable dump that neither is virtual in the original binary
  (addresses 0x786F60/0x786FA0 appear nowhere in the slot list), and no
  derived class overrides either (grepped). Low risk, but skipped to keep
  this commit's diff scoped to what was actually load-bearing — see the
  render-dispatch analysis below for why this turned out not to matter
  anyway.
- **The 21 own-new virtuals were NOT reordered** to match real slot
  sequence (4=DoInit, 5=Destroy, ... 24=Dump per the list above). Purely a
  fidelity/documentation nicety for a self-consistent recompile — see next
  section for why.
- **`CMauiCursor`** — FIXED same session, commit `6e8521f5`. Same shape,
  smaller (CScriptObject is CMauiCursor's ONLY real base, no TDatListItem).
  One difference: its `GetClass`/`GetDerivedObjectRef` (0x78C9A0/0x78C9C0)
  weren't just undeclared, the function BODIES had never been recovered at
  all — recovered fresh from their own decompiles this pass. Its declared
  class has zero data members (real 0x58-byte layout lives entirely behind
  `CMauiCursorTextureRuntimeView`); added an explicit 0x24-byte reserved
  storage member past the new base so `sizeof(CMauiCursor) == 0x58` holds
  for real (construction already hardcodes the 0x58 allocation size
  independent of `sizeof`, so this wasn't a correctness requirement, just
  keeping the size assert honest).

## Render-dispatch analysis (peer's live blocker, NOT resolved by this fix)

Peer reported, same investigation: engine now runs a real game (Game time
advancing past 00:09:19), 603 UI controls construct and tick
(`[FRAMEDIAG]` probe: `visited=603 ticked=7` in-game), but **nothing draws**
— a window capture shows only a blue gradient, no HUD, no world. Peer's
hypothesis was that a CMauiControl vtable-shape bug could make `DoRender`
tick through the wrong slot while everything else ticks fine.

Traced the actual call chain: `CUIManager::ValidateFrame`/`RenderFrames`/
`DrawUI`/`DrawHead` (all confirmed wired into the main loop from
`WxRuntimeTypes.cpp`, not dead code) call `frame->Render()` and
`mFrames[head]->RenderChildControls(primBatcher, mask)` through a
**concrete `boost::shared_ptr<CMauiFrame>`**, not a base pointer — these
calls resolve at compile time regardless of virtual-ness, so no vtable
slot number is in play there at all. `RenderChildControls`
(`UiRuntimeTypes.cpp`) does walk `mRenderedChildren` and calls
`childControl->DoRender(primBatcher, drawMask)` through a base
`CMauiControl*` — that IS a genuine virtual dispatch — but it is resolved
entirely by our own compiler against our own compiled vtable, consistently
at both the construction site and the call site (same TU, same header, no
ODR split found). **A self-consistent recompile cannot misdispatch a
virtual call this way regardless of what slot number the original 2007
binary used**, unless something does a raw vtable-slot read
(`*(void**)obj + N*4`-style) instead of a normal C++ call — none was found
anywhere in this render path.

Conclusion, not 100% certain but well-supported: the vtable-shape fix in
this file is very unlikely to be the cause of "nothing draws." It's still
worth having landed — real RTTI/typeid correctness and the
`weakLinkHead_` initialization fix are both independently valuable and
could easily be masking or contributing to OTHER symptoms peer has chased
this session (the `newkey` collision-chain crash, allocator corruption).
**CONFIRMED by peer 2026-09-01, same session**: `ren_Ui` theory dead (a
probe on every transition never fired, stays true). Peer independently
retracted their "slots don't matter" pushback in the SAME direction as
this analysis and found no raw vtable-slot reads either. More importantly,
peer found the UI-tree build is **nondeterministic across runs of the same
binary** (603 controls tick one run, 2 controls the next, sim thread dies
outright a third) — all three downstream of ONE root cause: heap free-list
corruption. `[LANEBAD] kind=25 blockSize=768 head=00000178` — a live
768-byte block's first dword keeps getting rewritten while on the free
list; depending on WHERE the corrupted block lands next (Lua stack buffer
→ sim thread dies in `PopLaneNode`; a Lua table → GC marks a garbage
pointer in `traversetable`; elsewhere → UI Lua half-builds) determines
which symptom you see. **There is no separate "render bug" — the render
symptom IS this corruption.** Do not chase `mRenderPass`/D3D state further
on the strength of this file's earlier suggestion; that lead is retracted
in favor of the UAF hunt. See
[[project_session_runs_full_skirmish_display_blocked]] for the live
tracking of that investigation (peer has a DR0 hardware watchpoint armed
on the next reproduction).

Peer's own high-value ask, explicitly rated above continuing the Maui
sweep: **grep for the SAME shape as the `CDecoder::DecodeCells` fix**
(free a buffer, keep using it after — or free inline/SBO storage a
container still thinks it owns) on anything touching Lua buffers or a
~0x300-byte engine struct, since 768 bytes = 96 `TObject`s (a Lua stack
segment) or a `Proto` constant array. Static, grep-able, no live harness
needed — see [[project_lua_gc_string_table_corruption]] for the bug
class's established shape and the two prior confirmed instances.

## Reference

Related: [[feedback_thin_fake_composition_bug_class]] (bug class, instance
6), [[project_render_goal_first_frame_confirmed]] (earlier, DIFFERENT
render-path success — screenshot-verified main menu/cinematic, predates
peer's in-game HUD investigation, don't conflate the two).

---
name: project-maui-control-size
description: FIXED (5c233bc) - CMauiControl declared no storage so it was 4 bytes; CMauiScrollbar's IMauiDragger base landed on the weak-link head at +0x04 and every scrollbar destroyed afterwards faulted writing into .rdata.
metadata:
  type: project
---

# FIXED: destroying a scrollbar wrote a vtable address through a weak-link walk

Switching tabs in the options dialog crashed in
`CMauiControl::~CMauiControl` under `CMauiFrame::PurgeDeleted` -
`EXCEPTION_ACCESS_VIOLATION` writing to an address whose low half never
changed between runs.

## Root cause

Thin classes here declare **no** data members; all state is reached through
`*RuntimeView` overlays cast over a heap block allocated at the binary's true
size. `sizeof(CMauiControl)` was therefore **4** (vtable pointer only).

`class CMauiScrollbar : public CMauiControl, public IMauiDragger` - MSVC puts
the second base at `sizeof(CMauiControl)`, so the `IMauiDragger` sub-object
landed at **+0x04**, not the **+0x11C** `CMauiScrollbarRuntimeView` reads. And
+0x04 is `WeakObject::weakLinkHead_`, the head of this object's weak-reference
chain (`lea eax, [esi+4]` at 0x0078A729 in `CMauiControl::OnHide` pins it).

So every scrollbar construction stamped an `IMauiDragger` vtable pointer over
the chain head, and the next teardown - either the loop in `~CMauiControl` or
`ClearWeakObjectChain` in `~CScriptObject` - walked that vtable address as a
node and wrote through it. `.rdata` is read-only, hence the AV.
`DetachDraggerList` was reading the wrong 4 bytes for the same reason.

Fix: reserve the 0x118 bytes CMauiControl really owns after its vptr, with
`static_assert(sizeof(CMauiControl) == 0x11C)` and
`static_assert(sizeof(CMauiScrollbar) == 0x120)` to pin the sub-object.

## The tell, for next time

A pointer that faults on write and whose **low 16 bits are identical across
runs** is an image address (ASLR moves modules by whole 64K). Log
`GetModuleHandle(NULL)` and print the RVA; if it sits a few hundred bytes from
the object's own vptr, it *is* a vtable, and something constructed an object at
that offset. Also print `VirtualQuery`'s `Protect` - `PAGE_READONLY` means
.rdata/.text, `PAGE_READWRITE` means a legitimate global.

`CMauiScrollbar` was the only class adding a base to a Maui control; the edit
class embeds its dragger by placement-new into the overlay instead. Any new
derived class that adds bases or members is now safe.

## Unresolved: CUIWorldView's second vtable sits at +0x104

`dumps/moho_engine_rtti.json` has two `CUIWorldView@Moho` entries: the primary
(25 slots, col offset 0) and a 13-slot one at **col offset 260 = 0x104**, whose
bodies are all adjustor thunks (`mov ecx,[ecx+4]; mov eax,[ecx]; jmp [eax+N]`),
i.e. a genuine secondary sub-object.

0x104 is *inside* the 0x11C this note just pinned for `CMauiControl`, so the
two facts cannot both be read the naive way. Do not resolve this by assuming;
`CMauiScrollbar` (+0x11C dragger, asserted, runtime-verified) and `CMauiEdit`
(+0x11C click-dragger) are the two independent witnesses for 0x11C, so the
0x104 entry needs its own explanation before `CUIWorldView` is turned into a
real derived class.

Its primary vtable overrides exactly four CMauiControl slots plus the top
three: slot 6 DoRender (`sub_10433940` = our `UIWorldViewDraw`, FUN_0086EF40),
slot 7 SetHidden (`sub_10433630` = our `UIWorldViewSetHidden`, FUN_0086EC40),
slot 12 HandleEvent (`sub_10434DD0`, unrecovered) and slot 13 Frame
(`sub_10435A20`, unrecovered). Everything else is inherited.

Related: [[project-maui-render-slot-not-override]], [[project-lua-strlen-pseudo-index]].

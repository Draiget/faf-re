---
name: project-cuiworldview-class
description: LANDED 1a7b3dd - CUIWorldView is now a real class with its reflection pair, destructor, DoRender and SetHidden slots and a TypeInfo. Two slots the binary overrides are still inherited, and the next one down is a 945-instruction selection routine.
metadata:
  type: project
---

# CUIWorldView: half landed, and what the rest costs

`CUIWorldView` used to be a forward declaration whose Lua constructor
placement-new'd a plain `CMauiControl` into 0x2A8 bytes. Every instance wore
CMauiControl's vtable, so the two recovered bodies (`Draw` 0x0086EF40,
`SetHidden` 0x0086EC40) sat in the file as free functions nothing called, and
the class had no `RType` at all - the same hole that stopped buttons reaching
`OnClick` (see [[project-button-onclick-solved]]).

Landed in `1a7b3dd`: the class, `StaticGetClass`/`GetClass`/
`GetDerivedObjectRef` (0x0086DB70 / 0x0086DB90), `~CUIWorldView` (0x0086EA40),
`DoRender` and `SetHidden` as real overrides, the construction helper turned
into the constructor, and `CUIWorldViewTypeInfo` (size 0x2A8, base
CMauiControl, ctor 0x0086DCA0, Init 0x0086DD00, registrar 0x00BE6920).

## The vtable, read out of the in-repo PE

`??_7CUIWorldView@Moho@@6B@` is at VA **0x00E49074**; read it with the PE
section table rather than trusting `dumps/moho_engine_rtti.json`, whose
addresses and COL offsets are in a different frame (its second CUIWorldView
entry claims offset 0x104, which contradicts everything else and is a trap).

| slot | addr | state |
|---|---|---|
| 0 / 1 | 0x0086DB70 / 0x0086DB90 | landed (reflection pair) |
| 2 | 0x0086EA20 | landed (deleting dtor, compiler-emitted) |
| 6 (+0x18) DoRender | 0x0086EF40 | landed |
| 7 (+0x1C) SetHidden | 0x0086EC40 | landed |
| **12 (+0x30) HandleEvent** | **0x008704B0** | **still inherited** (889 instrs) |
| **13 (+0x34) Frame** | **0x00871140** | **still inherited** (223 instrs) |
| everything else | CMauiControl | genuinely inherited |

The constructor writes a second vtable to `[edi+11Ch]`
(0x0086E4DF/0x0086E4EF) for the `IRenderWorldView` sub-object - a third
independent witness for `sizeof(CMauiControl) == 0x11C`, see
[[project-maui-control-size]]. Its 13 slots (VA 0x00E490DC) are mostly shims
of the shape `mov ecx,[ecx+4]; mov eax,[ecx]; jmp [eax+N]`, i.e. they forward
through the pointer at **+0x120**, which the destructor proves is the camera
(`[edi+120h]` is destroyed via its scalar deleting dtor). `CUIWorldViewRuntimeView`
calls that same word `mViewportCallback`; the two names alias one field.

## What the remaining two slots cost

`Frame` (0x00871140) is small and readable on its own, but it calls
`CUIWorldView::UpdateSelection` (**0x0086F520, 945 instructions**), and it
needs five console globals that do not exist yet: `ui_KeyboardPanSpeed`,
`ui_KeyboardRotateSpeed`, `ui_KeyboardPanAccelerateMultiplier`,
`ui_KeyboardRotateAccelerateMultiplier`, `ui_ScreenEdgeScrollView`,
`ui_ArrowKeysScrollView`. So the honest order is: globals -> UpdateSelection ->
Frame -> HandleEvent. That is the world-view input/selection subsystem, not a
loose end - budget it as its own session and do not rush the 945-instruction
one.

Also corrected while here: the word pair at +0x29C is not an "overlay draw
token", it is a weak link to the overlay - `DoRender` resolves it with the same
`!= 0 && != 4` / `- 4` convention every sentinel in the file uses, and the
destructor unlinks it. Modelled now as `mOverlayLink`.

Related: [[project-maui-render-slot-not-override]], [[project-maui-control-size]].

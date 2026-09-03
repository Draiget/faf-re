---
name: project-maui-render-slot-not-override
description: FIXED (c990115, 1185935) - six MAUI controls had their recovered render body declared without `override`, so it was not the DoRender vtable slot and nothing ever drew them. Includes the audit recipe for the whole defect family.
metadata:
  type: project
---

# FIXED: recovered virtual bodies that are not actually overrides

A recovered method whose binary address is referenced **only** from its
class's `??_7…@@6B@` vtable is a virtual slot. If our header declares it
without `override` (or under IDA's name rather than the base's), it is not
that slot - it is a dead free-standing method, and the slot keeps resolving to
the base class's implementation.

For render slots the base is `CMauiControl::DoRender`, which draws nothing, so
the control silently never appears.

## What was hit (slot 6, +0x18 = DoRender)

`CMauiScrollbar`, `CMauiItemList`, `CMauiBorder`, `CMauiMesh`, `CMauiGroup`,
`CMauiHistogram` - all had `void Draw(CD3DPrimBatcher*, std::int32_t);`.
Renamed to `DoRender(...) override`. (Group's and Histogram's slots are the
binary's `nullsub`s, matching their already-empty bodies.)

Visible consequences, all resolved by this:
 - the scrollbar rendered as two arrow buttons with an empty gap - the arrows
   are separate Bitmap controls, the track and thumb are the scrollbar's own
   DoRender;
 - the Profile Manager's list was always empty, so OK had nothing to select
   and creating a profile never opened the main menu.

## Audit recipe (finds the rest of the family)

For every `Address: 0x…` doc block in a recovered `.cpp`, read
`decomp/recovery/disasm/<ns>/FUN_<addr>.xrefs.txt`. If every entry is
`data … ??_7…vftable` and no entry is `code`, the body is a vtable slot.
Then check the header declaration: no `override` and no `virtual` means it is
wired to nothing.

```python
entries = [x for x in body.split('\n') if x.startswith(('code ','data '))]
vtable_only = entries and all(e.startswith('data ') and '??_7' in e for e in entries)
```

Which slot it is comes from the RTTI dump, not from guessing:

```python
d = json.load(open('dumps/moho_engine_rtti.json'))
[it['slots'][6] for it in d['items'] if it['class']=='CMauiItemList@Moho' and it['col']['offset']==0]
```

Slot 6 (+0x18) is `DoRender`. `CMauiControl`'s dump has clean demangled names
for every slot, so use it as the index: IsHidden +0x20, HitTest +0x24,
DisableHitTest +0x28, IsHitTestDisabled +0x2C, HandleEvent +0x30, Frame +0x34,
AcquireKeyboardFocus +0x38, AbandonKeyboardFocus +0x3C, LosingKeyboardFocus
+0x40, OnKeyboardFocusChange +0x44.

**The dump's addresses are NOT a constant rebase of our IDA export** - the
deltas differ between symbols (0x0FBCA2F0 vs 0x0FBCA310), so match by slot
semantics and by the xrefs file, never by arithmetic on the dump address.

## Still open, same defect

`CUIWorldView` is only a forward declaration; `ConstructCUIWorldView` does
`new (storage) CMauiControl(...)`, so instances carry **CMauiControl's**
vtable. `UIWorldViewDraw` (FUN_0086EF40) and `UIWorldViewSetHidden`
(FUN_0086EC40) have no caller at all, and the world view therefore renders
nothing. Expect a black 3D view once a game starts. Fixing it means making
`CUIWorldView` a real class the way [[project-button-onclick-solved]] did for
`CMauiLuaDragger`.

Related: [[project-button-onclick-solved]], [[project-keyboard-input-path]].

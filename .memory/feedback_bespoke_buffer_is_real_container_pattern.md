---
name: feedback_bespoke_buffer_is_real_container_pattern
description: Before recovering a "bespoke" {begin,end,capacity}-shaped buffer struct as hand-written code, check whether its layout matches an existing msvc8::vector<T>/similar template exactly (including any "unused reserved word") -- it may BE that container, not a lookalike, and the container_lane_guard hook will correctly deny bespoke reimplementation either way.
metadata:
  type: feedback
---

## What happened

`Moho::MeshShaderPaletteBuffer` (`Mesh.h`) looked bespoke: a 4-word struct
with a leading `mReservedHeader` word documented as "unused by the palette
reserve path", then `mBegin`/`mEnd`/`mCapacity`. A prior pass recovered its
`sub_7E9280` (`insert`-shaped) function as a hand-written free function
(`AppendDefaultPaletteEntries`), reasoning the extra header word ruled out a
literal `msvc8::vector<T>` match.

That reasoning was wrong. `msvc8::vector<T, HasDebugProxy=true>`
(`legacy/containers/Vector.h`) has EXACTLY this shape:
`myProxy_@+0x0` (opaque debug-proxy slot, inert outside iterator-debug
builds), `first_@+0x4`, `last_@+0x8`, `end_@+0xC` — `HasDebugProxy=true` is
the template's DEFAULT, so any ordinary `msvc8::vector<T>` instantiation has
this same "extra" leading word. The "reserved header" wasn't a sibling field
outside the vector — it WAS the vector's own proxy slot. Once recognized,
`MeshShaderPaletteBuffer : msvc8::vector<SkinPaletteEntry> {}` was the exact,
correct model, and the hand-written free function was mid-edit for
extension when `container_lane_guard.py` denied it (correctly — see
[[project_wild_free_sweep_2026_09_02_two_more_severe_bugs]]'s sibling notes
on this hook, and CLAUDE.md's RULE ONE).

## The check to run before writing ANY bespoke buffer/container-shaped code

1. Note the struct's field layout and offsets precisely.
2. Grep the relevant canonical container header (`Vector.h`, `Map.h`,
   `FastVector.h`, etc.) for a template whose PRIVATE member layout matches
   — including template parameters with non-trivial defaults
   (`HasDebugProxy = true` is exactly this kind of trap: its effect is
   invisible unless you go looking for the parameter's default).
3. If the layout matches, the struct almost certainly SHOULD derive from (or
   alias) the canonical template, not reimplement it. This is true even if a
   field looks "unused" — an unused-looking field is a strong hint you're
   looking at a template feature you haven't identified yet, not proof the
   type is unrelated.
4. Per-instantiation codegen variance (memcpy vs. hand-rolled loop, whether a
   sub-step gets its own out-of-line body or stays inlined) is NORMAL and
   already precedented throughout `Vector.h`'s existing citations (e.g.
   `uninit_move_n`'s citations already document both `memmove_s`-based and
   hand-loop-based emissions for different `T`). Don't treat a codegen-shape
   mismatch against ONE other citation as proof the function is a different
   algorithm — check the template's OWN existing citation practice for how
   much per-T variance it already accepts.

## Downstream integration once you switch a struct to inherit the container

- Public accessors (`begin()`/`end()`/`size()`) replace raw field reads at
  every external call site — grep the WHOLE tree for the type name and any
  `.oldFieldName` access before assuming the blast radius is just the one
  file you started in.
- Manual "reset to empty" / "free and null out" code at construction/
  destruction sites usually becomes fully redundant once the type has a real
  constructor/destructor (implicit member init/teardown already does it) —
  delete it rather than leaving harmless-but-decompiler-shaped dead code.
- A member method that isn't literally on the canonical template (e.g. a
  domain-specific `ReserveToPaletteCapacity()`) can still derive from the
  container and add ITS OWN extra method — inheritance-with-no-new-data-
  members doesn't change `sizeof`, so the size/offset asserts still hold; add
  a `sizeof(Derived)==sizeof(Base)` static_assert to guard it explicitly
  since the old `offsetof` asserts on the base's now-private members won't
  compile from outside the class anymore.
- Prefer the container's PUBLIC API (`insert`/`erase`/`resize`) over trying
  to reach into base-class internals for one caller's convenience, even when
  the binary's own asm shows a directly-called helper for a degenerate case
  (e.g. an empty-range relocate-then-reposition-pointer shrink) — if a public
  method already collapses to the identical operation for a trivially
  destructible `T` (erase-of-a-tail-range degenerating to a pointer move is
  already a documented, precedented shape on this exact template), use it
  rather than inventing new base-class surface area.

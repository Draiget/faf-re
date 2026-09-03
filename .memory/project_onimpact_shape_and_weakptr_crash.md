---
name: project_onimpact_shape_and_weakptr_crash
description: "RESOLVED 2026-09-03 (a845ece6). Root cause was a 16-byte layout error in ProjectileDeserializeRuntimeView, NOT a WeakPtr lifetime bug. mCachedAimPoint/mKeepLastAimLatch sat before mDamage instead of at 0x30C/0x318, shifting mTargetPosData to 0x2FC. Fixed + asserted; OnImpact call shape fixed too. Zero crashes, zero errors."
metadata:
  type: project
---

## RESOLVED -- it was a duplicate-layout bug, not a lifetime bug

`ProjectileDeserializeRuntimeView` (an anonymous-namespace struct in
`Projectile.cpp`) duplicates `Projectile`'s layout and had **no offset
asserts**, so a 16-byte error hid in it. `mCachedAimPoint` and
`mKeepLastAimLatch` were declared **before `mDamage`**, when the binary places
them at **0x30C / 0x318** -- after `mTargetPosData`. Their own comments said so.

Everything downstream shifted: `mTargetPosData` landed at **0x2FC instead of
0x2EC**, so its weak-link words read `position`'s float bytes as a pointer. That
is where the bogus `ownerLinkSlot` came from, and why it never looked like a
freed object -- `0x00C466A1` is odd and inside the module image because it was
never a pointer.

Verified against `Projectile::Impact` (0x0069DEC0), which reads `[edi+270h]`,
`[edi+278h]`, `[edi+2A4h]`, `[edi+2ECh]`, `[edi+2F0h]`, `[edi+31Ch]`,
`[edi+320h]`, `[edi+324h]`, `[edi+328h]`, `[edi+364h]` -- each now pinned by a
`static_assert`.

With the layout right, the **OnImpact call shape** fix lands safely: the binary
runs `OnImpact(self, impactTypeString, collidedEntityObject)`, taking the
collided entity's `CScriptObject::mLuaObj` at `[base+0x20]`, or a temporary
`LuaObject` built on the projectile's Lua state (0x0069DF2E) when nothing was
hit. A default-constructed `LuaObject` has no state, so `PushStack` threw
`state->l_G == m_state->m_state->l_G`.

**Result:** 0 crashes and 0 "Error running OnImpact script" in a four-minute
run, against 2 crashes and 10,960 warnings.

## Lesson

Three batches were spent hunting a WeakPtr *lifetime* bug that did not exist --
`ClearWeakObjectChain`, `ResetFromOwnerLinkSlot`, the owner-link offset and a
two-subobject drain theory were all investigated and cleared. The tell was in
the data the whole time: **a garbage pointer that is odd and inside the module
image was never a freed object**, so look for a layout/aliasing fault, not a
lifetime one. And any struct that duplicates another's layout must carry
`static_assert`s -- see [[feedback_no_duplicate_container_helpers]] and the
duplicate-layout contract in CLAUDE.md.

---
name: feedback_ida_struct_field_names_are_ida_guesses
description: IDA's struct field names in decompiles are IDA's own guesses, not the real type's field order - reading `dest->x` literally cost two sessions on the quaternion lane bug
metadata:
  type: feedback
---

In an IDA `.c` decompile, `obj->fieldname` is named from **IDA's own struct
definition**, which is a guess it made (or a human made in the IDB), not the
real type's field order. Always translate the field name back to a **byte
offset** before mapping it onto a recovered C++ type.

**The case that proved it.** IDA's `Wm3::Quaternionf` struct names offset 0
`x`. The real vendored type is `union { Real m_afTuple[4]; struct { Real w, x,
y, z; }; }` -- offset 0 is `.w`. So every decompile printing
`dest->x = <scalar>` means *lane 0 gets the scalar*, which is `.w`. Reading it
as Wm3's `.x` rotates all four lanes, and that single misreading propagated
into ~60 sites across 30 files: `QuatToMatrix`, `VMatrix4::Set`,
`VTransform::Compose/Inverse`, `COORDS_Orient`, `QuatCrossAdd`, the GPU
skinning palette, the camera view matrix.

**Why it survived so long:** producers and consumers were *both* rotated, so
the errors cancelled and the engine half-worked. Fixing only the consumers
(commits `a4e7a334..77342756`) broke the cancellation and destroyed the view
matrix -- reverted whole as `b795819e`. The correct fix landed both halves in
one commit, `988fb7fd`.

**How to detect it cheaply, without the asm.** Ask what the recovered body
reduces to. A correct quaternion body always collapses to a clean identity:
- `COORDS_Orient(0, 0)` must be the identity, not a 180-degree rotation.
- `QuatCrossAdd(v, v)` must be the identity.
- `SolveAttachedWorldTransformFromChildLocal` must reduce to
  `parent * conj(child)`.
- A rotation matrix's diagonal must contain **only the three imaginary
  lanes**; the scalar lane appears in no diagonal term. That absence is the
  scalar's signature and identifies the layout on sight.
If the body reduces to something with no name, the lane assignment is wrong.

**General rule:** decompile field names are a hypothesis. Offsets are the
evidence. See [[feedback_verify_offsets_from_asm_yourself]] and
[[feedback_inverted_field_names_read_the_math]].

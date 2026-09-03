---
name: project-strategic-icons-stub
description: CWldSession::RenderStrategicIcons is a comment-only stub, so strategic icons never render. Closure is 43 functions / ~4900 instructions - a subsystem, not a batch.
metadata:
  type: project
---

`CWldSession::RenderStrategicIcons` (`CWldSession.cpp:11423`) is a
**comment-only body** - it lists its own intended flow and blockers and does
nothing. It is the same class of defect as the silhouette pass fixed in
`d6e6468`: strategic icons never render.

Its own stated blockers are `struct_IconAux` / `UnitIconData` layouts and the
`CD3D*` render interfaces.

## Scope (measured, do not under-estimate this one)

    closure: 43 functions, ~4921 instructions
    RenderStrategicIcons itself   0x0085B6E0   1333 instrs
    sub_85CD40                    0x0085CD40    568
    sub_85F3F0                    0x0085F3F0    261
    sub_85E3A0                    0x0085E3A0    274
    sub_85E0A0                    0x0085E0A0    211
    struct_IconAux::GetGenericIcons 0x0085E7F0  188
    ... plus ~25 smaller icon/lifebar helpers and the usual std::string /
    map_uint_WeakPtr_UserEntity emissions

This is a **subsystem**, not a batch. Do not start it at the tail of a run.

`sub_85E0A0` (211 instrs) looks attractive on its own - closure 0, everything it
calls is recovered - but its only caller is this stub, so landing it alone
produces an orphan. That is the false-recovered-caller trap; the note in
[[project-entity-deserializer-missing]] already flagged this exact function.

## Order of work when it is taken on

1. Model `struct_IconAux` and `UnitIconData` from the ctor/dtor and
   `GetGenericIcons` (0x0085E7F0), which names several fields.
2. Recover bottom-up: the small icon helpers, then `sub_85E0A0` /
   `sub_85E3A0` / `sub_85CD40`, then `RenderStrategicIcons` itself.
3. The caller chain above it is already real - `RenderStrategicIcons` is
   invoked from recovered source - so no caller wiring is needed, only the
   stub replacement.

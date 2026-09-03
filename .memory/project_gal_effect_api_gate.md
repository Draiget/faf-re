---
name: project-gal-effect-api-gate
description: RETRACTED. I claimed gpg::gal::EffectD3D9 was only forward-declared and gated the render side. It is fully implemented in D3D9Interfaces.cpp - I missed it by searching only *.h when the GAL backend uses *.hpp.
metadata:
  type: project
---

**This note previously claimed `gpg::gal::EffectD3D9` was never defined
and that it gated `func_Draw_Rings` plus the mesh-render shader debt.
That was wrong. Retracted 2026-08-17.**

`EffectD3D9` is declared in
`src/sdk/gpg/gal/backends/d3d9/EffectD3D9.hpp` and **fully implemented**
in `D3D9Interfaces.cpp`. All seven vtable slots have real bodies:

    slot 0  0x00942EC0   11   D3D9Interfaces.cpp:8659
    slot 1  0x009415B0    2   GetContext        :8670
    slot 2  0x00942920  188   GetTechnique      :8697
    slot 3  0x00941D70  154   SetMatrix         :8740
    slot 4  0x00941F60  153   SetTechnique      :8779
    slot 5  0x00942150  123   OnReset           :8813
    slot 6  0x00942290   53   OnLost            :8829

`DeviceD3D9::SetVertexDeclaration` (:8087), `SetVertexBuffer` (:8106) and
`SetBufferIndices` (:8151) are implemented too.

## The mistake, so it does not repeat

I searched `rg "class EffectD3D9" src/sdk --glob '*.h'`, found only two
forward declarations, and concluded the class did not exist.

**The GAL backend headers are `.hpp`, not `.h`.** The repo contract says
*new* recovered headers must be `.h`, which is easy to read as "everything
is `.h`" - but `src/sdk/gpg/gal/backends/d3d9/` is all `.hpp`
(`EffectD3D9.hpp`, `DeviceD3D9.hpp`, `EffectTechniqueD3D9.hpp`, ...), and
so are other pre-existing trees.

**Never conclude a type is missing from a `--glob '*.h'` search.** Use
`--glob '*.h*'`, or `ls` the owning directory, or grep for a *member* name
rather than the class declaration. A forward declaration in a header is
evidence of nothing except that someone needed the name there.

Corollary: "only forward-declared" is a much weaker signal than it looks
in a tree this size. Confirm by looking for a member definition before
declaring a subsystem blocked - the same discipline
[[reference-have-set-detection-gap]] records for addresses.

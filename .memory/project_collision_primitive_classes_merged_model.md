---
name: project_collision_primitive_classes_merged_model
description: "EntityCollisionUpdater is one declaration standing for TWO binary classes (a sphere primitive and a box primitive). Its GetBox() is stubbed to nullptr while the box class really returns this+4. Evidence gathered; the fix is to recover DColPrimSphere/DColPrimBox as separate classes, not to patch the stub."
metadata:
  type: project
---

## CORRECTED: it is one TEMPLATE, and the existing model is right

An earlier version of this note said `EntityCollisionUpdater` "wrongly merges
two classes". **That was wrong.** The RTTI dump settles it:
`EntityCollisionUpdater` is `Moho::CColPrimitive<T>`, a template with exactly
two instantiations, and listing both instantiations' addresses on one
declaration is precisely what RULE ONE prescribes.

`dumps/rtti_dump_all.hpp` has both, each `: public Moho::CColPrimitiveBase`
with a 10-slot primary vftable:

| slot | `CColPrimitive<Wm3::Box3f>` @0xE0D50C | `CColPrimitive<Wm3::Sphere3f>` @0xE0D480 |
|---|---|---|
| 0 | 0x4FFC20 | 0x4FF9A0 |
| 1 | 0x4FF130 | 0x4FE780 |
| 2 | 0x4FF140 | 0x4FE790 |
| 3 | 0x4FF470 | 0x4FEBC0 |
| 4 | 0x4FFBE0 | 0x4FF960 |
| 5 | 0x4FFC00 | 0x4FF980 |
| 6 | 0x4FF2D0 | 0x4FE9D0 |
| 7 | 0x4FF260 | 0x4FE860 |
| 8 | 0x4FF150 | 0x4FE7A0 |
| 9 | 0x4FF450 | 0x4FEB60 |

Every paired address already annotated in
`moho/entity/EntityCollisionUpdater.h` lines up with this table
(`GetBoundingBox` = slot 0, `GetSphere` = slot 1, `GetBox` = slot 2,
`SetTransform` = slot 3, ...). The reflection helpers name the template
directly: `gpg::SerSaveLoadHelper<Moho::CColPrimitive<Wm3::Box3<float>>>`.

## The one real defect

The payload lives at **+0x04** and each instantiation returns it only for its
own shape -- both accessor bodies are two instructions:

| | slot 1 `GetSphere` | slot 2 `GetBox` |
|---|---|---|
| `<Sphere3f>` | `lea eax,[ecx+4]; ret` | `xor eax,eax; ret` |
| `<Box3f>` | `xor eax,eax; ret` | `lea eax,[ecx+4]; ret` |

`EngineMethodStubs2.cpp` stubs **both** to `return nullptr`, so box collision
queries get null where the binary hands back the box.

There is no bounded fix while `EntityCollisionUpdater` is a plain class: it
cannot express "depends on T". The correct recovery is to make it the template
it actually is --

```cpp
template <class T>
class CColPrimitive : public CColPrimitiveBase {
  T mPayload;  // +0x04
  const Wm3::Sphere3f* GetSphere() const override;  // &mPayload iff T is Sphere3f
  const Wm3::Box3f*    GetBox()    const override;  // &mPayload iff T is Box3f
};
```

with `if constexpr (std::is_same_v<T, ...>)`, which emits exactly the two
two-instruction bodies per instantiation. Then drop the merged accessors from
`EngineMethodStubs2.cpp`.

Still needed: `CColPrimitiveBase`'s own layout (ctor 0x004FFDE0) and names for
slots 4-9. This is live gameplay collision, so it wants a runtime check, not
just a build gate.

## Stub-file state (2026-09-02)

Swept every `*Stub*.cpp` for live definitions:

- `moho/EngineUnrecoveredStubs.cpp` -- **fully drained**, zero definitions left,
  only forward declarations and a commented history of what replaced each stub.
- `moho/lua/UnrecoveredLuaCallbackStubs.cpp` -- **fully drained**, same shape.
- `moho/EngineMethodStubs.cpp` -- a few left (`DeviceAppView::IsReady` /
  `GetInstance`).
- `moho/EngineMethodStubs2.cpp` -- the `EntityCollisionUpdater` group above,
  plus others.
- `render/d3d/D3DResUnreachableStubs.cpp` -- `[[noreturn]]` unreachable markers,
  a different and legitimate thing.

Also verified as faithful rather than stubbed, so they do not need work:
`Sim::SimAssert` (0x00735110 is a bare `retn`), the `UserUnit` IUnit bridge
predicates (`xor al,al; ret`), and `register_MotorSinkAwaySerializer` (a link
anchor).

---
name: project_caiattackerimpl_untyped_shell_target
description: "CAiAttackerImpl is still an untyped shell -- a vptr plus mLayoutPadding[0xA4-4] with every field reached through CAiAttackerImplRuntimeView, and two undeclared base classes. All the evidence needed to type it in place is gathered here."
metadata:
  type: project
---

## What it is

`moho/ai/CAiAttackerImpl.h` declares the class with **no bases** and a single
opaque member:

```cpp
class CAiAttackerImpl { ... std::uint8_t mLayoutPadding[0xA4 - sizeof(void*)]; };
static_assert(sizeof(CAiAttackerImpl) == 0xA4);
```

Every field is then reached through a `CAiAttackerImplRuntimeView` reinterpret
in the .cpp. The header says so outright: "until the class members are typed
in-place". This is the RULE ONE reach-in pattern at class scope.

## Evidence already gathered (2026-09-02)

**Two undeclared bases.** `CAiAttackerImpl.cpp` casts the object to
`IAiAttacker*` at **+0x00** and to `CScriptObject*` at **+0x0C**, and
`sizeof(IAiAttacker) == 0x0C` (IAiAttacker.h:91). So the real declaration is

```cpp
class CAiAttackerImpl : public IAiAttacker, public CScriptObject
```

and both of those casts become plain `static_cast`s -- the same fix already
landed for `CUnitCommand`/`Broadcaster` (`1347d17d`) and `Unit`/`Entity`
(`b687b054`), where the offset turned out to be exactly what the compiler
computes for a declared base.

**Field offsets**, already recorded in the header's own comment:

| offset | field |
|---|---|
| +0x40 | `mUnit` |
| +0x44 | `mStage` |
| +0x58 | `mWeapons` |
| +0x68 | `mThread` |
| +0x70 | `mTasks` |
| +0x80 | `mDesiredTarget` |
| +0xA0 | `mReportingState` (`CAiAttackerImpl::State`, enum already typed) |

Total size 0xA4. The gaps between these are still unknown, so they stay as
named pad arrays with `offsetof` static_asserts on every typed field -- that is
the sanctioned form, not a reason to defer.

**Blast radius: 40 uses, all inside `moho/ai/CAiAttackerImpl.cpp`** (3217
lines). Nothing outside that file touches the view.

## Why it was not landed on 2026-09-02

Declaring the two bases changes vtable layout for a class on the live AI attack
path, and this was the tail of a very long run. It is a deliberate piece of
surgery, not a quick cleanup -- but it is fully specified above and the work is
bounded to one file.

Order to do it in: declare the bases and convert the two casts first (cheap,
independently verifiable, mirrors two commits that already landed), build, then
type the seven fields with asserts and retire the runtime view.

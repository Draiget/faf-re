---
name: feedback_purecall_vtable_exposes_invented_stub_bodies
description: "If a class's vftable in rtti_dump_all.hpp points its slots at _purecall (0x00A82547), that class has NO bodies -- any stub defining them is inventing behaviour and any address cited on them belongs to a derived override. Three classes fixed this way; the recipe and what the build error tells you."
metadata:
  type: feedback
---

## The check

In `dumps/rtti_dump_all.hpp`, look up the class and read its primary vftable:

```
// vftable@0xE2E794 subobjectOffset=0 slots=24
virtual void sub_A82547() = 0; // 0xA82547 (slot 0)
```

`0xA82547` is `_purecall`. Every slot pointing there means **the class supplies
no body for that slot**.

**Why it matters:** the stub files (`EngineMethodStubs*.cpp`) define bodies for
these, and a stub is worse than a missing symbol. A pure slot that is stubbed
answers a virtual dispatch with an invented value instead of failing to link.
`CColPrimitiveBase::GetBox()` returned `nullptr` where a real box primitive
returns its payload (`0x004FF140` is `lea eax,[ecx+4]; ret`) -- silent wrong
collision answers.

**How to apply:** change the declarations to `= 0`, delete the stub bodies, and
rebuild. `sizeof`/instantiation errors are the point, not an obstacle -- see
below.

## Landed with this check (2026-09-02)

| commit | class | vftable | slots |
|---|---|---|---|
| `2a0265b3` | `CColPrimitiveBase` (= `EntityCollisionUpdater`) | 0x00E0D3F4 | 10/10 pure |
| `ee804b5d` | `IWldSessionLoader` | 0x00E49FA4 | 7/7 pure |
| `9f51b4a5` | `ICommandSink` | 0x00E2E794 | 24/24 pure |

Checked and **not** applicable: `CMauiMesh` (real bodies, no `_purecall`),
`DeviceAppView` (no vftable record in the dump).

## Addresses cited on a pure slot are a derived override

A pure slot has no address, so any `Address:` annotation on such a declaration
belongs to a **subclass**. Grep the dump for the bare address to find its real
owner:

```bash
grep -n "0x749F40" dumps/rtti_dump_all.hpp     # -> slot 22 of Moho::Sim
```

- `ICommandSink::AdvanceBeat` / `EndGame` cited 0x00749F40 / 0x0074B100. Those
  are slots 22-23 of `Moho::Sim`'s vftable (0x00E34714), already cited
  correctly on `Sim::AdvanceBeat` / `Sim::EndGame`.
- `EntityCollisionUpdater`'s methods each cite a **pair** of addresses. Those
  are the two instantiations of the template that implements it,
  `CColPrimitive<Wm3::Box3f>` (0x00E0D50C) and `CColPrimitive<Wm3::Sphere3f>`
  (0x00E0D480) -- first of each pair is Box3f. That is correct RULE ONE form,
  not a defect; see
  [[project_collision_primitive_classes_merged_model]].

## The build error is the useful part

Making `IWldSessionLoader` pure broke one call site:
`ResetWldSessionLoaderSingletonToInterfaceVtable` was placement-new-ing the
abstract base over the loader singleton to "rebind the vtable lane".

Reading 0x00885630 showed why it had looked constructible -- the body is

```
mov  sWldSessionLoader.__vftable, offset ??_7IWldSessionLoader@Moho@@6B@
mov  eax, offset sWldSessionLoader
```

which is just what MSVC emits for **the abstract base's constructor**, run by
the derived loader before it installs its own vtable. So the address moved onto
`IWldSessionLoader::IWldSessionLoader` (protected, defaulted) and the orphan
helper went. When purifying a class breaks a construction, read the address
before assuming the class is not abstract: it is usually the base ctor.

Watch the LNK count across the change (steady at 28+1 here). If it does not
move, nothing was calling those bodies non-virtually either.


## Sweeping this mechanically -- and three ways I got it wrong

The check generalises to a tree-wide sweep, but three naive versions produced
confident nonsense before one worked. All three failed *silently*, returning a
clean "0".

1. **`` eaten by the heredoc.** `grep` invoked from Python inside a
   `<<'PYEOF'` heredoc received `class Foo` as `class Foo` + **backspace**
   (``), matching nothing. 1143 of 1143 lookups failed and the sweep
   reported "0 mismatches". *Always print a coverage counter* -- `compared: 0`
   is what exposed it. Better: do the matching in Python, never shell out.
2. **Comparing per-class virtual counts to vtable slot counts.** The dump's
   slot count is the **whole** vtable including inherited slots; counting
   `virtual` in one class body counts only newly-declared ones. `RCamCamera`
   shows "1 declared vs 44 slots" and is perfectly correct. A real comparison
   needs chain-aware counting.
3. **`=\s*0\s*;` matches data members.** `std::uint8_t mHasGoal = 0;` is not a
   pure virtual. That version claimed 29 classes were wrongly declared pure;
   the real answer was 1. The working pattern is
   `virtual[^;{}]*?=\s*0\s*;` -- **validate it** against classes with
   known counts (ICommandSink 24, IWldSessionLoader 7,
   EntityCollisionUpdater 10) before trusting a sweep.

### Result once the sweep was correct

- Classes fully `_purecall` in the binary but carrying bodies in our tree:
  the four fixed above.
- Classes fully concrete in the binary but declared with pure virtuals here:
  **one**, `CD3DDevice` (`src/sdk/moho/render/d3d/CD3DDevice.h`), with
  `GetResources()`, `InitContext()` and `Destroy()` marked `= 0` against a
  53-slot all-concrete vftable (0x00E02214).

**Checked, and it is NOT a defect** -- a fourth wrong reading, caught before
acting. The binary splits the device in two:

```
Moho::ID3DDevice   53 slots, all _purecall   (interface)
Moho::CD3DDevice : public Moho::ID3DDevice, public Broadcaster<SD3DDeviceEvent const&>
                   53 real slots             (implementation)
```

Our tree has the same two levels with the names collapsed one step: there is no
`ID3DDevice` class at all, `moho::CD3DDevice` (header) plays the interface role
with its three `= 0`, and `CD3DDeviceSingleton final : public moho::CD3DDevice`
(`CD3DDevice.cpp:543`) is the implementation. It works and it dispatches
correctly.

What is true is only that the header models **3 of the interface's 53** pure
slots -- ordinary incompleteness in a partially recovered subsystem, not a bug,
and not something to "fix" by declaring a base that does not exist here. Fully
aligning the names would mean introducing `ID3DDevice` and recovering 53
bodies: a subsystem-sized job with no behavioural payoff.

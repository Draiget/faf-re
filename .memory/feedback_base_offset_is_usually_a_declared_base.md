---
name: feedback_base_offset_is_usually_a_declared_base
description: "A hand-computed `(uint8_t*)obj + 0xNN` to reach a sub-object is usually not a magic number -- it is where the compiler already puts a DECLARED base class. Four landed examples, the two-line check that proves it, and the one case where converting would have been a bug."
metadata:
  type: feedback
---

## The pattern

Recovered code keeps reaching sub-objects with pointer arithmetic:

```cpp
return reinterpret_cast<Broadcaster*>(reinterpret_cast<uint8_t*>(command) + 0x34u);
```

**Why it matters:** in almost every case the class already declares that base,
and the offset is exactly what the compiler computes. The arithmetic is not
modelling anything the type system cannot express -- it is a hand-rolled
`static_cast` that silently goes wrong if a base ever changes size.

**How to apply:** before treating `+0xNN` as a magic offset, run the two-line
check:

1. Does the class declare a base list? (`class X : public A, public B`)
2. Does `sizeof(A)` equal the offset? (there is usually a `static_assert`)

If both hold, replace it with `static_cast<B*>(x)`.

## Landed with this check (2026-09-02)

| commit | offset | was | is |
|---|---|---|---|
| `1347d17d` | +0x34 | `CUnitCommand` -> `Broadcaster` | `sizeof(CScriptObject) == 0x34`, second base |
| `b687b054` | +0x08 | `Unit` -> `Entity` | `sizeof(IUnit) == 0x08`, second base (Entity's dtor is virtual, so `delete` still destroys the whole Unit) |
| `1c0a1575` | +0x0C | `CameraImpl` -> `CScriptEvent` | `sizeof(RCamCamera) == 0x0C`, second base |
| `9635d5a8` | +0x290 | raw field read | `Physics.MotionType` -- see below |

For a magic **field** offset rather than a base, the same idea works one level
down: find the sub-struct whose base offset brackets it, subtract, look up the
remainder. `0x290 - 0x278 (Physics) = 0x18 = MotionType`. And check for an
explicit `Slot:` annotation in the header before counting virtuals by hand --
`Unit.h` annotated `Slot: 7` on `GetBlueprint` outright.

## The case where converting WOULD have been a bug

`CameraImpl.cpp`'s `AsCameraTrackingBroadcaster` reaches `camera + 0x04`.
`CameraImpl : public RCamCamera`, `RCamCamera : public Broadcaster`, and with
RCamCamera's virtual dtor the vptr takes +0x00 -- so +0x04 looks exactly like
the `Broadcaster` base. **Do not convert it.**

The two link structs name the same two slots in opposite order:

| struct | +0x00 | +0x04 |
|---|---|---|
| `CameraTrackingBroadcasterLink` (`CameraTrackingListener.h`) | `mListNext` | `mListPrev` |
| `TDatListItem` (`moho/containers/TDatList.h`) | `mPrev` | `mNext` |

**Resolved from the binary (2026-09-02): `+0x00` is NEXT, `+0x04` is PREV.**
Two independent functions agree:

- `FUN_007AE2B0` (`Broadcaster<SCameraTracking>::BroadcastEvent`) splices with
  `X->[+0]->[+4] = S` and `X->[+4]->[+0] = S` -- `next->prev` then
  `prev->next` -- and tests emptiness on `[+4]`.
- `FUN_00632BC0` (generic `TDatListItem` unlink) does
  `[+0]->[+4] = [+4]` then `[+4]->[+0] = [+0]` -- `next->prev = prev;
  prev->next = next`.

So **`CameraTrackingBroadcasterLink` is named correctly and `TDatListItem` is
the inverted one**: its `mPrev` is really the next pointer.

**It is not a runtime bug and must not be "fixed" casually.** A doubly-linked
list is symmetric under swapping the two names, and every use is internally
consistent -- `ListUnlinkSelf`'s `mPrev->mNext = mNext; mNext->mPrev = mPrev;`
emits exactly the binary's two stores. Renaming `TDatListItem`'s fields would
touch essentially the whole engine for zero behavioural gain, and a
half-applied swap would be catastrophic.

What it does mean: **never mix the two views on one list, and never convert
`camera + 0x04` into a `Broadcaster*`/`TDatListItem*` and then use the field
names.** By slot the two agree; by name they are opposites, so a conversion
that looks like a tidy-up silently swaps prev and next.


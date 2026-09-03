---
name: feedback_raw_storage_assigned_into_bug_class
description: "Recurring crash class: storage from ::operator new(sizeof(T)) handed to an Initialize* function that assigns into non-trivial members. The assignment releases a garbage control block or frees a garbage string buffer. Found 3 real crashes; includes the sweep and how to pick the right fix."
metadata:
  type: feedback
---

## The shape

```cpp
auto* const p = static_cast<T*>(::operator new(sizeof(T)));   // NO constructor
InitializeTFromX(*p, ...);          // first act: p->handle.reset() or p->s = ...
```

`reset()` and `operator=` on a `boost::shared_ptr` **destroy the old value
first**, so on never-constructed storage they call `release()` on whatever the
heap block happened to hold. Assigning into an unconstructed `msvc8::string`
frees a garbage buffer pointer the same way.

**Why it matters:** this is what stopped the sim beating -- see
[[project_sim_stall_countedptr_root_cause_2026_09_03]]. Symptom is an AV in
`sp_counted_base::release` writing near address 3 (`pi_` garbage, `use_count_`
at +4), or a heap fault in a string destructor.

## The sweep

Regex `operator new\(\s*sizeof\((\w+)\)` over `src/sdk/**/*.cpp`, then:

1. Drop sites with a placement-new (`new (x) T`) within a few lines -- that is
   the legitimate raw-alloc-then-construct idiom.
2. Locate each type's definition and keep only those with non-trivial members
   (`msvc8::string`, `msvc8::vector`, `boost::shared_ptr`, `CountedPtr`,
   `fastvector`, another wrapper struct).

Measured 2026-09-03: **208** raw-allocation sites, 135 without a nearby
placement-new, but only **24** types carry non-trivial members, and just
**3** were genuine bugs. The rest allocate POD link/tree nodes. Do not
"fix" those -- raw allocation of a POD node is correct and matches the binary.

## Picking the fix -- read the binary, do not guess

Two different correct answers, and choosing wrongly is worse than the bug:

- **`new T()`** when the binary calls `operator new(sizeof(T))` *and then a
  constructor*. Emits the same allocation plus the construction. Used for
  `ParticleRenderBucketRuntime` and `TrailRenderBucketRuntime`.
- **Placement-construct the offending member only**, when the binary flatly
  field-initialises raw storage and deliberately skips the real constructor.
  `CAniPoseTypeInfo::NewRef` (0x0054D8A0) stores two zero dwords straight into
  `mSkeleton` (0x0054D8BC / 0x0054D8C2); calling `CAniPose`'s real ctor would
  additionally substitute `CAniSkel::GetDefaultSkeleton()` and resize `mBones`,
  none of which is at that address. `new T()` there would have been a
  behaviour change, and the type has no default ctor anyway.

## Two false-positive classes to leave alone

- **RB-tree sentinels.** `AllocateIntAnnotationSentinel` /
  `AllocateStringAnnotationSentinel` (`CD3DEffectTechnique.cpp`) allocate raw
  and set only link/colour/nil fields; the payload is never read. That matches
  msvc8's own `_Myhead` and constructing it would diverge.
- **POD node structs** -- `ParticleBufferPoolNodeRuntime`,
  `TrailSegmentBufferRuntime`, `ParticleRenderWorkItemRuntime` and most of the
  other 135.

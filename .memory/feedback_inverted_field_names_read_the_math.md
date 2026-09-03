---
name: feedback_inverted_field_names_read_the_math
description: A recovered field name can be confidently, exactly backwards - mMinMagnitude held the maximum. Names are not evidence; the arithmetic that consumes the field is. Resolve naming conflicts from the consuming math in the .c, never by majority vote among declarations.
metadata:
  type: feedback
---

## What happened

`SCamShakeParams` (`CameraImpl.h`) declared two floats:

```cpp
float mMinMagnitude = 0.0f;   // +0x10
float mMaxMagnitude = 0.0f;   // +0x14
```

An anon-namespace producer view in `Entity.cpp` disagreed, putting the
`ShakeCamera` binding's `maxIntensity` at `+0x10`. Two declarations said one
thing (`CameraImpl.h` and a second view in `CameraImpl.cpp`), one said the
other. I nearly resolved it 2-to-1 and left a note.

**The vote was not the evidence.** `func_CameraImplUpdateShake`
(`FUN_007A67C0`) settles it in one line:

```c
v6  = distance / a3->v4;                      // v4 = +0x0C, the range
if (v6 >= 1.0) v6 = 1.0;
v10 = (1.0 - elapsed/duration)
    * ((a3->v6 - a3->v5) * v6 + a3->v5);      // v5 = +0x10, v6 = +0x14
```

`(field@0x14 - field@0x10) * distanceFactor + field@0x10`. At distance **zero**
the result is `field@0x10`; at the range limit it is `field@0x14`. So `+0x10` is
the **epicentre** magnitude -- the larger one in any sane use -- and the name
`mMinMagnitude` stated the exact opposite. Renamed to `mMagnitudeAtCenter` /
`mMagnitudeAtMaxRange` in `c54f809a`.

The producer, the one declaration that disagreed, had been right all along.

## The rule

**A field name in recovered code is a hypothesis, not evidence.** When two
declarations of the same offset disagree:

1. Find the arithmetic that **consumes** the field in the `.c`, not another
   declaration of it. Interpolation endpoints, comparison directions, divisors
   and clamps all pin semantics that a name cannot.
2. Cross-check from the **producer** end too -- what the Lua binding or caller
   passes in. Agreement from both ends is conclusive.
3. Only then rename, and record the derivation on the field so the next reader
   does not have to redo it.

Counting declarations is a popularity contest among guesses. Three files
repeating the same wrong name is one mistake copied twice, which is exactly what
the duplicate-layout contract exists to stop -- see
[[project_sim_sync_partial_lift_hid_every_unit]] for two more 0x1C/0x0C structs
declared two and three times over.

A name that reads as documentation and says the opposite of the truth is worse
than `field_0x10`, because it stops the next person looking.

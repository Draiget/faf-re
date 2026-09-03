---
name: project-cformationinstance-base-missing
description: CFormationInstance is a real intermediate base the repo flattened into CAiFormationInstance; its RType is never registered, so formation serialization asserts.
metadata:
  type: project
---

The binary has a **three-level** formation hierarchy:

```
IFormationInstance
  └─ CFormationInstance      MemberDeserialize 0x005741D0 / MemberSerialize 0x005744E0
       └─ CAiFormationInstance  MemberDeserialize 0x0059E950 / MemberSerialize 0x0059E9B0
```

`src/sdk/moho/ai/CAiFormationInstance.h` **flattens all three into one class**
(`CAiFormationInstance : IFormationInstance`, size 0x330). The intermediate
`CFormationInstance` does not exist in source.

**The layout is NOT the blocker.** Both tokens are marked
`blocker_type=owner_layout`, which is wrong — I derived every field offset from
the `lea edx,[edi+N]` displacements in `FUN_005744E0.asm` and all **15 of 15**
match asserts already in the header:

| off | binary field (IDA) | header field |
|---|---|---|
| 0x10 | mState | mLuaState |
| 0x14 | mGamerules (RRuleGameRulesImpl*) | — |
| 0x18 | mCommandType | mCommandType |
| 0x20 | mUnits `fastvector<WeakPtr<IUnit>>` | mUnits |
| 0x50 / 0xF8 | mOffsetInfo[0..1] `fastvector<SOffsetInfo>` (stride 0xA8) | mLanes |
| 0x1A0 | mSlots `fastvector<SAssignedLocInfo>` (0x110) | mOccupiedSlots |
| 0x2B0 / 0x2BC | mMap1/mMap2 `map<EntId,SCoordsVec2>` | mCoordCachePrimary/Secondary |
| 0x2C8 | mPos1 Vector3f | mForwardVector |
| 0x2D4 / 0x2E4 | mOrientation / mOrientationChng Quatf | same |
| 0x2F4 | mScriptName (string, 0x1C) | mScriptName |
| 0x310 | mCoord SCoordsVec2 | mFormationCenter |
| 0x318 / 0x31C / 0x320 | mVal2 f / mPlanUpdate b / mMaxSize i | same |

`CAiFormationInstance`'s own serializers are already faithful — they write the
base payload via `archive->Write(CachedCFormationInstanceType(), this, owner)`
then the `Sim*` at 0x328. That is exactly what the binary does.

**The live defect:** `CachedCFormationInstanceType()`
(`CAiFormationInstance.cpp:552`) resolves the base by *name* via
`ResolveTypeByAnyName({"CFormationInstance", "Moho::CFormationInstance"})`, and
nothing in `src/sdk/**` ever registers a `CFormationInstance` RType — there is no
`CFormationInstanceTypeInfo`. So it returns null, the `GPG_ASSERT(baseType)`
fires, and formation save/load never round-trips.

The real unblock order is: split `CFormationInstance` out as the intermediate
base → add its TypeInfo + preregistration → recover its serializer pair
(0x005741D0 / 0x005744E0) → keep the existing 0x330 asserts working. Related:
[[project_cformationinstance_split_blocked]] (records the older "blocked on the
formation Lua subsystem" framing), [[project_descriptor_registration_vein]] (the
same "ctor preregisters but nothing constructed → LookupRType threw" pattern).

---
name: project-descriptor-registration-vein
description: Reflected types constructed but never preregistered.
metadata:
  type: project
---


## Inverse case found 2026-08-17: constructed but ctor never registers

`dc472be` fixed `RWeakPtrType<STaskEventLinkage>`. Its bootstrap
(`register_RWeakPtrType_STaskEventLinkage`, 0x00BC2F90) existed and did
touch the global `gRWeakPtrTypeSTaskEventLinkage` to force construction -
but the class declared **only a destructor**, so the default ctor ran and
`gpg::PreRegisterRType` was never reached. Recovered the ctor at
0x00407E10; the vftable stores the binary makes are what the C++ base
initialisers emit, so the registration call is the only real behaviour.

### Sweep recipe, and its false-positive mode

Find `gpg::RType` subclasses that declare a dtor but no default ctor:

    class\s+(\w[\w:<>]*)\s*(?:final\s*)?:\s*public\s+gpg::RType

That gives ~59 hits. Most are fine - they register from a **named
registrar function** rather than from the ctor, e.g.
`moho::register_EntitySetTemplateUnitVectorType()`
(`ArmyUnitSetVectorReflection.cpp:178`).

**Do not filter by looking for the class name inside the
`PreRegisterRType(...)` argument.** The argument is a `typeid` of the
*represented* type, not the descriptor class - e.g.
`PreRegisterRType(typeid(msvc8::vector<moho::SEntitySetTemplateUnit>), type)`
for `RVectorType<SEntitySetTemplateUnit>`. That mistake reported 8 false
candidates.

The correct test is per-class: does **any** reachable path construct the
descriptor and call `PreRegisterRType` with it as the second argument?
Grep the owning `.cpp` for `PreRegisterRType` and check the second
operand, or for a `register_*` / `Acquire*Type` helper.

### Vein is now CLEAN (audited 2026-08-17)

Applying the corrected per-class test to all 8 raw candidates: every one
of the other seven (`RBoolType`, `RIntType`, `RStringType`,
`RFastVectorType<CAniPoseBone>`, `DColPrimSphereTypeInfo`,
`RWeakPointerType<INetNATTraversalProvider>`,
`RVectorType<PrefetchHandleBase>`) calls `PreRegisterRType` from its own
`.cpp`. `RWeakPtrType<STaskEventLinkage>` was the last unregistered
descriptor in the tree. Do not re-run this sweep expecting more hits.


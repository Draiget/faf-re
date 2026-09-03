---
name: project-lua-class-binders
description: How the engine binds a C++ class into Lua - a per-class metatable factory plus a CScrLuaClassBinder that publishes it at moho.<x>_methods - and how to read the 31 binder records out of the image.
metadata:
  type: project
---

Binding a C++ class into Lua takes two halves, and both were broken on the sim
side until `73bf269`.

**Half one: the per-class metatable factory.** Every `CScrLuaBinder` names a
`CScrLuaObjectFactory*`, and the binary always names the *concrete* class:
`&Moho::CScrLuaMetatableFactory<Moho::CAiBrain>::sInstance` for all 71 CAiBrain
method definitions, `<Moho::Entity>` for all 65 Entity ones, and so on. Our tree
had `CScrLuaMetatableFactory<CScriptObject*>` in CAiBrain.cpp (66), Entity.cpp
(50), CAiAttackerImpl.cpp (17) and the Entity block of Sim.cpp (14), so those
methods landed in a table nothing reads. Only `CScrLuaObjectFactory.cpp` and
`GetScriptObjectMetatable` legitimately use the `CScriptObject*` specialisation.

To check a class quickly:

    grep -l 'mClassName = "<Name>"' decomp/.../*.c | xargs grep -h 'mFactory = '

**Half two: the class binder.** A `CScrLuaClassBinder` publishes that factory's
table at a dotted Lua path, which is what the matching Lua module builds its
class from - the first line of `/lua/aibrain.lua` is
`AIBrain = Class(moho.aibrain_methods)`. Without it the module raises, the
engine logs "Can't find AIBrain, using CAiBrain directly", and nothing scripted
works.

The image publishes **31** of them. The 16 Maui ones were already in
`UiRuntimeTypes.cpp`. The other 15 had been recovered as inert "startup lane
anchor" functions that explicitly suppress the prepend and publish nothing, or
were missing outright:

| path | class | set | thunk |
|---|---|---|---|
| aibrain | CAiBrain | Sim | 0x00BCB6C0 |
| aipersonality | CAiPersonality | Sim | 0x00BCD730 |
| blip | ReconBlip | Sim | 0x00BCDC10 |
| entity | Entity | Sim | 0x00BD5300 |
| manipulator | IAniManipulator | Sim | 0x00BD2C00 |
| navigator | CAiNavigatorImpl | Sim | 0x00BCC760 |
| platoon | CPlatoon | Sim | 0x00BDAD90 |
| projectile | Projectile | Sim | 0x00BD65E0 |
| prop | Prop | Sim | 0x00BD9A30 |
| shield | Shield | Sim | 0x00BDD4C0 |
| unit | Unit | Sim | 0x00BD7910 |
| weapon | UnitWeapon | Sim | 0x00BD8790 |
| lobby | CLobby | User | 0x00BDFE10 |
| discovery_service | CDiscoveryService | User | 0x00BDFDB0 |
| sound | HSound | Core | 0x00BC6A90 |

**How to read a binder record out of the image.** The records are statically
initialised in `.data`; the decompiled `.c` exports do not contain the strings,
so read the PE directly. Find the `moho\.[a-z0-9_]+_methods\x00` strings, scan
the data sections for a 4-byte pointer to each, and the record starts 4 bytes
earlier - `CScrLuaInitForm` is `{vftable, mName, mGroupName, mDocString,
mNextInSet}` and `CScrLuaClassBinder` adds `mClassFactory` at +0x14. The class
string and the factory pointer both fall straight out. To find which set a
record belongs to, search the image for `C7 05 <setHead> <recordVA>` - the
registration thunk - and read the set object 4 bytes below the head pointer,
whose first field is its name: 0x00F5967C "Core", 0x00F5968C "User",
0x00F5A120 "Sim".

**The trap this leaves behind.** A registrar that publishes nothing still has a
caller, still has an address comment, and still looks recovered. When a class
lookup falls back at runtime, check whether its binder actually constructs a
`CScrLuaClassBinder` before assuming the Lua side is at fault.

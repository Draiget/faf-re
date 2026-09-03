---
name: project_scriptmodule_never_populated_prop_throw_storm
description: REntityBlueprint::mScriptModule is never populated, so every entity falls into the synthesised <id>_script.lua path. For 5182 props that file does not exist, and each one raises a Lua error - 3000+ C++ throws during Sim::Setup. Retail emits ZERO of these warnings. Both halves verified against the binary.
metadata:
  type: project
---

## The symptom

Our SCMP_009 log, at `NUM PROPS = 5182`:

```
446 warning: Unable to find file /env/evergreen/props/rocks/rockNN_script.lua
446 warning: Problems loading module '/env/evergreen/props/rocks/rockNN_script.lua'.
              Falling back to 'Prop' in '/lua/sim/prop.lua'.
462 warning: stack traceback: [C]: ? / ...lua\system\import.lua: in function `import'
```

Retail on the same map: **zero** of any of them -- not "Problems loading
module", not "exists but doesn't define", not "Can't find module", not "Can't
tell the type", not "Unable to find file". See
[[reference_retail_engine_ab_oracle]].

`dbgrun` counts **3000 first-chance C++ throws** (its cap) during the run, and
throw #3000's stack is exactly this:

```
  !CxxThrowException
  main!luaD_call                        [LuaObject.cpp:16855]
  main!LuaCallProtected / LuaFunction::operator()
  main!moho::CScriptObject::RunScript<> [CScriptObject.h:224]
  main!moho::Prop::Prop                 [Prop.cpp:607]
  main!moho::Prop::CreateFromBlueprintResolved / PROP_Create
  main!moho::Sim::Setup                 [Sim.cpp:10083]
```

Every prop that fails costs a full C++ throw and unwind inside sim setup.

## Both halves of our side are FAITHFUL -- the gap is upstream

- **The `<id>_script.lua` synthesis is in the binary.** `FUN_00677360`
  (`ResolveBlueprintScriptFactory`) does
  `assign(v33, blueprint->mScriptModule); if (!v33._Mysize) { substr(mSource, 1,
  rfind('_')-1); "/" + that + "_script.lua"; }`. Reached only when
  `mScriptModule` is **empty**.
- **Erroring on a missing file is in the binary.** `FUN_004CE2C0`
  (`func_LuaDoScript`) at `0x004CE343` pushes `"Unable to find file %s"`, and
  the decompile at line 240-246 does `STR_Printf` then `LuaPlus::LuaState::
  Error`. Identical to ours. Do not "fix" either of these.

`FUN_00677360` is called from `Moho::Entity::Entity` (its only xref,
`0x00677CFA`), i.e. **per instance**, in retail too -- so retail is not caching
its way out of this either.

## Therefore

**`REntityBlueprint::mScriptModule` (+0x70) is populated in retail and empty in
ours.** The reflection field exists and is registered --
`REntityBlueprintTypeInfo.cpp:801`,
`AddFieldWithDescription(typeInfo, "ScriptModule", CachedStringType(), 0x70,
"Module defining entity's class.")` -- and the raw `.bp` file does **not** set
it (checked `env.nx2` -> `env/Evergreen/Props/Rocks/Rock05_prop.bp`: no
`ScriptModule`, no `ScriptClass`). So the value comes from Lua
post-processing (`/lua/system/Blueprints.lua`) writing it back into the C++
blueprint, and that write-back is what is missing on our side.

It is masked for units because the synthesised path
`/units/uel0001/uel0001_script.lua` happens to exist. Only props, whose scripts
genuinely do not exist, expose it.

## Next step

Find where blueprint post-processing hands the table back to
`REntityBlueprint` and confirm whether string fields are copied back at all, or
only before post-processing runs. Compare the ordering against the binary.

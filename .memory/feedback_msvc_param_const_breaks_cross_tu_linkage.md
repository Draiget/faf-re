---
name: feedback_msvc_param_const_breaks_cross_tu_linkage
description: TECHNIQUE. A top-level const on a POINTER parameter changes the MSVC decorated name (Q vs P), so a function defined as f(T* const) cannot be linked against a cross-TU declaration of f(T*). Three LNK2019s in this tree were this, not missing bodies. Find them with dumpbin /SYMBOLS on the .obj.
metadata:
  type: feedback
---

## The trap

MSVC encodes a **top-level `const` on a pointer parameter** into the decorated
name:

| Source | Decorated fragment |
|---|---|
| `f(lua_State* luaContext)`       | `PAUlua_State@@` |
| `f(lua_State* const luaContext)` | `QAUlua_State@@` |

So a function **defined** as `f(T* const)` and **declared** in another TU as
`f(T*)` produces two different symbols. The definition compiles, the caller
compiles, and the link fails with LNK2019 — while the source looks perfectly
correct at both ends.

**Same-TU cases are safe** and must be left alone: when the declaration sits
above the definition in the same file, the compiler emits the declaration's
symbol. `cfunc_UnitShowBone` defines with `const` and links fine because
`Unit.cpp` declares it at `:686`. The bug only bites when the *only* other
reference is in a different TU.

## Confirmed instances (all fixed 2026-09-02)

- `cfunc_CreateThrustController` (`CThrustManipulator.cpp`) — commit `4d7bb0fd`
- `cfunc_CreateStorageManip` (`CStorageManipulator.cpp`) — commit `4d7bb0fd`
- `SetConstructResultSharedAniSkel` (`CAniResourceSkelConstruct.cpp`) — `b18bb989`

All three were *defined at namespace scope and compiled*. Nothing about them
looked wrong; the earlier note calling `cfunc_CreateThrustController` a
"cross-TU file-private helper" trap (CLAUDE.md) mis-diagnosed the cause.

## How to find them — dumpbin is decisive

Do not reason about it from source. Compare what the object actually exports
against what the linker asked for:

```powershell
$dumpbin = "<VS>\VC\Tools\MSVC\<ver>\bin\Hostx64\x86\dumpbin.exe"
& $dumpbin /SYMBOLS "buildstage\main\Win32\Debug\<TU>.obj" | Select-String "<symbol>"
```

A `Q` where the LNK2019 message shows `P` (or vice versa) is this bug. Fix by
removing the top-level `const` from the **definition**, which is also the form
the rest of this codebase declares.

## Why it matters here

`src/sdk/main.vcxproj` links with **`/FORCE`**, so LNK2019s do not fail the
build — `main.exe` is produced anyway and the unresolved call sites survive to
runtime as jumps into nothing. A build that "succeeds" can therefore ship live
call sites that take the process out when reached. Always check the link log
for `error LNK` even when the exe appears. As of 2026-09-02 the tree still had
**37 LNK2019s / 2 LNK2001s**, mostly anonymous-namespace wx bridges
(`?A0x5900937f`) — see [[project_anon_namespace_statics_are_the_wall]].

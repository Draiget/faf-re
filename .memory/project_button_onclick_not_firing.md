---
name: project-button-onclick-solved
description: SOLVED (552966a) - front-end buttons never ran OnClick because CMauiLuaDragger was never a real class, so it had no RType and its DragRelease was an empty probe vtable.
metadata:
  type: project
---

# SOLVED: buttons highlight and depress but OnClick never fires

A MAUI button does **not** act on `MET_ButtonRelease` - `lua/maui/button.lua`
has no such branch. Its `ButtonPress` branch builds a `Dragger()`, hangs
`self:OnClick` off the dragger's `OnRelease`, and calls
`PostDragger(self:GetRootFrame(), event.KeyCode, dragger)`. That last statement
is where the whole click completes.

## Root cause

`CMauiLuaDragger` was a forward declaration. `cfunc_InternalCreateDraggerL`
allocated 0x3C bytes, cast to it, and installed an `IMauiDragger` vtable copied
off a local `MauiDraggerVtableProbe` whose slots were all empty. So:

  - no RTTI and no reflected type, so `REF_FindTypeNamed("CMauiLuaDragger")`
    returned null and `SCR_FromLua_CMauiLuaDragger` raised out of
    `cfunc_PostDraggerL` on its third argument - killing the Lua handler on its
    final statement, silently, because `LuaCallProtected` discards the status;
  - and even past that, `DragRelease` was the probe's empty body, so
    `OnRelease` could never have run.

Recovered as the class the binary has: `CScriptObject` at +0x00, `IMauiDragger`
at +0x34, list link at +0x38, ctor FUN_0078DE50, dtor FUN_0078DEF0,
StaticGetClass / GetClass / GetDerivedObjectRef, the three drag slots
forwarding to `OnMove`/`OnRelease`/`OnCancel`, plus `CMauiLuaDraggerTypeInfo`
(FUN_0078DC70 / FUN_0078DCD0 with mSize 0x3C / FUN_0078DD00 / base from
FUN_0078E690).

## The generalisable lesson

A thin class with a hand-installed vtable is a trap twice over: `typeid(*obj)`
gives the wrong dynamic type so the reflection registry cannot find it, and the
slots point at whatever donor class supplied the vtable. When the binary shows
a real class - a ctor calling the base ctor and writing two vtables, its own
RTTI descriptor, an RType TypeInfo - recover it as a real class.

## Debugging notes worth keeping

  - `lua/LuaPrimitives.h` has `#define lua_call LuaCallProtected` and callers
    discard the status, so a C++ throw inside a Lua C function aborts the
    handler with no error, no traceback, and no `catch` firing. Probing
    `luaG_errormsg` catches Lua *runtime* errors but **not** these: `luaL_error`
    comes from the vendored LuaPlus lib and does not route through our copy.
  - The way in was bracketing `cfunc_PostDraggerL` statement by statement. The
    probe that named it was `DRAGPROBE E` never printing while `D` did.
  - `MAUI_SetKeyboardFocus` parks a two-word list node on the stack and splices
    it ahead of the focus owner. Written as two separate locals those words are
    not adjacent in a debug build (guard bytes), and the unlink loop walked off
    the list. Use the typed 8-byte node.

Related: [[project-maui-render-slot-not-override]], [[project-keyboard-input-path]].

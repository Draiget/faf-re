---
name: project-external-dependency-audit-2026-08-21
description: "Audit of the 5,421 external_dependency tokens: the naive __imp_ test is WRONG (statically-linked CRT/wx/WildMagic have no __imp_); only ~328 are engine-range suspects and only 4 are confirmed misclassified"
metadata:
  node_type: project
---

Run 2026-08-21 (batch 34), triggered by finding `FUN_0082DBA0` marked
`external_dependency` while its own note described engine behaviour.

## The naive test is wrong -- do not repeat it

CLAUDE.md says "if you cannot point at an `__imp_*` IAT entry or a documented
external runtime symbol, the function is engine code." Applying only the first
half of that as a mechanical filter gives a **false 81%**: on a 400-token
sample, 325 had >2 instructions and no `__imp_`.

They are almost all correctly classified. **Statically-linked code has a real
body and no `__imp_`** -- the CRT (>= ~0x00A80000), wxWidgets
(~0x0096xxxx-0x0099xxxx), WildMagic3p8, CRI/Sofdec middleware, libpng/zlib.
`__imp_` only identifies *DLL* imports. The "documented external runtime
symbol" half of the rule is what covers the rest, and the terminal-leaf list
(`__imp_*` / CRT / D3D / wx / WildMagic) already names them.

## The filter that actually isolates signal

Keep a token only if **all** hold:
1. address < 0x00900000 (engine range, not the CRT/wx/middleware region)
2. more than 2 instructions (bare `jmp`/`ret` trampolines are defensible either way)
3. no `__imp_` in its `.asm`
4. its note makes no external-library claim (wx / WildMagic / CRT / libpng /
   zlib / Sofdec / CRI / "statically-linked" / "STL template ... external")

That leaves **328 of 5,421**. Of those, by note text:
- **3** are plainly STL/boost instantiated for an **engine** type --
  `FUN_008DBA00` and `FUN_008DBCB0` (`std::map<const type_info*, RType*,
  TypeInfoLess>::_Tree::erase`), `FUN_004E8220`
  (`boost::function1<R,A>::operator()`). CLAUDE.md names this case explicitly:
  templated STL/boost emissions instantiated for engine types "stay
  `recovered` (or `blocked`), **never `external_dependency`**". Their correct
  home is an `Address:` citation on the canonical `msvc8::map` / RbTree.h
  template, per RULE ONE.
- **19** are CRT stream/locale machinery from msvcprt8.lib (`filebuf::uflow`,
  `basic_stringbuf<wchar_t>::overflow`, ...) -- correctly external.
- **306 are unclassified by note text and were NOT reviewed.** Do not assume
  they are wrong. My classifier is keyword matching on prose, which is far too
  weak to conclude anything; each needs its own look.

## Confirmed and fixed this pass: 1

`FUN_0082DBA0` -> `blocked` / `needs_recovered_caller`. 30 instructions, engine
address range, zero `__imp_`, and its only call is to `sub_82F7A0` which is
itself engine code (`msvc8::vector<T>::_Insert_n` for a 4-byte element). Its
own note described engine behaviour ("resets mMapC's bucket vector to a fixed
9-slot span before a rebuild pass").

**Do not mass-flip the other 327.** Batch-marking without per-token proof is
the process bug the rules call out, and an earlier broad audit in this project
produced 54 bad reverts exactly that way
([[project-rpointertype-dbintegrity-falsepositives]]).

Companion to [[project-citation-audit-2026-08-21]], which audited the
`recovered` status the same way.

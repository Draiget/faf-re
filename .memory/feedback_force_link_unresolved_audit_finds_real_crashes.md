---
name: feedback_force_link_unresolved_audit_finds_real_crashes
description: Auditing the LNK2019 list that /FORCE hides is a five-minute technique that finds guaranteed crash sites - it found all three command-path crashes on 2026-09-03
metadata:
  type: feedback
---

`main.vcxproj` links with `/FORCE`, so **LNK2019/LNK2001 do not fail the
build**. Every unresolved external is a call site the linker wired to garbage:
a guaranteed crash the moment that path runs. The build being "clean" says
nothing about them.

**The audit** (cheap, run it whenever a crash has no obvious cause):

```bash
grep -oE 'unresolved external symbol "[^"]+"' <buildlog> | sort -u | grep -v "anonymous namespace"
```

Filter out the wx debug-window constructors (only reachable if the debug
window opens). What is left is the real list. On 2026-09-03 that was four
symbols, three of them on the command-issuing path - a complete mechanical
explanation for "issuing a move command crashes".

**The three root causes, all different, all invisible to the compiler:**

1. **A stray unterminated `/**`** in `UserUnit.cpp` swallowed
   `} // namespace` + `namespace moho {` and ran to the next `*/`. The
   function landed inside the anonymous namespace that opened ~300 lines
   earlier: internal linkage, unused in its own TU, never emitted. Braces
   still balanced, so it compiled with zero diagnostics. Detect with: scan
   block comments for a body line that does not start with `*`
   (`.memory` scan script pattern) - a doc comment whose body contains real
   code or a second `/**` is the signature.
2. **A non-template declaration shadowing a template.** `UICommandGraph::
   HashKeyToBucketIndex(const HashTable<HashListNode88>&, uint32)` was
   declared next to the generalised `template <TNode>` version. Being an
   exact match it won overload resolution at every call site and had no
   definition anywhere. Delete the redundant non-template declaration.
3. **MSVC mangles top-level `const` on pointer parameters.** A definition
   taking `T* const p` decorates as `QA...`; a declaration taking `T* p`
   decorates as `PA...`. Different symbols. `AllocatePackedCommandIdFromManager`
   was defined in Sim.cpp with `const` and declared in CWldSession.cpp
   without. Compare the two objects directly to see it:
   `grep -a -oE "\?Name@moho@@[A-Za-z0-9@_?$]*" build/X.obj`

**Verifying a fix:** byte-grep the object file for the mangled name
(`grep -c Name build/X.obj`). Absent means the compiler never emitted it -
and note that a forced recompile producing a *byte-identical* object proves
the source really is being compiled that way, rather than the object being
stale.

Related: [[project_force_hides_declonly_bridges]],
[[project_anon_namespace_statics_are_the_wall]].

---
name: feedback-function-cutter-failure-modes
description: "The regex function-deleter has bitten repeatedly: it matches call sites as definitions and leaves dangling template headers; here is the safe version and the checks that catch both"
metadata:
  node_type: memory
  type: feedback
---

Deleting a function by regex + brace matching is the workhorse of container
migrations, and it has now failed in four distinct ways across several
batches. Two of them cost a `git checkout HEAD --` revert on 2026-08-21
(batch 47).

## Failure 1: matching call sites as definitions

`^[^\n]*\bNAME\s*\([^;{]*?\)\s*\{` happily matches
`    if (IsNameIndexNil(node)) {`. That deleted twelve call sites and their
enclosing blocks. The tell in the log is a **removal count far above 1** for a
name you expect once (`removed IsNameIndexNil x12`).

Safe finder -- require all of:
  - the line does **not** start with `if|while|for|return|else|switch|do|}|)|,`
  - indentation <= 4 (definitions live at namespace/class scope)
  - there is a return-type token before the name, and the text immediately
    before it does not end with `= ( , && || !`

Always print the per-name removal count and sanity-check it before compiling.

## Failure 2: dangling `template <...>` headers

Cutting a templated function from its signature line leaves the
`template <class T, class U>` line above it orphaned, which then binds to
whatever declaration follows -- in batch 47 it attached to the next `class`,
producing `cannot deduce template arguments` errors pointing at a class that
was never templated.

After any cut pass, scan for it:
```python
if re.match(r'^\s*template\s*<', line) and next_nonblank.startswith(('/**','class ','struct ')):
```
That is a reliable orphan signature: a template header should be followed by a
declaration, never by a doc block or a class.

## Failure 3 (older): swallowing a neighbour when there is no doc block

The doc-block extension must be *proximity guarded* -- only absorb the
preceding `/** ... */` if it ends within ~2000 chars of the signature and the
line before the signature really is `*/`.

## Failure 4: lazy quantifiers splitting identifiers

`&([\w>-]+?)\.?(\w*)` against `&armyStats->mNameIndex` captures `m` +
`NameIndex`, emitting `m.NameIndex` and `armyStats->.mNameIndex`. Use greedy
matching and an explicit alternation for `.`/`->`, or just match the whole
expression and post-process.

## The cheap insurance

These are all recoverable *only because* the file's own last commit was mine:
`git checkout HEAD -- <file>` restored it cleanly. **Commit the previous
increment before starting a cut pass**, so a botched deletion costs one batch
and not another agent's work. Never `git stash` -- see
[[feedback-concurrent-commit-race-orphans-commits]].

## Failure 5: wrapped signatures (return type on its own line)

```cpp
    [[nodiscard]] RRuleGameRulesBlueprintNode*
    LowerBoundBlueprintNodeById(const Map& map, const msvc8::string& id) noexcept
```

The "there must be a return-type token before the name" guard from Failure 1
sees an empty prefix here and skips a real definition -- reported as `x0`.
**A removal count of 0 for a name you can see in the file is this bug.**
Accept an empty prefix when the previous non-blank line ends with `*`, `&` or
a type identifier.

## Scoping, not just cutting: exclude shared helpers

Batch 48 deleted `StoreAdapterLane`, a generic template used by three
unrelated lane families in the same file, because it matched a `*Lane` name
sweep. Never build a deletion list from name patterns. Build it from
*functions whose bodies touch the type being migrated*, then **subtract every
name referenced from a function outside that set**. `*Lane`, `*Adapter*` and
`Store*` are shared vocabulary in this codebase.

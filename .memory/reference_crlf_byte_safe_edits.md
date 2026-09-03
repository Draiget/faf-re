---
name: reference-crlf-byte-safe-edits
description: Many src/sdk files are all-CRLF with one stray bare LF; any text-mode write (including the Edit tool) normalizes it and turns a small change into a whole-file diff. Splice bytes instead.
metadata:
  type: reference
---

Several `src/sdk/**` files are **all-CRLF with a single stray bare LF**. Any
text-mode write normalizes that one byte, and git then reports the entire file
as rewritten: `CAiTransportImplTypeInfo.cpp` produced **120+/107-** for a
~30-line change. **The Edit tool does this too**, so reverting and retrying with
Edit does not help - it is not a Python-only problem.

Why it matters: this checkout is shared with other agents. A whole-file
line-ending rewrite maximises conflict surface and makes the real change
unreviewable.

## Recipe that produces a correct minimal diff

    b = open(p, "rb").read()
    eol = b"\r\n" if b.count(b"\r\n") else b"\n"
    old = b"  line one" + eol + b"  line two" + eol      # build patterns WITH eol
    assert old in b, "anchor not found"
    open(p, "wb").write(b.replace(old, new, 1))

Check before trusting an edit:

    python -c "b=open(P,'rb').read(); print('CRLF',b.count(b'\r\n'),'bareLF',b.count(b'\n')-b.count(b'\r\n'))"

**Always `git diff --stat` before committing.** A changed-line count near the
file's total line count means it normalized - revert and redo byte-wise. Landed
correctly this way in 0a10186 (24/11 and 32/15).

Related: [[project-motiontick-chain-walled]] for the other tooling traps found
in the same run.

## Two follow-on traps (hit 2026-08-17)

**1. Detect the *dominant* ending, not merely presence.** `main.vcxproj` is
LF-terminated with a handful of stray CRLFs (2624 LF vs 4 CRLF), so
`eol = CRLF if b.count(CRLF) else LF` picks CRLF and rewrites the whole file.
Count both and compare:

    crlf = b.count(b"\r\n")
    lf   = b.count(b"\n") - crlf
    eol  = b"\r\n" if crlf > lf else b"\n"

The mix varies per file even inside `src/sdk`: `.vcxproj` / `.filters` are LF,
most `.cpp` / `.h` are CRLF. Never assume by extension.

**2. Use raw byte literals for Windows paths.** In a non-raw literal
`b"moho\ai\Foo.cpp"`, the `\a` is a **bell character**, so the search silently
matches nothing. Write `rb"moho\ai\Foo.cpp"`, and always `assert` the anchor is
present so a bad escape fails loudly instead of no-op'ing.

**3. Writing this note is subject to trap 2.** A heredoc'd Python string
containing backslash-r-backslash-n will emit real newlines into the markdown.
Use a raw string (`r"""..."""`) when documenting escape sequences.

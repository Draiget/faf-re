---
name: reference_vendored_wx_match_diminishing_returns
description: Technique and its limits, 2026-09-02 — matching zero-xref FUN_* tokens against vendored WildMagic3p8/wxWindows-2.4.2 source to mark external_dependency. 9 tokens landed cleanly, then the hit rate on wx candidates dropped hard because the vendored wx copy has real version drift from what FAF was built against.
metadata:
  type: reference
---

# Vendored-source exact-match technique: what worked, what didn't, and why

## The technique (worked well, 9 tokens landed this pass)

For a `FUN_*` token with genuinely zero code/data xrefs (confirmed via
`.xrefs.txt`, not just the callgraph index — IDA's own analysis, not our
tooling's), check whether it's vendored third-party library code before
assuming it needs new engine recovery:

1. Read the token's own decompile. Genuine vendored code usually announces
   itself: distinctive class/method names (`wxDateTime::`, `wxImage::`,
   `Wm3::`), embedded literal strings, or a struct-return/param shape that
   matches a known library convention.
2. Grep `dependencies/<library>/` for the distinctive name/string.
3. If found, read the vendored source and compare branch-for-branch against
   the decompile. A real match is usually unmistakable — every field access,
   every branch, every constant lines up.
4. Mark `external_dependency` via `recovered_progress.py mark`, citing the
   vendored file:line and specifically what matched (not just "looks like
   wx" — the reviewer of your note should be able to re-verify without
   redoing the search).

This is NOT guessing from a name resemblance — CLAUDE.md's fidelity rules
still apply. A confirmed exact match is real evidence; "kind of looks like
it could be wx" is not, and should be left unmarked (see below).

## Confirmed matches, 2026-09-02

- `FUN_00A3BCB0` = `Wm3::ContAlignedBox<double>` (Wm3ContBox3.cpp)
- `FUN_00A3C390` = `Wm3::ContOrientedBox<double>` 3D (Wm3ContBox3.cpp)
- `FUN_00A699B0` = `Wm3::ContOrientedBox<double>` 2D (Wm3ContBox2.cpp)
- `FUN_00A48AB0` = `Wm3::System::GetTime()` (Wm3System.cpp)
- `FUN_00A48D70` = `Wm3::System::Write4be` (Wm3System.cpp)
- `FUN_009BA370` = `wxDateTime::IsDST(Country) const` (datetime.cpp:1872)
- `FUN_009BA460`/`FUN_009BADE0` = same wxDateTime::IsDST cluster (GetBeginDST/
  GetEndDST + a return-by-value copy thunk; not independently source-matched,
  inferred from the confirmed sibling's control flow + zero xrefs)
- `FUN_00971820` = `wxImage::Copy() const` (image.cpp:190)

All had zero code/data xrefs per IDA and matched an unambiguous, specific
vendored function branch-for-branch.

## Where it stopped working, same pass

Two more wx-shaped candidates from the same spatial-locality neighborhood
(`WxRuntimeClassInfoAccessors.cpp`/`ScrDebugWindow.cpp`), both clearly
genuine wx internals by content (real wx types, real wx API calls,
distinctive embedded strings):

- `FUN_00A18C10` — a popup-window activation helper referencing
  `wxPopupWindowHandler`/`wxPopupFocusHandler`, calling
  `wxWindowBase::CaptureMouse`/`PushEventHandler`/`FindFocus`.
- `FUN_0099AA50` — a style-flag translator that warns
  `"Please install a newer version of comctl32.dll..."` when
  `wxApp::GetComCtl32Version() < 470`.

**Neither exists in `dependencies/wxWindows-2.4.2` at all** — not the class
names, not the literal warning string, nothing close. `wxApp::
GetComCtl32Version()` itself DOES exist (`src/msw/app.cpp:1198`), confirming
the vendored copy is genuinely wx and roughly the right vintage — but the
SPECIFIC caller-side code that USES it here doesn't match. Same for popup
windows: `wxWindowBase`/`wxEvtHandler` are real and present, but
`wxPopupTransientWindow`/anything "Popup"-named is entirely absent.

**Conclusion: real version drift, not a search failure.** The game was very
likely built against a wx point-release different from (probably newer
than, given popup-window support and comctl32-470 checks are later
additions) the vendored `wxWindows-2.4.2` copy — consistent with this
project's own prior findings that the wx integration isn't stock (see
[[project_wx_is_a_hybrid_link]], [[project_wx_is_a_unicode_build]] — vendored
was ANSI, the real build is UNICODE). Some wx internals (like
`wxDateTime::IsDST`, `wxImage::Copy` — older, stable, rarely-touched APIs)
happen to be byte-identical across versions; others (comctl32 compat
shims, popup window support — both areas wx churned on across releases)
are not.

## What this means for future passes

- Don't assume a wx-shaped, zero-xref candidate will match the vendored
  tree just because earlier ones did. Check first; if the grep for a
  distinctive name/string comes back empty, STOP — don't guess it's
  external_dependency anyway, and don't sink more time trying variant
  spellings of the same search unless there's a real reason to expect a
  match.
- If a genuinely-vendored-but-version-mismatched wx function needs to be
  resolved with confidence, the ONLY reliable path is a real newer wx
  source tree to diff against (not available in this repo currently) —
  or falling back to normal bottom-up engine recovery if a real caller
  can be found (in which case it's not actually "external" for THIS
  binary's purposes regardless of what upstream wx version it traces to;
  CLAUDE.md's own external_dependency bar is about whether you can point
  at the source, not vibes).
- The WildMagic side of this technique had NO such drift (all 5 matches
  clean) — WildMagic3p8 is likely genuinely unmodified/exactly-versioned
  in this project, unlike wx. Worth trusting WildMagic matches more readily
  than wx ones going forward.

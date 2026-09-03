---
name: feedback-operator-new-size-audit-technique
description: Pair every `operator new(N)` in the corpus with the type/ctor at the site, then join against our sizeof asserts — finds real layout bugs cheaply and needs no runtime.
metadata:
  type: feedback
---

# The `operator new(N)` size audit

A whole-corpus, static, no-runtime way to find layout errors. Landed two real
fixes on its first run (`aec8130b`, `b576d510`) plus an out-of-bounds read.
**Reach for this when runtime verification is blocked** — it needs nothing but
the decompiled corpus and the tree.

**Why:** the binary tells us the exact size of every heap-allocated class, and
that is checkable against our recovered `sizeof` without running anything. A
class we model too small is a silent corruptor wherever anything reaches past
our object; a class we model at the wrong size is a layout error regardless.

**How to apply** (scripts in the session scratchpad, ~40 lines each; rewrite
rather than hunt for them):

1. **Pass 2 first, not pass 1.** The high-yield extraction reads the type
   straight out of the cast — `v1 = (BinaryReadArchive *)operator new(0x44u);`
   — over all `*.c` in the namespace dir. That gave 437 named types. Pairing
   `operator new` with a following ctor call (pass 1) gave only 124 and needs
   a keyword filter, because `if (v3)` parses as a call with `v3` as its first
   argument and swamps everything.
2. Join against `static_assert(sizeof(X) == N)` in `src/sdk`, bucketing into
   MISMATCH / NO-ASSERT / OK. **Match `FAF_RUNTIME_LAYOUT_ASSERT` too** — a
   plain `static_assert` regex reported CSimDriver as ungated when it was not.
3. Probe our real sizes in bulk with `char (*p)[sizeof(T)] = 1;` in a scratch
   TU — the C2440 names the size (`cannot convert from 'int' to 'char (*)[40]'`).
   One tucheck gets many sizes; MSVC will not print a size from a failing
   `static_assert`.

## Triaging MISMATCH — most are false positives, and they have tells

Of 21 mismatches, 2 were real. Check the site before believing any of them:

- **Base-typed cast of a derived allocation.** `(ReadArchive *)operator new(0x44u)`
  calling `gpg::ReadArchive::ReadArchive` is a *BinaryReadArchive*; the base is
  genuinely 0x38. Same for `(CMersenneTwister *)operator new(0x9CCu)`, which is
  a `CRandomStream`.
- **Interface-typed casts.** `IAiNavigator` 0x8c, `ISoundManager` 0x720,
  `CameraImpl` 0x858 — all concrete subclasses through an interface pointer.
- **Exception allocations reusing a typed variable.** `(gpg::PipeStream *)operator
  new(0x28u)` is a `std::runtime_error` being thrown; IDA reused `v1`.
  Suspect this whenever *our* size is BIGGER than the binary's.

**A hit is real when the cast type AND the constructor invoked on the result are
both the same concrete class.** That is what made STIMap (two sites,
`operator new(0x1548u)` + `STIMap::STIMap`, asserted 0x1544) trustworthy.

## Locating the missing bytes

Grep the ctor/dtor `.asm` for the highest offset touched
(`\[(ecx|esi|edi|ebx)\+[0-9A-F]+h\]`), and grep the whole corpus for
`\+<offset>h\]` to see if anything reads the gap. Twice now the answer was a
trailing 4-byte field that nothing initializes or reads — recorded as
`field_0x1C` / `field_0x1544` per the offset convention rather than guessed a
name for.

**Rule out alignment padding before adding a field.** A type is only rounded up
if some member forces 8-byte alignment. For STIMap the candidate was
`LuaPlus::LuaObject`, and `sizeof(LuaObject) == 0x14` settles it — not a
multiple of 8, so it cannot be 8-aligned, so 0x1544 is not rounded to 0x1548.

## Free side effect

Derived classes turned up two archives keeping a plain duplicate of their
stream handle beside the shared owner, with every read/write slot using the
duplicate (`fread(..., this->str)`, `mov eax,[ecx+28h]`). That is the engine's
own idiom — `TextWriteArchive` already modelled it — and it is what makes those
classes 0x44/0x2C instead of 0x40/0x28.

## Companion audit: RuntimeView overrun — CHECKED CLEAN 2026-09-01

The sibling bug class, and the one that produced both known heap corruptors:
a class whose fields are declared by an `<X>RuntimeView` instead of as real
members has a tiny `sizeof(X)` while its constructor writes through the view to
the view's full extent, so a plain `new X` smashes the heap. That is
`CD3DPrimBatcher` writing 0x120 bytes past a 4-byte allocation
([[project_lua_gc_upvalue_corruption]], fixed `60ec20f`) and why `CameraImpl`
must be allocated with `kCameraImplRuntimeSize`.

The audit: collect every `struct <X>RuntimeView`, take its extent as the highest
`offsetof(<X>RuntimeView, …)` assert, and intersect with classes constructed by
a plain `new <X>`. 1950 views reduce to **6** candidates. Verify each by probing
the real `sizeof` and comparing:

| class | view extent | our sizeof | binary | verdict |
|---|---|---|---|---|
| CMauiScrollbar | 0x154 | — | 0x158 | safe: `AllocateZeroedUiObject<T>(0x158u)` + placement new |
| CD3DPrimBatcher | 0x120 | 0x124 | 0x124 | safe: real members, matches exactly |
| UserCommandIssueHelper | 0xC8 | 0xD8 | — | safe: object outgrows the view |
| CAiAttackerImpl | 0xA0 | 0xA4 | 0xA4 | safe: matches exactly |
| CEconStorage | 0x4 | — | — | trivially safe |
| PathQueue | 0x0 | — | — | trivially safe |

**All six clean — do not re-hunt this without new evidence.** Two script
gotchas that cost a false alarm each: the `new <X>(` regex matches *placement*
new and matches inside comment blocks, so read every hit before believing it.

Related: [[project_d3d9_zero_adapters_is_host_not_code]] (why runtime was
blocked when this was written), [[project_mistyped_void_fields]],
[[project_lua_gc_upvalue_corruption]], [[project_lua_gc_string_table_corruption]]
(whose lesson — never substitute lane assignment for a container `cpy` — was
also swept clean: no surviving cross-container `.start_ = other.start_` sites).

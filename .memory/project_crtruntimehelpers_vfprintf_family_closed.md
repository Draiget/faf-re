---
name: project_crtruntimehelpers_vfprintf_family_closed
description: Recovered the whole untokenized-gap cluster of vfprintf/fprintf CRT variants sitting right after fprintf's body in CrtRuntimeHelpers.cpp (0xA85D11-0xA85D8E callers, 0xA8841A-0xA88490 cores) -- 10 functions across 4 commits, found via direct objdump disassembly since IDA never tokenized the small varargs-wrapper bodies separately. One more candidate (_vfprintf_p at 0xA884AC, mirrors _vfprintf_s) found but left unrecovered -- genuinely zero callers, code and data.
metadata:
  type: project
---

## Technique (reusable)

`fprintf`/`vfprintf` were already recovered in `CrtRuntimeHelpers.cpp`,
both thin forwards into a shared dispatcher `RuntimeDispatchLockedFormattedOutput`
(`FUN_00A882CC`) whose own doc comment already named FOUR callback
variants it's invoked with: `_output_l`/`_output_s_l`/`outfn`/`woutput_l`.
Only the first was wired to a recovered caller. The callgraph index
reported real call edges to the other three cores (`0xA8841A`, `0xA88438`,
`0xA88456`) from addresses like `0xA85D22` -- but `find_callers.py`
couldn't identify those CALLERS, because IDA never tokenized them as
separate functions (`FUN_00A85D22.asm` doesn't exist).

**The fix**: `objdump -d --start-address=0x<VA> --stop-address=0x<VA+N>
-M intel "<path to ForgedAlliance.exe>"` disassembles ANY address range
directly from the real binary, tokenized-or-not. Running it across
`0xA85D10-0xA85DA0` in one shot revealed FIVE small, clearly-bounded
thin wrappers (each a `lea eax,[esp+N]` va_list computation + a few stack
reads + one `call`), each ending in `ret` and separated from the next by
nothing (no padding needed since they're all reachable/real, confirmed by
the earlier `int3` padding immediately after the whole cluster, at
`0xA85D8F` onward, which belongs to a completely different function).

This is the general technique for any "callgraph says a real call exists,
but the caller has no FUN_ token" situation: `objdump` the address range
directly rather than assuming the edge is a phantom.

## What got recovered (all in `src/sdk/moho/misc/CrtRuntimeHelpers.cpp`)

| commit | functions | real addresses |
|---|---|---|
| `1b0630e3` | `_vfprintf_l`, `_fprintf_l` | `0xA8841A`, `0xA85D11` |
| `064e26b1` | `_vfprintf_s_l`, `_fprintf_s_l`, `_fprintf_s` | `0xA88438`, `0xA85D2B`, `0xA85D45` |
| `6dee3e88` | `_vfprintf_p_l`, `_fprintf_p_l`, `_fprintf_p` | `0xA88456`, `0xA85D5D`, `0xA85D77` |
| `b857b384` | `_vfprintf_s` (separate from `_vfprintf_s_l`, null-locale, distinct real address), `fprintf_s` (C11 non-underscore name, own null-check before forwarding) | `0xA88490`, `0xA48EF0` |

Each `_X_l` core is a thin forward into `RuntimeDispatchLockedFormattedOutput`
with a specific callback (`_output_l`/`_output_s_l`/`outfn`) and the
caller's locale; each varargs wrapper (`_fprintf_*`) just builds a
`va_list` and calls the matching `_l` core, either passing its own
explicit locale parameter through or hardcoding `nullptr`.

## Left open, deliberately

**`_vfprintf_p`** (`0xA884AC`, right after `_vfprintf_s`'s body,
same `push 0x0` + `outfn` callback shape as `_vfprintf_s`'s `_output_s_l`
shape) — genuinely **zero** callers, code or data, per
`find_callers.py` (`NO_CALLSITE_EVIDENCE`, `reach: UNREACHED`). Per this
project's callsite-verification rule, not recovered without evidence.
If a caller surfaces later (e.g. via a future IDA re-export or a
data-xref from an unrecognized dispatch table), this is a 3-line
addition mirroring `_vfprintf_s` exactly.

**`0xA884C8`** (right after `_vfprintf_p`) is NOT part of this family —
confirmed via `find_callers.py`: already correctly classified
`external_dependency`, `__imp_ldiv` (the standard C library `ldiv`).
Do not re-investigate this address as part of the printf cluster.

## Also checked and correctly left alone

A parallel WIDE-character stream family (`_vfwprintf_l`/`fwprintf`/etc.)
almost certainly exists somewhere, since `woutput_l` (the 4th callback
the shared dispatcher's own doc comment names) is already used elsewhere
in this file (lines ~5289/5347, via a *different* helper called
`vwprintf_helper`, not `RuntimeDispatchLockedFormattedOutput`) — but no
wide-stream dispatcher analogous to `RuntimeDispatchLockedFormattedOutput`
was found near this cluster. Worth a dedicated look in a future pass;
not attempted here (would need to first locate the wide dispatcher's own
address before hunting its callers the same way).

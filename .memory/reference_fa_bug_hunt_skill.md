---
name: reference_fa_bug_hunt_skill
description: skills/fa-bug-hunt - invariant-first gameplay bug hunting across Lua sim + recovered engine, with a state machine that blocks closure while sites are open
metadata:
  node_type: memory
  type: reference
---

`skills/fa-bug-hunt/SKILL.md` (untracked — `skills/` is gitignored in this repo,
like every other skill here).

**Core rule: never reason about a consumer of state before enumerating every
producer of that state.** The air-staging bug was mis-analysed exactly that way
— the engine predicate `Health == MaxHealth` was found and confirmed, which
explained nothing, because nobody asked what makes `Health > MaxHealth`.

Method: name the invariant → enumerate ALL producers of its operands →
filter to those that can *lower* a ceiling (`Duration != -1`) → read the
mutation path line by line → follow each Lua setter into the engine (do NOT
assume it clamps) → verify against disassembly → close only when every site
is terminal.

Scripts:
- `unpack_gamedata.py` — extraction with verified precedence, writes `_origin.json`
- `enum_state_producers.py --affect X [--flag Y] [--transient-only]` — buff/modifier
  enumeration incl. runtime-built buffs in unit scripts
- `bughunt_state.py init|add|set|status` — site state machine; `status` exits
  non-zero while any site is non-terminal and refuses evidence-free terminals.
  Hunts persist under `decomp/recovery/bughunts/<name>.json` (gitignored).

Key asymmetry it encodes: `SetHealth` routes through `AdjustHealth` and IS
clamped; `SetMaxHealth` (0x0068D790) is a bare store and is NOT. That asymmetry
is invisible from the Lua side and is the whole air-staging bug.

Worked example reduced 26 MaxHealth producers to the 2 that matter.

Related: [[project_gamedata_archive_precedence]] [[project_air_staging_detach_exact_compare]]

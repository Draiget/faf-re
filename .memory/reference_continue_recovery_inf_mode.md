---
name: reference-continue-recovery-inf-mode
description: /continue-recovery takes a run-mode argument — inf / inf=N / stop — enforced by cr_run_guard.py, not by intent.
metadata:
  type: reference
---

`/continue-recovery` accepts a **run mode** as its first argument (added
2026-08-13 at the operator's request, because the plain skill stopped after one
batch):

| Arg | Effect |
|---|---|
| *(none)* | once — sentinel self-clears on the first commit touching `src/sdk/**` or `README.md` |
| `inf` / `infinite` / `forever` / `until I stop` | never releases; each landed batch re-arms the sentinel to the new HEAD and re-blocks Stop with "batch N landed, start N+1 now" |
| `inf=N` / `inf:N` | as `inf`, capped at N batches |
| `stop` / `off` / `halt` / `cancel` | clears an in-flight inf run |

Mode and focus hint compose: `/continue-recovery inf=3 effects`.

Implemented in `.claude/skills/continue-recovery/scripts/cr_run_guard.py`
(Stop + UserPromptSubmit hooks, wired in `.claude/settings.json`); documented in
`.claude/skills/continue-recovery/SKILL.md` under "Run modes and arguments".
**Both paths are gitignored**, so `git log` will never show this change — read
the files.

Two things worth knowing:

- **Anti-brick backstops release the guard, and a release is not a finished
  run.** 12 *consecutive* stops with no landed commit, or 48h since the last
  landed batch. The nudge counter resets on every landed batch, so a productive
  loop is never cut off. If a backstop fires, report the stall and its blocker.
- **Merely talking about the skill used to arm it.** The trigger regex matched
  `continue-recovery` anywhere in a prompt, so "the continue-recovery skill
  doesn't loop, can we change it?" armed the guard and blocked a conversational
  answer behind a source commit. `META_MARKERS` now suppresses arming when the
  prompt contains `?` or mentions skill/hook/sentinel/guard.

This is the in-skill alternative to composing `/loop /continue-recovery`;
`/loop` still works and paces at turn boundaries instead of blocking Stop.
Related: [[project_startup_debugging_harness]].

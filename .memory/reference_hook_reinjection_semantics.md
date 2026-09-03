---
name: reference-hook-reinjection-semantics
description: Which Claude Code hooks can actually push text at the model (PostCompact cannot); wiring of rules_reinject.py.
metadata:
  type: reference
---

Verified by disassembling `C:\Users\Draiget\.local\bin\claude.exe` (v2.1.183),
not from docs — the docs list `PostCompact` as if it were a reinjection point
and it is not.

| Hook | What its stdout becomes | Reaches the model? |
|---|---|---|
| `PreCompact` | `newCustomInstructions`, handed to the compaction pass | only via the summary it steers |
| `PostCompact` | `userDisplayMessage` | **NO** — user-visible only |
| `PostToolBatch` | `hookSpecificOutput.additionalContext`, once per tool batch | YES |
| `PostToolUse` / `Stop` / `SubagentStop` / `UserPromptSubmit` / `SessionStart` | `additionalContext` | YES |

So a `PostCompact` hook alone reinjects nothing. The working chain is
**PreCompact (steer the summary) -> PostCompact (arm a sentinel) ->
PostToolBatch (inject on the next tool call)**. `PostToolBatch` is the only
cheap event that fires mid-turn — which is what matters here, because under
`/loop` and `/continue-recovery inf` a turn runs for hours and compacts several
times with no `UserPromptSubmit` in between, so [[project-startup-debugging-harness]]-style
long runs get no rule restatement from `goal_guard.py` at all.

Implementation: `.claude/skills/continue-recovery/scripts/rules_reinject.py`
(modes `precompact` / `postcompact` / `inject` / `sessionstart` / `card` /
`arm` / `status`), wired in `.claude/settings.json`. Arm is consumed per
`agent_id` (max 3, 15-min TTL) so a subagent batch cannot swallow the main
loop's card. `FAF_RULES_CADENCE=n` adds periodic restatement;
`FAF_RULES_DEBUG=1` makes it raise instead of exiting 0.

**Trap:** these guards all `except: pass` so a crash cannot wedge a session.
That swallowed a real bug — box-drawing glyphs in the card raised
`UnicodeEncodeError` on the Windows console codepage and the hook became a
silent no-op that still exited 0. Keep hook output ASCII-only; the `\uXXXX`
escapes written into the source render as non-ASCII at runtime even when the
file itself greps clean. Test with `FAF_RULES_DEBUG=1` before trusting a guard.

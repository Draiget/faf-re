---
name: feedback-uncommitted-work-after-compaction-check-before-avoiding
description: after a context compaction, an uncommitted diff in the shared checkout may be YOUR OWN pre-compaction work, not a peer's live edit -- inspect content and mtime-vs-session-start before steering clear of it or asking a peer
metadata:
  type: feedback
---

Found 2026-09-01 (faf-main-f7), after a peer (faf-main-6b) caught it.

## What happened

Mid-session, `git status` showed a large (~1064-line) uncommitted diff in
`src/sdk/moho/app/WxRuntimeTypes.cpp`. Reasoned it looked like active work
by someone else (a shared checkout, other agents' unstaged edits are
routinely present) and avoided the file entirely rather than risk a
collision, redirecting to a different recovery target.

A peer (`faf-main-6b`) pushed back with a sharper diagnostic: their own
session had touched exactly one file all session (not this one), the diff
was already present when *their* session opened (so not something they'd
started), its mtime was 3+ hours stale (not active editing), and — most
importantly — its *content* (wxString COW-buffer machinery, wxArrayString,
wxFileName path composition) matched wx-cluster work this session's own
prior context (before compaction) had been circling. Checking the actual
diff content confirmed it: this was **my own pre-compaction work**,
uncommitted because the compaction/continuation boundary landed before I'd
gotten to committing it.

## Why this matters

Compaction preserves a *summary* of what happened, not perfect memory of
every edit. A large uncommitted diff surviving across that boundary reads,
from the post-compaction side, exactly like "someone else's unfamiliar
in-progress state" — because in a real sense it *is* unfamiliar; the
fine-grained memory of writing it is gone even though the work is real and
mine. The instinctive caution ("don't touch a shared checkout's unfamiliar
diff") is right for genuinely-foreign state but produces a false positive
here, and the failure mode is expensive: real, finished, tucheck-clean
work sits uncommitted indefinitely while the session goes hunting for a
new target instead of finishing and landing what's already done.

## How to apply

Before treating an uncommitted diff in a shared checkout as "someone
else's active work" and avoiding it:

1. **Check the file's mtime against the peer's/your own session start
   time**, not against "now". A diff that predates every current session's
   start is nobody's *current* live edit — it's a leftover from an earlier
   session (possibly a since-compacted version of yourself).
2. **Read the actual diff content**, not just its size/existence. Does it
   match a cluster/subsystem your own (pre-compaction) context was working
   in? [[project_wxscrollhelper_needs_evthandler_base]] and the wx-cluster
   memory notes are exactly the kind of thread a compaction summary
   compresses down to "deferred, not landed" while losing the fact that
   substantial uncommitted progress toward it already existed.
3. **If it's plausibly yours**: verify it's complete and sound (tucheck
   clean, no TODO/stub/`[[maybe_unused]]`-without-justification markers,
   internally consistent — e.g. a struct moved from one file location to
   another should show a matching deletion at the old site and addition at
   the new one) before committing. Don't commit blind just because it
   compiles.
4. **If it's genuinely a stranger's** (content doesn't match anything you
   were doing, mtime is recent relative to a still-running peer session):
   the original caution still applies — don't touch it, ask.

Cheap habit worth keeping regardless of outcome: when redirecting away
from a file because it "looks like someone else's work," say so to peers
rather than silently pivoting — it gives them the chance to correct a
wrong attribution before real work sits idle for hours.

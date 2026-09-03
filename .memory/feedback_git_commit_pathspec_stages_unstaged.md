---
name: feedback-git-commit-pathspec-stages-unstaged
description: git commit -m "..." -- <path> commits ALL working-tree changes to that path, not just what was git apply --cached'd into the index. Nearly swept another session's ~1064 lines of unrelated work into a commit.
metadata:
  type: feedback
---

**What happened:** isolating one hunk in a shared multi-author file
(`WxRuntimeTypes.cpp`, carrying another session's in-flight wx-cluster
work alongside mine) via `git diff | sed -n '<hunk range>p'` -> hand-built
patch -> `git apply --cached patch.diff` -> `git diff --cached --stat`
confirmed only my 22 lines were staged. Then committed with
`git commit -m "..." -- src/sdk/moho/app/WxRuntimeTypes.cpp` (a pathspec,
because that's what prior sessions' memory recorded as the safe pattern -
see the now-corrected note this file supersedes). `git show --stat HEAD`
immediately after showed 1086 insertions, not 22 - the commit had pulled
in the *entire* unstaged working-tree diff for that path, including all
of the other session's uncommitted work.

**Why:** `git commit <pathspec>` does not commit "what's staged, limited
to this path." It re-stages the pathspec's current working-tree content
first (same effect as `git add <pathspec>` immediately before the
commit), THEN commits the index. Whatever you `git apply --cached`ed
into the index for that path is irrelevant once a pathspec is given -
the working tree wins.

**How to apply:** after `git apply --cached` to isolate one hunk, commit
with a bare `git commit -m "..."` and **no pathspec at all**. The
pathspec-based technique in prior memory (and possibly still described
that way in some skill docs) is wrong for this exact scenario and should
not be repeated. Verify recovery, if it happens anyway: this was caught
immediately via `git show --stat HEAD` before anything left the local
repo, fixed with `git reset HEAD~1` (mixed reset - rewinds HEAD and the
index, leaves the working tree, including the other session's unstaged
changes, completely untouched), then re-`git apply --cached` the same
patch and commit again with no pathspec. `git reset HEAD~1` is safe here
specifically because the over-broad commit was never pushed and the
working tree was never touched by the reset - always confirm both before
relying on this recovery.

See [[project_commander_spawn_script_class_resolution_gap]] for the
session this happened in (the `WRenViewport::Render`
`UpdateRenderViewportCoordinates` fix, commit `234fda53`).

## RESOLVED 2026-09-01: the "other session's" ~1064/1086 lines were mine all along

Same session, after a context compaction. Re-encountered this exact
uncommitted diff (still sitting in the working tree, now read as
~1064 lines) and, this time, reasoned it away as a *peer's* live work
and avoided the file entirely — the inverse mistake from the one this
note originally documents, but rooted in the same misattribution: this
was never a second party's code, it was this session's own wx-cluster
work from before the compaction that lost the fine-grained memory of
having written it. A peer (`faf-main-6b`) caught the second near-miss;
see [[feedback_uncommitted_work_after_compaction_check_before_avoiding]]
for that half of the story. Finally committed clean as `84e8b7b0`
(wxString/wxArrayString COW-buffer machinery + `wxFileName` path
composition) — tucheck passed with no new warnings, no TODO/stub
markers found on inspection.

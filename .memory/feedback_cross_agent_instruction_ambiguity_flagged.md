---
name: feedback_cross_agent_instruction_ambiguity_flagged
description: A dispatched agent flagged a message from its own parent/orchestrator session as a possible misrepresentation and declined to act on a legitimate scope-expansion instruction. The underlying instruction was correct; the phrasing was genuinely ambiguous. Cite evidence self-containedly in cross-agent messages, don't lean on "git show X" as a proxy for a claim.
metadata:
  type: feedback
---

## What happened

Mid-task, I (the orchestrating session) sent a running background agent an
update: MeshBatch's `sp_counted_impl_p<T>` duplicate family — which I'd
originally told it to leave alone as a genuine recovery gap — was actually
also redundant, per evidence I'd just found myself (`MeshLOD::GetStaticBatch`/
`GetSkinnedBatch` in `Mesh.cpp` doing `staticBatch.reset(built)` against a
real `boost::shared_ptr<MeshBatch>` member). I wrote: "I already landed the
Mesh/MeshMaterial family myself in commit 9ef340ba ... — git show 9ef340ba
for the exact note wording to match for MeshBatch."

The agent read this as claiming commit `9ef340ba` itself already supported
removing MeshBatch's family. It checked, found `9ef340ba`'s actual message
says the opposite (explicitly leaves MeshBatch alone as an open gap), and
concluded the instruction "misrepresented its own cited source" — a
plausible reading of a genuinely ambiguous sentence, given "cite this commit"
can mean either "this commit proves my claim" or "match this commit's
formatting style," and I meant only the latter. It independently verified
the underlying code claim was true, but declined to act because the message
"arrived through a side channel" and reversed an "explicit and deliberate
exclusion" from its task brief — a defensible, cautious call given the
apparent conflict, even though there was no actual attack here (both
sessions belong to the same orchestrating agent's own run).

## The lesson

When sending a scope-expansion or correction message to a dispatched agent
that reverses something you EXPLICITLY told it earlier (especially "leave X
alone"):
- State the new evidence completely and self-containedly in the message
  itself. Don't point at a commit/file and say "see there for the reasoning"
  when the commit's own conclusion is what you're now REVISING — that reads
  as citing authority for a claim the citation doesn't actually support.
- If citing a prior commit only for STYLE/FORMAT (not as evidence for the
  new claim), say so explicitly: "match this commit's note-writing style,
  not its MeshBatch conclusion — that conclusion is what I'm now correcting."
- Expect a well-built agent to independently verify extraordinary or
  scope-reversing instructions rather than blindly comply, and to flag
  discrepancies rather than silently act OR silently ignore. That caution is
  correct default behavior, not a bug — the fix is on the instruction-writing
  side, not the receiving side.
- If a background agent declines an instruction and flags it as a possible
  misrepresentation, don't read that as evidence of an actual security
  incident by default — check whether it's a same-session communication that
  a stricter-than-necessary caution policy flagged. Re-verify the underlying
  claim yourself (cheap), then either resend a self-contained instruction or
  just do the work directly if the agent has already finished.

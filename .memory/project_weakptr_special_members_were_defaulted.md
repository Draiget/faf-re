---
name: project_weakptr_special_members_were_defaulted
description: WeakPtr<T>'s copy ctor, copy assignment and destructor were implicit/defaulted, stranding dead nodes in owner chains - the mechanism behind several "corrupt ownerLinkSlot" and heap-corruption crashes
metadata:
  type: project
---

Fixed 2026-09-03, commit `8316e257`.

`moho::WeakPtr<T>` is an intrusive weak-reference node: `{ownerLinkSlot,
nextInOwner}`, threaded onto a chain whose head lives in the owner
(`owner + kOwnerLinkOffset`). Three of its four special members were wrong:

- `~WeakPtr<T>` was `= default` for every `T` except `IUnit`. A node that died
  while still aimed at a live owner **stayed in that owner's chain**.
- the copy constructor was implicit, so a copy claimed membership in a chain it
  was never spliced into;
- copy assignment was implicit, so an assignment abandoned the chain it left.

The binary has real bodies for all three:

| member | address | how it was found |
|---|---|---|
| destructor | `0x005A6DE0` (`WeakPtr<Entity>`), `0x0056AA50` (`WeakPtr<IUnit>`) | the `CDamage` copy-ctor unwind funclets at `0x00BAC2EF` / `0x00BAC2FA` are `mov ecx,[ebp+4]; add ecx,38h/40h; jmp sub_5A6DE0` -- i.e. the member destructor of `mInstigator` (+0x38) and `mTarget` (+0x40) |
| copy ctor | inlined at `0x00736C8F` | `CDamage::CDamage(const CDamage&)`, once per weak lane: store slot, splice at head, no detach |
| copy assign | inlined at `0x00737D52` | `func_DoDamageRing`'s `pointDamage.mInstigator = damage.mInstigator`; it is `ResetFromOwnerLinkSlot` verbatim |

**Why it matters far beyond the one crash.** A stranded node is not merely a
dangling read. The next walk of that chain -- a `Set`, another destructor, or
`ClearWeakObjectChain` -- *writes* through it:
`node->ownerLinkSlot = nullptr; node->nextInOwner = nullptr;`. Two 4-byte zero
stores into heap memory the allocator has since handed to someone else. That is
a wild write that can corrupt anything, which makes this a strong candidate for
crashes with no local explanation, including the Lua GC one
(`traverseproto` / `propagatemarks` faulting on a GCObject).

Reported symptoms it explains:
- `DamageRing` right after spawn -> `func_DoDamageRing` -> `~CDamage` ->
  `WeakPtr<Entity>::ResetFromOwnerLinkSlot` faulting on `*cursor`;
- the two "corrupt ownerLinkSlot" faults already documented on
  `ReplaceInOwnerChain` in `WeakPtr.h` (`0xF2B8458D` from `~Projectile`,
  `0x00C4669D` from a `CAiTarget`). Both investigations concluded the drain was
  correct -- it is; the **departures** were not.

Fixing the template fixed the whole family at once (`CAiTarget::targetEntity`,
`SEntAttachInfo::mAttachTargetWeak`, `IAniManipulator::mTargetEntity`,
`Projectile`'s launcher/collided lanes, ...), which is the RULE ONE payoff:
never fork a per-type copy around a divergence.

**Transferable check:** when a recovered type models an intrusive node, look for
a real per-type destructor emission in the binary before accepting `= default`.
The unwind funclets of any function holding one as a local or member name it
directly. Related: [[feedback_force_link_unresolved_audit_finds_real_crashes]].

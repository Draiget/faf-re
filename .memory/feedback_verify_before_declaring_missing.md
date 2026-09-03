---
name: feedback-verify-before-declaring-missing
description: Four times in one session I concluded a type or function was missing and was wrong every time. A failed grep is not evidence of absence in this tree.
metadata:
  type: feedback
---

**Why:** I reported four blockers this session that did not exist. Each
one cost a batch and one of them shipped a wrong claim in a commit
message that the next batch had to retract.

    "gpg::gal::EffectD3D9 is only forward-declared"
        -> fully implemented in D3D9Interfaces.cpp. I searched --glob '*.h';
           the GAL backend is .hpp.

    "boost::bad_pointer is only forward-declared, nothing to throw"
        -> complete, from <boost/ptr_container/exception.hpp>, and already
           thrown in the same file I was reading.

    "sub_687A70 needs recovering"
        -> already recovered as CopyPrefixedWeakPtrDwordPayloadLane.

    "ProjectBoxOntoAxis / LowerBoundUnitEntityById are unrecovered"
        -> both implemented, and called by name from the recovered caller
           a few lines above.

**How to apply:** before writing "X is missing" in a commit, a note, or a
report, run the checks a failed grep does not cover:

  1. `--glob '*.h*'`, never `'*.h'`. Pre-existing trees use `.hpp`.
  2. Grep the **behaviour or a member name**, not the declaration -
     `SetTechnique`, `ProjectBox`, `LowerBound`. Recovered code uses
     intent-first names with no address annotation.
  3. Check the includes. A vendored library may already supply the type.
  4. If code near your target already compiles against it - a `throw X()`,
     a `static_cast<Base*>` - the type is complete. Incomplete types do not
     compile in those positions. That single observation would have caught
     two of the four above.
  5. Check the body hash against the have-set
     ([[project-icf-twin-pool]]).

And state absence proportionally. "I did not find it with <this search>"
is honest; "it does not exist" needs all five checks behind it. The
strong version, wrong, sends the next session hunting a subsystem that
was already there - see [[project-gal-effect-api-gate]], which claimed a
whole GAL interface was missing and had to be retracted wholesale.

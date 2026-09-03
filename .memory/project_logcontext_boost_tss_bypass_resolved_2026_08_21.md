---
name: project-logcontext-boost-tss-bypass-resolved-2026-08-21
description: Supersedes the legacy project_logcontext_singleton_layout_open note - the ContextStack==ThreadState layout identity question IS resolved; the real remaining blocker on FUN_00937A70's boost TSS chain is a permanent architectural bypass, not a layout unknown
metadata:
  type: project
---

## Status update on the old "LogContext singleton layout OPEN" blocker

The legacy memory note (`project_logcontext_singleton_layout_open`, written
2026-08-20, in the old `~/.claude/projects/<slug>/memory/` path) flagged
`gpg::LogContext` (`src/sdk/gpg/core/utils/Logging.h`) as having an
unresolved layout mismatch: real ctor members `mPtr`/`mLock`/`mTargets`/
`mStringVec` vs modeled `tss`/`rw`/`head`/`lastTls`, with an explicitly
open question about whether `mPtr`'s `boost::thread_specific_ptr<ContextStack>`
key is the same TSS slot as `ThreadState`.

**As of this session, that question is resolved and the layout is correctly
modeled.** `Logging.h` now has:

```cpp
struct ThreadState {
  void* field_0x00{};
  ThreadCtxEntry** begin{};
  ThreadCtxEntry** end{};
  ThreadCtxEntry** cap{};
  std::uint32_t depthCache{};
  // dtor comment explicitly: "matching the original
  // boost::thread_specific_ptr<ContextStack> cleanup callback"
};

struct LogContext {
  core::TssPtr<ThreadState, ThreadStateTssDeleter> tss;  // == real mPtr
  core::SharedLock rw;                                   // == real mLock
  LogTargetNode head;                                     // == real mTargets
  ThreadState* lastTls{};
};
```

`ThreadState` **is** `ContextStack` (confirmed by the recovered
`ThreadState::~ThreadState()`'s Doxygen comment citing `0x00936CC0` as
"`boost::thread_specific_ptr_ContextStack` cleanup body operating on a
ContextStack instance"). `LogContext::LogContext()` (`FUN_00937A70`) is
genuinely recovered and correctly initializes all four real members —
not a fake-recovery, verified by reading the actual constructor body.

## The real remaining blocker (narrower than the old note thought)

`FUN_009379F0` (`boost::thread_specific_ptr_ContextStack::thread_specific_ptr_ContextStack`),
`FUN_00937950` (`boost::function1_ContextStack`), and `FUN_00936B30`
(`boost::detail::tss_adapter_ContextStack::tss_adapter_ContextStack`) stay
`blocked` — but not because of an unresolved layout. `gpg::LogContext::mPtr`
is recovered as `core::TssPtr<ThreadState, ThreadStateTssDeleter>`
(`src/sdk/gpg/core/utils/Tss.h`), a **from-scratch modern reimplementation**
of per-thread storage (a `thread_local` registry keyed by `this`, see
`TLRegistry`/`TlsRegistry()`) — not a literal `boost::thread_specific_ptr<T>`
member. `TssPtr`'s constructor is `constexpr ... = default`; it never calls
into `boost::thread_specific_ptr`/`boost::function1`/
`boost::detail::tss_adapter` at all. So these three functions are
**architecturally bypassed by the modernization already chosen for
`LogContext`**, not merely unwired — recovering them for real would mean
reverting `LogContext::mPtr` to hold an actual
`boost::thread_specific_ptr<ContextStack>` and undoing that modernization,
which is not warranted just to satisfy the invocation rule for three
otherwise-inert vendored-template ctors.

**I found and corrected a DB inconsistency** while investigating this: all
three tokens were `status: blocked` but their `note` text argued they
should be `external_dependency` ("genuine templated boost ctor emission...
so external_dependency", "confirmed... literal vendored Boost 1.34.1
template ctor"). That reasoning is wrong per CLAUDE.md's explicit rule —
templated boost/STL ctors instantiated for **engine types** stay
engine code (recovered/blocked), never `external_dependency`, and
`ContextStack`==`ThreadState` is a real engine type. I left `status=blocked`
(correct) and rewrote the `note` on all three to explain the actual
architectural-bypass reason instead.

**Practical takeaway**: this blocker is very likely permanent under the
current `core::TssPtr`-based architecture. Don't re-open it expecting a
layout fix to unblock it — the layout is fine. Only revisit if there's ever
a deliberate decision to replace `core::TssPtr` with a literal boost-backed
implementation for fidelity reasons, which is not currently planned.

Supersedes: [[project_logcontext_singleton_layout_open]] (legacy path,
left in place per the "don't delete, don't write new" policy for that
directory — this file is the current source of truth going forward).

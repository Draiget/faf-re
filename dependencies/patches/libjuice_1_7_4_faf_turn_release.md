# FAF libjuice 1.7.4 patch

Baseline: the libjuice 1.7.4 release archive (`dependencies/libjuice`, pinned by SHA256 in `cmake/FafDependencies.cmake`). `cmake/FafDependencies.cmake` applies the patch at configure time.

## Patch scope

| File | Change | Load-bearing? |
|---|---|---|
| `src/agent.c` | `agent_destroy` sends a TURN Refresh with LIFETIME 0 for every relay entry that holds an allocation, before it stops the connection (`agent_release_turn_allocations`) | **Yes** for FAF's TURN servers: without it each allocation stays there until it expires |

## Why

Issue #325. When an agent was destroyed, libjuice freed its own state but never told the TURN server, so every allocation stayed until `TURN_LIFETIME` (10 minutes, `src/agent.h`) ran out. Every native link that closes or restarts destroys its agent (`src/netlink/Link.cpp`, `DestroyAgentLocked`), so a game left one allocation per relayed peer behind, plus one for every restart.

RFC 8656 section 7 deletes an allocation with a Refresh whose LIFETIME is 0. The request reuses the entry's credentials, as the regular Refresh does, and gets a new transaction id, so its answer can't be taken for the entry's own refresh. Nothing waits for the answer: the agent is going away. If the server answers with a stale nonce (438), the allocation expires as before.

Not reported upstream yet.

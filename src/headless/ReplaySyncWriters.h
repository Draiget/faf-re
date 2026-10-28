#pragma once

#include <string>

// Engine addition, server mode (plan WP6.1, M0.4): headless `--sync-writers <file>`. Attributes
// every write to the sim's Lua `Sync` table to the Lua call site that made it.
//
// Lua 5.0 hooks fire on calls, returns, lines and counts, not on table writes, so the attribution
// uses metamethods: a `__newindex` on `Sync` (its keys are cleared every beat by `ResetSyncTable`,
// so each beat's first write to a key passes through it), one on every table stored under a key
// (the persistent `AIBrainData`, `UnitData`, `ReleaseIds`, `Reclaim` and each beat's new ones),
// and a `table.insert` wrapper for appends to those tables (which bypass metamethods). Each one
// records the key and its caller's `source:line`; a write made from C++ (no Lua caller) is
// recorded as such, and writes of nil are not counted. Every table in the sim shares a default
// metatable (empty in the game's Lua); a recorded table gets a copy of it with the `__newindex`.
// They are installed inside the sim thread, before the sim's scripts run: an init form in the
// engine's "Sim" set (run on the sim's new Lua state) sets a call hook (`lua_sethook`, the WPR.26
// mechanism), and the hook installs them at the first call after `lua/SimSync.lua` has created
// `Sync`, then removes itself. Every new key is seen (a top-level key's first write each beat,
// each new entry of a stored table); an overwrite of an existing entry is not.

namespace faf::headless
{
  class CSyncWriters
  {
  public:
    /** Registers the init form; call before the sim is created. */
    void Enable();

    [[nodiscard]] bool Installed() const noexcept;

    /** Writes "key<TAB>writes<TAB>call site" lines, sorted, and returns a one-line summary. */
    [[nodiscard]] std::string Write(const std::string& path) const;
  };
} // namespace faf::headless

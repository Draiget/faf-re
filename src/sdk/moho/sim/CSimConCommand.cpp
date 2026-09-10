#include "legacy/containers/Map.h"
#include "moho/sim/CSimConCommand.h"

#include <algorithm>
#include <map>
#include <string>

#include "gpg/core/containers/String.h"

namespace
{
  /**
   * Command names compare case-insensitively: every descent in `sSimConList`
   * ends in `gpg::STR_CompareNoCase` on the two `c_str()`s.
   */
  struct SimConCommandNameLess
  {
    [[nodiscard]]
    bool operator()(const msvc8::string& lhs, const msvc8::string& rhs) const noexcept
    {
      return gpg::STR_CompareNoCase(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  /**
   * `Moho::sSimConList` at 0x010C7884: the 0x0C `{proxy, head, size}` head,
   * node 0x30 with the key at `node+0x0C` (the lower bound at 0x007355F0
   * reads `_Bx` at `node+0x10` and `_Myres` at `node+0x24`, the plain 0x1C
   * layout), the command pointer at `node+0x28` and colour/nil at
   * `+0x2C`/`+0x2D`.
   */
  using SimConCommandRegistry = msvc8::map<msvc8::string, moho::CSimConCommand*, SimConCommandNameLess>;

  [[nodiscard]] SimConCommandRegistry& GetSimConCommandRegistry()
  {
    static SimConCommandRegistry sRegistry;
    return sRegistry;
  }

  /**
   * Address: 0x00736250 (FUN_00736250, func_GetSimCon)
   *
   * What it does:
   * Returns the case-insensitive lower-bound node for one command name in the
   * sim-command registry tree.
   */
  [[nodiscard]] SimConCommandRegistry::iterator
  FindSimConLowerBound(SimConCommandRegistry& registry, const msvc8::string& commandName)
  {
    return registry.lower_bound(commandName);
  }

  /**
   * Address: 0x00735300 (FUN_00735300)
   *
   * What it does:
   * Returns the lower-bound iterator only when the candidate compares as an
   * exact case-insensitive match for `commandName`; otherwise returns `end()`.
   */
  [[nodiscard]] SimConCommandRegistry::iterator
  FindSimConExactOrEnd(SimConCommandRegistry& registry, const msvc8::string& commandName)
  {
    const auto candidate = FindSimConLowerBound(registry, commandName);
    if (candidate == registry.end()) {
      return registry.end();
    }

    return gpg::STR_CompareNoCase(commandName.c_str(), candidate->first.c_str()) < 0
      ? registry.end()
      : candidate;
  }



  /**
   * Address: 0x00735290 (FUN_00735290, sub_735290)
   * Address: 0x00736760 (FUN_00736760, sub_736760) -- `std::map<std::string,
   * moho::CSimConCommand*, SimConCommandNameLess>::iterator`'s in-order
   * successor walk (Dinkumware `_Tree::_Inc`/`_Incr`, real toolchain
   * `std::map` -- see `SimConCommandRegistry`'s declaration comment above),
   * exercised by `++upperBound` below. No new source line needed: the real
   * `std::map` this project's own toolchain compiles for `registry` already
   * provides this walk, the same "satisfied by std::map's own internals"
   * substitution already documented for `FUN_00735D40`/`FUN_007355F0`
   * elsewhere in this file. Eight real callers confirmed via the callgraph
   * index, all inside this same neighborhood's `SimConCommandRegistry`
   * bookkeeping (0x00735290/this function, 0x007355F0, 0x00735D40, plus
   * four owner=<none> inlined chunks in the 0x736xxx range).
   * Address: 0x00736320 (FUN_00736320, sub_736320) -- `iterator&
   * operator++()` (prefix): calls the successor walk above then returns the
   * same slot, matching `++upperBound`'s prefix-increment ABI shape.
   * Address: 0x00736330 (FUN_00736330, sub_736330) -- `iterator
   * operator++(int)` (postfix): copies the current iterator out before
   * calling the successor walk above, matching the pair's postfix-increment
   * shape. Neither has an incoming xref recorded in this export sweep
   * (small COMDATs the linker can fold/inline per call site); both are the
   * same real `std::map` iterator machinery as `FUN_00736760` above, not
   * separate engine logic. Corrects a prior mis-attribution: all three were
   * previously cited as an "armor-map node successor helper" hand-rolled in
   * `moho/unit/core/Unit.cpp` (`AdvanceArmorMultiplierNodeCursor` and its
   * two slot adapters) -- that Unit.cpp code had zero real callers (dead
   * weight predating the `Unit::ArmorMultipliers` -> `msvc8::map`
   * migration) and has been deleted; these addresses' real callers, per the
   * callgraph index, were always here.
   *
   * What it does:
   * Removes every registry entry case-insensitively equivalent to
   * `commandName` and returns the number of removed entries.
   */
  int RemoveSimConCommandEntriesByName(
    SimConCommandRegistry& registry,
    const msvc8::string& commandName
  )
  {
    const auto lowerBound = FindSimConExactOrEnd(registry, commandName);
    if (lowerBound == registry.end()) {
      return 0;
    }

    int removedCount = 0;
    auto upperBound = lowerBound;
    SimConCommandNameLess less{};
    while (upperBound != registry.end() && !less(commandName, upperBound->first) && !less(upperBound->first, commandName)) {
      ++removedCount;
      ++upperBound;
    }

    registry.erase(lowerBound, upperBound);
    return removedCount;
  }

  /**
   * Address: 0x00735130 (FUN_00735130, func_InitSimConList)
   *
   * What it does:
   * Forces lazy construction of the global case-insensitive sim-command
   * registry map before first use.
   */
  void InitSimConList()
  {
    (void)GetSimConCommandRegistry();
  }

  int DestroySimConRegistryStorage(void* const /*ownerContext*/)
  {
    auto& registry = GetSimConCommandRegistry();
    registry.clear();
    return 0;
  }

} // namespace

namespace moho
{
  CSimConCommand::CSimConCommand() noexcept
    : mName(nullptr)
    , mRequiresCheat(0u)
    , mPad09{0u, 0u, 0u}
  {
  }

  /**
   * Address: 0x00734630 (FUN_00734630, ??0CSimConCommand@Moho@@QAE@EPBD@Z)
   *
   * Address: 0x00735170 (FUN_00735170) / 0x007355F0 (FUN_007355F0,
   * IDA-typed against a guessed `Moho::CSimConFunc` node struct that does
   * not reflect this map's real layout -- the field accesses it shows
   * (`SimCon[2].name`/`SimCon[1].__vftable` gated on a `< 0x10` SSO check)
   * are `std::string`'s own capacity/buffer-union fields, not a distinct
   * engine class) -- MSVC8's compiled `SimConCommandRegistry::operator[]`
   * (FUN_00735170, resolves the case-insensitive lower-bound via
   * `func_GetSimCon`/`FindSimConLowerBound` above, `stricmp`-compares
   * against the candidate key) and its internal RB-tree node
   * construct-and-insert (FUN_007355F0, called only on the not-found
   * path). No separate source line to write for these -- they are
   * `operator[]`'s own standard-library internals, already fully covered
   * by `GetSimConCommandRegistry()[mName] = this` below, the same way the
   * `sSimConList` bookkeeping addresses above are covered by
   * `registry.clear()`. Same rationale as this file's
   * `SimConCommandRegistry` design note: a process-local map that never
   * crosses the binary's serialized surface uses the current toolchain's
   * own `std::map`, so its `operator[]` machinery is standard-library
   * code, not engine code to hand-write.
   *
   * Address: 0x00735C20 (FUN_00735C20) -- another compiled internal of
   * this same `operator[]` chain: a case-insensitive lower-bound walk
   * (same `isnil@+45`/`stricmp` shape as FUN_00735170) that either
   * returns the existing node (exact match found) or inserts a new one
   * via the same buy-node primitive (`sub_7360A0` = FUN_007360A0,
   * already recovered) on the not-found path. Its own callees
   * (FUN_007360A0, recovered; FUN_00736700, an ICF twin of the canonical
   * body cited on `RbTree.h`) are both already terminal-status. Reached
   * from FUN_007355F0 per the callgraph -- same "no separate source
   * line" rationale as the entries above.
   */
  CSimConCommand::CSimConCommand(const bool requiresCheat, const char* const name)
    : mName(name)
    , mRequiresCheat(requiresCheat ? 1u : 0u)
    , mPad09{0u, 0u, 0u}
  {
    InitSimConList();

    if (mName == nullptr || *mName == '\0') {
      return;
    }

    GetSimConCommandRegistry()[msvc8::string(mName)] = this;
  }

  /**
   * Address: 0x00734760 (FUN_00734760, ??1CSimConCommand@Moho@@UAE@XZ)
   */
  CSimConCommand::~CSimConCommand()
  {
    if (mName == nullptr || *mName == '\0') {
      return;
    }

    (void)RemoveSimConCommandEntriesByName(GetSimConCommandRegistry(), msvc8::string(mName));
  }

  /**
   * Address: 0x005BE350 (FUN_005BE350, sub_5BE350)
   */
  CSimConCommand* CSimConCommand::Identity()
  {
    return this;
  }

  CSimConCommand* FindRegisteredSimConCommand(const std::string& commandName)
  {
    InitSimConList();

    if (commandName.empty()) {
      return nullptr;
    }

    auto& registry = GetSimConCommandRegistry();
    const auto it = FindSimConExactOrEnd(registry, msvc8::string(commandName.c_str()));
    if (it == registry.end()) {
      return nullptr;
    }

    return it->second;
  }
} // namespace moho

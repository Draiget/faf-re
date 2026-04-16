#include "moho/sim/CSimConCommand.h"

#include <algorithm>
#include <map>
#include <string>

#include "gpg/core/containers/String.h"

namespace
{
  struct SimConCommandNameLess
  {
    [[nodiscard]]
    bool operator()(const std::string& lhs, const std::string& rhs) const noexcept
    {
      return gpg::STR_CompareNoCase(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  using SimConCommandRegistry = std::map<std::string, moho::CSimConCommand*, SimConCommandNameLess>;

  [[nodiscard]] SimConCommandRegistry& GetSimConCommandRegistry()
  {
    static SimConCommandRegistry sRegistry;
    return sRegistry;
  }

  /**
   * Address: 0x007362C0 (FUN_007362C0)
   *
   * What it does:
   * Returns the process-static sim-command registry map storage lane.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry* GetSimConRegistryStorageLaneA(const int) noexcept
  {
    return &GetSimConCommandRegistry();
  }

  /**
   * Address: 0x00736640 (FUN_00736640)
   *
   * What it does:
   * Returns the process-static sim-command registry map storage lane.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry* GetSimConRegistryStorageLaneB(const int) noexcept
  {
    return &GetSimConCommandRegistry();
  }

  /**
   * Address: 0x007366C0 (FUN_007366C0)
   *
   * What it does:
   * Returns the process-static sim-command registry map storage lane.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry* GetSimConRegistryStorageLaneC(const int) noexcept
  {
    return &GetSimConCommandRegistry();
  }

  /**
   * Address: 0x00736820 (FUN_00736820)
   *
   * What it does:
   * Returns the process-static sim-command registry map storage lane.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry* GetSimConRegistryStorageLaneD(const int) noexcept
  {
    return &GetSimConCommandRegistry();
  }

  /**
   * Address: 0x00736250 (FUN_00736250, func_GetSimCon)
   *
   * What it does:
   * Returns the case-insensitive lower-bound node for one command name in the
   * sim-command registry tree.
   */
  [[nodiscard]] SimConCommandRegistry::iterator
  FindSimConLowerBound(SimConCommandRegistry& registry, const std::string& commandName)
  {
    return registry.lower_bound(commandName);
  }

  /**
   * Address: 0x00735880 (FUN_00735880)
   *
   * What it does:
   * Resolves one lower-bound iterator for `commandName` and stores it into the
   * caller-provided iterator slot.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry::iterator* StoreSimConLowerBoundIterator(
    SimConCommandRegistry& registry,
    const std::string& commandName,
    SimConCommandRegistry::iterator* const outIterator
  )
  {
    *outIterator = FindSimConLowerBound(registry, commandName);
    return outIterator;
  }

  /**
   * Address: 0x00735300 (FUN_00735300)
   *
   * What it does:
   * Returns the lower-bound iterator only when the candidate compares as an
   * exact case-insensitive match for `commandName`; otherwise returns `end()`.
   */
  [[nodiscard]] SimConCommandRegistry::iterator
  FindSimConExactOrEnd(SimConCommandRegistry& registry, const std::string& commandName)
  {
    const auto candidate = FindSimConLowerBound(registry, commandName);
    if (candidate == registry.end()) {
      return registry.end();
    }

    return gpg::STR_CompareNoCase(commandName.c_str(), candidate->first.c_str()) < 0
      ? registry.end()
      : candidate;
  }

  using SimConIteratorRange =
    std::pair<SimConCommandRegistry::iterator, SimConCommandRegistry::iterator>;

  /**
   * Address: 0x007358A0 (FUN_007358A0)
   *
   * What it does:
   * Builds one case-insensitive equal-range iterator pair for `commandName`
   * inside the sim-command registry and stores it into `outRange`.
   */
  [[maybe_unused]] SimConIteratorRange* BuildSimConEqualRange(
    SimConCommandRegistry& registry,
    const std::string& commandName,
    SimConIteratorRange* const outRange
  )
  {
    const SimConIteratorRange range = registry.equal_range(commandName);
    outRange->first = range.first;
    outRange->second = range.second;
    return outRange;
  }

  /**
   * Address: 0x00735290 (FUN_00735290, sub_735290)
   *
   * What it does:
   * Removes every registry entry case-insensitively equivalent to
   * `commandName` and returns the number of removed entries.
   */
  int RemoveSimConCommandEntriesByName(
    SimConCommandRegistry& registry,
    const std::string& commandName
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
   * Address: 0x00736070 (FUN_00736070)
   *
   * What it does:
   * Forces construction of the static sim-command registry tree header/sentinel
   * storage and returns the initialized registry lane.
   */
  [[maybe_unused]] SimConCommandRegistry* InitializeSimConRegistryTreeHeadLane()
  {
    SimConCommandRegistry& registry = GetSimConCommandRegistry();
    return &registry;
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
    (void)InitializeSimConRegistryTreeHeadLane();
  }

  /**
   * Address: 0x007355B0 (FUN_007355B0)
   *
   * What it does:
   * Reinitializes the global sim-command registry to an empty tree-header
   * state and returns the registry storage lane.
   */
  [[maybe_unused]] [[nodiscard]] SimConCommandRegistry* InitializeSimConRegistryTreeHeaderLaneLegacy()
  {
    SimConCommandRegistry& registry = GetSimConCommandRegistry();
    registry.clear();
    return &registry;
  }

  int DestroySimConRegistryStorage(void* const /*ownerContext*/)
  {
    auto& registry = GetSimConCommandRegistry();
    registry.clear();
    return 0;
  }

  /**
   * Address: 0x00734720 (FUN_00734720)
   *
   * What it does:
   * Clears and releases one static sim-command registry storage lane for the
   * legacy startup/teardown callback chain.
   */
  [[maybe_unused]] int DestroySimConRegistryStorageLaneA(void* const ownerContext)
  {
    return DestroySimConRegistryStorage(ownerContext);
  }

  /**
   * Address: 0x00735240 (FUN_00735240)
   *
   * What it does:
   * Clears and releases one static sim-command registry storage lane for the
   * legacy startup/teardown callback chain.
   */
  [[maybe_unused]] int DestroySimConRegistryStorageLaneB(void* const ownerContext)
  {
    return DestroySimConRegistryStorage(ownerContext);
  }

  /**
   * Address: 0x007358C0 (FUN_007358C0)
   *
   * What it does:
   * Clears and releases one static sim-command registry storage lane for the
   * legacy startup/teardown callback chain.
   */
  [[maybe_unused]] int DestroySimConRegistryStorageLaneC(void* const ownerContext)
  {
    return DestroySimConRegistryStorage(ownerContext);
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

    GetSimConCommandRegistry()[mName] = this;
  }

  /**
   * Address: 0x00734760 (FUN_00734760, ??1CSimConCommand@Moho@@UAE@XZ)
   */
  CSimConCommand::~CSimConCommand()
  {
    if (mName == nullptr || *mName == '\0') {
      return;
    }

    auto& registry = GetSimConCommandRegistry();
    const std::string commandName = mName;
    (void)RemoveSimConCommandEntriesByName(registry, commandName);
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
    const auto it = FindSimConExactOrEnd(registry, commandName);
    if (it == registry.end()) {
      return nullptr;
    }

    return it->second;
  }
} // namespace moho

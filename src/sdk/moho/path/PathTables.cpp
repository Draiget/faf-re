#include "PathTables.h"
#include "gpg/core/utils/Logging.h"

#include <array>
#include <cassert>
#include <climits>
#include <limits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/algorithms/AStarSearch.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/containers/TDatList.h"
#include "moho/path/ClusterMap.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/SNamedFootprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/sim/STIMap.h"

#ifdef _WIN32
#include <windows.h>
#include "gpg/core/reflection/StaticInitPhase.h"
#endif

namespace
{
  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  /**
   * Orders cell keys by their packed 32-bit representation, which is how the
   * binary compares them (`cmp` on the whole dword at node+8, unsigned).
   */
  struct PathQueueCellLess
  {
    [[nodiscard]] bool operator()(const moho::SOCellPos& lhs, const moho::SOCellPos& rhs) const noexcept
    {
      return PackCellKey(lhs) < PackCellKey(rhs);
    }
  };

  using PathQueueCellTraits = msvc8::hash_compare<moho::SOCellPos, PathQueueCellLess>;

  /**
   * Address: 0x00E35E84 / 0x00E35E8C / 0x00E35E94 / 0x00E35E9C
   *
   * The 8-way step table, read out of the binary. Cardinals come first so the
   * diagonals can gate on them: `kStepGate[i]` is a mask of the cardinal
   * indices that must already have succeeded before diagonal `i` is allowed,
   * which is what stops a unit cutting the corner between two blocked cells.
   */
  constexpr std::int8_t kStepOffsetX[8] = { 0, -1, 0, 1, -1, -1, 1, 1 };
  constexpr std::int8_t kStepOffsetZ[8] = { -1, 0, 1, 0, -1, 1, 1, -1 };
  constexpr std::uint8_t kStepGate[8] = { 0u, 0u, 0u, 0u, 3u, 6u, 12u, 9u };
  constexpr float kStepCost[8] = { 1.0f, 1.0f, 1.0f, 1.0f, 1.414f, 1.414f, 1.414f, 1.414f };
} // namespace

namespace moho
{
  /**
   * `Moho::PathQueue::ImplBase` - one in-flight path query.
   *
   * The first 0x4C bytes are the generic A* search state (node table + open
   * heap); everything from +0x4C onward is this class's own per-query state.
   * The derivation is what makes the binary pass the same pointer as both the
   * search and the traits argument (`push edi; push edi` at 0x00765F36).
   *
   * Layout:
   *   +0x00 : gpg::AStarSearch base   (node hash_map 0x28 + open heap 0x24)
   *   +0x4C : mTraveler       in-flight traveler (a list; at most one entry).
   *                           `PathQueue::Work` tests it with `cmp [ecx+4], ecx`
   *                           (0x00765EE5) and reads the traveler through the
   *                           +0x04 slot (0x00766141)
   *   +0x54 : mClosestCell    best cell seen so far, by heuristic
   *   +0x58 : mClosestDistance
   *   +0x5C : mClusterMap     cluster map selected for this traveler's footprint
   *   +0x60 : mBudget         remaining CPU budget, decremented per expansion
   *   +0x64 : mResultCells    the path handed back to the traveler
   *   +0x74 : mExpandCount    expansions performed for this traveler
   *   +0x78 : mPathCap        traveler-supplied expansion cap
   */
  struct PathQueue::ImplBase
    : gpg::AStarSearch<SOCellPos, PathQueue::ImplBase, PathQueueCellTraits>
  {
    /** How one expansion ends: `ExpandNode`'s answer, which `WorkOnce` returns. */
    enum class Step : std::int32_t
    {
      Continue = 0,
      GoalReached = 1,
      BudgetExhausted = 2,
      PathCapExceeded = 3,
    };

    /**
     * Address: 0x00765B90 (FUN_00765B90, ??0ImplBase@PathQueue@Moho@@QAE@@Z)
     *          0x00766CE0 (FUN_00766CE0) - open-heap freelist arming
     *          0x00767600 (FUN_00767600) - node-table arming
     *
     * What it does:
     * Empty traveler list, zero closest cell, empty result path; the search
     * structures arm themselves in the base constructor.
     */
    ImplBase()
      : mClosestCell()
      , mClosestDistance(0.0f)
      , mClusterMap(nullptr)
      , mBudget(0)
      , mExpandCount(0)
      , mPathCap(0)
    {
    }

    /**
     * Address: 0x00765BE0 (FUN_00765BE0, ~ImplBase, `this` in ESI)
     * Address: 0x00765C30 (FUN_00765C30, the `AStarSearch` base's part)
     *          0x007672E0 (FUN_007672E0) - open-heap release
     *          0x007676A0 (FUN_007676A0) - node-table element release
     *          0x00767C70 (FUN_00767C70) - bucket-window release
     *
     * What it does:
     * Nothing of its own: `mResultCells` is freed, then the traveler list
     * unlinks, then the search base releases its tables -- reverse member
     * order, as 0x00765BE0 runs it.
     */
    ~ImplBase() = default;

    /** The traveler currently being served, or null when the ring is empty. */
    [[nodiscard]] IPathTraveler* CurrentTraveler() const noexcept;

    /** A* traits hook: distance estimate from `cell` to this traveler's goal. */
    [[nodiscard]] float GetHeuristicCost(const SOCellPos& cell) const;

    /** A* traits hook: tracks the closest cell reached, for fallback paths. */
    void NoteCandidateCell(const SOCellPos& cell, float estimate) noexcept;

    /** A* traits hook: charges one expansion and offers the edges out of `cell`. */
    [[nodiscard]] Step ExpandNode(const SOCellPos& cell, neighbour_list& outNeighbours);

    /** Starts the query for `traveler` on the cluster map its footprint uses. */
    void BeginQuery(IPathTraveler& traveler, PathTables& owner);

    /** Hands the path to the best cell reached back to the traveler. */
    void FinishQuery(bool reachedGoal);

    gpg::DList<IPathTraveler> mTraveler;    // +0x4C
    SOCellPos mClosestCell;                 // +0x54
    float mClosestDistance;                 // +0x58
    gpg::HaStar::ClusterMap* mClusterMap;   // +0x5C
    std::int32_t mBudget;                   // +0x60
    msvc8::vector<SOCellPos> mResultCells;  // +0x64
    std::int32_t mExpandCount;              // +0x74
    std::int32_t mPathCap;                  // +0x78

  private:
    [[nodiscard]] bool CollectNeighbours(const SOCellPos& cell, neighbour_list& outNeighbours);
    [[nodiscard]] bool AddNeighbours(const SOCellPos& cell, int level, neighbour_list& outNeighbours);
    [[nodiscard]] bool AddAdjacentCells(const SOCellPos& cell, neighbour_list& outNeighbours);
    [[nodiscard]] bool AddClusterEdges(const SOCellPos& cell, int level, neighbour_list& outNeighbours);
  };

  static_assert(sizeof(PathQueue::ImplBase) == 0x7C, "PathQueue::ImplBase size must be 0x7C");
  static_assert(offsetof(PathQueue::ImplBase, mTraveler) == 0x4C, "PathQueue::ImplBase::mTraveler offset must be 0x4C");
  static_assert(offsetof(PathQueue::ImplBase, mClosestCell) == 0x54, "PathQueue::ImplBase::mClosestCell offset must be 0x54");
  static_assert(offsetof(PathQueue::ImplBase, mClusterMap) == 0x5C, "PathQueue::ImplBase::mClusterMap offset must be 0x5C");
  static_assert(offsetof(PathQueue::ImplBase, mBudget) == 0x60, "PathQueue::ImplBase::mBudget offset must be 0x60");
  static_assert(offsetof(PathQueue::ImplBase, mResultCells) == 0x64, "PathQueue::ImplBase::mResultCells offset must be 0x64");
  static_assert(offsetof(PathQueue::ImplBase, mExpandCount) == 0x74, "PathQueue::ImplBase::mExpandCount offset must be 0x74");
  static_assert(offsetof(PathQueue::ImplBase, mPathCap) == 0x78, "PathQueue::ImplBase::mPathCap offset must be 0x78");

  /**
   * Address: 0x00766141 / 0x007684E3 / 0x0076614B (the recurring
   *          `mov eax, [reg+50h]` + `lea .., [eax-4]` pair)
   *
   * What it does:
   * The traveler being served: the list's front, recovered from its node at
   * `IPathTraveler`+0x04 (the `-4` the binary applies); null when empty.
   */
  IPathTraveler* PathQueue::ImplBase::CurrentTraveler() const noexcept
  {
    // The A* traits hooks are const; the traveler they call is not.
    return const_cast<IPathTraveler*>(mTraveler.front());
  }

  /**
   * Address: 0x007684ED (vtable slot 3, `moho::IPathTraveler::GetHeuristicCost`)
   *
   * What it does:
   * A* traits hook - defers the distance estimate to the traveler being served.
   */
  float PathQueue::ImplBase::GetHeuristicCost(const SOCellPos& cell) const
  {
    const IPathTraveler* const traveler = CurrentTraveler();
    if (traveler == nullptr) {
      return 0.0f;
    }
    return traveler->GetHeuristicCost(cell);
  }

  /**
   * Address: 0x007684F9 (FUN_007684C0) and 0x00768502 (FUN_007685A0)
   *
   * What it does:
   * A* traits hook - remembers the cell with the smallest heuristic seen during
   * this query, so a search that runs out of budget can still hand back the
   * closest approach instead of failing outright.
   */
  void PathQueue::ImplBase::NoteCandidateCell(const SOCellPos& cell, const float estimate) noexcept
  {
    if (mClosestDistance > estimate) {
      mClosestCell = cell;
      mClosestDistance = estimate;
    }
  }

  /**
   * What it does:
   * The level-0 arm of `AddNeighbours` (0x00766350): the walkable subset of
   * the eight cells adjacent to `cell`.
   *
   * Each candidate must clear three gates in order: the traveler must want to
   * search the cluster the candidate falls in, the candidate cell must be
   * traversable, and the traveler must accept the edge (which may also revise
   * its cost). Only a candidate that clears all three sets its bit in
   * `acceptedMask`, so a diagonal is offered only once both of its adjacent
   * cardinals have been accepted.
   */
  bool PathQueue::ImplBase::AddAdjacentCells(const SOCellPos& cell, neighbour_list& outNeighbours)
  {
    IPathTraveler* const traveler = CurrentTraveler();
    if (traveler == nullptr) {
      return true;
    }

    std::uint32_t acceptedMask = 0u;
    for (std::size_t step = 0; step < 8; ++step) {
      if ((acceptedMask & kStepGate[step]) != kStepGate[step]) {
        continue;
      }

      const int candidateX = static_cast<std::uint16_t>(cell.x) + kStepOffsetX[step];
      const int candidateZ = static_cast<std::uint16_t>(cell.z) + kStepOffsetZ[step];

      if (!traveler->ShouldSearchRect(mClusterMap->ClusterRect(candidateX, candidateZ, 1u))) {
        continue;
      }

      SOCellPos candidate{};
      candidate.x = static_cast<std::int16_t>(candidateX);
      candidate.z = static_cast<std::int16_t>(candidateZ);

      if (!traveler->CanTraverseCell(candidate)) {
        continue;
      }

      float cost = kStepCost[step];
      if (!traveler->IsInBounds(cell, candidate, &cost)) {
        continue;
      }

      outNeighbours.push_back(neighbour_type{candidate, cost});
      acceptedMask |= 1u << step;
    }
    return true;
  }

  /**
   * What it does:
   * The level>0 arm of `AddNeighbours` (0x00766350): the cluster-graph edges
   * leaving `cell` at `level`.
   *
   * At a coarse level the map is precomputed into clusters, each holding a
   * handful of boundary nodes and a triangular matrix of costs between them.
   * If `cell` is one of those nodes, every other node in the same cluster that
   * has a recorded edge becomes a candidate - which is how the search covers
   * open ground in a few steps instead of one cell at a time.
   *
   * Returns false only when the cluster build ran out of budget, which aborts
   * the whole query rather than yielding a partial neighbour set.
   */
  bool PathQueue::ImplBase::AddClusterEdges(const SOCellPos& cell, const int level, neighbour_list& outNeighbours)
  {
    IPathTraveler* const traveler = CurrentTraveler();
    if (traveler == nullptr) {
      return true;
    }

    gpg::HaStar::ClusterMap& clusterMap = *mClusterMap;
    const std::uint32_t topLevel = clusterMap.mNumLevels;
    const int originShift = gpg::HaStar::sClusterSizeLog2[level];
    const int cellX = static_cast<std::uint16_t>(cell.x);
    const int cellZ = static_cast<std::uint16_t>(cell.z);

    const gpg::Rect2i clusterBounds =
      clusterMap.ClusterIndexRect(cellX, cellZ, static_cast<std::uint8_t>(level));

    for (int clusterX = clusterBounds.x0; clusterX < clusterBounds.x1; ++clusterX) {
      const int originX = clusterX << originShift;

      for (int clusterZ = clusterBounds.z0; clusterZ < clusterBounds.z1; ++clusterZ) {
        const int originZ = clusterZ << originShift;

        if (!clusterMap.WorkOnCluster(clusterX, clusterZ, level, mBudget)) {
          return false;
        }

        const gpg::HaStar::Subcluster& subcluster = clusterMap.mLevels[level];

        // Hold the payload across the walk by taking a counted handle:
        // WorkOnCluster on a neighbouring cluster can otherwise evict it.
        const gpg::HaStar::Cluster clusterHandle =
          subcluster.mArray[clusterX + clusterZ * subcluster.mWidth];
        gpg::HaStar::Cluster::Data* const data = clusterHandle.mData;

        const std::uint32_t nodeCount = (data != nullptr) ? data->mNodeCount : 0u;
        const gpg::HaStar::Cluster::Node* const nodes = (data != nullptr) ? data->mNodes : nullptr;
        const auto* const edges = (data != nullptr)
          ? reinterpret_cast<const std::int8_t*>(nodes + nodeCount)
          : nullptr;

        std::uint32_t fromIndex = 0u;
        for (; fromIndex < nodeCount; ++fromIndex) {
          if (nodes[fromIndex].x == static_cast<std::uint8_t>(cellX - originX)
              && nodes[fromIndex].z == static_cast<std::uint8_t>(cellZ - originZ)) {
            break;
          }
        }
        if (fromIndex < nodeCount) {
          for (std::uint32_t toIndex = 0u; toIndex < nodeCount; ++toIndex) {
            if (toIndex == fromIndex) {
              continue;
            }

            const std::uint32_t edgeIndex = (fromIndex >= toIndex)
              ? toIndex + ((fromIndex * (fromIndex - 1u)) >> 1)
              : fromIndex + ((toIndex * (toIndex - 1u)) >> 1);

            // A negative bucket means the pair is unreachable inside the cluster.
            if (edges[edgeIndex] < 0) {
              continue;
            }

            SOCellPos candidate{};
            candidate.x = static_cast<std::int16_t>(originX + nodes[toIndex].x);
            candidate.z = static_cast<std::int16_t>(originZ + nodes[toIndex].z);

            // At the coarsest level there is no parent cluster left to consult.
            if (static_cast<std::uint32_t>(level) != topLevel) {
              const gpg::Rect2i parentRect =
                clusterMap.ClusterRect(candidate.x, candidate.z, static_cast<std::uint8_t>(level + 1));
              if (!traveler->ShouldSearchRect(parentRect)) {
                continue;
              }
            }

            float cost = gpg::HaStar::Cluster::DequantizeEdgeCost(
              edges[edgeIndex],
              gpg::HaStar::Cluster::NodeOctileDistance(*data, fromIndex, toIndex)
            );

            if (!traveler->IsInBounds(cell, candidate, &cost)) {
              continue;
            }

            outNeighbours.push_back(neighbour_type{candidate, cost});
          }
        }

      }
    }
    return true;
  }

  /**
   * Address: 0x00766350 (FUN_00766350)
   *
   * What it does:
   * Offers the edges leaving `cell` at one level of the hierarchy: the
   * walkable neighbour cells at level 0, the cluster-graph edges above it.
   * False when a cluster build ran out of budget.
   */
  bool PathQueue::ImplBase::AddNeighbours(const SOCellPos& cell, const int level, neighbour_list& outNeighbours)
  {
    return (level == 0) ? AddAdjacentCells(cell, outNeighbours) : AddClusterEdges(cell, level, outNeighbours);
  }

  /**
   * Address: 0x00766280 (FUN_00766280)
   *
   * IDA signature:
   * bool __userpurge sub_766280@<al>(Moho::PathQueue::ImplBase *a1@<ebx>, Moho::SOCellPos *a2@<esi>, int a3);
   *
   * What it does:
   * Produces the candidate steps out of `cell`, coarse levels first.
   *
   * The traveler decides how coarse to start: if it still wants to search the
   * immediate neighbourhood the walk begins at level 0, otherwise it begins at
   * the top of the hierarchy. Descending stops early once the traveler loses
   * interest in the cluster around `cell`. A level only contributes when `cell`
   * sits on that level's cluster grid, since only grid-aligned cells carry
   * cluster nodes.
   */
  bool PathQueue::ImplBase::CollectNeighbours(const SOCellPos& cell, neighbour_list& outNeighbours)
  {
    IPathTraveler* const traveler = CurrentTraveler();
    if (traveler == nullptr) {
      return true;
    }

    gpg::HaStar::ClusterMap& clusterMap = *mClusterMap;
    const int cellX = static_cast<std::uint16_t>(cell.x);
    const int cellZ = static_cast<std::uint16_t>(cell.z);

    int level = traveler->ShouldSearchRect(clusterMap.ClusterRect(cellX, cellZ, 0u))
      ? 0
      : static_cast<int>(clusterMap.mNumLevels);

    for (; level >= 0; --level) {
      const int clusterMask = gpg::HaStar::sClusterSize[level] - 1;
      if ((cellX & clusterMask) != 0 && (cellZ & clusterMask) != 0) {
        continue;
      }

      if (!AddNeighbours(cell, level, outNeighbours)) {
        return false;
      }

      if (level > 0
          && !traveler->ShouldSearchRect(
               clusterMap.ClusterRect(cellX, cellZ, static_cast<std::uint8_t>(level)))) {
        return true;
      }
    }
    return true;
  }

  /**
   * Address: 0x007661C0 (FUN_007661C0)
   *
   * IDA signature:
   * int __userpurge sub_7661C0@<eax>(Moho::SOCellPos *a1@<eax>, Moho::PathQueue::ImplBase *a2@<ecx>, int a3);
   *
   * What it does:
   * Charges one expansion against the query's budgets and decides whether the
   * search should continue, stop at the goal, or give up.
   *
   * Note the budget is spent before the goal test, so reaching the goal on the
   * final unit of budget still costs it.
   */
  PathQueue::ImplBase::Step PathQueue::ImplBase::ExpandNode(const SOCellPos& cell, neighbour_list& outNeighbours)
  {
    --mBudget;
    ++mExpandCount;

    if (mBudget <= 0) {
      return Step::BudgetExhausted;
    }

    IPathTraveler* const traveler = CurrentTraveler();
    if (traveler != nullptr && traveler->IsGoalCandidateCell(cell)) {
      mClosestCell = cell;
      return Step::GoalReached;
    }

    if (mExpandCount > mPathCap) {
      return Step::PathCapExceeded;
    }

    return CollectNeighbours(cell, outNeighbours) ? Step::Continue : Step::BudgetExhausted;
  }

  struct PathQueue::Impl
  {
    /**
     * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
     * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
     *
     * What it does:
     * Null owner, empty pending list (self-linked at +0x04), then the
     * `ImplBase` at +0x0C.
     */
    Impl();

    /**
     * Address: 0x00768A10 (FUN_00768A10)
     *
     * What it does:
     * Loads the owner, the pending travelers and the in-flight one, then puts
     * the in-flight traveler back at the front of the pending list.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00768AD0 (FUN_00768AD0)
     *
     * What it does:
     * Saves the owner as an unowned pointer, then both traveler lists.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    // The `PathTables` this queue searches: `BeginQuery` picks each
    // traveler's cluster map out of it (`[[owner] + 0x1C][footprintIndex]`).
    PathTables* mOwner;                           // +0x00
    gpg::DList<IPathTraveler> mPendingTravelers;  // +0x04
    ImplBase mBase;                               // +0x0C
  };

  static_assert(sizeof(PathQueue::Impl) == 0x88, "PathQueue::Impl size must be 0x88");
  static_assert(offsetof(PathQueue::Impl, mOwner) == 0x00, "PathQueue::Impl::mOwner offset must be 0x00");
  static_assert(offsetof(PathQueue::Impl, mBase) == 0x0C, "PathQueue::Impl::mBase offset must be 0x0C");

  namespace
  {
    /**
     * Address: 0x00766970 (FUN_00766970, Moho::PathQueueSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback: `PathQueue::MemberDeserialize` (0x0076AD40),
     * the archive handed over in EBX.
     */
    void PathQueueSerializerDeserialize(
      gpg::ReadArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      reinterpret_cast<PathQueue*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
    }

    /**
     * Address: 0x00766980 (FUN_00766980, Moho::PathQueueSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback: `PathQueue::MemberSerialize`, inlined.
     */
    void PathQueueSerializerSerialize(
      gpg::WriteArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      reinterpret_cast<const PathQueue*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
    }

    /**
     * VFTABLE: 0x00E35FC0 (`??_7PathQueueSerializer@Moho@@6B@`)
     * Also installed as: 0x00E35FC8 (`??_7?$SerSaveLoadHelper@VPathQueue@Moho@@@gpg@@6B@`)
     *
     * Demangled: gpg::SerSaveLoadHelper<class Moho::PathQueue>
     *
     * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
     * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
     * load/save callback lanes@0x0C-0x13. Total 0x14 bytes, matching every
     * sibling `SerHelperBase`-derived serializer in this codebase
     * (`CUnitCarrierRetrieveSerializerHelper`, `SPathNeighborSerializer`, ...).
     *
     * Investigation note (2026-08-25): this class replaces a prior hand-rolled
     * `PathQueueSerializerHelper` POD whose `register_PathQueueSerializer`
     * manually self-linked an intrusive node instead of deriving
     * `gpg::SerHelperBase` (so it never spliced into the real
     * `sNewHelpers` pending list), and which bound `serLoadFunc_`/
     * `serSaveFunc_` at *construction* time. The raw disassembly proves
     * 0x00BDC920 (construction) and 0x00767080 (the vtable-slot-0 `Init()`
     * body, dispatched later by `gpg::SerHelperBase::InitNewHelpers`) are two
     * distinct functions -- see
     * decomp/recovery/reports/by-source/src/sdk/gpg/core/containers/ArchiveSerialization.cpp.reconstruction.md.
     */
    class PathQueueSerializerHelper : public gpg::SerHelperBase
    {
    public:
      /**
       * Address: 0x00BDC920 (FUN_00BDC920, register_PathQueueSerializer,
       * dynamic initializer for the global `PathQueueSerializer` singleton)
       *
       * What it does:
       * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
       * and splices it into the process-global `sNewHelpers` pending list),
       * then binds the deserialize/serialize callback fields and installs
       * process-exit cleanup.
       */
      PathQueueSerializerHelper();

      /**
       * Address: 0x00C01AB0 (FUN_00C01AB0, dynamic atexit destructor for `gPathQueueSerializerHelper`)
       *
       * What it does:
       * Unlinks this helper node from the serializer-helper list (the
       * `TDatListItem` base destructor). The compiler registers it with
       * `atexit` from the global's dynamic initializer (0x00BDC920).
       * `FUN_007669F0` and `FUN_00766A20` are
       * unreferenced out-of-line copies of the same body.
       */
      ~PathQueueSerializerHelper() = default;

      /**
       * Address: 0x00767080 (FUN_00767080, gpg::SerSaveLoadHelper<Moho::PathQueue>::Init)
       *
       * What it does:
       * Resolves `PathQueue` RTTI and installs this helper's load/save
       * callbacks into the reflected type descriptor.
       */
      void Init() override;

    public:
      gpg::RType::load_func_t mLoadCallback;
      gpg::RType::save_func_t mSaveCallback;
    };
    static_assert(
      offsetof(PathQueueSerializerHelper, mLoadCallback) == 0x0C,
      "PathQueueSerializerHelper::mLoadCallback offset must be 0x0C"
    );
    static_assert(
      offsetof(PathQueueSerializerHelper, mSaveCallback) == 0x10,
      "PathQueueSerializerHelper::mSaveCallback offset must be 0x10"
    );
    static_assert(sizeof(PathQueueSerializerHelper) == 0x14, "PathQueueSerializerHelper size must be 0x14");

    PathQueueSerializerHelper gPathQueueSerializerHelper;

    PathQueueSerializerHelper::PathQueueSerializerHelper()
      : mLoadCallback(&PathQueueSerializerDeserialize)
      , mSaveCallback(&PathQueueSerializerSerialize)
    {}

    /**
     * Address: 0x00767080 (FUN_00767080, gpg::SerSaveLoadHelper<Moho::PathQueue>::Init)
     *
     * What it does:
     * Resolves `PathQueue` RTTI (via the cached `PathQueue::sType`, falling
     * back to `gpg::LookupRType(typeid(PathQueue))` on a cache miss) and
     * binds this helper's load/save callbacks into the reflected type
     * descriptor. Dispatched by `gpg::SerHelperBase::InitNewHelpers` when
     * this helper is drained from the pending list (vtable slot 0).
     */
    void PathQueueSerializerHelper::Init()
    {
      gpg::RType* type = moho::PathQueue::sType;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(moho::PathQueue));
        moho::PathQueue::sType = type;
      }

      GPG_ASSERT(type->serLoadFunc_ == nullptr);
      type->serLoadFunc_ = mLoadCallback;
      GPG_ASSERT(type->serSaveFunc_ == nullptr);
      type->serSaveFunc_ = mSaveCallback;
    }

    /**
     * Address: 0x00767900 (FUN_00767900, Moho::PathQueueTypeInfo::Delete)
     *
     * What it does:
     * `delete` of a reflected `PathQueue`, its destructor inlined.
     */
    void DeletePathQueueRefCallback(void* const objectStorage)
    {
      delete static_cast<PathQueue*>(objectStorage);
    }

    /**
     * Address: 0x00767990 (FUN_00767990, Moho::PathQueueTypeInfo::Destruct)
     *
     * What it does:
     * Destroys a `PathQueue` in place: its `Impl` is deleted and the pointer
     * left as it was.
     */
    void DestructPathQueueRefCallback(void* const objectStorage)
    {
      static_cast<PathQueue*>(objectStorage)->~PathQueue();
    }

    /**
     * Address: 0x007678C0 (FUN_007678C0, Moho::PathQueueTypeInfo::NewRef)
     *
     * What it does:
     * `new PathQueue` - empty, no `Impl` - as a reflected reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueRefCallback()
    {
      gpg::RRef objectRef{};
      objectRef = gpg::MakeRRef<moho::PathQueue>(new PathQueue());
      return objectRef;
    }

    /**
     * Address: 0x00767950 (FUN_00767950, Moho::PathQueueTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs an empty `PathQueue` in caller storage, as a reflected
     * reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueRefCallback(void* const objectStorage)
    {
      gpg::RRef objectRef{};
      objectRef = gpg::MakeRRef<moho::PathQueue>(::new (objectStorage) PathQueue());
      return objectRef;
    }

    /**
     * Address: 0x00767A50 (FUN_00767A50, Moho::PathQueueImplTypeInfo::Delete)
     *
     * What it does:
     * `delete` of a reflected `PathQueue::Impl`.
     */
    void DeletePathQueueImplRefCallback(void* const objectStorage)
    {
      delete static_cast<PathQueue::Impl*>(objectStorage);
    }

    /**
     * Address: 0x00767B00 (FUN_00767B00, Moho::PathQueueImplTypeInfo::Destruct)
     *
     * What it does:
     * Destroys a `PathQueue::Impl` in place, leaving its storage.
     */
    void DestructPathQueueImplRefCallback(void* const objectStorage)
    {
      static_cast<PathQueue::Impl*>(objectStorage)->~Impl();
    }

    /**
     * Address: 0x007679D0 (FUN_007679D0, Moho::PathQueueImplTypeInfo::NewRef)
     *
     * What it does:
     * `new PathQueue::Impl` as a reflected reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueImplRefCallback()
    {
      gpg::RRef objectRef{};
      (void)gpg::RRef_PathQueue_Impl(&objectRef, new PathQueue::Impl());
      return objectRef;
    }

    /**
     * Address: 0x00767A90 (FUN_00767A90, Moho::PathQueueImplTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs a `PathQueue::Impl` in caller storage, as a reflected
     * reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueImplRefCallback(void* const objectStorage)
    {
      gpg::RRef objectRef{};
      (void)gpg::RRef_PathQueue_Impl(&objectRef, ::new (objectStorage) PathQueue::Impl());
      return objectRef;
    }

    /**
     * Address: 0x00767030 (FUN_00767030)
     *
     * What it does:
     * Binds `PathQueue` reflection lifecycle callbacks (`new/ctor/delete/dtr`)
     * into one destination `gpg::RType` lane.
     */
    [[nodiscard]] gpg::RType* BindPathQueueTypeInfoLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
    {
      return gpg::BindRTypeLifecycleCallbacks(
        typeInfo,
        &NewPathQueueRefCallback,
        &ConstructPathQueueRefCallback,
        &DeletePathQueueRefCallback,
        &DestructPathQueueRefCallback
      );
    }

    /**
     * Address: 0x007670F0 (FUN_007670F0)
     *
     * What it does:
     * Binds `PathQueue::Impl` reflection lifecycle callbacks
     * (`new/ctor/delete/dtr`) into one destination `gpg::RType` lane.
     */
    [[nodiscard]] gpg::RType* BindPathQueueImplTypeInfoLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
    {
      return gpg::BindRTypeLifecycleCallbacks(
        typeInfo,
        &NewPathQueueImplRefCallback,
        &ConstructPathQueueImplRefCallback,
        &DeletePathQueueImplRefCallback,
        &DestructPathQueueImplRefCallback
      );
    }

    /**
     * Address: 0x00766BB0 (FUN_00766BB0, Moho::PathQueueImplSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback: `PathQueue::Impl::MemberDeserialize`
     * (0x00768A10), the object in EAX and the archive in ECX.
     */
    void PathQueueImplSerializerDeserialize(
      gpg::ReadArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      reinterpret_cast<PathQueue::Impl*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
    }

    /**
     * Address: 0x00766BC0 (FUN_00766BC0, Moho::PathQueueImplSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback: `PathQueue::Impl::MemberSerialize`
     * (0x00768AD0), the object in EAX and the archive in EBX.
     */
    void PathQueueImplSerializerSerialize(
      gpg::WriteArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      reinterpret_cast<const PathQueue::Impl*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
    }

    /**
     * VFTABLE: 0x00E36000 (`??_7PathQueueImplSerializer@Moho@@6B@`)
     *
     * Demangled: gpg::SerSaveLoadHelper<struct Moho::PathQueue::Impl>
     * (IDA symbol: `gpg::SerSaveLoadHelper_PathQueue_Impl::Init`)
     *
     * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
     * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
     * load/save callback lanes@0x0C-0x13. Total 0x14 bytes, matching every
     * sibling `SerHelperBase`-derived serializer in this codebase.
     *
     * The binary stores the address of the save callback (via the 0x00766BC0
     * calling-convention thunk over 0x00768AD0) and the load callback (via
     * the 0x00766BB0 trampoline over 0x00768A10) into this helper's
     * save/load lanes; `Init()` (0x00767140) then copies them into the
     * reflected `Moho::PathQueue::Impl` type's `serSaveFunc_` /
     * `serLoadFunc_` slots. Taking the address of both callbacks in the
     * constructor below is the source-level invocation (evidence class 2,
     * function-pointer table) that keeps them linked into the engine binary.
     *
     * Investigation note (2026-08-25): this class replaces a prior
     * `InstallPathQueueImplSerializerCallbacks` free function operating on a
     * raw the deleted overlay POD (never a real
     * `gpg::SerHelperBase`, so never spliced into `sNewHelpers`, so never
     * actually dispatched -- the free function that would have invoked it
     * directly, `InstallPathQueueImplSerializerLifecycleCallbacks`, was
     * itself `[[maybe_unused]]` and uncalled). The `Init()` body below is
     * unchanged from that free function's logic, which already matched the
     * raw disassembly at 0x00767140 (typeid-cached `gpg::LookupRType`
     * lookup, not `REF_FindTypeNamed`) -- only the wiring mechanism was
     * wrong. See
     * decomp/recovery/reports/by-source/src/sdk/gpg/core/containers/ArchiveSerialization.cpp.reconstruction.md.
     */
    class PathQueueImplSerializerHelper : public gpg::SerHelperBase
    {
    public:
      /**
       * Address: 0x00BDC980 (FUN_00BDC980, register_PathQueueImplSerializer,
       * dynamic initializer for the global `PathQueueImplSerializer` singleton)
       *
       * What it does:
       * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
       * and splices it into the process-global `sNewHelpers` pending list),
       * then binds the deserialize/serialize callback fields and installs
       * process-exit cleanup.
       */
      PathQueueImplSerializerHelper();

      /**
       * Address: 0x00C01B40 (FUN_00C01B40, dynamic atexit destructor for `gPathQueueImplSerializerHelper`)
       *
       * What it does:
       * Unlinks this helper node from the serializer-helper list (the
       * `TDatListItem` base destructor). The compiler registers it with
       * `atexit` from the global's dynamic initializer (0x00BDC980).
       * `FUN_00766C00` and `FUN_00766C30` are
       * unreferenced out-of-line copies of the same body.
       */
      ~PathQueueImplSerializerHelper() = default;

      /**
       * Address: 0x00767140 (FUN_00767140, gpg::SerSaveLoadHelper<Moho::PathQueue::Impl>::Init)
       *
       * What it does:
       * Resolves `PathQueue::Impl` RTTI and installs this helper's load/save
       * callbacks into the reflected type descriptor.
       */
      void Init() override;

    public:
      gpg::RType::load_func_t mLoadCallback;
      gpg::RType::save_func_t mSaveCallback;
    };
    static_assert(
      offsetof(PathQueueImplSerializerHelper, mLoadCallback) == 0x0C,
      "PathQueueImplSerializerHelper::mLoadCallback offset must be 0x0C"
    );
    static_assert(
      offsetof(PathQueueImplSerializerHelper, mSaveCallback) == 0x10,
      "PathQueueImplSerializerHelper::mSaveCallback offset must be 0x10"
    );
    static_assert(
      sizeof(PathQueueImplSerializerHelper) == 0x14, "PathQueueImplSerializerHelper size must be 0x14"
    );

    PathQueueImplSerializerHelper gPathQueueImplSerializerHelper;

    PathQueueImplSerializerHelper::PathQueueImplSerializerHelper()
      : mLoadCallback(&PathQueueImplSerializerDeserialize)
      , mSaveCallback(&PathQueueImplSerializerSerialize)
    {}

    /**
     * Address: 0x00767140 (FUN_00767140, gpg::SerSaveLoadHelper<Moho::PathQueue::Impl>::Init)
     *
     * What it does:
     * Resolves reflected type metadata for `PathQueue::Impl` (via a cached
     * `sType` singleton, lazy `gpg::LookupRType(typeid(PathQueue::Impl))`)
     * and installs this helper's load/save callbacks into it. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void PathQueueImplSerializerHelper::Init()
    {
      static gpg::RType* type = nullptr;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(PathQueue::Impl));
      }

      if (type->serLoadFunc_ != nullptr) {
        gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
      }

      const bool saveWasNull = type->serSaveFunc_ == nullptr;
      type->serLoadFunc_ = mLoadCallback;

      if (!saveWasNull) {
        gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
      }

      type->serSaveFunc_ = mSaveCallback;
    }

    class PathQueueTypeInfo final : public gpg::RType
    {
    public:
      /**
       * Address: 0x007668B0 (FUN_007668B0, Moho::PathQueueTypeInfo::GetName)
       */
      [[nodiscard]] const char* GetName() const override
      {
        return "PathQueue";
      }

      /**
       * Address: 0x00766870 (FUN_00766870, Moho::PathQueueTypeInfo::Init)
       */
      void Init() override
      {
        size_ = sizeof(PathQueue);
        (void)BindPathQueueTypeInfoLifecycleCallbacks(this);
        gpg::RType::Init();
        Finish();
      }
    };

    class PathQueueImplTypeInfo final : public gpg::RType
    {
    public:
      /**
       * Address: 0x00766AF0 (FUN_00766AF0, Moho::PathQueueImplTypeInfo::GetName)
       */
      [[nodiscard]] const char* GetName() const override
      {
        return "PathQueueImpl";
      }

      /**
       * Address: 0x00766AB0 (FUN_00766AB0, Moho::PathQueueImplTypeInfo::Init)
       */
      void Init() override
      {
        size_ = sizeof(PathQueue::Impl);
        (void)BindPathQueueImplTypeInfoLifecycleCallbacks(this);
        gpg::RType::Init();
        Finish();
      }
    };
  } // namespace

  /**
   * Address: 0x00768A10 (FUN_00768A10)
   *
   * IDA signature:
   * int *__usercall sub_768A10@<eax>(gpg::ReadArchive *this@<ecx>, int a2@<eax>);
   *
   * What it does:
   * The inverse of `MemberSerialize`:
   *   1) the tracked `PathTables*` owner (+0x00);
   *   2) the pending travelers (`mPendingTravelers`, +0x04) as a
   *      `gpg::DList<Moho::IPathTraveler,void>`;
   *   3) the in-flight traveler (`mBase.mTraveler`, +0x58), the same type;
   *   4) the in-flight traveler back to the front of the pending list, so the
   *      interrupted query restarts first.
   *
   * The list type is resolved once into a function-local cache, and every read
   * gets a fresh zeroed owner reference, as in the binary. The spliced ring's
   * first node that the binary leaves in EAX is discarded by its caller.
   */
  void PathQueue::Impl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    gpg::RRef ownerRef{};
    archive->ReadPointer(&mOwner, &ownerRef);

    static gpg::RType* dlistType = nullptr;
    if (dlistType == nullptr) {
      dlistType = gpg::LookupRType(typeid(gpg::DList<IPathTraveler, void>));
    }

    gpg::RRef pendingOwner{};
    archive->Read(dlistType, &mPendingTravelers, pendingOwner);

    if (dlistType == nullptr) {
      dlistType = gpg::LookupRType(typeid(gpg::DList<IPathTraveler, void>));
    }

    gpg::RRef travelerOwner{};
    archive->Read(dlistType, &mBase.mTraveler, travelerOwner);

    // The in-flight traveler goes back to the front of the pending list
    // (0x00768AA8), so the query restarts first.
    mPendingTravelers.splice_front(mBase.mTraveler);
  }

  /**
   * Address: 0x00768AD0 (FUN_00768AD0)
   *
   * IDA signature:
   * void __usercall sub_768AD0(Moho::PathQueue::Impl *a1@<eax>, BinaryWriteArchive *a2@<ebx>);
   *
   * What it does:
   * Saves the owning `PathTables*` as an unowned tracked pointer, then the
   * pending travelers (+0x04) and the in-flight traveler (`mBase.mTraveler`,
   * +0x58) as `gpg::DList<Moho::IPathTraveler,void>` values. The list type is
   * resolved once into a function-local cache and every write gets a fresh
   * zeroed owner reference, as in the binary.
   */
  void PathQueue::Impl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    gpg::RRef ownerRef{};
    archive->WritePointer<moho::PathTables>(mOwner, gpg::TrackedPointerState::Unowned, ownerRef);

    static gpg::RType* dlistType = nullptr;
    if (dlistType == nullptr) {
      dlistType = gpg::LookupRType(typeid(gpg::DList<IPathTraveler, void>));
    }

    gpg::RRef pendingOwner{};
    archive->Write(dlistType, &mPendingTravelers, pendingOwner);

    if (dlistType == nullptr) {
      dlistType = gpg::LookupRType(typeid(gpg::DList<IPathTraveler, void>));
    }

    gpg::RRef travelerOwner{};
    archive->Write(dlistType, &mBase.mTraveler, travelerOwner);
  }

  /**
   * Address: 0x00766810 (FUN_00766810)
   *
   * What it does:
   * Constructs and preregisters the reflected type-info object for
   * `moho::PathQueue`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* RegisterPathQueueTypeInfo()
  {
    static PathQueueTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(PathQueue), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00766A50 (FUN_00766A50)
   *
   * What it does:
   * Constructs and preregisters the reflected type-info object for
   * `moho::PathQueue::Impl`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* RegisterPathQueueImplTypeInfo()
  {
    static PathQueueImplTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(PathQueue::Impl), &typeInfo);
    return &typeInfo;
  }

  namespace
  {
    struct PathQueueTypeInfoBootstrap
    {
      PathQueueTypeInfoBootstrap()
      {
        (void)RegisterPathQueueTypeInfo();
        (void)RegisterPathQueueImplTypeInfo();
      }
    };

    [[maybe_unused]] PathQueueTypeInfoBootstrap gPathQueueTypeInfoBootstrap;
  } // namespace

  struct OccupySourceBinding final : public gpg::HaStar::IOccupationSource
  {
    COGrid* mGrid;                // +0x04
    SNamedFootprint* mFootprint;  // +0x08

    /**
     * Address: 0x0076B750 (FUN_0076B750, ??0OccupySourceBinding@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Initializes one path occupation-source binding with null grid and
     * null footprint owners.
     */
    OccupySourceBinding();

    /**
     * Address: 0x0076B760 (FUN_0076B760, ??0OccupySourceBinding@Moho@@QAE@@Z_1)
     *
     * What it does:
     * Initializes one path occupation-source binding with explicit grid and
     * footprint owners.
     */
    OccupySourceBinding(COGrid* grid, SNamedFootprint* footprint);

    /**
     * Address: 0x0076CB50 (FUN_0076CB50, ??0OccupySourceBinding@Moho@@QAE@@Z)
     *
     * What it does:
     * Copy-constructs one path occupation-source binding owner pair.
     */
    OccupySourceBinding(const OccupySourceBinding& other);

    /**
     * Address: 0x0076B770 (FUN_0076B770, Moho::OccupySourceBinding::GetOccupyData)
     *
     * What it does:
     * Builds one 9-lane HaStar occupation mask neighborhood for the supplied
     * world cell using footprint occupancy filtering.
     */
    void GetOccupationData(int worldX, int worldY, gpg::HaStar::OccupationData& outData) override;
  };

  static_assert(sizeof(OccupySourceBinding) == 0x0C, "OccupySourceBinding size must be 0x0C");
  static_assert(offsetof(OccupySourceBinding, mGrid) == 0x04, "OccupySourceBinding::mGrid offset must be 0x04");
  static_assert(
    offsetof(OccupySourceBinding, mFootprint) == 0x08, "OccupySourceBinding::mFootprint offset must be 0x08"
  );

  /**
   * `Moho::PathTables::Impl`: one occupancy source and one cluster map per
   * footprint, every map sharing one cluster cache.
   */
  struct PathTables::Impl
  {
    /**
     * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Empty source and map vectors, then a fresh cluster cache.
     */
    Impl();

    /**
     * Address: 0x0076CF30 (FUN_0076CF30, ??1Impl@PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases the cluster cache, then the map and source vectors' storage.
     */
    ~Impl();

    std::int32_t mWidth;                          // +0x00
    std::int32_t mHeight;                         // +0x04
    msvc8::vector<OccupySourceBinding> mSources;  // +0x08
    msvc8::vector<ClusterMap*> mMaps;             // +0x18
    gpg::HaStar::ClusterCache mClusterCache;      // +0x28
  };

  static_assert(sizeof(PathTables::Impl) == 0x30, "PathTables::Impl size must be 0x30");
  static_assert(offsetof(PathTables::Impl, mSources) == 0x08, "PathTables::Impl::mSources offset must be 0x08");
  static_assert(offsetof(PathTables::Impl, mMaps) == 0x18, "PathTables::Impl::mMaps offset must be 0x18");
  static_assert(offsetof(PathTables::Impl, mClusterCache) == 0x28, "PathTables::Impl::mClusterCache offset must be 0x28");
} // namespace moho

namespace
{
  bool gGenPathWarmupPending = true;

  [[nodiscard]] bool IsGenPathEnabled()
  {
#ifdef _WIN32
    const char* const commandLine = ::GetCommandLineA();
    return commandLine && std::strstr(commandLine, "/genpath");
#else
    return false;
#endif
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
   * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
   *
   * What it does:
   * Null owner, empty pending list (self-linked at +0x04), then the
   * `ImplBase` at +0x0C.
   */
  PathQueue::Impl::Impl()
    : mOwner(nullptr)
  {}

  /**
   * Address: 0x00765D30 (FUN_00765D30, ??0PathQueue@Moho@@QA@Z)
   *
   * What it does:
   * Allocates the `Impl`, then records the `PathTables` it searches.
   */
  PathQueue::PathQueue(PathTables* const owner)
    : mImpl(new Impl())
  {
    mImpl->mOwner = owner;
  }

  PathQueue::~PathQueue() = default;

  /**
   * Address: 0x0076AD40 (FUN_0076AD40)
   *
   * IDA signature:
   * void __usercall sub_76AD40(int* slot@<eax>, gpg::ReadArchive* archive@<ebx>);
   *
   * What it does:
   * Reads the owned `Impl` and installs it; the `Impl` it replaces is deleted
   * after the store, which is `scoped_ptr::reset`.
   */
  void PathQueue::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    Impl* loaded = nullptr;
    const gpg::RRef owner{};
    (void)archive->ReadPointerOwned(&loaded, &owner);
    mImpl.reset(loaded);
  }

  /**
   * What it does:
   * Writes the `Impl` as an owned tracked pointer. Inlined into
   * `PathQueueSerializer::Serialize` (0x00766980), which builds the
   * reference through `gpg::RRef_PathQueue_Impl` (0x0076A5F0).
   */
  void PathQueue::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef owner{};
    gpg::RRef payload{};
    (void)gpg::RRef_PathQueue_Impl(&payload, mImpl.get());
    gpg::WriteRawPointer(archive, payload, gpg::TrackedPointerState::Owned, owner);
  }

  /**
   * Address: 0x00765FE0 (FUN_00765FE0)
   *
   * IDA signature:
   * void __userpurge sub_765FE0(Moho::PathQueue::ImplBase *a1@<eax>, Moho::CAiPathFinder *a2@<edi>, int a3);
   *
   * What it does:
   * Starts a query for `traveler`: clears the previous search, picks the
   * cluster map matching the traveler's footprint, moves the traveler out of
   * the pending ring into the active slot, and seeds the search at its anchor
   * cell.
   */
  void PathQueue::ImplBase::BeginQuery(IPathTraveler& traveler, PathTables& owner)
  {
    // "mTraveler.empty()", PathQueue.cpp:148
    assert(mTraveler.empty());

    const SFootprint* const footprint = traveler.GetFootprint();

    mExpandCount = 0;
    mPathCap = traveler.GetPathcap();

    HPathCell anchor{};
    traveler.GetAnchorCell(&anchor);
    mClosestCell.x = static_cast<std::int16_t>(anchor.x);
    mClosestCell.z = static_cast<std::int16_t>(anchor.z);
    mClosestDistance = std::numeric_limits<float>::max();

    // The traveller hands back its named footprint; the binary reads the index
    // at +0x2C, which only exists on SNamedFootprint. The declared return type
    // is the base, so the concrete type has to be recovered here.
    const auto* const namedFootprint = static_cast<const SNamedFootprint*>(footprint);
    mClusterMap = owner.ClusterMapForFootprint(namedFootprint->mIndex);

    ResetSearch();
    mResultCells.clear();

    // Move the traveler from the pending list to the in-flight one.
    mTraveler.push_back(&traveler);

    AddStartNode(mClosestCell, *this);
  }

  /**
   * Address: 0x00766140 (FUN_00766140)
   *
   * IDA signature:
   * int __userpurge sub_766140@<eax>(Moho::PathQueue::ImplBase *a1@<edi>, char a2);
   *
   * What it does:
   * Ends the current query: materialises the path to the best cell reached,
   * detaches the traveler, and notifies it of the outcome.
   *
   * The path is built even on failure - the traveler still gets the closest
   * approach through `OnPathRejected` and can decide what to do with it.
   */
  void PathQueue::ImplBase::FinishQuery(const bool reachedGoal)
  {
    IPathTraveler* const traveler = CurrentTraveler();

    mResultCells.clear();
    (void)BuildPath(mClosestCell, mResultCells);

    // 0x00766186: the traveler's own node leaves the in-flight list.
    if (traveler == nullptr) {
      return;
    }
    traveler->ListUnlink();

    const SNavPath& path = *reinterpret_cast<const SNavPath*>(&mResultCells);
    if (reachedGoal) {
      traveler->OnPathAccepted(path);
    } else {
      traveler->OnPathRejected(path);
    }
  }

  /**
   * Address: 0x00766047 (inlined into the query-setup lane at 0x00765FE0)
   */
  gpg::HaStar::ClusterMap* PathTables::ClusterMapForFootprint(const std::int32_t footprintIndex) const
  {
    return mImpl->mMaps[footprintIndex];
  }

  /**
   * Address: 0x00765ED0 (FUN_00765ED0, Moho::PathQueue::Work)
   *
   * IDA signature:
   * void __usercall Moho::PathQueue::Work(Moho::PathQueue *this@<ebx>, int *budget@<esi>);
   *
   * What it does:
   * Drains the traveller queue while budget remains.
   *
   * Each turn of the loop either continues the query already in flight or, if
   * none is, promotes the next traveller off the pending ring. `WorkOnce` then
   * runs until it either finishes the query or reports the budget spent - the
   * one outcome that leaves the query in flight, to be resumed on a later tick.
   * That is what makes pathfinding here incremental across frames rather than a
   * single blocking search.
   */
  void PathQueue::Work(int& budget)
  {
    while (budget > 0) {
      Impl& impl = *mImpl;

      if (impl.mBase.mTraveler.empty()) {
        if (impl.mPendingTravelers.empty()) {
          // Nothing queued; the remaining budget goes unspent.
          return;
        }

        impl.mBase.BeginQuery(*impl.mPendingTravelers.front(), *impl.mOwner);
      }

      // "!mTraveler.empty()", PathQueue.cpp:169
      assert(!impl.mBase.mTraveler.empty());

      impl.mBase.mBudget = budget;
      const ImplBase::Step step = impl.mBase.WorkOnce(impl.mBase);
      budget = impl.mBase.mBudget;

      if (step == ImplBase::Step::BudgetExhausted) {
        // "cpuBudget <= 0", PathQueue.cpp:179
        assert(budget <= 0);
      } else {
        impl.mBase.FinishQuery(step == ImplBase::Step::GoalReached);
      }
    }
  }

  /**
   * Address: 0x00765DD0 (FUN_00765DD0)
   *
   * IDA signature:
   * void __userpurge sub_765DD0(int *pBudget@<esi>, Moho::PathQueue *arg0, Moho::CAiPathFinder *a2);
   *
   * What it does:
   * Answers one path query synchronously instead of queueing it.
   *
   * The search state is a local `ImplBase` rather than the queue's own, so a
   * caller that needs an answer this instant cannot corrupt whatever query the
   * queue already has in flight. Only a single `WorkOnce` pass runs: whatever
   * the budget buys is what the traveller gets, and it is notified either way.
   */
  void PathQueue::WorkImmediate(int& budget, IPathTraveler& traveller)
  {
    ImplBase scratch;

    scratch.BeginQuery(traveller, *mImpl->mOwner);

    // "!mTraveler.empty()", PathQueue.cpp:169
    assert(!scratch.mTraveler.empty());

    scratch.mBudget = budget;
    const ImplBase::Step step = scratch.WorkOnce(scratch);
    budget = scratch.mBudget;

    scratch.FinishQuery(step == ImplBase::Step::GoalReached);
  }

  void PathQueue::QueueTraveler(IPathTraveler& traveller)
  {
    mImpl->mPendingTravelers.push_back(&traveller);
  }

  /**
   * Address: 0x00701AD0 (FUN_00701AD0, Moho::PathQueue::Move)
   *
   * What it does:
   * Stores the new queue in the owner's slot, then deletes the previous one
   * (`~PathQueue` deletes its `Impl`) -- `scoped_ptr::reset` inlined.
   */
  void PathQueue::Move(PathQueue** const slot, PathQueue* const replacement) noexcept
  {
    PathQueue* const previous = *slot;
    *slot = replacement;
    delete previous;
  }

  /**
   * Address: 0x0076B750 (FUN_0076B750, ??0OccupySourceBinding@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Initializes one path occupation-source binding with null grid and
   * null footprint owners.
   */
  OccupySourceBinding::OccupySourceBinding()
    : mGrid(nullptr)
    , mFootprint(nullptr)
  {
  }

  /**
   * Address: 0x0076B760 (FUN_0076B760, ??0OccupySourceBinding@Moho@@QAE@@Z_1)
   *
   * What it does:
   * Initializes one path occupation-source binding with explicit grid and
   * footprint owners.
   */
  OccupySourceBinding::OccupySourceBinding(COGrid* const grid, SNamedFootprint* const footprint)
    : mGrid(grid)
    , mFootprint(footprint)
  {
  }

  /**
   * Address: 0x0076CB50 (FUN_0076CB50, ??0OccupySourceBinding@Moho@@QAE@@Z)
   *
   * What it does:
   * Copy-constructs one path occupation-source binding owner pair.
   */
  OccupySourceBinding::OccupySourceBinding(const OccupySourceBinding& other)
    : mGrid(other.mGrid)
    , mFootprint(other.mFootprint)
  {
  }

  /**
   * Address: 0x0076B770 (FUN_0076B770, Moho::OccupySourceBinding::GetOccupyData)
   *
   * What it does:
   * Builds one 9-lane HaStar occupation mask neighborhood for the supplied
   * world cell using footprint occupancy filtering.
   */
  void OccupySourceBinding::GetOccupationData(
    const int worldX,
    const int worldY,
    gpg::HaStar::OccupationData& outData
  )
  {
    constexpr std::size_t kOccupationResultColumnCount = 9u;
    constexpr std::size_t kMaxFootprintRows = 32u;
    constexpr std::size_t kMaxRowMaskCount = kOccupationResultColumnCount + kMaxFootprintRows;

    if (mFootprint == nullptr || mGrid == nullptr) {
      outData = {};
      return;
    }

    const std::uint32_t footprintWidth = static_cast<std::uint32_t>(mFootprint->mSizeX);
    const std::uint32_t footprintHeight = static_cast<std::uint32_t>(mFootprint->mSizeZ);
    const std::uint32_t activeRowCount = footprintHeight + static_cast<std::uint32_t>(kOccupationResultColumnCount - 1u);
    const std::uint32_t widthMask = (1u << footprintWidth) - 1u;

    std::array<std::uint32_t, kMaxRowMaskCount> rowMasks{};
    for (std::uint32_t row = 0; row < activeRowCount && row < rowMasks.size(); ++row) {
      rowMasks[row] = 0x1FFu;
      for (std::uint32_t x = 0; x < (footprintWidth + static_cast<std::uint32_t>(kOccupationResultColumnCount - 1u)); ++x) {
        SOCellPos cellPos{};
        cellPos.x = static_cast<std::int16_t>(worldX + static_cast<int>(x));
        cellPos.z = static_cast<std::int16_t>(worldY + static_cast<int>(row));

        const EOccupancyCaps filteredCaps = OCCUPY_Filter(*mFootprint, *mGrid, cellPos, EOccupancyCaps::OC_ANY);
        if (filteredCaps == static_cast<EOccupancyCaps>(0u)) {
          const std::uint32_t shiftedMask = (widthMask << x) >> (footprintWidth - 1u);
          rowMasks[row] &= ~shiftedMask;
        }
      }
    }

    if (footprintHeight > 1u) {
      for (std::size_t column = 0; column < kOccupationResultColumnCount; ++column) {
        for (std::uint32_t y = 1u; y < footprintHeight; ++y) {
          rowMasks[column] &= rowMasks[column + y];
        }
      }
    }

    for (std::size_t i = 0; i < kOccupationResultColumnCount; ++i) {
      outData.mRows[i] = static_cast<std::uint16_t>(rowMasks[i]);
    }
    outData.mPad = 0u;
  }

  /**
   * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Empty source and map vectors, then a fresh cluster cache: one
   * `ClusterCacheImpl` under a new shared count (`FUN_009356E0`).
   */
  PathTables::Impl::Impl()
  {
    gpg::HaStar::InitializeClusterCache(mClusterCache);
  }

  /**
   * Address: 0x0076CF30 (FUN_0076CF30, ??1Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Member teardown in reverse order: the cluster cache's reference, then the
   * map and source vectors' storage. The maps themselves are `~PathTables`'.
   */
  PathTables::Impl::~Impl() = default;

  /**
   * Address: 0x0076B8C0 (FUN_0076B8C0, ??0PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * One occupancy source and one cluster map per footprint, in footprint index
   * order. Each map spans the whole grid with two hierarchy levels and pads
   * its cluster area by one cell around the footprint.
   */
  PathTables::PathTables(
    const SRuleFootprintsBlueprint& footprints,
    COGrid* const grid,
    const int width,
    const int height
  )
    : mImpl(new Impl())
  {
    mImpl->mWidth = width;
    mImpl->mHeight = height;

    const std::size_t footprintCount = footprints.mFootprints.size();
    mImpl->mSources.resize(footprintCount);
    mImpl->mMaps.resize(footprintCount);

    std::int32_t index = 0;
    for (const SNamedFootprint& entry : footprints.mFootprints) {
      SNamedFootprint& footprint = const_cast<SNamedFootprint&>(entry);
      if (index != footprint.mIndex) {
        gpg::HandleAssertFailure("i == fp.mIndex", 113, "c:\\work\\rts\\main\\code\\src\\sim\\PathTables.cpp");
      }

      OccupySourceBinding& source = mImpl->mSources[index];
      source.mGrid = grid;
      source.mFootprint = &footprint;

      gpg::Rect2i area{};
      area.x0 = -1;
      area.z0 = -1;
      area.x1 = static_cast<int>(footprint.mSizeX) + 1;
      area.z1 = static_cast<int>(footprint.mSizeZ) + 1;
      mImpl->mMaps[index] = new ClusterMap(
        &source,
        static_cast<unsigned int>(width),
        static_cast<unsigned int>(height),
        mImpl->mClusterCache,
        2u,
        area
      );
      ++index;
    }
  }

  /**
   * Address: 0x0076BAC0 (FUN_0076BAC0, ??1PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Deletes every cluster map, then the `Impl`.
   */
  PathTables::~PathTables()
  {
    for (ClusterMap* const map : mImpl->mMaps) {
      delete map;
    }
    delete mImpl;
  }

  /**
   * Address: 0x0076BC10 (FUN_0076BC10)
   */
  void PathTables::UpdateBackground(int* budget)
  {
    if (!budget || !mImpl) {
      return;
    }

    // /genpath one-shot pass forces "unlimited" budget through every cluster once.
    if (IsGenPathEnabled() && gGenPathWarmupPending) {
      for (ClusterMap* const cluster : mImpl->mMaps) {
        if (cluster != nullptr) {
          *budget = INT_MAX;
          cluster->BackgroundWork(*budget);
        }
      }
      gGenPathWarmupPending = false;
    }

    for (ClusterMap* const cluster : mImpl->mMaps) {
      if (cluster != nullptr) {
        cluster->BackgroundWork(*budget);
      }
    }
  }

  // ---------------------------------------------------------------------
  // TEMPORARY PROBE -- delete with the call site in DirtyClusters below.
  // Not part of the recovery: the binary dereferences the lane unguarded.
  // ---------------------------------------------------------------------

  /// True when `cluster` points at committed, writable private heap memory,
  /// which every live `ClusterMap` does (`::operator new(sizeof(ClusterMap))`
  /// in the `PathTables` constructor). A pointer into the image, a reserved
  /// or free region, or a read-only page is corruption by definition.
  [[nodiscard]] bool ClusterMapPointerLooksLive(const ClusterMap* const cluster) noexcept
  {
    MEMORY_BASIC_INFORMATION info{};
    if (::VirtualQuery(cluster, &info, sizeof(info)) != sizeof(info)) {
      return false;
    }
    if (info.State != MEM_COMMIT || info.Type != MEM_PRIVATE) {
      return false;
    }

    constexpr DWORD kWritableMask = PAGE_READWRITE | PAGE_WRITECOPY
                                  | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((info.Protect & kWritableMask) == 0u || (info.Protect & PAGE_GUARD) != 0u) {
      return false;
    }

    // The object must fit inside the region it starts in; a pointer landing in
    // the last few bytes of a block is the signature of a mid-block overwrite.
    const auto address = reinterpret_cast<std::uintptr_t>(cluster);
    const auto regionEnd = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    return (address + sizeof(ClusterMap)) <= regionEnd;
  }

  /// Emits one line per corrupt lane entry, plus the whole array on the first
  /// hit, so the shape of the damage is visible: a single bad slot means the
  /// `ClusterMap` block was recycled, whereas several bad slots (or a wrecked
  /// begin/end pair) mean the pointer array itself was overwritten.
  void ReportCorruptClusterMapLane(
    const PathTables::Impl* const impl,
    ClusterMap** const slot,
    const ClusterMap* const cluster
  ) noexcept
  {
    static bool sDumpedLane = false;

    char line[256];
    MEMORY_BASIC_INFORMATION info{};
    const bool queried = ::VirtualQuery(cluster, &info, sizeof(info)) == sizeof(info);
    (void)std::snprintf(
      line, sizeof(line),
      "[CLUSTERLANE] bad slot=%p index=%d cluster=%p state=%08lX type=%08lX protect=%08lX\n",
      static_cast<const void*>(slot),
      static_cast<int>(slot - impl->mMaps.begin()),
      static_cast<const void*>(cluster),
      queried ? info.State : 0ul,
      queried ? info.Type : 0ul,
      queried ? info.Protect : 0ul
    );
    ::OutputDebugStringA(line);

    if (sDumpedLane) {
      return;
    }
    sDumpedLane = true;

    (void)std::snprintf(
      line, sizeof(line),
      "[CLUSTERLANE] impl=%p first=%p last=%p end=%p count=%d\n",
      static_cast<const void*>(impl),
      static_cast<const void*>(impl->mMaps.begin()),
      static_cast<const void*>(impl->mMaps.end()),
      static_cast<const void*>(impl->mMaps.begin() + impl->mMaps.capacity()),
      static_cast<int>(impl->mMaps.size())
    );
    ::OutputDebugStringA(line);

    for (ClusterMap** it = impl->mMaps.begin(); it != impl->mMaps.end(); ++it) {
      (void)std::snprintf(
        line, sizeof(line), "[CLUSTERLANE]   [%d] = %p\n",
        static_cast<int>(it - impl->mMaps.begin()), static_cast<const void*>(*it)
      );
      ::OutputDebugStringA(line);
    }
  }

  /**
   * Address: 0x0076BBD0 (FUN_0076BBD0, Moho::PathQueue::DirtyClusters)
   */
  void PathTables::DirtyClusters(const gpg::Rect2i& dirtyRect)
  {
    if (!mImpl) {
      return;
    }

    for (ClusterMap** it = mImpl->mMaps.begin(); it != mImpl->mMaps.end(); ++it) {
      ClusterMap* const cluster = *it;
      if (!cluster) {
        continue;
      }

      // TEMPORARY PROBE (remove once the ClusterMap* corruption is root-caused).
      // The reported fault is inside DirtyRect's very first statement, reading
      // `mArea` at +0x90 -- i.e. this array held a readable-but-wrong pointer.
      // Classify it before dereferencing so one run says whether the *array*
      // was smashed or a single entry, and what the garbage actually is (a
      // freed block, an image/.rdata address like the documented small-block
      // allocator defect, or an unmapped page).
      //
      // Each slot is queried once per pointer value: the array is filled in the
      // PathTables constructor and never reassigned, so the corruption this
      // hunts shows up as a slot whose value changed. A VirtualQuery on every
      // call cost one syscall per cluster per dirtied rect, and every prop
      // creation dirties one - that stalled the sim for ~40s while the
      // commander's warp-in knocked trees down, and slowed it after.
      static const ClusterMap* sVerifiedLanes[32]{};
      const std::ptrdiff_t lane = it - mImpl->mMaps.begin();
      const bool cached = lane < std::ssize(sVerifiedLanes) && sVerifiedLanes[lane] == cluster;
      if (!cached) {
        if (!ClusterMapPointerLooksLive(cluster)) {
          ReportCorruptClusterMapLane(mImpl, it, cluster);
          continue;
        }
        if (lane < std::ssize(sVerifiedLanes)) {
          sVerifiedLanes[lane] = cluster;
        }
      }

      cluster->DirtyRect(dirtyRect);
    }
  }

  // Static cached RType slot for the placeholder `PathQueue` type;
  // populated lazily by `gpg::RRef_PathQueue` via cached lookup.
  gpg::RType* PathQueue::sType = nullptr;
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(RegisterPathQueueTypeInfo_96e1d0, moho::RegisterPathQueueTypeInfo)
GPG_PREREGISTER_INIT(RegisterPathQueueImplTypeInfo_96e1d0, moho::RegisterPathQueueImplTypeInfo)

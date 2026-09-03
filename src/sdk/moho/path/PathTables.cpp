#include "PathTables.h"

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
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
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

template <typename T>
struct LegacyVectorStorage
{
  T* mFirst;
  T* mLast;
  T* mEnd;
};

static_assert(sizeof(LegacyVectorStorage<std::uint8_t>) == 0x0C, "LegacyVectorStorage size must be 0x0C");

namespace
{
  constexpr const char* kSerializationHeaderPath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.h";

  /**
   * The traveler ring node. `moho::TDatListItem` is `{mPrev, mNext}` in that order,
   * which is what the binary uses: `PathQueue::Work` tests emptiness with
   * `cmp [ecx+4], ecx` (0x00765EE5) and reaches the current traveler through
   * `[edi+50h]` (0x00766141), i.e. through the *second* word of the node at
   * +0x4C. An earlier reconstruction had these two fields the other way round.
   */
  using PathQueueIntrusiveNode = moho::TDatListItem<void, void>;

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
   * `Moho::PathQueue::ImplBase` - one in-flight path query.
   *
   * The first 0x4C bytes are the generic A* search state (node table + open
   * heap); everything from +0x4C onward is this class's own per-query state.
   * The derivation is what makes the binary pass the same pointer as both the
   * search and the traits argument (`push edi; push edi` at 0x00765F36).
   *
   * Layout:
   *   +0x00 : gpg::AStarSearch base   (node hash_map 0x28 + open heap 0x24)
   *   +0x4C : mTraveler       traveler ring head (at most one entry is live)
   *   +0x54 : mClosestCell    best cell seen so far, by heuristic
   *   +0x58 : mClosestDistance
   *   +0x5C : mClusterMap     cluster map selected for this traveler's footprint
   *   +0x60 : mBudget         remaining CPU budget, decremented per expansion
   *   +0x64 : mResultCells    the path handed back to the traveler
   *   +0x74 : mExpandCount    expansions performed for this traveler
   *   +0x78 : mPathCap        traveler-supplied expansion cap
   */
  struct PathQueueImplBaseRuntime
    : gpg::AStarSearch<moho::SOCellPos, PathQueueImplBaseRuntime, PathQueueCellTraits>
  {
    PathQueueIntrusiveNode mTraveler;         // +0x4C
    moho::SOCellPos mClosestCell;                   // +0x54
    float mClosestDistance;                   // +0x58
    gpg::HaStar::ClusterMap* mClusterMap;     // +0x5C
    std::int32_t mBudget;                     // +0x60
    msvc8::vector<moho::SOCellPos> mResultCells;    // +0x64
    std::int32_t mExpandCount;                // +0x74
    std::int32_t mPathCap;                    // +0x78

    PathQueueImplBaseRuntime()
      : mClosestCell()
      , mClosestDistance(0.0f)
      , mClusterMap(nullptr)
      , mBudget(0)
      , mExpandCount(0)
      , mPathCap(0)
    {
    }

    /** The traveler currently being served, or null when the ring is empty. */
    [[nodiscard]] moho::IPathTraveler* CurrentTraveler() const noexcept;

    /** A* traits hook: distance estimate from `cell` to this traveler's goal. */
    [[nodiscard]] float GetHeuristicCost(const moho::SOCellPos& cell) const;

    /** A* traits hook: tracks the closest cell reached, for fallback paths. */
    void NoteCandidateCell(const moho::SOCellPos& cell, float estimate) noexcept;
  };

  static_assert(sizeof(PathQueueIntrusiveNode) == 0x08, "PathQueueIntrusiveNode size must be 0x08");
  static_assert(sizeof(PathQueueImplBaseRuntime) == 0x7C, "PathQueueImplBaseRuntime size must be 0x7C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mTraveler) == 0x4C, "PathQueueImplBaseRuntime::mTraveler offset must be 0x4C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mClosestCell) == 0x54, "PathQueueImplBaseRuntime::mClosestCell offset must be 0x54");
  static_assert(offsetof(PathQueueImplBaseRuntime, mClusterMap) == 0x5C, "PathQueueImplBaseRuntime::mClusterMap offset must be 0x5C");
  static_assert(offsetof(PathQueueImplBaseRuntime, mBudget) == 0x60, "PathQueueImplBaseRuntime::mBudget offset must be 0x60");
  static_assert(offsetof(PathQueueImplBaseRuntime, mResultCells) == 0x64, "PathQueueImplBaseRuntime::mResultCells offset must be 0x64");
  static_assert(offsetof(PathQueueImplBaseRuntime, mExpandCount) == 0x74, "PathQueueImplBaseRuntime::mExpandCount offset must be 0x74");
  static_assert(offsetof(PathQueueImplBaseRuntime, mPathCap) == 0x78, "PathQueueImplBaseRuntime::mPathCap offset must be 0x78");

  /**
   * Address: 0x00765B90 (FUN_00765B90, ??0ImplBase@PathQueue@Moho@@QAE@@Z)
   *          0x00766CE0 (FUN_00766CE0) - open-heap freelist arming
   *          0x00767600 (FUN_00767600) - node-table arming
   *
   * What it does:
   * Brings one `ImplBase` up to its empty-but-usable state: the traveler ring
   * is self-linked and the search structures are armed by their own
   * constructors.
   */
  void InitializePathQueueImplBase(PathQueueImplBaseRuntime& implBase)
  {
    implBase.mTraveler.mNext = &implBase.mTraveler;
    implBase.mTraveler.mPrev = &implBase.mTraveler;
    implBase.mClosestCell = moho::SOCellPos();
    implBase.mResultCells.clear();
  }

  /**
   * Address: 0x00766141 / 0x007684E3 / 0x0076614B (the recurring
   *          `mov eax, [reg+50h]` + `lea .., [eax-4]` pair)
   *
   * What it does:
   * Recovers the traveler from its ring node. `moho::IPathTraveler::mPathQueueNode`
   * sits at +0x04, which is the `-4` the binary applies; a null head means the
   * ring is empty.
   */
  moho::IPathTraveler* PathQueueImplBaseRuntime::CurrentTraveler() const noexcept
  {
    PathQueueIntrusiveNode* const head = mTraveler.mNext;
    if (head == nullptr || head == &mTraveler) {
      return nullptr;
    }

    return reinterpret_cast<moho::IPathTraveler*>(
      reinterpret_cast<std::uint8_t*>(head) - offsetof(moho::IPathTraveler, mPathQueueNode)
    );
  }

  /**
   * Address: 0x007684ED (vtable slot 3, `moho::IPathTraveler::GetHeuristicCost`)
   *
   * What it does:
   * A* traits hook - defers the distance estimate to the traveler being served.
   */
  float PathQueueImplBaseRuntime::GetHeuristicCost(const moho::SOCellPos& cell) const
  {
    const moho::IPathTraveler* const traveler = CurrentTraveler();
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
  void PathQueueImplBaseRuntime::NoteCandidateCell(const moho::SOCellPos& cell, float estimate) noexcept
  {
    if (mClosestDistance > estimate) {
      mClosestCell = cell;
      mClosestDistance = estimate;
    }
  }

  void ResetPathQueueNodeLinks(PathQueueIntrusiveNode& node)
  {
    node.mNext = &node;
    node.mPrev = &node;
  }

  void UnlinkAndResetPathQueueNode(PathQueueIntrusiveNode& node)
  {
    PathQueueIntrusiveNode* const next = node.mNext;
    PathQueueIntrusiveNode* const prev = node.mPrev;
    next->mPrev = prev;
    prev->mNext = next;
    ResetPathQueueNodeLinks(node);
  }

  /**
   * Splices every node currently linked into the circular `source` ring into
   * the destination ring immediately after `afterNode`, then resets `source`
   * back to an empty self-linked singleton.
   *
   * This is the O(1) whole-ring transfer the binary open-codes inline in
   * `DeserializePathQueueImplRefCallback` (0x00768A10) via three pointer
   * rewrites: the deserialized `mBase.mTraveler` traveler ring is drained into
   * the height-sentinel ring (the ring whose head node `afterNode` is the
   * sentinel's predecessor), preserving traveler order.
   *
   * Returns the source ring's original first node (`source.mNext`) when the
   * ring was non-empty, or `&source` when it was already empty, mirroring the
   * binary's `eax` return lane (discarded by the `load_func_t` callback).
   */
  PathQueueIntrusiveNode* SplicePathQueueNodesAfter(
    PathQueueIntrusiveNode& source,
    PathQueueIntrusiveNode* const afterNode
  ) noexcept
  {
    if (source.mPrev == &source) {
      // Empty ring: nothing to move; return the empty-ring sentinel address.
      return source.mPrev;
    }

    PathQueueIntrusiveNode* const first = source.mNext;
    PathQueueIntrusiveNode* const last = source.mPrev;
    PathQueueIntrusiveNode* const afterOldNext = afterNode->mNext;

    // Stitch the moved chain [first .. last] between afterNode and its old next.
    afterOldNext->mPrev = last;
    afterNode->mNext = first;
    first->mPrev = afterNode;
    last->mNext = afterOldNext;

    // Source ring becomes empty again.
    ResetPathQueueNodeLinks(source);
    return first;
  }

  /**
   * Address: 0x00765C30 (FUN_00765C30, Moho::PathQueue::ImplBase::~ImplBase)
   *
   * Reaches, through `AStarSearch::ResetSearch`:
   *   0x007672E0 (FUN_007672E0) - open-heap reset
   *   0x007676A0 (FUN_007676A0) - node-table element release
   *   0x00767C70 (FUN_00767C70) - bucket-window re-arm
   *
   * What it does:
   * Releases every search record and open-heap entry owned by one `ImplBase`,
   * leaving both structures armed for the next traveler.
   */
  void DestroyPathQueueImplBase(PathQueueImplBaseRuntime& implBase)
  {
    implBase.mResultCells.clear();
    implBase.ResetSearch();
  }

  /**
   * Address: 0x00765BE0 (FUN_00765BE0)
   *
   * What it does:
   * Detaches the traveler ring before releasing the search structures.
   */
  void DestroyPathQueueImpl(PathQueueImplBaseRuntime& implBase)
  {
    UnlinkAndResetPathQueueNode(implBase.mTraveler);
    DestroyPathQueueImplBase(implBase);
  }

  // ---------------------------------------------------------------------
  // PathQueue::Work closure
  // ---------------------------------------------------------------------

  /** One candidate step produced by expansion: where to, and at what cost. */
  struct PathQueueNeighbour
  {
    moho::SOCellPos mCell;  // +0x00
    float mCost;            // +0x04
  };
  static_assert(sizeof(PathQueueNeighbour) == 0x08, "PathQueueNeighbour size must be 0x08");

  /**
   * `WorkOnce` holds candidates in a stack buffer spanning `[esp+660h]` to
   * `[esp+CA0h]` (0x640 bytes) with a 0x10-byte header at `[esp+650h]`, i.e.
   * 200 inline entries before the vector spills to the heap.
   *
   * The 0x10-byte header is the four `FastVectorN` pointer lanes, and the
   * grow/insert lanes below read them at exactly those displacements:
   * `+0x00 start_`, `+0x04 end_`, `+0x08 capacity_`, `+0x0C originalVec_`
   * (`mov esi,[edi+4]` / `cmp edx,[edi+8]` at 0x00767378-0x00767384, and
   * `mov eax,[esi+0Ch]` at 0x00767848 for the inline-origin check).
   *
   * Address: 0x00767370 (FUN_00767370)
   *
   * IDA signature:
   * int __userpurge sub_767370@<eax>(_DWORD *a1@<edi>, int a2, int a3, int a4);
   *
   * What it does:
   * The out-of-line MSVC8 emission of
   * `gpg::core::FastVectorN<PathQueueNeighbour, 200>::InsertAt` - the
   * trivially-copyable element lane. It splices `[a3, a4)` in before `a2`:
   * when `size + count` still fits the capacity lane it copy-constructs the
   * displaced tail past `end_`, memmoves the middle block up by `count`, then
   * memmoves the source over the vacated window; when the range spills past
   * `end_` it copy-constructs the overflow suffix and the displaced tail
   * instead. When capacity is short it doubles it (`requiredSize < 2*capacity
   * ? 2*capacity : requiredSize`) and tail-calls the grow lane.
   *
   * This body is not written out again here: it is the template in
   * `gpg/core/containers/FastVector.h` (`FastVectorN::InsertAt`, the
   * `is_trivially_copyable_v<T>` lane at the tail of the function), and the
   * compiler emits it for this instantiation because
   * `EnumerateAdjacentCells` / `EnumerateClusterEdges` below odr-use
   * `PathQueueNeighbourBuffer::push_back`. Writing a second per-element-size
   * copy of it would duplicate a container operation the SDK already models.
   * Its sibling emissions of the same template body are already recovered as
   * `gpg::core::legacy::AppendRange8ByteLane` (0x0080EF20 / 0x007A24B0);
   * FUN_0080EF20 decompiles line-for-line identically to FUN_00767370,
   * differing only in the two callee addresses.
   *
   * Reached from the two `push_back` full-storage arms in this file:
   *   - 0x00766490, the `outNeighbours.push_back(neighbour)` in
   *     `EnumerateAdjacentCells` (FUN_00766350, level-0 arm),
   *   - 0x0076674D, the `outNeighbours.push_back(neighbour)` in
   *     `EnumerateClusterEdges` (FUN_00766350, level>0 arm).
   * Both sites match the template's `if (end_ == capacity_) InsertAt(end_,
   * &value, &value + 1);` guard exactly (`mov eax,[edi+4]; cmp eax,[edi+8];
   * jnz <in-place store>` at 0x0076646A / 0x0076671A).
   *
   * Address: 0x007677D0 (FUN_007677D0)
   *
   * IDA signature:
   * int __fastcall sub_7677D0(int splitPos@<ecx>, char **vec@<edx>, int capacity, int first, int last);
   *
   * What it does:
   * The matching `FastVectorN::GrowInsert` emission this instantiation
   * tail-calls at 0x007673B4. Allocates `operator new[](8 * capacity)`,
   * materializes prefix / inserted range / suffix into it through the copy
   * lane, then either hands the inline window back
   * (`*originalVec_ = capacity_` when `start_ == originalVec_`) or
   * `operator delete[]`s the old heap block, and rebinds the three lanes.
   * On a throwing copy the funclet at 0x00767882 frees the new block before
   * rethrowing, which is what `new T[]` + the template's scope give here.
   *
   * Address: 0x007678A0 (FUN_007678A0)
   *
   * What it does:
   * The element copy lane both of the above call; already recovered as
   * `gpg::core::legacy::CopyForward8ByteLane`.
   */
  using PathQueueNeighbourBuffer = gpg::core::FastVectorN<PathQueueNeighbour, 200>;

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

  /**
   * Address: 0x00766350 (FUN_00766350, level-0 arm)
   *
   * What it does:
   * Emits the walkable subset of the eight cells adjacent to `cell`.
   *
   * Each candidate must clear three gates in order: the traveler must want to
   * search the cluster the candidate falls in, the candidate cell must be
   * traversable, and the traveler must accept the edge (which may also revise
   * its cost). Only a candidate that clears all three sets its bit in
   * `acceptedMask`, so a diagonal is offered only once both of its adjacent
   * cardinals have been accepted.
   */
  [[nodiscard]] bool EnumerateAdjacentCells(
    PathQueueImplBaseRuntime& implBase,
    const moho::SOCellPos& cell,
    PathQueueNeighbourBuffer& outNeighbours
  )
  {
    moho::IPathTraveler* const traveler = implBase.CurrentTraveler();
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

      if (!traveler->ShouldSearchRect(implBase.mClusterMap->ClusterRect(candidateX, candidateZ, 1u))) {
        continue;
      }

      moho::SOCellPos candidate{};
      candidate.x = static_cast<std::int16_t>(candidateX);
      candidate.z = static_cast<std::int16_t>(candidateZ);

      if (!traveler->CanTraverseCell(candidate)) {
        continue;
      }

      float cost = kStepCost[step];
      if (!traveler->IsInBounds(cell, candidate, &cost)) {
        continue;
      }

      PathQueueNeighbour neighbour{};
      neighbour.mCell = candidate;
      neighbour.mCost = cost;
      outNeighbours.push_back(neighbour);

      acceptedMask |= 1u << step;
    }
    return true;
  }

  /**
   * Address: 0x00766350 (FUN_00766350, level>0 arm)
   *
   * What it does:
   * Emits the cluster-graph edges leaving `cell` at `level`.
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
  [[nodiscard]] bool EnumerateClusterEdges(
    PathQueueImplBaseRuntime& implBase,
    const moho::SOCellPos& cell,
    const int level,
    PathQueueNeighbourBuffer& outNeighbours
  )
  {
    moho::IPathTraveler* const traveler = implBase.CurrentTraveler();
    if (traveler == nullptr) {
      return true;
    }

    gpg::HaStar::ClusterMap& clusterMap = *implBase.mClusterMap;
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

        if (!clusterMap.WorkOnCluster(clusterX, clusterZ, level, implBase.mBudget)) {
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

            moho::SOCellPos candidate{};
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

            PathQueueNeighbour neighbour{};
            neighbour.mCell = candidate;
            neighbour.mCost = cost;
            outNeighbours.push_back(neighbour);
          }
        }

      }
    }
    return true;
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
  [[nodiscard]] bool ExpandCellNeighbours(
    PathQueueImplBaseRuntime& implBase,
    const moho::SOCellPos& cell,
    PathQueueNeighbourBuffer& outNeighbours
  )
  {
    moho::IPathTraveler* const traveler = implBase.CurrentTraveler();
    if (traveler == nullptr) {
      return true;
    }

    gpg::HaStar::ClusterMap& clusterMap = *implBase.mClusterMap;
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

      const bool completed = (level == 0)
        ? EnumerateAdjacentCells(implBase, cell, outNeighbours)
        : EnumerateClusterEdges(implBase, cell, level, outNeighbours);
      if (!completed) {
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

  /** Outcome of one expansion step, in the encoding `WorkOnce` returns. */
  enum class PathQueueStep : int
  {
    Continue = 0,
    GoalReached = 1,
    BudgetExhausted = 2,
    PathCapExceeded = 3,
  };

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
  [[nodiscard]] PathQueueStep StepExpansion(
    PathQueueImplBaseRuntime& implBase,
    const moho::SOCellPos& cell,
    PathQueueNeighbourBuffer& outNeighbours
  )
  {
    --implBase.mBudget;
    ++implBase.mExpandCount;

    if (implBase.mBudget <= 0) {
      return PathQueueStep::BudgetExhausted;
    }

    moho::IPathTraveler* const traveler = implBase.CurrentTraveler();
    if (traveler != nullptr && traveler->IsGoalCandidateCell(cell)) {
      implBase.mClosestCell = cell;
      return PathQueueStep::GoalReached;
    }

    if (implBase.mExpandCount > implBase.mPathCap) {
      return PathQueueStep::PathCapExceeded;
    }

    return ExpandCellNeighbours(implBase, cell, outNeighbours)
      ? PathQueueStep::Continue
      : PathQueueStep::BudgetExhausted;
  }

} // namespace

namespace moho
{
  struct PathQueue::Impl
  {
    /**
     * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
     * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
     *
     * What it does:
     * Initializes one `PathQueue::Impl` lane to empty state by zeroing queue
     * size, self-linking the height sentinel, and constructing the ImplBase
     * runtime owner lanes.
     */
    Impl();

    // +0x00 is the owning `PathTables`: `PathQueue::Work` hands it to the query
    // setup lane at 0x00765F04, which dereferences it twice
    // (`[[owner] + 0x1C][footprintIndex]`) to pick this traveler's cluster map.
    // It is still typed as a word here because nothing in this translation unit
    // dereferences it yet; the Work chain retypes it.
    PathTables* mOwner;                     // +0x00
    PathQueueIntrusiveNode mHeightSentinel; // +0x04
    // mBase now spans +0x0C..+0x88: the previous reconstruction stopped it at
    // +0x80 and padded the remainder, which hid `mExpandCount` / `mPathCap`.
    PathQueueImplBaseRuntime mBase;         // +0x0C
  };

  static_assert(sizeof(PathQueue::Impl) == 0x88, "PathQueue::Impl size must be 0x88");
  static_assert(offsetof(PathQueue::Impl, mOwner) == 0x00, "PathQueue::Impl::mOwner offset must be 0x00");
  static_assert(offsetof(PathQueue::Impl, mBase) == 0x0C, "PathQueue::Impl::mBase offset must be 0x0C");

  namespace
  {
    struct PathQueueRuntimeView
    {
      PathQueue::Impl* mImpl;
    };
    static_assert(sizeof(PathQueueRuntimeView) == sizeof(PathQueue), "PathQueue runtime view size must match PathQueue");
    static_assert(offsetof(PathQueueRuntimeView, mImpl) == 0x00, "PathQueueRuntimeView::mImpl offset must be 0x00");

    [[nodiscard]] gpg::RRef BuildPathQueueRefFromRuntime(PathQueueRuntimeView* const runtime) noexcept
    {
      gpg::RRef objectRef{};
      (void)gpg::RRef_PathQueue(&objectRef, reinterpret_cast<PathQueue*>(runtime));
      return objectRef;
    }

    [[nodiscard]] gpg::RType* ResolvePathQueueImplType() noexcept
    {
      static gpg::RType* sType = nullptr;
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(PathQueue::Impl));
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("Moho::PathQueue::Impl");
        }
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("PathQueue::Impl");
        }
        if (sType == nullptr) {
          sType = gpg::REF_FindTypeNamed("PathQueue_Impl");
        }
      }
      return sType;
    }

    [[nodiscard]] gpg::RRef BuildPathQueueImplRef(PathQueue::Impl* const impl) noexcept
    {
      gpg::RRef objectRef{};
      objectRef.mObj = impl;
      objectRef.mType = ResolvePathQueueImplType();
      return objectRef;
    }

    /**
     * Address: 0x0076AD40 (FUN_0076AD40, sub_76AD40)
     *
     * IDA signature:
     * void __usercall sub_76AD40(int* slot@<eax>, gpg::ReadArchive* archive@<ebx>);
     *
     * What it does:
     * Loads the owned `PathQueue::Impl` payload, installs it, and tears down
     * whatever the queue was holding. The old payload's search structures and
     * traveler ring go first, then its height sentinel leaves the queue's ring,
     * then the block itself is freed -- the same order the typeinfo delete lane
     * below uses.
     */
    void LoadPathQueueImplPayload(gpg::ReadArchive* const archive, PathQueueRuntimeView* const runtime)
    {
      GPG_ASSERT(archive != nullptr);
      GPG_ASSERT(runtime != nullptr);
      if (archive == nullptr || runtime == nullptr) {
        return;
      }

      moho::PathQueue::Impl* loaded = nullptr;
      const gpg::RRef owner{};
      (void)archive->ReadPointerOwned_PathQueue_Impl(&loaded, &owner);

      moho::PathQueue::Impl* const prior = runtime->mImpl;
      runtime->mImpl = loaded;

      if (prior != nullptr) {
        DestroyPathQueueImpl(prior->mBase);
        UnlinkAndResetPathQueueNode(prior->mHeightSentinel);
        ::operator delete(prior);
      }
    }

    /**
     * Address: 0x00766970 (FUN_00766970, Moho::PathQueueSerializer::Deserialize)
     *
     * What it does:
     * Reflection LOAD adapter: forwards one archive lane into
     * `LoadPathQueueImplPayload`.
     */
    void PathQueueSerializerDeserialize(
      gpg::ReadArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      LoadPathQueueImplPayload(
        archive,
        reinterpret_cast<PathQueueRuntimeView*>(static_cast<std::uintptr_t>(objectPtr))
      );
    }

    /**
     * Address: 0x00766980 (FUN_00766980, Moho::PathQueueSerializer::Serialize)
     *
     * What it does:
     * Reflection SAVE adapter. The save side writes the owned `Impl` payload as
     * a tracked pointer; the load adapter above is its mirror.
     */
    void PathQueueSerializerSerialize(
      gpg::WriteArchive* const archive,
      const int objectPtr,
      const int,
      gpg::RRef* const
    )
    {
      auto* const runtime = reinterpret_cast<PathQueueRuntimeView*>(static_cast<std::uintptr_t>(objectPtr));
      GPG_ASSERT(archive != nullptr);
      if (archive == nullptr || runtime == nullptr) {
        return;
      }

      gpg::RRef payloadRef{};
      payloadRef.mObj = runtime->mImpl;
      payloadRef.mType = ResolvePathQueueImplType();
      const gpg::RRef owner{};
      gpg::WriteRawPointer(archive, payloadRef, gpg::TrackedPointerState::Owned, owner);
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

    /**
     * Address: 0x00C01AB0 (FUN_00C01AB0, atexit-registered cleanup target)
     * ICF twins: 0x007669F0 (FUN_007669F0), 0x00766A20 (FUN_00766A20) --
     * identical unlink/self-link bodies hardcoded to the same global; only
     * 0x00C01AB0 is the one `register_PathQueueSerializer` (0x00BDC920)
     * actually registers via `atexit`.
     *
     * What it does:
     * Unlinks this helper node from the intrusive serializer-helper list and
     * restores a self-linked sentinel state.
     */
    void cleanup_PathQueueSerializer()
    {
      gPathQueueSerializerHelper.ResetLinks();
    }

    PathQueueSerializerHelper::PathQueueSerializerHelper()
      : mLoadCallback(&PathQueueSerializerDeserialize)
      , mSaveCallback(&PathQueueSerializerSerialize)
    {
      (void)std::atexit(&cleanup_PathQueueSerializer);
    }

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
     * Deletes one `PathQueue` owner lane and tears down the owned `Impl`
     * payload when present.
     */
    void DeletePathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime == nullptr) {
        return;
      }

      if (runtime->mImpl != nullptr) {
        auto* const impl = runtime->mImpl;
        DestroyPathQueueImpl(impl->mBase);
        UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
        ::operator delete(impl);
        runtime->mImpl = nullptr;
      }

      ::operator delete(runtime);
    }

    /**
     * Address: 0x00767990 (FUN_00767990, Moho::PathQueueTypeInfo::Destruct)
     *
     * What it does:
     * Destroys one in-place `PathQueue` owner lane and tears down the owned
     * `Impl` payload when present.
     */
    void DestructPathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime == nullptr || runtime->mImpl == nullptr) {
        return;
      }

      auto* const impl = runtime->mImpl;
      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
      runtime->mImpl = nullptr;
    }

    /**
     * Address: 0x007678C0 (FUN_007678C0, Moho::PathQueueTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one zeroed `PathQueue` owner lane and returns it as a typed
     * reflection reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueRefCallback()
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(::operator new(sizeof(PathQueueRuntimeView), std::nothrow));
      if (runtime != nullptr) {
        runtime->mImpl = nullptr;
      }
      return BuildPathQueueRefFromRuntime(runtime);
    }

    /**
     * Address: 0x00767950 (FUN_00767950, Moho::PathQueueTypeInfo::CtrRef)
     *
     * What it does:
     * Initializes one caller-provided `PathQueue` storage lane to null-impl
     * state and returns it as a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueRefCallback(void* const objectStorage)
    {
      auto* const runtime = static_cast<PathQueueRuntimeView*>(objectStorage);
      if (runtime != nullptr) {
        runtime->mImpl = nullptr;
      }
      return BuildPathQueueRefFromRuntime(runtime);
    }

    /**
     * Address: 0x00767A50 (FUN_00767A50, Moho::PathQueueImplTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `PathQueue::Impl` lane after running teardown.
     */
    void DeletePathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl == nullptr) {
        return;
      }

      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
    }

    /**
     * Address: 0x00767B00 (FUN_00767B00, Moho::PathQueueImplTypeInfo::Destruct)
     *
     * What it does:
     * Destroys one in-place `PathQueue::Impl` lane without releasing owner
     * storage.
     */
    void DestructPathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl == nullptr) {
        return;
      }

      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
    }

    /**
     * Address: 0x007679D0 (FUN_007679D0, Moho::PathQueueImplTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and constructs one `PathQueue::Impl` payload and returns it as
     * a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef NewPathQueueImplRefCallback()
    {
      auto* const impl = static_cast<PathQueue::Impl*>(::operator new(sizeof(PathQueue::Impl), std::nothrow));
      if (impl != nullptr) {
        ::new (impl) PathQueue::Impl();
      }
      return BuildPathQueueImplRef(impl);
    }

    /**
     * Address: 0x00767A90 (FUN_00767A90, Moho::PathQueueImplTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `PathQueue::Impl` payload in caller-provided storage and
     * returns it as a typed reflection reference.
     */
    [[nodiscard]] gpg::RRef ConstructPathQueueImplRefCallback(void* const objectStorage)
    {
      auto* const impl = static_cast<PathQueue::Impl*>(objectStorage);
      if (impl != nullptr) {
        ::new (impl) PathQueue::Impl();
      }
      return BuildPathQueueImplRef(impl);
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
     * Address: 0x00768AD0 (FUN_00768AD0, Moho::PathQueueImplSerializer::Serialize body)
     * Mangled: (reached via the cdecl->usercall thunk 0x00766BC0,
     *   Moho::PathQueueImplSerializer::Serialize)
     *
     * IDA signature:
     * void __usercall sub_768AD0(
     *     Moho::PathQueue::Impl *a1@<eax>, BinaryWriteArchive *a2@<ebx>);
     *
     * What it does:
     * Reflected save callback for `Moho::PathQueue::Impl`:
     *   1) reads the `PathTables*` lane at the impl header (+0x00) and writes
     *      it as an UNOWNED tracked raw pointer via `RRef_PathTables`;
     *   2) writes the height sentinel (`mHeightSentinel`, +0x04) as a
     *      `gpg::DList<Moho::IPathTraveler,void>` value;
     *   3) writes the base traveler list head (`mBase.mTraveler`, +0x58) as a
     *      `gpg::DList<Moho::IPathTraveler,void>` value.
     *
     * The `DList<IPathTraveler,void>` reflected type is resolved once through a
     * cached `sType` singleton (lazy `LookupRType`), matching the binary's
     * idiom, and every write passes a fresh zeroed owner `RRef` temporary, just
     * as the binary rebuilds the temporary before each call. The thin cdecl
     * calling-convention thunk 0x00766BC0 that the reflection slot dispatches to
     * is subsumed by this body.
     */
    /**
     * Address: 0x00768A10 (FUN_00768A10, Moho::PathQueueImplSerializer::Deserialize body)
     * Mangled: (reached via the cdecl->usercall trampoline 0x00766BB0,
     *   Moho::PathQueueImplSerializer::Deserialize)
     *
     * IDA signature:
     * int *__usercall sub_768A10@<eax>(gpg::ReadArchive *this@<ecx>, int a2@<eax>);
     *
     * What it does:
     * Reflected load callback for `Moho::PathQueue::Impl`, the exact inverse of
     * `SavePathQueueImplRefCallback` (0x00768AD0):
     *   1) reads the tracked `PathTables*` owner lane into the impl header
     *      (+0x00) via `ReadArchive::ReadPointer_PathTables`;
     *   2) reads the height sentinel ring (`mHeightSentinel`, +0x04) as a
     *      `gpg::DList<Moho::IPathTraveler,void>` value;
     *   3) reads the base traveler ring head (`mBase.mTraveler`, +0x58) as a
     *      `gpg::DList<Moho::IPathTraveler,void>` value;
     *   4) splices every deserialized traveler node out of `mBase.mTraveler`
     *      and into the height-sentinel ring immediately after the sentinel's
     *      predecessor (`mHeightSentinel.mPrev`), leaving `mBase.mTraveler`
     *      empty. This re-homes the freshly read travelers onto the live queue
     *      ring the runtime iterates.
     *
     * The `DList<IPathTraveler,void>` reflected type is resolved once through a
     * cached `sType` singleton (lazy `LookupRType`), matching both the binary's
     * idiom and the save side, and every read passes a fresh zeroed owner `RRef`
     * temporary, just as the binary rebuilds the temporary before each call. The
     * thin cdecl calling-convention trampoline 0x00766BB0 (`return
     * sub_768A10(a1)`) that the reflection slot dispatches to is subsumed by this
     * body; the binary's discarded `eax` return lane (the spliced ring's first
     * node) is not propagated because `load_func_t` returns void.
     */
    void DeserializePathQueueImplRefCallback(gpg::ReadArchive* const archive, PathQueue::Impl* const impl)
    {
      // (1) Owner PathTables* lane at the impl header (+0x00).
      gpg::RRef ownerRef{};
      ownerRef.mObj = nullptr;
      ownerRef.mType = nullptr;
      archive->ReadPointer_PathTables(&impl->mOwner, &ownerRef);

      static gpg::RType* dlistType = nullptr;
      if (dlistType == nullptr) {
        dlistType = gpg::LookupRType(typeid(gpg::DList<moho::IPathTraveler, void>));
      }

      // (2) Height sentinel ring (+0x04).
      gpg::RRef heightRef{};
      archive->Read(dlistType, &impl->mHeightSentinel, heightRef);

      if (dlistType == nullptr) {
        dlistType = gpg::LookupRType(typeid(gpg::DList<moho::IPathTraveler, void>));
      }

      // (3) Base traveler ring head (+0x58).
      gpg::RRef travelerRef{};
      archive->Read(dlistType, &impl->mBase.mTraveler, travelerRef);

      // (4) Splice the deserialized travelers into the height-sentinel ring
      // right after the sentinel's predecessor, then empty the source ring.
      (void)SplicePathQueueNodesAfter(impl->mBase.mTraveler, impl->mHeightSentinel.mPrev);
    }

    void SavePathQueueImplRefCallback(PathQueue::Impl* const impl, gpg::WriteArchive& archive)
    {
      PathTables* const pathTables = impl->mOwner;

      gpg::RRef pathTablesRef{};
      (void)gpg::RRef_PathTables(&pathTablesRef, pathTables);
      gpg::RRef ownerRef{};
      gpg::WriteRawPointer(&archive, pathTablesRef, gpg::TrackedPointerState::Unowned, ownerRef);

      static gpg::RType* dlistType = nullptr;
      if (dlistType == nullptr) {
        dlistType = gpg::LookupRType(typeid(gpg::DList<moho::IPathTraveler, void>));
      }

      gpg::RRef heightRef{};
      archive.Write(dlistType, &impl->mHeightSentinel, heightRef);

      if (dlistType == nullptr) {
        dlistType = gpg::LookupRType(typeid(gpg::DList<moho::IPathTraveler, void>));
      }

      gpg::RRef travelerRef{};
      archive.Write(dlistType, &impl->mBase.mTraveler, travelerRef);
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
     * raw `SerSaveLoadHelperInitRuntimeView` POD (never a real
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

    /**
     * Address: 0x00C01B40 (FUN_00C01B40, atexit-registered cleanup target)
     * ICF twins: 0x00766C00 (FUN_00766C00), 0x00766C30 (FUN_00766C30) --
     * identical unlink/self-link bodies hardcoded to the same global; only
     * 0x00C01B40 is the one `register_PathQueueImplSerializer` (0x00BDC980)
     * actually registers via `atexit`.
     *
     * What it does:
     * Unlinks this helper node from the intrusive serializer-helper list and
     * restores a self-linked sentinel state.
     */
    void cleanup_PathQueueImplSerializer()
    {
      gPathQueueImplSerializerHelper.ResetLinks();
    }

    PathQueueImplSerializerHelper::PathQueueImplSerializerHelper()
      : mLoadCallback(reinterpret_cast<gpg::RType::load_func_t>(&DeserializePathQueueImplRefCallback))
      , mSaveCallback(reinterpret_cast<gpg::RType::save_func_t>(&SavePathQueueImplRefCallback))
    {
      (void)std::atexit(&cleanup_PathQueueImplSerializer);
    }

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

  struct PathTablesImpl
  {
    /**
     * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes source/map vector lanes to null range state and constructs
     * the cluster-cache smart pointer lane.
     */
    PathTablesImpl();

    std::int32_t mWidth;                                      // +0x00
    std::int32_t mHeight;                                     // +0x04
    std::int32_t mUnknown08;                                  // +0x08
    LegacyVectorStorage<OccupySourceBinding> mSources;        // +0x0C
    std::int32_t mUnknown18;                                  // +0x18
    LegacyVectorStorage<moho::ClusterMap*> mMaps;             // +0x1C
    gpg::HaStar::ClusterCache mClusterCache;                  // +0x28
  };

  static_assert(sizeof(PathTablesImpl) == 0x30, "PathTablesImpl size must be 0x30");
  static_assert(offsetof(PathTablesImpl, mSources) == 0x0C, "PathTablesImpl::mSources offset must be 0x0C");
  static_assert(offsetof(PathTablesImpl, mMaps) == 0x1C, "PathTablesImpl::mMaps offset must be 0x1C");
  static_assert(offsetof(PathTablesImpl, mClusterCache) == 0x28, "PathTablesImpl::mClusterCache offset must be 0x28");
} // namespace moho

// Defined at file scope (global namespace, external linkage) in
// CrtRuntimeHelpers.cpp - shared by every legacy VC8 "<container> too long"
// throw lane. Forward-declared here (not inside the anonymous namespace
// below) so this TU's unqualified calls bind to that same external symbol
// instead of silently declaring a second, anonymous-namespace-local,
// never-defined one of the same name.
[[noreturn]] void RuntimeThrowContainerTooLong(const char* message);

namespace
{
  bool gGenPathWarmupPending = true;

  struct BindingPayloadLane3Runtime
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
  };
  static_assert(sizeof(BindingPayloadLane3Runtime) == 0x0C, "BindingPayloadLane3Runtime size must be 0x0C");

  [[nodiscard]] bool IsGenPathEnabled()
  {
#ifdef _WIN32
    const char* const commandLine = ::GetCommandLineA();
    return commandLine && std::strstr(commandLine, "/genpath");
#else
    return false;
#endif
  }

  /**
   * Address: 0x0076C430 (FUN_0076C430)
   *
   * What it does:
   * Copies one trailing `OccupySourceBinding` payload range (`{mGrid,mFootprint}`)
   * into destination slots, commits owner `mEnd`, and returns destination begin.
   */
  [[maybe_unused]] void CopyOccupySourceBindingTailRangeAndCommitRuntime(
    LegacyVectorStorage<moho::OccupySourceBinding>* const owner,
    moho::OccupySourceBinding** const outDestinationBegin,
    moho::OccupySourceBinding* destinationBegin,
    const moho::OccupySourceBinding* sourceBegin
  ) noexcept
  {
    moho::OccupySourceBinding* const destinationStart = destinationBegin;
    if (owner != nullptr && destinationBegin != sourceBegin) {
      const moho::OccupySourceBinding* const sourceEnd = owner->mEnd;
      while (sourceBegin != sourceEnd) {
        destinationBegin->mGrid = sourceBegin->mGrid;
        destinationBegin->mFootprint = sourceBegin->mFootprint;
        ++destinationBegin;
        ++sourceBegin;
      }
      owner->mEnd = destinationBegin;
    }

    if (outDestinationBegin != nullptr) {
      *outDestinationBegin = destinationStart;
    }
  }

  /**
   * Address: 0x0076CD30 (FUN_0076CD30)
   *
   * What it does:
   * Writes one repeated `OccupySourceBinding` payload pair
   * (`{mGrid,mFootprint}`) into `[destinationBegin,destinationEnd)`.
   */
  [[maybe_unused]] std::uint32_t* FillOccupySourceBindingPayloadRangeRuntime(
    std::uint32_t* destinationBegin,
    const std::uint32_t* const destinationEnd,
    const moho::OccupySourceBinding* const sourceBinding
  ) noexcept
  {
    if (destinationBegin == nullptr || destinationEnd == nullptr || sourceBinding == nullptr) {
      return destinationBegin;
    }
    if (destinationBegin == destinationEnd) {
      return destinationBegin;
    }

    auto* write = reinterpret_cast<BindingPayloadLane3Runtime*>(destinationBegin);
    auto* const end = reinterpret_cast<const BindingPayloadLane3Runtime*>(destinationEnd);
    while (write != end) {
      write->lane1 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceBinding->mGrid));
      write->lane2 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceBinding->mFootprint));
      ++write;
    }
    return reinterpret_cast<std::uint32_t*>(const_cast<BindingPayloadLane3Runtime*>(end)) + 2;
  }

  /**
   * Address: 0x0076CD60 (FUN_0076CD60)
   *
   * What it does:
   * Copies `OccupySourceBinding` payload pairs (`{mGrid,mFootprint}`) backward
   * from source range into destination tail slots.
   */
  std::uint32_t* CopyOccupySourceBindingPayloadRangeBackwardRuntime(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    auto* destination = reinterpret_cast<BindingPayloadLane3Runtime*>(destinationEnd);
    auto* source = reinterpret_cast<const BindingPayloadLane3Runtime*>(sourceEnd);
    auto* const begin = reinterpret_cast<const BindingPayloadLane3Runtime*>(sourceBegin);

    while (begin != source) {
      --destination;
      --source;
      destination->lane1 = source->lane1;
      destination->lane2 = source->lane2;
    }

    return reinterpret_cast<std::uint32_t*>(destination);
  }

  struct OccupationDataRuntimeView
  {
    std::uint16_t mLayers[9];
    std::uint16_t mPad;
  };
  static_assert(
    sizeof(OccupationDataRuntimeView) == sizeof(gpg::HaStar::OccupationData),
    "OccupationDataRuntimeView size must match OccupationData"
  );

  /**
   * Address: 0x0076CBA0 (FUN_0076CBA0)
   *
   * What it does:
   * Fills `count` contiguous `OccupySourceBinding` lanes from one prototype
   * binding and returns one-past the final destination lane.
   */
  moho::OccupySourceBinding* FillOccupySourceBindingRangeFromPrototype(
    moho::OccupySourceBinding* destinationBegin,
    const std::uint32_t count,
    const moho::OccupySourceBinding* const prototype
  ) noexcept
  {
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(destinationBegin);
    for (std::uint32_t index = 0u; index < count; ++index) {
      if (cursor != 0u && prototype != nullptr) {
        auto* const output = reinterpret_cast<moho::OccupySourceBinding*>(cursor);
        *output = *prototype;
      }
      cursor += sizeof(moho::OccupySourceBinding);
    }
    return reinterpret_cast<moho::OccupySourceBinding*>(cursor);
  }

  /**
   * Address: 0x0076C490 (FUN_0076C490)
   *
   * IDA signature:
   * void callcnv_73 sub_76C490(unsigned int insertCount@<ecx>,
   *   LegacyVectorStorage_OccupySourceBinding *storage@<edx>,
   *   OccupySourceBinding *insertPosition, const OccupySourceBinding *fillValue);
   *
   * What it does:
   * Out-of-line `msvc8::vector<OccupySourceBinding>::_Insert_n(position, count, value)`
   * grow path (each binding is 12 bytes). No-ops when `insertCount` is zero, throws
   * `std::length_error("vector<T> too long")` (FUN_0076C730) when the requested size
   * would exceed `max_size()`. When existing capacity already covers the new size, the
   * `[insertPosition, mLast)` tail is shifted right in place and the vacated range is
   * filled with `insertCount` copies of `*fillValue`. Otherwise the storage is
   * reallocated at 1.5x growth (or exactly `newSize` when that growth would overflow
   * or undershoot): the `[mFirst, insertPosition)` prefix and `[insertPosition, mLast)`
   * suffix are copy-constructed into the new buffer around a freshly filled gap, the
   * old buffer is freed, and the storage pointers are committed.
   */
  void InsertOccupySourceBindingRange(
    LegacyVectorStorage<moho::OccupySourceBinding>& storage,
    moho::OccupySourceBinding* const insertPosition,
    const std::size_t insertCount,
    const moho::OccupySourceBinding& fillValue
  )
  {
    if (insertCount == 0u) {
      return;
    }

    constexpr std::size_t kMaxElements = 0x15555555u; // max_size() for a 12-byte element
    const std::size_t curSize = storage.mFirst != nullptr
      ? static_cast<std::size_t>(storage.mLast - storage.mFirst)
      : 0u;
    if (kMaxElements - curSize < insertCount) {
      RuntimeThrowContainerTooLong("vector<T> too long");
    }

    const std::size_t capacity = storage.mFirst != nullptr
      ? static_cast<std::size_t>(storage.mEnd - storage.mFirst)
      : 0u;
    const std::size_t newSize = curSize + insertCount;

    if (capacity >= newSize) {
      // In-place: shift the existing [insertPosition, mLast) tail right by insertCount
      // slots, then fill the vacated range at insertPosition with fillValue.
      moho::OccupySourceBinding* const oldLast = storage.mLast;
      CopyOccupySourceBindingPayloadRangeBackwardRuntime(
        reinterpret_cast<std::uint32_t*>(oldLast + insertCount),
        reinterpret_cast<std::uint32_t*>(oldLast),
        reinterpret_cast<std::uint32_t*>(insertPosition)
      );
      FillOccupySourceBindingRangeFromPrototype(insertPosition, static_cast<std::uint32_t>(insertCount), &fillValue);
      storage.mLast = oldLast + insertCount;
      return;
    }

    // Reallocate: 1.5x growth, or exactly newSize when growth would overflow/undershoot.
    std::size_t newCapacity = capacity + capacity / 2u;
    if (newCapacity < newSize) {
      newCapacity = newSize;
    }

    auto* const newFirst = static_cast<moho::OccupySourceBinding*>(
      newCapacity != 0u
        ? gpg::core::legacy::AllocateChecked12ByteLane(static_cast<std::uint32_t>(newCapacity))
        : ::operator new(0)
    );

    moho::OccupySourceBinding* dest = newFirst;
    for (const moho::OccupySourceBinding* src = storage.mFirst; src != insertPosition; ++src, ++dest) {
      ::new (static_cast<void*>(dest)) moho::OccupySourceBinding(*src);
    }
    for (std::size_t i = 0; i < insertCount; ++i, ++dest) {
      ::new (static_cast<void*>(dest)) moho::OccupySourceBinding(fillValue);
    }
    for (const moho::OccupySourceBinding* src = insertPosition; src != storage.mLast; ++src, ++dest) {
      ::new (static_cast<void*>(dest)) moho::OccupySourceBinding(*src);
    }

    if (storage.mFirst != nullptr) {
      ::operator delete(storage.mFirst);
    }
    storage.mFirst = newFirst;
    storage.mLast = dest;
    storage.mEnd = newFirst + newCapacity;
  }

  /**
   * Address: 0x0076C130 (FUN_0076C130)
   *
   * IDA signature:
   * void callcnv_E3 sub_76C130(unsigned int newSize@<ecx>,
   *   std::vector_IOccupationSource *vec@<edi>, OccupySourceBinding fillValue);
   *
   * What it does:
   * Out-of-line specialization of
   * `msvc8::vector<OccupySourceBinding>::resize(size_type, const OccupySourceBinding&)`.
   * When `newSize <= current size`, truncates `mLast` to `mFirst + newSize` (bindings
   * are trivially destructible, so no per-element teardown is needed). When
   * `newSize > current size`, forwards to the `_Insert_n` grow path
   * (`InsertOccupySourceBindingRange`, FUN_0076C490) appending `newSize - current size`
   * copies of the prefilled binding at the tail. Each binding is 12 bytes.
   */
  void ResizeOccupySourceBindingVectorWithFill(
    LegacyVectorStorage<moho::OccupySourceBinding>& storage,
    const std::size_t newSize,
    const moho::OccupySourceBinding& fillValue
  )
  {
    const std::size_t curSize = storage.mFirst != nullptr
      ? static_cast<std::size_t>(storage.mLast - storage.mFirst)
      : 0u;

    if (newSize <= curSize) {
      if (storage.mFirst != nullptr) {
        storage.mLast = storage.mFirst + newSize;
      }
      return;
    }

    InsertOccupySourceBindingRange(storage, storage.mLast, newSize - curSize, fillValue);
  }

  /**
   * Address: 0x0076BFA0 (FUN_0076BFA0, sub_76BFA0)
   *
   * What it does:
   * Builds one default `OccupySourceBinding` payload (`{nullptr,nullptr}`) and
   * forwards to the typed binding-vector resize helper (FUN_0076C130) so the
   * linker preserves the binary's per-type resize-with-fill symbol shape.
   */
  void ResizeOccupySourceStorageWithDefaultBinding(
    LegacyVectorStorage<moho::OccupySourceBinding>* const storage,
    const std::uint32_t count
  )
  {
    if (storage == nullptr) {
      return;
    }

    const moho::OccupySourceBinding defaultBinding{};
    ResizeOccupySourceBindingVectorWithFill(*storage, static_cast<std::size_t>(count), defaultBinding);
  }

  /**
   * Address: 0x0076C270 (FUN_0076C270, msvc8::vector<ClusterMap*>::resize)
   *
   * The binary's `PathTables::PathTables` ctor called the per-T
   * `msvc8::vector<ClusterMap*>::resize(n)` template emission
   * (FUN_0076C270, 4-byte pointer stride) to grow `mImpl->mMaps`
   * to the footprint count before populating each slot with a fresh
   * `ClusterMap*`. The recovered `ResizeLegacyPointerStorage`
   * provides the same role through a single ::operator new[] +
   * std::memset zero-init pass, so the per-T vector-resize emission
   * is absorbed by this named helper. The inner blocked helper
   * FUN_0076C850 (per-T uninitialized fill) corresponds to the
   * `std::memset(begin, 0, count*sizeof(T))` step below.
   */
  bool ResizeLegacyPointerStorage(LegacyVectorStorage<moho::ClusterMap*>& storage, const std::size_t count)
  {
    if (count == 0u) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return true;
    }

    auto* const begin = static_cast<moho::ClusterMap**>(::operator new(sizeof(moho::ClusterMap*) * count, std::nothrow));
    if (begin == nullptr) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return false;
    }

    std::memset(begin, 0, sizeof(moho::ClusterMap*) * count);
    storage.mFirst = begin;
    storage.mLast = begin + count;
    storage.mEnd = begin + count;
    return true;
  }

  template <typename T>
  void ResetLegacyVectorStorage(LegacyVectorStorage<T>& storage)
  {
    if (storage.mFirst) {
      operator delete(storage.mFirst);
    }

    storage.mFirst = nullptr;
    storage.mLast = nullptr;
    storage.mEnd = nullptr;
  }

  template <typename Fn>
  void ForEachClusterMap(moho::PathTablesImpl* impl, Fn&& fn)
  {
    if (!impl) {
      return;
    }

    for (moho::ClusterMap** it = impl->mMaps.mFirst; it != impl->mMaps.mLast; ++it) {
      moho::ClusterMap* const map = *it;
      if (!map) {
        continue;
      }

      fn(map);
    }
  }

  struct IntrusiveListNodeRuntime
  {
    IntrusiveListNodeRuntime* next; // +0x00
    IntrusiveListNodeRuntime* prev; // +0x04
  };
  static_assert(sizeof(IntrusiveListNodeRuntime) == 0x08, "IntrusiveListNodeRuntime size must be 0x08");

  struct IntrusiveListOwnerRuntime
  {
    std::uint32_t lane00;            // +0x00
    IntrusiveListNodeRuntime* head;  // +0x04
    std::int32_t count;              // +0x08
  };
  static_assert(sizeof(IntrusiveListOwnerRuntime) == 0x0C, "IntrusiveListOwnerRuntime size must be 0x0C");
  static_assert(offsetof(IntrusiveListOwnerRuntime, head) == 0x04, "IntrusiveListOwnerRuntime::head offset must be 0x04");
  static_assert(offsetof(IntrusiveListOwnerRuntime, count) == 0x08, "IntrusiveListOwnerRuntime::count offset must be 0x08");

  /**
   * Address: 0x0076A2B0 (FUN_0076A2B0)
   *
   * What it does:
   * Unlinks one intrusive node from its owner lane, deletes that node, and
   * stores the next-node lane into `outNext`.
   */
  [[maybe_unused]] IntrusiveListNodeRuntime** UnlinkAndDeleteIntrusiveNode(
    IntrusiveListNodeRuntime** const outNext,
    IntrusiveListOwnerRuntime& owner,
    IntrusiveListNodeRuntime* const node
  ) noexcept
  {
    IntrusiveListNodeRuntime* next = node != nullptr ? node->next : nullptr;
    if (node != nullptr && node != owner.head) {
      IntrusiveListNodeRuntime* const prev = node->prev;
      if (prev != nullptr) {
        prev->next = next;
      }
      if (next != nullptr) {
        next->prev = prev;
      }
      ::operator delete(node);
      --owner.count;
    }

    if (outNext != nullptr) {
      *outNext = next;
      return outNext;
    }
    return nullptr;
  }

  /**
   * Address: 0x0076CF30 (FUN_0076CF30, ??1Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Destroys impl-owned cache handles and releases the source/map vector storage buffers.
   */
  void DestroyPathTablesImpl(moho::PathTablesImpl* impl)
  {
    if (!impl) {
      return;
    }

    impl->mClusterCache.~ClusterCache();
    ResetLegacyVectorStorage(impl->mMaps);
    ResetLegacyVectorStorage(impl->mSources);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00765B20 (FUN_00765B20, ??0Impl@PathQueue@Moho@@QAE@@Z_0)
   * Mangled: ??0Impl@PathQueue@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one `PathQueue::Impl` lane to empty state by zeroing queue
   * size, self-linking the height sentinel, and constructing the ImplBase
   * runtime owner lanes.
   */
  PathQueue::Impl::Impl()
    : mOwner(nullptr)
  {
    mHeightSentinel.mNext = &mHeightSentinel;
    mHeightSentinel.mPrev = &mHeightSentinel;
    InitializePathQueueImplBase(mBase);
  }

  /**
   * Address: 0x00765D30 (FUN_00765D30, ??0PathQueue@Moho@@QA@Z)
   *
   * What it does:
   * Allocates one `PathQueue::Impl`, runs the impl initialization chain, and
   * records the requested queue-size lane.
   */
  PathQueue::PathQueue(PathTables* const owner)
    : mImpl(nullptr)
  {
    // Allocation size and constructor chain from:
    // - 0x00765D30 (PathQueue::PathQueue)
    // - 0x00765B20 (PathQueue::Impl::Impl)
    // - 0x00765B90 (PathQueue::ImplBase::ImplBase)
    // - 0x00766CE0 (sub_766CE0)
    auto* const impl = static_cast<PathQueue::Impl*>(::operator new(sizeof(PathQueue::Impl), std::nothrow));
    if (impl == nullptr) {
      return;
    }

    ::new (impl) PathQueue::Impl();
    impl->mOwner = owner;
    mImpl = impl;
  }

  /**
   * Address: 0x007685A0 (FUN_007685A0, Moho::PathQueue::WorkOnce)
   *
   * IDA signature:
   * int __stdcall sub_7685A0(Moho::PathQueue::ImplBase *a3, Moho::PathQueue::ImplBase *a2);
   *
   * What it does:
   * Runs the A* main loop for the traveler currently being served, until the
   * search finishes or one of the budgets runs out.
   *
   * Each pass takes the cheapest open node, asks `StepExpansion` for its
   * neighbours, closes it, and relaxes each candidate. The two arguments are
   * the same object twice - the search state and the traits - which is why the
   * binary pushes `edi` twice at the call site.
   *
   * Returns `Continue` only when the open set is exhausted without reaching the
   * goal, i.e. no path exists within the searched region.
   */
  [[nodiscard]] PathQueueStep PathQueueWorkOnce(PathQueueImplBaseRuntime& implBase)
  {
    PathQueueNeighbourBuffer neighbours;

    while (!implBase.OpenSet().empty()) {
      gpg::AStarNode<SOCellPos>* const current = implBase.OpenSet().top();

      neighbours.clear();
      const PathQueueStep step = StepExpansion(implBase, current->mCell, neighbours);
      if (step != PathQueueStep::Continue) {
        return step;
      }

      current->mState = gpg::AStarNodeState::Closed;
      (void)implBase.OpenSet().Pop();

      moho::IPathTraveler* const traveler = implBase.CurrentTraveler();

      for (const PathQueueNeighbour& neighbour : neighbours) {
        gpg::AStarNode<SOCellPos>& node = implBase.FindOrCreateNode(neighbour.mCell);
        const float reachedCost = current->mCost + neighbour.mCost;

        switch (node.mState) {
          case gpg::AStarNodeState::Unvisited: {
            node.mState = gpg::AStarNodeState::Open;

            const float estimate =
              (traveler != nullptr) ? traveler->GetHeuristicCost(neighbour.mCell) : 0.0f;
            implBase.NoteCandidateCell(neighbour.mCell, estimate);

            node.mEstimate = estimate;
            node.mParent = current;
            node.mCell = neighbour.mCell;
            node.mCost = reachedCost;
            node.mHandle = implBase.OpenSet().Push(reachedCost + estimate, &node);
            break;
          }

          case gpg::AStarNodeState::Open: {
            // Only re-parent when this route is genuinely cheaper; the estimate
            // is unchanged, so the new priority is a pure decrease-key.
            if (node.mCost > reachedCost) {
              node.mParent = current;
              node.mCell = neighbour.mCell;
              node.mCost = reachedCost;
              implBase.OpenSet().UpdatePriority(node.mHandle, node.mEstimate + reachedCost);
            }
            break;
          }

          case gpg::AStarNodeState::Closed:
          default:
            // "neib->mState == CLOSED", AStarSearch.h:253
            assert(node.mState == gpg::AStarNodeState::Closed);
            break;
        }
      }
    }

    return PathQueueStep::Continue;
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
  void BeginPathQueueQuery(
    PathQueueImplBaseRuntime& implBase,
    IPathTraveler& traveler,
    PathTables& owner
  )
  {
    // "mTraveler.empty()", PathQueue.cpp:148
    assert(implBase.mTraveler.mNext == &implBase.mTraveler);

    const SFootprint* const footprint = traveler.GetFootprint();

    implBase.mExpandCount = 0;
    implBase.mPathCap = traveler.GetPathcap();

    HPathCell anchorCell{};
    traveler.GetAnchorCell(&anchorCell);
    implBase.mClosestCell = *reinterpret_cast<const SOCellPos*>(&anchorCell);
    implBase.mClosestDistance = std::numeric_limits<float>::max();

    // The traveller hands back its named footprint; the binary reads the index
    // at +0x2C, which only exists on SNamedFootprint. The declared return type
    // is the base, so the concrete type has to be recovered here.
    const auto* const namedFootprint = static_cast<const SNamedFootprint*>(footprint);
    implBase.mClusterMap = owner.ClusterMapForFootprint(namedFootprint->mIndex);

    implBase.ResetSearch();
    implBase.mResultCells.clear();

    // Move the traveler from the pending ring to the active slot.
    UnlinkAndResetPathQueueNode(traveler.mPathQueueNode);
    PathQueueIntrusiveNode& node = traveler.mPathQueueNode;
    node.mPrev = implBase.mTraveler.mPrev;
    node.mNext = &implBase.mTraveler;
    implBase.mTraveler.mPrev = &node;
    node.mPrev->mNext = &node;

    implBase.AddStartNode(implBase.mClosestCell, implBase);
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
  void FinishPathQueueQuery(PathQueueImplBaseRuntime& implBase, const bool reachedGoal)
  {
    IPathTraveler* const traveler = implBase.CurrentTraveler();

    implBase.mResultCells.clear();
    (void)implBase.BuildPath(implBase.mClosestCell, implBase.mResultCells);

    UnlinkAndResetPathQueueNode(implBase.mTraveler);

    if (traveler == nullptr) {
      return;
    }

    const SNavPath& path = *reinterpret_cast<const SNavPath*>(&implBase.mResultCells);
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
    return mImpl->mMaps.mFirst[footprintIndex];
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

      const bool queryInFlight = impl.mBase.mTraveler.mNext != &impl.mBase.mTraveler;
      if (!queryInFlight) {
        if (impl.mHeightSentinel.mNext == &impl.mHeightSentinel) {
          // Nothing queued; the remaining budget goes unspent.
          return;
        }

        auto* const pendingNode = impl.mHeightSentinel.mNext;
        auto* const pending = reinterpret_cast<IPathTraveler*>(
          reinterpret_cast<std::uint8_t*>(pendingNode) - offsetof(IPathTraveler, mPathQueueNode)
        );
        BeginPathQueueQuery(impl.mBase, *pending, *impl.mOwner);
      }

      // "!mTraveler.empty()", PathQueue.cpp:169
      assert(impl.mBase.mTraveler.mNext != &impl.mBase.mTraveler);

      impl.mBase.mBudget = budget;
      const PathQueueStep step = PathQueueWorkOnce(impl.mBase);
      budget = impl.mBase.mBudget;

      if (step == PathQueueStep::BudgetExhausted) {
        // "cpuBudget <= 0", PathQueue.cpp:179
        assert(budget <= 0);
      } else {
        FinishPathQueueQuery(impl.mBase, step == PathQueueStep::GoalReached);
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
    PathQueueImplBaseRuntime scratch;
    InitializePathQueueImplBase(scratch);

    BeginPathQueueQuery(scratch, traveller, *mImpl->mOwner);

    // "!mTraveler.empty()", PathQueue.cpp:169
    assert(scratch.mTraveler.mNext != &scratch.mTraveler);

    scratch.mBudget = budget;
    const PathQueueStep step = PathQueueWorkOnce(scratch);
    budget = scratch.mBudget;

    FinishPathQueueQuery(scratch, step == PathQueueStep::GoalReached);

    scratch.mResultCells.clear();
    UnlinkAndResetPathQueueNode(scratch.mTraveler);
    DestroyPathQueueImplBase(scratch);
  }

  /**
   * Address: 0x00701AD0 (FUN_00701AD0, Moho::PathQueue::Move)
   *
   * What it does:
   * Replaces one owner slot with a new queue pointer, then tears down and
   * frees the previous queue payload when present.
   */
  void PathQueue::Move(PathQueue** const slot, PathQueue* const replacement) noexcept
  {
    PathQueue* const previous = *slot;
    *slot = replacement;

    if (previous == nullptr) {
      return;
    }

    Impl* const impl = previous->mImpl;
    if (impl != nullptr) {
      DestroyPathQueueImpl(impl->mBase);
      UnlinkAndResetPathQueueNode(impl->mHeightSentinel);
      ::operator delete(impl);
    }

    ::operator delete(previous);
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

    auto& outView = reinterpret_cast<OccupationDataRuntimeView&>(outData);
    for (std::size_t i = 0; i < kOccupationResultColumnCount; ++i) {
      outView.mLayers[i] = static_cast<std::uint16_t>(rowMasks[i]);
    }
    outView.mPad = 0u;
  }

  /**
   * Address: 0x0076BA40 (FUN_0076BA40, ??0Impl@PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Resets impl vector lanes (`mSources`, `mMaps`) to empty null ranges,
   * then constructs the cluster-cache smart pointer lane (`mClusterCache`)
   * via `gpg::HaStar::InitializeClusterCache()` -- `FUN_00935580`
   * (allocates and default-constructs one `ClusterCacheImpl`) followed by
   * `FUN_009356E0`
   * (`boost::shared_ptr_HaStar_ClusterCache_Impl::shared_ptr_HaStar_ClusterCache_Impl`,
   * the shared-count control block wrap), which this function calls
   * directly (confirmed via `FUN_0076BA40`'s own callee list: it calls
   * `FUN_009356E0` and nothing else cluster-related).
   */
  PathTablesImpl::PathTablesImpl()
  {
    mSources.mFirst = nullptr;
    mSources.mLast = nullptr;
    mSources.mEnd = nullptr;

    mMaps.mFirst = nullptr;
    mMaps.mLast = nullptr;
    mMaps.mEnd = nullptr;

    gpg::HaStar::InitializeClusterCache(mClusterCache);
  }

  /**
   * Address: 0x0076B8C0 (FUN_0076B8C0, ??0PathTables@Moho@@QAE@@Z)
   *
   * What it does:
   * Builds per-footprint occupation-source bindings and cluster-map lanes for
   * one `(width,height)` grid.
   */
  PathTables::PathTables(
    const SRuleFootprintsBlueprint& footprints,
    COGrid* const grid,
    const int width,
    const int height
  )
    : mImpl(static_cast<PathTablesImpl*>(::operator new(sizeof(PathTablesImpl), std::nothrow)))
  {
    if (mImpl == nullptr) {
      return;
    }

    ::new (mImpl) PathTablesImpl();
    mImpl->mWidth = width;
    mImpl->mHeight = height;

    const std::size_t footprintCount = static_cast<std::size_t>(footprints.mSize);
    const OccupySourceBinding defaultSource{};
    ResizeOccupySourceBindingVectorWithFill(mImpl->mSources, footprintCount, defaultSource);
    if (!ResizeLegacyPointerStorage(mImpl->mMaps, footprintCount)) {
      return;
    }
    if (mImpl->mSources.mFirst == nullptr && footprintCount != 0u) {
      return;
    }

    const SRuleFootprintNode* const head = footprints.mHead;
    if (head == nullptr) {
      return;
    }

    const SRuleFootprintNode* node = head->next;
    std::size_t sourceIndex = 0u;
    std::size_t footprintIndex = 0u;
    while (node != nullptr && node != head && sourceIndex < footprintCount) {
      SNamedFootprint* const footprint = const_cast<SNamedFootprint*>(&node->value);
      if (footprintIndex != static_cast<std::size_t>(footprint->mIndex)) {
        gpg::HandleAssertFailure("i == fp.mIndex", 113, "c:\\work\\rts\\main\\code\\src\\sim\\PathTables.cpp");
      }

      OccupySourceBinding& source = mImpl->mSources.mFirst[sourceIndex];
      source.mGrid = grid;
      source.mFootprint = footprint;

      ClusterMap* clusterMap = nullptr;
      if (auto* const clusterStorage = static_cast<ClusterMap*>(::operator new(sizeof(ClusterMap), std::nothrow));
          clusterStorage != nullptr) {
        gpg::Rect2i area{};
        area.x0 = -1;
        area.z0 = -1;
        area.x1 = static_cast<int>(footprint->mSizeX) + 1;
        area.z1 = static_cast<int>(footprint->mSizeZ) + 1;
        clusterMap = ::new (clusterStorage) ClusterMap(
          &source,
          static_cast<unsigned int>(width),
          static_cast<unsigned int>(height),
          mImpl->mClusterCache,
          2u,
          area
        );
      }

      mImpl->mMaps.mFirst[footprintIndex] = clusterMap;
      node = node->next;
      ++sourceIndex;
      ++footprintIndex;
    }
  }

  /**
   * Address: 0x0076BAC0 (FUN_0076BAC0, ??1PathTables@Moho@@QAE@@Z)
   */
  PathTables::~PathTables()
  {
    if (mImpl == nullptr) {
      return;
    }

    for (ClusterMap** it = mImpl->mMaps.mFirst; it != mImpl->mMaps.mLast; ++it) {
      ClusterMap* const map = *it;
      if (!map) {
        continue;
      }

      map->~ClusterMap();
      operator delete(map);
    }

    PathTablesImpl* const impl = mImpl;
    if (impl) {
      DestroyPathTablesImpl(impl);
      operator delete(impl);
    }
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
      ForEachClusterMap(mImpl, [&](moho::ClusterMap* cluster) {
        *budget = INT_MAX;
        cluster->BackgroundWork(*budget);
      });
      gGenPathWarmupPending = false;
    }

    ForEachClusterMap(mImpl, [&](moho::ClusterMap* cluster) {
      cluster->BackgroundWork(*budget);
    });
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
  /// `mFirst`/`mLast` pair) mean the pointer array itself was overwritten.
  void ReportCorruptClusterMapLane(
    const PathTablesImpl* const impl,
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
      static_cast<int>(slot - impl->mMaps.mFirst),
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
      static_cast<const void*>(impl->mMaps.mFirst),
      static_cast<const void*>(impl->mMaps.mLast),
      static_cast<const void*>(impl->mMaps.mEnd),
      static_cast<int>(impl->mMaps.mLast - impl->mMaps.mFirst)
    );
    ::OutputDebugStringA(line);

    for (ClusterMap** it = impl->mMaps.mFirst; it != impl->mMaps.mLast; ++it) {
      (void)std::snprintf(
        line, sizeof(line), "[CLUSTERLANE]   [%d] = %p\n",
        static_cast<int>(it - impl->mMaps.mFirst), static_cast<const void*>(*it)
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

    for (ClusterMap** it = mImpl->mMaps.mFirst; it != mImpl->mMaps.mLast; ++it) {
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
      if (!ClusterMapPointerLooksLive(cluster)) {
        ReportCorruptClusterMapLane(mImpl, it, cluster);
        continue;
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

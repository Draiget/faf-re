#include "Cluster.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "platform/Interlocked.h"
#include "legacy/math/X87Math.h"

#include <algorithm>
#include <bit>
#include <array>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <new>
#include <utility>
#include <vector>

#include <intrin.h>

#include "gpg/core/algorithms/AStarSearch.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/FastVector.h"
#include "legacy/algorithms/Sort.h"
#include "gpg/core/utils/SharedPtrUtils.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/HashMap.h"
#include "legacy/containers/Vector.h"

namespace
{
  constexpr std::uint8_t kClusterSizeLog2ByLevel[] = {0u, 3u, 5u, 7u};
  constexpr std::size_t kClusterSizeLog2Count = sizeof(kClusterSizeLog2ByLevel) / sizeof(kClusterSizeLog2ByLevel[0]);
  constexpr std::uint8_t kClusterSizeByLevel[] = {1u, 8u, 32u, 128u};
  constexpr std::size_t kClusterSizeCount = sizeof(kClusterSizeByLevel) / sizeof(kClusterSizeByLevel[0]);

  constexpr std::uint32_t kOccupationKeySalt = 0x7BEF2693u;

  constexpr std::array<std::uint8_t, 4> kOccupationEdgeStartBit = {0u, 0u, 0u, 8u};
  constexpr std::array<std::uint8_t, 4> kOccupationEdgeStartLayer = {0u, 8u, 0u, 0u};
  constexpr std::array<std::uint8_t, 4> kOccupationEdgeBitStep = {1u, 1u, 0u, 0u};
  constexpr std::array<std::uint8_t, 4> kOccupationEdgeLayerStep = {0u, 0u, 1u, 1u};

  /**
   * One cell of the 9x9 octile search `BuildClusterEdgeCosts` runs from each
   * source node: a `gpg::DListItem` ring link (the search's FIFO open list)
   * followed by the cell's search state. 0x00954940 is the constructor the
   * binary runs over the grid with `eh vector constructor iterator`: links
   * self-linked, cost, flags and cell zeroed.
   */
  struct PathSearchFrontierNode : gpg::DListItem<PathSearchFrontierNode>
  {
    float pathCost = 0.0f;       // +0x08
    std::uint8_t visitFlags = 0; // +0x0C
    std::uint8_t packedCell = 0; // +0x0D
  };
  static_assert(sizeof(PathSearchFrontierNode) == 0x10, "PathSearchFrontierNode size must be 0x10");
  static_assert(
    offsetof(PathSearchFrontierNode, pathCost) == 0x08,
    "PathSearchFrontierNode::pathCost offset must be 0x08"
  );
  static_assert(
    offsetof(PathSearchFrontierNode, visitFlags) == 0x0C,
    "PathSearchFrontierNode::visitFlags offset must be 0x0C"
  );
  static_assert(
    offsetof(PathSearchFrontierNode, packedCell) == 0x0D,
    "PathSearchFrontierNode::packedCell offset must be 0x0D"
  );

  /**
   * The binary sorts and deduplicates both builds' boundary node sets through
   * one shared sort instantiation (0x0092F4E0, called from 0x0092FE30 and
   * 0x009550E0) on the packed `x | (z << 8)` word, compared as a signed 16-bit
   * value.
   */
  [[nodiscard]] std::int16_t PackedNodeKey(
    const gpg::HaStar::Cluster::Node& node
  ) noexcept
  {
    return static_cast<std::int16_t>(node.x | (static_cast<std::uint16_t>(node.z) << 8u));
  }

  void SortUniqueNodes(
    gpg::fastvector<gpg::HaStar::Cluster::Node>& nodes
  )
  {
    using Node = gpg::HaStar::Cluster::Node;
    fa::sort(nodes.begin(), nodes.end(), [](const Node& lhs, const Node& rhs) {
      return PackedNodeKey(lhs) < PackedNodeKey(rhs);
    });
    const auto uniqueEnd = std::unique(nodes.begin(), nodes.end(), [](const Node& lhs, const Node& rhs) {
      return PackedNodeKey(lhs) == PackedNodeKey(rhs);
    });
    nodes.erase(uniqueEnd, nodes.end());
  }

  /**
   * Address: 0x009550E0 (FUN_009550E0)
   *
   * What it does:
   * Finds the level-1 cluster's boundary nodes: walks the four edges of the
   * 9x9 occupation window, and for every run of passable cells along an edge
   * appends one node at the run's midpoint (snapped to the edge centre or a
   * corner when the run covers it), then sorts and deduplicates the set.
   * Each append is `fastvector<Node>::push_back`, whose grow arm is
   * `insert_range` 0x0092D9B0.
   */
  void BuildOccupationEdgeContacts(
    const gpg::HaStar::OccupationData& occupationData,
    gpg::fastvector<gpg::HaStar::Cluster::Node>& outNodes
  )
  {
    for (std::uint32_t edgeIndex = 0; edgeIndex < 4u; ++edgeIndex) {
      std::uint8_t currentBit = kOccupationEdgeStartBit[edgeIndex];
      std::uint8_t currentLayer = kOccupationEdgeStartLayer[edgeIndex];
      std::uint8_t runStart = 0xFFu;
      std::uint8_t runEnd = 0xFFu;

      for (std::uint8_t step = 0u; step <= 8u; ++step) {
        const bool occupied = (occupationData.mRows[currentLayer] & (1u << currentBit)) != 0u;
        if (occupied) {
          runEnd = step;
          if (runStart == 0xFFu) {
            runStart = step;
          }
        }

        if (runStart != 0xFFu && (step == 8u || step != runEnd)) {
          std::uint8_t midpoint = 0u;
          if (runStart <= 4u && runEnd >= 4u) {
            midpoint = 4u;
          } else if (runStart == 0u) {
            midpoint = 0u;
          } else if (runEnd == 8u) {
            midpoint = 8u;
          } else {
            midpoint = static_cast<std::uint8_t>(
              (static_cast<std::uint32_t>(runStart) + static_cast<std::uint32_t>(runEnd) + (runEnd < 4u ? 1u : 0u)) >>
              1u
            );
          }

          gpg::HaStar::Cluster::Node node{};
          if (kOccupationEdgeBitStep[edgeIndex] != 0u) {
            node.x = midpoint;
            node.z = currentLayer;
          } else {
            node.x = currentBit;
            node.z = midpoint;
          }
          outNodes.push_back(node);

          runStart = 0xFFu;
          runEnd = 0xFFu;
        }

        currentBit = static_cast<std::uint8_t>(currentBit + kOccupationEdgeBitStep[edgeIndex]);
        currentLayer = static_cast<std::uint8_t>(currentLayer + kOccupationEdgeLayerStep[edgeIndex]);
      }
    }

    SortUniqueNodes(outNodes);
  }
} // namespace

namespace gpg::HaStar
{
  /**
   * Address: 0x00931460 (FUN_00931460)
   *
   * What it does:
   * Orders two occupation windows by their 0x12 bytes (an inlined
   * `memcmp(lhs, rhs, sizeof(OccupationData)) < 0`). The occupation cache's
   * `hash_compare` uses it to keep each bucket window sorted.
   */
  [[nodiscard]] bool operator<(
    const OccupationData& lhs,
    const OccupationData& rhs
  )
  {
    return std::memcmp(&lhs, &rhs, sizeof(OccupationData)) < 0;
  }

  /**
   * Address: 0x00932080 (FUN_00932080) - the inlined key-hash half; the
   *   enclosing bucket fold is `fa::hash_map::_Buckno`
   *
   * What it does:
   * MSVC8's `stdext::hash_value` for an occupation window: `gpg::HashBytes`
   * over its 0x12 bytes with salt 0x7BEF2693 (`push 12h` / `push 7BEF2693h`
   * at 0x0093208A / 0x00932085), then the Park-Miller pseudorandomizing step
   * `stdext::hash_compare::operator()(const Key&)` applies to every key
   * (`fa::hash_value`). `fa::hash_compare` finds it by argument-dependent
   * lookup.
   *
   * 0x00932080 is the out-of-line `_Buckno` of
   * `fa::hash_map<OccupationData, Cluster::Data*>`, shared by `find`
   * (0x00932B70), `equal_range` (0x00933EF0) and `erase` (0x00933F80): `mov
   * ecx,[esi+20h]` is `mMask`, `cmp [esi+24h],eax` is `mMaxidx`. The fold
   * itself lives once in `legacy/containers/HashMap.h`.
   */
  [[nodiscard]] std::size_t hash_value(
    const OccupationData& key
  )
  {
    const std::uint32_t keyHash = gpg::HashBytes(&key, sizeof(OccupationData), kOccupationKeySalt);
    return fa::hash_value(static_cast<long>(static_cast<std::int32_t>(keyHash)));
  }

  /**
   * Address: 0x00931500 (FUN_00931500)
   *
   * What it does:
   * Hashes a subcluster for the subcluster cache: a Murmur-style mix of
   * `mLevel` seeded with 0x7BEF2693 (`xor eax, 7BEF2693h`), then of
   * `hash_value` of each of the 16 cluster handles, so structurally equal
   * subclusters hash equal whichever allocations back their clusters.
   *
   * The binary inlines MSVC8's `stdext::hash_compare` Park-Miller step right
   * after the call (0x00934C89 and 0x00934D84, inside `insert` 0x00934BE0);
   * `fa::hash_value` below is that step.
   */
  [[nodiscard]] std::size_t hash_value(
    const SubclusterData& key
  )
  {
    constexpr std::uint32_t kMul = 0x106D643Du;
    constexpr std::uint32_t kLevelXor = 0x7BEF2693u;

    std::uint32_t mixed = kMul * (static_cast<std::uint32_t>(key.mLevel) ^ kLevelXor);
    std::uint32_t hash = mixed ^ (mixed >> 13);
    for (const Cluster& cluster : key.mClusters) {
      mixed = kMul * (hash ^ hash_value(cluster));
      hash = mixed ^ (mixed >> 13);
    }
    return fa::hash_value(static_cast<long>(static_cast<std::int32_t>(hash)));
  }

  /**
   * Address: 0x00931560 (FUN_00931560)
   *
   * What it does:
   * Orders two subclusters by level first, then each of the 16 cluster
   * handles by payload (`Cluster::cmp`). The subcluster cache's
   * `hash_compare` keeps each bucket window sorted by it, which is what lets
   * `insert` (0x00934BE0) scan a window backwards and stop at the first key
   * that does not compare greater.
   */
  [[nodiscard]] bool operator<(
    const SubclusterData& lhs,
    const SubclusterData& rhs
  )
  {
    if (lhs.mLevel != rhs.mLevel) {
      return lhs.mLevel < rhs.mLevel;
    }
    for (int i = 0; i < 16; ++i) {
      const int order = lhs.mClusters[i].cmp(rhs.mClusters[i]);
      if (order != 0) {
        return order < 0;
      }
    }
    return false;
  }
} // namespace gpg::HaStar

namespace
{

  /**
   * The occupation half of `ClusterCache`, built from the same MSVC8
   * `stdext::hash_map` template as the subcluster half below. The whole
   * member family the binary emits for this key type reads the container
   * through the layout `fa::hash_map` already models:
   *
   *   `mov ecx,[edi+14h]` / `[ecx+eax*4]` / `[ecx+eax*4+4]`
   *                       -> `mVec._Myfirst[bucket]` and `[bucket + 1]`,
   *                          i.e. the window `[mVec[b], mVec[b + 1])`
   *                          (0x00932B81, 0x00933F00, 0x00933F92)
   *   `mov ebx,[ebx+8]`   -> `mList._Myhead`, the `end()` sentinel the miss
   *                          paths return (0x00933F28, 0x0093528D)
   *   `add [edi+0Ch],-1`  -> `mList._Mysize` (0x00933FD5)
   *   `[esi+20h]`/`[esi+24h]`
   *                       -> `mMask` / `mMaxidx` (0x009320B8, 0x009320BF)
   *
   * and each list node is `{_Next, _Prev, pair<const key, Data*>}` - every
   * key access in those bodies is `node + 8` (0x00933F11, 0x00933F87), and
   * `ClusterInternalCache<OccupationData>::Fetch` publishes `node + 8` as the
   * eviction key at 0x0093506A.
   */
  using OccupationCacheMap = fa::hash_map<gpg::HaStar::OccupationData, gpg::HaStar::Cluster::Data*>;

  /**
   * The subcluster half of `ClusterCache` as the binary actually builds it:
   * MSVC8's `stdext::hash_map`, already recovered once as `fa::hash_map`
   * (`legacy/containers/HashMap.h`) for the pathfinder node table. The
   * cluster-cache emission is a second instantiation of that same template -
   * every `this` displacement in 0x00934BE0 lines up slot for slot:
   *
   *   `lea ecx,[esi+4]`  -> `mList`      (list, +0x04 proxy / +0x08 head / +0x0C size)
   *   `mov edi,[esi+14h]`-> `mVec._Myfirst`, `[esi+18h]` -> `mVec._Mylast`
   *   `mov [esi+20h],eax`-> `mMask`
   *   `add [esi+24h],1`  -> `mMaxidx`
   *
   * and the load-factor test at 0x00934BE8 (`[esi+0Ch] >> 2` against
   * `[esi+24h]`) is `mMaxidx <= size() / bucket_size` with the MSVC8
   * `bucket_size = 4`. The nine bucket slots the occupation table re-arms in
   * `clear()` (`push 9` at 0x00934EDB) are the same `min_buckets + 1` this
   * container seeds `mVec` with.
   */
  using SubclusterCacheMap = fa::hash_map<gpg::HaStar::SubclusterData, gpg::HaStar::Cluster::Data*>;

  void RetainClusterData(
    gpg::HaStar::Cluster::Data* data
  )
  {
    if (data) {
      ++data->mRefs;
    }
  }

  void ReleaseClusterData(
    gpg::HaStar::Cluster::Data* data
  )
  {
    if (!data) {
      return;
    }

    --data->mRefs;
    if (data->mRefs != 0) {
      return;
    }

    if (data->mReleaseObject) {
      // Binary: `mov edx,[ecx]; mov edx,[edx]; call edx` at
      // 0x009350A0..0x009350AB - a slot-0 virtual dispatch through
      // `Cluster::Data::mReleaseObject`. `ICache::Evict` is that slot.
      data->mReleaseObject->Evict(data->mReleaseArg);
    }
    operator delete[](data);
  }

  void AssignClusterData(
    gpg::HaStar::Cluster& dst,
    const gpg::HaStar::Cluster& src
  )
  {
    if (dst.mData == src.mData) {
      return;
    }

    RetainClusterData(src.mData);
    ReleaseClusterData(dst.mData);
    dst.mData = src.mData;
  }

  void SetClusterData(
    gpg::HaStar::Cluster& dst,
    gpg::HaStar::Cluster::Data* data
  )
  {
    if (dst.mData == data) {
      return;
    }

    RetainClusterData(data);
    ReleaseClusterData(dst.mData);
    dst.mData = data;
  }

  /**
   * `gpg::HaStar::ClusterInternalCache<T>`: one `ICache` plus one
   * `fa::hash_map<T, Cluster::Data*>`, keyed directly on the build input
   * (`OccupationData` or `SubclusterData`). `ClusterCache::ClusterCache()`
   * (0x00935580) constructs both instantiations in place, `mOccupationData`
   * at `this+0x00` and `mSubclusterData` at `this+0x2C`, each `sizeof ==
   * 0x2C` (vtable + the 0x28-byte map: `mMask`/`mMaxidx` at `this+0x20`/
   * `+0x24`, list head/size at `this+0x0C`/`+0x10` in FUN_00934820 and
   * FUN_00934B60).
   *
   * `fa::hash_map`'s default constructor reproduces FUN_00934820 /
   * FUN_00934B60: `_Init()` seeds the same nine bucket copies of
   * `mList.end()`. The one binary write not reproduced is
   * `this->mBool = *cacheEnabledFlag` at the map's `+0x00` traits slot: both
   * construct sites (0x0093559B / 0x009355A0) pass the same uninitialised
   * stack byte and no member ever reads it back.
   *
   * Per instantiation:
   *   OccupationData: dtor 0x00933DE0, Fetch 0x00934F80, Evict 0x009355F0
   *     (vtable 0x00D47884 slot 0, tail-jumps into `hash_map::erase`
   *     0x00935480), 0x20-byte map nodes.
   *   SubclusterData: dtor 0x00934500, Fetch 0x009350F0, Evict 0x00935600
   *     (tail-jumps into `hash_map::erase` 0x009354D0), 0x50-byte map nodes
   *     whose 16 `Cluster` keys are copy-constructed (0x009329A0) and
   *     destroyed with the node.
   */
  template <class T>
  class ClusterInternalCache final : public gpg::HaStar::ICache
  {
  public:
    ClusterInternalCache() = default;

    /**
     * Address: 0x00933DE0 (FUN_00933DE0, OccupationData)
     * Address: 0x00934500 (FUN_00934500, SubclusterData)
     * Mangled: ??1?$ClusterInternalCache@UOccupationData@HaStar@gpg@@@HaStar@gpg@@UAE@XZ
     *
     * What it does:
     * Severs every live entry's backpointer (asserting `data->mCache ==
     * this`, `ClusterCache.cpp:70`, then clearing
     * `mReleaseObject`/`mReleaseArg`) so a handle that outlives this cache
     * never calls back into a destroyed `ICache::Evict`. `mVec`'s own
     * destructor then frees the bucket vector and the nodes.
     *
     * Not `override`: `ICache`'s vtable has one slot (`Evict`), no virtual
     * destructor.
     */
    ~ClusterInternalCache()
    {
      for (auto& entry : mVec) {
        gpg::HaStar::Cluster::Data* const data = entry.second;
        if (data->mReleaseObject != this) {
          gpg::HandleAssertFailure(
            "data->mCache == this", 70, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterCache.cpp"
          );
        }
        data->mReleaseObject = nullptr;
        data->mReleaseArg = nullptr;
      }
    }

    /**
     * Address: 0x00934F80 (FUN_00934F80, OccupationData)
     * Address: 0x009350F0 (FUN_009350F0, SubclusterData)
     *
     * What it does:
     * Returns the cached cluster for `key`, building and caching one on a
     * miss. A successful insert arms this cache's `ICache::Evict` on the
     * new `Cluster::Data` (`mov [ecx+4], edi` / `add edx, 8; mov [eax+8],
     * edx` at 0x00935063 / 0x0093506A) so `ReleaseClusterData` drops the
     * entry once the last `Cluster` handle to it goes.
     */
    [[nodiscard]] gpg::HaStar::Cluster Fetch(
      const T& key
    )
    {
      gpg::HaStar::Cluster result{};

      const auto found = mVec.find(key);
      if (found != mVec.end()) {
        SetClusterData(result, found->second);
        return result;
      }

      gpg::HaStar::Cluster built = gpg::HaStar::ClusterBuild(key);
      const auto inserted = mVec.insert(typename Map::value_type(key, built.mData));
      if (!inserted.second) {
        gpg::HandleAssertFailure(
          "ins.second", 87, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterCache.cpp"
        );
      } else {
        RetainClusterData(inserted.first->second);
        inserted.first->second->mReleaseObject = this;
        inserted.first->second->mReleaseArg = &inserted.first->first;
      }

      SetClusterData(result, inserted.first->second);
      return result;
    }

  private:
    using Map = fa::hash_map<T, gpg::HaStar::Cluster::Data*>;

    /**
     * Address: 0x009355F0 (OccupationData), 0x00935600 (SubclusterData)
     *
     * What it does:
     * Vtable slot 0: `add ecx, 4` onto `mVec`, then a tail `jmp` into
     * `hash_map::erase(const key_type&)`. `key` is the map node's key that
     * `Fetch` published as `mReleaseArg`.
     */
    void Evict(
      const void* const key
    ) override
    {
      mVec.erase(*static_cast<const T*>(key));
    }

    Map mVec;
  };
  static_assert(
    sizeof(ClusterInternalCache<gpg::HaStar::OccupationData>) == 0x2C,
    "ClusterInternalCache<OccupationData> size must be 0x2C"
  );
  static_assert(
    sizeof(ClusterInternalCache<gpg::HaStar::SubclusterData>) == 0x2C,
    "ClusterInternalCache<SubclusterData> size must be 0x2C"
  );

} // namespace

namespace gpg::HaStar
{
  /**
   * The real backing object behind `ClusterCache`'s shared handle (see
   * that class's Doxygen block in `Cluster.h` for the handle/impl split's
   * evidence trail). Constructs/destroys its two `ClusterInternalCache<T>`
   * members in declaration order - reverse order on the way out, which is
   * exactly what FUN_00934F30 does by explicit call
   * (`sub_934500(this+44)` then `sub_933DE0(this)`) and what
   * FUN_00935580 does by explicit vtable-write-then-construct
   * (`mOccupationData` at `this+0`, `mSubclusterData` at `this+0x2C`).
   *
   * `ClusterInternalCache<T>` lives in this TU's anonymous namespace;
   * unqualified lookup from here finds it.
   */
  class ClusterCacheImpl
  {
  public:
    /**
     * Address: 0x00935580 (FUN_00935580, ??0ClusterCache@HaStar@gpg@@QAE@@Z)
     *
     * What it does:
     * Constructs `mOccupationData` then `mSubclusterData` in place -
     * `operator new(0x58)` for the block this lands in is the caller's
     * job (`boost::shared_ptr<ClusterCacheImpl>`'s own constructor,
     * FUN_009356E0). If `mSubclusterData`'s construction were to throw,
     * the compiler-generated unwind funclet for this constructor runs
     * `mOccupationData.~ClusterInternalCache()` (FUN_00933DE0) - the
     * `owner_ea=FUN_00935580` unwind edge recorded against that token.
     */
    ClusterCacheImpl() = default;

    /**
     * Address: 0x00934F30 (FUN_00934F30)
     *
     * What it does:
     * Destroys `mSubclusterData` then `mOccupationData` - the binary's
     * `sub_934500(this+44)` then `sub_933DE0(this)` pair, reproduced
     * here by ordinary reverse-declaration-order member destruction.
     */
    ~ClusterCacheImpl() = default;

    /**
     * Address: 0x00935420 (FUN_00935420,
     * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUOccupationData@23@@Z)
     */
    [[nodiscard]] gpg::HaStar::Cluster FetchCluster(
      const gpg::HaStar::OccupationData& occupationData
    )
    {
      return mOccupationData.Fetch(occupationData);
    }

    /**
     * Address: 0x00935450 (FUN_00935450,
     * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUSubclusterData@23@@Z)
     */
    [[nodiscard]] gpg::HaStar::Cluster FetchCluster(
      const gpg::HaStar::SubclusterData& subclusterData
    )
    {
      return mSubclusterData.Fetch(subclusterData);
    }

    // Layout-transparent: `ClusterCache::FetchCluster` (below) is
    // handle-forwarding only and never reaches in here, so there is no
    // encapsulation to buy by hiding these - keeping them public lets
    // the offset asserts below run as ordinary namespace-scope checks.
    ClusterInternalCache<gpg::HaStar::OccupationData> mOccupationData; // +0x00
    ClusterInternalCache<gpg::HaStar::SubclusterData> mSubclusterData; // +0x2C
  };
  static_assert(sizeof(ClusterCacheImpl) == 0x58, "ClusterCacheImpl size must be 0x58");
  static_assert(
    offsetof(ClusterCacheImpl, mSubclusterData) == 0x2C,
    "ClusterCacheImpl::mSubclusterData offset must be 0x2C"
  );
} // namespace gpg::HaStar

namespace
{
  void DestroySubclusterStorage(
    gpg::HaStar::Subcluster& subcluster
  )
  {
    delete[] subcluster.mArray;
    subcluster.mArray = nullptr;
    subcluster.mWidth = 0;
    subcluster.mHeight = 0;
  }

  void CreateSubclusterStorage(
    gpg::HaStar::Subcluster& subcluster,
    const int width,
    const int height
  )
  {
    subcluster.mWidth = width;
    subcluster.mHeight = height;

    const int clusterCount = width * height;
    subcluster.mArray = clusterCount > 0 ? new gpg::HaStar::Cluster[clusterCount] : nullptr;
  }

  // ------------------------------------------------------------------
  // gpg::HaStar cluster edge-cost search (octile grid label-correcting)
  // tables. The binary's four relaxation blocks (loop unrolled x4 over the
  // eight octile neighbours) all read the same underlying delta/mask tables at
  // a shifted base, so a single ascending pass over `k = 0..7` reproduces the
  // exact relaxation order. Values extracted byte-for-byte from the `.rdata`
  // blocks at 0x00D49430 (sHaStar_datf8, step costs), 0x00D49450
  // (sHaStar_dat7, row deltas), 0x00D49458 (sHaStar_dat6, column deltas) and
  // 0x00D49460 (sHaStar_dat5, diagonal prerequisite masks).
  // ------------------------------------------------------------------
  // The diagonal step is 0x3FB4FDF4 = 1.414f, not sqrt(2) (0x3FB504F3). The
  // node distance it is quantised against uses the sqrt(2)-1 factor, so a
  // straight-plus-diagonal route comes out just under its octile distance
  // and lands in bucket 0 rather than 1.
  constexpr std::array<float, 8> kOctileStepCost = {1.0f, 1.0f, 1.0f, 1.0f, 1.414f, 1.414f, 1.414f, 1.414f};
  constexpr std::array<std::int8_t, 8> kOctileRowDelta = {-1, 0, 1, 0, -1, 1, 1, -1};
  constexpr std::array<std::int8_t, 8> kOctileColDelta = {0, -1, 0, 1, -1, -1, 1, 1};
  // Diagonal neighbours (k>=4) may only relax once both of their orthogonal
  // neighbours have already been settled this expansion; orthogonals (k<4)
  // have no prerequisite.
  constexpr std::array<std::uint8_t, 8> kNeighborPrereqMask = {0u, 0u, 0u, 0u, 3u, 6u, 12u, 9u};

  // 9x9 expansion grid: cell (row z, column x) lives at grid[9*z + x].
  constexpr std::int32_t kEdgeSearchGridSpan = 9;
  constexpr std::int32_t kEdgeSearchGridCells = kEdgeSearchGridSpan * kEdgeSearchGridSpan; // 81

  /**
   * Address: 0x00954A40 (FUN_00954A40)
   *
   * IDA signature:
   * void __cdecl sub_954A40(
   *   gpg::HaStar::OccupationData *a1,
   *   gpg::fastvector<gpg::HaStar::Cluster::Node> *a2,
   *   gpg::fastvector<gpg::HaStar::Cluster::Edge> *a3);
   *
   * What it does:
   * Builds the cluster's triangular edge-cost matrix. For each ordered node
   * pair (s < t) it runs a label-correcting octile-grid search (FIFO ring
   * open-list over a 9x9 cell grid, seeded from node s) and, once the grid is
   * settled, stores `Cluster::Node::CostTo(s, t, pathCost)` (inlined here) at
   * triangular index `s + t*(t-1)/2`. Unreachable pairs store -1. When fewer
   * than two nodes exist the edge vector is emptied. The fill is
   * `fastvector<Edge>::resize` (0x0092E410), the same emission the subcluster
   * build uses.
   */
  void BuildClusterEdgeCosts(
    const gpg::HaStar::OccupationData& occupation,
    const gpg::fastvector<gpg::HaStar::Cluster::Node>& nodes,
    gpg::core::FastVectorInline<gpg::HaStar::Cluster::Edge>& outEdges
  )
  {
    using gpg::HaStar::Cluster;

    const std::uint32_t nodeCount = static_cast<std::uint32_t>(nodes.Size());

    if (nodeCount < 2u) {
      // No pairs: drop any heap storage and go back to the inline block.
      outEdges.ResetStorageToInline();
      return;
    }

    // Prefill the whole triangular matrix with -1 (unreachable).
    Cluster::Edge noEdge{};
    noEdge.cost = -1;
    outEdges.resize(Cluster::TriangularSize(nodeCount), noEdge);

    // 9x9 search grid. The binary constructs all 81 cells once (0x00954940
    // over an `eh vector constructor iterator`), then re-inits cost, flags and
    // cell once per source expansion; the ring links are self-linked again
    // by the time each expansion ends.
    std::array<PathSearchFrontierNode, kEdgeSearchGridCells> grid{};
    const std::uint16_t* const layerRows = occupation.mRows;

    for (std::uint32_t source = 0u; source + 1u < nodeCount; ++source) {
      gpg::DListItem<PathSearchFrontierNode> openList;

      // Cell (row z, col x) encodes packedCell = (z << 4) | x.
      for (std::int32_t row = 0; row < kEdgeSearchGridSpan; ++row) {
        for (std::int32_t col = 0; col < kEdgeSearchGridSpan; ++col) {
          PathSearchFrontierNode& cell = grid[row * kEdgeSearchGridSpan + col];
          cell.pathCost = 0.0f;
          cell.visitFlags = 0u;
          cell.packedCell = static_cast<std::uint8_t>((row << 4) | col);
        }
      }

      // Seed the source node's cell into the open list.
      const Cluster::Node& sourceNode = nodes[source];
      PathSearchFrontierNode& seed = grid[sourceNode.z * kEdgeSearchGridSpan + sourceNode.x];
      seed.visitFlags = 1u;
      seed.ListLinkBefore(&openList);

      // Label-correcting drain of the FIFO ring.
      while (!openList.ListIsUnlinked()) {
        PathSearchFrontierNode* const current = openList.mNext->Get();
        current->ListUnlink();

        std::uint8_t settledMask = 0u;
        const std::int32_t currentRow = current->packedCell >> 4;
        const std::int32_t currentCol = current->packedCell & 0x0F;

        for (std::int32_t k = 0; k < 8; ++k) {
          if ((settledMask & kNeighborPrereqMask[k]) != kNeighborPrereqMask[k]) {
            continue;
          }

          const std::int32_t neighborRow = currentRow + kOctileRowDelta[k];
          const std::int32_t neighborCol = currentCol + kOctileColDelta[k];
          if (neighborCol < 0 || neighborRow < 0 || neighborCol > 8 || neighborRow > 8) {
            continue;
          }
          if ((static_cast<unsigned int>(layerRows[neighborRow]) & (1u << neighborCol)) == 0u) {
            continue;
          }

          const float candidateCost = kOctileStepCost[k] + current->pathCost;
          settledMask |= static_cast<std::uint8_t>(1u << k);

          PathSearchFrontierNode& neighbor = grid[neighborRow * kEdgeSearchGridSpan + neighborCol];
          if (neighbor.visitFlags != 0u && candidateCost >= neighbor.pathCost) {
            continue;
          }

          neighbor.visitFlags = 1u;
          neighbor.pathCost = candidateCost;
          neighbor.ListLinkBefore(&openList);
        }
      }

      // Emit the quantized edge cost for every later node t (source < t).
      for (std::uint32_t target = source + 1u; target < nodeCount; ++target) {
        const Cluster::Node& targetNode = nodes[target];
        const PathSearchFrontierNode& targetCell = grid[targetNode.z * kEdgeSearchGridSpan + targetNode.x];
        Cluster::Edge& edge = outEdges[Cluster::EdgeIndex(source, target)];
        edge.cost = targetCell.visitFlags == 0u ? std::int8_t{-1}
                                                : Cluster::Node::CostTo(sourceNode, targetNode, targetCell.pathCost);
      }
    }
  }
} // namespace

namespace gpg::HaStar
{
  /**
   * Address: 0x00954650 (FUN_00954650,
   * ?EraseUnconnectedNodes@HaStar@gpg@@YAXAAV?$fastvector@UNode@Cluster@HaStar@gpg@@@2@AAV?$fastvector@UEdge@Cluster@HaStar@gpg@@@2@@Z)
   *
   * What it does:
   * Drops every cluster node that has no non-negative edge to any other node,
   * compacting both the node array and the triangular edge matrix in place so
   * that only reachable nodes and their pairwise edges survive. A node counts
   * as reached if it is an endpoint of at least one edge whose quantized cost
   * is >= 0. Asserts `nnodes_used == ioNodes.size()` and
   * `ioEdges.size() == TriangularSize(nnodes_used)`. Both `ClusterBuild`
   * overloads call it (0x00955369, 0x009312E7).
   */
  void EraseUnconnectedNodes(
    gpg::fastvector<Cluster::Node>& ioNodes,
    gpg::fastvector<Cluster::Edge>& ioEdges
  )
  {
    // One byte per node, in the binary's 12-element inline stack buffer.
    gpg::fastvector_n<char, 12> reachable;

    const std::uint32_t nodeCount = static_cast<std::uint32_t>(ioNodes.Size());
    reachable.resize(nodeCount, char{0});

    // Mark endpoints of every non-negative edge as reached.
    std::int32_t reachedCount = 0;
    for (std::uint32_t high = 1u; high < nodeCount; ++high) {
      std::uint32_t edgeIndex = Cluster::TriangularSize(high);
      for (std::uint32_t low = 0u; low < high; ++low, ++edgeIndex) {
        if (ioEdges[edgeIndex].cost >= 0) {
          reachedCount += (reachable[low] == 0) ? 1 : 0;
          reachedCount += (reachable[high] == 0) ? 1 : 0;
          reachable[low] = 1;
          reachable[high] = 1;
        }
      }
    }

    if (reachedCount == static_cast<std::int32_t>(nodeCount)) {
      return;
    }

    // Compact both arrays row by row, keeping only reached nodes and the
    // edges between them.
    std::size_t edgeWrite = 0u;
    std::size_t nodeWrite = 0u;
    for (std::uint32_t high = 0u; high < nodeCount; ++high) {
      if (reachable[high] == 0) {
        continue;
      }
      const std::uint32_t rowBase = Cluster::TriangularSize(high);
      for (std::uint32_t low = 0u; low < high; ++low) {
        if (reachable[low] != 0) {
          ioEdges[edgeWrite++] = ioEdges[rowBase + low];
        }
      }
      ioNodes[nodeWrite++] = ioNodes[high];
    }

    ioNodes.erase(ioNodes.begin() + nodeWrite, ioNodes.end());
    ioEdges.erase(ioEdges.begin() + edgeWrite, ioEdges.end());

    if (reachedCount != static_cast<std::int32_t>(ioNodes.Size())) {
      gpg::HandleAssertFailure(
        "nnodes_used == ioNodes.size()", 168, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\Cluster.cpp"
      );
    }
    if (ioEdges.Size() != Cluster::TriangularSize(static_cast<std::uint32_t>(reachedCount))) {
      gpg::HandleAssertFailure(
        "ioEdges.size() == TriangularSize(nnodes_used)",
        169,
        "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\Cluster.cpp"
      );
    }
  }

  /**
   * Address: 0x009315C0 (FUN_009315C0)
   *
   * What it does:
   * Initializes one `ICache` interface object by binding its vtable.
   */
  ICache::ICache() = default;

  /**
   * Address: 0x00765840 (FUN_00765840, ??0Cluster@HaStar@gpg@@QAE@ABV012@@Z)
   */
  Cluster::Cluster(
    const Cluster& other
  )
    : mData(other.mData)
  {
    RetainClusterData(mData);
  }

  /**
   * Address: 0x008E3450 (FUN_008E3450, ??4Cluster@HaStar@gpg@@QAEAAV012@ABV012@@Z)
   */
  Cluster& Cluster::operator=(
    const Cluster& other
  )
  {
    AssignClusterData(*this, other);
    return *this;
  }

  /**
   * Address: 0x00765860 (FUN_00765860, ??1Cluster@HaStar@gpg@@QAE@XZ)
   */
  Cluster::~Cluster()
  {
    ReleaseClusterData(mData);
  }

  /**
   * Address: 0x00F32C60 (?sDefaultConstructData@Cluster@HaStar@gpg@@0UData@123@B)
   *
   * Shared zero-node sentinel payload used by `ClusterBuild`. Initialized with
   * `mRefs=1` so the sentinel is never destroyed, no dispose callback, and zero
   * nodes; the trailing `mNodes[1]` flexible slot is value-initialized.
   */
  Cluster::Data Cluster::sDefaultConstructData = {1, nullptr, 0u, 0u, {{0u, 0u}}};

  /**
   * Address: 0x0092D8B0 (FUN_0092D8B0, ?QuantizeEdgeCost@Cluster@HaStar@gpg@@SAMMM@Z)
   *
   * What it does:
   * Quantizes one edge-cost ratio into a 0..31 cost bucket.
   */
  float Cluster::QuantizeEdgeCost(
    const float a,
    const float b
  )
  {
    // 0x0092D8B0..0x0092D8C4: `fld a; fdiv b; fldln2; fxch; fyl2x; fmul 6.0f`.
    // The logarithm is never rounded to float on its own.
    const float scaled = fa::ScaledLnQuotient(a, b, 6.0f);
    // 0x0092D8C8..0x0092D8E2: ceil as `frndint`, +1 when the value is above its
    // nearest integer (`cmova`, false when unordered), added to the `fistp`. An
    // infinite or NaN quotient stores the integer indefinite, which the clamp
    // below turns into bucket 0; a plain cast of `ceil(+inf)` is undefined, and
    // clang's x64 code saturated it into bucket 31 (difffuzz, plan WPR.21).
    const float nearest = std::nearbyint(scaled);
    int quantized =
      static_cast<int>(static_cast<std::uint32_t>(fa::RoundToInt(nearest)) + (scaled > nearest ? 1u : 0u));
    if (quantized > 31) {
      quantized = 31;
    }
    if (quantized < 0) {
      quantized = 0;
    }
    return static_cast<float>(quantized);
  }

  /**
   * Address: 0x0092E2E0 (FUN_0092E2E0, gpg::HaStar::Cluster::Node::CostTo)
   *
   * What it does:
   * Quantises `cost` against the octile distance between the two nodes.
   */
  std::int8_t Cluster::Node::CostTo(
    const Node& from,
    const Node& to,
    const float cost
  )
  {
    const float dx = std::fabs(static_cast<float>(static_cast<int>(from.x) - static_cast<int>(to.x)));
    const float dz = std::fabs(static_cast<float>(static_cast<int>(from.z) - static_cast<int>(to.z)));
    const float distance = (dz <= dx) ? (dz * 0.41421354f + dx) : (dx * 0.41421354f + dz);
    return static_cast<std::int8_t>(static_cast<int>(QuantizeEdgeCost(cost, distance)));
  }

  /**
   * Address: 0x00954110 (FUN_00954110,
   * ?SetData@Cluster@HaStar@gpg@@QAEXPBUNode@123@PBUEdge@123@I@Z)
   *
   * IDA signature:
   * void __thiscall gpg::HaStar::Cluster::SetData(
   *   gpg::HaStar::Cluster *this@<ecx>,
   *   const Node *nodes, const Edge *edges, unsigned int nodeCount);
   *
   * What it does:
   * If the current payload is null, has a different node count, or is shared
   * (refcount != 1), allocates a fresh payload sized for the requested node
   * count (`header + nodeCount*2 + nodeCount*(nodeCount-1)/2`) and releases
   * the prior payload (invoking its dispose-callback when refcount hits zero).
   * Then copies `nodeCount` `Node` entries (2 bytes each) and
   * `nodeCount*(nodeCount-1)/2` `Edge` buckets (1 byte each) into the trailing
   * storage. Asserts `nodeCount < 256`.
   */
  void Cluster::SetData(
    const Cluster::Node* const nodes,
    const Cluster::Edge* const edges,
    const unsigned int nodeCount
  )
  {
    if (nodeCount >= 0x100u) {
      gpg::HandleAssertFailure(
        "nnodes < 256", 58, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\Cluster.cpp"
      );
    }

    constexpr std::size_t kHeaderBytes = offsetof(Data, mNodes); // 0x0D on x86
    const std::size_t nodeBytes = static_cast<std::size_t>(nodeCount) * sizeof(Node);
    const std::size_t edgeBytes = TriangularSize(nodeCount) * sizeof(Edge);

    Cluster::Data* payload = mData;
    const bool reuseInPlace =
      (payload != nullptr) && (static_cast<unsigned int>(payload->mNodeCount) == nodeCount) && (payload->mRefs == 1);

    if (!reuseInPlace) {
      const std::size_t totalBytes = kHeaderBytes + nodeBytes + edgeBytes;
      auto* const replacement = static_cast<Cluster::Data*>(::operator new[](totalBytes));
      replacement->mRefs = 1;
      replacement->mReleaseObject = nullptr;
      replacement->mReleaseArg = nullptr;
      replacement->mNodeCount = static_cast<std::uint8_t>(nodeCount);

      if (mData != nullptr) {
        --mData->mRefs;
        Cluster::Data* const prior = mData;
        if (prior->mRefs == 0) {
          if (prior->mReleaseObject != nullptr) {
            // Slot-0 virtual dispatch through `mReleaseObject` - see
            // `ICache::Evict`'s Doxygen block in Cluster.h for the
            // binary evidence (`mov edx,[ecx]; mov edx,[edx];
            // call edx` at 0x009350A0..0x009350AB).
            prior->mReleaseObject->Evict(prior->mReleaseArg);
          }
          ::operator delete[](prior);
        }
      }

      mData = replacement;
      payload = replacement;
    }

    if (nodes != nullptr) {
      std::copy_n(nodes, nodeCount, payload->mNodes);
    }
    if (edges != nullptr) {
      std::copy_n(edges, TriangularSize(nodeCount), payload->Edges());
    }
  }

  /**
   * Address: 0x00954030 (FUN_00954030, ?cmp@Cluster@HaStar@gpg@@QBEHABV123@@Z)
   *
   * What it does:
   * Total-orders two cluster handles by their shared payload. Handles that
   * reference the same Data compare equal; otherwise the inline payload blob
   * (mNodeCount + Node[n] + Edge[n*(n-1)/2], n = this handle's node count) is
   * compared byte-for-byte and the sign normalized to -1 / 0 / +1.
   */
  int Cluster::cmp(
    const Cluster& other
  ) const
  {
    const Data* const self = mData;
    const Data* const rhs = other.mData;
    if (self == rhs) {
      return 0;
    }

    const unsigned int nodeCount = self->mNodeCount;

    // The binary's inline compare (0x00954057..0x00954072) stops at the first word that differs, and the
    // node count is the first byte, so it never reads past a smaller cluster. std::memcmp may read ahead
    // over its whole length, which faulted at the end of a mapping (replay 26904000). Counts that differ
    // decide the order here, as that first byte does in the binary.
    if (nodeCount != rhs->mNodeCount) {
      return (nodeCount < rhs->mNodeCount) ? -1 : 1;
    }

    const std::size_t payloadBytes = 1u + nodeCount * sizeof(Cluster::Node) + Cluster::TriangularSize(nodeCount);
    const int diff = std::memcmp(&self->mNodeCount, &rhs->mNodeCount, payloadBytes);
    return (diff < 0) ? -1 : (diff > 0 ? 1 : 0);
  }

  /**
   * Address: 0x009540E0 (FUN_009540E0, ?hash_value@HaStar@gpg@@YAIABVCluster@12@@Z)
   *
   * IDA signature:
   * unsigned int __cdecl gpg::HaStar::hash_value(gpg::HaStar::Cluster const &cluster);
   *
   * What it does:
   * Hashes one cluster handle's inline payload blob - the same
   * `mNodeCount + Node[n] + Edge[n*(n-1)/2]` span `Cluster::cmp` compares
   * byte-for-byte - through the engine's general-purpose `gpg::HashBytes`,
   * salted with a fixed constant. Two handles sharing the same payload bytes
   * hash equal regardless of which heap block backs them, which is the whole
   * point: this is `SubclusterData::Hash`'s per-cluster mixing step, and a
   * subcluster cache keyed on cluster identity instead of payload would never
   * hit.
   */
  unsigned int hash_value(
    const Cluster& cluster
  )
  {
    const Cluster::Data* const data = cluster.mData;
    const unsigned int nodeCount = data->mNodeCount;
    const std::size_t payloadBytes = 1u + nodeCount * sizeof(Cluster::Node) + Cluster::TriangularSize(nodeCount);
    return gpg::HashBytes(&data->mNodeCount, payloadBytes, 2079270547u);
  }

  /**
   * Address: 0x009552D0 (FUN_009552D0,
   * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUOccupationData@12@@Z)
   *
   * IDA signature:
   * gpg::HaStar::Cluster *__cdecl gpg::HaStar::ClusterBuild(
   *   gpg::HaStar::Cluster *result, const gpg::HaStar::OccupationData *occupation);
   *
   * What it does:
   * Builds a cluster payload from occupancy cell data. Extracts the boundary
   * node set (`BuildOccupationEdgeContacts`), computes the pairwise octile-search
   * edge-cost matrix (`BuildClusterEdgeCosts`), drops nodes with no reachable
   * edge (`EraseUnconnectedNodes`), seeds the handle with the shared empty
   * sentinel payload, then commits the surviving nodes/edges via
   * `Cluster::SetData`. Both scratch vectors free their heap storage (edges
   * first, then nodes) before returning.
   */
  Cluster ClusterBuild(
    const OccupationData& occupationData
  )
  {
    // Scratch with the binary's inline sizes: 16 nodes, 120 edges.
    gpg::fastvector_n<Cluster::Node, 16> nodes;
    gpg::fastvector_n<Cluster::Edge, 120> edges;

    BuildOccupationEdgeContacts(occupationData, nodes);
    BuildClusterEdgeCosts(occupationData, nodes, edges);
    EraseUnconnectedNodes(nodes, edges);

    Cluster cluster{};
    cluster.mData = &Cluster::sDefaultConstructData;
    ++Cluster::sDefaultConstructData.mRefs;
    cluster.SetData(nodes.begin(), edges.begin(), static_cast<unsigned int>(nodes.Size()));

    return cluster;
  }

  namespace
  {
    /**
     * One search cell of the subcluster merge: the running distance the
     * search reached this node with, plus the node's coordinates inside the
     * parent (level+1) cluster. The binary hashes and compares cells by the
     * packed `(x | z << 8)` word only (`a3` in FUN_00930D60), the distance is
     * payload. `AStarNode<SubclusterCell>` is IDA's `struct_Ha4`: cell @+0x00,
     * state @+0x08, parent @+0x0C, cost @+0x10, estimate @+0x14, handle @+0x18.
     */
    struct SubclusterCell
    {
      float mDistance;      // +0x00
      Cluster::Node mNode;  // +0x04
      std::uint8_t mPad[2]; // +0x06
    };
    static_assert(sizeof(SubclusterCell) == 0x08, "SubclusterCell size must be 0x08");

    [[nodiscard]] std::uint16_t PackedSubclusterNodeKey(
      const Cluster::Node& node
    ) noexcept
    {
      return static_cast<std::uint16_t>(node.x | (static_cast<std::uint16_t>(node.z) << 8u));
    }

    [[nodiscard]] std::size_t hash_value(
      const SubclusterCell& cell
    )
    {
      return fa::hash_value(static_cast<long>(PackedSubclusterNodeKey(cell.mNode)));
    }

    struct SubclusterCellLess
    {
      [[nodiscard]] bool operator()(
        const SubclusterCell& lhs,
        const SubclusterCell& rhs
      ) const noexcept
      {
        return PackedSubclusterNodeKey(lhs.mNode) < PackedSubclusterNodeKey(rhs.mNode);
      }
    };

    using SubclusterCellTraits = fa::hash_compare<SubclusterCell, SubclusterCellLess>;

    /**
     * One neighbour emitted by `SubclusterSearch::ExpandNode` (the 12-byte
     * record `v42` in FUN_009304F0): the distance reached through this edge,
     * the neighbour node, and the edge cost itself.
     */
    struct SubclusterNeighbour
    {
      float mDistance;      // +0x00
      Cluster::Node mNode;  // +0x04
      std::uint8_t mPad[2]; // +0x06
      float mEdgeCost;      // +0x08
    };
    static_assert(sizeof(SubclusterNeighbour) == 0x0C, "SubclusterNeighbour size must be 0x0C");

    /**
     * The Dijkstra the subcluster merge runs from each boundary node over the
     * 4x4 child clusters' edge graphs. IDA's `struct_Ha1` is exactly
     * `gpg::AStarSearch<SubclusterCell, SubclusterSearch>`: the node hash map
     * at +0x00 and the open heap (`struct_Ha2`) at +0x28.
     *
     * Address: 0x00930C00 (FUN_00930C00, struct_Ha1::struct_Ha1) -- the
     *   `AStarSearch` constructor emission for this instantiation.
     * Address: 0x0092EF80 (FUN_0092EF80, struct_Ha2::Reset) -- `ResetSearch`'s
     *   open-heap clear.
     * Address: 0x00930C80 (FUN_00930C80) -- `AddStartNode` for this
     *   instantiation (`ClusterBuild` seeds it with cost 0).
     * Address: 0x0092DD60 / 0x00930B40 (FUN_0092DD60, FUN_00930B40) --
     *   `fa::hash_map<SubclusterCell, AStarNode>::find` / `clear`.
     */
    class SubclusterSearch final : public gpg::AStarSearch<SubclusterCell, SubclusterSearch, SubclusterCellTraits>
    {
    public:
      // The merge is a plain shortest-path relaxation: no heuristic, no
      // closest-cell tracking (both hooks are empty in the binary).
      [[nodiscard]] float GetHeuristicCost(
        const SubclusterCell&
      ) const noexcept
      {
        return 0.0f;
      }
      void NoteCandidateCell(
        const SubclusterCell&,
        float
      ) noexcept
      {}

      /**
       * Address: 0x009304F0 (FUN_009304F0)
       *
       * What it does:
       * Emits every neighbour reachable from `node` through the child
       * clusters that contain it: for each child cluster of the parent's 4x4
       * grid whose index rect covers the node, finds the node's slot in that
       * child's node table and, for every other node of the child with a
       * non-negative quantised edge, pushes a neighbour whose edge cost is
       * the dequantised bucket scaled by the octile distance. Never reports
       * a goal (the merge wants every node's distance).
       */
      bool ExpandNode(
        const SubclusterData& data,
        const node_type& node,
        std::vector<SubclusterNeighbour>& outNeighbours
      ) const;

      /**
       * Address: 0x00930D60 (FUN_00930D60)
       *
       * What it does:
       * Drains the open heap: expands the cheapest node, closes it, and
       * relaxes every emitted neighbour -- fresh nodes open with the
       * reached cost, open nodes improve when the reached cost is lower.
       * Returns true only if an expansion reports a goal (never, here).
       */
      bool Run(const SubclusterData& data);
    };

    bool SubclusterSearch::ExpandNode(
      const SubclusterData& data,
      const node_type& node,
      std::vector<SubclusterNeighbour>& outNeighbours
    ) const
    {
      const int level = data.mLevel;
      const int shift = sClusterSizeLog2[level];
      const int nodeX = node.mCell.mNode.x;
      const int nodeZ = node.mCell.mNode.z;

      const gpg::Rect2i childRect = ClusterIndexRect(nodeX, nodeZ, static_cast<std::uint8_t>(level), 4, 4);

      for (int childZ = childRect.z0; childZ != childRect.z1; ++childZ) {
        const int originZ = childZ << shift;
        for (int childX = childRect.x0; childX != childRect.x1; ++childX) {
          const int originX = childX << shift;

          const Cluster::Data* const child = data.mClusters[childX + 4 * childZ].mData;
          const std::uint32_t nodeCount = (child != nullptr) ? child->mNodeCount : 0u;
          if (nodeCount == 0u) {
            continue;
          }

          const Cluster::Node* const nodes = child->mNodes;
          const Cluster::Edge* const edges = child->Edges();

          std::uint32_t fromIndex = 0u;
          for (; fromIndex < nodeCount; ++fromIndex) {
            if (
              nodes[fromIndex].x == static_cast<std::uint8_t>(nodeX - originX) &&
              nodes[fromIndex].z == static_cast<std::uint8_t>(nodeZ - originZ)
            ) {
              break;
            }
          }
          if (fromIndex == nodeCount) {
            continue;
          }

          for (std::uint32_t toIndex = 0u; toIndex < nodeCount; ++toIndex) {
            if (toIndex == fromIndex) {
              continue;
            }

            const std::int8_t bucket = edges[Cluster::EdgeIndex(fromIndex, toIndex)].cost;
            if (bucket < 0) {
              continue;
            }

            const float edgeCost =
              Cluster::DequantizeEdgeCost(bucket, Cluster::NodeOctileDistance(*child, fromIndex, toIndex));

            SubclusterNeighbour neighbour{};
            neighbour.mDistance = node.mCell.mDistance + edgeCost;
            neighbour.mNode.x = static_cast<std::uint8_t>(originX + nodes[toIndex].x);
            neighbour.mNode.z = static_cast<std::uint8_t>(originZ + nodes[toIndex].z);
            neighbour.mEdgeCost = edgeCost;
            outNeighbours.push_back(neighbour);
          }
        }
      }

      return false;
    }

    bool SubclusterSearch::Run(
      const SubclusterData& data
    )
    {
      std::vector<SubclusterNeighbour> neighbours;

      while (!OpenSet().empty()) {
        node_type* const current = OpenSet().top();

        neighbours.clear();
        if (ExpandNode(data, *current, neighbours)) {
          return true;
        }

        current->mState = gpg::AStarNodeState::Closed;
        (void)OpenSet().Pop();

        for (const SubclusterNeighbour& neighbour : neighbours) {
          SubclusterCell cell{};
          cell.mDistance = neighbour.mDistance;
          cell.mNode = neighbour.mNode;

          node_type& next = FindOrCreateNode(cell);
          const float reachedCost = current->mCost + neighbour.mEdgeCost;

          switch (next.mState) {
          case gpg::AStarNodeState::Unvisited: {
            next.mState = gpg::AStarNodeState::Open;
            next.mEstimate = 0.0f;
            next.mParent = current;
            next.mCell = cell;
            next.mCost = reachedCost;
            next.mHandle = OpenSet().Push(reachedCost, &next);
            break;
          }

          case gpg::AStarNodeState::Open: {
            if (next.mCost > reachedCost) {
              next.mParent = current;
              next.mCell = cell;
              next.mCost = reachedCost;
              OpenSet().UpdatePriority(next.mHandle, next.mEstimate + reachedCost);
            }
            break;
          }

          case gpg::AStarNodeState::Closed:
          default:
            // "neib->mState == CLOSED", AStarSearch.h:253
            assert(next.mState == gpg::AStarNodeState::Closed);
            break;
          }
        }
      }

      return false;
    }

    /**
     * Address: 0x0092FE30 (FUN_0092FE30)
     *
     * What it does:
     * Gathers the parent cluster's boundary node set from its sixteen
     * children: every child node that lands on the parent-size grid boundary
     * (`x` or `z` a multiple of the level+1 cluster size) is appended in
     * parent-local coordinates, then the set is sorted by its packed
     * `(x | z << 8)` word and deduplicated.
     */
    void CollectSubclusterBoundaryNodes(
      const SubclusterData& data,
      gpg::fastvector_n<Cluster::Node, 64>& outNodes
    )
    {
      const int level = data.mLevel;
      const int boundaryMask = sClusterSize[level + 1] - 1;
      const int shift = sClusterSizeLog2[level];

      outNodes.clear();
      for (int childZ = 0; childZ < 4; ++childZ) {
        for (int childX = 0; childX < 4; ++childX) {
          const Cluster::Data* const child = data.mClusters[childX + 4 * childZ].mData;
          const std::uint32_t nodeCount = (child != nullptr) ? child->mNodeCount : 0u;
          for (std::uint32_t index = 0u; index < nodeCount; ++index) {
            const int parentX = (childX << shift) + child->mNodes[index].x;
            const int parentZ = (childZ << shift) + child->mNodes[index].z;
            if ((parentX & boundaryMask) != 0 && (parentZ & boundaryMask) != 0) {
              continue;
            }
            Cluster::Node node{};
            node.x = static_cast<std::uint8_t>(parentX);
            node.z = static_cast<std::uint8_t>(parentZ);
            outNodes.push_back(node);
          }
        }
      }

      SortUniqueNodes(outNodes);
    }
  } // namespace

  /**
   * Address: 0x009310E0 (FUN_009310E0,
   * ?ClusterBuild@HaStar@gpg@@YA?AVCluster@12@ABUSubclusterData@12@@Z)
   *
   * IDA signature:
   * gpg::HaStar::Cluster *__cdecl gpg::HaStar::ClusterBuild(
   *   gpg::HaStar::Cluster *result, gpg::HaStar::SubclusterData *children);
   *
   * What it does:
   * Builds one level-N cluster from its sixteen level-(N-1) children: collects
   * the parent-boundary node set (`CollectSubclusterBoundaryNodes`), sizes the
   * triangular edge table to n(n-1)/2 "no edge" buckets, then for every node i
   * runs one `SubclusterSearch` from it over the children's edge graphs and
   * quantises the distance to each earlier node j into edge (j, i)
   * (`Cluster::Node::CostTo`). Nodes that end up with no edge are dropped and
   * the survivors are committed through `Cluster::SetData`.
   *
   * Address: 0x0092E410 (FUN_0092E410) -- `edges.resize(n(n-1)/2, {-1})`, the
   *   `gpg::fastvector_n<Cluster::Edge, 50>::resize` fill emission.
   */
  Cluster ClusterBuild(
    const SubclusterData& subclusterData
  )
  {
    gpg::fastvector_n<Cluster::Node, 64> nodes;
    gpg::fastvector_n<Cluster::Edge, 50> edges;

    CollectSubclusterBoundaryNodes(subclusterData, nodes);

    const std::uint32_t nodeCount = static_cast<std::uint32_t>(nodes.Size());
    Cluster::Edge noEdge{};
    noEdge.cost = -1;
    edges.resize(Cluster::TriangularSize(nodeCount), noEdge);

    SubclusterSearch search;
    for (std::uint32_t high = 1u; high < nodeCount; ++high) {
      search.ResetSearch();

      SubclusterCell start{};
      start.mNode = nodes[high];
      start.mDistance = 0.0f;
      search.AddStartNode(start, search);
      (void)search.Run(subclusterData);

      for (std::uint32_t low = 0u; low < high; ++low) {
        SubclusterCell key{};
        key.mNode = nodes[low];
        const auto* const found = search.Nodes().Find(key);
        if (found == nullptr) {
          continue;
        }
        edges[Cluster::EdgeIndex(low, high)].cost =
          Cluster::Node::CostTo(nodes[low], nodes[high], found->mCell.mDistance);
      }
    }

    EraseUnconnectedNodes(nodes, edges);

    Cluster cluster{};
    cluster.mData = &Cluster::sDefaultConstructData;
    ++Cluster::sDefaultConstructData.mRefs;
    cluster.SetData(nodes.begin(), edges.begin(), static_cast<unsigned int>(nodes.Size()));
    return cluster;
  }

  /**
   * Address: 0x00931FB0 (FUN_00931FB0, ??1WeakPtr_ClusterCache@Moho@@QAE@@Z)
   *
   * Note:
   * `ClusterCache` is the two-word `boost::shared_ptr<ClusterCacheImpl>` handle. 0x00931FB0 loads the control block
   * and releases it, never reading the pointee: the impl is deleted by the control block's `dispose()` when the last
   * reference goes, running `ClusterCacheImpl::~ClusterCacheImpl()` (FUN_00934F30), which destroys
   * `mSubclusterData` then `mOccupationData` (FUN_00934500/FUN_00933DE0).
   */
  ClusterCache::~ClusterCache() = default;

  /**
   * Address: 0x00935580 (FUN_00935580) + 0x009356E0 (FUN_009356E0), see the
   * Doxygen block on the declaration (`Cluster.h`) for the full evidence
   * trail.
   */
  void InitializeClusterCache(
    ClusterCache& outCache
  )
  {
    // Address: 0x00931EB0 (FUN_00931EB0 -- `sp_counted_impl_p<ClusterCache::Impl>`'s constructor), 0x00931ED0
    // (FUN_00931ED0 -- its `get_deleter`, null) and 0x00935520 (FUN_00935520 -- its `dispose`, `delete px`) are the
    // control block this `shared_ptr` makes; formerly hand-built in BoostWrappers over a raw vtable probe.
    outCache.mImpl.reset(new ClusterCacheImpl());
  }

  /**
   * Address: 0x008E3420 (FUN_008E3420, ??0struct_Subcluster@@QAE@@Z)
   */
  Subcluster::Subcluster()
    : mArray(nullptr)
    , mWidth(0)
    , mHeight(0)
  {}

  /**
   * Address: 0x008E36C0 (FUN_008E36C0, ??0struct_Subcluster@@QAE@HH@Z)
   */
  Subcluster::Subcluster(
    const int width,
    const int height
  )
    : mArray(nullptr)
    , mWidth(0)
    , mHeight(0)
  {
    CreateSubclusterStorage(*this, width, height);
  }

  /**
   * Address: 0x0076BF30 (FUN_0076BF30, ??1struct_Subcluster@@QAE@@Z)
   */
  Subcluster::~Subcluster()
  {
    DestroySubclusterStorage(*this);
  }

  /**
   * Address: 0x008E3CD0 (FUN_008E3CD0,
   * ??0ClusterMap@HaStar@gpg@@QAE@PAUIOccupationSource@12@IIABVClusterCache@12@IABV?$Rect2@H@2@@Z)
   */
  ClusterMap::ClusterMap(
    IOccupationSource* const source,
    const unsigned int widthM,
    const unsigned int heightM,
    const ClusterCache& cache,
    const unsigned int numLevels,
    const gpg::Rect2i& area
  )
    : mNumLevels(numLevels)
    , mWidth(0)
    , mHeight(0)
    , mSrc(source)
    , mCache(cache)
    , mLevels{}
    , mCheckLevels{}
    , mIsDone(0u)
    , pad_89{0u, 0u, 0u}
    , mProgress(0u)
    , mArea(area)
  {
    if (mNumLevels >= kClusterSizeCount) {
      gpg::HandleAssertFailure(
        "numlevels <= MAX_LEVEL", 29, "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\hastar\\ClusterMap.cpp"
      );
      mNumLevels = static_cast<std::uint32_t>(kClusterSizeCount - 1);
    }

    const unsigned int levelSize = kClusterSizeByLevel[mNumLevels];
    const int alignMask = ~static_cast<int>(levelSize - 1u);
    mWidth = alignMask & static_cast<int>(levelSize + widthM - 1u);
    mHeight = alignMask & static_cast<int>(levelSize + heightM - 1u);

    for (std::uint32_t level = 1u; level <= mNumLevels; ++level) {
      const unsigned int clusterSize = kClusterSizeByLevel[level];
      const unsigned int levelWidth = static_cast<unsigned int>(mWidth) / clusterSize;
      const unsigned int levelHeight = static_cast<unsigned int>(mHeight) / clusterSize;

      Subcluster& levelStorage = mLevels[level];
      DestroySubclusterStorage(levelStorage);
      CreateSubclusterStorage(levelStorage, static_cast<int>(levelWidth), static_cast<int>(levelHeight));

      mCheckLevels[level].Reset(levelWidth, levelHeight);
      mCheckLevels[level].FillRect(0, 0, static_cast<int>(levelWidth), static_cast<int>(levelHeight), true);
    }
  }

  /**
   * Address: 0x0076BB60 (FUN_0076BB60, ??1ClusterMap@HaStar@gpg@@QAE@@Z)
   */
  ClusterMap::~ClusterMap() = default;

  /**
   * Address: 0x00935420 (FUN_00935420,
   * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUOccupationData@23@@Z)
   */
  Cluster ClusterCache::FetchCluster(
    const OccupationData& occupationData
  )
  {
    if (mImpl.get() == nullptr) {
      return Cluster{};
    }
    return mImpl->FetchCluster(occupationData);
  }

  /**
   * Address: 0x00935450 (FUN_00935450,
   * ?FetchCluster@ClusterCache@HaStar@gpg@@QAE?AVCluster@23@ABUSubclusterData@23@@Z)
   */
  Cluster ClusterCache::FetchCluster(
    const SubclusterData& subclusterData
  )
  {
    if (mImpl.get() == nullptr) {
      return Cluster{};
    }
    return mImpl->FetchCluster(subclusterData);
  }

  /**
   * Address: 0x009542D0 (FUN_009542D0,
   * ?ClusterRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z_0)
   */
  gpg::Rect2i ClusterRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level,
    const int maxClusterX,
    const int maxClusterZ
  )
  {
    const std::uint8_t clusterSize =
      (level < kClusterSizeCount) ? kClusterSizeByLevel[level] : kClusterSizeByLevel[kClusterSizeCount - 1];
    const int alignMask = -static_cast<int>(clusterSize);
    const int clusterSizeSigned = static_cast<int>(clusterSize);

    gpg::Rect2i out{};
    out.z1 = (alignMask & (clusterSizeSigned + worldZ)) + 1;
    if (out.z1 >= maxClusterZ) {
      out.z1 = maxClusterZ;
    }

    out.x1 = (alignMask & (clusterSizeSigned + worldX)) + 1;
    if (out.x1 >= maxClusterX) {
      out.x1 = maxClusterX;
    }

    out.z0 = alignMask & (worldZ - 1);
    if (out.z0 < 0) {
      out.z0 = 0;
    }

    out.x0 = alignMask & (worldX - 1);
    if (out.x0 < 0) {
      out.x0 = 0;
    }

    return out;
  }

  /**
   * Address: 0x00954340 (FUN_00954340,
   * ?ClusterIndexRect@HaStar@gpg@@YA?AV?$Rect2@H@2@HHEHH@Z)
   */
  gpg::Rect2i ClusterIndexRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level,
    const int maxClusterX,
    const int maxClusterZ
  )
  {
    const std::uint8_t shift = (level < kClusterSizeLog2Count) ? kClusterSizeLog2ByLevel[level]
                                                               : kClusterSizeLog2ByLevel[kClusterSizeLog2Count - 1];

    gpg::Rect2i out{};
    out.z1 = (worldZ >> shift) + 1;
    if (out.z1 >= maxClusterZ) {
      out.z1 = maxClusterZ;
    }

    out.x1 = (worldX >> shift) + 1;
    if (out.x1 >= maxClusterX) {
      out.x1 = maxClusterX;
    }

    out.z0 = (worldZ - 1) >> shift;
    if (out.z0 < 0) {
      out.z0 = 0;
    }

    out.x0 = (worldX - 1) >> shift;
    if (out.x0 < 0) {
      out.x0 = 0;
    }

    return out;
  }

  /**
   * Address: 0x008E33E0 (FUN_008E33E0,
   * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@HHE@Z)
   */
  gpg::Rect2i ClusterMap::ClusterIndexRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level
  ) const
  {
    const std::uint8_t shift = (level < kClusterSizeLog2Count) ? kClusterSizeLog2ByLevel[level]
                                                               : kClusterSizeLog2ByLevel[kClusterSizeLog2Count - 1];

    return gpg::HaStar::ClusterIndexRect(worldX, worldZ, level, (mWidth >> shift), (mHeight >> shift));
  }

  /**
   * Address: 0x0092D8E0 (?DequantizeEdgeCost@Cluster@HaStar@gpg@@SAMHM@Z)
   *
   * What it does:
   * Inverts `QuantizeEdgeCost`. The 32 entries are `exp(q / 6)` for q in 0..31,
   * copied bit for bit from the table at 0x00E35DA0. Entries 1, 2, 3, 6 and 7
   * sit one to three ulps off the correctly rounded `exp(q / 6)`, so they are
   * written as hex floats rather than decimal approximations.
   */
  float Cluster::DequantizeEdgeCost(
    const int bucket,
    const float distance
  )
  {
    static constexpr float kBucketScale[32] = {
      0x1p+0f,        0x1.2e6d9cp+0f, 0x1.6546d4p+0f, 0x1.a61294p+0f, 0x1.f29eb2p+0f, 0x1.268662p+1f, 0x1.5bf0aap+1f,
      0x1.9b0aeep+1f, 0x1.e596eap+1f, 0x1.1ed3fep+2f, 0x1.52d8ecp+2f, 0x1.904d06p+2f, 0x1.d8e64cp+2f, 0x1.17551ap+3f,
      0x1.49fe06p+3f, 0x1.85d6fep+3f, 0x1.cc8a94p+3f, 0x1.10085cp+4f, 0x1.415e5cp+4f, 0x1.7ba6f2p+4f, 0x1.c0818ap+4f,
      0x1.08ec72p+5f, 0x1.38f864p+5f, 0x1.71bb0ep+5f, 0x1.b4c902p+5f, 0x1.020018p+6f, 0x1.30ca9cp+6f, 0x1.68118ap+6f,
      0x1.a95ee6p+6f, 0x1.f6842p+6f,  0x1.28d38ap+7f, 0x1.5ea8acp+7f,
    };

    return kBucketScale[bucket] * distance;
  }

  /**
   * Address: 0x007658D0 (FUN_007658D0)
   *
   * What it does:
   * Octile distance between two of a cluster's boundary nodes.
   */
  float Cluster::NodeOctileDistance(
    const Data& data,
    const std::uint32_t lhs,
    const std::uint32_t rhs
  )
  {
    const float deltaX = std::fabs(static_cast<float>(data.mNodes[rhs].x) - static_cast<float>(data.mNodes[lhs].x));
    const float deltaZ = std::fabs(static_cast<float>(data.mNodes[rhs].z) - static_cast<float>(data.mNodes[lhs].z));

    return (deltaZ <= deltaX) ? (deltaZ * 0.41421354f) + deltaX : (deltaX * 0.41421354f) + deltaZ;
  }

  /**
   * Address: 0x008E33B0 (FUN_008E33B0)
   *
   * What it does:
   * Cluster-aligned world rectangle containing the single cell `(x, z)`.
   */
  gpg::Rect2i ClusterMap::ClusterRect(
    const int worldX,
    const int worldZ,
    const std::uint8_t level
  ) const
  {
    return gpg::HaStar::ClusterRect(worldX, worldZ, level, mWidth, mHeight);
  }

  /**
   * Address: 0x008E3530 (FUN_008E3530,
   * ?ClusterRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
   */
  gpg::Rect2i ClusterMap::ClusterRect(
    const gpg::Rect2i& worldRect,
    const std::uint8_t level
  ) const
  {
    const int clusterSize = static_cast<int>(kClusterSizeByLevel[level]);
    const int alignMask = -clusterSize;

    gpg::Rect2i out{};
    out.z1 = (alignMask & (worldRect.z1 + clusterSize - 1)) + 1;
    if (out.z1 >= mHeight) {
      out.z1 = mHeight;
    }

    out.x1 = (alignMask & (worldRect.x1 + clusterSize - 1)) + 1;
    if (out.x1 >= mWidth) {
      out.x1 = mWidth;
    }

    out.z0 = alignMask & (worldRect.z0 - 1);
    if (out.z0 < 0) {
      out.z0 = 0;
    }

    out.x0 = alignMask & (worldRect.x0 - 1);
    if (out.x0 < 0) {
      out.x0 = 0;
    }

    return out;
  }

  /**
   * Address: 0x008E35A0 (FUN_008E35A0,
   * ?ClusterIndexRect@ClusterMap@HaStar@gpg@@QBE?AV?$Rect2@H@3@ABV43@E@Z)
   * Alt binary: 0x10035650 (FUN_10035650, ?...@Z_0)
   */
  gpg::Rect2i ClusterMap::ClusterIndexRect(
    const gpg::Rect2i& worldRect,
    const std::uint8_t level
  ) const
  {
    const std::uint8_t shift = kClusterSizeLog2ByLevel[level];

    gpg::Rect2i out{};
    out.z1 = ((worldRect.z1 - 1) >> shift) + 1;
    const int maxZ = (mHeight >> shift);
    if (out.z1 >= maxZ) {
      out.z1 = maxZ;
    }

    out.x1 = ((worldRect.x1 - 1) >> shift) + 1;
    const int maxX = (mWidth >> shift);
    if (out.x1 >= maxX) {
      out.x1 = maxX;
    }

    out.z0 = (worldRect.z0 - 1) >> shift;
    if (out.z0 < 0) {
      out.z0 = 0;
    }

    out.x0 = (worldRect.x0 - 1) >> shift;
    if (out.x0 < 0) {
      out.x0 = 0;
    }

    return out;
  }

  /**
   * Address: 0x008E3620 (FUN_008E3620,
   * ?DirtyRect@ClusterMap@HaStar@gpg@@QAEXABV?$Rect2@H@3@@Z_0)
   */
  void ClusterMap::DirtyRect(
    const gpg::Rect2i& worldRect
  )
  {
    gpg::Rect2i expandedRect{};
    expandedRect.x0 = mArea.x0 + worldRect.x0;
    expandedRect.z0 = mArea.z0 + worldRect.z0;
    expandedRect.x1 = mArea.x1 + worldRect.x1;
    expandedRect.z1 = mArea.z1 + worldRect.z1;

    mIsDone = 0u;

    if (mNumLevels == 0u) {
      return;
    }

    gpg::BitArray2D* levelBits = &mCheckLevels[1];
    for (std::uint8_t level = 1; level <= static_cast<std::uint8_t>(mNumLevels); ++level, ++levelBits) {
      const gpg::Rect2i clusterRect = ClusterIndexRect(expandedRect, level);
      levelBits->FillRect(
        clusterRect.x0, clusterRect.z0, clusterRect.x1 - clusterRect.x0, clusterRect.z1 - clusterRect.z0, true
      );
    }
  }

  /**
   * Address: 0x008E37D0 (FUN_008E37D0,
   * ?WorkOnCluster@ClusterMap@HaStar@gpg@@QAE_NHHHAAH@Z)
   */
  bool ClusterMap::WorkOnCluster(
    const int width,
    const int height,
    const int level,
    int& budget
  )
  {
    gpg::BitArray2D& checkLevel = mCheckLevels[level];
    const int bitMask = 1 << (height & 0x1F);
    const unsigned int rowWord = static_cast<unsigned int>(height) >> 5;
    const int bitIndex = width + static_cast<int>(rowWord * static_cast<unsigned int>(checkLevel.width));

    if ((checkLevel.ptr[bitIndex] & bitMask) == 0) {
      return true;
    }

    if (budget <= 0) {
      return false;
    }

    Cluster resolvedCluster{};

    if (level == 1) {
      OccupationData occupationData{};
      mSrc->GetOccupationData(8 * width, 8 * height, occupationData);
      resolvedCluster = mCache.FetchCluster(occupationData);
      budget -= 10;
    } else {
      SubclusterData subclusterData{};
      subclusterData.mLevel = level - 1;

      const Subcluster& childLevel = mLevels[level - 1];
      int writeIndex = 0;
      for (int childY = 4 * height; childY < 4 * height + 4; ++childY) {
        for (int childX = 4 * width; childX < 4 * width + 4; ++childX) {
          if (!WorkOnCluster(childX, childY, level - 1, budget)) {
            return false;
          }

          const int childIndex = childX + childY * childLevel.mWidth;
          AssignClusterData(subclusterData.mClusters[writeIndex], childLevel.mArray[childIndex]);
          ++writeIndex;
        }
      }

      resolvedCluster = mCache.FetchCluster(subclusterData);
      budget -= 10;
    }

    Subcluster& outLevel = mLevels[level];
    const int outIndex = width + height * outLevel.mWidth;
    AssignClusterData(outLevel.mArray[outIndex], resolvedCluster);

    (void)checkLevel.ClearBitAndReturnWord(width, static_cast<unsigned int>(height));
    return true;
  }

  void ClusterMap::SaveExact(
    gpg::WriteArchive* const archive
  ) const
  {
    archive->WriteBool(mIsDone != 0u);
    archive->WriteUInt(mProgress);

    for (std::uint32_t level = 1u; level <= mNumLevels; ++level) {
      const gpg::BitArray2D& bits = mCheckLevels[level];
      archive->WriteBytes(bits.ptr, static_cast<std::size_t>(bits.size) * sizeof(std::int32_t));

      const Subcluster& clusters = mLevels[level];
      const int count = clusters.mWidth * clusters.mHeight;
      for (int index = 0; index < count; ++index) {
        const Cluster::Data* const data = clusters.mArray[index].mData;
        if (data == nullptr) {
          archive->WriteUShort(0xFFFFu);
          continue;
        }

        const std::size_t nodes = data->mNodeCount;
        archive->WriteUShort(static_cast<unsigned short>(nodes));
        const std::size_t bytes =
          nodes * sizeof(Cluster::Node) + Cluster::TriangularSize(static_cast<std::uint32_t>(nodes));
        if (bytes != 0u) {
          archive->WriteBytes(&data->mNodes[0], bytes);
        }
      }
    }
  }

  void ClusterMap::LoadExact(
    gpg::ReadArchive* const archive,
    std::unordered_map<std::string, Cluster>& shared
  )
  {
    bool isDone = false;
    archive->ReadBool(&isDone);
    mIsDone = isDone ? 1u : 0u;
    archive->ReadUInt(&mProgress);

    std::string payload;
    for (std::uint32_t level = 1u; level <= mNumLevels; ++level) {
      gpg::BitArray2D& bits = mCheckLevels[level];
      archive->ReadBytes(bits.ptr, static_cast<std::size_t>(bits.size) * sizeof(std::int32_t));

      Subcluster& clusters = mLevels[level];
      const int count = clusters.mWidth * clusters.mHeight;
      for (int index = 0; index < count; ++index) {
        unsigned short nodes = 0u;
        archive->ReadUShort(&nodes);
        if (nodes == 0xFFFFu) {
          clusters.mArray[index] = Cluster{};
          continue;
        }

        const std::size_t nodeBytes = static_cast<std::size_t>(nodes) * sizeof(Cluster::Node);
        const std::size_t bytes = nodeBytes + Cluster::TriangularSize(nodes);
        payload.assign(bytes + 1u, '\0');
        payload[0] = static_cast<char>(nodes);
        if (bytes != 0u) {
          archive->ReadBytes(payload.data() + 1, bytes);
        }

        auto found = shared.find(payload);
        if (found == shared.end()) {
          std::vector<Cluster::Node> nodeList(nodes);
          std::vector<Cluster::Edge> edgeList((bytes - nodeBytes) / sizeof(Cluster::Edge));
          std::memcpy(nodeList.data(), payload.data() + 1, nodeBytes);
          std::memcpy(edgeList.data(), payload.data() + 1 + nodeBytes, bytes - nodeBytes);
          Cluster built{};
          built.SetData(nodeList.data(), edgeList.data(), nodes);
          found = shared.emplace(payload, built).first;
        }
        clusters.mArray[index] = found->second;
      }
    }
  }

  /**
   * Address: 0x008E3C00 (FUN_008E3C00,
   * ?BackgroundWork@ClusterMap@HaStar@gpg@@QAEXAAH@Z)
   */
  void ClusterMap::BackgroundWork(
    int& budget
  )
  {
    const bool unlimitedBudget = (budget == INT_MAX);

    while (mIsDone == 0u) {
      if (budget <= 0) {
        break;
      }

      unsigned int clusterX = 0u;
      unsigned int clusterY = 0u;
      if (mCheckLevels[mNumLevels].AnyBitSet(&clusterX, &clusterY, &mProgress)) {
        if (unlimitedBudget) {
          budget = INT_MAX;
        }

        (void)WorkOnCluster(
          static_cast<int>(clusterX), static_cast<int>(clusterY), static_cast<int>(mNumLevels), budget
        );
      } else {
        mIsDone = 1u;
      }
    }
  }
} // namespace gpg::HaStar

#include "PathTables.h"

#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/algorithms/AStarSearch.h"
#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/containers/TDatList.h"
#include "moho/path/ClusterMap.h"
#include "moho/path/IPathTraveler.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/sim/STIMap.h"

#ifdef _WIN32
#include <windows.h>
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

  struct SerSaveLoadHelperInitRuntimeView
  {
    void* mVTable = nullptr;                    // +0x00
    gpg::SerHelperBase* mHelperNext = nullptr; // +0x04
    gpg::SerHelperBase* mHelperPrev = nullptr; // +0x08
    gpg::RType::load_func_t mLoadCallback = nullptr; // +0x0C
    gpg::RType::save_func_t mSaveCallback = nullptr; // +0x10
  };
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperNext) == 0x04,
    "SerSaveLoadHelperInitRuntimeView::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mHelperPrev) == 0x08,
    "SerSaveLoadHelperInitRuntimeView::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mLoadCallback) == 0x0C,
    "SerSaveLoadHelperInitRuntimeView::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelperInitRuntimeView, mSaveCallback) == 0x10,
    "SerSaveLoadHelperInitRuntimeView::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SerSaveLoadHelperInitRuntimeView) == 0x14,
    "SerSaveLoadHelperInitRuntimeView size must be 0x14"
  );

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
   * Address: 0x007676A0 (FUN_007676A0) + 0x00767C70 (FUN_00767C70)
   *          0x007672E0 (FUN_007672E0)
   *
   * What it does:
   * Releases every search record and open-heap entry accumulated by the
   * previous query, leaving both structures armed for the next traveler.
   */
  void ResetPathQueueSearchState(PathQueueImplBaseRuntime& implBase)
  {
    implBase.ResetSearch();
  }

  /**
   * Address: 0x00765C30 (FUN_00765C30, Moho::PathQueue::ImplBase::~ImplBase)
   *
   * What it does:
   * Tears down the search structures owned by one `ImplBase`.
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
    std::int32_t mSize;                     // +0x00
    PathQueueIntrusiveNode mHeightSentinel; // +0x04
    // mBase now spans +0x0C..+0x88: the previous reconstruction stopped it at
    // +0x80 and padded the remainder, which hid `mExpandCount` / `mPathCap`.
    PathQueueImplBaseRuntime mBase;         // +0x0C
  };

  static_assert(sizeof(PathQueue::Impl) == 0x88, "PathQueue::Impl size must be 0x88");
  static_assert(offsetof(PathQueue::Impl, mSize) == 0x00, "PathQueue::Impl::mSize offset must be 0x00");
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
     * Address: 0x00767140 (FUN_00767140, gpg::SerSaveLoadHelper_PathQueue_Impl::Init)
     *
     * What it does:
     * Resolves reflected type metadata for `PathQueue::Impl`, installs
     * serializer callbacks from helper storage, and returns the load callback.
     */
    [[nodiscard]] gpg::RType::load_func_t InstallPathQueueImplSerializerCallbacks(
      SerSaveLoadHelperInitRuntimeView* const helper
    )
    {
      static gpg::RType* type = nullptr;
      if (type == nullptr) {
        type = gpg::LookupRType(typeid(PathQueue::Impl));
      }

      if (type->serLoadFunc_ != nullptr) {
        gpg::HandleAssertFailure("!type->mSerLoadFunc", 84, kSerializationHeaderPath);
      }

      const bool saveWasNull = type->serSaveFunc_ == nullptr;
      const gpg::RType::load_func_t loadCallback = helper->mLoadCallback;
      type->serLoadFunc_ = loadCallback;

      if (!saveWasNull) {
        gpg::HandleAssertFailure("!type->mSerSaveFunc", 87, kSerializationHeaderPath);
      }

      type->serSaveFunc_ = helper->mSaveCallback;
      return loadCallback;
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
      archive->ReadPointer_PathTables(
        reinterpret_cast<PathTables**>(&impl->mSize),
        &ownerRef
      );

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
      // The impl header lane at +0x00 holds the owning `PathTables*` in the
      // serialize context (IDA reads `[edi]` and hands it to RRef_PathTables).
      auto* const pathTables =
        reinterpret_cast<PathTables*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(impl->mSize)));

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
     * Source-level wiring for the `PathQueue::Impl` reflected serializer pair.
     *
     * The binary stores the address of the save callback (via the 0x00766BC0
     * calling-convention thunk over 0x00768AD0) and the load callback (via the
     * 0x00766BB0 trampoline over 0x00768A10) into the
     * `SerSaveLoadHelper_PathQueue_Impl` helper node's save/load lanes, which
     * `InstallPathQueueImplSerializerCallbacks` (0x00767140) then copies into
     * the reflected `Moho::PathQueue::Impl` type's `serSaveFunc_` /
     * `serLoadFunc_` slots. Taking the address of both callbacks here is the
     * source-level invocation (evidence class 2, function-pointer table) that
     * keeps them linked into the engine binary.
     */
    SerSaveLoadHelperInitRuntimeView gPathQueueImplSaveHelper{};

    /**
     * Populates the `PathQueue::Impl` serializer helper node's save and load
     * lanes with the recovered callback addresses, mirroring the binary's
     * startup helper-node population. Installing the lanes onto the live
     * reflected type is deferred to `InstallPathQueueImplSerializerCallbacks`,
     * which the engine runs once the `Moho::PathQueue::Impl` type descriptor is
     * registered.
     */
    SerSaveLoadHelperInitRuntimeView* PopulatePathQueueImplSerializerCallbackStorage() noexcept
    {
      gPathQueueImplSaveHelper.mLoadCallback =
        reinterpret_cast<gpg::RType::load_func_t>(&DeserializePathQueueImplRefCallback);
      gPathQueueImplSaveHelper.mSaveCallback =
        reinterpret_cast<gpg::RType::save_func_t>(&SavePathQueueImplRefCallback);
      return &gPathQueueImplSaveHelper;
    }

    [[maybe_unused]] gpg::RType::load_func_t InstallPathQueueImplSerializerLifecycleCallbacks()
    {
      return InstallPathQueueImplSerializerCallbacks(PopulatePathQueueImplSerializerCallbackStorage());
    }

    struct PathQueueImplSerializerCallbackBootstrap
    {
      PathQueueImplSerializerCallbackBootstrap() noexcept
      {
        (void)PopulatePathQueueImplSerializerCallbackStorage();
      }
    };

    [[maybe_unused]] PathQueueImplSerializerCallbackBootstrap gPathQueueImplSerializerCallbackBootstrap;

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
  [[maybe_unused]] std::uint32_t* CopyOccupySourceBindingPayloadRangeBackwardRuntime(
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

  template <typename T>
  bool ResizeLegacyVectorStorage(LegacyVectorStorage<T>& storage, const std::size_t count, const T& fillValue)
  {
    if (count == 0u) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return true;
    }

    auto* const begin = static_cast<T*>(::operator new(sizeof(T) * count, std::nothrow));
    if (begin == nullptr) {
      storage.mFirst = nullptr;
      storage.mLast = nullptr;
      storage.mEnd = nullptr;
      return false;
    }

    T* current = begin;
    for (std::size_t i = 0; i < count; ++i, ++current) {
      ::new (current) T(fillValue);
    }

    storage.mFirst = begin;
    storage.mLast = begin + count;
    storage.mEnd = begin + count;
    return true;
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
   * When `newSize <= current size`, calls the range-erase helper (FUN_0076C430) on
   * the tail. When `newSize > current size`, forwards to the `_Insert_n` grow path
   * (FUN_0076C490) with the prefilled binding. Each binding is 16 bytes.
   */
  void ResizeOccupySourceBindingVectorWithFill(
    LegacyVectorStorage<moho::OccupySourceBinding>& storage,
    const std::size_t newSize,
    const moho::OccupySourceBinding& fillValue
  )
  {
    (void)ResizeLegacyVectorStorage(storage, newSize, fillValue);
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
   * Address: 0x0076CBA0 (FUN_0076CBA0)
   *
   * What it does:
   * Fills `count` contiguous `OccupySourceBinding` lanes from one prototype
   * binding and returns one-past the final destination lane.
   */
  [[maybe_unused]] moho::OccupySourceBinding* FillOccupySourceBindingRangeFromPrototype(
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
    : mSize(0)
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
  PathQueue::PathQueue(const int size)
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
    impl->mSize = size;
    mImpl = impl;
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
   * Resets impl vector lanes (`mSources`, `mMaps`) to empty null ranges.
   */
  PathTablesImpl::PathTablesImpl()
  {
    mSources.mFirst = nullptr;
    mSources.mLast = nullptr;
    mSources.mEnd = nullptr;

    mMaps.mFirst = nullptr;
    mMaps.mLast = nullptr;
    mMaps.mEnd = nullptr;
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

      cluster->DirtyRect(dirtyRect);
    }
  }

  // Static cached RType slot for the placeholder `PathQueue` type;
  // populated lazily by `gpg::RRef_PathQueue` via cached lookup.
  gpg::RType* PathQueue::sType = nullptr;
} // namespace moho

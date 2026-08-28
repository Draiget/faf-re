#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"
#include "moho/sim/IdPool.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Entity;
  class EntitySetBase;
  struct SEntitySetTemplateUnit;
  struct BVIntSetAddResult;
  class Prop;
  class CArmyImpl;
  class Sim;
  class Unit;
  struct CEntityDbBoundedPropQueueNode;

  struct CEntityDbListHead
  {
    CEntityDbListHead* next; // +0x00
    CEntityDbListHead* prev; // +0x04
  };
  static_assert(sizeof(CEntityDbListHead) == 0x08, "CEntityDbListHead size must be 0x08");

  struct CEntityDbAllUnitsNode : msvc8::Tree<CEntityDbAllUnitsNode>
  {
    std::uint32_t key;      // +0x0C
    void* unitListNode;     // +0x10 (points to intrusive unit list node)
    std::uint8_t color;     // +0x14
    std::uint8_t isNil;     // +0x15
    std::uint8_t pad_16[2]; // +0x16
  };

  static_assert(offsetof(CEntityDbAllUnitsNode, key) == 0x0C, "CEntityDbAllUnitsNode::key offset must be 0x0C");
  static_assert(
    offsetof(CEntityDbAllUnitsNode, unitListNode) == 0x10, "CEntityDbAllUnitsNode::unitListNode offset must be 0x10"
  );
  static_assert(sizeof(CEntityDbAllUnitsNode) == 0x18, "CEntityDbAllUnitsNode size must be 0x18");

  struct CEntityDbEntityListRuntime
  {
    std::uint32_t iteratorProxy; // +0x00
    CEntityDbListHead* head;     // +0x04
    std::uint32_t size;          // +0x08
  };
  static_assert(sizeof(CEntityDbEntityListRuntime) == 0x0C, "CEntityDbEntityListRuntime size must be 0x0C");

  /**
   * Binary layout of `gpg::PriorityQueue<Moho::SPropPriorityInfo,
   * Moho::WeakPtr<Moho::Prop>>` as used by `EntityDB::mBoundedProps`: a
   * min-heap of `CEntityDbBoundedPropQueueNode` ordered by
   * `(mPriority, mBoundedTick)`, plus a stable-id -> heap-index map
   * (`handleSlots`, doubling as a free list via `lastHandle`) that lets a
   * `Handle` returned by `Insert` keep resolving to the right node across
   * heap reorders.
   */
  struct CEntityDbBoundedPropQueueRuntime
  {
    msvc8::vector<CEntityDbBoundedPropQueueNode> heap; // +0x00 (proxy +0x00, first +0x04, last +0x08, end +0x0C)
    msvc8::vector<std::int32_t> handleSlots;           // +0x10 (proxy +0x10, first +0x14, last +0x18, end +0x1C)
    std::int32_t lastHandle = -1;                      // +0x20

    /**
     * Address: 0x00685980 (FUN_00685980)
     *
     * What it does:
     * The binary's "initialize to empty" lane sets the pointer triples null
     * and seeds `lastHandle` to `-1`; the default-constructed `heap` and
     * `handleSlots` members already start empty, so only `lastHandle`'s
     * default member initializer above is needed to reproduce it.
     */
    CEntityDbBoundedPropQueueRuntime() noexcept = default;

    /**
     * Address: 0x00684360 (FUN_00684360)
     *
     * What it does:
     * Releases the bounded-prop queue lanes: unlinks each node's
     * owner-chain link, then empties `heap` and `handleSlots` (which frees
     * their backing storage).
     */
    void Reset() noexcept;

    /**
     * Address: 0x006859F0 (FUN_006859F0)
     *
     * What it does:
     * Inserts one (priority, boundedTick, prop) entry into the bounded
     * reclaim-priority queue: acquires a handle id, links a temporary weak
     * pointer to `prop` at the head of its owner observer chain, copies that
     * linked snapshot into a fresh node appended to `heap` (growing storage
     * when full), unlinks the temporary from the chain again, then restores
     * the heap invariant by sifting the new node up. Returns the acquired
     * handle id.
     *
     * Sole caller: `Moho::EntityDB::AddBoundedProp` (0x00684C30), which
     * calls this at 0x00684CCF.
     */
    [[nodiscard]] std::int32_t Insert(std::int32_t priority, std::int32_t boundedTick, Prop* prop) noexcept;

    /**
     * Address: 0x006867F0 (FUN_006867F0)
     *
     * What it does:
     * Removes the queue node at `index`: swaps it with the tail node
     * (unless already the tail) and sifts the moved node back down to
     * restore the heap invariant, releases the removed node's handle id
     * back to the free-handle list, unlinks the removed node's owner-chain
     * link, then shrinks `heap` by one node.
     *
     * Common inner step of `AddBoundedProp` (evict head when queue is
     * full), `RemoveBoundedProp` (explicit removal by handle), and
     * `Prop::~Prop` (auto-unregister on prop destruction).
     */
    void PopAt(std::int32_t index) noexcept;

  private:
    /**
     * Address: 0x00686790 (FUN_00686790, sub_686790)
     *
     * What it does:
     * Acquires one handle slot from the free-list lane when available;
     * otherwise appends one new handle slot via `handleSlots.push_back` and
     * returns its index. See definition for full evidence.
     */
    [[nodiscard]] std::int32_t AcquireHandle(std::int32_t payload) noexcept;

    /**
     * Address: 0x00686740 (FUN_00686740, sub_686740)
     *
     * What it does:
     * Sifts one priority-queue entry up toward the root using
     * `(priority, boundedTick)` ordering. See definition for full evidence.
     */
    [[nodiscard]] std::int32_t SiftUp(std::int32_t index) noexcept;

    /**
     * Address: 0x006875F0 (FUN_006875F0)
     *
     * What it does:
     * Sifts the node at `index` down toward the leaves using
     * `(priority, boundedTick)` ordering -- at each level, swaps with
     * whichever child sorts lower -- until the heap invariant is restored
     * or a leaf is reached. `count` is the current node count.
     */
    void SiftDown(std::int32_t index, std::int32_t count) noexcept;

    /**
     * Address: 0x00687530 (FUN_00687530, sub_687530)
     *
     * What it does:
     * Exchanges two heap slots (owner-chain relink + position-map rewrite
     * for both). See definition for full evidence.
     */
    void Swap(std::int32_t lhs, std::int32_t rhs) noexcept;
  };
  static_assert(
    sizeof(CEntityDbBoundedPropQueueRuntime) == 0x24, "CEntityDbBoundedPropQueueRuntime size must be 0x24"
  );
  static_assert(offsetof(CEntityDbBoundedPropQueueRuntime, heap) == 0x00, "CEntityDbBoundedPropQueueRuntime::heap offset must be 0x00");
  static_assert(offsetof(CEntityDbBoundedPropQueueRuntime, handleSlots) == 0x10, "CEntityDbBoundedPropQueueRuntime::handleSlots offset must be 0x10");
  static_assert(offsetof(CEntityDbBoundedPropQueueRuntime, lastHandle) == 0x20, "CEntityDbBoundedPropQueueRuntime::lastHandle offset must be 0x20");

  /**
   * Iterator payload used by all-army unit scans against `CEntityDb::mAllUnits`.
   */
  class CUnitIterAllArmies
  {
  public:
    /**
     * Address: 0x006B69D0 (FUN_006B69D0, Moho::CUnitIterAllArmies::CUnitIterAllArmies)
     *
     * What it does:
     * Initializes one all-armies iterator lane for a specific army source id
     * by taking `[source, source + 1)` bounds inside `CEntityDb::mAllUnits`.
     */
    explicit CUnitIterAllArmies(CArmyImpl* army);

    /**
     * Address: 0x006B6AA0 (FUN_006B6AA0, Moho::CUnitIterAllArmies::CUnitIterAllArmies)
     *
     * What it does:
     * Initializes one all-armies unit iterator from `sim->mEntityDB` by
     * capturing the leftmost all-units tree node, iterator end sentinel, and
     * current decoded unit payload.
     */
    explicit CUnitIterAllArmies(Sim* sim);

    /**
     * Address: 0x005C87A0 (FUN_005C87A0, Moho::CUnitIterAllArmies::Next)
     *
     * What it does:
     * Advances to the next all-units tree node and refreshes `mCur`.
     */
    void Next() noexcept;

  public:
    CEntityDbAllUnitsNode* mItr; // +0x00
    CEntityDbAllUnitsNode* mEnd; // +0x04
    Unit* mCur;                  // +0x08
  };

  static_assert(sizeof(CUnitIterAllArmies) == 0x0C, "CUnitIterAllArmies size must be 0x0C");
  static_assert(offsetof(CUnitIterAllArmies, mItr) == 0x00, "CUnitIterAllArmies::mItr offset must be 0x00");
  static_assert(offsetof(CUnitIterAllArmies, mEnd) == 0x04, "CUnitIterAllArmies::mEnd offset must be 0x04");
  static_assert(offsetof(CUnitIterAllArmies, mCur) == 0x08, "CUnitIterAllArmies::mCur offset must be 0x08");

  class CEntityDb
  {
  public:
    // Reflection RTTI cache slot -- confirmed against the real
    // `EntityDBSerializer::Init()` body (0x00686010), which reads/writes
    // `Moho::EntityDB::sType` directly (not a local/file-static cache).
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x00684230 (FUN_00684230, Moho::EntityDB::EntityDB)
     *
     * What it does:
     * Constructs all tree/list sentinel lanes and clears bounded-prop queue
     * ranges for a fresh EntityDB instance.
     */
    CEntityDb();

    /**
     * Address: 0x006843B0 (FUN_006843B0, Moho::EntityDB::~EntityDB)
     *
     * What it does:
     * Tears down bounded-prop/entity-list/id-pool/all-units lanes and clears
     * DB-owned runtime tracking maps.
     */
    ~CEntityDb();

    /**
     * Address: 0x00684560 (FUN_00684560)
     * Mangled: ?Purge@EntityDB@Moho@@QAEXXZ
     *
     * What it does:
     * Compacts registered entity-set payloads to remove destroy-dispatched
     * entities, destroys every tracked entity, and advances the DB id-pool
     * lanes.
     */
    void Purge();

    /**
     * Address: 0x00684C30 (FUN_00684C30, Moho::EntityDB::AddBoundedProp)
     *
     * What it does:
     * Inserts one Prop into the bounded reclaim-priority queue and evicts head
     * entries while queue occupancy is at least 1000.
     */
    [[nodiscard]] std::int32_t AddBoundedProp(Prop* prop);

    /**
     * Address: 0x00684CE0 (FUN_00684CE0, ?RemoveBoundedProp@EntityDB@Moho@@QAEXW4Handle@?$PriorityQueue@USPropPriorityInfo@Moho@@V?$WeakPtr@VProp@Moho@@@2@@gpg@@@Z)
     * Mangled: ?RemoveBoundedProp@EntityDB@Moho@@QAEXW4Handle@?$PriorityQueue@USPropPriorityInfo@Moho@@V?$WeakPtr@VProp@Moho@@@2@@gpg@@@Z
     *
     * What it does:
     * Removes one bounded-prop queue lane by handle when the handle resolves
     * to a live entry.
     */
    void RemoveBoundedProp(std::int32_t handle);

    /**
     * Address: 0x00684480 (FUN_00684480, ?DoReserveId@EntityDB@Moho@@AAE?AVEntId@2@I@Z)
     *
     * What it does:
     * Reserves a new entity id in the requested packed-id family/source key
     * (`[31..28]=family`, `[27..20]=source`).
     */
    [[nodiscard]] std::uint32_t DoReserveId(std::uint32_t requestedFamilySourceBits);

    /**
     * Address: 0x00684690 (FUN_00684690, Moho::EntityDB::ReleaseId)
     * Mangled: ?ReleaseId@EntityDB@Moho@@QAEXVEntId@2@@Z
     *
     * What it does:
     * Releases one packed entity id, updates entity-count stats, removes
     * matching runtime entity tracking entries, and queues the serial lane for
     * reuse in this family/source id pool.
     */
    [[nodiscard]] BVIntSetAddResult ReleaseId(std::uint32_t releasedId);

    /**
     * Address: 0x00683C90 (FUN_00683C90,
     * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ)
     *
     * What it does:
     * Returns the lower-bound tree iterator node for `sourceIndex << 20`.
     */
    [[nodiscard]] CEntityDbAllUnitsNode* AllUnitsEnd(std::uint32_t sourceIndex) const;

    /**
     * Address: 0x00683D10 (FUN_00683D10,
     * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ_0)
     *
     * What it does:
     * Returns the lower-bound tree iterator node for the first non-unit family key
     * (`EEntityIdSentinel::FirstNonUnitFamily`, value `0x10000000`).
     */
    [[nodiscard]] CEntityDbAllUnitsNode* AllUnitsEnd() const;

    /**
      * Alias of FUN_005C87A0 (non-canonical helper lane).
     *
     * What it does:
     * Advances one all-units tree iterator node to its in-order successor.
     */
    [[nodiscard]]
    static CEntityDbAllUnitsNode* NextAllUnitsNode(CEntityDbAllUnitsNode* node) noexcept;

    /**
      * Alias of FUN_005C87A0 (non-canonical helper lane).
     *
     * What it does:
     * Converts one all-units tree node payload into the owning `Unit*`.
     */
    [[nodiscard]]
    static Unit* UnitFromAllUnitsNode(const CEntityDbAllUnitsNode* node) noexcept;

    /**
     * Address: 0x00686EF0 (FUN_00686EF0, sub_686EF0)
     *
     * What it does:
     * Erases `[first, last)` from the `mAllUnits` RB-tree. Takes the O(1)
     * whole-tree fast path (recursive subtree destroy + sentinel reset) when
     * erasing the full range (`first == begin() && last == end()`);
     * otherwise advances to each node's successor before erasing it, so the
     * walk stays valid across the erase. Returns the node that followed the
     * erased range. MSVC8 `std::_Tree<EntId, Entity*>::erase(iterator, iterator)`.
     */
    CEntityDbAllUnitsNode* EraseAllUnitsRange(CEntityDbAllUnitsNode* first, CEntityDbAllUnitsNode* last);

    /**
     * Address: 0x006856C0 (FUN_006856C0)
     * Mangled: ?find@?$map@VEntId@Moho@@PAVEntity@2@@std@@QAE?AViterator@12@ABVEntId@Moho@@@Z
     *
     * IDA signature:
     * std::map_EntId_Entity::_Node **__usercall find@<eax>(
     *     _Node **result@<eax>, std::map_EntId_Entity *this@<ecx>, unsigned int *id@<ebx>);
     *
     * What it does:
     * Looks one entity id up in the all-units tree and returns the entity
     * stored in that node, or `nullptr` when the id is absent (the binary
     * returns the head node, i.e. `end()`, in that case).
     */
    [[nodiscard]] Entity* FindEntityById(std::uint32_t entityId) const noexcept;

    [[nodiscard]] msvc8::list<Entity*>& Entities() noexcept;
    [[nodiscard]] const msvc8::list<Entity*>& Entities() const noexcept;

    /**
     * What it does:
     * Registers one intrusive entity-set node in the DB-owned set registry.
     */
    void RegisterEntitySet(SEntitySetTemplateUnit& set) noexcept;

    /**
     * What it does:
     * Registers one `EntitySetBase` intrusive node in the DB-owned set registry.
     */
    void RegisterEntitySet(EntitySetBase& set) noexcept;

    /**
     * Address: 0x00689760 (FUN_00689760, Moho::EntityDB::MemberDeserialize)
     *
     * What it does:
     * Loads EntityDB-owned entity/id-pool/set payload lanes from a read archive.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006897F0 (FUN_006897F0, Moho::EntityDB::MemberSerialize)
     *
     * What it does:
     * Saves EntityDB-owned entity/id-pool/set payload lanes into a write archive.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00684AA0 (FUN_00684AA0, Moho::EntityDB::SerEntities read lane)
     *
     * What it does:
     * Reads the entity-id + owned-entity pointer stream until sentinel id `0xF0000000`.
     */
    void SerEntities(gpg::ReadArchive* archive);

    /**
     * Address: 0x006849C0 (FUN_006849C0, Moho::EntityDB::SerEntities write lane)
     *
     * What it does:
     * Writes the entity-id + owned-entity pointer stream and appends sentinel id
     * `0xF0000000`.
     */
    void SerEntities(gpg::WriteArchive* archive);

    /**
     * Address: 0x00684B40 (FUN_00684B40, Moho::EntityDB::SerSets read lane)
     *
     * What it does:
     * Reads unowned `EntitySetBase` pointers and links them into the registered
     * intrusive set list.
     */
    void SerSets(gpg::ReadArchive* archive);

    /**
     * Address: 0x00684BC0 (FUN_00684BC0, Moho::EntityDB::SerSets write lane)
     *
     * What it does:
     * Writes registered intrusive `EntitySetBase` pointers as an unowned pointer
     * stream terminated by `nullptr`.
     */
    void SerSets(gpg::WriteArchive* archive);

  public:
    std::uint32_t mAllUnitsIteratorProxy;           // +0x00
    CEntityDbAllUnitsNode* mAllUnits;               // +0x04
    std::uint32_t mAllUnitsSize;                    // +0x08
    // `std::map<unsigned int, Moho::IdPool>` (`Moho::EntityDB::mIdPool` in the
    // binary). Confirmed against `gpg/core/containers/ArchiveSerialization.cpp`
    // and `EntityDb.cpp`'s own reflection typing, both of which read this field
    // through `typeid(std::map<unsigned int, moho::IdPool>)`. Real tree-insert
    // machinery: `FUN_006870D0` (insert_unique), `FUN_00687280` (insert_at),
    // `FUN_006881C0` (buy_node), `FUN_006880A0`/`FUN_00688120` (rotate_left/
    // rotate_right) -- all cited on `legacy/containers/RbTree.h`'s shared
    // members, not reimplemented here (RULE ONE).
    msvc8::map<std::uint32_t, IdPool> mIdPoolTree;  // +0x0C
    CEntityDbListHead mRegisteredEntitySets;        // +0x18
    CEntityDbEntityListRuntime mEntityList;         // +0x20
    CEntityDbBoundedPropQueueRuntime mBoundedProps; // +0x2C
  };

  static_assert(offsetof(CEntityDb, mAllUnits) == 0x04, "CEntityDb::mAllUnits offset must be 0x04");
  static_assert(offsetof(CEntityDb, mIdPoolTree) == 0x0C, "CEntityDb::mIdPoolTree offset must be 0x0C");
  static_assert(
    offsetof(CEntityDb, mRegisteredEntitySets) == 0x18, "CEntityDb::mRegisteredEntitySets offset must be 0x18"
  );
  static_assert(offsetof(CEntityDb, mEntityList) == 0x20, "CEntityDb::mEntityList offset must be 0x20");
  static_assert(offsetof(CEntityDb, mBoundedProps) == 0x2C, "CEntityDb::mBoundedProps offset must be 0x2C");
  static_assert(sizeof(CEntityDb) == 0x50, "CEntityDb size must be 0x50");

  /**
   * VFTABLE: 0x00E27980
   * COL: 0x00E8D0F0
   *
   * `vtable_writers` for `EntityDBSerializer@Moho` shows two writers:
   * `FUN_00BD51A0` (real, `__xc_a`-reachable via one incoming xref) and
   * `FUN_00684930` (zero incoming xrefs, unreachable -- dead COMDAT twin,
   * marked `skip`). `FUN_00686010.xrefs.txt` shows this class's own
   * `??_7EntityDBSerializer@Moho@@6B@` vtable slot 0 AND the separately
   * emitted (never directly named in source) `gpg::SerSaveLoadHelper<Moho::
   * EntityDB>` intermediate vtable's slot 0 both point at the exact same
   * address (0x00686010) -- so this class does not override `Init()` with
   * any class-specific logic, it is the plain generic
   * `gpg::SerSaveLoadHelper<T>::Init()` body. Deserialize/Serialize
   * (0x00684910/0x00684920) likewise just forward to
   * `CEntityDb::MemberDeserialize`/`MemberSerialize`, matching the generic
   * template's `T::MemberDeserialize`/`MemberSerialize` calls exactly. Kept
   * as its own concrete `SerHelperBase` derivative rather than the
   * `gpg::SerSaveLoadHelper<CEntityDb>` alias (the `BVIntSetSerializer`
   * shape) because `CEntityDb::MemberSerialize` is not `const`-qualified
   * (it folds `gRuntimePools` back into `mIdPoolTree` before writing) and
   * the generic template's `Serialize()` requires a `const T*` call --
   * forcing that would mean changing already-recovered `MemberSerialize`
   * behavior, which is out of scope here.
   */
  class EntityDBSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD51A0 (FUN_00BD51A0, dynamic initializer for the global
     * `EntityDBSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    EntityDBSerializer();

    /**
     * Address: 0x00BFCAD0 (FUN_00BFCAD0, Moho::EntityDBSerializer::~EntityDBSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~EntityDBSerializer();

    /**
     * Address: 0x00684910 (FUN_00684910, Moho::EntityDBSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load flow into `CEntityDb::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00684920 (FUN_00684920, Moho::EntityDBSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save flow into `CEntityDb::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00686010 (FUN_00686010, gpg::SerSaveLoadHelper_EntityDB::Init)
     *
     * What it does:
     * Resolves `EntityDB` RTTI (caching on `CEntityDb::sType`) and installs
     * this helper's load/save callbacks onto that type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };
  static_assert(
    offsetof(EntityDBSerializer, mDeserialize) == 0x0C, "EntityDBSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityDBSerializer, mSerialize) == 0x10, "EntityDBSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EntityDBSerializer) == 0x14, "EntityDBSerializer size must be 0x14");

  /**
   * Address: 0x00BD51A0 (FUN_00BD51A0, register_EntityDBSerializer)
   *
   * What it does:
   * Forces this translation unit's global `EntityDBSerializer` instance to
   * link into the reflection bootstrap sequence. The ctor/vtable-install/
   * atexit-dtor-registration sequence this address decompiles to is MSVC's
   * own compiler-generated dynamic initializer for that global, not
   * hand-written source -- see `gpg::SerSaveLoadHelper<T>` in Reflection.h,
   * which documents the same shape for other real instantiations
   * (`BVIntSetSerializer`, etc).
   */
  void register_EntityDBSerializer();
} // namespace moho

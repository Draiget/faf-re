#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"
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
     * Address: 0x00684360 (FUN_00684360 -- the implicit destructor, emitted
     * out of line with `this` in EDI and called only from `~EntityDB`
     * 0x006843B0 for `mBoundedProps`. Members go last-declared first:
     * `handleSlots`' storage is freed, then `heap`'s nodes are destroyed
     * through `destroy_range` 0x006892E0, each `WeakPtr<Prop>` unlinking
     * itself, and its storage freed. Formerly `Reset()`, which `~EntityDB`
     * called by hand and which tore `heap` down first, removed 2026-09-30.)
     */
    ~CEntityDbBoundedPropQueueRuntime() = default;

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
   * Iterator payload used by all-army unit scans against `EntityDB::mAllUnits`.
   */
  class CUnitIterAllArmies
  {
  public:
    /**
     * Address: 0x006B69D0 (FUN_006B69D0, Moho::CUnitIterAllArmies::CUnitIterAllArmies)
     *
     * What it does:
     * Initializes one all-armies iterator lane for a specific army source id
     * by taking `[source, source + 1)` bounds inside `EntityDB::mAllUnits`.
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

  class EntityDB
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
    EntityDB();

    /**
     * Address: 0x006843B0 (FUN_006843B0, Moho::EntityDB::~EntityDB)
     *
     * What it does:
     * Tears down bounded-prop/entity-list/id-pool/all-units lanes and clears
     * DB-owned runtime tracking maps.
     */
    ~EntityDB();

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
     * The `mAllUnits` header sentinel, typed as the node view the
     * family-boundary iterators walk. Never null: the map allocates its
     * head in its constructor (`FUN_00684230` line 1).
     */
    [[nodiscard]] CEntityDbAllUnitsNode* AllUnitsHead() const noexcept;

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
    // `std::map<Moho::EntId, Moho::Entity*>` (`Moho::EntityDB::mAllUnits` in
    // the binary). `DoReserveId` (0x00684480) inserts `{id, nullptr}` through
    // `sub_685350` (insert_unique), `Entity::StandardInit` (0x00678370) stores
    // the entity into `find(id)->second`, `ReleaseId` (0x00684690) erases the
    // node through `sub_685410` (erase_node), and every id lookup in the sim
    // is `std::map_EntId_Entity::find` (0x006856C0). The node layout is the
    // `CEntityDbAllUnitsNode` view below (`AllUnitsHead()` hands it out for
    // the family-boundary iterators).
    msvc8::map<std::uint32_t, Entity*> mAllUnits;    // +0x00
    // `std::map<unsigned int, Moho::IdPool>` (`Moho::EntityDB::mIdPool` in the
    // binary). Confirmed against `gpg/core/containers/ArchiveSerialization.cpp`
    // and `EntityDb.cpp`'s own reflection typing, both of which read this field
    // through `typeid(std::map<unsigned int, moho::IdPool>)`. Real tree-insert
    // machinery: `FUN_006870D0` (insert_unique), `FUN_00687280` (insert_at),
    // `FUN_006881C0` (buy_node), `FUN_006880A0`/`FUN_00688120` (rotate_left/
    // rotate_right) -- all cited on `legacy/containers/RbTree.h`'s shared
    // members, not reimplemented here (RULE ONE).
    msvc8::map<std::uint32_t, IdPool> mIdPoolTree;  // +0x0C
    // Every live entity set (`EntitySetBase` and each `EntitySetTemplate<T>`),
    // for `Purge` to drop destroyed entities from and `SerSets` to save.
    TDatList<EntitySetBase, void> mRegisteredEntitySets; // +0x18
    // `std::list<Moho::Entity*>` (`Moho::EntityDB::mEntList`): the entities
    // waiting for `Purge` to destroy them. `Entity::OnDestroy` (0x00679B80)
    // appends with `push_back`, `Purge` (0x00684560) drains it, and
    // `MemberSerialize` (0x006897F0) writes it whole at `this + 0x20`. Every
    // live entity is in `mAllUnits`, not here.
    msvc8::list<Entity*> mEntList;                  // +0x20
    CEntityDbBoundedPropQueueRuntime mBoundedProps; // +0x2C
  };

  static_assert(offsetof(EntityDB, mAllUnits) == 0x00, "EntityDB::mAllUnits offset must be 0x00");
  static_assert(sizeof(msvc8::map<std::uint32_t, Entity*>) == 0x0C, "EntityDB::mAllUnits must be the 12-byte MSVC8 map header");
  static_assert(offsetof(EntityDB, mIdPoolTree) == 0x0C, "EntityDB::mIdPoolTree offset must be 0x0C");
  static_assert(
    offsetof(EntityDB, mRegisteredEntitySets) == 0x18, "EntityDB::mRegisteredEntitySets offset must be 0x18"
  );
  static_assert(offsetof(EntityDB, mEntList) == 0x20, "EntityDB::mEntList offset must be 0x20");
  static_assert(offsetof(EntityDB, mBoundedProps) == 0x2C, "EntityDB::mBoundedProps offset must be 0x2C");
  static_assert(sizeof(EntityDB) == 0x50, "EntityDB size must be 0x50");

} // namespace moho

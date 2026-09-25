#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/containers/TDatList.h"
#include "Wm3Box2.h"
#include "Wm3Circle2.h"
#include "Wm3Vector2.h"

namespace moho
{
#if INTPTR_MAX == INT32_MAX
#define MOHO_VISIONDB_X86_ASSERT(...) static_assert(__VA_ARGS__)
#else
#define MOHO_VISIONDB_X86_ASSERT(...) static_assert(true)
#endif

  /**
   * VFTABLE: 0x00E422AC
   * COL:     0x00E98CA0
   *
   * The user-side vision database: a loose tree of circles over the map.
   * `Init` lays down the structural quadtree nodes, every vision-granting user
   * entity owns one emitter entry through a `Handle`, and the fog-of-war
   * renderer walks the tree each frame (`TryAdd`).
   */
  class VisionDB
  {
  public:
    class Handle;

    /**
     * One 0x28-byte node of the vision tree (IDA's `VisionDB::Entry`, also
     * `struct1`). The tree is intrusive: a node points at its parent, at the
     * first node of the chain it contains, and at the next node of its own
     * chain. A node sits under the deepest node whose circles contain both of
     * its own.
     *
     * Each node carries two circles, the previous and current samples of the
     * same moving circle; `TryAdd` interpolates between them. They are
     * `Wm3::Circle2f`: the binary builds them through that type's
     * `(center, radius)` constructor, emitted in this TU at 0x0081A7E0.
     */
    struct Entry
    {
      /**
       * Address: 0x0081AB70 (FUN_0081AB70)
       *
       * What it does:
       * Zeroes the links, both flags and both circles. `Pool::NewEntry` hands
       * it to the vector constructor iterator (`push 0x81AB70` at 0x0081AA4B)
       * for every block it allocates.
       */
      Entry() noexcept;

      /**
       * Empty, but user-provided on purpose: `new Entry[500]` in
       * `Pool::NewEntry` stores the element count ahead of the block and
       * passes this destructor (folded into the shared `ret`, nullsub_3 at
       * 0x006610E0) to the EH vector iterators there and in `~Pool`. A
       * defaulted destructor would be trivial and drop both.
       */
      ~Entry() {}

      /**
       * Whether both of this node's circles enclose `other`'s. Inlined at
       * every use (`PutInChain`, `Handle::Update`); the per-circle test has an
       * uncalled out-of-line copy at 0x0081A7F0.
       */
      [[nodiscard]] bool Contains(const Entry& other) const noexcept;

      /**
       * Address: 0x0081A8C0 (FUN_0081A8C0)
       * Address: 0x103E38B0
       *
       * What it does:
       * Appends `entry` after the last node of the chain this node is in;
       * `entry` joins that chain's parent.
       */
      void AddToChain(Entry* entry) noexcept;

      /**
       * Makes `entry` the first node this one contains, or appends it to the
       * chain it already contains. Every caller inlines it (`PutInChain`,
       * `RemoveFromChain`, `GenerateQuadTree`); the binary also keeps an
       * uncalled out-of-line copy at 0x0081A890.
       */
      void AddContained(Entry* entry) noexcept;

      /**
       * Address: 0x0081A8E0 (FUN_0081A8E0)
       * Address: 0x103E38D0
       *
       * What it does:
       * Unlinks `entry` from the chain this node contains. The nodes `entry`
       * contained move up into this node's chain, and `entry` is left with
       * no links.
       */
      void RemoveFromChain(Entry* entry) noexcept;

      /**
       * Takes this node out of its parent's chain. `Handle::~Handle` and
       * `Handle::Update` inline it (both reload `mParent` from the node right
       * before the `RemoveFromChain` call); the binary also keeps an uncalled
       * out-of-line copy at 0x0081B480.
       */
      void Remove() noexcept;

      /**
       * Address: 0x0081B310 (FUN_0081B310, Moho::VisionDB::Entry::PutInChain)
       *
       * What it does:
       * Links this node under the deepest node, starting at `root`, whose
       * circles contain both of its own, or under `root` itself when nothing
       * below it does.
       */
      void PutInChain(Entry* root) noexcept;

      Entry* mParent;             // +0x00
      Entry* mContained;          // +0x04 first node of the chain this one contains
      Entry* mNext;               // +0x08 next node in this node's own chain
      bool mIsReal;               // +0x0C an emitter held by a Handle, not a quadtree node
      bool mVisible;              // +0x0D the emitter currently grants vision
      Wm3::Circle2f mPrevCircle;  // +0x10
      Wm3::Circle2f mCurCircle;   // +0x1C
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Entry) == 0x28, "VisionDB::Entry size must be 0x28");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mParent) == 0x00, "VisionDB::Entry::mParent offset must be 0x00");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mContained) == 0x04, "VisionDB::Entry::mContained offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mNext) == 0x08, "VisionDB::Entry::mNext offset must be 0x08");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mIsReal) == 0x0C, "VisionDB::Entry::mIsReal offset must be 0x0C");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mVisible) == 0x0D, "VisionDB::Entry::mVisible offset must be 0x0D");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mPrevCircle) == 0x10, "VisionDB::Entry::mPrevCircle offset must be 0x10");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Entry, mCurCircle) == 0x1C, "VisionDB::Entry::mCurCircle offset must be 0x1C");

    /**
     * VFTABLE: 0x00E422B4
     * COL:     0x00E98C58
     *
     * Block allocator for entries: 500 at a time, recycled through a free
     * list, and released only when the pool dies. Both lists hold one
     * `Entry*` per node - the `{next, prev, value}` 0x0C node and
     * `{proxy, head, size}` 0x0C head of `msvc8::list`, which is what IDA
     * types the free list (`_List_nod_VisionDB_Entry::_Node`, 0x0081BA00).
     */
    class Pool
    {
    public:
      /// `new Entry[500]` at 0x0081AA2D (`push 0x4E24` = 4 + 500 * 0x28).
      static constexpr std::size_t kEntriesPerBlock = 500u;

      /**
       * Address: 0x0081ACA0 (FUN_0081ACA0)
       * Mangled: ??0Pool@VisionDB@Moho@@QAE@@Z
       *
       * What it does:
       * Constructs both lists; each buys and self-links its header sentinel.
       */
      Pool();

      /**
       * Address: 0x0081AD20 (FUN_0081AD20)
       * Address: 0x0081AD00 (FUN_0081AD00, scalar deleting destructor)
       * Address: 0x103E3CA0
       * Address: 0x103E3C80
       * Slot: 0
       *
       * What it does:
       * `delete[]`s every entry block, then the two lists are destroyed.
       * 0x0081AD20 rewrites the vptr on entry, and `~VisionDB` calls it for
       * its `pool_` member, so it is the destructor itself, not a `Clear`.
       */
      virtual ~Pool();

      /**
       * Address: 0x0081AA00 (FUN_0081AA00)
       *
       * What it does:
       * Takes the first free entry - allocating a block of 500 and queueing
       * all of them first when the free list is empty - and initialises it
       * with the two circles, the emitter flag, no links and not visible.
       */
      [[nodiscard]] Entry* NewEntry(const Wm3::Circle2f& previous, const Wm3::Circle2f& current, bool isReal);

      /**
       * Address: 0x0081ABF0 (FUN_0081ABF0)
       * Address: 0x103E3B70
       *
       * What it does:
       * Clears the entry's links and both flags (the circles are left as they
       * were) and appends it to the free list.
       */
      void FreeEntry(Entry* entry);

      /// One node per block allocated; the value is the block's first entry.
      msvc8::list<Entry*> mEntryBlocks; // +0x04
      /// The entries `NewEntry` hands out next.
      msvc8::list<Entry*> mFreeEntries; // +0x10
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Pool) == 0x1C, "VisionDB::Pool size must be 0x1C");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Pool, mEntryBlocks) == 0x04, "VisionDB::Pool::mEntryBlocks offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Pool, mFreeEntries) == 0x10, "VisionDB::Pool::mFreeEntries offset must be 0x10");

    /**
     * VFTABLE: 0x00E422BC
     * COL:     0x00E98C0C
     *
     * One user entity's emitter entry in the tree (`UserEntity::mVisionHandle`).
     */
    class Handle
    {
    public:
      /**
       * Address: 0x0081AE10 (FUN_0081AE10)
       *
       * What it does:
       * Stores the owning database and the entry. `NewHandle` inlines it
       * (0x0081B03C); this is the uncalled out-of-line copy.
       */
      Handle(VisionDB* db, Entry* entry) noexcept;

      /**
       * Address: 0x0081AE60 (FUN_0081AE60)
       * Address: 0x0081AE20 (FUN_0081AE20, scalar deleting destructor)
       * Address: 0x103E3DA0
       * Slot: 0
       *
       * What it does:
       * Takes the entry out of the tree and returns it to the database's pool.
       */
      virtual ~Handle();

      /**
       * Address: 0x008B83B0 (FUN_008B83B0, Moho::VisionDB::Handle::Update)
       *
       * What it does:
       * Stores the visibility bit and both circles, then moves the entry back
       * down from the root when its parent no longer contains it.
       */
      void Update(const Wm3::Vector2f& next, const Wm3::Vector2f& previous, float radius, bool visible);

      VisionDB* mDB;  // +0x04
      Entry* mEntry;  // +0x08
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Handle) == 0x0C, "VisionDB::Handle size must be 0x0C");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Handle, mDB) == 0x04, "VisionDB::Handle::mDB offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Handle, mEntry) == 0x08, "VisionDB::Handle::mEntry offset must be 0x08");

    /**
     * Address: 0x0081AE90 (FUN_0081AE90, sub_81AE90)
     *
     * What it does:
     * Constructs the pool and clears the root.
     */
    VisionDB();

    /**
     * Address: 0x0081AF00 (FUN_0081AF00, Moho::VisionDB::Init)
     *
     * What it does:
     * Allocates the root entry covering a circle whose center is
     * `(width/2, height/2)` and radius is `2 * sqrt((width/2)^2 + (height/2)^2)`,
     * stores it as the vision tree root, and recursively subdivides the area
     * via `GenerateQuadTree`.
     */
    void Init(float width, float height);

    /**
     * Address: 0x0081B080 (FUN_0081B080, Moho::VisionDB::GenerateQuadTree)
     *
     * What it does:
     * Recursively subdivides `parent` into four quadrant child nodes (NW, SW,
     * NE, SE) when `level < maxLevel`. Each child covers a (width/2, height/2)
     * sub-rectangle centered at the corresponding offset from the parent's
     * stored circle center, with bounding-circle radius equal to the
     * sub-rectangle's diagonal half-length.
     */
    void GenerateQuadTree(Entry* parent, const Wm3::Vector2f& size, int level, int maxLevel);

    /**
     * Address: 0x0081AFD0 (FUN_0081AFD0, Moho::VisionDB::NewHandle)
     *
     * What it does:
     * Takes an emitter entry from the pool for the previous/current positions
     * (radius 0 until the first `Handle::Update`), puts it in the tree from
     * the root and wraps it in a new `Handle`.
     */
    [[nodiscard]] Handle* NewHandle(const Wm3::Vector2f& current, const Wm3::Vector2f& previous);

    /**
     * Inline capacity of the circle accumulator `RenderFogOfWar` hands to
     * `TryAdd`: the shipped body binds `capacity_` to `inlineVec_ + 3000 bytes`
     * (0x0081C7BF / 0x0081C7F0), i.e. 250 `Wm3::Circle2f` slots before the
     * first heap growth.
     */
    static constexpr std::size_t kVisibleCircleInlineCapacity = 250u;

    /**
     * Address: 0x0081B490 (FUN_0081B490, Moho::VisionDB::Entry::TryAdd)
     *
     * IDA signature:
     * void __stdcall Moho::VisionDB::struct1::TryAdd(gpg::fastvector_Circle2f *accum,
     *         Moho::VisionDB::Entry *a2, const Wm3::Box3f *box, float amt);
     *
     * IDA's prototype drops the register argument and mis-widens the box. The
     * shipped body is `__thiscall` with four stack arguments (`retn 10h` at
     * 0x0081B5CC): `mov ebx, ecx` at 0x0081B4AC parks the `this` pointer and
     * `mov ecx, ebx` at 0x0081B59B feeds it straight back into the recursive
     * call, and both external call sites load `ecx` with the object whose
     * `+0x20` lane is `VisionDB::rootNode_` (0x0081B065 and 0x0081C815), so
     * `this` is the `VisionDB`, not the entry. The box is a `Wm3::Box2f`: it is
     * forwarded unchanged to `Wm3::IntrBox2Circle2f::IntrBox2Circle2f` at
     * 0x0081B52C, and the caller at 0x0081C660 fills exactly the eight floats
     * of a `Box2f` (center, two unit axes, two extents).
     *
     * What it does:
     * Interpolates `entry`'s vision circle between its previous and current
     * samples by `interpolant` and tests it against `box`. On overlap it either
     * appends that interpolated circle to `accumulator` (real, currently
     * visible emitter) or recurses over the entry's `mContained` chain.
     *
     * `accumulator` is the renderer's inline-backed vector and has to stay typed
     * as one: the append grows through the inline-aware lane (0x0081B6E0 ->
     * 0x0081B830 -> 0x0081BBC0, which compares `start_` with `originalVec_` at
     * +0x0C and never frees the inline window). Taken as the plain
     * `gpg::fastvector<Wm3::Circle2f>` base, `FastVector::Reserve` handed the
     * inline window - a stack buffer - to `operator delete` as soon as more
     * than 250 circles were in view.
     */
    void TryAdd(
      gpg::fastvector_n<Wm3::Circle2f, kVisibleCircleInlineCapacity>& accumulator,
      Entry* entry,
      const Wm3::Box2f& box,
      float interpolant
    ) const;

    /**
     * Address: 0x0081AEB0 (FUN_0081AEB0)
     * Address: 0x103E3E30
     * Slot: 0
     * Demangled: Moho::VisionDB::Dtr
     *
     * What it does:
     * Clears the root pointer then tears down `Pool`.
     */
    virtual ~VisionDB();

  public:
    friend struct VisionDBLayoutAsserts;

    Pool pool_;                // +0x04
    Entry* rootNode_{nullptr}; // +0x20
  };

  struct VisionDBLayoutAsserts
  {
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, pool_) == 0x04, "VisionDB::pool_ offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, rootNode_) == 0x20, "VisionDB::rootNode_ offset must be 0x20");
  };

  MOHO_VISIONDB_X86_ASSERT(sizeof(VisionDB) == 0x24, "VisionDB size must be 0x24");

#undef MOHO_VISIONDB_X86_ASSERT
} // namespace moho

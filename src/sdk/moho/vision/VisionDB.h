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
   */
  class VisionDB
  {
  public:
    class Handle;

    /**
     * VFTABLE: 0x00E422B4
     * COL:     0x00E98C58
     */
    class Pool
    {
    public:
      /**
       * 0x28-byte pooled vision node.
       *
       * Address: 0x0081AB70 (FUN_0081AB70)
       * Mangled: ??0struct1@VisionDB@Moho@@QAE@@Z
       *
       * What it does:
       * Stores owner/tree links, visibility flags, and previous/current 2D circles.
       */
      struct EntryCircle
      {
        float x{0.0f};      // +0x00
        float y{0.0f};      // +0x04
        float radius{0.0f}; // +0x08
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(EntryCircle) == 0x0C, "VisionDB::Pool::EntryCircle size must be 0x0C");

      struct PooledNode
      {
        void* mParent{nullptr};      // +0x00
        PooledNode* mContained{nullptr}; // +0x04
        PooledNode* mNext{nullptr};      // +0x08
        std::uint8_t mIsReal{0};         // +0x0C
        std::uint8_t mVis{0};            // +0x0D
        std::uint16_t mPad0E{0};         // +0x0E
        EntryCircle mPrevCircle{};       // +0x10
        EntryCircle mCurCircle{};        // +0x1C
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(PooledNode) == 0x28, "VisionDB::Pool::PooledNode size must be 0x28");
      MOHO_VISIONDB_X86_ASSERT(offsetof(PooledNode, mParent) == 0x00, "VisionDB::Pool::PooledNode::mParent offset must be 0x00");
      MOHO_VISIONDB_X86_ASSERT(
        offsetof(PooledNode, mContained) == 0x04, "VisionDB::Pool::PooledNode::mContained offset must be 0x04"
      );
      MOHO_VISIONDB_X86_ASSERT(offsetof(PooledNode, mNext) == 0x08, "VisionDB::Pool::PooledNode::mNext offset must be 0x08");
      MOHO_VISIONDB_X86_ASSERT(
        offsetof(PooledNode, mIsReal) == 0x0C, "VisionDB::Pool::PooledNode::mIsReal offset must be 0x0C"
      );
      MOHO_VISIONDB_X86_ASSERT(offsetof(PooledNode, mVis) == 0x0D, "VisionDB::Pool::PooledNode::mVis offset must be 0x0D");
      MOHO_VISIONDB_X86_ASSERT(
        offsetof(PooledNode, mPrevCircle) == 0x10, "VisionDB::Pool::PooledNode::mPrevCircle offset must be 0x10"
      );
      MOHO_VISIONDB_X86_ASSERT(
        offsetof(PooledNode, mCurCircle) == 0x1C, "VisionDB::Pool::PooledNode::mCurCircle offset must be 0x1C"
      );

      using Entry = PooledNode;

      /**
       * Both of this pool's lists hold one `PooledNode*` per node: the
       * `{next, prev, value}` 0x0C node and the `{proxy, head, size}` 0x0C
       * head are `msvc8::list<PooledNode*>` exactly, which is what IDA already
       * types the free list (`_List_nod_VisionDB_Entry::_Node`, 0x0081BA00)
       * and what the 0x3FFFFFFF `_Incsize` guard at 0x0081BA40 belongs to.
       */
      using EntryList = msvc8::list<PooledNode*>;

      MOHO_VISIONDB_X86_ASSERT(sizeof(EntryList) == 0x0C, "VisionDB::Pool::EntryList size must be 0x0C");

      /**
       * Address: 0x0081ACA0 (FUN_0081ACA0)
       * Mangled: ??0Pool@VisionDB@Moho@@QAE@@Z
       *
       * What it does:
       * Allocates and self-links zone/free-node list sentinels.
       */
      Pool();

      /**
       * Address: 0x0081AD00 (FUN_0081AD00)
       * Address: 0x103E3C80
       * Slot: 0
       * Demangled: Moho::VisionDB::Pool::dtr
       *
       * What it does:
       * Invokes `Clear()` and optionally deletes the object (scalar deleting dtor).
       */
      virtual ~Pool();

      /**
       * Address: 0x0081AD20 (FUN_0081AD20)
       * Address: 0x103E3CA0
       * Demangled: Moho::VisionDB::Pool::Clear
       *
       * What it does:
       * Releases pooled-node blocks, clears both intrusive lists, and frees sentinels.
       */
      void Clear();

      /**
       * Address: 0x0081AA00 (FUN_0081AA00)
       *
       * What it does:
       * Obtains one entry from the reusable pool, allocating and seeding a 500-entry
       * block when the free-list is empty.
       */
      [[nodiscard]] Entry* NewEntry(const EntryCircle& previousCircle, const EntryCircle& currentCircle, bool isReal);

    private:
      static void FreeZoneBlocks(EntryList& blocks);

    public:
      friend class Handle;

      /// One entry per allocated block; the value is the block's first node,
      /// and the block's element count sits in the dword before it.
      EntryList mEntryBlocks{}; // +0x04
      /// The reusable nodes handed back out by `NewEntry`.
      EntryList mFreeEntries{}; // +0x10
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Pool) == 0x1C, "VisionDB::Pool size must be 0x1C");

    /**
     * VFTABLE: 0x00E422BC
     * COL:     0x00E98C0C
     */
    class Handle
    {
    public:
      /**
       * Address: 0x0081AE20 (FUN_0081AE20)
       * Address: 0x103E3DA0
       * Slot: 0
       * Demangled: Moho::VisionDB::Handle::dtr
       *
       * What it does:
       * Unlinks the pooled node from its owner chain and returns it to the pool free-list.
       */
      virtual ~Handle();

      /**
       * Address: 0x008B83B0 (FUN_008B83B0, Moho::VisionDB::Handle::Update)
       *
       * What it does:
       * Refreshes this handle's previous/current circles and visibility bit,
       * then reparents into the vision tree when containment no longer holds.
       */
      void Update(const Wm3::Vector2f& next, const Wm3::Vector2f& previous, float radius, bool visible);

      /**
       * Address: 0x0081AE10 (FUN_0081AE10)
       *
       * What it does:
       * Stores owner and pooled-node pointers for this handle.
       */
      static Handle* Init(Handle* self, std::uintptr_t pooledNodePtr, std::uintptr_t ownerPtr);

    private:
      /**
       * Address: 0x0081AE60 (FUN_0081AE60)
       *
       * What it does:
       * Runs the non-deleting handle teardown lane: unlinks this handle's
       * pooled node from the owner chain and returns it to the VisionDB pool.
       */
      void ReleasePooledNodeToOwnerPool();

      struct OwnerChainView
      {
        void* mOwnerCookie;     // +0x00
        Pool::PooledNode* mRoot; // +0x04
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(OwnerChainView) == 0x08, "VisionDB::Handle::OwnerChainView size must be 0x08");

      /**
       * Address: 0x0081A8C0 (FUN_0081A8C0)
       * Address: 0x103E38B0
       *
       * What it does:
       * Appends a sibling chain to the tail of another sibling chain.
       */
      static void AttachSiblingChain(Pool::PooledNode* tailChain, Pool::PooledNode* chainHead);
      /**
       * Address: 0x0081A8E0 (FUN_0081A8E0)
       * Address: 0x103E38D0
       *
       * What it does:
       * Unlinks a pooled node from its owner chain and reparents children.
       */
      static void UnlinkFromOwnerTree(OwnerChainView* ownerChain, Pool::PooledNode* node);
      /**
       * Address: 0x0081ABF0 (FUN_0081ABF0)
       * Address: 0x103E3B70
       *
       * What it does:
       * Clears one pooled node and pushes it back to the pool free-list.
       */
      static void ReturnNodeToFreeList(Pool* ownerPool, Pool::PooledNode* node);

    public:
      std::uintptr_t mDB{0};   // +0x04
      std::uintptr_t mNode{0}; // +0x08
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Handle) == 0x0C, "VisionDB::Handle size must be 0x0C");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Handle, mDB) == 0x04, "VisionDB::Handle::mDB offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Handle, mNode) == 0x08, "VisionDB::Handle::mNode offset must be 0x08");

    /**
     * Address: 0x0081AE90 (FUN_0081AE90, sub_81AE90)
     *
     * What it does:
     * Initializes one `VisionDB` object: seeds the pool subobject and clears
     * the root node pointer lane.
     */
    VisionDB();

    /**
     * Address: 0x0081AF00 (FUN_0081AF00, Moho::VisionDB::Init)
     *
     * What it does:
     * Allocates the root pooled-node entry covering a circle whose center is
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
     * sub-rectangle's diagonal half-length. New nodes are linked into the
     * parent's `mContained` chain.
     */
    void GenerateQuadTree(Pool::PooledNode* parent, const Wm3::Vector2f& size, int level, int maxLevel);

    /**
     * Address: 0x0081AFD0 (FUN_0081AFD0, Moho::VisionDB::NewHandle)
     *
     * What it does:
     * Allocates one tracked vision handle using previous/current 2D positions
     * and inserts its pooled node under the root vision entry.
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
     * visible emitter) or recurses over the entry's `mContained` sibling chain.
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
      Pool::Entry* entry,
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

    Pool pool_;                      // +0x04
    Pool::Entry* rootNode_{nullptr}; // +0x20
  };

  struct VisionDBLayoutAsserts
  {
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, pool_) == 0x04, "VisionDB::pool_ offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, rootNode_) == 0x20, "VisionDB::rootNode_ offset must be 0x20");
  };

  MOHO_VISIONDB_X86_ASSERT(sizeof(VisionDB) == 0x24, "VisionDB size must be 0x24");

#undef MOHO_VISIONDB_X86_ASSERT
} // namespace moho

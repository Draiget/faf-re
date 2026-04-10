#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"
#include "wm3/Vector2.h"

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
       * Circular-list node that points to a pooled-node block base.
       */
      struct ZoneBlockEntry : TDatListItem<ZoneBlockEntry, void>
      {
        PooledNode* blockBase{nullptr}; // +0x08
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(ZoneBlockEntry) == 0x0C, "VisionDB::Pool::ZoneBlockEntry size must be 0x0C");

      /**
       * Circular-list node that points to one reusable pooled node.
       */
      struct FreeNodeEntry : TDatListItem<FreeNodeEntry, void>
      {
        PooledNode* node{nullptr}; // +0x08
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(FreeNodeEntry) == 0x0C, "VisionDB::Pool::FreeNodeEntry size must be 0x0C");

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
      static void FreeZoneBlocks(ZoneBlockEntry* head);

    public:
      friend class Handle;

      std::uint32_t mEntriesListState{0};       // +0x04 (legacy std::list proxy lane)
      ZoneBlockEntry* mEntriesHead{nullptr};    // +0x08
      std::uint32_t mEntriesSize{0};            // +0x0C
      std::uint32_t mEntryPoolListState{0};     // +0x10 (legacy std::list proxy lane)
      FreeNodeEntry* mEntryPoolHead{nullptr};   // +0x14
      std::uint32_t mEntryPoolSize{0};          // +0x18
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Pool) == 0x1C, "VisionDB::Pool size must be 0x1C");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Pool, mEntriesHead) == 0x08, "VisionDB::Pool::mEntriesHead offset must be 0x08");
    MOHO_VISIONDB_X86_ASSERT(offsetof(Pool, mEntriesSize) == 0x0C, "VisionDB::Pool::mEntriesSize offset must be 0x0C");
    MOHO_VISIONDB_X86_ASSERT(
      offsetof(Pool, mEntryPoolHead) == 0x14, "VisionDB::Pool::mEntryPoolHead offset must be 0x14"
    );
    MOHO_VISIONDB_X86_ASSERT(
      offsetof(Pool, mEntryPoolSize) == 0x18, "VisionDB::Pool::mEntryPoolSize offset must be 0x18"
    );

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

    VisionDB();

    /**
     * Address: 0x0081AFD0 (FUN_0081AFD0, Moho::VisionDB::NewHandle)
     *
     * What it does:
     * Allocates one tracked vision handle using previous/current 2D positions
     * and inserts its pooled node under the root vision entry.
     */
    [[nodiscard]] Handle* NewHandle(const Wm3::Vector2f& current, const Wm3::Vector2f& previous);

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

  private:
    friend struct VisionDBLayoutAsserts;

    Pool pool_;               // +0x04
    void* rootNode_{nullptr}; // +0x20
  };

  struct VisionDBLayoutAsserts
  {
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, pool_) == 0x04, "VisionDB::pool_ offset must be 0x04");
    MOHO_VISIONDB_X86_ASSERT(offsetof(VisionDB, rootNode_) == 0x20, "VisionDB::rootNode_ offset must be 0x20");
  };

  MOHO_VISIONDB_X86_ASSERT(sizeof(VisionDB) == 0x24, "VisionDB size must be 0x24");

#undef MOHO_VISIONDB_X86_ASSERT
} // namespace moho

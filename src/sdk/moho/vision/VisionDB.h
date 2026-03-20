// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"

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
       * Stores owner/tree links, two flag bytes, and two 3-float bounds vectors.
       */
      struct PooledNode
      {
        void* ownerOrChain{nullptr};      // +0x00
        PooledNode* firstChild{nullptr};  // +0x04
        PooledNode* nextSibling{nullptr}; // +0x08
        std::uint8_t typeFlag{0};         // +0x0C
        std::uint8_t markFlag{0};         // +0x0D
        std::uint16_t pad0E{0};           // +0x0E
        float minBounds[3]{};             // +0x10
        float maxBounds[3]{};             // +0x1C
      };
      MOHO_VISIONDB_X86_ASSERT(sizeof(PooledNode) == 0x28, "VisionDB::Pool::PooledNode size must be 0x28");

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

    private:
      static void FreeZoneBlocks(ZoneBlockEntry* head);

    private:
      friend class Handle;

      std::uint32_t zoneListState_;             // +0x04 (list bookkeeping, semantics unresolved)
      ZoneBlockEntry* zoneBlocksHead_{nullptr}; // +0x08
      std::uint32_t zoneBlockCount_{0};         // +0x0C
      std::uint32_t freeListState_;             // +0x10 (list bookkeeping, semantics unresolved)
      FreeNodeEntry* freeNodeHead_{nullptr};    // +0x14
      std::uint32_t freeNodeCount_{0};          // +0x18
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
       * Address: 0x0081AE10 (FUN_0081AE10)
       *
       * What it does:
       * Stores owner and pooled-node pointers for this handle.
       */
      static Handle* Init(Handle* self, std::uintptr_t pooledNodePtr, std::uintptr_t ownerPtr);

    private:
      struct OwnerChainView
      {
        void* ownerCookie;          // +0x00
        Pool::PooledNode* rootNode; // +0x04
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

    private:
      std::uintptr_t ownerPtr_{0};      // +0x04
      std::uintptr_t pooledNodePtr_{0}; // +0x08
    };
    MOHO_VISIONDB_X86_ASSERT(sizeof(Handle) == 0x0C, "VisionDB::Handle size must be 0x0C");

    VisionDB();

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

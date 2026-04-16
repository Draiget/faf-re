#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>

namespace
{
  struct LegacyRangeRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::byte* begin;     // +0x04
    std::byte* end;       // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(LegacyRangeRuntimeView, begin) == 0x04, "LegacyRangeRuntimeView::begin offset must be 0x04");
  static_assert(offsetof(LegacyRangeRuntimeView, end) == 0x08, "LegacyRangeRuntimeView::end offset must be 0x08");
  static_assert(sizeof(LegacyRangeRuntimeView) == 0x0C, "LegacyRangeRuntimeView size must be 0x0C");
#endif

  template <std::size_t kElementSize>
  [[nodiscard]] std::int32_t CountRangeEntries(const LegacyRangeRuntimeView& range) noexcept
  {
    if (range.begin == nullptr) {
      return 0;
    }

    const std::ptrdiff_t spanBytes = range.end - range.begin;
    return static_cast<std::int32_t>(spanBytes / static_cast<std::ptrdiff_t>(kElementSize));
  }

  template <std::size_t kSentinelOffset>
  struct SentinelTreeNodeRuntimeView
  {
    SentinelTreeNodeRuntimeView* link0; // +0x00
    SentinelTreeNodeRuntimeView* link4; // +0x04
    SentinelTreeNodeRuntimeView* link8; // +0x08
    std::byte payload[kSentinelOffset - 0x0C];
    std::uint8_t isSentinel;
  };

  using SentinelNodeOffsetB9RuntimeView = SentinelTreeNodeRuntimeView<0xB9>;
  using SentinelNodeOffset39RuntimeView = SentinelTreeNodeRuntimeView<0x39>;
  using SentinelNodeOffset2DRuntimeView = SentinelTreeNodeRuntimeView<0x2D>;
  using SentinelNodeOffset25RuntimeView = SentinelTreeNodeRuntimeView<0x25>;
  using SentinelNodeOffset15RuntimeView = SentinelTreeNodeRuntimeView<0x15>;

  template <std::size_t kSentinelOffset>
  struct OrderedSentinelTreeNodeRuntimeView
  {
    OrderedSentinelTreeNodeRuntimeView* link0; // +0x00
    OrderedSentinelTreeNodeRuntimeView* link4; // +0x04
    OrderedSentinelTreeNodeRuntimeView* link8; // +0x08
    std::uint32_t key;                         // +0x0C
    std::byte payload[kSentinelOffset - 0x10];
    std::uint8_t isSentinel;
  };

  using OrderedSentinelNodeOffset2DRuntimeView = OrderedSentinelTreeNodeRuntimeView<0x2D>;
  using OrderedSentinelNodeOffset15RuntimeView = OrderedSentinelTreeNodeRuntimeView<0x15>;

#if defined(_M_IX86)
  static_assert(
    offsetof(SentinelNodeOffsetB9RuntimeView, isSentinel) == 0xB9,
    "SentinelNodeOffsetB9RuntimeView::isSentinel offset must be 0xB9"
  );
  static_assert(
    offsetof(SentinelNodeOffset39RuntimeView, isSentinel) == 0x39,
    "SentinelNodeOffset39RuntimeView::isSentinel offset must be 0x39"
  );
  static_assert(
    offsetof(SentinelNodeOffset2DRuntimeView, isSentinel) == 0x2D,
    "SentinelNodeOffset2DRuntimeView::isSentinel offset must be 0x2D"
  );
  static_assert(
    offsetof(SentinelNodeOffset25RuntimeView, isSentinel) == 0x25,
    "SentinelNodeOffset25RuntimeView::isSentinel offset must be 0x25"
  );
  static_assert(
    offsetof(SentinelNodeOffset15RuntimeView, isSentinel) == 0x15,
    "SentinelNodeOffset15RuntimeView::isSentinel offset must be 0x15"
  );
  static_assert(
    offsetof(OrderedSentinelNodeOffset2DRuntimeView, key) == 0x0C,
    "OrderedSentinelNodeOffset2DRuntimeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(OrderedSentinelNodeOffset2DRuntimeView, isSentinel) == 0x2D,
    "OrderedSentinelNodeOffset2DRuntimeView::isSentinel offset must be 0x2D"
  );
  static_assert(
    offsetof(OrderedSentinelNodeOffset15RuntimeView, key) == 0x0C,
    "OrderedSentinelNodeOffset15RuntimeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(OrderedSentinelNodeOffset15RuntimeView, isSentinel) == 0x15,
    "OrderedSentinelNodeOffset15RuntimeView::isSentinel offset must be 0x15"
  );
#endif

  template <typename TSentinelNode>
  [[nodiscard]] TSentinelNode** AscendLink0UntilSentinel(TSentinelNode** linkSlot) noexcept
  {
    TSentinelNode* cursor = *linkSlot;
    if (cursor->isSentinel == 0u) {
      do {
        linkSlot = reinterpret_cast<TSentinelNode**>(cursor);
        cursor = cursor->link0;
      } while (cursor->isSentinel == 0u);
    }
    return linkSlot;
  }

  template <typename TSentinelNode>
  [[nodiscard]] TSentinelNode* WalkLink8UntilSentinel(TSentinelNode* node) noexcept
  {
    TSentinelNode* cursor = node->link8;
    while (cursor->isSentinel == 0u) {
      node = cursor;
      cursor = cursor->link8;
    }
    return node;
  }

  template <typename TSentinelNode>
  [[nodiscard]] TSentinelNode* LowerBoundSentinelTreeByDwordKey(
    TSentinelNode* const globalHead,
    const std::uint32_t key
  ) noexcept
  {
    TSentinelNode* lowerBound = globalHead;
    TSentinelNode* cursor = globalHead->link4;
    while (cursor->isSentinel == 0u) {
      if (cursor->key >= key) {
        lowerBound = cursor;
        cursor = cursor->link0;
      } else {
        cursor = cursor->link8;
      }
    }
    return lowerBound;
  }

  struct QuadWordBlockRuntimeView
  {
    std::uint32_t lane0;
    std::uint32_t lane1;
    std::uint32_t lane2;
    std::uint32_t lane3;
  };
  static_assert(sizeof(QuadWordBlockRuntimeView) == 0x10, "QuadWordBlockRuntimeView size must be 0x10");

  [[nodiscard]] QuadWordBlockRuntimeView* FillQuadWordBlockRange(
    QuadWordBlockRuntimeView* destination,
    QuadWordBlockRuntimeView* end,
    const QuadWordBlockRuntimeView& fillValue
  ) noexcept
  {
    for (; destination != end; ++destination) {
      *destination = fillValue;
    }
    return destination;
  }

  [[nodiscard]] QuadWordBlockRuntimeView* CopyQuadWordBlockRangeBackward(
    QuadWordBlockRuntimeView* destinationEnd,
    const QuadWordBlockRuntimeView* sourceBegin,
    const QuadWordBlockRuntimeView* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  struct LegacyDwordSpanRuntimeView
  {
    std::uint32_t lane00;    // +0x00
    std::uint32_t* lane04;   // +0x04
    std::uint32_t* end;      // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(LegacyDwordSpanRuntimeView, end) == 0x08, "LegacyDwordSpanRuntimeView::end offset must be 0x08");
#endif

  struct LegacyVectorElement20RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::byte* begin;     // +0x04
    std::byte* end;       // +0x08
    std::byte* capacity;  // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(LegacyVectorElement20RuntimeView, begin) == 0x04,
    "LegacyVectorElement20RuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyVectorElement20RuntimeView, end) == 0x08,
    "LegacyVectorElement20RuntimeView::end offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyVectorElement20RuntimeView, capacity) == 0x0C,
    "LegacyVectorElement20RuntimeView::capacity offset must be 0x0C"
  );
  static_assert(sizeof(LegacyVectorElement20RuntimeView) == 0x10, "LegacyVectorElement20RuntimeView size must be 0x10");
#endif

  struct LegacyVectorDwordRuntimeView
  {
    std::uint32_t lane00;     // +0x00
    std::uint32_t* begin;     // +0x04
    std::uint32_t* end;       // +0x08
    std::uint32_t* capacity;  // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(LegacyVectorDwordRuntimeView, begin) == 0x04,
    "LegacyVectorDwordRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyVectorDwordRuntimeView, end) == 0x08,
    "LegacyVectorDwordRuntimeView::end offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyVectorDwordRuntimeView, capacity) == 0x0C,
    "LegacyVectorDwordRuntimeView::capacity offset must be 0x0C"
  );
  static_assert(sizeof(LegacyVectorDwordRuntimeView) == 0x10, "LegacyVectorDwordRuntimeView size must be 0x10");
#endif

  [[nodiscard]] std::uint32_t* MoveDwordTailToGapAndCommitEnd(
    LegacyDwordSpanRuntimeView& span,
    std::uint32_t* destination,
    std::uint32_t* source
  ) noexcept
  {
    if (destination != source) {
      std::uint32_t* const tail = span.end;
      std::uint32_t* writeCursor = destination;
      if (source != tail) {
        do {
          *writeCursor++ = *source++;
        } while (source != tail);
      }
      span.end = writeCursor;
    }

    return destination;
  }

  [[nodiscard]] std::uint32_t* CopyDwordRangeBackward(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --destinationEnd;
      --sourceEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x008DCAD0 (FUN_008DCAD0)
   *
   * What it does:
   * Initializes one 20-byte-element vector lane and optionally allocates
   * backing storage for `elementCount` entries.
   */
  [[maybe_unused]] bool InitializeElement20VectorStorage(
    LegacyVectorElement20RuntimeView* const vectorView,
    const std::uint32_t elementCount
  )
  {
    vectorView->begin = nullptr;
    vectorView->end = nullptr;
    vectorView->capacity = nullptr;
    if (elementCount == 0u) {
      return false;
    }

    if (elementCount > 0x0CCCCCCCu) {
      throw std::length_error("vector<T> too long");
    }

    const std::size_t byteCount = static_cast<std::size_t>(elementCount) * 20u;
    auto* const base = static_cast<std::byte*>(::operator new(byteCount));
    vectorView->begin = base;
    vectorView->end = base;
    vectorView->capacity = base + byteCount;
    return true;
  }

  /**
   * Address: 0x008DCB20 (FUN_008DCB20)
   *
   * What it does:
   * Initializes one dword-vector lane and optionally allocates backing storage
   * for `elementCount` entries.
   */
  [[maybe_unused]] bool InitializeDwordVectorStorage(
    LegacyVectorDwordRuntimeView* const vectorView,
    const std::size_t elementCount
  )
  {
    vectorView->begin = nullptr;
    vectorView->end = nullptr;
    vectorView->capacity = nullptr;
    if (elementCount == 0u) {
      return false;
    }

    if (elementCount > 0x3FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    auto* const base = static_cast<std::uint32_t*>(::operator new(elementCount * sizeof(std::uint32_t)));
    vectorView->begin = base;
    vectorView->end = base;
    vectorView->capacity = base + elementCount;
    return true;
  }

  struct SharedControlBlockRuntimeView
  {
    void** vtable;              // +0x00
    volatile LONG useCount;     // +0x04
    volatile LONG weakCount;    // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(SharedControlBlockRuntimeView, useCount) == 0x04, "SharedControlBlockRuntimeView::useCount offset must be 0x04");
  static_assert(offsetof(SharedControlBlockRuntimeView, weakCount) == 0x08, "SharedControlBlockRuntimeView::weakCount offset must be 0x08");
  static_assert(sizeof(SharedControlBlockRuntimeView) == 0x0C, "SharedControlBlockRuntimeView size must be 0x0C");
#endif

  using SharedControlBlockCall = std::intptr_t(__thiscall*)(SharedControlBlockRuntimeView*);

  [[nodiscard]] std::intptr_t InvokeSharedControlBlockSlot(
    SharedControlBlockRuntimeView* const control,
    const std::size_t slot
  ) noexcept
  {
    const auto function = reinterpret_cast<SharedControlBlockCall>(control->vtable[slot]);
    return function(control);
  }

  [[nodiscard]] std::intptr_t ReleaseSharedControlBlockAndReturnLastValue(SharedControlBlockRuntimeView* const control) noexcept
  {
    std::intptr_t result = 0;
    if (control == nullptr) {
      return result;
    }

    result = reinterpret_cast<std::intptr_t>(const_cast<LONG*>(&control->useCount));
    if (InterlockedExchangeAdd(&control->useCount, -1) == 1) {
      result = InvokeSharedControlBlockSlot(control, 1u);
      if (InterlockedExchangeAdd(&control->weakCount, -1) == 1) {
        result = InvokeSharedControlBlockSlot(control, 2u);
      }
    }
    return result;
  }

  struct SharedOwnershipPairRuntimeView
  {
    void* object;                          // +0x00
    SharedControlBlockRuntimeView* owner;  // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(SharedOwnershipPairRuntimeView) == 0x08, "SharedOwnershipPairRuntimeView size must be 0x08");
#endif

  struct Float3RuntimeView
  {
    float x;
    float y;
    float z;
  };
  static_assert(sizeof(Float3RuntimeView) == 0x0C, "Float3RuntimeView size must be 0x0C");

  struct TerrainTransferRuntimeView
  {
    std::byte pad00_3F[0x40];
    std::int32_t commandLane;                   // +0x40
    Float3RuntimeView primaryVectorFromArg4;    // +0x44
    Float3RuntimeView secondaryVectorFromArg1;  // +0x50
    std::byte pad5C_1AF[0x154];
    void* retainedObject;                       // +0x1B0
    SharedControlBlockRuntimeView* retainedOwner; // +0x1B4
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(TerrainTransferRuntimeView, commandLane) == 0x40,
    "TerrainTransferRuntimeView::commandLane offset must be 0x40"
  );
  static_assert(
    offsetof(TerrainTransferRuntimeView, primaryVectorFromArg4) == 0x44,
    "TerrainTransferRuntimeView::primaryVectorFromArg4 offset must be 0x44"
  );
  static_assert(
    offsetof(TerrainTransferRuntimeView, secondaryVectorFromArg1) == 0x50,
    "TerrainTransferRuntimeView::secondaryVectorFromArg1 offset must be 0x50"
  );
  static_assert(
    offsetof(TerrainTransferRuntimeView, retainedObject) == 0x1B0,
    "TerrainTransferRuntimeView::retainedObject offset must be 0x1B0"
  );
  static_assert(
    offsetof(TerrainTransferRuntimeView, retainedOwner) == 0x1B4,
    "TerrainTransferRuntimeView::retainedOwner offset must be 0x1B4"
  );
#endif

  using BufferLockCall = void*(__thiscall*)(void* owner, std::uint32_t offsetBytes, std::uint32_t sizeBytes, std::int32_t flags);

  struct BufferLockVTableRuntimeView
  {
    void* slot00;
    void* slot04;
    BufferLockCall lock; // +0x08
  };

  struct BufferLockOwnerRuntimeView
  {
    BufferLockVTableRuntimeView* vtable;
  };

  struct VertexReservationRuntimeView
  {
    std::byte pad00_23[0x24];
    std::uint32_t reservedVertexCount;     // +0x24
    BufferLockOwnerRuntimeView* lockOwner; // +0x28
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(VertexReservationRuntimeView, reservedVertexCount) == 0x24,
    "VertexReservationRuntimeView::reservedVertexCount offset must be 0x24"
  );
  static_assert(
    offsetof(VertexReservationRuntimeView, lockOwner) == 0x28,
    "VertexReservationRuntimeView::lockOwner offset must be 0x28"
  );
#endif

  [[nodiscard]] std::uint32_t* LockVertexTripletWindow(
    VertexReservationRuntimeView& reservation,
    const std::uint32_t firstVertex,
    const std::uint32_t vertexCount,
    const std::int32_t lockFlags
  ) noexcept
  {
    if (reservation.lockOwner == nullptr || reservation.lockOwner->vtable == nullptr) {
      return nullptr;
    }

    void* const raw = reservation.lockOwner->vtable->lock(
      reservation.lockOwner,
      firstVertex * 12u,
      vertexCount * 12u,
      lockFlags
    );
    return static_cast<std::uint32_t*>(raw);
  }

  struct IntrusiveLinkRuntimeView
  {
    IntrusiveLinkRuntimeView** ownerSlot; // +0x00
    IntrusiveLinkRuntimeView* next;       // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(IntrusiveLinkRuntimeView) == 0x08, "IntrusiveLinkRuntimeView size must be 0x08");
#endif

  struct IntrusiveOwnerAtOffset08RuntimeView
  {
    std::byte pad00_07[0x08];
    IntrusiveLinkRuntimeView* head; // +0x08
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveOwnerAtOffset08RuntimeView, head) == 0x08,
    "IntrusiveOwnerAtOffset08RuntimeView::head offset must be 0x08"
  );
#endif

  [[nodiscard]] IntrusiveLinkRuntimeView* RelinkIntrusiveNode(
    IntrusiveLinkRuntimeView* const node,
    IntrusiveLinkRuntimeView** const newOwnerSlot
  ) noexcept
  {
    if (newOwnerSlot != node->ownerSlot) {
      IntrusiveLinkRuntimeView** oldOwnerSlot = node->ownerSlot;
      if (oldOwnerSlot != nullptr) {
        while (*oldOwnerSlot != node) {
          oldOwnerSlot = &((*oldOwnerSlot)->next);
        }
        *oldOwnerSlot = node->next;
      }

      node->ownerSlot = newOwnerSlot;
      if (newOwnerSlot == nullptr) {
        node->next = nullptr;
      } else {
        node->next = *newOwnerSlot;
        *newOwnerSlot = node;
      }
    }
    return node;
  }

  struct GlobalAccessorStorageRuntimeView
  {
    std::uint32_t lane00;        // +0x00
    std::uint32_t pointerLane04; // +0x04
    std::uint32_t scalarLane08;  // +0x08
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(GlobalAccessorStorageRuntimeView, pointerLane04) == 0x04,
    "GlobalAccessorStorageRuntimeView::pointerLane04 offset must be 0x04"
  );
  static_assert(
    offsetof(GlobalAccessorStorageRuntimeView, scalarLane08) == 0x08,
    "GlobalAccessorStorageRuntimeView::scalarLane08 offset must be 0x08"
  );
  static_assert(sizeof(GlobalAccessorStorageRuntimeView) == 0x0C, "GlobalAccessorStorageRuntimeView size must be 0x0C");
#endif

  GlobalAccessorStorageRuntimeView gPrimaryGlobalAccessorStorage{};
  GlobalAccessorStorageRuntimeView gSecondaryGlobalAccessorStorage{};

  [[nodiscard]] const std::uint32_t* ReadGlobalPointerLaneAddress(const GlobalAccessorStorageRuntimeView& storage) noexcept
  {
    return reinterpret_cast<const std::uint32_t*>(static_cast<std::uintptr_t>(storage.pointerLane04));
  }

  [[nodiscard]] std::uint32_t* WriteGlobalPointerLanePointee(
    std::uint32_t* const outResult,
    const GlobalAccessorStorageRuntimeView& storage
  ) noexcept
  {
    *outResult = *ReadGlobalPointerLaneAddress(storage);
    return outResult;
  }

  [[nodiscard]] std::uint32_t* WriteGlobalPointerLaneValue(
    std::uint32_t* const outResult,
    const GlobalAccessorStorageRuntimeView& storage
  ) noexcept
  {
    *outResult = storage.pointerLane04;
    return outResult;
  }

  [[nodiscard]] std::uint32_t ReadGlobalPointerLaneValue(const GlobalAccessorStorageRuntimeView& storage) noexcept
  {
    return storage.pointerLane04;
  }

  [[nodiscard]] std::uint32_t ReadGlobalScalarLaneValue(const GlobalAccessorStorageRuntimeView& storage) noexcept
  {
    return storage.scalarLane08;
  }

  [[nodiscard]] GlobalAccessorStorageRuntimeView* ReadGlobalStorageAddress(GlobalAccessorStorageRuntimeView& storage) noexcept
  {
    return &storage;
  }

  struct SparseRuntimeLaneAccessorView
  {
    std::byte pad000_0DF[0xE0];
    std::uint32_t lane0E0; // +0x0E0
    std::uint32_t lane0E4; // +0x0E4
    std::byte pad0E8_140[0x59];
    std::uint8_t lane141; // +0x141
    std::byte pad142_147[0x06];
    std::uint32_t lane148; // +0x148
    std::byte pad14C_23F[0xF4];
    std::uint32_t lane240; // +0x240
    std::byte pad244_2A1[0x5E];
    std::uint8_t lane2A2; // +0x2A2
    std::byte pad2A3_4AF[0x20D];
    std::uint32_t lane4B0; // +0x4B0
    std::uint32_t lane4B4; // +0x4B4
    std::byte pad4B8_54F[0x98];
    std::uint32_t lane550; // +0x550
    std::byte pad554_55B[0x08];
    std::uint32_t lane55C; // +0x55C
    std::byte pad560_689[0x12A];
    std::uint8_t lane68A; // +0x68A
    std::uint8_t lane68B; // +0x68B
    std::byte pad68C_8FF[0x274];
    std::uint32_t lane900; // +0x900
    std::uint32_t lane904; // +0x904
    std::byte pad908_97F[0x78];
    std::uint32_t lane980; // +0x980
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane0E0) == 0x0E0,
    "SparseRuntimeLaneAccessorView::lane0E0 offset must be 0x0E0"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane0E4) == 0x0E4,
    "SparseRuntimeLaneAccessorView::lane0E4 offset must be 0x0E4"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane141) == 0x141,
    "SparseRuntimeLaneAccessorView::lane141 offset must be 0x141"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane148) == 0x148,
    "SparseRuntimeLaneAccessorView::lane148 offset must be 0x148"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane240) == 0x240,
    "SparseRuntimeLaneAccessorView::lane240 offset must be 0x240"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane2A2) == 0x2A2,
    "SparseRuntimeLaneAccessorView::lane2A2 offset must be 0x2A2"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane4B0) == 0x4B0,
    "SparseRuntimeLaneAccessorView::lane4B0 offset must be 0x4B0"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane4B4) == 0x4B4,
    "SparseRuntimeLaneAccessorView::lane4B4 offset must be 0x4B4"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane550) == 0x550,
    "SparseRuntimeLaneAccessorView::lane550 offset must be 0x550"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane55C) == 0x55C,
    "SparseRuntimeLaneAccessorView::lane55C offset must be 0x55C"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane68A) == 0x68A,
    "SparseRuntimeLaneAccessorView::lane68A offset must be 0x68A"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane68B) == 0x68B,
    "SparseRuntimeLaneAccessorView::lane68B offset must be 0x68B"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane900) == 0x900,
    "SparseRuntimeLaneAccessorView::lane900 offset must be 0x900"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane904) == 0x904,
    "SparseRuntimeLaneAccessorView::lane904 offset must be 0x904"
  );
  static_assert(
    offsetof(SparseRuntimeLaneAccessorView, lane980) == 0x980,
    "SparseRuntimeLaneAccessorView::lane980 offset must be 0x980"
  );
#endif

  struct SparseRuntimeSmallLaneAccessorView
  {
    std::byte pad00_47[0x48];
    std::uint32_t lane48; // +0x48
    std::uint32_t lane4C; // +0x4C
    std::byte pad50_AB[0x5C];
    std::uint8_t laneAC; // +0xAC
    std::byte padAD_29F[0x1F3];
    std::uint8_t lane2A0; // +0x2A0
    std::byte pad2A1_543[0x2A3];
    std::uint32_t lane544; // +0x544
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SparseRuntimeSmallLaneAccessorView, lane48) == 0x48,
    "SparseRuntimeSmallLaneAccessorView::lane48 offset must be 0x48"
  );
  static_assert(
    offsetof(SparseRuntimeSmallLaneAccessorView, lane4C) == 0x4C,
    "SparseRuntimeSmallLaneAccessorView::lane4C offset must be 0x4C"
  );
  static_assert(
    offsetof(SparseRuntimeSmallLaneAccessorView, laneAC) == 0xAC,
    "SparseRuntimeSmallLaneAccessorView::laneAC offset must be 0xAC"
  );
  static_assert(
    offsetof(SparseRuntimeSmallLaneAccessorView, lane2A0) == 0x2A0,
    "SparseRuntimeSmallLaneAccessorView::lane2A0 offset must be 0x2A0"
  );
  static_assert(
    offsetof(SparseRuntimeSmallLaneAccessorView, lane544) == 0x544,
    "SparseRuntimeSmallLaneAccessorView::lane544 offset must be 0x544"
  );
  static_assert(sizeof(SparseRuntimeSmallLaneAccessorView) == 0x548, "SparseRuntimeSmallLaneAccessorView size must be 0x548");
#endif

  /**
   * Address: 0x005CE820 (FUN_005CE820)
   *
   * What it does:
   * Returns the byte lane at offset `+0x2A0` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint8_t ReadSparseLane2A0(const SparseRuntimeSmallLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane2A0;
  }

  /**
   * Address: 0x005CE830 (FUN_005CE830)
   *
   * What it does:
   * Returns the dword lane at offset `+0x544` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane544(const SparseRuntimeSmallLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane544;
  }

  /**
   * Address: 0x005CE880 (FUN_005CE880)
   *
   * What it does:
   * Returns the dword lane at offset `+0x48` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane48(const SparseRuntimeSmallLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane48;
  }

  /**
   * Address: 0x005CE890 (FUN_005CE890)
   *
   * What it does:
   * Returns the dword lane at offset `+0x4C` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane4C(const SparseRuntimeSmallLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane4C;
  }

  /**
   * Address: 0x005CE8A0 (FUN_005CE8A0)
   *
   * What it does:
   * Returns the byte lane at offset `+0xAC` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint8_t ReadSparseLaneAC(const SparseRuntimeSmallLaneAccessorView* const runtime) noexcept
  {
    return runtime->laneAC;
  }

  /**
   * Address: 0x005964B0 (FUN_005964B0)
   *
   * What it does:
   * Returns the dword lane at offset `+0x900` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane900(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane900;
  }

  /**
   * Address: 0x005964C0 (FUN_005964C0)
   *
   * What it does:
   * Returns the dword lane at offset `+0x904` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane904(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane904;
  }

  /**
   * Address: 0x005964D0 (FUN_005964D0)
   *
   * What it does:
   * Returns the dword lane at offset `+0x148` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane148(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane148;
  }

  /**
   * Address: 0x00596500 (FUN_00596500)
   *
   * What it does:
   * Returns the dword lane at offset `+0x550` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane550(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane550;
  }

  /**
   * Address: 0x00596510 (FUN_00596510)
   *
   * What it does:
   * Returns the dword lane at offset `+0x55C` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane55C(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane55C;
  }

  /**
   * Address: 0x00596520 (FUN_00596520)
   *
   * What it does:
   * Returns the dword lane at offset `+0x4B0` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane4B0(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane4B0;
  }

  /**
   * Address: 0x00596530 (FUN_00596530)
   *
   * What it does:
   * Returns the dword lane at offset `+0x4B4` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane4B4(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane4B4;
  }

  /**
   * Address: 0x00596540 (FUN_00596540)
   *
   * What it does:
   * Returns the byte lane at offset `+0x68A` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint8_t ReadSparseLane68A(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane68A;
  }

  /**
   * Address: 0x00596550 (FUN_00596550)
   *
   * What it does:
   * Returns the byte lane at offset `+0x68B` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint8_t ReadSparseLane68B(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane68B;
  }

  /**
   * Address: 0x005965C0 (FUN_005965C0)
   *
   * What it does:
   * Returns the dword lane at offset `+0x240` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane240(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane240;
  }

  /**
   * Address: 0x00598B50 (FUN_00598B50)
   *
   * What it does:
   * Returns the byte lane at offset `+0x2A2` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint8_t ReadSparseLane2A2(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane2A2;
  }

  /**
   * Address: 0x00598B60 (FUN_00598B60)
   *
   * What it does:
   * Returns the dword lane at offset `+0x0E0` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane0E0(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane0E0;
  }

  /**
   * Address: 0x00598B70 (FUN_00598B70)
   *
   * What it does:
   * Returns the dword lane at offset `+0x0E4` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane0E4(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane0E4;
  }

  /**
   * Address: 0x00598B80 (FUN_00598B80)
   *
   * What it does:
   * Writes one dword into lane `+0x0E4` and marks lane `+0x141` as dirty.
   */
  [[maybe_unused]] SparseRuntimeLaneAccessorView* WriteSparseLane0E4AndMarkLane141(
    SparseRuntimeLaneAccessorView* const runtime,
    const std::uint32_t value
  ) noexcept
  {
    runtime->lane0E4 = value;
    runtime->lane141 = 1u;
    return runtime;
  }

  /**
   * Address: 0x0059A3B0 (FUN_0059A3B0)
   *
   * What it does:
   * Returns the dword lane at offset `+0x980` from one sparse runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadSparseLane980(const SparseRuntimeLaneAccessorView* const runtime) noexcept
  {
    return runtime->lane980;
  }

  /**
   * Address: 0x007EFF80 (FUN_007EFF80)
   * Address: 0x00889C60 (FUN_00889C60)
   *
   * What it does:
   * Returns element count for one `[begin,end)` lane with 136-byte entries.
   */
  [[maybe_unused]] std::int32_t CountElement136RangeEntries(const LegacyRangeRuntimeView& runtime) noexcept
  {
    return CountRangeEntries<136u>(runtime);
  }

  /**
   * Address: 0x007F2640 (FUN_007F2640)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0xB9 sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffsetB9RuntimeView** AscendLink0ToOffsetB9Sentinel(
    SentinelNodeOffsetB9RuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x007F2F10 (FUN_007F2F10)
   *
   * What it does:
   * Walks one tree branch via `link8` until the 0xB9 sentinel lane is reached.
   */
  [[maybe_unused]] SentinelNodeOffsetB9RuntimeView* WalkLink8ToOffsetB9Sentinel(
    SentinelNodeOffsetB9RuntimeView* node
  ) noexcept
  {
    return WalkLink8UntilSentinel(node);
  }

  /**
   * Address: 0x007F3000 (FUN_007F3000)
   *
   * What it does:
   * Walks one tree branch via `link8` until the 0x2D sentinel lane is reached.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView* WalkLink8ToOffset2DSentinel(
    SentinelNodeOffset2DRuntimeView* node
  ) noexcept
  {
    return WalkLink8UntilSentinel(node);
  }

  /**
   * Address: 0x007F3020 (FUN_007F3020)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x2D sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView** AscendLink0ToOffset2DSentinel(
    SentinelNodeOffset2DRuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x007F3530 (FUN_007F3530)
   *
   * What it does:
   * Fills one `[destination,end)` range with repeated 16-byte payload blocks.
   */
  [[maybe_unused]] QuadWordBlockRuntimeView* FillQuadWordBlocks(
    QuadWordBlockRuntimeView* destination,
    QuadWordBlockRuntimeView* end,
    const QuadWordBlockRuntimeView& fillValue
  ) noexcept
  {
    return FillQuadWordBlockRange(destination, end, fillValue);
  }

  /**
   * Address: 0x007F3560 (FUN_007F3560)
   *
   * What it does:
   * Copies 16-byte payload blocks backward from `[sourceBegin,sourceEnd)` into
   * destination tail storage.
   */
  [[maybe_unused]] QuadWordBlockRuntimeView* CopyQuadWordBlocksBackward(
    QuadWordBlockRuntimeView* destinationEnd,
    const QuadWordBlockRuntimeView* sourceBegin,
    const QuadWordBlockRuntimeView* sourceEnd
  ) noexcept
  {
    return CopyQuadWordBlockRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x007FAD40 (FUN_007FAD40)
   *
   * What it does:
   * Clears one shared-ownership pair and releases one retained control block.
   */
  [[maybe_unused]] std::intptr_t ClearSharedOwnershipPairLaneA(SharedOwnershipPairRuntimeView* pair) noexcept
  {
    pair->object = nullptr;
    SharedControlBlockRuntimeView* const owner = pair->owner;
    pair->owner = nullptr;
    return ReleaseSharedControlBlockAndReturnLastValue(owner);
  }

  /**
   * Address: 0x007FADB0 (FUN_007FADB0)
   *
   * What it does:
   * Alias lane of shared-ownership pair clear/release behavior.
   */
  [[maybe_unused]] std::intptr_t ClearSharedOwnershipPairLaneB(SharedOwnershipPairRuntimeView* pair) noexcept
  {
    pair->object = nullptr;
    SharedControlBlockRuntimeView* const owner = pair->owner;
    pair->owner = nullptr;
    return ReleaseSharedControlBlockAndReturnLastValue(owner);
  }

  /**
   * Address: 0x007FAF90 (FUN_007FAF90)
   *
   * What it does:
   * Returns element count for one `[begin,end)` lane with 20-byte entries.
   */
  [[maybe_unused]] std::int32_t CountElement20RangeEntries(const LegacyRangeRuntimeView& runtime) noexcept
  {
    return CountRangeEntries<20u>(runtime);
  }

  /**
   * Address: 0x008154A0 (FUN_008154A0)
   *
   * What it does:
   * Clears one retained shared-owner lane and writes command/vector lanes into
   * one terrain-transfer runtime view.
   */
  [[maybe_unused]] std::intptr_t ResetTerrainTransferRuntime(
    const Float3RuntimeView* arg1Vector,
    TerrainTransferRuntimeView* runtime,
    const std::int32_t commandLane,
    const Float3RuntimeView* arg4Vector
  ) noexcept
  {
    runtime->retainedObject = nullptr;
    SharedControlBlockRuntimeView* const owner = runtime->retainedOwner;
    runtime->retainedOwner = nullptr;

    const std::intptr_t result = ReleaseSharedControlBlockAndReturnLastValue(owner);
    runtime->commandLane = commandLane;
    runtime->primaryVectorFromArg4 = *arg4Vector;
    runtime->secondaryVectorFromArg1 = *arg1Vector;
    return result;
  }

  /**
   * Address: 0x0081CCB0 (FUN_0081CCB0)
   *
   * What it does:
   * Reserves one contiguous 12-byte-per-vertex window in one lockable buffer
   * with 0x3000-vertex wrap semantics.
   */
  [[maybe_unused]] bool ReserveVertexTripletWindow(
    std::uint32_t** outMappedVertexData,
    VertexReservationRuntimeView* reservation,
    const std::uint32_t requestedVertexCount,
    std::uint32_t* outBaseVertex
  ) noexcept
  {
    const std::uint32_t current = reservation->reservedVertexCount;
    if (current + requestedVertexCount >= 0x3000u) {
      if (requestedVertexCount > 0x3000u) {
        return false;
      }

      reservation->reservedVertexCount = requestedVertexCount;
      *outBaseVertex = 0u;
      std::uint32_t* const mapped = LockVertexTripletWindow(*reservation, 0u, requestedVertexCount, 1);
      *outMappedVertexData = mapped;
      return mapped != nullptr;
    }

    std::uint32_t* const mapped = LockVertexTripletWindow(*reservation, current, requestedVertexCount, 4);
    *outMappedVertexData = mapped;
    if (mapped == nullptr) {
      return false;
    }

    *outBaseVertex = current;
    reservation->reservedVertexCount = current + requestedVertexCount;
    return true;
  }

  /**
   * Address: 0x0082DE20 (FUN_0082DE20)
   *
   * What it does:
   * Slides one tail dword range over a gap and commits the new end pointer.
   */
  [[maybe_unused]] std::uint32_t** MoveDwordTailLaneA(
    std::uint32_t** outResult,
    LegacyDwordSpanRuntimeView* span,
    std::uint32_t* destination,
    std::uint32_t* source
  ) noexcept
  {
    *outResult = MoveDwordTailToGapAndCommitEnd(*span, destination, source);
    return outResult;
  }

  /**
   * Address: 0x0082F1C0 (FUN_0082F1C0)
   *
   * What it does:
   * Alias lane of dword tail slide/commit behavior.
   */
  [[maybe_unused]] std::uint32_t** MoveDwordTailLaneB(
    std::uint32_t** outResult,
    LegacyDwordSpanRuntimeView* span,
    std::uint32_t* destination,
    std::uint32_t* source
  ) noexcept
  {
    *outResult = MoveDwordTailToGapAndCommitEnd(*span, destination, source);
    return outResult;
  }

  /**
   * Address: 0x0082F750 (FUN_0082F750)
   *
   * What it does:
   * Alias lane of dword tail slide/commit behavior.
   */
  [[maybe_unused]] std::uint32_t** MoveDwordTailLaneC(
    std::uint32_t** outResult,
    LegacyDwordSpanRuntimeView* span,
    std::uint32_t* destination,
    std::uint32_t* source
  ) noexcept
  {
    *outResult = MoveDwordTailToGapAndCommitEnd(*span, destination, source);
    return outResult;
  }

  /**
   * Address: 0x00830060 (FUN_00830060)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x25 sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset25RuntimeView** AscendLink0ToOffset25Sentinel(
    SentinelNodeOffset25RuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x00830920 (FUN_00830920)
   *
   * What it does:
   * Walks one tree branch via `link8` until the 0x25 sentinel lane is reached.
   */
  [[maybe_unused]] SentinelNodeOffset25RuntimeView* WalkLink8ToOffset25Sentinel(
    SentinelNodeOffset25RuntimeView* node
  ) noexcept
  {
    return WalkLink8UntilSentinel(node);
  }

  /**
   * Address: 0x00831690 (FUN_00831690)
   *
   * What it does:
   * Copies one dword range backward from source tail to destination tail.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardLaneA(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    return CopyDwordRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x008318B0 (FUN_008318B0)
   *
   * What it does:
   * Alias lane of backward dword range copy behavior.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardLaneB(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    return CopyDwordRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00831960 (FUN_00831960)
   *
   * What it does:
   * Alias lane of backward dword range copy behavior.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardLaneC(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    return CopyDwordRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00836B90 (FUN_00836B90)
   *
   * What it does:
   * Relinks one intrusive node to a caller-provided owner-slot pointer lane.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView* RelinkIntrusiveNodeViaIndirectOwner(
    IntrusiveLinkRuntimeView* node,
    IntrusiveLinkRuntimeView*** ownerSlotAddress
  ) noexcept
  {
    IntrusiveLinkRuntimeView** const ownerSlot = (ownerSlotAddress != nullptr) ? *ownerSlotAddress : nullptr;
    return RelinkIntrusiveNode(node, ownerSlot);
  }

  /**
   * Address: 0x00836BD0 (FUN_00836BD0)
   *
   * What it does:
   * Relinks one intrusive node to owner storage located at `owner+0x08`.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView* RelinkIntrusiveNodeViaOwnerOffset08(
    IntrusiveLinkRuntimeView* node,
    IntrusiveOwnerAtOffset08RuntimeView* owner
  ) noexcept
  {
    IntrusiveLinkRuntimeView** const ownerSlot = (owner != nullptr) ? &owner->head : nullptr;
    return RelinkIntrusiveNode(node, ownerSlot);
  }

  /**
   * Address: 0x00836E80 (FUN_00836E80)
   *
   * What it does:
   * Reports whether one 48-byte-entry range is empty.
   */
  [[maybe_unused]] bool IsElement48RangeEmpty(const LegacyRangeRuntimeView& runtime) noexcept
  {
    return runtime.begin == nullptr || CountRangeEntries<48u>(runtime) == 0;
  }

  /**
   * Address: 0x0083A620 (FUN_0083A620)
   *
   * What it does:
   * Loads one pointer lane from the primary global storage, dereferences it,
   * and writes the pointed dword value to `outResult`.
   */
  [[maybe_unused]] std::uint32_t* LoadPrimaryGlobalPointerPointee(std::uint32_t* outResult) noexcept
  {
    return WriteGlobalPointerLanePointee(outResult, gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083A630 (FUN_0083A630)
   *
   * What it does:
   * Writes the primary global pointer-lane value to `outResult`.
   */
  [[maybe_unused]] std::uint32_t* LoadPrimaryGlobalPointerValue(std::uint32_t* outResult) noexcept
  {
    return WriteGlobalPointerLaneValue(outResult, gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083AA60 (FUN_0083AA60)
   *
   * What it does:
   * Writes the secondary global pointer-lane value to `outResult`.
   */
  [[maybe_unused]] std::uint32_t* LoadSecondaryGlobalPointerValue(std::uint32_t* outResult) noexcept
  {
    return WriteGlobalPointerLaneValue(outResult, gSecondaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083B0E0 (FUN_0083B0E0)
   *
   * What it does:
   * Returns the primary global pointer-lane value.
   */
  [[maybe_unused]] std::uint32_t ReadPrimaryGlobalPointerValue() noexcept
  {
    return ReadGlobalPointerLaneValue(gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083B4B0 (FUN_0083B4B0)
   *
   * What it does:
   * Returns the secondary global pointer-lane value.
   */
  [[maybe_unused]] std::uint32_t ReadSecondaryGlobalPointerValue() noexcept
  {
    return ReadGlobalPointerLaneValue(gSecondaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083B840 (FUN_0083B840)
   *
   * What it does:
   * Returns the scalar lane stored in primary global storage.
   */
  [[maybe_unused]] std::uint32_t ReadPrimaryGlobalScalarValue() noexcept
  {
    return ReadGlobalScalarLaneValue(gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083BBE0 (FUN_0083BBE0)
   *
   * What it does:
   * Returns the address of primary global storage (stdcall lane with one unused
   * stack argument).
   */
  [[maybe_unused]] GlobalAccessorStorageRuntimeView* ReadPrimaryGlobalStorageAddressLaneA(
    const std::int32_t /*unused*/
  ) noexcept
  {
    return ReadGlobalStorageAddress(gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083BC30 (FUN_0083BC30)
   *
   * What it does:
   * Loads one pointer lane from secondary global storage, dereferences it, and
   * writes the pointed dword value to `outResult`.
   */
  [[maybe_unused]] std::uint32_t* LoadSecondaryGlobalPointerPointee(std::uint32_t* outResult) noexcept
  {
    return WriteGlobalPointerLanePointee(outResult, gSecondaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083BC40 (FUN_0083BC40)
   *
   * What it does:
   * Returns the scalar lane stored in secondary global storage.
   */
  [[maybe_unused]] std::uint32_t ReadSecondaryGlobalScalarValue() noexcept
  {
    return ReadGlobalScalarLaneValue(gSecondaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083BFE0 (FUN_0083BFE0)
   *
   * What it does:
   * Returns the address of secondary global storage (stdcall lane with one
   * unused stack argument).
   */
  [[maybe_unused]] GlobalAccessorStorageRuntimeView* ReadSecondaryGlobalStorageAddress(
    const std::int32_t /*unused*/
  ) noexcept
  {
    return ReadGlobalStorageAddress(gSecondaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083C200 (FUN_0083C200)
   *
   * What it does:
   * Alias lane that returns the address of primary global storage (stdcall
   * shape with one unused stack argument).
   */
  [[maybe_unused]] GlobalAccessorStorageRuntimeView* ReadPrimaryGlobalStorageAddressLaneB(
    const std::int32_t /*unused*/
  ) noexcept
  {
    return ReadGlobalStorageAddress(gPrimaryGlobalAccessorStorage);
  }

  /**
   * Address: 0x0083B050 (FUN_0083B050, sub_83B050)
   *
   * What it does:
   * Writes the lower-bound node address for one dword key in the primary
   * nil-`0x2D` tree lane to `outNode`.
   */
  [[maybe_unused]] OrderedSentinelNodeOffset2DRuntimeView** FindPrimaryOffset2DTreeLowerBoundNode(
    OrderedSentinelNodeOffset2DRuntimeView** outNode,
    const std::uint32_t* const keyAddress
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadPrimaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<OrderedSentinelNodeOffset2DRuntimeView*>(globalHeadAddress);
    *outNode = LowerBoundSentinelTreeByDwordKey(globalHead, *keyAddress);
    return outNode;
  }

  /**
   * Address: 0x0083B440 (FUN_0083B440, sub_83B440)
   *
   * What it does:
   * Writes the lower-bound node address for one dword key in the secondary
   * nil-`0x15` tree lane to `outNode`.
   */
  [[maybe_unused]] OrderedSentinelNodeOffset15RuntimeView** FindSecondaryOffset15TreeLowerBoundNode(
    OrderedSentinelNodeOffset15RuntimeView** outNode,
    const std::uint32_t* const keyAddress
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadSecondaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<OrderedSentinelNodeOffset15RuntimeView*>(globalHeadAddress);
    *outNode = LowerBoundSentinelTreeByDwordKey(globalHead, *keyAddress);
    return outNode;
  }

  template <typename TSentinelNode>
  [[nodiscard]] TSentinelNode* RotateSentinelTreeLeftViaGlobalHead(
    TSentinelNode* const pivot,
    TSentinelNode* const globalHead
  ) noexcept
  {
    TSentinelNode* const promoted = pivot->link8;
    pivot->link8 = promoted->link0;
    if (pivot->link8->isSentinel == 0u) {
      pivot->link8->link4 = pivot;
    }

    promoted->link4 = pivot->link4;
    if (pivot == globalHead->link4) {
      globalHead->link4 = promoted;
    } else {
      TSentinelNode* const parent = pivot->link4;
      if (pivot == parent->link0) {
        parent->link0 = promoted;
      } else {
        parent->link8 = promoted;
      }
    }

    promoted->link0 = pivot;
    pivot->link4 = promoted;
    return promoted;
  }

  template <typename TSentinelNode>
  [[nodiscard]] TSentinelNode* RotateSentinelTreeRightViaGlobalHead(
    TSentinelNode* const pivot,
    TSentinelNode* const globalHead
  ) noexcept
  {
    TSentinelNode* const promoted = pivot->link0;
    pivot->link0 = promoted->link8;
    if (pivot->link0->isSentinel == 0u) {
      pivot->link0->link4 = pivot;
    }

    promoted->link4 = pivot->link4;
    if (pivot == globalHead->link4) {
      globalHead->link4 = promoted;
    } else {
      TSentinelNode* const parent = pivot->link4;
      if (pivot == parent->link8) {
        parent->link8 = promoted;
      } else {
        parent->link0 = promoted;
      }
    }

    promoted->link8 = pivot;
    pivot->link4 = promoted;
    return promoted;
  }

  /**
   * Address: 0x0083B0F0 (FUN_0083B0F0, sub_83B0F0)
   *
   * What it does:
   * Performs one left rotation in the nil-`0x2D` key-action map tree rooted
   * by the primary global head node lane.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView* RotateOffset2DTreeLeftViaPrimaryGlobalHead(
    SentinelNodeOffset2DRuntimeView* const pivot
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadPrimaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<SentinelNodeOffset2DRuntimeView*>(globalHeadAddress);
    return RotateSentinelTreeLeftViaGlobalHead(pivot, globalHead);
  }

  /**
   * Address: 0x0083B1A0 (FUN_0083B1A0, sub_83B1A0)
   *
   * What it does:
   * Performs one right rotation in the nil-`0x2D` key-action map tree rooted
   * by the primary global head node lane.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView* RotateOffset2DTreeRightViaPrimaryGlobalHead(
    SentinelNodeOffset2DRuntimeView* const pivot
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadPrimaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<SentinelNodeOffset2DRuntimeView*>(globalHeadAddress);
    return RotateSentinelTreeRightViaGlobalHead(pivot, globalHead);
  }

  /**
   * Address: 0x0083B4C0 (FUN_0083B4C0, sub_83B4C0)
   *
   * What it does:
   * Performs one left rotation in the nil-`0x15` key-repeat map tree rooted by
   * the secondary global head node lane.
   */
  [[maybe_unused]] SentinelNodeOffset15RuntimeView* RotateOffset15TreeLeftViaSecondaryGlobalHead(
    SentinelNodeOffset15RuntimeView* const pivot
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadSecondaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<SentinelNodeOffset15RuntimeView*>(globalHeadAddress);
    return RotateSentinelTreeLeftViaGlobalHead(pivot, globalHead);
  }

  /**
   * Address: 0x0083B570 (FUN_0083B570, sub_83B570)
   *
   * What it does:
   * Performs one right rotation in the nil-`0x15` key-repeat map tree rooted
   * by the secondary global head node lane.
   */
  [[maybe_unused]] SentinelNodeOffset15RuntimeView* RotateOffset15TreeRightViaSecondaryGlobalHead(
    SentinelNodeOffset15RuntimeView* const pivot
  ) noexcept
  {
    const auto globalHeadAddress = static_cast<std::uintptr_t>(ReadSecondaryGlobalPointerValue());
    auto* const globalHead = reinterpret_cast<SentinelNodeOffset15RuntimeView*>(globalHeadAddress);
    return RotateSentinelTreeRightViaGlobalHead(pivot, globalHead);
  }

  /**
   * Address: 0x0083B140 (FUN_0083B140)
   *
   * What it does:
   * Walks one tree branch via `link8` until the 0x2D sentinel lane is reached.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView* WalkLink8ToOffset2DSentinelLaneB(
    SentinelNodeOffset2DRuntimeView* node
  ) noexcept
  {
    return WalkLink8UntilSentinel(node);
  }

  /**
   * Address: 0x0083B160 (FUN_0083B160)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x2D sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset2DRuntimeView** AscendLink0ToOffset2DSentinelLaneB(
    SentinelNodeOffset2DRuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x0083B510 (FUN_0083B510)
   *
   * What it does:
   * Walks one tree branch via `link8` until the 0x15 sentinel lane is reached.
   */
  [[maybe_unused]] SentinelNodeOffset15RuntimeView* WalkLink8ToOffset15Sentinel(
    SentinelNodeOffset15RuntimeView* node
  ) noexcept
  {
    return WalkLink8UntilSentinel(node);
  }

  /**
   * Address: 0x0083B530 (FUN_0083B530)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x15 sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset15RuntimeView** AscendLink0ToOffset15Sentinel(
    SentinelNodeOffset15RuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x008487F0 (FUN_008487F0)
   *
   * What it does:
   * Returns element count for one `[begin,end)` lane with 12-byte entries.
   */
  [[maybe_unused]] std::int32_t CountElement12RangeEntries(const LegacyRangeRuntimeView& runtime) noexcept
  {
    return CountRangeEntries<12u>(runtime);
  }

  /**
   * Address: 0x00849860 (FUN_00849860)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x15 sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset15RuntimeView** AscendLink0ToOffset15SentinelLaneB(
    SentinelNodeOffset15RuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }

  /**
   * Address: 0x00849BF0 (FUN_00849BF0)
   *
   * What it does:
   * Walks one tree-link lane via `link0` until the 0x39 sentinel byte is set.
   */
  [[maybe_unused]] SentinelNodeOffset39RuntimeView** AscendLink0ToOffset39Sentinel(
    SentinelNodeOffset39RuntimeView** linkSlot
  ) noexcept
  {
    return AscendLink0UntilSentinel(linkSlot);
  }
} // namespace

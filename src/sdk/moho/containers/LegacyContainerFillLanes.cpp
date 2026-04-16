#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <cstdint>
#include <stdexcept>

namespace
{
  [[nodiscard]] std::uint32_t* FillDwordSpanByCount(
    const std::uint32_t* const valueSlot,
    std::uint32_t* const destination,
    const std::uint32_t count
  ) noexcept
  {
    std::uint32_t* write = destination;
    std::uint32_t remaining = count;
    while (remaining != 0u) {
      *write = *valueSlot;
      ++write;
      --remaining;
    }

    return write;
  }

  [[nodiscard]] std::uint32_t* FillDwordSpanByEnd(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* const valueSlot
  ) noexcept
  {
    while (begin != end) {
      *begin = *valueSlot;
      ++begin;
    }
    return begin;
  }

  struct GlobalIntrusiveSentinelRuntimeView
  {
    GlobalIntrusiveSentinelRuntimeView* prev;
    GlobalIntrusiveSentinelRuntimeView* next;

    GlobalIntrusiveSentinelRuntimeView() noexcept
      : prev(this)
      , next(this)
    {}
  };
#if defined(_M_IX86)
  static_assert(sizeof(GlobalIntrusiveSentinelRuntimeView) == 0x08, "GlobalIntrusiveSentinelRuntimeView size must be 0x08");
#endif

  [[nodiscard]] std::uint32_t* ResetGlobalIntrusiveSentinel(GlobalIntrusiveSentinelRuntimeView& sentinel) noexcept
  {
    sentinel.prev->next = sentinel.next;
    sentinel.next->prev = sentinel.prev;

    auto* const self = &sentinel;
    sentinel.prev = self;
    sentinel.next = self;
    return reinterpret_cast<std::uint32_t*>(&sentinel.prev);
  }

  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneA;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneB;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneC;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneD;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneE;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneF;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneG;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneH;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneI;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneJ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneK;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneL;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneM;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneN;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneO;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneP;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneQ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneR;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneS;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneT;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneU;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneV;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneW;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneX;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneY;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneZ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAA;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAB;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAC;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAD;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAE;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAF;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAG;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAH;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAI;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAJ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAK;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAL;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAM;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAN;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAO;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAP;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAQ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAR;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAS;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAT;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAU;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAV;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAW;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAX;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAY;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneAZ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBA;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBB;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBC;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBD;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBE;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBF;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBG;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBH;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBI;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBJ;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBK;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBL;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBM;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBN;
  GlobalIntrusiveSentinelRuntimeView gGlobalIntrusiveSentinelLaneBO;

  struct IntrusiveLinkRuntimeView
  {
    IntrusiveLinkRuntimeView** ownerSlot; // +0x00
    IntrusiveLinkRuntimeView* next;       // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(IntrusiveLinkRuntimeView) == 0x08, "IntrusiveLinkRuntimeView size must be 0x08");
#endif

  [[nodiscard]] IntrusiveLinkRuntimeView** LocateIntrusiveNodeOwnerLink(
    IntrusiveLinkRuntimeView* const node
  ) noexcept
  {
    IntrusiveLinkRuntimeView** cursor = node->ownerSlot;
    if (cursor == nullptr) {
      return nullptr;
    }

    while (*cursor != node) {
      cursor = &((*cursor)->next);
    }
    return cursor;
  }

  using ScalarDeletingDtorCall = std::intptr_t(__thiscall*)(void* self, std::int32_t deleteFlag);

  [[nodiscard]] std::intptr_t InvokeScalarDeletingDtorSlot0(void* const object, void** const vtable) noexcept
  {
    const auto destroy = reinterpret_cast<ScalarDeletingDtorCall>(vtable[0]);
    return destroy(object, 0);
  }

  struct VirtualDtor16RuntimeView
  {
    void** vtable;          // +0x00
    std::uint32_t lane04;   // +0x04
    std::uint32_t lane08;   // +0x08
    std::uint32_t lane0C;   // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(VirtualDtor16RuntimeView) == 0x10, "VirtualDtor16RuntimeView size must be 0x10");
#endif

  struct VirtualDtor136RuntimeView
  {
    void** vtable;          // +0x00
    std::byte payload[0x84]; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(VirtualDtor136RuntimeView) == 0x88, "VirtualDtor136RuntimeView size must be 0x88");
#endif

  [[nodiscard]] std::intptr_t DestroyVirtualRangeStride16(
    VirtualDtor16RuntimeView* begin,
    VirtualDtor16RuntimeView* end
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(begin);
    for (VirtualDtor16RuntimeView* item = begin; item != end; ++item) {
      result = InvokeScalarDeletingDtorSlot0(item, item->vtable);
    }
    return result;
  }

  [[nodiscard]] std::intptr_t DestroyVirtualRangeStride136(
    VirtualDtor136RuntimeView* begin,
    VirtualDtor136RuntimeView* end
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(begin);
    std::byte* itemBytes = reinterpret_cast<std::byte*>(begin);
    const std::byte* const endBytes = reinterpret_cast<const std::byte*>(end);
    while (itemBytes != endBytes) {
      auto* const item = reinterpret_cast<VirtualDtor136RuntimeView*>(itemBytes);
      result = InvokeScalarDeletingDtorSlot0(item, item->vtable);
      itemBytes += sizeof(VirtualDtor136RuntimeView);
    }
    return result;
  }

  using SharedOwnerReleaseCall = std::intptr_t(__thiscall*)(void* self);

  struct SharedOwnerControlBlockRuntimeView
  {
    void** vtable;          // +0x00
    volatile LONG useCount; // +0x04
    volatile LONG weakCount; // +0x08
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(SharedOwnerControlBlockRuntimeView) == 0x0C,
    "SharedOwnerControlBlockRuntimeView size must be 0x0C"
  );
  static_assert(
    offsetof(SharedOwnerControlBlockRuntimeView, useCount) == 0x04,
    "SharedOwnerControlBlockRuntimeView::useCount offset must be 0x04"
  );
  static_assert(
    offsetof(SharedOwnerControlBlockRuntimeView, weakCount) == 0x08,
    "SharedOwnerControlBlockRuntimeView::weakCount offset must be 0x08"
  );
#endif

  [[nodiscard]] std::intptr_t InvokeSharedOwnerReleaseSlot(
    SharedOwnerControlBlockRuntimeView* const owner,
    const std::size_t slot
  ) noexcept
  {
    const auto callback = reinterpret_cast<SharedOwnerReleaseCall>(owner->vtable[slot]);
    return callback(owner);
  }

  [[nodiscard]] std::intptr_t ReleaseSharedOwnerControlBlock(
    SharedOwnerControlBlockRuntimeView* const owner
  ) noexcept
  {
    std::intptr_t result = 0;
    if (owner == nullptr) {
      return result;
    }

    result = reinterpret_cast<std::intptr_t>(const_cast<LONG*>(&owner->useCount));
    if (InterlockedExchangeAdd(&owner->useCount, -1) == 1) {
      result = InvokeSharedOwnerReleaseSlot(owner, 1u);
      if (InterlockedExchangeAdd(&owner->weakCount, -1) == 1) {
        result = InvokeSharedOwnerReleaseSlot(owner, 2u);
      }
    }

    return result;
  }

  struct IntrusiveRefCountedObjectRuntimeView
  {
    void** vtable;         // +0x00
    std::int32_t refCount; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveRefCountedObjectRuntimeView, refCount) == 0x04,
    "IntrusiveRefCountedObjectRuntimeView::refCount offset must be 0x04"
  );
#endif

  [[nodiscard]] std::uint32_t* AssignIntrusiveRefCountedObjectWord(
    std::uint32_t* const destinationWord,
    const std::uint32_t incomingWord
  ) noexcept
  {
    const std::uint32_t previousWord = *destinationWord;
    if (previousWord == incomingWord) {
      return destinationWord;
    }

    if (previousWord != 0u) {
      auto* const previous = reinterpret_cast<IntrusiveRefCountedObjectRuntimeView*>(previousWord);
      if (previous->refCount-- == 1) {
        const auto destroy = reinterpret_cast<ScalarDeletingDtorCall>(previous->vtable[0]);
        (void)destroy(previous, 1);
      }
    }

    *destinationWord = incomingWord;
    if (incomingWord != 0u) {
      auto* const incoming = reinterpret_cast<IntrusiveRefCountedObjectRuntimeView*>(incomingWord);
      ++incoming->refCount;
    }
    return destinationWord;
  }

  struct SmallBufferArrayRuntimeView
  {
    std::uint32_t lane00;                       // +0x00
    SharedOwnerControlBlockRuntimeView* owner; // +0x04
    std::byte pad08_27[0x20];
    void* begin;                // +0x28
    void* cursor;               // +0x2C
    void* end;                  // +0x30
    void** inlineStorageCursor; // +0x34
  };
#if defined(_M_IX86)
  static_assert(offsetof(SmallBufferArrayRuntimeView, owner) == 0x04, "SmallBufferArrayRuntimeView::owner offset must be 0x04");
  static_assert(offsetof(SmallBufferArrayRuntimeView, begin) == 0x28, "SmallBufferArrayRuntimeView::begin offset must be 0x28");
  static_assert(offsetof(SmallBufferArrayRuntimeView, cursor) == 0x2C, "SmallBufferArrayRuntimeView::cursor offset must be 0x2C");
  static_assert(offsetof(SmallBufferArrayRuntimeView, end) == 0x30, "SmallBufferArrayRuntimeView::end offset must be 0x30");
  static_assert(
    offsetof(SmallBufferArrayRuntimeView, inlineStorageCursor) == 0x34,
    "SmallBufferArrayRuntimeView::inlineStorageCursor offset must be 0x34"
  );
#endif

  [[nodiscard]] std::intptr_t ResetSmallBufferArrayAndReleaseOwner(SmallBufferArrayRuntimeView& array) noexcept
  {
    if (array.begin != static_cast<void*>(array.inlineStorageCursor)) {
      operator delete[](array.begin);
      array.begin = array.inlineStorageCursor;
      array.end = *array.inlineStorageCursor;
    }

    array.cursor = array.begin;
    return ReleaseSharedOwnerControlBlock(array.owner);
  }

  /**
   * Address: 0x0054DBC0 (FUN_0054DBC0)
   *
   * What it does:
   * Runs scalar-delete destruction for one small-buffer array owner lane.
   * It resets heap-backed storage to inline storage and releases the shared owner.
   */
  [[maybe_unused]] SmallBufferArrayRuntimeView* DestroySmallBufferArrayOwnerScalar(
    SmallBufferArrayRuntimeView* const self,
    const std::uint8_t deleteFlag
  ) noexcept
  {
    // Inlined block from FUN_0054DBE0.
    ResetSmallBufferArrayAndReleaseOwner(*self);
    if ((deleteFlag & 1u) != 0u) {
      operator delete(self);
    }
    return self;
  }

  struct DwordTripleLaneRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
  };
  static_assert(sizeof(DwordTripleLaneRuntimeView) == 0x0C, "DwordTripleLaneRuntimeView size must be 0x0C");
  static_assert(
    offsetof(DwordTripleLaneRuntimeView, lane08) == 0x08,
    "DwordTripleLaneRuntimeView::lane08 offset must be 0x08"
  );

  struct DwordPointerLane04RuntimeView
  {
    std::uint32_t lane00 = 0u;              // +0x00
    const std::uint32_t* lane04 = nullptr;  // +0x04
  };
  static_assert(sizeof(DwordPointerLane04RuntimeView) == 0x08, "DwordPointerLane04RuntimeView size must be 0x08");
  static_assert(
    offsetof(DwordPointerLane04RuntimeView, lane04) == 0x04,
    "DwordPointerLane04RuntimeView::lane04 offset must be 0x04"
  );

  struct DwordBytePairLane
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint8_t lane04 = 0u;  // +0x04
  };
  static_assert(offsetof(DwordBytePairLane, lane04) == 0x04, "DwordBytePairLane::lane04 offset must be 0x04");

  struct DwordPairLaneRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
  };
  static_assert(sizeof(DwordPairLaneRuntimeView) == 0x08, "DwordPairLaneRuntimeView size must be 0x08");
  static_assert(offsetof(DwordPairLaneRuntimeView, lane04) == 0x04, "DwordPairLaneRuntimeView::lane04 offset must be 0x04");

  struct ByteAt120RuntimeView
  {
    std::byte pad0000_011F[0x120];
    std::uint8_t lane120 = 0u; // +0x120
  };
  static_assert(offsetof(ByteAt120RuntimeView, lane120) == 0x120, "ByteAt120RuntimeView::lane120 offset must be 0x120");

  struct WordAt28RuntimeView
  {
    std::byte pad0000_0027[0x28];
    std::uint32_t lane28 = 0u; // +0x28
  };
  static_assert(offsetof(WordAt28RuntimeView, lane28) == 0x28, "WordAt28RuntimeView::lane28 offset must be 0x28");

  struct FloatAt0CRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    float lane0C = 0.0f;       // +0x0C
  };
  static_assert(offsetof(FloatAt0CRuntimeView, lane0C) == 0x0C, "FloatAt0CRuntimeView::lane0C offset must be 0x0C");

  /**
   * Address: 0x006C3860 (FUN_006C3860)
   *
   * What it does:
   * Returns the minimum scalar across five float lanes.
   */
  [[maybe_unused]] float MinOfFiveFloatLanes(
    const float lane0,
    float lane1,
    const float lane2,
    const float lane3,
    const float lane4
  ) noexcept
  {
    if (lane0 <= lane1) {
      lane1 = lane0;
    }

    float result = lane3;
    if (lane3 > lane2) {
      result = lane2;
    }
    if (lane1 <= result) {
      result = lane1;
    }
    if (lane4 <= result) {
      return lane4;
    }
    return result;
  }

  /**
   * Address: 0x006C3890 (FUN_006C3890)
   *
   * What it does:
   * Returns the maximum scalar across five float lanes.
   */
  [[maybe_unused]] float MaxOfFiveFloatLanes(
    const float lane0,
    float lane1,
    const float lane2,
    const float lane3,
    const float lane4
  ) noexcept
  {
    if (lane0 > lane1) {
      lane1 = lane0;
    }

    float result = lane3;
    if (lane2 > lane3) {
      result = lane2;
    }
    if (lane1 > result) {
      result = lane1;
    }
    if (lane4 > result) {
      return lane4;
    }
    return result;
  }

  /**
   * Address: 0x006C38C0 (FUN_006C38C0)
   *
   * What it does:
   * Reads one byte lane at offset `+0x120`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAt120(const ByteAt120RuntimeView* const source) noexcept
  {
    return source->lane120;
  }

  /**
   * Address: 0x006C3950 (FUN_006C3950)
   *
   * What it does:
   * Stores one scalar dword into lane `+0x04`.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* StoreWordAtOffset4(
    DwordPairLaneRuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane04 = value;
    return outValue;
  }

  /**
   * Address: 0x006C3960 (FUN_006C3960)
   *
   * What it does:
   * Stores one scalar dword into lane `+0x28`.
   */
  [[maybe_unused]] WordAt28RuntimeView* StoreWordAtOffset28(
    WordAt28RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane28 = value;
    return outValue;
  }

  /**
   * Address: 0x006C3A90 (FUN_006C3A90)
   *
   * What it does:
   * Stores one scalar float into lane `+0x0C`.
   */
  [[maybe_unused]] FloatAt0CRuntimeView* StoreFloatAtOffset0C(
    FloatAt0CRuntimeView* const outValue,
    const float value
  ) noexcept
  {
    outValue->lane0C = value;
    return outValue;
  }

  struct DwordSpanRuntimeView
  {
    std::uint32_t origin = 0u; // +0x00
    std::uint32_t begin = 0u;  // +0x04
    std::uint32_t end = 0u;    // +0x08
    std::uint32_t cursor = 0u; // +0x0C
  };
  static_assert(sizeof(DwordSpanRuntimeView) == 0x10, "DwordSpanRuntimeView size must be 0x10");
  static_assert(offsetof(DwordSpanRuntimeView, begin) == 0x04, "DwordSpanRuntimeView::begin offset must be 0x04");
  static_assert(offsetof(DwordSpanRuntimeView, end) == 0x08, "DwordSpanRuntimeView::end offset must be 0x08");
  static_assert(offsetof(DwordSpanRuntimeView, cursor) == 0x0C, "DwordSpanRuntimeView::cursor offset must be 0x0C");

  struct FiveWordAndTwoFlagsRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
    std::uint32_t lane10 = 0u; // +0x10
    std::uint8_t flag14 = 0u;  // +0x14
    std::uint8_t flag15 = 0u;  // +0x15
  };
  static_assert(
    offsetof(FiveWordAndTwoFlagsRuntimeView, flag14) == 0x14,
    "FiveWordAndTwoFlagsRuntimeView::flag14 offset must be 0x14"
  );
  static_assert(
    offsetof(FiveWordAndTwoFlagsRuntimeView, flag15) == 0x15,
    "FiveWordAndTwoFlagsRuntimeView::flag15 offset must be 0x15"
  );

  struct HeaderAndThreeWordLanesRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
  };
  static_assert(
    sizeof(HeaderAndThreeWordLanesRuntimeView) == 0x10,
    "HeaderAndThreeWordLanesRuntimeView size must be 0x10"
  );

  struct SpanHeaderSelfRefRuntimeView
  {
    std::uint32_t begin = 0u;  // +0x00
    std::uint32_t cursor = 0u; // +0x04
    std::uint32_t end = 0u;    // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
  };
  static_assert(sizeof(SpanHeaderSelfRefRuntimeView) == 0x10, "SpanHeaderSelfRefRuntimeView size must be 0x10");

  struct LinkedWordNodeRuntimeView
  {
    std::uint32_t nextNodeAddress = 0u; // +0x00
  };
  static_assert(sizeof(LinkedWordNodeRuntimeView) == 0x04, "LinkedWordNodeRuntimeView size must be 0x04");

  [[nodiscard]] std::uint32_t* SwapThreeTrailingWordLanes(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    const std::uint32_t lane04 = rhs->lane04;
    rhs->lane04 = lhs->lane04;
    lhs->lane04 = lane04;

    const std::uint32_t lane08 = rhs->lane08;
    rhs->lane08 = lhs->lane08;
    lhs->lane08 = lane08;

    const std::uint32_t lane0C = rhs->lane0C;
    rhs->lane0C = lhs->lane0C;
    lhs->lane0C = lane0C;

    return reinterpret_cast<std::uint32_t*>(lhs);
  }

  [[nodiscard]] std::uint32_t* SwapSingleWordLane(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    const std::uint32_t lane = *lhs;
    *lhs = *rhs;
    *rhs = lane;
    return lhs;
  }

  [[nodiscard]] std::uint32_t* CopyFirstWordFromIndirectLane04(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }

  [[nodiscard]] std::uint32_t** AdvancePointerSlotFromNodeHead(std::uint32_t** const pointerSlot) noexcept
  {
    *pointerSlot = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(**pointerSlot));
    return pointerSlot;
  }

  /**
   * Address: 0x00899910 (FUN_00899910)
   * Address: 0x0089A480 (FUN_0089A480)
   *
   * What it does:
   * Copies one `{dword, byte}` payload from separate source pointers.
   */
  [[nodiscard]] DwordBytePairLane* CopyWordAndBytePair(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const wordValue,
    const std::uint8_t* const byteValue
  ) noexcept
  {
    outValue->lane00 = *wordValue;
    outValue->lane04 = *byteValue;
    return outValue;
  }

  [[nodiscard]] std::uint32_t* ZeroSingleWordLane(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x007036C0 (FUN_007036C0)
   *
   * What it does:
   * Computes `base + index * 4` and stores the result dword in `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride4ByteOffset(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(index * 4);
    return outValue;
  }

  /**
   * Address: 0x007036E0 (FUN_007036E0)
   *
   * What it does:
   * Computes `base + index * 40` and stores the result dword in `outValue`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride40ByteOffset(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(index * 40);
    return outValue;
  }

  /**
   * Address: 0x00704420 (FUN_00704420)
   *
   * What it does:
   * Swaps the three trailing dword lanes (`+0x04`, `+0x08`, `+0x0C`) between
   * two 16-byte lane blocks.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanesPrimary(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00704C00 (FUN_00704C00)
   *
   * What it does:
   * Secondary entrypoint for swapping trailing dword triplet lanes between
   * two 16-byte lane blocks.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanesSecondary(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00705A40 (FUN_00705A40)
   *
   * What it does:
   * Swaps one leading dword lane between two word slots.
   */
  [[maybe_unused]] std::uint32_t* SwapLeadingWordLanePrimary(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00706D10 (FUN_00706D10)
   *
   * What it does:
   * Secondary entrypoint for swapping one leading dword lane.
   */
  [[maybe_unused]] std::uint32_t* SwapLeadingWordLaneSecondary(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0070E3D0 (FUN_0070E3D0)
   *
   * What it does:
   * Copies the first dword at `*source->lane04` into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLaneA(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x0070E400 (FUN_0070E400)
   *
   * What it does:
   * Secondary entrypoint for copying the first dword at `*source->lane04`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLaneB(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x0070E870 (FUN_0070E870)
   *
   * What it does:
   * Initializes a self-relative span header with begin/cursor/lane0C pointing
   * at `this + 0x10`, and end pointing at `this + 0x80`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeader(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    const std::uint32_t base = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outValue));
    outValue->begin = base + 0x10u;
    outValue->cursor = base + 0x10u;
    outValue->end = base + 0x80u;
    outValue->lane0C = base + 0x10u;
    return outValue;
  }

  /**
   * Address: 0x0070EF50 (FUN_0070EF50)
   *
   * What it does:
   * Zeros both dword lanes of a `{word,word}` pair.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* ZeroDwordPairLanePrimary(
    DwordPairLaneRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0070EFA0 (FUN_0070EFA0)
   *
   * What it does:
   * Advances one pointer slot to its current node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlotPrimary(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x0070F020 (FUN_0070F020)
   *
   * What it does:
   * Tertiary entrypoint for copying the first dword at `*source->lane04`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLaneC(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x0070FF70 (FUN_0070FF70)
   *
   * What it does:
   * Pops one intrusive node head from `headSlot`, writes the popped node
   * address to `outNodeAddress`, and advances `headSlot` to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopLinkedWordHeadNode(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    const auto* const head = reinterpret_cast<const LinkedWordNodeRuntimeView*>(*headSlot);
    *outNodeAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(head));
    *headSlot = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(head->nextNodeAddress));
    return outNodeAddress;
  }

  /**
   * Address: 0x0070FF90 (FUN_0070FF90)
   *
   * What it does:
   * Secondary entrypoint for advancing one pointer slot to node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlotSecondary(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00710240 (FUN_00710240)
   *
   * What it does:
   * Copies one `{dword,byte}` pair from separate source lanes.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairPrimary(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const wordValue,
    const std::uint8_t* const byteValue
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, wordValue, byteValue);
  }

  /**
   * Address: 0x00710C40 (FUN_00710C40)
   *
   * What it does:
   * Fourth entrypoint for copying the first dword at `*source->lane04`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLaneD(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x00710C70 (FUN_00710C70)
   *
   * What it does:
   * Fifth entrypoint for copying the first dword at `*source->lane04`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLaneE(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x007111A0 (FUN_007111A0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroSingleWordLanePrimary(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00711BC0 (FUN_00711BC0)
   *
   * What it does:
   * Secondary entrypoint for zeroing one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroSingleWordLaneSecondary(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00711FB0 (FUN_00711FB0)
   *
   * What it does:
   * Secondary entrypoint for copying one `{dword,byte}` pair.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairSecondary(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const wordValue,
    const std::uint8_t* const byteValue
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, wordValue, byteValue);
  }

  /**
   * Address: 0x00712120 (FUN_00712120)
   *
   * What it does:
   * Packs five dword lanes plus two trailing byte flags into one 0x16-byte
   * runtime record.
   */
  [[maybe_unused]] FiveWordAndTwoFlagsRuntimeView* StoreFiveWordAndTwoFlagRecord(
    FiveWordAndTwoFlagsRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t* const pairSource,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint8_t flag14
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = pairSource[0];
    outValue->lane10 = pairSource[1];
    outValue->flag14 = flag14;
    outValue->flag15 = 0u;
    return outValue;
  }

  struct DwordQuadLaneRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
  };
  static_assert(sizeof(DwordQuadLaneRuntimeView) == 0x10, "DwordQuadLaneRuntimeView size must be 0x10");

  struct ByteAt4RuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint8_t lane04 = 0u;  // +0x04
  };
  static_assert(offsetof(ByteAt4RuntimeView, lane04) == 0x04, "ByteAt4RuntimeView::lane04 offset must be 0x04");

  struct Float4RuntimeView
  {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float w = 0.0f;
  };
  static_assert(sizeof(Float4RuntimeView) == 0x10, "Float4RuntimeView size must be 0x10");

  [[nodiscard]] std::uint32_t* CopySingleWordIfDestinationNonNull(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != nullptr) {
      *destination = *source;
    }
    return destination;
  }

  [[nodiscard]] DwordPairLaneRuntimeView* CopyWordPairIfDestinationNonNull(
    DwordPairLaneRuntimeView* const destination,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    if (destination != nullptr) {
      destination->lane00 = source->lane00;
      destination->lane04 = source->lane04;
    }
    return destination;
  }

  [[nodiscard]] DwordPairLaneRuntimeView* SwapWordPairLanes(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    std::uint32_t tmp = lhs->lane00;
    lhs->lane00 = rhs->lane00;
    rhs->lane00 = tmp;

    tmp = lhs->lane04;
    lhs->lane04 = rhs->lane04;
    rhs->lane04 = tmp;
    return lhs;
  }

  [[nodiscard]] std::uint32_t* TakeWordAndClear(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    const std::uint32_t value = *source;
    *source = 0u;
    *outValue = value;
    return outValue;
  }

  [[nodiscard]] std::uint32_t TakeAndClearWordLane(std::uint32_t* const lane) noexcept
  {
    const std::uint32_t value = *lane;
    *lane = 0u;
    return value;
  }

  [[nodiscard]] std::uint32_t* ComputeWordAddressPlus8(
    const std::uint32_t* const source
  ) noexcept
  {
    return reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(*source + 8u));
  }

  [[nodiscard]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderWithTailOffset(
    SpanHeaderSelfRefRuntimeView* const outValue,
    const std::uint32_t tailOffset
  ) noexcept
  {
    const std::uint32_t base = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outValue));
    outValue->begin = base + 0x10u;
    outValue->cursor = base + 0x10u;
    outValue->end = base + tailOffset;
    outValue->lane0C = base + 0x10u;
    return outValue;
  }

  [[nodiscard]] std::uint32_t ComputeStride16Address(
    const std::int32_t index,
    const std::uint32_t baseAddress
  ) noexcept
  {
    return baseAddress + (static_cast<std::uint32_t>(index) * 16u);
  }

  /**
   * Address: 0x00739C00 (FUN_00739C00)
   *
   * What it does:
   * Advances one pointer slot to its current node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot739C00(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00739C20 (FUN_00739C20)
   * Address: 0x007AE5E0 (FUN_007AE5E0)
   *
   * What it does:
   * Returns one dword-address lane at `*source + 8`.
   */
  [[maybe_unused]] std::uint32_t* ComputeWordAddressPlus8LaneA(const std::uint32_t* const source) noexcept
  {
    return ComputeWordAddressPlus8(source);
  }

  /**
   * Address: 0x00739C30 (FUN_00739C30)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot739C30(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00739C50 (FUN_00739C50)
   *
   * What it does:
   * Initializes one self-relative span header with tail anchor at `+0x4C0`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail4C0(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x4C0u);
  }

  /**
   * Address: 0x00739CA0 (FUN_00739CA0)
   *
   * What it does:
   * Initializes one self-relative span header with tail anchor at `+0x970`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail970(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x970u);
  }

  /**
   * Address: 0x00739D30 (FUN_00739D30)
   *
   * What it does:
   * Copies the first dword at `*source->lane04` into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLane739D30(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x00739EC0 (FUN_00739EC0)
   *
   * What it does:
   * Alias lane returning one dword-address at `*source + 8`.
   */
  [[maybe_unused]] std::uint32_t* ComputeWordAddressPlus8LaneB(const std::uint32_t* const source) noexcept
  {
    return ComputeWordAddressPlus8(source);
  }

  /**
   * Address: 0x00739ED0 (FUN_00739ED0)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot739ED0(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00739F00 (FUN_00739F00)
   *
   * What it does:
   * Alias lane returning one dword-address at `*source + 8`.
   */
  [[maybe_unused]] std::uint32_t* ComputeWordAddressPlus8LaneC(const std::uint32_t* const source) noexcept
  {
    return ComputeWordAddressPlus8(source);
  }

  /**
   * Address: 0x00739F10 (FUN_00739F10)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot739F10(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x0073A0A0 (FUN_0073A0A0)
   *
   * What it does:
   * Copies one dword from `source` into `destination` when destination is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullA(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073A230 (FUN_0073A230)
   *
   * What it does:
   * Alias lane for guarded single-word copy.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullB(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073A270 (FUN_0073A270)
   *
   * What it does:
   * Pops one intrusive node head from `headSlot`, writes popped node address
   * to `outNodeAddress`, then advances `headSlot` to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopLinkedWordHeadNode73A270(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopLinkedWordHeadNode(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x0073A2C0 (FUN_0073A2C0)
   *
   * What it does:
   * Alias lane for guarded single-word copy.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullC(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073A2F0 (FUN_0073A2F0)
   *
   * What it does:
   * Copies one two-dword pair from `source` when destination is non-null.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* CopyWordPairIfDestinationNonNullA(
    DwordPairLaneRuntimeView* const destination,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return CopyWordPairIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073A9A0 (FUN_0073A9A0)
   *
   * What it does:
   * Alias lane for guarded single-word copy.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullD(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073AA20 (FUN_0073AA20)
   *
   * What it does:
   * Alias lane for guarded single-word copy.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullE(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073AA50 (FUN_0073AA50)
   *
   * What it does:
   * Alias lane for guarded single-word copy.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordIfDestinationNonNullF(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopySingleWordIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073AA70 (FUN_0073AA70)
   *
   * What it does:
   * Alias lane for guarded two-dword pair copy.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* CopyWordPairIfDestinationNonNullB(
    DwordPairLaneRuntimeView* const destination,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return CopyWordPairIfDestinationNonNull(destination, source);
  }

  /**
   * Address: 0x0073AE90 (FUN_0073AE90)
   *
   * What it does:
   * Returns true when all four float lanes are exactly equal.
   */
  [[maybe_unused]] BOOL AreFloat4LanesExactlyEqual(
    const Float4RuntimeView* const lhs,
    const Float4RuntimeView* const rhs
  ) noexcept
  {
    return rhs->x == lhs->x && rhs->y == lhs->y && rhs->z == lhs->z && rhs->w == lhs->w;
  }

  /**
   * Address: 0x0073AEE0 (FUN_0073AEE0)
   *
   * What it does:
   * Computes one byte address lane as `baseAddress + index * 16`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride16AddressLane(
    const std::int32_t index,
    const std::uint32_t baseAddress
  ) noexcept
  {
    return ComputeStride16Address(index, baseAddress);
  }

  /**
   * Address: 0x0073B0A0 (FUN_0073B0A0)
   *
   * What it does:
   * Stores one dword subtraction lane `*source - subtractValue`.
   */
  [[maybe_unused]] std::uint32_t* StoreSubtractedWordLane(
    std::uint32_t* const outValue,
    const std::uint32_t* const source,
    const std::int32_t subtractValue
  ) noexcept
  {
    *outValue = *source - static_cast<std::uint32_t>(subtractValue);
    return outValue;
  }

  /**
   * Address: 0x0073B0B0 (FUN_0073B0B0)
   *
   * What it does:
   * Stores one source dword into `outValue`, then increments the source dword.
   */
  [[maybe_unused]] std::uint32_t* StoreWordAndPostIncrementSource(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    const std::uint32_t value = *source;
    *outValue = value;
    *source = value + 1u;
    return outValue;
  }

  /**
   * Address: 0x0073B0F0 (FUN_0073B0F0)
   *
   * What it does:
   * Zeros one 16-byte quad-dword lane.
   */
  [[maybe_unused]] DwordQuadLaneRuntimeView* ZeroDwordQuadLane(
    DwordQuadLaneRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x0073F580 (FUN_0073F580)
   *
   * What it does:
   * Reads one byte lane at offset `+0x04`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAt4(const ByteAt4RuntimeView* const source) noexcept
  {
    return source->lane04;
  }

  /**
   * Address: 0x0073F830 (FUN_0073F830)
   *
   * What it does:
   * Copies one source dword to `outValue` and clears source to zero.
   */
  [[maybe_unused]] std::uint32_t* TakeWordAndClearPrimary(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x0073FAE0 (FUN_0073FAE0)
   *
   * What it does:
   * Alias lane for copying one source dword and clearing it to zero.
   */
  [[maybe_unused]] std::uint32_t* TakeWordAndClearSecondary(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x0073FB50 (FUN_0073FB50)
   *
   * What it does:
   * Returns one dword lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearWordLanePrimary(std::uint32_t* const lane) noexcept
  {
    return TakeAndClearWordLane(lane);
  }

  /**
   * Address: 0x0073FB80 (FUN_0073FB80)
   *
   * What it does:
   * Alias lane returning one dword and clearing it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearWordLaneSecondary(std::uint32_t* const lane) noexcept
  {
    return TakeAndClearWordLane(lane);
  }

  /**
   * Address: 0x00740320 (FUN_00740320)
   *
   * What it does:
   * Swaps two dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanes740320(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  struct DwordAt2664RuntimeView
  {
    std::byte pad0000_0A67[0x0A68];
    std::uint32_t lane0A68 = 0u; // +0x0A68 (2664)
  };
  static_assert(offsetof(DwordAt2664RuntimeView, lane0A68) == 0x0A68, "DwordAt2664RuntimeView::lane0A68 offset must be 0x0A68");

  struct ByteAt504RuntimeView
  {
    std::byte pad0000_01F7[0x1F8];
    std::uint8_t lane01F8 = 0u; // +0x1F8 (504)
  };
  static_assert(offsetof(ByteAt504RuntimeView, lane01F8) == 0x1F8, "ByteAt504RuntimeView::lane01F8 offset must be 0x1F8");

  [[nodiscard]] DwordPairLaneRuntimeView* CopyFromTwoIndependentWordSources(
    DwordPairLaneRuntimeView* const outValue,
    const std::uint32_t* const sourceA,
    const std::uint32_t* const sourceB
  ) noexcept
  {
    outValue->lane00 = *sourceA;
    outValue->lane04 = *sourceB;
    return outValue;
  }

  [[nodiscard]] std::uint32_t* ComputeStride8ByteOffset(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(index * 8);
    return outValue;
  }

  [[nodiscard]] std::uint32_t* ComputeStride12ByteOffset(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *base + static_cast<std::uint32_t>(index * 12);
    return outValue;
  }

  [[nodiscard]] std::uint32_t* FillWordPairRangeWithConstant(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* const sourcePair
  ) noexcept
  {
    while (begin != end) {
      begin[0] = sourcePair[0];
      begin[1] = sourcePair[1];
      begin += 2;
    }
    return begin;
  }

  /**
   * Address: 0x007517D0 (FUN_007517D0)
   *
   * What it does:
   * Swaps one dword lane between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane7517D0(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00751820 (FUN_00751820)
   *
   * What it does:
   * Alias lane for swapping one dword between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane751820(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00751830 (FUN_00751830)
   *
   * What it does:
   * Swaps trailing dword triplet lanes (`+0x04`, `+0x08`, `+0x0C`) between
   * two 16-byte lane blocks.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes751830(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752140 (FUN_00752140)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes752140(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752170 (FUN_00752170)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes752170(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x007521A0 (FUN_007521A0)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes7521A0(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x007521D0 (FUN_007521D0)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes7521D0(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752200 (FUN_00752200)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes752200(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752230 (FUN_00752230)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes752230(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752260 (FUN_00752260)
   *
   * What it does:
   * Alias lane for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanes752260(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00752290 (FUN_00752290)
   *
   * What it does:
   * Swaps two dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanes752290(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  /**
   * Address: 0x007544C0 (FUN_007544C0)
   *
   * What it does:
   * Alias lane for swapping one dword between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane7544C0(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x007544E0 (FUN_007544E0)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane7544E0(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754500 (FUN_00754500)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754500(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754520 (FUN_00754520)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754520(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754540 (FUN_00754540)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754540(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754560 (FUN_00754560)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754560(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754580 (FUN_00754580)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754580(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00754590 (FUN_00754590)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane754590(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00758DF0 (FUN_00758DF0)
   *
   * What it does:
   * Stores one dword into lane `+0x0A68`.
   */
  [[maybe_unused]] DwordAt2664RuntimeView* StoreWordAtOffset2664(
    DwordAt2664RuntimeView* const object,
    const std::uint32_t value
  ) noexcept
  {
    object->lane0A68 = value;
    return object;
  }

  /**
   * Address: 0x00758E00 (FUN_00758E00)
   *
   * What it does:
   * Stores one byte into lane `+0x1F8`.
   */
  [[maybe_unused]] ByteAt504RuntimeView* StoreByteAtOffset504(
    ByteAt504RuntimeView* const object,
    const std::uint8_t value
  ) noexcept
  {
    object->lane01F8 = value;
    return object;
  }

  /**
   * Address: 0x0075F100 (FUN_0075F100)
   *
   * What it does:
   * Stores one word from `sourceA` and one word from `sourceB` into a pair lane.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* CopyFromTwoIndependentWordSources75F100(
    DwordPairLaneRuntimeView* const outValue,
    const std::uint32_t* const sourceA,
    const std::uint32_t* const sourceB
  ) noexcept
  {
    return CopyFromTwoIndependentWordSources(outValue, sourceA, sourceB);
  }

  /**
   * Address: 0x0075FB10 (FUN_0075FB10)
   *
   * What it does:
   * Computes one address lane as `*base + index * 8`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride8ByteOffset75FB10(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride8ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x0075FB50 (FUN_0075FB50)
   *
   * What it does:
   * Computes one address lane as `*base + index * 12`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride12ByteOffset75FB50(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride12ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x00760020 (FUN_00760020)
   *
   * What it does:
   * Fills `[begin,end)` pair lanes with one constant two-word source payload.
   */
  [[maybe_unused]] std::uint32_t* FillWordPairRangeWithConstant760020(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* const sourcePair
  ) noexcept
  {
    return FillWordPairRangeWithConstant(begin, end, sourcePair);
  }

  /**
   * Address: 0x00760470 (FUN_00760470)
   *
   * What it does:
   * Alias lane storing one word from each of two independent sources.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* CopyFromTwoIndependentWordSources760470(
    DwordPairLaneRuntimeView* const outValue,
    const std::uint32_t* const sourceA,
    const std::uint32_t* const sourceB
  ) noexcept
  {
    return CopyFromTwoIndependentWordSources(outValue, sourceA, sourceB);
  }

  /**
   * Address: 0x00760550 (FUN_00760550)
   *
   * What it does:
   * Alias lane for swapping two dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanes760550(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  /**
   * Address: 0x00760700 (FUN_00760700)
   *
   * What it does:
   * Alias lane for swapping two dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanes760700(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  /**
   * Address: 0x00760830 (FUN_00760830)
   *
   * What it does:
   * Alias lane for swapping two dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanes760830(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  /**
   * Address: 0x007609D0 (FUN_007609D0)
   *
   * What it does:
   * Alias lane for swapping one dword between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane7609D0(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  struct ForwardLinkNodeRuntimeView
  {
    ForwardLinkNodeRuntimeView* next;          // +0x00
    ForwardLinkNodeRuntimeView** ownerSlot;    // +0x04
  };
  static_assert(sizeof(ForwardLinkNodeRuntimeView) == 0x08, "ForwardLinkNodeRuntimeView size must be 0x08");

  struct LinkAndFourWordLanesRuntimeView
  {
    ForwardLinkNodeRuntimeView link; // +0x00
    std::uint32_t lane08 = 0u;       // +0x08
    std::uint32_t lane0C = 0u;       // +0x0C
    std::uint32_t lane10 = 0u;       // +0x10
    std::uint32_t lane14 = 0u;       // +0x14
  };
  static_assert(sizeof(LinkAndFourWordLanesRuntimeView) == 0x18, "LinkAndFourWordLanesRuntimeView size must be 0x18");

  struct DwordPairAt8RuntimeView
  {
    std::byte pad0000_0007[0x08];
    std::uint32_t lane08 = 0u; // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
  };
  static_assert(offsetof(DwordPairAt8RuntimeView, lane08) == 0x08, "DwordPairAt8RuntimeView::lane08 offset must be 0x08");

  struct IndexedWordLaneAt44RuntimeView
  {
    std::byte pad0000_002B[0x2C];
    std::uint32_t lane2C = 0u; // +0x2C (44)
  };
  static_assert(
    offsetof(IndexedWordLaneAt44RuntimeView, lane2C) == 0x2C,
    "IndexedWordLaneAt44RuntimeView::lane2C offset must be 0x2C"
  );

  struct TablePointerAt28RuntimeView
  {
    std::byte pad0000_001B[0x1C];
    const std::uint32_t* table = nullptr; // +0x1C (28)
  };
  static_assert(
    offsetof(TablePointerAt28RuntimeView, table) == 0x1C,
    "TablePointerAt28RuntimeView::table offset must be 0x1C"
  );

  struct ByteAt24RuntimeView
  {
    std::byte pad0000_0017[0x18];
    std::uint8_t lane18 = 0u; // +0x18 (24)
  };
  static_assert(offsetof(ByteAt24RuntimeView, lane18) == 0x18, "ByteAt24RuntimeView::lane18 offset must be 0x18");

  struct IndexedWordsFrom16RuntimeView
  {
    std::byte pad0000_000F[0x10];
    std::uint32_t values[1];
  };
  static_assert(
    offsetof(IndexedWordsFrom16RuntimeView, values) == 0x10,
    "IndexedWordsFrom16RuntimeView::values offset must be 0x10"
  );

  [[nodiscard]] ForwardLinkNodeRuntimeView* UnlinkForwardLinkNode(ForwardLinkNodeRuntimeView* const node) noexcept
  {
    node->next->ownerSlot = node->ownerSlot;
    *node->ownerSlot = node->next;
    return node;
  }

  [[nodiscard]] ForwardLinkNodeRuntimeView* SelfLinkForwardNode(ForwardLinkNodeRuntimeView* const node) noexcept
  {
    node->ownerSlot = reinterpret_cast<ForwardLinkNodeRuntimeView**>(node);
    node->next = node;
    return node;
  }

  [[nodiscard]] ForwardLinkNodeRuntimeView* InsertForwardNodeAtSlot(
    ForwardLinkNodeRuntimeView* const node,
    ForwardLinkNodeRuntimeView** const slot
  ) noexcept
  {
    node->next = *slot;
    node->ownerSlot = slot;
    *slot = node;
    node->next->ownerSlot = reinterpret_cast<ForwardLinkNodeRuntimeView**>(node);
    return node;
  }

  /**
   * Address: 0x00769DA0 (FUN_00769DA0)
   *
   * What it does:
   * Advances one pointer slot to its current node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot769DA0(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00769DE0 (FUN_00769DE0)
   *
   * What it does:
   * Copies one `{dword,byte}` pair from separate source lanes.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePair769DE0(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const wordValue,
    const std::uint8_t* const byteValue
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, wordValue, byteValue);
  }

  /**
   * Address: 0x0076A1F0 (FUN_0076A1F0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroSingleWordLane76A1F0(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0076A200 (FUN_0076A200)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlot76A200(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x0076A240 (FUN_0076A240)
   *
   * What it does:
   * Computes one address lane as `*base + index * 12`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride12ByteOffset76A240(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride12ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x0076A280 (FUN_0076A280)
   *
   * What it does:
   * Computes one address lane as `*base + index * 4`.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride4ByteOffset76A280(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride4ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x0076A290 (FUN_0076A290)
   *
   * What it does:
   * Copies the first dword at `*source->lane04` into `outValue`.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordLane76A290(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x0076A3E0 (FUN_0076A3E0)
   *
   * What it does:
   * Pops one intrusive node head from `headSlot`, writes the popped node
   * address to `outNodeAddress`, and advances `headSlot` to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopLinkedWordHeadNode76A3E0(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopLinkedWordHeadNode(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x0076B510 (FUN_0076B510)
   *
   * What it does:
   * Swaps one dword lane between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane76B510(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0076BAA0 (FUN_0076BAA0)
   *
   * What it does:
   * Copies the dword pair at offsets `+0x04/+0x08` from `source` to `destination`.
   */
  [[maybe_unused]] DwordTripleLaneRuntimeView* CopyTailWordPairFromTriple(
    DwordTripleLaneRuntimeView* const destination,
    const DwordTripleLaneRuntimeView* const source
  ) noexcept
  {
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    return destination;
  }

  /**
   * Address: 0x0076BDA0 (FUN_0076BDA0)
   *
   * What it does:
   * Resolves one dword table pointer at `(*ownerSlot)->+0x1C` and returns
   * `table[indexSource->+0x2C]`.
   */
  [[maybe_unused]] std::uint32_t LoadIndexedWordFromNestedTable(
    const IndexedWordLaneAt44RuntimeView* const indexSource,
    const TablePointerAt28RuntimeView* const* const ownerSlot
  ) noexcept
  {
    const TablePointerAt28RuntimeView* const owner = *ownerSlot;
    return owner->table[indexSource->lane2C];
  }

  /**
   * Address: 0x0076BFD0 (FUN_0076BFD0)
   *
   * What it does:
   * Computes one byte address lane as `baseAt4 + index * 12`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromBaseAt4(
    const std::int32_t index,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return source->lane04 + (static_cast<std::uint32_t>(index) * 12u);
  }

  /**
   * Address: 0x0076CB20 (FUN_0076CB20)
   */
  [[maybe_unused]] std::uint32_t* ComputeStride4ByteOffset76CB20(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride4ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x0076CB40 (FUN_0076CB40)
   */
  [[maybe_unused]] std::uint32_t* ComputeStride12ByteOffset76CB40(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride12ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x0076D970 (FUN_0076D970)
   *
   * What it does:
   * Reads one byte lane at offset `+0x18`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAt24(const ByteAt24RuntimeView* const source) noexcept
  {
    return source->lane18;
  }

  /**
   * Address: 0x0076E880 (FUN_0076E880)
   */
  [[maybe_unused]] std::uint32_t* SwapSingleWordLane76E880(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00772D90 (FUN_00772D90)
   *
   * What it does:
   * Unlinks one forward-link node from its current owner slot and re-inserts
   * it at owner lane `ownerBase + 0x58`.
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* RelinkForwardNodeToOwnerOffset58(
    ForwardLinkNodeRuntimeView* const node,
    std::byte* const ownerBase
  ) noexcept
  {
    (void)UnlinkForwardLinkNode(node);
    (void)SelfLinkForwardNode(node);
    auto* const slot = reinterpret_cast<ForwardLinkNodeRuntimeView**>(ownerBase + 0x58);
    return InsertForwardNodeAtSlot(node, slot);
  }

  /**
   * Address: 0x00772DC0 (FUN_00772DC0)
   *
   * What it does:
   * Unlinks one forward-link node and restores self-links.
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* UnlinkAndSelfLinkForwardNode(
    ForwardLinkNodeRuntimeView* const node
  ) noexcept
  {
    (void)UnlinkForwardLinkNode(node);
    return SelfLinkForwardNode(node);
  }

  /**
   * Address: 0x00773230 (FUN_00773230)
   *
   * What it does:
   * Zeros the first three dword lanes of one runtime block.
   */
  [[maybe_unused]] DwordTripleLaneRuntimeView* ZeroDwordTripleLane773230(
    DwordTripleLaneRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    return outValue;
  }

  /**
   * Address: 0x00773610 (FUN_00773610)
   *
   * What it does:
   * Initializes link lanes to self and zeroes four trailing dword lanes.
   */
  [[maybe_unused]] LinkAndFourWordLanesRuntimeView* InitializeSelfLinkedAndZeroTail(
    LinkAndFourWordLanesRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    outValue->link.ownerSlot = reinterpret_cast<ForwardLinkNodeRuntimeView**>(&outValue->link);
    outValue->link.next = &outValue->link;
    outValue->lane10 = 0u;
    outValue->lane14 = 0u;
    return outValue;
  }

  /**
   * Address: 0x00773680 (FUN_00773680)
   *
   * What it does:
   * Copies one source dword pair into destination lanes `+0x08` and `+0x0C`.
   */
  [[maybe_unused]] std::uint32_t CopyWordPairToDestinationOffset8(
    const DwordPairLaneRuntimeView* const source,
    DwordPairAt8RuntimeView* const destination
  ) noexcept
  {
    destination->lane08 = source->lane00;
    destination->lane0C = source->lane04;
    return source->lane04;
  }

  /**
   * Address: 0x00773690 (FUN_00773690)
   *
   * What it does:
   * Reads one indexed dword lane from array base at offset `+0x10`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordFromOffset16(
    const IndexedWordsFrom16RuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->values[index];
  }

  /**
   * Address: 0x00773AB0 (FUN_00773AB0)
   *
   * What it does:
   * Initializes one forward-link node to self-links.
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* SelfLinkForwardNode773AB0(
    ForwardLinkNodeRuntimeView* const node
  ) noexcept
  {
    return SelfLinkForwardNode(node);
  }

  /**
   * Address: 0x00773B00 (FUN_00773B00)
   *
   * What it does:
   * Unlinks one forward-link node, self-links it, then inserts it at `slot`.
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* RelinkForwardNodeAtExternalSlot(
    ForwardLinkNodeRuntimeView* const node,
    ForwardLinkNodeRuntimeView** const slot
  ) noexcept
  {
    (void)UnlinkForwardLinkNode(node);
    (void)SelfLinkForwardNode(node);
    return InsertForwardNodeAtSlot(node, slot);
  }

  /**
   * Address: 0x00773B30 (FUN_00773B30)
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* UnlinkAndSelfLinkForwardNode773B30(
    ForwardLinkNodeRuntimeView* const node
  ) noexcept
  {
    return UnlinkAndSelfLinkForwardNode(node);
  }

  /**
   * Address: 0x00773B50 (FUN_00773B50)
   */
  [[maybe_unused]] ForwardLinkNodeRuntimeView* SelfLinkForwardNode773B50(
    ForwardLinkNodeRuntimeView* const node
  ) noexcept
  {
    return SelfLinkForwardNode(node);
  }

  /**
   * Address: 0x00773BB0 (FUN_00773BB0)
   *
   * What it does:
   * Initializes one self-relative span header with tail anchor at `+0x18`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail18_773BB0(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x18u);
  }

  /**
   * Address: 0x00775BE0 (FUN_00775BE0)
   *
   * What it does:
   * Alias lane for zeroing one dword.
   */
  [[maybe_unused]] std::uint32_t* ZeroSingleWordLane775BE0(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  struct WideTailPairAccessorRuntimeView
  {
    std::byte pad0000_0C7F[0x0C80];
    std::uint32_t lane0C80; // +0x0C80
    std::uint32_t lane0C84; // +0x0C84
  };
  static_assert(
    offsetof(WideTailPairAccessorRuntimeView, lane0C80) == 0x0C80,
    "WideTailPairAccessorRuntimeView::lane0C80 offset must be 0x0C80"
  );
  static_assert(
    offsetof(WideTailPairAccessorRuntimeView, lane0C84) == 0x0C84,
    "WideTailPairAccessorRuntimeView::lane0C84 offset must be 0x0C84"
  );

  /**
   * Address: 0x00688710 (FUN_00688710)
   *
   * What it does:
   * Composes one five-word lane and clears two trailing flag bytes.
   */
  [[maybe_unused]] [[nodiscard]] FiveWordAndTwoFlagsRuntimeView* ComposeFiveWordAndTwoFlagsLane(
    FiveWordAndTwoFlagsRuntimeView* const outValue,
    const std::uint32_t lane00,
    const DwordPairLaneRuntimeView* const sourcePair,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = sourcePair->lane00;
    outValue->lane10 = sourcePair->lane04;
    outValue->flag14 = 0u;
    outValue->flag15 = 0u;
    return outValue;
  }

  /**
   * Address: 0x006887B0 (FUN_006887B0)
   *
   * What it does:
   * Writes `{object_address, object->lane0C80}` into one two-word output lane.
   */
  [[maybe_unused]] [[nodiscard]] DwordPairLaneRuntimeView* ComposeObjectAndWideTailLane0C80(
    DwordPairLaneRuntimeView* const outValue,
    const WideTailPairAccessorRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source));
    outValue->lane04 = source->lane0C80;
    return outValue;
  }

  /**
   * Address: 0x006887C0 (FUN_006887C0)
   *
   * What it does:
   * Writes `{object_address, object->lane0C84}` into one two-word output lane.
   */
  [[maybe_unused]] [[nodiscard]] DwordPairLaneRuntimeView* ComposeObjectAndWideTailLane0C84(
    DwordPairLaneRuntimeView* const outValue,
    const WideTailPairAccessorRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source));
    outValue->lane04 = source->lane0C84;
    return outValue;
  }

  /**
   * Address: 0x0057EBD0 (FUN_0057EBD0)
   *
   * What it does:
   * Initializes one four-lane dword span view with `count * 4` byte stride.
   */
  [[maybe_unused]] [[nodiscard]] DwordSpanRuntimeView* InitializeDwordSpanStride4(
    DwordSpanRuntimeView* const outSpan,
    const std::int32_t count,
    const std::uint32_t beginAddress
  ) noexcept
  {
    outSpan->origin = beginAddress;
    outSpan->begin = beginAddress;
    outSpan->end = beginAddress + (static_cast<std::uint32_t>(count) * static_cast<std::uint32_t>(sizeof(std::uint32_t)));
    outSpan->cursor = beginAddress;
    return outSpan;
  }

  /**
   * Address: 0x0057F8F0 (FUN_0057F8F0)
   *
   * What it does:
   * Initializes one four-lane dword span view with `count * 24` byte stride.
   */
  [[maybe_unused]] [[nodiscard]] DwordSpanRuntimeView* InitializeDwordSpanStride24(
    DwordSpanRuntimeView* const outSpan,
    const std::int32_t count,
    const std::uint32_t beginAddress
  ) noexcept
  {
    outSpan->origin = beginAddress;
    outSpan->begin = beginAddress;
    outSpan->end = beginAddress + (static_cast<std::uint32_t>(count) * 24u);
    outSpan->cursor = beginAddress;
    return outSpan;
  }

  /**
   * Address: 0x0057F720 (FUN_0057F720)
   * Address: 0x0057F8B0 (FUN_0057F8B0)
   * Address: 0x0057F940 (FUN_0057F940)
   * Address: 0x0057F960 (FUN_0057F960)
   * Address: 0x0057FBA0 (FUN_0057FBA0)
   * Address: 0x00580970 (FUN_00580970)
   * Address: 0x00580C70 (FUN_00580C70)
   * Address: 0x00580CE0 (FUN_00580CE0)
   * Address: 0x005810F0 (FUN_005810F0)
   * Address: 0x00581130 (FUN_00581130)
   * Address: 0x00581560 (FUN_00581560)
   * Address: 0x005C8900 (FUN_005C8900)
   * Address: 0x005C8980 (FUN_005C8980)
   * Address: 0x005C89B0 (FUN_005C89B0)
   * Address: 0x005C8B40 (FUN_005C8B40)
   * Address: 0x005CF9E0 (FUN_005CF9E0)
   * Address: 0x00651EE0 (FUN_00651EE0)
   * Address: 0x00651F40 (FUN_00651F40)
   * Address: 0x00652190 (FUN_00652190)
   * Address: 0x00652340 (FUN_00652340)
   * Address: 0x00652350 (FUN_00652350)
   * Address: 0x00652640 (FUN_00652640)
   * Address: 0x00652650 (FUN_00652650)
   * Address: 0x006526B0 (FUN_006526B0)
   * Address: 0x0066A4B0 (FUN_0066A4B0)
   * Address: 0x0066AB40 (FUN_0066AB40)
   * Address: 0x0066AB50 (FUN_0066AB50)
   * Address: 0x0066AD90 (FUN_0066AD90)
   * Address: 0x0066C1E0 (FUN_0066C1E0)
   * Address: 0x0066C210 (FUN_0066C210)
   * Address: 0x0067BAB0 (FUN_0067BAB0)
   * Address: 0x0067BB10 (FUN_0067BB10)
   * Address: 0x0067BB70 (FUN_0067BB70)
   * Address: 0x0067BBF0 (FUN_0067BBF0)
   * Address: 0x0067BC40 (FUN_0067BC40)
   * Address: 0x0067BD60 (FUN_0067BD60)
   * Address: 0x0067E260 (FUN_0067E260)
   * Address: 0x0067E2D0 (FUN_0067E2D0)
   * Address: 0x0067E300 (FUN_0067E300)
   * Address: 0x0067EA70 (FUN_0067EA70)
   * Address: 0x0067EAD0 (FUN_0067EAD0)
   * Address: 0x0067EAF0 (FUN_0067EAF0)
   * Address: 0x006858C0 (FUN_006858C0)
   * Address: 0x00685B70 (FUN_00685B70)
   * Address: 0x00685BC0 (FUN_00685BC0)
   * Address: 0x00685C00 (FUN_00685C00)
   * Address: 0x00685C40 (FUN_00685C40)
   * Address: 0x00686C80 (FUN_00686C80)
   * Address: 0x00686CC0 (FUN_00686CC0)
   * Address: 0x00687840 (FUN_00687840)
   * Address: 0x00687890 (FUN_00687890)
   * Address: 0x00688750 (FUN_00688750)
   * Address: 0x00688980 (FUN_00688980)
   * Address: 0x006927A0 (FUN_006927A0)
   * Address: 0x00692C10 (FUN_00692C10)
   * Address: 0x00692D60 (FUN_00692D60)
   * Address: 0x00695B30 (FUN_00695B30)
   * Address: 0x00695B70 (FUN_00695B70)
   * Address: 0x00696D50 (FUN_00696D50)
   * Address: 0x0069F300 (FUN_0069F300)
   * Address: 0x0069F420 (FUN_0069F420)
   * Address: 0x006AD720 (FUN_006AD720)
   * Address: 0x006AD7E0 (FUN_006AD7E0)
   * Address: 0x006AD840 (FUN_006AD840)
   * Address: 0x006AD8A0 (FUN_006AD8A0)
   * Address: 0x006AD930 (FUN_006AD930)
   * Address: 0x006AD990 (FUN_006AD990)
   * Address: 0x006AD9F0 (FUN_006AD9F0)
   * Address: 0x006ADA40 (FUN_006ADA40)
   * Address: 0x006ADA80 (FUN_006ADA80)
   * Address: 0x006ADAC0 (FUN_006ADAC0)
   * Address: 0x006ADB10 (FUN_006ADB10)
   * Address: 0x006ADB70 (FUN_006ADB70)
   * Address: 0x006ADDB0 (FUN_006ADDB0)
   * Address: 0x006ADDD0 (FUN_006ADDD0)
   * Address: 0x006AF600 (FUN_006AF600)
   * Address: 0x006AF610 (FUN_006AF610)
   * Address: 0x006AF620 (FUN_006AF620)
   * Address: 0x006AFDE0 (FUN_006AFDE0)
   * Address: 0x006C3940 (FUN_006C3940)
   * Address: 0x006D1CE0 (FUN_006D1CE0)
   * Address: 0x006D1DE0 (FUN_006D1DE0)
   * Address: 0x006DAF60 (FUN_006DAF60)
   * Address: 0x006DC330 (FUN_006DC330)
   * Address: 0x006DC340 (FUN_006DC340)
   * Address: 0x006DD140 (FUN_006DD140)
   * Address: 0x006DD220 (FUN_006DD220)
   * Address: 0x006E21E0 (FUN_006E21E0)
   * Address: 0x006E27C0 (FUN_006E27C0)
   * Address: 0x006E27E0 (FUN_006E27E0)
   * Address: 0x006E2940 (FUN_006E2940)
   * Address: 0x006E4010 (FUN_006E4010)
   * Address: 0x006E59D0 (FUN_006E59D0)
   * Address: 0x006EB1B0 (FUN_006EB1B0)
   * Address: 0x006EB3A0 (FUN_006EB3A0)
   * Address: 0x006EB430 (FUN_006EB430)
   * Address: 0x006EB560 (FUN_006EB560)
   * Address: 0x006EB5C0 (FUN_006EB5C0)
   * Address: 0x006F87F0 (FUN_006F87F0)
   * Address: 0x006F8890 (FUN_006F8890)
   * Address: 0x006F8BB0 (FUN_006F8BB0)
   * Address: 0x006F8BC0 (FUN_006F8BC0)
   * Address: 0x006F8C30 (FUN_006F8C30)
   * Address: 0x00701890 (FUN_00701890)
   * Address: 0x007018F0 (FUN_007018F0)
   * Address: 0x00701950 (FUN_00701950)
   * Address: 0x006FD150 (FUN_006FD150)
   * Address: 0x00702440 (FUN_00702440)
   * Address: 0x0070FD60 (FUN_0070FD60)
   * Address: 0x00710250 (FUN_00710250)
   * Address: 0x00711300 (FUN_00711300)
   * Address: 0x00711560 (FUN_00711560)
   * Address: 0x0071A020 (FUN_0071A020)
   * Address: 0x0071A040 (FUN_0071A040)
   * Address: 0x0071A0A0 (FUN_0071A0A0)
   * Address: 0x0071A140 (FUN_0071A140)
   * Address: 0x0071A180 (FUN_0071A180)
   * Address: 0x0071BD80 (FUN_0071BD80)
   * Address: 0x0071BDE0 (FUN_0071BDE0)
   * Address: 0x0071BE90 (FUN_0071BE90)
   * Address: 0x0072A960 (FUN_0072A960)
   * Address: 0x0072D840 (FUN_0072D840)
   * Address: 0x00733660 (FUN_00733660)
   * Address: 0x007339E0 (FUN_007339E0)
   * Address: 0x00735910 (FUN_00735910)
   * Address: 0x00736350 (FUN_00736350)
   * Address: 0x00739EB0 (FUN_00739EB0)
   * Address: 0x00739EF0 (FUN_00739EF0)
   * Address: 0x0073A250 (FUN_0073A250)
   * Address: 0x0073A280 (FUN_0073A280)
   * Address: 0x0073F7B0 (FUN_0073F7B0)
   * Address: 0x0073F870 (FUN_0073F870)
   * Address: 0x0073F8D0 (FUN_0073F8D0)
   * Address: 0x0073FAD0 (FUN_0073FAD0)
   * Address: 0x00741000 (FUN_00741000)
   * Address: 0x00741020 (FUN_00741020)
   * Address: 0x00741240 (FUN_00741240)
   * Address: 0x007415F0 (FUN_007415F0)
   * Address: 0x007416C0 (FUN_007416C0)
   * Address: 0x007416E0 (FUN_007416E0)
   * Address: 0x00741770 (FUN_00741770)
   * Address: 0x00741840 (FUN_00741840)
   * Address: 0x00741910 (FUN_00741910)
   * Address: 0x00741920 (FUN_00741920)
   * Address: 0x00741CC0 (FUN_00741CC0)
   * Address: 0x00741CD0 (FUN_00741CD0)
   * Address: 0x00741CF0 (FUN_00741CF0)
   * Address: 0x00741D00 (FUN_00741D00)
   * Address: 0x00741D40 (FUN_00741D40)
   * Address: 0x0074C310 (FUN_0074C310)
   * Address: 0x0074C360 (FUN_0074C360)
   * Address: 0x0074C3C0 (FUN_0074C3C0)
   * Address: 0x0074C470 (FUN_0074C470)
   * Address: 0x0074C4B0 (FUN_0074C4B0)
   * Address: 0x0074C680 (FUN_0074C680)
   * Address: 0x0074C6E0 (FUN_0074C6E0)
   * Address: 0x0074C730 (FUN_0074C730)
   * Address: 0x0074C790 (FUN_0074C790)
   * Address: 0x0074C7F0 (FUN_0074C7F0)
   * Address: 0x0074C900 (FUN_0074C900)
   * Address: 0x0074CE50 (FUN_0074CE50)
   * Address: 0x0074D160 (FUN_0074D160)
   * Address: 0x0074DF00 (FUN_0074DF00)
   * Address: 0x0074E4B0 (FUN_0074E4B0)
   * Address: 0x0074E4C0 (FUN_0074E4C0)
   * Address: 0x0074FC40 (FUN_0074FC40)
   * Address: 0x0074FC60 (FUN_0074FC60)
   * Address: 0x0074FC70 (FUN_0074FC70)
   * Address: 0x0074FC80 (FUN_0074FC80)
   * Address: 0x0074FCC0 (FUN_0074FCC0)
   * Address: 0x0074FD10 (FUN_0074FD10)
   * Address: 0x00750870 (FUN_00750870)
   * Address: 0x00750890 (FUN_00750890)
   * Address: 0x007508D0 (FUN_007508D0)
   * Address: 0x00750900 (FUN_00750900)
   * Address: 0x007509E0 (FUN_007509E0)
   * Address: 0x0075F470 (FUN_0075F470)
   * Address: 0x0075FB30 (FUN_0075FB30)
   * Address: 0x00761D10 (FUN_00761D10)
   * Address: 0x00762330 (FUN_00762330)
   * Address: 0x00763B40 (FUN_00763B40)
   * Address: 0x00766C60 (FUN_00766C60)
   * Address: 0x007677A0 (FUN_007677A0)
   * Address: 0x00767DC0 (FUN_00767DC0)
   * Address: 0x00768000 (FUN_00768000)
   * Address: 0x00768010 (FUN_00768010)
   * Address: 0x00768340 (FUN_00768340)
   * Address: 0x00768350 (FUN_00768350)
   * Address: 0x00768370 (FUN_00768370)
   * Address: 0x00768490 (FUN_00768490)
   * Address: 0x00769950 (FUN_00769950)
   * Address: 0x00769A10 (FUN_00769A10)
   * Address: 0x0076BEF0 (FUN_0076BEF0)
   * Address: 0x0076C3A0 (FUN_0076C3A0)
   * Address: 0x0076CB30 (FUN_0076CB30)
   * Address: 0x0076CC30 (FUN_0076CC30)
   * Address: 0x0076CC70 (FUN_0076CC70)
   * Address: 0x0076E760 (FUN_0076E760)
   * Address: 0x00773AD0 (FUN_00773AD0)
   * Address: 0x00773AF0 (FUN_00773AF0)
   * Address: 0x00773FE0 (FUN_00773FE0)
   * Address: 0x00773FF0 (FUN_00773FF0)
   * Address: 0x00774110 (FUN_00774110)
   * Address: 0x0077A1C0 (FUN_0077A1C0)
   * Address: 0x0077B840 (FUN_0077B840)
   * Address: 0x0077B8A0 (FUN_0077B8A0)
   * Address: 0x007A5A00 (FUN_007A5A00)
   * Address: 0x007A5DF0 (FUN_007A5DF0)
   * Address: 0x00783250 (FUN_00783250)
   * Address: 0x00783660 (FUN_00783660)
   * Address: 0x007AE620 (FUN_007AE620)
   * Address: 0x00899990 (FUN_00899990)
   * Address: 0x0089A280 (FUN_0089A280)
   * Address: 0x0089A490 (FUN_0089A490)
   * Address: 0x0089A4A0 (FUN_0089A4A0)
   * Address: 0x0089AB60 (FUN_0089AB60)
   * Address: 0x0089AB70 (FUN_0089AB70)
   *
   * What it does:
   * Stores one caller-provided scalar dword lane into output storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreScalarDwordLane(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x005810D0 (FUN_005810D0)
   * Address: 0x005814E0 (FUN_005814E0)
   * Address: 0x006A1150 (FUN_006A1150)
   * Address: 0x006A1160 (FUN_006A1160)
   * Address: 0x006A1170 (FUN_006A1170)
   * Address: 0x007AE5D0 (FUN_007AE5D0)
   *
   * What it does:
   * Zeros one caller-provided dword lane.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* ZeroScalarDwordLane(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x0057EDA0 (FUN_0057EDA0)
   * Address: 0x00580130 (FUN_00580130)
   *
   * What it does:
   * Computes one `source->lane04 + index * 24` byte-offset lane.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ComputeLane04OffsetByIndexStride24(
    const std::int32_t index,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return source->lane04 + (static_cast<std::uint32_t>(index) * 24u);
  }

  /**
   * Address: 0x00580C50 (FUN_00580C50)
   * Address: 0x0074FC50 (FUN_0074FC50)
   *
   * What it does:
   * Computes one `*baseWord + index * 4` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride4(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * static_cast<std::uint32_t>(sizeof(std::uint32_t)));
    return outValue;
  }

  /**
   * Address: 0x005927A0 (FUN_005927A0)
   * Address: 0x0069F310 (FUN_0069F310)
   *
   * What it does:
   * Computes one `*baseWord + index * 12` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride12(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 12u);
    return outValue;
  }

  /**
   * Address: 0x00580CB0 (FUN_00580CB0)
   *
   * What it does:
   * Computes one `*baseWord + index * 24` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride24(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 24u);
    return outValue;
  }

  /**
   * Address: 0x006EA020 (FUN_006EA020)
   * Address: 0x00783670 (FUN_00783670)
   * Address: 0x007A5820 (FUN_007A5820)
   *
   * What it does:
   * Computes one `*baseWord + index * 8` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride8(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 8u);
    return outValue;
  }

  /**
   * Address: 0x00581140 (FUN_00581140)
   * Address: 0x00688770 (FUN_00688770)
   *
   * What it does:
   * Computes one `*baseWord + index * 20` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride20(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 20u);
    return outValue;
  }

  /**
   * Address: 0x006EB3B0 (FUN_006EB3B0)
   *
   * What it does:
   * Computes one `*baseWord + index * 60` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride60(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 60u);
    return outValue;
  }

  /**
   * Address: 0x006EB3F0 (FUN_006EB3F0)
   *
   * What it does:
   * Computes one `*baseWord + index * 120` byte-offset lane and stores it.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreBaseWordOffsetByIndexStride120(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 120u);
    return outValue;
  }

  /**
   * Address: 0x00688960 (FUN_00688960)
   * Address: 0x00688A50 (FUN_00688A50)
   *
   * What it does:
   * Advances one stored address lane by `index * 20` bytes.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* AdvanceStoredAddressByIndexStride20(
    std::uint32_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    *addressSlot += static_cast<std::uint32_t>(index) * 20u;
    return addressSlot;
  }

  /**
   * Address: 0x006EB550 (FUN_006EB550)
   * Address: 0x006EB5E0 (FUN_006EB5E0)
   *
   * What it does:
   * Advances one stored address lane by `index * 60` bytes.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* AdvanceStoredAddressByIndexStride60(
    std::uint32_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    *addressSlot += static_cast<std::uint32_t>(index) * 60u;
    return addressSlot;
  }

  /**
   * Address: 0x006EB590 (FUN_006EB590)
   * Address: 0x006EB5F0 (FUN_006EB5F0)
   *
   * What it does:
   * Advances one stored address lane by `index * 120` bytes.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* AdvanceStoredAddressByIndexStride120(
    std::uint32_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    *addressSlot += static_cast<std::uint32_t>(index) * 120u;
    return addressSlot;
  }

  /**
   * Address: 0x00688780 (FUN_00688780)
   * Address: 0x00688970 (FUN_00688970)
   *
   * What it does:
   * Retreats one stored address lane by one 20-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* RetreatStoredAddressByStride20(
    std::uint32_t* const addressSlot
  ) noexcept
  {
    *addressSlot -= 20u;
    return addressSlot;
  }

  /**
   * Address: 0x00688790 (FUN_00688790)
   * Address: 0x006889A0 (FUN_006889A0)
   *
   * What it does:
   * Returns signed element distance between two stored address lanes with
   * 20-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t DistanceBetweenStoredAddressesStride20(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    const std::int32_t delta = static_cast<std::int32_t>(*leftAddressSlot) -
      static_cast<std::int32_t>(*rightAddressSlot);
    return delta / 20;
  }

  /**
   * Address: 0x006EAB40 (FUN_006EAB40)
   * Address: 0x006EB390 (FUN_006EB390)
   * Address: 0x00783680 (FUN_00783680)
   * Address: 0x007836A0 (FUN_007836A0)
   *
   * What it does:
   * Returns signed element distance between two stored address lanes with
   * 8-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t DistanceBetweenStoredAddressesStride8(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    const std::int32_t delta = static_cast<std::int32_t>(*leftAddressSlot) -
      static_cast<std::int32_t>(*rightAddressSlot);
    return delta >> 3;
  }

  /**
   * Address: 0x006EB3D0 (FUN_006EB3D0)
   * Address: 0x006EB570 (FUN_006EB570)
   *
   * What it does:
   * Returns signed element distance between two stored address lanes with
   * 60-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t DistanceBetweenStoredAddressesStride60(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    const std::int32_t delta = static_cast<std::int32_t>(*leftAddressSlot) -
      static_cast<std::int32_t>(*rightAddressSlot);
    return delta / 60;
  }

  /**
   * Address: 0x006EB410 (FUN_006EB410)
   * Address: 0x006EB5A0 (FUN_006EB5A0)
   *
   * What it does:
   * Returns signed element distance between two stored address lanes with
   * 120-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t DistanceBetweenStoredAddressesStride120(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    const std::int32_t delta = static_cast<std::int32_t>(*leftAddressSlot) -
      static_cast<std::int32_t>(*rightAddressSlot);
    return delta / 120;
  }

  /**
   * Address: 0x006889C0 (FUN_006889C0)
   * Address: 0x00688A60 (FUN_00688A60)
   *
   * What it does:
   * Returns signed element distance between two stored address lanes with
   * 4-byte stride.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t DistanceBetweenStoredAddressesStride4(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    const std::int32_t delta = static_cast<std::int32_t>(*leftAddressSlot) -
      static_cast<std::int32_t>(*rightAddressSlot);
    return delta >> 2;
  }

  /**
   * Address: 0x00688A00 (FUN_00688A00)
   *
   * What it does:
   * Computes one `base + index * 32` byte address from a two-word lane.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ComputeBasePlusIndexStride32(
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return source->lane00 + (source->lane04 << 5u);
  }

  /**
   * Address: 0x005355D0 (FUN_005355D0)
   * Address: 0x00537BE0 (FUN_00537BE0)
   * Address: 0x0057ED10 (FUN_0057ED10)
   * Address: 0x0057F770 (FUN_0057F770)
   * Address: 0x0057F9C0 (FUN_0057F9C0)
   * Address: 0x006521D0 (FUN_006521D0)
   * Address: 0x0066A110 (FUN_0066A110)
   * Address: 0x0067C690 (FUN_0067C690)
   * Address: 0x0067C810 (FUN_0067C810)
   * Address: 0x00680360 (FUN_00680360)
   * Address: 0x006876C0 (FUN_006876C0)
   * Address: 0x00692830 (FUN_00692830)
   * Address: 0x0069ED10 (FUN_0069ED10)
   * Address: 0x006D19F0 (FUN_006D19F0)
   * Address: 0x006DB130 (FUN_006DB130)
   * Address: 0x006DB140 (FUN_006DB140)
   * Address: 0x006DBA90 (FUN_006DBA90)
   * Address: 0x006DE5B0 (FUN_006DE5B0)
   * Address: 0x006E20D0 (FUN_006E20D0)
   * Address: 0x006E30B0 (FUN_006E30B0)
   * Address: 0x006E7A60 (FUN_006E7A60)
   * Address: 0x006EA180 (FUN_006EA180)
   * Address: 0x006F8330 (FUN_006F8330)
   * Address: 0x00701ED0 (FUN_00701ED0)
   * Address: 0x00701EE0 (FUN_00701EE0)
   * Address: 0x00702720 (FUN_00702720)
   * Address: 0x00702F90 (FUN_00702F90)
   * Address: 0x00704F20 (FUN_00704F20)
   * Address: 0x00718260 (FUN_00718260)
   * Address: 0x00718270 (FUN_00718270)
   * Address: 0x007187B0 (FUN_007187B0)
   * Address: 0x0071E1F0 (FUN_0071E1F0)
   * Address: 0x00733470 (FUN_00733470)
   * Address: 0x00740EE0 (FUN_00740EE0)
   * Address: 0x0074C8B0 (FUN_0074C8B0)
   * Address: 0x0074D0C0 (FUN_0074D0C0)
   * Address: 0x0074D890 (FUN_0074D890)
   * Address: 0x0074D9D0 (FUN_0074D9D0)
   * Address: 0x0074DB30 (FUN_0074DB30)
   * Address: 0x0074DD50 (FUN_0074DD50)
   * Address: 0x0074E6E0 (FUN_0074E6E0)
   * Address: 0x00753390 (FUN_00753390)
   * Address: 0x007533E0 (FUN_007533E0)
   * Address: 0x00753420 (FUN_00753420)
   * Address: 0x00753470 (FUN_00753470)
   * Address: 0x007534B0 (FUN_007534B0)
   * Address: 0x00753500 (FUN_00753500)
   * Address: 0x0075F160 (FUN_0075F160)
   * Address: 0x00767670 (FUN_00767670)
   * Address: 0x00767CF0 (FUN_00767CF0)
   * Address: 0x00767EB0 (FUN_00767EB0)
   * Address: 0x0076AB60 (FUN_0076AB60)
   * Address: 0x0076C030 (FUN_0076C030)
   * Address: 0x0076C3F0 (FUN_0076C3F0)
   * Address: 0x0077AC90 (FUN_0077AC90)
   * Address: 0x0077E2C0 (FUN_0077E2C0)
   * Address: 0x00782F10 (FUN_00782F10)
   * Address: 0x007830E0 (FUN_007830E0)
   * Address: 0x00789FE0 (FUN_00789FE0)
   * Address: 0x007982C0 (FUN_007982C0)
   * Address: 0x007AE950 (FUN_007AE950)
   * Address: 0x007AF2E0 (FUN_007AF2E0)
   * Address: 0x007AF440 (FUN_007AF440)
   * Address: 0x007AF520 (FUN_007AF520)
   * Address: 0x007AF530 (FUN_007AF530)
   * Address: 0x007BB760 (FUN_007BB760)
   * Address: 0x007BB770 (FUN_007BB770)
   * Address: 0x007C8760 (FUN_007C8760)
   * Address: 0x007C8EB0 (FUN_007C8EB0)
   * Address: 0x007C91A0 (FUN_007C91A0)
   * Address: 0x007D7DB0 (FUN_007D7DB0)
   * Address: 0x007D9FB0 (FUN_007D9FB0)
   * Address: 0x007E2990 (FUN_007E2990)
   * Address: 0x007E2E30 (FUN_007E2E30)
   * Address: 0x007E9230 (FUN_007E9230)
   * Address: 0x007EFF70 (FUN_007EFF70)
   * Address: 0x007F0C00 (FUN_007F0C00)
   * Address: 0x007FAB70 (FUN_007FAB70)
   * Address: 0x007FAB80 (FUN_007FAB80)
   * Address: 0x00813700 (FUN_00813700)
   * Address: 0x0082B430 (FUN_0082B430)
   * Address: 0x0082B5D0 (FUN_0082B5D0)
   * Address: 0x0082BCA0 (FUN_0082BCA0)
   * Address: 0x0082C470 (FUN_0082C470)
   * Address: 0x0082D4C0 (FUN_0082D4C0)
   * Address: 0x0082D660 (FUN_0082D660)
   * Address: 0x0082DE10 (FUN_0082DE10)
   * Address: 0x0082F1B0 (FUN_0082F1B0)
   * Address: 0x0082F720 (FUN_0082F720)
   * Address: 0x00830240 (FUN_00830240)
   * Address: 0x00836FF0 (FUN_00836FF0)
   * Address: 0x00837A20 (FUN_00837A20)
   * Address: 0x008487E0 (FUN_008487E0)
   * Address: 0x00848B60 (FUN_00848B60)
   * Address: 0x0084EA60 (FUN_0084EA60)
   *
   * What it does:
   * Stores source lane `+0x08` into caller-provided dword output storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreLane08Dword(
    std::uint32_t* const outValue,
    const DwordTripleLaneRuntimeView* const source
  ) noexcept
  {
    *outValue = source->lane08;
    return outValue;
  }

  /**
   * Address: 0x0056E890 (FUN_0056E890)
   *
   * What it does:
   * Composes one `{dword,dword,dword}` output lane from one scalar source lane
   * and one two-dword source lane.
   */
  [[maybe_unused]] [[nodiscard]] DwordTripleLaneRuntimeView* ComposeDwordTripleFromScalarAndPairLane(
    DwordTripleLaneRuntimeView* const outValue,
    const std::uint32_t* const scalarLaneSource,
    const DwordPairLaneRuntimeView* const pairLaneSource
  ) noexcept
  {
    outValue->lane00 = *scalarLaneSource;
    outValue->lane04 = pairLaneSource->lane00;
    outValue->lane08 = pairLaneSource->lane04;
    return outValue;
  }

  /**
   * Address: 0x00535740 (FUN_00535740)
   * Address: 0x00535D50 (FUN_00535D50)
   * Address: 0x00537BD0 (FUN_00537BD0)
   * Address: 0x0056AC40 (FUN_0056AC40)
   * Address: 0x0056AC50 (FUN_0056AC50)
   * Address: 0x0056B770 (FUN_0056B770)
   * Address: 0x0056D110 (FUN_0056D110)
   * Address: 0x0056EEC0 (FUN_0056EEC0)
   * Address: 0x00592420 (FUN_00592420)
   * Address: 0x0057ED00 (FUN_0057ED00)
   * Address: 0x0057F760 (FUN_0057F760)
   * Address: 0x00580500 (FUN_00580500)
   * Address: 0x00580CF0 (FUN_00580CF0)
   * Address: 0x005815E0 (FUN_005815E0)
   * Address: 0x00692920 (FUN_00692920)
   * Address: 0x0069F030 (FUN_0069F030)
   * Address: 0x006ADCF0 (FUN_006ADCF0)
   * Address: 0x006ADDA0 (FUN_006ADDA0)
   * Address: 0x006ADDC0 (FUN_006ADDC0)
   * Address: 0x006AEDB0 (FUN_006AEDB0)
   * Address: 0x006D1A80 (FUN_006D1A80)
   * Address: 0x006DB110 (FUN_006DB110)
   * Address: 0x006DB120 (FUN_006DB120)
   * Address: 0x006DBA80 (FUN_006DBA80)
   * Address: 0x006DE5A0 (FUN_006DE5A0)
   * Address: 0x006E1590 (FUN_006E1590)
   * Address: 0x006E24A0 (FUN_006E24A0)
   * Address: 0x006E30A0 (FUN_006E30A0)
   * Address: 0x006EA300 (FUN_006EA300)
   * Address: 0x006EAB80 (FUN_006EAB80)
   * Address: 0x006EB1A0 (FUN_006EB1A0)
   * Address: 0x006F8320 (FUN_006F8320)
   * Address: 0x006F85A0 (FUN_006F85A0)
   * Address: 0x006F8880 (FUN_006F8880)
   * Address: 0x00701EC0 (FUN_00701EC0)
   * Address: 0x00702710 (FUN_00702710)
   * Address: 0x00702770 (FUN_00702770)
   * Address: 0x00702F80 (FUN_00702F80)
   * Address: 0x00704F10 (FUN_00704F10)
   * Address: 0x0070E3E0 (FUN_0070E3E0)
   * Address: 0x0070E410 (FUN_0070E410)
   * Address: 0x0070F030 (FUN_0070F030)
   * Address: 0x00710C50 (FUN_00710C50)
   * Address: 0x00710C80 (FUN_00710C80)
   * Address: 0x00717EE0 (FUN_00717EE0)
   * Address: 0x00718240 (FUN_00718240)
   * Address: 0x00718250 (FUN_00718250)
   * Address: 0x00718400 (FUN_00718400)
   * Address: 0x007187A0 (FUN_007187A0)
   * Address: 0x0071A990 (FUN_0071A990)
   * Address: 0x0071B350 (FUN_0071B350)
   * Address: 0x0071E1E0 (FUN_0071E1E0)
   * Address: 0x00733460 (FUN_00733460)
   * Address: 0x00735280 (FUN_00735280)
   * Address: 0x00739AF0 (FUN_00739AF0)
   * Address: 0x00739BA0 (FUN_00739BA0)
   * Address: 0x00739D40 (FUN_00739D40)
   * Address: 0x00740ED0 (FUN_00740ED0)
   * Address: 0x0074C8A0 (FUN_0074C8A0)
   * Address: 0x0074DD40 (FUN_0074DD40)
   * Address: 0x0074E6D0 (FUN_0074E6D0)
   * Address: 0x0074EF80 (FUN_0074EF80)
   * Address: 0x0074F040 (FUN_0074F040)
   * Address: 0x0074F3C0 (FUN_0074F3C0)
   * Address: 0x00753380 (FUN_00753380)
   * Address: 0x007533D0 (FUN_007533D0)
   * Address: 0x00753410 (FUN_00753410)
   * Address: 0x00753460 (FUN_00753460)
   * Address: 0x007534A0 (FUN_007534A0)
   * Address: 0x007534F0 (FUN_007534F0)
   * Address: 0x0075F150 (FUN_0075F150)
   * Address: 0x00763B30 (FUN_00763B30)
   * Address: 0x00767790 (FUN_00767790)
   * Address: 0x00767C20 (FUN_00767C20)
   * Address: 0x00767CE0 (FUN_00767CE0)
   * Address: 0x00767EA0 (FUN_00767EA0)
   * Address: 0x007690F0 (FUN_007690F0)
   * Address: 0x0076AD00 (FUN_0076AD00)
   * Address: 0x0076C020 (FUN_0076C020)
   * Address: 0x0076C3E0 (FUN_0076C3E0)
   * Address: 0x00773AC0 (FUN_00773AC0)
   * Address: 0x00773AE0 (FUN_00773AE0)
   * Address: 0x0077A1B0 (FUN_0077A1B0)
   * Address: 0x0077A920 (FUN_0077A920)
   * Address: 0x0077AF20 (FUN_0077AF20)
   * Address: 0x0077B980 (FUN_0077B980)
   * Address: 0x0077C960 (FUN_0077C960)
   * Address: 0x0077CF10 (FUN_0077CF10)
   * Address: 0x0077E2B0 (FUN_0077E2B0)
   * Address: 0x00782F00 (FUN_00782F00)
   * Address: 0x007830D0 (FUN_007830D0)
   * Address: 0x00789F00 (FUN_00789F00)
   * Address: 0x00789FD0 (FUN_00789FD0)
   * Address: 0x007982B0 (FUN_007982B0)
   * Address: 0x007AE470 (FUN_007AE470)
   * Address: 0x007AE480 (FUN_007AE480)
   * Address: 0x007AE940 (FUN_007AE940)
   * Address: 0x007AEEB0 (FUN_007AEEB0)
   * Address: 0x007AF2D0 (FUN_007AF2D0)
   * Address: 0x007AF430 (FUN_007AF430)
   * Address: 0x007AF510 (FUN_007AF510)
   * Address: 0x007B0310 (FUN_007B0310)
   * Address: 0x007B26A0 (FUN_007B26A0)
   * Address: 0x007B2DE0 (FUN_007B2DE0)
   * Address: 0x007CA720 (FUN_007CA720)
   * Address: 0x007CFBF0 (FUN_007CFBF0)
   * Address: 0x007D3B20 (FUN_007D3B20)
   * Address: 0x007D3B30 (FUN_007D3B30)
   * Address: 0x007D42F0 (FUN_007D42F0)
   * Address: 0x007D5BE0 (FUN_007D5BE0)
   * Address: 0x007D77E0 (FUN_007D77E0)
   * Address: 0x007D7990 (FUN_007D7990)
   * Address: 0x007D7AB0 (FUN_007D7AB0)
   * Address: 0x007D7DA0 (FUN_007D7DA0)
   * Address: 0x007D9FA0 (FUN_007D9FA0)
   * Address: 0x007E2980 (FUN_007E2980)
   * Address: 0x007E2BC0 (FUN_007E2BC0)
   * Address: 0x007E2D70 (FUN_007E2D70)
   * Address: 0x007E2E20 (FUN_007E2E20)
   * Address: 0x007E2E50 (FUN_007E2E50)
   * Address: 0x007E3B50 (FUN_007E3B50)
   * Address: 0x007E5B10 (FUN_007E5B10)
   * Address: 0x007E9220 (FUN_007E9220)
   * Address: 0x007EBAD0 (FUN_007EBAD0)
   *
   * What it does:
   * Stores source lane `+0x04` into caller-provided dword output storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreLane04Dword(
    std::uint32_t* const outValue,
    const DwordTripleLaneRuntimeView* const source
  ) noexcept
  {
    *outValue = source->lane04;
    return outValue;
  }

  /**
   * Address: 0x00535730 (FUN_00535730)
   * Address: 0x0056AC30 (FUN_0056AC30)
   * Address: 0x0056EA50 (FUN_0056EA50)
   * Address: 0x0056F340 (FUN_0056F340)
   * Address: 0x0056F350 (FUN_0056F350)
   * Address: 0x0056F360 (FUN_0056F360)
   * Address: 0x005804F0 (FUN_005804F0)
   * Address: 0x007AE460 (FUN_007AE460)
   *
   * What it does:
   * Loads one dword through the pointer lane at `+0x04` and stores it into
   * caller-provided output storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreDereferencedLane04Dword(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }

  /**
   * Address: 0x00535620 (FUN_00535620)
   *
   * What it does:
   * Writes one repeated dword value into `count` contiguous destination lanes.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneA(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x005356C0 (FUN_005356C0)
   * Address: 0x005356E0 (FUN_005356E0)
   * Address: 0x005356F0 (FUN_005356F0)
   * Address: 0x00535700 (FUN_00535700)
   * Address: 0x00535710 (FUN_00535710)
   * Address: 0x00535720 (FUN_00535720)
   * Address: 0x005952A0 (FUN_005952A0)
   * Address: 0x00570470 (FUN_00570470)
   * Address: 0x00570480 (FUN_00570480)
   * Address: 0x00581590 (FUN_00581590)
   *
   * What it does:
   * Initializes one `{dword,byte}` lane pair record from caller source slots.
   */
  [[maybe_unused]] [[nodiscard]] DwordBytePairLane* InitializeDwordBytePairLaneA(
    DwordBytePairLane* const outLane,
    const std::uint32_t* const dwordSlot,
    const std::uint8_t* const byteSlot
  ) noexcept
  {
    outLane->lane00 = *dwordSlot;
    outLane->lane04 = *byteSlot;
    return outLane;
  }

  /**
   * Address: 0x005356D0 (FUN_005356D0)
   *
   * What it does:
   * Alias lane of `{dword,byte}` pair-record initialization.
   */
  [[maybe_unused]] [[nodiscard]] DwordBytePairLane* InitializeDwordBytePairLaneB(
    DwordBytePairLane* const outLane,
    const std::uint32_t* const dwordSlot,
    const std::uint8_t* const byteSlot
  ) noexcept
  {
    return InitializeDwordBytePairLaneA(outLane, dwordSlot, byteSlot);
  }

  /**
   * Address: 0x00595A60 (FUN_00595A60)
   * Address: 0x006C38D0 (FUN_006C38D0)
   *
   * What it does:
   * Initializes one `{dword,dword}` lane pair record from caller source slots.
   */
  [[maybe_unused]] [[nodiscard]] DwordPairLaneRuntimeView* InitializeDwordPairLane(
    DwordPairLaneRuntimeView* const outLane,
    const std::uint32_t* const firstDwordSlot,
    const std::uint32_t* const secondDwordSlot
  ) noexcept
  {
    outLane->lane00 = *firstDwordSlot;
    outLane->lane04 = *secondDwordSlot;
    return outLane;
  }

  /**
   * Address: 0x00595B80 (FUN_00595B80)
   * Address: 0x00595DC0 (FUN_00595DC0)
   *
   * What it does:
   * Swaps two `{dword,dword,dword}` lane records in place.
   */
  [[maybe_unused]] [[nodiscard]] DwordTripleLaneRuntimeView* SwapDwordTripleLanes(
    DwordTripleLaneRuntimeView* const left,
    DwordTripleLaneRuntimeView* const right
  ) noexcept
  {
    const DwordTripleLaneRuntimeView temporary = *left;
    *left = *right;
    *right = temporary;
    return left;
  }

  /**
   * Address: 0x0057F860 (FUN_0057F860)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneB(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x005C5F90 (FUN_005C5F90)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneC(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x005DC940 (FUN_005DC940)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneD(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x005DCAE0 (FUN_005DCAE0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneE(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x006522F0 (FUN_006522F0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneF(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0066A460 (FUN_0066A460)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneG(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0067CB80 (FUN_0067CB80)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneH(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x006F87A0 (FUN_006F87A0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneI(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x00701FA0 (FUN_00701FA0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneJ(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0078A2A0 (FUN_0078A2A0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneK(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x007AF3B0 (FUN_007AF3B0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneL(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x007AF620 (FUN_007AF620)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneM(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x007DA1D0 (FUN_007DA1D0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneN(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x007E31E0 (FUN_007E31E0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneO(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0082D250 (FUN_0082D250)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneP(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0084EAD0 (FUN_0084EAD0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneQ(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x008558E0 (FUN_008558E0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneR(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x00869C80 (FUN_00869C80)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneS(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x00879A80 (FUN_00879A80)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneT(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x00879ED0 (FUN_00879ED0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneU(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0087A310 (FUN_0087A310)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneV(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x0088A2E0 (FUN_0088A2E0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneW(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x008B2FD0 (FUN_008B2FD0)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanCountedLaneX(
    const std::uint32_t* valueSlot,
    std::uint32_t* destination,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordSpanByCount(valueSlot, destination, count);
  }

  /**
   * Address: 0x00623C50 (FUN_00623C50)
   * Address: 0x00674690 (FUN_00674690)
   *
   * What it does:
   * Unlinks one intrusive link node from its owner-slot chain.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView** UnlinkIntrusiveLinkNode(IntrusiveLinkRuntimeView* const node) noexcept
  {
    IntrusiveLinkRuntimeView** const ownerLink = LocateIntrusiveNodeOwnerLink(node);
    if (ownerLink != nullptr) {
      *ownerLink = node->next;
    }
    return ownerLink;
  }

  /**
   * Address: 0x0057D5B0 (FUN_0057D5B0)
   *
   * What it does:
   * Unlinks one intrusive owner-link lane from its owning owner-slot chain.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView** UnlinkIntrusiveLinkNodeOwnerChainAlias(
    IntrusiveLinkRuntimeView* const node
  ) noexcept
  {
    return UnlinkIntrusiveLinkNode(node);
  }

  struct Stride20IntrusiveLinkElementRuntimeView
  {
    std::byte lane00_07[0x08]{};
    IntrusiveLinkRuntimeView ownerLink; // +0x08
    std::byte lane10_13[0x04]{};
  };
#if defined(_M_IX86)
  static_assert(sizeof(Stride20IntrusiveLinkElementRuntimeView) == 0x14, "Stride20IntrusiveLinkElementRuntimeView size must be 0x14");
  static_assert(
    offsetof(Stride20IntrusiveLinkElementRuntimeView, ownerLink) == 0x08,
    "Stride20IntrusiveLinkElementRuntimeView::ownerLink offset must be 0x08"
  );
#endif

  /**
   * Address: 0x006892E0 (FUN_006892E0)
   *
   * What it does:
   * Walks one half-open stride-20 range and unlinks each embedded intrusive
   * owner-link lane at offset `+0x08`.
   */
  [[maybe_unused]] void UnlinkIntrusiveLinkRangeStride20(
    Stride20IntrusiveLinkElementRuntimeView* begin,
    Stride20IntrusiveLinkElementRuntimeView* const end
  ) noexcept
  {
    while (begin != end) {
      (void)UnlinkIntrusiveLinkNode(&begin->ownerLink);
      ++begin;
    }
  }

  /**
   * Address: 0x006877E0 (FUN_006877E0)
   *
   * What it does:
   * Alternate entrypoint that forwards one stride-20 half-open range to the
   * intrusive unlink walk helper.
   */
  [[maybe_unused]] void UnlinkIntrusiveLinkRangeStride20AliasA(
    Stride20IntrusiveLinkElementRuntimeView* const begin,
    Stride20IntrusiveLinkElementRuntimeView* const end
  ) noexcept
  {
    UnlinkIntrusiveLinkRangeStride20(begin, end);
  }

  /**
   * Address: 0x00688D00 (FUN_00688D00)
   *
   * What it does:
   * Secondary entrypoint that forwards one stride-20 half-open range to the
   * intrusive unlink walk helper.
   */
  [[maybe_unused]] void UnlinkIntrusiveLinkRangeStride20AliasB(
    Stride20IntrusiveLinkElementRuntimeView* const begin,
    Stride20IntrusiveLinkElementRuntimeView* const end
  ) noexcept
  {
    UnlinkIntrusiveLinkRangeStride20(begin, end);
  }

  struct RefCountedFloatLaneRuntimeView
  {
    std::uint8_t lane00 = 0;           // +0x00
    std::uint8_t lane01_03[0x03]{};    // +0x01
    std::uint32_t lane04 = 0;          // +0x04
    std::uint32_t lane08 = 0;          // +0x08
    std::uint32_t lane0C = 0;          // +0x0C
    std::uint32_t ref10 = 0;           // +0x10
    std::uint32_t lane14 = 0;          // +0x14
    std::uint32_t ref18 = 0;           // +0x18
    std::uint32_t lane1C = 0;          // +0x1C
    std::uint32_t ref20 = 0;           // +0x20
    float lane24 = 0.0f;               // +0x24
    float lane28 = 0.0f;               // +0x28
    float lane2C = 0.0f;               // +0x2C
    std::uint8_t lane30 = 0;           // +0x30
    std::uint8_t lane31_33[0x03]{};    // +0x31
  };
#if defined(_M_IX86)
  static_assert(offsetof(RefCountedFloatLaneRuntimeView, ref10) == 0x10, "RefCountedFloatLaneRuntimeView::ref10 offset must be 0x10");
  static_assert(offsetof(RefCountedFloatLaneRuntimeView, ref18) == 0x18, "RefCountedFloatLaneRuntimeView::ref18 offset must be 0x18");
  static_assert(offsetof(RefCountedFloatLaneRuntimeView, ref20) == 0x20, "RefCountedFloatLaneRuntimeView::ref20 offset must be 0x20");
  static_assert(offsetof(RefCountedFloatLaneRuntimeView, lane30) == 0x30, "RefCountedFloatLaneRuntimeView::lane30 offset must be 0x30");
#endif

  [[maybe_unused]] void IncrementRefCountWordIfPresent(std::uint32_t refWord) noexcept
  {
    if (refWord == 0u) {
      return;
    }

    (void)InterlockedExchangeAdd(
      reinterpret_cast<volatile LONG*>(static_cast<std::uintptr_t>(refWord) + 4u),
      1
    );
  }

  /**
   * Address: 0x005C84D0 (FUN_005C84D0)
   *
   * What it does:
   * Copies one mixed payload lane and bumps three intrusive ref-count lanes
   * (`+0x10`, `+0x18`, `+0x20`) when present.
   */
  [[maybe_unused]] RefCountedFloatLaneRuntimeView* CopyRefCountedFloatLaneRuntime(
    RefCountedFloatLaneRuntimeView* const destination,
    const RefCountedFloatLaneRuntimeView* const source
  ) noexcept
  {
    destination->lane00 = source->lane00;
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;

    destination->ref10 = source->ref10;
    IncrementRefCountWordIfPresent(destination->ref10);

    destination->lane14 = source->lane14;

    destination->ref18 = source->ref18;
    IncrementRefCountWordIfPresent(destination->ref18);

    destination->lane1C = source->lane1C;

    destination->ref20 = source->ref20;
    IncrementRefCountWordIfPresent(destination->ref20);

    destination->lane24 = source->lane24;
    destination->lane28 = source->lane28;
    destination->lane2C = source->lane2C;
    destination->lane30 = source->lane30;
    return destination;
  }

  struct Stride28SharedOwnerElementRuntimeView
  {
    std::byte lane00_13[0x14]{};
    SharedOwnerControlBlockRuntimeView* owner = nullptr; // +0x14
    std::byte lane18_1B[0x04]{};
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(Stride28SharedOwnerElementRuntimeView) == 0x1C,
    "Stride28SharedOwnerElementRuntimeView size must be 0x1C"
  );
  static_assert(
    offsetof(Stride28SharedOwnerElementRuntimeView, owner) == 0x14,
    "Stride28SharedOwnerElementRuntimeView::owner offset must be 0x14"
  );
#endif

  /**
   * Address: 0x005CC280 (FUN_005CC280)
   *
   * What it does:
   * Walks one half-open stride-28 range and releases each shared-owner control
   * block stored at lane `+0x14`.
   */
  [[maybe_unused]] std::intptr_t ReleaseSharedOwnerRangeStride28(
    Stride28SharedOwnerElementRuntimeView* begin,
    Stride28SharedOwnerElementRuntimeView* const end
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(begin);
    while (begin != end) {
      if (begin->owner != nullptr) {
        result = ReleaseSharedOwnerControlBlock(begin->owner);
      }
      ++begin;
    }
    return result;
  }

  /**
   * Address: 0x007D8600 (FUN_007D8600)
   *
   * What it does:
   * Calls scalar-deleting-destructor slot 0 for each 16-byte object in one
   * half-open range.
   */
  [[maybe_unused]] std::intptr_t DestroyVirtualRange16(
    VirtualDtor16RuntimeView* begin,
    VirtualDtor16RuntimeView* end
  ) noexcept
  {
    return DestroyVirtualRangeStride16(begin, end);
  }

  /**
   * Address: 0x0088A3E0 (FUN_0088A3E0)
   *
   * What it does:
   * Calls scalar-deleting-destructor slot 0 for each 136-byte object in one
   * half-open range.
   */
  [[maybe_unused]] std::intptr_t DestroyVirtualRange136(
    VirtualDtor136RuntimeView* begin,
    VirtualDtor136RuntimeView* end
  ) noexcept
  {
    return DestroyVirtualRangeStride136(begin, end);
  }

  /**
   * Address: 0x008D9D50 (FUN_008D9D50)
   *
   * What it does:
   * Writes one repeated dword value into one `[begin,end)` destination range.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanByEndLaneA(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordSpanByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x008D9E20 (FUN_008D9E20)
   *
   * What it does:
   * Swaps two 5-dword lanes in place and returns the first lane pointer.
   */
  [[maybe_unused]] std::int32_t* SwapFiveDwordLanes(
    std::int32_t* const firstLane,
    std::int32_t* const secondLane
  ) noexcept
  {
    const std::int32_t first0 = firstLane[0];
    const std::int32_t first1 = firstLane[1];
    const std::int32_t first2 = firstLane[2];
    const std::int32_t first3 = firstLane[3];
    const std::int32_t first4 = firstLane[4];

    firstLane[0] = secondLane[0];
    firstLane[1] = secondLane[1];
    firstLane[2] = secondLane[2];
    firstLane[3] = secondLane[3];
    firstLane[4] = secondLane[4];

    secondLane[0] = first0;
    secondLane[1] = first1;
    secondLane[2] = first2;
    secondLane[3] = first3;
    secondLane[4] = first4;
    return firstLane;
  }

  /**
   * Address: 0x008E9260 (FUN_008E9260)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanByEndLaneB(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordSpanByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x008E9280 (FUN_008E9280)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanByEndLaneC(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordSpanByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x0053A740 (FUN_0053A740)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneA() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneA);
  }

  /**
   * Address: 0x0053A860 (FUN_0053A860)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneB);
  }

  /**
   * Address: 0x0053A890 (FUN_0053A890)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneB);
  }

  /**
   * Address: 0x00545B70 (FUN_00545B70)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneCPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneC);
  }

  /**
   * Address: 0x00545BA0 (FUN_00545BA0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneCAliasSecondary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneC);
  }

  /**
   * Address: 0x0054AAB0 (FUN_0054AAB0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneDPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneD);
  }

  /**
   * Address: 0x0054AAE0 (FUN_0054AAE0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneDAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneD);
  }

  /**
   * Address: 0x0054AB50 (FUN_0054AB50)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneEPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneE);
  }

  /**
   * Address: 0x0054AB80 (FUN_0054AB80)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneEAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneE);
  }

  /**
   * Address: 0x005524F0 (FUN_005524F0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneFPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneF);
  }

  /**
   * Address: 0x00552520 (FUN_00552520)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneFAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneF);
  }

  /**
   * Address: 0x0055AF80 (FUN_0055AF80)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneGPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneG);
  }

  /**
   * Address: 0x0055AFB0 (FUN_0055AFB0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneGAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneG);
  }

  /**
   * Address: 0x0055B930 (FUN_0055B930)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneHPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneH);
  }

  /**
   * Address: 0x0055B960 (FUN_0055B960)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneHAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneH);
  }

  /**
   * Address: 0x0055BAB0 (FUN_0055BAB0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneIPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneI);
  }

  /**
   * Address: 0x0055BAE0 (FUN_0055BAE0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneIAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneI);
  }

  /**
   * Address: 0x0055BFC0 (FUN_0055BFC0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneJPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneJ);
  }

  /**
   * Address: 0x0055BFF0 (FUN_0055BFF0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneJAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneJ);
  }

  /**
   * Address: 0x00563AB0 (FUN_00563AB0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneKPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneK);
  }

  /**
   * Address: 0x00563AE0 (FUN_00563AE0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneKAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneK);
  }

  /**
   * Address: 0x00579C90 (FUN_00579C90)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneLPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneL);
  }

  /**
   * Address: 0x00579CC0 (FUN_00579CC0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneLAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneL);
  }

  /**
   * Address: 0x0059FD20 (FUN_0059FD20)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneMPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneM);
  }

  /**
   * Address: 0x0059FD50 (FUN_0059FD50)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneMAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneM);
  }

  /**
   * Address: 0x005A3130 (FUN_005A3130)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneNPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneN);
  }

  /**
   * Address: 0x005A3160 (FUN_005A3160)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneNAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneN);
  }

  /**
   * Address: 0x005A46D0 (FUN_005A46D0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneOPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneO);
  }

  /**
   * Address: 0x005A4700 (FUN_005A4700)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneOAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneO);
  }

  /**
   * Address: 0x005A55D0 (FUN_005A55D0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneP() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneP);
  }

  /**
   * Address: 0x0060AA90 (FUN_0060AA90)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneQ() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneQ);
  }

  /**
   * Address: 0x0060B150 (FUN_0060B150)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneRPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneR);
  }

  /**
   * Address: 0x0060B180 (FUN_0060B180)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneRAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneR);
  }

  /**
   * Address: 0x0060DCB0 (FUN_0060DCB0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneSPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneS);
  }

  /**
   * Address: 0x0060DCE0 (FUN_0060DCE0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneSAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneS);
  }

  /**
   * Address: 0x00619A30 (FUN_00619A30)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneTPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneT);
  }

  /**
   * Address: 0x00619A60 (FUN_00619A60)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneTAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneT);
  }

  /**
   * Address: 0x0061ACA0 (FUN_0061ACA0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneUPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneU);
  }

  /**
   * Address: 0x0061ACD0 (FUN_0061ACD0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneUAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneU);
  }

  /**
   * Address: 0x006262D0 (FUN_006262D0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneVPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneV);
  }

  /**
   * Address: 0x00626300 (FUN_00626300)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneVAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneV);
  }

  /**
   * Address: 0x0062F5F0 (FUN_0062F5F0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneWPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneW);
  }

  /**
   * Address: 0x0062F620 (FUN_0062F620)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneWAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneW);
  }

  /**
   * Address: 0x0065DF80 (FUN_0065DF80)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneXPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneX);
  }

  /**
   * Address: 0x0065DFB0 (FUN_0065DFB0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneXAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneX);
  }

  /**
   * Address: 0x0066BA00 (FUN_0066BA00)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneYPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneY);
  }

  /**
   * Address: 0x0066BA30 (FUN_0066BA30)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneYAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneY);
  }

  /**
   * Address: 0x0066BAE0 (FUN_0066BAE0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneZPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneZ);
  }

  /**
   * Address: 0x0066BB10 (FUN_0066BB10)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneZAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneZ);
  }

  /**
   * Address: 0x0066BC20 (FUN_0066BC20)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAAPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAA);
  }

  /**
   * Address: 0x0066BC50 (FUN_0066BC50)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAAAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAA);
  }

  /**
   * Address: 0x00672090 (FUN_00672090)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneABPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAB);
  }

  /**
   * Address: 0x006720C0 (FUN_006720C0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneABAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAB);
  }

  /**
   * Address: 0x006738F0 (FUN_006738F0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneACPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAC);
  }

  /**
   * Address: 0x00673920 (FUN_00673920)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneACAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAC);
  }

  /**
   * Address: 0x00694F80 (FUN_00694F80)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneADPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAD);
  }

  /**
   * Address: 0x00694FB0 (FUN_00694FB0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneADAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAD);
  }

  /**
   * Address: 0x00696780 (FUN_00696780)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAEPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAE);
  }

  /**
   * Address: 0x006967B0 (FUN_006967B0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAEAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAE);
  }

  /**
   * Address: 0x006968E0 (FUN_006968E0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAF() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAF);
  }

  /**
   * Address: 0x00696910 (FUN_00696910)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAFAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAF);
  }

  /**
   * Address: 0x00698060 (FUN_00698060)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAGPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAG);
  }

  /**
   * Address: 0x00698090 (FUN_00698090)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAGAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAG);
  }

  /**
   * Address: 0x00698150 (FUN_00698150)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAHPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAH);
  }

  /**
   * Address: 0x00698180 (FUN_00698180)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAHAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAH);
  }

  /**
   * Address: 0x0069A7F0 (FUN_0069A7F0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAIPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAI);
  }

  /**
   * Address: 0x0069A820 (FUN_0069A820)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAIAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAI);
  }

  /**
   * Address: 0x0069E3C0 (FUN_0069E3C0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAJPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAJ);
  }

  /**
   * Address: 0x0069E3F0 (FUN_0069E3F0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAJAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAJ);
  }

  /**
   * Address: 0x0069E4A0 (FUN_0069E4A0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAKPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAK);
  }

  /**
   * Address: 0x0069E4D0 (FUN_0069E4D0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAKAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAK);
  }

  /**
   * Address: 0x006AD260 (FUN_006AD260)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneALPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAL);
  }

  /**
   * Address: 0x006AD290 (FUN_006AD290)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneALAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAL);
  }

  /**
   * Address: 0x006BA210 (FUN_006BA210)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAMPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAM);
  }

  /**
   * Address: 0x006BA240 (FUN_006BA240)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAMAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAM);
  }

  /**
   * Address: 0x006D2D00 (FUN_006D2D00)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneANPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAN);
  }

  /**
   * Address: 0x006D2D30 (FUN_006D2D30)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneANAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAN);
  }

  /**
   * Address: 0x006E1090 (FUN_006E1090)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAOPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAO);
  }

  /**
   * Address: 0x006E10C0 (FUN_006E10C0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAOAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAO);
  }

  /**
   * Address: 0x006E11C0 (FUN_006E11C0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAPPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAP);
  }

  /**
   * Address: 0x006E11F0 (FUN_006E11F0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAPAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAP);
  }

  /**
   * Address: 0x006E7E30 (FUN_006E7E30)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAQPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAQ);
  }

  /**
   * Address: 0x006E7E60 (FUN_006E7E60)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAQAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAQ);
  }

  /**
   * Address: 0x006EE910 (FUN_006EE910)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneARPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAR);
  }

  /**
   * Address: 0x006EE940 (FUN_006EE940)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneARAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAR);
  }

  /**
   * Address: 0x006FA550 (FUN_006FA550)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneASPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAS);
  }

  /**
   * Address: 0x006FA580 (FUN_006FA580)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneASAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAS);
  }

  /**
   * Address: 0x006FA630 (FUN_006FA630)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneATPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAT);
  }

  /**
   * Address: 0x006FA660 (FUN_006FA660)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneATAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAT);
  }

  /**
   * Address: 0x0070AF50 (FUN_0070AF50)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAU() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAU);
  }

  /**
   * Address: 0x0070AF80 (FUN_0070AF80)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAUAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAU);
  }

  /**
   * Address: 0x0070B7C0 (FUN_0070B7C0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAVPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAV);
  }

  /**
   * Address: 0x0070B7F0 (FUN_0070B7F0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAVAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAV);
  }

  /**
   * Address: 0x0070DFB0 (FUN_0070DFB0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAWPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAW);
  }

  /**
   * Address: 0x0070DFE0 (FUN_0070DFE0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAWAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAW);
  }

  /**
   * Address: 0x0070E0E0 (FUN_0070E0E0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAXPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAX);
  }

  /**
   * Address: 0x0070E110 (FUN_0070E110)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAXAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAX);
  }

  /**
   * Address: 0x007156F0 (FUN_007156F0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAYPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAY);
  }

  /**
   * Address: 0x00715720 (FUN_00715720)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAYAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAY);
  }

  /**
   * Address: 0x00717600 (FUN_00717600)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAZPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAZ);
  }

  /**
   * Address: 0x00717630 (FUN_00717630)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneAZAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneAZ);
  }

  /**
   * Address: 0x00717750 (FUN_00717750)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBAPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBA);
  }

  /**
   * Address: 0x00717780 (FUN_00717780)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBAAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBA);
  }

  /**
   * Address: 0x00717950 (FUN_00717950)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBBPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBB);
  }

  /**
   * Address: 0x00717980 (FUN_00717980)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBBAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBB);
  }

  /**
   * Address: 0x00717D40 (FUN_00717D40)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBCPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBC);
  }

  /**
   * Address: 0x00717D70 (FUN_00717D70)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBCAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBC);
  }

  /**
   * Address: 0x00723C60 (FUN_00723C60)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBDPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBD);
  }

  /**
   * Address: 0x00723C90 (FUN_00723C90)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBDAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBD);
  }

  /**
   * Address: 0x007248B0 (FUN_007248B0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBEPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBE);
  }

  /**
   * Address: 0x007248E0 (FUN_007248E0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBEAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBE);
  }

  /**
   * Address: 0x0072A060 (FUN_0072A060)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBFPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBF);
  }

  /**
   * Address: 0x0072A090 (FUN_0072A090)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBFAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBF);
  }

  /**
   * Address: 0x007611E0 (FUN_007611E0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBGPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBG);
  }

  /**
   * Address: 0x00761210 (FUN_00761210)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBGAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBG);
  }

  /**
   * Address: 0x0076E700 (FUN_0076E700)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBHPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBH);
  }

  /**
   * Address: 0x0076E730 (FUN_0076E730)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBHAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBH);
  }

  /**
   * Address: 0x0076F2E0 (FUN_0076F2E0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBIPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBI);
  }

  /**
   * Address: 0x0076F310 (FUN_0076F310)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBIAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBI);
  }

  /**
   * Address: 0x0076F8A0 (FUN_0076F8A0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBJ() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBJ);
  }

  /**
   * Address: 0x0076F8D0 (FUN_0076F8D0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBJAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBJ);
  }

  /**
   * Address: 0x00772F50 (FUN_00772F50)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBKPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBK);
  }

  /**
   * Address: 0x00772F80 (FUN_00772F80)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBKAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBK);
  }

  /**
   * Address: 0x00775470 (FUN_00775470)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBLPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBL);
  }

  /**
   * Address: 0x007754A0 (FUN_007754A0)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBLAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBL);
  }

  /**
   * Address: 0x00776700 (FUN_00776700)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBMPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBM);
  }

  /**
   * Address: 0x00776730 (FUN_00776730)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBMAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBM);
  }

  /**
   * Address: 0x007767E0 (FUN_007767E0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBNPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBN);
  }

  /**
   * Address: 0x00776810 (FUN_00776810)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBNAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBN);
  }

  /**
   * Address: 0x007772D0 (FUN_007772D0)
   *
   * What it does:
   * Re-links one intrusive-list sentinel lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBOPrimary() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBO);
  }

  /**
   * Address: 0x00777300 (FUN_00777300)
   *
   * What it does:
   * Alias lane of global intrusive-sentinel reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneBOAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneBO);
  }

  struct LargeRuntimeWordAccessView
  {
    std::byte pad0000_08D7[0x8D8];
    std::uint32_t primaryWord; // +0x8D8
    std::byte pad08DC_0907[0x2C];
    std::uint32_t secondaryWord; // +0x908
  };
#if defined(_M_IX86)
  static_assert(offsetof(LargeRuntimeWordAccessView, primaryWord) == 0x8D8, "LargeRuntimeWordAccessView::primaryWord offset");
  static_assert(offsetof(LargeRuntimeWordAccessView, secondaryWord) == 0x908, "LargeRuntimeWordAccessView::secondaryWord offset");
  static_assert(sizeof(LargeRuntimeWordAccessView) == 0x90C, "LargeRuntimeWordAccessView size must be 0x90C");
#endif

  struct EntityFieldAccessorRuntimeView
  {
    std::byte pad0000_005F[0x60];
    std::uint32_t coordNodeLinkWord; // +0x60
    std::byte pad0064_0067[0x04];
    std::uint32_t entityIdWord; // +0x68
    std::uint32_t blueprintWord; // +0x6C
    std::byte pad0070_0098[0x29];
    std::uint8_t deadFlag; // +0x99
    std::byte pad009A_014B[0xB2];
    std::uint32_t armyWord; // +0x14C
    std::byte pad0150_01B8[0x69];
    std::uint8_t destroyQueuedFlag; // +0x1B9
    std::byte pad01BA_0553[0x39A];
    std::uint32_t builderSubsystemWord; // +0x554
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, coordNodeLinkWord) == 0x60,
    "EntityFieldAccessorRuntimeView::coordNodeLinkWord offset"
  );
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, entityIdWord) == 0x68,
    "EntityFieldAccessorRuntimeView::entityIdWord offset"
  );
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, blueprintWord) == 0x6C,
    "EntityFieldAccessorRuntimeView::blueprintWord offset"
  );
  static_assert(offsetof(EntityFieldAccessorRuntimeView, deadFlag) == 0x99, "EntityFieldAccessorRuntimeView::deadFlag offset");
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, armyWord) == 0x14C,
    "EntityFieldAccessorRuntimeView::armyWord offset"
  );
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, destroyQueuedFlag) == 0x1B9,
    "EntityFieldAccessorRuntimeView::destroyQueuedFlag offset"
  );
  static_assert(
    offsetof(EntityFieldAccessorRuntimeView, builderSubsystemWord) == 0x554,
    "EntityFieldAccessorRuntimeView::builderSubsystemWord offset"
  );
  static_assert(sizeof(EntityFieldAccessorRuntimeView) == 0x558, "EntityFieldAccessorRuntimeView size must be 0x558");
#endif

  struct DualAnchorListHeaderRuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* begin; // +0x08
    std::uint32_t* end; // +0x0C
    std::uint32_t* overflow; // +0x10
    std::uint32_t* freeHead; // +0x14
    std::uint32_t beginAnchorWords[4]; // +0x18
    std::uint32_t overflowAnchorWord; // +0x28
  };
#if defined(_M_IX86)
  static_assert(offsetof(DualAnchorListHeaderRuntimeView, beginAnchorWords) == 0x18, "DualAnchorListHeaderRuntimeView begin anchor");
  static_assert(
    offsetof(DualAnchorListHeaderRuntimeView, overflowAnchorWord) == 0x28,
    "DualAnchorListHeaderRuntimeView overflow anchor"
  );
  static_assert(sizeof(DualAnchorListHeaderRuntimeView) == 0x2C, "DualAnchorListHeaderRuntimeView size must be 0x2C");
#endif

  struct FourLaneHeaderTail14RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::uint32_t tailAnchorWord; // +0x14
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail14RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail14RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail14RuntimeView, tailAnchorWord) == 0x14,
    "FourLaneHeaderTail14RuntimeView tail anchor"
  );
  static_assert(sizeof(FourLaneHeaderTail14RuntimeView) == 0x18, "FourLaneHeaderTail14RuntimeView size must be 0x18");
#endif

  struct FourLaneHeaderTail20RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_001F[0x0C];
    std::uint32_t tailAnchorWord; // +0x20
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail20RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail20RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail20RuntimeView, tailAnchorWord) == 0x20,
    "FourLaneHeaderTail20RuntimeView tail anchor"
  );
  static_assert(sizeof(FourLaneHeaderTail20RuntimeView) == 0x24, "FourLaneHeaderTail20RuntimeView size must be 0x24");
#endif

  struct FourLaneHeaderTail18RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_0017[0x04];
    std::uint32_t tailAnchorWord; // +0x18
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail18RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail18RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail18RuntimeView, tailAnchorWord) == 0x18,
    "FourLaneHeaderTail18RuntimeView tail anchor"
  );
  static_assert(sizeof(FourLaneHeaderTail18RuntimeView) == 0x1C, "FourLaneHeaderTail18RuntimeView size must be 0x1C");
#endif

  struct FourLaneHeaderTail150RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_014F[0x13C];
    std::uint32_t tailAnchorWord; // +0x150
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail150RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail150RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail150RuntimeView, tailAnchorWord) == 0x150,
    "FourLaneHeaderTail150RuntimeView tail anchor"
  );
  static_assert(
    sizeof(FourLaneHeaderTail150RuntimeView) == 0x154,
    "FourLaneHeaderTail150RuntimeView size must be 0x154"
  );
#endif

  struct FourLaneHeaderTail1A0RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_019F[0x18C];
    std::uint32_t tailAnchorWord; // +0x1A0
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail1A0RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail1A0RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail1A0RuntimeView, tailAnchorWord) == 0x1A0,
    "FourLaneHeaderTail1A0RuntimeView tail anchor"
  );
  static_assert(
    sizeof(FourLaneHeaderTail1A0RuntimeView) == 0x1A4,
    "FourLaneHeaderTail1A0RuntimeView size must be 0x1A4"
  );
#endif

  struct FourLaneHeaderTail100RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_00FF[0xEC];
    std::uint32_t tailAnchorWord; // +0x100
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail100RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail100RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail100RuntimeView, tailAnchorWord) == 0x100,
    "FourLaneHeaderTail100RuntimeView tail anchor"
  );
  static_assert(sizeof(FourLaneHeaderTail100RuntimeView) == 0x104, "FourLaneHeaderTail100RuntimeView size must be 0x104");
#endif

  struct FourLaneHeaderTail1F0RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_01EF[0x1DC];
    std::uint32_t tailAnchorWord; // +0x1F0
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail1F0RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail1F0RuntimeView begin anchor"
  );
  static_assert(
    offsetof(FourLaneHeaderTail1F0RuntimeView, tailAnchorWord) == 0x1F0,
    "FourLaneHeaderTail1F0RuntimeView tail anchor"
  );
  static_assert(sizeof(FourLaneHeaderTail1F0RuntimeView) == 0x1F4, "FourLaneHeaderTail1F0RuntimeView size must be 0x1F4");
#endif

  struct SourceLane4RuntimeView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
  };
#if defined(_M_IX86)
  static_assert(offsetof(SourceLane4RuntimeView, lane04) == 0x04, "SourceLane4RuntimeView::lane04 offset must be 0x04");
#endif

  struct SourceLane8RuntimeView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
  };
#if defined(_M_IX86)
  static_assert(offsetof(SourceLane8RuntimeView, lane08) == 0x08, "SourceLane8RuntimeView::lane08 offset must be 0x08");
#endif

  struct SourceLane12RuntimeView
  {
    std::uint32_t lane00;
    std::uint32_t lane04;
    std::uint32_t lane08;
    std::uint32_t lane0C;
  };
#if defined(_M_IX86)
  static_assert(offsetof(SourceLane12RuntimeView, lane0C) == 0x0C, "SourceLane12RuntimeView::lane0C offset must be 0x0C");
#endif

  struct SourceIndirectLane4RuntimeView
  {
    std::uint32_t lane00;
    std::uint32_t* lane04;
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SourceIndirectLane4RuntimeView, lane04) == 0x04,
    "SourceIndirectLane4RuntimeView::lane04 offset must be 0x04"
  );
#endif

  struct Stride24SpanRuntimeView
  {
    std::byte* begin; // +0x00
  };

  struct Stride20SpanRuntimeView
  {
    std::uint32_t lane00;
    std::byte* begin; // +0x04
  };
#if defined(_M_IX86)
  static_assert(offsetof(Stride20SpanRuntimeView, begin) == 0x04, "Stride20SpanRuntimeView::begin offset must be 0x04");
#endif

  template <typename TFourLaneHeaderView>
  [[nodiscard]] std::uint32_t* InitializeFourLaneHeader(TFourLaneHeaderView* const header) noexcept
  {
    auto* const beginAnchor = &header->beginAnchorWord;
    auto* const tailAnchor = &header->tailAnchorWord;
    header->prev = beginAnchor;
    header->next = beginAnchor;
    header->tail = tailAnchor;
    header->freeHead = beginAnchor;
    return reinterpret_cast<std::uint32_t*>(header);
  }

  [[nodiscard]] std::uint32_t* InitializeDualAnchorListHeader(DualAnchorListHeaderRuntimeView* const header) noexcept
  {
    auto* const selfAnchor = reinterpret_cast<std::uint32_t*>(&header->prev);
    auto* const beginAnchor = header->beginAnchorWords;
    auto* const overflowAnchor = &header->overflowAnchorWord;
    header->prev = selfAnchor;
    header->next = selfAnchor;
    header->begin = beginAnchor;
    header->end = beginAnchor;
    header->overflow = overflowAnchor;
    header->freeHead = beginAnchor;
    return reinterpret_cast<std::uint32_t*>(header);
  }

  [[nodiscard]] std::uint32_t* CopyWordToOutput(std::uint32_t* const output, const std::uint32_t value) noexcept
  {
    *output = value;
    return output;
  }

  /**
   * Address: 0x005794C0 (FUN_005794C0)
   *
   * What it does:
   * Reads one 32-bit runtime lane from offset `+0x8D8`.
   */
  [[maybe_unused]] std::uint32_t LoadLargeRuntimePrimaryWord(const LargeRuntimeWordAccessView* const view) noexcept
  {
    return view->primaryWord;
  }

  /**
   * Address: 0x005794D0 (FUN_005794D0)
   *
   * What it does:
   * Reads one 32-bit runtime lane from offset `+0x908`.
   */
  [[maybe_unused]] std::uint32_t LoadLargeRuntimeSecondaryWord(const LargeRuntimeWordAccessView* const view) noexcept
  {
    return view->secondaryWord;
  }

  /**
   * Address: 0x005794E0 (FUN_005794E0)
   *
   * What it does:
   * Initializes one dual-anchor list header to singleton/self and static
   * anchor lanes.
   */
  [[maybe_unused]] std::uint32_t* InitializeDualAnchorListHeaderPrimary(DualAnchorListHeaderRuntimeView* const header) noexcept
  {
    return InitializeDualAnchorListHeader(header);
  }

  /**
   * Address: 0x005795D0 (FUN_005795D0)
   *
   * What it does:
   * Copies one entity-id runtime lane (`+0x68`) into caller-provided output.
   */
  [[maybe_unused]] std::uint32_t* CopyEntityIdWordToOutput(
    std::uint32_t* const output,
    const EntityFieldAccessorRuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->entityIdWord);
  }

  /**
   * Address: 0x005795E0 (FUN_005795E0)
   *
   * What it does:
   * Reads one entity blueprint/runtime word lane (`+0x6C`).
   */
  [[maybe_unused]] std::uint32_t LoadEntityBlueprintWord(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->blueprintWord;
  }

  /**
   * Address: 0x005795F0 (FUN_005795F0)
   *
   * What it does:
   * Reads one entity army-owner lane (`+0x14C`).
   */
  [[maybe_unused]] std::uint32_t LoadEntityArmyWord(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->armyWord;
  }

  /**
   * Address: 0x00579600 (FUN_00579600)
   *
   * What it does:
   * Reads one entity dead-flag lane (`+0x99`).
   */
  [[maybe_unused]] std::uint8_t LoadEntityDeadFlag(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->deadFlag;
  }

  /**
   * Address: 0x00579610 (FUN_00579610)
   *
   * What it does:
   * Reads one entity destroy-queued flag lane (`+0x1B9`).
   */
  [[maybe_unused]] std::uint8_t LoadEntityDestroyQueuedFlag(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->destroyQueuedFlag;
  }

  /**
   * Address: 0x00579630 (FUN_00579630)
   *
   * What it does:
   * Reads one builder-subsystem pointer lane from offset `+0x554`.
   */
  [[maybe_unused]] std::uint32_t LoadEntityBuilderSubsystemWord(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->builderSubsystemWord;
  }

  /**
   * Address: 0x00579660 (FUN_00579660)
   *
   * What it does:
   * Reads one intrusive link/runtime word from offset `+0x60`.
   */
  [[maybe_unused]] std::uint32_t LoadEntityCoordNodeLinkWord(const EntityFieldAccessorRuntimeView* const view) noexcept
  {
    return view->coordNodeLinkWord;
  }

  /**
   * Address: 0x0057D390 (FUN_0057D390)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x20`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail20(FourLaneHeaderTail20RuntimeView* const header) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x006ADEF0 (FUN_006ADEF0)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x18`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail18(FourLaneHeaderTail18RuntimeView* const header) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x0069EAE0 (FUN_0069EAE0)
   * Address: 0x007AE670 (FUN_007AE670)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x150`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail150(
    FourLaneHeaderTail150RuntimeView* const header
  ) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x007AE770 (FUN_007AE770)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x1A0`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail1A0(
    FourLaneHeaderTail1A0RuntimeView* const header
  ) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  struct ExternalDwordSpanHeader80RuntimeView
  {
    std::uint32_t base; // +0x00
    std::uint32_t begin; // +0x04
    std::uint32_t end; // +0x08
    std::uint32_t cursor; // +0x0C
  };

  /**
   * Address: 0x0069EFA0 (FUN_0069EFA0)
   *
   * What it does:
   * Binds one external dword-span header to `base` with a fixed 80-dword
   * capacity window.
   */
  [[maybe_unused]] ExternalDwordSpanHeader80RuntimeView* InitializeExternalDwordSpanCount80(
    ExternalDwordSpanHeader80RuntimeView* const outHeader,
    const std::uint32_t base
  ) noexcept
  {
    outHeader->base = base;
    outHeader->begin = base;
    outHeader->end = base + 0x140u;
    outHeader->cursor = base;
    return outHeader;
  }

  /**
   * Address: 0x0057D6C0 (FUN_0057D6C0)
   *
   * What it does:
   * Copies one input word directly into caller-provided output.
   */
  [[maybe_unused]] std::uint32_t* CopyInputWordToOutputPrimary(
    std::uint32_t* const output,
    const std::uint32_t inputWord
  ) noexcept
  {
    return CopyWordToOutput(output, inputWord);
  }

  /**
   * Address: 0x0057D800 (FUN_0057D800)
   * Address: 0x00899C90 (FUN_00899C90)
   * Address: 0x008A7DB0 (FUN_008A7DB0)
   * Address: 0x008A7DC0 (FUN_008A7DC0)
   *
   * What it does:
   * Copies source lane `+0x04` into caller-provided output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceLane4ToOutputPrimary(
    std::uint32_t* const output,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane04);
  }

  /**
   * Address: 0x0057D810 (FUN_0057D810)
   *
   * What it does:
   * Copies source lane `+0x08` into caller-provided output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceLane8ToOutputPrimary(
    std::uint32_t* const output,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane08);
  }

  /**
   * Address: 0x0057DA30 (FUN_0057DA30)
   *
   * What it does:
   * Loads one source indirect lane (`*(*(source + 0x04))`) into output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceIndirectLane4ToOutput(
    std::uint32_t* const output,
    const SourceIndirectLane4RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, *source->lane04);
  }

  /**
   * Address: 0x0057DA40 (FUN_0057DA40)
   *
   * What it does:
   * Alias lane for copying source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceLane4ToOutputAlias(
    std::uint32_t* const output,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane04);
  }

  /**
   * Address: 0x0057DD40 (FUN_0057DD40)
   *
   * What it does:
   * Alias lane for copying one input word directly into output.
   */
  [[maybe_unused]] std::uint32_t* CopyInputWordToOutputAlias(
    std::uint32_t* const output,
    const std::uint32_t inputWord
  ) noexcept
  {
    return CopyWordToOutput(output, inputWord);
  }

  /**
   * Address: 0x0057DD90 (FUN_0057DD90)
   *
   * What it does:
   * Alias lane for dual-anchor list-header singleton initialization.
   */
  [[maybe_unused]] std::uint32_t* InitializeDualAnchorListHeaderAlias(DualAnchorListHeaderRuntimeView* const header) noexcept
  {
    return InitializeDualAnchorListHeader(header);
  }

  /**
   * Address: 0x0057DDB0 (FUN_0057DDB0)
   *
   * What it does:
   * Alias lane for copying source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceLane8ToOutputAlias(
    std::uint32_t* const output,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane08);
  }

  /**
   * Address: 0x0057DDC0 (FUN_0057DDC0)
   *
   * What it does:
   * Copies source lane `+0x0C` into caller-provided output.
   */
  [[maybe_unused]] std::uint32_t* CopySourceLane12ToOutput(
    std::uint32_t* const output,
    const SourceLane12RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane0C);
  }

  /**
   * Address: 0x0057E500 (FUN_0057E500)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x14`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail14(FourLaneHeaderTail14RuntimeView* const header) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x0057E650 (FUN_0057E650)
   *
   * What it does:
   * Copies source lane `+0x04` into output (compact-lane variant).
   */
  [[maybe_unused]] std::uint32_t* CopyCompactSourceLane4ToOutputPrimary(
    std::uint32_t* const output,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane04);
  }

  /**
   * Address: 0x0057E660 (FUN_0057E660)
   *
   * What it does:
   * Copies source lane `+0x08` into output (compact-lane variant).
   */
  [[maybe_unused]] std::uint32_t* CopyCompactSourceLane8ToOutputPrimary(
    std::uint32_t* const output,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane08);
  }

  /**
   * Address: 0x0057E720 (FUN_0057E720)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x1F0`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail1F0(FourLaneHeaderTail1F0RuntimeView* const header) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x0057E790 (FUN_0057E790)
   *
   * What it does:
   * Returns address of one stride-24 element from a base span.
   */
  [[maybe_unused]] std::uintptr_t LocateStride24ElementAddress(
    const std::int32_t index,
    const Stride24SpanRuntimeView* const span
  ) noexcept
  {
    const std::ptrdiff_t signedIndex = static_cast<std::ptrdiff_t>(index);
    return reinterpret_cast<std::uintptr_t>(span->begin + (signedIndex * 24));
  }

  /**
   * Address: 0x0057E7A0 (FUN_0057E7A0)
   *
   * What it does:
   * Alias lane for copying source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* CopyCompactSourceLane4ToOutputAlias(
    std::uint32_t* const output,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane04);
  }

  /**
   * Address: 0x0057E7B0 (FUN_0057E7B0)
   *
   * What it does:
   * Alias lane for copying source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* CopyCompactSourceLane8ToOutputAlias(
    std::uint32_t* const output,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(output, source->lane08);
  }

  /**
   * Address: 0x0057E870 (FUN_0057E870)
   * Address: 0x0074CEB0 (FUN_0074CEB0)
   *
   * What it does:
   * Returns address of one stride-20 element from source lane `+0x04`.
   */
  [[maybe_unused]] std::uintptr_t LocateStride20ElementAddress(
    const std::int32_t index,
    const Stride20SpanRuntimeView* const span
  ) noexcept
  {
    const std::ptrdiff_t signedIndex = static_cast<std::ptrdiff_t>(index);
    return reinterpret_cast<std::uintptr_t>(span->begin + (signedIndex * 20));
  }

  /**
   * Address: 0x0057E9B0 (FUN_0057E9B0)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x100`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail100(FourLaneHeaderTail100RuntimeView* const header) noexcept
  {
    return InitializeFourLaneHeader(header);
  }

  /**
   * Address: 0x0057EA70 (FUN_0057EA70)
   *
   * What it does:
   * Alias lane of intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] std::uint32_t* ResetGlobalIntrusiveSentinelLaneCAlias() noexcept
  {
    return ResetGlobalIntrusiveSentinel(gGlobalIntrusiveSentinelLaneC);
  }

  struct DwordPairRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordPairRuntimeView) == 0x08, "DwordPairRuntimeView size must be 0x08");
  static_assert(offsetof(DwordPairRuntimeView, lane04) == 0x04, "DwordPairRuntimeView::lane04 offset must be 0x04");
#endif

  struct DwordTripleRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordTripleRuntimeView) == 0x0C, "DwordTripleRuntimeView size must be 0x0C");
  static_assert(offsetof(DwordTripleRuntimeView, lane08) == 0x08, "DwordTripleRuntimeView::lane08 offset must be 0x08");
#endif

  struct DwordPointerAt4RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t* lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DwordPointerAt4RuntimeView, lane04) == 0x04,
    "DwordPointerAt4RuntimeView::lane04 offset must be 0x04"
  );
#endif

  struct PointerRangeRuntimeView
  {
    std::uint32_t* begin; // +0x00
    std::uint32_t* reserveEnd; // +0x04
    std::uint32_t* end; // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(PointerRangeRuntimeView) == 0x0C, "PointerRangeRuntimeView size must be 0x0C");
  static_assert(offsetof(PointerRangeRuntimeView, begin) == 0x00, "PointerRangeRuntimeView::begin offset must be 0x00");
  static_assert(offsetof(PointerRangeRuntimeView, end) == 0x08, "PointerRangeRuntimeView::end offset must be 0x08");
#endif

  struct VTableOwnerRuntimeView
  {
    std::uint32_t* vtable; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(VTableOwnerRuntimeView) == 0x04, "VTableOwnerRuntimeView size must be 0x04");
#endif

  struct DwordByteLaneRuntimeView
  {
    std::uint32_t value; // +0x00
    std::uint8_t flag; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordByteLaneRuntimeView) == 0x08, "DwordByteLaneRuntimeView size must be 0x08");
  static_assert(offsetof(DwordByteLaneRuntimeView, flag) == 0x04, "DwordByteLaneRuntimeView::flag offset must be 0x04");
#endif

  [[nodiscard]] std::uint32_t* StoreDword(std::uint32_t* const outValue, const std::uint32_t value) noexcept
  {
    *outValue = value;
    return outValue;
  }

  [[nodiscard]] std::uintptr_t ComputeOffsetAddressByStride(
    const std::uint32_t baseAddress,
    const std::int32_t index,
    const std::uint32_t stride
  ) noexcept
  {
    return static_cast<std::uintptr_t>(baseAddress + (static_cast<std::uint32_t>(index) * stride));
  }

  /**
   * Address: 0x005C3D10 (FUN_005C3D10)
   * Address: 0x0066A1A0 (FUN_0066A1A0)
   * Address: 0x0066A270 (FUN_0066A270)
   * Address: 0x00672EB0 (FUN_00672EB0)
   * Address: 0x00674680 (FUN_00674680)
   * Address: 0x0089CBD0 (FUN_0089CBD0)
   *
   * What it does:
   * Clears one two-word output lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLane(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x005C3D70 (FUN_005C3D70)
   *
   * What it does:
   * Stores one scalar dword into output lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C3D70(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C3D80 (FUN_005C3D80)
   *
   * What it does:
   * Returns one virtual-slot dword from vtable offset `+0x10`.
   */
  [[maybe_unused]] std::uint32_t ReadVTableSlot10(const VTableOwnerRuntimeView* const owner) noexcept
  {
    return owner->vtable[4];
  }

  /**
   * Address: 0x005C4540 (FUN_005C4540)
   * Address: 0x0066A370 (FUN_0066A370)
   *
   * What it does:
   * Stores one dereferenced indirect dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreIndirectLane4Dword(
    std::uint32_t* const outValue,
    const DwordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, *source->lane04);
  }

  /**
   * Address: 0x005C4550 (FUN_005C4550)
   *
   * What it does:
   * Stores source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C4550(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C4560 (FUN_005C4560)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C4560(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C4A50 (FUN_005C4A50)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C4A50(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C4A60 (FUN_005C4A60)
   *
   * What it does:
   * Stores source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane8Dword5C4A60(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane08);
  }

  /**
   * Address: 0x005C4B90 (FUN_005C4B90)
   * Address: 0x0066AB20 (FUN_0066AB20)
   * Address: 0x005DD960 (FUN_005DD960)
   * Address: 0x005DDAF0 (FUN_005DDAF0)
   *
   * What it does:
   * Stores one `source[0] + index * 4` address lane into output.
   */
  [[maybe_unused]] std::uint32_t* StoreOffsetAddressStride4FromBaseWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreDword(
      outValue,
      static_cast<std::uint32_t>(ComputeOffsetAddressByStride(*baseWord, index, 4u))
    );
  }

  /**
   * Address: 0x005C4C90 (FUN_005C4C90)
   *
   * What it does:
   * Computes one `source lane +0x04 + index * 12` byte address.
   */
  [[maybe_unused]] std::uintptr_t ComputeOffsetAddressStride12FromLane4(
    const std::int32_t index,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return ComputeOffsetAddressByStride(source->lane04, index, 12u);
  }

  /**
   * Address: 0x005C50D0 (FUN_005C50D0)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane8Dword5C50D0(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane08);
  }

  /**
   * Address: 0x005C56C0 (FUN_005C56C0)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C56C0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C5FE0 (FUN_005C5FE0)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C5FE0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C6000 (FUN_005C6000)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C6000(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C6030 (FUN_005C6030)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C6030(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C6090 (FUN_005C6090)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane8Dword5C6090(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane08);
  }

  /**
   * Address: 0x005C61D0 (FUN_005C61D0)
   * Address: 0x0089B420 (FUN_0089B420)
   * Address: 0x0089BC60 (FUN_0089BC60)
   *
   * What it does:
   * Writes one `{left, right}` dword pair into output lanes.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromTwoSources(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const left,
    const std::uint32_t* const right
  ) noexcept
  {
    outValue->lane00 = *left;
    outValue->lane04 = *right;
    return outValue;
  }

  /**
   * Address: 0x005C61E0 (FUN_005C61E0)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C61E0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C6570 (FUN_005C6570)
   * Address: 0x005CAD20 (FUN_005CAD20)
   * Address: 0x005CFD70 (FUN_005CFD70)
   * Address: 0x005D0160 (FUN_005D0160)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C6570(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C6C10 (FUN_005C6C10)
   *
   * What it does:
   * Returns count of 4-byte elements in one pointer range lane.
   */
  [[maybe_unused]] std::int32_t CountDwordRangeElements(const PointerRangeRuntimeView* const range) noexcept
  {
    return static_cast<std::int32_t>(range->end - range->begin);
  }

  /**
   * Address: 0x005C6E40 (FUN_005C6E40)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C6E40(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C6E50 (FUN_005C6E50)
   * Address: 0x005CAD30 (FUN_005CAD30)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane8Dword5C6E50(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane08);
  }

  /**
   * Address: 0x005C73B0 (FUN_005C73B0)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C73B0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C73F0 (FUN_005C73F0)
   * Address: 0x005CFD60 (FUN_005CFD60)
   * Address: 0x005D0150 (FUN_005D0150)
   *
   * What it does:
   * Alias lane for storing dereferenced indirect source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreIndirectLane4Dword5C73F0(
    std::uint32_t* const outValue,
    const DwordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, *source->lane04);
  }

  /**
   * Address: 0x005C7AE0 (FUN_005C7AE0)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output.
   */
  [[maybe_unused]] std::uint32_t* StoreLane4Dword5C7AE0(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x005C7E50 (FUN_005C7E50)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C7E50(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C7F80 (FUN_005C7F80)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C7F80(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C8020 (FUN_005C8020)
   * Address: 0x005CA620 (FUN_005CA620)
   *
   * What it does:
   * Writes one `{dword, byte}` lane to output storage.
   */
  [[maybe_unused]] DwordByteLaneRuntimeView* StoreDwordByteLane(
    DwordByteLaneRuntimeView* const outValue,
    const std::uint32_t* const sourceDword,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->value = *sourceDword;
    outValue->flag = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x005C8030 (FUN_005C8030)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane5C8030(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x005C8040 (FUN_005C8040)
   *
   * What it does:
   * Stores one `source[0] + index * 12` address lane into output.
   */
  [[maybe_unused]] std::uint32_t* StoreOffsetAddressStride12FromBaseWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreDword(
      outValue,
      static_cast<std::uint32_t>(ComputeOffsetAddressByStride(*baseWord, index, 12u))
    );
  }

  /**
   * Address: 0x005CFE60 (FUN_005CFE60)
   *
   * What it does:
   * Replaces one pointer slot with the pointer stored at the pointed dword
   * lane.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotThroughStoredAddress(std::uint32_t** const pointerSlot) noexcept
  {
    *pointerSlot = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(**pointerSlot));
    return pointerSlot;
  }

  struct ForwardLinkNodeSingleLaneRuntimeView
  {
    ForwardLinkNodeSingleLaneRuntimeView* next; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(ForwardLinkNodeSingleLaneRuntimeView) == 0x04, "ForwardLinkNodeSingleLaneRuntimeView size must be 0x04");
#endif

  struct IntrusiveNodeRuntimeView
  {
    IntrusiveNodeRuntimeView* prev; // +0x00
    IntrusiveNodeRuntimeView* next; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(IntrusiveNodeRuntimeView) == 0x08, "IntrusiveNodeRuntimeView size must be 0x08");
#endif

  struct SparseRuntimeStateAccessorView
  {
    std::byte pad0000_0027[0x28];
    std::uint32_t rootWord; // +0x28
    std::byte pad002C_006B[0x40];
    std::uint32_t profileWord; // +0x6C
    std::byte pad0070_008B[0x1C];
    std::uint8_t primaryFlag; // +0x8C
    std::uint8_t secondaryFlag; // +0x8D
    std::uint8_t tertiaryFlag; // +0x8E
    std::byte pad008F_009F[0x11];
    std::uint32_t sourceWord; // +0xA0
    std::uint32_t configWord; // +0xA4
    std::byte pad00A8_0147[0xA0];
    std::uint32_t ownerWord; // +0x148
    std::byte pad014C_016F[0x24];
    std::uint32_t timerWord; // +0x170
    std::uint8_t timerFlag; // +0x174
    std::byte pad0175_0247[0xD3];
    std::uint32_t capacityWord; // +0x248
  };
#if defined(_M_IX86)
  static_assert(offsetof(SparseRuntimeStateAccessorView, rootWord) == 0x28, "SparseRuntimeStateAccessorView::rootWord offset");
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, profileWord) == 0x6C,
    "SparseRuntimeStateAccessorView::profileWord offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, primaryFlag) == 0x8C,
    "SparseRuntimeStateAccessorView::primaryFlag offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, secondaryFlag) == 0x8D,
    "SparseRuntimeStateAccessorView::secondaryFlag offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, tertiaryFlag) == 0x8E,
    "SparseRuntimeStateAccessorView::tertiaryFlag offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, sourceWord) == 0xA0,
    "SparseRuntimeStateAccessorView::sourceWord offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, configWord) == 0xA4,
    "SparseRuntimeStateAccessorView::configWord offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, ownerWord) == 0x148,
    "SparseRuntimeStateAccessorView::ownerWord offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, timerWord) == 0x170,
    "SparseRuntimeStateAccessorView::timerWord offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, timerFlag) == 0x174,
    "SparseRuntimeStateAccessorView::timerFlag offset"
  );
  static_assert(
    offsetof(SparseRuntimeStateAccessorView, capacityWord) == 0x248,
    "SparseRuntimeStateAccessorView::capacityWord offset"
  );
  static_assert(sizeof(SparseRuntimeStateAccessorView) == 0x24C, "SparseRuntimeStateAccessorView size must be 0x24C");
#endif

  struct FourLaneHeaderTail38RuntimeView
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_0037[0x24];
    std::uint32_t tailAnchorWord; // +0x38
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail38RuntimeView, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail38RuntimeView::beginAnchorWord offset"
  );
  static_assert(
    offsetof(FourLaneHeaderTail38RuntimeView, tailAnchorWord) == 0x38,
    "FourLaneHeaderTail38RuntimeView::tailAnchorWord offset"
  );
  static_assert(sizeof(FourLaneHeaderTail38RuntimeView) == 0x3C, "FourLaneHeaderTail38RuntimeView size must be 0x3C");
#endif

  struct ExternalDwordSpanHeaderRuntimeView
  {
    std::uint32_t base; // +0x00
    std::uint32_t begin; // +0x04
    std::uint32_t end; // +0x08
    std::uint32_t cursor; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(ExternalDwordSpanHeaderRuntimeView) == 0x10, "ExternalDwordSpanHeaderRuntimeView size must be 0x10");
#endif

  [[nodiscard]] std::uint32_t* StoreWordAtOutput(std::uint32_t* const output, const std::uint32_t value) noexcept
  {
    *output = value;
    return output;
  }

  struct SevenWordLaneRuntimeView
  {
    std::uint32_t lanes[7];
  };
  static_assert(sizeof(SevenWordLaneRuntimeView) == 0x1C, "SevenWordLaneRuntimeView size must be 0x1C");

  /**
   * Address: 0x00688820 (FUN_00688820)
   * Address: 0x006888C0 (FUN_006888C0)
   * Address: 0x00688EE0 (FUN_00688EE0)
   * Address: 0x00688F90 (FUN_00688F90)
   *
   * What it does:
   * Copies one source dword into output storage when output is non-null.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopySourceWordIfOutputPresent(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (output != nullptr) {
      *output = *sourceWord;
    }
    return output;
  }

  /**
   * Address: 0x00689ED0 (FUN_00689ED0)
   *
   * What it does:
   * Clears one seven-word lane to all zeros.
   */
  [[maybe_unused]] [[nodiscard]] SevenWordLaneRuntimeView* ClearSevenWordLane(
    SevenWordLaneRuntimeView* const outValue
  ) noexcept
  {
    outValue->lanes[0] = 0u;
    outValue->lanes[1] = 0u;
    outValue->lanes[2] = 0u;
    outValue->lanes[3] = 0u;
    outValue->lanes[4] = 0u;
    outValue->lanes[5] = 0u;
    outValue->lanes[6] = 0u;
    return outValue;
  }

  [[nodiscard]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeAndSelfLink(IntrusiveNodeRuntimeView* const node) noexcept
  {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;
    return node;
  }

  /**
   * Address: 0x005C5250 (FUN_005C5250)
   *
   * What it does:
   * Initializes one intrusive node's two links from a caller head slot and
   * patches the previous head's back-link when present.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* LinkIntrusiveNodeFromHeadSlot(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView** const headSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const head = *headSlot;
    node->prev = head;
    if (head != nullptr) {
      node->next = head->prev;
      head->prev = node;
    } else {
      node->next = nullptr;
    }
    return node;
  }

  /**
   * Address: 0x005D0260 (FUN_005D0260)
   *
   * What it does:
   * Stores one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneAlpha(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005D0430 (FUN_005D0430)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneBeta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005D0440 (FUN_005D0440)
   * Address: 0x007AE5F0 (FUN_007AE5F0)
   *
   * What it does:
   * Pops one head node from a forward-link chain and stores the removed node.
   */
  [[maybe_unused]] ForwardLinkNodeSingleLaneRuntimeView** PopForwardLinkHeadToOutput(
    ForwardLinkNodeSingleLaneRuntimeView** const outValue,
    ForwardLinkNodeSingleLaneRuntimeView** const headSlot
  ) noexcept
  {
    ForwardLinkNodeSingleLaneRuntimeView* const head = *headSlot;
    *outValue = head;
    *headSlot = head->next;
    return outValue;
  }

  /**
   * Address: 0x005D0480 (FUN_005D0480)
   *
   * What it does:
   * Advances one forward-link head slot to the current head's next node.
   */
  [[maybe_unused]] ForwardLinkNodeSingleLaneRuntimeView** AdvanceForwardLinkHead(
    ForwardLinkNodeSingleLaneRuntimeView** const headSlot
  ) noexcept
  {
    *headSlot = (*headSlot)->next;
    return headSlot;
  }

  /**
   * Address: 0x005D0AC0 (FUN_005D0AC0)
   *
   * What it does:
   * Unlinks one intrusive node from its ring and restores singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfAlpha(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005D0AE0 (FUN_005D0AE0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfBeta(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005D0CA0 (FUN_005D0CA0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfGamma(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005D1F50 (FUN_005D1F50)
   *
   * What it does:
   * Reads one runtime capacity/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateCapacityWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->capacityWord;
  }

  /**
   * Address: 0x005D1F70 (FUN_005D1F70)
   *
   * What it does:
   * Writes one runtime primary flag byte.
   */
  [[maybe_unused]] SparseRuntimeStateAccessorView* WriteRuntimeStatePrimaryFlag(
    SparseRuntimeStateAccessorView* const runtime,
    const std::uint8_t value
  ) noexcept
  {
    runtime->primaryFlag = value;
    return runtime;
  }

  /**
   * Address: 0x005D1F90 (FUN_005D1F90)
   *
   * What it does:
   * Reads one runtime secondary flag byte.
   */
  [[maybe_unused]] std::uint8_t ReadRuntimeStateSecondaryFlag(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->secondaryFlag;
  }

  /**
   * Address: 0x005D1FB0 (FUN_005D1FB0)
   *
   * What it does:
   * Reads one runtime tertiary flag byte.
   */
  [[maybe_unused]] std::uint8_t ReadRuntimeStateTertiaryFlag(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->tertiaryFlag;
  }

  /**
   * Address: 0x005D2760 (FUN_005D2760)
   *
   * What it does:
   * Clears one two-word output lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneAlias(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x005D3D50 (FUN_005D3D50)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneGamma(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005D3DE0 (FUN_005D3DE0)
   *
   * What it does:
   * Initializes one four-lane intrusive header with a tail anchor at `+0x38`.
   */
  [[maybe_unused]] std::uint32_t* InitializeFourLaneHeaderTail38(FourLaneHeaderTail38RuntimeView* const header) noexcept
  {
    auto* const beginAnchor = &header->beginAnchorWord;
    auto* const tailAnchor = &header->tailAnchorWord;
    header->prev = beginAnchor;
    header->next = beginAnchor;
    header->tail = tailAnchor;
    header->freeHead = beginAnchor;
    return reinterpret_cast<std::uint32_t*>(header);
  }

  /**
   * Address: 0x005D3FF0 (FUN_005D3FF0)
   * Address: 0x005E1080 (FUN_005E1080)
   * Address: 0x005E10A0 (FUN_005E10A0)
   *
   * What it does:
   * Swaps one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValues(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t temp = *left;
    *left = *right;
    *right = temp;
    return left;
  }

  struct DwordQuadRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordQuadRuntimeView) == 0x10, "DwordQuadRuntimeView size must be 0x10");
  static_assert(offsetof(DwordQuadRuntimeView, lane04) == 0x04, "DwordQuadRuntimeView::lane04 offset must be 0x04");
  static_assert(offsetof(DwordQuadRuntimeView, lane08) == 0x08, "DwordQuadRuntimeView::lane08 offset must be 0x08");
  static_assert(offsetof(DwordQuadRuntimeView, lane0C) == 0x0C, "DwordQuadRuntimeView::lane0C offset must be 0x0C");
#endif

  /**
   * Address: 0x005DF230 (FUN_005DF230)
   * Address: 0x005DF270 (FUN_005DF270)
   * Address: 0x005DFA00 (FUN_005DFA00)
   * Address: 0x005DFA30 (FUN_005DFA30)
   * Address: 0x006EB9B0 (FUN_006EB9B0)
   * Address: 0x006EBDC0 (FUN_006EBDC0)
   * Address: 0x00751340 (FUN_00751340)
   * Address: 0x00751390 (FUN_00751390)
   * Address: 0x007513C0 (FUN_007513C0)
   * Address: 0x007513F0 (FUN_007513F0)
   * Address: 0x00751420 (FUN_00751420)
   * Address: 0x00751450 (FUN_00751450)
   *
   * What it does:
   * Swaps lanes `+0x04/+0x08/+0x0C` between two four-lane records while
   * preserving lane `+0x00`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapTrailingThreeDwordLanes(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = left->lane04;
    left->lane04 = right->lane04;
    right->lane04 = lane04;

    const std::uint32_t lane08 = left->lane08;
    left->lane08 = right->lane08;
    right->lane08 = lane08;

    const std::uint32_t lane0C = left->lane0C;
    left->lane0C = right->lane0C;
    right->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x005D4130 (FUN_005D4130)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanHeader(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::int32_t count,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    const std::uint32_t base = static_cast<std::uint32_t>(baseAddress);
    outHeader->base = base;
    outHeader->begin = base;
    outHeader->end = base + (static_cast<std::uint32_t>(count) * 4u);
    outHeader->cursor = base;
    return outHeader;
  }

  /**
   * Address: 0x005D5660 (FUN_005D5660)
   *
   * What it does:
   * Reads one runtime profile/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateProfileWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->profileWord;
  }

  /**
   * Address: 0x005D57C0 (FUN_005D57C0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfDelta(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005D58B0 (FUN_005D58B0)
   *
   * What it does:
   * Reads one runtime owner/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateOwnerWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->ownerWord;
  }

  /**
   * Address: 0x005D58F0 (FUN_005D58F0)
   *
   * What it does:
   * Reads one runtime timer/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateTimerWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->timerWord;
  }

  /**
   * Address: 0x005D5900 (FUN_005D5900)
   *
   * What it does:
   * Reads one runtime timer flag byte.
   */
  [[maybe_unused]] std::uint8_t ReadRuntimeStateTimerFlag(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->timerFlag;
  }

  /**
   * Address: 0x005D5940 (FUN_005D5940)
   *
   * What it does:
   * Reads one runtime config/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateConfigWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->configWord;
  }

  /**
   * Address: 0x005D5970 (FUN_005D5970)
   *
   * What it does:
   * Reads one runtime source/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateSourceWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->sourceWord;
  }

  /**
   * Address: 0x005D62A0 (FUN_005D62A0)
   *
   * What it does:
   * Reads one runtime root/state dword lane.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeStateRootWord(const SparseRuntimeStateAccessorView* const runtime) noexcept
  {
    return runtime->rootWord;
  }

  /**
   * Address: 0x005DB600 (FUN_005DB600)
   *
   * What it does:
   * Computes one `source lane +0x04 + index * 40` byte address.
   */
  [[maybe_unused]] std::uintptr_t LocateStride40ElementAddress(
    const std::int32_t index,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return ComputeOffsetAddressByStride(source->lane04, index, 40u);
  }

  /**
   * Address: 0x005DBE20 (FUN_005DBE20)
   * Address: 0x005DCF50 (FUN_005DCF50)
   * Address: 0x005DD0A0 (FUN_005DD0A0)
   * Address: 0x005E0150 (FUN_005E0150)
   * Address: 0x005E01B0 (FUN_005E01B0)
   * Address: 0x005E88A0 (FUN_005E88A0)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StorePairLaneWordToOutputPrimary(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005DBE30 (FUN_005DBE30)
   * Address: 0x005E0160 (FUN_005E0160)
   * Address: 0x005E01C0 (FUN_005E01C0)
   * Address: 0x005E88B0 (FUN_005E88B0)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreTripleLaneWordToOutputPrimary(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005DC280 (FUN_005DC280)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StorePairLaneWordToOutputAlias(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005DC800 (FUN_005DC800)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreTripleLaneWordToOutputAlias(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005DCCF0 (FUN_005DCCF0)
   * Address: 0x005DCF60 (FUN_005DCF60)
   * Address: 0x005DD980 (FUN_005DD980)
   * Address: 0x005DDAA0 (FUN_005DDAA0)
   * Address: 0x005DDAE0 (FUN_005DDAE0)
   * Address: 0x005DE440 (FUN_005DE440)
   * Address: 0x005DE460 (FUN_005DE460)
   *
   * What it does:
   * Alias lane for storing one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneOmega(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  using OffsetVisitorCallback = void(__thiscall*)(std::uintptr_t objectAddress);

  struct OffsetVisitorBindingRuntimeView
  {
    OffsetVisitorCallback callback; // +0x00
    void* contextBase; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(OffsetVisitorBindingRuntimeView) == 0x08, "OffsetVisitorBindingRuntimeView size must be 0x08");
  static_assert(
    offsetof(OffsetVisitorBindingRuntimeView, contextBase) == 0x04,
    "OffsetVisitorBindingRuntimeView::contextBase offset must be 0x04"
  );
#endif

  /**
   * Address: 0x005DEB00 (FUN_005DEB00)
   * Address: 0x0066A4F0 (FUN_0066A4F0)
   * Address: 0x005DFA80 (FUN_005DFA80)
   *
   * What it does:
   * Writes one two-word output lane from two scalar dword inputs.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposeDwordPairFromValues(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t left,
    const std::uint32_t right
  ) noexcept
  {
    outValue->lane00 = left;
    outValue->lane04 = right;
    return outValue;
  }

  /**
   * Address: 0x005DEB10 (FUN_005DEB10)
   *
   * What it does:
   * Applies one callback to each `context + offset` entry in the range, then
   * stores the callback/context pair into one two-word binding lane.
   */
  [[maybe_unused]] OffsetVisitorBindingRuntimeView* ApplyOffsetRangeAndBindVisitor(
    OffsetVisitorBindingRuntimeView* const outBinding,
    const std::uint32_t* const beginOffsets,
    const std::uint32_t* const endOffsets,
    const OffsetVisitorCallback callback,
    void* const contextBase
  ) noexcept
  {
    const std::uintptr_t baseAddress = reinterpret_cast<std::uintptr_t>(contextBase);
    for (const std::uint32_t* offset = beginOffsets; offset != endOffsets; ++offset) {
      callback(baseAddress + static_cast<std::uintptr_t>(*offset));
    }

    outBinding->callback = callback;
    outBinding->contextBase = contextBase;
    return outBinding;
  }

  struct ForwardLinkHeadRuntimeView
  {
    ForwardLinkHeadRuntimeView* next; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(ForwardLinkHeadRuntimeView) == 0x04, "ForwardLinkHeadRuntimeView size must be 0x04");
#endif

  struct IntrusiveOwnerNodeSlotRuntimeView
  {
    std::uint32_t lane00; // +0x00
    IntrusiveNodeRuntimeView* node; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveOwnerNodeSlotRuntimeView, node) == 0x04,
    "IntrusiveOwnerNodeSlotRuntimeView::node offset must be 0x04"
  );
  static_assert(sizeof(IntrusiveOwnerNodeSlotRuntimeView) == 0x08, "IntrusiveOwnerNodeSlotRuntimeView size must be 0x08");
#endif

  struct RuntimeStateProfileRuntimeView
  {
    std::byte pad0000_006B[0x6C];
    std::uint32_t profileWord; // +0x6C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateProfileRuntimeView, profileWord) == 0x6C,
    "RuntimeStateProfileRuntimeView::profileWord offset must be 0x6C"
  );
  static_assert(sizeof(RuntimeStateProfileRuntimeView) == 0x70, "RuntimeStateProfileRuntimeView size must be 0x70");
#endif

  struct RuntimeStateRootRuntimeView
  {
    std::byte pad0000_0027[0x28];
    std::uint32_t rootWord; // +0x28
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateRootRuntimeView, rootWord) == 0x28,
    "RuntimeStateRootRuntimeView::rootWord offset must be 0x28"
  );
  static_assert(sizeof(RuntimeStateRootRuntimeView) == 0x2C, "RuntimeStateRootRuntimeView size must be 0x2C");
#endif

  struct RuntimeStateOwnerRuntimeView
  {
    std::byte pad0000_0147[0x148];
    std::uint32_t ownerWord; // +0x148
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateOwnerRuntimeView, ownerWord) == 0x148,
    "RuntimeStateOwnerRuntimeView::ownerWord offset must be 0x148"
  );
  static_assert(sizeof(RuntimeStateOwnerRuntimeView) == 0x14C, "RuntimeStateOwnerRuntimeView size must be 0x14C");
#endif

  struct RuntimeStateConfigSourceRuntimeView
  {
    std::byte pad0000_009F[0xA0];
    std::uint32_t sourceWord; // +0xA0
    std::uint32_t configWord; // +0xA4
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateConfigSourceRuntimeView, sourceWord) == 0xA0,
    "RuntimeStateConfigSourceRuntimeView::sourceWord offset must be 0xA0"
  );
  static_assert(
    offsetof(RuntimeStateConfigSourceRuntimeView, configWord) == 0xA4,
    "RuntimeStateConfigSourceRuntimeView::configWord offset must be 0xA4"
  );
  static_assert(sizeof(RuntimeStateConfigSourceRuntimeView) == 0xA8, "RuntimeStateConfigSourceRuntimeView size must be 0xA8");
#endif

  struct RuntimeStateTimerRuntimeView
  {
    std::byte pad0000_016F[0x170];
    std::uint32_t timerWord; // +0x170
    std::uint8_t timerFlag; // +0x174
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateTimerRuntimeView, timerWord) == 0x170,
    "RuntimeStateTimerRuntimeView::timerWord offset must be 0x170"
  );
  static_assert(
    offsetof(RuntimeStateTimerRuntimeView, timerFlag) == 0x174,
    "RuntimeStateTimerRuntimeView::timerFlag offset must be 0x174"
  );
  static_assert(sizeof(RuntimeStateTimerRuntimeView) == 0x178, "RuntimeStateTimerRuntimeView size must be 0x178");
#endif

  struct RuntimeStateFlagsRuntimeView
  {
    std::byte pad0000_008B[0x8C];
    std::uint8_t primaryFlag; // +0x8C
    std::uint8_t secondaryFlag; // +0x8D
    std::uint8_t tertiaryFlag; // +0x8E
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateFlagsRuntimeView, primaryFlag) == 0x8C,
    "RuntimeStateFlagsRuntimeView::primaryFlag offset must be 0x8C"
  );
  static_assert(
    offsetof(RuntimeStateFlagsRuntimeView, secondaryFlag) == 0x8D,
    "RuntimeStateFlagsRuntimeView::secondaryFlag offset must be 0x8D"
  );
  static_assert(
    offsetof(RuntimeStateFlagsRuntimeView, tertiaryFlag) == 0x8E,
    "RuntimeStateFlagsRuntimeView::tertiaryFlag offset must be 0x8E"
  );
  static_assert(sizeof(RuntimeStateFlagsRuntimeView) == 0x8F, "RuntimeStateFlagsRuntimeView size must be 0x8F");
#endif

  struct RuntimeStateCapacityRuntimeView
  {
    std::byte pad0000_0247[0x248];
    std::uint32_t capacityWord; // +0x248
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeStateCapacityRuntimeView, capacityWord) == 0x248,
    "RuntimeStateCapacityRuntimeView::capacityWord offset must be 0x248"
  );
  static_assert(sizeof(RuntimeStateCapacityRuntimeView) == 0x24C, "RuntimeStateCapacityRuntimeView size must be 0x24C");
#endif

  struct FourLaneHeaderTail38RuntimeViewSecondary
  {
    std::uint32_t* prev; // +0x00
    std::uint32_t* next; // +0x04
    std::uint32_t* tail; // +0x08
    std::uint32_t* freeHead; // +0x0C
    std::uint32_t beginAnchorWord; // +0x10
    std::byte pad0014_0037[0x24];
    std::uint32_t tailAnchorWord; // +0x38
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourLaneHeaderTail38RuntimeViewSecondary, beginAnchorWord) == 0x10,
    "FourLaneHeaderTail38RuntimeViewSecondary::beginAnchorWord offset must be 0x10"
  );
  static_assert(
    offsetof(FourLaneHeaderTail38RuntimeViewSecondary, tailAnchorWord) == 0x38,
    "FourLaneHeaderTail38RuntimeViewSecondary::tailAnchorWord offset must be 0x38"
  );
  static_assert(
    sizeof(FourLaneHeaderTail38RuntimeViewSecondary) == 0x3C,
    "FourLaneHeaderTail38RuntimeViewSecondary size must be 0x3C"
  );
#endif

  struct ExternalSpanHeaderRuntimeView
  {
    std::uint32_t base; // +0x00
    std::uint32_t begin; // +0x04
    std::uint32_t end; // +0x08
    std::uint32_t cursor; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(ExternalSpanHeaderRuntimeView) == 0x10, "ExternalSpanHeaderRuntimeView size must be 0x10");
#endif

  [[nodiscard]] std::uint32_t* InitializeTwoWordSelfLink(std::uint32_t* const linkWords) noexcept
  {
    linkWords[0] = reinterpret_cast<std::uint32_t>(linkWords);
    linkWords[1] = reinterpret_cast<std::uint32_t>(linkWords);
    return linkWords;
  }

  struct FourWordTailRuntimeView
  {
    std::uint32_t lane00 = 0u; // +0x00
    std::uint32_t lane04 = 0u; // +0x04
    std::uint32_t lane08 = 0u; // +0x08
    std::uint32_t lane0C = 0u; // +0x0C
  };
  static_assert(sizeof(FourWordTailRuntimeView) == 0x10, "FourWordTailRuntimeView size must be 0x10");
  static_assert(offsetof(FourWordTailRuntimeView, lane04) == 0x04, "FourWordTailRuntimeView::lane04 offset must be 0x04");
  static_assert(offsetof(FourWordTailRuntimeView, lane08) == 0x08, "FourWordTailRuntimeView::lane08 offset must be 0x08");
  static_assert(offsetof(FourWordTailRuntimeView, lane0C) == 0x0C, "FourWordTailRuntimeView::lane0C offset must be 0x0C");

  [[nodiscard]] IntrusiveNodeRuntimeView* RelinkOwnerNodeAtOffsetBeforeAnchor(
    void* const ownerBase,
    IntrusiveNodeRuntimeView* const anchor,
    const std::size_t ownerNodeOffset
  ) noexcept
  {
    auto* const node = ownerBase != nullptr
      ? reinterpret_cast<IntrusiveNodeRuntimeView*>(static_cast<std::byte*>(ownerBase) + ownerNodeOffset)
      : nullptr;

    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = node;
    node->next = node;

    node->prev = anchor->prev;
    node->next = anchor;
    anchor->prev = node;
    node->prev->next = node;
    return node;
  }

  /**
   * Address: 0x00651EC0 (FUN_00651EC0)
   *
   * What it does:
   * Initializes one two-word intrusive lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* InitializeSelfLinkPairLateA(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x00651EF0 (FUN_00651EF0)
   *
   * What it does:
   * Unlinks one owner node at `owner+0x04`, restores singleton self-links, and
   * inserts it directly before `anchor`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkOwnerNodeOffset04BeforeAnchor(
    void* const ownerBase,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkOwnerNodeAtOffsetBeforeAnchor(ownerBase, anchor, 0x04u);
  }

  /**
   * Address: 0x00651F50 (FUN_00651F50)
   *
   * What it does:
   * Unlinks one owner node at `owner+0x68`, restores singleton self-links, and
   * inserts it directly before `anchor`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkOwnerNodeOffset68BeforeAnchor(
    void* const ownerBase,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkOwnerNodeAtOffsetBeforeAnchor(ownerBase, anchor, 0x68u);
  }

  /**
   * Address: 0x006ADDF0 (FUN_006ADDF0)
   *
   * What it does:
   * Unlinks one owner node at `owner+0x48`, restores singleton self-links, and
   * inserts it directly before `anchor`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkOwnerNodeOffset48BeforeAnchor(
    void* const ownerBase,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkOwnerNodeAtOffsetBeforeAnchor(ownerBase, anchor, 0x48u);
  }

  /**
   * Address: 0x00651F90 (FUN_00651F90)
   *
   * What it does:
   * Returns owner base address for one intrusive node slot at offset `0x68`,
   * or null when the node slot is null.
   */
  [[maybe_unused]] void* ResolveOwnerBaseFromNodeSlotOffset68Primary(
    IntrusiveNodeRuntimeView* const* const nodeSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = *nodeSlot;
    if (node == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(node) - 0x68u);
  }

  /**
   * Address: 0x00651FA0 (FUN_00651FA0)
   *
   * What it does:
   * Alias lane for owner-base recovery from one offset-`0x68` node slot.
   */
  [[maybe_unused]] void* ResolveOwnerBaseFromNodeSlotOffset68Alias(
    IntrusiveNodeRuntimeView* const* const nodeSlot
  ) noexcept
  {
    return ResolveOwnerBaseFromNodeSlotOffset68Primary(nodeSlot);
  }

  /**
   * Address: 0x006ADE20 (FUN_006ADE20)
   *
   * What it does:
   * Returns owner base address for one intrusive node slot at offset `0x48`,
   * or null when the node slot is null.
   */
  [[maybe_unused]] void* ResolveOwnerBaseFromNodeSlotOffset48(
    IntrusiveNodeRuntimeView* const* const nodeSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = *nodeSlot;
    if (node == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(node) - 0x48u);
  }

  /**
   * Address: 0x00651FC0 (FUN_00651FC0)
   *
   * What it does:
   * Clears one four-word lane tail (`+0x04/+0x08/+0x0C`) to zero.
   */
  [[maybe_unused]] FourWordTailRuntimeView* ClearFourWordTailLanes(FourWordTailRuntimeView* const outValue) noexcept
  {
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x00652660 (FUN_00652660)
   *
   * What it does:
   * Stores one `*base + index * 4` address lane to output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4Late(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreWordAtOutput(outValue, *baseWord + (static_cast<std::uint32_t>(index) * 4u));
  }

  /**
   * Address: 0x00652B90 (FUN_00652B90)
   *
   * What it does:
   * Reads one owner/state dword lane at offset `+0x148`.
   */
  [[maybe_unused]] std::uint32_t ReadRuntimeOwnerWordLate(const RuntimeStateOwnerRuntimeView* const runtime) noexcept
  {
    return runtime->ownerWord;
  }

  /**
   * Address: 0x006532A0 (FUN_006532A0)
   *
   * What it does:
   * Returns element count for one pointer span with 48-byte stride, or zero
   * when the begin lane is null.
   */
  [[maybe_unused]] std::int32_t CountStride48Elements(const ExternalSpanHeaderRuntimeView* const span) noexcept
  {
    if (span == nullptr || span->begin == 0u) {
      return 0;
    }

    const std::intptr_t byteSpan = static_cast<std::intptr_t>(span->end) - static_cast<std::intptr_t>(span->begin);
    return static_cast<std::int32_t>(byteSpan / 48);
  }

  /**
   * Address: 0x005E8B30 (FUN_005E8B30)
   * Address: 0x006ADD90 (FUN_006ADD90)
   *
   * What it does:
   * Initializes one two-word intrusive lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* InitializeSelfLinkPairPrimary(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x005E8B40 (FUN_005E8B40)
   *
   * What it does:
   * Unlinks one intrusive node from its ring and restores singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfEpsilon(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005E3CB0 (FUN_005E3CB0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfEta(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005E95F0 (FUN_005E95F0)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordAlpha(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005E9600 (FUN_005E9600)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordBeta(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005E9610 (FUN_005E9610)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane8WordAlpha(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005E9620 (FUN_005E9620)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane8WordBeta(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005E9970 (FUN_005E9970)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordGamma(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005E9980 (FUN_005E9980)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane8WordGamma(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005E99F0 (FUN_005E99F0)
   *
   * What it does:
   * Computes one `source lane +0x04 + index * 20` byte address.
   */
  [[maybe_unused]] std::uintptr_t LocateStride20ElementAddressPrimary(
    const std::int32_t index,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return ComputeOffsetAddressByStride(source->lane04, index, 20u);
  }

  /**
   * Address: 0x005E9B60 (FUN_005E9B60)
   *
   * What it does:
   * Advances one stored dword address by 4 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceStoredAddressBy4(std::uint32_t* const addressSlot) noexcept
  {
    *addressSlot += 4u;
    return addressSlot;
  }

  /**
   * Address: 0x005E9CE0 (FUN_005E9CE0)
   *
   * What it does:
   * Returns true when a two-word range lane is empty (`begin == end`).
   */
  [[maybe_unused]] bool IsTwoWordRangeEmpty(const DwordPairRuntimeView* const range) noexcept
  {
    return range->lane00 == range->lane04;
  }

  struct DwordVectorBeginEndRuntimeView
  {
    std::uint32_t lane00; // +0x00
    const std::uint32_t* begin; // +0x04
    const std::uint32_t* end; // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordVectorBeginEndRuntimeView) == 0x0C, "DwordVectorBeginEndRuntimeView size must be 0x0C");
  static_assert(
    offsetof(DwordVectorBeginEndRuntimeView, begin) == 0x04,
    "DwordVectorBeginEndRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(DwordVectorBeginEndRuntimeView, end) == 0x08,
    "DwordVectorBeginEndRuntimeView::end offset must be 0x08"
  );
#endif

  /**
   * Address: 0x005E8860 (FUN_005E8860)
   *
   * What it does:
   * Returns true when a dword-vector lane is not allocated or contains no
   * elements (`begin == nullptr || begin == end`).
   */
  [[maybe_unused]] bool IsDwordVectorLaneEmptyOrUnallocated(
    const DwordVectorBeginEndRuntimeView* const vectorLane
  ) noexcept
  {
    return vectorLane->begin == nullptr || vectorLane->begin == vectorLane->end;
  }

  /**
   * Address: 0x005E9D30 (FUN_005E9D30)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordDelta(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005E9D50 (FUN_005E9D50)
   *
   * What it does:
   * Unlinks one intrusive owner-node lane at `+0x04`, restores singleton
   * self-links, then relinks that node directly before `anchor`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkOwnerNodeBeforeAnchor(
    IntrusiveOwnerNodeSlotRuntimeView* const owner,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = UnlinkIntrusiveNodeAndSelfLink(owner->node);
    node->prev = anchor->prev;
    node->next = anchor;
    anchor->prev = node;
    node->prev->next = node;
    return node;
  }

  /**
   * Address: 0x005E9D80 (FUN_005E9D80)
   *
   * What it does:
   * Unlinks the intrusive node referenced by owner lane `+0x04` and returns
   * the owner base pointer located 4 bytes before that node.
   */
  [[maybe_unused]] IntrusiveOwnerNodeSlotRuntimeView* UnlinkOwnerNodeAndReturnOwnerBase(
    IntrusiveOwnerNodeSlotRuntimeView* const owner
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = owner->node;
    (void)UnlinkIntrusiveNodeAndSelfLink(node);
    auto* const ownerBaseWord = reinterpret_cast<std::uint32_t*>(node) - 1;
    return reinterpret_cast<IntrusiveOwnerNodeSlotRuntimeView*>(ownerBaseWord);
  }

  /**
   * Address: 0x006EA320 (FUN_006EA320)
   *
   * What it does:
   * Unlinks one intrusive node referenced by owner lane `+0x04`, restores
   * singleton self-links, and returns owner base pointer (`node - 4`).
   */
  [[maybe_unused]] IntrusiveOwnerNodeSlotRuntimeView* UnlinkOwnerNodeAndReturnOwnerBaseLate(
    IntrusiveOwnerNodeSlotRuntimeView* const owner
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = owner->node;
    (void)UnlinkIntrusiveNodeAndSelfLink(node);
    auto* const ownerBaseWord = reinterpret_cast<std::uint32_t*>(node) - 1;
    return reinterpret_cast<IntrusiveOwnerNodeSlotRuntimeView*>(ownerBaseWord);
  }

  /**
   * Address: 0x006EAB50 (FUN_006EAB50)
   *
   * What it does:
   * When `node` is linked into a non-singleton ring, rewires adjacent links
   * through owner-head lanes and then restores `node` to singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* PatchOwnerHeadAndUnlinkNode(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView** const ownerHeadSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const nodeNext = node->next;
    if (nodeNext != node) {
      IntrusiveNodeRuntimeView* const ownerHead = *ownerHeadSlot;
      IntrusiveNodeRuntimeView* const ownerTail = ownerHead->prev;
      ownerTail->next = nodeNext;
      *ownerHeadSlot = node->prev;
      node->prev->next = *ownerHeadSlot;
      node->next->prev = ownerTail;
      node->next = node;
      node->prev = node;
    }

    return node;
  }

  /**
   * Address: 0x006EB450 (FUN_006EB450)
   *
   * What it does:
   * Returns owner base pointer from one intrusive node pointer (`node - 4`)
   * and propagates null for null input.
   */
  [[maybe_unused]] IntrusiveOwnerNodeSlotRuntimeView* ResolveOwnerBaseFromNodeMinus4(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<IntrusiveOwnerNodeSlotRuntimeView*>(reinterpret_cast<std::uintptr_t>(node) - 0x04u);
  }

  /**
   * Address: 0x005E9DA0 (FUN_005E9DA0)
   *
   * What it does:
   * Alias lane for two-word singleton self-link initialization.
   */
  [[maybe_unused]] std::uint32_t* InitializeSelfLinkPairAlias(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x005E9DB0 (FUN_005E9DB0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfZeta(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x005EA870 (FUN_005EA870)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordEpsilon(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005EA880 (FUN_005EA880)
   *
   * What it does:
   * Alias lane for storing source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane8WordDelta(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x005EAA70 (FUN_005EAA70)
   *
   * What it does:
   * Stores one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneA(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EAAB0 (FUN_005EAAB0)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneB(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EAAD0 (FUN_005EAAD0)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneC(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EAB20 (FUN_005EAB20)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneD(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EADB0 (FUN_005EADB0)
   *
   * What it does:
   * Alias lane for storing source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane4WordZeta(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x005EADC0 (FUN_005EADC0)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneE(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EB310 (FUN_005EB310)
   *
   * What it does:
   * Alias lane for computing `source lane +0x04 + index * 20`.
   */
  [[maybe_unused]] std::uintptr_t LocateStride20ElementAddressAlias(
    const std::int32_t index,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return ComputeOffsetAddressByStride(source->lane04, index, 20u);
  }

  /**
   * Address: 0x005EB730 (FUN_005EB730)
   *
   * What it does:
   * Stores one `base[0] + index * 20` address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreOffsetAddressStride20FromBaseWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreWordAtOutput(
      outValue,
      static_cast<std::uint32_t>(ComputeOffsetAddressByStride(*baseWord, index, 20u))
    );
  }

  /**
   * Address: 0x005EB760 (FUN_005EB760)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneF(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EB790 (FUN_005EB790)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneG(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EB7A0 (FUN_005EB7A0)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneH(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EB840 (FUN_005EB840)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneI(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x005EE660 (FUN_005EE660)
   *
   * What it does:
   * Swaps one dword slot value between two storage pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapWordSlotValues(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t temp = *right;
    *right = *left;
    *left = temp;
    return left;
  }

  struct PrefixMinus8WordReaderRuntimeView
  {
    const std::uint32_t* payload; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(PrefixMinus8WordReaderRuntimeView) == 0x04, "PrefixMinus8WordReaderRuntimeView size must be 0x04");
#endif

  struct Lane08WordWriterRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(Lane08WordWriterRuntimeView, lane08) == 0x08, "Lane08WordWriterRuntimeView::lane08 offset must be 0x08");
  static_assert(sizeof(Lane08WordWriterRuntimeView) == 0x0C, "Lane08WordWriterRuntimeView size must be 0x0C");
#endif

  struct IndexedWordAccessorRuntimeView
  {
    std::uint32_t words[13];
  };
#if defined(_M_IX86)
  static_assert(sizeof(IndexedWordAccessorRuntimeView) == 0x34, "IndexedWordAccessorRuntimeView size must be 0x34");
#endif

  struct WordAt44RuntimeView
  {
    std::byte pad0000_0043[0x44];
    std::uint32_t lane44; // +0x44
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt44RuntimeView, lane44) == 0x44, "WordAt44RuntimeView::lane44 offset must be 0x44");
#endif

  struct WordAt134RuntimeView
  {
    std::byte pad0000_0133[0x134];
    std::uint32_t lane134; // +0x134
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt134RuntimeView, lane134) == 0x134, "WordAt134RuntimeView::lane134 offset must be 0x134");
#endif

  struct WordAt99CRuntimeView
  {
    std::byte pad0000_099B[0x99C];
    std::uint32_t lane99C; // +0x99C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt99CRuntimeView, lane99C) == 0x99C, "WordAt99CRuntimeView::lane99C offset must be 0x99C");
#endif

  struct RuntimeCounter988And98CRuntimeView
  {
    std::byte pad0000_0987[0x988];
    std::uint32_t lane988; // +0x988
    std::uint32_t lane98C; // +0x98C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(RuntimeCounter988And98CRuntimeView, lane988) == 0x988,
    "RuntimeCounter988And98CRuntimeView::lane988 offset must be 0x988"
  );
  static_assert(
    offsetof(RuntimeCounter988And98CRuntimeView, lane98C) == 0x98C,
    "RuntimeCounter988And98CRuntimeView::lane98C offset must be 0x98C"
  );
#endif

  struct WordAt8C4RuntimeView
  {
    std::byte pad0000_08C3[0x8C4];
    std::uint32_t lane8C4; // +0x8C4
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt8C4RuntimeView, lane8C4) == 0x8C4, "WordAt8C4RuntimeView::lane8C4 offset must be 0x8C4");
#endif

  struct Lane4AddressPairRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(offsetof(Lane4AddressPairRuntimeView, lane04) == 0x04, "Lane4AddressPairRuntimeView::lane04 offset must be 0x04");
  static_assert(sizeof(Lane4AddressPairRuntimeView) == 0x08, "Lane4AddressPairRuntimeView size must be 0x08");
#endif

  using ScalarDeleteThunk = std::int32_t(__thiscall*)(void* self, std::int32_t deleteFlag);

  struct PrefixedVirtualObjectRuntimeView
  {
    void** vtable; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(PrefixedVirtualObjectRuntimeView) == 0x04, "PrefixedVirtualObjectRuntimeView size must be 0x04");
#endif

  struct DwordVectorBeginEndAt0x0CRuntimeView
  {
    std::uint32_t lane00; // +0x00
    const std::uint32_t* begin; // +0x04
    const std::uint32_t* lane08; // +0x08
    const std::uint32_t* end; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DwordVectorBeginEndAt0x0CRuntimeView, begin) == 0x04,
    "DwordVectorBeginEndAt0x0CRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(DwordVectorBeginEndAt0x0CRuntimeView, end) == 0x0C,
    "DwordVectorBeginEndAt0x0CRuntimeView::end offset must be 0x0C"
  );
  static_assert(
    sizeof(DwordVectorBeginEndAt0x0CRuntimeView) == 0x10,
    "DwordVectorBeginEndAt0x0CRuntimeView size must be 0x10"
  );
#endif

  /**
   * Address: 0x00660940 (FUN_00660940)
   *
   * What it does:
   * Reads one dword lane from 8 bytes before the payload pointer stored at `+0x00`.
   */
  [[maybe_unused]] std::uint32_t ReadPayloadPrefixMinus8Word(
    const PrefixMinus8WordReaderRuntimeView* const self
  ) noexcept
  {
    const auto* const payloadBytes = reinterpret_cast<const std::byte*>(self->payload);
    return *reinterpret_cast<const std::uint32_t*>(payloadBytes - 8);
  }

  /**
   * Address: 0x00660990 (FUN_00660990)
   *
   * What it does:
   * Stores one scalar dword into lane `+0x08` and returns that value.
   */
  [[maybe_unused]] std::uint32_t StoreLane08WordAndReturn(
    Lane08WordWriterRuntimeView* const self,
    const std::uint32_t value
  ) noexcept
  {
    self->lane08 = value;
    return value;
  }

  /**
   * Address: 0x00660A50 (FUN_00660A50)
   *
   * What it does:
   * Returns lane index `9` from one indexed dword runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWord9(const IndexedWordAccessorRuntimeView* const self) noexcept
  {
    return self->words[9];
  }

  /**
   * Address: 0x00660A60 (FUN_00660A60)
   *
   * What it does:
   * Returns lane index `12` from one indexed dword runtime view.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWord12(const IndexedWordAccessorRuntimeView* const self) noexcept
  {
    return self->words[12];
  }

  /**
   * Address: 0x006610F0 (FUN_006610F0)
   *
   * What it does:
   * Copies one dword from source offset `+0x44` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyWordAt44ToOutput(
    std::uint32_t* const outValue,
    const WordAt44RuntimeView* const source
  ) noexcept
  {
    *outValue = source->lane44;
    return outValue;
  }

  /**
   * Address: 0x006E0870 (FUN_006E0870)
   *
   * What it does:
   * Stores one source dword into destination offset `+0x44`.
   */
  [[maybe_unused]] const std::uint32_t* StoreWordIntoLane44(
    WordAt44RuntimeView* const destination,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    destination->lane44 = *sourceWord;
    return sourceWord;
  }

  /**
   * Address: 0x00662670 (FUN_00662670)
   *
   * What it does:
   * Reads one dword lane at offset `+0x134`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt134(const WordAt134RuntimeView* const source) noexcept
  {
    return source->lane134;
  }

  /**
   * Address: 0x0066A320 (FUN_0066A320)
   *
   * What it does:
   * Writes `{source_address, source->lane04}` into one two-word output lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposePairFromSourceAddressAndLane4(
    DwordPairRuntimeView* const outValue,
    const Lane4AddressPairRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = reinterpret_cast<std::uint32_t>(source);
    outValue->lane04 = source->lane04;
    return outValue;
  }

  /**
   * Address: 0x0066D310 (FUN_0066D310)
   *
   * What it does:
   * Reads one dword lane at offset `+0x99C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt99C(const WordAt99CRuntimeView* const source) noexcept
  {
    return source->lane99C;
  }

  /**
   * Address: 0x006E7CA0 (FUN_006E7CA0)
   *
   * What it does:
   * Reads one dword lane at offset `+0x988`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt988(const RuntimeCounter988And98CRuntimeView* const source) noexcept
  {
    return source->lane988;
  }

  /**
   * Address: 0x006E7CB0 (FUN_006E7CB0)
   *
   * What it does:
   * Returns lane `+0x98C` and post-increments it.
   */
  [[maybe_unused]] std::uint32_t PostIncrementWordAt98C(RuntimeCounter988And98CRuntimeView* const source) noexcept
  {
    const std::uint32_t previous = source->lane98C;
    source->lane98C = previous + 1u;
    return previous;
  }

  /**
   * Address: 0x00689F00 (FUN_00689F00)
   *
   * What it does:
   * Reads one dword lane at offset `+0x8C4`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt8C4(const WordAt8C4RuntimeView* const source) noexcept
  {
    return source->lane8C4;
  }

  /**
   * Address: 0x00674660 (FUN_00674660)
   *
   * What it does:
   * Dispatches the scalar deleting-destructor slot for one prefixed virtual
   * object pointer unless the slot is null or sentinel `4`.
   */
  [[maybe_unused]] std::uint32_t DispatchPrefixedVirtualDeleteLane(
    const std::uint32_t* const objectSlot,
    const std::int32_t deleteFlag
  ) noexcept
  {
    const std::uint32_t objectValue = *objectSlot;
    if (objectValue == 0u || objectValue == 4u) {
      return objectValue;
    }

    auto* const runtime = reinterpret_cast<PrefixedVirtualObjectRuntimeView*>(objectValue - 4u);
    const auto callback = reinterpret_cast<ScalarDeleteThunk>(runtime->vtable[0]);
    return static_cast<std::uint32_t>(callback(runtime, deleteFlag));
  }

  /**
   * Address: 0x0067B950 (FUN_0067B950)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfTheta(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x0067C420 (FUN_0067C420)
   * Address: 0x0074CB10 (FUN_0074CB10)
   * Address: 0x0074CEA0 (FUN_0074CEA0)
   *
   * What it does:
   * Returns one dword from storage and clears that storage to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearDword(std::uint32_t* const valueSlot) noexcept
  {
    const std::uint32_t value = *valueSlot;
    *valueSlot = 0u;
    return value;
  }

  /**
   * Address: 0x0067C7F0 (FUN_0067C7F0)
   *
   * What it does:
   * Returns 4-byte element count from one begin/end lane pair at
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountDwordVectorElementsBeginAt4EndAtC(
    const DwordVectorBeginEndAt0x0CRuntimeView* const vectorLane
  ) noexcept
  {
    if (vectorLane->begin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(vectorLane->end - vectorLane->begin);
  }

  /**
   * Address: 0x006D7890 (FUN_006D7890)
   * Address: 0x0069AEC0 (FUN_0069AEC0)
   * Address: 0x0069E7A0 (FUN_0069E7A0)
   *
   * What it does:
   * Clears one two-word output lane to `{0,0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLane6D7890(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x006DBA50 (FUN_006DBA50)
   *
   * What it does:
   * Swaps one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValues6DBA50(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *left;
    *left = *right;
    *right = value;
    return left;
  }

  /**
   * Address: 0x006DBA60 (FUN_006DBA60)
   *
   * What it does:
   * Returns 40-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountStride40ElementsBeginAt4EndAtC(
    const DwordVectorBeginEndAt0x0CRuntimeView* const vectorLane
  ) noexcept
  {
    if (vectorLane->begin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(
      (reinterpret_cast<std::uintptr_t>(vectorLane->end) - reinterpret_cast<std::uintptr_t>(vectorLane->begin)) / 40u
    );
  }

  /**
   * Address: 0x006DBC90 (FUN_006DBC90)
   * Address: 0x0074D870 (FUN_0074D870)
   *
   * What it does:
   * Returns 12-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountStride12ElementsBeginAt4EndAtC(
    const DwordVectorBeginEndAt0x0CRuntimeView* const vectorLane
  ) noexcept
  {
    if (vectorLane->begin == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(
      (reinterpret_cast<std::uintptr_t>(vectorLane->end) - reinterpret_cast<std::uintptr_t>(vectorLane->begin)) / 12u
    );
  }

  /**
   * Address: 0x006DBCF0 (FUN_006DBCF0)
   *
   * What it does:
   * Computes one `begin@+0x04 + index*12` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromBeginAt4(
    const std::int32_t index,
    const DwordVectorBeginEndAt0x0CRuntimeView* const source
  ) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->begin) + (static_cast<std::uint32_t>(index) * 12u));
  }

  /**
   * Address: 0x006DC5D0 (FUN_006DC5D0)
   *
   * What it does:
   * Computes one `begin@+0x04 + index*40` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride40AddressFromBeginAt4(
    const std::int32_t index,
    const DwordVectorBeginEndAt0x0CRuntimeView* const source
  ) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->begin) + (static_cast<std::uint32_t>(index) * 40u));
  }

  /**
   * Address: 0x006DCC10 (FUN_006DCC10)
   *
   * What it does:
   * Alias lane for `begin@+0x04 + index*12` address computation.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromBeginAt4Alias(
    const std::int32_t index,
    const DwordVectorBeginEndAt0x0CRuntimeView* const source
  ) noexcept
  {
    return ComputeStride12AddressFromBeginAt4(index, source);
  }

  /**
   * Address: 0x006DD110 (FUN_006DD110)
   *
   * What it does:
   * Stores one `*base + index*12` byte address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreStride12AddressFromBaseSlot(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseSlot,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseSlot + (static_cast<std::uint32_t>(index) * 12u);
    return outValue;
  }

  /**
   * Address: 0x006DD120 (FUN_006DD120)
   *
   * What it does:
   * Returns 12-byte index delta between two address lanes (`(*lhs-*rhs)/12`).
   */
  [[maybe_unused]] std::int32_t ComputeStride12IndexFromPointerDeltaPrimary(
    const std::uint32_t* const lhsAddressSlot,
    const std::uint32_t* const rhsAddressSlot
  ) noexcept
  {
    return static_cast<std::int32_t>((*lhsAddressSlot - *rhsAddressSlot) / 12u);
  }

  /**
   * Address: 0x006DD150 (FUN_006DD150)
   * Address: 0x0074FC90 (FUN_0074FC90)
   *
   * What it does:
   * Stores one `*base + index*40` byte address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreStride40AddressFromBaseSlot(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseSlot,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseSlot + (static_cast<std::uint32_t>(index) * 40u);
    return outValue;
  }

  /**
   * Address: 0x006DD160 (FUN_006DD160)
   * Address: 0x006DD230 (FUN_006DD230)
   *
   * What it does:
   * Returns 40-byte index delta between two address lanes (`(*lhs-*rhs)/40`).
   */
  [[maybe_unused]] std::int32_t ComputeStride40IndexFromPointerDelta(
    const std::uint32_t* const lhsAddressSlot,
    const std::uint32_t* const rhsAddressSlot
  ) noexcept
  {
    return static_cast<std::int32_t>((*lhsAddressSlot - *rhsAddressSlot) / 40u);
  }

  struct IntrusiveLinkWithPayloadRuntimeView
  {
    IntrusiveLinkRuntimeView link; // +0x00
    std::uint32_t lane08;          // +0x08
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveLinkWithPayloadRuntimeView, link) == 0x00,
    "IntrusiveLinkWithPayloadRuntimeView::link offset must be 0x00"
  );
  static_assert(
    offsetof(IntrusiveLinkWithPayloadRuntimeView, lane08) == 0x08,
    "IntrusiveLinkWithPayloadRuntimeView::lane08 offset must be 0x08"
  );
  static_assert(
    sizeof(IntrusiveLinkWithPayloadRuntimeView) == 0x0C,
    "IntrusiveLinkWithPayloadRuntimeView size must be 0x0C"
  );
#endif

  /**
   * Address: 0x006DD190 (FUN_006DD190)
   *
   * What it does:
   * Copies one intrusive link-and-payload lane and inserts the copied link
   * into the owner slot chain.
   */
  [[maybe_unused]] IntrusiveLinkWithPayloadRuntimeView* CopyIntrusiveLinkWithPayload(
    IntrusiveLinkWithPayloadRuntimeView* const outValue,
    const IntrusiveLinkWithPayloadRuntimeView* const source
  ) noexcept
  {
    IntrusiveLinkRuntimeView** const ownerSlot = source->link.ownerSlot;
    outValue->link.ownerSlot = ownerSlot;
    if (ownerSlot != nullptr) {
      outValue->link.next = *ownerSlot;
      *ownerSlot = &outValue->link;
    } else {
      outValue->link.next = nullptr;
    }
    outValue->lane08 = source->lane08;
    return outValue;
  }

  /**
   * Address: 0x008B39A0 (FUN_008B39A0)
   *
   * What it does:
   * Initializes `count` contiguous intrusive-link lanes from one owner-slot
   * source, stitching each new lane into that owner-slot chain.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView* CopyIntrusiveLinkRangeFromOwnerSlotLane(
    IntrusiveLinkRuntimeView* outValue,
    std::uint32_t count,
    IntrusiveLinkRuntimeView*** const ownerSlotLane
  ) noexcept
  {
    std::uintptr_t writeAddress = reinterpret_cast<std::uintptr_t>(outValue);
    while (count > 0u) {
      auto* const writeLink = reinterpret_cast<IntrusiveLinkRuntimeView*>(writeAddress);
      if (writeLink != nullptr) {
        IntrusiveLinkRuntimeView** const ownerSlot = *ownerSlotLane;
        writeLink->ownerSlot = ownerSlot;
        if (ownerSlot != nullptr) {
          writeLink->next = *ownerSlot;
          *ownerSlot = writeLink;
        } else {
          writeLink->next = nullptr;
        }
      }

      --count;
      writeAddress += sizeof(IntrusiveLinkRuntimeView);
    }

    return reinterpret_cast<IntrusiveLinkRuntimeView*>(writeAddress);
  }

  /**
   * Address: 0x008B2E20 (FUN_008B2E20)
   *
   * What it does:
   * Source-first register-shape adapter that forwards one intrusive-link range
   * fill lane into `CopyIntrusiveLinkRangeFromOwnerSlotLane` and returns the
   * advanced destination cursor.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView* CopyIntrusiveLinkRangeFromOwnerSlotLaneSourceFirstAdapterA(
    IntrusiveLinkRuntimeView* const outValue,
    IntrusiveLinkRuntimeView*** const ownerSlotLane,
    const std::int32_t count
  ) noexcept
  {
    (void)CopyIntrusiveLinkRangeFromOwnerSlotLane(outValue, static_cast<std::uint32_t>(count), ownerSlotLane);
    return outValue + count;
  }

  /**
   * Address: 0x006DD1E0 (FUN_006DD1E0)
   * Address: 0x006DD260 (FUN_006DD260)
   *
   * What it does:
   * Advances one stored address lane in-place by `index*12` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride12(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 12u;
    return addressLane;
  }

  /**
   * Address: 0x006DD1F0 (FUN_006DD1F0)
   *
   * What it does:
   * Alias lane for 12-byte index delta between two address slots.
   */
  [[maybe_unused]] std::int32_t ComputeStride12IndexFromPointerDeltaSecondary(
    const std::uint32_t* const lhsAddressSlot,
    const std::uint32_t* const rhsAddressSlot
  ) noexcept
  {
    return ComputeStride12IndexFromPointerDeltaPrimary(lhsAddressSlot, rhsAddressSlot);
  }

  /**
   * Address: 0x006DD210 (FUN_006DD210)
   * Address: 0x006DD270 (FUN_006DD270)
   *
   * What it does:
   * Advances one stored address lane in-place by `index*40` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride40(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 40u;
    return addressLane;
  }

  /**
   * Address: 0x006E01F0 (FUN_006E01F0)
   * Address: 0x006E0790 (FUN_006E0790)
   *
   * What it does:
   * Advances one stored address lane by a single 40-byte element stride.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByOneStride40(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 40u;
    return addressLane;
  }

  struct PackedHighByteWordRuntimeView
  {
    std::uint32_t packedWord; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(PackedHighByteWordRuntimeView) == 0x04, "PackedHighByteWordRuntimeView size must be 0x04");
#endif

  /**
   * Address: 0x006E0800 (FUN_006E0800)
   *
   * What it does:
   * Stores one packed word as `lowWord | (highByte << 24)`.
   */
  [[maybe_unused]] PackedHighByteWordRuntimeView* PackHighByteIntoWord(
    PackedHighByteWordRuntimeView* const outValue,
    const std::int32_t highByte,
    const std::uint32_t lowWord
  ) noexcept
  {
    outValue->packedWord = lowWord | (static_cast<std::uint32_t>(highByte) << 24u);
    return outValue;
  }

  /**
   * Address: 0x006E0820 (FUN_006E0820)
   *
   * What it does:
   * Returns the top-byte lane from one packed dword.
   */
  [[maybe_unused]] std::uint8_t ReadPackedWordTopByte(const PackedHighByteWordRuntimeView* const value) noexcept
  {
    return static_cast<std::uint8_t>(value->packedWord >> 24u);
  }

  /**
   * Address: 0x006E0830 (FUN_006E0830)
   *
   * What it does:
   * Returns true when packed top-byte lane is not `0xFF`.
   */
  [[maybe_unused]] bool IsPackedWordTopByteNotFF(const PackedHighByteWordRuntimeView* const value) noexcept
  {
    return (value->packedWord & 0xFF000000u) != 0xFF000000u;
  }

  struct DwordQuintWithFlagPairRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t lane10; // +0x10
    std::uint8_t flag14;  // +0x14
    std::uint8_t flag15;  // +0x15
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DwordQuintWithFlagPairRuntimeView, lane10) == 0x10,
    "DwordQuintWithFlagPairRuntimeView::lane10 offset must be 0x10"
  );
  static_assert(
    offsetof(DwordQuintWithFlagPairRuntimeView, flag14) == 0x14,
    "DwordQuintWithFlagPairRuntimeView::flag14 offset must be 0x14"
  );
  static_assert(
    offsetof(DwordQuintWithFlagPairRuntimeView, flag15) == 0x15,
    "DwordQuintWithFlagPairRuntimeView::flag15 offset must be 0x15"
  );
#endif

  struct SelfRelativeLaneBlockRuntimeView
  {
    std::uint32_t lanes[8];
  };
#if defined(_M_IX86)
  static_assert(sizeof(SelfRelativeLaneBlockRuntimeView) == 0x20, "SelfRelativeLaneBlockRuntimeView size must be 0x20");
#endif

  struct DwordTripleAndFlagRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint8_t lane0C;  // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DwordTripleAndFlagRuntimeView, lane08) == 0x08,
    "DwordTripleAndFlagRuntimeView::lane08 offset must be 0x08"
  );
  static_assert(
    offsetof(DwordTripleAndFlagRuntimeView, lane0C) == 0x0C,
    "DwordTripleAndFlagRuntimeView::lane0C offset must be 0x0C"
  );
#endif

  [[nodiscard]] std::int32_t CountDwordSlotsBetweenAddresses(
    const std::uint32_t leftAddress,
    const std::uint32_t rightAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((leftAddress - rightAddress) >> 2);
  }

  /**
   * Address: 0x006E19A0 (FUN_006E19A0)
   *
   * What it does:
   * Clears dword tail lanes `+0x04`, `+0x08`, and `+0x0C`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearDwordQuadTailLanes(DwordQuadRuntimeView* const lane) noexcept
  {
    lane->lane04 = 0u;
    lane->lane08 = 0u;
    lane->lane0C = 0u;
    return lane;
  }

  /**
   * Address: 0x006E19E0 (FUN_006E19E0)
   *
   * What it does:
   * Returns true when one span lane is empty, treating null `begin` as empty.
   */
  [[maybe_unused]] bool IsDwordSpanBeginEndAt4And8Empty(const DwordSpanRuntimeView* const span) noexcept
  {
    return span->begin == 0u || CountDwordSlotsBetweenAddresses(span->end, span->begin) == 0;
  }

  /**
   * Address: 0x006E1AE0 (FUN_006E1AE0)
   *
   * What it does:
   * Writes one dword pair from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromWordPointers(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const firstSource,
    const std::uint32_t* const secondSource
  ) noexcept
  {
    outValue->lane00 = *firstSource;
    outValue->lane04 = *secondSource;
    return outValue;
  }

  /**
   * Address: 0x006E20B0 (FUN_006E20B0)
   *
   * What it does:
   * Returns the dword count between span lanes `+0x04` and `+0x0C`.
   */
  [[maybe_unused]] std::int32_t CountDwordSpanCursorFromBegin(const DwordSpanRuntimeView* const span) noexcept
  {
    if (span->begin == 0u) {
      return 0;
    }
    return CountDwordSlotsBetweenAddresses(span->cursor, span->begin);
  }

  /**
   * Address: 0x006E20E0 (FUN_006E20E0)
   *
   * What it does:
   * Returns the dword count between span lanes `+0x04` and `+0x08`.
   */
  [[maybe_unused]] std::int32_t CountDwordSpanEndFromBegin(const DwordSpanRuntimeView* const span) noexcept
  {
    if (span->begin == 0u) {
      return 0;
    }
    return CountDwordSlotsBetweenAddresses(span->end, span->begin);
  }

  /**
   * Address: 0x006E2280 (FUN_006E2280)
   *
   * What it does:
   * Writes one `{dword, byte}` lane from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointers(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->lane00 = *sourceWord;
    outValue->lane04 = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x006E27F0 (FUN_006E27F0)
   *
   * What it does:
   * Stores `base + index * 4` into one output address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordStrideAddress(
    std::uint32_t* const outAddress,
    const std::uint32_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outAddress = *baseAddress + (static_cast<std::uint32_t>(index) * 4u);
    return outAddress;
  }

  /**
   * Address: 0x006E2800 (FUN_006E2800)
   *
   * What it does:
   * Returns the dword-slot distance between two address lanes.
   */
  [[maybe_unused]] std::int32_t CountDwordAddressDistanceA(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return CountDwordSlotsBetweenAddresses(*leftAddress, *rightAddress);
  }

  /**
   * Address: 0x006E2930 (FUN_006E2930)
   *
   * What it does:
   * Advances one address lane by `count * 4`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByDwordCountA(
    std::uint32_t* const addressLane,
    const std::int32_t count
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(count) * 4u;
    return addressLane;
  }

  /**
   * Address: 0x006E2950 (FUN_006E2950)
   *
   * What it does:
   * Alias lane for dword-slot distance between two address lanes.
   */
  [[maybe_unused]] std::int32_t CountDwordAddressDistanceB(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return CountDwordSlotsBetweenAddresses(*leftAddress, *rightAddress);
  }

  /**
   * Address: 0x006E2960 (FUN_006E2960)
   *
   * What it does:
   * Initializes one five-dword lane payload and clears two trailing flags.
   */
  [[maybe_unused]] DwordQuintWithFlagPairRuntimeView* InitializeDwordQuintWithFlags(
    DwordQuintWithFlagPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const DwordPairRuntimeView* const sourcePair,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = sourcePair->lane00;
    outValue->lane10 = sourcePair->lane04;
    outValue->flag14 = 0u;
    outValue->flag15 = 0u;
    return outValue;
  }

  /**
   * Address: 0x006E29E0 (FUN_006E29E0)
   *
   * What it does:
   * Copies one source dword into output when output storage is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentA(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x006E29F0 (FUN_006E29F0)
   *
   * What it does:
   * Alias lane for advancing one address lane by `count * 4`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByDwordCountB(
    std::uint32_t* const addressLane,
    const std::int32_t count
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(count) * 4u;
    return addressLane;
  }

  /**
   * Address: 0x006E2A10 (FUN_006E2A10)
   * Address: 0x006DDAE0 (FUN_006DDAE0)
   * Address: 0x006DDB50 (FUN_006DDB50)
   * Address: 0x006DDEA0 (FUN_006DDEA0)
   * Address: 0x006DDED0 (FUN_006DDED0)
   *
   * What it does:
   * Swaps dword tail lanes `(+0x04,+0x08,+0x0C)` between two quad lanes.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesA(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x006E2E00 (FUN_006E2E00)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentB(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x006E2E30 (FUN_006E2E30)
   *
   * What it does:
   * Alias lane for swapping dword tail lanes `(+0x04,+0x08,+0x0C)`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesB(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x006E30C0 (FUN_006E30C0)
   *
   * What it does:
   * Rewinds lane `+0x08` to lane `+0x04` when they differ.
   */
  [[maybe_unused]] void AlignLane08ToLane04IfDifferent(DwordTripleRuntimeView* const lane) noexcept
  {
    if (lane->lane04 != lane->lane08) {
      lane->lane08 = lane->lane04;
    }
  }

  /**
   * Address: 0x006E3540 (FUN_006E3540)
   * Address: 0x006DEF00 (FUN_006DEF00)
   * Address: 0x006DEF20 (FUN_006DEF20)
   * Address: 0x0077E8A0 (FUN_0077E8A0)
   * Address: 0x0074DCE0 (FUN_0074DCE0)
   * Address: 0x0074DCF0 (FUN_0074DCF0)
   * Address: 0x0074DD00 (FUN_0074DD00)
   * Address: 0x0074DD10 (FUN_0074DD10)
   * Address: 0x0074DD20 (FUN_0074DD20)
   * Address: 0x0074DD30 (FUN_0074DD30)
   * Address: 0x0074DD80 (FUN_0074DD80)
   * Address: 0x0074DD90 (FUN_0074DD90)
   * Address: 0x0074DDA0 (FUN_0074DDA0)
   * Address: 0x0074DDB0 (FUN_0074DDB0)
   * Address: 0x0074DDC0 (FUN_0074DDC0)
   * Address: 0x0074DEF0 (FUN_0074DEF0)
   *
   * What it does:
   * Swaps one dword between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *right;
    *right = *left;
    *left = value;
    return left;
  }

  /**
   * Address: 0x006E35D0 (FUN_006E35D0)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentC(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x006E3D80 (FUN_006E3D80)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentD(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
    *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x006E7A90 (FUN_006E7A90)
   *
   * What it does:
   * Copies one source dword lane into destination storage.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordToOutput(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    *outValue = *sourceWord;
    return outValue;
  }

  struct StreamWriteWindowRuntimeView
  {
    void** vtable;             // +0x00
    std::uint32_t lane04;      // +0x04
    std::uint32_t lane08;      // +0x08
    std::uint32_t lane0C;      // +0x0C
    std::uint32_t lane10;      // +0x10
    std::uint32_t* writeHead;  // +0x14
    std::uint32_t* writeEnd;   // +0x18
  };
#if defined(_M_IX86)
  static_assert(offsetof(StreamWriteWindowRuntimeView, writeHead) == 0x14, "StreamWriteWindowRuntimeView::writeHead");
  static_assert(offsetof(StreamWriteWindowRuntimeView, writeEnd) == 0x18, "StreamWriteWindowRuntimeView::writeEnd");
  static_assert(sizeof(StreamWriteWindowRuntimeView) == 0x1C, "StreamWriteWindowRuntimeView size must be 0x1C");
#endif

  using StreamWriteBlockThunk =
    std::uint32_t*(__thiscall*)(StreamWriteWindowRuntimeView* self, const std::uint32_t* source, std::uint32_t sizeBytes);

  [[nodiscard]] std::uint32_t* WriteFixedWordBlockFastOrVirtual(
    StreamWriteWindowRuntimeView* const stream,
    const std::uint32_t* const sourceWords,
    const std::uint32_t wordCount
  ) noexcept
  {
    std::uint32_t* const writeHead = stream->writeHead;
    if (static_cast<std::uint32_t>(stream->writeEnd - writeHead) < wordCount) {
      const auto callback = reinterpret_cast<StreamWriteBlockThunk>(stream->vtable[7]);
      return callback(stream, sourceWords, wordCount * sizeof(std::uint32_t));
    }

    for (std::uint32_t index = 0; index < wordCount; ++index) {
      writeHead[index] = sourceWords[index];
    }
    stream->writeHead = writeHead + wordCount;
    return writeHead;
  }

  /**
   * Address: 0x006E7AA0 (FUN_006E7AA0)
   * Address: 0x006E7B80 (FUN_006E7B80)
   *
   * What it does:
   * Writes one 16-byte word block through stream write-window fast path with
   * virtual fallback.
   */
  [[maybe_unused]] std::uint32_t* WriteStreamWordBlock16(
    StreamWriteWindowRuntimeView* const* const streamSlot,
    const std::uint32_t* const sourceWords
  ) noexcept
  {
    return WriteFixedWordBlockFastOrVirtual(*streamSlot, sourceWords, 4u);
  }

  /**
   * Address: 0x006E7AE0 (FUN_006E7AE0)
   *
   * What it does:
   * Writes one 8-byte word block through stream write-window fast path with
   * virtual fallback.
   */
  [[maybe_unused]] std::uint32_t* WriteStreamWordBlock8(
    StreamWriteWindowRuntimeView* const* const streamSlot,
    const std::uint32_t* const sourceWords
  ) noexcept
  {
    return WriteFixedWordBlockFastOrVirtual(*streamSlot, sourceWords, 2u);
  }

  /**
   * Address: 0x006E7B10 (FUN_006E7B10)
   *
   * What it does:
   * Writes one 12-byte word block through stream write-window fast path with
   * virtual fallback.
   */
  [[maybe_unused]] std::uint32_t* WriteStreamWordBlock12(
    StreamWriteWindowRuntimeView* const* const streamSlot,
    const std::uint32_t* const sourceWords
  ) noexcept
  {
    return WriteFixedWordBlockFastOrVirtual(*streamSlot, sourceWords, 3u);
  }

  /**
   * Address: 0x006E3F20 (FUN_006E3F20)
   *
   * What it does:
   * Advances one address lane by one dword slot.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByOneDword(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 4u;
    return addressLane;
  }

  /**
   * Address: 0x006E3FF0 (FUN_006E3FF0)
   *
   * What it does:
   * Copy-assigns one four-dword lane.
   */
  [[maybe_unused]] DwordQuadRuntimeView* CopyDwordQuadLane(
    DwordQuadRuntimeView* const destination,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    destination->lane00 = source->lane00;
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;
    return destination;
  }

  /**
   * Address: 0x006E5620 (FUN_006E5620)
   *
   * What it does:
   * Initializes one self-relative lane block with anchors at `self + 0x20`
   * and `self + 0x28`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockRuntimeView* InitializeSelfRelativeLaneBlockA(
    SelfRelativeLaneBlockRuntimeView* const self
  ) noexcept
  {
    const auto* const words = self->lanes;
    const std::uint32_t anchorAt20 = reinterpret_cast<std::uint32_t>(words + 8);
    const std::uint32_t anchorAt28 = reinterpret_cast<std::uint32_t>(words + 10);

    self->lanes[2] = 0u;
    self->lanes[4] = anchorAt20;
    self->lanes[5] = anchorAt20;
    self->lanes[6] = anchorAt28;
    self->lanes[7] = anchorAt20;
    return self;
  }

  /**
   * Address: 0x006E56A0 (FUN_006E56A0)
   *
   * What it does:
   * Initializes one four-lane self-relative header with anchors at
   * `self + 0x10` and `self + 0x20`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockRuntimeView* InitializeSelfRelativeLaneBlockB(
    SelfRelativeLaneBlockRuntimeView* const self
  ) noexcept
  {
    const auto* const words = self->lanes;
    const std::uint32_t anchorAt10 = reinterpret_cast<std::uint32_t>(words + 4);
    const std::uint32_t anchorAt20 = reinterpret_cast<std::uint32_t>(words + 8);

    self->lanes[0] = anchorAt10;
    self->lanes[1] = anchorAt10;
    self->lanes[2] = anchorAt20;
    self->lanes[3] = anchorAt10;
    return self;
  }

  /**
   * Address: 0x006E5780 (FUN_006E5780)
   *
   * What it does:
   * Stores two scalar dwords into lanes `+0x04` and `+0x08`.
   */
  [[maybe_unused]] DwordTripleRuntimeView* StoreLane04AndLane08A(
    DwordTripleRuntimeView* const lane,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    lane->lane04 = lane04;
    lane->lane08 = lane08;
    return lane;
  }

  /**
   * Address: 0x006E57A0 (FUN_006E57A0)
   *
   * What it does:
   * Alias lane for storing scalar dwords into `+0x04` and `+0x08`.
   */
  [[maybe_unused]] DwordTripleRuntimeView* StoreLane04AndLane08B(
    DwordTripleRuntimeView* const lane,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    lane->lane04 = lane04;
    lane->lane08 = lane08;
    return lane;
  }

  /**
   * Address: 0x006E5990 (FUN_006E5990)
   *
   * What it does:
   * Initializes one three-dword-and-flag lane payload.
   */
  [[maybe_unused]] DwordTripleAndFlagRuntimeView* InitializeDwordTripleAndFlag(
    DwordTripleAndFlagRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint8_t lane0C
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = lane0C;
    return outValue;
  }

  /**
   * Address: 0x006E59B0 (FUN_006E59B0)
   *
   * What it does:
   * Initializes one three-dword-and-flag lane from source pair-plus-byte.
   */
  [[maybe_unused]] DwordTripleAndFlagRuntimeView* InitializeDwordTripleAndFlagFromSources(
    DwordTripleAndFlagRuntimeView* const outValue,
    const DwordTripleRuntimeView* const source,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->lane00 = source->lane00;
    outValue->lane04 = source->lane04;
    outValue->lane08 = source->lane08;
    outValue->lane0C = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x006E79C0 (FUN_006E79C0)
   *
   * What it does:
   * Returns true when the first two dword lanes are equal.
   */
  [[maybe_unused]] bool AreFirstTwoDwordLanesEqual(const DwordPairRuntimeView* const lane) noexcept
  {
    return lane->lane00 == lane->lane04;
  }

  /**
   * Address: 0x006E7A70 (FUN_006E7A70)
   *
   * What it does:
   * Returns true when lane `+0x08` differs between two triple-lane values.
   */
  [[maybe_unused]] bool IsLane08Different(
    const DwordTripleRuntimeView* const left,
    const DwordTripleRuntimeView* const right
  ) noexcept
  {
    return left->lane08 != right->lane08;
  }

  struct GridCellMapperRuntimeView
  {
    std::byte pad00_07[0x08];
    std::uint32_t cellsPerRow; // +0x08
    std::byte pad0C_0F[0x04];
    std::uint32_t cellSize; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(GridCellMapperRuntimeView, cellsPerRow) == 0x08, "GridCellMapperRuntimeView::cellsPerRow offset must be 0x08");
  static_assert(offsetof(GridCellMapperRuntimeView, cellSize) == 0x10, "GridCellMapperRuntimeView::cellSize offset must be 0x10");
#endif

  struct GridCellPositionRuntimeView
  {
    float x; // +0x00
    std::uint32_t y; // +0x04
    float z; // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(GridCellPositionRuntimeView) == 0x0C, "GridCellPositionRuntimeView size must be 0x0C");
  static_assert(offsetof(GridCellPositionRuntimeView, y) == 0x04, "GridCellPositionRuntimeView::y offset must be 0x04");
#endif

  struct PointerHeadAt4RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t* head; // +0x04
  };
#if defined(_M_IX86)
  static_assert(offsetof(PointerHeadAt4RuntimeView, head) == 0x04, "PointerHeadAt4RuntimeView::head offset must be 0x04");
#endif

  struct AddressSpanBeginCursorAt4AndCRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t begin; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t cursor; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(AddressSpanBeginCursorAt4AndCRuntimeView, begin) == 0x04,
    "AddressSpanBeginCursorAt4AndCRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(AddressSpanBeginCursorAt4AndCRuntimeView, cursor) == 0x0C,
    "AddressSpanBeginCursorAt4AndCRuntimeView::cursor offset must be 0x0C"
  );
#endif

  struct DwordPairFloatPayload44RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    float lane08; // +0x08
    float lane0C; // +0x0C
    float lane10; // +0x10
    std::uint32_t lane14; // +0x14
    std::uint32_t lane18; // +0x18
    std::uint8_t lane1C; // +0x1C
    std::byte pad1D_1F[0x03];
    float lane20; // +0x20
    float lane24; // +0x24
    std::uint32_t lane28; // +0x28
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordPairFloatPayload44RuntimeView) == 0x2C, "DwordPairFloatPayload44RuntimeView size must be 0x2C");
  static_assert(offsetof(DwordPairFloatPayload44RuntimeView, lane1C) == 0x1C, "DwordPairFloatPayload44RuntimeView::lane1C offset must be 0x1C");
  static_assert(offsetof(DwordPairFloatPayload44RuntimeView, lane20) == 0x20, "DwordPairFloatPayload44RuntimeView::lane20 offset must be 0x20");
  static_assert(offsetof(DwordPairFloatPayload44RuntimeView, lane28) == 0x28, "DwordPairFloatPayload44RuntimeView::lane28 offset must be 0x28");
#endif

  struct PrefixedDwordPayload48RuntimeView
  {
    std::uint32_t lane00; // +0x00
    DwordPairFloatPayload44RuntimeView payload; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(PrefixedDwordPayload48RuntimeView) == 0x30, "PrefixedDwordPayload48RuntimeView size must be 0x30");
  static_assert(offsetof(PrefixedDwordPayload48RuntimeView, payload) == 0x04, "PrefixedDwordPayload48RuntimeView::payload offset must be 0x04");
#endif

  struct TreeNodeFlagAt3DRuntimeView
  {
    TreeNodeFlagAt3DRuntimeView* left; // +0x00
    TreeNodeFlagAt3DRuntimeView* parentOrRoot; // +0x04
    TreeNodeFlagAt3DRuntimeView* right; // +0x08
    std::uint32_t key; // +0x0C
    std::byte pad10_3C[0x2D];
    std::uint8_t isSentinel; // +0x3D
  };
#if defined(_M_IX86)
  static_assert(offsetof(TreeNodeFlagAt3DRuntimeView, key) == 0x0C, "TreeNodeFlagAt3DRuntimeView::key offset must be 0x0C");
  static_assert(offsetof(TreeNodeFlagAt3DRuntimeView, isSentinel) == 0x3D, "TreeNodeFlagAt3DRuntimeView::isSentinel offset must be 0x3D");
#endif

  struct TreeNodeFlagAt15RuntimeView
  {
    TreeNodeFlagAt15RuntimeView* left; // +0x00
    TreeNodeFlagAt15RuntimeView* parentOrRoot; // +0x04
    TreeNodeFlagAt15RuntimeView* right; // +0x08
    std::uint32_t key; // +0x0C
    std::byte pad10_14[0x05];
    std::uint8_t isSentinel; // +0x15
  };
#if defined(_M_IX86)
  static_assert(offsetof(TreeNodeFlagAt15RuntimeView, key) == 0x0C, "TreeNodeFlagAt15RuntimeView::key offset must be 0x0C");
  static_assert(offsetof(TreeNodeFlagAt15RuntimeView, isSentinel) == 0x15, "TreeNodeFlagAt15RuntimeView::isSentinel offset must be 0x15");
#endif

  template <typename NodeT>
  struct TreeHeaderAt4RuntimeView
  {
    std::uint32_t lane00; // +0x00
    NodeT* header; // +0x04
  };

  template <typename NodeT>
  [[nodiscard]] NodeT* FindLowerBoundTreeNode(
    NodeT* const header,
    const std::uint32_t key
  ) noexcept
  {
    NodeT* candidate = header;
    NodeT* cursor = candidate->parentOrRoot;
    while (cursor->isSentinel == 0u) {
      if (cursor->key >= key) {
        candidate = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }
    return candidate;
  }

  [[nodiscard]] std::int32_t CountStrideElementsFromBeginToCursor(
    const AddressSpanBeginCursorAt4AndCRuntimeView* const span,
    const std::uint32_t strideBytes
  ) noexcept
  {
    if (span->begin == 0u) {
      return 0;
    }
    return static_cast<std::int32_t>((span->cursor - span->begin) / strideBytes);
  }

  /**
   * Address: 0x00713390 (FUN_00713390)
   *
   * What it does:
   * Swaps one dword slot value between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots71A(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *left;
    *left = *right;
    *right = value;
    return left;
  }

  /**
   * Address: 0x007146F0 (FUN_007146F0)
   * Address: 0x0074D6A0 (FUN_0074D6A0)
   * Address: 0x0074DD60 (FUN_0074DD60)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanes71A(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane00 = right->lane00;
    right->lane00 = left->lane00;
    left->lane00 = lane00;

    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;
    return left;
  }

  /**
   * Address: 0x00714A70 (FUN_00714A70)
   *
   * What it does:
   * Alias lane for swapping one dword slot value.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots71B(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *left;
    *left = *right;
    *right = value;
    return left;
  }

  /**
   * Address: 0x00715CC0 (FUN_00715CC0)
   *
   * What it does:
   * Maps one flat grid-cell index to centered X/Z world-space coordinates.
   */
  [[maybe_unused]] GridCellPositionRuntimeView* BuildGridCellCenterPosition(
    const GridCellMapperRuntimeView* const mapper,
    GridCellPositionRuntimeView* const outPosition,
    const std::int32_t cellIndex
  ) noexcept
  {
    const std::uint32_t cellSize = mapper->cellSize;
    const std::uint32_t cellsPerRow = mapper->cellsPerRow;
    outPosition->x = static_cast<float>(cellSize / 2u + (static_cast<std::uint32_t>(cellIndex) % cellsPerRow) * cellSize);
    outPosition->y = 0u;
    outPosition->z = static_cast<float>(cellSize / 2u + (static_cast<std::uint32_t>(cellIndex) / cellsPerRow) * cellSize);
    return outPosition;
  }

  /**
   * Address: 0x00715E50 (FUN_00715E50)
   *
   * What it does:
   * Stores one fixed sentinel dword value `0xF0000000`.
   */
  [[maybe_unused]] std::uint32_t* StoreSentinelWordF0000000(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0xF0000000u;
    return outValue;
  }

  /**
   * Address: 0x00717ED0 (FUN_00717ED0)
   *
   * What it does:
   * Reads one nested head dword through source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyNestedHeadWord71A(
    std::uint32_t* const outValue,
    const PointerHeadAt4RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->head;
    return outValue;
  }

  /**
   * Address: 0x00718980 (FUN_00718980)
   *
   * What it does:
   * Advances one stored address lane by 56 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride56A(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 56u;
    return addressLane;
  }

  /**
   * Address: 0x00718A00 (FUN_00718A00)
   *
   * What it does:
   * Advances one stored address lane by 140 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride140A(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 140u;
    return addressLane;
  }

  /**
   * Address: 0x00718A30 (FUN_00718A30)
   *
   * What it does:
   * Alias lane for advancing one address lane by 56 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride56B(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 56u;
    return addressLane;
  }

  /**
   * Address: 0x00719650 (FUN_00719650)
   *
   * What it does:
   * Computes lower-bound node for one key in a tree with sentinel flag at `+0x3D`.
   */
  [[maybe_unused]] TreeNodeFlagAt3DRuntimeView** LowerBoundTreeNodeFlag3DToOutput(
    TreeNodeFlagAt3DRuntimeView** const outNode,
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt3DRuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    *outNode = FindLowerBoundTreeNode(tree->header, *key);
    return outNode;
  }

  /**
   * Address: 0x007197F0 (FUN_007197F0)
   *
   * What it does:
   * Returns element count for one begin/cursor span using 56-byte stride.
   */
  [[maybe_unused]] std::int32_t CountStride56ElementsBeginToCursor(
    const AddressSpanBeginCursorAt4AndCRuntimeView* const span
  ) noexcept
  {
    return CountStrideElementsFromBeginToCursor(span, 56u);
  }

  /**
   * Address: 0x006EA150 (FUN_006EA150)
   *
   * What it does:
   * Returns 60-byte element count between begin (`+0x04`) and cursor (`+0x0C`).
   */
  [[maybe_unused]] std::int32_t CountStride60ElementsBeginToCursor(
    const AddressSpanBeginCursorAt4AndCRuntimeView* const span
  ) noexcept
  {
    return CountStrideElementsFromBeginToCursor(span, 60u);
  }

  /**
   * Address: 0x00719BD0 (FUN_00719BD0)
   *
   * What it does:
   * Computes lower-bound node for one key in a tree with sentinel flag at `+0x15`.
   */
  [[maybe_unused]] TreeNodeFlagAt15RuntimeView** LowerBoundTreeNodeFlag15ToOutput(
    TreeNodeFlagAt15RuntimeView** const outNode,
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt15RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    *outNode = FindLowerBoundTreeNode(tree->header, *key);
    return outNode;
  }

  /**
   * Address: 0x00719DB0 (FUN_00719DB0)
   *
   * What it does:
   * Returns element count for one begin/cursor span using 140-byte stride.
   */
  [[maybe_unused]] std::int32_t CountStride140ElementsBeginToCursor(
    const AddressSpanBeginCursorAt4AndCRuntimeView* const span
  ) noexcept
  {
    return CountStrideElementsFromBeginToCursor(span, 140u);
  }

  /**
   * Address: 0x0071A090 (FUN_0071A090)
   *
   * What it does:
   * Writes one dword pair from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposeDwordPairFromTwoWordSources71A(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const firstSource,
    const std::uint32_t* const secondSource
  ) noexcept
  {
    outValue->lane00 = *firstSource;
    outValue->lane04 = *secondSource;
    return outValue;
  }

  /**
   * Address: 0x0071A0F0 (FUN_0071A0F0)
   *
   * What it does:
   * Writes one prefixed dword plus one 44-byte mixed payload lane.
   */
  [[maybe_unused]] PrefixedDwordPayload48RuntimeView* ComposePrefixedPayload48(
    PrefixedDwordPayload48RuntimeView* const outValue,
    const std::uint32_t* const prefixSource,
    const DwordPairFloatPayload44RuntimeView* const payloadSource
  ) noexcept
  {
    outValue->lane00 = *prefixSource;
    outValue->payload = *payloadSource;
    return outValue;
  }

  /**
   * Address: 0x0071A160 (FUN_0071A160)
   *
   * What it does:
   * Alias lane for advancing one stored address lane by 140 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride140B(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 140u;
    return addressLane;
  }

  /**
   * Address: 0x0071A190 (FUN_0071A190)
   *
   * What it does:
   * Returns 16-byte element count between begin (`+0x04`) and cursor (`+0x0C`).
   */
  [[maybe_unused]] std::int32_t CountStride16ElementsBeginToCursor(
    const AddressSpanBeginCursorAt4AndCRuntimeView* const span
  ) noexcept
  {
    return CountStrideElementsFromBeginToCursor(span, 16u);
  }

  /**
   * Address: 0x0071A920 (FUN_0071A920)
   *
   * What it does:
   * Copy-assigns one 44-byte mixed dword/float payload lane.
   */
  [[maybe_unused]] DwordPairFloatPayload44RuntimeView* CopyPayload44MixedLanes(
    DwordPairFloatPayload44RuntimeView* const outValue,
    const DwordPairFloatPayload44RuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x0071A980 (FUN_0071A980)
   *
   * What it does:
   * Alias lane for reading one nested head dword through source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyNestedHeadWord71B(
    std::uint32_t* const outValue,
    const PointerHeadAt4RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->head;
    return outValue;
  }

  /**
   * Address: 0x0071AD30 (FUN_0071AD30)
   *
   * What it does:
   * Returns lower-bound node pointer for one key in a tree with sentinel flag at `+0x3D`.
   */
  [[maybe_unused]] TreeNodeFlagAt3DRuntimeView* LowerBoundTreeNodeFlag3D(
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt3DRuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    return FindLowerBoundTreeNode(tree->header, *key);
  }

  /**
   * Address: 0x0071B330 (FUN_0071B330)
   *
   * What it does:
   * Alias lane for reading one nested head dword through source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyNestedHeadWord71C(
    std::uint32_t* const outValue,
    const PointerHeadAt4RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->head;
    return outValue;
  }

  /**
   * Address: 0x0071B340 (FUN_0071B340)
   *
   * What it does:
   * Alias lane for reading one nested head dword through source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyNestedHeadWord71D(
    std::uint32_t* const outValue,
    const PointerHeadAt4RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->head;
    return outValue;
  }

  /**
   * Address: 0x0071B6C0 (FUN_0071B6C0)
   *
   * What it does:
   * Returns lower-bound node pointer for one key in a tree with sentinel flag at `+0x15`.
   */
  [[maybe_unused]] TreeNodeFlagAt15RuntimeView* LowerBoundTreeNodeFlag15(
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt15RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    return FindLowerBoundTreeNode(tree->header, *key);
  }

  /**
   * Address: 0x0071BD60 (FUN_0071BD60)
   *
   * What it does:
   * Clears one output dword lane to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearDwordLane71A(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x0071BDC0 (FUN_0071BDC0)
   *
   * What it does:
   * Alias lane for clearing one output dword to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearDwordLane71B(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x0071BE60 (FUN_0071BE60)
   *
   * What it does:
   * Stores one `base + index * 140` byte address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreStride140Address(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseAddress + (static_cast<std::uint32_t>(index) * 140u);
    return outValue;
  }

  /**
   * Address: 0x0071BE70 (FUN_0071BE70)
   *
   * What it does:
   * Returns 140-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride140IndexFromPointerDelta(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*lhsAddress - *rhsAddress) / 140u);
  }

  /**
   * Address: 0x0071BEA0 (FUN_0071BEA0)
   *
   * What it does:
   * Stores one `base + index * 56` byte address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreStride56Address(
    std::uint32_t* const outValue,
    const std::int32_t index,
    const std::uint32_t* const baseAddress
  ) noexcept
  {
    *outValue = *baseAddress + (static_cast<std::uint32_t>(index) * 56u);
    return outValue;
  }

  /**
   * Address: 0x0071BEC0 (FUN_0071BEC0)
   *
   * What it does:
   * Returns 56-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride56IndexFromPointerDelta(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*lhsAddress - *rhsAddress) / 56u);
  }

  /**
   * Address: 0x0071C130 (FUN_0071C130)
   *
   * What it does:
   * Stores one `base + index * 16` byte address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreStride16Address(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseAddress + (static_cast<std::uint32_t>(index) * 16u);
    return outValue;
  }

  struct LaneE0E4AndFlag141RuntimeView
  {
    std::byte pad00_DF[0xE0];
    std::uint32_t laneE0;      // +0x0E0
    std::uint32_t laneE4;      // +0x0E4
    std::byte padE8_140[0x59];
    std::uint8_t flag141;      // +0x141
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(LaneE0E4AndFlag141RuntimeView, laneE0) == 0x0E0,
    "LaneE0E4AndFlag141RuntimeView::laneE0 offset must be 0x0E0"
  );
  static_assert(
    offsetof(LaneE0E4AndFlag141RuntimeView, laneE4) == 0x0E4,
    "LaneE0E4AndFlag141RuntimeView::laneE4 offset must be 0x0E4"
  );
  static_assert(
    offsetof(LaneE0E4AndFlag141RuntimeView, flag141) == 0x141,
    "LaneE0E4AndFlag141RuntimeView::flag141 offset must be 0x141"
  );
#endif

  struct WordAt1CRuntimeView
  {
    std::byte pad00_1B[0x1C];
    std::uint32_t lane1C; // +0x01C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt1CRuntimeView, lane1C) == 0x1C, "WordAt1CRuntimeView::lane1C offset must be 0x1C");
#endif

  struct PointerSpanStride8At10RuntimeView
  {
    std::byte pad00_0F[0x10];
    std::uint32_t begin; // +0x10
    std::uint32_t end;   // +0x14
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerSpanStride8At10RuntimeView, begin) == 0x10,
    "PointerSpanStride8At10RuntimeView::begin offset must be 0x10"
  );
  static_assert(
    offsetof(PointerSpanStride8At10RuntimeView, end) == 0x14,
    "PointerSpanStride8At10RuntimeView::end offset must be 0x14"
  );
#endif

  struct WordAtE4RuntimeView
  {
    std::byte pad00_E3[0xE4];
    std::uint32_t laneE4; // +0x0E4
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAtE4RuntimeView, laneE4) == 0x0E4, "WordAtE4RuntimeView::laneE4 offset must be 0x0E4");
#endif

  struct WordAt900RuntimeView
  {
    std::byte pad00_8FF[0x900];
    std::uint32_t lane900; // +0x0900
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt900RuntimeView, lane900) == 0x900, "WordAt900RuntimeView::lane900 offset must be 0x900");
#endif

  struct SourceAt148AndTailRuntimeView
  {
    std::byte pad00_147[0x148];
    const WordAt900RuntimeView* sourceAt148; // +0x0148
    std::byte pad14C_27B[0x130];
    std::uint32_t lane27C; // +0x027C
    std::uint32_t lane280; // +0x0280
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SourceAt148AndTailRuntimeView, sourceAt148) == 0x148,
    "SourceAt148AndTailRuntimeView::sourceAt148 offset must be 0x148"
  );
  static_assert(
    offsetof(SourceAt148AndTailRuntimeView, lane27C) == 0x27C,
    "SourceAt148AndTailRuntimeView::lane27C offset must be 0x27C"
  );
  static_assert(
    offsetof(SourceAt148AndTailRuntimeView, lane280) == 0x280,
    "SourceAt148AndTailRuntimeView::lane280 offset must be 0x280"
  );
#endif

  struct SelfRelativeLaneBlockTail60RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t anchor10; // +0x10
    std::byte pad14_5F[0x4C];
    std::uint32_t anchor60; // +0x60
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SelfRelativeLaneBlockTail60RuntimeView, anchor10) == 0x10,
    "SelfRelativeLaneBlockTail60RuntimeView::anchor10 offset must be 0x10"
  );
  static_assert(
    offsetof(SelfRelativeLaneBlockTail60RuntimeView, anchor60) == 0x60,
    "SelfRelativeLaneBlockTail60RuntimeView::anchor60 offset must be 0x60"
  );
#endif

  struct FourteenWordRuntimeView
  {
    std::uint32_t lanes[14];
  };
#if defined(_M_IX86)
  static_assert(sizeof(FourteenWordRuntimeView) == 0x38, "FourteenWordRuntimeView size must be 0x38");
#endif

  struct FiveWordRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t lane10; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(FiveWordRuntimeView, lane10) == 0x10, "FiveWordRuntimeView::lane10 offset must be 0x10");
#endif

  struct WordAt97CRuntimeView
  {
    std::byte pad00_97B[0x97C];
    std::uint32_t lane97C; // +0x097C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt97CRuntimeView, lane97C) == 0x97C, "WordAt97CRuntimeView::lane97C offset must be 0x97C");
#endif

  struct WordPairAt4And8RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordPairAt4And8RuntimeView, lane04) == 0x04, "WordPairAt4And8RuntimeView::lane04 offset must be 0x04");
  static_assert(offsetof(WordPairAt4And8RuntimeView, lane08) == 0x08, "WordPairAt4And8RuntimeView::lane08 offset must be 0x08");
#endif

  struct ByteAt54RuntimeView
  {
    std::byte pad00_53[0x54];
    std::uint8_t lane54; // +0x54
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAt54RuntimeView, lane54) == 0x54, "ByteAt54RuntimeView::lane54 offset must be 0x54");
#endif

  struct InlineStorageAt74RuntimeView
  {
    std::byte pad00_73[0x74];
    std::uint32_t lane74; // +0x74
    std::byte pad78_87[0x10];
    std::uint32_t length88; // +0x88
  };
#if defined(_M_IX86)
  static_assert(offsetof(InlineStorageAt74RuntimeView, lane74) == 0x74, "InlineStorageAt74RuntimeView::lane74 offset must be 0x74");
  static_assert(
    offsetof(InlineStorageAt74RuntimeView, length88) == 0x88,
    "InlineStorageAt74RuntimeView::length88 offset must be 0x88"
  );
#endif

  struct InlineStorageAt90RuntimeView
  {
    std::byte pad00_8F[0x90];
    std::uint32_t lane90; // +0x90
    std::byte pad94_A3[0x10];
    std::uint32_t lengthA4; // +0xA4
  };
#if defined(_M_IX86)
  static_assert(offsetof(InlineStorageAt90RuntimeView, lane90) == 0x90, "InlineStorageAt90RuntimeView::lane90 offset must be 0x90");
  static_assert(
    offsetof(InlineStorageAt90RuntimeView, lengthA4) == 0xA4,
    "InlineStorageAt90RuntimeView::lengthA4 offset must be 0xA4"
  );
#endif

  struct ByteAtE0RuntimeView
  {
    std::byte pad00_DF[0xE0];
    std::uint8_t laneE0; // +0xE0
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAtE0RuntimeView, laneE0) == 0xE0, "ByteAtE0RuntimeView::laneE0 offset must be 0xE0");
#endif

  struct SharedOwnerUseCountAt4RuntimeView
  {
    std::byte pad00_03[0x04];
    volatile LONG useCount; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SharedOwnerUseCountAt4RuntimeView, useCount) == 0x04,
    "SharedOwnerUseCountAt4RuntimeView::useCount offset must be 0x04"
  );
#endif

  struct SharedOwnerPairRuntimeView
  {
    std::uint32_t objectWord; // +0x00
    std::uint32_t ownerWord;  // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(SharedOwnerPairRuntimeView) == 0x08, "SharedOwnerPairRuntimeView size must be 0x08");
  static_assert(
    offsetof(SharedOwnerPairRuntimeView, ownerWord) == 0x04,
    "SharedOwnerPairRuntimeView::ownerWord offset must be 0x04"
  );
#endif

  struct SelfRelativeLaneBlockTail30RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t anchor10; // +0x10
    std::byte pad14_2F[0x1C];
    std::uint32_t anchor30; // +0x30
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(SelfRelativeLaneBlockTail30RuntimeView, anchor10) == 0x10,
    "SelfRelativeLaneBlockTail30RuntimeView::anchor10 offset must be 0x10"
  );
  static_assert(
    offsetof(SelfRelativeLaneBlockTail30RuntimeView, anchor30) == 0x30,
    "SelfRelativeLaneBlockTail30RuntimeView::anchor30 offset must be 0x30"
  );
#endif

  /**
   * Address: 0x006ED9A0 (FUN_006ED9A0)
   *
   * What it does:
   * Stores one dword into lanes `+0x0E0/+0x0E4` and marks byte lane `+0x141`.
   */
  [[maybe_unused]] LaneE0E4AndFlag141RuntimeView* StoreLaneE0AndE4AndMarkFlag141(
    LaneE0E4AndFlag141RuntimeView* const self,
    const std::uint32_t value
  ) noexcept
  {
    self->laneE4 = value;
    self->laneE0 = value;
    self->flag141 = 1u;
    return self;
  }

  /**
   * Address: 0x006ED9C0 (FUN_006ED9C0)
   *
   * What it does:
   * Stores one dword into lane `+0x1C`.
   */
  [[maybe_unused]] WordAt1CRuntimeView* StoreLane1CWord(
    WordAt1CRuntimeView* const self,
    const std::uint32_t value
  ) noexcept
  {
    self->lane1C = value;
    return self;
  }

  /**
   * Address: 0x006EE390 (FUN_006EE390)
   *
   * What it does:
   * Returns lane `+0xE4` from one prefixed object selected by index from an
   * 8-byte stride span at `(+0x10,+0x14)`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedPrefixedLaneE4(
    const PointerSpanStride8At10RuntimeView* const span,
    const std::uint32_t index
  ) noexcept
  {
    const std::uint32_t begin = span->begin;
    if (begin == 0u) {
      return 0u;
    }

    const std::uint32_t count = (span->end - begin) >> 3u;
    if (index >= count) {
      return 0u;
    }

    const std::uint32_t prefixedObjectWord =
      *reinterpret_cast<const std::uint32_t*>(begin + (index * 8u));
    if (prefixedObjectWord == 0u) {
      return 0u;
    }

    const std::uint32_t objectBaseWord = prefixedObjectWord - 4u;
    if (objectBaseWord == 0u) {
      return 0u;
    }

    return reinterpret_cast<const WordAtE4RuntimeView*>(objectBaseWord)->laneE4;
  }

  /**
   * Address: 0x006F86C0 (FUN_006F86C0)
   *
   * What it does:
   * Returns 4-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountDwordElementsBeginAt4EndAtCAlias(
    const DwordVectorBeginEndAt0x0CRuntimeView* const vectorLane
  ) noexcept
  {
    return CountDwordVectorElementsBeginAt4EndAtC(vectorLane);
  }

  /**
   * Address: 0x006F8B90 (FUN_006F8B90)
   *
   * What it does:
   * Stores one `*base + index * 4` address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreStride4AddressFromBaseWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride4(outValue, baseWord, index);
  }

  /**
   * Address: 0x006F8C10 (FUN_006F8C10)
   *
   * What it does:
   * Advances one stored address lane by `index * 4` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByDwordCountC(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceAddressLaneByDwordCountA(addressLane, index);
  }

  /**
   * Address: 0x006F8C20 (FUN_006F8C20)
   *
   * What it does:
   * Returns 4-byte element distance between two stored address lanes.
   */
  [[maybe_unused]] std::int32_t CountDwordAddressDistanceC(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return CountDwordAddressDistanceA(lhsAddress, rhsAddress);
  }

  /**
   * Address: 0x006F9A00 (FUN_006F9A00)
   *
   * What it does:
   * Clears one two-word output lane to `{0,0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneA(DwordPairRuntimeView* const outValue) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x006FBF60 (FUN_006FBF60)
   *
   * What it does:
   * Writes one two-word lane from ordered scalar inputs.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteOrderedDwordPair(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x006FBF70 (FUN_006FBF70)
   *
   * What it does:
   * Stores one scalar dword into lane `+0x27C` and mirrors source lane
   * `source@+0x148 -> +0x900` into lane `+0x280`.
   */
  [[maybe_unused]] SourceAt148AndTailRuntimeView* CaptureSourceLane900IntoTail(
    SourceAt148AndTailRuntimeView* const self,
    const std::uint32_t lane27CValue
  ) noexcept
  {
    self->lane27C = lane27CValue;
    self->lane280 = self->sourceAt148->lane900;
    return self;
  }

  /**
   * Address: 0x006FD0F0 (FUN_006FD0F0)
   *
   * What it does:
   * Initializes one four-lane self-relative header with anchors at
   * `self + 0x10` and `self + 0x60`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockTail60RuntimeView* InitializeSelfRelativeLaneBlockTail60(
    SelfRelativeLaneBlockTail60RuntimeView* const self
  ) noexcept
  {
    const std::uint32_t beginAnchor = reinterpret_cast<std::uint32_t>(&self->anchor10);
    const std::uint32_t tailAnchor = reinterpret_cast<std::uint32_t>(&self->anchor60);
    self->lane00 = beginAnchor;
    self->lane04 = beginAnchor;
    self->lane08 = tailAnchor;
    self->lane0C = beginAnchor;
    return self;
  }

  /**
   * Address: 0x006FD2E0 (FUN_006FD2E0)
   *
   * What it does:
   * Clears one 14-word lane block.
   */
  [[maybe_unused]] FourteenWordRuntimeView* ClearFourteenWordBlock(FourteenWordRuntimeView* const outValue) noexcept
  {
    for (auto& lane : outValue->lanes) {
      lane = 0u;
    }
    return outValue;
  }

  /**
   * Address: 0x006FD380 (FUN_006FD380)
   *
   * What it does:
   * Clears lanes `+0x04`, `+0x08`, `+0x0C`, and `+0x10`.
   */
  [[maybe_unused]] FiveWordRuntimeView* ClearLanes04Through10(FiveWordRuntimeView* const outValue) noexcept
  {
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    outValue->lane10 = 0u;
    return outValue;
  }

  /**
   * Address: 0x006FD790 (FUN_006FD790)
   *
   * What it does:
   * Reads one dword lane from offset `+0x97C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt97C(const WordAt97CRuntimeView* const source) noexcept
  {
    return source->lane97C;
  }

  /**
   * Address: 0x006FD7A0 (FUN_006FD7A0)
   *
   * What it does:
   * Returns `max(lane04, lane08) - 1` from one pointed lane pair.
   */
  [[maybe_unused]] std::int32_t ReadMaxLane04OrLane08MinusOne(
    const WordPairAt4And8RuntimeView* const* const sourceSlot
  ) noexcept
  {
    const auto* const source = *sourceSlot;
    const std::int32_t lane08MinusOne = static_cast<std::int32_t>(source->lane08) - 1;
    const std::int32_t lane04MinusOne = static_cast<std::int32_t>(source->lane04) - 1;
    return lane04MinusOne >= lane08MinusOne ? lane04MinusOne : lane08MinusOne;
  }

  /**
   * Address: 0x006FD8E0 (FUN_006FD8E0)
   *
   * What it does:
   * Reads one byte lane from offset `+0x54`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAt54(const ByteAt54RuntimeView* const source) noexcept
  {
    return source->lane54;
  }

  /**
   * Address: 0x006FD8F0 (FUN_006FD8F0)
   *
   * What it does:
   * Returns inline storage address at `+0x74` when length `+0x88 < 16`,
   * otherwise returns heap-pointer lane `+0x74`.
   */
  [[maybe_unused]] std::uint32_t ResolveStoragePointerAt74(const InlineStorageAt74RuntimeView* const source) noexcept
  {
    if (source->length88 < 16u) {
      return reinterpret_cast<std::uint32_t>(const_cast<std::uint32_t*>(&source->lane74));
    }
    return source->lane74;
  }

  /**
   * Address: 0x006FD910 (FUN_006FD910)
   *
   * What it does:
   * Returns inline storage address at `+0x90` when length `+0xA4 < 16`,
   * otherwise returns heap-pointer lane `+0x90`.
   */
  [[maybe_unused]] std::uint32_t ResolveStoragePointerAt90(const InlineStorageAt90RuntimeView* const source) noexcept
  {
    if (source->lengthA4 < 16u) {
      return reinterpret_cast<std::uint32_t>(const_cast<std::uint32_t*>(&source->lane90));
    }
    return source->lane90;
  }

  /**
   * Address: 0x006FD960 (FUN_006FD960)
   *
   * What it does:
   * Reads one byte lane from offset `+0xE0`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAtE0(const ByteAtE0RuntimeView* const source) noexcept
  {
    return source->laneE0;
  }

  /**
   * Address: 0x006FE350 (FUN_006FE350)
   *
   * What it does:
   * Copy-assigns one `{object, owner}` pair and increments owner use-count
   * lane `+0x04` when owner is present.
   */
  [[maybe_unused]] SharedOwnerPairRuntimeView* CopySharedOwnerPairAndRetain(
    SharedOwnerPairRuntimeView* const destination,
    const SharedOwnerPairRuntimeView* const source
  ) noexcept
  {
    destination->objectWord = source->objectWord;
    const std::uint32_t ownerWord = source->ownerWord;
    destination->ownerWord = ownerWord;
    if (ownerWord != 0u) {
      auto* const owner = reinterpret_cast<SharedOwnerUseCountAt4RuntimeView*>(ownerWord);
      InterlockedExchangeAdd(&owner->useCount, 1);
    }
    return destination;
  }

  /**
   * Address: 0x00701B40 (FUN_00701B40)
   *
   * What it does:
   * Clears one two-word output lane to `{0,0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneB(DwordPairRuntimeView* const outValue) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x00701B50 (FUN_00701B50)
   *
   * What it does:
   * Initializes one four-lane self-relative header with anchors at
   * `self + 0x10` and `self + 0x30`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockTail30RuntimeView* InitializeSelfRelativeLaneBlockTail30(
    SelfRelativeLaneBlockTail30RuntimeView* const self
  ) noexcept
  {
    const std::uint32_t beginAnchor = reinterpret_cast<std::uint32_t>(&self->anchor10);
    const std::uint32_t tailAnchor = reinterpret_cast<std::uint32_t>(&self->anchor30);
    self->lane00 = beginAnchor;
    self->lane04 = beginAnchor;
    self->lane08 = tailAnchor;
    self->lane0C = beginAnchor;
    return self;
  }

  /**
   * Address: 0x00701CE0 (FUN_00701CE0)
   *
   * What it does:
   * Computes one `begin@+0x04 + index*40` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride40AddressFromBeginAt4AliasA(
    const std::int32_t index,
    const DwordVectorBeginEndAt0x0CRuntimeView* const source
  ) noexcept
  {
    return ComputeStride40AddressFromBeginAt4(index, source);
  }

  /**
   * Address: 0x00701CF0 (FUN_00701CF0)
   *
   * What it does:
   * Alias lane for `begin@+0x04 + index*40` address computation.
   */
  [[maybe_unused]] std::uint32_t ComputeStride40AddressFromBeginAt4AliasB(
    const std::int32_t index,
    const DwordVectorBeginEndAt0x0CRuntimeView* const source
  ) noexcept
  {
    return ComputeStride40AddressFromBeginAt4(index, source);
  }

  /**
   * Address: 0x007022D0 (FUN_007022D0)
   *
   * What it does:
   * Swaps one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesA(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x007022E0 (FUN_007022E0)
   *
   * What it does:
   * Alias lane for swapping one dword between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesB(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x007022F0 (FUN_007022F0)
   *
   * What it does:
   * Alias lane for swapping one dword between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesC(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x00702300 (FUN_00702300)
   *
   * What it does:
   * Alias lane for swapping one dword between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesD(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x00702310 (FUN_00702310)
   *
   * What it does:
   * Alias lane for swapping one dword between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesE(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  struct Float4LaneRuntimeView
  {
    float x; // +0x00
    float y; // +0x04
    float z; // +0x08
    float w; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(Float4LaneRuntimeView) == 0x10, "Float4LaneRuntimeView size must be 0x10");
#endif

  struct DwordTripleFloatPayload48RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    float lane0C; // +0x0C
    float lane10; // +0x10
    float lane14; // +0x14
    std::uint32_t lane18; // +0x18
    std::uint32_t lane1C; // +0x1C
    std::uint8_t lane20; // +0x20
    std::byte pad21_23[0x03];
    float lane24; // +0x24
    float lane28; // +0x28
    std::uint32_t lane2C; // +0x2C
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(DwordTripleFloatPayload48RuntimeView) == 0x30,
    "DwordTripleFloatPayload48RuntimeView size must be 0x30"
  );
  static_assert(
    offsetof(DwordTripleFloatPayload48RuntimeView, lane20) == 0x20,
    "DwordTripleFloatPayload48RuntimeView::lane20 offset must be 0x20"
  );
  static_assert(
    offsetof(DwordTripleFloatPayload48RuntimeView, lane2C) == 0x2C,
    "DwordTripleFloatPayload48RuntimeView::lane2C offset must be 0x2C"
  );
#endif

  struct Payload56RuntimeView
  {
    std::byte bytes[0x38];
  };
#if defined(_M_IX86)
  static_assert(sizeof(Payload56RuntimeView) == 0x38, "Payload56RuntimeView size must be 0x38");
#endif

  [[nodiscard]] std::int32_t ComputeStride16IndexFromAddressDelta(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*leftAddress - *rightAddress) >> 4);
  }

  /**
   * Address: 0x0071C140 (FUN_0071C140)
   *
   * What it does:
   * Returns 16-byte index delta between two address slots.
   */
  [[maybe_unused]] std::int32_t ComputeStride16IndexFromPointerDeltaA(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return ComputeStride16IndexFromAddressDelta(leftAddress, rightAddress);
  }

  /**
   * Address: 0x0071C1C0 (FUN_0071C1C0)
   *
   * What it does:
   * Copy-assigns one four-float lane payload.
   */
  [[maybe_unused]] Float4LaneRuntimeView* CopyFloat4Lane(
    Float4LaneRuntimeView* const outValue,
    const Float4LaneRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x0071C540 (FUN_0071C540)
   *
   * What it does:
   * Returns 56-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride56IndexFromPointerDeltaB(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*leftAddress - *rightAddress) / 56u);
  }

  /**
   * Address: 0x0071C570 (FUN_0071C570)
   *
   * What it does:
   * Clears one output dword lane to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearDwordLaneA(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x0071C5F0 (FUN_0071C5F0)
   *
   * What it does:
   * Alias lane for clearing one output dword to zero.
   */
  [[maybe_unused]] std::uint32_t* ClearDwordLaneB(std::uint32_t* const outValue) noexcept
  {
    *outValue = 0u;
    return outValue;
  }

  /**
   * Address: 0x0071C610 (FUN_0071C610)
   *
   * What it does:
   * Advances one address lane by `index * 140`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride140C(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 140u;
    return addressLane;
  }

  /**
   * Address: 0x0071C620 (FUN_0071C620)
   *
   * What it does:
   * Returns 140-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride140IndexFromPointerDeltaB(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*leftAddress - *rightAddress) / 140u);
  }

  /**
   * Address: 0x0071C640 (FUN_0071C640)
   *
   * What it does:
   * Advances one address lane by `index * 56`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride56C(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 56u;
    return addressLane;
  }

  /**
   * Address: 0x0071C660 (FUN_0071C660)
   *
   * What it does:
   * Advances one address lane by `index * 16`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride16A(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 16u;
    return addressLane;
  }

  /**
   * Address: 0x0071C670 (FUN_0071C670)
   *
   * What it does:
   * Alias lane for 16-byte index delta between address slots.
   */
  [[maybe_unused]] std::int32_t ComputeStride16IndexFromPointerDeltaB(
    const std::uint32_t* const leftAddress,
    const std::uint32_t* const rightAddress
  ) noexcept
  {
    return ComputeStride16IndexFromAddressDelta(leftAddress, rightAddress);
  }

  /**
   * Address: 0x0071C680 (FUN_0071C680)
   *
   * What it does:
   * Writes one `{dword, byte}` lane from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointersA(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->lane00 = *sourceWord;
    outValue->lane04 = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x0071C690 (FUN_0071C690)
   *
   * What it does:
   * Alias lane for writing one `{dword, byte}` payload.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointersB(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->lane00 = *sourceWord;
    outValue->lane04 = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x0071C760 (FUN_0071C760)
   *
   * What it does:
   * Copies one source dword into output when output storage is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentE(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x0071C7A0 (FUN_0071C7A0)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentF(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x0071C7B0 (FUN_0071C7B0)
   *
   * What it does:
   * Advances one address lane by `index * 56`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride56D(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 56u;
    return addressLane;
  }

  /**
   * Address: 0x0071C890 (FUN_0071C890)
   *
   * What it does:
   * Advances one address lane by `index * 140`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride140D(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 140u;
    return addressLane;
  }

  /**
   * Address: 0x0071C8A0 (FUN_0071C8A0)
   *
   * What it does:
   * Advances one address lane by `index * 16`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride16B(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 16u;
    return addressLane;
  }

  /**
   * Address: 0x0071C920 (FUN_0071C920)
   *
   * What it does:
   * Initializes one five-dword lane payload and clears two trailing flags.
   */
  [[maybe_unused]] DwordQuintWithFlagPairRuntimeView* InitializeDwordQuintWithFlagsB(
    DwordQuintWithFlagPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const DwordPairRuntimeView* const sourcePair,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = sourcePair->lane00;
    outValue->lane10 = sourcePair->lane04;
    outValue->flag14 = 0u;
    outValue->flag15 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0071C950 (FUN_0071C950)
   *
   * What it does:
   * Copy-assigns one mixed 48-byte dword/float payload lane.
   */
  [[maybe_unused]] DwordTripleFloatPayload48RuntimeView* CopyMixedPayload48(
    DwordTripleFloatPayload48RuntimeView* const outValue,
    const DwordTripleFloatPayload48RuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x0071D260 (FUN_0071D260)
   *
   * What it does:
   * Swaps dword tail lanes `(+0x04,+0x08,+0x0C)` between two quad lanes.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesC(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x0071D390 (FUN_0071D390)
   *
   * What it does:
   * Alias lane for swapping dword tail lanes between two quads.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesD(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x0071D790 (FUN_0071D790)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentG(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x0071D810 (FUN_0071D810)
   *
   * What it does:
   * Alias lane for copying one source dword when output is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentH(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *sourceWord;
    }
    return outValue;
  }

  /**
   * Address: 0x0071D920 (FUN_0071D920)
   *
   * What it does:
   * Alias lane for swapping dword tail lanes between two quads.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesE(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x0071D950 (FUN_0071D950)
   *
   * What it does:
   * Alias lane for swapping dword tail lanes between two quads.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesF(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;

    const std::uint32_t lane0C = right->lane0C;
    right->lane0C = left->lane0C;
    left->lane0C = lane0C;
    return left;
  }

  /**
   * Address: 0x0071E970 (FUN_0071E970)
   *
   * What it does:
   * Fills one 56-byte payload range `[begin, end)` with one template payload.
   */
  [[maybe_unused]] Payload56RuntimeView* FillPayload56Range(
    Payload56RuntimeView* begin,
    Payload56RuntimeView* end,
    const Payload56RuntimeView* const value
  ) noexcept
  {
    while (begin != end) {
      *begin = *value;
      ++begin;
    }
    return begin;
  }

  /**
   * Address: 0x0071E9B0 (FUN_0071E9B0)
   *
   * What it does:
   * Backward-copies one 56-byte payload range from `[sourceBegin, sourceEnd)`
   * into destination ending at `destEnd`.
   */
  [[maybe_unused]] Payload56RuntimeView* CopyPayload56RangeBackward(
    Payload56RuntimeView* destEnd,
    Payload56RuntimeView* sourceEnd,
    Payload56RuntimeView* sourceBegin
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destEnd;
      *destEnd = *sourceEnd;
    }
    return destEnd;
  }

  /**
   * Address: 0x0071EB70 (FUN_0071EB70)
   *
   * What it does:
   * Fills one `[begin, end)` float4 range with one source float4 lane.
   */
  [[maybe_unused]] Float4LaneRuntimeView* FillFloat4Range(
    Float4LaneRuntimeView* begin,
    Float4LaneRuntimeView* end,
    const Float4LaneRuntimeView* const value
  ) noexcept
  {
    while (begin != end) {
      *begin = *value;
      ++begin;
    }
    return begin;
  }

  /**
   * Address: 0x0071EC30 (FUN_0071EC30)
   *
   * What it does:
   * Forward-copies one 56-byte payload range `[sourceBegin, sourceEnd)` to destination.
   */
  [[maybe_unused]] Payload56RuntimeView* CopyPayload56RangeForward(
    Payload56RuntimeView* destBegin,
    Payload56RuntimeView* sourceBegin,
    Payload56RuntimeView* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destBegin = *sourceBegin;
      ++sourceBegin;
      ++destBegin;
    }
    return destBegin;
  }

  /**
   * Address: 0x0071EC60 (FUN_0071EC60)
   *
   * What it does:
   * Swaps one dword slot between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotsIota(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    const std::uint32_t value = *right;
    *right = *left;
    *left = value;
    return left;
  }

  struct ByteFlagAt524RuntimeView
  {
    std::byte pad0000_0523[0x524];
    std::uint8_t flag524; // +0x524
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteFlagAt524RuntimeView, flag524) == 0x524, "ByteFlagAt524RuntimeView::flag524 offset must be 0x524");
#endif

  struct DwordAndDirtyFlagRuntimeView
  {
    std::byte pad0000_0097[0x98];
    std::uint32_t lane98; // +0x98
    std::byte pad009C_0140[0xA5];
    std::uint8_t dirty141; // +0x141
  };
#if defined(_M_IX86)
  static_assert(offsetof(DwordAndDirtyFlagRuntimeView, lane98) == 0x98, "DwordAndDirtyFlagRuntimeView::lane98 offset must be 0x98");
  static_assert(
    offsetof(DwordAndDirtyFlagRuntimeView, dirty141) == 0x141,
    "DwordAndDirtyFlagRuntimeView::dirty141 offset must be 0x141"
  );
#endif

  struct DwordAt284RuntimeView
  {
    std::byte pad0000_0283[0x284];
    std::uint32_t lane284; // +0x284
  };
#if defined(_M_IX86)
  static_assert(offsetof(DwordAt284RuntimeView, lane284) == 0x284, "DwordAt284RuntimeView::lane284 offset must be 0x284");
#endif

  struct SelfRelativeHeaderLane7RuntimeView
  {
    std::uint32_t lanes[7];
  };
#if defined(_M_IX86)
  static_assert(sizeof(SelfRelativeHeaderLane7RuntimeView) == 0x1C, "SelfRelativeHeaderLane7RuntimeView size must be 0x1C");
#endif

  struct BaseAddressAt4RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t baseAddress; // +0x04
  };
#if defined(_M_IX86)
  static_assert(offsetof(BaseAddressAt4RuntimeView, baseAddress) == 0x04, "BaseAddressAt4RuntimeView::baseAddress offset must be 0x04");
#endif

  [[nodiscard]] void* GetJumpThunkSentinelTargetMarker() noexcept
  {
    static std::byte sJumpThunkTargetMarker = std::byte{0};
    return &sJumpThunkTargetMarker;
  }

  /**
   * Address: 0x00740780 (FUN_00740780)
   *
   * What it does:
   * Swaps one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesF(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x007407A0 (FUN_007407A0)
   *
   * What it does:
   * Returns one dword lane value and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearDwordLaneA(std::uint32_t* const lane) noexcept
  {
    const std::uint32_t value = *lane;
    *lane = 0u;
    return value;
  }

  /**
   * Address: 0x007407B0 (FUN_007407B0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesG(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x007407C0 (FUN_007407C0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesH(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x007409A0 (FUN_007409A0)
   *
   * What it does:
   * Moves one dword through source double-pointer and clears source to zero.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearDoublePointerDword(
    std::uint32_t* const outValue,
    std::uint32_t** const source
  ) noexcept
  {
    *outValue = **source;
    **source = 0u;
    return outValue;
  }

  /**
   * Address: 0x00740EF0 (FUN_00740EF0)
   *
   * What it does:
   * Jump-thunk lane returning one stable internal marker pointer.
   */
  [[maybe_unused]] void* ReturnJumpThunkMarkerA() noexcept
  {
    return GetJumpThunkSentinelTargetMarker();
  }

  /**
   * Address: 0x007414D0 (FUN_007414D0)
   *
   * What it does:
   * Jump-thunk alias returning one stable internal marker pointer.
   */
  [[maybe_unused]] void* ReturnJumpThunkMarkerB() noexcept
  {
    return GetJumpThunkSentinelTargetMarker();
  }

  /**
   * Address: 0x007416F0 (FUN_007416F0)
   * Address: 0x0074FD20 (FUN_0074FD20)
   * Address: 0x007508F0 (FUN_007508F0)
   * Address: 0x0089ADA0 (FUN_0089ADA0)
   *
   * What it does:
   * Writes one dword pair as `{lane00 = a3, lane04 = a2}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposePairFromEdxAndEcxOrderA(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x00741730 (FUN_00741730)
   * Address: 0x0089ADB0 (FUN_0089ADB0)
   *
   * What it does:
   * Copy-assigns one dword pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLaneA(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00741790 (FUN_00741790)
   *
   * What it does:
   * Alias lane for copy-assigning one dword pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLaneB(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x007417A0 (FUN_007417A0)
   *
   * What it does:
   * Alias lane writing one dword pair as `{lane00 = a3, lane04 = a2}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposePairFromEdxAndEcxOrderB(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x00741800 (FUN_00741800)
   *
   * What it does:
   * Alias lane writing one dword pair as `{lane00 = a3, lane04 = a2}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposePairFromEdxAndEcxOrderC(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x00741950 (FUN_00741950)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesI(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlots(left, right);
  }

  /**
   * Address: 0x00741CA0 (FUN_00741CA0)
   *
   * What it does:
   * Alias lane for copy-assigning one dword pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLaneC(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00741CB0 (FUN_00741CB0)
   *
   * What it does:
   * Writes one dword pair as `{lane00 = value, lane04 = *sourceWord}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ComposePairFromValueAndPointerWord(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane00 = value;
    outValue->lane04 = *sourceWord;
    return outValue;
  }

  /**
   * Address: 0x00741CE0 (FUN_00741CE0)
   *
   * What it does:
   * Copy-assigns one dword lane.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLaneFromSource(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    *outValue = *sourceWord;
    return outValue;
  }

  /**
   * Address: 0x007424E0 (FUN_007424E0)
   *
   * What it does:
   * Alias lane for copy-assigning one dword pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLaneD(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00742F50 (FUN_00742F50)
   *
   * What it does:
   * Copy-assigns one four-dword lane.
   */
  [[maybe_unused]] DwordQuadRuntimeView* CopyDwordQuadLaneB(
    DwordQuadRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x007431C0 (FUN_007431C0)
   *
   * What it does:
   * Reads one byte flag lane at offset `+0x524`.
   */
  [[maybe_unused]] std::uint8_t ReadFlagByteAt524(const ByteFlagAt524RuntimeView* const source) noexcept
  {
    return source->flag524;
  }

  /**
   * Address: 0x007431D0 (FUN_007431D0)
   *
   * What it does:
   * Stores dword lane at `+0x98` and sets dirty byte at `+0x141`.
   */
  [[maybe_unused]] DwordAndDirtyFlagRuntimeView* StoreWordAndSetDirtyFlag(
    DwordAndDirtyFlagRuntimeView* const self,
    const std::uint32_t value
  ) noexcept
  {
    self->lane98 = value;
    self->dirty141 = 1u;
    return self;
  }

  /**
   * Address: 0x00743220 (FUN_00743220)
   *
   * What it does:
   * Reads one dword lane at offset `+0x284`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt284(const DwordAt284RuntimeView* const source) noexcept
  {
    return source->lane284;
  }

  /**
   * Address: 0x0074A620 (FUN_0074A620)
   *
   * What it does:
   * Initializes a self-relative 4-lane header and sets sentinel lane `+0x18`.
   */
  [[maybe_unused]] SelfRelativeHeaderLane7RuntimeView* InitializeSelfRelativeHeaderWithSentinel(
    SelfRelativeHeaderLane7RuntimeView* const self
  ) noexcept
  {
    const std::uint32_t selfAddress = reinterpret_cast<std::uint32_t>(self);
    self->lanes[0] = selfAddress + 16u;
    self->lanes[1] = selfAddress + 16u;
    self->lanes[2] = selfAddress + 24u;
    self->lanes[3] = selfAddress + 16u;
    self->lanes[6] = 0xF0000000u;
    return self;
  }

  /**
   * Address: 0x0074BCB0 (FUN_0074BCB0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with anchor at `self + 24`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderLane24A(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    const std::uint32_t selfAddress = reinterpret_cast<std::uint32_t>(self);
    self->lane00 = selfAddress + 16u;
    self->lane04 = selfAddress + 16u;
    self->lane08 = selfAddress + 24u;
    self->lane0C = selfAddress + 16u;
    return self;
  }

  /**
   * Address: 0x0074BCD0 (FUN_0074BCD0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with anchor at `self + 240`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderLane240(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    const std::uint32_t selfAddress = reinterpret_cast<std::uint32_t>(self);
    self->lane00 = selfAddress + 16u;
    self->lane04 = selfAddress + 16u;
    self->lane08 = selfAddress + 240u;
    self->lane0C = selfAddress + 16u;
    return self;
  }

  /**
   * Address: 0x0074BE00 (FUN_0074BE00)
   *
   * What it does:
   * Clears one two-dword lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneASecondary(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0074C0F0 (FUN_0074C0F0)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBSecondary(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0074C100 (FUN_0074C100)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneC(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0074C1D0 (FUN_0074C1D0)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneD(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0074C420 (FUN_0074C420)
   * Address: 0x0074C600 (FUN_0074C600)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneE(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0074C5E0 (FUN_0074C5E0)
   * Address: 0x0074C5F0 (FUN_0074C5F0)
   *
   * What it does:
   * Computes one `base@+0x04 + index*36` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride36AddressFromBaseAt4(
    const std::int32_t index,
    const BaseAddressAt4RuntimeView* const source
  ) noexcept
  {
    return source->baseAddress + (static_cast<std::uint32_t>(index) * 36u);
  }

  struct InlineStorageAt44RuntimeView
  {
    std::byte pad00_43[0x44];
    std::uint32_t lane44; // +0x44
    std::byte pad48_57[0x10];
    std::uint32_t length58; // +0x58
  };
#if defined(_M_IX86)
  static_assert(offsetof(InlineStorageAt44RuntimeView, lane44) == 0x44, "InlineStorageAt44RuntimeView::lane44 offset must be 0x44");
  static_assert(
    offsetof(InlineStorageAt44RuntimeView, length58) == 0x58,
    "InlineStorageAt44RuntimeView::length58 offset must be 0x58"
  );
#endif

  struct DwordTripleAddressRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordTripleAddressRuntimeView) == 0x0C, "DwordTripleAddressRuntimeView size must be 0x0C");
  static_assert(
    offsetof(DwordTripleAddressRuntimeView, lane08) == 0x08,
    "DwordTripleAddressRuntimeView::lane08 offset must be 0x08"
  );
#endif

  struct DwordBeginMidEndRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t begin;  // +0x04
    std::uint32_t mid;    // +0x08
    std::uint32_t end;    // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordBeginMidEndRuntimeView) == 0x10, "DwordBeginMidEndRuntimeView size must be 0x10");
  static_assert(
    offsetof(DwordBeginMidEndRuntimeView, begin) == 0x04,
    "DwordBeginMidEndRuntimeView::begin offset must be 0x04"
  );
  static_assert(offsetof(DwordBeginMidEndRuntimeView, end) == 0x0C, "DwordBeginMidEndRuntimeView::end offset must be 0x0C");
#endif

  struct DwordAndFloatRuntimeView
  {
    std::uint32_t lane00; // +0x00
    float lane04;         // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordAndFloatRuntimeView) == 0x08, "DwordAndFloatRuntimeView size must be 0x08");
  static_assert(offsetof(DwordAndFloatRuntimeView, lane04) == 0x04, "DwordAndFloatRuntimeView::lane04 offset must be 0x04");
#endif

  struct ByteAt08RuntimeView
  {
    std::byte pad00_07[0x08];
    std::uint8_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAt08RuntimeView, lane08) == 0x08, "ByteAt08RuntimeView::lane08 offset must be 0x08");
#endif

  struct PointerToWordAt04RuntimeView
  {
    std::uint32_t lane00; // +0x00
    const std::uint32_t* lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(PointerToWordAt04RuntimeView) == 0x08, "PointerToWordAt04RuntimeView size must be 0x08");
  static_assert(
    offsetof(PointerToWordAt04RuntimeView, lane04) == 0x04,
    "PointerToWordAt04RuntimeView::lane04 offset must be 0x04"
  );
#endif

  [[nodiscard]] std::int32_t CountStride8BetweenAddresses(
    const std::uint32_t high,
    const std::uint32_t low
  ) noexcept
  {
    return static_cast<std::int32_t>((high - low) >> 3u);
  }

  /**
   * Address: 0x0072A3B0 (FUN_0072A3B0)
   *
   * What it does:
   * Alias lane for initializing one self-relative header with `+0x10/+0x30`
   * anchors.
   */
  [[maybe_unused]] SelfRelativeLaneBlockTail30RuntimeView* InitializeSelfRelativeLaneBlockTail30Alias(
    SelfRelativeLaneBlockTail30RuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeLaneBlockTail30(self);
  }

  /**
   * Address: 0x0072AA40 (FUN_0072AA40)
   *
   * What it does:
   * Returns dword-slot distance between lanes `+0x00` and `+0x04`.
   */
  [[maybe_unused]] std::int32_t CountDwordSlotsFromLane00ToLane04(
    const DwordTripleAddressRuntimeView* const lanes
  ) noexcept
  {
    return static_cast<std::int32_t>((lanes->lane04 - lanes->lane00) >> 2u);
  }

  /**
   * Address: 0x0072AA50 (FUN_0072AA50)
   *
   * What it does:
   * Returns dword-slot distance between lanes `+0x00` and `+0x08`.
   */
  [[maybe_unused]] std::int32_t CountDwordSlotsFromLane00ToLane08(
    const DwordTripleAddressRuntimeView* const lanes
  ) noexcept
  {
    return static_cast<std::int32_t>((lanes->lane08 - lanes->lane00) >> 2u);
  }

  /**
   * Address: 0x0072B800 (FUN_0072B800)
   *
   * What it does:
   * Returns inline storage address at `+0x44` when length `+0x58 < 16`,
   * otherwise returns heap-pointer lane `+0x44`.
   */
  [[maybe_unused]] std::uint32_t ResolveStoragePointerAt44(const InlineStorageAt44RuntimeView* const source) noexcept
  {
    if (source->length58 < 16u) {
      return reinterpret_cast<std::uint32_t>(const_cast<std::uint32_t*>(&source->lane44));
    }
    return source->lane44;
  }

  /**
   * Address: 0x0072D850 (FUN_0072D850)
   *
   * What it does:
   * Returns whether left float lane `+0x04` is greater than right lane `+0x04`.
   */
  [[maybe_unused]] bool IsLane04FloatGreater(
    const DwordAndFloatRuntimeView* const left,
    const DwordAndFloatRuntimeView* const right
  ) noexcept
  {
    return left->lane04 > right->lane04;
  }

  /**
   * Address: 0x00733420 (FUN_00733420)
   * Address: 0x00782EB0 (FUN_00782EB0)
   *
   * What it does:
   * Clears dword lanes `+0x04/+0x08/+0x0C`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearDwordLanes04To0C(DwordQuadRuntimeView* const lanes) noexcept
  {
    lanes->lane04 = 0u;
    lanes->lane08 = 0u;
    lanes->lane0C = 0u;
    return lanes;
  }

  /**
   * Address: 0x00733500 (FUN_00733500)
   * Address: 0x007847F0 (FUN_007847F0)
   *
   * What it does:
   * Advances one stored address lane by 8 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneBy8A(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 8u;
    return addressLane;
  }

  /**
   * Address: 0x00733520 (FUN_00733520)
   * Address: 0x007830B0 (FUN_007830B0)
   *
   * What it does:
   * Returns 8-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountStride8ElementsBeginAt4EndAtC(
    const DwordBeginMidEndRuntimeView* const lanes
  ) noexcept
  {
    if (lanes->begin == 0u) {
      return 0;
    }
    return CountStride8BetweenAddresses(lanes->end, lanes->begin);
  }

  /**
   * Address: 0x00733540 (FUN_00733540)
   * Address: 0x00782F20 (FUN_00782F20)
   *
   * What it does:
   * Returns 8-byte element count from one begin/mid pair at offsets
   * `(+0x04,+0x08)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountStride8ElementsBeginAt4MidAt8(
    const DwordBeginMidEndRuntimeView* const lanes
  ) noexcept
  {
    if (lanes->begin == 0u) {
      return 0;
    }
    return CountStride8BetweenAddresses(lanes->mid, lanes->begin);
  }

  /**
   * Address: 0x00782F40 (FUN_00782F40)
   *
   * What it does:
   * Returns true when one 8-byte begin/mid span is empty or unallocated.
   */
  [[maybe_unused]] bool IsStride8ElementsBeginAt4MidAt8Empty(
    const DwordBeginMidEndRuntimeView* const lanes
  ) noexcept
  {
    return lanes->begin == 0u || CountStride8BetweenAddresses(lanes->mid, lanes->begin) == 0;
  }

  /**
   * Address: 0x00783030 (FUN_00783030)
   *
   * What it does:
   * Returns `-1` when one source dword lane is zero; otherwise returns `0`.
   */
  [[maybe_unused]] std::int32_t ReturnMinusOneIfSourceWordZero(const std::uint32_t* const sourceWord) noexcept
  {
    return (*sourceWord != 0u) ? 0 : -1;
  }

  /**
   * Address: 0x00733680 (FUN_00733680)
   *
   * What it does:
   * Alias lane for advancing one stored address lane by 8 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneBy8B(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 8u;
    return addressLane;
  }

  /**
   * Address: 0x007836C0 (FUN_007836C0)
   * Address: 0x007836D0 (FUN_007836D0)
   * Address: 0x00784680 (FUN_00784680)
   * Address: 0x00784730 (FUN_00784730)
   *
   * What it does:
   * Advances one stored address lane by `index * 8` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByIndexStride8(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 8u;
    return addressLane;
  }

  /**
   * Address: 0x00784640 (FUN_00784640)
   * Address: 0x007846F0 (FUN_007846F0)
   *
   * What it does:
   * Adds one `(end - begin) / 8` span count into one caller-provided counter.
   */
  [[maybe_unused]] std::int32_t* AddStride8SpanCountToAccumulator(
    std::int32_t* const accumulator,
    const std::uint32_t beginAddress,
    const std::uint32_t endAddress
  ) noexcept
  {
    const std::int32_t deltaBytes = static_cast<std::int32_t>(endAddress) - static_cast<std::int32_t>(beginAddress);
    *accumulator += (deltaBytes >> 3);
    return accumulator;
  }

  /**
   * Address: 0x0077F630 (FUN_0077F630)
   *
   * What it does:
   * Advances one stored address lane by one 144-byte stride.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride144(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 144u;
    return addressLane;
  }

  /**
   * Address: 0x007339C0 (FUN_007339C0)
   *
   * What it does:
   * Stores one `*base + index * 8` address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreStride8AddressFromBaseWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride8(outValue, baseWord, index);
  }

  /**
   * Address: 0x00734090 (FUN_00734090)
   *
   * What it does:
   * Writes one two-word lane from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromWordPointersA(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const firstSource,
    const std::uint32_t* const secondSource
  ) noexcept
  {
    return WriteDwordPairFromWordPointers(outValue, firstSource, secondSource);
  }

  /**
   * Address: 0x00734170 (FUN_00734170)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesA(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x00734330 (FUN_00734330)
   *
   * What it does:
   * Alias lane for swapping both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesB(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x00734620 (FUN_00734620)
   *
   * What it does:
   * Reads one byte lane at offset `+0x08`.
   */
  [[maybe_unused]] std::uint8_t ReadByteAt08(const ByteAt08RuntimeView* const source) noexcept
  {
    return source->lane08;
  }

  struct ByteLanesAt28To2ERuntimeView
  {
    std::byte pad0000_0027[0x28];
    std::uint8_t lane28; // +0x28
    std::uint8_t lane29; // +0x29
    std::uint8_t lane2A; // +0x2A
    std::byte pad2B;     // +0x2B
    std::uint8_t lane2C; // +0x2C
    std::uint8_t lane2D; // +0x2D
    std::uint8_t lane2E; // +0x2E
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLanesAt28To2ERuntimeView, lane28) == 0x28, "ByteLanesAt28To2ERuntimeView::lane28 offset");
  static_assert(offsetof(ByteLanesAt28To2ERuntimeView, lane2C) == 0x2C, "ByteLanesAt28To2ERuntimeView::lane2C offset");
  static_assert(offsetof(ByteLanesAt28To2ERuntimeView, lane2D) == 0x2D, "ByteLanesAt28To2ERuntimeView::lane2D offset");
  static_assert(offsetof(ByteLanesAt28To2ERuntimeView, lane2E) == 0x2E, "ByteLanesAt28To2ERuntimeView::lane2E offset");
#endif

  struct WordAt30RuntimeView
  {
    std::byte pad0000_002F[0x30];
    std::uint32_t lane30; // +0x30
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt30RuntimeView, lane30) == 0x30, "WordAt30RuntimeView::lane30 offset");
#endif

  struct WordAt34RuntimeView
  {
    std::byte pad0000_0033[0x34];
    std::uint32_t lane34; // +0x34
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt34RuntimeView, lane34) == 0x34, "WordAt34RuntimeView::lane34 offset");
#endif

  struct ByteAt71RuntimeView
  {
    std::byte pad0000_0070[0x71];
    std::uint8_t lane71; // +0x71
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAt71RuntimeView, lane71) == 0x71, "ByteAt71RuntimeView::lane71 offset");
#endif

  struct WordAt120RuntimeView
  {
    std::byte pad0000_011F[0x120];
    std::uint32_t lane120; // +0x120
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt120RuntimeView, lane120) == 0x120, "WordAt120RuntimeView::lane120 offset");
#endif

  struct ByteAt170RuntimeView
  {
    std::byte pad0000_016F[0x170];
    std::uint8_t lane170; // +0x170
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAt170RuntimeView, lane170) == 0x170, "ByteAt170RuntimeView::lane170 offset");
#endif

  /**
   * Address: 0x007A4450 (FUN_007A4450)
   * Address: 0x007A44E0 (FUN_007A44E0)
   *
   * What it does:
   * Returns one byte lane from offset `+0x2D`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane2D(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane2D;
  }

  /**
   * Address: 0x007A4460 (FUN_007A4460)
   * Address: 0x007A44C0 (FUN_007A44C0)
   *
   * What it does:
   * Returns one byte lane from offset `+0x2C`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane2C(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane2C;
  }

  /**
   * Address: 0x007A4470 (FUN_007A4470)
   *
   * What it does:
   * Returns one byte lane from offset `+0x28`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane28(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane28;
  }

  /**
   * Address: 0x007A4480 (FUN_007A4480)
   *
   * What it does:
   * Returns one byte lane from offset `+0x29`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane29(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane29;
  }

  /**
   * Address: 0x007A4490 (FUN_007A4490)
   *
   * What it does:
   * Returns one byte lane from offset `+0x2A`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane2A(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane2A;
  }

  /**
   * Address: 0x007A44D0 (FUN_007A44D0)
   *
   * What it does:
   * Returns one byte lane from offset `+0x2E`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane2E(const ByteLanesAt28To2ERuntimeView* const source) noexcept
  {
    return source->lane2E;
  }

  /**
   * Address: 0x007A44F0 (FUN_007A44F0)
   *
   * What it does:
   * Returns one dword lane from offset `+0x28`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane28(const WordAt28RuntimeView* const source) noexcept
  {
    return source->lane28;
  }

  /**
   * Address: 0x007A44B0 (FUN_007A44B0)
   * Address: 0x007A4500 (FUN_007A4500)
   *
   * What it does:
   * Returns one dword lane from offset `+0x34`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane34(const WordAt34RuntimeView* const source) noexcept
  {
    return source->lane34;
  }

  /**
   * Address: 0x007A4510 (FUN_007A4510)
   *
   * What it does:
   * Returns one dword lane from offset `+0x30`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane30(const WordAt30RuntimeView* const source) noexcept
  {
    return source->lane30;
  }

  /**
   * Address: 0x007A6350 (FUN_007A6350)
   *
   * What it does:
   * Returns one byte lane from offset `+0x170`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane170(const ByteAt170RuntimeView* const source) noexcept
  {
    return source->lane170;
  }

  /**
   * Address: 0x007A63B0 (FUN_007A63B0)
   *
   * What it does:
   * Returns one dword lane from offset `+0x120`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane120(const WordAt120RuntimeView* const source) noexcept
  {
    return source->lane120;
  }

  /**
   * Address: 0x007A63C0 (FUN_007A63C0)
   *
   * What it does:
   * Returns one byte lane from offset `+0x71`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane71(const ByteAt71RuntimeView* const source) noexcept
  {
    return source->lane71;
  }

  /**
   * Address: 0x007AE4A0 (FUN_007AE4A0)
   *
   * What it does:
   * Returns whether dword lane `+0x08` is zero.
   */
  [[maybe_unused]] bool IsLane08Zero(const DwordTripleLaneRuntimeView* const source) noexcept
  {
    return source->lane08 == 0u;
  }

  class ILegacyDeleteDispatchAtVtable4
  {
  public:
    virtual void ReservedSlot0() = 0;
    virtual std::uintptr_t DeleteWithFlag(std::int32_t shouldDelete) = 0;
  };

  /**
   * Address: 0x007AE640 (FUN_007AE640)
   *
   * What it does:
   * Replaces one owner-word slot and runs deleting dispatch (`flag=1`) on the
   * previous owner when present.
   */
  [[maybe_unused]] std::uint32_t* AssignReleasableWordAndReleasePrevious(
    std::uint32_t* const ownerWordSlot,
    const std::uint32_t newOwnerWord
  ) noexcept
  {
    const std::uint32_t previousOwnerWord = *ownerWordSlot;
    *ownerWordSlot = newOwnerWord;
    if (previousOwnerWord != 0u) {
      auto* const previousOwner = reinterpret_cast<ILegacyDeleteDispatchAtVtable4*>(previousOwnerWord);
      return reinterpret_cast<std::uint32_t*>(previousOwner->DeleteWithFlag(1));
    }
    return ownerWordSlot;
  }

  /**
   * Address: 0x007AE810 (FUN_007AE810)
   *
   * What it does:
   * Returns true when two lane-`+0x04` dwords differ.
   */
  [[maybe_unused]] bool IsLane04WordDifferent(
    const DwordPairLaneRuntimeView* const left,
    const DwordPairLaneRuntimeView* const right
  ) noexcept
  {
    return left->lane04 != right->lane04;
  }

  /**
   * Address: 0x00735C00 (FUN_00735C00)
   *
   * What it does:
   * Writes one dword from `*(source->lane04)` into output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDereferencedLane04WordA(
    std::uint32_t* const outValue,
    const PointerToWordAt04RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }

  /**
   * Address: 0x00736310 (FUN_00736310)
   *
   * What it does:
   * Stores one zero dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordA(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x00736360 (FUN_00736360)
   *
   * What it does:
   * Alias lane for writing one two-word lane from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromWordPointersB(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const firstSource,
    const std::uint32_t* const secondSource
  ) noexcept
  {
    return WriteDwordPairFromWordPointers(outValue, firstSource, secondSource);
  }

  /**
   * Address: 0x00736680 (FUN_00736680)
   *
   * What it does:
   * Alias lane for storing one zero dword.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordB(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x007366B0 (FUN_007366B0)
   *
   * What it does:
   * Writes one `{dword, byte}` lane from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointersAlias(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return WriteDwordBytePairFromPointers(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x00739AE0 (FUN_00739AE0)
   *
   * What it does:
   * Alias lane for writing one dword from `*(source->lane04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDereferencedLane04WordB(
    std::uint32_t* const outValue,
    const PointerToWordAt04RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }

  /**
   * Address: 0x00739B20 (FUN_00739B20)
   *
   * What it does:
   * Clears one two-word output lane to `{0,0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLane739B20(DwordPairRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x00739B90 (FUN_00739B90)
   *
   * What it does:
   * Alias lane for writing one dword from `*(source->lane04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDereferencedLane04WordC(
    std::uint32_t* const outValue,
    const PointerToWordAt04RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }

  [[nodiscard]] Float4LaneRuntimeView* CopyFloat4LaneIfOutputPresent(
    Float4LaneRuntimeView* const outValue,
    const Float4LaneRuntimeView* const source
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *source;
    }
    return outValue;
  }

  [[nodiscard]] Payload56RuntimeView* CopyPayload56IfOutputPresent(
    Payload56RuntimeView* const outValue,
    const Payload56RuntimeView* const source
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *source;
    }
    return outValue;
  }

  [[nodiscard]] Float4LaneRuntimeView* SwapFloat4LaneValues(
    Float4LaneRuntimeView* const left,
    Float4LaneRuntimeView* const right
  ) noexcept
  {
    const Float4LaneRuntimeView value = *right;
    *right = *left;
    *left = value;
    return left;
  }

  [[nodiscard]] std::uint32_t* RetreatAddressLaneByStride16(
    std::uint32_t* const addressLane
  ) noexcept
  {
    *addressLane -= 16u;
    return addressLane;
  }

  struct EightWordRuntimeView
  {
    std::uint32_t lanes[8];
  };
#if defined(_M_IX86)
  static_assert(sizeof(EightWordRuntimeView) == 0x20, "EightWordRuntimeView size must be 0x20");
#endif

  struct DwordPairFloat4Payload24RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    float lane08;         // +0x08
    float lane0C;         // +0x0C
    float lane10;         // +0x10
    float lane14;         // +0x14
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(DwordPairFloat4Payload24RuntimeView) == 0x18,
    "DwordPairFloat4Payload24RuntimeView size must be 0x18"
  );
  static_assert(
    offsetof(DwordPairFloat4Payload24RuntimeView, lane14) == 0x14,
    "DwordPairFloat4Payload24RuntimeView::lane14 offset must be 0x14"
  );
#endif

  struct DwordAndFloat7Payload32RuntimeView
  {
    std::uint32_t lane00; // +0x00
    float lane04;         // +0x04
    float lane08;         // +0x08
    float lane0C;         // +0x0C
    float lane10;         // +0x10
    float lane14;         // +0x14
    float lane18;         // +0x18
    float lane1C;         // +0x1C
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(DwordAndFloat7Payload32RuntimeView) == 0x20,
    "DwordAndFloat7Payload32RuntimeView size must be 0x20"
  );
  static_assert(
    offsetof(DwordAndFloat7Payload32RuntimeView, lane1C) == 0x1C,
    "DwordAndFloat7Payload32RuntimeView::lane1C offset must be 0x1C"
  );
#endif

  struct PointerWordSlotSpanRuntimeView
  {
    std::uint32_t** begin; // +0x00
    std::uint32_t** end;   // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(PointerWordSlotSpanRuntimeView) == 0x08, "PointerWordSlotSpanRuntimeView size must be 0x08");
#endif

  struct ByteSpanWithEndAt8RuntimeView
  {
    std::byte* begin;  // +0x00
    std::byte* lane04; // +0x04
    std::byte* end;    // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(ByteSpanWithEndAt8RuntimeView) == 0x0C, "ByteSpanWithEndAt8RuntimeView size must be 0x0C");
  static_assert(
    offsetof(ByteSpanWithEndAt8RuntimeView, end) == 0x08,
    "ByteSpanWithEndAt8RuntimeView::end offset must be 0x08"
  );
#endif

  struct InlineStorageAt38RuntimeView
  {
    std::byte pad00_2F[0x30];
    std::uint32_t lane30; // +0x30
    std::byte pad34_37[0x04];
    std::uint32_t lane38; // +0x38
    std::byte pad3C_4B[0x10];
    std::uint32_t length4C; // +0x4C
  };
#if defined(_M_IX86)
  static_assert(offsetof(InlineStorageAt38RuntimeView, lane30) == 0x30, "InlineStorageAt38RuntimeView::lane30 offset must be 0x30");
  static_assert(offsetof(InlineStorageAt38RuntimeView, lane38) == 0x38, "InlineStorageAt38RuntimeView::lane38 offset must be 0x38");
  static_assert(
    offsetof(InlineStorageAt38RuntimeView, length4C) == 0x4C,
    "InlineStorageAt38RuntimeView::length4C offset must be 0x4C"
  );
#endif

  struct ByteFlagAt108RuntimeView
  {
    std::byte pad00_107[0x108];
    std::uint8_t flag108; // +0x108
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteFlagAt108RuntimeView, flag108) == 0x108, "ByteFlagAt108RuntimeView::flag108 offset must be 0x108");
#endif

  struct PointerSlotSpanAt10RuntimeView
  {
    std::byte pad00_0F[0x10];
    const std::uint32_t* begin; // +0x10
    const std::uint32_t* end;   // +0x14
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerSlotSpanAt10RuntimeView, begin) == 0x10,
    "PointerSlotSpanAt10RuntimeView::begin offset must be 0x10"
  );
  static_assert(
    offsetof(PointerSlotSpanAt10RuntimeView, end) == 0x14,
    "PointerSlotSpanAt10RuntimeView::end offset must be 0x14"
  );
#endif

  /**
   * Address: 0x0071EC80 (FUN_0071EC80)
   *
   * What it does:
   * Alias lane for swapping one dword slot between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotsKappa(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  /**
   * Address: 0x0071ED70 (FUN_0071ED70)
   *
   * What it does:
   * Alias lane for copy-assigning one four-float payload.
   */
  [[maybe_unused]] Float4LaneRuntimeView* CopyFloat4LaneAliasB(
    Float4LaneRuntimeView* const outValue,
    const Float4LaneRuntimeView* const source
  ) noexcept
  {
    return CopyFloat4Lane(outValue, source);
  }

  /**
   * Address: 0x0071EDF0 (FUN_0071EDF0)
   *
   * What it does:
   * Copies one 56-byte payload when destination storage is non-null.
   */
  [[maybe_unused]] Payload56RuntimeView* CopyPayload56IfOutputPresentA(
    Payload56RuntimeView* const outValue,
    const Payload56RuntimeView* const source
  ) noexcept
  {
    return CopyPayload56IfOutputPresent(outValue, source);
  }

  /**
   * Address: 0x0071EE80 (FUN_0071EE80)
   *
   * What it does:
   * Copies one four-float payload when destination storage is non-null.
   */
  [[maybe_unused]] Float4LaneRuntimeView* CopyFloat4IfOutputPresentC(
    Float4LaneRuntimeView* const outValue,
    const Float4LaneRuntimeView* const source
  ) noexcept
  {
    return CopyFloat4LaneIfOutputPresent(outValue, source);
  }

  /**
   * Address: 0x0071F530 (FUN_0071F530)
   *
   * What it does:
   * Alias lane for backward-copying one 56-byte payload range.
   */
  [[maybe_unused]] Payload56RuntimeView* CopyPayload56RangeBackwardAliasA(
    Payload56RuntimeView* destEnd,
    Payload56RuntimeView* sourceEnd,
    Payload56RuntimeView* sourceBegin
  ) noexcept
  {
    return CopyPayload56RangeBackward(destEnd, sourceEnd, sourceBegin);
  }

  /**
   * Address: 0x0071F660 (FUN_0071F660)
   *
   * What it does:
   * Backward-copies one float4 range from `[sourceBegin, sourceEnd)` to
   * destination ending at `destEnd`.
   */
  [[maybe_unused]] Float4LaneRuntimeView* CopyFloat4RangeBackwardA(
    Float4LaneRuntimeView* destEnd,
    Float4LaneRuntimeView* sourceEnd,
    Float4LaneRuntimeView* sourceBegin
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destEnd;
      *destEnd = *sourceEnd;
    }
    return destEnd;
  }

  /**
   * Address: 0x0071F7D0 (FUN_0071F7D0)
   *
   * What it does:
   * Alias lane for copying one four-float payload when output is non-null.
   */
  [[maybe_unused]] Float4LaneRuntimeView* CopyFloat4IfOutputPresentD(
    Float4LaneRuntimeView* const outValue,
    const Float4LaneRuntimeView* const source
  ) noexcept
  {
    return CopyFloat4LaneIfOutputPresent(outValue, source);
  }

  /**
   * Address: 0x0071F800 (FUN_0071F800)
   *
   * What it does:
   * Stores one address lane and advances source address by 16 bytes.
   */
  [[maybe_unused]] std::uint32_t* StoreAddressLaneAndAdvanceByStride16(
    std::uint32_t* const outAddress,
    std::uint32_t* const sourceAddress
  ) noexcept
  {
    const std::uint32_t value = *sourceAddress;
    *outAddress = value;
    *sourceAddress = value + 16u;
    return outAddress;
  }

  /**
   * Address: 0x0071F810 (FUN_0071F810)
   *
   * What it does:
   * Moves one address lane backward by 16 bytes.
   */
  [[maybe_unused]] std::uint32_t* RetreatAddressLaneByStride16D(
    std::uint32_t* const addressLane
  ) noexcept
  {
    return RetreatAddressLaneByStride16(addressLane);
  }

  /**
   * Address: 0x0071F820 (FUN_0071F820)
   *
   * What it does:
   * Stores one `baseAddress - 16*count` lane into output.
   */
  [[maybe_unused]] std::uint32_t* StoreAddressLaneWithStride16Backstep(
    std::uint32_t* const outAddress,
    const std::uint32_t* const baseAddress,
    const std::int32_t count
  ) noexcept
  {
    *outAddress = *baseAddress - (static_cast<std::uint32_t>(count) * 16u);
    return outAddress;
  }

  /**
   * Address: 0x0071F840 (FUN_0071F840)
   *
   * What it does:
   * Writes one two-word lane from two input scalar slots.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromSlotsA(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const lane00Source,
    const std::uint32_t* const lane04Source
  ) noexcept
  {
    outValue->lane00 = *lane00Source;
    outValue->lane04 = *lane04Source;
    return outValue;
  }

  /**
   * Address: 0x0071F850 (FUN_0071F850)
   *
   * What it does:
   * Moves one address lane backward by `16 * count` bytes.
   */
  [[maybe_unused]] std::uint32_t* RetreatAddressLaneByStride16ScaledA(
    std::uint32_t* const addressLane,
    const std::int32_t count
  ) noexcept
  {
    *addressLane -= static_cast<std::uint32_t>(count) * 16u;
    return addressLane;
  }

  /**
   * Address: 0x0071F860 (FUN_0071F860)
   *
   * What it does:
   * Alias lane for moving one address lane backward by 16 bytes.
   */
  [[maybe_unused]] std::uint32_t* RetreatAddressLaneByStride16E(
    std::uint32_t* const addressLane
  ) noexcept
  {
    return RetreatAddressLaneByStride16(addressLane);
  }

  /**
   * Address: 0x0071F920 (FUN_0071F920)
   *
   * What it does:
   * Swaps two four-float payload lanes.
   */
  [[maybe_unused]] Float4LaneRuntimeView* SwapFloat4LanesA(
    Float4LaneRuntimeView* const left,
    Float4LaneRuntimeView* const right
  ) noexcept
  {
    return SwapFloat4LaneValues(left, right);
  }

  /**
   * Address: 0x0071FFD0 (FUN_0071FFD0)
   *
   * What it does:
   * Alias lane for swapping two four-float payload lanes.
   */
  [[maybe_unused]] Float4LaneRuntimeView* SwapFloat4LanesB(
    Float4LaneRuntimeView* const left,
    Float4LaneRuntimeView* const right
  ) noexcept
  {
    return SwapFloat4LaneValues(left, right);
  }

  /**
   * Address: 0x007204E0 (FUN_007204E0)
   *
   * What it does:
   * Clears one eight-dword lane block to zero.
   */
  [[maybe_unused]] EightWordRuntimeView* ClearEightDwordLaneBlockA(
    EightWordRuntimeView* const outValue
  ) noexcept
  {
    for (auto& lane : outValue->lanes) {
      lane = 0u;
    }
    return outValue;
  }

  /**
   * Address: 0x00722E70 (FUN_00722E70)
   *
   * What it does:
   * Alias lane for initializing one self-relative header with tail anchor
   * at `self + 0x60`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockTail60RuntimeView* InitializeSelfRelativeLaneBlockTail60AliasA(
    SelfRelativeLaneBlockTail60RuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeLaneBlockTail60(self);
  }

  /**
   * Address: 0x00723000 (FUN_00723000)
   *
   * What it does:
   * Copy-assigns one 24-byte payload lane (`2 dwords + 4 floats`).
   */
  [[maybe_unused]] DwordPairFloat4Payload24RuntimeView* CopyPayload24LaneA(
    DwordPairFloat4Payload24RuntimeView* const outValue,
    const DwordPairFloat4Payload24RuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00723030 (FUN_00723030)
   *
   * What it does:
   * Copy-assigns one 32-byte payload lane (`1 dword + 7 floats`).
   */
  [[maybe_unused]] DwordAndFloat7Payload32RuntimeView* CopyPayload32LaneA(
    DwordAndFloat7Payload32RuntimeView* const outValue,
    const DwordAndFloat7Payload32RuntimeView* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00723060 (FUN_00723060)
   *
   * What it does:
   * Re-bases every pointer slot in one `[begin,end)` span by subtracting 76.
   * Returns number of adjusted slots.
   */
  [[maybe_unused]] std::int32_t RebasePointerWordSlotsByMinus76(
    PointerWordSlotSpanRuntimeView* const span
  ) noexcept
  {
    const std::intptr_t byteDelta =
      reinterpret_cast<std::intptr_t>(span->end) - reinterpret_cast<std::intptr_t>(span->begin);
    const std::int32_t slotCount = static_cast<std::int32_t>(byteDelta >> 2);
    if (slotCount <= 0) {
      return 0;
    }

    std::int32_t adjusted = 0;
    while (adjusted < slotCount) {
      std::uint32_t* const pointerWord = span->begin[adjusted];
      span->begin[adjusted] = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<std::uintptr_t>(pointerWord) - 76u
      );
      ++adjusted;
    }
    return adjusted;
  }

  /**
   * Address: 0x00723320 (FUN_00723320)
   *
   * What it does:
   * Returns 24-byte element count from one begin/end-at-`+0x08` span.
   */
  [[maybe_unused]] std::int32_t CountStride24ElementsFromSpanAt0And8(
    const ByteSpanWithEndAt8RuntimeView* const span
  ) noexcept
  {
    const std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(span->begin);
    const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(span->end);
    return static_cast<std::int32_t>((end - begin) / 24u);
  }

  /**
   * Address: 0x00723460 (FUN_00723460)
   *
   * What it does:
   * Returns 32-byte element count from one begin/end-at-`+0x08` span.
   */
  [[maybe_unused]] std::int32_t CountStride32ElementsFromSpanAt0And8(
    const ByteSpanWithEndAt8RuntimeView* const span
  ) noexcept
  {
    const std::uintptr_t begin = reinterpret_cast<std::uintptr_t>(span->begin);
    const std::uintptr_t end = reinterpret_cast<std::uintptr_t>(span->end);
    return static_cast<std::int32_t>((end - begin) >> 5u);
  }

  /**
   * Address: 0x00723930 (FUN_00723930)
   *
   * What it does:
   * Alias lane for copy-assigning one 24-byte payload.
   */
  [[maybe_unused]] DwordPairFloat4Payload24RuntimeView* CopyPayload24LaneB(
    DwordPairFloat4Payload24RuntimeView* const outValue,
    const DwordPairFloat4Payload24RuntimeView* const source
  ) noexcept
  {
    return CopyPayload24LaneA(outValue, source);
  }

  /**
   * Address: 0x00723960 (FUN_00723960)
   *
   * What it does:
   * Alias lane for copy-assigning one 32-byte payload.
   */
  [[maybe_unused]] DwordAndFloat7Payload32RuntimeView* CopyPayload32LaneB(
    DwordAndFloat7Payload32RuntimeView* const outValue,
    const DwordAndFloat7Payload32RuntimeView* const source
  ) noexcept
  {
    return CopyPayload32LaneA(outValue, source);
  }

  /**
   * Address: 0x00723A40 (FUN_00723A40)
   *
   * What it does:
   * Returns inline-storage address `+0x38` when length `+0x4C < 16`,
   * otherwise returns heap pointer lane `+0x38`.
   */
  [[maybe_unused]] std::uint32_t ResolveStoragePointerAt38(
    const InlineStorageAt38RuntimeView* const source
  ) noexcept
  {
    if (source->length4C < 16u) {
      return reinterpret_cast<std::uint32_t>(const_cast<std::uint32_t*>(&source->lane38));
    }
    return source->lane38;
  }

  /**
   * Address: 0x00723A70 (FUN_00723A70)
   *
   * What it does:
   * Reads one dword lane from offset `+0x30`.
   */
  [[maybe_unused]] std::uint32_t ReadWordAt30FromInlineStorageBlock(
    const InlineStorageAt38RuntimeView* const source
  ) noexcept
  {
    return source->lane30;
  }

  /**
   * Address: 0x00723B00 (FUN_00723B00)
   *
   * What it does:
   * Stores one byte flag into offset `+0x108`.
   */
  [[maybe_unused]] ByteFlagAt108RuntimeView* WriteFlagByteAt108(
    ByteFlagAt108RuntimeView* const outValue,
    const std::uint8_t flag
  ) noexcept
  {
    outValue->flag108 = flag;
    return outValue;
  }

  /**
   * Address: 0x00724120 (FUN_00724120)
   *
   * What it does:
   * Scans one pointer-slot span at `(+0x10,+0x14)` and returns true when
   * any slot resolves to `targetWord` after applying `slotValue ? slotValue-8 : 0`.
   */
  [[maybe_unused]] bool ContainsPointerMinus8InSlotSpan(
    const PointerSlotSpanAt10RuntimeView* const span,
    const std::uint32_t targetWord
  ) noexcept
  {
    for (const std::uint32_t* slot = span->begin; slot != span->end; ++slot) {
      const std::uint32_t slotValue = *slot;
      const std::uint32_t adjusted = slotValue != 0u ? slotValue - 8u : 0u;
      if (adjusted == targetWord) {
        return true;
      }
    }
    return false;
  }

  /**
   * Address: 0x007244D0 (FUN_007244D0)
   *
   * What it does:
   * Returns dword-slot count from pointer-span lanes `(+0x10,+0x14)`.
   */
  [[maybe_unused]] std::int32_t CountDwordSlotsInSpanAt10And14(
    const PointerSlotSpanAt10RuntimeView* const span
  ) noexcept
  {
    return static_cast<std::int32_t>(span->end - span->begin);
  }

  struct PointerToPointerAt04RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t** lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerToPointerAt04RuntimeView, lane04) == 0x04,
    "PointerToPointerAt04RuntimeView::lane04 offset must be 0x04"
  );
  static_assert(sizeof(PointerToPointerAt04RuntimeView) == 0x08, "PointerToPointerAt04RuntimeView size must be 0x08");
#endif

  struct DimensionsAt4And8RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t width;  // +0x04
    std::uint32_t height; // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(DimensionsAt4And8RuntimeView, width) == 0x04, "DimensionsAt4And8RuntimeView::width offset must be 0x04");
  static_assert(offsetof(DimensionsAt4And8RuntimeView, height) == 0x08, "DimensionsAt4And8RuntimeView::height offset must be 0x08");
#endif

  struct PointerToDimensionsPointerAt04RuntimeView
  {
    std::uint32_t lane00;                  // +0x00
    DimensionsAt4And8RuntimeView** lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerToDimensionsPointerAt04RuntimeView, lane04) == 0x04,
    "PointerToDimensionsPointerAt04RuntimeView::lane04 offset must be 0x04"
  );
#endif

  /**
   * Address: 0x0089E6E0 (FUN_0089E6E0)
   *
   * What it does:
   * Initializes one bounds quad as `{0, 0, width - 1, height - 1}` from the
   * nested dimensions pointer at lane `**(+0x04)`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeBoundsQuadFromNestedDimensionsMinusOne(
    DwordQuadRuntimeView* const outValue,
    const PointerToDimensionsPointerAt04RuntimeView* const source
  ) noexcept
  {
    const DimensionsAt4And8RuntimeView* const dimensions = *source->lane04;
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = dimensions->width - 1u;
    outValue->lane0C = dimensions->height - 1u;
    return outValue;
  }

  /**
   * Address: 0x006ADF40 (FUN_006ADF40)
   *
   * What it does:
   * Computes one `*baseWord + index * 20` byte-offset lane and stores it.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride20AliasA(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride20(outValue, baseWord, index);
  }

  /**
   * Address: 0x006ADF60 (FUN_006ADF60)
   *
   * What it does:
   * Initializes one intrusive two-link lane to singleton self-links.
   */
  [[maybe_unused]] std::uint32_t* InitializeTwoWordSelfLinkAliasA(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x006AEBE0 (FUN_006AEBE0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesJ(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AECC0 (FUN_006AECC0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesK(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AECD0 (FUN_006AECD0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesL(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AECE0 (FUN_006AECE0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesM(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AECF0 (FUN_006AECF0)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesN(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED00 (FUN_006AED00)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesO(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED10 (FUN_006AED10)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesP(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED20 (FUN_006AED20)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesQ(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED30 (FUN_006AED30)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesR(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED40 (FUN_006AED40)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesS(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED50 (FUN_006AED50)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesT(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AED60 (FUN_006AED60)
   *
   * What it does:
   * Alias lane for swapping one dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotValuesU(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x006AF030 (FUN_006AF030)
   *
   * What it does:
   * Alias lane for initializing one intrusive two-link lane to self-links.
   */
  [[maybe_unused]] std::uint32_t* InitializeTwoWordSelfLinkAliasB(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x006AF040 (FUN_006AF040)
   *
   * What it does:
   * Unlinks one intrusive node from its ring and restores singleton
   * self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfLambda(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x006AF060 (FUN_006AF060)
   *
   * What it does:
   * Unlinks one intrusive node from its current ring, then inserts it
   * directly after `anchor`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkIntrusiveNodeAfterAnchor(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const detached = UnlinkIntrusiveNodeAndSelfLink(node);
    detached->next = anchor->next;
    detached->prev = anchor;
    anchor->next = detached;
    detached->next->prev = detached;
    return detached;
  }

  /**
   * Address: 0x006AF1A0 (FUN_006AF1A0)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=2)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount2(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 2, baseAddress);
  }

  /**
   * Address: 0x006AF820 (FUN_006AF820)
   * Address: 0x00899C80 (FUN_00899C80)
   * Address: 0x008A7D90 (FUN_008A7D90)
   * Address: 0x008A7DA0 (FUN_008A7DA0)
   *
   * What it does:
   * Writes one dword from `**(source->lane04)` into output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordA(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    *outValue = **source->lane04;
    return outValue;
  }

  /**
   * Address: 0x006AF830 (FUN_006AF830)
   *
   * What it does:
   * Alias lane for writing one dword from `**(source->lane04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordB(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x006AFDD0 (FUN_006AFDD0)
   *
   * What it does:
   * Alias lane for storing one zero dword.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordC(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x006B02C0 (FUN_006B02C0)
   *
   * What it does:
   * Alias lane for storing one zero dword.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordD(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x006B0340 (FUN_006B0340)
   *
   * What it does:
   * Alias lane for writing one `{dword, byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointersLaneB(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return WriteDwordBytePairFromPointers(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x006B03C0 (FUN_006B03C0)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasA(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x006B6F50 (FUN_006B6F50)
   *
   * What it does:
   * Alias lane for storing one zero dword.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordE(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x006BA390 (FUN_006BA390)
   *
   * What it does:
   * Initializes one self-relative span header with tail anchor at `+0x60`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail60(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x60u);
  }

  /**
   * Address: 0x006C0C90 (FUN_006C0C90)
   *
   * What it does:
   * Initializes one self-relative span header with tail anchor at `+0x90`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail90A(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x90u);
  }

  /**
   * Address: 0x006C0CE0 (FUN_006C0CE0)
   *
   * What it does:
   * Alias lane for initializing one self-relative span header at tail
   * `+0x90`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail90B(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x90u);
  }

  /**
   * Address: 0x006C0D90 (FUN_006C0D90)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=32)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount32A(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 32, baseAddress);
  }

  /**
   * Address: 0x006C0EB0 (FUN_006C0EB0)
   *
   * What it does:
   * Alias lane for initializing one external dword-span header with
   * `(base, count=32)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount32B(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 32, baseAddress);
  }

  struct TreeNodeFlagAt11RuntimeView
  {
    TreeNodeFlagAt11RuntimeView* left;         // +0x00
    TreeNodeFlagAt11RuntimeView* parentOrRoot; // +0x04
    TreeNodeFlagAt11RuntimeView* right;        // +0x08
    std::uint32_t key;                         // +0x0C
    std::byte pad10[0x01];
    std::uint8_t isSentinel;                   // +0x11
  };
#if defined(_M_IX86)
  static_assert(offsetof(TreeNodeFlagAt11RuntimeView, key) == 0x0C, "TreeNodeFlagAt11RuntimeView::key offset must be 0x0C");
  static_assert(
    offsetof(TreeNodeFlagAt11RuntimeView, isSentinel) == 0x11,
    "TreeNodeFlagAt11RuntimeView::isSentinel offset must be 0x11"
  );
#endif

  struct TreeNodeFlag11InitRuntimeView
  {
    std::uint32_t lane00;    // +0x00
    std::uint32_t lane04;    // +0x04
    std::uint32_t lane08;    // +0x08
    std::uint32_t key;       // +0x0C
    std::uint8_t lane10;     // +0x10
    std::uint8_t isSentinel; // +0x11
  };
#if defined(_M_IX86)
  static_assert(offsetof(TreeNodeFlag11InitRuntimeView, key) == 0x0C, "TreeNodeFlag11InitRuntimeView::key offset must be 0x0C");
  static_assert(
    offsetof(TreeNodeFlag11InitRuntimeView, isSentinel) == 0x11,
    "TreeNodeFlag11InitRuntimeView::isSentinel offset must be 0x11"
  );
#endif

  [[nodiscard]] std::uint32_t* StoreStride144AddressLane(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseAddress + (static_cast<std::uint32_t>(index) * 144u);
    return outValue;
  }

  [[nodiscard]] std::int32_t ComputeStride144IndexFromPointerDelta(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((*lhsAddress - *rhsAddress) / 144u);
  }

  template <typename NodeT>
  [[nodiscard]] NodeT* FindUpperBoundTreeNode(
    NodeT* const header,
    const std::uint32_t key
  ) noexcept
  {
    NodeT* candidate = header;
    NodeT* cursor = candidate->parentOrRoot;
    while (cursor->isSentinel == 0u) {
      if (key >= cursor->key) {
        cursor = cursor->right;
      } else {
        candidate = cursor;
        cursor = cursor->left;
      }
    }
    return candidate;
  }

  [[nodiscard]] float MinOfFourFloatLanes(
    const float lane0,
    float lane1,
    const float lane2,
    const float lane3
  ) noexcept
  {
    if (lane0 <= lane1) {
      lane1 = lane0;
    }

    float result = lane3;
    if (lane3 > lane2) {
      result = lane2;
    }
    if (lane1 <= result) {
      return lane1;
    }
    return result;
  }

  [[nodiscard]] float MaxOfFourFloatLanes(
    const float lane0,
    float lane1,
    const float lane2,
    const float lane3
  ) noexcept
  {
    if (lane0 > lane1) {
      lane1 = lane0;
    }

    float result = lane3;
    if (lane2 > lane3) {
      result = lane2;
    }
    if (lane1 > result) {
      return lane1;
    }
    return result;
  }

  [[nodiscard]] DwordTripleRuntimeView* SwapDwordTailPairLanes(
    DwordTripleRuntimeView* const left,
    DwordTripleRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t lane04 = right->lane04;
    right->lane04 = left->lane04;
    left->lane04 = lane04;

    const std::uint32_t lane08 = right->lane08;
    right->lane08 = left->lane08;
    left->lane08 = lane08;
    return left;
  }

  /**
   * Address: 0x0077C920 (FUN_0077C920)
   *
   * What it does:
   * Stores one `base + index * 144` byte address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreStride144AddressLaneA(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseAddress,
    const std::int32_t index
  ) noexcept
  {
    return StoreStride144AddressLane(outValue, baseAddress, index);
  }

  /**
   * Address: 0x0077C930 (FUN_0077C930)
   *
   * What it does:
   * Returns 144-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride144IndexFromPointerDeltaA(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return ComputeStride144IndexFromPointerDelta(lhsAddress, rhsAddress);
  }

  /**
   * Address: 0x0077C950 (FUN_0077C950)
   *
   * What it does:
   * Writes one dword from `**(source->lane04)` into output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordC(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x0077CA20 (FUN_0077CA20)
   *
   * What it does:
   * Writes one two-word lane from two source-word slots.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromSlotsB(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const lane00Source,
    const std::uint32_t* const lane04Source
  ) noexcept
  {
    return WriteDwordPairFromSlotsA(outValue, lane00Source, lane04Source);
  }

  /**
   * Address: 0x0077CA30 (FUN_0077CA30)
   *
   * What it does:
   * Returns one stored address lane advanced by 8 bytes.
   */
  [[maybe_unused]] std::uint32_t ReadAddressLanePlus8(
    const std::uint32_t* const addressLane
  ) noexcept
  {
    return *addressLane + 8u;
  }

  /**
   * Address: 0x0077CA40 (FUN_0077CA40)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to the current node-head dword.
   */
  [[maybe_unused]] std::uint32_t** AdvancePointerSlotTertiary(std::uint32_t** const pointerSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x0077CC60 (FUN_0077CC60)
   *
   * What it does:
   * Returns lower-bound node pointer for one key in a tree with sentinel flag
   * at `+0x11`.
   */
  [[maybe_unused]] TreeNodeFlagAt11RuntimeView* LowerBoundTreeNodeFlag11(
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt11RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    return FindLowerBoundTreeNode(tree->header, *key);
  }

  /**
   * Address: 0x0077CCD0 (FUN_0077CCD0)
   *
   * What it does:
   * Returns upper-bound node pointer for one key in a tree with sentinel flag
   * at `+0x11`.
   */
  [[maybe_unused]] TreeNodeFlagAt11RuntimeView* UpperBoundTreeNodeFlag11(
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt11RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    return FindUpperBoundTreeNode(tree->header, *key);
  }

  /**
   * Address: 0x0077CDE0 (FUN_0077CDE0)
   *
   * What it does:
   * Initializes one tree node lane block (`+0x00..+0x11`) with key, links,
   * one state byte, and clears sentinel byte.
   */
  [[maybe_unused]] TreeNodeFlag11InitRuntimeView* InitializeTreeNodeFlag11FromLanes(
    TreeNodeFlag11InitRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00,
    const std::uint32_t lane08,
    const std::uint32_t* const keySource,
    const std::uint8_t lane10
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->key = *keySource;
    outValue->lane10 = lane10;
    outValue->isSentinel = 0u;
    return outValue;
  }

  /**
   * Address: 0x0077CE20 (FUN_0077CE20)
   *
   * What it does:
   * Alias lane for storing one zero dword.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDwordF(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x0077CEA0 (FUN_0077CEA0)
   *
   * What it does:
   * Advances one stored address lane by `index * 144`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride144A(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane += static_cast<std::uint32_t>(index) * 144u;
    return addressLane;
  }

  /**
   * Address: 0x0077CEB0 (FUN_0077CEB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDword77A(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0077CEC0 (FUN_0077CEC0)
   *
   * What it does:
   * Alias lane for 144-byte index delta between two address lanes.
   */
  [[maybe_unused]] std::int32_t ComputeStride144IndexFromPointerDeltaB(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return ComputeStride144IndexFromPointerDelta(lhsAddress, rhsAddress);
  }

  /**
   * Address: 0x0077CFB0 (FUN_0077CFB0)
   *
   * What it does:
   * Writes one `{dword, byte}` lane from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* WriteDwordBytePairFromPointersLaneC(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return WriteDwordBytePairFromPointers(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0077CFC0 (FUN_0077CFC0)
   *
   * What it does:
   * Alias lane for storing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDword77B(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDword77A(outValue, value);
  }

  /**
   * Address: 0x0077D070 (FUN_0077D070)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasB(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077D150 (FUN_0077D150)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasC(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077D1C0 (FUN_0077D1C0)
   *
   * What it does:
   * Alias lane for advancing one stored address lane by `index * 144`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride144B(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceAddressLaneByStride144A(addressLane, index);
  }

  /**
   * Address: 0x0077D330 (FUN_0077D330)
   *
   * What it does:
   * Alias lane for storing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDword77C(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDword77A(outValue, value);
  }

  /**
   * Address: 0x0077D3F0 (FUN_0077D3F0)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasD(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077D410 (FUN_0077D410)
   *
   * What it does:
   * Returns the minimum scalar across four float lanes.
   */
  [[maybe_unused]] float MinOfFourFloatLanesA(
    const float lane0,
    const float lane1,
    const float lane2,
    const float lane3
  ) noexcept
  {
    return MinOfFourFloatLanes(lane0, lane1, lane2, lane3);
  }

  /**
   * Address: 0x0077D430 (FUN_0077D430)
   *
   * What it does:
   * Returns the maximum scalar across four float lanes.
   */
  [[maybe_unused]] float MaxOfFourFloatLanesA(
    const float lane0,
    const float lane1,
    const float lane2,
    const float lane3
  ) noexcept
  {
    return MaxOfFourFloatLanes(lane0, lane1, lane2, lane3);
  }

  /**
   * Address: 0x0077D6D0 (FUN_0077D6D0)
   *
   * What it does:
   * Swaps dword lanes `+0x04/+0x08` between two triple-lane records.
   */
  [[maybe_unused]] DwordTripleRuntimeView* SwapDwordTailPairLanesA(
    DwordTripleRuntimeView* const left,
    DwordTripleRuntimeView* const right
  ) noexcept
  {
    return SwapDwordTailPairLanes(left, right);
  }

  /**
   * Address: 0x0077D6F0 (FUN_0077D6F0)
   *
   * What it does:
   * Swaps dword tail lanes `(+0x04,+0x08,+0x0C)` between two quad lanes.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesG(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    return SwapDwordQuadTailLanesC(left, right);
  }

  /**
   * Address: 0x0077DC90 (FUN_0077DC90)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasE(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077DCB0 (FUN_0077DCB0)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasF(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077DD60 (FUN_0077DD60)
   *
   * What it does:
   * Alias lane for copying one source dword into output when output is
   * non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentAliasG(
    std::uint32_t* const output,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopySourceWordIfOutputPresent(output, sourceWord);
  }

  /**
   * Address: 0x0077DED0 (FUN_0077DED0)
   *
   * What it does:
   * Alias lane for swapping dword tail lanes `(+0x04,+0x08,+0x0C)` between
   * two quad lanes.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanesH(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    return SwapDwordQuadTailLanesC(left, right);
  }

  /**
   * Address: 0x0077DF60 (FUN_0077DF60)
   *
   * What it does:
   * Alias lane for swapping dword lanes `+0x04/+0x08` between two triple-lane
   * records.
   */
  [[maybe_unused]] DwordTripleRuntimeView* SwapDwordTailPairLanesB(
    DwordTripleRuntimeView* const left,
    DwordTripleRuntimeView* const right
  ) noexcept
  {
    return SwapDwordTailPairLanes(left, right);
  }

  /**
   * Address: 0x0077E870 (FUN_0077E870)
   *
   * What it does:
   * Alias lane for swapping one dword slot between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotsLambda(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  struct DwordSpanStateRuntimeView
  {
    std::uint32_t begin;  // +0x00
    std::uint32_t cursor; // +0x04
    std::uint32_t end;    // +0x08
  };
#if defined(_M_IX86)
  static_assert(sizeof(DwordSpanStateRuntimeView) == 0x0C, "DwordSpanStateRuntimeView size must be 0x0C");
  static_assert(offsetof(DwordSpanStateRuntimeView, cursor) == 0x04, "DwordSpanStateRuntimeView::cursor offset must be 0x04");
  static_assert(offsetof(DwordSpanStateRuntimeView, end) == 0x08, "DwordSpanStateRuntimeView::end offset must be 0x08");
#endif

  struct PointerToSpanStateAt10RuntimeView
  {
    std::byte pad00_0F[0x10];
    DwordSpanStateRuntimeView* span; // +0x10
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerToSpanStateAt10RuntimeView, span) == 0x10,
    "PointerToSpanStateAt10RuntimeView::span offset must be 0x10"
  );
#endif

  struct FourWordAndSelfPointerRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    FourWordAndSelfPointerRuntimeView* lane10; // +0x10
  };
#if defined(_M_IX86)
  static_assert(sizeof(FourWordAndSelfPointerRuntimeView) == 0x14, "FourWordAndSelfPointerRuntimeView size must be 0x14");
  static_assert(
    offsetof(FourWordAndSelfPointerRuntimeView, lane10) == 0x10,
    "FourWordAndSelfPointerRuntimeView::lane10 offset must be 0x10"
  );
#endif

  struct FourWordAndSpanPointerRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    DwordSpanStateRuntimeView* span; // +0x10
  };
#if defined(_M_IX86)
  static_assert(sizeof(FourWordAndSpanPointerRuntimeView) == 0x14, "FourWordAndSpanPointerRuntimeView size must be 0x14");
  static_assert(
    offsetof(FourWordAndSpanPointerRuntimeView, span) == 0x10,
    "FourWordAndSpanPointerRuntimeView::span offset must be 0x10"
  );
#endif

  [[nodiscard]] std::int32_t FillCountWithSourceWordCore(
    std::uint32_t count,
    const std::uint32_t* const sourceWord,
    std::uint32_t* destination
  ) noexcept
  {
    while (count != 0u) {
      *destination = *sourceWord;
      ++destination;
      --count;
    }
    return static_cast<std::int32_t>(count);
  }

  [[nodiscard]] std::uint32_t* CopyDwordRangeForwardCore(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  [[nodiscard]] std::uint32_t* CopyDwordRangeBackwardCore(
    std::uint32_t* destinationEnd,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      *destinationEnd = *sourceEnd;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x007A62A0 (FUN_007A62A0)
   *
   * What it does:
   * Computes one `baseAddress + index * 4` byte address.
   */
  [[nodiscard]] std::uint32_t StoreStride4AddressCore(
    const std::uint32_t baseAddress,
    const std::int32_t index
  ) noexcept
  {
    return baseAddress + (static_cast<std::uint32_t>(index) * 4u);
  }

  [[nodiscard]] std::int32_t ComputeStride4IndexDeltaCore(
    const std::uint32_t lhsAddress,
    const std::uint32_t rhsAddress
  ) noexcept
  {
    return static_cast<std::int32_t>((lhsAddress - rhsAddress) >> 2u);
  }

  /**
   * Address: 0x0078B360 (FUN_0078B360)
   *
   * What it does:
   * Fills `count` dword lanes in destination from one source-word slot.
   * Returns zero after the count is exhausted.
   */
  [[maybe_unused]] std::int32_t FillDwordCountFromSourceWordA(
    const std::uint32_t count,
    const std::uint32_t* const sourceWord,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillCountWithSourceWordCore(count, sourceWord, destination);
  }

  /**
   * Address: 0x0078B3C0 (FUN_0078B3C0)
   *
   * What it does:
   * Fills one `[begin,end)` dword range from a single source-word value.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanByEndFromSourceWord78A(
    std::uint32_t* const begin,
    std::uint32_t* const end,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return FillDwordSpanByEnd(begin, end, sourceWord);
  }

  /**
   * Address: 0x0078B410 (FUN_0078B410)
   *
   * What it does:
   * Initializes one five-lane header with zeroed first three lanes, caller
   * lane at `+0x0C`, and self pointer at `+0x10`.
   */
  [[maybe_unused]] FourWordAndSelfPointerRuntimeView* InitializeFourWordHeaderWithSelfPointer(
    FourWordAndSelfPointerRuntimeView* const outValue,
    const std::uint32_t lane0C
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = lane0C;
    outValue->lane10 = outValue;
    return outValue;
  }

  /**
   * Address: 0x0078B460 (FUN_0078B460)
   *
   * What it does:
   * Advances one index lane by stride-4 element distance between two
   * addresses.
   */
  [[maybe_unused]] std::uint32_t* AdvanceIndexLaneByStride4AddressDeltaA(
    std::uint32_t* const indexLane,
    const std::uint32_t beginAddress,
    const std::uint32_t endAddress
  ) noexcept
  {
    *indexLane += static_cast<std::uint32_t>(ComputeStride4IndexDeltaCore(endAddress, beginAddress));
    return indexLane;
  }

  /**
   * Address: 0x0078B530 (FUN_0078B530)
   *
   * What it does:
   * Alias lane for count-based dword fill from one source-word slot.
   */
  [[maybe_unused]] std::int32_t FillDwordCountFromSourceWordB(
    const std::uint32_t count,
    const std::uint32_t* const sourceWord,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillCountWithSourceWordCore(count, sourceWord, destination);
  }

  /**
   * Address: 0x0078B630 (FUN_0078B630)
   *
   * What it does:
   * Alias lane for advancing one index lane by stride-4 address delta.
   */
  [[maybe_unused]] std::uint32_t* AdvanceIndexLaneByStride4AddressDeltaB(
    std::uint32_t* const indexLane,
    const std::uint32_t beginAddress,
    const std::uint32_t endAddress
  ) noexcept
  {
    return AdvanceIndexLaneByStride4AddressDeltaA(indexLane, beginAddress, endAddress);
  }

  /**
   * Address: 0x0078B6D0 (FUN_0078B6D0)
   *
   * What it does:
   * Advances one address lane by `index * 4`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride4A(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    *addressLane = StoreStride4AddressCore(*addressLane, index);
    return addressLane;
  }

  /**
   * Address: 0x0078BA10 (FUN_0078BA10)
   *
   * What it does:
   * Alias lane for count-based dword fill from one source-word slot.
   */
  [[maybe_unused]] std::int32_t FillDwordCountFromSourceWordC(
    const std::uint32_t count,
    const std::uint32_t* const sourceWord,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillCountWithSourceWordCore(count, sourceWord, destination);
  }

  /**
   * Address: 0x0078BAE0 (FUN_0078BAE0)
   *
   * What it does:
   * Stores zero to one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDword78A(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x0078BB00 (FUN_0078BB00)
   *
   * What it does:
   * Advances one address lane by 4 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneBy4A(std::uint32_t* const addressLane) noexcept
  {
    *addressLane += 4u;
    return addressLane;
  }

  /**
   * Address: 0x0078BB10 (FUN_0078BB10)
   *
   * What it does:
   * Retreats one address lane by 4 bytes.
   */
  [[maybe_unused]] std::uint32_t* RetreatAddressLaneBy4A(std::uint32_t* const addressLane) noexcept
  {
    *addressLane -= 4u;
    return addressLane;
  }

  /**
   * Address: 0x0078BB20 (FUN_0078BB20)
   *
   * What it does:
   * Initializes one five-lane header with zeroed first four lanes and copies
   * span pointer lane `+0x10` from source.
   */
  [[maybe_unused]] FourWordAndSpanPointerRuntimeView* InitializeFourWordHeaderWithCopiedSpanPointer(
    FourWordAndSpanPointerRuntimeView* const outValue,
    const PointerToSpanStateAt10RuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    outValue->span = source->span;
    return outValue;
  }

  /**
   * Address: 0x0078BB50 (FUN_0078BB50)
   *
   * What it does:
   * Reads begin lane (`+0x00`) from the span object referenced by lane `+0x10`.
   */
  [[maybe_unused]] std::uint32_t ReadSpanBeginFromLane10(
    const PointerToSpanStateAt10RuntimeView* const source
  ) noexcept
  {
    return source->span->begin;
  }

  /**
   * Address: 0x0078BB60 (FUN_0078BB60)
   *
   * What it does:
   * Reads cursor lane (`+0x04`) from the span object referenced by lane `+0x10`.
   */
  [[maybe_unused]] std::uint32_t ReadSpanCursorFromLane10(
    const PointerToSpanStateAt10RuntimeView* const source
  ) noexcept
  {
    return source->span->cursor;
  }

  /**
   * Address: 0x0078BB70 (FUN_0078BB70)
   *
   * What it does:
   * Alias lane for writing one two-word payload from source-word slots.
   */
  [[maybe_unused]] DwordPairRuntimeView* WriteDwordPairFromSlotsC(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const lane00Source,
    const std::uint32_t* const lane04Source
  ) noexcept
  {
    return WriteDwordPairFromSlotsA(outValue, lane00Source, lane04Source);
  }

  /**
   * Address: 0x0078BB80 (FUN_0078BB80)
   *
   * What it does:
   * Alias lane for storing zero to one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroDword78B(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x0078BBA0 (FUN_0078BBA0)
   *
   * What it does:
   * Alias lane for advancing one address lane by 4 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneBy4B(std::uint32_t* const addressLane) noexcept
  {
    return AdvanceAddressLaneBy4A(addressLane);
  }

  /**
   * Address: 0x0078BBB0 (FUN_0078BBB0)
   *
   * What it does:
   * Alias lane for retreating one address lane by 4 bytes.
   */
  [[maybe_unused]] std::uint32_t* RetreatAddressLaneBy4B(std::uint32_t* const addressLane) noexcept
  {
    return RetreatAddressLaneBy4A(addressLane);
  }

  /**
   * Address: 0x0078BBC0 (FUN_0078BBC0)
   *
   * What it does:
   * Copies span pointer lane `+0x10` from source to destination.
   */
  [[maybe_unused]] FourWordAndSpanPointerRuntimeView* CopySpanPointerLane10(
    FourWordAndSpanPointerRuntimeView* const destination,
    const PointerToSpanStateAt10RuntimeView* const source
  ) noexcept
  {
    destination->span = source->span;
    return destination;
  }

  /**
   * Address: 0x0078BC00 (FUN_0078BC00)
   *
   * What it does:
   * Alias lane for advancing one address lane by `index * 4`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride4B(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceAddressLaneByStride4A(addressLane, index);
  }

  /**
   * Address: 0x0078BCA0 (FUN_0078BCA0)
   *
   * What it does:
   * Alias lane for swapping one dword slot between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotsMu(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  /**
   * Address: 0x0078BF90 (FUN_0078BF90)
   *
   * What it does:
   * Alias lane for count-based dword fill from one source-word slot.
   */
  [[maybe_unused]] std::int32_t FillDwordCountFromSourceWordD(
    const std::uint32_t count,
    const std::uint32_t* const sourceWord,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillCountWithSourceWordCore(count, sourceWord, destination);
  }

  /**
   * Address: 0x0078C1C0 (FUN_0078C1C0)
   *
   * What it does:
   * Alias lane for swapping one dword slot between two pointers.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlotsNu(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  /**
   * Address: 0x0078C420 (FUN_0078C420)
   *
   * What it does:
   * Forward-copies one dword range `[sourceBegin, sourceEnd)` into destination
   * and stores resulting destination end address.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForwardStoreEndA(
    std::uint32_t* const outEndAddress,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    const std::uint32_t* const result = CopyDwordRangeForwardCore(destination, sourceBegin, sourceEnd);
    *outEndAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    return outEndAddress;
  }

  /**
   * Address: 0x0078C450 (FUN_0078C450)
   *
   * What it does:
   * Backward-copies one dword range `[sourceBegin, sourceEnd)` into destination
   * ending at `destinationEnd` and stores resulting destination begin address.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardStoreBeginA(
    std::uint32_t* const outBeginAddress,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationEnd
  ) noexcept
  {
    const std::uint32_t* const result = CopyDwordRangeBackwardCore(destinationEnd, sourceBegin, sourceEnd);
    *outBeginAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(result));
    return outBeginAddress;
  }

  /**
   * Address: 0x0078C480 (FUN_0078C480)
   *
   * What it does:
   * Alias lane for backward-copying one dword range and storing resulting
   * destination begin address.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeBackwardStoreBeginB(
    std::uint32_t* const outBeginAddress,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationEnd
  ) noexcept
  {
    return CopyDwordRangeBackwardStoreBeginA(outBeginAddress, sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x0078C4B0 (FUN_0078C4B0)
   *
   * What it does:
   * Alias lane for forward-copying one dword range and storing destination end.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForwardStoreEndB(
    std::uint32_t* const outEndAddress,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeForwardStoreEndA(outEndAddress, sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0078C4E0 (FUN_0078C4E0)
   *
   * What it does:
   * Writes one source dword through span cursor (`owner+0x10 -> span+0x04`),
   * advances cursor by 4, and grows end to cursor when cursor was already at
   * or beyond end.
   */
  [[maybe_unused]] PointerToSpanStateAt10RuntimeView* WriteDwordThroughSpanCursorAndGrowEnd(
    PointerToSpanStateAt10RuntimeView* const owner,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    DwordSpanStateRuntimeView* const span = owner->span;
    std::uint32_t* const cursor = reinterpret_cast<std::uint32_t*>(span->cursor);
    if (span->cursor < span->end) {
      *cursor = *sourceWord;
      span->cursor += 4u;
      return owner;
    }

    if (cursor != nullptr) {
      *cursor = *sourceWord;
    }
    span->cursor += 4u;
    span->end = span->cursor;
    return owner;
  }

  /**
   * Address: 0x0078C670 (FUN_0078C670)
   *
   * What it does:
   * Alias lane for advancing one address lane by `index * 4`.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByStride4C(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceAddressLaneByStride4A(addressLane, index);
  }

  /**
   * Address: 0x0078C6E0 (FUN_0078C6E0)
   *
   * What it does:
   * Alias lane for forward-copying one dword range and storing destination end.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForwardStoreEndC(
    std::uint32_t* const outEndAddress,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeForwardStoreEndA(outEndAddress, sourceBegin, sourceEnd, destination);
  }

  struct PackedPairTableRuntimeView
  {
    std::byte pad0000_000B[0x0C];
    std::uint8_t pairCount; // +0x0C
    std::uint8_t bytes[1]; // +0x0D
  };
#if defined(_M_IX86)
  static_assert(offsetof(PackedPairTableRuntimeView, pairCount) == 0x0C, "PackedPairTableRuntimeView::pairCount offset");
#endif

  struct PackedPairTableOwnerRuntimeView
  {
    PackedPairTableRuntimeView* table; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(PackedPairTableOwnerRuntimeView) == 0x04, "PackedPairTableOwnerRuntimeView size must be 0x04");
#endif

  struct OwnerPointerLaneRuntimeView
  {
    void* owner; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(OwnerPointerLaneRuntimeView) == 0x04, "OwnerPointerLaneRuntimeView size must be 0x04");
#endif

  struct NearestCandidateMetricContextRuntimeView
  {
    std::byte pad0000_004F[0x50];
    std::uint8_t* metricObjectHandle; // +0x50 (call target lives at handle-4)
    std::uint32_t bestCandidateWord; // +0x54
    float bestMetric; // +0x58
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(NearestCandidateMetricContextRuntimeView, metricObjectHandle) == 0x50,
    "NearestCandidateMetricContextRuntimeView::metricObjectHandle offset"
  );
  static_assert(
    offsetof(NearestCandidateMetricContextRuntimeView, bestCandidateWord) == 0x54,
    "NearestCandidateMetricContextRuntimeView::bestCandidateWord offset"
  );
  static_assert(
    offsetof(NearestCandidateMetricContextRuntimeView, bestMetric) == 0x58,
    "NearestCandidateMetricContextRuntimeView::bestMetric offset"
  );
#endif

  struct IndexChainPushRuntimeView
  {
    std::byte pad0000_0013[0x14];
    std::uint32_t* nextByIndex; // +0x14
    std::byte pad0018_001F[0x08];
    std::uint32_t headIndex; // +0x20
  };
#if defined(_M_IX86)
  static_assert(offsetof(IndexChainPushRuntimeView, nextByIndex) == 0x14, "IndexChainPushRuntimeView::nextByIndex offset");
  static_assert(offsetof(IndexChainPushRuntimeView, headIndex) == 0x20, "IndexChainPushRuntimeView::headIndex offset");
#endif

  using CandidateMetricCallback = double(__thiscall*)(void* self, const std::uint32_t* candidateWord);

  [[nodiscard]] std::uintptr_t ComputePackedPairTailBaseAddress(const PackedPairTableRuntimeView* const table) noexcept
  {
    if (table != nullptr) {
      return reinterpret_cast<std::uintptr_t>(table)
        + (static_cast<std::uintptr_t>(table->pairCount) << 1u)
        + 0x0Du;
    }
    return 0x0Du;
  }

  [[nodiscard]] double InvokeCandidateMetricSlot3(
    void* const callbackObject,
    const std::uint32_t* const candidateWord
  ) noexcept
  {
    auto* const vtable = *reinterpret_cast<void***>(callbackObject);
    const auto callback = reinterpret_cast<CandidateMetricCallback>(vtable[3]);
    return callback(callbackObject, candidateWord);
  }

  /**
   * Address: 0x00760A50 (FUN_00760A50)
   *
   * What it does:
   * Clears lane `+0x0C`, then stores two caller lanes into `+0x14/+0x18`.
   */
  [[maybe_unused]] SevenWordLaneRuntimeView* ClearLane0CAndStoreTailPair(
    SevenWordLaneRuntimeView* const outValue,
    const std::uint32_t lane18Value,
    const std::uint32_t lane14Value
  ) noexcept
  {
    outValue->lanes[3] = 0u;
    outValue->lanes[5] = lane14Value;
    outValue->lanes[6] = lane18Value;
    return outValue;
  }

  /**
   * Address: 0x00761C50 (FUN_00761C50)
   *
   * What it does:
   * Initializes a self-relative span header with begin/cursor/lane0C at
   * `this+0x10` and end at `this+0x710`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail710(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x710u);
  }

  /**
   * Address: 0x00763C50 (FUN_00763C50)
   *
   * What it does:
   * Swaps trailing dword lanes (`+0x04/+0x08/+0x0C`) between two 16-byte
   * lane blocks.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanesLateA(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00763EB0 (FUN_00763EB0)
   *
   * What it does:
   * Alias entry for swapping trailing dword triplet lanes.
   */
  [[maybe_unused]] std::uint32_t* SwapTrailingTripletLanesLateB(
    HeaderAndThreeWordLanesRuntimeView* const lhs,
    HeaderAndThreeWordLanesRuntimeView* const rhs
  ) noexcept
  {
    return SwapThreeTrailingWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00764650 (FUN_00764650)
   *
   * What it does:
   * Swaps one leading dword lane between two word slots.
   */
  [[maybe_unused]] std::uint32_t* SwapLeadingWordLaneLateA(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00765420 (FUN_00765420)
   *
   * What it does:
   * Computes `*baseWord + index*4` and stores the resulting byte address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4PathQueueVariant(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride4ByteOffset(outValue, baseWord, index);
  }

  /**
   * Address: 0x00765580 (FUN_00765580)
   *
   * What it does:
   * Swaps two consecutive dword lanes (`+0x00/+0x04`) between two records.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* SwapWordPairLanesLate(
    DwordPairLaneRuntimeView* const lhs,
    DwordPairLaneRuntimeView* const rhs
  ) noexcept
  {
    return SwapWordPairLanes(lhs, rhs);
  }

  /**
   * Address: 0x00765650 (FUN_00765650)
   *
   * What it does:
   * Alias entry for swapping one leading dword lane.
   */
  [[maybe_unused]] std::uint32_t* SwapLeadingWordLaneLateB(
    std::uint32_t* const lhs,
    std::uint32_t* const rhs
  ) noexcept
  {
    return SwapSingleWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00765820 (FUN_00765820)
   *
   * What it does:
   * Computes one upper-triangle flattened index: `offset + n*(n-1)/2`.
   */
  [[maybe_unused]] std::int32_t ComputeUpperTriangleOffsetIndex(
    const std::int32_t offset,
    const std::int32_t n
  ) noexcept
  {
    const std::uint32_t value = static_cast<std::uint32_t>(n);
    const std::uint32_t triangular = (value * (value - 1u)) >> 1u;
    return offset + static_cast<std::int32_t>(triangular);
  }

  /**
   * Address: 0x007658A0 (FUN_007658A0)
   *
   * What it does:
   * Returns packed pair count byte at `table+0x0C`, or zero when table is null.
   */
  [[maybe_unused]] std::int32_t ReadPackedPairCountOrZero(
    const PackedPairTableOwnerRuntimeView* const owner
  ) noexcept
  {
    if (owner->table != nullptr) {
      return owner->table->pairCount;
    }
    return 0;
  }

  /**
   * Address: 0x007658B0 (FUN_007658B0)
   *
   * What it does:
   * Reads first byte from one packed pair lane at `table + (index*2) + 0x0D`.
   */
  [[maybe_unused]] std::int32_t ReadPackedPairFirstByte(
    const PackedPairTableOwnerRuntimeView* const owner,
    const std::int32_t pairIndex
  ) noexcept
  {
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(owner->table);
    return bytes[(static_cast<std::uint32_t>(pairIndex) << 1u) + 0x0Du];
  }

  /**
   * Address: 0x007658C0 (FUN_007658C0)
   *
   * What it does:
   * Reads second byte from one packed pair lane at `table + (index*2) + 0x0E`.
   */
  [[maybe_unused]] std::int32_t ReadPackedPairSecondByte(
    const PackedPairTableOwnerRuntimeView* const owner,
    const std::int32_t pairIndex
  ) noexcept
  {
    const auto* const bytes = reinterpret_cast<const std::uint8_t*>(owner->table);
    return bytes[(static_cast<std::uint32_t>(pairIndex) << 1u) + 0x0Eu];
  }

  /**
   * Address: 0x00765970 (FUN_00765970)
   *
   * What it does:
   * Scans packed pair lanes for a `(first,second)` byte tuple and returns its
   * pair index, or `-1` when not found.
   */
  [[maybe_unused]] std::int32_t FindPackedPairIndexByByteTuple(
    const PackedPairTableOwnerRuntimeView* const owner,
    const std::uint8_t first,
    const std::uint8_t second
  ) noexcept
  {
    const PackedPairTableRuntimeView* const table = owner->table;
    const std::int32_t pairCount = table != nullptr ? static_cast<std::int32_t>(table->pairCount) : 0;
    if (pairCount == 0) {
      return -1;
    }

    const std::uint8_t* cursor = reinterpret_cast<const std::uint8_t*>(table) + 0x0Eu;
    for (std::int32_t index = 0; index < pairCount; ++index, cursor += 2) {
      if (cursor[-1] == first && cursor[0] == second) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Address: 0x007659B0 (FUN_007659B0)
   *
   * What it does:
   * Reads one byte from the packed-table tail block at
   * `table + (pairCount*2) + selector + 0x0D`; when table is null, it reads
   * from absolute lane `selector + 0x0D` to preserve original fallback shape.
   */
  [[maybe_unused]] std::uint8_t ReadPackedPairTailByte(
    const PackedPairTableOwnerRuntimeView* const owner,
    const std::int32_t selector
  ) noexcept
  {
    const std::uintptr_t address = ComputePackedPairTailBaseAddress(owner->table)
      + static_cast<std::uintptr_t>(selector);
    return *reinterpret_cast<const std::uint8_t*>(address);
  }

  /**
   * Address: 0x007659E0 (FUN_007659E0)
   *
   * What it does:
   * Increments ref-count dword at table base when owner table is present.
   */
  [[maybe_unused]] std::uint32_t* AddRefPackedPairTableWord(
    PackedPairTableOwnerRuntimeView* const owner
  ) noexcept
  {
    auto* const tableWord = reinterpret_cast<std::uint32_t*>(owner->table);
    if (tableWord != nullptr) {
      ++(*tableWord);
    }
    return tableWord;
  }

  /**
   * Address: 0x00765A90 (FUN_00765A90)
   *
   * What it does:
   * Tests whether packed relation byte for one unordered pair is non-negative.
   */
  [[maybe_unused]] bool IsPackedPairRelationNonNegative(
    const PackedPairTableOwnerRuntimeView* const owner,
    const std::uint32_t firstIndex,
    const std::uint32_t secondIndex
  ) noexcept
  {
    if (firstIndex == secondIndex) {
      return false;
    }

    const std::uint32_t lower = firstIndex < secondIndex ? firstIndex : secondIndex;
    const std::uint32_t upper = firstIndex < secondIndex ? secondIndex : firstIndex;
    const std::uint32_t relationIndex = lower + ((upper * (upper - 1u)) >> 1u);
    const std::uintptr_t relationAddress = ComputePackedPairTailBaseAddress(owner->table) + relationIndex;
    return *reinterpret_cast<const std::int8_t*>(relationAddress) >= 0;
  }

  /**
   * Address: 0x00765B00 (FUN_00765B00)
   *
   * What it does:
   * Resolves one 2D cell address from table descriptor lane `(base,stride)`
   * stored at descriptor index `lane*3 + 6`.
   */
  [[maybe_unused]] std::uintptr_t ResolveTableCellAddressFromDescriptorLane(
    const std::int32_t lane,
    const std::uint32_t* const descriptorWords,
    const std::int32_t x,
    const std::int32_t y
  ) noexcept
  {
    const std::uint32_t descriptorIndex = static_cast<std::uint32_t>((lane * 3) + 6);
    const std::uint32_t dataBase = descriptorWords[descriptorIndex];
    const std::uint32_t rowStride = descriptorWords[descriptorIndex + 1u];
    const std::uint32_t linearIndex =
      static_cast<std::uint32_t>(x) + (static_cast<std::uint32_t>(y) * rowStride);
    return dataBase + (static_cast<std::uintptr_t>(linearIndex) << 2u);
  }

  /**
   * Address: 0x00765D20 (FUN_00765D20)
   *
   * What it does:
   * Zeros one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLanePathQueueA(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x00765F80 (FUN_00765F80)
   *
   * What it does:
   * Unlinks owner node at `owner+0x04`, restores singleton self-links, and
   * inserts it directly before anchor node at `(*ownerSlot->owner)+0x04`.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkOwnerNodeOffset04BeforeForeignOffset04Anchor(
    void* const ownerBase,
    const OwnerPointerLaneRuntimeView* const ownerSlot
  ) noexcept
  {
    auto* const anchorOwnerBase = ownerSlot->owner;
    auto* const anchor = reinterpret_cast<IntrusiveNodeRuntimeView*>(
      static_cast<std::byte*>(anchorOwnerBase) + 0x04u
    );
    return RelinkOwnerNodeAtOffsetBeforeAnchor(ownerBase, anchor, 0x04u);
  }

  /**
   * Address: 0x00765FC0 (FUN_00765FC0)
   *
   * What it does:
   * Unlinks owner node at `owner+0x04` and restores singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkOwnerNodeOffset04AndSelfLink(
    void* const ownerBase
  ) noexcept
  {
    auto* const node = reinterpret_cast<IntrusiveNodeRuntimeView*>(static_cast<std::byte*>(ownerBase) + 0x04u);
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x00766240 (FUN_00766240)
   *
   * What it does:
   * Evaluates one candidate metric through callback vtable slot `+0x0C` and
   * stores candidate id and metric when it improves the current best metric.
   */
  [[maybe_unused]] void UpdateNearestCandidateMetric(
    const std::uint32_t* const candidateWord,
    NearestCandidateMetricContextRuntimeView* const context
  ) noexcept
  {
    auto* const callbackObject = context->metricObjectHandle != nullptr
      ? static_cast<void*>(context->metricObjectHandle - 4)
      : nullptr;
    const double metric = InvokeCandidateMetricSlot3(callbackObject, candidateWord);
    if (static_cast<double>(context->bestMetric) > metric) {
      context->bestCandidateWord = *candidateWord;
      context->bestMetric = static_cast<float>(metric);
    }
  }

  /**
   * Address: 0x00767BD0 (FUN_00767BD0)
   *
   * What it does:
   * Copies one byte lane from source to destination.
   */
  [[maybe_unused]] std::uint8_t* CopySingleByteLane(
    std::uint8_t* const outValue,
    const std::uint8_t* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x00769100 (FUN_00769100)
   *
   * What it does:
   * Initializes a self-relative span header with begin/cursor/lane0C at
   * `this+0x10` and end at `this+0x650`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail650(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x650u);
  }

  /**
   * Address: 0x007698B0 (FUN_007698B0)
   *
   * What it does:
   * Computes one address lane as `*source->lane04 + index*12`.
   */
  [[maybe_unused]] std::uintptr_t ComputeStride12AddressFromLane04(
    const std::int32_t index,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return ComputeOffsetAddressByStride(*source->lane04, index, 12u);
  }

  /**
   * Address: 0x00769A00 (FUN_00769A00)
   *
   * What it does:
   * Zeros both lanes of one dword pair record.
   */
  [[maybe_unused]] DwordPairLaneRuntimeView* ZeroDwordPairLanePathQueue(
    DwordPairLaneRuntimeView* const outValue
  ) noexcept
  {
    return ZeroDwordPairLanePrimary(outValue);
  }

  /**
   * Address: 0x00769A50 (FUN_00769A50)
   *
   * What it does:
   * Copies one scalar dword lane from source to destination.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordLane(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return StoreDword(outValue, *source);
  }

  /**
   * Address: 0x00769C90 (FUN_00769C90)
   *
   * What it does:
   * Pushes one index onto a freelist chain: `nextByIndex[index]=head; head=index`.
   */
  [[maybe_unused]] IndexChainPushRuntimeView* PushIndexOntoHeadChain(
    IndexChainPushRuntimeView* const chain,
    const std::uint32_t index
  ) noexcept
  {
    chain->nextByIndex[index] = chain->headIndex;
    chain->headIndex = index;
    return chain;
  }

  /**
   * Address: 0x00769D90 (FUN_00769D90)
   *
   * What it does:
   * Alias entry for zeroing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLanePathQueueB(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  struct FloatLaneAtD4RuntimeView
  {
    std::byte pad00_D3[0xD4];
    float laneD4; // +0xD4
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatLaneAtD4RuntimeView, laneD4) == 0xD4, "FloatLaneAtD4RuntimeView::laneD4 offset must be 0xD4");
#endif

  struct IntrusiveOwnerNode52RuntimeView
  {
    std::byte pad00_33[0x34];
    IntrusiveNodeRuntimeView node52; // +0x34
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveOwnerNode52RuntimeView, node52) == 0x34,
    "IntrusiveOwnerNode52RuntimeView::node52 offset must be 0x34"
  );
#endif

  struct IntrusiveOwnerNode52AndAnchor292RuntimeView
  {
    std::byte pad00_33[0x34];
    IntrusiveNodeRuntimeView node52; // +0x34
    std::byte pad3C_123[0xE8];
    IntrusiveNodeRuntimeView anchor292; // +0x124
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IntrusiveOwnerNode52AndAnchor292RuntimeView, node52) == 0x34,
    "IntrusiveOwnerNode52AndAnchor292RuntimeView::node52 offset must be 0x34"
  );
  static_assert(
    offsetof(IntrusiveOwnerNode52AndAnchor292RuntimeView, anchor292) == 0x124,
    "IntrusiveOwnerNode52AndAnchor292RuntimeView::anchor292 offset must be 0x124"
  );
#endif

  struct IntrusiveNodeSlotAt00RuntimeView
  {
    IntrusiveNodeRuntimeView* node; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(IntrusiveNodeSlotAt00RuntimeView) == 0x04, "IntrusiveNodeSlotAt00RuntimeView size must be 0x04");
#endif

  /**
   * Address: 0x00786360 (FUN_00786360)
   *
   * What it does:
   * Clears one four-dword lane block to zero.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearDwordQuadLane786360(DwordQuadRuntimeView* const outValue) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x007863A0 (FUN_007863A0)
   *
   * What it does:
   * Returns one float lane from offset `+0xD4`.
   */
  [[maybe_unused]] float ReadFloatLaneAtD4(const FloatLaneAtD4RuntimeView* const value) noexcept
  {
    return value->laneD4;
  }

  /**
   * Address: 0x00786490 (FUN_00786490)
   *
   * What it does:
   * Stores the same scalar dword into both lanes of one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreRepeatedDwordPair(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane00 = value;
    outValue->lane04 = value;
    return outValue;
  }

  /**
   * Address: 0x007864D0 (FUN_007864D0)
   *
   * What it does:
   * Returns whether left float lane `+0xD4` is greater than right lane
   * `+0xD4`.
   */
  [[maybe_unused]] bool IsFloatLaneD4Greater(
    const FloatLaneAtD4RuntimeView* const left,
    const FloatLaneAtD4RuntimeView* const right
  ) noexcept
  {
    return left->laneD4 > right->laneD4;
  }

  /**
   * Address: 0x007864F0 (FUN_007864F0)
   *
   * What it does:
   * When owners differ, unlinks owner node at `+0x34` and inserts it directly
   * after target owner anchor lane `+0x124`.
   */
  [[maybe_unused]] std::uint32_t* RelinkOwnerNode52AfterOwnerAnchor292(
    IntrusiveOwnerNode52AndAnchor292RuntimeView* const owner,
    IntrusiveOwnerNode52AndAnchor292RuntimeView* const targetOwner
  ) noexcept
  {
    if (owner != targetOwner) {
      IntrusiveNodeRuntimeView* const node = owner != nullptr ? &owner->node52 : nullptr;
      IntrusiveNodeRuntimeView* const anchor = &targetOwner->anchor292;
      return reinterpret_cast<std::uint32_t*>(RelinkIntrusiveNodeAfterAnchor(node, anchor));
    }
    return reinterpret_cast<std::uint32_t*>(owner);
  }

  /**
   * Address: 0x00789EA0 (FUN_00789EA0)
   * Address: 0x00789EF0 (FUN_00789EF0)
   *
   * What it does:
   * Alias lane for initializing one intrusive two-link lane to singleton
   * self-links.
   */
  [[maybe_unused]] std::uint32_t* InitializeTwoWordSelfLinkAliasC(std::uint32_t* const linkWords) noexcept
  {
    return InitializeTwoWordSelfLink(linkWords);
  }

  /**
   * Address: 0x00789ED0 (FUN_00789ED0)
   *
   * What it does:
   * Alias lane for intrusive unlink-and-selflink reset behavior.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelfMu(IntrusiveNodeRuntimeView* const node) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x00789F10 (FUN_00789F10)
   * Address: 0x0078A0B0 (FUN_0078A0B0)
   * Address: 0x0078A2F0 (FUN_0078A2F0)
   * Address: 0x0078A300 (FUN_0078A300)
   * Address: 0x0078A610 (FUN_0078A610)
   *
   * What it does:
   * Stores one scalar dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneGammaSecondary(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x00789F30 (FUN_00789F30)
   * Address: 0x0078A130 (FUN_0078A130)
   *
   * What it does:
   * Unlinks owner node at `+0x34` and inserts it directly after `anchor`.
   */
  [[maybe_unused]] std::uint32_t* RelinkOwnerNode52AfterAnchor(
    IntrusiveOwnerNode52RuntimeView* const owner,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = owner != nullptr ? &owner->node52 : nullptr;
    return reinterpret_cast<std::uint32_t*>(RelinkIntrusiveNodeAfterAnchor(node, anchor));
  }

  /**
   * Address: 0x00789F60 (FUN_00789F60)
   *
   * What it does:
   * Returns owner base address from one intrusive node slot at `+0x04`
   * (`node - 0x34`), or null when slot is null.
   */
  [[maybe_unused]] void* ResolveOwnerBaseFromNodeSlotAt04Minus52(
    const IntrusiveOwnerNodeSlotRuntimeView* const ownerSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = ownerSlot->node;
    if (node == nullptr) {
      return nullptr;
    }
    return static_cast<void*>(reinterpret_cast<std::byte*>(node) - 0x34u);
  }

  /**
   * Address: 0x00789F70 (FUN_00789F70)
   *
   * What it does:
   * Unlinks one node from slot storage and returns owner base (`node - 0x34`).
   */
  [[maybe_unused]] IntrusiveOwnerNode52RuntimeView* UnlinkNodeFromSlotAndResolveOwnerBase52(
    IntrusiveNodeRuntimeView** const nodeSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = *nodeSlot;
    (void)UnlinkIntrusiveNodeAndSelfLink(node);
    return reinterpret_cast<IntrusiveOwnerNode52RuntimeView*>(reinterpret_cast<std::byte*>(node) - 0x34u);
  }

  /**
   * Address: 0x00789F90 (FUN_00789F90)
   *
   * What it does:
   * Alias lane for clearing dword lanes `+0x04/+0x08/+0x0C`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearDwordLanes04To0CAliasB(DwordQuadRuntimeView* const lanes) noexcept
  {
    return ClearDwordLanes04To0C(lanes);
  }

  /**
   * Address: 0x00789FF0 (FUN_00789FF0)
   *
   * What it does:
   * Returns 4-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x08)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountDwordSlotsFromLane04ToLane08(
    const WordPairAt4And8RuntimeView* const lanes
  ) noexcept
  {
    if (lanes->lane04 == 0u) {
      return 0;
    }
    return static_cast<std::int32_t>((lanes->lane08 - lanes->lane04) >> 2u);
  }

  /**
   * Address: 0x0078A0D0 (FUN_0078A0D0)
   * Address: 0x0078A0E0 (FUN_0078A0E0)
   *
   * What it does:
   * Returns owner base address from one intrusive node slot at `+0x00`
   * (`node - 0x34`), or null when slot is null.
   */
  [[maybe_unused]] void* ResolveOwnerBaseFromNodeSlotAt00Minus52(
    const IntrusiveNodeSlotAt00RuntimeView* const nodeSlot
  ) noexcept
  {
    IntrusiveNodeRuntimeView* const node = nodeSlot->node;
    if (node == nullptr) {
      return nullptr;
    }
    return static_cast<void*>(reinterpret_cast<std::byte*>(node) - 0x34u);
  }

  /**
   * Address: 0x0078A100 (FUN_0078A100)
   *
   * What it does:
   * Alias lane for initializing one self-relative span header with tail anchor
   * at `+0x60`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail60AliasB(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderTail60(outValue);
  }

  /**
   * Address: 0x0078A170 (FUN_0078A170)
   *
   * What it does:
   * Returns 4-byte element count from one begin/end pair at offsets
   * `(+0x04,+0x0C)`; returns zero when begin is null.
   */
  [[maybe_unused]] std::int32_t CountDwordSlotsFromLane04ToLane0C(
    const DwordBeginMidEndRuntimeView* const lanes
  ) noexcept
  {
    if (lanes->begin == 0u) {
      return 0;
    }
    return static_cast<std::int32_t>((lanes->end - lanes->begin) >> 2u);
  }

  /**
   * Address: 0x0078A5F0 (FUN_0078A5F0)
   *
   * What it does:
   * Alias lane for storing one `*base + index * 4` address lane.
   */
  [[maybe_unused]] std::uint32_t* StoreStride4AddressFromBaseWordAliasA(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreStride4AddressFromBaseWord(outValue, baseWord, index);
  }

  /**
   * Address: 0x0078A600 (FUN_0078A600)
   * Address: 0x0078A650 (FUN_0078A650)
   *
   * What it does:
   * Alias lane for 4-byte element distance between two stored address lanes.
   */
  [[maybe_unused]] std::int32_t CountDwordAddressDistanceD(
    const std::uint32_t* const lhsAddress,
    const std::uint32_t* const rhsAddress
  ) noexcept
  {
    return CountDwordAddressDistanceC(lhsAddress, rhsAddress);
  }

  /**
   * Address: 0x0078A640 (FUN_0078A640)
   * Address: 0x0078A670 (FUN_0078A670)
   *
   * What it does:
   * Alias lane for advancing one stored address lane by `index * 4` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceAddressLaneByDwordCountD(
    std::uint32_t* const addressLane,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceAddressLaneByDwordCountC(addressLane, index);
  }

  /**
   * Address: 0x0078ADD0 (FUN_0078ADD0)
   * Address: 0x0089BC40 (FUN_0089BC40)
   * Address: 0x0089C330 (FUN_0089C330)
   *
   * What it does:
   * Fills `count` destination dword lanes with one source dword value and
   * returns remaining count (zero on normal completion).
   */
  [[maybe_unused]] std::int32_t FillDwordSpanCountedReturnRemaining(
    std::int32_t count,
    const std::uint32_t* const valueSlot,
    std::uint32_t* destination
  ) noexcept
  {
    while (count != 0) {
      *destination = *valueSlot;
      ++destination;
      --count;
    }
    return count;
  }

  /**
   * Address: 0x0078AE30 (FUN_0078AE30)
   *
   * What it does:
   * Fills one `[begin,end)` dword span with one source dword value.
   */
  [[maybe_unused]] std::uint32_t* FillDwordSpanByEndFromSingleWord(
    std::uint32_t* begin,
    const std::uint32_t* const sourceWord,
    std::uint32_t* const end
  ) noexcept
  {
    if (begin != end) {
      const std::uint32_t fillWord = *sourceWord;
      do {
        *begin = fillWord;
        ++begin;
      } while (begin != end);
    }
    return begin;
  }

  struct FloatAndTagWordsAt16CRuntimeView
  {
    std::byte pad0000_016B[0x16C];
    float lane16C; // +0x16C
    std::uint32_t lane170; // +0x170
    std::uint32_t lane174; // +0x174
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatAndTagWordsAt16CRuntimeView, lane16C) == 0x16C, "FloatAndTagWordsAt16CRuntimeView::lane16C offset");
  static_assert(offsetof(FloatAndTagWordsAt16CRuntimeView, lane170) == 0x170, "FloatAndTagWordsAt16CRuntimeView::lane170 offset");
  static_assert(offsetof(FloatAndTagWordsAt16CRuntimeView, lane174) == 0x174, "FloatAndTagWordsAt16CRuntimeView::lane174 offset");
#endif

  struct WordLanesAt11CThrough134RuntimeView
  {
    std::byte pad0000_011B[0x11C];
    std::uint32_t lane11C; // +0x11C
    std::uint32_t lane120; // +0x120
    std::uint32_t lane124; // +0x124
    std::uint32_t lane128; // +0x128
    std::uint32_t lane12C; // +0x12C
    std::uint32_t lane130; // +0x130
    std::uint32_t lane134; // +0x134
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane11C) == 0x11C, "WordLanesAt11CThrough134RuntimeView::lane11C offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane120) == 0x120, "WordLanesAt11CThrough134RuntimeView::lane120 offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane124) == 0x124, "WordLanesAt11CThrough134RuntimeView::lane124 offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane128) == 0x128, "WordLanesAt11CThrough134RuntimeView::lane128 offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane12C) == 0x12C, "WordLanesAt11CThrough134RuntimeView::lane12C offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane130) == 0x130, "WordLanesAt11CThrough134RuntimeView::lane130 offset");
  static_assert(offsetof(WordLanesAt11CThrough134RuntimeView, lane134) == 0x134, "WordLanesAt11CThrough134RuntimeView::lane134 offset");
#endif

  struct WordTripletAt8RuntimeView
  {
    std::byte pad0000_0007[0x08];
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t lane10; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordTripletAt8RuntimeView, lane08) == 0x08, "WordTripletAt8RuntimeView::lane08 offset");
  static_assert(offsetof(WordTripletAt8RuntimeView, lane0C) == 0x0C, "WordTripletAt8RuntimeView::lane0C offset");
  static_assert(offsetof(WordTripletAt8RuntimeView, lane10) == 0x10, "WordTripletAt8RuntimeView::lane10 offset");
#endif

  struct WordTripletAt4RuntimeView
  {
    std::byte pad0000_0003[0x04];
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordTripletAt4RuntimeView, lane04) == 0x04, "WordTripletAt4RuntimeView::lane04 offset");
  static_assert(offsetof(WordTripletAt4RuntimeView, lane08) == 0x08, "WordTripletAt4RuntimeView::lane08 offset");
  static_assert(offsetof(WordTripletAt4RuntimeView, lane0C) == 0x0C, "WordTripletAt4RuntimeView::lane0C offset");
#endif

  struct Stride20BeginAndEndAt4AndCRuntimeView
  {
    std::uint32_t lane00; // +0x00
    const std::byte* begin; // +0x04
    std::uint32_t lane08; // +0x08
    const std::byte* end; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(Stride20BeginAndEndAt4AndCRuntimeView, begin) == 0x04,
    "Stride20BeginAndEndAt4AndCRuntimeView::begin offset"
  );
  static_assert(
    offsetof(Stride20BeginAndEndAt4AndCRuntimeView, end) == 0x0C,
    "Stride20BeginAndEndAt4AndCRuntimeView::end offset"
  );
#endif

  struct WeakOwnerPairRuntimeView
  {
    std::uint32_t objectWord; // +0x00
    SharedOwnerControlBlockRuntimeView* owner; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(WeakOwnerPairRuntimeView) == 0x08, "WeakOwnerPairRuntimeView size must be 0x08");
  static_assert(offsetof(WeakOwnerPairRuntimeView, owner) == 0x04, "WeakOwnerPairRuntimeView::owner offset");
#endif

  [[nodiscard]] std::intptr_t ReleaseWeakOwnerControlBlock(
    SharedOwnerControlBlockRuntimeView* const owner
  ) noexcept
  {
    if (owner == nullptr) {
      return 0;
    }

    const LONG priorWeakCount = InterlockedExchangeAdd(&owner->weakCount, -1);
    if (priorWeakCount == 1) {
      return InvokeSharedOwnerReleaseSlot(owner, 2u);
    }
    return priorWeakCount;
  }

  using DeleteFlagVirtualCall = std::intptr_t(__thiscall*)(void* self, std::int32_t deleteFlag);

  [[nodiscard]] std::intptr_t InvokeDeleteFlagVirtualSlot2IfPresent(void* const object) noexcept
  {
    if (object == nullptr) {
      return 0;
    }

    auto* const vtable = *reinterpret_cast<void***>(object);
    const auto callback = reinterpret_cast<DeleteFlagVirtualCall>(vtable[2]);
    return callback(object, 1);
  }

  /**
   * Address: 0x00791370 (FUN_00791370)
   *
   * What it does:
   * Stores one float lane and two byte-tag words at offsets
   * `+0x16C/+0x170/+0x174`.
   */
  [[maybe_unused]] FloatAndTagWordsAt16CRuntimeView* SetFloatAndTagWordsAt16C(
    FloatAndTagWordsAt16CRuntimeView* const outValue,
    const float value,
    const std::uint8_t tagAt174,
    const std::uint8_t tagAt170
  ) noexcept
  {
    outValue->lane16C = value;
    outValue->lane174 = tagAt174;
    outValue->lane170 = tagAt170;
    return outValue;
  }

  /**
   * Address: 0x00794DF0 (FUN_00794DF0)
   *
   * What it does:
   * Zeros one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLanePrimarySharedOwner(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x00794E60 (FUN_00794E60)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePrimarySharedOwner(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x00796040 (FUN_00796040)
   *
   * What it does:
   * Reads one dword lane at offset `+0x130`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane130(
    const WordLanesAt11CThrough134RuntimeView* const source
  ) noexcept
  {
    return source->lane130;
  }

  /**
   * Address: 0x00796050 (FUN_00796050)
   *
   * What it does:
   * Stores one dword lane at offset `+0x130`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane130Primary(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane130 = value;
    return outValue;
  }

  /**
   * Address: 0x00796D10 (FUN_00796D10)
   *
   * What it does:
   * Zeros a two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneSharedOwnerA(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x00796D60 (FUN_00796D60)
   *
   * What it does:
   * Alias lane for zeroing a two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneSharedOwnerB(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x00796DA0 (FUN_00796DA0)
   *
   * What it does:
   * Releases weak owner control block at lane `+0x04`.
   */
  [[maybe_unused]] std::intptr_t ReleaseWeakOwnerFromPairLane(
    const SharedOwnerPairRuntimeView* const pair
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(pair);
    auto* const owner = reinterpret_cast<SharedOwnerControlBlockRuntimeView*>(pair->ownerWord);
    if (owner != nullptr) {
      result = ReleaseWeakOwnerControlBlock(owner);
    }
    return result;
  }

  /**
   * Address: 0x00796DC0 (FUN_00796DC0)
   *
   * What it does:
   * Copy-assigns one `{object, owner}` pair and increments owner use-count.
   */
  [[maybe_unused]] SharedOwnerPairRuntimeView* CopySharedOwnerPairWithUseRetain(
    SharedOwnerPairRuntimeView* const destination,
    const SharedOwnerPairRuntimeView* const source
  ) noexcept
  {
    return CopySharedOwnerPairAndRetain(destination, source);
  }

  /**
   * Address: 0x00796DE0 (FUN_00796DE0)
   *
   * What it does:
   * Alias lane for zeroing a two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneSharedOwnerC(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x00796FC0 (FUN_00796FC0)
   *
   * What it does:
   * Replaces weak-owner pair contents, retains incoming owner weak-count, and
   * releases previous owner weak-count.
   */
  [[maybe_unused]] std::intptr_t ReplaceWeakOwnerPairAndRetainIncoming(
    const std::uint32_t objectWord,
    SharedOwnerControlBlockRuntimeView* const* const incomingOwnerSlot,
    WeakOwnerPairRuntimeView* const destination
  ) noexcept
  {
    std::intptr_t result = static_cast<std::intptr_t>(objectWord);
    if (destination != nullptr) {
      destination->objectWord = objectWord;
      SharedOwnerControlBlockRuntimeView* const incomingOwner = *incomingOwnerSlot;
      if (incomingOwner != nullptr) {
        result = InterlockedExchangeAdd(&incomingOwner->weakCount, 1);
      }

      SharedOwnerControlBlockRuntimeView* const previousOwner = destination->owner;
      if (previousOwner != nullptr) {
        result = ReleaseWeakOwnerControlBlock(previousOwner);
      }

      destination->owner = incomingOwner;
    }
    return result;
  }

  /**
   * Address: 0x007970C0 (FUN_007970C0)
   *
   * What it does:
   * Invokes virtual slot `+0x08` with delete-flag `1` when object is non-null.
   */
  [[maybe_unused]] std::intptr_t DestroyObjectWithDeleteFlagOneIfPresent(void* const object) noexcept
  {
    return InvokeDeleteFlagVirtualSlot2IfPresent(object);
  }

  /**
   * Address: 0x00797630 (FUN_00797630)
   *
   * What it does:
   * Stores one dword lane at offset `+0x11C`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane11C(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane11C = value;
    return outValue;
  }

  /**
   * Address: 0x00797640 (FUN_00797640)
   *
   * What it does:
   * Stores one dword lane at offset `+0x120`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane120Primary(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane120 = value;
    return outValue;
  }

  /**
   * Address: 0x00798100 (FUN_00798100)
   *
   * What it does:
   * Zeros word triplet lanes `+0x08/+0x0C/+0x10`.
   */
  [[maybe_unused]] WordTripletAt8RuntimeView* ZeroWordTripletAt8(
    WordTripletAt8RuntimeView* const outValue
  ) noexcept
  {
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    outValue->lane10 = 0u;
    return outValue;
  }

  /**
   * Address: 0x00798140 (FUN_00798140)
   *
   * What it does:
   * Zeros word triplet lanes `+0x04/+0x08/+0x0C`.
   */
  [[maybe_unused]] WordTripletAt4RuntimeView* ZeroWordTripletAt4(
    WordTripletAt4RuntimeView* const outValue
  ) noexcept
  {
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x00798290 (FUN_00798290)
   *
   * What it does:
   * Returns element count for a 20-byte stride span at lanes `+0x04/+0x0C`.
   */
  [[maybe_unused]] std::int32_t CountStride20ElementsFromBeginAndEnd(
    const Stride20BeginAndEndAt4AndCRuntimeView* const span
  ) noexcept
  {
    if (span->begin == nullptr) {
      return 0;
    }
    const std::ptrdiff_t byteDelta = span->end - span->begin;
    return static_cast<std::int32_t>(byteDelta / 20);
  }

  struct Stride20OwnedPointerTripletRuntimeView
  {
    std::byte lane00_07[0x08]{};   // +0x00
    void* ownedPointer = nullptr;  // +0x08
    std::uint32_t lane0C = 0u;     // +0x0C
    std::uint32_t lane10 = 0u;     // +0x10
  };
  static_assert(
    offsetof(Stride20OwnedPointerTripletRuntimeView, ownedPointer) == 0x08,
    "Stride20OwnedPointerTripletRuntimeView::ownedPointer offset must be 0x08"
  );
  static_assert(sizeof(Stride20OwnedPointerTripletRuntimeView) == 0x14, "Stride20OwnedPointerTripletRuntimeView size must be 0x14");

  /**
   * Address: 0x00798D10 (FUN_00798D10, sub_798D10)
   *
   * What it does:
   * Walks one half-open stride-20 range and scalar-deletes each optional owned
   * pointer lane at `+0x08`, then clears trailing dword lanes `+0x0C/+0x10`.
   */
  [[maybe_unused]] void DestroyOwnedPointerTripletsInStride20Range(
    Stride20OwnedPointerTripletRuntimeView* begin,
    Stride20OwnedPointerTripletRuntimeView* const end
  ) noexcept
  {
    while (begin != end) {
      if (begin->ownedPointer != nullptr) {
        ::operator delete(begin->ownedPointer);
      }
      begin->ownedPointer = nullptr;
      begin->lane0C = 0u;
      begin->lane10 = 0u;
      ++begin;
    }
  }

  /**
   * Address: 0x00798870 (FUN_00798870)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneStride20A(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x00798880 (FUN_00798880)
   *
   * What it does:
   * Stores one `*base + index*20` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride20Primary(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride20(outValue, baseWord, index);
  }

  /**
   * Address: 0x00798890 (FUN_00798890)
   *
   * What it does:
   * Returns signed element distance between two stored addresses at 20-byte
   * stride.
   */
  [[maybe_unused]] std::int32_t DistanceBetweenStoredAddressesStride20Primary(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    return DistanceBetweenStoredAddressesStride20(leftAddressSlot, rightAddressSlot);
  }

  /**
   * Address: 0x007988F0 (FUN_007988F0)
   *
   * What it does:
   * Advances one stored address lane by `index*20` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceStoredAddressByIndexStride20Primary(
    std::uint32_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceStoredAddressByIndexStride20(addressSlot, index);
  }

  /**
   * Address: 0x00798900 (FUN_00798900)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneStride20B(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x00798910 (FUN_00798910)
   *
   * What it does:
   * Alias lane for signed 20-byte stride element distance.
   */
  [[maybe_unused]] std::int32_t DistanceBetweenStoredAddressesStride20Secondary(
    const std::uint32_t* const leftAddressSlot,
    const std::uint32_t* const rightAddressSlot
  ) noexcept
  {
    return DistanceBetweenStoredAddressesStride20(leftAddressSlot, rightAddressSlot);
  }

  /**
   * Address: 0x00798940 (FUN_00798940)
   *
   * What it does:
   * Alias lane for advancing one stored address by `index*20` bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceStoredAddressByIndexStride20Secondary(
    std::uint32_t* const addressSlot,
    const std::int32_t index
  ) noexcept
  {
    return AdvanceStoredAddressByIndexStride20(addressSlot, index);
  }

  /**
   * Address: 0x00799090 (FUN_00799090)
   *
   * What it does:
   * Stores one dword lane at offset `+0x120`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane120Secondary(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane120 = value;
    return outValue;
  }

  /**
   * Address: 0x007990A0 (FUN_007990A0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x124`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane124(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane124 = value;
    return outValue;
  }

  /**
   * Address: 0x007990B0 (FUN_007990B0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x128`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane128(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane128 = value;
    return outValue;
  }

  /**
   * Address: 0x007990C0 (FUN_007990C0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x12C`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane12C(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane12C = value;
    return outValue;
  }

  /**
   * Address: 0x007990D0 (FUN_007990D0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x130`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane130Secondary(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane130 = value;
    return outValue;
  }

  /**
   * Address: 0x007990E0 (FUN_007990E0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x134`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLane134(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane134 = value;
    return outValue;
  }
  struct Stride28BeginEndAndFlagsRuntimeView
  {
    std::byte pad0000_013B[0x13C];
    const std::byte* begin; // +0x13C
    const std::byte* end; // +0x140
    std::byte pad0144_0147[0x04];
    std::uint32_t lane148; // +0x148
    std::byte pad014C_014F[0x04];
    std::uint8_t flag150; // +0x150
    std::uint8_t flag151; // +0x151
  };
#if defined(_M_IX86)
  static_assert(offsetof(Stride28BeginEndAndFlagsRuntimeView, begin) == 0x13C, "Stride28BeginEndAndFlagsRuntimeView::begin offset");
  static_assert(offsetof(Stride28BeginEndAndFlagsRuntimeView, end) == 0x140, "Stride28BeginEndAndFlagsRuntimeView::end offset");
  static_assert(offsetof(Stride28BeginEndAndFlagsRuntimeView, lane148) == 0x148, "Stride28BeginEndAndFlagsRuntimeView::lane148 offset");
  static_assert(offsetof(Stride28BeginEndAndFlagsRuntimeView, flag150) == 0x150, "Stride28BeginEndAndFlagsRuntimeView::flag150 offset");
  static_assert(offsetof(Stride28BeginEndAndFlagsRuntimeView, flag151) == 0x151, "Stride28BeginEndAndFlagsRuntimeView::flag151 offset");
#endif

  /**
   * Address: 0x00799120 (FUN_00799120)
   *
   * What it does:
   * Returns true when the 28-byte stride span at `+0x13C/+0x140` is empty.
   */
  [[maybe_unused]] bool IsStride28SpanEmpty(
    const Stride28BeginEndAndFlagsRuntimeView* const state
  ) noexcept
  {
    if (state->begin == nullptr) {
      return true;
    }

    const std::ptrdiff_t byteDelta = state->end - state->begin;
    return (byteDelta / 28) == 0;
  }

  /**
   * Address: 0x00799160 (FUN_00799160)
   *
   * What it does:
   * Computes one address lane as `begin + index*28` from span lane `+0x13C`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride28AddressFromBeginAt13C(
    const std::int32_t index,
    const Stride28BeginEndAndFlagsRuntimeView* const state
  ) noexcept
  {
    const std::uint32_t beginWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(state->begin));
    const std::uint32_t byteOffset = static_cast<std::uint32_t>(index) * 28u;
    return beginWord + byteOffset;
  }

  /**
   * Address: 0x00799180 (FUN_00799180)
   *
   * What it does:
   * Reads one dword lane at offset `+0x148`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane148(
    const Stride28BeginEndAndFlagsRuntimeView* const state
  ) noexcept
  {
    return state->lane148;
  }

  /**
   * Address: 0x00799190 (FUN_00799190)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x150`.
   */
  [[maybe_unused]] Stride28BeginEndAndFlagsRuntimeView* SetByteFlag150(
    Stride28BeginEndAndFlagsRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag150 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x007991A0 (FUN_007991A0)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x151`.
   */
  [[maybe_unused]] Stride28BeginEndAndFlagsRuntimeView* SetByteFlag151(
    Stride28BeginEndAndFlagsRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag151 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x00799700 (FUN_00799700)
   *
   * What it does:
   * Writes six consecutive dword lanes at offsets `+0x120..+0x134`.
   */
  [[maybe_unused]] WordLanesAt11CThrough134RuntimeView* SetWordLanes120Through134FromSixInputs(
    WordLanesAt11CThrough134RuntimeView* const outValue,
    const std::uint32_t lane124Value,
    const std::uint32_t lane120Value,
    const std::uint32_t lane128Value,
    const std::uint32_t lane12CValue,
    const std::uint32_t lane130Value,
    const std::uint32_t lane134Value
  ) noexcept
  {
    outValue->lane120 = lane120Value;
    outValue->lane124 = lane124Value;
    outValue->lane128 = lane128Value;
    outValue->lane12C = lane12CValue;
    outValue->lane130 = lane130Value;
    outValue->lane134 = lane134Value;
    return outValue;
  }

  using ZeroWordAndFloatCall = std::int32_t(__stdcall*)(std::uint32_t lane00, float lane04);

  struct Slot58DispatchTableRuntimeView
  {
    std::byte pad0000_0057[0x58];
    ZeroWordAndFloatCall slot58; // +0x58
  };
#if defined(_M_IX86)
  static_assert(offsetof(Slot58DispatchTableRuntimeView, slot58) == 0x58, "Slot58DispatchTableRuntimeView::slot58 offset");
#endif

  struct Slot58DispatchTableOwnerRuntimeView
  {
    Slot58DispatchTableRuntimeView* dispatchTable; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(Slot58DispatchTableOwnerRuntimeView) == 0x04, "Slot58DispatchTableOwnerRuntimeView size must be 0x04");
#endif

  /**
   * Address: 0x0079A860 (FUN_0079A860)
   *
   * What it does:
   * Invokes dispatch-table slot `+0x58` with zero scalar and zero float args.
   */
  [[maybe_unused]] std::int32_t InvokeSlot58WithZeroWordAndFloat(
    const Slot58DispatchTableOwnerRuntimeView* const owner
  ) noexcept
  {
    return owner->dispatchTable->slot58(0u, 0.0f);
  }

  struct FloatLanes10And20RuntimeView
  {
    std::byte pad0000_000F[0x10];
    float lane10; // +0x10
    std::byte pad0014_001F[0x0C];
    float lane20; // +0x20
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatLanes10And20RuntimeView, lane10) == 0x10, "FloatLanes10And20RuntimeView::lane10 offset");
  static_assert(offsetof(FloatLanes10And20RuntimeView, lane20) == 0x20, "FloatLanes10And20RuntimeView::lane20 offset");
#endif

  struct FloatLanePointerAt11CRuntimeView
  {
    std::byte pad0000_011B[0x11C];
    const FloatLanes10And20RuntimeView* lanes; // +0x11C
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatLanePointerAt11CRuntimeView, lanes) == 0x11C, "FloatLanePointerAt11CRuntimeView::lanes offset");
#endif

  /**
   * Address: 0x0079A940 (FUN_0079A940)
   *
   * What it does:
   * Returns the sum of indirect float lanes `+0x10` and `+0x20`.
   */
  [[maybe_unused]] float SumIndirectFloatLanes10And20(
    const FloatLanePointerAt11CRuntimeView* const source
  ) noexcept
  {
    return source->lanes->lane20 + source->lanes->lane10;
  }

  struct WordLane00RuntimeView
  {
    std::uint32_t lane00; // +0x00
  };
#if defined(_M_IX86)
  static_assert(sizeof(WordLane00RuntimeView) == 0x04, "WordLane00RuntimeView size must be 0x04");
#endif

  /**
   * Address: 0x0079C9A0 (FUN_0079C9A0)
   *
   * What it does:
   * Returns the pointer whose lane `+0x00` value is greater-or-equal.
   */
  [[maybe_unused]] WordLane00RuntimeView* SelectWordPointerByGreaterOrEqual(
    WordLane00RuntimeView* const left,
    WordLane00RuntimeView* const right
  ) noexcept
  {
    if (right->lane00 >= left->lane00) {
      return right;
    }
    return left;
  }

  /**
   * Address: 0x0079C9B0 (FUN_0079C9B0)
   *
   * What it does:
   * Returns the pointer whose lane `+0x00` value is less-or-equal.
   */
  [[maybe_unused]] WordLane00RuntimeView* SelectWordPointerByLessOrEqual(
    WordLane00RuntimeView* const left,
    WordLane00RuntimeView* const right
  ) noexcept
  {
    if (left->lane00 >= right->lane00) {
      return right;
    }
    return left;
  }

  struct WordAt18RuntimeView
  {
    std::byte pad0000_0017[0x18];
    std::uint32_t lane18; // +0x18
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAt18RuntimeView, lane18) == 0x18, "WordAt18RuntimeView::lane18 offset");
#endif

  /**
   * Address: 0x0079DC50 (FUN_0079DC50)
   *
   * What it does:
   * Reads one dword lane at offset `+0x18`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane18(
    const WordAt18RuntimeView* const source
  ) noexcept
  {
    return source->lane18;
  }

  struct WordAndFlagLanesRuntimeView
  {
    std::byte pad0000_0120[0x121];
    std::uint8_t flag121; // +0x121
    std::byte pad0122_0123[0x02];
    std::uint8_t flag124; // +0x124
    std::byte pad0125_013B[0x17];
    std::uint32_t lane13C; // +0x13C
    std::uint8_t flag140; // +0x140
    std::uint8_t flag141; // +0x141
    std::uint8_t flag142; // +0x142
    std::uint8_t flag143; // +0x143
    std::byte pad0144_0153[0x10];
    std::uint32_t lane154; // +0x154
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag121) == 0x121, "WordAndFlagLanesRuntimeView::flag121 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag124) == 0x124, "WordAndFlagLanesRuntimeView::flag124 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, lane13C) == 0x13C, "WordAndFlagLanesRuntimeView::lane13C offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag140) == 0x140, "WordAndFlagLanesRuntimeView::flag140 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag141) == 0x141, "WordAndFlagLanesRuntimeView::flag141 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag142) == 0x142, "WordAndFlagLanesRuntimeView::flag142 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, flag143) == 0x143, "WordAndFlagLanesRuntimeView::flag143 offset");
  static_assert(offsetof(WordAndFlagLanesRuntimeView, lane154) == 0x154, "WordAndFlagLanesRuntimeView::lane154 offset");
#endif

  /**
   * Address: 0x0079E090 (FUN_0079E090)
   *
   * What it does:
   * Stores one dword lane at `+0x13C` and sets byte flag `+0x124` to one.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetWord13CAndMarkFlag124(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane13C = value;
    outValue->flag124 = 1u;
    return outValue;
  }

  /**
   * Address: 0x0079E0A0 (FUN_0079E0A0)
   *
   * What it does:
   * Reads one dword lane at offset `+0x13C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane13C(
    const WordAndFlagLanesRuntimeView* const source
  ) noexcept
  {
    return source->lane13C;
  }

  /**
   * Address: 0x0079F190 (FUN_0079F190)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x121`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetByteFlag121(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag121 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x007A0070 (FUN_007A0070)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7A0070(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007A00B0 (FUN_007A00B0)
   *
   * What it does:
   * Returns one dword lane then clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeScalarWordAndClear(
    std::uint32_t* const lane
  ) noexcept
  {
    const std::uint32_t result = *lane;
    *lane = 0u;
    return result;
  }

  /**
   * Address: 0x007A0350 (FUN_007A0350)
   *
   * What it does:
   * Reads one dword lane at offset `+0x154`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane154(
    const WordAndFlagLanesRuntimeView* const source
  ) noexcept
  {
    return source->lane154;
  }

  struct FloatQuartetRuntimeView
  {
    float lane00; // +0x00
    float lane04; // +0x04
    float lane08; // +0x08
    float lane0C; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(sizeof(FloatQuartetRuntimeView) == 0x10, "FloatQuartetRuntimeView size must be 0x10");
#endif

  /**
   * Address: 0x007A1520 (FUN_007A1520)
   *
   * What it does:
   * Maps two source lanes from a four-float range into one output range.
   */
  [[maybe_unused]] float* MapTwoFloatsFromQuartetIntoRange(
    const FloatQuartetRuntimeView* const source,
    const float* const outputRangeMin,
    const float* const outputRangeMax,
    float* const outLaneA,
    float* const outLaneB
  ) noexcept
  {
    const float lane00 = source->lane00;
    const float lane04 = source->lane04;
    const float lane08 = source->lane08;
    const float lane0C = source->lane0C;
    const float denominator = lane04 - lane00;
    const float outputDelta = *outputRangeMax - *outputRangeMin;

    *outLaneA = (((lane08 - lane00) / denominator) * outputDelta) + *outputRangeMin;
    *outLaneB = (outputDelta * ((lane0C - lane00) / denominator)) + *outputRangeMin;
    return outLaneA;
  }

  struct Stride8BeginCursorEndBaseRuntimeView
  {
    std::byte* begin; // +0x00
    std::byte* cursor; // +0x04
    std::byte* end; // +0x08
    std::byte* base; // +0x0C
    std::byte inlineStorage[0x20]; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(Stride8BeginCursorEndBaseRuntimeView, begin) == 0x00, "Stride8BeginCursorEndBaseRuntimeView::begin offset");
  static_assert(offsetof(Stride8BeginCursorEndBaseRuntimeView, cursor) == 0x04, "Stride8BeginCursorEndBaseRuntimeView::cursor offset");
  static_assert(offsetof(Stride8BeginCursorEndBaseRuntimeView, end) == 0x08, "Stride8BeginCursorEndBaseRuntimeView::end offset");
  static_assert(offsetof(Stride8BeginCursorEndBaseRuntimeView, base) == 0x0C, "Stride8BeginCursorEndBaseRuntimeView::base offset");
  static_assert(offsetof(Stride8BeginCursorEndBaseRuntimeView, inlineStorage) == 0x10, "Stride8BeginCursorEndBaseRuntimeView::inlineStorage offset");
#endif

  /**
   * Address: 0x007A23E0 (FUN_007A23E0)
   *
   * What it does:
   * Initializes an inline 8-byte-stride span header with capacity 8 elements.
   */
  [[maybe_unused]] Stride8BeginCursorEndBaseRuntimeView* InitializeInlineStride8SpanHeader(
    Stride8BeginCursorEndBaseRuntimeView* const outValue
  ) noexcept
  {
    outValue->begin = outValue->inlineStorage;
    outValue->cursor = outValue->inlineStorage;
    outValue->end = outValue->inlineStorage + sizeof(outValue->inlineStorage);
    outValue->base = outValue->inlineStorage;
    return outValue;
  }

  /**
   * Address: 0x007A24A0 (FUN_007A24A0)
   *
   * What it does:
   * Returns element count for one 8-byte-stride span at `begin/cursor`.
   */
  [[maybe_unused]] std::int32_t CountStride8ElementsFromBeginAndCursor(
    const Stride8BeginCursorEndBaseRuntimeView* const source
  ) noexcept
  {
    return static_cast<std::int32_t>((source->cursor - source->begin) / 8);
  }

  /**
   * Address: 0x007A2580 (FUN_007A2580)
   *
   * What it does:
   * Initializes an external 8-byte-stride span header from base and count.
   */
  [[maybe_unused]] Stride8BeginCursorEndBaseRuntimeView* InitializeExternalStride8SpanHeader(
    Stride8BeginCursorEndBaseRuntimeView* const outValue,
    const std::int32_t elementCount,
    std::byte* const base
  ) noexcept
  {
    outValue->begin = base;
    outValue->cursor = base;
    outValue->end = base + (static_cast<std::ptrdiff_t>(elementCount) * 8);
    outValue->base = base;
    return outValue;
  }

  struct FloatPairRuntimeView
  {
    float lane00; // +0x00
    float lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(FloatPairRuntimeView) == 0x08, "FloatPairRuntimeView size must be 0x08");
#endif

  [[nodiscard]] FloatPairRuntimeView* MoveFloatPairRangeBackward(
    FloatPairRuntimeView* destinationEnd,
    const FloatPairRuntimeView* sourceBegin,
    const FloatPairRuntimeView* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      destinationEnd->lane00 = sourceEnd->lane00;
      destinationEnd->lane04 = sourceEnd->lane04;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x007A2920 (FUN_007A2920)
   *
   * What it does:
   * Backward-copies one range of float-pair elements.
   */
  [[maybe_unused]] FloatPairRuntimeView* MoveFloatPairRangeBackwardPrimary(
    FloatPairRuntimeView* const destinationEnd,
    const FloatPairRuntimeView* const sourceBegin,
    const FloatPairRuntimeView* const sourceEnd
  ) noexcept
  {
    return MoveFloatPairRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x007A2960 (FUN_007A2960)
   *
   * What it does:
   * Alias lane for backward-copying one range of float-pair elements.
   */
  [[maybe_unused]] FloatPairRuntimeView* MoveFloatPairRangeBackwardSecondary(
    FloatPairRuntimeView* const destinationEnd,
    const FloatPairRuntimeView* const sourceBegin,
    const FloatPairRuntimeView* const sourceEnd
  ) noexcept
  {
    return MoveFloatPairRangeBackward(destinationEnd, sourceBegin, sourceEnd);
  }

  struct FloatAt1CRuntimeView
  {
    std::byte pad0000_001B[0x1C];
    float lane1C; // +0x1C
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatAt1CRuntimeView, lane1C) == 0x1C, "FloatAt1CRuntimeView::lane1C offset");
#endif

  /**
   * Address: 0x007A29A0 (FUN_007A29A0)
   *
   * What it does:
   * Reads one float lane at offset `+0x1C`.
   */
  [[maybe_unused]] float ReadFloatLane1C(
    const FloatAt1CRuntimeView* const source
  ) noexcept
  {
    return source->lane1C;
  }

  /**
   * Address: 0x007A2A10 (FUN_007A2A10)
   *
   * What it does:
   * Stores one dword lane at offset `+0x13C`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetWordLane13C(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane13C = value;
    return outValue;
  }

  /**
   * Address: 0x007A2A20 (FUN_007A2A20)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x140`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetByteFlag140(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag140 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x007A2A30 (FUN_007A2A30)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x142`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetByteFlag142(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag142 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x007A2A40 (FUN_007A2A40)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x143`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetByteFlag143(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag143 = flagValue;
    return outValue;
  }

  /**
   * Address: 0x007A2A80 (FUN_007A2A80)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x141`.
   */
  [[maybe_unused]] WordAndFlagLanesRuntimeView* SetByteFlag141(
    WordAndFlagLanesRuntimeView* const outValue,
    const std::uint8_t flagValue
  ) noexcept
  {
    outValue->flag141 = flagValue;
    return outValue;
  }

  struct ByteAt2BRuntimeView
  {
    std::byte pad0000_002A[0x2B];
    std::uint8_t lane2B; // +0x2B
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteAt2BRuntimeView, lane2B) == 0x2B, "ByteAt2BRuntimeView::lane2B offset");
#endif

  /**
   * Address: 0x007A4440 (FUN_007A4440)
   *
   * What it does:
   * Reads one byte lane at offset `+0x2B`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane2B(
    const ByteAt2BRuntimeView* const source
  ) noexcept
  {
    return source->lane2B;
  }

  struct PointerWithWordAt0CRuntimeView7B
  {
    std::uint32_t lane00; // +0x00
    std::byte pad04_0B[0x08];
    std::uint32_t lane0C; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(offsetof(PointerWithWordAt0CRuntimeView7B, lane0C) == 0x0C, "PointerWithWordAt0CRuntimeView7B::lane0C offset");
#endif

  struct DwordDwordWord16RuntimeView7B
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint16_t lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(offsetof(DwordDwordWord16RuntimeView7B, lane08) == 0x08, "DwordDwordWord16RuntimeView7B::lane08 offset");
#endif

  [[nodiscard]] std::intptr_t InvokeDeleteFlagVirtualSlot0IfPresent(void* const object) noexcept
  {
    if (object == nullptr) {
      return 0;
    }
    auto* const vtable = *reinterpret_cast<void***>(object);
    return InvokeScalarDeletingDtorSlot0(object, vtable);
  }

  /**
   * Address: 0x0089E620 (FUN_0089E620)
   *
   * What it does:
   * Stores one two-dword lane pair from ordered scalar inputs.
   */
  [[nodiscard]] DwordPairRuntimeView* StoreDwordPairFromTwoScalars7B(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x0089E550 (FUN_0089E550)
   *
   * What it does:
   * Rebinds one intrusive refcounted-object word and applies release/retain
   * semantics (`--refCount` then virtual slot-0 delete with flag `1` on zero).
   */
  [[maybe_unused]] std::uint32_t* AssignIntrusiveRefCountedWord(
    std::uint32_t* const destinationWord,
    const std::uint32_t incomingWord
  ) noexcept
  {
    return AssignIntrusiveRefCountedObjectWord(destinationWord, incomingWord);
  }

  /**
   * Address: 0x0089E580 (FUN_0089E580)
   * Address: 0x00794E10 (FUN_00794E10)
   *
   * What it does:
   * Rebinds one intrusive refcounted-object word from a source slot with the
   * same release/retain transfer semantics as `AssignIntrusiveRefCountedWord`.
   */
  [[maybe_unused]] std::uint32_t* AssignIntrusiveRefCountedWordFromSlot(
    const std::uint32_t* const sourceWordSlot,
    std::uint32_t* const destinationWord
  ) noexcept
  {
    return AssignIntrusiveRefCountedObjectWord(destinationWord, *sourceWordSlot);
  }

  [[nodiscard]] DwordDwordWord16RuntimeView7B* StoreDwordDwordWord16Record7B(
    DwordDwordWord16RuntimeView7B* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint16_t lane08
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    return outValue;
  }

  /**
   * Address: 0x007BB2B0 (FUN_007BB2B0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7BB2B0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007BB320 (FUN_007BB320)
   *
   * What it does:
   * Alias lane for storing one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7BB320(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007BB580 (FUN_007BB580)
   *
   * What it does:
   * Zeros one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLane7BB580(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007BB8E0 (FUN_007BB8E0)
   *
   * What it does:
   * Alias lane for zeroing one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLane7BB8E0(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007BB8F0 (FUN_007BB8F0)
   *
   * What it does:
   * Swaps one leading dword lane between two word slots.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleDwordLane7BB8F0(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  /**
   * Address: 0x007BB900 (FUN_007BB900)
   *
   * What it does:
   * Alias lane for swapping one leading dword lane.
   */
  [[maybe_unused]] std::uint32_t* SwapSingleDwordLane7BB900(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotsIota(left, right);
  }

  /**
   * Address: 0x007BB910 (FUN_007BB910)
   *
   * What it does:
   * Stores source pointer plus source lane `+0x0C` into a two-dword record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StorePointerAndWordAt0C7BB910(
    DwordPairRuntimeView* const outValue,
    const PointerWithWordAt0CRuntimeView7B* const source
  ) noexcept
  {
    outValue->lane00 = reinterpret_cast<std::uint32_t>(const_cast<PointerWithWordAt0CRuntimeView7B*>(source));
    outValue->lane04 = source->lane0C;
    return outValue;
  }

  /**
   * Address: 0x007BBC40 (FUN_007BBC40)
   *
   * What it does:
   * Alias lane for zeroing one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLane7BBC40(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007BC230 (FUN_007BC230)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7BC230(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007BC240 (FUN_007BC240)
   *
   * What it does:
   * Alias lane for storing one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7BC240(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007BC250 (FUN_007BC250)
   *
   * What it does:
   * Stores one `*baseWord + index*36` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride36_7BC250(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    *outValue = *baseWord + (static_cast<std::uint32_t>(index) * 36u);
    return outValue;
  }

  /**
   * Address: 0x007BC280 (FUN_007BC280)
   *
   * What it does:
   * Stores two scalar dword lanes into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairLane7BC280(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007BC3A0 (FUN_007BC3A0)
   *
   * What it does:
   * Alias lane for storing two scalar dwords into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairLane7BC3A0(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007BC3C0 (FUN_007BC3C0)
   *
   * What it does:
   * Packs four dword lanes plus one 16-bit lane (zero-extended) into a
   * five-dword record.
   */
  [[maybe_unused]] FiveWordRuntimeView* ComposeFiveWordRecordWithWord16Tail7BC3C0(
    FiveWordRuntimeView* const outValue,
    const std::uint16_t lane10LowWord,
    const std::uint32_t lane08,
    const std::uint32_t lane0C,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = lane0C;
    outValue->lane10 = static_cast<std::uint32_t>(lane10LowWord);
    return outValue;
  }

  /**
   * Address: 0x007BCB50 (FUN_007BCB50)
   *
   * What it does:
   * Invokes scalar-deleting destructor slot `+0x00` with delete flag `1`
   * when object is non-null.
   */
  [[maybe_unused]] std::intptr_t DestroyViaVirtualSlot0WithDeleteFlag7BCB50(void* const object) noexcept
  {
    return InvokeDeleteFlagVirtualSlot0IfPresent(object);
  }

  /**
   * Address: 0x007BCB60 (FUN_007BCB60)
   *
   * What it does:
   * Alias lane for scalar-deleting destructor dispatch.
   */
  [[maybe_unused]] std::intptr_t DestroyViaVirtualSlot0WithDeleteFlag7BCB60(void* const object) noexcept
  {
    return InvokeDeleteFlagVirtualSlot0IfPresent(object);
  }

  /**
   * Address: 0x007BCF90 (FUN_007BCF90)
   *
   * What it does:
   * Stores two scalar lanes and one source dword triplet into a five-dword
   * record.
   */
  [[maybe_unused]] FiveWordRuntimeView* ComposeFiveWordRecordFromPairAndTriplet7BCF90(
    FiveWordRuntimeView* const outValue,
    const DwordTripleLaneRuntimeView* const sourceTriplet,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = sourceTriplet->lane00;
    outValue->lane0C = sourceTriplet->lane04;
    outValue->lane10 = sourceTriplet->lane08;
    return outValue;
  }

  /**
   * Address: 0x007BCFC0 (FUN_007BCFC0)
   *
   * What it does:
   * Stores two scalar dword lanes into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairLane7BCFC0(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007BCFD0 (FUN_007BCFD0)
   *
   * What it does:
   * Stores two dword lanes plus one 16-bit lane into a packed record.
   */
  [[maybe_unused]] DwordDwordWord16RuntimeView7B* StoreDwordDwordWord16Record7BCFD0(
    DwordDwordWord16RuntimeView7B* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint16_t lane08
  ) noexcept
  {
    return StoreDwordDwordWord16Record7B(outValue, lane00, lane04, lane08);
  }

  /**
   * Address: 0x007BCFF0 (FUN_007BCFF0)
   *
   * What it does:
   * Copies one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordLane7BCFF0(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return StoreDword(outValue, *source);
  }

  /**
   * Address: 0x007BD000 (FUN_007BD000)
   *
   * What it does:
   * Alias lane for copying one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordLane7BD000(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return StoreDword(outValue, *source);
  }

  /**
   * Address: 0x007BD010 (FUN_007BD010)
   *
   * What it does:
   * Copies one 16-bit lane.
   */
  [[maybe_unused]] std::uint16_t* CopySingleWord16Lane7BD010(
    std::uint16_t* const outValue,
    const std::uint16_t* const source
  ) noexcept
  {
    *outValue = *source;
    return outValue;
  }

  /**
   * Address: 0x007BD060 (FUN_007BD060)
   *
   * What it does:
   * Alias lane for storing two scalar dwords into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairLane7BD060(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007BD2B0 (FUN_007BD2B0)
   *
   * What it does:
   * Alias lane for storing two dwords and one 16-bit lane.
   */
  [[maybe_unused]] DwordDwordWord16RuntimeView7B* StoreDwordDwordWord16Record7BD2B0(
    DwordDwordWord16RuntimeView7B* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint16_t lane08
  ) noexcept
  {
    return StoreDwordDwordWord16Record7B(outValue, lane00, lane04, lane08);
  }

  /**
   * Address: 0x007BD340 (FUN_007BD340)
   *
   * What it does:
   * Copies one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLane7BD340(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    if (outValue != nullptr) {
      outValue->lane00 = source->lane00;
      outValue->lane04 = source->lane04;
    }
    return outValue;
  }

  /**
   * Address: 0x007BD350 (FUN_007BD350)
   *
   * What it does:
   * Alias lane for storing source pointer plus source lane `+0x0C` into one
   * two-dword record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StorePointerAndWordAt0C7BD350(
    DwordPairRuntimeView* const outValue,
    const PointerWithWordAt0CRuntimeView7B* const source
  ) noexcept
  {
    outValue->lane00 = reinterpret_cast<std::uint32_t>(const_cast<PointerWithWordAt0CRuntimeView7B*>(source));
    outValue->lane04 = source->lane0C;
    return outValue;
  }

  /**
   * Address: 0x007BD4B0 (FUN_007BD4B0)
   *
   * What it does:
   * Alias lane for storing two scalar dword lanes into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairLane7BD4B0(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007BD4C0 (FUN_007BD4C0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7BD4C0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007BD4D0 (FUN_007BD4D0)
   *
   * What it does:
   * Alias lane for copying one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairLane7BD4D0(
    DwordPairRuntimeView* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    if (outValue != nullptr) {
      outValue->lane00 = source->lane00;
      outValue->lane04 = source->lane04;
    }
    return outValue;
  }

  /**
   * Address: 0x007BD790 (FUN_007BD790)
   *
   * What it does:
   * Replaces weak-owner pair contents, retains incoming owner weak-count, and
   * releases previous owner weak-count.
   */
  [[maybe_unused]] std::intptr_t ReplaceWeakOwnerPairAndRetainIncoming7BD790(
    const std::uint32_t objectWord,
    SharedOwnerControlBlockRuntimeView* const* const incomingOwnerSlot,
    WeakOwnerPairRuntimeView* const destination
  ) noexcept
  {
    return ReplaceWeakOwnerPairAndRetainIncoming(objectWord, incomingOwnerSlot, destination);
  }
  struct TreeNodeFlagAt1DRuntimeView
  {
    TreeNodeFlagAt1DRuntimeView* left;         // +0x00
    TreeNodeFlagAt1DRuntimeView* parentOrRoot; // +0x04
    TreeNodeFlagAt1DRuntimeView* right;        // +0x08
    std::uint32_t key;                         // +0x0C
    std::byte pad10_1C[0x0D];
    std::uint8_t isSentinel;                   // +0x1D
  };
#if defined(_M_IX86)
  static_assert(offsetof(TreeNodeFlagAt1DRuntimeView, key) == 0x0C, "TreeNodeFlagAt1DRuntimeView::key offset must be 0x0C");
  static_assert(
    offsetof(TreeNodeFlagAt1DRuntimeView, isSentinel) == 0x1D,
    "TreeNodeFlagAt1DRuntimeView::isSentinel offset must be 0x1D"
  );
#endif

  struct IndirectWordPointerAt4RuntimeView
  {
    std::uint32_t lane00;                  // +0x00
    const std::uint32_t* const* slotAt04; // +0x04
  };

  struct IntrusiveOwnerAt10RuntimeView
  {
    std::byte pad00_0F[0x10];
    IntrusiveLinkRuntimeView link; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(IntrusiveOwnerAt10RuntimeView, link) == 0x10, "IntrusiveOwnerAt10RuntimeView::link offset must be 0x10");
#endif

  struct FourDwordAndTwoByteInitRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint8_t lane10;  // +0x10
    std::uint8_t lane11;  // +0x11
  };
  static_assert(offsetof(FourDwordAndTwoByteInitRuntimeView, lane10) == 0x10, "FourDwordAndTwoByteInitRuntimeView::lane10 offset must be 0x10");
  static_assert(offsetof(FourDwordAndTwoByteInitRuntimeView, lane11) == 0x11, "FourDwordAndTwoByteInitRuntimeView::lane11 offset must be 0x11");

  struct InlineStringLaneRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::byte pad08_0B[0x04];
    std::uint8_t lane0C; // +0x0C
    std::byte pad0D_1B[0x0F];
    std::uint32_t size1C;     // +0x1C
    std::uint32_t capacity20; // +0x20
  };
  static_assert(offsetof(InlineStringLaneRuntimeView, lane0C) == 0x0C, "InlineStringLaneRuntimeView::lane0C offset must be 0x0C");
  static_assert(offsetof(InlineStringLaneRuntimeView, size1C) == 0x1C, "InlineStringLaneRuntimeView::size1C offset must be 0x1C");
  static_assert(offsetof(InlineStringLaneRuntimeView, capacity20) == 0x20, "InlineStringLaneRuntimeView::capacity20 offset must be 0x20");

  [[nodiscard]] std::uint32_t* CopyWordIfDestinationPresent(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    if (outValue != nullptr) {
      *outValue = *source;
    }
    return outValue;
  }

  [[nodiscard]] IntrusiveLinkRuntimeView** UnlinkOwnerNodeAtOffset10(
    IntrusiveOwnerAt10RuntimeView* const owner
  ) noexcept
  {
    return UnlinkIntrusiveLinkNode(&owner->link);
  }

  [[nodiscard]] std::uint8_t* FillHalfwordCountWithValue(
    std::uint8_t* const destination,
    const std::uint16_t value,
    const std::uint32_t halfwordCount
  ) noexcept
  {
    std::uint8_t* write = destination;
    const std::uint8_t low = static_cast<std::uint8_t>(value & 0x00FFu);
    const std::uint8_t high = static_cast<std::uint8_t>(value >> 8u);
    std::uint32_t remaining = halfwordCount;
    while (remaining != 0u) {
      write[0] = low;
      write[1] = high;
      write += 2;
      --remaining;
    }
    return destination;
  }

  /**
   * Address: 0x007B2FF0 (FUN_007B2FF0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchAlpha(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B3040 (FUN_007B3040)
   *
   * What it does:
   * Resolves one payload pointer lane as `headerAt+0x04 - 8` when header is
   * present; otherwise returns zero.
   */
  [[maybe_unused]] std::uint32_t ResolvePayloadAddressFromHeaderMinus8(
    const BaseAddressAt4RuntimeView* const source
  ) noexcept
  {
    const std::uint32_t headerAddress = source->baseAddress;
    if (headerAddress == 0u) {
      return 0u;
    }
    return headerAddress - 8u;
  }

  /**
   * Address: 0x007B3740 (FUN_007B3740)
   *
   * What it does:
   * Stores one dword read from a double-indirect lane at `*(*source+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordFromLane04(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, **source->slotAt04);
  }

  /**
   * Address: 0x007B3AB0 (FUN_007B3AB0)
   *
   * What it does:
   * Returns lower-bound candidate from one tree header using key lane
   * `*keyValue`.
   */
  [[maybe_unused]] TreeNodeFlagAt1DRuntimeView* FindLowerBoundTreeNodeFlag1D(
    TreeHeaderAt4RuntimeView<TreeNodeFlagAt1DRuntimeView>* const tree,
    const std::uint32_t* const keyValue
  ) noexcept
  {
    return FindLowerBoundTreeNode(tree->header, *keyValue);
  }

  /**
   * Address: 0x007B3B40 (FUN_007B3B40)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchBeta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B3B90 (FUN_007B3B90)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneBatchAlpha(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007B3BA0 (FUN_007B3BA0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchGamma(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B3BE0 (FUN_007B3BE0)
   *
   * What it does:
   * Returns true when lane `+0x04` is neither null nor sentinel value `8`.
   */
  [[maybe_unused]] bool HasNonNullNonSentinelLane04(const BaseAddressAt4RuntimeView* const source) noexcept
  {
    return source->baseAddress != 0u && source->baseAddress != 8u;
  }

  /**
   * Address: 0x007B3DB0 (FUN_007B3DB0)
   *
   * What it does:
   * Unlinks one intrusive owner-node stored at `owner+0x10`.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView** UnlinkIntrusiveOwnerNodeAt10A(
    IntrusiveOwnerAt10RuntimeView* const owner
  ) noexcept
  {
    return UnlinkOwnerNodeAtOffset10(owner);
  }

  /**
   * Address: 0x007B4520 (FUN_007B4520)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchDelta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B4550 (FUN_007B4550)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneBatchBeta(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007B4560 (FUN_007B4560)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchEpsilon(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B45A0 (FUN_007B45A0)
   *
   * What it does:
   * Initializes one four-dword-plus-two-byte lane record.
   */
  [[maybe_unused]] FourDwordAndTwoByteInitRuntimeView* InitializeFourDwordTwoByteLanePrimary(
    FourDwordAndTwoByteInitRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00,
    const std::uint32_t lane08,
    const std::uint32_t* const lane0CSource,
    const std::uint8_t lane10
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = *lane0CSource;
    outValue->lane10 = lane10;
    outValue->lane11 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007B45D0 (FUN_007B45D0)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneBatch(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007B4BB0 (FUN_007B4BB0)
   *
   * What it does:
   * Conditionally copy-assigns one dword when destination is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentPrimary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B4D00 (FUN_007B4D00)
   *
   * What it does:
   * Alias lane for conditional one-dword copy.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentSecondary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B4D70 (FUN_007B4D70)
   *
   * What it does:
   * Alias lane for conditional one-dword copy.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentTertiary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B4E30 (FUN_007B4E30)
   *
   * What it does:
   * Unlinks one intrusive owner-node stored at `owner+0x10`.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView** UnlinkIntrusiveOwnerNodeAt10B(
    IntrusiveOwnerAt10RuntimeView* const owner
  ) noexcept
  {
    return UnlinkOwnerNodeAtOffset10(owner);
  }

  /**
   * Address: 0x007B4F80 (FUN_007B4F80)
   *
   * What it does:
   * Alias lane for conditional one-dword copy.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentQuaternary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B5000 (FUN_007B5000)
   *
   * What it does:
   * Alias lane for conditional one-dword copy.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentQuinary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B5030 (FUN_007B5030)
   *
   * What it does:
   * Alias lane for conditional one-dword copy.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresentSenary(
    std::uint32_t* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, source);
  }

  /**
   * Address: 0x007B5040 (FUN_007B5040)
   *
   * What it does:
   * Unlinks one intrusive owner-node stored at `owner+0x10` and returns owner.
   */
  [[maybe_unused]] IntrusiveOwnerAt10RuntimeView* UnlinkIntrusiveOwnerNodeAt10AndReturnOwner(
    IntrusiveOwnerAt10RuntimeView* const owner
  ) noexcept
  {
    (void)UnlinkOwnerNodeAtOffset10(owner);
    return owner;
  }

  /**
   * Address: 0x007B50A0 (FUN_007B50A0)
   *
   * What it does:
   * Alias lane for unlinking one intrusive owner-node at `owner+0x10`.
   */
  [[maybe_unused]] IntrusiveLinkRuntimeView** UnlinkIntrusiveOwnerNodeAt10C(
    IntrusiveOwnerAt10RuntimeView* const owner
  ) noexcept
  {
    return UnlinkOwnerNodeAtOffset10(owner);
  }

  /**
   * Address: 0x007B5140 (FUN_007B5140)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchZeta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007B6470 (FUN_007B6470)
   *
   * What it does:
   * Fills `halfwordCount` 16-bit elements in destination with `value`.
   */
  [[maybe_unused]] char* FillHalfwordSpanByValueThenCount(
    char* const destination,
    const std::uint16_t value,
    const std::uint32_t halfwordCount
  ) noexcept
  {
    return reinterpret_cast<char*>(
      FillHalfwordCountWithValue(
        reinterpret_cast<std::uint8_t*>(destination),
        value,
        halfwordCount
      )
    );
  }

  /**
   * Address: 0x007B64B0 (FUN_007B64B0)
   *
   * What it does:
   * Alias lane for filling 16-bit destination span with one value.
   */
  [[maybe_unused]] char* FillHalfwordSpanByCountThenValue(
    char* const destination,
    const std::uint32_t halfwordCount,
    const std::uint16_t value
  ) noexcept
  {
    return reinterpret_cast<char*>(
      FillHalfwordCountWithValue(
        reinterpret_cast<std::uint8_t*>(destination),
        value,
        halfwordCount
      )
    );
  }

  /**
   * Address: 0x007B6520 (FUN_007B6520)
   *
   * What it does:
   * Initializes one inline-string lane block with external pointer seed.
   */
  [[maybe_unused]] InlineStringLaneRuntimeView* InitializeInlineStringLaneWithExternalSeed(
    InlineStringLaneRuntimeView* const outValue,
    const std::uint32_t externalLane04
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = externalLane04;
    outValue->capacity20 = 15u;
    outValue->size1C = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x007BB100 (FUN_007BB100)
   *
   * What it does:
   * Computes one `base@+0x04 + index*36` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride36AddressFromBaseAt4LaneA(
    const std::int32_t index,
    const BaseAddressAt4RuntimeView* const source
  ) noexcept
  {
    return ComputeStride36AddressFromBaseAt4(index, source);
  }

  /**
   * Address: 0x007BB110 (FUN_007BB110)
   *
   * What it does:
   * Alias lane for `base@+0x04 + index*36`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride36AddressFromBaseAt4LaneB(
    const std::int32_t index,
    const BaseAddressAt4RuntimeView* const source
  ) noexcept
  {
    return ComputeStride36AddressFromBaseAt4(index, source);
  }

  /**
   * Address: 0x007BB260 (FUN_007BB260)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneBatch(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007C8A40 (FUN_007C8A40)
   *
   * What it does:
   * Stores one dword loaded through source lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04Word7C8A40(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007C8CD0 (FUN_007C8CD0)
   *
   * What it does:
   * Initializes one intrusive node as self-linked (`prev=this`, `next=this`).
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* InitializeIntrusiveNodeSelfLink7C8CD0(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    (void)InitializeTwoWordSelfLink(reinterpret_cast<std::uint32_t*>(node));
    return node;
  }

  /**
   * Address: 0x007C8CF0 (FUN_007C8CF0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C8CF0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C8D10 (FUN_007C8D10)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C8D10(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C8D30 (FUN_007C8D30)
   *
   * What it does:
   * Unlinks one intrusive node and relinks it after anchor.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkIntrusiveNodeAfterAnchor7C8D30(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkIntrusiveNodeAfterAnchor(node, anchor);
  }

  /**
   * Address: 0x007C8E50 (FUN_007C8E50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C8E50(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C8E80 (FUN_007C8E80)
   *
   * What it does:
   * Clears dword lanes `+0x04/+0x08/+0x0C` in one 4-lane record.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearDwordTailLanes04To0C7C8E80(
    DwordQuadRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x007C8F20 (FUN_007C8F20)
   *
   * What it does:
   * Computes one `source@+0x04 + index*24` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride24AddressFromLane04_7C8F20(
    const std::int32_t index,
    const DwordPairLaneRuntimeView* const source
  ) noexcept
  {
    return ComputeLane04OffsetByIndexStride24(index, source);
  }

  /**
   * Address: 0x007C8FC0 (FUN_007C8FC0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C8FC0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C8FD0 (FUN_007C8FD0)
   *
   * What it does:
   * Moves one scalar dword from source into output and clears source to zero.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearSourceWord7C8FD0(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    *outValue = TakeScalarWordAndClear(source);
    return outValue;
  }

  /**
   * Address: 0x007C9390 (FUN_007C9390)
   *
   * What it does:
   * Swaps one scalar dword lane between two slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLane7C9390(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x007C93A0 (FUN_007C93A0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C93A0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C93C0 (FUN_007C93C0)
   *
   * What it does:
   * Stores one source address lane backstepped by 16 bytes.
   */
  [[maybe_unused]] std::uint32_t* StoreWordMinusStride16_7C93C0(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceAddress
  ) noexcept
  {
    *outValue = *sourceAddress - 16u;
    return outValue;
  }

  /**
   * Address: 0x007C93D0 (FUN_007C93D0)
   *
   * What it does:
   * Advances one stored address lane by 16 bytes.
   */
  [[maybe_unused]] std::uint32_t* AdvanceWordByStride16_7C93D0(
    std::uint32_t* const addressLane
  ) noexcept
  {
    return AdvanceAddressLaneByStride16A(addressLane, 1);
  }

  /**
   * Address: 0x007C93F0 (FUN_007C93F0)
   *
   * What it does:
   * Unlinks one intrusive node and relinks it after anchor.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkIntrusiveNodeAfterAnchor7C93F0(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkIntrusiveNodeAfterAnchor(node, anchor);
  }

  /**
   * Address: 0x007C9720 (FUN_007C9720)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C9720(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C9730 (FUN_007C9730)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C9730(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C9740 (FUN_007C9740)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C9740(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C9920 (FUN_007C9920)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C9920(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007C9940 (FUN_007C9940)
   *
   * What it does:
   * Returns one scalar dword lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeScalarWordAndClear7C9940(
    std::uint32_t* const lane
  ) noexcept
  {
    return TakeScalarWordAndClear(lane);
  }

  /**
   * Address: 0x007C9980 (FUN_007C9980)
   *
   * What it does:
   * Stores one `{dword,byte}` pair from two scalar source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairFromPointers7C9980(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007C9FF0 (FUN_007C9FF0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7C9FF0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007CA260 (FUN_007CA260)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7CA260(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007CA6A0 (FUN_007CA6A0)
   *
   * What it does:
   * Stores one `*baseWord + index*24` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride24_7CA6A0(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride24(outValue, baseWord, index);
  }

  /**
   * Address: 0x007CA6D0 (FUN_007CA6D0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7CA6D0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007CA710 (FUN_007CA710)
   *
   * What it does:
   * Stores one dword loaded through source lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04Word7CA710(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007CA810 (FUN_007CA810)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7CA810(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007CA820 (FUN_007CA820)
   *
   * What it does:
   * Stores one `*baseWord + index*36` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride36_7CA820(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride36_7BC250(outValue, baseWord, index);
  }

  /**
   * Address: 0x007CAFC0 (FUN_007CAFC0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7CAFC0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007CB1F0 (FUN_007CB1F0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane7CB1F0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  struct DwordTripleWithBytePairTerminatorRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint8_t lane0C;  // +0x0C
    std::uint8_t lane0D;  // +0x0D
    std::uint8_t lane0E;  // +0x0E
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DwordTripleWithBytePairTerminatorRuntimeView, lane0E) == 0x0E,
    "DwordTripleWithBytePairTerminatorRuntimeView::lane0E offset must be 0x0E"
  );
#endif

  struct FourDwordAndByteFlagRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint8_t flag10;  // +0x10
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourDwordAndByteFlagRuntimeView, flag10) == 0x10,
    "FourDwordAndByteFlagRuntimeView::flag10 offset must be 0x10"
  );
#endif

  struct ByteFlagAt1534RuntimeView
  {
    std::byte pad0000_1533[0x1534];
    std::uint8_t flag1534; // +0x1534
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(ByteFlagAt1534RuntimeView, flag1534) == 0x1534,
    "ByteFlagAt1534RuntimeView::flag1534 offset must be 0x1534"
  );
#endif

  struct PointerAt04ToByteFlag1534RuntimeView
  {
    std::uint32_t lane00;             // +0x00
    ByteFlagAt1534RuntimeView* lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(PointerAt04ToByteFlag1534RuntimeView, lane04) == 0x04,
    "PointerAt04ToByteFlag1534RuntimeView::lane04 offset must be 0x04"
  );
#endif

  struct PointerAt5CToWordRuntimeView
  {
    std::byte pad00_5B[0x5C];
    std::uint32_t* lane5C; // +0x5C
  };
#if defined(_M_IX86)
  static_assert(offsetof(PointerAt5CToWordRuntimeView, lane5C) == 0x5C, "PointerAt5CToWordRuntimeView::lane5C offset must be 0x5C");
#endif

  [[nodiscard]] DwordPairRuntimeView* CopyHeadDwordPairFromQuad(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->lane00;
    outValue->lane04 = source->lane04;
    return outValue;
  }

  [[nodiscard]] DwordPairRuntimeView* CopyTailDwordPairFromQuad(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->lane08;
    outValue->lane04 = source->lane0C;
    return outValue;
  }

  [[nodiscard]] std::int32_t CountLaneDeltaWhenFlag10Clear(
    const FourDwordAndByteFlagRuntimeView* const source
  ) noexcept
  {
    if (source->flag10 != 0u) {
      return 0;
    }

    const std::uint32_t delta = source->lane0C - source->lane04;
    return static_cast<std::int32_t>(delta);
  }

  /**
   * Address: 0x007CC600 (FUN_007CC600)
   *
   * What it does:
   * Stores three dwords and one byte-pair, then clears the trailing byte lane.
   */
  [[maybe_unused]] DwordTripleWithBytePairTerminatorRuntimeView* InitializeDwordTripleBytePairTerminator(
    DwordTripleWithBytePairTerminatorRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00,
    const std::uint32_t lane08,
    const std::uint8_t* const lane0CSource,
    const std::uint8_t lane0D
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = *lane0CSource;
    outValue->lane0D = lane0D;
    outValue->lane0E = 0u;
    return outValue;
  }

  /**
   * Address: 0x007CD420 (FUN_007CD420)
   *
   * What it does:
   * Clears one two-dword lane pair to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLanePrimary(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007CD450 (FUN_007CD450)
   *
   * What it does:
   * Clears one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* ClearScalarDwordLanePrimary(
    std::uint32_t* const outValue
  ) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x007CD4B0 (FUN_007CD4B0)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneSecondary(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007CD4C0 (FUN_007CD4C0)
   *
   * What it does:
   * Alias lane for clearing one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* ClearScalarDwordLaneSecondary(
    std::uint32_t* const outValue
  ) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x007CDE10 (FUN_007CDE10)
   *
   * What it does:
   * Returns one scalar lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearScalarLanePrimary(
    std::uint32_t* const lane
  ) noexcept
  {
    return TakeScalarWordAndClear(lane);
  }

  struct FiveWordLaneRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t lane10; // +0x10
  };
#if defined(_M_IX86)
  static_assert(sizeof(FiveWordLaneRuntimeView) == 0x14, "FiveWordLaneRuntimeView size must be 0x14");
#endif

  struct FourArgCallableRuntimeView
  {
    void* callableVtable;     // +0x00
    std::uint32_t lane04;     // +0x04
    std::uint32_t payload08;  // +0x08
    std::uint32_t payload0C;  // +0x0C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(FourArgCallableRuntimeView, payload08) == 0x08,
    "FourArgCallableRuntimeView::payload08 offset must be 0x08"
  );
#endif

  struct DeferredCursorLaneRuntimeView
  {
    FourArgCallableRuntimeView callable; // +0x00
    std::byte pad10_1F[0x10];
    std::uint32_t committedLane20; // +0x20
    std::uint32_t committedLane24; // +0x24
    std::uint32_t activeLane28; // +0x28
    std::uint32_t activeLane2C; // +0x2C
    std::uint8_t activeFlag30; // +0x30
    std::byte pad31_33[0x03];
    std::uint32_t pendingLane34; // +0x34
    std::uint32_t pendingLane38; // +0x38
    std::uint32_t fallbackLane3C; // +0x3C
    std::uint32_t fallbackLane40; // +0x40
    std::uint8_t exhaustedFlag44; // +0x44
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DeferredCursorLaneRuntimeView, pendingLane34) == 0x34,
    "DeferredCursorLaneRuntimeView::pendingLane34 offset must be 0x34"
  );
  static_assert(
    offsetof(DeferredCursorLaneRuntimeView, fallbackLane3C) == 0x3C,
    "DeferredCursorLaneRuntimeView::fallbackLane3C offset must be 0x3C"
  );
  static_assert(
    offsetof(DeferredCursorLaneRuntimeView, exhaustedFlag44) == 0x44,
    "DeferredCursorLaneRuntimeView::exhaustedFlag44 offset must be 0x44"
  );
#endif

  /**
   * Address: 0x007CE8B0 (FUN_007CE8B0)
   *
   * What it does:
   * Invokes one deferred four-argument callable payload and copies the
   * resulting five-word lane into caller-provided output storage.
   */
  [[maybe_unused]] FiveWordLaneRuntimeView* InvokeDeferredCallableToFiveWordLane(
    const FourArgCallableRuntimeView* const callable,
    FiveWordLaneRuntimeView* const outValue,
    const std::uint32_t laneA3,
    const std::uint32_t laneA4,
    const std::uint32_t laneA5,
    const std::uint32_t laneA6
  )
  {
    if (callable == nullptr || callable->callableVtable == nullptr) {
      throw std::runtime_error("bad_function_call");
    }

    using InvokeFn = FiveWordLaneRuntimeView* (__cdecl*)(
      void* scratchStorage,
      void* callablePayload,
      std::uint32_t,
      std::uint32_t,
      std::uint32_t,
      std::uint32_t
    );

    std::byte scratchStorage[0x14]{};
    auto* const vtableWords = reinterpret_cast<const std::uint32_t*>(callable->callableVtable);
    const auto invoke = reinterpret_cast<InvokeFn>(vtableWords[1]);
    FiveWordLaneRuntimeView* const produced = invoke(
      scratchStorage,
      const_cast<std::uint32_t*>(&callable->payload08),
      laneA3,
      laneA4,
      laneA5,
      laneA6
    );

    *outValue = *produced;
    return outValue;
  }

  /**
   * Address: 0x007CDFB0 (FUN_007CDFB0)
   *
   * What it does:
   * Advances one deferred-cursor lane by promoting pending lanes to committed
   * state and resolving the next active window from deferred callable output.
   */
  [[maybe_unused]] std::uint32_t AdvanceDeferredCursorLane(
    DeferredCursorLaneRuntimeView* const cursor
  )
  {
    FiveWordLaneRuntimeView callableOutput{};
    std::uint32_t nextActiveStart = 0u;
    std::uint32_t nextActiveEnd = 0u;
    std::uint32_t nextPendingStart = 0u;
    std::uint32_t nextPendingEnd = 0u;

    if (cursor->callable.callableVtable != nullptr) {
      (void)InvokeDeferredCallableToFiveWordLane(
        &cursor->callable,
        &callableOutput,
        cursor->pendingLane34,
        cursor->pendingLane38,
        cursor->fallbackLane3C,
        cursor->fallbackLane40
      );
      nextActiveStart = callableOutput.lane00;
      nextActiveEnd = callableOutput.lane04;
      nextPendingStart = callableOutput.lane08;
      nextPendingEnd = callableOutput.lane0C;
    } else {
      nextActiveStart = cursor->fallbackLane3C;
      nextActiveEnd = cursor->fallbackLane40;
      nextPendingStart = nextActiveStart;
      nextPendingEnd = nextActiveEnd;
    }

    const std::uint32_t fallbackEnd = cursor->fallbackLane40;
    if (
      nextActiveEnd == fallbackEnd && nextPendingEnd == fallbackEnd &&
      cursor->activeLane2C == fallbackEnd
    ) {
      cursor->exhaustedFlag44 = 1u;
    }

    cursor->committedLane20 = cursor->pendingLane34;
    cursor->committedLane24 = cursor->pendingLane38;
    cursor->activeLane28 = nextActiveStart;
    cursor->activeLane2C = nextActiveEnd;
    cursor->activeFlag30 = 0u;
    cursor->pendingLane34 = nextPendingStart;
    cursor->pendingLane38 = nextPendingEnd;

    return cursor->committedLane24;
  }

  /**
   * Address: 0x007CF150 (FUN_007CF150)
   *
   * What it does:
   * Alias entrypoint for one deferred-cursor advance step.
   */
  [[maybe_unused]] std::uint32_t AdvanceDeferredCursorLaneAliasA(
    DeferredCursorLaneRuntimeView* const cursor
  )
  {
    return AdvanceDeferredCursorLane(cursor);
  }

  /**
   * Address: 0x007CF380 (FUN_007CF380)
   *
   * What it does:
   * Alias entrypoint for one deferred-cursor advance step.
   */
  [[maybe_unused]] std::uint32_t AdvanceDeferredCursorLaneAliasB(
    DeferredCursorLaneRuntimeView* const cursor
  )
  {
    return AdvanceDeferredCursorLane(cursor);
  }

  /**
   * Address: 0x007CF3B0 (FUN_007CF3B0)
   *
   * What it does:
   * Alias entrypoint for one deferred-cursor advance step.
   */
  [[maybe_unused]] std::uint32_t AdvanceDeferredCursorLaneAliasC(
    DeferredCursorLaneRuntimeView* const cursor
  )
  {
    return AdvanceDeferredCursorLane(cursor);
  }

  /**
   * Address: 0x007CF630 (FUN_007CF630)
   *
   * What it does:
   * Alias entrypoint for one deferred-cursor advance step.
   */
  [[maybe_unused]] std::uint32_t AdvanceDeferredCursorLaneAliasD(
    DeferredCursorLaneRuntimeView* const cursor
  )
  {
    return AdvanceDeferredCursorLane(cursor);
  }

  /**
   * Address: 0x007CDF90 (FUN_007CDF90)
   *
   * What it does:
   * Writes one two-dword lane from two independent source pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairFromIndependentWordSources(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceLane00,
    const std::uint32_t* const sourceLane04
  ) noexcept
  {
    outValue->lane00 = *sourceLane00;
    outValue->lane04 = *sourceLane04;
    return outValue;
  }

  /**
   * Address: 0x007CE280 (FUN_007CE280)
   *
   * What it does:
   * Copies one four-dword-plus-flag lane record.
   */
  [[maybe_unused]] FourDwordAndByteFlagRuntimeView* CopyFourDwordAndByteFlagLane(
    FourDwordAndByteFlagRuntimeView* const outValue,
    const FourDwordAndByteFlagRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->lane00;
    outValue->lane04 = source->lane04;
    outValue->lane08 = source->lane08;
    outValue->lane0C = source->lane0C;
    outValue->flag10 = source->flag10;
    return outValue;
  }

  /**
   * Address: 0x007CE2A0 (FUN_007CE2A0)
   *
   * What it does:
   * Copies the head pair (`+0x00,+0x04`) from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyHeadDwordPairFromQuadPrimary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyHeadDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CE2B0 (FUN_007CE2B0)
   *
   * What it does:
   * Copies the tail pair (`+0x08,+0x0C`) from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyTailDwordPairFromQuadPrimary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyTailDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CE310 (FUN_007CE310)
   *
   * What it does:
   * Writes one `{dword,byte}` lane from two source pointers.
   */
  [[maybe_unused]] ByteAt4RuntimeView* CopyWordAndByteLaneFromPointers(
    ByteAt4RuntimeView* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    outValue->lane00 = *sourceWord;
    outValue->lane04 = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x007CE730 (FUN_007CE730)
   *
   * What it does:
   * Stores four dwords and clears trailing flag lane `+0x10`.
   */
  [[maybe_unused]] FourDwordAndByteFlagRuntimeView* StoreFourDwordLaneAndClearFlag(
    FourDwordAndByteFlagRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint32_t lane0C
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    outValue->lane0C = lane0C;
    outValue->flag10 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007CF740 (FUN_007CF740)
   *
   * What it does:
   * Alias lane for copying the head pair from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyHeadDwordPairFromQuadSecondary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyHeadDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CF750 (FUN_007CF750)
   *
   * What it does:
   * Alias lane for copying the tail pair from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyTailDwordPairFromQuadSecondary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyTailDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CF910 (FUN_007CF910)
   *
   * What it does:
   * Alias lane for copying the head pair from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyHeadDwordPairFromQuadTertiary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyHeadDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CF920 (FUN_007CF920)
   *
   * What it does:
   * Alias lane for copying the tail pair from one four-dword source.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyTailDwordPairFromQuadTertiary(
    DwordPairRuntimeView* const outValue,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    return CopyTailDwordPairFromQuad(outValue, source);
  }

  /**
   * Address: 0x007CFDE0 (FUN_007CFDE0)
   *
   * What it does:
   * Returns the signed lane delta `left(+0x04) - right(+0x04)`.
   */
  [[maybe_unused]] std::int32_t CompareLane04DeltaBetweenPairs(
    const DwordPairRuntimeView* const left,
    const DwordPairRuntimeView* const right
  ) noexcept
  {
    const std::uint32_t delta = left->lane04 - right->lane04;
    return static_cast<std::int32_t>(delta);
  }

  /**
   * Address: 0x007CFE90 (FUN_007CFE90)
   *
   * What it does:
   * Returns zero when flag `+0x10` is set; otherwise returns `lane0C-lane04`.
   */
  [[maybe_unused]] std::int32_t CountLaneDeltaWhenFlagClearPrimary(
    const FourDwordAndByteFlagRuntimeView* const source
  ) noexcept
  {
    return CountLaneDeltaWhenFlag10Clear(source);
  }

  /**
   * Address: 0x007CFF00 (FUN_007CFF00)
   *
   * What it does:
   * Alias lane for `CountLaneDeltaWhenFlagClearPrimary`.
   */
  [[maybe_unused]] std::int32_t CountLaneDeltaWhenFlagClearSecondary(
    const FourDwordAndByteFlagRuntimeView* const source
  ) noexcept
  {
    return CountLaneDeltaWhenFlag10Clear(source);
  }

  /**
   * Address: 0x007CFF90 (FUN_007CFF90)
   *
   * What it does:
   * Alias lane for `CountLaneDeltaWhenFlagClearPrimary`.
   */
  [[maybe_unused]] std::int32_t CountLaneDeltaWhenFlagClearTertiary(
    const FourDwordAndByteFlagRuntimeView* const source
  ) noexcept
  {
    return CountLaneDeltaWhenFlag10Clear(source);
  }

  /**
   * Address: 0x007D0010 (FUN_007D0010)
   *
   * What it does:
   * Merges two source dword pairs into one four-dword record.
   */
  [[maybe_unused]] DwordQuadRuntimeView* MergeTwoDwordPairsIntoQuad(
    DwordQuadRuntimeView* const outValue,
    const DwordPairRuntimeView* const firstPair,
    const DwordPairRuntimeView* const secondPair
  ) noexcept
  {
    outValue->lane00 = firstPair->lane00;
    outValue->lane04 = firstPair->lane04;
    outValue->lane08 = secondPair->lane00;
    outValue->lane0C = secondPair->lane04;
    return outValue;
  }

  /**
   * Address: 0x007D0DB0 (FUN_007D0DB0)
   *
   * What it does:
   * Reads one byte lane at offset `+0x1534`.
   */
  [[maybe_unused]] std::uint8_t ReadFlagByte1534FromObject(
    const ByteFlagAt1534RuntimeView* const source
  ) noexcept
  {
    return source->flag1534;
  }

  /**
   * Address: 0x007D0DE0 (FUN_007D0DE0)
   *
   * What it does:
   * Reads one dword through lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t ReadDoubleDereferencedWordFromLane04(
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return **source->lane04;
  }

  /**
   * Address: 0x007D0DF0 (FUN_007D0DF0)
   *
   * What it does:
   * Reads byte lane `+0x1534` from object pointer stored in lane `+0x04`.
   */
  [[maybe_unused]] std::uint8_t ReadFlagByte1534FromLane04Object(
    const PointerAt04ToByteFlag1534RuntimeView* const source
  ) noexcept
  {
    return source->lane04->flag1534;
  }

  /**
   * Address: 0x007D1780 (FUN_007D1780)
   *
   * What it does:
   * Stores one dword loaded through source pointer lane `*(+0x5C)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane5CWordPrimary(
    std::uint32_t* const outValue,
    const PointerAt5CToWordRuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane5C;
    return outValue;
  }

  /**
   * Address: 0x007D1790 (FUN_007D1790)
   *
   * What it does:
   * Stores raw pointer lane `+0x5C` as one dword.
   */
  [[maybe_unused]] std::uint32_t* WriteLane5CPointerWordPrimary(
    std::uint32_t* const outValue,
    const PointerAt5CToWordRuntimeView* const source
  ) noexcept
  {
    *outValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane5C));
    return outValue;
  }

  /**
   * Address: 0x007D17A0 (FUN_007D17A0)
   *
   * What it does:
   * Alias lane for writing one dword loaded through source pointer lane `+0x5C`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane5CWordSecondary(
    std::uint32_t* const outValue,
    const PointerAt5CToWordRuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane5C;
    return outValue;
  }

  /**
   * Address: 0x007D17B0 (FUN_007D17B0)
   *
   * What it does:
   * Alias lane for storing raw pointer lane `+0x5C` as one dword.
   */
  [[maybe_unused]] std::uint32_t* WriteLane5CPointerWordSecondary(
    std::uint32_t* const outValue,
    const PointerAt5CToWordRuntimeView* const source
  ) noexcept
  {
    *outValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->lane5C));
    return outValue;
  }

  /**
   * Address: 0x007D3B00 (FUN_007D3B00)
   *
   * What it does:
   * Writes one dword loaded through source lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordPrimary(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007D3B10 (FUN_007D3B10)
   *
   * What it does:
   * Alias lane for writing one dword through `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordSecondary(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }
  struct IndirectWordLaneAt108RuntimeView
  {
    std::byte pad0000_006B[0x6C];
    const std::uint32_t* const* lane108; // +0x6C
  };
  static_assert(
    offsetof(IndirectWordLaneAt108RuntimeView, lane108) == 0x6C,
    "IndirectWordLaneAt108RuntimeView::lane108 offset must be 0x6C"
  );

  struct WordLaneAt108RuntimeView
  {
    std::byte pad0000_006B[0x6C];
    std::uint32_t lane108; // +0x6C
  };
  static_assert(offsetof(WordLaneAt108RuntimeView, lane108) == 0x6C, "WordLaneAt108RuntimeView::lane108 offset must be 0x6C");

  struct ByteLaneAt100RuntimeView
  {
    std::byte pad0000_0063[0x64];
    std::uint8_t lane100; // +0x64
  };
  static_assert(offsetof(ByteLaneAt100RuntimeView, lane100) == 0x64, "ByteLaneAt100RuntimeView::lane100 offset must be 0x64");

  struct WordLaneAt36RuntimeView
  {
    std::byte pad0000_0023[0x24];
    std::uint32_t lane36; // +0x24
  };
  static_assert(offsetof(WordLaneAt36RuntimeView, lane36) == 0x24, "WordLaneAt36RuntimeView::lane36 offset must be 0x24");

  [[nodiscard]] std::uint32_t* PopHeadNodeAddressAndAdvance(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopLinkedWordHeadNode(outNodeAddress, headSlot);
  }

  [[nodiscard]] std::uint32_t** AdvanceHeadPointerSlot(std::uint32_t** const headSlot) noexcept
  {
    return AdvancePointerSlotFromNodeHead(headSlot);
  }

  [[nodiscard]] std::uint32_t* ReadDoubleIndirectWordAt108(
    std::uint32_t* const outValue,
    const IndirectWordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, **source->lane108);
  }

  [[nodiscard]] std::uint32_t* ReadWordAt108(
    std::uint32_t* const outValue,
    const WordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane108);
  }

  [[nodiscard]] ByteLaneAt100RuntimeView* StoreByteAt100(
    ByteLaneAt100RuntimeView* const outValue,
    const std::uint8_t value
  ) noexcept
  {
    outValue->lane100 = value;
    return outValue;
  }

  [[nodiscard]] WordLaneAt36RuntimeView* StoreWordAt36(
    WordLaneAt36RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane36 = value;
    return outValue;
  }

  [[nodiscard]] WordLaneAt36RuntimeView* StoreWordAt36FromLane04(
    const DwordPairRuntimeView* const source,
    WordLaneAt36RuntimeView* const outValue
  ) noexcept
  {
    outValue->lane36 = source->lane04;
    return outValue;
  }

  /**
   * Address: 0x007D3C10 (FUN_007D3C10)
   *
   * What it does:
   * Pops one intrusive head-node pointer, writes popped node address, and
   * advances head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneA(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x007D3D10 (FUN_007D3D10)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D3D30 (FUN_007D3D30)
   *
   * What it does:
   * Advances one head-slot pointer to `*head`.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneA(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007D3D40 (FUN_007D3D40)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTheta(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D3F00 (FUN_007D3F00)
   *
   * What it does:
   * Alias lane for advancing one head-slot pointer.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneB(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007D42D0 (FUN_007D42D0)
   *
   * What it does:
   * Stores one dword read from a double-indirect lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneA(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007D42E0 (FUN_007D42E0)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneB(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007D4410 (FUN_007D4410)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneIota(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D4420 (FUN_007D4420)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneKappa(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D4680 (FUN_007D4680)
   *
   * What it does:
   * Alias lane for advancing one head-slot pointer.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneC(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007D47B0 (FUN_007D47B0)
   *
   * What it does:
   * Alias lane for popping one head-node address and advancing head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneB(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x007D4850 (FUN_007D4850)
   *
   * What it does:
   * Alias lane for advancing one head-slot pointer.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneD(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007D5090 (FUN_007D5090)
   *
   * What it does:
   * Stores one dword read from double-indirect lane at `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneAt108A(
    std::uint32_t* const outValue,
    const IndirectWordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return ReadDoubleIndirectWordAt108(outValue, source);
  }

  /**
   * Address: 0x007D50A0 (FUN_007D50A0)
   *
   * What it does:
   * Stores one direct dword lane from `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t* CopyWordLaneAt108A(
    std::uint32_t* const outValue,
    const WordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return ReadWordAt108(outValue, source);
  }

  /**
   * Address: 0x007D50B0 (FUN_007D50B0)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneAt108B(
    std::uint32_t* const outValue,
    const IndirectWordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return ReadDoubleIndirectWordAt108(outValue, source);
  }

  /**
   * Address: 0x007D50C0 (FUN_007D50C0)
   *
   * What it does:
   * Alias lane for direct dword read at `+0x6C`.
   */
  [[maybe_unused]] std::uint32_t* CopyWordLaneAt108B(
    std::uint32_t* const outValue,
    const WordLaneAt108RuntimeView* const source
  ) noexcept
  {
    return ReadWordAt108(outValue, source);
  }

  /**
   * Address: 0x007D5BB0 (FUN_007D5BB0)
   *
   * What it does:
   * Stores one byte lane at offset `+0x64`.
   */
  [[maybe_unused]] ByteLaneAt100RuntimeView* StoreByteLaneAt100(
    ByteLaneAt100RuntimeView* const outValue,
    const std::uint8_t value
  ) noexcept
  {
    return StoreByteAt100(outValue, value);
  }

  /**
   * Address: 0x007D5C60 (FUN_007D5C60)
   *
   * What it does:
   * Alias lane for popping one head-node address and advancing head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneC(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x007D5DD0 (FUN_007D5DD0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x24`.
   */
  [[maybe_unused]] WordLaneAt36RuntimeView* StoreWordLaneAt36(
    WordLaneAt36RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAt36(outValue, value);
  }

  /**
   * Address: 0x007D5E50 (FUN_007D5E50)
   *
   * What it does:
   * Writes one source `+0x04` dword into destination lane `+0x24`.
   */
  [[maybe_unused]] WordLaneAt36RuntimeView* StoreWordLaneAt36FromSourceLane04(
    const DwordPairRuntimeView* const source,
    WordLaneAt36RuntimeView* const destination
  ) noexcept
  {
    return StoreWordAt36FromLane04(source, destination);
  }

  /**
   * Address: 0x007D77D0 (FUN_007D77D0)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneC(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007D7980 (FUN_007D7980)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneD(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007D7C80 (FUN_007D7C80)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneSigma(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007D80C0 (FUN_007D80C0)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneE(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007D8450 (FUN_007D8450)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneLambda(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D8460 (FUN_007D8460)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneMu(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D8480 (FUN_007D8480)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneNu(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D84C0 (FUN_007D84C0)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneOmega(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007D8F50 (FUN_007D8F50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneXi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D8F70 (FUN_007D8F70)
   *
   * What it does:
   * Alias lane for popping one head-node address and advancing head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneD(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }
  struct WordPointerAt30RuntimeView
  {
    std::byte pad0000_002F[0x30];
    const std::uint32_t* lane30; // +0x30
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordPointerAt30RuntimeView, lane30) == 0x30, "WordPointerAt30RuntimeView::lane30 offset must be 0x30");
#endif

  struct WordAndByteFlagsAt24AndA5RuntimeView
  {
    std::byte pad0000_0023[0x24];
    std::uint32_t lane24; // +0x24
    std::uint8_t lane28;  // +0x28
    std::byte pad0029_00A4[0x7C];
    std::uint8_t laneA5;  // +0xA5
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(WordAndByteFlagsAt24AndA5RuntimeView, lane24) == 0x24,
    "WordAndByteFlagsAt24AndA5RuntimeView::lane24 offset must be 0x24"
  );
  static_assert(
    offsetof(WordAndByteFlagsAt24AndA5RuntimeView, lane28) == 0x28,
    "WordAndByteFlagsAt24AndA5RuntimeView::lane28 offset must be 0x28"
  );
  static_assert(
    offsetof(WordAndByteFlagsAt24AndA5RuntimeView, laneA5) == 0xA5,
    "WordAndByteFlagsAt24AndA5RuntimeView::laneA5 offset must be 0xA5"
  );
#endif

  struct FloatAt20RuntimeView
  {
    std::byte pad0000_001F[0x20];
    float lane20; // +0x20
  };
#if defined(_M_IX86)
  static_assert(offsetof(FloatAt20RuntimeView, lane20) == 0x20, "FloatAt20RuntimeView::lane20 offset must be 0x20");
#endif

  [[nodiscard]] std::intptr_t ResetSharedOwnerPairAndReleaseControlBlock(
    SharedOwnerPairRuntimeView* const pair
  ) noexcept
  {
    std::intptr_t result = reinterpret_cast<std::intptr_t>(pair);
    pair->objectWord = 0u;
    auto* const owner = reinterpret_cast<SharedOwnerControlBlockRuntimeView*>(pair->ownerWord);
    pair->ownerWord = 0u;
    if (owner != nullptr) {
      result = ReleaseSharedOwnerControlBlock(owner);
    }
    return result;
  }

  /**
   * Address: 0x007D8F80 (FUN_007D8F80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchMu(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D8FB0 (FUN_007D8FB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchNu(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D8FD0 (FUN_007D8FD0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchXi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D9010 (FUN_007D9010)
   *
   * What it does:
   * Stores one two-dword pair from two scalar source pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairFromSourcePointersBatchA(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceLane00,
    const std::uint32_t* const sourceLane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, *sourceLane00, *sourceLane04);
  }

  /**
   * Address: 0x007D91B0 (FUN_007D91B0)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceA(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x007D9240 (FUN_007D9240)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchOmicron(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007D9300 (FUN_007D9300)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceB(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x007D9870 (FUN_007D9870)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceC(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x007D98B0 (FUN_007D98B0)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceD(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x007DA210 (FUN_007DA210)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchPi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007DA520 (FUN_007DA520)
   *
   * What it does:
   * Stores one `*baseWord + index*4` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4BatchA(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride4(outValue, baseWord, index);
  }

  /**
   * Address: 0x007DA540 (FUN_007DA540)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchRho(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007DADB0 (FUN_007DADB0)
   *
   * What it does:
   * Reads one dword through pointer lane `+0x30`.
   */
  [[maybe_unused]] std::uint32_t ReadDereferencedWordPointerAt30(
    const WordPointerAt30RuntimeView* const source
  ) noexcept
  {
    return *source->lane30;
  }

  /**
   * Address: 0x007DADF0 (FUN_007DADF0)
   *
   * What it does:
   * Reads one dword lane at offset `+0x24`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane24(
    const WordAndByteFlagsAt24AndA5RuntimeView* const source
  ) noexcept
  {
    return source->lane24;
  }

  /**
   * Address: 0x007DAE00 (FUN_007DAE00)
   *
   * What it does:
   * Reads one byte lane at offset `+0x28`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane28FromWordAndFlagsState(
    const WordAndByteFlagsAt24AndA5RuntimeView* const source
  ) noexcept
  {
    return source->lane28;
  }

  /**
   * Address: 0x007DAE10 (FUN_007DAE10)
   *
   * What it does:
   * Reads one byte lane at offset `+0xA5`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLaneA5(
    const WordAndByteFlagsAt24AndA5RuntimeView* const source
  ) noexcept
  {
    return source->laneA5;
  }

  /**
   * Address: 0x007DB2C0 (FUN_007DB2C0)
   *
   * What it does:
   * Stores two scalar dword lanes into one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromScalarsBatchB(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007DB2D0 (FUN_007DB2D0)
   *
   * What it does:
   * Reads one dword through lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t ReadDoubleDereferencedWordFromLane04BatchA(
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return ReadDoubleDereferencedWordFromLane04(source);
  }

  /**
   * Address: 0x007DB380 (FUN_007DB380)
   *
   * What it does:
   * Alias lane for reading one dword at offset `+0x24`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane24Alias(
    const WordAndByteFlagsAt24AndA5RuntimeView* const source
  ) noexcept
  {
    return source->lane24;
  }

  /**
   * Address: 0x007DDAB0 (FUN_007DDAB0)
   *
   * What it does:
   * Invokes scalar-deleting destructor slot `+0x00` with delete flag `1`
   * when object is non-null.
   */
  [[maybe_unused]] std::intptr_t DestroyViaVirtualSlot0DeleteFlagOneIfPresentBatch(
    void* const object
  ) noexcept
  {
    return InvokeDeleteFlagVirtualSlot0IfPresent(object);
  }

  /**
   * Address: 0x007DE530 (FUN_007DE530)
   *
   * What it does:
   * Clears one two-dword pair lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBatchAlpha(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007DE8F0 (FUN_007DE8F0)
   *
   * What it does:
   * Stores one float lane at offset `+0x20`.
   */
  [[maybe_unused]] FloatAt20RuntimeView* StoreFloatLane20Batch(
    FloatAt20RuntimeView* const outValue,
    const float value
  ) noexcept
  {
    outValue->lane20 = value;
    return outValue;
  }

  /**
   * Address: 0x007E2760 (FUN_007E2760)
   *
   * What it does:
   * Initializes one self-relative span header with anchors at `+0x10/+0x30`.
   */
  [[maybe_unused]] SelfRelativeLaneBlockTail30RuntimeView* InitializeSelfRelativeLaneBlockTail30AliasBatch(
    SelfRelativeLaneBlockTail30RuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeLaneBlockTail30(outValue);
  }

  /**
   * Address: 0x007E27B0 (FUN_007E27B0)
   *
   * What it does:
   * Clears one two-dword pair lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBatchBeta(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007E27C0 (FUN_007E27C0)
   *
   * What it does:
   * Clears one `{object, owner}` pair and releases owner use/weak counts.
   */
  [[maybe_unused]] std::intptr_t ResetSharedOwnerPairAndReleaseBatchA(
    SharedOwnerPairRuntimeView* const pair
  ) noexcept
  {
    return ResetSharedOwnerPairAndReleaseControlBlock(pair);
  }

  /**
   * Address: 0x007E2810 (FUN_007E2810)
   *
   * What it does:
   * Clears one two-dword pair lane.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBatchGamma(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane6D7890(outValue);
  }

  /**
   * Address: 0x007E2820 (FUN_007E2820)
   *
   * What it does:
   * Alias lane for clearing one `{object, owner}` pair and releasing owner.
   */
  [[maybe_unused]] std::intptr_t ResetSharedOwnerPairAndReleaseBatchB(
    SharedOwnerPairRuntimeView* const pair
  ) noexcept
  {
    return ResetSharedOwnerPairAndReleaseControlBlock(pair);
  }

  /**
   * Address: 0x007E2880 (FUN_007E2880)
   *
   * What it does:
   * Returns zero when lane `+0x00` is non-zero, otherwise returns `-1`.
   */
  [[maybe_unused]] std::int32_t ReturnZeroWhenWordNonZeroElseMinusOne(
    const WordLane00RuntimeView* const source
  ) noexcept
  {
    return source->lane00 != 0u ? 0 : -1;
  }

  /**
   * Address: 0x007E2890 (FUN_007E2890)
   *
   * What it does:
   * Returns true when lane `+0x00` is zero.
   */
  [[maybe_unused]] BOOL IsWordLane00Zero(
    const WordLane00RuntimeView* const source
  ) noexcept
  {
    return source->lane00 == 0u ? TRUE : FALSE;
  }

  /**
   * Address: 0x007E28A0 (FUN_007E28A0)
   *
   * What it does:
   * Alias lane for clearing one `{object, owner}` pair and releasing owner.
   */
  [[maybe_unused]] std::intptr_t ResetSharedOwnerPairAndReleaseBatchC(
    SharedOwnerPairRuntimeView* const pair
  ) noexcept
  {
    return ResetSharedOwnerPairAndReleaseControlBlock(pair);
  }

  struct WordLaneAt488RuntimeView
  {
    std::byte pad0000_0487[0x488];
    std::uint32_t lane488; // +0x488
  };
  static_assert(offsetof(WordLaneAt488RuntimeView, lane488) == 0x488, "WordLaneAt488RuntimeView::lane488 offset must be 0x488");

  [[nodiscard]] std::uint32_t ReadIndexedWordFromStride8TableAtOffset8(
    const std::uint8_t* const tableBase,
    const std::int32_t index
  ) noexcept
  {
    const auto* const entries = reinterpret_cast<const SourceLane8RuntimeView*>(tableBase + 8);
    return entries[index].lane00;
  }

  /**
   * Address: 0x007F02E0 (FUN_007F02E0)
   *
   * What it does:
   * Stores one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordAlpha(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x007F0B50 (FUN_007F0B50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmicron(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F0B80 (FUN_007F0B80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F0DB0 (FUN_007F0DB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneRho(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F0E70 (FUN_007F0E70)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneSigma(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F0E80 (FUN_007F0E80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTau(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F0EB0 (FUN_007F0EB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneUpsilon(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F1D00 (FUN_007F1D00)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneGamma(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007F2040 (FUN_007F2040)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePhi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F20B0 (FUN_007F20B0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneDelta(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007F2190 (FUN_007F2190)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneChi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007F2CB0 (FUN_007F2CB0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneEpsilon(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007F2D30 (FUN_007F2D30)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneZeta(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007F2E40 (FUN_007F2E40)
   *
   * What it does:
   * Copies one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneAlpha(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007F2E50 (FUN_007F2E50)
   *
   * What it does:
   * Alias lane for copying one `{dword,byte}` pair.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneBeta(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007F4CF0 (FUN_007F4CF0)
   *
   * What it does:
   * Reads one indexed dword lane from a stride-8 table at base offset `+0x08`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordFromStride8TableOffset8(
    const std::uint8_t* const tableBase,
    const std::int32_t index
  ) noexcept
  {
    return ReadIndexedWordFromStride8TableAtOffset8(tableBase, index);
  }

  /**
   * Address: 0x007F6380 (FUN_007F6380)
   *
   * What it does:
   * Reads one dword lane at offset `+0x488`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane488(
    const WordLaneAt488RuntimeView* const source
  ) noexcept
  {
    return source->lane488;
  }

  /**
   * Address: 0x007FAAD0 (FUN_007FAAD0)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneTauSecondary(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007FAB50 (FUN_007FAB50)
   *
   * What it does:
   * Stores one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordBeta(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x007FAB60 (FUN_007FAB60)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordGamma(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x007FAD30 (FUN_007FAD30)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneUpsilonSecondary(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007FADA0 (FUN_007FADA0)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLanePhi(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007FAE20 (FUN_007FAE20)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePsi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007FAE90 (FUN_007FAE90)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneEta(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007FB3F0 (FUN_007FB3F0)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesGamma(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x007FB410 (FUN_007FB410)
   *
   * What it does:
   * Alias lane for swapping both dword lanes between pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesDelta(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x007FB430 (FUN_007FB430)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneTheta(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x007FB440 (FUN_007FB440)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmega(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007FB480 (FUN_007FB480)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneAlpha2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x007FB4A0 (FUN_007FB4A0)
   *
   * What it does:
   * Stores one `*baseWord + index*20` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride20Batch(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride20(outValue, baseWord, index);
  }

  struct ByteAt29RuntimeView
  {
    std::byte pad00_28[0x29];
    std::uint8_t lane29; // +0x29
  };
  static_assert(offsetof(ByteAt29RuntimeView, lane29) == 0x29, "ByteAt29RuntimeView::lane29 offset must be 0x29");

  struct WordAt2CRuntimeView
  {
    std::byte pad00_2B[0x2C];
    std::uint32_t lane2C; // +0x2C
  };
  static_assert(offsetof(WordAt2CRuntimeView, lane2C) == 0x2C, "WordAt2CRuntimeView::lane2C offset must be 0x2C");

  struct ByteAt48RuntimeView
  {
    std::byte pad00_47[0x48];
    std::uint8_t lane48; // +0x48
  };
  static_assert(offsetof(ByteAt48RuntimeView, lane48) == 0x48, "ByteAt48RuntimeView::lane48 offset must be 0x48");

  struct SparseFloatLaneBlockRuntimeView
  {
    std::byte pad00_0F[0x10];
    float lane10; // +0x10
    float lane14; // +0x14
    float lane18; // +0x18
    float lane1C; // +0x1C
    float lane20; // +0x20
    float lane24; // +0x24
    float lane28; // +0x28
    float lane2C; // +0x2C
    float lane30; // +0x30
    float lane34; // +0x34
    float lane38; // +0x38
    float lane3C; // +0x3C
    float lane40; // +0x40
    float lane44; // +0x44
    float lane48; // +0x48
    float lane4C; // +0x4C
    std::byte pad50_57[0x08];
    float lane58; // +0x58
    float lane5C; // +0x5C
    float lane60; // +0x60
    float lane64; // +0x64
    float lane68; // +0x68
    float lane6C; // +0x6C
    float lane70; // +0x70
    float lane74; // +0x74
    float lane78; // +0x78
    float lane7C; // +0x7C
    float lane80; // +0x80
    float lane84; // +0x84
    float lane88; // +0x88
    float lane8C; // +0x8C
    float lane90; // +0x90
    float lane94; // +0x94
    float lane98; // +0x98
    float lane9C; // +0x9C
    float laneA0; // +0xA0
    std::byte padA4_A7[0x04];
    float laneA8; // +0xA8
    float laneAC; // +0xAC
  };
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, lane10) == 0x10, "SparseFloatLaneBlockRuntimeView::lane10 offset must be 0x10");
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, lane4C) == 0x4C, "SparseFloatLaneBlockRuntimeView::lane4C offset must be 0x4C");
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, lane58) == 0x58, "SparseFloatLaneBlockRuntimeView::lane58 offset must be 0x58");
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, laneA0) == 0xA0, "SparseFloatLaneBlockRuntimeView::laneA0 offset must be 0xA0");
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, laneA8) == 0xA8, "SparseFloatLaneBlockRuntimeView::laneA8 offset must be 0xA8");
  static_assert(offsetof(SparseFloatLaneBlockRuntimeView, laneAC) == 0xAC, "SparseFloatLaneBlockRuntimeView::laneAC offset must be 0xAC");

  [[nodiscard]] SparseFloatLaneBlockRuntimeView* ClearSparseFloatLanes(
    SparseFloatLaneBlockRuntimeView* const self
  ) noexcept
  {
    self->lane10 = 0.0f;
    self->lane14 = 0.0f;
    self->lane18 = 0.0f;
    self->lane1C = 0.0f;
    self->lane20 = 0.0f;
    self->lane24 = 0.0f;
    self->lane28 = 0.0f;
    self->lane2C = 0.0f;
    self->lane30 = 0.0f;
    self->lane34 = 0.0f;
    self->lane38 = 0.0f;
    self->lane3C = 0.0f;
    self->lane40 = 0.0f;
    self->lane44 = 0.0f;
    self->lane48 = 0.0f;
    self->lane4C = 0.0f;
    self->lane58 = 0.0f;
    self->lane5C = 0.0f;
    self->lane60 = 0.0f;
    self->lane64 = 0.0f;
    self->lane68 = 0.0f;
    self->lane6C = 0.0f;
    self->lane70 = 0.0f;
    self->lane74 = 0.0f;
    self->lane78 = 0.0f;
    self->lane7C = 0.0f;
    self->lane80 = 0.0f;
    self->lane84 = 0.0f;
    self->lane88 = 0.0f;
    self->lane8C = 0.0f;
    self->lane90 = 0.0f;
    self->lane94 = 0.0f;
    self->lane98 = 0.0f;
    self->lane9C = 0.0f;
    self->laneA0 = 0.0f;
    self->laneA8 = 0.0f;
    self->laneAC = 0.0f;
    return self;
  }

  [[nodiscard]] std::uint32_t* WriteWordFromLane04(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreDword(outValue, source->lane04);
  }

  /**
   * Address: 0x007E5020 (FUN_007E5020)
   *
   * What it does:
   * Stores one scalar dword lane from source argument.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLanePi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007E5440 (FUN_007E5440)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarWordLanesAlpha(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x007E5450 (FUN_007E5450)
   *
   * What it does:
   * Alias lane for swapping one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarWordLanesBeta(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x007E5B00 (FUN_007E5B00)
   *
   * What it does:
   * Clears one two-dword lane pair to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneTau(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007E5CF0 (FUN_007E5CF0)
   *
   * What it does:
   * Alias lane for clearing one two-dword lane pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneUpsilon(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x007E5DA0 (FUN_007E5DA0)
   *
   * What it does:
   * Stores one dword pair from two scalar inputs.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromScalarsTau(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x007E6020 (FUN_007E6020)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from scalar source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairFromPointerSourcesPsi(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x007E6C40 (FUN_007E6C40)
   *
   * What it does:
   * Returns one dword lane at offset `+0x1C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLaneAt1CPrimary(
    const WordAt1CRuntimeView* const source
  ) noexcept
  {
    return source->lane1C;
  }

  /**
   * Address: 0x007E6C60 (FUN_007E6C60)
   *
   * What it does:
   * Returns one byte lane at offset `+0x29`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLaneAt29Primary(
    const ByteAt29RuntimeView* const source
  ) noexcept
  {
    return source->lane29;
  }

  /**
   * Address: 0x007E6C70 (FUN_007E6C70)
   *
   * What it does:
   * Returns one dword lane at offset `+0x2C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLaneAt2CPrimary(
    const WordAt2CRuntimeView* const source
  ) noexcept
  {
    return source->lane2C;
  }

  /**
   * Address: 0x007E6D80 (FUN_007E6D80)
   *
   * What it does:
   * Returns one byte lane at offset `+0x48`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLaneAt48Primary(
    const ByteAt48RuntimeView* const source
  ) noexcept
  {
    return source->lane48;
  }

  /**
   * Address: 0x007E8B90 (FUN_007E8B90)
   *
   * What it does:
   * Clears sparse float lanes from `+0x10` to `+0xAC`.
   */
  [[maybe_unused]] SparseFloatLaneBlockRuntimeView* ClearSparseFloatLaneBlockA(
    SparseFloatLaneBlockRuntimeView* const self
  ) noexcept
  {
    return ClearSparseFloatLanes(self);
  }

  /**
   * Address: 0x007E9600 (FUN_007E9600)
   *
   * What it does:
   * Stores one scalar dword lane from source argument.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRho(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007E9630 (FUN_007E9630)
   *
   * What it does:
   * Alias lane for storing one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneSigma(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007EBAC0 (FUN_007EBAC0)
   *
   * What it does:
   * Stores one dword read from double-indirect lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleIndirectWordFromLane04A(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007EBBD0 (FUN_007EBBD0)
   *
   * What it does:
   * Swaps both dword lanes across two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesXi(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x007EBBF0 (FUN_007EBBF0)
   *
   * What it does:
   * Alias lane for swapping both dword lanes across pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesOmicron(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x007EBC30 (FUN_007EBC30)
   *
   * What it does:
   * Alias lane for reading one double-indirect dword from lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleIndirectWordFromLane04B(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007EBC40 (FUN_007EBC40)
   *
   * What it does:
   * Stores one direct dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteWordFromLane04A(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return WriteWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007EBD00 (FUN_007EBD00)
   *
   * What it does:
   * Stores one scalar dword lane from source argument.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneTau(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007EBD10 (FUN_007EBD10)
   *
   * What it does:
   * Pops one head-node address and advances the source head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressPrimary(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x007EBEC0 (FUN_007EBEC0)
   *
   * What it does:
   * Advances one head-slot pointer to the next node.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotPrimary(
    std::uint32_t** const headSlot
  ) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007EBED0 (FUN_007EBED0)
   *
   * What it does:
   * Stores one scalar dword lane from source argument.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneUpsilon(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x007EBF10 (FUN_007EBF10)
   *
   * What it does:
   * Alias lane for advancing one head-slot pointer.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotSecondary(
    std::uint32_t** const headSlot
  ) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x007EBF90 (FUN_007EBF90)
   *
   * What it does:
   * Alias lane for swapping one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarWordLanesGamma(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x007EBFA0 (FUN_007EBFA0)
   *
   * What it does:
   * Alias lane for swapping one scalar dword.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarWordLanesDelta(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x007EFE90 (FUN_007EFE90)
   *
   * What it does:
   * Alias lane for reading one double-indirect dword from lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleIndirectWordFromLane04C(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x007EFEA0 (FUN_007EFEA0)
   *
   * What it does:
   * Alias lane for storing one direct dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteWordFromLane04B(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return WriteWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007EFF60 (FUN_007EFF60)
   *
   * What it does:
   * Alias lane for storing one direct dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteWordFromLane04C(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return WriteWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x007F02D0 (FUN_007F02D0)
   *
   * What it does:
   * Alias lane for storing one direct dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteWordFromLane04D(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return WriteWordFromLane04(outValue, source);
  }
  struct WordLaneAt04RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
  };
  static_assert(offsetof(WordLaneAt04RuntimeView, lane04) == 0x04, "WordLaneAt04RuntimeView::lane04 offset must be 0x04");

  struct WordLaneAt0F0RuntimeView
  {
    std::byte pad0000_00EF[0xF0];
    std::uint32_t lane0F0; // +0xF0
  };
  static_assert(offsetof(WordLaneAt0F0RuntimeView, lane0F0) == 0xF0, "WordLaneAt0F0RuntimeView::lane0F0 offset must be 0xF0");

  struct WordLaneAt3FCRuntimeView
  {
    std::byte pad0000_03FB[0x3FC];
    std::uint32_t lane3FC; // +0x3FC
  };
  static_assert(offsetof(WordLaneAt3FCRuntimeView, lane3FC) == 0x3FC, "WordLaneAt3FCRuntimeView::lane3FC offset must be 0x3FC");

  struct WordLaneAt400RuntimeView
  {
    std::byte pad0000_03FF[0x400];
    std::uint32_t lane400; // +0x400
  };
  static_assert(offsetof(WordLaneAt400RuntimeView, lane400) == 0x400, "WordLaneAt400RuntimeView::lane400 offset must be 0x400");

  struct ByteLaneAt4D5RuntimeView
  {
    std::byte pad0000_04D4[0x4D5];
    std::uint8_t lane4D5; // +0x4D5
  };
  static_assert(offsetof(ByteLaneAt4D5RuntimeView, lane4D5) == 0x4D5, "ByteLaneAt4D5RuntimeView::lane4D5 offset must be 0x4D5");

  struct SelfRelativeTailBB8HeaderRuntimeView
  {
    std::uint32_t begin;  // +0x00
    std::uint32_t cursor; // +0x04
    std::uint32_t end;    // +0x08
    std::uint32_t free;   // +0x0C
  };
  static_assert(sizeof(SelfRelativeTailBB8HeaderRuntimeView) == 0x10, "SelfRelativeTailBB8HeaderRuntimeView size must be 0x10");
  static_assert(
    offsetof(SelfRelativeTailBB8HeaderRuntimeView, free) == 0x0C,
    "SelfRelativeTailBB8HeaderRuntimeView::free offset must be 0x0C"
  );

  struct BasePointerWordRuntimeView
  {
    std::uint32_t base; // +0x00
  };

  struct SegmentExtentsRuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint8_t lane0C;  // +0x0C
    std::uint8_t lane0D;  // +0x0D
    std::byte pad0E_0F[0x02];
    float minX; // +0x10
    float minY; // +0x14
    float minZ; // +0x18
    float maxX; // +0x1C
    float maxY; // +0x20
    float maxZ; // +0x24
  };
  static_assert(offsetof(SegmentExtentsRuntimeView, minX) == 0x10, "SegmentExtentsRuntimeView::minX offset must be 0x10");
  static_assert(offsetof(SegmentExtentsRuntimeView, maxZ) == 0x24, "SegmentExtentsRuntimeView::maxZ offset must be 0x24");

  /**
   * Address: 0x0081A240 (FUN_0081A240)
   *
   * What it does:
   * Stores one dword read from a double-indirect lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneF(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x0081A250 (FUN_0081A250)
   *
   * What it does:
   * Stores one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordDelta(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0081A260 (FUN_0081A260)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordEpsilon(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0081A2F0 (FUN_0081A2F0)
   *
   * What it does:
   * Zeros both dword lanes in one pair record.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneChi(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0081A360 (FUN_0081A360)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordZeta(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0081A3B0 (FUN_0081A3B0)
   *
   * What it does:
   * Pops one intrusive head-node pointer and advances the head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneE(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x0081A4C0 (FUN_0081A4C0)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesEpsilon(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x0081A4E0 (FUN_0081A4E0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBeta2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0081A4F0 (FUN_0081A4F0)
   *
   * What it does:
   * Alias lane for popping one head-node pointer and advancing head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneF(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x0081A500 (FUN_0081A500)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneGamma2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0081A510 (FUN_0081A510)
   *
   * What it does:
   * Advances one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneE(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0081A540 (FUN_0081A540)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneDelta2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0081A6B0 (FUN_0081A6B0)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneF(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0081A720 (FUN_0081A720)
   *
   * What it does:
   * Swaps one leading dword lane between two word slots.
   */
  [[maybe_unused]] std::uint32_t* SwapLeadingWordLaneTertiary(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapSingleWordLane(left, right);
  }

  /**
   * Address: 0x0081AC40 (FUN_0081AC40)
   *
   * What it does:
   * Initializes one segment-extents lane block with zeroed header flags and
   * two source float3 vectors.
   */
  [[maybe_unused]] SegmentExtentsRuntimeView* InitializeSegmentExtentsFromMinMaxVectors(
    SegmentExtentsRuntimeView* const outValue,
    const float* const minVector,
    const float* const maxVector
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    outValue->lane0D = 0u;
    outValue->minX = minVector[0];
    outValue->minY = minVector[1];
    outValue->minZ = minVector[2];
    outValue->maxX = maxVector[0];
    outValue->maxY = maxVector[1];
    outValue->maxZ = maxVector[2];
    return outValue;
  }

  /**
   * Address: 0x0081B620 (FUN_0081B620)
   *
   * What it does:
   * Alias lane for double-indirect dword read at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordLaneG(
    std::uint32_t* const outValue,
    const IndirectWordPointerAt4RuntimeView* const source
  ) noexcept
  {
    return CopyDoubleIndirectWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x0081B630 (FUN_0081B630)
   *
   * What it does:
   * Stores one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordEta(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0081B6C0 (FUN_0081B6C0)
   *
   * What it does:
   * Alias lane for popping one head-node pointer and advancing head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneG(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x0081B7F0 (FUN_0081B7F0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEpsilon2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0081B800 (FUN_0081B800)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneG(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0081BB50 (FUN_0081BB50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneZeta2(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0081BB60 (FUN_0081BB60)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneH(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0081CD40 (FUN_0081CD40)
   *
   * What it does:
   * Initializes one self-relative header with begin/cursor/free at `this+0x10`
   * and tail at `begin+0xBB8`.
   */
  [[maybe_unused]] SelfRelativeTailBB8HeaderRuntimeView* InitializeSelfRelativeTailBB8Header(
    SelfRelativeTailBB8HeaderRuntimeView* const outValue
  ) noexcept
  {
    const std::uint32_t begin = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(outValue) + 0x10u);
    outValue->begin = begin;
    outValue->cursor = begin;
    outValue->end = begin + 0xBB8u;
    outValue->free = begin;
    return outValue;
  }

  /**
   * Address: 0x0081CD90 (FUN_0081CD90)
   *
   * What it does:
   * Computes one `base + index*12` byte address lane from pointer slot `+0x00`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromBasePointer(
    const std::int32_t index,
    const BasePointerWordRuntimeView* const source
  ) noexcept
  {
    return source->base + (static_cast<std::uint32_t>(index) * 12u);
  }

  /**
   * Address: 0x0081CDA0 (FUN_0081CDA0)
   *
   * What it does:
   * Initializes one header from external begin pointer with tail `begin+0xBB8`.
   */
  [[maybe_unused]] SelfRelativeTailBB8HeaderRuntimeView* InitializeExternalTailBB8Header(
    SelfRelativeTailBB8HeaderRuntimeView* const outValue,
    const std::uint32_t begin
  ) noexcept
  {
    outValue->begin = begin;
    outValue->cursor = begin;
    outValue->end = begin + 0xBB8u;
    outValue->free = begin;
    return outValue;
  }

  /**
   * Address: 0x0081CE60 (FUN_0081CE60)
   *
   * What it does:
   * Writes one source dword into destination lane `+0x04`.
   */
  [[maybe_unused]] WordLaneAt04RuntimeView* StoreWordLane04FromPointer(
    WordLaneAt04RuntimeView* const outValue,
    const std::uint32_t* const source
  ) noexcept
  {
    outValue->lane04 = *source;
    return outValue;
  }

  /**
   * Address: 0x0081CE70 (FUN_0081CE70)
   *
   * What it does:
   * Reads one dword lane at offset `+0x400`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane400(
    const WordLaneAt400RuntimeView* const source
  ) noexcept
  {
    return source->lane400;
  }

  /**
   * Address: 0x0081CE80 (FUN_0081CE80)
   *
   * What it does:
   * Reads one dword lane at offset `+0x3FC`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane3FC(
    const WordLaneAt3FCRuntimeView* const source
  ) noexcept
  {
    return source->lane3FC;
  }

  /**
   * Address: 0x0081CE90 (FUN_0081CE90)
   *
   * What it does:
   * Reads one byte lane at offset `+0x4D5`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane4D5(
    const ByteLaneAt4D5RuntimeView* const source
  ) noexcept
  {
    return source->lane4D5;
  }

  /**
   * Address: 0x0081CF60 (FUN_0081CF60)
   *
   * What it does:
   * Reads one dword lane at offset `+0x0F0`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane0F0(
    const WordLaneAt0F0RuntimeView* const source
  ) noexcept
  {
    return source->lane0F0;
  }

  [[nodiscard]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderWithTailOffsetBytes(
    DwordQuadRuntimeView* const self,
    const std::uint32_t tailOffsetBytes
  ) noexcept
  {
    const std::uint32_t selfAddress = reinterpret_cast<std::uint32_t>(self);
    const std::uint32_t beginAnchor = selfAddress + static_cast<std::uint32_t>(sizeof(DwordQuadRuntimeView));
    self->lane00 = beginAnchor;
    self->lane04 = beginAnchor;
    self->lane08 = selfAddress + tailOffsetBytes;
    self->lane0C = beginAnchor;
    return self;
  }

  struct PointerLaneAtB8RuntimeView
  {
    std::byte pad0000_00B7[0xB8];
    const std::uint32_t* laneB8; // +0xB8
  };
#if defined(_M_IX86)
  static_assert(offsetof(PointerLaneAtB8RuntimeView, laneB8) == 0xB8, "PointerLaneAtB8RuntimeView::laneB8 offset must be 0xB8");
#endif

  struct FloatValueAndSampleTimeRuntimeView
  {
    float value;      // +0x00
    float sampleTime; // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(FloatValueAndSampleTimeRuntimeView) == 0x08, "FloatValueAndSampleTimeRuntimeView size must be 0x08");
#endif

  /**
   * Address: 0x0080AC60 (FUN_0080AC60)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=100)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount100A(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 100, baseAddress);
  }

  /**
   * Address: 0x0080AE10 (FUN_0080AE10)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=3000)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount3000A(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 3000, baseAddress);
  }

  /**
   * Address: 0x0080AFD0 (FUN_0080AFD0)
   *
   * What it does:
   * Alias lane for initializing one external dword-span header with
   * `(base, count=3000)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount3000B(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 3000, baseAddress);
  }

  /**
   * Address: 0x0080B470 (FUN_0080B470)
   *
   * What it does:
   * Stores one scalar dword lane from source argument.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryA(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080B480 (FUN_0080B480)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryB(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080B490 (FUN_0080B490)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryC(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080B620 (FUN_0080B620)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryD(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080B630 (FUN_0080B630)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryE(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080B640 (FUN_0080B640)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryF(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x0080ECB0 (FUN_0080ECB0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with a tail anchor at
   * `self + 0x42`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail42(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x42u);
  }

  /**
   * Address: 0x0080ED10 (FUN_0080ED10)
   *
   * What it does:
   * Computes one `*baseWord + index*2` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeBaseWordOffsetByIndexStride2(
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return *baseWord + (static_cast<std::uint32_t>(index) * 2u);
  }

  /**
   * Address: 0x0080EDF0 (FUN_0080EDF0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with a tail anchor at
   * `self + 0x90`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail90(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x90u);
  }

  /**
   * Address: 0x0080EEC0 (FUN_0080EEC0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with a tail anchor at
   * `self + 0x58`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail58(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x58u);
  }

  /**
   * Address: 0x0080F320 (FUN_0080F320)
   *
   * What it does:
   * Alias lane for initializing one external dword-span header with
   * `(base, count=32)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount32C(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 32, baseAddress);
  }

  /**
   * Address: 0x00811260 (FUN_00811260)
   *
   * What it does:
   * Returns the sum of two scalar float lanes.
   */
  [[maybe_unused]] float AddScalarFloatLanes(
    const float* const left,
    const float* const right
  ) noexcept
  {
    return *right + *left;
  }

  /**
   * Address: 0x00811290 (FUN_00811290)
   *
   * What it does:
   * Returns one scalar float lane multiplied by a scalar factor.
   */
  [[maybe_unused]] float MultiplyScalarFloatLane(
    const float* const value,
    const float scalar
  ) noexcept
  {
    return *value * scalar;
  }

  /**
   * Address: 0x008112F0 (FUN_008112F0)
   *
   * What it does:
   * Interpolates between two `{value,time}` samples at a requested sample time.
   */
  [[maybe_unused]] float InterpolateFloatValueAtSampleTime(
    const FloatValueAndSampleTimeRuntimeView* const left,
    const FloatValueAndSampleTimeRuntimeView* const right,
    const float sampleTime
  ) noexcept
  {
    const float timeFactor = (sampleTime - right->sampleTime) / (left->sampleTime - right->sampleTime);
    return right->value + ((left->value - right->value) * timeFactor);
  }

  /**
   * Address: 0x00812750 (FUN_00812750)
   *
   * What it does:
   * Clears one two-dword lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneRecovery(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x00813630 (FUN_00813630)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with a tail anchor at
   * `self + 0x1A0`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail1A0(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x1A0u);
  }

  /**
   * Address: 0x008136F0 (FUN_008136F0)
   *
   * What it does:
   * Stores one direct dword from source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* WriteWordFromLane04RecoveryA(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return WriteWordFromLane04(outValue, source);
  }

  /**
   * Address: 0x00813880 (FUN_00813880)
   *
   * What it does:
   * Alias lane for initializing one external dword-span header with
   * `(base, count=100)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount100B(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 100, baseAddress);
  }

  /**
   * Address: 0x00813CC0 (FUN_00813CC0)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryG(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x00813CD0 (FUN_00813CD0)
   *
   * What it does:
   * Alias lane for computing one `*baseWord + index * 8` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride8Recovery(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride8(outValue, baseWord, index);
  }

  /**
   * Address: 0x00813D50 (FUN_00813D50)
   *
   * What it does:
   * Alias lane for scalar dword store behavior.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordLaneRecoveryH(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreWordAtOutput(outValue, value);
  }

  /**
   * Address: 0x00815780 (FUN_00815780)
   *
   * What it does:
   * Stores one dword loaded through source lane `*(+0xB8)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDereferencedLaneB8WordA(
    std::uint32_t* const outValue,
    const PointerLaneAtB8RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->laneB8;
    return outValue;
  }

  /**
   * Address: 0x00815790 (FUN_00815790)
   *
   * What it does:
   * Stores raw pointer lane `+0xB8` as one dword.
   */
  [[maybe_unused]] std::uint32_t* WriteLaneB8PointerWordA(
    std::uint32_t* const outValue,
    const PointerLaneAtB8RuntimeView* const source
  ) noexcept
  {
    *outValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->laneB8));
    return outValue;
  }

  /**
   * Address: 0x008157A0 (FUN_008157A0)
   *
   * What it does:
   * Alias lane for storing one dword loaded through source lane `*(+0xB8)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDereferencedLaneB8WordB(
    std::uint32_t* const outValue,
    const PointerLaneAtB8RuntimeView* const source
  ) noexcept
  {
    return WriteDereferencedLaneB8WordA(outValue, source);
  }

  /**
   * Address: 0x008157B0 (FUN_008157B0)
   *
   * What it does:
   * Alias lane for storing raw pointer lane `+0xB8` as one dword.
   */
  [[maybe_unused]] std::uint32_t* WriteLaneB8PointerWordB(
    std::uint32_t* const outValue,
    const PointerLaneAtB8RuntimeView* const source
  ) noexcept
  {
    return WriteLaneB8PointerWordA(outValue, source);
  }

  /**
   * Address: 0x008159B0 (FUN_008159B0)
   *
   * What it does:
   * Computes one `base + 0x140 + index*20` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeOffsetAddressFromBaseWithTail140Stride20(
    const std::int32_t index,
    const std::uint32_t baseAddress
  ) noexcept
  {
    return baseAddress + 0x140u + (static_cast<std::uint32_t>(index) * 20u);
  }

  /**
   * Address: 0x0081A230 (FUN_0081A230)
   *
   * What it does:
   * Stores one dword loaded through source lane `*(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordRecovery(
    std::uint32_t* const outValue,
    const SourceIndirectLane4RuntimeView* const source
  ) noexcept
  {
    *outValue = *source->lane04;
    return outValue;
  }
  struct DoubleIndirectLane04RuntimeView
  {
    std::uint32_t lane00;                  // +0x00
    const std::uint32_t* const* lane04;   // +0x04
  };
  static_assert(offsetof(DoubleIndirectLane04RuntimeView, lane04) == 0x04, "DoubleIndirectLane04RuntimeView::lane04 offset must be 0x04");

  [[nodiscard]] std::uint32_t* CopyWordFromPointer(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    *outValue = *sourceWord;
    return outValue;
  }

  [[nodiscard]] std::uint8_t* CopyByteFromPointer(
    std::uint8_t* const outValue,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    *outValue = *sourceByte;
    return outValue;
  }

  /**
   * Address: 0x0082D900 (FUN_0082D900)
   *
   * What it does:
   * Copies one dword from source pointer to destination pointer.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordFromPointerA(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopyWordFromPointer(outValue, sourceWord);
  }

  /**
   * Address: 0x0082D940 (FUN_0082D940)
   *
   * What it does:
   * Copies one byte from source pointer to destination pointer.
   */
  [[maybe_unused]] std::uint8_t* CopySingleByteFromPointerA(
    std::uint8_t* const outValue,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyByteFromPointer(outValue, sourceByte);
  }

  /**
   * Address: 0x0082DA10 (FUN_0082DA10)
   *
   * What it does:
   * Stores one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordTheta(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0082DC20 (FUN_0082DC20)
   *
   * What it does:
   * Alias lane for copying one byte from source pointer.
   */
  [[maybe_unused]] std::uint8_t* CopySingleByteFromPointerB(
    std::uint8_t* const outValue,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyByteFromPointer(outValue, sourceByte);
  }

  /**
   * Address: 0x0082DE00 (FUN_0082DE00)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordIota(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0082E7C0 (FUN_0082E7C0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneIota(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0082E7D0 (FUN_0082E7D0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBeta3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EB80 (FUN_0082EB80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneGamma3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EB90 (FUN_0082EB90)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneKappa(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0082EBA0 (FUN_0082EBA0)
   *
   * What it does:
   * Advances one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneI(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0082EBD0 (FUN_0082EBD0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneLambda(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0082EBF0 (FUN_0082EBF0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneDelta3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EC60 (FUN_0082EC60)
   *
   * What it does:
   * Stores one `*baseWord + index*4` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4RecoveryA(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride4(outValue, baseWord, index);
  }

  /**
   * Address: 0x0082EC80 (FUN_0082EC80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEpsilon3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EE00 (FUN_0082EE00)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneZeta3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EE30 (FUN_0082EE30)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneGamma(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0082EE40 (FUN_0082EE40)
   *
   * What it does:
   * Writes one dword pair from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairFromTwoPointersA(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceWord0,
    const std::uint32_t* const sourceWord1
  ) noexcept
  {
    outValue->lane00 = *sourceWord0;
    outValue->lane04 = *sourceWord1;
    return outValue;
  }

  /**
   * Address: 0x0082EE50 (FUN_0082EE50)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneMu(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0082EE60 (FUN_0082EE60)
   *
   * What it does:
   * Alias lane for advancing one pointer slot to node-head next.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotLaneJ(std::uint32_t** const headSlot) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x0082EEA0 (FUN_0082EEA0)
   *
   * What it does:
   * Alias lane for writing one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneDelta(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0082EEB0 (FUN_0082EEB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEta3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0082EEE0 (FUN_0082EEE0)
   *
   * What it does:
   * Alias lane for storing one `*baseWord + index*4` byte-offset.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4RecoveryB(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride4(outValue, baseWord, index);
  }

  /**
   * Address: 0x0082EF30 (FUN_0082EF30)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordKappa(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0082F1A0 (FUN_0082F1A0)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordLambda(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0082F710 (FUN_0082F710)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordMu(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0082FA60 (FUN_0082FA60)
   *
   * What it does:
   * Stores one dword through lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordRecoveryB(
    std::uint32_t* const outValue,
    const DoubleIndirectLane04RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, **source->lane04);
  }

  /**
   * Address: 0x008301F0 (FUN_008301F0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneNu(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00830200 (FUN_00830200)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTheta3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00830230 (FUN_00830230)
   *
   * What it does:
   * Alias lane for storing source dword at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordNu(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00830320 (FUN_00830320)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneIota3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  struct WordLaneAt38RuntimeView
  {
    std::byte pad0000_0037[0x38];
    std::uint32_t lane38; // +0x38
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt38RuntimeView, lane38) == 0x38, "WordLaneAt38RuntimeView::lane38 offset must be 0x38");
#endif

  struct WordLaneAt14CRuntimeView
  {
    std::byte pad0000_014B[0x14C];
    std::uint32_t lane14C; // +0x14C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt14CRuntimeView, lane14C) == 0x14C, "WordLaneAt14CRuntimeView::lane14C offset must be 0x14C");
#endif

  struct ByteLaneAt188RuntimeView
  {
    std::byte pad0000_0187[0x188];
    std::uint8_t lane188; // +0x188
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAt188RuntimeView, lane188) == 0x188, "ByteLaneAt188RuntimeView::lane188 offset must be 0x188");
#endif

  struct ByteFlagLanesAt4E8RuntimeView
  {
    std::byte pad0000_04E7[0x4E8];
    std::uint8_t flag4E8; // +0x4E8
    std::uint8_t flag4E9; // +0x4E9
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(ByteFlagLanesAt4E8RuntimeView, flag4E8) == 0x4E8,
    "ByteFlagLanesAt4E8RuntimeView::flag4E8 offset must be 0x4E8"
  );
  static_assert(
    offsetof(ByteFlagLanesAt4E8RuntimeView, flag4E9) == 0x4E9,
    "ByteFlagLanesAt4E8RuntimeView::flag4E9 offset must be 0x4E9"
  );
#endif

  struct ByteLaneAtB8RuntimeView
  {
    std::byte pad0000_00B7[0xB8];
    std::uint8_t laneB8; // +0xB8
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAtB8RuntimeView, laneB8) == 0xB8, "ByteLaneAtB8RuntimeView::laneB8 offset must be 0xB8");
#endif

  struct IndexedWordBlockAt1C0RuntimeView
  {
    std::byte pad0000_01BF[0x1C0];
    std::uint32_t lane1C0[2]; // +0x1C0
    std::uint32_t lane1C8[2]; // +0x1C8
    std::uint32_t lane1D0[2]; // +0x1D0
    std::byte pad01D8_01F7[0x20];
    DwordPairRuntimeView pair1F8; // +0x1F8
    DwordPairRuntimeView pair200; // +0x200
    DwordPairRuntimeView pair208; // +0x208
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, lane1C0) == 0x1C0,
    "IndexedWordBlockAt1C0RuntimeView::lane1C0 offset must be 0x1C0"
  );
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, lane1C8) == 0x1C8,
    "IndexedWordBlockAt1C0RuntimeView::lane1C8 offset must be 0x1C8"
  );
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, lane1D0) == 0x1D0,
    "IndexedWordBlockAt1C0RuntimeView::lane1D0 offset must be 0x1D0"
  );
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, pair1F8) == 0x1F8,
    "IndexedWordBlockAt1C0RuntimeView::pair1F8 offset must be 0x1F8"
  );
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, pair200) == 0x200,
    "IndexedWordBlockAt1C0RuntimeView::pair200 offset must be 0x200"
  );
  static_assert(
    offsetof(IndexedWordBlockAt1C0RuntimeView, pair208) == 0x208,
    "IndexedWordBlockAt1C0RuntimeView::pair208 offset must be 0x208"
  );
#endif

  /**
   * Address: 0x00837700 (FUN_00837700)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneKappa3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00837A10 (FUN_00837A10)
   *
   * What it does:
   * Stores one source dword lane at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordXi(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00837F90 (FUN_00837F90)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordOmicron(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00838020 (FUN_00838020)
   *
   * What it does:
   * Writes one dword pair from two source-word pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairFromWordPointersRecovery83(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceWord0,
    const std::uint32_t* const sourceWord1
  ) noexcept
  {
    outValue->lane00 = *sourceWord0;
    outValue->lane04 = *sourceWord1;
    return outValue;
  }

  /**
   * Address: 0x00838B80 (FUN_00838B80)
   *
   * What it does:
   * Reads one dword lane at offset `+0x38`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane38(
    const WordLaneAt38RuntimeView* const source
  ) noexcept
  {
    return source->lane38;
  }

  /**
   * Address: 0x0083ADF0 (FUN_0083ADF0)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with tail anchor at `self+0x80`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail80Recovery(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x80u);
  }

  /**
   * Address: 0x0083B630 (FUN_0083B630)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneLambda3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0083B670 (FUN_0083B670)
   *
   * What it does:
   * Alias lane for storing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneMu3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0083B820 (FUN_0083B820)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneRecovery83A(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0083C020 (FUN_0083C020)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneXi(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0083C040 (FUN_0083C040)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneNu3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0083C070 (FUN_0083C070)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneOmicron(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0083C090 (FUN_0083C090)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneXi3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0083C2C0 (FUN_0083C2C0)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLanePi(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0083C340 (FUN_0083C340)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneRho(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x0083C360 (FUN_0083C360)
   *
   * What it does:
   * Alias lane for writing one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneRecovery83B(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0083C370 (FUN_0083C370)
   *
   * What it does:
   * Alias lane for writing one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneRecovery83C(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0083C870 (FUN_0083C870)
   *
   * What it does:
   * Clears one two-dword lane pair to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ZeroDwordPairLaneRecovery83(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0083C880 (FUN_0083C880)
   *
   * What it does:
   * Stores one dword pair from two scalar inputs.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromScalarsRecovery83(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x0083C9D0 (FUN_0083C9D0)
   *
   * What it does:
   * Reads one dword lane at offset `+0x14C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane14C(
    const WordLaneAt14CRuntimeView* const source
  ) noexcept
  {
    return source->lane14C;
  }

  /**
   * Address: 0x0083C9F0 (FUN_0083C9F0)
   *
   * What it does:
   * Reads one byte lane at offset `+0x188`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane188(
    const ByteLaneAt188RuntimeView* const source
  ) noexcept
  {
    return source->lane188;
  }

  /**
   * Address: 0x0083CA70 (FUN_0083CA70)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x4E8`.
   */
  [[maybe_unused]] ByteFlagLanesAt4E8RuntimeView* SetByteFlag4E8(
    ByteFlagLanesAt4E8RuntimeView* const outValue,
    const std::uint8_t value
  ) noexcept
  {
    outValue->flag4E8 = value;
    return outValue;
  }

  /**
   * Address: 0x0083CA80 (FUN_0083CA80)
   *
   * What it does:
   * Stores one byte flag lane at offset `+0x4E9`.
   */
  [[maybe_unused]] ByteFlagLanesAt4E8RuntimeView* SetByteFlag4E9(
    ByteFlagLanesAt4E8RuntimeView* const outValue,
    const std::uint8_t value
  ) noexcept
  {
    outValue->flag4E9 = value;
    return outValue;
  }

  /**
   * Address: 0x0083CAC0 (FUN_0083CAC0)
   *
   * What it does:
   * Reads one byte lane at offset `+0xB8`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLaneB8(
    const ByteLaneAtB8RuntimeView* const source
  ) noexcept
  {
    return source->laneB8;
  }

  /**
   * Address: 0x0083CAD0 (FUN_0083CAD0)
   *
   * What it does:
   * Reads one indexed dword lane from table block at offset `+0x1C0`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordLane1C0(
    const IndexedWordBlockAt1C0RuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->lane1C0[index];
  }

  /**
   * Address: 0x0083CAE0 (FUN_0083CAE0)
   *
   * What it does:
   * Reads one indexed dword lane from table block at offset `+0x1C8`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordLane1C8(
    const IndexedWordBlockAt1C0RuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->lane1C8[index];
  }

  /**
   * Address: 0x0083CAF0 (FUN_0083CAF0)
   *
   * What it does:
   * Reads one indexed dword lane from table block at offset `+0x1D0`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordLane1D0(
    const IndexedWordBlockAt1C0RuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->lane1D0[index];
  }

  /**
   * Address: 0x0083CB00 (FUN_0083CB00)
   *
   * What it does:
   * Copies one two-dword pair from source lanes `+0x1F8/+0x1FC`.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyWordPairAt1F8(
    DwordPairRuntimeView* const outValue,
    const IndexedWordBlockAt1C0RuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->pair1F8.lane00;
    outValue->lane04 = source->pair1F8.lane04;
    return outValue;
  }

  /**
   * Address: 0x0083CB20 (FUN_0083CB20)
   *
   * What it does:
   * Copies one two-dword pair from source lanes `+0x200/+0x204`.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyWordPairAt200(
    DwordPairRuntimeView* const outValue,
    const IndexedWordBlockAt1C0RuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->pair200.lane00;
    outValue->lane04 = source->pair200.lane04;
    return outValue;
  }

  /**
   * Address: 0x0083CB40 (FUN_0083CB40)
   *
   * What it does:
   * Copies one two-dword pair from source lanes `+0x208/+0x20C`.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyWordPairAt208(
    DwordPairRuntimeView* const outValue,
    const IndexedWordBlockAt1C0RuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->pair208.lane00;
    outValue->lane04 = source->pair208.lane04;
    return outValue;
  }

  struct WordLaneAt58RuntimeView
  {
    std::byte pad0000_0057[0x58];
    std::uint32_t lane58; // +0x58
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt58RuntimeView, lane58) == 0x58, "WordLaneAt58RuntimeView::lane58 offset must be 0x58");
#endif

  struct WordLaneAt40RuntimeView
  {
    std::byte pad0000_003F[0x40];
    std::uint32_t lane40; // +0x40
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt40RuntimeView, lane40) == 0x40, "WordLaneAt40RuntimeView::lane40 offset must be 0x40");
#endif

  struct ByteLaneAt1B0RuntimeView
  {
    std::byte pad0000_01AF[0x1B0];
    std::uint8_t lane1B0; // +0x1B0
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAt1B0RuntimeView, lane1B0) == 0x1B0, "ByteLaneAt1B0RuntimeView::lane1B0 offset must be 0x1B0");
#endif

  /**
   * Address: 0x00855730 (FUN_00855730)
   *
   * What it does:
   * Stores one source dword lane at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordPi(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00855CB0 (FUN_00855CB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmicron3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00855D30 (FUN_00855D30)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneSigma(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00855D40 (FUN_00855D40)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePi3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00855D60 (FUN_00855D60)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneTau(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00855DB0 (FUN_00855DB0)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneRecovery85A(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x00856830 (FUN_00856830)
   *
   * What it does:
   * Zeros one dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarDwordLaneUpsilon(std::uint32_t* const outValue) noexcept
  {
    return ZeroSingleWordLane(outValue);
  }

  /**
   * Address: 0x00856840 (FUN_00856840)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneRho3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008568B0 (FUN_008568B0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneSigma3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008568C0 (FUN_008568C0)
   *
   * What it does:
   * Stores one `*baseWord + index*8` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride8RecoveryB(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride8(outValue, baseWord, index);
  }

  /**
   * Address: 0x008568F0 (FUN_008568F0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTau3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00856900 (FUN_00856900)
   *
   * What it does:
   * Stores one `*baseWord + index*4` byte-offset lane.
   */
  [[maybe_unused]] std::uint32_t* StoreBaseWordOffsetByIndexStride4RecoveryC(
    std::uint32_t* const outValue,
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreBaseWordOffsetByIndexStride4(outValue, baseWord, index);
  }

  /**
   * Address: 0x00856E50 (FUN_00856E50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneUpsilon3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00856E90 (FUN_00856E90)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePhi3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00857120 (FUN_00857120)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLaneRecovery85A(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x008583A0 (FUN_008583A0)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceE(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00858460 (FUN_00858460)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneChi3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00858480 (FUN_00858480)
   *
   * What it does:
   * Replaces one pointer slot with its double-dereferenced value.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotViaDoubleDereferenceF(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x00858620 (FUN_00858620)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePsi3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00858820 (FUN_00858820)
   *
   * What it does:
   * Pops one head-node address and advances the head slot.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneH(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x00858830 (FUN_00858830)
   *
   * What it does:
   * Reads one byte flag lane at offset `+0x4E8`.
   */
  [[maybe_unused]] std::uint8_t ReadByteFlag4E8(
    const ByteFlagLanesAt4E8RuntimeView* const source
  ) noexcept
  {
    return source->flag4E8;
  }

  /**
   * Address: 0x00858840 (FUN_00858840)
   *
   * What it does:
   * Reads one dword lane at offset `+0x58`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane58(
    const WordLaneAt58RuntimeView* const source
  ) noexcept
  {
    return source->lane58;
  }

  /**
   * Address: 0x0085A670 (FUN_0085A670)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmega3(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0085A730 (FUN_0085A730)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneAlpha4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0085B040 (FUN_0085B040)
   *
   * What it does:
   * Reads one byte flag lane at offset `+0x4E9`.
   */
  [[maybe_unused]] std::uint8_t ReadByteFlag4E9(
    const ByteFlagLanesAt4E8RuntimeView* const source
  ) noexcept
  {
    return source->flag4E9;
  }

  /**
   * Address: 0x0085B080 (FUN_0085B080)
   *
   * What it does:
   * Reads one dword lane at offset `+0x40`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane40(
    const WordLaneAt40RuntimeView* const source
  ) noexcept
  {
    return source->lane40;
  }

  /**
   * Address: 0x0085B0A0 (FUN_0085B0A0)
   *
   * What it does:
   * Reads one byte lane at offset `+0x1B0`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane1B0(
    const ByteLaneAt1B0RuntimeView* const source
  ) noexcept
  {
    return source->lane1B0;
  }

  /**
   * Address: 0x0085ED00 (FUN_0085ED00)
   *
   * What it does:
   * Stores one dword loaded through source lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordRecoveryC(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x0085EF80 (FUN_0085EF80)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBeta4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0085F110 (FUN_0085F110)
   *
   * What it does:
   * Stores one source dword lane at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordRho(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  struct StateWordLanesAt88RuntimeView
  {
    std::byte pad0000_0087[0x88];
    std::uint32_t lane88; // +0x88
    std::byte pad008C_0097[0x0C];
    std::uint32_t lane98; // +0x98
    std::uint32_t lane9C; // +0x9C
    std::uint8_t laneA0;  // +0xA0
  };
#if defined(_M_IX86)
  static_assert(offsetof(StateWordLanesAt88RuntimeView, lane88) == 0x88, "StateWordLanesAt88RuntimeView::lane88 offset must be 0x88");
  static_assert(offsetof(StateWordLanesAt88RuntimeView, lane98) == 0x98, "StateWordLanesAt88RuntimeView::lane98 offset must be 0x98");
  static_assert(offsetof(StateWordLanesAt88RuntimeView, lane9C) == 0x9C, "StateWordLanesAt88RuntimeView::lane9C offset must be 0x9C");
  static_assert(offsetof(StateWordLanesAt88RuntimeView, laneA0) == 0xA0, "StateWordLanesAt88RuntimeView::laneA0 offset must be 0xA0");
#endif

  using DeleteOneVirtualCall = std::int32_t(__thiscall*)(void* self, std::int32_t deleteFlag);
  using VirtualSlot44WordCall = std::int32_t(__thiscall*)(void* self, std::uint32_t value);

  [[nodiscard]] std::int32_t DestroyViaVTableSlot0DeleteOneIfPresent(VTableOwnerRuntimeView* const self) noexcept
  {
    if (self == nullptr) {
      return 0;
    }
    const auto callback = reinterpret_cast<DeleteOneVirtualCall>(self->vtable[0]);
    return callback(self, 1);
  }

  [[nodiscard]] std::int32_t InvokeVirtualSlot44WithDereferencedWord(
    VTableOwnerRuntimeView* const self,
    const std::uint32_t* const valueSlot
  ) noexcept
  {
    const auto callback = reinterpret_cast<VirtualSlot44WordCall>(self->vtable[11]);
    return callback(self, *valueSlot);
  }

  struct TreeNodeFloatKeyFlagAt11RuntimeView
  {
    TreeNodeFloatKeyFlagAt11RuntimeView* left;         // +0x00
    TreeNodeFloatKeyFlagAt11RuntimeView* parentOrRoot; // +0x04
    TreeNodeFloatKeyFlagAt11RuntimeView* right;        // +0x08
    float key;                                         // +0x0C
    std::byte pad10[0x01];
    std::uint8_t isSentinel;                           // +0x11
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(TreeNodeFloatKeyFlagAt11RuntimeView, key) == 0x0C,
    "TreeNodeFloatKeyFlagAt11RuntimeView::key offset must be 0x0C"
  );
  static_assert(
    offsetof(TreeNodeFloatKeyFlagAt11RuntimeView, isSentinel) == 0x11,
    "TreeNodeFloatKeyFlagAt11RuntimeView::isSentinel offset must be 0x11"
  );
#endif

  [[nodiscard]] TreeNodeFloatKeyFlagAt11RuntimeView* FindLowerBoundTreeNodeFloatKeyFlag11(
    TreeNodeFloatKeyFlagAt11RuntimeView* const header,
    const float key
  ) noexcept
  {
    TreeNodeFloatKeyFlagAt11RuntimeView* candidate = header;
    TreeNodeFloatKeyFlagAt11RuntimeView* cursor = candidate->parentOrRoot;
    while (cursor->isSentinel == 0u) {
      if (cursor->key >= key) {
        candidate = cursor;
        cursor = cursor->left;
      } else {
        cursor = cursor->right;
      }
    }
    return candidate;
  }

  /**
   * Address: 0x00876F90 (FUN_00876F90)
   *
   * What it does:
   * Moves one source dword into output storage and clears the source lane.
   */
  [[maybe_unused]] std::uint32_t* TakeSourceWordIntoOutputAndClear(
    std::uint32_t* const outValue,
    std::uint32_t* const sourceWord
  ) noexcept
  {
    const std::uint32_t value = *sourceWord;
    *sourceWord = 0u;
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x00877120 (FUN_00877120)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneGamma4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00877160 (FUN_00877160)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneDelta4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008771F0 (FUN_008771F0)
   *
   * What it does:
   * Stores one dword lane at offset `+0x9C`.
   */
  [[maybe_unused]] StateWordLanesAt88RuntimeView* SetWordLane9C(
    StateWordLanesAt88RuntimeView* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    outValue->lane9C = value;
    return outValue;
  }

  /**
   * Address: 0x00877200 (FUN_00877200)
   *
   * What it does:
   * Reads one dword lane at offset `+0x98`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane98(
    const StateWordLanesAt88RuntimeView* const source
  ) noexcept
  {
    return source->lane98;
  }

  /**
   * Address: 0x00877210 (FUN_00877210)
   *
   * What it does:
   * Reads one dword lane at offset `+0x88`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane88(
    const StateWordLanesAt88RuntimeView* const source
  ) noexcept
  {
    return source->lane88;
  }

  /**
   * Address: 0x00877220 (FUN_00877220)
   *
   * What it does:
   * Reads one byte lane at offset `+0xA0`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLaneA0(
    const StateWordLanesAt88RuntimeView* const source
  ) noexcept
  {
    return source->laneA0;
  }

  /**
   * Address: 0x00877690 (FUN_00877690)
   *
   * What it does:
   * Calls virtual slot 0 with delete-flag `1` when object is non-null.
   */
  [[maybe_unused]] std::int32_t DestroyViaVTableSlot0DeleteOneA(
    VTableOwnerRuntimeView* const self
  ) noexcept
  {
    return DestroyViaVTableSlot0DeleteOneIfPresent(self);
  }

  /**
   * Address: 0x008776A0 (FUN_008776A0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEpsilon4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008776B0 (FUN_008776B0)
   *
   * What it does:
   * Invokes virtual slot `+0x2C` with one dereferenced dword argument.
   */
  [[maybe_unused]] std::int32_t InvokeVirtualSlot44WithDereferencedWordA(
    VTableOwnerRuntimeView* const self,
    const std::uint32_t* const valueSlot
  ) noexcept
  {
    return InvokeVirtualSlot44WithDereferencedWord(self, valueSlot);
  }

  /**
   * Address: 0x008776C0 (FUN_008776C0)
   *
   * What it does:
   * Alias lane for virtual slot-0 delete-flag invocation.
   */
  [[maybe_unused]] std::int32_t DestroyViaVTableSlot0DeleteOneB(
    VTableOwnerRuntimeView* const self
  ) noexcept
  {
    return DestroyViaVTableSlot0DeleteOneIfPresent(self);
  }

  /**
   * Address: 0x00879010 (FUN_00879010)
   *
   * What it does:
   * Stores one source dword lane at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordSigma(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x008791C0 (FUN_008791C0)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordTau(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x008791D0 (FUN_008791D0)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordUpsilon(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00879240 (FUN_00879240)
   *
   * What it does:
   * Computes lower-bound node for one key in a tree with sentinel flag at `+0x15`.
   */
  [[maybe_unused]] TreeNodeFlagAt15RuntimeView** LowerBoundTreeNodeFlag15ToOutputRecoveryA(
    TreeNodeFlagAt15RuntimeView** const outNode,
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt15RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    *outNode = FindLowerBoundTreeNode(tree->header, *key);
    return outNode;
  }

  /**
   * Address: 0x00879340 (FUN_00879340)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordPhi(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x008794F0 (FUN_008794F0)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordChi(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00879500 (FUN_00879500)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordPsi(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00879570 (FUN_00879570)
   *
   * What it does:
   * Alias lane for lower-bound search in tree with sentinel flag at `+0x15`.
   */
  [[maybe_unused]] TreeNodeFlagAt15RuntimeView** LowerBoundTreeNodeFlag15ToOutputRecoveryB(
    TreeNodeFlagAt15RuntimeView** const outNode,
    const TreeHeaderAt4RuntimeView<TreeNodeFlagAt15RuntimeView>* const tree,
    const std::uint32_t* const key
  ) noexcept
  {
    return LowerBoundTreeNodeFlag15ToOutputRecoveryA(outNode, tree, key);
  }

  /**
   * Address: 0x00879670 (FUN_00879670)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordOmega(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00879800 (FUN_00879800)
   *
   * What it does:
   * Alias lane for storing one source dword lane at `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordAlpha5(
    std::uint32_t* const outValue,
    const SourceLane4RuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x008798C0 (FUN_008798C0)
   *
   * What it does:
   * Returns lower-bound node pointer for one float key in a tree with sentinel
   * flag at `+0x11`.
   */
  [[maybe_unused]] std::uint32_t* LowerBoundTreeNodeFloatKeyFlag11ToOutput(
    std::uint32_t* const outNodeAddress,
    const float* const key,
    const TreeHeaderAt4RuntimeView<TreeNodeFloatKeyFlagAt11RuntimeView>* const tree
  ) noexcept
  {
    const auto* const node = FindLowerBoundTreeNodeFloatKeyFlag11(tree->header, *key);
    *outNodeAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(node));
    return outNodeAddress;
  }

  /**
   * Address: 0x0087A360 (FUN_0087A360)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneZeta4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0087A430 (FUN_0087A430)
   *
   * What it does:
   * Stores one dword loaded through source lane `**(+0x04)`.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordRecoveryD(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x0087A690 (FUN_0087A690)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneEta4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0087A6C0 (FUN_0087A6C0)
   *
   * What it does:
   * Writes one `{dword,byte}` pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairLaneRecovery85B(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0087A6D0 (FUN_0087A6D0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTheta4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0087A6E0 (FUN_0087A6E0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneIota4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0087A700 (FUN_0087A700)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneKappa4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0087A730 (FUN_0087A730)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneLambda4(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  struct HeapComparableNodeLane14RuntimeView
  {
    std::byte pad00_13[0x14];
    std::uint32_t keyLane14; // +0x14
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(HeapComparableNodeLane14RuntimeView, keyLane14) == 0x14,
    "HeapComparableNodeLane14RuntimeView::keyLane14 offset must be 0x14"
  );
#endif

  /**
   * Address: 0x0087E850 (FUN_0087E850)
   *
   * What it does:
   * Sifts one heap slot down through the larger-child path, then sifts the
   * pending node upward so max-heap ordering by key lane `+0x14` is preserved.
   */
  [[maybe_unused]] std::int32_t SiftHeapNodeDownThenUpByKeyLane14(
    std::int32_t startIndex,
    const std::int32_t heapCount,
    HeapComparableNodeLane14RuntimeView** const heapSlots,
    HeapComparableNodeLane14RuntimeView* const pendingNode
  ) noexcept
  {
    std::int32_t writeIndex = startIndex;
    std::int32_t childIndex = writeIndex * 2 + 2;
    bool childEqualsHeapCount = (childIndex == heapCount);

    if (childIndex < heapCount) {
      do {
        HeapComparableNodeLane14RuntimeView* const rightChild = heapSlots[childIndex];
        HeapComparableNodeLane14RuntimeView* const leftChild = heapSlots[childIndex - 1];
        if (rightChild->keyLane14 < leftChild->keyLane14) {
          --childIndex;
        }

        heapSlots[writeIndex] = heapSlots[childIndex];
        writeIndex = childIndex;
        childIndex = childIndex * 2 + 2;
        childEqualsHeapCount = (childIndex == heapCount);
      } while (childIndex < heapCount);
    }

    if (childEqualsHeapCount) {
      heapSlots[writeIndex] = heapSlots[heapCount - 1];
      writeIndex = heapCount - 1;
    }

    std::int32_t parentIndex = (writeIndex - 1) / 2;
    while (startIndex < writeIndex) {
      HeapComparableNodeLane14RuntimeView* const parentNode = heapSlots[parentIndex];
      if (parentNode->keyLane14 >= pendingNode->keyLane14) {
        break;
      }

      heapSlots[writeIndex] = parentNode;
      writeIndex = parentIndex;
      parentIndex = (parentIndex - 1) / 2;
    }

    heapSlots[writeIndex] = pendingNode;
    return parentIndex;
  }

  /**
   * Address: 0x0087EA30 (FUN_0087EA30)
   *
   * What it does:
   * Sifts one node pointer upward in a max-heap lane while parent key `+0x14`
   * is smaller than the inserted node key.
   */
  [[maybe_unused]] std::int32_t SiftHeapNodeUpByKeyLane14(
    std::int32_t writeIndex,
    const std::int32_t stopIndex,
    HeapComparableNodeLane14RuntimeView* const insertedNode,
    HeapComparableNodeLane14RuntimeView** const heapSlots
  ) noexcept
  {
    std::int32_t parentIndex = (writeIndex - 1) / 2;
    while (stopIndex < writeIndex) {
      HeapComparableNodeLane14RuntimeView* const parentNode = heapSlots[parentIndex];
      if (parentNode->keyLane14 >= insertedNode->keyLane14) {
        break;
      }

      heapSlots[writeIndex] = parentNode;
      writeIndex = parentIndex;
      parentIndex = (parentIndex - 1) / 2;
    }

    heapSlots[writeIndex] = insertedNode;
    return parentIndex;
  }

  /**
   * Address: 0x008823A0 (FUN_008823A0)
   *
   * What it does:
   * Clears one two-dword lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLane86A(DwordPairRuntimeView* const outValue) noexcept
  {
    return ClearDwordPairLane(outValue);
  }

  /**
   * Address: 0x00882450 (FUN_00882450)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86A(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00882480 (FUN_00882480)
   *
   * What it does:
   * Alias lane for storing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86B(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008826B0 (FUN_008826B0)
   *
   * What it does:
   * Returns one scalar dword lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearScalarLane86A(std::uint32_t* const lane) noexcept
  {
    return TakeAndClearWordLane(lane);
  }

  /**
   * Address: 0x00882880 (FUN_00882880)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanes86A(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x008828D0 (FUN_008828D0)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots86A(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00882A50 (FUN_00882A50)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04Word86A(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00882A60 (FUN_00882A60)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane08Word86A(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane08);
  }

  /**
   * Address: 0x00883100 (FUN_00883100)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86C(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00883150 (FUN_00883150)
   *
   * What it does:
   * Alias lane for storing one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86D(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008836F0 (FUN_008836F0)
   *
   * What it does:
   * Swaps lanes `+0x04/+0x08/+0x0C` between two four-lane records.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanes86A(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    return SwapTrailingThreeDwordLanes(left, right);
  }

  /**
   * Address: 0x00883760 (FUN_00883760)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots86B(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00883930 (FUN_00883930)
   *
   * What it does:
   * Alias lane for swapping lanes `+0x04/+0x08/+0x0C` between two four-lane
   * records.
   */
  [[maybe_unused]] DwordQuadRuntimeView* SwapDwordQuadTailLanes86B(
    DwordQuadRuntimeView* const left,
    DwordQuadRuntimeView* const right
  ) noexcept
  {
    return SwapTrailingThreeDwordLanes(left, right);
  }

  /**
   * Address: 0x00883DC0 (FUN_00883DC0)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04Word86B(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00883DD0 (FUN_00883DD0)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane08Word86B(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane08);
  }

  /**
   * Address: 0x008843E0 (FUN_008843E0)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots86C(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x008848A0 (FUN_008848A0)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanes86B(
    DwordPairRuntimeView* const left,
    DwordPairRuntimeView* const right
  ) noexcept
  {
    return SwapDwordPairLanes71A(left, right);
  }

  /**
   * Address: 0x00884EA0 (FUN_00884EA0)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots86D(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00884EE0 (FUN_00884EE0)
   *
   * What it does:
   * Returns one scalar dword lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearScalarLane86B(std::uint32_t* const lane) noexcept
  {
    return TakeAndClearWordLane(lane);
  }

  /**
   * Address: 0x00885520 (FUN_00885520)
   *
   * What it does:
   * Returns one dword from vtable slot at offset `+0x48`.
   */
  [[maybe_unused]] std::uint32_t ReadVTableSlot72(const VTableOwnerRuntimeView* const owner) noexcept
  {
    return owner->vtable[18];
  }

  /**
   * Address: 0x00885AA0 (FUN_00885AA0)
   *
   * What it does:
   * Moves three dword lanes from source to output and clears the source lanes.
   */
  [[maybe_unused]] DwordTripleRuntimeView* MoveAndClearDwordTripleLanes86A(
    DwordTripleRuntimeView* const outValue,
    DwordTripleRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->lane00;
    source->lane00 = 0u;

    outValue->lane04 = source->lane04;
    source->lane04 = 0u;

    outValue->lane08 = source->lane08;
    source->lane08 = 0u;
    return outValue;
  }

  /**
   * Address: 0x008864F0 (FUN_008864F0)
   *
   * What it does:
   * Moves one source dword to output and clears the source lane.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearSourceWord86A(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x00886560 (FUN_00886560)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86E(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886570 (FUN_00886570)
   *
   * What it does:
   * Moves one source dword to output and clears the source lane.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearSourceWord86B(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x008865F0 (FUN_008865F0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86F(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886600 (FUN_00886600)
   *
   * What it does:
   * Moves one source dword to output and clears the source lane.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearSourceWord86C(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x00886670 (FUN_00886670)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLane86G(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008867D0 (FUN_008867D0)
   *
   * What it does:
   * Returns one scalar dword lane and clears it to zero.
   */
  [[maybe_unused]] std::uint32_t TakeAndClearScalarLane86C(std::uint32_t* const lane) noexcept
  {
    return TakeAndClearWordLane(lane);
  }

  /**
   * Address: 0x00886800 (FUN_00886800)
   *
   * What it does:
   * Unlinks one intrusive two-link node from its ring and restores
   * singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeSelf86A(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  using ScenarioLoadEntryRuntimeFn = void (*)(void* scenario, void** waitSet);

  struct ScenarioLoadCallbackBindingRuntimeView
  {
    ScenarioLoadEntryRuntimeFn entryPoint; // +0x00
    void* context;                         // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(ScenarioLoadCallbackBindingRuntimeView) == 0x08,
    "ScenarioLoadCallbackBindingRuntimeView size must be 0x08"
  );
  static_assert(
    offsetof(ScenarioLoadCallbackBindingRuntimeView, context) == 0x04,
    "ScenarioLoadCallbackBindingRuntimeView::context offset must be 0x04"
  );
#endif

  struct WordTableAt9CRuntimeView
  {
    std::byte pad0000_009B[0x9C];
    const std::uint32_t* table9C; // +0x9C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordTableAt9CRuntimeView, table9C) == 0x9C, "WordTableAt9CRuntimeView::table9C offset must be 0x9C");
#endif

  struct WordLaneAt1CRuntimeView
  {
    std::byte pad0000_001B[0x1C];
    std::uint32_t lane1C; // +0x1C
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt1CRuntimeView, lane1C) == 0x1C, "WordLaneAt1CRuntimeView::lane1C offset must be 0x1C");
#endif

  struct WordLaneAt480RuntimeView
  {
    std::byte pad0000_047F[0x480];
    std::uint32_t lane480; // +0x480
  };
#if defined(_M_IX86)
  static_assert(offsetof(WordLaneAt480RuntimeView, lane480) == 0x480, "WordLaneAt480RuntimeView::lane480 offset must be 0x480");
#endif

  struct ByteLaneAt484RuntimeView
  {
    std::byte pad0000_0483[0x484];
    std::uint8_t lane484; // +0x484
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAt484RuntimeView, lane484) == 0x484, "ByteLaneAt484RuntimeView::lane484 offset must be 0x484");
#endif

  struct ByteLaneAt485RuntimeView
  {
    std::byte pad0000_0484[0x485];
    std::uint8_t lane485; // +0x485
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAt485RuntimeView, lane485) == 0x485, "ByteLaneAt485RuntimeView::lane485 offset must be 0x485");
#endif

  void WorldSessionUserLoadEntryRuntime(void* const /*scenario*/, void** const /*waitSet*/) noexcept
  {}

  /**
   * Address: 0x00886820 (FUN_00886820)
   *
   * What it does:
   * Unlinks one intrusive node from its current ring and relinks it directly
   * after the provided anchor node.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* RelinkIntrusiveNodeAfterAnchorEpsilon(
    IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView* const anchor
  ) noexcept
  {
    return RelinkIntrusiveNodeAfterAnchor(node, anchor);
  }

  /**
   * Address: 0x00886860 (FUN_00886860)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLaneEta(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00886870 (FUN_00886870)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneMu5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886880 (FUN_00886880)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneNu5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886890 (FUN_00886890)
   *
   * What it does:
   * Binds the world-session load entry callback and caller-provided context
   * into one callback-binding pair.
   */
  [[maybe_unused]] ScenarioLoadCallbackBindingRuntimeView* BindWorldSessionLoadEntryWithContext(
    ScenarioLoadCallbackBindingRuntimeView* const outBinding,
    void* const context
  ) noexcept
  {
    outBinding->entryPoint = &WorldSessionUserLoadEntryRuntime;
    outBinding->context = context;
    return outBinding;
  }

  /**
   * Address: 0x00886910 (FUN_00886910)
   *
   * What it does:
   * Stores one scalar word and one dereferenced source word as a dword pair.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreWordPairFromScalarAndSourceWord(
    DwordPairRuntimeView* const outPair,
    const std::uint32_t* const sourceWord,
    const std::uint32_t scalar
  ) noexcept
  {
    outPair->lane00 = scalar;
    outPair->lane04 = *sourceWord;
    return outPair;
  }

  /**
   * Address: 0x00886920 (FUN_00886920)
   *
   * What it does:
   * Binds the world-session load entry callback into one callback-binding pair.
   */
  [[maybe_unused]] ScenarioLoadCallbackBindingRuntimeView* BindWorldSessionLoadEntry(
    ScenarioLoadCallbackBindingRuntimeView* const outBinding
  ) noexcept
  {
    outBinding->entryPoint = &WorldSessionUserLoadEntryRuntime;
    return outBinding;
  }

  /**
   * Address: 0x00886930 (FUN_00886930)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneXi5(
    std::uint32_t* const outValue,
    const std::uint32_t value,
    const std::uint32_t /*unused*/
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886940 (FUN_00886940)
   *
   * What it does:
   * Copies one source dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordToOutputOmega(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    *outValue = *sourceWord;
    return outValue;
  }

  /**
   * Address: 0x00886950 (FUN_00886950)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmicron5(
    std::uint32_t* const outValue,
    const std::uint32_t value,
    const std::uint32_t /*unused*/
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886960 (FUN_00886960)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePi5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886BF0 (FUN_00886BF0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneRho5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00886C00 (FUN_00886C00)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneSigma5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00887BD0 (FUN_00887BD0)
   *
   * What it does:
   * Clears one two-dword lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneDelta(DwordPairRuntimeView* const outValue) noexcept
  {
    return ClearDwordPairLane(outValue);
  }

  /**
   * Address: 0x008899D0 (FUN_008899D0)
   *
   * What it does:
   * Reads one indexed dword from table pointer lane `+0x9C`.
   */
  [[maybe_unused]] std::uint32_t ReadIndexedWordFromTableAt9C(
    const WordTableAt9CRuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->table9C[index];
  }

  /**
   * Address: 0x00889DE0 (FUN_00889DE0)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordTheta(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x00889DF0 (FUN_00889DF0)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane08WordTheta(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane08);
  }

  /**
   * Address: 0x00889F10 (FUN_00889F10)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with tail anchor at
   * `self + 0x1A0`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail1A0Alias(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderTail1A0(self);
  }

  /**
   * Address: 0x0088A030 (FUN_0088A030)
   *
   * What it does:
   * Stores source lane `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane04WordIota(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane04);
  }

  /**
   * Address: 0x0088A040 (FUN_0088A040)
   *
   * What it does:
   * Stores source lane `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSourceLane08WordIota(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, source->lane08);
  }

  /**
   * Address: 0x0088A330 (FUN_0088A330)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=100)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount100C(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 100, baseAddress);
  }

  /**
   * Address: 0x0088A390 (FUN_0088A390)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneTau5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088AA70 (FUN_0088AA70)
   *
   * What it does:
   * Stores one `base + index*4` address lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreOffsetAddressStride4FromSourceWord(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord,
    const std::int32_t index
  ) noexcept
  {
    return StoreOffsetAddressStride4FromBaseWord(outValue, sourceWord, index);
  }

  /**
   * Address: 0x0088AA90 (FUN_0088AA90)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneUpsilon5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088AAB0 (FUN_0088AAB0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePhi5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088AC50 (FUN_0088AC50)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneChi5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088B730 (FUN_0088B730)
   *
   * What it does:
   * Reads one dword lane at offset `+0x1C`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane1C(const WordLaneAt1CRuntimeView* const source) noexcept
  {
    return source->lane1C;
  }

  /**
   * Address: 0x0088B750 (FUN_0088B750)
   *
   * What it does:
   * Reads one dword lane at offset `+0x480`.
   */
  [[maybe_unused]] std::uint32_t ReadWordLane480(const WordLaneAt480RuntimeView* const source) noexcept
  {
    return source->lane480;
  }

  /**
   * Address: 0x0088B760 (FUN_0088B760)
   *
   * What it does:
   * Reads one byte lane at offset `+0x484`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane484(const ByteLaneAt484RuntimeView* const source) noexcept
  {
    return source->lane484;
  }

  /**
   * Address: 0x0088B770 (FUN_0088B770)
   *
   * What it does:
   * Reads one byte lane at offset `+0x485`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane485(const ByteLaneAt485RuntimeView* const source) noexcept
  {
    return source->lane485;
  }

  struct ByteLaneAt486RuntimeView
  {
    std::byte pad0000_0485[0x486];
    std::uint8_t lane486; // +0x486
  };
#if defined(_M_IX86)
  static_assert(offsetof(ByteLaneAt486RuntimeView, lane486) == 0x486, "ByteLaneAt486RuntimeView::lane486 offset must be 0x486");
#endif

  using DriverGameSpeedChangedRuntimeFn = std::intptr_t(__cdecl*)(std::intptr_t, std::intptr_t);

  struct DriverGameSpeedCallbackPairRuntimeView
  {
    DriverGameSpeedChangedRuntimeFn lane00; // +0x00
    DriverGameSpeedChangedRuntimeFn lane04; // +0x04
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(DriverGameSpeedCallbackPairRuntimeView) == 0x08,
    "DriverGameSpeedCallbackPairRuntimeView size must be 0x08"
  );
#endif

  struct DriverGameSpeedCallbackTripleRuntimeView
  {
    DriverGameSpeedChangedRuntimeFn lane00; // +0x00
    DriverGameSpeedChangedRuntimeFn lane04; // +0x04
    DriverGameSpeedChangedRuntimeFn lane08; // +0x08
  };
#if defined(_M_IX86)
  static_assert(
    sizeof(DriverGameSpeedCallbackTripleRuntimeView) == 0x0C,
    "DriverGameSpeedCallbackTripleRuntimeView size must be 0x0C"
  );
#endif

  std::intptr_t DriverNoteGameSpeedChangedRuntime(
    const std::intptr_t /*unusedA*/,
    const std::intptr_t /*unusedB*/
  ) noexcept
  {
    return 0;
  }

  struct SboDispatchAt1CRuntimeView
  {
    void* callback;             // +0x00
    std::uint32_t lane04;       // +0x04
    std::uint32_t storageOrPtr; // +0x08
    std::byte pad0C_1B[0x10];
    std::uint32_t length1C;     // +0x1C
    std::uint32_t lane20;       // +0x20
  };
#if defined(_M_IX86)
  static_assert(offsetof(SboDispatchAt1CRuntimeView, length1C) == 0x1C, "SboDispatchAt1CRuntimeView::length1C offset must be 0x1C");
  static_assert(offsetof(SboDispatchAt1CRuntimeView, lane20) == 0x20, "SboDispatchAt1CRuntimeView::lane20 offset must be 0x20");
#endif

  struct SboDispatchAt18RuntimeView
  {
    std::uint32_t lane00;       // +0x00
    std::uint32_t storageOrPtr; // +0x04
    std::byte pad08_17[0x10];
    std::uint32_t length18;     // +0x18
    std::uint32_t lane1C;       // +0x1C
  };
#if defined(_M_IX86)
  static_assert(offsetof(SboDispatchAt18RuntimeView, length18) == 0x18, "SboDispatchAt18RuntimeView::length18 offset must be 0x18");
  static_assert(offsetof(SboDispatchAt18RuntimeView, lane1C) == 0x1C, "SboDispatchAt18RuntimeView::lane1C offset must be 0x1C");
#endif

  using UnaryDispatchRuntimeFn = std::int32_t(__cdecl*)(std::uint32_t);
  using BinaryDispatchRuntimeFn = std::int32_t(__cdecl*)(std::uint32_t, std::uint32_t);
  using DeleteOneThisCallRuntimeFn = std::int32_t(__thiscall*)(void*, std::int32_t);

  [[nodiscard]] std::uint32_t ResolveSboPointerAt08(const SboDispatchAt1CRuntimeView* const source) noexcept
  {
    if (source->length1C < 16u) {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(const_cast<std::uint32_t*>(&source->storageOrPtr)));
    }
    return source->storageOrPtr;
  }

  [[nodiscard]] std::uint32_t ResolveSboPointerAt04(const SboDispatchAt18RuntimeView* const source) noexcept
  {
    if (source->length18 < 16u) {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(const_cast<std::uint32_t*>(&source->storageOrPtr)));
    }
    return source->storageOrPtr;
  }

  /**
   * Address: 0x0088B780 (FUN_0088B780)
   *
   * What it does:
   * Reads one byte lane at offset `+0x486`.
   */
  [[maybe_unused]] std::uint8_t ReadByteLane486(const ByteLaneAt486RuntimeView* const source) noexcept
  {
    return source->lane486;
  }

  /**
   * Address: 0x0088E890 (FUN_0088E890)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLanePsi5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088E950 (FUN_0088E950)
   *
   * What it does:
   * Moves one source dword to output and clears the source lane.
   */
  [[maybe_unused]] std::uint32_t* MoveAndClearSourceWord86D(
    std::uint32_t* const outValue,
    std::uint32_t* const source
  ) noexcept
  {
    return TakeWordAndClear(outValue, source);
  }

  /**
   * Address: 0x0088E970 (FUN_0088E970)
   *
   * What it does:
   * Initializes one self-relative 4-lane header with tail anchor at
   * `self + 0x18`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail18(
    DwordQuadRuntimeView* const self
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(self, 0x18u);
  }

  /**
   * Address: 0x0088EA10 (FUN_0088EA10)
   *
   * What it does:
   * Initializes one external dword-span header from `(base, count=2)`.
   */
  [[maybe_unused]] ExternalDwordSpanHeaderRuntimeView* InitializeExternalDwordSpanCount2Alias(
    ExternalDwordSpanHeaderRuntimeView* const outHeader,
    const std::uintptr_t baseAddress
  ) noexcept
  {
    return InitializeExternalDwordSpanHeader(outHeader, 2, baseAddress);
  }

  /**
   * Address: 0x0088ED50 (FUN_0088ED50)
   *
   * What it does:
   * Stores a driver game-speed callback triple as
   * `{DriverNoteGameSpeedChanged, lane04, lane08}`.
   */
  [[maybe_unused]] DriverGameSpeedCallbackTripleRuntimeView* BindDriverGameSpeedCallbackTripleA(
    DriverGameSpeedCallbackTripleRuntimeView* const outValue,
    const DriverGameSpeedChangedRuntimeFn lane08,
    const DriverGameSpeedChangedRuntimeFn lane04
  ) noexcept
  {
    outValue->lane00 = &DriverNoteGameSpeedChangedRuntime;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    return outValue;
  }

  /**
   * Address: 0x0088F000 (FUN_0088F000)
   *
   * What it does:
   * Stores a driver game-speed callback triple as
   * `{DriverNoteGameSpeedChanged, source[0], source[1]}`.
   */
  [[maybe_unused]] DriverGameSpeedCallbackTripleRuntimeView* BindDriverGameSpeedCallbackTripleB(
    DriverGameSpeedCallbackTripleRuntimeView* const outValue,
    const DriverGameSpeedCallbackPairRuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = &DriverNoteGameSpeedChangedRuntime;
    outValue->lane04 = source->lane00;
    outValue->lane08 = source->lane04;
    return outValue;
  }

  /**
   * Address: 0x0088F020 (FUN_0088F020)
   *
   * What it does:
   * Stores one dword pair from two scalar lanes.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromScalarsUpsilon(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x0088F030 (FUN_0088F030)
   *
   * What it does:
   * Copies one source dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordToOutputAlpha6(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    *outValue = *sourceWord;
    return outValue;
  }

  /**
   * Address: 0x0088F130 (FUN_0088F130)
   *
   * What it does:
   * Stores one dword pair from two scalar lanes.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromScalarsPhi(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, lane00, lane04);
  }

  /**
   * Address: 0x0088F140 (FUN_0088F140)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneOmega5(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x0088FB80 (FUN_0088FB80)
   *
   * What it does:
   * Stores three scalar dword lanes into output when output is non-null.
   */
  [[maybe_unused]] DwordTripleRuntimeView* StoreDwordTripleIfOutputPresent(
    DwordTripleRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    if (outValue != nullptr) {
      outValue->lane00 = lane00;
      outValue->lane04 = lane04;
      outValue->lane08 = lane08;
    }
    return outValue;
  }

  /**
   * Address: 0x0088FD60 (FUN_0088FD60)
   *
   * What it does:
   * Invokes one unary callback with inline-storage pointer (`+0x08`) when
   * length lane `+0x1C` is small, otherwise with heap pointer lane `+0x08`.
   */
  [[maybe_unused]] std::int32_t InvokeSboUnaryCallbackAt1C(
    const SboDispatchAt1CRuntimeView* const source
  ) noexcept
  {
    const auto callback = reinterpret_cast<UnaryDispatchRuntimeFn>(source->callback);
    return callback(ResolveSboPointerAt08(source));
  }

  /**
   * Address: 0x0088FD80 (FUN_0088FD80)
   *
   * What it does:
   * Invokes one binary callback with inline/heap source pointer and trailing
   * lane address at `+0x20`.
   */
  [[maybe_unused]] std::int32_t InvokeSboBinaryCallbackAt1C(
    SboDispatchAt1CRuntimeView* const source
  ) noexcept
  {
    const auto callback = reinterpret_cast<BinaryDispatchRuntimeFn>(source->callback);
    const auto trailingAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&source->lane20));
    return callback(ResolveSboPointerAt08(source), trailingAddress);
  }

  /**
   * Address: 0x0088FDB0 (FUN_0088FDB0)
   *
   * What it does:
   * Invokes one binary callback stored at `+0x00` with scalar lanes
   * `+0x04/+0x08`.
   */
  [[maybe_unused]] std::int32_t InvokeBinaryCallbackWithPairLanes(
    const SboDispatchAt1CRuntimeView* const source
  ) noexcept
  {
    const auto callback = reinterpret_cast<BinaryDispatchRuntimeFn>(source->callback);
    return callback(source->lane04, source->storageOrPtr);
  }

  /**
   * Address: 0x00890120 (FUN_00890120)
   *
   * What it does:
   * Invokes one unary external callback with inline/heap pointer resolved from
   * lane `+0x04` and length lane `+0x18`.
   */
  [[maybe_unused]] std::int32_t InvokeExternalUnaryCallbackWithSboPointer(
    const SboDispatchAt18RuntimeView* const source,
    UnaryDispatchRuntimeFn* const callbackSlot
  ) noexcept
  {
    return (*callbackSlot)(ResolveSboPointerAt04(source));
  }

  /**
   * Address: 0x00890150 (FUN_00890150)
   *
   * What it does:
   * Invokes one binary external callback with resolved inline/heap pointer and
   * trailing lane address at `+0x1C`.
   */
  [[maybe_unused]] std::int32_t InvokeExternalBinaryCallbackWithSboPointer(
    SboDispatchAt18RuntimeView* const source,
    BinaryDispatchRuntimeFn* const callbackSlot
  ) noexcept
  {
    const auto trailingAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&source->lane1C));
    return (*callbackSlot)(ResolveSboPointerAt04(source), trailingAddress);
  }

  /**
   * Address: 0x00890180 (FUN_00890180)
   *
   * What it does:
   * Invokes one binary external callback with dword pair lanes.
   */
  [[maybe_unused]] std::int32_t InvokeExternalBinaryCallbackWithDwordPair(
    const DwordPairRuntimeView* const source,
    BinaryDispatchRuntimeFn* const callbackSlot
  ) noexcept
  {
    return (*callbackSlot)(source->lane00, source->lane04);
  }

  /**
   * Address: 0x008902D0 (FUN_008902D0)
   *
   * What it does:
   * Invokes virtual slot `+0x04` on one object with delete-flag `1`.
   */
  [[maybe_unused]] std::int32_t InvokeVirtualSlot04DeleteOne(
    VTableOwnerRuntimeView* const self
  ) noexcept
  {
    auto* const vtable = reinterpret_cast<void**>(self->vtable);
    const auto callback = reinterpret_cast<DeleteOneThisCallRuntimeFn>(vtable[1]);
    return callback(self, 1);
  }

  /**
   * Address: 0x008913D0 (FUN_008913D0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneAlpha6(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00891430 (FUN_00891430)
   *
   * What it does:
   * Returns whether one pointer slot is null.
   */
  [[maybe_unused]] std::int32_t IsPointerSlotNullAlpha(const void* const* const slot) noexcept
  {
    return (*slot == nullptr) ? 1 : 0;
  }

  /**
   * Address: 0x00891440 (FUN_00891440)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBeta6(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x00891460 (FUN_00891460)
   * Address: 0x008A8290 (FUN_008A8290)
   *
   * What it does:
   * Replaces one owned virtual-object pointer slot and releases previous value
   * through virtual slot 0 with delete-flag `1` when present.
   */
  [[maybe_unused]] void*** ReplaceOwnedVirtualPointerAndReleasePrevious(
    void*** const slot,
    void** const replacement
  ) noexcept
  {
    void** const previous = *slot;
    *slot = replacement;
    if (previous != nullptr) {
      auto* const previousOwner = reinterpret_cast<VTableOwnerRuntimeView*>(previous);
      (void)DestroyViaVTableSlot0DeleteOneIfPresent(previousOwner);
    }
    return slot;
  }

  /**
   * Address: 0x00891490 (FUN_00891490)
   *
   * What it does:
   * Returns whether one pointer slot is null.
   */
  [[maybe_unused]] std::int32_t IsPointerSlotNullBeta(const void* const* const slot) noexcept
  {
    return (*slot == nullptr) ? 1 : 0;
  }

  /**
   * Address: 0x008914A0 (FUN_008914A0)
   *
   * What it does:
   * Stores one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneGamma6(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008914E0 (FUN_008914E0)
   *
   * What it does:
   * Returns whether one pointer slot is null.
   */
  [[maybe_unused]] std::int32_t IsPointerSlotNullGamma(const void* const* const slot) noexcept
  {
    return (*slot == nullptr) ? 1 : 0;
  }

  /**
   * Address: 0x00891530 (FUN_00891530)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLaneTheta(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00891540 (FUN_00891540)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLaneIota(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00891550 (FUN_00891550)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarDwordLaneKappa(
    std::uint32_t* const left,
    std::uint32_t* const right
  ) noexcept
  {
    return SwapDwordSlotValues(left, right);
  }

  /**
   * Address: 0x00891640 (FUN_00891640)
   *
   * What it does:
   * Invokes virtual slot 0 with delete-flag `1` when object is present.
   */
  [[maybe_unused]] std::int32_t DestroyViaVTableSlot0DeleteOneIfNonNull(
    VTableOwnerRuntimeView* const self
  ) noexcept
  {
    return DestroyViaVTableSlot0DeleteOneIfPresent(self);
  }

  [[nodiscard]] SpanHeaderSelfRefRuntimeView* InitializeExternalSpanHeaderWithByteSpan(
    SpanHeaderSelfRefRuntimeView* const outValue,
    const std::uint32_t baseAddress,
    const std::uint32_t spanBytes
  ) noexcept
  {
    outValue->begin = baseAddress;
    outValue->cursor = baseAddress;
    outValue->end = baseAddress + spanBytes;
    outValue->lane0C = baseAddress;
    return outValue;
  }

  /**
   * Address: 0x008AE4B0 (FUN_008AE4B0)
   * Address: 0x008AEBF0 (FUN_008AEBF0)
   *
   * What it does:
   * Clears one two-dword output lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBatchOmega(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane(outValue);
  }

  /**
   * Address: 0x008AE5A0 (FUN_008AE5A0)
   * Address: 0x008AEB70 (FUN_008AEB70)
   *
   * What it does:
   * Writes one dword from `**(source->lane04)` into output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDoubleDereferencedLane04WordBatchOmega(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x008AE5B0 (FUN_008AE5B0)
   * Address: 0x008AEB80 (FUN_008AEB80)
   * Address: 0x008B2750 (FUN_008B2750)
   * Address: 0x008B2A30 (FUN_008B2A30)
   * Address: 0x008B3180 (FUN_008B3180)
   *
   * What it does:
   * Copies the first dword at `*source->lane04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteIndirectLane04WordBatchOmega(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x008AE9A0 (FUN_008AE9A0)
   *
   * What it does:
   * Initializes one self-relative span header with inline start at `+0x10`
   * and tail anchor at `+0x110`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail110BatchOmega(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x110u);
  }

  /**
   * Address: 0x008AE9F0 (FUN_008AE9F0)
   *
   * What it does:
   * Initializes one self-relative span header with inline start at `+0x10`
   * and tail anchor at `+0x2810`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeSelfRelativeSpanHeaderTail2810BatchOmega(
    SpanHeaderSelfRefRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeSpanHeaderWithTailOffset(outValue, 0x2810u);
  }

  /**
   * Address: 0x008AEB20 (FUN_008AEB20)
   *
   * What it does:
   * Computes one `*baseAddress + index * 40` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride40AddressFromBaseWordBatchOmega(
    const std::int32_t index,
    const std::uint32_t* const baseAddress
  ) noexcept
  {
    return static_cast<std::uint32_t>(ComputeOffsetAddressByStride(*baseAddress, index, 40u));
  }

  /**
   * Address: 0x008AECB0 (FUN_008AECB0)
   * Address: 0x008AF450 (FUN_008AF450)
   *
   * What it does:
   * Advances one head pointer slot to `(*headSlot)->next`.
   */
  [[maybe_unused]] std::uint32_t** AdvanceHeadPointerSlotBatchOmega(
    std::uint32_t** const headSlot
  ) noexcept
  {
    return AdvanceHeadPointerSlot(headSlot);
  }

  /**
   * Address: 0x008AF220 (FUN_008AF220)
   *
   * What it does:
   * Initializes one `{dword,byte}` lane pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* CopyDwordBytePairFromPointersBatchOmega(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const wordSource,
    const std::uint8_t* const byteSource
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, wordSource, byteSource);
  }

  /**
   * Address: 0x008AF230 (FUN_008AF230)
   * Address: 0x008AF420 (FUN_008AF420)
   * Address: 0x008AF680 (FUN_008AF680)
   * Address: 0x008AF9F0 (FUN_008AF9F0)
   * Address: 0x008B3020 (FUN_008B3020)
   * Address: 0x008B3480 (FUN_008B3480)
   * Address: 0x008B34A0 (FUN_008B34A0)
   *
   * What it does:
   * Stores one scalar dword into output lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchOmega(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008AF320 (FUN_008AF320)
   *
   * What it does:
   * Initializes one external span header from `(base, spanBytes=0x2800)`.
   */
  [[maybe_unused]] SpanHeaderSelfRefRuntimeView* InitializeExternalSpanHeaderTail2800BatchOmega(
    SpanHeaderSelfRefRuntimeView* const outValue,
    const std::uint32_t baseAddress
  ) noexcept
  {
    return InitializeExternalSpanHeaderWithByteSpan(outValue, baseAddress, 0x2800u);
  }

  /**
   * Address: 0x008AF430 (FUN_008AF430)
   *
   * What it does:
   * Pops one intrusive head-node pointer, writes popped node address, and
   * advances the head slot to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressLaneBatchOmega(
    std::uint32_t* const outNodeAddress,
    std::uint32_t** const headSlot
  ) noexcept
  {
    return PopHeadNodeAddressAndAdvance(outNodeAddress, headSlot);
  }

  /**
   * Address: 0x008AFC50 (FUN_008AFC50)
   *
   * What it does:
   * Initializes one four-dword-plus-two-byte lane record.
   */
  [[maybe_unused]] FourDwordAndTwoByteInitRuntimeView* InitializeFourDwordTwoByteLaneBatchOmega(
    FourDwordAndTwoByteInitRuntimeView* const outValue,
    const std::uint32_t lane04,
    const std::uint32_t lane00,
    const std::uint32_t lane08,
    const std::uint32_t* const lane0CSource,
    const std::uint8_t lane10
  ) noexcept
  {
    return InitializeFourDwordTwoByteLanePrimary(outValue, lane04, lane00, lane08, lane0CSource, lane10);
  }

  /**
   * Address: 0x008B2760 (FUN_008B2760)
   * Address: 0x008B2A40 (FUN_008B2A40)
   * Address: 0x008B2EF0 (FUN_008B2EF0)
   *
   * What it does:
   * Stores source lane `+0x08` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane08DwordBatchOmega(
    std::uint32_t* const outValue,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x008B3030 (FUN_008B3030)
   *
   * What it does:
   * Computes `*base + index * 8` and stores the result dword in output.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride8ByteOffsetBatchOmega(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride8ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x008B34B0 (FUN_008B34B0)
   *
   * What it does:
   * Computes `*base + index * 4` and stores the result dword in output.
   */
  [[maybe_unused]] std::uint32_t* ComputeStride4ByteOffsetBatchOmega(
    std::uint32_t* const outValue,
    const std::uint32_t* const base,
    const std::int32_t index
  ) noexcept
  {
    return ComputeStride4ByteOffset(outValue, base, index);
  }

  /**
   * Address: 0x008D7A60 (FUN_008D7A60)
   * Address: 0x008D7AE0 (FUN_008D7AE0)
   * Address: 0x008D7B30 (FUN_008D7B30)
   * Address: 0x008D7B90 (FUN_008D7B90)
   *
   * What it does:
   * Stores source lane `+0x08` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane08WordToOutputBatchSigma(
    std::uint32_t* const outValue,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x008D7AD0 (FUN_008D7AD0)
   * Address: 0x008D7B20 (FUN_008D7B20)
   * Address: 0x008D7B80 (FUN_008D7B80)
   *
   * What it does:
   * Stores source lane `+0x04` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane04WordToOutputBatchSigma(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x008D7BE0 (FUN_008D7BE0)
   * Address: 0x008D7BF0 (FUN_008D7BF0)
   * Address: 0x008D7C00 (FUN_008D7C00)
   * Address: 0x008D7C10 (FUN_008D7C10)
   * Address: 0x008D8AA0 (FUN_008D8AA0)
   * Address: 0x008D8B50 (FUN_008D8B50)
   * Address: 0x008D8C20 (FUN_008D8C20)
   * Address: 0x008D8C40 (FUN_008D8C40)
   * Address: 0x008D8D60 (FUN_008D8D60)
   *
   * What it does:
   * Stores one scalar dword into output lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchSigma(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008D8D20 (FUN_008D8D20)
   *
   * What it does:
   * Stores zero into output lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreZeroScalarDwordLaneBatchSigma(
    std::uint32_t* const outValue
  ) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x008D8620 (FUN_008D8620)
   *
   * What it does:
   * Reads and returns source lane `+0x08`.
   */
  [[maybe_unused]] std::uint32_t ReadLane08WordBatchSigma(const SourceLane8RuntimeView* const source) noexcept
  {
    return source->lane08;
  }

  /**
   * Address: 0x008D8630 (FUN_008D8630)
   *
   * What it does:
   * Reads and returns source lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t ReadLane04WordBatchSigma(const DwordPairRuntimeView* const source) noexcept
  {
    return source->lane04;
  }

  /**
   * Address: 0x008D8690 (FUN_008D8690)
   *
   * What it does:
   * Returns true when left pointed C-string is lexicographically less than
   * right pointed C-string.
   */
  [[maybe_unused]] bool CompareCStringPointerSlotsLessBatchSigma(
    const char* const* const leftSlot,
    const char* const* const rightSlot
  ) noexcept
  {
    const auto* left = reinterpret_cast<const std::uint8_t*>(*leftSlot);
    const auto* right = reinterpret_cast<const std::uint8_t*>(*rightSlot);
    while (*left == *right) {
      if (*left == 0u) {
        return false;
      }
      ++left;
      ++right;
    }
    return *left < *right;
  }

  /**
   * Address: 0x008D8870 (FUN_008D8870)
   *
   * What it does:
   * Computes one `source lane +0x04 + index * 20` byte address.
   */
  [[maybe_unused]] std::uint32_t ComputeStride20AddressFromLane04BatchSigma(
    const std::int32_t index,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return static_cast<std::uint32_t>(ComputeOffsetAddressByStride(source->lane04, index, 20u));
  }

  /**
   * Address: 0x008D8880 (FUN_008D8880)
   * Address: 0x008D8A80 (FUN_008D8A80)
   *
   * What it does:
   * Initializes one two-dword lane pair from two source pointers.
   */
  [[maybe_unused]] DwordPairRuntimeView* StoreDwordPairFromPointerSourcesBatchSigma(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const lane00Source,
    const std::uint32_t* const lane04Source
  ) noexcept
  {
    return StoreDwordPairFromTwoScalars7B(outValue, *lane00Source, *lane04Source);
  }

  /**
   * Address: 0x008D89C0 (FUN_008D89C0)
   * Address: 0x008D8DC0 (FUN_008D8DC0)
   *
   * What it does:
   * Initializes one `{dword,byte}` lane pair from source pointers.
   */
  [[maybe_unused]] DwordBytePairLane* StoreDwordBytePairFromPointerSourcesBatchSigma(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const lane00Source,
    const std::uint8_t* const lane04Source
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, lane00Source, lane04Source);
  }

  /**
   * Address: 0x008D8D80 (FUN_008D8D80)
   * Address: 0x008D8F40 (FUN_008D8F40)
   *
   * What it does:
   * Packs five dword lanes plus one input flag and one trailing zero flag into
   * one 0x16-byte runtime record.
   */
  [[maybe_unused]] FiveWordAndTwoFlagsRuntimeView* InitializeFiveWordAndTwoFlagRecordBatchSigma(
    FiveWordAndTwoFlagsRuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08,
    const std::uint32_t* const pairSource,
    const std::uint8_t flag14
  ) noexcept
  {
    return StoreFiveWordAndTwoFlagRecord(outValue, lane00, pairSource, lane04, lane08, flag14);
  }

  /**
   * Address: 0x008D9160 (FUN_008D9160)
   * Address: 0x008D9200 (FUN_008D9200)
   *
   * What it does:
   * Copies one source dword into output when output storage is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentBatchSigma(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, sourceWord);
  }

  /**
   * Address: 0x008D9230 (FUN_008D9230)
   *
   * What it does:
   * Fills one `[begin,end)` range of dword pairs from one source pair lane.
   */
  [[maybe_unused]] std::uint32_t* FillWordPairRangeWithConstantBatchSigma(
    std::uint32_t* const begin,
    std::uint32_t* const end,
    const std::uint32_t* const sourcePair
  ) noexcept
  {
    return FillWordPairRangeWithConstant(begin, end, sourcePair);
  }

  struct WordLanesAt0CAnd14RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint32_t lane10; // +0x10
    std::uint32_t lane14; // +0x14
  };
  static_assert(
    offsetof(WordLanesAt0CAnd14RuntimeView, lane0C) == 0x0C,
    "WordLanesAt0CAnd14RuntimeView::lane0C offset must be 0x0C"
  );
  static_assert(
    offsetof(WordLanesAt0CAnd14RuntimeView, lane14) == 0x14,
    "WordLanesAt0CAnd14RuntimeView::lane14 offset must be 0x14"
  );

  struct ThreeWordAndByteAt10RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint32_t lane04; // +0x04
    std::uint32_t lane08; // +0x08
    std::uint32_t lane0C; // +0x0C
    std::uint8_t lane10;  // +0x10
  };
  static_assert(
    offsetof(ThreeWordAndByteAt10RuntimeView, lane10) == 0x10,
    "ThreeWordAndByteAt10RuntimeView::lane10 offset must be 0x10"
  );
  static_assert(
    sizeof(ThreeWordAndByteAt10RuntimeView) == 0x14,
    "ThreeWordAndByteAt10RuntimeView size must be 0x14"
  );

  using VirtualSlot0DeleteOneCall = std::int32_t(__thiscall*)(void* self, std::int32_t deleteFlag);
  using VirtualSlot2ReleaseCall = std::int32_t(__stdcall*)(void* self);
  using VirtualSlot24Call = void(__thiscall*)(void* self, std::int32_t, std::int32_t, std::int32_t, std::int32_t);

  /**
   * Address: 0x008E41E0 (FUN_008E41E0)
   *
   * What it does:
   * Advances one pointer slot to the node link stored at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* AdvancePointerSlotFromNodeLink04BatchTau(
    std::uint32_t* const pointerSlot
  ) noexcept
  {
    const auto* const node = reinterpret_cast<const DwordPairRuntimeView*>(*pointerSlot);
    *pointerSlot = node->lane04;
    return pointerSlot;
  }

  /**
   * Address: 0x008E41F0 (FUN_008E41F0)
   * Address: 0x008E6610 (FUN_008E6610)
   * Address: 0x008E84D0 (FUN_008E84D0)
   * Address: 0x008E85C0 (FUN_008E85C0)
   * Address: 0x008E8BB0 (FUN_008E8BB0)
   *
   * What it does:
   * Stores one scalar dword into output lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchTau(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x008E4200 (FUN_008E4200)
   *
   * What it does:
   * Pops one intrusive head-node pointer, writes popped node address, and
   * advances the head slot to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressFromThisSlotBatchTau(
    std::uint32_t* const headSlot,
    std::uint32_t* const outNodeAddress
  ) noexcept
  {
    const std::uint32_t headAddress = *headSlot;
    *outNodeAddress = headAddress;
    const auto* const node = reinterpret_cast<const LinkedWordNodeRuntimeView*>(static_cast<std::uintptr_t>(headAddress));
    *headSlot = node->nextNodeAddress;
    return outNodeAddress;
  }

  /**
   * Address: 0x008E4230 (FUN_008E4230)
   *
   * What it does:
   * Copies one source dword into output when output storage is non-null.
   */
  [[maybe_unused]] std::uint32_t* CopySourceWordIfOutputPresentBatchTau(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return CopyWordIfDestinationPresent(outValue, sourceWord);
  }

  /**
   * Address: 0x008E4260 (FUN_008E4260)
   * Address: 0x008E42E0 (FUN_008E42E0)
   *
   * What it does:
   * Returns one dword-address lane at `*source + 8`.
   */
  [[maybe_unused]] std::uint32_t ComputeWordAddressPlus8BatchTau(const std::uint32_t* const source) noexcept
  {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ComputeWordAddressPlus8(source)));
  }

  /**
   * Address: 0x008E4290 (FUN_008E4290)
   *
   * What it does:
   * Copies the first dword at `*source->lane04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectWordBatchTau(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x008E42A0 (FUN_008E42A0)
   *
   * What it does:
   * Writes one dword from `**(source->lane04)` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDoubleIndirectWordBatchTau(
    std::uint32_t* const outValue,
    const PointerToPointerAt04RuntimeView* const source
  ) noexcept
  {
    return WriteDoubleDereferencedLane04WordA(outValue, source);
  }

  /**
   * Address: 0x008E42B0 (FUN_008E42B0)
   *
   * What it does:
   * Stores source lane `+0x04` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane04WordToOutputBatchTau(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x008E5A10 (FUN_008E5A10)
   *
   * What it does:
   * Returns lane `+0x14` and updates lane `+0x0C` when lane `+0x14` is
   * non-zero and greater.
   */
  [[maybe_unused]] std::uint32_t UpdateMaxLane0CFromLane14BatchTau(
    WordLanesAt0CAnd14RuntimeView* const valueLanes
  ) noexcept
  {
    const std::uint32_t value = valueLanes->lane14;
    if (value != 0u && value > valueLanes->lane0C) {
      valueLanes->lane0C = value;
    }
    return value;
  }

  /**
   * Address: 0x008E5A20 (FUN_008E5A20)
   *
   * What it does:
   * Returns the maximum of two signed 64-bit values.
   */
  [[maybe_unused]] std::int64_t MaxSignedQwordBatchTau(
    const std::int64_t leftValue,
    const std::int64_t rightValue
  ) noexcept
  {
    return leftValue < rightValue ? rightValue : leftValue;
  }

  /**
   * Address: 0x008E6640 (FUN_008E6640)
   *
   * What it does:
   * Replaces one owned virtual-object pointer slot and releases previous value
   * through virtual slot `+0x00` with delete-flag `1` when replaced.
   */
  [[maybe_unused]] std::int32_t ReplaceOwnedVirtualPointerSlotBatchTau(
    void** const ownerSlot,
    void* const replacement
  ) noexcept
  {
    void* const previous = *ownerSlot;
    std::int32_t result = 0;
    if (replacement != previous && previous != nullptr) {
      auto* const vtable = *reinterpret_cast<void***>(previous);
      const auto callback = reinterpret_cast<VirtualSlot0DeleteOneCall>(vtable[0]);
      result = callback(previous, 1);
    }
    *ownerSlot = replacement;
    return result;
  }

  /**
   * Address: 0x008E6D00 (FUN_008E6D00)
   * Address: 0x008E6D10 (FUN_008E6D10)
   * Address: 0x008E6D20 (FUN_008E6D20)
   * Address: 0x008E6D30 (FUN_008E6D30)
   *
   * What it does:
   * Clears trailing dword lanes `+0x04/+0x08/+0x0C`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* ClearTrailingThreeWordLanesBatchTau(
    DwordQuadRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane04 = 0u;
    outValue->lane08 = 0u;
    outValue->lane0C = 0u;
    return outValue;
  }

  /**
   * Address: 0x008E7F10 (FUN_008E7F10)
   *
   * What it does:
   * Copies lanes `+0x04/+0x08/+0x0C/+0x10` from source to destination.
   */
  [[maybe_unused]] ThreeWordAndByteAt10RuntimeView* CopyTrailingThreeWordsAndByteBatchTau(
    ThreeWordAndByteAt10RuntimeView* const destination,
    const ThreeWordAndByteAt10RuntimeView* const source
  ) noexcept
  {
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;
    destination->lane10 = source->lane10;
    return destination;
  }

  /**
   * Address: 0x008E7F60 (FUN_008E7F60)
   *
   * What it does:
   * Calls virtual slot `+0x08` on one owned pointer slot when non-null, then
   * clears the slot.
   */
  [[maybe_unused]] std::int32_t ReleaseOwnedPointerSlotViaVirtualSlot08BatchTau(
    void** const ownerSlot
  ) noexcept
  {
    std::int32_t result = 0;
    void* const object = *ownerSlot;
    if (object != nullptr) {
      auto* const vtable = *reinterpret_cast<void***>(object);
      const auto callback = reinterpret_cast<VirtualSlot2ReleaseCall>(vtable[2]);
      result = callback(object);
    }
    *ownerSlot = nullptr;
    return result;
  }

  /**
   * Address: 0x008E8180 (FUN_008E8180)
   *
   * What it does:
   * Initializes three contiguous dword lanes from scalar inputs.
   */
  [[maybe_unused]] SourceLane8RuntimeView* InitializeThreeWordRecordBatchTau(
    SourceLane8RuntimeView* const outValue,
    const std::uint32_t lane00,
    const std::uint32_t lane04,
    const std::uint32_t lane08
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    outValue->lane08 = lane08;
    return outValue;
  }

  /**
   * Address: 0x008E8460 (FUN_008E8460)
   *
   * What it does:
   * Invokes virtual slot `+0x24` with four scalar args and returns the first
   * argument lane.
   */
  [[maybe_unused]] std::int32_t InvokeVirtualSlot24AndReturnFirstArgBatchTau(
    VTableOwnerRuntimeView* const self,
    const std::int32_t firstArg,
    const std::int32_t secondArg,
    const std::int32_t thirdArg,
    const std::int32_t fourthArg
  ) noexcept
  {
    auto* const vtable = reinterpret_cast<void**>(self->vtable);
    const auto callback = reinterpret_cast<VirtualSlot24Call>(vtable[9]);
    callback(self, firstArg, secondArg, thirdArg, fourthArg);
    return firstArg;
  }

  /**
   * Address: 0x008E8770 (FUN_008E8770)
   *
   * What it does:
   * Swaps one scalar dword lane between two storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapScalarWordSlotsBatchTau(
    std::uint32_t* const leftWord,
    std::uint32_t* const rightWord
  ) noexcept
  {
    return SwapDwordSlotValues(leftWord, rightWord);
  }

  /**
   * Address: 0x008E8DF0 (FUN_008E8DF0)
   *
   * What it does:
   * Copies trailing dword lanes `+0x04/+0x08/+0x0C` from source to
   * destination.
   */
  [[maybe_unused]] DwordQuadRuntimeView* CopyTrailingThreeWordLanesBatchTau(
    DwordQuadRuntimeView* const destination,
    const DwordQuadRuntimeView* const source
  ) noexcept
  {
    destination->lane04 = source->lane04;
    destination->lane08 = source->lane08;
    destination->lane0C = source->lane0C;
    return destination;
  }

  /**
   * Address: 0x008E8FC0 (FUN_008E8FC0)
   *
   * What it does:
   * Stores source lane `+0x04` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane04WordToOutputBatchTauB(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x008E8FD0 (FUN_008E8FD0)
   *
   * What it does:
   * Stores source lane `+0x08` into caller-provided dword output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane08WordToOutputBatchTauB(
    std::uint32_t* const outValue,
    const SourceLane8RuntimeView* const source
  ) noexcept
  {
    return CopyWordToOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x008E8FE0 (FUN_008E8FE0)
   *
   * What it does:
   * Clears one two-dword output lane to `{0, 0}`.
   */
  [[maybe_unused]] DwordPairRuntimeView* ClearDwordPairLaneBatchTau(
    DwordPairRuntimeView* const outValue
  ) noexcept
  {
    return ClearDwordPairLane(outValue);
  }

  /**
   * Address: 0x008E9040 (FUN_008E9040)
   *
   * What it does:
   * Swaps both dword lanes between two pair records.
   */
  [[maybe_unused]] DwordPairRuntimeView* SwapDwordPairLanesBatchTau(
    DwordPairRuntimeView* const leftPair,
    DwordPairRuntimeView* const rightPair
  ) noexcept
  {
    const std::uint32_t left0 = leftPair->lane00;
    leftPair->lane00 = rightPair->lane00;
    rightPair->lane00 = left0;

    const std::uint32_t left4 = leftPair->lane04;
    leftPair->lane04 = rightPair->lane04;
    rightPair->lane04 = left4;
    return rightPair;
  }

  struct WordAndTail28RuntimeView
  {
    std::uint16_t leadingWord;   // +0x00
    std::byte pad02_03[0x02];    // +0x02
    std::byte tail04_1F[0x1C];   // +0x04
  };
#if defined(_M_IX86)
  static_assert(sizeof(WordAndTail28RuntimeView) == 0x20, "WordAndTail28RuntimeView size must be 0x20");
  static_assert(
    offsetof(WordAndTail28RuntimeView, tail04_1F) == 0x04,
    "WordAndTail28RuntimeView::tail04_1F offset must be 0x04"
  );
#endif

  /**
   * Address: 0x0092C2D0 (FUN_0092C2D0)
   *
   * What it does:
   * Computes one `source->lane04 + index * 12` byte address lane.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromLane04BatchUpsilon(
    const DwordPairRuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return static_cast<std::uint32_t>(ComputeOffsetAddressByStride(source->lane04, index, 12u));
  }

  /**
   * Address: 0x0092C310 (FUN_0092C310)
   *
   * What it does:
   * Copies one leading halfword and 0x1C tail bytes into destination lanes.
   */
  [[maybe_unused]] WordAndTail28RuntimeView* CopyLeadingWordAndTail28BatchUpsilon(
    WordAndTail28RuntimeView* const outValue,
    const std::uint16_t* const sourceWord,
    const void* const sourceTailBytes
  ) noexcept
  {
    outValue->leadingWord = *sourceWord;
    std::memcpy(outValue->tail04_1F, sourceTailBytes, sizeof(outValue->tail04_1F));
    return outValue;
  }

  /**
   * Address: 0x0092C340 (FUN_0092C340)
   *
   * What it does:
   * Clears lane `+0x08` in one three-word record.
   */
  [[maybe_unused]] DwordTripleRuntimeView* ClearLane08BatchUpsilon(DwordTripleRuntimeView* const outValue) noexcept
  {
    outValue->lane08 = 0u;
    return outValue;
  }

  /**
   * Address: 0x0092C350 (FUN_0092C350)
   *
   * What it does:
   * Copies one scalar dword lane from source into destination.
   */
  [[maybe_unused]] std::uint32_t* CopySingleWordFromSourceSlotBatchUpsilon(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceWord
  ) noexcept
  {
    return StoreDword(outValue, *sourceWord);
  }

  /**
   * Address: 0x0092C460 (FUN_0092C460)
   *
   * What it does:
   * Pushes one index onto a freelist chain and returns the pushed index.
   */
  [[maybe_unused]] std::uint32_t PushIndexOntoHeadChainBatchUpsilon(
    IndexChainPushRuntimeView* const chain,
    const std::uint32_t index
  ) noexcept
  {
    chain->nextByIndex[index] = chain->headIndex;
    chain->headIndex = index;
    return index;
  }

  /**
   * Address: 0x0092C4B0 (FUN_0092C4B0)
   * Address: 0x0092D3E0 (FUN_0092D3E0)
   *
   * What it does:
   * Clears one scalar dword lane.
   */
  [[maybe_unused]] std::uint32_t* ZeroScalarWordBatchUpsilon(std::uint32_t* const outValue) noexcept
  {
    return ZeroScalarDwordLane(outValue);
  }

  /**
   * Address: 0x0092C4C0 (FUN_0092C4C0)
   * Address: 0x0092D3F0 (FUN_0092D3F0)
   *
   * What it does:
   * Collapses one pointer slot through the node-head lane at `*slot`.
   */
  [[maybe_unused]] std::uint32_t** CollapsePointerSlotThroughNodeHeadBatchUpsilon(
    std::uint32_t** const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeHead(pointerSlot);
  }

  /**
   * Address: 0x0092C4F0 (FUN_0092C4F0)
   *
   * What it does:
   * Writes one `{dword, byte}` pair from independent source lanes.
   */
  [[maybe_unused]] DwordBytePairLane* CopyWordAndBytePairBatchUpsilon(
    DwordBytePairLane* const outValue,
    const std::uint32_t* const sourceWord,
    const std::uint8_t* const sourceByte
  ) noexcept
  {
    return CopyWordAndBytePair(outValue, sourceWord, sourceByte);
  }

  /**
   * Address: 0x0092C560 (FUN_0092C560)
   * Address: 0x0092D400 (FUN_0092D400)
   *
   * What it does:
   * Advances one pointer slot to the node link stored at offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* AdvancePointerSlotFromNodeLink04BatchUpsilon(
    std::uint32_t* const pointerSlot
  ) noexcept
  {
    return AdvancePointerSlotFromNodeLink04BatchTau(pointerSlot);
  }

  /**
   * Address: 0x0092CA30 (FUN_0092CA30)
   *
   * What it does:
   * Copies two independent dword sources into destination lanes `+0x00/+0x04`.
   */
  [[maybe_unused]] DwordPairRuntimeView* CopyDwordPairFromIndependentSourcesBatchUpsilon(
    DwordPairRuntimeView* const outValue,
    const std::uint32_t* const sourceWordA,
    const std::uint32_t* const sourceWordB
  ) noexcept
  {
    outValue->lane00 = *sourceWordA;
    outValue->lane04 = *sourceWordB;
    return outValue;
  }

  /**
   * Address: 0x0092CAC0 (FUN_0092CAC0)
   * Address: 0x0092D680 (FUN_0092D680)
   *
   * What it does:
   * Swaps one 16-bit lane value between two slots.
   */
  [[maybe_unused]] std::uint16_t* SwapSingleHalfwordLaneBatchUpsilon(
    std::uint16_t* const left,
    std::uint16_t* const right
  ) noexcept
  {
    const std::uint16_t value = *left;
    *left = *right;
    *right = value;
    return left;
  }

  /**
   * Address: 0x0092CDF0 (FUN_0092CDF0)
   * Address: 0x0092CEE0 (FUN_0092CEE0)
   * Address: 0x0092CEF0 (FUN_0092CEF0)
   * Address: 0x0092CF60 (FUN_0092CF60)
   *
   * What it does:
   * Stores one scalar dword lane from argument into destination.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarWordBatchUpsilon(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDword(outValue, value);
  }

  /**
   * Address: 0x0092D150 (FUN_0092D150)
   * Address: 0x0092D9A0 (FUN_0092D9A0)
   * Address: 0x0092DC20 (FUN_0092DC20)
   *
   * What it does:
   * Stores source lane `+0x08` into caller-provided output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane08WordToOutputBatchUpsilon(
    std::uint32_t* const outValue,
    const DwordTripleRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane08);
  }

  /**
   * Address: 0x0092D340 (FUN_0092D340)
   *
   * What it does:
   * Reads one scalar dword lane at offset `+0x0C`.
   */
  [[maybe_unused]] std::uint32_t ReadLane0CWordBatchUpsilon(const DwordQuadRuntimeView* const source) noexcept
  {
    return source->lane0C;
  }

  /**
   * Address: 0x0092D440 (FUN_0092D440)
   *
   * What it does:
   * Copies one dword from `*source->lane04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyFirstIndirectLane04WordBatchUpsilon(
    std::uint32_t* const outValue,
    const DwordPointerLane04RuntimeView* const source
  ) noexcept
  {
    return CopyFirstWordFromIndirectLane04(outValue, source);
  }

  /**
   * Address: 0x0092D4E0 (FUN_0092D4E0)
   *
   * What it does:
   * Pops one head-node address from lane `+0x00` and advances it to `node->next`.
   */
  [[maybe_unused]] std::uint32_t* PopHeadNodeAddressAndAdvanceBatchUpsilon(
    DwordPairRuntimeView* const headSlotOwner,
    std::uint32_t* const outNodeAddress
  ) noexcept
  {
    return PopHeadNodeAddressFromThisSlotBatchTau(&headSlotOwner->lane00, outNodeAddress);
  }

  /**
   * Address: 0x0092D950 (FUN_0092D950)
   *
   * What it does:
   * Initializes one self-relative four-lane header with tail at `this+0x90`.
   */
  [[maybe_unused]] DwordQuadRuntimeView* InitializeSelfRelativeHeaderTail90BatchUpsilon(
    DwordQuadRuntimeView* const outValue
  ) noexcept
  {
    return InitializeSelfRelativeHeaderWithTailOffsetBytes(outValue, 0x90u);
  }

  /**
   * Address: 0x0092DBD0 (FUN_0092DBD0)
   * Address: 0x0092DC00 (FUN_0092DC00)
   * Address: 0x0092DC10 (FUN_0092DC10)
   *
   * What it does:
   * Stores source lane `+0x04` into caller-provided output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane04WordToOutputBatchUpsilon(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source
  ) noexcept
  {
    return StoreWordAtOutput(outValue, source->lane04);
  }

  /**
   * Address: 0x0092DBE0 (FUN_0092DBE0)
   *
   * What it does:
   * Stores one `source->lane00 + index * 12` byte address into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreLane00Stride12AddressByIndexBatchUpsilon(
    std::uint32_t* const outValue,
    const DwordPairRuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return StoreWordAtOutput(
      outValue,
      static_cast<std::uint32_t>(ComputeOffsetAddressByStride(source->lane00, index, 12u))
    );
  }

  struct BytePairRuntimeView
  {
    std::uint8_t lane00; // +0x00
    std::uint8_t lane01; // +0x01
  };
  static_assert(sizeof(BytePairRuntimeView) == 0x02, "BytePairRuntimeView size must be 0x02");
  static_assert(offsetof(BytePairRuntimeView, lane01) == 0x01, "BytePairRuntimeView::lane01 offset must be 0x01");

  struct BytePairAt04RuntimeView
  {
    std::uint32_t lane00; // +0x00
    std::uint8_t lane04;  // +0x04
    std::uint8_t lane05;  // +0x05
  };
  static_assert(offsetof(BytePairAt04RuntimeView, lane04) == 0x04, "BytePairAt04RuntimeView::lane04 offset must be 0x04");
  static_assert(offsetof(BytePairAt04RuntimeView, lane05) == 0x05, "BytePairAt04RuntimeView::lane05 offset must be 0x05");

  struct NestedSpanPointerRuntimeView
  {
    DwordSpanRuntimeView* span; // +0x00
  };
  static_assert(
    offsetof(NestedSpanPointerRuntimeView, span) == 0x00,
    "NestedSpanPointerRuntimeView::span offset must be 0x00"
  );

  using Slot5CPayloadDispatchCall = std::int32_t(__thiscall*)(void* self, void* payload);

  struct CallbackDispatchTableAt5CRuntimeView
  {
    std::byte pad00_5B[0x5C];
    Slot5CPayloadDispatchCall dispatch; // +0x5C
  };
  static_assert(
    offsetof(CallbackDispatchTableAt5CRuntimeView, dispatch) == 0x5C,
    "CallbackDispatchTableAt5CRuntimeView::dispatch offset must be 0x5C"
  );

  struct CallbackDispatchPayloadOwnerRuntimeView
  {
    std::byte pad00_0B[0x0C];
    CallbackDispatchTableAt5CRuntimeView* dispatchTable; // +0x0C
    std::byte payload[1];                                // +0x10
  };
  static_assert(
    offsetof(CallbackDispatchPayloadOwnerRuntimeView, dispatchTable) == 0x0C,
    "CallbackDispatchPayloadOwnerRuntimeView::dispatchTable offset must be 0x0C"
  );
  static_assert(
    offsetof(CallbackDispatchPayloadOwnerRuntimeView, payload) == 0x10,
    "CallbackDispatchPayloadOwnerRuntimeView::payload offset must be 0x10"
  );

  struct WordAt134RuntimeViewBatchPhi
  {
    std::byte pad00_133[0x134];
    std::uint32_t lane134; // +0x134
  };
  static_assert(
    offsetof(WordAt134RuntimeViewBatchPhi, lane134) == 0x134,
    "WordAt134RuntimeViewBatchPhi::lane134 offset must be 0x134"
  );

  struct OwnerPointerAt10RuntimeView
  {
    std::byte pad00_0F[0x10];
    WordAt134RuntimeViewBatchPhi* owner; // +0x10
  };
  static_assert(
    offsetof(OwnerPointerAt10RuntimeView, owner) == 0x10,
    "OwnerPointerAt10RuntimeView::owner offset must be 0x10"
  );

  struct NodeWithOwnerAt10RuntimeView;

  struct BackLinkLaneAt44RuntimeView
  {
    std::byte pad00_43[0x44];
    NodeWithOwnerAt10RuntimeView* backLink; // +0x44
  };
  static_assert(
    offsetof(BackLinkLaneAt44RuntimeView, backLink) == 0x44,
    "BackLinkLaneAt44RuntimeView::backLink offset must be 0x44"
  );

  struct NodeWithOwnerAt10RuntimeView
  {
    std::byte pad00_0F[0x10];
    BackLinkLaneAt44RuntimeView* owner; // +0x10
  };
  static_assert(
    offsetof(NodeWithOwnerAt10RuntimeView, owner) == 0x10,
    "NodeWithOwnerAt10RuntimeView::owner offset must be 0x10"
  );

  struct OwnerAndPreviousBackLinkRuntimeView
  {
    BackLinkLaneAt44RuntimeView* owner;         // +0x00
    NodeWithOwnerAt10RuntimeView* previousLink; // +0x04
  };
  static_assert(
    offsetof(OwnerAndPreviousBackLinkRuntimeView, previousLink) == 0x04,
    "OwnerAndPreviousBackLinkRuntimeView::previousLink offset must be 0x04"
  );

  /**
   * Address: 0x009064A0 (FUN_009064A0)
   * Address: 0x00906BF0 (FUN_00906BF0)
   * Address: 0x00907250 (FUN_00907250)
   * Address: 0x009236C0 (FUN_009236C0)
   * Address: 0x0092BBE0 (FUN_0092BBE0)
   * Address: 0x0092BE90 (FUN_0092BE90)
   * Address: 0x0092BF30 (FUN_0092BF30)
   * Address: 0x0092BF40 (FUN_0092BF40)
   * Address: 0x0092BFB0 (FUN_0092BFB0)
   *
   * What it does:
   * Stores one scalar dword into lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t* StoreScalarDwordLaneBatchPhi(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreScalarDwordLane(outValue, value);
  }

  /**
   * Address: 0x009064D0 (FUN_009064D0)
   *
   * What it does:
   * Resets one intrusive two-link node to singleton self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* InitializeIntrusiveNodeSelfLinksBatchPhi(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    node->next = node;
    node->prev = node;
    return node;
  }

  /**
   * Address: 0x009064E0 (FUN_009064E0)
   *
   * What it does:
   * Unlinks one intrusive node from its ring and restores singleton
   * self-links.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView* UnlinkIntrusiveNodeAndRestoreSelfLinksBatchPhi(
    IntrusiveNodeRuntimeView* const node
  ) noexcept
  {
    return UnlinkIntrusiveNodeAndSelfLink(node);
  }

  /**
   * Address: 0x00906500 (FUN_00906500)
   *
   * What it does:
   * Stores one intrusive node `next` pointer into caller-provided output.
   */
  [[maybe_unused]] IntrusiveNodeRuntimeView** StoreIntrusiveNextPointerIntoOutputBatchPhi(
    const IntrusiveNodeRuntimeView* const node,
    IntrusiveNodeRuntimeView** const outValue
  ) noexcept
  {
    *outValue = node->next;
    return outValue;
  }

  /**
   * Address: 0x00907000 (FUN_00907000)
   *
   * What it does:
   * Initializes one `{dword, byte}` lane pair from scalar inputs.
   */
  [[maybe_unused]] DwordBytePairLane* InitializeDwordBytePairLaneBatchPhi(
    DwordBytePairLane* const outValue,
    const std::uint32_t lane00,
    const std::uint8_t lane04
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane04 = lane04;
    return outValue;
  }

  /**
   * Address: 0x00907260 (FUN_00907260)
   *
   * What it does:
   * Returns one byte pointer lane at `this + 0x24`.
   */
  [[maybe_unused]] std::byte* ResolveOffset24PointerBatchPhi(void* const self) noexcept
  {
    return static_cast<std::byte*>(self) + 0x24;
  }

  /**
   * Address: 0x00907340 (FUN_00907340)
   *
   * What it does:
   * Returns whether lane `+0x0C` equals `6`.
   */
  [[maybe_unused]] bool IsLane0CEqualSixBatchPhi(
    const HeaderAndThreeWordLanesRuntimeView* const source
  ) noexcept
  {
    return source->lane0C == 6u;
  }

  /**
   * Address: 0x00907470 (FUN_00907470)
   *
   * What it does:
   * Returns one signed `((spanEnd - spanCursor) >> 3)` element count from a
   * nested span pointer.
   */
  [[maybe_unused]] std::int32_t ComputeNestedStride8SpanCountBatchPhi(
    const NestedSpanPointerRuntimeView* const source
  ) noexcept
  {
    return static_cast<std::int32_t>(source->span->end - source->span->cursor) >> 3;
  }

  /**
   * Address: 0x0090A4C0 (FUN_0090A4C0)
   *
   * What it does:
   * Returns one byte pointer lane at `this + 0x2C`.
   */
  [[maybe_unused]] std::byte* ResolveOffset2CPointerBatchPhi(void* const self) noexcept
  {
    return static_cast<std::byte*>(self) + 0x2C;
  }

  /**
   * Address: 0x00915B10 (FUN_00915B10)
   *
   * What it does:
   * Dispatches through table callback lane `+0x5C` with payload pointer
   * `this + 0x10`.
   */
  [[maybe_unused]] std::int32_t InvokeCallbackSlot5CWithInlinePayloadBatchPhi(
    CallbackDispatchPayloadOwnerRuntimeView* const owner
  ) noexcept
  {
    return owner->dispatchTable->dispatch(owner->dispatchTable, owner->payload);
  }

  /**
   * Address: 0x00915EB0 (FUN_00915EB0)
   *
   * What it does:
   * Resets one `{dword, byte}` lane pair to `{0, 1}`.
   */
  [[maybe_unused]] DwordBytePairLane* ResetDwordBytePairToDefaultBatchPhi(
    DwordBytePairLane* const outValue
  ) noexcept
  {
    outValue->lane00 = 0u;
    outValue->lane04 = 1u;
    return outValue;
  }

  /**
   * Address: 0x00924030 (FUN_00924030)
   *
   * What it does:
   * Stores one scalar dword into nested owner lane `+0x134`.
   */
  [[maybe_unused]] OwnerPointerAt10RuntimeView* StoreNestedWordAt134BatchPhi(
    OwnerPointerAt10RuntimeView* const owner,
    const std::uint32_t value
  ) noexcept
  {
    owner->owner->lane134 = value;
    return owner;
  }

  /**
   * Address: 0x00929BC0 (FUN_00929BC0)
   *
   * What it does:
   * Captures owner/back-link lanes from `source + 0x10` and installs `source`
   * as the new owner back-link.
   */
  [[maybe_unused]] OwnerAndPreviousBackLinkRuntimeView* CaptureOwnerAndInstallBackLinkBatchPhi(
    OwnerAndPreviousBackLinkRuntimeView* const outValue,
    NodeWithOwnerAt10RuntimeView* const source
  ) noexcept
  {
    BackLinkLaneAt44RuntimeView* const owner = source->owner;
    outValue->owner = owner;
    outValue->previousLink = owner->backLink;
    owner->backLink = source;
    return outValue;
  }

  /**
   * Address: 0x0092BB30 (FUN_0092BB30)
   *
   * What it does:
   * Initializes one two-byte lane pair from scalar inputs.
   */
  [[maybe_unused]] BytePairRuntimeView* InitializeBytePairLaneBatchPhi(
    BytePairRuntimeView* const outValue,
    const std::uint8_t lane00,
    const std::uint8_t lane01
  ) noexcept
  {
    outValue->lane00 = lane00;
    outValue->lane01 = lane01;
    return outValue;
  }

  /**
   * Address: 0x0092BB50 (FUN_0092BB50)
   *
   * What it does:
   * Writes `0xFF` into the first byte lane.
   */
  [[maybe_unused]] BytePairRuntimeView* SetFirstByteToFFBatchPhi(
    BytePairRuntimeView* const outValue
  ) noexcept
  {
    outValue->lane00 = 0xFFu;
    return outValue;
  }

  /**
   * Address: 0x0092BBC0 (FUN_0092BBC0)
   *
   * What it does:
   * Copies source bytes at lanes `+0x04/+0x05` into a two-byte output pair.
   */
  [[maybe_unused]] BytePairRuntimeView* CopyBytePairFromOffset04SourceBatchPhi(
    BytePairRuntimeView* const outValue,
    const BytePairAt04RuntimeView* const source
  ) noexcept
  {
    outValue->lane00 = source->lane04;
    outValue->lane01 = source->lane05;
    return outValue;
  }

  /**
   * Address: 0x0092BC60 (FUN_0092BC60)
   *
   * What it does:
   * Computes one `base + index * 2` byte address from lane `+0x00`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride2AddressFromLane00BatchPhi(
    const std::uint32_t* const baseWord,
    const std::int32_t index
  ) noexcept
  {
    return *baseWord + static_cast<std::uint32_t>(index * 2);
  }

  /**
   * Address: 0x0092BCC0 (FUN_0092BCC0)
   *
   * What it does:
   * Initializes one span header as `{origin=base, begin=base, end=base+2*count, cursor=base}`.
   */
  [[maybe_unused]] DwordSpanRuntimeView* InitializeStride2SpanHeaderBatchPhi(
    DwordSpanRuntimeView* const outValue,
    const std::uint32_t base,
    const std::int32_t count
  ) noexcept
  {
    outValue->origin = base;
    outValue->begin = base;
    outValue->end = base + static_cast<std::uint32_t>(count * 2);
    outValue->cursor = base;
    return outValue;
  }

  /**
   * Address: 0x0092BDE0 (FUN_0092BDE0)
   *
   * What it does:
   * Copies one first-byte lane from source to destination.
   */
  [[maybe_unused]] BytePairRuntimeView* CopyFirstByteLaneBatchPhi(
    BytePairRuntimeView* const destination,
    const BytePairRuntimeView* const source
  ) noexcept
  {
    destination->lane00 = source->lane00;
    return destination;
  }

  /**
   * Address: 0x0092C240 (FUN_0092C240)
   *
   * What it does:
   * Computes one `begin + index * 12` byte address from lane `+0x04`.
   */
  [[maybe_unused]] std::uint32_t ComputeStride12AddressFromBeginLaneBatchPhi(
    const DwordSpanRuntimeView* const source,
    const std::int32_t index
  ) noexcept
  {
    return source->begin + static_cast<std::uint32_t>(index * 12);
  }

  /**
   * Address: 0x0092C270 (FUN_0092C270)
   *
   * What it does:
   * Stores span `begin` lane (`+0x04`) into caller output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreSpanBeginLaneToOutputBatchPhi(
    const DwordSpanRuntimeView* const source,
    std::uint32_t* const outValue
  ) noexcept
  {
    *outValue = source->begin;
    return outValue;
  }
} // namespace


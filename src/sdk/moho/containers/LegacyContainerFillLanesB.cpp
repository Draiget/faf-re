#include <cstddef>
#include <cstdint>
#include <cstring>

namespace
{
  [[nodiscard]] std::uint32_t* FillDwordRangeByEnd(
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

  [[nodiscard]] std::uint32_t* CopyDwordRangeForward(
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destination
  ) noexcept
  {
    const std::uint32_t* source = sourceBegin;
    std::uint32_t* write = destination;
    while (source != sourceEnd) {
      *write = *source;
      ++source;
      ++write;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* FillDwordPairRangeByEnd(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* const pairValue
  ) noexcept
  {
    std::uint32_t* write = begin;
    while (write != end) {
      write[0] = pairValue[0];
      write[1] = pairValue[1];
      write += 2;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* FillDwordTripleRangeByEnd(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* const tripleValue
  ) noexcept
  {
    std::uint32_t* write = begin;
    while (write != end) {
      write[0] = tripleValue[0];
      write[1] = tripleValue[1];
      write[2] = tripleValue[2];
      write += 3;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* CopyDwordPairRangeForward(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    const std::uint32_t* source = sourceBegin;
    std::uint32_t* write = destination;
    while (source != sourceEnd) {
      write[0] = source[0];
      write[1] = source[1];
      write += 2;
      source += 2;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* CopyDwordTripleRangeForward(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    const std::uint32_t* source = sourceBegin;
    std::uint32_t* write = destination;
    while (source != sourceEnd) {
      write[0] = source[0];
      write[1] = source[1];
      write[2] = source[2];
      write += 3;
      source += 3;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* FillCountedDwordSpan(
    std::uint32_t* destination,
    std::uint32_t count,
    const std::uint32_t* const valueSlot
  ) noexcept
  {
    std::uint32_t* write = destination;
    while (count != 0u) {
      *write = *valueSlot;
      ++write;
      --count;
    }
    return write;
  }

  [[nodiscard]] std::uint32_t* CopyDwordRangeWithMemmove(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
    const std::size_t byteCount = dwordCount * sizeof(std::uint32_t);
    if (dwordCount != 0u) {
      (void)memmove_s(destination, byteCount, sourceBegin, byteCount);
    }
    return destination + dwordCount;
  }

  struct DwordVectorRuntimeView
  {
    void* proxy;             // +0x00
    std::uint32_t* first;    // +0x04
    std::uint32_t* last;     // +0x08
    std::uint32_t* capacity; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(offsetof(DwordVectorRuntimeView, first) == 0x04, "DwordVectorRuntimeView::first offset must be 0x04");
  static_assert(offsetof(DwordVectorRuntimeView, last) == 0x08, "DwordVectorRuntimeView::last offset must be 0x08");
  static_assert(offsetof(DwordVectorRuntimeView, capacity) == 0x0C, "DwordVectorRuntimeView::capacity offset must be 0x0C");
  static_assert(sizeof(DwordVectorRuntimeView) == 0x10, "DwordVectorRuntimeView size must be 0x10");
#endif

  struct LinkNodeRuntimeView
  {
    std::byte pad00_0F[0x10];
    LinkNodeRuntimeView* next; // +0x10
  };
#if defined(_M_IX86)
  static_assert(offsetof(LinkNodeRuntimeView, next) == 0x10, "LinkNodeRuntimeView::next offset must be 0x10");
#endif

  struct LinkCountOwnerRuntimeView
  {
    std::uint32_t pad00_03[4];
    LinkNodeRuntimeView* head;   // +0x10
    std::uint32_t activeMarker;  // +0x14
  };
#if defined(_M_IX86)
  static_assert(offsetof(LinkCountOwnerRuntimeView, head) == 0x10, "LinkCountOwnerRuntimeView::head offset must be 0x10");
  static_assert(
    offsetof(LinkCountOwnerRuntimeView, activeMarker) == 0x14,
    "LinkCountOwnerRuntimeView::activeMarker offset must be 0x14"
  );
#endif

  struct ValueIndexAccessorRuntimeView
  {
    std::uint32_t pad00_217[0x218 / 4];
    std::int32_t valueAt218; // +0x218
    std::int32_t valueAt21C; // +0x21C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(ValueIndexAccessorRuntimeView, valueAt218) == 0x218,
    "ValueIndexAccessorRuntimeView::valueAt218 offset must be 0x218"
  );
  static_assert(
    offsetof(ValueIndexAccessorRuntimeView, valueAt21C) == 0x21C,
    "ValueIndexAccessorRuntimeView::valueAt21C offset must be 0x21C"
  );
#endif

  struct NestedValueOwnerRuntimeView
  {
    std::byte pad00_19B[0x19C];
    std::int32_t value; // +0x19C
  };
#if defined(_M_IX86)
  static_assert(offsetof(NestedValueOwnerRuntimeView, value) == 0x19C, "NestedValueOwnerRuntimeView::value offset must be 0x19C");
#endif

  struct ParentWithNestedOwnerRuntimeView
  {
    std::byte pad00_133[0x134];
    NestedValueOwnerRuntimeView* nested; // +0x134
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(ParentWithNestedOwnerRuntimeView, nested) == 0x134,
    "ParentWithNestedOwnerRuntimeView::nested offset must be 0x134"
  );
#endif

  struct SetterAtOffset28RuntimeView
  {
    std::byte pad00_27[0x28];
    std::int32_t value; // +0x28
  };

  struct SetterAtOffset84RuntimeView
  {
    std::byte pad00_83[0x84];
    std::int32_t value; // +0x84
  };

  struct FlagSetterAtOffset88RuntimeView
  {
    std::byte pad00_87[0x88];
    std::uint8_t flag; // +0x88
  };

  struct SetterAtOffset0CRuntimeView
  {
    std::byte pad00_0B[0x0C];
    std::int32_t value; // +0x0C
  };

  struct SetterAtOffset10RuntimeView
  {
    std::byte pad00_0F[0x10];
    std::int32_t value; // +0x10
  };

  struct SetterAtOffset7CRuntimeView
  {
    std::byte pad00_7B[0x7C];
    std::int32_t value; // +0x7C
  };

  struct NestedValueAtOffset08RuntimeView
  {
    std::byte pad00_07[0x08];
    std::int32_t value; // +0x08
  };

  struct PointerAtOffset04RuntimeView
  {
    void* vtable;                                   // +0x00
    NestedValueAtOffset08RuntimeView* nested;       // +0x04
  };

  struct ValueAtOffset24RuntimeView
  {
    std::byte pad00_23[0x24];
    std::uint32_t value; // +0x24
  };

#if defined(_M_IX86)
  static_assert(offsetof(SetterAtOffset28RuntimeView, value) == 0x28, "SetterAtOffset28RuntimeView::value offset must be 0x28");
  static_assert(offsetof(SetterAtOffset84RuntimeView, value) == 0x84, "SetterAtOffset84RuntimeView::value offset must be 0x84");
  static_assert(
    offsetof(FlagSetterAtOffset88RuntimeView, flag) == 0x88,
    "FlagSetterAtOffset88RuntimeView::flag offset must be 0x88"
  );
  static_assert(offsetof(SetterAtOffset0CRuntimeView, value) == 0x0C, "SetterAtOffset0CRuntimeView::value offset must be 0x0C");
  static_assert(offsetof(SetterAtOffset10RuntimeView, value) == 0x10, "SetterAtOffset10RuntimeView::value offset must be 0x10");
  static_assert(offsetof(SetterAtOffset7CRuntimeView, value) == 0x7C, "SetterAtOffset7CRuntimeView::value offset must be 0x7C");
  static_assert(
    offsetof(NestedValueAtOffset08RuntimeView, value) == 0x08,
    "NestedValueAtOffset08RuntimeView::value offset must be 0x08"
  );
  static_assert(
    offsetof(PointerAtOffset04RuntimeView, nested) == 0x04,
    "PointerAtOffset04RuntimeView::nested offset must be 0x04"
  );
  static_assert(offsetof(ValueAtOffset24RuntimeView, value) == 0x24, "ValueAtOffset24RuntimeView::value offset must be 0x24");
#endif

  using VirtualInitCall = void(__thiscall*)(void* self, std::int32_t arg0, std::int32_t arg1);

  struct InitAndStoreRuntimeView
  {
    void** vtable; // +0x00
    std::uint32_t pad04_1B[6];
    std::int32_t lane1C; // +0x1C
    std::int32_t lane20; // +0x20
  };
#if defined(_M_IX86)
  static_assert(offsetof(InitAndStoreRuntimeView, lane1C) == 0x1C, "InitAndStoreRuntimeView::lane1C offset must be 0x1C");
  static_assert(offsetof(InitAndStoreRuntimeView, lane20) == 0x20, "InitAndStoreRuntimeView::lane20 offset must be 0x20");
#endif

  struct DualSelectionRuntimeView
  {
    std::byte pad00_3B[0x3C];
    std::int32_t valueForSelector4; // +0x3C
    std::int32_t valueForOther;     // +0x40
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(DualSelectionRuntimeView, valueForSelector4) == 0x3C,
    "DualSelectionRuntimeView::valueForSelector4 offset must be 0x3C"
  );
  static_assert(
    offsetof(DualSelectionRuntimeView, valueForOther) == 0x40,
    "DualSelectionRuntimeView::valueForOther offset must be 0x40"
  );
#endif

  struct IndexedLookupOwnerRuntimeView
  {
    std::byte pad00_12B[0x12C];
    std::int32_t* lookupTable; // +0x12C
  };
#if defined(_M_IX86)
  static_assert(
    offsetof(IndexedLookupOwnerRuntimeView, lookupTable) == 0x12C,
    "IndexedLookupOwnerRuntimeView::lookupTable offset must be 0x12C"
  );
#endif

  struct PointerLaneRuntimeView
  {
    void* vtable;       // +0x00
    std::uintptr_t ptr; // +0x04
  };
#if defined(_M_IX86)
  static_assert(offsetof(PointerLaneRuntimeView, ptr) == 0x04, "PointerLaneRuntimeView::ptr offset must be 0x04");
#endif

  struct ValueAtPlus0CRuntimeView
  {
    std::byte pad00_0B[0x0C];
    std::int32_t value; // +0x0C
  };
#if defined(_M_IX86)
  static_assert(offsetof(ValueAtPlus0CRuntimeView, value) == 0x0C, "ValueAtPlus0CRuntimeView::value offset must be 0x0C");
#endif

  /**
   * Address: 0x008F9A50 (FUN_008F9A50)
   *
   * What it does:
   * Fills one `[begin,end)` dword range from one repeated source value lane.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeByEndLaneD(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordRangeByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x0092D130 (FUN_0092D130)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeByEndLaneE(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordRangeByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x00932490 (FUN_00932490)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeByEndLaneF(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordRangeByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x009324E0 (FUN_009324E0)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeByEndLaneG(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordRangeByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x00936050 (FUN_00936050)
   *
   * What it does:
   * Alias lane of `[begin,end)` repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeByEndLaneH(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillDwordRangeByEnd(begin, end, valueSlot);
  }

  /**
   * Address: 0x008D7DC0 (FUN_008D7DC0)
   *
   * What it does:
   * Copies one source dword range into destination and returns destination end.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForwardLaneA(
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destination
  ) noexcept
  {
    return CopyDwordRangeForward(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x008D7E20 (FUN_008D7E20)
   *
   * What it does:
   * Alias lane of forward dword range copy behavior.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForwardLaneB(
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destination
  ) noexcept
  {
    return CopyDwordRangeForward(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00935BD0 (FUN_00935BD0)
   *
   * What it does:
   * Copies one dword range `[sourceBegin,sourceEnd)` with overlap-safe memmove
   * semantics and returns the one-past-end destination cursor.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeWithMemmoveLaneA(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeWithMemmove(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00936000 (FUN_00936000)
   *
   * What it does:
   * Alias lane of overlap-safe dword range copy behavior.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeWithMemmoveLaneB(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeWithMemmove(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x00936610 (FUN_00936610)
   *
   * What it does:
   * Erases one dword at `eraseAt` from a vector lane by shifting trailing data
   * left with overlap-safe memmove and returns the iterator out-slot.
   */
  [[maybe_unused]] std::uint32_t** EraseDwordAtCursorAndReturnSlot(
    DwordVectorRuntimeView* const vector,
    std::uint32_t** const outIteratorSlot,
    std::uint32_t* const eraseAt
  ) noexcept
  {
    const std::ptrdiff_t trailingCount = vector->last - (eraseAt + 1);
    if (trailingCount > 0) {
      const std::size_t trailingBytes = static_cast<std::size_t>(trailingCount) * sizeof(std::uint32_t);
      (void)memmove_s(eraseAt, trailingBytes, eraseAt + 1, trailingBytes);
    }

    vector->last -= 1;
    *outIteratorSlot = eraseAt;
    return outIteratorSlot;
  }

  /**
   * Address: 0x0094FE90 (FUN_0094FE90)
   *
   * What it does:
   * Fills one dword-pair range `[begin,end)` from one repeated pair value.
   */
  [[maybe_unused]] std::uint32_t* FillDwordPairRangeLaneA(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* pairValue
  ) noexcept
  {
    return FillDwordPairRangeByEnd(begin, end, pairValue);
  }

  /**
   * Address: 0x008E9230 (FUN_008E9230)
   *
   * What it does:
   * Fills one dword-triple range `[begin,end)` from one repeated triple value.
   */
  [[maybe_unused]] std::uint32_t* FillDwordTripleRangeLaneA(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* tripleValue
  ) noexcept
  {
    return FillDwordTripleRangeByEnd(begin, end, tripleValue);
  }

  /**
   * Address: 0x0092D0A0 (FUN_0092D0A0)
   *
   * What it does:
   * Alias lane of dword-triple fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordTripleRangeLaneB(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* tripleValue
  ) noexcept
  {
    return FillDwordTripleRangeByEnd(begin, end, tripleValue);
  }

  /**
   * Address: 0x0092D580 (FUN_0092D580)
   *
   * What it does:
   * Alias lane of dword-triple fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordTripleRangeLaneC(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* tripleValue
  ) noexcept
  {
    return FillDwordTripleRangeByEnd(begin, end, tripleValue);
  }

  /**
   * Address: 0x008D9D10 (FUN_008D9D10)
   *
   * What it does:
   * Alias lane of dword-pair fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordPairRangeLaneB(
    std::uint32_t* begin,
    std::uint32_t* end,
    const std::uint32_t* pairValue
  ) noexcept
  {
    return FillDwordPairRangeByEnd(begin, end, pairValue);
  }

  /**
   * Address: 0x00754830 (FUN_00754830)
   *
   * What it does:
   * Copies one source dword-pair range into destination pair storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordPairRangeLaneA(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    return CopyDwordPairRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x007547A0 (FUN_007547A0)
   *
   * What it does:
   * Copies one source dword-triple range into destination triple storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordTripleRangeLaneA(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    return CopyDwordTripleRangeForward(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x008DB390 (FUN_008DB390)
   *
   * What it does:
   * Writes one repeated dword value into `count` contiguous destination lanes.
   */
  [[maybe_unused]] std::uint32_t* FillDwordCountedLaneY(
    std::uint32_t* destination,
    const std::uint32_t count,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillCountedDwordSpan(destination, count, valueSlot);
  }

  /**
   * Address: 0x008FA970 (FUN_008FA970)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordCountedLaneZ(
    std::uint32_t* destination,
    const std::uint32_t count,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillCountedDwordSpan(destination, count, valueSlot);
  }

  /**
   * Address: 0x00936B00 (FUN_00936B00)
   *
   * What it does:
   * Alias lane of counted repeated-dword fill behavior.
   */
  [[maybe_unused]] std::uint32_t* FillDwordCountedLaneAA(
    std::uint32_t* destination,
    const std::uint32_t count,
    const std::uint32_t* valueSlot
  ) noexcept
  {
    return FillCountedDwordSpan(destination, count, valueSlot);
  }

  /**
   * Address: 0x00978210 (FUN_00978210)
   *
   * What it does:
   * Returns linked-node count when the owner activation marker is set.
   * Returns `-1` when the activation marker is clear.
   */
  [[maybe_unused]] std::int32_t CountLinkedNodesIfActive(const LinkCountOwnerRuntimeView* const owner) noexcept
  {
    if (owner->activeMarker == 0u) {
      return -1;
    }

    std::int32_t count = 0;
    for (LinkNodeRuntimeView* node = owner->head; node != nullptr; node = node->next) {
      ++count;
    }
    return count;
  }

  /**
   * Address: 0x00982530 (FUN_00982530)
   *
   * What it does:
   * Returns one cached dword value from offset `+0x21C`.
   */
  [[maybe_unused]] std::int32_t GetValueAtOffset21C(const ValueIndexAccessorRuntimeView* const runtime) noexcept
  {
    return runtime->valueAt21C;
  }

  /**
   * Address: 0x00982540 (FUN_00982540)
   *
   * What it does:
   * Returns one cached dword value from offset `+0x218`.
   */
  [[maybe_unused]] std::int32_t GetValueAtOffset218(const ValueIndexAccessorRuntimeView* const runtime) noexcept
  {
    return runtime->valueAt218;
  }

  /**
   * Address: 0x00983000 (FUN_00983000)
   *
   * What it does:
   * Returns one nested owner dword from `*(this+0x134)+0x19C`.
   */
  [[maybe_unused]] std::int32_t GetNestedValueAtOffset134_19C(const ParentWithNestedOwnerRuntimeView* const runtime) noexcept
  {
    return runtime->nested->value;
  }

  /**
   * Address: 0x009A0990 (FUN_009A0990)
   *
   * What it does:
   * Stores one caller dword at offset `+0x28` and returns that value.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset28(SetterAtOffset28RuntimeView* const runtime, const std::int32_t value) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x009A5E00 (FUN_009A5E00)
   *
   * What it does:
   * Writes constant `1` to one byte lane at offset `+0x88`.
   */
  [[maybe_unused]] void SetFlagAtOffset88True(FlagSetterAtOffset88RuntimeView* const runtime) noexcept
  {
    runtime->flag = 1u;
  }

  /**
   * Address: 0x009A5E10 (FUN_009A5E10)
   *
   * What it does:
   * Stores one caller dword at offset `+0x84` and returns that value.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset84LaneA(
    SetterAtOffset84RuntimeView* const runtime,
    const std::int32_t value
  ) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x009A5E20 (FUN_009A5E20)
   *
   * What it does:
   * Alias lane of offset `+0x84` dword store/return behavior.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset84LaneB(
    SetterAtOffset84RuntimeView* const runtime,
    const std::int32_t value
  ) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x009D31A0 (FUN_009D31A0)
   *
   * What it does:
   * Stores one caller dword at offset `+0x0C` and returns that value.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset0C(
    SetterAtOffset0CRuntimeView* const runtime,
    const std::int32_t value
  ) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x00A2E470 (FUN_00A2E470)
   *
   * What it does:
   * Stores one caller dword at offset `+0x10` and returns that value.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset10(
    SetterAtOffset10RuntimeView* const runtime,
    const std::int32_t value
  ) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x009C9BD0 (FUN_009C9BD0)
   *
   * What it does:
   * Stores one caller dword at offset `+0x7C` and returns that value.
   */
  [[maybe_unused]] std::int32_t SetValueAtOffset7C(
    SetterAtOffset7CRuntimeView* const runtime,
    const std::int32_t value
  ) noexcept
  {
    runtime->value = value;
    return value;
  }

  /**
   * Address: 0x0097C240 (FUN_0097C240)
   *
   * What it does:
   * Returns nested dword lane at `*(this+0x04)+0x08`; returns `0` when
   * nested pointer lane is null.
   */
  [[maybe_unused]] std::int32_t GetNestedValueAtOffset04Then08OrZero(
    const PointerAtOffset04RuntimeView* const runtime
  ) noexcept
  {
    const auto* const nested = runtime->nested;
    return nested != nullptr ? nested->value : 0;
  }

  /**
   * Address: 0x00981F80 (FUN_00981F80)
   *
   * What it does:
   * Writes one out-dword from `(*sourceOwnerSlot)+0x24` when owner is present;
   * otherwise writes `0`, then returns out slot.
   */
  [[maybe_unused]] std::uint32_t* StoreOwnerValueAtOffset24OrZero(
    std::uint32_t* const outValue,
    const ValueAtOffset24RuntimeView* const* const sourceOwnerSlot
  ) noexcept
  {
    const ValueAtOffset24RuntimeView* const owner = *sourceOwnerSlot;
    outValue[0] = owner != nullptr ? owner->value : 0u;
    return outValue;
  }

  /**
   * Address: 0x00981270 (FUN_00981270)
   *
   * What it does:
   * Calls virtual init slot `vtable[4]` with `(arg0,1)`, stores two lane values,
   * and returns the first stored value.
   */
  [[maybe_unused]] std::int32_t InitAndStoreLaneValues(
    InitAndStoreRuntimeView* const runtime,
    const std::int32_t arg0,
    const std::int32_t valueA,
    const std::int32_t valueB
  ) noexcept
  {
    const auto init = reinterpret_cast<VirtualInitCall>(runtime->vtable[4]);
    init(runtime, arg0, 1);
    runtime->lane1C = valueA;
    runtime->lane20 = valueB;
    return valueA;
  }

  /**
   * Address: 0x009F1080 (FUN_009F1080)
   *
   * What it does:
   * Returns one of two cached values based on selector (`4` vs non-`4`).
   */
  [[maybe_unused]] std::int32_t SelectDualCachedValue(
    const DualSelectionRuntimeView* const runtime,
    const std::int32_t selector
  ) noexcept
  {
    return (selector == 4) ? runtime->valueForSelector4 : runtime->valueForOther;
  }

  /**
   * Address: 0x009F10A0 (FUN_009F10A0)
   *
   * What it does:
   * Writes one dual-cache lane selected by `selector` (`4` vs non-`4`) and
   * returns the stored value.
   */
  [[maybe_unused]] std::int32_t SetDualCachedValue(
    DualSelectionRuntimeView* const runtime,
    const std::int32_t selector,
    const std::int32_t value
  ) noexcept
  {
    if (selector == 4) {
      runtime->valueForSelector4 = value;
      return value;
    }

    runtime->valueForOther = value;
    return value;
  }

  /**
   * Address: 0x009CF620 (FUN_009CF620)
   *
   * What it does:
   * Returns indexed lookup-table entry when table pointer is present.
   * Returns `0` when table pointer is null.
   */
  [[maybe_unused]] std::int32_t LookupIndexedValueOrZero(
    const IndexedLookupOwnerRuntimeView* const runtime,
    const std::int32_t index
  ) noexcept
  {
    if (runtime->lookupTable == nullptr) {
      return 0;
    }
    return runtime->lookupTable[index];
  }

  /**
   * Address: 0x009D2A90 (FUN_009D2A90)
   *
   * What it does:
   * Returns base pointer lane at `+0x04`, offset by `+12` when non-null.
   */
  [[maybe_unused]] std::uintptr_t GetPointerPlus12WhenPresent(const PointerLaneRuntimeView* const runtime) noexcept
  {
    const std::uintptr_t value = runtime->ptr;
    return (value != 0u) ? (value + 12u) : value;
  }

  /**
   * Address: 0x009E25FD (FUN_009E25FD)
   *
   * What it does:
   * Returns `*(a2+0x0C)` only when both input pointers are non-null; otherwise `0`.
   */
  [[maybe_unused]] std::int32_t GetSecondaryValueAtOffset0CIfBothPresent(
    const void* const first,
    const ValueAtPlus0CRuntimeView* const second
  ) noexcept
  {
    if (first == nullptr || second == nullptr) {
      return 0;
    }
    return second->value;
  }
} // namespace

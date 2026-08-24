#include "EntityDb.h"

#include <cstdlib>
#include <initializer_list>
#include <list>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "Entity.h"
#include "legacy/containers/Tree.h"
#include "moho/containers/BVIntSet.h"
#include "moho/entity/Prop.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  struct CEntityDbBoundedPropQueueNode
  {
    std::uint8_t mUnknown0000_0007[0x08]{};        // +0x00
    CEntityDbBoundedPropQueueNode** mLinkBackRef;   // +0x08
    CEntityDbBoundedPropQueueNode* mLinkNext;       // +0x0C
    std::uint32_t mUnknown0010;                     // +0x10
  };
  static_assert(
    sizeof(CEntityDbBoundedPropQueueNode) == 0x14, "CEntityDbBoundedPropQueueNode size must be 0x14"
  );
} // namespace moho

namespace
{
  // Packed EntId layout used by family/source allocation:
  // [31..28]=family, [27..20]=source index, [19..0]=serial.
  constexpr moho::EEntityIdBitMask kEntityIdFamilySourceMask =
    moho::EEntityIdBitMask::Family | moho::EEntityIdBitMask::Source;
  constexpr std::uint32_t kEntityIdFamilySourceMaskRaw = moho::ToMask(kEntityIdFamilySourceMask);
  constexpr std::uint32_t kEntityIdSerialMask = moho::ToMask(moho::EEntityIdBitMask::Serial);
  constexpr std::uint32_t kEntityIdSourceShift = moho::kEntityIdSourceShift;
  constexpr std::uint32_t kAllUnitsUnitTypeBoundaryKey = moho::ToRaw(moho::EEntityIdSentinel::FirstNonUnitFamily);
  constexpr std::uint32_t kAllUnitsHighFamilyBoundaryKey = 0x20000000u;
  constexpr std::uint32_t kAllUnitsMidFamilyBoundaryKey = 0x30000000u;
  constexpr std::uint32_t kAllUnitsShieldFamilyBoundaryKey = 0x40000000u;
  constexpr std::uint32_t kAllUnitsOtherFamilyBoundaryKey = 0x50000000u;
  constexpr std::uint32_t kAllUnitsLateFamilyBoundaryKey = 0x60000000u;
  constexpr std::uint32_t kEntityIdFamilyNibbleMask = 0xF0000000u;

  struct EntityIdWordLaneView
  {
    std::uint32_t value;
  };
  static_assert(sizeof(EntityIdWordLaneView) == 0x04, "EntityIdWordLaneView size must be 0x04");

  struct EntityIdPairWordLaneView
  {
    std::uint32_t high;
    std::uint32_t low;
  };
  static_assert(sizeof(EntityIdPairWordLaneView) == 0x08, "EntityIdPairWordLaneView size must be 0x08");

  struct DwordQuadLaneView
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::uint32_t lane8;
    std::uint32_t laneC;
  };
  static_assert(sizeof(DwordQuadLaneView) == 0x10, "DwordQuadLaneView size must be 0x10");

  struct PointerBaseLaneView
  {
    std::uint32_t base;
  };
  static_assert(sizeof(PointerBaseLaneView) == 0x04, "PointerBaseLaneView size must be 0x04");

  struct ListHeadProxyLaneView
  {
    std::uint32_t proxy;
    moho::CEntityDbListHead* head;
  };
  static_assert(offsetof(ListHeadProxyLaneView, head) == 0x04, "ListHeadProxyLaneView::head offset must be 0x04");
  static_assert(sizeof(ListHeadProxyLaneView) == 0x08, "ListHeadProxyLaneView size must be 0x08");

  struct QueueNodeRangeLaneView
  {
    std::uint32_t proxy;
    moho::CEntityDbBoundedPropQueueNode* begin;
    moho::CEntityDbBoundedPropQueueNode* end;
  };
  static_assert(offsetof(QueueNodeRangeLaneView, begin) == 0x04, "QueueNodeRangeLaneView::begin offset must be 0x04");
  static_assert(offsetof(QueueNodeRangeLaneView, end) == 0x08, "QueueNodeRangeLaneView::end offset must be 0x08");
  static_assert(sizeof(QueueNodeRangeLaneView) == 0x0C, "QueueNodeRangeLaneView size must be 0x0C");

  struct Offset8WordLaneView
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    std::uint32_t lane8;
  };
  static_assert(sizeof(Offset8WordLaneView) == 0x0C, "Offset8WordLaneView size must be 0x0C");

  struct EntityDbWindowLaneView
  {
    std::uint8_t pad000_27B[0x27C];
    std::uint32_t windowBegin; // +0x27C
    std::uint32_t windowEnd;   // +0x280
    std::uint32_t windowCursor; // +0x284
  };
  static_assert(offsetof(EntityDbWindowLaneView, windowBegin) == 0x27C, "EntityDbWindowLaneView::windowBegin offset must be 0x27C");
  static_assert(offsetof(EntityDbWindowLaneView, windowEnd) == 0x280, "EntityDbWindowLaneView::windowEnd offset must be 0x280");
  static_assert(offsetof(EntityDbWindowLaneView, windowCursor) == 0x284, "EntityDbWindowLaneView::windowCursor offset must be 0x284");

  struct WindowPairLaneView
  {
    std::uint32_t first;
    std::uint32_t second;
  };
  static_assert(sizeof(WindowPairLaneView) == 0x08, "WindowPairLaneView size must be 0x08");

  struct DualWordLaneView
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
  };
  static_assert(sizeof(DualWordLaneView) == 0x08, "DualWordLaneView size must be 0x08");

  struct WordAndByteLaneView
  {
    std::uint32_t lane0;
    std::uint8_t lane4;
  };
  static_assert(offsetof(WordAndByteLaneView, lane4) == 0x04, "WordAndByteLaneView::lane4 offset must be 0x04");

  struct ForwardLinkNodeRuntime
  {
    ForwardLinkNodeRuntime* next;
  };
  static_assert(sizeof(ForwardLinkNodeRuntime) == 0x04, "ForwardLinkNodeRuntime size must be 0x04");

  struct BackLinkNodeRuntime
  {
    BackLinkNodeRuntime** backRef;
    BackLinkNodeRuntime* next;
  };
  static_assert(sizeof(BackLinkNodeRuntime) == 0x08, "BackLinkNodeRuntime size must be 0x08");
  static_assert(offsetof(BackLinkNodeRuntime, backRef) == 0x00, "BackLinkNodeRuntime::backRef offset must be 0x00");
  static_assert(offsetof(BackLinkNodeRuntime, next) == 0x04, "BackLinkNodeRuntime::next offset must be 0x04");

  struct BackLinkOwnerLaneView
  {
    std::uint32_t proxy;
    BackLinkNodeRuntime* head;
  };
  static_assert(sizeof(BackLinkOwnerLaneView) == 0x08, "BackLinkOwnerLaneView size must be 0x08");
  static_assert(offsetof(BackLinkOwnerLaneView, head) == 0x04, "BackLinkOwnerLaneView::head offset must be 0x04");

  struct EmbeddedBackLinkLaneView
  {
    std::uint32_t lane0;
    std::uint32_t lane4;
    BackLinkNodeRuntime hook; // +0x08
    std::uint32_t lane10;
  };
  static_assert(offsetof(EmbeddedBackLinkLaneView, hook) == 0x08, "EmbeddedBackLinkLaneView::hook offset must be 0x08");
  static_assert(offsetof(EmbeddedBackLinkLaneView, lane10) == 0x10, "EmbeddedBackLinkLaneView::lane10 offset must be 0x10");
  static_assert(sizeof(EmbeddedBackLinkLaneView) == 0x14, "EmbeddedBackLinkLaneView size must be 0x14");

  [[nodiscard]] std::uint32_t* SwapWordLane(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    const std::uint32_t tmp = *lhs;
    *lhs = *rhs;
    *rhs = tmp;
    return lhs;
  }

  [[nodiscard]] DwordQuadLaneView* SwapTailThreeWordLanes(
    DwordQuadLaneView* const lhs, DwordQuadLaneView* const rhs
  ) noexcept
  {
    std::swap(lhs->lane4, rhs->lane4);
    std::swap(lhs->lane8, rhs->lane8);
    std::swap(lhs->laneC, rhs->laneC);
    return lhs;
  }

  [[nodiscard]] std::uint32_t* StoreStride4AddressFromBaseLane(
    std::uint32_t* const outAddress,
    const PointerBaseLaneView* const baseLane,
    const std::uint32_t index
  ) noexcept
  {
    *outAddress = baseLane->base + (index * 4u);
    return outAddress;
  }

  [[nodiscard]] std::uint32_t* StoreStride12AddressFromBaseLane(
    std::uint32_t* const outAddress,
    const PointerBaseLaneView* const baseLane,
    const std::uint32_t index
  ) noexcept
  {
    *outAddress = baseLane->base + (index * 12u);
    return outAddress;
  }

  [[nodiscard]] std::uint32_t LoadIndirectBaseWithOffset(
    const PointerBaseLaneView* const baseLane, const std::uint32_t byteOffset
  ) noexcept
  {
    return baseLane->base + byteOffset;
  }

  [[nodiscard]] ForwardLinkNodeRuntime** AdvanceForwardLinkSlot(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    *slot = (*slot)->next;
    return slot;
  }

  [[nodiscard]] ForwardLinkNodeRuntime** ResetForwardLinkSlot(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    *slot = nullptr;
    return slot;
  }

  /**
   * Address: 0x0067CC90 (FUN_0067CC90)
   *
   * What it does:
   * Swaps one dword lane between two pointers and returns the first pointer.
   */
  std::uint32_t* SwapWordLanePrimary(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067CCA0 (FUN_0067CCA0)
   *
   * What it does:
   * Secondary swap lane for one dword pointer pair.
   */
  std::uint32_t* SwapWordLaneSecondary(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067CCB0 (FUN_0067CCB0)
   *
   * What it does:
   * Tertiary swap lane for one dword pointer pair.
   */
  std::uint32_t* SwapWordLaneTertiary(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067CCC0 (FUN_0067CCC0)
   *
   * What it does:
   * Mirror swap lane for one dword pointer pair.
   */
  std::uint32_t* SwapWordLaneMirrorA(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067CCD0 (FUN_0067CCD0)
   *
   * What it does:
   * Mirror swap lane for one dword pointer pair.
   */
  std::uint32_t* SwapWordLaneMirrorB(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067CCE0 (FUN_0067CCE0)
   *
   * What it does:
   * Mirror swap lane for one dword pointer pair.
   */
  std::uint32_t* SwapWordLaneMirrorC(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x0067E160 (FUN_0067E160)
   *
   * What it does:
   * Stores `base + index * 4` into output address storage.
   */
  std::uint32_t* StoreStride4AddressPrimary(
    std::uint32_t* const outAddress,
    const PointerBaseLaneView* const baseLane,
    const std::uint32_t index
  ) noexcept
  {
    return StoreStride4AddressFromBaseLane(outAddress, baseLane, index);
  }

  /**
   * Address: 0x0067E270 (FUN_0067E270)
   *
   * What it does:
   * Stores `base + index * 12` into output address storage.
   */
  std::uint32_t* StoreStride12AddressPrimary(
    std::uint32_t* const outAddress,
    const PointerBaseLaneView* const baseLane,
    const std::uint32_t index
  ) noexcept
  {
    return StoreStride12AddressFromBaseLane(outAddress, baseLane, index);
  }

  /**
   * Address: 0x0067E2E0 (FUN_0067E2E0)
   *
   * What it does:
   * Mirror lane that stores `base + index * 4` into output address storage.
   */
  std::uint32_t* StoreStride4AddressSecondary(
    std::uint32_t* const outAddress,
    const PointerBaseLaneView* const baseLane,
    const std::uint32_t index
  ) noexcept
  {
    return StoreStride4AddressFromBaseLane(outAddress, baseLane, index);
  }

  /**
   * Address: 0x0067F8C0 (FUN_0067F8C0)
   *
   * What it does:
   * Swaps tail dword lanes (`+0x4/+0x8/+0xC`) between two 16-byte records.
   */
  DwordQuadLaneView* SwapTailThreeWordLanesPrimary(
    DwordQuadLaneView* const lhs, DwordQuadLaneView* const rhs
  ) noexcept
  {
    return SwapTailThreeWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x0067FED0 (FUN_0067FED0)
   *
   * What it does:
   * Mirror lane that swaps tail dword lanes (`+0x4/+0x8/+0xC`) between two 16-byte records.
   */
  DwordQuadLaneView* SwapTailThreeWordLanesSecondary(
    DwordQuadLaneView* const lhs, DwordQuadLaneView* const rhs
  ) noexcept
  {
    return SwapTailThreeWordLanes(lhs, rhs);
  }

  /**
   * Address: 0x00680FA0 (FUN_00680FA0)
   *
   * What it does:
   * Additional dword-lane swap adapter.
   */
  std::uint32_t* SwapWordLaneAdapter(std::uint32_t* const lhs, std::uint32_t* const rhs) noexcept
  {
    return SwapWordLane(lhs, rhs);
  }

  /**
   * Address: 0x00683BD0 (FUN_00683BD0)
   *
   * What it does:
   * Returns true when the entity-id family nibble is zero (`0x0`).
   */
  bool IsUnitFamilyEntityId(const EntityIdWordLaneView* const id) noexcept
  {
    return (id->value & kEntityIdFamilyNibbleMask) == 0u;
  }

  /**
   * Address: 0x00683BE0 (FUN_00683BE0)
   *
   * What it does:
   * Returns true when the entity-id family nibble is `0x1`.
   */
  bool IsPropFamilyEntityId(const EntityIdWordLaneView* const id) noexcept
  {
    return (id->value & kEntityIdFamilyNibbleMask) == kAllUnitsUnitTypeBoundaryKey;
  }

  /**
   * Address: 0x00683C00 (FUN_00683C00)
   *
   * What it does:
   * Returns true when the entity-id family nibble is `0x2`.
   */
  bool IsProjectileFamilyEntityId(const EntityIdWordLaneView* const id) noexcept
  {
    return (id->value & kEntityIdFamilyNibbleMask) == kAllUnitsHighFamilyBoundaryKey;
  }

  /**
   * Address: 0x00683C20 (FUN_00683C20)
   *
   * What it does:
   * Returns true when the entity-id family nibble is `0x3`.
   */
  bool IsShieldFamilyEntityId(const EntityIdWordLaneView* const id) noexcept
  {
    return (id->value & kEntityIdFamilyNibbleMask) == kAllUnitsMidFamilyBoundaryKey;
  }

  /**
   * Address: 0x00683C40 (FUN_00683C40)
   *
   * What it does:
   * Returns true when the entity-id family nibble is `0x5`.
   */
  bool IsOtherFamilyEntityId(const EntityIdWordLaneView* const id) noexcept
  {
    return (id->value & kEntityIdFamilyNibbleMask) == kAllUnitsOtherFamilyBoundaryKey;
  }

  /**
   * Address: 0x00683C70 (FUN_00683C70)
   *
   * What it does:
   * Lexicographically compares two `(high, low)` key pairs and returns true
   * when `second` sorts before `first`.
   */
  bool IsSecondEntityIdPairBeforeFirst(
    const EntityIdPairWordLaneView* const first,
    const EntityIdPairWordLaneView* const second
  ) noexcept
  {
    return (second->high < first->high) || (second->high == first->high && second->low < first->low);
  }

  /**
   * Address: 0x00684000 (FUN_00684000)
   *
   * What it does:
   * Copies a two-word window range (`+0x27C/+0x280`) into output storage.
   */
  WindowPairLaneView* StoreWindowPairFromRuntime(
    WindowPairLaneView* const outPair, const EntityDbWindowLaneView* const runtime
  ) noexcept
  {
    outPair->first = runtime->windowBegin;
    outPair->second = runtime->windowEnd;
    return outPair;
  }

  /**
   * Address: 0x00684020 (FUN_00684020)
   *
   * What it does:
   * Writes the window cursor lane at offset `+0x284`.
   */
  EntityDbWindowLaneView* SetWindowCursorLane(
    EntityDbWindowLaneView* const runtime, const std::uint32_t value
  ) noexcept
  {
    runtime->windowCursor = value;
    return runtime;
  }

  /**
   * Address: 0x00684720 (FUN_00684720)
   *
   * What it does:
   * Unlinks one intrusive set-node and inserts it at the front of
   * `CEntityDb::mRegisteredEntitySets`.
   */
  moho::CEntityDbListHead* RelinkNodeIntoRegisteredEntitySetFront(
    moho::CEntityDbListHead* const node,
    moho::CEntityDb* const entityDb
  ) noexcept
  {
    node->next->prev = node->prev;
    node->prev->next = node->next;

    node->next = node;
    node->prev = node;

    moho::CEntityDbListHead& head = entityDb->mRegisteredEntitySets;
    node->next = head.next;
    node->prev = &head;
    head.next = node;
    node->next->prev = node;
    return node;
  }

  /**
   * Address: 0x00685340 (FUN_00685340)
   *
   * What it does:
   * Returns true when the lane at offset `+0x8` is null.
   */
  bool IsOffset8LaneNull(const Offset8WordLaneView* const runtime) noexcept
  {
    return runtime->lane8 == 0u;
  }

  /**
   * Address: 0x00685880 (FUN_00685880)
   *
   * What it does:
   * Stores `head->next` from one `(+0x4)` list-head proxy lane.
   */
  moho::CEntityDbListHead** StoreListHeadNextPrimary(
    moho::CEntityDbListHead** const outNode,
    const ListHeadProxyLaneView* const runtime
  ) noexcept
  {
    *outNode = runtime->head->next;
    return outNode;
  }

  /**
   * Address: 0x006858A0 (FUN_006858A0)
   *
   * What it does:
   * Resets one intrusive node to self-links.
   */
  moho::CEntityDbListHead* ResetListNodeSelfLinks(moho::CEntityDbListHead* const node) noexcept
  {
    node->prev = node;
    node->next = node;
    return node;
  }

  /**
   * Address: 0x006858D0 (FUN_006858D0)
   *
   * What it does:
   * Unlinks one intrusive node, restores self-links, then inserts it at the
   * front of the provided list head.
   */
  moho::CEntityDbListHead* RelinkNodeIntoListHeadFront(
    moho::CEntityDbListHead* const node,
    moho::CEntityDbListHead* const head
  ) noexcept
  {
    node->next->prev = node->prev;
    node->prev->next = node->next;

    node->next = node;
    node->prev = node;

    node->next = head->next;
    node->prev = head;
    head->next = node;
    node->next->prev = node;
    return node;
  }

  /**
   * Address: 0x00685940 (FUN_00685940)
   *
   * What it does:
   * Secondary lane that stores `head->next` from one `(+0x4)` list-head proxy lane.
   */
  moho::CEntityDbListHead** StoreListHeadNextSecondary(
    moho::CEntityDbListHead** const outNode,
    const ListHeadProxyLaneView* const runtime
  ) noexcept
  {
    *outNode = runtime->head->next;
    return outNode;
  }

  /**
   * Address: 0x006859D0 (FUN_006859D0)
   *
   * What it does:
   * Returns the node-count lane from `[begin,end)` queue storage where each
   * element is `CEntityDbBoundedPropQueueNode` (`0x14` bytes).
   */
  int CountQueueNodeRangeEntries(const QueueNodeRangeLaneView* const queue) noexcept
  {
    if (queue->begin == nullptr) {
      return 0;
    }
    return static_cast<int>(queue->end - queue->begin);
  }

  /**
   * Address: 0x00685B80 (FUN_00685B80)
   *
   * What it does:
   * Decodes current all-armies iterator payload (`node->unitListNode - 0x8`)
   * into `Unit*`, or returns null when payload is null.
   */
  moho::Unit* DecodeCurrentAllArmiesIteratorUnit(
    const moho::CUnitIterAllArmies* const iterator
  ) noexcept
  {
    void* const encodedPayload = iterator->mItr->unitListNode;
    if (encodedPayload == nullptr) {
      return nullptr;
    }
    return reinterpret_cast<moho::Unit*>(reinterpret_cast<std::uintptr_t>(encodedPayload) - 0x8u);
  }

  /**
   * Address: 0x00685BD0 (FUN_00685BD0)
   *
   * What it does:
   * Returns current raw all-armies iterator payload pointer (`node->unitListNode`).
   */
  void* GetCurrentAllArmiesIteratorRawPayloadPrimary(
    const moho::CUnitIterAllArmies* const iterator
  ) noexcept
  {
    return iterator->mItr->unitListNode;
  }

  /**
   * Address: 0x00685C10 (FUN_00685C10)
   *
   * What it does:
   * Secondary lane that returns current raw all-armies iterator payload pointer.
   */
  void* GetCurrentAllArmiesIteratorRawPayloadSecondary(
    const moho::CUnitIterAllArmies* const iterator
  ) noexcept
  {
    return iterator->mItr->unitListNode;
  }

  /**
   * Address: 0x00685F20 (FUN_00685F20)
   *
   * What it does:
   * Copies one dword from each source slot into a 2-lane output record.
   */
  DualWordLaneView* CopyDualWordLaneFromSeparateSlots(
    DualWordLaneView* const outValue,
    const std::uint32_t* const firstSlot,
    const std::uint32_t* const secondSlot
  ) noexcept
  {
    outValue->lane0 = *firstSlot;
    outValue->lane4 = *secondSlot;
    return outValue;
  }

  /**
   * Address: 0x00685F70 (FUN_00685F70)
   *
   * What it does:
   * Loads one indirect base lane and returns `base + 0x8`.
   */
  std::uint32_t LoadIndirectBasePlus8Primary(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x8u);
  }

  /**
   * Address: 0x00685F90 (FUN_00685F90)
   *
   * What it does:
   * Loads one indirect base lane and returns `base + 0x10`.
   */
  std::uint32_t LoadIndirectBasePlus16Primary(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x10u);
  }

  [[nodiscard]] gpg::RRef NewEntityDbTypeLaneRef()
  {
    moho::CEntityDb* entityDb = nullptr;
    if (void* const storage = ::operator new(sizeof(moho::CEntityDb), std::nothrow); storage != nullptr) {
      entityDb = new (storage) moho::CEntityDb();
    }

    gpg::RRef out{};
    (void)gpg::RRef_EntityDB(&out, entityDb);
    return out;
  }

  [[nodiscard]] gpg::RRef CtorEntityDbTypeLaneRef(void* const objectStorage)
  {
    moho::CEntityDb* entityDb = nullptr;
    if (objectStorage != nullptr) {
      entityDb = new (objectStorage) moho::CEntityDb();
    }

    gpg::RRef out{};
    (void)gpg::RRef_EntityDB(&out, entityDb);
    return out;
  }

  void DeleteEntityDbTypeLane(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    auto* const entityDb = static_cast<moho::CEntityDb*>(objectStorage);
    entityDb->~CEntityDb();
    ::operator delete(entityDb);
  }

  void DestructEntityDbTypeLane(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return;
    }

    auto* const entityDb = static_cast<moho::CEntityDb*>(objectStorage);
    entityDb->~CEntityDb();
  }

  /**
   * Address: 0x00685FC0 (FUN_00685FC0)
   *
   * What it does:
   * Binds one `EntityDB` type-info lifecycle callback set (`newRef`,
   * `ctorRef`, `delete`, `destruct`) into one destination `RType` lane.
   */
  gpg::RType* BindEntityDbTypeLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
  {
    typeInfo->newRefFunc_ = &NewEntityDbTypeLaneRef;
    typeInfo->ctorRefFunc_ = &CtorEntityDbTypeLaneRef;
    typeInfo->deleteFunc_ = &DeleteEntityDbTypeLane;
    typeInfo->dtrFunc_ = &DestructEntityDbTypeLane;
    return typeInfo;
  }

  /**
   * Address: 0x00686080 (FUN_00686080)
   *
   * What it does:
   * Initializes one back-link node from one owner lane (`owner + 0x4`) and
   * inserts it at the owner head slot.
   */
  BackLinkNodeRuntime* LinkBackLinkNodeFromOwnerLane(
    BackLinkNodeRuntime* const node,
    BackLinkOwnerLaneView* const owner
  ) noexcept
  {
    BackLinkNodeRuntime** const headSlot = owner != nullptr ? &owner->head : nullptr;
    node->backRef = headSlot;
    if (headSlot != nullptr) {
      node->next = *headSlot;
      *headSlot = node;
    } else {
      node->next = nullptr;
    }
    return node;
  }

  /**
   * Address: 0x006860D0 (FUN_006860D0)
   *
   * What it does:
   * Returns owner base pointer (`backRef - 0x4`) for one linked node, or
   * null when node is unlinked.
   */
  BackLinkOwnerLaneView* ResolveBackLinkNodeOwner(const BackLinkNodeRuntime* const node) noexcept
  {
    BackLinkNodeRuntime** const backRef = node->backRef;
    if (backRef == nullptr) {
      return nullptr;
    }

    auto* const ownerLane = reinterpret_cast<std::uint8_t*>(backRef) - 0x4u;
    return reinterpret_cast<BackLinkOwnerLaneView*>(ownerLane);
  }

  struct NextBackRefNodeRuntime
  {
    NextBackRefNodeRuntime* next;
    NextBackRefNodeRuntime** backRef;
  };
  static_assert(sizeof(NextBackRefNodeRuntime) == 0x08, "NextBackRefNodeRuntime size must be 0x08");

  /**
   * Address: 0x006866A0 (FUN_006866A0)
   *
   * What it does:
   * Unlinks one `(next, backRef)` intrusive node from its current list,
   * rewires it to self-links, then inserts it at one target head slot.
   */
  NextBackRefNodeRuntime* RelinkNextBackRefNodeToHead(
    NextBackRefNodeRuntime* const node,
    NextBackRefNodeRuntime** const headSlot
  ) noexcept
  {
    node->next->backRef = node->backRef;
    *node->backRef = node->next;

    node->next = node;
    node->backRef = reinterpret_cast<NextBackRefNodeRuntime**>(node);

    node->next = *headSlot;
    node->backRef = headSlot;
    *headSlot = node;
    node->next->backRef = &node->next;
    return node;
  }

  /**
   * Address: 0x00686880 (FUN_00686880)
   *
   * What it does:
   * Clears bounded-prop queue range lanes (`start/end/capacity`) to null.
   */
  moho::CEntityDbBoundedPropQueueRuntime* ClearBoundedPropQueueRangeLanes(
    moho::CEntityDbBoundedPropQueueRuntime* const queue
  ) noexcept
  {
    queue->start = nullptr;
    queue->end = nullptr;
    queue->capacity = nullptr;
    return queue;
  }

  /**
   * Address: 0x006868B0 (FUN_006868B0)
   *
   * What it does:
   * Returns element pointer at one bounded-prop queue index (`start + index`).
   */
  moho::CEntityDbBoundedPropQueueNode* ResolveBoundedPropQueueNodeAtIndex(
    const std::int32_t index,
    const moho::CEntityDbBoundedPropQueueRuntime* const queue
  ) noexcept
  {
    return queue->start + index;
  }

  /**
   * Address: 0x00686C70 (FUN_00686C70)
   * Address: 0x00688740 (FUN_00688740)
   *
   * What it does:
   * Copies one dword lane and one byte lane into output storage.
   */
  WordAndByteLaneView* CopyWordAndByteLane(
    WordAndByteLaneView* const outValue,
    const std::uint32_t* const wordSlot,
    const std::uint8_t* const byteSlot
  ) noexcept
  {
    outValue->lane0 = *wordSlot;
    outValue->lane4 = *byteSlot;
    return outValue;
  }

  /**
   * Address: 0x00686C90 (FUN_00686C90)
   *
   * What it does:
   * Pops one singly-linked forward node from head storage into output lane.
   */
  ForwardLinkNodeRuntime** PopForwardLinkNode(
    ForwardLinkNodeRuntime** const outNode,
    ForwardLinkNodeRuntime** const headSlot
  ) noexcept
  {
    ForwardLinkNodeRuntime* const head = *headSlot;
    *outNode = head;
    *headSlot = head->next;
    return outNode;
  }

  /**
   * Address: 0x00686CA0 (FUN_00686CA0)
   *
   * What it does:
   * Loads one indirect base lane and returns `base + 0x8`.
   */
  std::uint32_t LoadIndirectBasePlus8Secondary(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x8u);
  }

  /**
   * Address: 0x00686CD0 (FUN_00686CD0)
   *
   * What it does:
   * Loads one indirect base lane and returns `base + 0x10`.
   */
  std::uint32_t LoadIndirectBasePlus16Secondary(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x10u);
  }

  /**
   * Address: 0x00686D50 (FUN_00686D50)
   *
   * What it does:
   * Initializes one back-link node from one externally provided back-ref slot
   * lane and inserts it at that slot head.
   */
  BackLinkNodeRuntime* LinkBackLinkNodeFromBackRefOwner(
    BackLinkNodeRuntime* const node,
    BackLinkNodeRuntime** const* const backRefOwner
  ) noexcept
  {
    BackLinkNodeRuntime** const backRef = *backRefOwner;
    node->backRef = backRef;
    if (backRef != nullptr) {
      node->next = *backRef;
      *backRef = node;
    } else {
      node->next = nullptr;
    }
    return node;
  }

  /**
   * Address: 0x00687690 (FUN_00687690)
   *
   * What it does:
   * Pushes one released bounded-prop handle index into the freelist lane and
   * updates queue `lastHandle`.
   */
  moho::CEntityDbBoundedPropQueueRuntime* PushBoundedPropHandleFreeList(
    moho::CEntityDbBoundedPropQueueRuntime* const queue,
    const std::int32_t releasedHandle
  ) noexcept
  {
    auto* const freeListStorage = static_cast<std::int32_t*>(queue->storageBegin);
    freeListStorage[releasedHandle] = queue->lastHandle;
    queue->lastHandle = releasedHandle;
    return queue;
  }

  /**
   * Address: 0x006876A0 (FUN_006876A0)
   *
   * What it does:
   * Returns bounded-prop queue capacity-count lane (`capacity - start`) in
   * node units, or zero when start is null.
   */
  std::int32_t CountBoundedPropQueueCapacityNodes(
    const moho::CEntityDbBoundedPropQueueRuntime* const queue
  ) noexcept
  {
    if (queue->start == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(queue->capacity - queue->start);
  }

  /**
   * Address: 0x006876D0 (FUN_006876D0)
   *
   * What it does:
   * Returns pointer to the previous bounded-prop queue slot (`end - 1`).
   */
  moho::CEntityDbBoundedPropQueueNode* GetBoundedPropQueuePreviousEndSlot(
    const moho::CEntityDbBoundedPropQueueRuntime* const queue
  ) noexcept
  {
    return queue->end - 1;
  }

  /**
   * Address: 0x00687850 (FUN_00687850)
   *
   * What it does:
   * Advances one forward-link slot to `slot->next`.
   */
  ForwardLinkNodeRuntime** AdvanceForwardLinkSlotPrimary(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    return AdvanceForwardLinkSlot(slot);
  }

  /**
   * Address: 0x00687860 (FUN_00687860)
   *
   * What it does:
   * Secondary lane that advances one forward-link slot to `slot->next`.
   */
  ForwardLinkNodeRuntime** AdvanceForwardLinkSlotSecondary(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    return AdvanceForwardLinkSlot(slot);
  }

  /**
   * Address: 0x00687870 (FUN_00687870)
   *
   * What it does:
   * Clears one forward-link slot to null.
   */
  ForwardLinkNodeRuntime** ClearForwardLinkSlotPrimary(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    return ResetForwardLinkSlot(slot);
  }

  /**
   * Address: 0x006878A0 (FUN_006878A0)
   *
   * What it does:
   * Tertiary lane that loads one indirect base and returns `base + 0x10`.
   */
  std::uint32_t LoadIndirectBasePlus16Tertiary(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x10u);
  }

  /**
   * Address: 0x006878B0 (FUN_006878B0)
   *
   * What it does:
   * Mirror lane that loads one indirect base and returns `base + 0x10`.
   */
  std::uint32_t LoadIndirectBasePlus16Mirror(const PointerBaseLaneView* const baseLane) noexcept
  {
    return LoadIndirectBaseWithOffset(baseLane, 0x10u);
  }

  /**
   * Address: 0x00687A30 (FUN_00687A30)
   * Address: 0x006896E0 (FUN_006896E0)
   * Address: 0x00689AC0 (FUN_00689AC0)
   *
   * What it does:
   * Copies one embedded back-link runtime lane and relinks the copied hook
   * into the same intrusive back-ref slot chain.
   */
  EmbeddedBackLinkLaneView* CopyEmbeddedBackLinkLane(
    EmbeddedBackLinkLaneView* const outValue,
    const EmbeddedBackLinkLaneView* const source
  ) noexcept
  {
    if (outValue == nullptr) {
      return nullptr;
    }

    outValue->lane0 = source->lane0;
    outValue->lane4 = source->lane4;

    BackLinkNodeRuntime** const backRef = source->hook.backRef;
    outValue->hook.backRef = backRef;
    if (backRef != nullptr) {
      outValue->hook.next = *backRef;
      *backRef = &outValue->hook;
    } else {
      outValue->hook.next = nullptr;
    }

    outValue->lane10 = source->lane10;
    return outValue;
  }

  /**
   * Address: 0x00689720 (FUN_00689720)
   * Address: 0x00689B00 (FUN_00689B00)
   *
   * What it does:
   * Unlinks one embedded back-link hook (`+0x08`) from its current owner-slot
   * chain and returns the slot that previously referenced that hook.
   */
  BackLinkNodeRuntime** UnlinkEmbeddedBackLinkHookOwnerSlot(
    EmbeddedBackLinkLaneView* const value
  ) noexcept
  {
    BackLinkNodeRuntime** slot = value->hook.backRef;
    BackLinkNodeRuntime* const hookNode = &value->hook;
    if (slot != nullptr) {
      while (*slot != hookNode) {
        slot = &((*slot)->next);
      }
      *slot = hookNode->next;
    }
    return slot;
  }

  /**
   * Address: 0x00689B20 (FUN_00689B20)
   *
   * What it does:
   * Unlinks one embedded back-link hook (`+0x08`) from its owner-slot chain
   * and returns the original lane pointer.
   */
  EmbeddedBackLinkLaneView* UnlinkEmbeddedBackLinkLaneAndReturnSelf(
    EmbeddedBackLinkLaneView* const value
  ) noexcept
  {
    (void)UnlinkEmbeddedBackLinkHookOwnerSlot(value);
    return value;
  }

  /**
   * Address: 0x006882A0 (FUN_006882A0)
   *
   * What it does:
   * Returns true when bounded-prop queue occupancy lane is empty (`start` is
   * null or `end == start`).
   */
  bool IsBoundedPropQueueEmpty(const moho::CEntityDbBoundedPropQueueRuntime* const queue) noexcept
  {
    return (queue->start == nullptr) || ((queue->end - queue->start) == 0);
  }

  /**
   * Address: 0x006886B0 (FUN_006886B0)
   *
   * What it does:
   * Secondary lane that clears one forward-link slot to null.
   */
  ForwardLinkNodeRuntime** ClearForwardLinkSlotSecondary(
    ForwardLinkNodeRuntime** const slot
  ) noexcept
  {
    return ResetForwardLinkSlot(slot);
  }

  /**
   * Address: 0x006886D0 (FUN_006886D0)
   *
   * What it does:
   * Rebinds one back-link node from its current back-ref slot chain to a new
   * target back-ref slot owner.
   */
  BackLinkNodeRuntime* RebindBackLinkNode(
    BackLinkNodeRuntime* const node,
    BackLinkNodeRuntime** const* const backRefOwner
  ) noexcept
  {
    BackLinkNodeRuntime** const targetBackRef = *backRefOwner;
    if (targetBackRef != node->backRef) {
      BackLinkNodeRuntime** oldBackRef = node->backRef;
      if (oldBackRef != nullptr) {
        BackLinkNodeRuntime** cursor = oldBackRef;
        while (cursor != nullptr && *cursor != node) {
          cursor = (*cursor != nullptr) ? &((*cursor)->next) : nullptr;
        }
        if (cursor != nullptr) {
          *cursor = node->next;
        }
      }

      node->backRef = targetBackRef;
      if (targetBackRef == nullptr) {
        node->next = nullptr;
      } else {
        node->next = *targetBackRef;
        *targetBackRef = node;
      }
    }
    return node;
  }

  /**
   * Address: 0x005BE2B0 (FUN_005BE2B0)
   *
   * What it does:
   * Packs one `(familyNibble, sourceIndex)` pair into EntityId family/source
   * bits (`[31..28]` family, `[27..20]` source), reserves an id through
   * `EntityDB::DoReserveId`, and writes the result into `outEntityId`.
   */
  std::uint32_t* ReserveEntityIdFromFamilyAndSourceLanes(
    const std::uint32_t familyNibble,
    std::uint32_t* const outEntityId,
    moho::CEntityDb* const entityDb,
    const std::uint32_t sourceIndex
  )
  {
    const std::uint32_t packedFamilySource = (sourceIndex | (familyNibble << 8u)) << kEntityIdSourceShift;
    *outEntityId = entityDb->DoReserveId(packedFamilySource);
    return outEntityId;
  }

  gpg::RType* gLegacyEntityDbType = nullptr;
  gpg::RType* gLegacyEntityDbIdPoolMapType = nullptr;
  gpg::RType* gLegacyEntityDbEntityListType = nullptr;

  /**
   * Address: 0x00686DD0 (FUN_00686DD0)
   *
   * What it does:
   * Resolves and caches RTTI for one `EntityDB` object lane.
   */
  [[nodiscard]] gpg::RType* ResolveLegacyEntityDbType()
  {
    gpg::RType* type = gLegacyEntityDbType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CEntityDb));
      gLegacyEntityDbType = type;
    }
    return type;
  }

  /**
   * Address: 0x00689D30 (FUN_00689D30)
   *
   * What it does:
   * Resolves and caches RTTI for one `map<unsigned int, IdPool>` lane.
   */
  [[nodiscard]] gpg::RType* ResolveLegacyEntityDbIdPoolMapType()
  {
    gpg::RType* type = gLegacyEntityDbIdPoolMapType;
    if (!type) {
      type = gpg::LookupRType(typeid(std::map<unsigned int, moho::IdPool>));
      gLegacyEntityDbIdPoolMapType = type;
    }
    return type;
  }

  /**
   * Address: 0x00689D50 (FUN_00689D50)
   *
   * What it does:
   * Resolves and caches RTTI for one `list<Entity*>` lane.
   */
  [[nodiscard]] gpg::RType* ResolveLegacyEntityDbEntityListType()
  {
    gpg::RType* type = gLegacyEntityDbEntityListType;
    if (!type) {
      type = gpg::LookupRType(typeid(std::list<moho::Entity*>));
      gLegacyEntityDbEntityListType = type;
    }
    return type;
  }

  struct IdPoolRuntime
  {
    // Corresponds to the sequential `(*v3)++` path in 0x00684480.
    std::uint32_t mNextSerial = 1u;
    // Corresponds to `(BVIntSet*)(v3 + 2)` in 0x00684480.
    moho::BVIntSet mReleasedSerials{};
    bool mSeededFromEntityDb = false;
  };

  using FamilyPoolMap = std::unordered_map<std::uint32_t, IdPoolRuntime>;
  std::unordered_map<const moho::CEntityDb*, FamilyPoolMap> gRuntimePools;
  std::unordered_map<const moho::CEntityDb*, msvc8::list<moho::Entity*>> gRuntimeEntityLists;
  moho::EntityDBSerializer gEntityDBSerializer;
  constexpr std::uint32_t kEntityIdInvalidSentinel = moho::ToRaw(moho::EEntityIdSentinel::Invalid);
  constexpr std::size_t kBoundedPropQueueMaxSize = 1000u;
  moho::StatItem* sEngineStat_EntityCount = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Prop = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unit = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Blip = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Other = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Projectile = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Shield = nullptr;
  moho::StatItem* sEngineStat_EntityCount_Unknown = nullptr;

  struct BoundedPropQueueEntry
  {
    std::int32_t priority = 0;
    std::int32_t boundedTick = 0;
    moho::WeakPtr<moho::Prop> weakProp{};
    std::int32_t handleIndex = -1;
  };

  struct BoundedPropQueueRuntime
  {
    std::vector<std::unique_ptr<BoundedPropQueueEntry>> heap{};
    std::vector<std::int32_t> handleToHeapIndex{};
    std::int32_t lastFreeHandle = -1;
  };

  std::unordered_map<const moho::CEntityDb*, BoundedPropQueueRuntime> gRuntimeBoundedProps;

  [[nodiscard]] bool IsHigherBoundedPropPriority(
    const BoundedPropQueueEntry& lhs, const BoundedPropQueueEntry& rhs
  ) noexcept
  {
    // Binary comparator is lexicographic min-heap on (priority, boundedTick).
    if (lhs.priority != rhs.priority) {
      return lhs.priority < rhs.priority;
    }

    return lhs.boundedTick < rhs.boundedTick;
  }

  [[nodiscard]] std::int32_t AcquireBoundedPropHandle(
    BoundedPropQueueRuntime& queue, const std::int32_t heapIndex
  )
  {
    if (queue.lastFreeHandle == -1) {
      const std::int32_t newHandle = static_cast<std::int32_t>(queue.handleToHeapIndex.size());
      queue.handleToHeapIndex.push_back(heapIndex);
      return newHandle;
    }

    const std::int32_t reusedHandle = queue.lastFreeHandle;
    queue.lastFreeHandle = queue.handleToHeapIndex[static_cast<std::size_t>(reusedHandle)];
    queue.handleToHeapIndex[static_cast<std::size_t>(reusedHandle)] = heapIndex;
    return reusedHandle;
  }

  void ReleaseBoundedPropHandle(BoundedPropQueueRuntime& queue, const std::int32_t handleIndex)
  {
    if (handleIndex < 0) {
      return;
    }

    const std::size_t handle = static_cast<std::size_t>(handleIndex);
    if (handle >= queue.handleToHeapIndex.size()) {
      queue.handleToHeapIndex.resize(handle + 1u, -1);
    }

    queue.handleToHeapIndex[handle] = queue.lastFreeHandle;
    queue.lastFreeHandle = handleIndex;
  }

  void UpdateBoundedPropHandleMapping(BoundedPropQueueRuntime& queue, const std::size_t heapIndex)
  {
    if (heapIndex >= queue.heap.size() || !queue.heap[heapIndex]) {
      return;
    }

    const std::int32_t handleIndex = queue.heap[heapIndex]->handleIndex;
    if (handleIndex < 0) {
      return;
    }

    const std::size_t handle = static_cast<std::size_t>(handleIndex);
    if (handle >= queue.handleToHeapIndex.size()) {
      queue.handleToHeapIndex.resize(handle + 1u, -1);
    }
    queue.handleToHeapIndex[handle] = static_cast<std::int32_t>(heapIndex);
  }

  /**
   * The semantic counterpart of the queue swap at 0x00687530, which is
   * recovered as `SwapPriorityQueueEntries` in `moho/sim/SimRecoveryRuntime.cpp`
   * against the binary's own layout.
   *
   * Deliberately NOT annotated with that address: this is not a 1:1 recovery of
   * it. The binary stores entries by value in a 20-byte array and physically
   * moves them, which is why it has to carry each entry's weak node across the
   * exchange. This model stores owning pointers and swaps those, so nothing
   * moves and no relink is needed. Same observable behaviour, different layout.
   *
   * Two models of one queue is debt. If they are ever unified, the sim-side one
   * is the binary's layout and this one is the safer abstraction - pick
   * deliberately, and do not add a third.
   */
  void SwapBoundedPropHeapEntries(BoundedPropQueueRuntime& queue, const std::size_t lhs, const std::size_t rhs)
  {
    if (lhs == rhs) {
      return;
    }

    std::swap(queue.heap[lhs], queue.heap[rhs]);
    UpdateBoundedPropHandleMapping(queue, lhs);
    UpdateBoundedPropHandleMapping(queue, rhs);
  }

  void SiftBoundedPropUp(BoundedPropQueueRuntime& queue, std::size_t heapIndex)
  {
    while (heapIndex > 0u) {
      const std::size_t parent = (heapIndex - 1u) / 2u;
      if (!IsHigherBoundedPropPriority(*queue.heap[heapIndex], *queue.heap[parent])) {
        break;
      }

      SwapBoundedPropHeapEntries(queue, parent, heapIndex);
      heapIndex = parent;
    }
  }

  void SiftBoundedPropDown(BoundedPropQueueRuntime& queue, std::size_t heapIndex)
  {
    const std::size_t count = queue.heap.size();
    for (;;) {
      const std::size_t leftChild = heapIndex * 2u + 1u;
      if (leftChild >= count) {
        return;
      }

      std::size_t best = heapIndex;
      if (IsHigherBoundedPropPriority(*queue.heap[leftChild], *queue.heap[best])) {
        best = leftChild;
      }

      const std::size_t rightChild = leftChild + 1u;
      if (rightChild < count && IsHigherBoundedPropPriority(*queue.heap[rightChild], *queue.heap[best])) {
        best = rightChild;
      }

      if (best == heapIndex) {
        return;
      }

      SwapBoundedPropHeapEntries(queue, heapIndex, best);
      heapIndex = best;
    }
  }

  [[nodiscard]] std::int32_t PushBoundedPropEntry(
    BoundedPropQueueRuntime& queue, moho::Prop* const prop, const std::int32_t priority, const std::int32_t boundedTick
  )
  {
    const std::int32_t heapIndex = static_cast<std::int32_t>(queue.heap.size());
    const std::int32_t handleIndex = AcquireBoundedPropHandle(queue, heapIndex);

    auto entry = std::make_unique<BoundedPropQueueEntry>();
    entry->priority = priority;
    entry->boundedTick = boundedTick;
    entry->weakProp.ResetFromObject(prop);
    entry->handleIndex = handleIndex;

    queue.heap.push_back(std::move(entry));
    SiftBoundedPropUp(queue, queue.heap.size() - 1u);
    UpdateBoundedPropHandleMapping(queue, queue.heap.size() - 1u);
    return handleIndex;
  }

  /**
   * Address: 0x006867F0 (FUN_006867F0)
   *
   * IDA signature:
   * void __usercall sub_6867F0(int index@<ebx>, gpg::PriorityQueue *queue@<edi>);
   *
   * What it does:
   * Removes one entry from the prop-reclaim priority queue at `heapIndex`:
   * swaps it with the tail entry (unless already at tail), sifts the moved
   * entry down so the heap invariant is restored from the new tail-insertion
   * position (binary invokes `sub_687530` swap + `sub_6875F0` sift), reads
   * back the removed entry's handle index (binary reads
   * `end[-1].mBoundedTick`, which is the handle-index field inside the tail
   * entry), links that handle back into the free-handle list via
   * `mLastHandle` push, then shrinks the heap by popping the tail slot.
   *
   * This helper is the common inner step of:
   *   - `AddBoundedProp` (evict head when queue is full)
   *   - `RemoveBoundedProp` / `RemoveBoundedPropByHandle` (explicit removal)
   *   - `Prop::~Prop` (auto-unregister on prop destruction)
   */
  [[nodiscard]] std::unique_ptr<BoundedPropQueueEntry> RemoveBoundedPropAtHeapIndex(
    BoundedPropQueueRuntime& queue,
    const std::size_t heapIndex
  )
  {
    if (heapIndex >= queue.heap.size()) {
      return {};
    }

    const std::size_t lastIndex = queue.heap.size() - 1u;
    if (heapIndex != lastIndex) {
      SwapBoundedPropHeapEntries(queue, heapIndex, lastIndex);
      SiftBoundedPropDown(queue, heapIndex);
    }

    std::unique_ptr<BoundedPropQueueEntry> removed = std::move(queue.heap.back());
    queue.heap.pop_back();

    if (removed) {
      ReleaseBoundedPropHandle(queue, removed->handleIndex);
    }
    return removed;
  }

  [[nodiscard]] moho::Prop* PopBoundedPropHead(BoundedPropQueueRuntime& queue)
  {
    if (queue.heap.empty()) {
      return nullptr;
    }

    std::unique_ptr<BoundedPropQueueEntry> removed = RemoveBoundedPropAtHeapIndex(queue, 0u);
    if (!removed) {
      return nullptr;
    }

    moho::Prop* const removedProp = removed->weakProp.GetObject();
    removed->weakProp.ResetFromObject(nullptr);
    return removedProp;
  }

  [[nodiscard]] moho::Prop* RemoveBoundedPropByHandle(
    BoundedPropQueueRuntime& queue,
    const std::int32_t handleIndex
  )
  {
    if (handleIndex < 0) {
      return nullptr;
    }

    const std::size_t handle = static_cast<std::size_t>(handleIndex);
    if (handle >= queue.handleToHeapIndex.size()) {
      return nullptr;
    }

    const std::int32_t heapIndex = queue.handleToHeapIndex[handle];
    if (heapIndex < 0) {
      return nullptr;
    }

    const std::size_t removeIndex = static_cast<std::size_t>(heapIndex);
    std::unique_ptr<BoundedPropQueueEntry> removed = RemoveBoundedPropAtHeapIndex(queue, removeIndex);
    if (!removed) {
      return nullptr;
    }

    moho::Prop* const removedProp = removed->weakProp.GetObject();
    if (removedProp != nullptr) {
      removedProp->mHandleIndex = -1;
    }
    removed->weakProp.ResetFromObject(nullptr);

    // Re-establish the heap invariant at the position the moved tail entry
    // landed at: both directions because a handle-targeted remove can break
    // the invariant upward or downward (unlike head-pop which only goes down).
    if (removeIndex < queue.heap.size()) {
      SiftBoundedPropUp(queue, removeIndex);
    }
    return removedProp;
  }

  [[nodiscard]] moho::StatItem* EnsureEntityCountStatSlot(moho::StatItem*& slot, const char* const statPath)
  {
    if (slot) {
      return slot;
    }

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

    slot = engineStats->GetItem(statPath, true);
    if (slot) {
      (void)slot->Release(0);
    }
    return slot;
  }

  void AddEntityCountStat(moho::StatItem*& slot, const char* const statPath, const std::uint32_t delta) noexcept
  {
    moho::StatItem* const statItem = EnsureEntityCountStatSlot(slot, statPath);
    if (!statItem) {
      return;
    }

#if defined(_WIN32)
    ::InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), static_cast<long>(delta));
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  /**
   * Address: 0x00684030 (FUN_00684030, func_EngineStats_ChngEntityCount)
   *
   * What it does:
   * Updates engine entity-count stat lanes for one packed entity id family.
   */
  void UpdateEntityCountStats(const std::uint32_t entityId, const std::uint32_t delta)
  {
    AddEntityCountStat(sEngineStat_EntityCount, "EntityCount", delta);

    switch ((entityId >> moho::kEntityIdFamilyShift) & 0xFu) {
    case 0u:
      AddEntityCountStat(sEngineStat_EntityCount_Unit, "EntityCount_Unit", delta);
      break;
    case 1u:
      AddEntityCountStat(sEngineStat_EntityCount_Projectile, "EntityCount_Projectile", delta);
      break;
    case 2u:
      AddEntityCountStat(sEngineStat_EntityCount_Prop, "EntityCount_Prop", delta);
      break;
    case 3u:
      AddEntityCountStat(sEngineStat_EntityCount_Blip, "EntityCount_Blip", delta);
      break;
    case 4u:
      AddEntityCountStat(sEngineStat_EntityCount_Shield, "EntityCount_Shield", delta);
      break;
    case 5u:
      AddEntityCountStat(sEngineStat_EntityCount_Other, "EntityCount_Other", delta);
      break;
    default:
      AddEntityCountStat(sEngineStat_EntityCount_Unknown, "EntityCount_Unknown", delta);
      break;
    }
  }

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sEntIdType = nullptr;
    if (!sEntIdType) {
      sEntIdType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (!sEntIdType) {
        sEntIdType = gpg::LookupRType(typeid(int));
      }
    }
    return sEntIdType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityType()
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = ResolveTypeByAnyName({"Entity", "Moho::Entity"});
      if (!sEntityType) {
        sEntityType = gpg::LookupRType(typeid(moho::Entity));
      }
    }
    return sEntityType;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseType()
  {
    static gpg::RType* sEntitySetBaseType = nullptr;
    if (!sEntitySetBaseType) {
      sEntitySetBaseType = ResolveTypeByAnyName({"EntitySetBase", "Moho::EntitySetBase"});
    }
    return sEntitySetBaseType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityDbType()
  {
    static gpg::RType* sEntityDbType = nullptr;
    if (!sEntityDbType) {
      sEntityDbType = ResolveTypeByAnyName({"EntityDB", "CEntityDB", "Moho::EntityDB"});
      if (!sEntityDbType) {
        sEntityDbType = gpg::LookupRType(typeid(moho::CEntityDb));
      }
    }
    return sEntityDbType;
  }

  [[nodiscard]] gpg::RRef NullOwnerRef() noexcept
  {
    return {};
  }

  [[nodiscard]] bool ContainsEntityPointer(const msvc8::list<moho::Entity*>& entities, const moho::Entity* const entity) noexcept
  {
    for (const moho::Entity* const current : entities) {
      if (current == entity) {
        return true;
      }
    }
    return false;
  }

  void TrackEntityPointer(msvc8::list<moho::Entity*>& entities, moho::Entity* const entity)
  {
    if (!entity || ContainsEntityPointer(entities, entity)) {
      return;
    }
    entities.push_back(entity);
  }

  void RemoveTrackedEntityById(msvc8::list<moho::Entity*>& entities, const std::uint32_t releasedId) noexcept
  {
    for (auto it = entities.begin(); it != entities.end();) {
      const moho::Entity* const entity = *it;
      if (entity != nullptr && static_cast<std::uint32_t>(entity->id_) == releasedId) {
        it = entities.erase(it);
      } else {
        ++it;
      }
    }
  }

  [[nodiscard]] gpg::RRef MakeObjectRef(void* const object, gpg::RType* const type) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = object ? type : nullptr;
    return ref;
  }

  [[nodiscard]] moho::Entity* ReadOwnedEntityPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, NullOwnerRef());
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const entityType = ResolveEntityType();
    if (!entityType || !tracked.type) {
      return static_cast<moho::Entity*>(tracked.object);
    }

    const gpg::RRef source = MakeObjectRef(tracked.object, tracked.type);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, entityType);
    return static_cast<moho::Entity*>(upcast.mObj ? upcast.mObj : tracked.object);
  }

  [[nodiscard]] moho::CEntityDbListHead* ReadEntitySetPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, NullOwnerRef());
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expectedType = ResolveEntitySetBaseType();
    if (!expectedType || !tracked.type) {
      return static_cast<moho::CEntityDbListHead*>(tracked.object);
    }

    const gpg::RRef source = MakeObjectRef(tracked.object, tracked.type);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<moho::CEntityDbListHead*>(upcast.mObj ? upcast.mObj : tracked.object);
  }

  void EnsureSetListHeadInitialized(moho::CEntityDbListHead& head) noexcept
  {
    if (!head.next || !head.prev) {
      head.next = &head;
      head.prev = &head;
    }
  }

  /**
   * Address: 0x00684340 (FUN_00684340)
   *
   * What it does:
   * Resets one intrusive list-head lane to the empty self-linked sentinel
   * shape (`next=this`, `prev=this`) and returns the same head pointer.
   */
  moho::CEntityDbListHead* ResetEntityDbListHeadToSelf(moho::CEntityDbListHead* const head) noexcept
  {
    if (head != nullptr) {
      head->next = head;
      head->prev = head;
    }
    return head;
  }

  void LinkSetNodeToFront(moho::CEntityDbListHead& head, moho::CEntityDbListHead* const node) noexcept
  {
    if (!node) {
      return;
    }

    EnsureSetListHeadInitialized(head);

    if (node->next && node->prev) {
      node->next->prev = node->prev;
      node->prev->next = node->next;
    }

    node->next = node;
    node->prev = node;

    node->next = head.next;
    node->prev = &head;
    head.next->prev = node;
    head.next = node;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext && helper.mHelperPrev) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    return self;
  }

  /**
   * Address: 0x00684930 (FUN_00684930)
   *
   * What it does:
   * Initializes callback lanes for global `EntityDBSerializer` helper storage
   * and returns that helper object.
   */
  [[nodiscard]] moho::EntityDBSerializer* InitializeEntityDBSerializerStartupThunk() noexcept
  {
    InitializeHelperNode(gEntityDBSerializer);
    gEntityDBSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&moho::EntityDBSerializer::Deserialize);
    gEntityDBSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&moho::EntityDBSerializer::Serialize);
    return &gEntityDBSerializer;
  }

  /**
   * Address: 0x00685FE0 (FUN_00685FE0)
   *
   * What it does:
   * Initializes callback lanes for global `EntityDBSerializer` helper storage
   * and returns the serializer helper pointer.
   */
  [[nodiscard]] gpg::SerHelperBase* InitializeEntityDBSerializerStartupLeaf() noexcept
  {
    (void)InitializeEntityDBSerializerStartupThunk();
    return HelperSelfNode(gEntityDBSerializer);
  }

  /**
   * Address: 0x00684960 (FUN_00684960)
   *
   * What it does:
   * Unlinks global `EntityDBSerializer` helper links and resets the node to
   * the canonical self-linked state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkEntityDBSerializerHelperNodePrimary() noexcept
  {
    return UnlinkHelperNode(gEntityDBSerializer);
  }

  /**
   * Address: 0x00684990 (FUN_00684990)
   *
   * What it does:
   * Secondary unlink/reset entry for the global `EntityDBSerializer` helper
   * node.
   */
  [[nodiscard, maybe_unused]] gpg::SerHelperBase* UnlinkEntityDBSerializerHelperNodeSecondary() noexcept
  {
    return UnlinkHelperNode(gEntityDBSerializer);
  }

  void cleanup_EntityDBSerializer_atexit()
  {
    (void)moho::cleanup_EntityDBSerializer();
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode*
  TreeLowerBound(moho::CEntityDbAllUnitsNode* const head, const std::uint32_t lowerBoundKey) noexcept
  {
    return msvc8::lower_bound_node<moho::CEntityDbAllUnitsNode, &moho::CEntityDbAllUnitsNode::isNil>(
      head, lowerBoundKey, [](const auto& node, const std::uint32_t key) {
      return node.key < key;
    }
    );
  }

  /**
   * Address: 0x00683CC0 (FUN_00683CC0)
   *
   * What it does:
   * Stores the first all-units node at/after one source upper-bound key
   * `((sourceIndex + 1) << 20)` into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreAllUnitsSourceUpperBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t sourceIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    const std::uint32_t lowerBoundKey = (sourceIndex + 1u) << kEntityIdSourceShift;
    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, lowerBoundKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683CF0 (FUN_00683CF0)
   *
   * What it does:
   * Stores the left-most all-units tree node (minimum key) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreAllUnitsLeftmostNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    moho::CEntityDbAllUnitsNode* head = (entityDb != nullptr) ? entityDb->mAllUnits : nullptr;
    if (head == nullptr) {
      *outNode = nullptr;
      return outNode;
    }

    moho::CEntityDbAllUnitsNode* node = head;
    moho::CEntityDbAllUnitsNode* cursor = head->parent;
    while (cursor != nullptr && cursor->isNil == 0u) {
      node = cursor;
      cursor = cursor->left;
    }

    *outNode = node;
    return outNode;
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode* FindExactEntityNodeOrHead(
    moho::CEntityDbAllUnitsNode* const head,
    const std::uint32_t entityId
  ) noexcept
  {
    if (head == nullptr) {
      return nullptr;
    }

    moho::CEntityDbAllUnitsNode* const node = TreeLowerBound(head, entityId);
    if (node == nullptr || node == head || node->key != entityId) {
      return head;
    }
    return node;
  }

  /**
   * Address: 0x00684510 (FUN_00684510)
   *
   * What it does:
   * Finds one all-units tree node for `entityId` and stores `entity` in that
   * node payload lane.
   */
  moho::CEntityDbAllUnitsNode* AssignEntityPayloadAtIdNode(
    moho::CEntityDb* const entityDb,
    const std::uint32_t entityId,
    moho::Entity* const entity
  ) noexcept
  {
    if (entityDb == nullptr) {
      return nullptr;
    }

    moho::CEntityDbAllUnitsNode* const node = FindExactEntityNodeOrHead(entityDb->mAllUnits, entityId);
    if (node != nullptr) {
      node->unitListNode = entity;
    }
    return node;
  }

  /**
   * Address: 0x00684530 (FUN_00684530)
   *
   * What it does:
   * Returns the exact all-units payload pointer for one `entityId`, or `nullptr`
   * when lookup resolves to the map head/sentinel lane.
   */
  moho::Entity* FindEntityPayloadByIdNode(
    moho::CEntityDb* const entityDb,
    const std::uint32_t entityId
  ) noexcept
  {
    if (entityDb == nullptr || entityDb->mAllUnits == nullptr) {
      return nullptr;
    }

    moho::CEntityDbAllUnitsNode* const head = entityDb->mAllUnits;
    moho::CEntityDbAllUnitsNode* const node = FindExactEntityNodeOrHead(head, entityId);
    if (node == nullptr || node == head) {
      return nullptr;
    }
    return static_cast<moho::Entity*>(node->unitListNode);
  }

  /**
   * Address: 0x00683D90 (FUN_00683D90)
   *
   * What it does:
   * Stores the first all-units node at/after the high-family boundary key
   * (`0x20000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreHighFamilyBoundaryLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsHighFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683DC0 (FUN_00683DC0)
   *
   * What it does:
   * Stores the first all-units node at/after the mid-family boundary key
   * (`0x30000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreMidFamilyBoundaryLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsMidFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683EF0 (FUN_00683EF0)
   *
   * What it does:
   * Stores the first all-units node at/after the shield-family boundary key
   * (`0x40000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreShieldFamilyBoundaryLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsShieldFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683F20 (FUN_00683F20)
   * Address: 0x00683FA0 (FUN_00683FA0)
   *
   * What it does:
   * Stores the first all-units node at/after the other-family boundary key
   * (`0x50000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreOtherFamilyBoundaryLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsOtherFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683FD0 (FUN_00683FD0)
   *
   * What it does:
   * Stores the first all-units node at/after the late-family boundary key
   * (`0x60000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreLateFamilyBoundaryLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsLateFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683D40 (FUN_00683D40)
   *
   * What it does:
   * Stores the first all-units node at/after one prop-family purge key
   * `((armyIndex | 0x200) << 20)` into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StorePurgePropFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    const std::uint32_t lowerBoundKey = (armyIndex | 0x200U) << moho::kEntityIdSourceShift;
    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, lowerBoundKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683D80 (FUN_00683D80)
   *
   * What it does:
   * Register-shape adapter that forwards one `(armyIndex + 1)` prop-family
   * purge lower-bound query.
   */
  moho::CEntityDbAllUnitsNode** StorePurgePropFamilyUpperBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    return StorePurgePropFamilyLowerBoundNode(outNode, armyIndex + 1u, entityDb);
  }

  /**
   * Address: 0x00683DF0 (FUN_00683DF0)
   *
   * What it does:
   * Stores the first all-units node at/after one projectile-family purge key
   * `((armyIndex | 0x100) << 20)` into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeProjectileFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    const std::uint32_t lowerBoundKey = (armyIndex | 0x100U) << moho::kEntityIdSourceShift;
    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, lowerBoundKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683E30 (FUN_00683E30)
   *
   * What it does:
   * Register-shape adapter that forwards one `(armyIndex + 1)` projectile-family
   * purge lower-bound query.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeProjectileFamilyUpperBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    return StorePurgeProjectileFamilyLowerBoundNode(outNode, armyIndex + 1u, entityDb);
  }

  /**
   * Address: 0x00683EA0 (FUN_00683EA0)
   *
   * What it does:
   * Stores the first all-units node at/after one shield-family purge key
   * `((armyIndex | 0x400) << 20)` into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeShieldFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    const std::uint32_t lowerBoundKey = (armyIndex | 0x400U) << moho::kEntityIdSourceShift;
    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, lowerBoundKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683EE0 (FUN_00683EE0)
   *
   * What it does:
   * Register-shape adapter that forwards one `(armyIndex + 1)` shield-family
   * purge lower-bound query.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeShieldFamilyUpperBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    return StorePurgeShieldFamilyLowerBoundNode(outNode, armyIndex + 1u, entityDb);
  }

  /**
   * Address: 0x00683F50 (FUN_00683F50)
   *
   * What it does:
   * Stores the first all-units node at/after one other-family purge key
   * `((armyIndex | 0x500) << 20)` into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeOtherFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    const std::uint32_t lowerBoundKey = (armyIndex | 0x500U) << moho::kEntityIdSourceShift;
    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, lowerBoundKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683F90 (FUN_00683F90)
   *
   * What it does:
   * Register-shape adapter that forwards one `(armyIndex + 1)` other-family
   * purge lower-bound query.
   */
  moho::CEntityDbAllUnitsNode** StorePurgeOtherFamilyUpperBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const std::uint32_t armyIndex,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    return StorePurgeOtherFamilyLowerBoundNode(outNode, armyIndex + 1u, entityDb);
  }

  /**
   * Address: 0x00683E40 (FUN_00683E40)
   *
   * What it does:
   * Stores the first all-units node at/after the non-unit family boundary
   * (`0x10000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreFirstNonUnitFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsUnitTypeBoundaryKey) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x00683E70 (FUN_00683E70)
   *
   * What it does:
   * Stores the first all-units node at/after the high-family boundary
   * (`0x20000000`) into `outNode`.
   */
  moho::CEntityDbAllUnitsNode** StoreFirstHighFamilyLowerBoundNode(
    moho::CEntityDbAllUnitsNode** const outNode,
    const moho::CEntityDb* const entityDb
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    *outNode = (entityDb != nullptr) ? TreeLowerBound(entityDb->mAllUnits, kAllUnitsHighFamilyBoundaryKey) : nullptr;
    return outNode;
  }

  [[nodiscard]] moho::CEntityDbAllUnitsNode*
  NextNodeInAllUnitsTree(moho::CEntityDbAllUnitsNode* node) noexcept
  {
    if (node == nullptr || node->isNil != 0u) {
      return node;
    }

    moho::CEntityDbAllUnitsNode* childOrParent = node->right;
    if (childOrParent == nullptr) {
      return nullptr;
    }

    if (childOrParent->isNil != 0u) {
      for (moho::CEntityDbAllUnitsNode* next = node->parent; next != nullptr && next->isNil == 0u; next = next->parent) {
        if (node != next->right) {
          return next;
        }
        node = next;
      }
      return (node != nullptr) ? node->parent : nullptr;
    }

    moho::CEntityDbAllUnitsNode* next = childOrParent->left;
    while (next != nullptr && next->isNil == 0u) {
      childOrParent = next;
      next = next->left;
    }
    return childOrParent;
  }

  [[nodiscard]] moho::Unit* DecodeAllUnitsIteratorPayload(
    const moho::CEntityDbAllUnitsNode* const node
  ) noexcept
  {
    if (node == nullptr || node->unitListNode == nullptr) {
      return nullptr;
    }

    const auto encodedNode = reinterpret_cast<std::uintptr_t>(node->unitListNode);
    if (encodedNode < 0x8u) {
      return nullptr;
    }

    return reinterpret_cast<moho::Unit*>(encodedNode - 0x8u);
  }

  /**
   * Address: 0x006887D0 (FUN_006887D0)
   *
   * IDA signature:
   * void __stdcall sub_6887D0(void *node);
   *
   * What it does:
   * Post-order recursive destroy pass over one `CEntityDbAllUnitsNode`
   * sentinel-RB subtree: for each non-sentinel node it first recursively
   * destroys the right child (`v2[2]` in the decomp, `right` at offset
   * 0x08), then advances the working cursor to the left child (`*v2`,
   * `left` at offset 0x00), releases the previous node storage, and
   * repeats until the `isNil` byte (offset 0x15) is set.
   *
   * Reached directly from `CEntityDb::~CEntityDb`'s `mAllUnits` teardown,
   * matching the exact recursive shape the original 2007 destructor used.
   */
  void DestroyAllUnitsSubtreeRecursive(moho::CEntityDbAllUnitsNode* node) noexcept
  {
    while (node != nullptr && node->isNil == 0u) {
      DestroyAllUnitsSubtreeRecursive(node->right);
      moho::CEntityDbAllUnitsNode* const leftChild = node->left;
      ::operator delete(node);
      node = leftChild;
    }
  }

  /**
   * Address: 0x005C8A20 (FUN_005C8A20)
   *
   * IDA signature:
   * std::map_EntId_Entity::_Node *__usercall sub_5C8A20@<eax>(
   *     std::map_EntId_Entity::_Node *node@<eax>);
   *
   * What it does:
   * Walks one all-units node's left-child chain and returns the last
   * non-sentinel lane reached (dinkumware `std::_Tree::_Min`).
   */
  [[nodiscard]] moho::CEntityDbAllUnitsNode* DescendAllUnitsLeftChainRuntime(moho::CEntityDbAllUnitsNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    moho::CEntityDbAllUnitsNode* cursor = node->left;
    if (cursor != nullptr && cursor->isNil == 0u) {
      do {
        node = cursor;
        cursor = cursor->left;
      } while (cursor->isNil == 0u);
    }
    return node;
  }

  /**
   * Address: 0x00686390 (FUN_00686390)
   *
   * IDA signature:
   * std::map_EntId_Entity::_Node *__usercall sub_686390@<eax>(
   *     std::map_EntId_Entity::_Node *node@<eax>);
   *
   * What it does:
   * Walks one all-units node's right-child chain and returns the last
   * non-sentinel lane reached (dinkumware `std::_Tree::_Max`).
   */
  [[nodiscard]] moho::CEntityDbAllUnitsNode* DescendAllUnitsRightChainRuntime(moho::CEntityDbAllUnitsNode* node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    for (moho::CEntityDbAllUnitsNode* cursor = node->right; cursor != nullptr && cursor->isNil == 0u;
         cursor = cursor->right) {
      node = cursor;
    }
    return node;
  }

  /**
   * Address: 0x00686340 (FUN_00686340)
   *
   * IDA signature:
   * _DWORD *__thiscall sub_686340(_DWORD *this, int a2);
   *
   * ICF note: the linker folds every `std::_Tree<...>::_Lrotate`
   * instantiation whose node layout matches this project's sentinel-node
   * convention (`left@0/parent@4/right@8/isNil@0x15`) onto this one address.
   * This recovery covers the `CEntityDbAllUnitsNode` instantiation exercised
   * by `EraseAllUnitsTreeNode` below (verified caller: FUN_00685410, second
   * caller FUN_00686190 belongs to an unrelated tree and is out of scope
   * here).
   *
   * What it does:
   * Standard red-black left rotation around `node`, re-pointing the tree's
   * root link (`entityDb->mAllUnits->parent`) when `node` was the root.
   */
  moho::CEntityDbAllUnitsNode* RotateAllUnitsNodeLeft(
    moho::CEntityDbAllUnitsNode* const node,
    moho::CEntityDb* const entityDb
  ) noexcept
  {
    moho::CEntityDbAllUnitsNode* const pivot = node->right;
    node->right = pivot->left;
    if (pivot->left->isNil == 0u) {
      pivot->left->parent = node;
    }
    pivot->parent = node->parent;

    moho::CEntityDbAllUnitsNode* const head = entityDb->mAllUnits;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x006863C0 (FUN_006863C0)
   *
   * IDA signature:
   * int __thiscall sub_6863C0(_DWORD *this, int a2);
   *
   * ICF note: see `RotateAllUnitsNodeLeft`; same folding pattern, mirrored
   * rotation.
   *
   * What it does:
   * Standard red-black right rotation around `node`.
   */
  moho::CEntityDbAllUnitsNode* RotateAllUnitsNodeRight(
    moho::CEntityDbAllUnitsNode* const node,
    moho::CEntityDb* const entityDb
  ) noexcept
  {
    moho::CEntityDbAllUnitsNode* const pivot = node->left;
    node->left = pivot->right;
    if (pivot->right->isNil == 0u) {
      pivot->right->parent = node;
    }
    pivot->parent = node->parent;

    moho::CEntityDbAllUnitsNode* const head = entityDb->mAllUnits;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
    return pivot;
  }

  /**
   * Address: 0x00685410 (FUN_00685410)
   *
   * IDA signature:
   * int *__stdcall sub_685410(Moho::EntityDB *a1, std::map_EntId_Entity::_Node **a2,
   *     Moho::CUnitIterAllArmies a3);
   *
   * IDA typing note: the decompiler infers a 12-byte `CUnitIterAllArmies`
   * parameter for `a3` and separately mistypes the erased-node pointer as
   * `Moho::EntityDB*` (`a1a`) in the red-black fixup section, reading a
   * `mIdPool._Mysize` byte that is really the SAME register still holding
   * the erased tree node -- i.e. `a1a->mIdPool` at that point in the
   * pseudocode is really `erasedNode->color` (offset `+0x14`), not a real
   * `EntityDB::mIdPool` access. The raw disassembly resolves both
   * ambiguities: `retn 0Ch` pops exactly 3 caller-pushed dwords, and the
   * caller (FUN_00686EF0) pushes exactly one dword for the third argument,
   * so `a3` is a bare `CEntityDbAllUnitsNode*` node to erase, not a
   * struct-by-value iterator; and the "Next" call at the top is the plain
   * successor walk already recovered as `NextNodeInAllUnitsTree` (shared,
   * ICF-folded address 0x005C87A0).
   *
   * What it does:
   * Unlinks and destroys `erased` from the `mAllUnits` RB-tree, returning
   * its in-order successor. Transplants the successor into the erased
   * node's slot when both subtrees exist, then repairs the black-height
   * deficit from the stitched-up child upward. MSVC8
   * `std::_Tree<EntId, Entity*>::erase(iterator)` specialized for
   * `CEntityDbAllUnitsNode` (`color` at `+0x14`, `isNil` at `+0x15`).
   *
   * Throws `std::out_of_range` when `erased` is the header sentinel
   * (matches the binary's "invalid map/set<T> iterator" guard).
   */
  moho::CEntityDbAllUnitsNode* EraseAllUnitsTreeNode(
    moho::CEntityDb* const entityDb,
    moho::CEntityDbAllUnitsNode* const erased
  )
  {
    if (erased->isNil != 0u) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    moho::CEntityDbAllUnitsNode* const next = NextNodeInAllUnitsTree(erased);

    moho::CEntityDbAllUnitsNode* lifted = erased;
    moho::CEntityDbAllUnitsNode* fix = nullptr;
    moho::CEntityDbAllUnitsNode* fixParent = nullptr;

    if (erased->left->isNil != 0u) {
      fix = erased->right;
    } else if (erased->right->isNil != 0u) {
      fix = erased->left;
    } else {
      lifted = next;
      fix = lifted->right;
    }

    moho::CEntityDbAllUnitsNode* const head = entityDb->mAllUnits;

    if (lifted == erased) {
      fixParent = erased->parent;
      if (fix->isNil == 0u) {
        fix->parent = fixParent;
      }

      if (head->parent == erased) {
        head->parent = fix;
      } else if (fixParent->left == erased) {
        fixParent->left = fix;
      } else {
        fixParent->right = fix;
      }

      if (head->left == erased) {
        head->left = (fix->isNil != 0u) ? fixParent : DescendAllUnitsLeftChainRuntime(fix);
      }
      if (head->right == erased) {
        head->right = (fix->isNil != 0u) ? fixParent : DescendAllUnitsRightChainRuntime(fix);
      }
    } else {
      erased->left->parent = lifted;
      lifted->left = erased->left;

      if (lifted == erased->right) {
        fixParent = lifted;
      } else {
        fixParent = lifted->parent;
        if (fix->isNil == 0u) {
          fix->parent = fixParent;
        }
        fixParent->left = fix;
        lifted->right = erased->right;
        erased->right->parent = lifted;
      }

      if (head->parent == erased) {
        head->parent = lifted;
      } else if (erased->parent->left == erased) {
        erased->parent->left = lifted;
      } else {
        erased->parent->right = lifted;
      }

      lifted->parent = erased->parent;
      std::swap(lifted->color, erased->color);
    }

    if (erased->color == 1u) {
      moho::CEntityDbAllUnitsNode* fixCursor = fix;
      moho::CEntityDbAllUnitsNode* fixParentCursor = fixParent;
      while (fixCursor != head->parent && fixCursor->color == 1u) {
        if (fixCursor == fixParentCursor->left) {
          moho::CEntityDbAllUnitsNode* sibling = fixParentCursor->right;
          if (sibling->color == 0u) {
            sibling->color = 1u;
            fixParentCursor->color = 0u;
            (void)RotateAllUnitsNodeLeft(fixParentCursor, entityDb);
            sibling = fixParentCursor->right;
          }

          if (sibling->isNil != 0u) {
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else if (sibling->left->color == 1u && sibling->right->color == 1u) {
            sibling->color = 0u;
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else {
            if (sibling->right->color == 1u) {
              sibling->left->color = 1u;
              sibling->color = 0u;
              (void)RotateAllUnitsNodeRight(sibling, entityDb);
              sibling = fixParentCursor->right;
            }
            sibling->color = fixParentCursor->color;
            fixParentCursor->color = 1u;
            sibling->right->color = 1u;
            (void)RotateAllUnitsNodeLeft(fixParentCursor, entityDb);
            fixCursor = head->parent;
            break;
          }
        } else {
          moho::CEntityDbAllUnitsNode* sibling = fixParentCursor->left;
          if (sibling->color == 0u) {
            sibling->color = 1u;
            fixParentCursor->color = 0u;
            (void)RotateAllUnitsNodeRight(fixParentCursor, entityDb);
            sibling = fixParentCursor->left;
          }

          if (sibling->isNil != 0u) {
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else if (sibling->right->color == 1u && sibling->left->color == 1u) {
            sibling->color = 0u;
            fixCursor = fixParentCursor;
            fixParentCursor = fixCursor->parent;
          } else {
            if (sibling->left->color == 1u) {
              sibling->right->color = 1u;
              sibling->color = 0u;
              (void)RotateAllUnitsNodeLeft(sibling, entityDb);
              sibling = fixParentCursor->left;
            }
            sibling->color = fixParentCursor->color;
            fixParentCursor->color = 1u;
            sibling->left->color = 1u;
            (void)RotateAllUnitsNodeRight(fixParentCursor, entityDb);
            fixCursor = head->parent;
            break;
          }
        }
      }
      fixCursor->color = 1u;
    }

    ::operator delete(erased);
    if (entityDb->mAllUnitsSize != 0u) {
      --entityDb->mAllUnitsSize;
    }
    return next;
  }

  /**
   * Address: 0x00686EF0 (FUN_00686EF0)
   *
   * IDA signature:
   * int *__userpurge sub_686EF0@<eax>(Moho::EntityDB *a1@<edi>, int *arg0,
   *     Moho::Unit *a3, Moho::Unit *a3_4);
   *
   * IDA typing note: the decompiler types `a3`/`a3_4` as `Moho::Unit*` and
   * reads a `__vftable_unit`-shaped field from the same base pointer that
   * the loop branch treats as a raw `std::map_EntId_Entity::_Node*`
   * sentinel (`_Myhead`, `_Left`, `_Right`, `_Parent`). Both readings are
   * the SAME pointer: the `mAllUnits` RB-tree head/leftmost sentinel,
   * misattributed to `Moho::Unit` because the decompiler's type inference
   * for this register leaked in from an unrelated branch. Confirmed from
   * the raw disassembly: `a3`/`a3_4` are compared directly against
   * `entityDb->mAllUnits` and `entityDb->mAllUnits->left` -- real
   * `CEntityDbAllUnitsNode*` iterators, never a `Moho::Unit*`.
   *
   * What it does:
   * Erases `[first, last)` from the `mAllUnits` RB-tree. Takes the O(1)
   * whole-tree fast path (recursive subtree destroy + sentinel reset) when
   * erasing the full range (`first == begin() && last == end()`);
   * otherwise advances to each node's successor before erasing it, so the
   * walk stays valid across the erase. MSVC8
   * `std::_Tree<EntId, Entity*>::erase(iterator, iterator)`.
   */
  moho::CEntityDbAllUnitsNode* EraseAllUnitsTreeRange(
    moho::CEntityDb* const entityDb,
    moho::CEntityDbAllUnitsNode** const outPosition,
    moho::CEntityDbAllUnitsNode* const first,
    moho::CEntityDbAllUnitsNode* const last
  )
  {
    moho::CEntityDbAllUnitsNode* const head = entityDb->mAllUnits;
    moho::CEntityDbAllUnitsNode* cursor = first;

    if (first == head->left && last == head) {
      DestroyAllUnitsSubtreeRecursive(head->parent);
      head->parent = head;
      entityDb->mAllUnitsSize = 0u;
      head->left = head;
      head->right = head;
      *outPosition = head;
      return *outPosition;
    }

    if (first != last) {
      do {
        moho::CEntityDbAllUnitsNode* const erasing = cursor;
        cursor = NextNodeInAllUnitsTree(cursor);
        (void)EraseAllUnitsTreeNode(entityDb, erasing);
      } while (cursor != last);
    }

    *outPosition = cursor;
    return *outPosition;
  }

  /**
   * Address: 0x00687BC0 (FUN_00687BC0, sub_687BC0)
   *
   * What it does:
   * Raw node allocator only (left/parent/right left null); the immediate
   * caller (InitializeAllUnitsTreeHeadLane below) overwrites isNil=1 and
   * self-links left/parent/right, matching the binary's split shape.
   */
  [[nodiscard]] moho::CEntityDbAllUnitsNode* AllocateAllUnitsTreeNode()
  {
    auto* const node = static_cast<moho::CEntityDbAllUnitsNode*>(::operator new(sizeof(moho::CEntityDbAllUnitsNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = 1u;
    node->isNil = 0u;
    return node;
  }

  struct CEntityDbAllUnitsTreeRuntime
  {
    std::uint32_t iteratorProxy;
    moho::CEntityDbAllUnitsNode* head;
    std::uint32_t size;
  };
  static_assert(sizeof(CEntityDbAllUnitsTreeRuntime) == 0x0C, "CEntityDbAllUnitsTreeRuntime size must be 0x0C");
  static_assert(offsetof(CEntityDbAllUnitsTreeRuntime, head) == 0x04, "CEntityDbAllUnitsTreeRuntime::head offset must be 0x04");
  static_assert(offsetof(CEntityDbAllUnitsTreeRuntime, size) == 0x08, "CEntityDbAllUnitsTreeRuntime::size offset must be 0x08");

  /**
   * Address: 0x006852E0 (FUN_006852E0)
   * Address: 0x00686150 (FUN_00686150)
   *
   * What it does:
   * Allocates one all-units tree head node, marks it sentinel/self-linked, and
   * clears the tree-size lane.
   */
  CEntityDbAllUnitsTreeRuntime* InitializeAllUnitsTreeHeadLane(
    CEntityDbAllUnitsTreeRuntime* const tree
  ) noexcept
  {
    if (tree == nullptr) {
      return nullptr;
    }

    tree->head = AllocateAllUnitsTreeNode();
    tree->head->isNil = 1u;
    tree->head->parent = tree->head;
    tree->head->left = tree->head;
    tree->head->right = tree->head;
    tree->size = 0u;
    return tree;
  }

  /**
   * Address: 0x00686FB0 (FUN_00686FB0)
   *
   * What it does:
   * Initializes one all-units tree head lane and returns the allocated
   * sentinel-head node pointer.
   */
  moho::CEntityDbAllUnitsNode* InitializeAllUnitsTreeHeadLaneReturnHead(
    CEntityDbAllUnitsTreeRuntime* const tree
  ) noexcept
  {
    CEntityDbAllUnitsTreeRuntime* const initialized = InitializeAllUnitsTreeHeadLane(tree);
    return initialized != nullptr ? initialized->head : nullptr;
  }


  [[nodiscard]] moho::CEntityDbListHead* AllocateEntityListHeadNode()
  {
    auto* const head = static_cast<moho::CEntityDbListHead*>(::operator new(sizeof(moho::CEntityDbListHead)));
    head->next = head;
    head->prev = head;
    return head;
  }

  void ClearEntityListNodes(moho::CEntityDbListHead* const head) noexcept;

  /**
   * Address: 0x006868C0 (FUN_006868C0)
   *
   * What it does:
   * Appends one bounded-prop queue record to contiguous storage, preserving
   * the record payload and returning a pointer to the stored element.
   */
  [[nodiscard]] BoundedPropQueueEntry*
  AppendBoundedPropQueueEntry(msvc8::vector<BoundedPropQueueEntry>& entries, const BoundedPropQueueEntry& entry)
  {
    entries.push_back(entry);
    return &entries.back();
  }

  void DestroyBoundedPropQueueNodeRange(
    moho::CEntityDbBoundedPropQueueNode* begin,
    moho::CEntityDbBoundedPropQueueNode* const end
  ) noexcept
  {
    while (begin != nullptr && begin != end) {
      if (begin->mLinkBackRef != nullptr) {
        moho::CEntityDbBoundedPropQueueNode** const backRef = begin->mLinkBackRef;
        if (*backRef == begin) {
          *backRef = begin->mLinkNext;
        }
      }

      if (begin->mLinkNext != nullptr) {
        begin->mLinkNext->mLinkBackRef = begin->mLinkBackRef;
      }

      begin->mLinkBackRef = nullptr;
      begin->mLinkNext = nullptr;
      ++begin;
    }
  }

  struct BackRefListNodeRuntime
  {
    BackRefListNodeRuntime* next;
    BackRefListNodeRuntime** backRef;
  };
  static_assert(sizeof(BackRefListNodeRuntime) == 0x08, "BackRefListNodeRuntime size must be 0x08");

  struct BackRefListOwnerRuntime
  {
    std::uint32_t iteratorProxy;
    BackRefListNodeRuntime* head;
    std::uint32_t size;
  };
  static_assert(sizeof(BackRefListOwnerRuntime) == 0x0C, "BackRefListOwnerRuntime size must be 0x0C");

  /**
   * Address: 0x00685950 (FUN_00685950)
   *
   * What it does:
   * Unlinks one back-reference node lane from owner storage, optionally frees
   * the removed node, and returns the next node lane through `outNextNode`.
   */
  BackRefListNodeRuntime** EraseBackRefListNodeAndStoreNext(
    BackRefListNodeRuntime** const outNextNode,
    BackRefListOwnerRuntime* const owner,
    BackRefListNodeRuntime* const node
  ) noexcept
  {
    BackRefListNodeRuntime* const nextNode = node != nullptr ? node->next : nullptr;

    if (owner != nullptr && node != nullptr && node != owner->head) {
      if (node->backRef != nullptr) {
        *node->backRef = nextNode;
      }
      if (nextNode != nullptr) {
        nextNode->backRef = node->backRef;
      }

      ::operator delete(node);
      --owner->size;
    }

    if (outNextNode != nullptr) {
      *outNextNode = nextNode;
    }
    return outNextNode;
  }

  /**
   * Address: 0x00685980 (FUN_00685980)
   *
   * What it does:
   * Resets bounded-prop queue pointer lanes to empty state and seeds
   * `lastHandle` to `-1`.
   */
  void InitializeBoundedPropQueueLane(moho::CEntityDbBoundedPropQueueRuntime& queue) noexcept
  {
    queue.start = nullptr;
    queue.end = nullptr;
    queue.capacity = nullptr;
    queue.storageBegin = nullptr;
    queue.storageCurrent = nullptr;
    queue.storageEnd = nullptr;
    queue.lastHandle = -1;
  }

  /**
   * Address: 0x00684360 (FUN_00684360)
   *
   * What it does:
   * Releases the bounded-prop queue lanes, unlinks each intrusive queue node
   * from its link chain, and clears the legacy buffer pointers.
   */
  void ResetBoundedPropQueueLane(moho::CEntityDbBoundedPropQueueRuntime& queue) noexcept
  {
    DestroyBoundedPropQueueNodeRange(queue.start, queue.end);
    if (queue.start != nullptr) {
      ::operator delete(queue.start);
    }

    if (queue.storageBegin) {
      ::operator delete(queue.storageBegin);
    }

    queue.start = nullptr;
    queue.end = nullptr;
    queue.capacity = nullptr;
    queue.storageBegin = nullptr;
    queue.storageCurrent = nullptr;
    queue.storageEnd = nullptr;
  }

  /**
   * Address: 0x00685BA0 (FUN_00685BA0)
   * Address: 0x00685BE0 (FUN_00685BE0)
   * Address: 0x00685C20 (FUN_00685C20)
   * Address: 0x00685C60 (FUN_00685C60)
   *
   * What it does:
   * Register-shape adapter that advances one all-armies iterator object and
   * returns the same iterator pointer.
   */
  moho::CUnitIterAllArmies* AdvanceAllArmiesIteratorLane(
    moho::CUnitIterAllArmies* const iterator
  ) noexcept
  {
    if (iterator != nullptr) {
      iterator->Next();
    }
    return iterator;
  }

  /**
   * Address: 0x00687C30 (FUN_00687C30)
   *
   * What it does:
   * Stores the current all-armies iterator node lane into `outIterator`, then
   * advances the iterator with `Next()` and returns `outIterator`.
   */
  moho::CEntityDbAllUnitsNode** StoreAndAdvanceAllArmiesIteratorPostIncrement(
    moho::CUnitIterAllArmies* const iterator,
    moho::CEntityDbAllUnitsNode** const outIterator
  ) noexcept
  {
    *outIterator = iterator->mItr;
    iterator->Next();
    return outIterator;
  }

  /**
   * Address: 0x00684310 (FUN_00684310)
   *
   * What it does:
   * Destroys the entity-list sentinel head, releases each tracked node, and
   * clears the cached head/size lanes.
   */
  void DestroyEntityListRuntime(moho::CEntityDbEntityListRuntime& entityList) noexcept
  {
    if (!entityList.head) {
      return;
    }

    ClearEntityListNodes(entityList.head);
    ::operator delete(entityList.head);
    entityList.head = nullptr;
    entityList.size = 0u;
  }

  void ClearEntityListNodes(moho::CEntityDbListHead* const head) noexcept
  {
    if (!head) {
      return;
    }

    for (moho::CEntityDbListHead* node = head->next; node && node != head;) {
      moho::CEntityDbListHead* const next = node->next;
      ::operator delete(node);
      node = next;
    }

    head->next = head;
    head->prev = head;
  }

  using RegisteredEntitySetList = moho::TDatList<moho::EntitySetBase, void>;

  [[nodiscard]] RegisteredEntitySetList& AccessRegisteredEntitySetList(moho::CEntityDb& entityDb) noexcept
  {
    return *reinterpret_cast<RegisteredEntitySetList*>(&entityDb.mRegisteredEntitySets);
  }

  void PurgeRegisteredEntitySets(moho::CEntityDb& entityDb)
  {
    RegisteredEntitySetList& registry = AccessRegisteredEntitySetList(entityDb);
    for (auto* node = registry.mNext; node != &registry; node = node->mNext) {
      auto* const entitySet = static_cast<moho::EntitySetBase*>(static_cast<void*>(node));
      auto& entities = entitySet->mVec;
      for (auto it = entities.begin(); it != entities.end();) {
        moho::Entity* const entity = *it;
        if (entity != nullptr && entity->mOnDestroyDispatched == 0u) {
          ++it;
          continue;
        }

        it = entities.erase(it, it + 1);
      }
    }
  }

  void PurgeTrackedEntities(msvc8::list<moho::Entity*>& entities)
  {
    for (auto it = entities.begin(); it != entities.end();) {
      moho::Entity* const entity = *it;
      it = entities.erase(it);
      if (entity != nullptr) {
        delete entity;
      }
    }
  }

  void AdvanceRuntimeIdPools(moho::CEntityDb& entityDb)
  {
    auto poolsIt = gRuntimePools.find(&entityDb);
    if (poolsIt == gRuntimePools.end()) {
      return;
    }

    for (auto& [familySourceBits, pool] : poolsIt->second) {
      (void)familySourceBits;

      moho::IdPool mirroredPool{};
      mirroredPool.mNextLowId = static_cast<std::int32_t>(pool.mNextSerial);
      mirroredPool.mReleasedLows = pool.mReleasedSerials;
      mirroredPool.Update();

      const std::uint32_t mirroredNextSerial = static_cast<std::uint32_t>(mirroredPool.mNextLowId);
      pool.mNextSerial = mirroredNextSerial == 0u ? 1u : mirroredNextSerial;
      pool.mReleasedSerials = mirroredPool.mReleasedLows;
    }
  }

  [[nodiscard]] bool
  IdExistsInList(const msvc8::list<moho::Entity*>& entities, const std::uint32_t entityIdCandidate) noexcept
  {
    for (const moho::Entity* const entity : entities) {
      if (!entity) {
        continue;
      }

      if (static_cast<std::uint32_t>(entity->id_) == entityIdCandidate) {
        return true;
      }
    }

    return false;
  }

  void SeedFamilyPoolFromEntities(
    const msvc8::list<moho::Entity*>& entities, const std::uint32_t familySourceBits, IdPoolRuntime& pool
  )
  {
    if (pool.mSeededFromEntityDb) {
      return;
    }

    std::uint32_t maxSerial = 0u;
    for (const moho::Entity* const entity : entities) {
      if (!entity) {
        continue;
      }

      const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
      if ((entityId & kEntityIdFamilySourceMaskRaw) != familySourceBits) {
        continue;
      }

      const std::uint32_t serial = entityId & kEntityIdSerialMask;
      if (serial > maxSerial) {
        maxSerial = serial;
      }
    }

    pool.mNextSerial = maxSerial + 1u;
    if ((pool.mNextSerial & kEntityIdSerialMask) == 0u) {
      pool.mNextSerial = 1u;
    }

    pool.mSeededFromEntityDb = true;
  }

  [[nodiscard]] std::uint32_t AllocateSerialFromFamilyPool(IdPoolRuntime& pool)
  {
    if (pool.mReleasedSerials.Buckets() != 0) {
      const std::uint32_t serial = pool.mReleasedSerials.GetNext(std::numeric_limits<std::uint32_t>::max());
      if (serial < pool.mReleasedSerials.Max() && pool.mReleasedSerials.Remove(serial)) {
        return serial;
      }
    }

    for (;;) {
      const std::uint32_t serial = (pool.mNextSerial++) & kEntityIdSerialMask;
      if (serial != 0u) {
        return serial;
      }
    }
  }

  class EntityDbTypeInfo final : public gpg::RType
  {
  public:
    ~EntityDbTypeInfo() override;

    /**
     * Address: 0x00687920 (FUN_00687920, Moho::EntityDBTypeInfo::NewRef)
     *
     * What it does:
     * Allocates and default-constructs one `CEntityDb`, then wraps it in an
     * `EntityDB` reflection reference.
     */
    [[nodiscard]] static gpg::RRef NewRef();

    /**
     * Address: 0x006879B0 (FUN_006879B0, Moho::EntityDBTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CEntityDb` in caller-provided storage and wraps it in an
     * `EntityDB` reflection reference.
     */
    [[nodiscard]] static gpg::RRef CtrRef(void* objectStorage);

    [[nodiscard]] const char* GetName() const override
    {
      return "EntityDB";
    }

    void Init() override
    {
      newRefFunc_ = &EntityDbTypeInfo::NewRef;
      ctorRefFunc_ = &EntityDbTypeInfo::CtrRef;
      size_ = sizeof(moho::CEntityDb);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(EntityDbTypeInfo) == 0x64, "EntityDbTypeInfo size must be 0x64");

  /**
   * Address: 0x006848C0 (FUN_006848C0, EntityDBTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `EntityDB` type-info
   * object while preserving outer ownership of the instance storage.
   */
  void DestroyEntityDbTypeInfoBody(EntityDbTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  EntityDbTypeInfo::~EntityDbTypeInfo()
  {
    DestroyEntityDbTypeInfoBody(this);
  }

  /**
   * Address: 0x00687920 (FUN_00687920, Moho::EntityDBTypeInfo::NewRef)
   *
   * What it does:
   * Allocates and default-constructs one `CEntityDb`, then wraps it in an
   * `EntityDB` reflection reference.
   */
  gpg::RRef EntityDbTypeInfo::NewRef()
  {
    moho::CEntityDb* entityDb = nullptr;
    if (void* const storage = ::operator new(sizeof(moho::CEntityDb), std::nothrow); storage != nullptr) {
      entityDb = new (storage) moho::CEntityDb();
    }

    gpg::RRef out{};
    (void)gpg::RRef_EntityDB(&out, entityDb);
    return out;
  }

  /**
   * Address: 0x006879B0 (FUN_006879B0, Moho::EntityDBTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CEntityDb` in caller-provided storage and wraps it in an
   * `EntityDB` reflection reference.
   */
  gpg::RRef EntityDbTypeInfo::CtrRef(void* const objectStorage)
  {
    moho::CEntityDb* entityDb = nullptr;
    if (objectStorage != nullptr) {
      entityDb = new (objectStorage) moho::CEntityDb();
    }

    gpg::RRef out{};
    (void)gpg::RRef_EntityDB(&out, entityDb);
    return out;
  }

  extern msvc8::string gEntityDbIdPoolMapTypeName;
  extern std::uint32_t gEntityDbIdPoolMapTypeNameInitGuard;
  void cleanup_EntityDbIdPoolMapTypeName();

  /**
   * Shared `IdPool` RTTI cache lookup, used by `EntityDbIdPoolMapTypeInfo::
   * GetName`/`SerLoad`/`SerSave` (all three resolve the same element type).
   */
  [[nodiscard]] gpg::RType* CachedIdPoolElementType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    return type;
  }

  extern msvc8::string gEntityDbEntityListTypeName;
  extern std::uint32_t gEntityDbEntityListTypeNameInitGuard;
  void cleanup_EntityDbEntityListTypeName();

  class EntityDbIdPoolMapTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006891F0 (FUN_006891F0, gpg::RMapType_uint_IdPool::dtr)
     */
    ~EntityDbIdPoolMapTypeInfo() override;

    /**
     * Address: 0x00685C80 (FUN_00685C80, gpg::RMapType_uint_IdPool::GetName)
     *
     * What it does:
     * Builds/caches one lexical map type label from runtime key/value RTTI
     * names and returns `"map<key,value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gEntityDbIdPoolMapTypeNameInitGuard & 1u) == 0u) {
        gEntityDbIdPoolMapTypeNameInitGuard |= 1u;

        gpg::RType* const valueType = CachedIdPoolElementType();
        gpg::RType* keyType = gpg::LookupRType(typeid(unsigned int));
        const char* const keyName = keyType != nullptr ? keyType->GetName() : "unsigned int";
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "Moho::IdPool";

        gEntityDbIdPoolMapTypeName = gpg::STR_Printf("map<%s,%s>", keyName, valueName);
        (void)std::atexit(&cleanup_EntityDbIdPoolMapTypeName);
      }

      return gEntityDbIdPoolMapTypeName.c_str();
    }

    /**
     * Address: 0x00685D60 (FUN_00685D60, gpg::RMapType_uint_IdPool::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current map element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const map = static_cast<const msvc8::map<std::uint32_t, moho::IdPool>*>(ref.mObj);
      const int size = map ? static_cast<int>(map->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
    }

    /**
     * Address: 0x00685D40 (FUN_00685D40, gpg::RMapType_uint_IdPool::Init)
     *
     * What it does:
     * Sets the reflected object size to the real `map<uint,IdPool>` ABI
     * footprint (12 bytes: `{proxy, head, size}`, matching
     * `msvc8::map<std::uint32_t, IdPool>` exactly -- not the unrelated size a
     * modern `std::map<>` local variable would report) and installs the
     * map's load/save reflection callbacks. The binary writes these two
     * function pointers directly at `this+0x1C`/`this+0x14`; this override
     * assigns the same two members by name.
     */
    void Init() override
    {
      size_ = sizeof(msvc8::map<std::uint32_t, moho::IdPool>);
      version_ = 1;
      serLoadFunc_ = &EntityDbIdPoolMapTypeInfo::SerLoad;
      serSaveFunc_ = &EntityDbIdPoolMapTypeInfo::SerSave;
    }

    /**
     * Address: 0x00686990 (FUN_00686990, std::map_IdPool::Deserialize)
     *
     * What it does:
     * Clears the destination map, reads the element count, then reads and
     * inserts `count` `(key, IdPool)` pairs in archive order. Clearing is
     * `msvc8::map::clear()` (binary: `FUN_00688030` destroys the subtree from
     * the real root, then self-links the header -- see the
     * `rb_tree::destroy_subtree`/`clear()` citations in RbTree.h); each
     * insert is `msvc8::map::insert()`, i.e. `rb_tree::insert_unique()`
     * (`FUN_006870D0`) linking through `insert_at`/`buy_node`/the rotate pair
     * (`FUN_00687280`/`FUN_006881C0`/`FUN_006880A0`/`FUN_00688120`, all cited
     * on their RbTree.h members) exactly as every other `msvc8::map`
     * instantiation in this codebase does -- no per-map reimplementation.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00686B10 (FUN_00686B10, std::map_IdPool::Serialize)
     *
     * What it does:
     * Writes the element count, then walks the map in ascending key order
     * writing each `(key, IdPool)` pair. The walk is `msvc8::map`'s
     * `begin()`/`operator++` (`FUN_006878C0`/its register-shape adapters
     * `FUN_00685FA0`/`FUN_00686CE0`, cited on `rb_increment` in RbTree.h) --
     * no separate iteration mechanic is introduced here.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };
  static_assert(sizeof(EntityDbIdPoolMapTypeInfo) == 0x64, "EntityDbIdPoolMapTypeInfo size must be 0x64");

  /**
   * Address: 0x00688FA0 (FUN_00688FA0, EntityDbIdPoolMapTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `map<uint, IdPool>`
   * type-info object while preserving outer storage ownership.
   */
  void DestroyEntityDbIdPoolMapTypeInfoBody(EntityDbIdPoolMapTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  EntityDbIdPoolMapTypeInfo::~EntityDbIdPoolMapTypeInfo()
  {
    DestroyEntityDbIdPoolMapTypeInfoBody(this);
  }

  /**
   * Address: 0x00686990 (FUN_00686990, std::map_IdPool::Deserialize)
   *
   * What it does:
   * Clears the destination map, reads the element count, then reads and
   * inserts that many `(key, IdPool)` pairs in archive order.
   */
  void EntityDbIdPoolMapTypeInfo::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const map =
      reinterpret_cast<msvc8::map<std::uint32_t, moho::IdPool>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || map == nullptr) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);
    map->clear();

    gpg::RType* const idPoolType = CachedIdPoolElementType();
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    for (unsigned int i = 0; i < count; ++i) {
      std::uint32_t key = 0;
      archive->ReadUInt(&key);

      moho::IdPool pool{};
      archive->Read(idPoolType, &pool, owner);

      (void)map->insert(msvc8::map<std::uint32_t, moho::IdPool>::value_type(key, std::move(pool)));
    }
  }

  /**
   * Address: 0x00686B10 (FUN_00686B10, std::map_IdPool::Serialize)
   *
   * What it does:
   * Writes the element count, then walks the map in ascending key order
   * writing each `(key, IdPool)` pair.
   */
  void EntityDbIdPoolMapTypeInfo::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const map =
      reinterpret_cast<const msvc8::map<std::uint32_t, moho::IdPool>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || map == nullptr) {
      return;
    }

    archive->WriteUInt(static_cast<unsigned int>(map->size()));

    gpg::RType* const idPoolType = CachedIdPoolElementType();
    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    for (const auto& [key, pool] : *map) {
      archive->WriteUInt(key);
      archive->Write(idPoolType, &pool, owner);
    }
  }

  class EntityDbEntityListTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00689250 (FUN_00689250, gpg::RListType_EntityP::dtr)
     */
    ~EntityDbEntityListTypeInfo() override;

    /**
     * Address: 0x00685DF0 (FUN_00685DF0, gpg::RListType_EntityP::GetName)
     *
     * What it does:
     * Builds/caches one lexical list type label from runtime `Entity*` RTTI
     * and returns `"list<value>"`.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if ((gEntityDbEntityListTypeNameInitGuard & 1u) == 0u) {
        gEntityDbEntityListTypeNameInitGuard |= 1u;

        gpg::RType* const valueType = gpg::LookupRType(typeid(moho::Entity*));
        const char* const valueName = valueType != nullptr ? valueType->GetName() : "Entity *";
        gEntityDbEntityListTypeName = gpg::STR_Printf("list<%s>", valueName ? valueName : "Entity *");
        (void)std::atexit(&cleanup_EntityDbEntityListTypeName);
      }

      return gEntityDbEntityListTypeName.c_str();
    }

    /**
     * Address: 0x00685E90 (FUN_00685E90, gpg::RListType_EntityP::GetLexical)
     *
     * What it does:
     * Formats inherited lexical text and appends current list element count.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      const auto* const list = static_cast<const std::list<moho::Entity*>*>(ref.mObj);
      const int size = list ? static_cast<int>(list->size()) : 0;
      return gpg::STR_Printf("%s, size=%d", base.c_str(), size);
    }

    /**
     * Address: 0x00685E70 (FUN_00685E70, gpg::RListType_EntityP::Init)
     *
     * What it does:
     * Configures reflected `list<Entity*>` layout/version lanes and installs
     * list serializer callbacks.
     */
    void Init() override
    {
      size_ = sizeof(std::list<moho::Entity*>);
      version_ = 1;
      serLoadFunc_ = &EntityDbEntityListTypeInfo::SerLoad;
      serSaveFunc_ = &EntityDbEntityListTypeInfo::SerSave;
    }

    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };
  static_assert(sizeof(EntityDbEntityListTypeInfo) == 0x64, "EntityDbEntityListTypeInfo size must be 0x64");

  /**
   * Address: 0x00688FE0 (FUN_00688FE0, EntityDbEntityListTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `list<Entity*>`
   * type-info object while preserving outer storage ownership.
   */
  void DestroyEntityDbEntityListTypeInfoBody(EntityDbEntityListTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  EntityDbEntityListTypeInfo::~EntityDbEntityListTypeInfo()
  {
    DestroyEntityDbEntityListTypeInfoBody(this);
  }

  /**
   * Address: 0x00686B90 (FUN_00686B90, gpg::RListType_EntityP::SerLoad)
   *
   * What it does:
   * Clears one reflected `list<Entity*>`, reads element count, then
   * deserializes each tracked entity pointer in archive order.
   */
  void EntityDbEntityListTypeInfo::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const list = reinterpret_cast<std::list<moho::Entity*>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || list == nullptr) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);
    list->clear();

    gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      moho::Entity* entity = nullptr;
      (void)archive->ReadPointer_Entity(&entity, &owner);
      list->push_back(entity);
    }
  }

  /**
   * Address: 0x00686C10 (FUN_00686C10, gpg::RListType_EntityP::SerSave)
   *
   * What it does:
   * Writes reflected `list<Entity*>` element count, then serializes each
   * entity pointer in list traversal order as an unowned tracked pointer.
   */
  void EntityDbEntityListTypeInfo::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const list = reinterpret_cast<const std::list<moho::Entity*>*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr) {
      return;
    }

    const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
    archive->WriteUInt(count);
    if (list == nullptr) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (moho::Entity* const entity : *list) {
      gpg::RRef entityRef{};
      (void)gpg::RRef_Entity(&entityRef, entity);
      gpg::WriteRawPointer(archive, entityRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  alignas(EntityDbTypeInfo) std::byte gEntityDbTypeInfoStorage[sizeof(EntityDbTypeInfo)]{};
  bool gEntityDbTypeInfoConstructed = false;
  alignas(EntityDbIdPoolMapTypeInfo) std::byte gEntityDbIdPoolMapTypeInfoStorage[sizeof(EntityDbIdPoolMapTypeInfo)]{};
  bool gEntityDbIdPoolMapTypeInfoConstructed = false;
  msvc8::string gEntityDbIdPoolMapTypeName{};
  std::uint32_t gEntityDbIdPoolMapTypeNameInitGuard = 0u;
  msvc8::string gEntityDbEntityListTypeName{};
  std::uint32_t gEntityDbEntityListTypeNameInitGuard = 0u;
  alignas(EntityDbEntityListTypeInfo)
    std::byte gEntityDbEntityListTypeInfoStorage[sizeof(EntityDbEntityListTypeInfo)]{};
  bool gEntityDbEntityListTypeInfoConstructed = false;

  /**
   * Address: 0x00BFCB90 (FUN_00BFCB90)
   *
   * What it does:
   * Releases cached lexical storage for `gpg::RMapType_uint_IdPool::GetName`.
   */
  void cleanup_EntityDbIdPoolMapTypeName()
  {
    gEntityDbIdPoolMapTypeName.clear();
    gEntityDbIdPoolMapTypeNameInitGuard = 0u;
  }

  /**
   * Address: 0x00685DF0 (FUN_00685DF0, gpg::RListType_EntityP::GetName)
   *
   * What it does:
   * Releases cached lexical storage for `gpg::RListType_EntityP::GetName`.
   */
  void cleanup_EntityDbEntityListTypeName()
  {
    gEntityDbEntityListTypeName.clear();
    gEntityDbEntityListTypeNameInitGuard = 0u;
  }

  [[nodiscard]] EntityDbTypeInfo& AcquireEntityDbTypeInfo()
  {
    if (!gEntityDbTypeInfoConstructed) {
      new (gEntityDbTypeInfoStorage) EntityDbTypeInfo();
      gEntityDbTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbTypeInfo*>(gEntityDbTypeInfoStorage);
  }

  [[nodiscard]] EntityDbIdPoolMapTypeInfo& AcquireEntityDbIdPoolMapTypeInfo()
  {
    if (!gEntityDbIdPoolMapTypeInfoConstructed) {
      new (gEntityDbIdPoolMapTypeInfoStorage) EntityDbIdPoolMapTypeInfo();
      gEntityDbIdPoolMapTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbIdPoolMapTypeInfo*>(gEntityDbIdPoolMapTypeInfoStorage);
  }

  [[nodiscard]] EntityDbEntityListTypeInfo& AcquireEntityDbEntityListTypeInfo()
  {
    if (!gEntityDbEntityListTypeInfoConstructed) {
      new (gEntityDbEntityListTypeInfoStorage) EntityDbEntityListTypeInfo();
      gEntityDbEntityListTypeInfoConstructed = true;
    }
    return *reinterpret_cast<EntityDbEntityListTypeInfo*>(gEntityDbEntityListTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00684230 (FUN_00684230, Moho::EntityDB::EntityDB)
   *
   * `mIdPoolTree`'s sentinel-head allocate/self-link/isNil=1 sequence, inlined
   * here in the binary via the raw node allocator (`FUN_00688180`, cited on
   * `rb_tree::alloc_raw` in RbTree.h) rather than a named `buy_head` symbol,
   * is now `msvc8::map<std::uint32_t, IdPool>`'s own default constructor --
   * see the `buy_head()` citation on that member in RbTree.h. No source-level
   * call is needed here; member default-initialization runs it automatically.
   */
  CEntityDb::CEntityDb()
  {
    mAllUnits = AllocateAllUnitsTreeNode();
    mAllUnits->isNil = 1u;
    mAllUnits->parent = mAllUnits;
    mAllUnits->left = mAllUnits;
    mAllUnits->right = mAllUnits;
    mAllUnitsSize = 0u;

    (void)ResetEntityDbListHeadToSelf(&mRegisteredEntitySets);

    mEntityList.head = AllocateEntityListHeadNode();
    mEntityList.size = 0u;

    InitializeBoundedPropQueueLane(mBoundedProps);
  }

  /**
   * Address: 0x006843B0 (FUN_006843B0, Moho::EntityDB::~EntityDB)
   *
   * `mIdPoolTree`'s teardown -- recursive subtree destroy from the tree's
   * root (`FUN_00688030`, cited on `rb_tree::destroy_subtree` in RbTree.h),
   * then release the sentinel head -- is now `msvc8::map<std::uint32_t,
   * IdPool>`'s own destructor (see the `~rb_tree()` citation on that member),
   * run automatically by member destruction right after this body returns.
   * (A prior hand-rolled version of this teardown recursed from
   * `mIdPoolTree.head->left`, i.e. leftmost(), instead of `head->parent`
   * (root) -- a genuine bug that would have destroyed at most one node and
   * leaked the rest; `sub_688030`'s real argument, confirmed from
   * `std::map_IdPool::Deserialize`'s call site, is `head->parent`. The
   * container's own destructor does not have that bug.)
   */
  CEntityDb::~CEntityDb()
  {
    ResetBoundedPropQueueLane(mBoundedProps);

    DestroyEntityListRuntime(mEntityList);

    if (mRegisteredEntitySets.next && mRegisteredEntitySets.prev) {
      mRegisteredEntitySets.prev->next = mRegisteredEntitySets.next;
      mRegisteredEntitySets.next->prev = mRegisteredEntitySets.prev;
    }
    (void)ResetEntityDbListHeadToSelf(&mRegisteredEntitySets);

    if (mAllUnits != nullptr) {
      DestroyAllUnitsSubtreeRecursive(mAllUnits->left);
      mAllUnits->parent = mAllUnits;
      mAllUnits->left = mAllUnits;
      mAllUnits->right = mAllUnits;
    }
    ::operator delete(mAllUnits);
    mAllUnits = nullptr;
    mAllUnitsSize = 0u;

    gRuntimeBoundedProps.erase(this);
    gRuntimeEntityLists.erase(this);
    gRuntimePools.erase(this);
  }

  /**
   * Address: 0x00687AD0 (FUN_00687AD0)
   *
   * What it does:
   * Runs the `EntityDB` destructor and conditionally releases object storage
   * when scalar-delete flag bit 0 is set.
   */
  CEntityDb* DestroyEntityDbAndMaybeDelete(CEntityDb* const entityDb, const std::uint8_t deleteFlags)
  {
    entityDb->~CEntityDb();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(entityDb);
    }
    return entityDb;
  }

  /**
   * Address: 0x00684560 (FUN_00684560)
   * Mangled: ?Purge@EntityDB@Moho@@QAEXXZ
   *
   * What it does:
   * Removes destroy-dispatched entities from registered entity sets, destroys
   * every tracked entity, and advances the DB id-pool runtime lanes.
   */
  void CEntityDb::Purge()
  {
    PurgeRegisteredEntitySets(*this);

    msvc8::list<Entity*>& entities = Entities();
    PurgeTrackedEntities(entities);

    if (mEntityList.head) {
      ClearEntityListNodes(mEntityList.head);
      mEntityList.size = 0u;
    }

    AdvanceRuntimeIdPools(*this);
  }

  /**
   * Address: 0x006B69D0 (FUN_006B69D0, Moho::CUnitIterAllArmies::CUnitIterAllArmies)
   *
   * What it does:
   * Initializes one all-armies unit iterator from one concrete army source by
   * setting `[source, source + 1)` bounds over the all-units tree.
   */
  CUnitIterAllArmies::CUnitIterAllArmies(CArmyImpl* const army)
    : mItr(nullptr)
    , mEnd(nullptr)
    , mCur(nullptr)
  {
    if (army == nullptr) {
      return;
    }

    Sim* const sim = army->GetSim();
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }

    CEntityDb* const entityDb = sim->mEntityDB;
    const std::uint32_t sourceIndex = static_cast<std::uint32_t>(army->ArmyId);
    mItr = entityDb->AllUnitsEnd(sourceIndex);
    mEnd = entityDb->AllUnitsEnd(sourceIndex + 1u);
    if (mItr != mEnd) {
      mCur = DecodeAllUnitsIteratorPayload(mItr);
    }
  }

  /**
   * Address: 0x006B6AA0 (FUN_006B6AA0, Moho::CUnitIterAllArmies::CUnitIterAllArmies)
   *
   * What it does:
   * Initializes one all-armies unit iterator from `sim->mEntityDB` by
   * capturing the leftmost all-units tree node, iterator end sentinel, and
   * current decoded unit payload.
   */
  CUnitIterAllArmies::CUnitIterAllArmies(Sim* const sim)
    : mItr(nullptr)
    , mEnd(nullptr)
    , mCur(nullptr)
  {
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return;
    }

    CEntityDb* const entityDb = sim->mEntityDB;
    CEntityDbAllUnitsNode* leftMost = entityDb->mAllUnits;
    if (leftMost == nullptr) {
      return;
    }

    for (CEntityDbAllUnitsNode* node = leftMost->parent; node != nullptr && node->isNil == 0u; node = node->left) {
      leftMost = node;
    }

    mItr = leftMost;
    mEnd = entityDb->AllUnitsEnd();
    if (mItr != mEnd) {
      mCur = DecodeAllUnitsIteratorPayload(mItr);
    }
  }

  /**
   * Address: 0x005C87A0 (FUN_005C87A0, Moho::CUnitIterAllArmies::Next)
   * Address: 0x0087CD10 (FUN_0087CD10)
   * Address: 0x0087CDD0 (FUN_0087CDD0)
   * Address: 0x005A12E0 (FUN_005A12E0)
   *
   * What it does:
   * Advances to the next all-units node and refreshes `mCur` from the new
   * iterator payload lane.
   */
  void CUnitIterAllArmies::Next() noexcept
  {
    if (mItr == nullptr || mEnd == nullptr || mItr == mEnd) {
      mCur = nullptr;
      return;
    }

    mItr = CEntityDb::NextAllUnitsNode(mItr);
    mCur = (mItr != nullptr && mItr != mEnd) ? CEntityDb::UnitFromAllUnitsNode(mItr) : nullptr;
  }

  /**
   * Address: 0x00683C90 (FUN_00683C90,
   * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ)
   *
   * What it does:
   * Returns the first all-units tree node with key >= (`sourceIndex << 20`).
   */
  CEntityDbAllUnitsNode* CEntityDb::AllUnitsEnd(const std::uint32_t sourceIndex) const
  {
    return TreeLowerBound(mAllUnits, sourceIndex << kEntityIdSourceShift);
  }

  /**
   * Address: 0x00683D10 (FUN_00683D10,
   * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ_0)
   *
   * What it does:
   * Returns the first all-units tree node at/after the first non-unit family boundary
   * (`EEntityIdSentinel::FirstNonUnitFamily`, value `0x10000000`).
   */
  CEntityDbAllUnitsNode* CEntityDb::AllUnitsEnd() const
  {
    return TreeLowerBound(mAllUnits, kAllUnitsUnitTypeBoundaryKey);
  }

  /**
   * Alias of FUN_005C87A0 (non-canonical helper lane).
   *
   * What it does:
   * Returns the in-order successor for one all-units tree node.
   */
  CEntityDbAllUnitsNode* CEntityDb::NextAllUnitsNode(CEntityDbAllUnitsNode* node) noexcept
  {
    return NextNodeInAllUnitsTree(node);
  }

  /**
    * Alias of FUN_005C87A0 (non-canonical helper lane).
   */
  Unit* CEntityDb::UnitFromAllUnitsNode(const CEntityDbAllUnitsNode* const node) noexcept
  {
    if (node == nullptr || node->unitListNode == nullptr) {
      return nullptr;
    }

    auto* const entitySubobject = reinterpret_cast<Entity*>(node->unitListNode);
    return static_cast<Unit*>(entitySubobject);
  }

  /**
   * Address: 0x00686EF0 (FUN_00686EF0, sub_686EF0)
   *
   * What it does:
   * Erases `[first, last)` from `mAllUnits` and returns the node that
   * followed the erased range (see `EraseAllUnitsTreeRange` for the full
   * recovery, and `EraseAllUnitsTreeNode`/FUN_00685410 for the single-node
   * erase it loops on).
   */
  CEntityDbAllUnitsNode* CEntityDb::EraseAllUnitsRange(
    CEntityDbAllUnitsNode* const first,
    CEntityDbAllUnitsNode* const last
  )
  {
    CEntityDbAllUnitsNode* outPosition = nullptr;
    return EraseAllUnitsTreeRange(this, &outPosition, first, last);
  }

  /**
   * Address: 0x006856C0 (FUN_006856C0)
   *
   * What it does:
   * Resolves one entity id against the all-units tree. The binary is the
   * `std::map<EntId, Entity*>::find` emission: it lower-bounds the tree and
   * collapses "no such key" onto the head node (`end()`), which this returns
   * as `nullptr`.
   */
  Entity* CEntityDb::FindEntityById(const std::uint32_t entityId) const noexcept
  {
    CEntityDbAllUnitsNode* const node = FindExactEntityNodeOrHead(mAllUnits, entityId);
    if (node == nullptr || node == mAllUnits) {
      return nullptr;
    }
    return static_cast<Entity*>(node->unitListNode);
  }

  /**
   * Address: 0x00684480 (FUN_00684480, ?DoReserveId@EntityDB@Moho@@AAE?AVEntId@2@I@Z)
   *
   * What it does:
   * Reserves a new entity id in the requested packed-id family/source key.
   */
  std::uint32_t CEntityDb::DoReserveId(const std::uint32_t requestedFamilySourceBits)
  {
    const std::uint32_t familySourceBits = requestedFamilySourceBits & kEntityIdFamilySourceMaskRaw;
    IdPoolRuntime& pool = gRuntimePools[this][familySourceBits];
    SeedFamilyPoolFromEntities(Entities(), familySourceBits, pool);

    for (std::uint32_t attempt = 0; attempt < kEntityIdSerialMask; ++attempt) {
      const std::uint32_t serial = AllocateSerialFromFamilyPool(pool);
      const std::uint32_t entityId = familySourceBits | serial;
      if (!IdExistsInList(Entities(), entityId)) {
        UpdateEntityCountStats(entityId, 1u);
        return entityId;
      }
    }

    // Family/source pool exhausted: preserve old fail-safe behavior and hand back +1 serial.
    const std::uint32_t fallbackEntityId = familySourceBits | 1u;
    UpdateEntityCountStats(fallbackEntityId, 1u);
    return fallbackEntityId;
  }

  /**
   * Address: 0x00684690 (FUN_00684690, Moho::EntityDB::ReleaseId)
   * Mangled: ?ReleaseId@EntityDB@Moho@@QAEXVEntId@2@@Z
   *
   * What it does:
   * Releases one packed entity id, updates entity-count stats, removes runtime
   * entity tracking lanes for that id, and adds the serial lane back to the
   * family/source reuse set.
   */
  BVIntSetAddResult CEntityDb::ReleaseId(const std::uint32_t releasedId)
  {
    UpdateEntityCountStats(releasedId, static_cast<std::uint32_t>(-1));

    msvc8::list<Entity*>& entities = Entities();
    RemoveTrackedEntityById(entities, releasedId);

    const std::uint32_t familySourceBits = releasedId & kEntityIdFamilySourceMaskRaw;
    IdPoolRuntime& pool = gRuntimePools[this][familySourceBits];
    SeedFamilyPoolFromEntities(entities, familySourceBits, pool);

    const std::uint32_t serial = releasedId & kEntityIdSerialMask;
    return pool.mReleasedSerials.Add(serial);
  }

  /**
   * Address: 0x00684C30 (FUN_00684C30, Moho::EntityDB::AddBoundedProp)
   *
   * What it does:
   * Pushes one Prop into the bounded reclaim-priority queue and evicts queue
   * head entries while occupancy is at least 1000.
   */
  std::int32_t CEntityDb::AddBoundedProp(Prop* const prop)
  {
    BoundedPropQueueRuntime& queue = gRuntimeBoundedProps[this];
    while (queue.heap.size() >= kBoundedPropQueueMaxSize) {
      Prop* const evictedProp = PopBoundedPropHead(queue);
      if (!evictedProp) {
        continue;
      }

      evictedProp->mHandleIndex = -1;
      evictedProp->Destroy();
    }

    if (!prop) {
      return -1;
    }

    return PushBoundedPropEntry(queue, prop, prop->mPriorityInfo.mPriority, prop->mPriorityInfo.mBoundedTick);
  }

  /**
   * Address: 0x00684CE0 (FUN_00684CE0, ?RemoveBoundedProp@EntityDB@Moho@@QAEXW4Handle@?$PriorityQueue@USPropPriorityInfo@Moho@@V?$WeakPtr@VProp@Moho@@@2@@gpg@@@Z)
   * Mangled: ?RemoveBoundedProp@EntityDB@Moho@@QAEXW4Handle@?$PriorityQueue@USPropPriorityInfo@Moho@@V?$WeakPtr@VProp@Moho@@@2@@gpg@@@Z
   *
   * What it does:
   * Resolves one bounded-prop queue handle to its heap entry and removes it
   * from runtime bounded-prop storage.
   */
  void CEntityDb::RemoveBoundedProp(const std::int32_t handle)
  {
    auto it = gRuntimeBoundedProps.find(this);
    if (it == gRuntimeBoundedProps.end()) {
      return;
    }

    (void)RemoveBoundedPropByHandle(it->second, handle);
  }

  msvc8::list<Entity*>& CEntityDb::Entities() noexcept
  {
    return gRuntimeEntityLists[this];
  }

  const msvc8::list<Entity*>& CEntityDb::Entities() const noexcept
  {
    const auto it = gRuntimeEntityLists.find(this);
    if (it != gRuntimeEntityLists.end()) {
      return it->second;
    }

    static const msvc8::list<Entity*> kEmpty{};
    return kEmpty;
  }

  void CEntityDb::RegisterEntitySet(SEntitySetTemplateUnit& set) noexcept
  {
    LinkSetNodeToFront(mRegisteredEntitySets, reinterpret_cast<CEntityDbListHead*>(&set));
  }

  void CEntityDb::RegisterEntitySet(EntitySetBase& set) noexcept
  {
    LinkSetNodeToFront(mRegisteredEntitySets, reinterpret_cast<CEntityDbListHead*>(&set));
  }

  /**
   * Address: 0x00684AA0 (FUN_00684AA0, Moho::EntityDB::SerEntities read lane)
   */
  void CEntityDb::SerEntities(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdType();
    if (!entIdType) {
      return;
    }

    msvc8::list<Entity*>& entities = Entities();
    for (;;) {
      std::uint32_t entityId = kEntityIdInvalidSentinel;
      archive->Read(entIdType, &entityId, NullOwnerRef());
      if (entityId == kEntityIdInvalidSentinel) {
        break;
      }

      Entity* const entity = ReadOwnedEntityPointer(archive);
      if (!entity) {
        continue;
      }

      entity->id_ = static_cast<EntId>(entityId);
      TrackEntityPointer(entities, entity);
    }
  }

  /**
   * Address: 0x006849C0 (FUN_006849C0, Moho::EntityDB::SerEntities write lane)
   */
  void CEntityDb::SerEntities(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RType* const entIdType = ResolveEntIdType();
    gpg::RType* const entityType = ResolveEntityType();
    if (!entIdType) {
      return;
    }

    for (Entity* const entity : Entities()) {
      if (!entity) {
        continue;
      }

      const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
      archive->Write(entIdType, &entityId, NullOwnerRef());
      gpg::WriteRawPointer(
        archive,
        MakeObjectRef(entity, entityType),
        gpg::TrackedPointerState::Owned,
        NullOwnerRef()
      );
    }

    const std::uint32_t sentinel = kEntityIdInvalidSentinel;
    archive->Write(entIdType, &sentinel, NullOwnerRef());
  }

  /**
   * Address: 0x00684B40 (FUN_00684B40, Moho::EntityDB::SerSets read lane)
   */
  void CEntityDb::SerSets(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    EnsureSetListHeadInitialized(mRegisteredEntitySets);
    for (;;) {
      CEntityDbListHead* const setNode = ReadEntitySetPointer(archive);
      if (!setNode) {
        break;
      }

      LinkSetNodeToFront(mRegisteredEntitySets, setNode);
    }
  }

  /**
   * Address: 0x00684BC0 (FUN_00684BC0, Moho::EntityDB::SerSets write lane)
   */
  void CEntityDb::SerSets(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    EnsureSetListHeadInitialized(mRegisteredEntitySets);
    gpg::RType* const setType = ResolveEntitySetBaseType();

    for (CEntityDbListHead* node = mRegisteredEntitySets.next; node && node != &mRegisteredEntitySets;
         node = node->next) {
      gpg::WriteRawPointer(
        archive,
        MakeObjectRef(node, setType),
        gpg::TrackedPointerState::Unowned,
        NullOwnerRef()
      );
    }

    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(nullptr, setType),
      gpg::TrackedPointerState::Unowned,
      NullOwnerRef()
    );
  }

  /**
   * Address: 0x00689760 (FUN_00689760, Moho::EntityDB::MemberSerialize)
   */
  void CEntityDb::MemberSerialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    SerEntities(archive);

    // Reads directly into the real `mIdPoolTree` member (binary:
    // `gpg::ReadArchive::Read(a1, v4, &a2->mIdPool, ...)`, FUN_00689760) --
    // no local staging map. `gRuntimePools` is a separate, already-existing
    // runtime allocator-side cache (see `DoReserveId`/`ReleaseId`) kept in
    // sync from the now-authoritative `mIdPoolTree` values; it is not part
    // of the binary's own serialize path.
    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName(
          {"std::map<unsigned int,Moho::IdPool>", "map<unsigned int,Moho::IdPool>"}
        )) {
      archive->Read(idPoolMapType, &mIdPoolTree, NullOwnerRef());

      FamilyPoolMap& runtimePools = gRuntimePools[this];
      runtimePools.clear();
      for (const auto& [familySourceBits, serializedPool] : mIdPoolTree) {
        IdPoolRuntime runtimePool{};
        runtimePool.mNextSerial =
          serializedPool.mNextLowId > 0 ? static_cast<std::uint32_t>(serializedPool.mNextLowId) : 1u;
        runtimePool.mReleasedSerials = serializedPool.mReleasedLows;
        runtimePool.mSeededFromEntityDb = true;
        runtimePools[familySourceBits] = runtimePool;
      }
    }

    SerSets(archive);

    if (gpg::RType* const entityListType = ResolveTypeByAnyName({"std::list<Moho::Entity *>"})) {
      std::list<Entity*> serializedEntities;
      archive->Read(entityListType, &serializedEntities, NullOwnerRef());

      msvc8::list<Entity*>& runtimeEntities = Entities();
      runtimeEntities.clear();
      for (Entity* const entity : serializedEntities) {
        TrackEntityPointer(runtimeEntities, entity);
      }
    }
  }

  /**
   * Address: 0x006897F0 (FUN_006897F0, Moho::EntityDB::MemberDeserialize)
   */
  void CEntityDb::MemberDeserialize(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    SerEntities(archive);

    // Writes the real `mIdPoolTree` member directly (binary:
    // `gpg::WriteArchive::Write(a1, v4, &a2->mIdPool, &a5)`, FUN_006897F0 --
    // no synchronization step of any kind precedes it there). `gRuntimePools`
    // may hold newer allocator-side state accumulated since the last load
    // (`DoReserveId`/`ReleaseId`), so it is folded back into `mIdPoolTree`
    // via the map's own `operator[]` before writing, keeping the persisted
    // map authoritative without introducing a second serialization path.
    if (gpg::RType* const idPoolMapType = ResolveTypeByAnyName(
          {"std::map<unsigned int,Moho::IdPool>", "map<unsigned int,Moho::IdPool>"}
        )) {
      const auto poolsIt = gRuntimePools.find(this);
      if (poolsIt != gRuntimePools.end()) {
        for (const auto& [familySourceBits, runtimePool] : poolsIt->second) {
          moho::IdPool& destinationPool = mIdPoolTree[familySourceBits];
          destinationPool.mNextLowId = static_cast<std::int32_t>(runtimePool.mNextSerial);
          destinationPool.mReleasedLows = runtimePool.mReleasedSerials;
        }
      }

      archive->Write(idPoolMapType, &mIdPoolTree, NullOwnerRef());
    }

    SerSets(archive);

    if (gpg::RType* const entityListType = ResolveTypeByAnyName({"std::list<Moho::Entity *>"})) {
      std::list<Entity*> serializedEntities;
      for (Entity* const entity : Entities()) {
        if (!entity) {
          continue;
        }
        serializedEntities.push_back(entity);
      }
      archive->Write(entityListType, &serializedEntities, NullOwnerRef());
    }
  }

  /**
   * Address: 0x00688A70 (FUN_00688A70)
   *
   * What it does:
   * Tail-thunk alias that forwards one read-archive member load lane into
   * `CEntityDb::MemberSerialize`.
   */
  void LoadEntityDbMembersThunkPrimary(gpg::ReadArchive* const archive, CEntityDb* const entityDb)
  {
    entityDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x00688A80 (FUN_00688A80)
   *
   * What it does:
   * Tail-thunk alias that forwards one write-archive member save lane into
   * `CEntityDb::MemberDeserialize`.
   */
  void SaveEntityDbMembersThunkPrimary(gpg::WriteArchive* const archive, CEntityDb* const entityDb)
  {
    entityDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006892B0 (FUN_006892B0)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards one read-archive member load lane
   * into `CEntityDb::MemberSerialize`.
   */
  void LoadEntityDbMembersThunkSecondary(gpg::ReadArchive* const archive, CEntityDb* const entityDb)
  {
    entityDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x006892C0 (FUN_006892C0)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards one write-archive member save
   * lane into `CEntityDb::MemberDeserialize`.
   */
  void SaveEntityDbMembersThunkSecondary(gpg::WriteArchive* const archive, CEntityDb* const entityDb)
  {
    entityDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00684910 (FUN_00684910, Moho::EntityDBSerializer::Deserialize)
   */
  void EntityDBSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const entityDb = reinterpret_cast<CEntityDb*>(objectPtr);
    if (!entityDb) {
      return;
    }

    entityDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x00684920 (FUN_00684920, Moho::EntityDBSerializer::Serialize)
   */
  void EntityDBSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const entityDb = reinterpret_cast<CEntityDb*>(objectPtr);
    if (!entityDb) {
      return;
    }

    entityDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00686010 (FUN_00686010, gpg::SerSaveLoadHelper_EntityDB::Init)
   */
  void EntityDBSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const entityDbType = ResolveEntityDbType();
    GPG_ASSERT(entityDbType != nullptr);
    if (!entityDbType) {
      return;
    }

    GPG_ASSERT(entityDbType->serLoadFunc_ == nullptr);
    GPG_ASSERT(entityDbType->serSaveFunc_ == nullptr);
    entityDbType->serLoadFunc_ = mDeserialize;
    entityDbType->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFCAD0 (FUN_00BFCAD0, Moho::EntityDBSerializer::~EntityDBSerializer)
   */
  gpg::SerHelperBase* cleanup_EntityDBSerializer()
  {
    return UnlinkEntityDBSerializerHelperNodePrimary();
  }

  /**
   * Address: 0x00BD51A0 (FUN_00BD51A0, register_EntityDBSerializer)
   */
  int register_EntityDBSerializer()
  {
    InitializeHelperNode(gEntityDBSerializer);
    gEntityDBSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&EntityDBSerializer::Deserialize);
    gEntityDBSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&EntityDBSerializer::Serialize);
    return std::atexit(&cleanup_EntityDBSerializer_atexit);
  }

  /**
   * Address: 0x006847B0 (FUN_006847B0, preregister_EntityDbTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `EntityDB`.
   */
  gpg::RType* preregister_EntityDbTypeInfo()
  {
    EntityDbTypeInfo& typeInfo = AcquireEntityDbTypeInfo();
    gpg::PreRegisterRType(typeid(CEntityDb), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCA70 (FUN_00BFCA70, cleanup_EntityDbTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for `EntityDB`.
   */
  void cleanup_EntityDbTypeInfo()
  {
    if (!gEntityDbTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbTypeInfo().~EntityDbTypeInfo();
    gEntityDbTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5180 (FUN_00BD5180, register_EntityDbTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `EntityDB` RTTI and installs process-exit cleanup.
   */
  int register_EntityDbTypeInfoAtexit()
  {
    (void)preregister_EntityDbTypeInfo();
    return std::atexit(&cleanup_EntityDbTypeInfo);
  }

  /**
   * Address: 0x00689090 (FUN_00689090, preregister_EntityDbIdPoolMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::map<unsigned int,Moho::IdPool>`.
   */
  gpg::RType* preregister_EntityDbIdPoolMapTypeInfo()
  {
    EntityDbIdPoolMapTypeInfo& typeInfo = AcquireEntityDbIdPoolMapTypeInfo();
    gpg::PreRegisterRType(typeid(std::map<unsigned int, moho::IdPool>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCC20 (FUN_00BFCC20, cleanup_EntityDbIdPoolMapTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for
   * `std::map<unsigned int,Moho::IdPool>`.
   */
  void cleanup_EntityDbIdPoolMapTypeInfo()
  {
    if (!gEntityDbIdPoolMapTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbIdPoolMapTypeInfo().~EntityDbIdPoolMapTypeInfo();
    gEntityDbIdPoolMapTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5250 (FUN_00BD5250, register_EntityDbIdPoolMapTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `std::map<unsigned int,Moho::IdPool>` RTTI and installs
   * process-exit cleanup.
   */
  int register_EntityDbIdPoolMapTypeInfoAtexit()
  {
    (void)preregister_EntityDbIdPoolMapTypeInfo();
    return std::atexit(&cleanup_EntityDbIdPoolMapTypeInfo);
  }

  /**
   * Address: 0x006890F0 (FUN_006890F0, preregister_EntityDbEntityListTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `std::list<Moho::Entity *>`.
   */
  gpg::RType* preregister_EntityDbEntityListTypeInfo()
  {
    EntityDbEntityListTypeInfo& typeInfo = AcquireEntityDbEntityListTypeInfo();
    gpg::PreRegisterRType(typeid(std::list<moho::Entity*>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFCBC0 (FUN_00BFCBC0, cleanup_EntityDbEntityListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for `std::list<Moho::Entity *>`.
   */
  void cleanup_EntityDbEntityListTypeInfo()
  {
    if (!gEntityDbEntityListTypeInfoConstructed) {
      return;
    }

    AcquireEntityDbEntityListTypeInfo().~EntityDbEntityListTypeInfo();
    gEntityDbEntityListTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5270 (FUN_00BD5270, register_EntityDbEntityListTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `std::list<Moho::Entity *>` RTTI and installs process-exit
   * cleanup.
   */
  int register_EntityDbEntityListTypeInfoAtexit()
  {
    (void)preregister_EntityDbEntityListTypeInfo();
    return std::atexit(&cleanup_EntityDbEntityListTypeInfo);
  }
} // namespace moho

namespace
{
  struct EntityDbReflectionBootstrap
  {
    EntityDbReflectionBootstrap()
    {
      (void)moho::register_EntityDbTypeInfoAtexit();
      (void)moho::register_EntityDbIdPoolMapTypeInfoAtexit();
      (void)moho::register_EntityDbEntityListTypeInfoAtexit();
      (void)moho::register_EntityDBSerializer();
    }
  };

  EntityDbReflectionBootstrap gEntityDbReflectionBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EntityDbTypeInfo_53cb23, moho::preregister_EntityDbTypeInfo)
GPG_PREREGISTER_INIT(preregister_EntityDbIdPoolMapTypeInfo_53cb23, moho::preregister_EntityDbIdPoolMapTypeInfo)
GPG_PREREGISTER_INIT(preregister_EntityDbEntityListTypeInfo_53cb23, moho::preregister_EntityDbEntityListTypeInfo)

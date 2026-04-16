#include "moho/ai/IAiNavigator.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiNavigatorAir.h"
#include "moho/ai/CAiNavigatorImpl.h"
#include "moho/ai/CAiNavigatorLand.h"
#include "moho/misc/Listener.h"

using namespace moho;

namespace moho
{
  class RBroadcasterRType_EAiNavigatorEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A7790 (FUN_005A7790)
     *
     * What it does:
     * Deserializes listener pointer lanes and relinks them into the target
     * broadcaster ring.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7800 (FUN_005A7800)
     *
     * What it does:
     * Serializes broadcaster listener pointers as `UNOWNED` and appends a null
     * pointer sentinel.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Broadcaster);
      serLoadFunc_ = &RBroadcasterRType_EAiNavigatorEvent::SerLoad;
      serSaveFunc_ = &RBroadcasterRType_EAiNavigatorEvent::SerSave;
      Finish();
    }
  };

  class RListenerRType_EAiNavigatorEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(Listener<EAiNavigatorEvent>);
      Finish();
    }
  };
} // namespace moho

namespace
{
  using BroadcasterNavigatorType = moho::RBroadcasterRType_EAiNavigatorEvent;
  using ListenerNavigatorType = moho::RListenerRType_EAiNavigatorEvent;

  struct CachedTypeName
  {
    msvc8::string value;
    bool initialized = false;
  };

  alignas(BroadcasterNavigatorType) unsigned char gBroadcasterNavigatorTypeStorage[sizeof(BroadcasterNavigatorType)];
  bool gBroadcasterNavigatorTypeConstructed = false;

  alignas(ListenerNavigatorType) unsigned char gListenerNavigatorTypeStorage[sizeof(ListenerNavigatorType)];
  bool gListenerNavigatorTypeConstructed = false;

  [[nodiscard]] BroadcasterNavigatorType* AcquireBroadcasterNavigatorType()
  {
    if (!gBroadcasterNavigatorTypeConstructed) {
      new (gBroadcasterNavigatorTypeStorage) BroadcasterNavigatorType();
      gBroadcasterNavigatorTypeConstructed = true;
    }

    return reinterpret_cast<BroadcasterNavigatorType*>(gBroadcasterNavigatorTypeStorage);
  }

  [[nodiscard]] ListenerNavigatorType* AcquireListenerNavigatorType()
  {
    if (!gListenerNavigatorTypeConstructed) {
      new (gListenerNavigatorTypeStorage) ListenerNavigatorType();
      gListenerNavigatorTypeConstructed = true;
    }

    return reinterpret_cast<ListenerNavigatorType*>(gListenerNavigatorTypeStorage);
  }

  void cleanup_RBroadcasterRType_EAiNavigatorEvent()
  {
    if (!gBroadcasterNavigatorTypeConstructed) {
      return;
    }

    AcquireBroadcasterNavigatorType()->~BroadcasterNavigatorType();
    gBroadcasterNavigatorTypeConstructed = false;
  }

  void cleanup_RListenerRType_EAiNavigatorEvent()
  {
    if (!gListenerNavigatorTypeConstructed) {
      return;
    }

    AcquireListenerNavigatorType()->~ListenerNavigatorType();
    gListenerNavigatorTypeConstructed = false;
  }

  [[nodiscard]] gpg::RType* ResolveEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::EAiNavigatorEvent));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("EAiNavigatorEvent");
      }
    }
    return cached;
  }

  [[nodiscard]] CachedTypeName& CachedBroadcasterEAiNavigatorEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  [[nodiscard]] CachedTypeName& CachedListenerEAiNavigatorEventTypeName()
  {
    static CachedTypeName cache{};
    return cache;
  }

  void cleanup_RBroadcasterRType_EAiNavigatorEvent_GetName()
  {
    CachedTypeName& cache = CachedBroadcasterEAiNavigatorEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  void cleanup_RListenerRType_EAiNavigatorEvent_GetName()
  {
    CachedTypeName& cache = CachedListenerEAiNavigatorEventTypeName();
    cache.value = msvc8::string{};
    cache.initialized = false;
  }

  [[nodiscard]] gpg::RType* CachedBroadcasterEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(BroadcasterEventTag<EAiNavigatorEvent>));
    }
    return cached;
  }

  using GenericListNode = moho::TDatListItem<void, void>;

  [[nodiscard]] GenericListNode* GenericNodeFromListener(
    moho::Listener<moho::EAiNavigatorEvent>* const listener
  ) noexcept
  {
    if (!listener) {
      return nullptr;
    }

    return reinterpret_cast<GenericListNode*>(&listener->mListenerLink);
  }

  [[nodiscard]] moho::Listener<moho::EAiNavigatorEvent>* ListenerFromGenericNode(GenericListNode* const node) noexcept
  {
    if (!node) {
      return nullptr;
    }

    auto* const bytes = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<moho::Listener<moho::EAiNavigatorEvent>*>(
      bytes - offsetof(moho::Listener<moho::EAiNavigatorEvent>, mListenerLink)
    );
  }

  struct NavigatorGlueTailWordView
  {
    std::uint8_t pad00[0xA8];
    std::uint32_t tailWord0;
    std::uint32_t tailWord1;
    std::uint32_t tailWord2;
  };
  static_assert(offsetof(NavigatorGlueTailWordView, tailWord0) == 0xA8, "tailWord0 offset must be 0xA8");
  static_assert(offsetof(NavigatorGlueTailWordView, tailWord1) == 0xAC, "tailWord1 offset must be 0xAC");
  static_assert(offsetof(NavigatorGlueTailWordView, tailWord2) == 0xB0, "tailWord2 offset must be 0xB0");

  struct NavigatorGlueLateWordView
  {
    std::uint8_t pad00[0x118];
    std::uint32_t lateWord;
  };
  static_assert(offsetof(NavigatorGlueLateWordView, lateWord) == 0x118, "lateWord offset must be 0x118");

  /**
   * Address: 0x005A2BF0 (FUN_005A2BF0)
   *
   * What it does:
   * Returns the first trailing 32-bit payload lane from one opaque navigator
   * glue view object.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadNavigatorGlueTailWord0(
    const NavigatorGlueTailWordView* const view
  ) noexcept
  {
    return view->tailWord0;
  }

  /**
   * Address: 0x005A2C00 (FUN_005A2C00)
   *
   * What it does:
   * Returns the second trailing 32-bit payload lane from one opaque navigator
   * glue view object.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadNavigatorGlueTailWord1(
    const NavigatorGlueTailWordView* const view
  ) noexcept
  {
    return view->tailWord1;
  }

  /**
   * Address: 0x005A2C10 (FUN_005A2C10)
   *
   * What it does:
   * Returns the third trailing 32-bit payload lane from one opaque navigator
   * glue view object.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadNavigatorGlueTailWord2(
    const NavigatorGlueTailWordView* const view
  ) noexcept
  {
    return view->tailWord2;
  }

  /**
   * Address: 0x005A2DF0 (FUN_005A2DF0)
   *
   * What it does:
   * Returns one late 32-bit payload lane from one opaque navigator glue view
   * object.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadNavigatorGlueLateWord(
    const NavigatorGlueLateWordView* const view
  ) noexcept
  {
    return view->lateWord;
  }

  /**
   * Address: 0x005A8240 (FUN_005A8240)
   *
   * What it does:
   * Writes one `Listener<EAiNavigatorEvent>` pointer lane as `UNOWNED` to the
   * target archive.
   */
  [[nodiscard]] gpg::WriteArchive* WriteUnownedListenerEAiNavigatorEvent(
    moho::Listener<moho::EAiNavigatorEvent>* const listener,
    gpg::WriteArchive* const archive,
    const gpg::RRef* const ownerRef
  )
  {
    gpg::RRef listenerRef{};
    (void)gpg::RRef_Listener_EAiNavigatorEvent(&listenerRef, listener);

    const gpg::RRef nullOwner{};
    gpg::WriteRawPointer(
      archive,
      listenerRef,
      gpg::TrackedPointerState::Unowned,
      ownerRef ? *ownerRef : nullOwner
    );
    return archive;
  }

  /**
   * Address: 0x005A8370 (FUN_005A8370)
   *
   * What it does:
   * Constructs/registers the broadcaster reflection type for
   * `EAiNavigatorEvent`.
   */
  [[nodiscard]] gpg::RType* RegisterBroadcasterEAiNavigatorEventType()
  {
    gpg::RType* const type = AcquireBroadcasterNavigatorType();
    gpg::PreRegisterRType(typeid(moho::BroadcasterEventTag<moho::EAiNavigatorEvent>), type);
    return type;
  }

  /**
   * Address: 0x005A83D0 (FUN_005A83D0)
   *
   * What it does:
   * Constructs/registers the listener reflection type for
   * `EAiNavigatorEvent`.
   */
  [[nodiscard]] gpg::RType* RegisterListenerEAiNavigatorEventType()
  {
    gpg::RType* const type = AcquireListenerNavigatorType();
    gpg::PreRegisterRType(typeid(moho::Listener<moho::EAiNavigatorEvent>), type);
    return type;
  }

  struct NavigatorTypeDestructorRuntimeView
  {
    void* vftable;                       // +0x00
    std::uint8_t pad04_2B[0x28]{};       // +0x04
    void* storage2C;                     // +0x2C
    void* storage30;                     // +0x30
    void* storage34;                     // +0x34
    std::uint8_t pad38_3B[0x4]{};        // +0x38
    void* storage3C;                     // +0x3C
    void* storage40;                     // +0x40
    void* storage44;                     // +0x44
  };
  static_assert(
    offsetof(NavigatorTypeDestructorRuntimeView, storage2C) == 0x2C,
    "NavigatorTypeDestructorRuntimeView::storage2C offset must be 0x2C"
  );
  static_assert(
    offsetof(NavigatorTypeDestructorRuntimeView, storage3C) == 0x3C,
    "NavigatorTypeDestructorRuntimeView::storage3C offset must be 0x3C"
  );

  class RObjectVtableProbe final : public gpg::RObject
  {
  public:
    [[nodiscard]] gpg::RType* GetClass() const override
    {
      return nullptr;
    }

    [[nodiscard]] gpg::RRef GetDerivedObjectRef() override
    {
      return gpg::RRef{};
    }

    ~RObjectVtableProbe() override = default;
  };

  [[nodiscard]] void* RecoverRObjectVtable() noexcept
  {
    static RObjectVtableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }

  /**
   * Address: 0x005A8470 (FUN_005A8470)
   *
   * What it does:
   * Releases two owned heap-storage triplets, rebinds the base vtable lane to
   * `gpg::RObject`, and conditionally deletes the owning object.
   */
  [[maybe_unused]] [[nodiscard]] NavigatorTypeDestructorRuntimeView* DestroyNavigatorTypeStorageLane(
    NavigatorTypeDestructorRuntimeView* const object,
    const char deleteFlags
  ) noexcept
  {
    if (object->storage3C != nullptr) {
      ::operator delete(object->storage3C);
    }
    object->storage3C = nullptr;
    object->storage40 = nullptr;
    object->storage44 = nullptr;

    if (object->storage2C != nullptr) {
      ::operator delete(object->storage2C);
    }
    object->storage2C = nullptr;
    object->storage30 = nullptr;
    object->storage34 = nullptr;

    object->vftable = RecoverRObjectVtable();
    if ((deleteFlags & 1) != 0) {
      ::operator delete(object);
    }
    return object;
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplTypeForUpcast()
  {
    gpg::RType* type = moho::CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiNavigatorImpl));
      moho::CAiNavigatorImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerEAiNavigatorEventTypeForUpcast()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiNavigatorEvent>));
    }
    return cached;
  }

  /**
   * Address: 0x005A8970 (FUN_005A8970)
   *
   * What it does:
   * Upcasts one reflected source lane to `CAiNavigatorImpl` and returns the
   * resulting object pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] void* UpcastCAiNavigatorImplRefObject(gpg::RRef* const source)
  {
    if (!source) {
      return nullptr;
    }

    return gpg::REF_UpcastPtr(*source, CachedCAiNavigatorImplTypeForUpcast()).mObj;
  }

  /**
   * Address: 0x005A8A00 (FUN_005A8A00)
   *
   * What it does:
   * Upcasts one reflected source lane to `Listener<EAiNavigatorEvent>` and
   * returns the resulting object pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] void* UpcastListenerEAiNavigatorEventRefObject(gpg::RRef* const source)
  {
    if (!source) {
      return nullptr;
    }

    return gpg::REF_UpcastPtr(*source, CachedListenerEAiNavigatorEventTypeForUpcast()).mObj;
  }

  /**
   * Address: 0x005A7340 (FUN_005A7340)
   *
   * What it does:
   * Stores one intrusive-node cursor pointer and returns the destination lane.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeCursor(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    if (outCursor) {
      *outCursor = node;
    }
    return outCursor;
  }

  /**
   * Address: 0x005A7370 (FUN_005A7370)
   *
   * What it does:
   * Loads one intrusive-node cursor pointer from storage.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode* LoadNodeCursor(GenericListNode* const* const cursor) noexcept
  {
    return cursor ? *cursor : nullptr;
  }

  /**
   * Address: 0x005A75C0 (FUN_005A75C0)
   *
   * What it does:
   * Stores `node->mNext` into one intrusive-node cursor lane.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeNextCursor(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    if (outCursor) {
      *outCursor = node ? node->mNext : nullptr;
    }
    return outCursor;
  }

  /**
   * Address: 0x005A7690 (FUN_005A7690)
   *
   * What it does:
   * Unlinks one intrusive node from its current ring and resets it as
   * self-linked.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode* UnlinkAndResetGenericNode(GenericListNode* const node) noexcept
  {
    if (!node) {
      return nullptr;
    }

    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    node->mNext = node;
    node->mPrev = node;
    return node;
  }

  /**
   * Address: 0x005A7A10 (FUN_005A7A10)
   *
   * What it does:
   * Alias lane for storing `node->mNext` into one intrusive-node cursor lane.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeNextCursorAlias(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    return StoreNodeNextCursor(outCursor, node);
  }

  /**
   * Address: 0x005A7A20 (FUN_005A7A20)
   *
   * What it does:
   * Alias lane for storing one intrusive-node cursor pointer.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeCursorAlias(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    return StoreNodeCursor(outCursor, node);
  }

  /**
   * Address: 0x005A7A90 (FUN_005A7A90)
   *
   * What it does:
   * Alias lane for intrusive unlink/reset behavior.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode* UnlinkAndResetGenericNodeAlias(GenericListNode* const node) noexcept
  {
    return UnlinkAndResetGenericNode(node);
  }

  /**
   * Address: 0x005A7AB0 (FUN_005A7AB0)
   *
   * What it does:
   * Secondary alias lane for storing one intrusive-node cursor pointer.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeCursorAlias2(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    return StoreNodeCursor(outCursor, node);
  }

  /**
   * Address: 0x005A7AC0 (FUN_005A7AC0)
   *
   * What it does:
   * Advances one intrusive-node cursor to `(*cursor)->mNext`.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** AdvanceNodeCursor(GenericListNode** const cursor) noexcept
  {
    if (cursor && *cursor) {
      *cursor = (*cursor)->mNext;
    }
    return cursor;
  }

  /**
   * Address: 0x005A7AF0 (FUN_005A7AF0)
   *
   * What it does:
   * Tertiary alias lane for storing one intrusive-node cursor pointer.
   */
  [[maybe_unused]] [[nodiscard]] GenericListNode** StoreNodeCursorAlias3(
    GenericListNode** const outCursor,
    GenericListNode* const node
  ) noexcept
  {
    return StoreNodeCursor(outCursor, node);
  }

  /**
   * Address: 0x005A89F0 (FUN_005A89F0)
   *
   * What it does:
   * Returns the high byte from one 32-bit packed value lane.
   */
  [[maybe_unused]] [[nodiscard]] std::uint8_t ExtractPackedHighByte(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  }
} // namespace

/**
 * Address: 0x005A7000 (FUN_005A7000, Moho::RBroadcasterRType_EAiNavigatorEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Broadcaster<EAiNavigatorEvent>`
 * using the currently registered enum reflection type name.
 */
const char* moho::RBroadcasterRType_EAiNavigatorEvent::GetName() const
{
  CachedTypeName& cache = CachedBroadcasterEAiNavigatorEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiNavigatorEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiNavigatorEvent";
    cache.value = gpg::STR_Printf("Broadcaster<%s>", eventTypeName ? eventTypeName : "EAiNavigatorEvent");
    (void)std::atexit(&cleanup_RBroadcasterRType_EAiNavigatorEvent_GetName);
  }
  return cache.value.c_str();
}

/**
 * Address: 0x005A7790 (FUN_005A7790)
 *
 * What it does:
 * Deserializes listener pointer lanes and relinks each listener node into the
 * destination broadcaster ring.
 */
void moho::RBroadcasterRType_EAiNavigatorEvent::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const targetRing = reinterpret_cast<GenericListNode*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(targetRing != nullptr);
  if (!archive || !targetRing) {
    return;
  }

  moho::Listener<moho::EAiNavigatorEvent>* listener = nullptr;
  archive->ReadPointer_Listener_EAiNavigatorEvent(&listener, ownerRef);
  while (listener != nullptr) {
    if (GenericListNode* const listenerNode = GenericNodeFromListener(listener); listenerNode != nullptr) {
      listenerNode->ListLinkBefore(targetRing);
    }
    archive->ReadPointer_Listener_EAiNavigatorEvent(&listener, ownerRef);
  }
}

/**
 * Address: 0x005A7800 (FUN_005A7800)
 *
 * What it does:
 * Serializes listener pointers from one broadcaster ring as `UNOWNED` and
 * writes one null sentinel pointer terminator.
 */
void moho::RBroadcasterRType_EAiNavigatorEvent::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const sourceRing = reinterpret_cast<GenericListNode*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
  );
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(sourceRing != nullptr);
  if (!archive || !sourceRing) {
    return;
  }

  for (GenericListNode* node = sourceRing->mNext; node != sourceRing; node = node->mNext) {
    (void)WriteUnownedListenerEAiNavigatorEvent(ListenerFromGenericNode(node), archive, ownerRef);
  }
  (void)WriteUnownedListenerEAiNavigatorEvent(nullptr, archive, ownerRef);
}

/**
 * Address: 0x005A70C0 (FUN_005A70C0, Moho::RListenerRType_EAiNavigatorEvent::GetName)
 *
 * What it does:
 * Lazily builds and caches the runtime type name `Listener<EAiNavigatorEvent>`
 * using the currently registered enum reflection type name.
 */
const char* moho::RListenerRType_EAiNavigatorEvent::GetName() const
{
  CachedTypeName& cache = CachedListenerEAiNavigatorEventTypeName();
  if (!cache.initialized) {
    cache.initialized = true;
    gpg::RType* const eventType = ResolveEAiNavigatorEventType();
    const char* const eventTypeName = eventType ? eventType->GetName() : "EAiNavigatorEvent";
    cache.value = gpg::STR_Printf("Listener<%s>", eventTypeName ? eventTypeName : "EAiNavigatorEvent");
    (void)std::atexit(&cleanup_RListenerRType_EAiNavigatorEvent_GetName);
  }
  return cache.value.c_str();
}

namespace
{
  constexpr std::uint32_t kMaxPathCellCount = 0x3FFFFFFFu;

  /**
   * Address: 0x005A7660 (FUN_005A7660)
   *
   * What it does:
   * Releases one `SNavPath` storage pointer lane (`start`) and clears the
   * pointer triplet while preserving the leading metadata word.
   */
  [[maybe_unused]] void ResetPathCellStorageTriplet(SNavPath& path) noexcept
  {
    if (path.start) {
      ::operator delete(path.start);
    }
    path.start = nullptr;
    path.finish = nullptr;
    path.capacity = nullptr;
  }

  /**
   * Address: 0x005B0650 (FUN_005B0650)
   *
   * What it does:
   * Throws the legacy MSVC vector length exception used when a nav-path cell
   * span would exceed the 32-bit allocator bound.
   */
  [[noreturn]] void ThrowPathCellVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x005B0A90 (FUN_005B0A90)
   *
   * What it does:
   * Allocates one contiguous SOCellPos span after validating the 32-bit byte
   * multiplication bound used by the original allocator lane.
   */
  [[nodiscard]] SOCellPos* AllocatePathCellStorageChecked(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < sizeof(SOCellPos)) {
      throw std::bad_alloc();
    }

    return static_cast<SOCellPos*>(::operator new(sizeof(SOCellPos) * static_cast<std::size_t>(count)));
  }

  /**
   * Address: 0x005B0210 (FUN_005B0210)
   *
   * What it does:
   * Initializes one empty path span with exact capacity `count` and keeps the
   * start/finish pointers aligned to the allocated base.
   */
  [[nodiscard]] bool InitializePathStorageExact(SNavPath& path, const std::uint32_t count)
  {
    if (count > kMaxPathCellCount) {
      ThrowPathCellVectorTooLong();
    }

    SOCellPos* const storage =
      (count != 0u) ? AllocatePathCellStorageChecked(count) : static_cast<SOCellPos*>(::operator new(0));
    path.start = storage;
    path.finish = storage;
    path.capacity = storage + count;
    return true;
  }

  /**
   * Address: 0x005B09B0 (FUN_005B09B0)
   *
   * What it does:
   * Copies one `[sourceBegin, sourceEnd)` cell range into `destination` and
   * returns the advanced destination pointer.
   */
  [[nodiscard]] SOCellPos* CopyCellsForwardUnchecked(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  [[nodiscard]] SOCellPos* CopyCellsForwardRawAddress(
    std::uintptr_t destinationAddress,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<SOCellPos*>(destinationAddress) = *sourceBegin;
      }
      ++sourceBegin;
      destinationAddress += sizeof(SOCellPos);
    }
    return reinterpret_cast<SOCellPos*>(destinationAddress);
  }

  /**
   * Address: 0x005B1630 (FUN_005B1630)
   * Address: 0x00682980 (FUN_00682980)
   *
   * What it does:
   * Copies one source cell range while preserving the legacy "null destination
   * is allowed" advance semantics used by MSVC helper thunks.
   */
  [[nodiscard]] SOCellPos* CopyCellsForwardAllowNull(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardRawAddress(reinterpret_cast<std::uintptr_t>(destination), sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B1650 (FUN_005B1650)
   * Address: 0x0067FA10 (FUN_0067FA10)
   * Address: 0x00680C50 (FUN_00680C50)
   * Address: 0x00681CE0 (FUN_00681CE0)
   * Address: 0x00682380 (FUN_00682380)
   *
   * What it does:
   * Register-shape adapter that forwards one SOCellPos span copy into the
   * canonical null-tolerant forward-copy helper.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos* CopyCellsForwardAllowNullRegisterAdapter(
    const SOCellPos* const sourceBegin,
    const SOCellPos* const sourceEnd,
    SOCellPos* const destination
  ) noexcept
  {
    return CopyCellsForwardAllowNull(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B1A20 (FUN_005B1A20)
   *
   * What it does:
   * Stack-call bridge variant of null-tolerant forward copy for SOCellPos
   * spans.
   */
  [[nodiscard]] SOCellPos* CopyCellsForwardAllowNullStackBridge(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardRawAddress(reinterpret_cast<std::uintptr_t>(destination), sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B16B0 (FUN_005B16B0)
   *
   * What it does:
   * Register-shape adapter for the stack-bridge variant of null-tolerant
   * SOCellPos forward-copy.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos* CopyCellsForwardAllowNullStackBridgeRegisterAdapter(
    const SOCellPos* const sourceBegin,
    const SOCellPos* const sourceEnd,
    SOCellPos* const destination
  ) noexcept
  {
    return CopyCellsForwardAllowNullStackBridge(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B09D0 (FUN_005B09D0)
   *
   * What it does:
   * Assignment-lane bridge that forwards to the null-tolerant cell copy helper.
   */
  [[nodiscard]] SOCellPos* CopyCellsForAssignBridge(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardAllowNull(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B0A20 (FUN_005B0A20)
   *
   * What it does:
   * Insert-lane bridge that forwards to the null-tolerant cell copy helper.
   */
  [[nodiscard]] SOCellPos* CopyCellsForInsertBridge(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardAllowNull(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B0A70 (FUN_005B0A70)
   * Address: 0x008D6EF0 (FUN_008D6EF0)
   *
   * What it does:
   * Performs one backward copy over overlapping ranges and returns the updated
   * destination start pointer.
   */
  [[nodiscard]] SOCellPos* MoveCellsBackward(
    SOCellPos* destinationEnd,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
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
   * Address: 0x005B0E00 (FUN_005B0E00)
   *
   * What it does:
   * Writes `count` copies of one SOCellPos value into destination storage and
   * returns the remaining write count (always zero when finished).
   */
  std::uint32_t FillCellsWithValue(std::uint32_t count, const SOCellPos& value, SOCellPos* destination) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    while (count > 0u) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<SOCellPos*>(destinationAddress) = value;
      }
      --count;
      destinationAddress += sizeof(SOCellPos);
    }
    return count;
  }

  /**
   * Address: 0x005B0EF0 (FUN_005B0EF0)
   *
   * What it does:
   * Stack-call bridge variant of forward range copy for SOCellPos spans.
   */
  [[nodiscard]] SOCellPos* CopyCellsForwardUncheckedStackBridge(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardUnchecked(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x005B0EB0 (FUN_005B0EB0)
   *
   * What it does:
   * Stack-call bridge variant that forwards to the null-tolerant SOCellPos
   * copy helper.
   */
  [[nodiscard]] SOCellPos* CopyCellsForwardStackBridge(
    SOCellPos* destination,
    const SOCellPos* sourceBegin,
    const SOCellPos* sourceEnd
  ) noexcept
  {
    return CopyCellsForwardAllowNullStackBridge(destination, sourceBegin, sourceEnd);
  }

  [[nodiscard]] std::size_t ComputeGrowthCapacity(const std::size_t currentCapacity, const std::size_t requiredCount)
  {
    std::size_t grown = 0;
    if (currentCapacity <= (kMaxPathCellCount / 2u)) {
      grown = currentCapacity + (currentCapacity / 2u);
    }
    if (grown < requiredCount) {
      grown = requiredCount;
    }
    return grown;
  }

  /**
   * Address: 0x005B03C0 (FUN_005B03C0)
   *
   * What it does:
   * Returns the legacy maximum nav-path cell count accepted by the vector-like
   * path storage lane.
   */
  [[nodiscard]] constexpr std::uint32_t GetPathCellLimit() noexcept
  {
    return kMaxPathCellCount;
  }

  /**
   * Address: 0x005B0860 (FUN_005B0860)
   *
   * What it does:
   * Alias lane for the same legacy nav-path cell count limit.
   */
  [[nodiscard]] constexpr std::uint32_t GetPathCellLimitAlias() noexcept
  {
    return kMaxPathCellCount;
  }

  /**
   * Address: 0x005B0000 (FUN_005B0000)
   *
   * What it does:
   * Stores one 32-bit value through the supplied output pointer and returns the
   * destination pointer unchanged.
   */
  [[nodiscard]] std::uint32_t* StoreDwordValue(std::uint32_t* const destination, const std::uint32_t value) noexcept
  {
    if (destination) {
      *destination = value;
    }
    return destination;
  }

  /**
   * Address: 0x005B0300 (FUN_005B0300)
   *
   * What it does:
   * Alias lane for storing one 32-bit value through an output pointer.
   */
  [[nodiscard]] std::uint32_t* StoreDwordValueAlias(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordValue(destination, value);
  }

  /**
   * Address: 0x005B0340 (FUN_005B0340)
   *
   * What it does:
   * Secondary alias lane for storing one 32-bit value through an output
   * pointer.
   */
  [[nodiscard]] std::uint32_t* StoreDwordValueAlias2(
    std::uint32_t* const destination,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordValue(destination, value);
  }

  /**
   * Address: 0x005B0010 (FUN_005B0010)
   *
   * What it does:
   * Loads one 32-bit value from a source pointer.
   */
  [[nodiscard]] std::uint32_t LoadDwordValue(const std::uint32_t* const source) noexcept
  {
    return source ? *source : 0u;
  }

  /**
   * Address: 0x005B0310 (FUN_005B0310)
   *
   * What it does:
   * Alias lane for loading one 32-bit value from a source pointer.
   */
  [[nodiscard]] std::uint32_t LoadDwordValueAlias(const std::uint32_t* const source) noexcept
  {
    return LoadDwordValue(source);
  }

  /**
   * Address: 0x005B0350 (FUN_005B0350)
   *
   * What it does:
   * Secondary alias lane for loading one 32-bit value from a source pointer.
   */
  [[nodiscard]] std::uint32_t LoadDwordValueAlias2(const std::uint32_t* const source) noexcept
  {
    return LoadDwordValue(source);
  }

  /**
   * Address: 0x005B00C0 (FUN_005B00C0)
   *
   * What it does:
   * Reads one stored 32-bit base value, advances it by `index * 4`, and writes
   * the adjusted value to the destination pointer.
   */
  [[nodiscard]] std::uint32_t* AdvanceStoredDwordValue(
    std::uint32_t* const destination,
    const std::uint32_t* const source,
    const std::uint32_t index
  ) noexcept
  {
    if (destination && source) {
      *destination = *source + (4u * index);
    }
    return destination;
  }

  /**
   * Address: 0x005B01C0 (FUN_005B01C0)
   *
   * What it does:
   * Loads the third 32-bit lane from a source array and stores it through the
   * destination pointer.
   */
  [[nodiscard]] std::uint32_t* LoadThirdDword(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination && source) {
      *destination = source[2];
    }
    return destination;
  }

  /**
   * Address: 0x005AFE30 (FUN_005AFE30)
   *
   * What it does:
   * Stores one `SNavPath::start` pointer lane through an output pointer.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos** StorePathStartPointer(
    SOCellPos** const destination,
    const SNavPath* const path
  ) noexcept
  {
    if (destination) {
      *destination = path ? path->start : nullptr;
    }
    return destination;
  }

  /**
   * Address: 0x005AFE40 (FUN_005AFE40)
   *
   * What it does:
   * Alias lane for storing one `SNavPath::start` pointer.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos** StorePathStartPointerAlias(
    SOCellPos** const destination,
    const SNavPath* const path
  ) noexcept
  {
    return StorePathStartPointer(destination, path);
  }

  /**
   * Address: 0x005AFE50 (FUN_005AFE50)
   *
   * What it does:
   * Stores one `SNavPath::finish` pointer lane through an output pointer.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos** StorePathFinishPointer(
    SOCellPos** const destination,
    const SNavPath* const path
  ) noexcept
  {
    if (destination) {
      *destination = path ? path->finish : nullptr;
    }
    return destination;
  }

  /**
   * Address: 0x005B0870 (FUN_005B0870)
   *
   * What it does:
   * Computes the cell-span distance between two raw stored dword addresses.
   */
  [[nodiscard]] std::int32_t CountPathCellSpan(const SOCellPos* const end, const SOCellPos* const begin) noexcept
  {
    if (!end || !begin || end < begin) {
      return 0;
    }

    return static_cast<std::int32_t>(end - begin);
  }

  /**
   * Address: 0x005B0900 (FUN_005B0900)
   *
   * What it does:
   * Wrapper lane that preserves the legacy insert-path calling shape and
   * forwards to the range-insert helper.
   */
  [[nodiscard]] std::uint32_t InsertCellRangeBridge(
    SNavPath& path,
    SOCellPos* const insertPos,
    const SOCellPos* const sourceBegin,
    const SOCellPos* const sourceEnd
  )
  {
    const std::size_t insertCount = static_cast<std::size_t>(CountPathCellSpan(sourceEnd, sourceBegin));
    if (insertCount == 0u) {
      return static_cast<std::uint32_t>(path.Count());
    }

    const std::size_t currentCount = path.Count();
    if (insertCount > (GetPathCellLimitAlias() - currentCount)) {
      ThrowPathCellVectorTooLong();
    }

    const std::size_t currentCapacity = path.CapacityCount();
    const std::size_t insertIndex =
      (path.start && insertPos) ? static_cast<std::size_t>(insertPos - path.start) : 0u;
    SOCellPos* const position = path.start ? (path.start + insertIndex) : nullptr;
    const std::size_t requiredSize = currentCount + insertCount;

    if (currentCapacity >= requiredSize) {
      SOCellPos* const oldFinish = path.finish;
      const std::size_t tailCount = static_cast<std::size_t>(oldFinish - position);
      if (tailCount >= insertCount) {
        SOCellPos* const tailSource = oldFinish - insertCount;
        path.finish = CopyCellsForInsertBridge(oldFinish, tailSource, oldFinish);
        (void)MoveCellsBackward(oldFinish, position, tailSource);
        (void)CopyCellsForwardAllowNull(position, sourceBegin, sourceEnd);
      } else {
        const std::uint32_t spillCount = static_cast<std::uint32_t>(insertCount - tailCount);
        (void)CopyCellsForwardAllowNull(oldFinish, sourceBegin, sourceBegin + spillCount);
        path.finish = oldFinish + spillCount;
        path.finish = CopyCellsForwardStackBridge(path.finish, position, oldFinish);
        (void)CopyCellsForwardAllowNull(position, sourceBegin + spillCount, sourceEnd);
      }
      return static_cast<std::uint32_t>(path.Count());
    }

    std::size_t grownCapacity = ComputeGrowthCapacity(currentCapacity, requiredSize);
    if (grownCapacity > GetPathCellLimitAlias()) {
      ThrowPathCellVectorTooLong();
    }

    SOCellPos* const newStorage = (grownCapacity != 0u)
      ? AllocatePathCellStorageChecked(static_cast<std::uint32_t>(grownCapacity))
      : static_cast<SOCellPos*>(::operator new(0));

    SOCellPos* write = CopyCellsForwardAllowNull(newStorage, path.start, position);
    write = CopyCellsForwardAllowNull(write, sourceBegin, sourceEnd);
    write = CopyCellsForwardAllowNull(write, position, path.finish);

    if (path.start) {
      ::operator delete(path.start);
    }

    path.start = newStorage;
    path.finish = write;
    path.capacity = newStorage + grownCapacity;
    return static_cast<std::uint32_t>(path.Count());
  }

  /**
   * Address: 0x005B0A00 (FUN_005B0A00)
   *
   * What it does:
   * Zero-length fill bridge that preserves the legacy no-op call shape used by
   * the caller thunk lane.
   */
  [[nodiscard]] std::uint32_t FillZeroCellsBridge(SOCellPos* const destination) noexcept
  {
    const SOCellPos zeroCell{};
    return FillCellsWithValue(0u, zeroCell, destination);
  }

  /**
   * Address: 0x005B0DE0 (FUN_005B0DE0)
   *
   * What it does:
   * Zero-length copy bridge that preserves the legacy null-tolerant forward
   * copy call shape.
   */
  [[nodiscard]] SOCellPos* CopyZeroCellRangeBridge(SOCellPos* const destination) noexcept
  {
    return CopyCellsForwardAllowNull(destination, nullptr, nullptr);
  }

  /**
   * Address: 0x005B0E20 (FUN_005B0E20)
   *
   * What it does:
   * Secondary zero-length copy bridge for the same null-tolerant lane.
   */
  [[nodiscard]] SOCellPos* CopyZeroCellRangeBridge2(SOCellPos* const destination) noexcept
  {
    return CopyCellsForwardAllowNull(destination, nullptr, nullptr);
  }

  /**
   * Address: 0x005B0E60 (FUN_005B0E60)
   *
   * What it does:
   * Extracts the high byte from one 32-bit packed lane value.
   */
  [[nodiscard]] std::uint8_t ExtractArgumentHighByte(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  }

  /**
   * Address: 0x005B03D0 (FUN_005B03D0)
   *
   * What it does:
   * Inserts `insertCount` copies of `value` at `insertPos` within one nav-path
   * span while preserving vector-style growth and overlap behavior.
   */
  SOCellPos* InsertCellCopiesAt(
    SNavPath& path,
    SOCellPos* insertPos,
    const std::uint32_t insertCount,
    const SOCellPos& value
  )
  {
    if (insertCount == 0u) {
      return insertPos ? insertPos : path.start;
    }

    const std::size_t size = path.Count();
    if (size > kMaxPathCellCount || insertCount > (kMaxPathCellCount - size)) {
      ThrowPathCellVectorTooLong();
    }

    const std::size_t capacity = path.CapacityCount();
    const std::size_t insertIndex = (path.start && insertPos) ? static_cast<std::size_t>(insertPos - path.start) : 0u;
    SOCellPos* const position = path.start ? (path.start + insertIndex) : nullptr;
    const std::size_t requiredSize = size + insertCount;

    if (capacity >= requiredSize) {
      SOCellPos* const oldFinish = path.finish;
      const std::size_t tailCount = static_cast<std::size_t>(oldFinish - position);
      if (tailCount >= insertCount) {
        SOCellPos* const tailSource = oldFinish - insertCount;
        path.finish = CopyCellsForInsertBridge(oldFinish, tailSource, oldFinish);
        (void)MoveCellsBackward(oldFinish, position, tailSource);
        (void)FillCellsWithValue(insertCount, value, position);
      } else {
        const std::uint32_t spillCount = insertCount - static_cast<std::uint32_t>(tailCount);
        (void)FillCellsWithValue(spillCount, value, oldFinish);
        path.finish = oldFinish + spillCount;
        path.finish = CopyCellsForwardStackBridge(path.finish, position, oldFinish);
        (void)FillCellsWithValue(static_cast<std::uint32_t>(tailCount), value, position);
      }
      return position;
    }

    const std::size_t grownCapacity = ComputeGrowthCapacity(capacity, requiredSize);
    if (grownCapacity > kMaxPathCellCount) {
      ThrowPathCellVectorTooLong();
    }

    SOCellPos* const newStorage = (grownCapacity != 0u)
      ? AllocatePathCellStorageChecked(static_cast<std::uint32_t>(grownCapacity))
      : static_cast<SOCellPos*>(::operator new(0));

    SOCellPos* write = CopyCellsForwardAllowNull(newStorage, path.start, position);
    (void)FillCellsWithValue(insertCount, value, write);
    write += insertCount;
    write = CopyCellsForwardAllowNull(write, position, path.finish);

    if (path.start) {
      ::operator delete(path.start);
    }

    path.start = newStorage;
    path.finish = write;
    path.capacity = newStorage + grownCapacity;
    return path.start + insertIndex;
  }
} // namespace

std::size_t SNavPath::Count() const noexcept
{
  if (!start || !finish || finish < start) {
    return 0;
  }
  return static_cast<std::size_t>(CountPathCellSpan(finish, start));
}

std::int32_t SNavPath::CountInt() const noexcept
{
  return static_cast<std::int32_t>(Count());
}

std::size_t SNavPath::CapacityCount() const noexcept
{
  if (!start || !capacity || capacity < start) {
    return 0;
  }
  return static_cast<std::size_t>(CountPathCellSpan(capacity, start));
}

void SNavPath::ClearContent() noexcept
{
  if (start) {
    finish = start;
  }
}

void SNavPath::FreeStorage() noexcept
{
  if (start) {
    ::operator delete(start);
  }
  reserved0 = 0;
  start = nullptr;
  finish = nullptr;
  capacity = nullptr;
}

void SNavPath::EnsureCapacity(const std::size_t requiredCount)
{
  if (requiredCount > kMaxPathCellCount) {
    ThrowPathCellVectorTooLong();
  }

  const std::size_t currentCapacity = CapacityCount();
  if (currentCapacity >= requiredCount) {
    return;
  }

  const std::size_t currentSize = Count();
  std::size_t newCapacity = std::max(requiredCount, std::max<std::size_t>(4, currentCapacity * 2));
  if (newCapacity > GetPathCellLimit()) {
    newCapacity = requiredCount;
  }

  auto* const storage = AllocatePathCellStorageChecked(static_cast<std::uint32_t>(newCapacity));

  if (start && currentSize > 0) {
    (void)CopyCellsForwardUnchecked(storage, start, finish);
  }

  if (start) {
    ::operator delete(start);
  }

  start = storage;
  finish = storage + currentSize;
  capacity = storage + newCapacity;
}

/**
 * Address: 0x005AFCC0 (FUN_005AFCC0)
 *
 * What it does:
 * Assigns one source span into this path storage and clears content when the
 * source is empty.
 */
void SNavPath::AssignCopy(const SNavPath& src)
{
  if (this == &src) {
    return;
  }

  const std::size_t count = src.Count();
  if (count == 0) {
    ClearContent();
    return;
  }

  if (count > CapacityCount()) {
    FreeStorage();
    (void)InitializePathStorageExact(*this, static_cast<std::uint32_t>(count));
  }

  finish = CopyCellsForAssignBridge(start, src.start, src.start + count);
}

void SNavPath::AppendCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::size_t appendCount = static_cast<std::size_t>(CountPathCellSpan(end, begin));
  const std::size_t currentCount = Count();
  if (appendCount > (GetPathCellLimitAlias() - currentCount)) {
    ThrowPathCellVectorTooLong();
  }

  EnsureCapacity(currentCount + appendCount);
  finish = CopyCellsForwardUnchecked(finish, begin, end);
}

/**
 * Address: 0x005B0B60 (FUN_005B0B60)
 *
 * What it does:
 * Prepends one cell range at path front, preserving existing ordering while
 * growing capacity when required.
 */
void SNavPath::PrependCells(const SOCellPos* const begin, const SOCellPos* const end)
{
  if (!begin || !end || end <= begin) {
    return;
  }

  const std::uint32_t prependCount = static_cast<std::uint32_t>(CountPathCellSpan(end, begin));
  const std::size_t currentCount = Count();
  if (prependCount > (GetPathCellLimitAlias() - currentCount)) {
    ThrowPathCellVectorTooLong();
  }

  const std::size_t requiredCount = currentCount + prependCount;
  const std::size_t currentCapacity = CapacityCount();
  if (currentCapacity >= requiredCount) {
    SOCellPos* const oldFinish = finish;
    if (currentCount >= prependCount) {
      SOCellPos* const tailSource = oldFinish - prependCount;
      finish = CopyCellsForInsertBridge(oldFinish, tailSource, oldFinish);
      (void)MoveCellsBackward(oldFinish, start, tailSource);
      (void)CopyCellsForwardUncheckedStackBridge(start, begin, end);
    } else {
      const std::uint32_t tailCount = static_cast<std::uint32_t>(currentCount);
      finish = CopyCellsForwardStackBridge(oldFinish, begin + tailCount, end);
      finish = CopyCellsForInsertBridge(finish, start, oldFinish);
      (void)CopyCellsForwardUncheckedStackBridge(start, begin, begin + tailCount);
    }
    return;
  }

  std::size_t newCapacity = ComputeGrowthCapacity(currentCapacity, requiredCount);
  if (newCapacity > GetPathCellLimit()) {
    ThrowPathCellVectorTooLong();
  }

  SOCellPos* const newStorage = (newCapacity != 0u)
    ? AllocatePathCellStorageChecked(static_cast<std::uint32_t>(newCapacity))
    : static_cast<SOCellPos*>(::operator new(0));

  SOCellPos* write = CopyCellsForwardStackBridge(newStorage, begin, end);
  write = CopyCellsForInsertBridge(write, start, finish);

  if (start) {
    ::operator delete(start);
  }

  start = newStorage;
  finish = write;
  capacity = newStorage + newCapacity;
}

void SNavPath::AppendCell(const SOCellPos& cell)
{
  if (!start || finish >= capacity) {
    (void)InsertCellCopiesAt(*this, finish ? finish : start, 1u, cell);
    return;
  }

  *finish = cell;
  ++finish;
}

void SNavPath::EraseFrontCell() noexcept
{
  const std::size_t count = Count();
  if (count == 0) {
    return;
  }

  if (count == 1) {
    finish = start;
    return;
  }

  std::memmove(start, start + 1, sizeof(SOCellPos) * (count - 1));
  --finish;
}

void SNavPath::EraseFrontCells(std::int32_t count) noexcept
{
  while (count > 0 && CountInt() > 0) {
    EraseFrontCell();
    --count;
  }
}

gpg::RType* IAiNavigator::sType = nullptr;

/**
 * Address: 0x005A2CF0 (FUN_005A2CF0, ??0IAiNavigator@Moho@@QAE@XZ)
 *
 * What it does:
 * Initializes IAiNavigator base state and resets `mListenerNode` to a
 * self-linked singleton intrusive node.
 */
IAiNavigator::IAiNavigator()
{
  mListenerNode.ListUnlinkSelf();
}

/**
 * Address: 0x005A37D0 (FUN_005A37D0)
 *
 * What it does:
 * Alternate base-initialization lane that restores detached listener-node
 * state for one IAiNavigator interface subobject.
 */
[[maybe_unused]] IAiNavigator* InitializeIAiNavigatorInterfaceLane(
  IAiNavigator* const navigatorStorage
) noexcept
{
  if (navigatorStorage == nullptr) {
    return nullptr;
  }

  navigatorStorage->mListenerNode.ListUnlinkSelf();
  return navigatorStorage;
}

/**
 * Address: 0x005A5790 (FUN_005A5790, ?AI_CreatePathingNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiNavigatorLand` instance bound to `unit` and returns it as
 * the `IAiNavigator` interface pointer.
 */
IAiNavigator* moho::AI_CreatePathingNavigator(Unit* const unit)
{
  auto* const navigator = new (std::nothrow) CAiNavigatorLand(unit);
  return navigator;
}

/**
 * Address: 0x005A5800 (FUN_005A5800, ?AI_CreateAirNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
 *
 * What it does:
 * Allocates one `CAiNavigatorAir` instance bound to `unit` and returns it as
 * the `IAiNavigator` interface pointer.
 */
IAiNavigator* moho::AI_CreateAirNavigator(Unit* const unit)
{
  auto* const navigator = new (std::nothrow) CAiNavigatorAir(unit);
  return navigator;
}

/**
 * Address: 0x005A5850 (FUN_005A5850, ?AI_ClearPathData@Moho@@YAXXZ)
 *
 * What it does:
 * Preserves the legacy global AI path-data clear hook as a deliberate no-op.
 */
void moho::AI_ClearPathData()
{
}

/**
 * Address: 0x005A2D30 (FUN_005A2D30, scalar deleting thunk)
 */
IAiNavigator::~IAiNavigator()
{
  mListenerNode.ListUnlink();
}

/**
 * Address: 0x005A7B60 (FUN_005A7B60, Moho::IAiNavigator::MemberDeserialize)
 *
 * What it does:
 * Loads IAiNavigator broadcaster listener payload through reflected
 * `Broadcaster<EAiNavigatorEvent>` metadata.
 */
void IAiNavigator::MemberDeserialize(IAiNavigator* const object, gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(
    CachedBroadcasterEAiNavigatorEventType(),
    object ? static_cast<void*>(&object->mListenerNode) : nullptr,
    ownerRef
  );
}

/**
 * Address: 0x005A7BB0 (FUN_005A7BB0, Moho::IAiNavigator::MemberSerialize)
 *
 * What it does:
 * Saves IAiNavigator broadcaster listener payload through reflected
 * `Broadcaster<EAiNavigatorEvent>` metadata.
 */
void IAiNavigator::MemberSerialize(const IAiNavigator* const object, gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(
    CachedBroadcasterEAiNavigatorEventType(),
    object ? static_cast<const void*>(&object->mListenerNode) : nullptr,
    ownerRef
  );
}

/**
 * Address: 0x00BCC9A0 (FUN_00BCC9A0)
 *
 * What it does:
 * Registers the broadcaster reflection lane for `EAiNavigatorEvent` and
 * installs process-exit cleanup.
 */
int moho::register_RBroadcasterRType_EAiNavigatorEvent()
{
  (void)RegisterBroadcasterEAiNavigatorEventType();
  return std::atexit(&cleanup_RBroadcasterRType_EAiNavigatorEvent);
}

/**
 * Address: 0x00BCC9C0 (FUN_00BCC9C0)
 *
 * What it does:
 * Registers the listener reflection lane for `EAiNavigatorEvent` and installs
 * process-exit cleanup.
 */
int moho::register_RListenerRType_EAiNavigatorEvent()
{
  (void)RegisterListenerEAiNavigatorEventType();
  return std::atexit(&cleanup_RListenerRType_EAiNavigatorEvent);
}

namespace
{
  struct IAiNavigatorReflectionBootstrap
  {
    IAiNavigatorReflectionBootstrap()
    {
      (void)moho::register_RBroadcasterRType_EAiNavigatorEvent();
      (void)moho::register_RListenerRType_EAiNavigatorEvent();
    }
  };

  [[maybe_unused]] IAiNavigatorReflectionBootstrap gIAiNavigatorReflectionBootstrap;
} // namespace

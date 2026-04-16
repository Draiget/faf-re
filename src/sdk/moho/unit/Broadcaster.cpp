#include "moho/unit/Broadcaster.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/Listener.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace gpg
{
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(WriteArchive* archive, int objectPtr);
} // namespace gpg

namespace
{
  void cleanup_RBroadcasterRType_ECommandEvent_Name();
  void cleanup_RListenerRType_ECommandEvent_Name();

  gpg::RType* gECommandEventTypeCache = nullptr;

  /**
   * Address: 0x005F45D0 (FUN_005F45D0)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `ECommandEvent`.
   */
  [[nodiscard]] gpg::RType* ResolveECommandEventTypeCachePrimary()
  {
    if (!gECommandEventTypeCache) {
      gECommandEventTypeCache = gpg::LookupRType(typeid(moho::ECommandEvent));
    }
    return gECommandEventTypeCache;
  }

  [[nodiscard]] gpg::RType* CachedECommandEventType()
  {
    gpg::RType* cached = ResolveECommandEventTypeCachePrimary();
    if (!cached) {
      cached = gpg::REF_FindTypeNamed("ECommandEvent");
      gECommandEventTypeCache = cached;
    }
    return cached;
  }

  [[nodiscard]] msvc8::string& RBroadcasterECommandEventTypeName()
  {
    static msvc8::string value;
    return value;
  }

  [[nodiscard]] bool& RBroadcasterECommandEventTypeNameCleanupRegistered()
  {
    static bool value = false;
    return value;
  }

  [[nodiscard]] msvc8::string& RListenerECommandEventTypeName()
  {
    static msvc8::string value;
    return value;
  }

  [[nodiscard]] bool& RListenerECommandEventTypeNameCleanupRegistered()
  {
    static bool value = false;
    return value;
  }

  class RBroadcasterRType_ECommandEvent final : public gpg::RType
  {
  public:
    ~RBroadcasterRType_ECommandEvent() override;

    /**
     * Address: 0x006EA7A0 (FUN_006EA7A0, Moho::RBroadcasterRType_ECommandEvent::SerLoad)
     *
     * What it does:
     * Deserializes one intrusive `Broadcaster<ECommandEvent>` lane by reading
     * listener pointers until a null sentinel and relinking each listener node
     * into the broadcaster ring.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EA810 (FUN_006EA810, Moho::RBroadcasterRType_ECommandEvent::SerSave)
     *
     * What it does:
     * Serializes one intrusive `Broadcaster<ECommandEvent>` lane by writing
     * each linked listener pointer as `UNOWNED` and terminating with one null
     * pointer record.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E97D0 (FUN_006E97D0, Moho::RBroadcasterRType_ECommandEvent::GetName)
     *
     * What it does:
     * Lazily resolves the reflected `ECommandEvent` type name, formats the
     * broadcaster wrapper name, and caches the result for reuse.
     */
    [[nodiscard]] const char* GetName() const override
    {
      auto& cachedName = RBroadcasterECommandEventTypeName();
      auto& cleanupRegistered = RBroadcasterECommandEventTypeNameCleanupRegistered();
      if (cachedName.empty()) {
        gpg::RType* const eventType = CachedECommandEventType();
        const char* const eventTypeName = eventType ? eventType->GetName() : "ECommandEvent";
        cachedName = gpg::STR_Printf("Broadcaster<%s>", eventTypeName ? eventTypeName : "ECommandEvent");
        if (!cleanupRegistered) {
          cleanupRegistered = true;
          (void)std::atexit(&cleanup_RBroadcasterRType_ECommandEvent_Name);
        }
      }

      return cachedName.c_str();
    }

    void Init() override
    {
      size_ = sizeof(moho::Broadcaster);
      serLoadFunc_ = &RBroadcasterRType_ECommandEvent::SerLoad;
      serSaveFunc_ = &RBroadcasterRType_ECommandEvent::SerSave;
      Finish();
    }
  };

  class RBroadcasterRType_EUnitCommandQueueStatus final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006F85E0 (FUN_006F85E0, Moho::RBroadcasterRType_EUnitCommandQueueStatus::SerLoad)
     *
     * What it does:
     * Deserializes one intrusive `Broadcaster<EUnitCommandQueueStatus>` lane by
     * reading listener pointers until a null sentinel and relinking each
     * listener node into the broadcaster ring.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006F92F0 (FUN_006F92F0, Moho::RBroadcasterRType_EUnitCommandQueueStatus::dtr)
     *
     * What it does:
     * Tears down one broadcaster-status type-info descriptor and releases
     * inherited `gpg::RType` reflection storage lanes.
     */
    ~RBroadcasterRType_EUnitCommandQueueStatus() override;

    [[nodiscard]] const char* GetName() const override
    {
      return "Broadcaster<EUnitCommandQueueStatus>";
    }

    /**
     * Address: 0x006F8210 (FUN_006F8210)
     *
     * What it does:
     * Binds serializer load/save callback lanes and version metadata for
     * `Broadcaster<EUnitCommandQueueStatus>` reflection.
     */
    void Init() override
    {
      size_ = sizeof(moho::Broadcaster);
      version_ = 1;
      serLoadFunc_ = &RBroadcasterRType_EUnitCommandQueueStatus::SerLoad;
      serSaveFunc_ = reinterpret_cast<gpg::RType::save_func_t>(
        &gpg::SaveBroadcasterListenerChainEUnitCommandQueueStatus
      );
    }
  };

  class RListenerRType_ECommandEvent final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005F43B0 (FUN_005F43B0, Moho::RListenerRType_ECommandEvent::GetName)
     *
     * What it does:
     * Lazily resolves the reflected `ECommandEvent` type name, formats the
     * listener wrapper name, and caches the result for reuse.
     */
    [[nodiscard]] const char* GetName() const override;

    void Init() override
    {
      size_ = sizeof(moho::Listener<moho::ECommandEvent>);
      Finish();
    }
  };

  class RListenerRType_EUnitCommandQueueStatus final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006F9350 (FUN_006F9350, Moho::RListenerRType_EUnitCommandQueueStatus::dtr)
     *
     * What it does:
     * Tears down one listener-status type-info descriptor and releases
     * inherited `gpg::RType` reflection storage lanes.
     */
    ~RListenerRType_EUnitCommandQueueStatus() override;

    [[nodiscard]] const char* GetName() const override
    {
      return "Listener<EUnitCommandQueueStatus>";
    }

    void Init() override
    {
      size_ = sizeof(moho::Listener<moho::EUnitCommandQueueStatus>);
      Finish();
    }
  };

  /**
   * Address: 0x006EBCC0 (FUN_006EBCC0, RBroadcasterRType_ECommandEvent non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one
   * `RBroadcasterRType_ECommandEvent` instance while preserving outer storage
   * ownership.
   */
  [[maybe_unused]] void DestroyBroadcasterCommandEventRTypeBody(
    RBroadcasterRType_ECommandEvent* const typeInfo
  ) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  RBroadcasterRType_ECommandEvent::~RBroadcasterRType_ECommandEvent()
  {
    DestroyBroadcasterCommandEventRTypeBody(this);
  }

  /**
   * Address: 0x006F92F0 (FUN_006F92F0, Moho::RBroadcasterRType_EUnitCommandQueueStatus::dtr)
   *
   * What it does:
   * Tears down one broadcaster-status type-info descriptor and releases
   * inherited `gpg::RType` reflection storage lanes.
   */
  RBroadcasterRType_EUnitCommandQueueStatus::~RBroadcasterRType_EUnitCommandQueueStatus() = default;

  /**
   * Address: 0x006F9350 (FUN_006F9350, Moho::RListenerRType_EUnitCommandQueueStatus::dtr)
   *
   * What it does:
   * Tears down one listener-status type-info descriptor and releases
   * inherited `gpg::RType` reflection storage lanes.
   */
  RListenerRType_EUnitCommandQueueStatus::~RListenerRType_EUnitCommandQueueStatus() = default;

  [[nodiscard]] RBroadcasterRType_EUnitCommandQueueStatus& BroadcasterStatusRType()
  {
    static RBroadcasterRType_EUnitCommandQueueStatus sType;
    return sType;
  }

  [[nodiscard]] RBroadcasterRType_ECommandEvent& BroadcasterCommandEventRType()
  {
    static RBroadcasterRType_ECommandEvent sType;
    return sType;
  }

  [[nodiscard]] RListenerRType_EUnitCommandQueueStatus& ListenerStatusRType()
  {
    static RListenerRType_EUnitCommandQueueStatus sType;
    return sType;
  }

  [[nodiscard]] RListenerRType_ECommandEvent& ListenerCommandEventRType()
  {
    static RListenerRType_ECommandEvent sType;
    return sType;
  }

  [[nodiscard]] moho::Listener<moho::EUnitCommandQueueStatus>* ListenerFromLinkNode(moho::Broadcaster* const node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    auto* const bytePtr = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<moho::Listener<moho::EUnitCommandQueueStatus>*>(
      bytePtr - offsetof(moho::Listener<moho::EUnitCommandQueueStatus>, mListenerLink)
    );
  }

  [[nodiscard]] moho::Listener<moho::ECommandEvent>* ListenerFromCommandEventLinkNode(moho::Broadcaster* const node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    auto* const bytePtr = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<moho::Listener<moho::ECommandEvent>*>(
      bytePtr - offsetof(moho::Listener<moho::ECommandEvent>, mListenerLink)
    );
  }

  /**
   * Address: 0x006E8190 (FUN_006E8190)
   *
   * What it does:
   * Unlinks one broadcaster intrusive-list node and resets it to self-linked
   * sentinel state.
   */
  [[maybe_unused]] moho::Broadcaster* UnlinkBroadcasterNodeAndResetSentinel(moho::Broadcaster* const node) noexcept
  {
    if (node == nullptr || node->mPrev == nullptr || node->mNext == nullptr) {
      return node;
    }

    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x005F4567 (FUN_005F4567)
   *
   * What it does:
   * Unlinks one broadcaster node from its current intrusive ring, restores it
   * to singleton links, then relinks it directly before `anchor`.
   */
  [[maybe_unused]] moho::Broadcaster* RelinkBroadcasterNodeBeforeAnchor(
    moho::Broadcaster* const node,
    moho::Broadcaster* const anchor
  ) noexcept
  {
    if (node == nullptr || anchor == nullptr) {
      return node;
    }

    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    node->mPrev = node;
    node->mNext = node;

    node->mPrev = anchor->mPrev;
    node->mNext = anchor;
    anchor->mPrev = node;
    node->mPrev->mNext = node;
    return node;
  }

  struct BroadcasterOwnerNodeOffset4RuntimeView
  {
    std::uint32_t ownerWord; // +0x00
    moho::Broadcaster node;  // +0x04
  };
  static_assert(
    offsetof(BroadcasterOwnerNodeOffset4RuntimeView, node) == 0x04,
    "BroadcasterOwnerNodeOffset4RuntimeView::node offset must be 0x04"
  );
  static_assert(
    sizeof(BroadcasterOwnerNodeOffset4RuntimeView) == 0x0C,
    "BroadcasterOwnerNodeOffset4RuntimeView size must be 0x0C"
  );

  /**
   * Address: 0x005F4560 (FUN_005F4560)
   *
   * What it does:
   * Adjusts one owner pointer to its embedded broadcaster node at `+0x04`
   * and dispatches to the canonical intrusive relink lane.
   */
  [[maybe_unused]] moho::Broadcaster* RelinkOwnerOffset4NodeDispatchToCanonicalRelink(
    BroadcasterOwnerNodeOffset4RuntimeView* const owner,
    moho::Broadcaster* const anchor
  ) noexcept
  {
    moho::Broadcaster* node = nullptr;
    if (owner != nullptr) {
      node = &owner->node;
    }
    return RelinkBroadcasterNodeBeforeAnchor(node, anchor);
  }

  /**
   * Address: 0x005F4360 (FUN_005F4360)
   *
   * What it does:
   * Resets one broadcaster link node to singleton self-links.
   */
  [[maybe_unused]] moho::Broadcaster* ResetBroadcasterNodeSelfLinks(moho::Broadcaster* const node) noexcept
  {
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x005F4370 (FUN_005F4370)
   * Address: 0x005F4590 (FUN_005F4590)
   *
   * What it does:
   * Unlinks one broadcaster node from its current intrusive ring and restores
   * singleton self-links.
   */
  [[maybe_unused]] moho::Broadcaster* UnlinkBroadcasterNodeSelfLinkAlias(moho::Broadcaster* const node) noexcept
  {
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x005F4610 (FUN_005F4610)
   *
   * What it does:
   * Unlinks one broadcaster node from its current ring and relinks it
   * directly before `anchor`.
   */
  [[maybe_unused]] moho::Broadcaster* RelinkBroadcasterNodeBeforeAnchorAlias(
    moho::Broadcaster* const node,
    moho::Broadcaster* const anchor
  ) noexcept
  {
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;

    node->mPrev = anchor->mPrev;
    node->mNext = anchor;
    anchor->mPrev = node;
    node->mPrev->mNext = node;
    return node;
  }

  /**
   * Address: 0x005F42F0 (FUN_005F42F0)
   * Address: 0x005F4340 (FUN_005F4340)
   *
   * What it does:
   * Unlinks the owner node at offset `+0x04` and returns that node lane after
   * singleton self-link reset.
   */
  [[maybe_unused]] moho::Broadcaster* UnlinkOwnerOffset4BroadcasterNodeAndReturnNode(
    BroadcasterOwnerNodeOffset4RuntimeView* const owner
  ) noexcept
  {
    moho::Broadcaster* const node = &owner->node;
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;
    return node;
  }

  /**
   * Address: 0x005F42C0 (FUN_005F42C0)
   * Address: 0x005F4310 (FUN_005F4310)
   *
   * What it does:
   * Unlinks the owner node at offset `+0x04`, resets it to singleton links,
   * and relinks it directly before `anchor`.
   */
  [[maybe_unused]] moho::Broadcaster* RelinkOwnerOffset4BroadcasterNodeBeforeAnchor(
    BroadcasterOwnerNodeOffset4RuntimeView* const owner,
    moho::Broadcaster* const anchor
  ) noexcept
  {
    moho::Broadcaster* const node = &owner->node;
    node->mNext->mPrev = node->mPrev;
    node->mPrev->mNext = node->mNext;
    node->mPrev = node;
    node->mNext = node;

    node->mPrev = anchor->mPrev;
    node->mNext = anchor;
    anchor->mPrev = node;
    node->mPrev->mNext = node;
    return node;
  }

  /**
   * Address: 0x006EA7A0 (FUN_006EA7A0, Moho::RBroadcasterRType_ECommandEvent::SerLoad)
   *
   * What it does:
   * Reads listener pointers until a null sentinel and relinks each listener's
   * intrusive broadcaster node before the destination broadcaster sentinel.
   */
  void RBroadcasterRType_ECommandEvent::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    moho::Listener<moho::ECommandEvent>* listener = nullptr;
    archive->ReadPointer_Listener_ECommandEvent(&listener, ownerRef);
    while (listener != nullptr) {
      listener->mListenerLink.ListLinkBefore(broadcaster);
      archive->ReadPointer_Listener_ECommandEvent(&listener, ownerRef);
    }
  }

  /**
   * Address: 0x006EA810 (FUN_006EA810, Moho::RBroadcasterRType_ECommandEvent::SerSave)
   *
   * What it does:
   * Serializes one intrusive broadcaster lane by writing each linked command
   * listener pointer as `UNOWNED` and appending a null sentinel pointer.
   */
  void RBroadcasterRType_ECommandEvent::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RRef pointerRef{};

    for (
      moho::Broadcaster* node = static_cast<moho::Broadcaster*>(broadcaster->mNext);
      node != broadcaster;
      node = static_cast<moho::Broadcaster*>(node->mNext)
    ) {
      (void)gpg::RRef_Listener_ECommandEvent(&pointerRef, ListenerFromCommandEventLinkNode(node));
      gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

    (void)gpg::RRef_Listener_ECommandEvent(&pointerRef, nullptr);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  /**
   * Address: 0x006F85E0 (FUN_006F85E0, Moho::RBroadcasterRType_EUnitCommandQueueStatus::SerLoad)
   *
   * What it does:
   * Reads listener pointers until a null sentinel and relinks each
   * `Listener<EUnitCommandQueueStatus>` node before the destination
   * broadcaster sentinel.
   */
  void RBroadcasterRType_EUnitCommandQueueStatus::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    moho::Listener<moho::EUnitCommandQueueStatus>* listener = nullptr;
    archive->ReadPointer_Listener_EUnitCommandQueueStatus(&listener, ownerRef);
    while (listener != nullptr) {
      listener->mListenerLink.ListUnlink();
      listener->mListenerLink.ListLinkBefore(broadcaster);
      archive->ReadPointer_Listener_EUnitCommandQueueStatus(&listener, ownerRef);
    }
  }

  template <class TType>
  void ResetRTypeFieldAndBaseVectors(TType& type) noexcept
  {
    type.fields_ = msvc8::vector<gpg::RField>{};
    type.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BFF060 (FUN_00BFF060, sub_BFF060)
   *
   * What it does:
   * Releases broadcaster status-type reflection field/base vector storage and
   * resets both vectors to empty state for process teardown.
   */
  void cleanup_Broadcaster_EUnitCommandQueueStatus_RType()
  {
    ResetRTypeFieldAndBaseVectors(BroadcasterStatusRType());
  }

  /**
   * Address: 0x00BFEE20 (FUN_00BFEE20, sub_BFEE20)
   *
   * What it does:
   * Releases broadcaster command-event reflection field/base vector storage and
   * resets both vectors to empty state for process teardown.
   */
  void cleanup_Broadcaster_ECommandEvent_RType()
  {
    ResetRTypeFieldAndBaseVectors(BroadcasterCommandEventRType());
  }

  /**
   * Address: 0x00BFECD0 (FUN_00BFECD0, sub_BFECD0)
   *
   * What it does:
   * Releases the cached lexical name for `Broadcaster<ECommandEvent>` during
   * process teardown.
   */
  void cleanup_RBroadcasterRType_ECommandEvent_Name()
  {
    RBroadcasterECommandEventTypeName() = msvc8::string{};
    RBroadcasterECommandEventTypeNameCleanupRegistered() = false;
  }

  void cleanup_RListenerRType_ECommandEvent_Name()
  {
    RListenerECommandEventTypeName() = msvc8::string{};
    RListenerECommandEventTypeNameCleanupRegistered() = false;
  }

  /**
   * Address: 0x005F43B0 (FUN_005F43B0, Moho::RListenerRType_ECommandEvent::GetName)
   *
   * What it does:
   * Lazily resolves the reflected `ECommandEvent` type name, formats the
   * listener wrapper name, and caches the result for reuse.
   */
  const char* RListenerRType_ECommandEvent::GetName() const
  {
    auto& cachedName = RListenerECommandEventTypeName();
    auto& cleanupRegistered = RListenerECommandEventTypeNameCleanupRegistered();
    if (cachedName.empty()) {
      gpg::RType* const eventType = CachedECommandEventType();
      const char* const eventTypeName = eventType ? eventType->GetName() : "ECommandEvent";
      cachedName = gpg::STR_Printf("Listener<%s>", eventTypeName ? eventTypeName : "ECommandEvent");
      if (!cleanupRegistered) {
        cleanupRegistered = true;
        (void)std::atexit(&cleanup_RListenerRType_ECommandEvent_Name);
      }
    }

    return cachedName.c_str();
  }

  /**
   * Address: 0x00BFF000 (FUN_00BFF000, sub_BFF000)
   *
   * What it does:
   * Releases listener status-type reflection field/base vector storage and
   * resets both vectors to empty state for process teardown.
   */
  void cleanup_Listener_EUnitCommandQueueStatus_RType()
  {
    ResetRTypeFieldAndBaseVectors(ListenerStatusRType());
  }

  template <gpg::RType* (*InitFunc)(), void (*CleanupFunc)()>
  int RegisterRTypeAndInstallAtexit() noexcept
  {
    (void)InitFunc();
    return std::atexit(CleanupFunc);
  }
} // namespace

namespace moho
{
  namespace
  {
    struct CommandEventBroadcasterOwnerRuntimeView
    {
      std::byte lane00_33[0x34]{};
      Broadcaster commandEventBroadcaster; // +0x34
    };
    static_assert(
      offsetof(CommandEventBroadcasterOwnerRuntimeView, commandEventBroadcaster) == 0x34,
      "CommandEventBroadcasterOwnerRuntimeView::commandEventBroadcaster offset must be 0x34"
    );
  } // namespace

  /**
   * Address: 0x006E94A0 (FUN_006E94A0,
   * ?BroadcastEvent@?$Broadcaster@W4ECommandEvent@Moho@@@Moho@@IAEXW4ECommandEvent@2@@Z)
   *
   * What it does:
   * Broadcasts one command event to linked listeners while preserving
   * iteration safety if listeners relink/unlink themselves during callbacks.
   */
  void Broadcaster::BroadcastEvent(const ECommandEvent event)
  {
    Broadcaster detached{};

    if (mPrev == this) {
      return;
    }

    detached.mPrev = mPrev;
    detached.mNext = mNext;
    detached.mNext->mPrev = &detached;
    detached.mPrev->mNext = &detached;
    mPrev = this;
    mNext = this;

    while (detached.mPrev != &detached) {
      auto* const listenerLink = reinterpret_cast<Broadcaster*>(detached.mPrev);
      listenerLink->ListLinkAfter(this);

      if (Listener<ECommandEvent>* const listener = ListenerFromCommandEventLinkNode(listenerLink)) {
        listener->OnEvent(event);
      }
    }

    detached.mNext->mPrev = detached.mPrev;
    detached.mPrev->mNext = detached.mNext;
  }

  /**
   * Address: 0x006E9110 (FUN_006E9110)
   *
   * What it does:
   * Resolves one embedded broadcaster lane at owner offset `+0x34` and
   * forwards one command-event broadcast into that lane.
   */
  [[maybe_unused]] void BroadcastEmbeddedCommandEventLane(
    CommandEventBroadcasterOwnerRuntimeView* const ownerRuntime,
    const ECommandEvent event
  )
  {
    ownerRuntime->commandEventBroadcaster.BroadcastEvent(event);
  }

  /**
   * Address: 0x006F8070 (FUN_006F8070,
   * ?BroadcastEvent@?$Broadcaster@W4EUnitCommandQueueStatus@Moho@@@Moho@@IAEXW4EUnitCommandQueueStatus@2@@Z)
   *
   * What it does:
   * Broadcasts one queue-status event to linked listeners while preserving
   * iteration safety if listeners relink/unlink themselves during callbacks.
   */
  void Broadcaster::BroadcastEvent(const EUnitCommandQueueStatus event)
  {
    Broadcaster detached{};

    if (mPrev == this) {
      return;
    }

    detached.mPrev = mPrev;
    detached.mNext = mNext;
    detached.mNext->mPrev = &detached;
    detached.mPrev->mNext = &detached;
    mPrev = this;
    mNext = this;

    while (detached.mPrev != &detached) {
      auto* const listenerLink = reinterpret_cast<Broadcaster*>(detached.mPrev);
      listenerLink->ListLinkAfter(this);

      if (Listener<EUnitCommandQueueStatus>* const listener = ListenerFromLinkNode(listenerLink)) {
        listener->OnEvent(event);
      }
    }

    detached.mNext->mPrev = detached.mPrev;
    detached.mPrev->mNext = detached.mNext;
  }

  /**
   * Address: 0x006EBDF0 (FUN_006EBDF0, sub_6EBDF0)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Broadcaster_ECommandEvent_RType()
  {
    auto& type = BroadcasterCommandEventRType();
    gpg::PreRegisterRType(typeid(moho::BroadcasterEventTag<moho::ECommandEvent>), &type);
    return &type;
  }

  /**
   * Address: 0x005F4A70 (FUN_005F4A70, register_Listener_ECommandEvent_RType)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< ECommandEvent >` event-link family.
   */
  gpg::RType* register_Listener_ECommandEvent_RType()
  {
    auto& type = ListenerCommandEventRType();
    gpg::PreRegisterRType(typeid(moho::Listener<moho::ECommandEvent>), &type);
    return &type;
  }

  /**
   * Address: 0x00BD8FD0 (FUN_00BD8FD0, sub_BD8FD0)
   *
   * What it does:
   * Runs broadcaster command-event type registration and queues its shutdown
   * cleanup through `atexit`.
   */
  int register_Broadcaster_ECommandEvent_RType_AtExit()
  {
    return RegisterRTypeAndInstallAtexit<&register_Broadcaster_ECommandEvent_RType, &cleanup_Broadcaster_ECommandEvent_RType>();
  }

  /**
   * Address: 0x006F9210 (FUN_006F9210, sub_6F9210)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Broadcaster< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Broadcaster_EUnitCommandQueueStatus_RType()
  {
    auto& type = BroadcasterStatusRType();
    gpg::PreRegisterRType(typeid(moho::Broadcaster), &type);
    return &type;
  }

  /**
   * Address: 0x006F9270 (FUN_006F9270, sub_6F9270)
   *
   * What it does:
   * Initializes/preregisters reflection type metadata for the
   * `Listener< EUnitCommandQueueStatus >` event-link family.
   */
  gpg::RType* register_Listener_EUnitCommandQueueStatus_RType()
  {
    auto& type = ListenerStatusRType();
    gpg::PreRegisterRType(typeid(moho::Listener<moho::EUnitCommandQueueStatus>), &type);
    return &type;
  }

  /**
   * Address: 0x00BD95D0 (FUN_00BD95D0, sub_BD95D0)
   *
   * What it does:
   * Runs broadcaster status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Broadcaster_EUnitCommandQueueStatus_RType_AtExit()
  {
    return RegisterRTypeAndInstallAtexit<
      &register_Broadcaster_EUnitCommandQueueStatus_RType,
      &cleanup_Broadcaster_EUnitCommandQueueStatus_RType>();
  }

  /**
   * Address: 0x00BD95F0 (FUN_00BD95F0, sub_BD95F0)
   *
   * What it does:
   * Runs listener status-type registration and queues its shutdown cleanup
   * through `atexit`.
   */
  int register_Listener_EUnitCommandQueueStatus_RType_AtExit()
  {
    return RegisterRTypeAndInstallAtexit<
      &register_Listener_EUnitCommandQueueStatus_RType,
      &cleanup_Listener_EUnitCommandQueueStatus_RType>();
  }
} // namespace moho

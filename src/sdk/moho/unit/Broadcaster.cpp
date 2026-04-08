#include "moho/unit/Broadcaster.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/Listener.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace
{
  void cleanup_RBroadcasterRType_ECommandEvent_Name();
  void cleanup_RListenerRType_ECommandEvent_Name();

  [[nodiscard]] gpg::RType* CachedECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ECommandEvent));
      if (!cached) {
        cached = gpg::REF_FindTypeNamed("ECommandEvent");
      }
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
      Finish();
    }
  };

  class RBroadcasterRType_EUnitCommandQueueStatus final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Broadcaster<EUnitCommandQueueStatus>";
    }

    void Init() override
    {
      size_ = sizeof(moho::Broadcaster);
      Finish();
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
      listenerLink->mNext->mPrev = listenerLink->mPrev;
      listenerLink->mPrev->mNext = listenerLink->mNext;
      listenerLink->mPrev = listenerLink;
      listenerLink->mNext = listenerLink;

      listenerLink->mNext = mNext;
      listenerLink->mPrev = this;
      mNext = listenerLink;
      listenerLink->mNext->mPrev = listenerLink;

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

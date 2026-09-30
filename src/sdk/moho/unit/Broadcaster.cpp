#include "moho/unit/Broadcaster.h"

#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/Listener.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(WriteArchive* archive, int objectPtr);
} // namespace gpg

namespace
{
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

  gpg::RType* gEUnitCommandQueueStatusTypeCache = nullptr;

  // Shared reflected-type cache for the bare `EUnitCommandQueueStatus` enum,
  // read/written by both GetName() overrides below (confirmed against
  // FUN_006F8170 and FUN_006F8230's disassembly: both reference the same
  // binary global slot).
  [[nodiscard]] gpg::RType* CachedEUnitCommandQueueStatusType()
  {
    if (!gEUnitCommandQueueStatusTypeCache) {
      gEUnitCommandQueueStatusTypeCache = gpg::LookupRType(typeid(moho::EUnitCommandQueueStatus));
    }
    return gEUnitCommandQueueStatusTypeCache;
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
     * Address: 0x00BFECD0 (FUN_00BFECD0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `Broadcaster<ECommandEvent>` once from the reflected
     * `ECommandEvent` descriptor's name and returns it.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName =
        gpg::STR_Printf("Broadcaster<%s>", ResolveECommandEventTypeCachePrimary()->GetName());
      return sName.c_str();
    }

    void Init() override
    {
      size_ = sizeof(moho::Broadcaster<moho::ECommandEvent>);
      version_ = 1;
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

    /**
     * Address: 0x006F8170 (FUN_006F8170, Moho::RBroadcasterRType_EUnitCommandQueueStatus::GetName)
     * Address: 0x00BFEFD0 (FUN_00BFEFD0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `Broadcaster<EUnitCommandQueueStatus>` once from the reflected
     * `EUnitCommandQueueStatus` descriptor's name and returns it.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName =
        gpg::STR_Printf("Broadcaster<%s>", CachedEUnitCommandQueueStatusType()->GetName());
      return sName.c_str();
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
      size_ = sizeof(moho::Broadcaster<moho::EUnitCommandQueueStatus>);
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
     * Address: 0x00BF90D0 (FUN_00BF90D0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `Listener<ECommandEvent>` once from the reflected
     * `ECommandEvent` descriptor's name and returns it.
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

    /**
     * Address: 0x006F8230 (FUN_006F8230, Moho::RListenerRType_EUnitCommandQueueStatus::GetName)
     * Address: 0x00BFEFA0 (FUN_00BFEFA0, atexit destructor of GetName's cached name)
     *
     * What it does:
     * Builds `Listener<EUnitCommandQueueStatus>` once from the reflected
     * `EUnitCommandQueueStatus` descriptor's name and returns it.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName =
        gpg::STR_Printf("Listener<%s>", CachedEUnitCommandQueueStatusType()->GetName());
      return sName.c_str();
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

  /**
   * Address: 0x00BFF060 (FUN_00BFF060, atexit destructor of the Broadcaster<EUnitCommandQueueStatus> type object)
   */
  [[nodiscard]] RBroadcasterRType_EUnitCommandQueueStatus& BroadcasterStatusRType()
  {
    static RBroadcasterRType_EUnitCommandQueueStatus sType;
    return sType;
  }

  /**
   * Address: 0x00BFEE20 (FUN_00BFEE20, atexit destructor of the Broadcaster<ECommandEvent> type object)
   */
  [[nodiscard]] RBroadcasterRType_ECommandEvent& BroadcasterCommandEventRType()
  {
    static RBroadcasterRType_ECommandEvent sType;
    return sType;
  }

  /**
   * Address: 0x00BFF000 (FUN_00BFF000, atexit destructor of the Listener<EUnitCommandQueueStatus> type object)
   */
  [[nodiscard]] RListenerRType_EUnitCommandQueueStatus& ListenerStatusRType()
  {
    static RListenerRType_EUnitCommandQueueStatus sType;
    return sType;
  }

  /**
   * Address: 0x00BF9100 (FUN_00BF9100, atexit destructor of the Listener<ECommandEvent> type object)
   */
  [[nodiscard]] RListenerRType_ECommandEvent& ListenerCommandEventRType()
  {
    static RListenerRType_ECommandEvent sType;
    return sType;
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
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster<moho::ECommandEvent>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    moho::Listener<moho::ECommandEvent>* listener = nullptr;
    archive->ReadPointer(&listener, ownerRef);
    while (listener != nullptr) {
      broadcaster->AddListener(listener);
      archive->ReadPointer(&listener, ownerRef);
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
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster<moho::ECommandEvent>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RRef pointerRef{};

    for (moho::Listener<moho::ECommandEvent>* const listener : broadcaster->mListeners.owners()) {
      (void)gpg::RRef_Listener_ECommandEvent(&pointerRef, listener);
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
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster<moho::EUnitCommandQueueStatus>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    moho::Listener<moho::EUnitCommandQueueStatus>* listener = nullptr;
    archive->ReadPointer(&listener, ownerRef);
    while (listener != nullptr) {
      broadcaster->AddListener(listener);
      archive->ReadPointer(&listener, ownerRef);
    }
  }

  /**
   * Address: 0x005F43B0 (FUN_005F43B0, Moho::RListenerRType_ECommandEvent::GetName)
   * Address: 0x00BF90D0 (FUN_00BF90D0, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `Listener<ECommandEvent>` once from the reflected
   * `ECommandEvent` descriptor's name and returns it.
   */
  const char* RListenerRType_ECommandEvent::GetName() const
  {
    static const msvc8::string sName =
      gpg::STR_Printf("Listener<%s>", ResolveECommandEventTypeCachePrimary()->GetName());
    return sName.c_str();
  }
} // namespace

namespace moho
{
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
    gpg::PreRegisterRType(typeid(moho::Broadcaster<moho::ECommandEvent>), &type);
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
   * Runs broadcaster command-event type registration.
   */
  void register_Broadcaster_ECommandEvent_RTypeStartup()
  {
    (void)register_Broadcaster_ECommandEvent_RType();
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
    gpg::PreRegisterRType(typeid(moho::Broadcaster<moho::EUnitCommandQueueStatus>), &type);
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
   * Runs broadcaster status-type registration.
   */
  void register_Broadcaster_EUnitCommandQueueStatus_RTypeStartup()
  {
    (void)register_Broadcaster_EUnitCommandQueueStatus_RType();
  }

  /**
   * Address: 0x00BD95F0 (FUN_00BD95F0, sub_BD95F0)
   *
   * What it does:
   * Runs listener status-type registration.
   */
  void register_Listener_EUnitCommandQueueStatus_RTypeStartup()
  {
    (void)register_Listener_EUnitCommandQueueStatus_RType();
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006F8650 (FUN_006F8650, Moho::RBroadcasterRType_EUnitCommandQueueStatus::SerSave)
   *
   * IDA signature:
   * void __cdecl sub_6F8650(BinaryWriteArchive *archive, int objectPtr);
   *
   * What it does:
   * Serializes one intrusive `Broadcaster<EUnitCommandQueueStatus>` lane by
   * writing each linked listener pointer as `UNOWNED` and terminating the run
   * with one null pointer record — the exact twin of
   * `RBroadcasterRType_ECommandEvent::SerSave` (0x006EA810) for the other
   * broadcaster instantiation. Bound as the type's `serSaveFunc_`, which is
   * why it takes two arguments rather than the full four-argument save
   * signature.
   */
  void SaveBroadcasterListenerChainEUnitCommandQueueStatus(WriteArchive* const archive, const int objectPtr)
  {
    auto* const broadcaster = reinterpret_cast<moho::Broadcaster<moho::EUnitCommandQueueStatus>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(broadcaster != nullptr);
    if (!archive || !broadcaster) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RRef pointerRef{};

    for (moho::Listener<moho::EUnitCommandQueueStatus>* const listener : broadcaster->mListeners.owners()) {
      (void)gpg::RRef_Listener_EUnitCommandQueueStatus(&pointerRef, listener);
      gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

    (void)gpg::RRef_Listener_EUnitCommandQueueStatus(&pointerRef, nullptr);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, nullOwner);
  }
} // namespace gpg

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_Broadcaster_ECommandEvent_RType_566e21, moho::register_Broadcaster_ECommandEvent_RType)
GPG_PREREGISTER_INIT(register_Listener_ECommandEvent_RType_566e21, moho::register_Listener_ECommandEvent_RType)
GPG_PREREGISTER_INIT(register_Broadcaster_EUnitCommandQueueStatus_RType_566e21, moho::register_Broadcaster_EUnitCommandQueueStatus_RType)
GPG_PREREGISTER_INIT(register_Listener_EUnitCommandQueueStatus_RType_566e21, moho::register_Listener_EUnitCommandQueueStatus_RType)

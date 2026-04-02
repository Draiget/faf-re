#include "moho/unit/Broadcaster.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/Listener.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/EUnitCommandQueueStatus.h"

namespace
{
  class RBroadcasterRType_ECommandEvent final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "Broadcaster<ECommandEvent>";
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

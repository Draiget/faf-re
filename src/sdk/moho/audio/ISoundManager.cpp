#include "ISoundManager.h"

#include <new>

namespace
{
  struct ISoundManagerRuntimeView
  {
    void* vftable;
  };

  class ISoundManagerVtableProbe final : public moho::ISoundManager
  {
  public:
    void AddEntitySound(moho::Entity*, moho::CSndParams*) override
    {
    }

    void DrainRequests(gpg::fastvector_n<moho::SAudioRequest, 64>&) override
    {
    }

    moho::TDatListItem<moho::HSound, void>* AddLoop(moho::HSound*) override
    {
      return nullptr;
    }

    moho::TDatListItem<moho::HSound, void>* StopLoop(moho::HSound*) override
    {
      return nullptr;
    }

    void Shutdown() override
    {
    }

    moho::ISoundManager* Destroy(const std::uint8_t flags) override
    {
      (void)flags;
      return this;
    }
  };

  [[nodiscard]] ISoundManagerRuntimeView* AsRuntimeView(moho::ISoundManager* const soundManager) noexcept
  {
    return reinterpret_cast<ISoundManagerRuntimeView*>(soundManager);
  }

  [[nodiscard]] void* RecoveredISoundManagerVtable() noexcept
  {
    static ISoundManagerVtableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00760A60 (FUN_00760A60)
   *
   * What it does:
   * Restores one base `ISoundManager` vtable lane in place.
   */
  ISoundManager* InitializeSoundManagerVtable(ISoundManager* const soundManager) noexcept
  {
    AsRuntimeView(soundManager)->vftable = RecoveredISoundManagerVtable();
    return soundManager;
  }

  /**
   * Address: 0x00760F10 (FUN_00760F10)
   *
   * What it does:
   * Alias entry that restores the same base `ISoundManager` vtable lane.
   */
  ISoundManager* InitializeSoundManagerVtableAlias(ISoundManager* const soundManager) noexcept
  {
    return InitializeSoundManagerVtable(soundManager);
  }

  /**
   * Address: 0x00760A70 (FUN_00760A70)
   *
   * std::uint8_t deleteFlags
   *
   * IDA signature:
   * _DWORD *__thiscall sub_760A70(_DWORD *this, char deleteFlags);
   *
   * What it does:
   * Implements deleting-style virtual teardown for interface pointers.
   */
  ISoundManager* ISoundManager::Destroy(const std::uint8_t flags)
  {
    if ((flags & 1u) != 0u) {
      operator delete(this);
    }
    return this;
  }
} // namespace moho

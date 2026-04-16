#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "moho/audio/ISoundManager.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E35A50
   * COL:     0x00E8F1B8
   */
  class CSimSoundManager final : public ISoundManager
  {
  public:
    /**
     * Address: 0x00760C80 (FUN_00760C80)
     *
     * Sim* ownerSim
     *
     * IDA signature:
     * Moho::ISimSoundManager_vtbl **__usercall sub_760C80@<eax>(Moho::ISimSoundManager_vtbl **result@<eax>,
     * Moho::ISimSoundManager_vtbl *a2@<ecx>);
     *
     * What it does:
     * Initializes one `CSimSoundManager` runtime object with owner-sim pointer,
     * inline request-vector lanes, and self-linked active-loop sentinel.
     */
    explicit CSimSoundManager(Sim* ownerSim);

    /**
     * Address: 0x00760CC0 (FUN_00760CC0)
     * Slot: 0
     *
     * Moho::Entity*, Moho::CSndParams*
     *
     * IDA signature:
     * void __thiscall Moho::CSimSoundManager::AddEntitySound(Moho::CSimSoundManager *this, Moho::Entity *entity,
     * Moho::CSndParams *params);
     *
     * What it does:
     * Queues opcode-0 (one-shot) audio request using entity position/layer.
     */
    void AddEntitySound(Entity* entity, CSndParams* params) override;

    /**
     * Address: 0x00760EB0 (FUN_00760EB0)
     * Slot: 1
     *
     * gpg::fastvector_n<Moho::SAudioRequest, 64>& outRequests
     *
     * IDA signature:
     * Moho::SAudioRequest *__thiscall sub_760EB0(Moho::CSimSoundManager *this, gpg::fastvector_n64_SAudioRequest
     * *outRequests);
     *
     * What it does:
     * Copies pending requests into caller storage, then resets local queue
     * back to inline storage.
     */
    void DrainRequests(gpg::fastvector_n<SAudioRequest, 64>& outRequests) override;

    /**
     * Address: 0x00760D20 (FUN_00760D20)
     * Slot: 2
     *
     * Moho::HSound*
     *
     * IDA signature:
     * Moho::TDatListItem_HSound *__thiscall Moho::CSimSoundManager::AddLoop(Moho::CSimSoundManager *this, Moho::HSound
     * *sound);
     *
     * What it does:
     * Queues opcode-1 loop-start request and links handle into active list.
     */
    TDatListItem<HSound, void>* AddLoop(HSound* sound) override;

    /**
     * Address: 0x00760D90 (FUN_00760D90)
     * Slot: 3
     *
     * Moho::HSound*
     *
     * IDA signature:
     * Moho::TDatListItem_HSound *__thiscall Moho::CSimSoundManager::Func4(Moho::CSimSoundManager *this, Moho::HSound
     * *sound);
     *
     * What it does:
     * If handle is currently tracked, queues opcode-2 loop-stop request and
     * unlinks the handle from active list.
     */
    TDatListItem<HSound, void>* StopLoop(HSound* sound) override;

    /**
     * Address: 0x00760E70 (FUN_00760E70)
     * Slot: 4
     *
     * void
     *
     * IDA signature:
     * void __thiscall Moho::CSimSoundManager::Shutdown(Moho::CSimSoundManager *this);
     *
     * What it does:
     * Iterates active loop list and dispatches virtual slot 3 for each entry.
     */
    void Shutdown() override;

    /**
     * Address: 0x00760EF0 (FUN_00760EF0)
     * Slot: 5
     *
     * std::uint8_t deleteFlags
     *
     * IDA signature:
     * void *__thiscall sub_760EF0(void *this, char deleteFlags);
     *
     * What it does:
     * Executes deleting-style teardown: resets active-loop list and request
     * queue, then conditionally frees `this`.
     */
    ISoundManager* Destroy(std::uint8_t flags) override;

  private:
    /**
     * Address: 0x00761520 (FUN_00761520)
     *
     * IDA signature:
     * Moho::SAudioRequest *__usercall sub_761520@<eax>(Moho::CSimSoundManager *this@<esi>);
     *
     * What it does:
     * Non-deleting teardown helper used by slot-5 destroy wrapper.
     */
    void TeardownNonDeleting();

  public:
    Sim* mOwnerSim;                                 // +0x04
    gpg::fastvector_n<SAudioRequest, 64> mRequests; // +0x08
    TDatList<HSound, void> mActiveLoops;            // +0x718
  };

  static_assert(offsetof(CSimSoundManager, mOwnerSim) == 0x04, "CSimSoundManager::mOwnerSim offset must be 0x04");
  static_assert(offsetof(CSimSoundManager, mRequests) == 0x08, "CSimSoundManager::mRequests offset must be 0x08");
  static_assert(
    offsetof(CSimSoundManager, mActiveLoops) == 0x718, "CSimSoundManager::mActiveLoops offset must be 0x718"
  );
  static_assert(sizeof(CSimSoundManager) == 0x720, "CSimSoundManager size must be 0x720");
} // namespace moho

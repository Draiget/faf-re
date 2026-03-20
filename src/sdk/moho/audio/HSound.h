#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"

namespace moho
{
  class IXACTCue;

  /**
   * Sound handle object shared by sim/user audio paths.
   *
   * Recovered facts:
   * - object size: 0x58
   * - RTTI exposes two HSound vtables (`col.offset` 0 and 16), indicating
   *   an internal secondary subobject/view
   * - intrusive loop-list node at +0x44 (used by CSimSoundManager)
   * - slot 0 is a deleting-style virtual entry in retail binaries
   *
   * Only fields consumed by recovered sim audio code are semantically named.
   */
  class HSound
  {
  public:
    /**
     * Address: 0x004E1120 (FUN_004E1120)
     *
     * std::uint8_t deleteFlags
     *
     * IDA signature:
     * void *__thiscall FUN_004E1120(void *this, char deleteFlags);
     *
     * What it does:
     * Deleting-style virtual slot used when loop handles are released.
     */
    virtual HSound* Destroy(std::uint8_t flags) = 0;

  public:
    std::uint8_t mOpaque04[0x40];            // +0x04
    TDatListItem<HSound, void> mSimLoopLink; // +0x44
    IXACTCue* mLoopCue;                      // +0x4C
    void* mLoopOwnerContext;                 // +0x50
    std::uint8_t mAffectsDucking;            // +0x54
    std::uint8_t mOpaque55[0x03];            // +0x55
  };

  static_assert(sizeof(HSound) == 0x58, "HSound size must be 0x58");
  static_assert(offsetof(HSound, mSimLoopLink) == 0x44, "HSound::mSimLoopLink offset must be 0x44");
  static_assert(offsetof(HSound, mLoopCue) == 0x4C, "HSound::mLoopCue offset must be 0x4C");
  static_assert(offsetof(HSound, mLoopOwnerContext) == 0x50, "HSound::mLoopOwnerContext offset must be 0x50");
  static_assert(offsetof(HSound, mAffectsDucking) == 0x54, "HSound::mAffectsDucking offset must be 0x54");
} // namespace moho

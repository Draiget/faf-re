#pragma once

#include <cstdint>
#include <type_traits>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "moho/audio/SAudioRequest.h"

namespace moho
{
  class CSndParams;
  class UserArmy;
  class VTransform;

  /**
   * VFTABLE: 0x00E4C41C
   * COL:     0x00E9DB74
   */
  class IUserSoundManager
  {
  public:
    /**
     * Address: 0x008AB120 (FUN_008AB120, IUserSoundManager ctor lane)
     *
     * What it does:
     * Initializes one user-sound-manager base interface object.
     */
    IUserSoundManager();

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 0
     */
    virtual void UpdateSoundRequests(const gpg::fastvector<SAudioRequest>& requests) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 1
     */
    virtual void Frame(float simDeltaSeconds, float frameSeconds) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 2
     */
    virtual void SetListenerArmy(UserArmy* listenerArmy) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 3
     */
    virtual void Play(const msvc8::string& bankName, const msvc8::string& cueName) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 4
     */
    virtual void Play2D(const CSndParams& params) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 5
     */
    virtual void SetListenerTransform(const VTransform& transform) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 6
     */
    virtual void StopAllSounds() = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 7
     */
    virtual void SetVolume(gpg::StrArg category, float value) = 0;

    /**
     * Address: 0x00A82547 (_purecall)
     * Slot: 8
     */
    virtual float GetVolume(gpg::StrArg category) = 0;
  };

  /**
   * Address: 0x008AB220 (FUN_008AB220, ?USER_GetSound@Moho@@YAPAVIUserSoundManager@1@XZ)
   *
   * What it does:
   * Returns the process-global user sound manager, creating/replacing it on first use.
   */
  [[nodiscard]] IUserSoundManager* USER_GetSound();

  static_assert(sizeof(IUserSoundManager) == 0x4, "IUserSoundManager size must be 0x4");
  static_assert(std::is_polymorphic<IUserSoundManager>::value, "IUserSoundManager must remain polymorphic");
} // namespace moho

#pragma once

#include <cstdint>
#include <functional>
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
    virtual void Play(const fa::string& bankName, const fa::string& cueName) = 0;

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

  /**
   * Engine addition (snd_CreateEarly): builds the user sound manager (USER_GetSound's) on a helper
   * thread, so the audio engine comes up while the main thread goes on to create the window and the
   * graphics device. USER_GetSound waits for it.
   */
  void USER_StartSoundEarly();

  /** Waits for the build USER_StartSoundEarly started, if any. */
  void USER_FinishSoundEarly();

  /**
   * Runs `work` with the user sound manager: on the thread building it while that build runs (after
   * the build, in the order given), here otherwise. For work whose caller needs nothing back, such
   * as AudioSetLanguage.
   */
  void USER_WithSound(std::function<void(IUserSoundManager*)> work);

  static_assert(sizeof(IUserSoundManager) == 0x4, "IUserSoundManager size must be 0x4");
  static_assert(std::is_polymorphic<IUserSoundManager>::value, "IUserSoundManager must remain polymorphic");
} // namespace moho

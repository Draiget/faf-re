#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class CameraImpl;

  class RCamManager
  {
  public:
    /**
     * Address: 0x007AABB0 (FUN_007AABB0, ?Frame@RCamManager@Moho@@QAEXMM@Z)
     *
     * What it does:
     * Runs per-frame updates across the registered camera list.
     */
    void Frame(float simDeltaSeconds, float frameSeconds);

    /**
     * Address: 0x007AAAF0 (FUN_007AAAF0, ?GetCamera@RCamManager@Moho@@QAEPAVCameraImpl@2@VStrArg@gpg@@@Z)
     *
     * gpg::StrArg name
     *
     * What it does:
     * Finds a camera by runtime name, scanning from newest to oldest entry.
     */
    [[nodiscard]] CameraImpl* GetCamera(gpg::StrArg name);

  public:
    msvc8::vector<CameraImpl*> mCams; // +0x00
  };

  static_assert(sizeof(RCamManager) == 0x10, "RCamManager size must be 0x10");
  static_assert(offsetof(RCamManager, mCams) == 0x00, "RCamManager::mCams offset must be 0x00");

  /**
   * Address: 0x007AAC00 (FUN_007AAC00, ?CAM_GetManager@Moho@@YAPAVRCamManager@1@XZ)
   *
   * What it does:
   * Lazily initializes and returns the process-global camera manager.
   */
  [[nodiscard]] RCamManager* CAM_GetManager();
} // namespace moho

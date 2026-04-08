#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  class CameraImpl;

  class RCamManager
  {
  public:
    /**
     * Address: 0x007AA930 (FUN_007AA930, ??1RCamManager@Moho@@QAE@XZ)
     *
     * What it does:
     * Destroys owned runtime camera instances and releases camera pointer
     * vector storage.
     */
    ~RCamManager();

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

    /**
     * Address: 0x007AAB60 (FUN_007AAB60, ?GetAllCameras@RCamManager@Moho@@QAE?AV?$vector@PAVCameraImpl@Moho@@V?$allocator@PAVCameraImpl@Moho@@@std@@@std@@XZ)
     *
     * What it does:
     * Returns a copy of the current camera pointer vector.
     */
    [[nodiscard]] msvc8::vector<CameraImpl*> GetAllCameras();

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

  /**
   * Address: 0x007AAD20 (FUN_007AAD20, ?CAM_GetAllCameras@Moho@@YA?AV?$vector@VGeomCamera3@Moho@@V?$allocator@VGeomCamera3@Moho@@@std@@@std@@XZ)
   *
   * What it does:
   * Copies all non-minimap camera views into one output camera-view vector.
   */
  [[nodiscard]] msvc8::vector<GeomCamera3> CAM_GetAllCameras();

  /**
   * Address: 0x007AADE0 (FUN_007AADE0, ?CAM_GetAllRCamCameras@Moho@@YA?AV?$vector@PAVCameraImpl@Moho@@V?$allocator@PAVCameraImpl@Moho@@@std@@@std@@XZ)
   *
   * What it does:
   * Returns a copy of all runtime camera implementation pointers.
   */
  [[nodiscard]] msvc8::vector<CameraImpl*> CAM_GetAllRCamCameras();
} // namespace moho

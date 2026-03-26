#include "moho/render/RCamManager.h"

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <new>

#include "moho/render/camera/CameraImpl.h"

namespace
{
  bool gCamManagerInitialized = false;
  alignas(moho::RCamManager) std::uint8_t gCamManagerStorage[sizeof(moho::RCamManager)]{};
  moho::RCamManager* gCamManager = nullptr;

  void DestroyCamManager()
  {
    if (gCamManager == nullptr) {
      return;
    }

    gCamManager->~RCamManager();
    gCamManager = nullptr;
    gCamManagerInitialized = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007AABB0 (FUN_007AABB0, ?Frame@RCamManager@Moho@@QAEXMM@Z)
   */
  void RCamManager::Frame(const float simDeltaSeconds, const float frameSeconds)
  {
    for (CameraImpl* const camera : mCams) {
      if (camera != nullptr) {
        camera->Frame(simDeltaSeconds, frameSeconds);
      }
    }
  }

  /**
   * Address: 0x007AAAF0 (FUN_007AAAF0, ?GetCamera@RCamManager@Moho@@QAEPAVCameraImpl@2@VStrArg@gpg@@@Z)
   */
  CameraImpl* RCamManager::GetCamera(const gpg::StrArg name)
  {
    const std::size_t cameraCount = mCams.size();
    for (std::size_t index = cameraCount; index != 0u; --index) {
      CameraImpl* const camera = mCams[index - 1u];
      if (camera != nullptr && std::strcmp(name, camera->CameraGetName()) == 0) {
        return camera;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x007AAC00 (FUN_007AAC00, ?CAM_GetManager@Moho@@YAPAVRCamManager@1@XZ)
   */
  RCamManager* CAM_GetManager()
  {
    if (!gCamManagerInitialized) {
      gCamManagerInitialized = true;
      gCamManager = new (&gCamManagerStorage[0]) RCamManager();
      std::atexit(&DestroyCamManager);
    }

    return gCamManager;
  }
} // namespace moho

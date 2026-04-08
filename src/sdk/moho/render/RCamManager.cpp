#include "moho/render/RCamManager.h"

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <new>

#include "moho/console/CConCommand.h"
#include "moho/render/camera/CameraImpl.h"

namespace moho
{
  float cam_HighLOD = 2.0f;
  float cam_MediumLOD = 1.0f;
  float cam_LowLOD = 0.0f;
  float cam_DefaultLOD = 1.0f;
} // namespace moho

namespace
{
  bool gCamManagerInitialized = false;
  alignas(moho::RCamManager) std::uint8_t gCamManagerStorage[sizeof(moho::RCamManager)]{};
  moho::RCamManager* gCamManager = nullptr;

  moho::TConVar<float> gTConVar_cam_HighLOD("cam_HighLOD", "", &moho::cam_HighLOD);
  moho::TConVar<float> gTConVar_cam_MediumLOD("cam_MediumLOD", "", &moho::cam_MediumLOD);
  moho::TConVar<float> gTConVar_cam_LowLOD("cam_LowLOD", "", &moho::cam_LowLOD);
  moho::TConVar<float> gTConVar_cam_DefaultLOD("cam_DefaultLOD", "", &moho::cam_DefaultLOD);

  void DestroyCamManager()
  {
    if (gCamManager == nullptr) {
      return;
    }

    gCamManager->~RCamManager();
    gCamManager = nullptr;
    gCamManagerInitialized = false;
  }

  void CleanupTConVar_cam_HighLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_HighLOD);
  }

  void CleanupTConVar_cam_MediumLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_MediumLOD);
  }

  void CleanupTConVar_cam_LowLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_LowLOD);
  }

  void CleanupTConVar_cam_DefaultLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_DefaultLOD);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007AA930 (FUN_007AA930, ??1RCamManager@Moho@@QAE@XZ)
   */
  RCamManager::~RCamManager()
  {
    for (CameraImpl* const camera : mCams) {
      delete camera;
    }
    mCams.clear();
  }

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
   * Address: 0x007AAB60 (FUN_007AAB60, ?GetAllCameras@RCamManager@Moho@@QAE?AV?$vector@PAVCameraImpl@Moho@@V?$allocator@PAVCameraImpl@Moho@@@std@@@std@@XZ)
   */
  msvc8::vector<CameraImpl*> RCamManager::GetAllCameras()
  {
    return mCams;
  }

  /**
   * Address: 0x007AAD20 (FUN_007AAD20, ?CAM_GetAllCameras@Moho@@YA?AV?$vector@VGeomCamera3@Moho@@V?$allocator@VGeomCamera3@Moho@@@std@@@std@@XZ)
   *
   * What it does:
   * Copies all non-minimap camera views from the manager into one returned
   * vector.
   */
  msvc8::vector<GeomCamera3> CAM_GetAllCameras()
  {
    msvc8::vector<GeomCamera3> result{};
    RCamManager* const manager = CAM_GetManager();
    msvc8::vector<CameraImpl*> allCameras = manager->GetAllCameras();
    const std::size_t cameraCount = allCameras.size();
    for (std::size_t i = 0; i < cameraCount; ++i) {
      CameraImpl* const camera = allCameras[i];
      if (_stricmp(camera->CameraGetName(), "MiniMap") != 0) {
        result.push_back(camera->CameraGetView());
      }
    }
    return result;
  }

  /**
   * Address: 0x007AADE0 (FUN_007AADE0, ?CAM_GetAllRCamCameras@Moho@@YA?AV?$vector@PAVCameraImpl@Moho@@V?$allocator@PAVCameraImpl@Moho@@@std@@@std@@XZ)
   *
   * What it does:
   * Returns a copy of the manager camera-pointer vector.
   */
  msvc8::vector<CameraImpl*> CAM_GetAllRCamCameras()
  {
    RCamManager* const manager = CAM_GetManager();
    return manager->GetAllCameras();
  }

  /**
   * Address: 0x00BC47E0 (FUN_00BC47E0, register_TConVar_cam_HighLOD)
   *
   * What it does:
   * Registers the highest camera LOD convar and schedules process-exit teardown.
   */
  void register_TConVar_cam_HighLOD()
  {
    RegisterConCommand(gTConVar_cam_HighLOD);
    (void)std::atexit(&CleanupTConVar_cam_HighLOD);
  }

  /**
   * Address: 0x00BC4820 (FUN_00BC4820, register_TConVar_cam_MediumLOD)
   *
   * What it does:
   * Registers the medium camera LOD convar and schedules process-exit teardown.
   */
  void register_TConVar_cam_MediumLOD()
  {
    RegisterConCommand(gTConVar_cam_MediumLOD);
    (void)std::atexit(&CleanupTConVar_cam_MediumLOD);
  }

  /**
   * Address: 0x00BC4860 (FUN_00BC4860, register_TConVar_cam_LowLOD)
   *
   * What it does:
   * Registers the low camera LOD convar and schedules process-exit teardown.
   */
  void register_TConVar_cam_LowLOD()
  {
    RegisterConCommand(gTConVar_cam_LowLOD);
    (void)std::atexit(&CleanupTConVar_cam_LowLOD);
  }

  /**
   * Address: 0x00BC48A0 (FUN_00BC48A0, register_TConVar_cam_DefaultLOD)
   *
   * What it does:
   * Registers the default camera LOD selector convar and schedules process-exit teardown.
   */
  void register_TConVar_cam_DefaultLOD()
  {
    RegisterConCommand(gTConVar_cam_DefaultLOD);
    (void)std::atexit(&CleanupTConVar_cam_DefaultLOD);
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

namespace
{
  struct RCamManagerStartupBootstrap
  {
    RCamManagerStartupBootstrap()
    {
      moho::register_TConVar_cam_HighLOD();
      moho::register_TConVar_cam_MediumLOD();
      moho::register_TConVar_cam_LowLOD();
      moho::register_TConVar_cam_DefaultLOD();
    }
  };

  [[maybe_unused]] RCamManagerStartupBootstrap gRCamManagerStartupBootstrap;
} // namespace

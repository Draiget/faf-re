#include "legacy/algorithms/Remove.h"
#include "moho/render/RCamManager.h"

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <sstream>

#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"

#include "moho/render/camera/CameraImpl.h"

namespace moho
{
  // `.data` initializers, read straight out of the shipped image:
  // 0x00F58E40 = 0.9, 0x00F58E44 = 1.0, 0x00F58E48 = 1.2.
  //
  // These feed `GeomCamera3::SetLODScale`, and `viewport.r[1]` - the row every
  // LOD cutoff in the engine is measured against - is `viewport.r[0] *
  // lodScale`. A *larger* scale therefore makes the measured depth larger and
  // culls sooner, so the detail levels run high -> low as 0.9 -> 1.0 -> 1.2.
  // The values that used to sit here (2.0 / 1.0 / 0.0) had the relation
  // backwards and far out of range: on the "High" detail setting the scale was
  // 2.0 instead of 0.9, which is 2.2x too large, so every effect carrying a
  // LODCutoff - build beams among them - disappeared at 45% of the camera
  // distance it should survive to; "Low" became 0.0, which disables LOD
  // rejection altogether.
  float cam_HighLOD = 0.9f;
  float cam_MediumLOD = 1.0f;
  float cam_LowLOD = 1.2f;
  float cam_DefaultLOD = 1.0f;
} // namespace moho

namespace
{
  using CameraPointer = moho::CameraImpl*;



  /**
   * Address: 0x00BC47E0 (FUN_00BC47E0, dynamic initializer for `gTConVar_cam_HighLOD`)
   * Address: 0x00BEF640 (FUN_00BEF640, dynamic atexit destructor for `gTConVar_cam_HighLOD`)
   */
  moho::TConVar<float> gTConVar_cam_HighLOD("cam_HighLOD", "", &moho::cam_HighLOD);

  /**
   * Address: 0x00BC4820 (FUN_00BC4820, dynamic initializer for `gTConVar_cam_MediumLOD`)
   * Address: 0x00BEF670 (FUN_00BEF670, dynamic atexit destructor for `gTConVar_cam_MediumLOD`)
   */
  moho::TConVar<float> gTConVar_cam_MediumLOD("cam_MediumLOD", "", &moho::cam_MediumLOD);

  /**
   * Address: 0x00BC4860 (FUN_00BC4860, dynamic initializer for `gTConVar_cam_LowLOD`)
   * Address: 0x00BEF6A0 (FUN_00BEF6A0, dynamic atexit destructor for `gTConVar_cam_LowLOD`)
   */
  moho::TConVar<float> gTConVar_cam_LowLOD("cam_LowLOD", "", &moho::cam_LowLOD);

  /**
   * Address: 0x00BC48A0 (FUN_00BC48A0, dynamic initializer for `gTConVar_cam_DefaultLOD`)
   * Address: 0x00BEF6D0 (FUN_00BEF6D0, dynamic atexit destructor for `gTConVar_cam_DefaultLOD`)
   */
  moho::TConVar<float> gTConVar_cam_DefaultLOD("cam_DefaultLOD", "default value for camera level-of-detail scaling factor", &moho::cam_DefaultLOD);

  /// 0x00E00779 (the shared empty-string literal also used by
  /// `ResolutionCommands.cpp`'s startup commands), the `.data` initializer
  /// of `Moho::CConFunc_SC_CameraScaleLOD` (+0x08). No console-help text in
  /// the binary.
  constexpr const char* kConsoleStartupSCCameraScaleLODDescription = "";

  // 0x00F5BE80. The registrar only patches the vftable and the
  // `mHandlerOrValue` slot at +0x0C; the name and (empty) description
  // lanes are `.data` initializers, matching the `SC_PrimaryAdapter`/
  // `SC_ToggleCursorClip` pattern in ResolutionCommands.cpp.
  /**
   * Address: 0x00BE9540 (FUN_00BE9540, dynamic initializer for `gCConFunc_SC_CameraScaleLOD`)
   * Address: 0x00C08DC0 (FUN_00C08DC0, dynamic atexit destructor for `gCConFunc_SC_CameraScaleLOD`)
   */
  moho::CConFunc gCConFunc_SC_CameraScaleLOD("SC_CameraScaleLOD", kConsoleStartupSCCameraScaleLODDescription, &moho::SC_CameraScaleLOD);
} // namespace

namespace moho
{
  /**
   * Address: 0x007AA910 (FUN_007AA910, ??0RCamManager@Moho@@QAE@XZ)
   *
   * What it does:
   * Default-initializes camera pointer vector storage lanes.
   */
  RCamManager::RCamManager() = default;

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
   * Address: 0x007AA9C0 (FUN_007AA9C0, ?CreateCamera@RCamManager@Moho@@QAEPAVRCamCamera@2@VStrArg@gpg@@ABVSTIMap@2@PAVLuaState@LuaPlus@@@Z)
   *
   * MSVC inlines the `mCams.push_back(camera)` fast path here and calls the
   * grow half directly (0x007AAA68 `call sub_7AFD10`), which is why the
   * out-of-line `push_back` for this element (0x007AE990) ends up with no
   * callers at all.
   */
  CameraImpl* RCamManager::CreateCamera(
    const gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* const luaState
  )
  {
    CameraImpl* camera = nullptr;
    // 0x007AA9C0 allocates `operator new(0x858u)`, which `CameraImpl` now is
    // exactly -- a static_assert in its header ties the two together. The
    // explicit size survives because it is the binary's own constant and the
    // assert is what proves the class still matches it; it used to be load
    // bearing, back when the class was a thin shell whose state lived behind
    // runtime views and sizing the block by it would have handed the
    // constructor four bytes to write 0x854 past.
    CameraImpl* const storage = static_cast<CameraImpl*>(::operator new(kCameraImplRuntimeSize, std::nothrow));
    if (storage != nullptr) {
      try {
        camera = new (storage) CameraImpl(name, map, luaState);
      } catch (...) {
        ::operator delete(storage);
        throw;
      }
    }

    mCams.push_back(camera);
    return camera;
  }

  /**
   * Address: 0x007AAA90 (FUN_007AAA90, ?ForgetCamera@RCamManager@Moho@@QAEXPBVRCamCamera@2@@Z)
   */
  void RCamManager::ForgetCamera(const CameraImpl* const camera)
  {
    if (camera == nullptr) {
      return;
    }

    CameraImpl* const needle = const_cast<CameraImpl*>(camera);
    CameraImpl** const compactedEnd = msvc8::remove(mCams.begin(), mCams.end(), needle);
    if (compactedEnd != mCams.end()) {
      mCams.erase(compactedEnd, mCams.end());
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
   *
   * Returns the camera vector by value; the copy is `mCams`' own copy
   * constructor at 0x007AE840.
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
   * Copies every camera pointer from the manager's temporary camera vector into
   * a freshly allocated result vector and returns it. The binary builds a
   * temporary from RCamManager::GetAllCameras(), copies each element into the
   * result through a manual push_back loop (routing the capacity-full path
   * through the msvc8::vector<RCamCamera*>::_Insert_n grow lane FUN_007B0340),
   * then frees the temporary's buffer on scope exit.
   */
  msvc8::vector<CameraImpl*> CAM_GetAllRCamCameras()
  {
    msvc8::vector<CameraImpl*> result{};
    RCamManager* const manager = CAM_GetManager();
    // Temporary; its buffer is released on scope exit == the binary's
    // operator delete(start) at the end of the copy loop.
    msvc8::vector<CameraImpl*> allCameras = manager->GetAllCameras();
    const std::size_t cameraCount = allCameras.size();
    for (std::size_t i = 0; i < cameraCount; ++i) {
      result.push_back(allCameras[i]);
    }
    return result;
  }

  /**
   * Address: 0x007AAC00 (FUN_007AAC00, ?CAM_GetManager@Moho@@YAPAVRCamManager@1@XZ)
   * Address: 0x00C035B0 (FUN_00C035B0, atexit destructor of CAM_GetManager's RCamManager object)
   *
   * What it does:
   * Returns the process camera manager, constructing it on first call.
   */
  RCamManager* CAM_GetManager()
  {
    static RCamManager sManager;
    return &sManager;
  }

  /**
   * Address: 0x007AACD0 (FUN_007AACD0, ?CAM_CreateCamera@Moho@@YAPAVRCamCamera@1@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z)
   *
   * What it does:
   * Routes camera creation to the process-global camera manager.
   */
  CameraImpl* CAM_CreateCamera(const gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* const luaState)
  {
    RCamManager* const manager = CAM_GetManager();
    return manager->CreateCamera(name, map, luaState);
  }

  /**
   * Address: 0x007AAD00 (FUN_007AAD00, ?CAM_GetCamera@Moho@@YAPAVRCamCamera@1@VStrArg@gpg@@@Z)
   *
   * What it does:
   * Routes camera lookup by name to the process-global camera manager.
   */
  CameraImpl* CAM_GetCamera(const gpg::StrArg name)
  {
    RCamManager* const manager = CAM_GetManager();
    return manager->GetCamera(name);
  }

  /**
   * Address: 0x007AAEC0 (FUN_007AAEC0, ?CAM_ResetAllCameras@Moho@@YAXXZ)
   *
   * What it does:
   * Resets every registered camera through the manager camera list.
   */
  void CAM_ResetAllCameras()
  {
    RCamManager* const manager = CAM_GetManager();
    for (CameraImpl* const camera : manager->mCams) {
      camera->CameraReset();
    }
  }

  /**
   * Address: 0x007AAF00 (FUN_007AAF00, ?CAM_Frame@Moho@@YAXMM@Z)
   *
   * What it does:
   * Executes one frame tick on the process-global camera manager.
   */
  void CAM_Frame(const float simDeltaSeconds, const float frameSeconds)
  {
    RCamManager* const manager = CAM_GetManager();
    manager->Frame(simDeltaSeconds, frameSeconds);
  }

  /**
   * Address: 0x008D3870 (FUN_008D3870, sub_8D3870)
   *
   * What it does:
   * The `SC_CameraScaleLOD <index>` debug console command. Parses `index`
   * from the single supplied argument (`atoi`, unchecked against the
   * 3-entry table -- the binary itself has no bounds check here, preserved
   * exactly), selects one of `{cam_LowLOD, cam_MediumLOD, cam_HighLOD}` by
   * that index, then re-issues the selection as four executed console
   * commands: `cam_DefaultLOD <value>`, `cam_SetLOD WorldCamera <value>`,
   * `cam_SetLOD WorldCamera2 <value>`, `cam_SetLOD CameraHead2 <value>` --
   * a one-shot "snap every LOD-scaled camera to this level" debug helper.
   * `.asm`-confirmed: all four `std::ostringstream` blocks are built and
   * executed identically in sequence with no further argument parsing
   * between them; IDA's stack-slot naming diverges across the later three
   * blocks (intervening `ostringstream`/`string` temporaries shift the
   * frame), but no second value is ever loaded from a fresh source after
   * the initial `atoi`-selected float, so all four commands carry the same
   * selected LOD value.
   */
  void SC_CameraScaleLOD(const msvc8::vector<msvc8::string>& args)
  {
    if (args.size() != 2) {
      return;
    }

    const int lodIndex = std::atoi(ConCommandArg(args, 1)->c_str());
    const float lodValues[3] = {cam_LowLOD, cam_MediumLOD, cam_HighLOD};
    const float selectedLod = lodValues[lodIndex];

    {
      std::ostringstream stream;
      stream << "cam_DefaultLOD " << selectedLod;
      CON_Executef(stream.str().c_str());
    }
    {
      std::ostringstream stream;
      stream << "cam_SetLOD WorldCamera " << selectedLod;
      CON_Executef(stream.str().c_str());
    }
    {
      std::ostringstream stream;
      stream << "cam_SetLOD WorldCamera2 " << selectedLod;
      CON_Executef(stream.str().c_str());
    }
    {
      std::ostringstream stream;
      stream << "cam_SetLOD CameraHead2 " << selectedLod;
      CON_Executef(stream.str().c_str());
    }
  }

} // namespace moho


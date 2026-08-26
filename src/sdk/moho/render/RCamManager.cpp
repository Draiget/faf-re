#include "moho/render/RCamManager.h"

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <sstream>

#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/EngineVectorHelpers.h"
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

  using CameraPointer = moho::CameraImpl*;
  using CameraPointerRangeCursor = CameraPointer*;
  using CameraPointerRangeEndSlot = CameraPointerRangeCursor*;

  struct LegacyCameraVectorStorage
  {
    moho::CameraImpl** begin;
    moho::CameraImpl** end;
    moho::CameraImpl** capacityEnd;
  };

  static_assert(sizeof(LegacyCameraVectorStorage) == 0x0C, "LegacyCameraVectorStorage size must be 0x0C");

  /**
   * Address: 0x007AE820 (FUN_007AE820, sub_7AE820)
   *
   * What it does:
   * Clears the raw `{begin,end,capacity}` camera-vector lanes in static
   * manager storage and returns the static manager object address.
   */
  [[maybe_unused]] [[nodiscard]] moho::RCamManager* ResetStaticCamManagerStorageVectorLanes() noexcept
  {
    auto* const manager = reinterpret_cast<moho::RCamManager*>(&gCamManagerStorage[0]);
    auto* const vectorStorage = reinterpret_cast<LegacyCameraVectorStorage*>(&manager->mCams);
    vectorStorage->begin = nullptr;
    vectorStorage->end = nullptr;
    vectorStorage->capacityEnd = nullptr;
    return manager;
  }

  /**
   * Address: 0x007B1B10 (FUN_007B1B10, sub_7B1B10)
   *
   * What it does:
   * Copies one pointer range `[sourceBegin, sourceEnd)` into `destinationBegin`
   * while filtering out values equal to `*needleSlot`, stores resulting
   * destination end pointer through `outDestinationEnd`, and returns that slot
   * pointer.
   */
  [[maybe_unused]] [[nodiscard]] CameraPointerRangeEndSlot CompactCameraPointerRangeExcludingNeedle(
    CameraPointerRangeEndSlot const outDestinationEnd,
    CameraPointerRangeCursor sourceBegin,
    CameraPointerRangeCursor const sourceEnd,
    CameraPointerRangeCursor destinationBegin,
    CameraPointer const* const needleSlot
  ) noexcept
  {
    if (sourceBegin == sourceEnd) {
      *outDestinationEnd = destinationBegin;
      return outDestinationEnd;
    }

    CameraPointerRangeCursor writeCursor = destinationBegin;
    do {
      const CameraPointer value = *sourceBegin;
      if (value != *needleSlot) {
        *writeCursor = value;
        ++writeCursor;
      }
      ++sourceBegin;
    } while (sourceBegin != sourceEnd);

    *outDestinationEnd = writeCursor;
    return outDestinationEnd;
  }

  /**
   * Address: 0x007B15E0 (FUN_007B15E0, sub_7B15E0)
   *
   * What it does:
   * Adapter lane that forwards pointer-range compaction parameters into
   * `CompactCameraPointerRangeExcludingNeedle` and returns `outDestinationEnd`.
   */
  [[maybe_unused]] [[nodiscard]] CameraPointerRangeEndSlot CompactCameraPointerRangeExcludingNeedleAdapter(
    CameraPointerRangeCursor const destinationBegin,
    CameraPointerRangeEndSlot const outDestinationEnd,
    CameraPointerRangeCursor const sourceBegin,
    CameraPointerRangeCursor const sourceEnd,
    CameraPointer const* const needleSlot
  ) noexcept
  {
    (void)CompactCameraPointerRangeExcludingNeedle(
      outDestinationEnd,
      sourceBegin,
      sourceEnd,
      destinationBegin,
      needleSlot
    );
    return outDestinationEnd;
  }

  /**
   * Address: 0x007B0DE0 (FUN_007B0DE0, sub_7B0DE0)
   *
   * What it does:
   * Finds the first pointer equal to `*needleSlot` in `[begin,end)`, compacts
   * the remaining tail left over that slot while filtering duplicate matches,
   * stores the resulting logical end through `outDestinationEnd`, and returns
   * that slot pointer.
   */
  [[maybe_unused]] [[nodiscard]] CameraPointerRangeEndSlot RemoveCameraPointerFromRange(
    CameraPointer const* const needleSlot,
    CameraPointerRangeEndSlot const outDestinationEnd,
    CameraPointerRangeCursor begin,
    CameraPointerRangeCursor const end
  ) noexcept
  {
    CameraPointerRangeCursor match = begin;
    if (match == end) {
      *outDestinationEnd = match;
      return outDestinationEnd;
    }

    while (*match != *needleSlot) {
      ++match;
      if (match == end) {
        *outDestinationEnd = match;
        return outDestinationEnd;
      }
    }

    if (match == end) {
      *outDestinationEnd = match;
      return outDestinationEnd;
    }

    return CompactCameraPointerRangeExcludingNeedle(outDestinationEnd, match + 1, end, match, needleSlot);
  }

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

  /**
   * Address: 0x00BEF640 (FUN_00BEF640, Moho::TConVar_cam_HighLOD::~TConVar_cam_HighLOD)
   *
   * What it does:
   * Tears down the static `cam_HighLOD` console-variable registration: restores
   * the base `CConCommand` vftable and reregisters the slot when a name lane is
   * still set. Registered via `atexit` from the convar startup path.
   */
  void CleanupTConVar_cam_HighLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_HighLOD);
  }

  /**
   * Address: 0x00BEF670 (FUN_00BEF670, Moho::TConVar_cam_MediumLOD::~TConVar_cam_MediumLOD)
   *
   * What it does:
   * Tears down the static `cam_MediumLOD` console-variable registration via the
   * shared `TeardownConCommandRegistration` helper.
   */
  void CleanupTConVar_cam_MediumLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_MediumLOD);
  }

  /**
   * Address: 0x00BEF6A0 (FUN_00BEF6A0, Moho::TConVar_cam_LowLOD::~TConVar_cam_LowLOD)
   *
   * What it does:
   * Tears down the static `cam_LowLOD` console-variable registration via the
   * shared `TeardownConCommandRegistration` helper.
   */
  void CleanupTConVar_cam_LowLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_LowLOD);
  }

  /**
   * Address: 0x00BEF6D0 (FUN_00BEF6D0, Moho::TConVar_cam_DefaultLOD::~TConVar_cam_DefaultLOD)
   *
   * What it does:
   * Tears down the static `cam_DefaultLOD` console-variable registration via
   * the shared `TeardownConCommandRegistration` helper.
   */
  void CleanupTConVar_cam_DefaultLOD() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_cam_DefaultLOD);
  }

  /// 0x00E00779 (the shared empty-string literal also used by
  /// `ResolutionCommands.cpp`'s startup commands), the `.data` initializer
  /// of `Moho::CConFunc_SC_CameraScaleLOD` (+0x08). No console-help text in
  /// the binary.
  constexpr const char* kConsoleStartupSCCameraScaleLODDescription = "";

  // 0x00F5BE80. The registrar only patches the vftable and the
  // `mHandlerOrValue` slot at +0x0C; the name and (empty) description
  // lanes are `.data` initializers, matching the `SC_PrimaryAdapter`/
  // `SC_ToggleCursorClip` pattern in ResolutionCommands.cpp.
  moho::CConFunc gCConFunc_SC_CameraScaleLOD{};
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
   * The `mCams` append is routed through the per-T push_back-shape helper
   * `AppendCameraImplPtr` (which folds the fast-path in-place store and the
   * capacity-full `_Insert_n` grow lane FUN_007AFD10 / FUN_007AE990). In the
   * binary, CreateCamera open-codes the fast path inline and calls the grow
   * lane directly (0x007AAA68 `call sub_7AFD10`); wiring through the named
   * helper preserves those per-T MSVC8 symbols, which a bare
   * `mCams.push_back(camera)` would inline away.
   */
  CameraImpl* RCamManager::CreateCamera(
    const gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* const luaState
  )
  {
    CameraImpl* camera = nullptr;
    // 0x007AA9C0 allocates `operator new(0x858u)`. `sizeof(CameraImpl)` is one
    // pointer - the class is thin and its state lives behind runtime views - so
    // sizing the block by it hands the constructor four bytes and lets it write
    // 0x854 past the end, straight through whatever the allocator placed next.
    CameraImpl* const storage = static_cast<CameraImpl*>(::operator new(kCameraImplRuntimeSize, std::nothrow));
    if (storage != nullptr) {
      try {
        camera = new (storage) CameraImpl(name, map, luaState);
      } catch (...) {
        ::operator delete(storage);
        throw;
      }
    }

    AppendCameraImplPtr(mCams, camera);
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
    CameraImpl** compactedEnd = mCams.end();
    (void)RemoveCameraPointerFromRange(&needle, &compactedEnd, mCams.begin(), compactedEnd);
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
   * Returns the camera vector by value. The deep copy is routed through the
   * per-T named helper `CopyConstructVectorOfCameraImplPtr` (FUN_007AE840) so
   * the MSVC8 `vector<CameraImpl*>::vector(const vector&)` symbol shape is
   * preserved — a bare `return mCams;` would let the compiler NRVO the
   * out-of-line copy-ctor away.
   */
  msvc8::vector<CameraImpl*> RCamManager::GetAllCameras()
  {
    msvc8::vector<CameraImpl*> result;
    moho::CopyConstructVectorOfCameraImplPtr(result, mCams);
    return result;
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
  void SC_CameraScaleLOD(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() != 2) {
      return;
    }

    const int lodIndex = std::atoi(args.At(1)->c_str());
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

  void cleanup_CConFunc_SC_CameraScaleLOD()
  {
    CleanupStartupConCommand(gCConFunc_SC_CameraScaleLOD);
  }

  /**
   * Address: 0x00BE9540 (FUN_00BE9540, skip -- xc_a static initializer
   * lane; patches the vftable + callback slot on the already-`.data`-
   * initialized `gCConFunc_SC_CameraScaleLOD` and registers process-exit
   * teardown)
   */
  void register_CConFunc_SC_CameraScaleLOD()
  {
    gCConFunc_SC_CameraScaleLOD.InitializeRecovered(
      kConsoleStartupSCCameraScaleLODDescription, "SC_CameraScaleLOD", &moho::SC_CameraScaleLOD
    );
    (void)std::atexit(&cleanup_CConFunc_SC_CameraScaleLOD);
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
      moho::register_CConFunc_SC_CameraScaleLOD();
    }
  };

  [[maybe_unused]] RCamManagerStartupBootstrap gRCamManagerStartupBootstrap;
} // namespace

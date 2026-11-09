#include "moho/ui/UiPrivate.h"

#include "lua/LuaIncrementalGc.h"

namespace moho
{
}

namespace
{

  LuaPlus::LuaState* gUserLuaState = nullptr;

  void AttachTaskToStage(
    moho::CTask* const task,
    moho::CTaskStage* const stage,
    const bool owning
  )
  {
    if (task == nullptr || stage == nullptr || task->mOwnerThread != nullptr) {
      return;
    }

    moho::CTaskThread* const thread = new moho::CTaskThread(stage);
    if (thread == nullptr) {
      return;
    }

    task->mAutoDelete = owning;
    task->mOwnerThread = thread;
    task->mSubtask = thread->mTaskTop;
    thread->mTaskTop = task;
  }

  void RunLuaInitFormSetIfPresent(
    const char* const setName,
    LuaPlus::LuaState* const state
  )
  {
    moho::CScrLuaInitFormSet* const initSet = moho::SCR_FindLuaInitFormSet(setName);
    if (initSet == nullptr) {
      return;
    }

    initSet->mRegistered = 1;
    for (moho::CScrLuaInitForm* form = initSet->mForms; form != nullptr; form = form->mNextInSet) {
      form->Run(state);
    }
  }
  constexpr const char* kInternalCreateDraggerHelpText =
    "InternalCreateDragger(luaobj) -- for internal use by CreateDragger()";
  constexpr const char* kInternalCreateMapPreviewHelpText = "InternalCreateMapPreview(luaobj,parent)";
  constexpr const char* kInternalCreateWldUIProviderHelpText =
    "InternalCreateWldUIProvider(luaobj) - create the C++ script object";
  constexpr const char* kCMauiListItemScrollToBottomHelpText = "ItemList:ScrollToBottom()";
  constexpr const char* kCMauiBitMapGetNumFramesHelpText = "GetNumFrames()";
  constexpr const char* kAnyInputCaptureHelpText =
    "bool AnyInputCapture() - returns true if there is anything currently on the capture stack";
  constexpr const char* kSetFrontEndDataHelpText = "SetFrontEndData(key, data)";
  constexpr const char* kGetCursorHelpText = "GetCursor()";
  constexpr const char* kSetUIControlsAlphaHelpText =
    "SetUIControlsAlpha(float alpha) -- set the alpha multiplier for 2d UI controls";
  constexpr const char* kGetUIControlsAlphaHelpText =
    "float GetUIControlsAlpha() -- get the alpha multiplier for 2d UI controls";
  constexpr const char* kFlushEventsHelpText = "FlushEvents() -- flush mouse/keyboard events";
  constexpr const char* kClearCurrentFactoryForQueueDisplayHelpText = "ClearCurrentFactoryForQueueDisplay()";

  /**
   * Address: 0x0078C730 (FUN_0078C730)
   *
   * What it does:
   * Backward-copies one dword range `[sourceBegin, sourceEnd)` into destination
   * ending at `destinationEnd` and stores resulting begin pointer to output.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeBackwardToEnd(
    std::uint32_t** const outBeginSlot,
    const std::uint32_t* sourceEnd,
    const std::uint32_t* const sourceBegin,
    std::uint32_t* destinationEnd
  ) noexcept
  {
    if (sourceEnd != sourceBegin) {
      do {
        --sourceEnd;
        --destinationEnd;
        *destinationEnd = *sourceEnd;
      } while (sourceEnd != sourceBegin);
    }

    *outBeginSlot = destinationEnd;
    return outBeginSlot;
  }

  /**
   * Address: 0x0078C760 (FUN_0078C760)
   *
   * What it does:
   * Secondary entrypoint for backward dword-range copy into destination tail.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeBackwardToEndAlias(
    std::uint32_t** const outBeginSlot,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* sourceEnd,
    std::uint32_t* destinationEnd
  ) noexcept
  {
    return CopyDwordRangeBackwardToEnd(outBeginSlot, sourceEnd, sourceBegin, destinationEnd);
  }

  /**
   * Address: 0x0078C790 (FUN_0078C790)
   *
   * What it does:
   * Forward-copies one dword range `[sourceBegin, sourceEnd)` and stores
   * one-past-end destination pointer in output.
   */
  [[maybe_unused]] std::uint32_t** CopyDwordRangeForwardToEnd(
    std::uint32_t** const outEndSlot,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* destinationBegin
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destinationBegin = *sourceBegin;
      ++sourceBegin;
      ++destinationBegin;
    }

    *outEndSlot = destinationBegin;
    return outEndSlot;
  }

  /**
   * Address: 0x0078C7C0 (FUN_0078C7C0)
   *
   * What it does:
   * Conditionally stores one source dword into destination when destination
   * storage is present.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordIfDestinationPresent(
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != nullptr) {
      *destination = *source;
    }
    return destination;
  }

  /**
   * Address: 0x0078C8F0 (FUN_0078C8F0)
   *
   * What it does:
   * Advances one packed byte-address lane by `4 * dwordCount`.
   */
  [[maybe_unused]] std::uint32_t* AdvancePackedAddressByDwordCount(
    std::uint32_t* const packedAddressLane,
    const std::int32_t dwordCount
  ) noexcept
  {
    *packedAddressLane += static_cast<std::uint32_t>(4 * dwordCount);
    return packedAddressLane;
  }
}


  /// The dragger that owns the mouse until it is released or replaced. A
  /// weak link, so a dragger that deletes itself drops out of it.
  // Address: 0x0078E540 (FUN_0078E540 -- this global's constructor emitted
  // out of line: both words zeroed, `this` returned.)
  // Address: 0x0078E560 (FUN_0078E560 -- its destructor, `~WeakPtr`; ICF twin
  // 0x00C02D50 is the copy the exit list runs. Formerly the uncalled statics
  // `func_ResetCurrentDraggerLink` / `func_UnlinkCurrentDraggerLink`, removed
  // 2026-09-30.)
  moho::WeakPtr<IMauiDragger> sCurrentDragger{};
  std::int32_t sCurrentDraggerKeycode = 0;
  std::uint8_t sMouseIsCaptured = 0;
  std::uint8_t sMouseIsScrubbing = 0;
  POINT sMouseMoveStart{};
  POINT sMouseScrubDelta{};
  bool sInvertMidMouseScrub = false;
  POINT sMouseScrubAnchor{};
  // Engine addition, not in the binary: where the latest
  // SetCursorPos(sMouseScrubAnchor) actually put the cursor, re-read after
  // every warp. Under DPI scaling, or when the anchor falls outside the
  // window's ClipCursor rect, the cursor lands elsewhere, and not always on
  // the same spot; measuring against the requested anchor counted that gap as
  // mouse motion on every warp (a tiny drag spun the camera by hundreds of
  // pixels). Where the warp lands exactly, this equals the anchor and nothing
  // changes.
  POINT sMouseScrubLanded{};

  fa::vector<moho::WeakPtr<moho::CMauiControl>> sInputCapture;
namespace
{

  /**
   * Address: 0x007A59E0 (FUN_007A59E0)
   *
   * What it does:
   * Returns the process-global input-capture vector storage, ignoring one
   * stdcall argument lane.
   */
  [[nodiscard]] fa::vector<moho::WeakPtr<moho::CMauiControl>>* ResolveInputCaptureStorageWithArg(
    const std::int32_t /*ignoredArg*/
  ) noexcept
  {
    return &sInputCapture;
  }

  /**
   * Address: 0x007A5DA0 (FUN_007A5DA0)
   *
   * What it does:
   * Returns the process-global input-capture vector storage.
   */
  [[maybe_unused]] [[nodiscard]] fa::vector<moho::WeakPtr<moho::CMauiControl>>* ResolveInputCaptureStorage() noexcept
  {
    return ResolveInputCaptureStorageWithArg(0);
  }

  /**
   * Address: 0x007A5680 (FUN_007A5680)
   *
   * What it does:
   * Stores the current global input-capture begin lane into `outBegin`.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>** StoreInputCaptureBeginLane(
    moho::WeakPtr<moho::CMauiControl>** const outBegin
  ) noexcept
  {
    *outBegin = sInputCapture.begin();
    return outBegin;
  }

  /**
   * Address: 0x007A5690 (FUN_007A5690)
   *
   * What it does:
   * Stores the current global input-capture end lane into `outEnd`.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>** StoreInputCaptureEndLane(
    moho::WeakPtr<moho::CMauiControl>** const outEnd
  ) noexcept
  {
    *outEnd = sInputCapture.end();
    return outEnd;
  }

  /**
   * Address: 0x007A56F0 (FUN_007A56F0)
   *
   * What it does:
   * Returns one indexed weak-control lane from the global input-capture
   * vector storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::WeakPtr<moho::CMauiControl>* ResolveInputCaptureLaneAt(
    const std::size_t index
  ) noexcept
  {
    return sInputCapture.begin() + static_cast<std::ptrdiff_t>(index);
  }
  /**
   * Address: 0x00794DB0 (FUN_00794DB0)
   *
   * What it does:
   * Finds the first position at or after `startPos` where `text` contains any
   * character from `characterSet`.
   */
  [[maybe_unused, nodiscard]] std::size_t FindFirstOfCharacterSet(
    const fa::string& text,
    const fa::string& characterSet,
    const std::size_t startPos
  ) noexcept
  {
    return text.view().find_first_of(characterSet.view(), startPos);
  }
}


// `moho::sUIState` is defined in gpg/core/reflection/Reflection.cpp (sim side).
bool moho::cam_Free = false;
// 0x00F57AA0 `?ren_BgLowerBound@Moho@@3MA`; the shipped `.data` word is
// `00 00 fa 42` == 125.0f.
float moho::ren_BgLowerBound = 125.0f;
bool moho::ui_DisableCursorFixing = false;
float moho::ui_SelectTolerance = 4.0f;
float moho::ui_ExtractSnapTolerance = 20.0f;
float moho::ui_MinExtractSnapPixels = 20.0f;
float moho::ui_MaxExtractSnapPixels = 90.0f;
float moho::ui_FootprintMinThickness = 2.0f;
float moho::cam_DefaultMiniLOD = 1.8f;
bool moho::ui_WindowedAlwaysShowsCursor = false;
bool moho::ui_DragSelect2D = true;
// Byte-verified shipped defaults, read straight out of bin/external/ForgedAlliance.exe
// at the addresses in the header doc blocks (0x00F57AA4/A8/AC/B0, 0x00F57A8C, 0x00F57887).
float moho::ui_KeyboardPanSpeed = 90.0f;
float moho::ui_KeyboardPanAccelerateMultiplier = 4.0f;
float moho::ui_KeyboardRotateSpeed = 10.0f;
float moho::ui_KeyboardRotateAccelerateMultiplier = 2.0f;
bool moho::ui_ScreenEdgeScrollView = true;
bool moho::ui_ArrowKeysScrollView = true;
moho::IWldUIProvider* moho::sWldUIProvider = nullptr;
moho::WeakPtr<moho::CMauiControl> moho::Maui_CurrentFocusControl{};
bool moho::Maui_ControlHasFocus = false;

/**
 * Address: 0x0079CB70 (FUN_0079CB70, Moho::MAUI_KeyIsDown)
 *
 * What it does:
 * Polls one Maui key through MSW key state only when the GAL window is
 * foreground and focus capture does not block key-down processing.
 */
bool moho::MAUI_KeyIsDown(
  const EMauiKeyCode keyCode
)
{
  if (Maui_CurrentFocusControl.GetObjectPtr() != nullptr && Maui_ControlHasFocus) {
    return false;
  }

  bool isSpecial = false;
  const int virtualKey = wxCharCodeWXToMSW(static_cast<int>(keyCode), &isSpecial);
  (void)isSpecial;
  // Engine change: the same answer with the costly check last. GetForegroundWindow enters the kernel,
  // the world view asks for Shift each frame, and the key is rarely down.
  return ::GetKeyState(virtualKey) < 0 && gpg::gal::WindowIsForeground();
}

moho::CScrLuaMetatableFactory<moho::CUIWorldView> moho::CScrLuaMetatableFactory<moho::CUIWorldView>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>
  moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CUIWorldMesh> moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CUIMapPreview> moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiControl> moho::CScrLuaMetatableFactory<moho::CMauiControl>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiBorder> moho::CScrLuaMetatableFactory<moho::CMauiBorder>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiBitmap> moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiCursor> moho::CScrLuaMetatableFactory<moho::CMauiCursor>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger> moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiEdit> moho::CScrLuaMetatableFactory<moho::CMauiEdit>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiScrollbar> moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::sInstance{};
moho::CScrLuaMetatableFactory<moho::CMauiText> moho::CScrLuaMetatableFactory<moho::CMauiText>::sInstance{};

moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>&
moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>& moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIWorldView>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CUIWorldView>& moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CUIMapPreview>& moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiControl>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiControl>& moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00783EA0 (FUN_00783EA0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiControl>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiControl>*
startup_CScrLuaMetatableFactory_CMauiControl_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00783070 (FUN_00783070, Moho::CScrLuaMetatableFactory<Moho::CMauiControl>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiControl`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiControl>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiBorder>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiBorder>& moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007862E0 (FUN_007862E0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiBorder>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiBorder>*
startup_CScrLuaMetatableFactory_CMauiBorder_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00786180 (FUN_00786180, Moho::CScrLuaMetatableFactory<Moho::CMauiBorder>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiBorder`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiBitmap>& moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00783E70 (FUN_00783E70)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiBitmap>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiBitmap>*
startup_CScrLuaMetatableFactory_CMauiBitmap_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00783040 (FUN_00783040, Moho::CScrLuaMetatableFactory<Moho::CMauiBitmap>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiBitmap`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiCursor>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiCursor>& moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x0078DAA0 (FUN_0078DAA0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiCursor>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiCursor>*
startup_CScrLuaMetatableFactory_CMauiCursor_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x0078D940 (FUN_0078D940, Moho::CScrLuaMetatableFactory<Moho::CMauiCursor>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiCursor`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>& moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x0078EAF0 (FUN_0078EAF0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiLuaDragger>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>*
startup_CScrLuaMetatableFactory_CMauiLuaDragger_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x0078E660 (FUN_0078E660, Moho::CScrLuaMetatableFactory<Moho::CMauiLuaDragger>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiLuaDragger`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiEdit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiEdit>& moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00795610 (FUN_00795610)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CMauiEdit>` and returns that singleton.
 */
[[maybe_unused]] static moho::CScrLuaMetatableFactory<moho::CMauiEdit>*
startup_CScrLuaMetatableFactory_CMauiEdit_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00794E90 (FUN_00794E90, Moho::CScrLuaMetatableFactory<Moho::CMauiEdit>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiEdit`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>& moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007A2470 (FUN_007A2470, Moho::CScrLuaMetatableFactory<Moho::CMauiScrollbar>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiScrollbar`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

moho::CScrLuaMetatableFactory<moho::CMauiText>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory()
{}

moho::CScrLuaMetatableFactory<moho::CMauiText>& moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x007A4250 (FUN_007A4250, Moho::CScrLuaMetatableFactory<Moho::CMauiText>::Create)
 *
 * What it does:
 * Builds one simple Lua metatable object for `CMauiText`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CMauiText>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00798BB0 (FUN_00798BB0, register_CScrLuaMetatableFactory_CMauiHistogram_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CMauiHistogram.
 */
int moho::register_CScrLuaMetatableFactory_CMauiHistogram_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x007A2890 (FUN_007A2890, register_CScrLuaMetatableFactory_CMauiScrollbar_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CMauiScrollbar.
 */
int moho::register_CScrLuaMetatableFactory_CMauiScrollbar_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x0086AD10 (FUN_0086AD10, register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CLuaWldUIProvider.
 */
int moho::register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x0086D9D0 (FUN_0086D9D0, register_CScrLuaMetatableFactory_CUIWorldMesh_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CUIWorldMesh.
 */
int moho::register_CScrLuaMetatableFactory_CUIWorldMesh_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}

/**
 * Address: 0x00873B50 (FUN_00873B50, register_CScrLuaMetatableFactory_CUIWorldView_Index)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * CUIWorldView.
 */
int moho::register_CScrLuaMetatableFactory_CUIWorldView_Index()
{
  auto& instance = moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance();
  instance.SetFactoryObjectIndexForRecovery(moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return 0;
}
namespace
{
  struct UiLuaFactoryIndexStartup
  {
    UiLuaFactoryIndexStartup()
    {
      (void)moho::register_CScrLuaMetatableFactory_CMauiHistogram_Index();
      (void)moho::register_CScrLuaMetatableFactory_CMauiScrollbar_Index();
      (void)moho::register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUIWorldMesh_Index();
      (void)moho::register_CScrLuaMetatableFactory_CUIWorldView_Index();
    }
  };

  UiLuaFactoryIndexStartup gUiLuaFactoryIndexStartup;
}


/**
 * Address: 0x0077F670 (FUN_0077F670)
 *
 * What it does:
 * Writes `0.0` into Lua table lane `1` for one lazy-var object lane.
 */
[[maybe_unused]] void ResetLazyVarObjectLaneToZero(
  LuaPlus::LuaObject* const lazyVarObject
)
{
  if (lazyVarObject != nullptr) {
    lazyVarObject->SetNumber(1, 0.0);
  }
}

/**
 * Address: 0x00782E60 (FUN_00782E60)
 *
 * What it does:
 * Adapter lane that resolves and returns one `CScriptLazyVar_float` value.
 */
[[maybe_unused]] float EvaluateLazyVarFloatValueAdapter(
  const moho::CScriptLazyVar_float* const value
) noexcept
{
  return moho::CScriptLazyVar_float::GetValue(value);
}

/**
 * Address: 0x00782E70 (FUN_00782E70)
 *
 * What it does:
 * Adapter lane that sets one `CScriptLazyVar_float` value and returns the
 * same lazy-var lane pointer.
 */
[[maybe_unused]] moho::CScriptLazyVar_float* SetLazyVarFloatValueAdapter(
  moho::CScriptLazyVar_float* const value,
  const float next
) noexcept
{
  moho::CScriptLazyVar_float::SetValue(value, next);
  return value;
}

/**
 * Address: 0x007822C0 (FUN_007822C0, cfunc_CMauiBitMapGetNumFrames)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiBitMapGetNumFramesL`.
 */
int moho::cfunc_CMauiBitMapGetNumFrames(
  lua_State* const luaContext
)
{
  return cfunc_CMauiBitMapGetNumFramesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007822E0 (FUN_007822E0, func_CMauiBitMapGetNumFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiBitmap:GetNumFrames()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiBitMapGetNumFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetNumFrames",
    &moho::cfunc_CMauiBitMapGetNumFrames,
    &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
    "CMauiBitmap",
    kCMauiBitMapGetNumFramesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00782340 (FUN_00782340, cfunc_CMauiBitMapGetNumFramesL)
 *
 * What it does:
 * Resolves one bitmap object and pushes its frame-count lane.
 */
int moho::cfunc_CMauiBitMapGetNumFramesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiBitMapGetNumFramesHelpText);

  LuaPlus::LuaObject bitmapObject(LuaPlus::LuaStackObject(state, 1));
  CMauiBitmap* const bitmap = SCR_FromLua_CMauiBitmap(bitmapObject, state);
  const int frameCount = CountBitmapFramePatternEntries(bitmap);
  lua_pushnumber(state->m_state, static_cast<float>(frameCount));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00855040 (FUN_00855040, fa::vector<boost::shared_ptr<MeshInstance>>::push_back)
 *
 * What it does:
 * Per-T canonical-template-helper binding for the engine-instantiated
 * `fa::vector<boost::shared_ptr<MeshInstance>>::push_back(const&)`
 * fast/slow-path body (8-byte element stride: shared_ptr `(px, pi)` pair).
 *
 * Wires `AppendBuildPreviewMesh` from the inline
 * `mMeshes.push_back(meshInstance);` form to an explicit-name invocation
 * so the MSVC8 per-T template emission symbol shape is preserved even
 * when the modern compiler would inline the natural push_back call.
 */
void moho::PushBackMeshInstanceSharedPtrVector(
  fa::vector<boost::shared_ptr<moho::MeshInstance>>& destination,
  const boost::shared_ptr<moho::MeshInstance>& value
)
{
  destination.push_back(value);
}

/**
 * Address: 0x0086DDF0 (FUN_0086DDF0, sub_86DDF0)
 *
 * What it does:
 * Clears the global mouse-scrub active flag and returns its storage address.
 */
[[maybe_unused]] static std::uint8_t* func_ResetMouseScrubStateFlag()
{
  sMouseIsScrubbing = 0;
  return &sMouseIsScrubbing;
}

/**
 * Address: 0x0086DE00 (FUN_0086DE00, sub_86DE00)
 *
 * What it does:
 * Converts integer mouse-scrub delta lanes to float XY output.
 */
[[maybe_unused]] static float* func_GetMouseScrubDelta(
  float* const outDelta
)
{
  outDelta[0] = static_cast<float>(sMouseScrubDelta.x);
  outDelta[1] = static_cast<float>(sMouseScrubDelta.y);
  return outDelta;
}

/**
 * Address: 0x0086DE20 (FUN_0086DE20, sub_86DE20)
 *
 * What it does:
 * Returns whether mouse-scrub mode is currently active.
 */
[[maybe_unused]] static std::uint8_t func_IsMouseScrubbingActive()
{
  return sMouseIsScrubbing;
}

/**
 * Address: 0x0086DFE0 (FUN_0086DFE0, sub_86DFE0)
 *
 * What it does:
 * Clears accumulated integer mouse-scrub deltas and returns zero.
 */
[[maybe_unused]] static int func_ResetMouseScrubDelta()
{
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;
  return 0;
}

void moho::UI_SetInvertMidMouseScrub(
  const bool invert
) noexcept
{
  sInvertMidMouseScrub = invert;
}
  /**
   * Depth of MAUI event dispatch currently on the stack. `PurgeDeleted` skips
   * the delete while this is non-zero, so a control cannot be freed underneath
   * an event walk that still holds a pointer to it. Single-threaded: every
   * dispatch runs on the wx message loop.
   */
  int gMauiEventDispatchDepth = 0;

bool moho::MAUI_EventDispatchInProgress() noexcept
{
  return MauiEventDispatchInProgress();
}

/**
 * Address: 0x0078E0B0 (FUN_0078E0B0, cfunc_InternalCreateDragger)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateDraggerL`.
 */
int moho::cfunc_InternalCreateDragger(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateDraggerL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0078E0D0 (FUN_0078E0D0, func_InternalCreateDragger_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateDragger(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateDragger_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateDragger",
    &moho::cfunc_InternalCreateDragger,
    nullptr,
    "<global>",
    kInternalCreateDraggerHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078E130 (FUN_0078E130, cfunc_InternalCreateDraggerL)
 *
 * What it does:
 * Reads `(luaobj)`, allocates and constructs one `CMauiLuaDragger`, and
 * pushes the created dragger's Lua object. Unlike control factories the
 * dragger dispatches no `DoInit`.
 */
int moho::cfunc_InternalCreateDraggerL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kInternalCreateDraggerHelpText);

  // Binary: `operator new(0x3C)`.
  void* const storage = AllocateZeroedUiObject<void>(0x3C);
  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  auto* const dragger = new (storage) CMauiLuaDragger(luaObject);
  dragger->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079BF40 (FUN_0079BF40, cfunc_CMauiListItemScrollToBottom)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiListItemScrollToBottomL`.
 */
int moho::cfunc_CMauiListItemScrollToBottom(
  lua_State* const luaContext
)
{
  return cfunc_CMauiListItemScrollToBottomL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079BF60 (FUN_0079BF60, func_CMauiListItemScrollToBottom_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiItemList:ScrollToBottom()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiListItemScrollToBottom_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ScrollToBottom",
    &moho::cfunc_CMauiListItemScrollToBottom,
    &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
    "CMauiItemList",
    kCMauiListItemScrollToBottomHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079BFC0 (FUN_0079BFC0, cfunc_CMauiListItemScrollToBottomL)
 *
 * What it does:
 * Reads one `CMauiItemList` and scrolls to bottom.
 */
int moho::cfunc_CMauiListItemScrollToBottomL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiListItemScrollToBottomHelpText);

  LuaPlus::LuaObject itemListObject(LuaPlus::LuaStackObject(state, 1));
  CMauiItemList* const itemList = SCR_FromLua_CMauiItemList(itemListObject, state);
  itemList->ScrollToBottom();
  return 0;
}

/**
 * Address: 0x00846760 (FUN_00846760, cfunc_SetFrontEndData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetFrontEndDataL`.
 */
int moho::cfunc_SetFrontEndData(
  lua_State* const luaContext
)
{
  return cfunc_SetFrontEndDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846780 (FUN_00846780, func_SetFrontEndData_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetFrontEndData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetFrontEndData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "SetFrontEndData", &moho::cfunc_SetFrontEndData, nullptr, "<global>", kSetFrontEndDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008467E0 (FUN_008467E0, cfunc_SetFrontEndDataL)
 *
 * What it does:
 * Copies caller key/data lanes into user-state global `FrontEndData`.
 */
int moho::cfunc_SetFrontEndDataL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetFrontEndDataHelpText);

  LuaPlus::LuaState* const userState = USER_GetLuaState();
  LuaPlus::LuaObject frontEndData = userState->GetGlobals()["FrontEndData"];

  const LuaPlus::LuaObject callerValue(LuaPlus::LuaStackObject(state, 2));
  const LuaPlus::LuaObject callerKey(LuaPlus::LuaStackObject(state, 1));
  const LuaPlus::LuaObject valueOnUserState = SCR_Copy(callerValue, userState);
  const LuaPlus::LuaObject keyOnUserState = SCR_Copy(callerKey, userState);
  frontEndData.SetObject(keyOnUserState, valueOnUserState);
  return 0;
}

/**
 * Address: 0x0084DDE0 (FUN_0084DDE0, cfunc_GetCursor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetCursorL`.
 */
int moho::cfunc_GetCursor(
  lua_State* const luaContext
)
{
  return cfunc_GetCursorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084DE00 (FUN_0084DE00, func_GetCursor_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetCursor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetCursor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "GetCursor", &moho::cfunc_GetCursor, nullptr, "<global>", kGetCursorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084DE60 (FUN_0084DE60, cfunc_GetCursorL)
 *
 * What it does:
 * Returns active UI cursor script object when present; otherwise pushes `nil`.
 */
int moho::cfunc_GetCursorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetCursorHelpText);

  CMauiCursor* const cursor = g_UIManager != nullptr ? g_UIManager->GetCursor() : nullptr;
  if (cursor == nullptr) {
    lua_pushnil(state->m_state);
    return 1;
  }

  cursor->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0084DEF0 (FUN_0084DEF0, cfunc_SetUIControlsAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetUIControlsAlphaL`.
 */
int moho::cfunc_SetUIControlsAlpha(
  lua_State* const luaContext
)
{
  return cfunc_SetUIControlsAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084DF10 (FUN_0084DF10, func_SetUIControlsAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetUIControlsAlpha(float)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetUIControlsAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetUIControlsAlpha",
    &moho::cfunc_SetUIControlsAlpha,
    nullptr,
    "<global>",
    kSetUIControlsAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084DF70 (FUN_0084DF70, cfunc_SetUIControlsAlphaL)
 *
 * What it does:
 * Reads one float arg and updates active UI manager controls-alpha lane.
 */
int moho::cfunc_SetUIControlsAlphaL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kSetUIControlsAlphaHelpText);

  LuaPlus::LuaStackObject alphaArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }

  const float alphaValue = static_cast<float>(lua_tonumber(state->m_state, 1));
  if (g_UIManager != nullptr) {
    g_UIManager->SetUIControlsAlpha(alphaValue);
  }
  return 0;
}

/**
 * Address: 0x0084E000 (FUN_0084E000, cfunc_GetUIControlsAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUIControlsAlphaL`.
 */
int moho::cfunc_GetUIControlsAlpha(
  lua_State* const luaContext
)
{
  return cfunc_GetUIControlsAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0084E020 (FUN_0084E020, func_GetUIControlsAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetUIControlsAlpha()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUIControlsAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetUIControlsAlpha",
    &moho::cfunc_GetUIControlsAlpha,
    nullptr,
    "<global>",
    kGetUIControlsAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x0084E080 (FUN_0084E080, cfunc_GetUIControlsAlphaL)
 *
 * What it does:
 * Reads active UI controls-alpha lane and pushes it, or `nil` if unavailable.
 */
int moho::cfunc_GetUIControlsAlphaL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetUIControlsAlphaHelpText);

  if (g_UIManager == nullptr) {
    lua_pushnil(state->m_state);
    return 1;
  }

  lua_pushnumber(state->m_state, g_UIManager->GetUIControlsAlpha());
  return 1;
}
namespace moho
{
  /**
   * Address: 0x0084DA80 (FUN_0084DA80, sub_84DA80)
   *
   * IDA signature:
   * void sub_84DA80(void);
   *
   * What it does:
   * For every window in `g_UIManager->mInputWindows` (IDA's decompiler
   * mis-typed this field's pointee as `Moho::WRenViewport`; the raw
   * `sub ebp, [ebx+38h]` displacement off the `Moho::UI_Manager` global
   * lands exactly on `CUIManager::mInputWindows`, a
   * `gpg::fastvector_n<wxWindow*, 2>`, per CUIManager.h), pops that
   * window's two topmost pushed event handlers - the frame's
   * CMauiWxEventMapper and the CUIKeyHandler behind it.
   *
   * The saved-handler storage is a real `fa::vector<fa::vector<
   * wxEvtHandler*>>` (one dynamically-grown inner vector per window),
   * not a fixed 2-slot pair -- the raw decompile shows a capacity-checked
   * append-or-grow sequence per `PopEventHandler()` result
   * (`if (size < capacity) *end++ = val; else <grow-call>;`), the exact
   * shape of this container's `push_back`. The outer vector is
   * `resize()`-d to `mInputWindows.size()` up front (`FUN_0084E8A0`),
   * growing/shrinking through `FUN_0084EE20`/`FUN_0084EDB0`; the "move
   * existing 16-byte inner-vector elements into the new buffer" step
   * (`FUN_0084F820`/`FUN_0084F8A0`) calls `fa::vector<wxEvtHandler*>::
   * operator=` per element, cited as `FUN_0084FF80` on that template
   * member in `Vector.h`. (`FUN_0084E8A0`/`FUN_0084EE20`/`FUN_0084EDB0`/
   * `FUN_0084F8A0` are not yet independently address-annotated -- their
   * register-heavy `__userpurge`/`__usercall` shapes need a dedicated pass;
   * this call site is what makes their template instantiations real
   * either way.)
   *
   * After popping, pumps the wx message queue empty via
   * `wxTheApp->Pending()`/`Dispatch()` so raw wx events are processed
   * without those handlers intercepting them, then pushes the two handlers
   * back in reverse pop order (restoring the original front-to-back order,
   * matching a real PushEventHandler/PopEventHandler stack).
   *
   * Previously modeled with a fixed `{topHandler, nextHandler}` struct in a
   * `std::vector` -- behaviorally equivalent for the current 2-handler-per-
   * window reality, but not what the binary actually built, and silently
   * wrong if a window ever carries a different handler count. Corrected to
   * match the real per-window dynamic vector.
   */
  void SuspendInputWindowEventHandlersAndFlushQueue()
  {
    fa::vector<fa::vector<wxEvtHandler*>> suspended;
    suspended.resize(g_UIManager->mInputWindows.size());

    std::size_t index = 0;
    for (wxWindow* const inputWindow : g_UIManager->mInputWindows) {
      suspended[index].push_back(inputWindow->PopEventHandler(false));
      suspended[index].push_back(inputWindow->PopEventHandler(false));
      ++index;
    }

    while (wxTheApp->Pending()) {
      wxTheApp->Dispatch();
    }

    index = 0;
    for (wxWindow* const inputWindow : g_UIManager->mInputWindows) {
      inputWindow->PushEventHandler(suspended[index][1]);
      inputWindow->PushEventHandler(suspended[index][0]);
      ++index;
    }
  }
}


/**
 * Address: 0x0084E0F0 (FUN_0084E0F0, func_FlushEvents)
 * Mangled: registered directly as `luadef_FlushEvents.mFunc`, matching
 * `CScrLuaBinder::LuaFunction = int(__cdecl*)(lua_State*)`
 *
 * IDA signature:
 * int __cdecl func_FlushEvents(lua_State *luaContext);
 *
 * IDA's decompiler labels the parameter `LuaPlus::LuaState *a1` and the body
 * opens with `LuaPlus::LuaState::CastState((lua_State *)a1)` - but CastState
 * itself takes a `lua_State*` and returns the `LuaPlus::LuaState*` wrapper
 * (see its real signature, `?CastState@LuaState@LuaPlus@@SAPAV12@PAUlua_State@@@Z`),
 * which is exactly what this project's `ResolveBindingState` does inline by
 * reading `stateUserData`. So the true parameter is the raw `lua_State*` the
 * Lua VM hands every registered `lua_CFunction` - matching
 * `CScrLuaBinder::LuaFunction` exactly, and matching how
 * `func_FlushEvents_LuaFuncDef` below already registers `&moho::func_FlushEvents`
 * as that binder's raw C function.
 *
 * What it does:
 * Rejects any argument (FlushEvents takes none), then when the UI manager is
 * live, suspends each input window's pushed event handlers, pumps the wx
 * event queue empty, and restores them
 * (SuspendInputWindowEventHandlersAndFlushQueue / FUN_0084DA80).
 */
int moho::func_FlushEvents(
  lua_State* const luaContext
)
{
  LuaPlus::LuaState* const state = ResolveBindingState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kFlushEventsHelpText);

  if (g_UIManager != nullptr) {
    SuspendInputWindowEventHandlersAndFlushQueue();
  }

  return 0;
}

/**
 * Address: 0x0084E140 (FUN_0084E140, func_FlushEvents_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `FlushEvents()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_FlushEvents_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "FlushEvents", &moho::func_FlushEvents, nullptr, "<global>", kFlushEventsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BE4EC0 (FUN_00BE4EC0, register_FlushEvents_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_FlushEvents_LuaFuncDef()
{
  return func_FlushEvents_LuaFuncDef();
}

/**
 * Address: 0x00850D20 (FUN_00850D20, cfunc_InternalCreateMapPreview)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMapPreviewL`.
 */
int moho::cfunc_InternalCreateMapPreview(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateMapPreviewL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00850D40 (FUN_00850D40, func_InternalCreateMapPreview_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMapPreview(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMapPreview_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateMapPreview",
    &moho::cfunc_InternalCreateMapPreview,
    nullptr,
    "<global>",
    kInternalCreateMapPreviewHelpText
  );
  return &binder;
}

/**
 * Address: 0x00850DA0 (FUN_00850DA0, cfunc_InternalCreateMapPreviewL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CUIMapPreview`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMapPreviewL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateMapPreviewHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x124)`.
  auto* const mapPreview = AllocateZeroedUiObject<CUIMapPreview>(0x124u);
  new (mapPreview) CUIMapPreview(&luaObject, parentControl);
  mapPreview->DoInit();
  mapPreview->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0086A8D0 (FUN_0086A8D0, cfunc_InternalCreateWldUIProvider)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateWldUIProviderL`.
 */
int moho::cfunc_InternalCreateWldUIProvider(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateWldUIProviderL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0086A8F0 (FUN_0086A8F0, func_InternalCreateWldUIProvider_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateWldUIProvider(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateWldUIProvider_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateWldUIProvider",
    &moho::cfunc_InternalCreateWldUIProvider,
    nullptr,
    "<global>",
    kInternalCreateWldUIProviderHelpText
  );
  return &binder;
}

/**
 * Address: 0x0086A950 (FUN_0086A950, cfunc_InternalCreateWldUIProviderL)
 *
 * What it does:
 * Builds one `CLuaWldUIProvider` from one Lua object lane, pushes the
 * script-object handle to Lua, and updates global world-ui-provider ownership.
 */
int moho::cfunc_InternalCreateWldUIProviderL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kInternalCreateWldUIProviderHelpText);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  CLuaWldUIProvider* const provider = new CLuaWldUIProvider(&luaObject);
  CScriptObject* const providerScriptObject = static_cast<CScriptObject*>(provider);
  providerScriptObject->mLuaObj.PushStack(state);

  if (sWldUIProvider != provider && sWldUIProvider != nullptr) {
    delete sWldUIProvider;
  }
  sWldUIProvider = provider;
  return 1;
}
namespace
{

  /**
   * Address: 0x00780230 (FUN_00780230)
   *
   * What it does:
   * Returns frame count from one bitmap frame-pattern vector lane.
   */
  [[maybe_unused]] std::int32_t CountBitmapFramePatternEntries(
    const moho::CMauiBitmap* const bitmap
  ) noexcept
  {
    const std::int32_t* const frameStart = bitmap->mFrames.begin();
    if (frameStart == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(bitmap->mFrames.end() - frameStart);
  }
}


/**
 * Address: 0x00795BD0 (FUN_00795BD0, func_CreateLuaEvent)
 *
 * What it does:
 * Builds one script-visible event payload table from one `SMauiEventData`
 * packet, including event type text, mouse/key lanes, modifier flags, and
 * optional source control object.
 */
LuaPlus::LuaObject* moho::CreateLuaEventObject(
  SMauiEventData* const eventData,
  LuaPlus::LuaObject* const outEvent,
  LuaPlus::LuaState* const state
)
{
  LuaPlus::LuaObject modifiers;
  modifiers.AssignNewTable(state, 6, 0);

  if ((eventData->mModifiers & MEM_Shift) != 0u) {
    modifiers.SetBoolean("Shift", true);
  }
  if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
    modifiers.SetBoolean("Ctrl", true);
  }
  if ((eventData->mModifiers & MEM_Alt) != 0u) {
    modifiers.SetBoolean("Alt", true);
  }
  if ((eventData->mModifiers & MEM_Left) != 0u) {
    modifiers.SetBoolean("Left", true);
  }
  if ((eventData->mModifiers & MEM_Middle) != 0u) {
    modifiers.SetBoolean("Middle", true);
  }
  if ((eventData->mModifiers & MEM_Right) != 0u) {
    modifiers.SetBoolean("Right", true);
  }

  new (outEvent) LuaPlus::LuaObject();
  outEvent->AssignNewTable(state, 0, 8u);

  gpg::RRef eventTypeRef{};
  eventTypeRef = gpg::MakeRRef<moho::EMauiEventType>(&eventData->mEventType);
  const auto eventTypeLexical = eventTypeRef.GetLexical();
  outEvent->SetString("Type", eventTypeLexical.c_str());

  outEvent->SetNumber("MouseX", eventData->mMousePos.x);
  outEvent->SetNumber("MouseY", eventData->mMousePos.y);
  outEvent->SetInteger("WheelRotation", eventData->mWheelRotation);
  outEvent->SetInteger("WheelDelta", eventData->mWheelData);
  outEvent->SetInteger("KeyCode", eventData->mKeyCode);
  outEvent->SetInteger("RawKeyCode", eventData->mRawKeyCode);
  outEvent->SetObject("Modifiers", modifiers);

  if (eventData->mSource != nullptr) {
    outEvent->SetObject("Control", eventData->mSource->mLuaObj);
  }

  return outEvent;
}

/**
 * Address: 0x008C65B0 (FUN_008C65B0, Moho::USER_GetLuaState)
 * Address: 0x00C08810 (FUN_00C08810, atexit destructor of USER_GetLuaState's static LuaState)
 * Address: 0x00C08800 (FUN_00C08800, atexit destructor of USER_GetLuaState's static CTaskStage)
 *
 * What it does:
 * Lazily initializes process-global user Lua state/runtime stage, installs
 * debug hook wiring when the script debug window is active, attaches one
 * `ScrDiskWatcherTask`, and runs core/user Lua init-form chains.
 */
LuaPlus::LuaState* moho::USER_GetLuaState()
{
  LuaPlus::LuaState* state = gUserLuaState;
  if (state != nullptr) {
    return state;
  }

  static LuaPlus::LuaState sLuaState(
    LuaPlus::LuaState::LIB_BASE,
    static_cast<int>(moho::lua_incremental::ELuaVmRole::FrontendUi)
  );
  static CTaskStage sStage;

  sUserStage = &sStage;
  gUserLuaState = &sLuaState;
  lua::NameLuaVm(gUserLuaState->m_state, "UI"); // diagnostics label only

  if (SCR_IsDebugWindowActive()) {
    lua_sethook(gUserLuaState->m_state, &DebugLuaHook, 4, 0);
  }

  gUserLuaState->m_taskStage = sUserStage;

  ScrDiskWatcherTask* const diskWatcherTask = new (std::nothrow) ScrDiskWatcherTask(gUserLuaState);
  AttachTaskToStage(diskWatcherTask, sUserStage, true);

  RunLuaInitFormSetIfPresent("Core", gUserLuaState);
  RunLuaInitFormSetIfPresent("User", gUserLuaState);

  // No script runs from here. The Lua bootstrap is /lua/userInit.lua, which
  // CScApp::AppInit runs (the binary does so at 0x008CF057), and userInit.lua
  // doscripts /lua/globalInit.lua itself at its line 19 - after setting
  // __language on line 8, which is the order the rest of the scripts expect.
  //
  // Driving globalInit.lua from here instead inverted that: it ran before
  // __language existed, so every script reaching for it hit config.lua's
  // raising __index on _G. The string "globalInit" does not appear anywhere in
  // the shipped image, which is the giveaway that the engine never loads it
  // directly.
  return gUserLuaState;
}

/**
 * Address: 0x0083CD30 (FUN_0083CD30, Moho::MAUI_StartMainScript)
 *
 * What it does:
 * Imports `/lua/ui/uimain.lua`, resolves `SetupUI`, and executes the entry
 * callback against the active UI Lua state.
 */
bool moho::MAUI_StartMainScript()
{
  LuaPlus::LuaState* const state = ResolveUiManagerLuaState();
  if (state == nullptr || state->m_state == nullptr) {
    return false;
  }

  return InvokeUiLuaCallback(state, "/lua/ui/uimain.lua", "SetupUI", [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  });
}

/**
 * Address: 0x0083D810 (FUN_0083D810, Moho::MAUI_ToggleConsole)
 *
 * What it does:
 * Imports `/lua/ui/uimain.lua`, resolves `ToggleConsole`, and executes the
 * callback against the active UI Lua state.
 */
void moho::MAUI_ToggleConsole()
{
  LuaPlus::LuaState* const state = ResolveUiManagerLuaState();
  if (state == nullptr || state->m_state == nullptr) {
    return;
  }

  (void)InvokeUiLuaCallback(
    state, "/lua/ui/uimain.lua", "ToggleConsole", [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  }
  );
}

/**
 * Address: 0x0083D670 (FUN_0083D670)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:NoteGameSpeedChanged(slotPlusOne, speed)` on
 * the active UI Lua state.
 */
void moho::UI_NoteGameSpeedChanged(
  const std::int32_t slotZeroBased,
  const std::int32_t gameSpeed
)
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "NoteGameSpeedChanged",
    [slotZeroBased, gameSpeed](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction(slotZeroBased + 1, gameSpeed);
  }
  );
}

/**
 * Address: 0x0083D740 (FUN_0083D740, ?UI_NoteGameOver@Moho@@YAXXZ)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:NoteGameOver()` on the active UI Lua state.
 */
void moho::UI_NoteGameOver()
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(), "/lua/ui/uimain.lua", "NoteGameOver", [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  }
  );
}

/**
 * Address: 0x0083D9C0 (FUN_0083D9C0)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:OnApplicationResize(frameIdx, width, height)`.
 */
void moho::MAUI_OnApplicationResize(
  const std::int32_t frameIdx,
  const std::int32_t width,
  const std::int32_t height
)
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "OnApplicationResize",
    [frameIdx, width, height](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction(frameIdx, width, height);
  }
  );
}

bool moho::UI_InitKeyHandler()
{
  return IN_InitKeyHandler();
}

/**
 * Address: 0x007A5190 (FUN_007A5190, cfunc_AnyInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_AnyInputCaptureL`.
 */
int moho::cfunc_AnyInputCapture(
  lua_State* const luaContext
)
{
  return cfunc_AnyInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A51B0 (FUN_007A51B0, func_AnyInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `AnyInputCapture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_AnyInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "AnyInputCapture", &moho::cfunc_AnyInputCapture, nullptr, "<global>", kAnyInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5210 (FUN_007A5210, cfunc_AnyInputCaptureL)
 *
 * What it does:
 * Returns whether the global input-capture stack currently has any valid
 * control.
 */
int moho::cfunc_AnyInputCaptureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 0, kAnyInputCaptureHelpText);

  const bool hasCapture = ResolveTopInputCaptureControl() != nullptr;
  lua_pushboolean(state->m_state, hasCapture);
  (void)lua_gettop(state->m_state);
  return 1;
}

void moho::UI_ClearInputCapture()
{
  while (!sInputCapture.empty()) {
    RemoveInputCaptureAt(sInputCapture.size() - 1u);
  }
}

moho::FactoryQueueDisplaySnapshot moho::sCurrentBuildQueue{};
moho::WeakPtr<moho::UserUnit> moho::sCurrentBuildFactory{};
namespace
{

  /**
   * Address: 0x00836E60 (FUN_00836E60, sub_836E60)
   *
   * IDA signature:
   * int __thiscall sub_836E60(gpg::fastvector_BuildQueueItem *this);
   *
   * What it does:
   * Element count of one 0x30-stride queue lane, short-circuiting to zero when
   * `_Myfirst` is null instead of dividing a null-based difference.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t FactoryQueueItemCount(
    const FactoryQueueItem* const begin,
    const FactoryQueueItem* const end
  ) noexcept
  {
    if (begin == nullptr) {
      return 0u;
    }
    return static_cast<std::uint32_t>(end - begin);
  }
}


void moho::CurrentBuildQueueItemCommands(
  const int oneBasedQueueIndex,
  const moho::CmdId** const outBegin,
  const moho::CmdId** const outEnd
) noexcept
{
  *outBegin = nullptr;
  *outEnd = nullptr;

  const FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();
  const std::ptrdiff_t itemCount = static_cast<std::ptrdiff_t>(currentLanes.size());
  const std::ptrdiff_t itemIndex = static_cast<std::ptrdiff_t>(oneBasedQueueIndex) - 1;
  if (itemIndex < 0 || itemIndex >= itemCount) {
    return;
  }

  const fa::vector<moho::CmdId>& commands = currentLanes[static_cast<std::size_t>(itemIndex)].commands;
  *outBegin = commands.begin();
  *outEnd = commands.end();
}

/**
 * Address: 0x0083DCC0 (FUN_0083DCC0, ?UI_LuaBeat@Moho@@YA_NXZ)
 *
 * What it does:
 * Invokes `/lua/ui/game/gamemain.lua:OnBeat()` and returns false when the Lua
 * callback throws.
 */
bool moho::UI_LuaBeat()
{
  return InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/game/gamemain.lua",
    "OnBeat",
    [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  }
  );
}

/**
 * Address: 0x0083EDF0 (FUN_0083EDF0, ?UI_StopCursorText@Moho@@YAXXZ)
 *
 * What it does:
 * Invokes `/lua/ui/uimain.lua:StopCursorText()` on the active UI Lua state.
 */
void moho::UI_StopCursorText()
{
  (void)InvokeUiLuaCallback(
    ResolveUiManagerLuaState(),
    "/lua/ui/uimain.lua",
    "StopCursorText",
    [](LuaPlus::LuaFunction<void>& callbackFunction) {
    callbackFunction();
  }
  );
}
namespace moho
{
  WeakSet<UserEntity> sSelectionBrackets;
}


/**
 * Address: 0x007FD9F0 (FUN_007FD9F0, func_PushBlinkyBox)
 *
 * What it does:
 * Allocates one blinky-box runtime node, links its weak unit owner lane, and
 * inserts it at the tail of the global blinky-box intrusive list.
 */
void moho::func_PushBlinkyBox(
  UserEntity* const entity,
  const float onTime,
  const float offTime,
  const float totalTime
)
{
  auto* const blinkyBox = new moho::BlinkyBox{};

  blinkyBox->mUnit.ResetFromObject(entity);
  blinkyBox->mCurDuration = 0.0f;
  blinkyBox->mCurCycleTime = 0.0f;
  blinkyBox->mOnTime = onTime;
  blinkyBox->mOffTime = offTime;
  blinkyBox->mIsOn = 0u;
  blinkyBox->mTotalTime = totalTime;

  blinkyBox->ListLinkBefore(&moho::sBlinkyBoxes);
}

/**
 * Address: 0x007FDA90 (FUN_007FDA90)
 *
 * What it does:
 * Adds one user-unit lane into the global selection-bracket weak-set and
 * returns the raw register lane value from WeakSet_UserEntity::Add.
 */
void moho::func_AddSelectionBracketUserUnit(
  UserUnit* const unit
)
{
  (void)sSelectionBrackets.Add(unit);
}

  fa::list<SCommandFeedbackBlip> sCommandFeedbackBlips;
namespace
{

  void DestroyCommandFeedbackBlipMeshInstance(
    moho::MeshInstance*& meshInstance
  ) noexcept
  {
    if (meshInstance == nullptr) {
      return;
    }

    delete meshInstance;
    meshInstance = nullptr;
  }
}


/**
 * Address: 0x008586C0 (FUN_008586C0, Moho::RemoveCommandFeedbackBlips)
 *
 * What it does:
 * Removes every command-feedback blip whose `mCurTime >= mDuration`.
 *
 * Notes:
 * The binary uses one unused stdcall argument lane (`push 0`).
 */
void moho::RemoveCommandFeedbackBlips(
  const std::int32_t unused
)
{
  (void)unused;

  for (fa::list<SCommandFeedbackBlip>::iterator it = sCommandFeedbackBlips.begin();
       it != sCommandFeedbackBlips.end();) {
    if (it->mCurTime < it->mDuration) {
      ++it;
      continue;
    }

    it = sCommandFeedbackBlips.erase(it);
  }
}

/**
 * Address: 0x00857B00 (FUN_00857B00, Moho::UpdateCommandFeedbackBlips)
 *
 * What it does:
 * Advances command-feedback blip timers, destroys expired meshes, then
 * compacts expired blip nodes from the global blip list.
 */
void moho::UI_UpdateCommandFeedbackBlips(
  const float deltaSeconds
)
{
  (void)moho::MeshRenderer::GetInstance();

  for (fa::list<SCommandFeedbackBlip>::iterator it = sCommandFeedbackBlips.begin();
       it != sCommandFeedbackBlips.end();
       ++it) {
    SCommandFeedbackBlip& blip = *it;
    const float updatedTime = blip.mCurTime + deltaSeconds;
    blip.mCurTime = updatedTime;
    if (updatedTime >= blip.mDuration) {
      DestroyCommandFeedbackBlipMeshInstance(blip.mMeshInstance);
    }
  }

  RemoveCommandFeedbackBlips(0);
}
void moho::UI_DumpCurrentInputCapture() {}

// Rows 0x00F5B150.
BEGIN_EVENT_TABLE(moho::CUIKeyHandler, wxEvtHandler)
  EVT_KEY_UP(moho::CUIKeyHandler::OnKeyUp)
  EVT_KEY_DOWN(moho::CUIKeyHandler::OnKeyDown)
END_EVENT_TABLE()

namespace moho
{
  fa::string in_keyNames[256]{};
} // namespace moho

/**
 * Address: 0x008365B0 (FUN_008365B0, cfunc_ClearCurrentFactoryForQueueDisplay)
 *
 * What it does:
 * Unwraps raw Lua callback state and forwards to
 * `cfunc_ClearCurrentFactoryForQueueDisplayL`.
 */
int moho::cfunc_ClearCurrentFactoryForQueueDisplay(
  lua_State* const luaContext
)
{
  return cfunc_ClearCurrentFactoryForQueueDisplayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x008365D0 (FUN_008365D0, func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `ClearCurrentFactoryForQueueDisplay()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearCurrentFactoryForQueueDisplay",
    &moho::cfunc_ClearCurrentFactoryForQueueDisplay,
    nullptr,
    "<global>",
    kClearCurrentFactoryForQueueDisplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00836630 (FUN_00836630, cfunc_ClearCurrentFactoryForQueueDisplayL)
 *
 * What it does:
 * Validates zero-arg Lua call shape, unlinks current factory-owner lane from
 * its intrusive owner chain, clears current-factory pointers, and compacts the
 * current build-queue range.
 */
int moho::cfunc_ClearCurrentFactoryForQueueDisplayL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 0, kClearCurrentFactoryForQueueDisplayHelpText);

  // 0x00836495..0x008364CB walks the factory's weak-link chain to the slot that
  // still names this node, splices the node's successor into it, and clears both
  // node lanes.
  sCurrentBuildFactory.UnlinkFromOwnerChain();

  FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();
  FactoryQueueDisplayItem* rebasedBegin = nullptr;
  (void)RebaseFactoryQueueRangeAndTrimTail(&rebasedBegin, currentLanes.begin(), currentLanes.end());
  return 0;
}

/**
 * Address: 0x00BE4690 (FUN_00BE4690, register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  return func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef();
}

/**
 * Address: 0x00BE4950 (FUN_00BE4950, register_IN_AddKeyMapTable_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_AddKeyMapTable_LuaFuncDef()
{
  return func_IN_AddKeyMapTable_LuaFuncDef();
}

/**
 * Address: 0x00BE4960 (FUN_00BE4960, register_IN_RemoveKeyMapTable_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_RemoveKeyMapTable_LuaFuncDef()
{
  return func_IN_RemoveKeyMapTable_LuaFuncDef();
}

/**
 * Address: 0x00BE4970 (FUN_00BE4970, register_IN_ClearKeyMap_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_IN_ClearKeyMap_LuaFuncDef()
{
  return func_IN_ClearKeyMap_LuaFuncDef();
}

const moho::VMatrix4& moho::UI_IdentityMatrix()
{
  static const VMatrix4 kIdentity = VMatrix4::Identity();
  return kIdentity;
}
namespace
{
  /**
   * Address: 0x00858440 (FUN_00858440)
   *
   * What it does:
   * Returns the global command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] fa::list<SCommandFeedbackBlip>* GetCommandFeedbackBlipsLaneA(
    const int /*unused*/
  ) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x008585C0 (FUN_008585C0)
   *
   * What it does:
   * Secondary entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] fa::list<SCommandFeedbackBlip>* GetCommandFeedbackBlipsLaneB(
    const int /*unused*/
  ) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x00858670 (FUN_00858670)
   *
   * What it does:
   * Third entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] fa::list<SCommandFeedbackBlip>* GetCommandFeedbackBlipsLaneC(
    const int /*unused*/
  ) noexcept
  {
    return &sCommandFeedbackBlips;
  }

  /**
   * Address: 0x008587A0 (FUN_008587A0)
   *
   * What it does:
   * Fourth entrypoint returning the command-feedback blip-list lane.
   */
  [[maybe_unused]] [[nodiscard]] fa::list<SCommandFeedbackBlip>* GetCommandFeedbackBlipsLaneD() noexcept
  {
    return &sCommandFeedbackBlips;
  }
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct UiLuaBinderStartup
  {
    UiLuaBinderStartup()
    {
      (void)::moho::register_FlushEvents_LuaFuncDef();
      (void)::moho::register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef();
      (void)::moho::register_IN_AddKeyMapTable_LuaFuncDef();
      (void)::moho::register_IN_RemoveKeyMapTable_LuaFuncDef();
      (void)::moho::register_IN_ClearKeyMap_LuaFuncDef();
    }
  };

  const UiLuaBinderStartup gUiLuaBinderStartup{};
  /**
   * The Maui class binders.
   *
   * Every `moho.<x>_methods` table Lua reaches its UI classes through is a
   * `CScrLuaClassBinder` - a form whose name is a dotted path, so
   * `CScrLuaClassBinder::Run` walks it, creating `moho` under globals on the
   * first one and setting the tail segment to the class's metatable. Without
   * these there is no `moho` table at all, and `/lua/maui/control.lua` fails
   * on its first line: `Control = ClassUI(moho.control_methods)`.
   *
   * In the binary each is a statically-initialized record in `.data` linked
   * into `scr_UserInits` by a four-instruction thunk; the addresses below are
   * those records. Names and class strings are read from the image, and the
   * doc string is empty in every one of them.
   */
  /**
   * Address: 0x00BDD9F0 (FUN_00BDD9F0) -- record at 0x00F5A1F0
   *
   * Publishes CMauiBitmap's method table as `moho.bitmap_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiBitmap()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.bitmap_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
      "CMauiBitmap",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDDC40 (FUN_00BDDC40) -- record at 0x00F5A224
   *
   * Publishes CMauiBorder's method table as `moho.border_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiBorder()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.border_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
      "CMauiBorder",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDDD80 (FUN_00BDDD80) -- record at 0x00F5A258
   *
   * Publishes CMauiControl's method table as `moho.control_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiControl()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.control_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiControl",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE010 (FUN_00BDE010) -- record at 0x00F5A280
   *
   * Publishes CMauiCursor's method table as `moho.cursor_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiCursor()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.cursor_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiCursor>::Instance(),
      "CMauiCursor",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE150 (FUN_00BDE150) -- record at 0x00F5A298
   *
   * Publishes CMauiLuaDragger's method table as `moho.dragger_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiLuaDragger()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.dragger_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiLuaDragger>::Instance(),
      "CMauiLuaDragger",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE250 (FUN_00BDE250) -- record at 0x00F5A2B0
   *
   * Publishes CMauiEdit's method table as `moho.edit_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiEdit()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.edit_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
      "CMauiEdit",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE5D0 (FUN_00BDE5D0) -- record at 0x00F5A2E4
   *
   * Publishes CMauiFrame's method table as `moho.frame_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiFrame()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.frame_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
      "CMauiFrame",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE700 (FUN_00BDE700) -- record at 0x00F5A318
   *
   * Publishes CMauiGroup's method table as `moho.group_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiGroup()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.group_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiGroup>::Instance(),
      "CMauiGroup",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE800 (FUN_00BDE800) -- record at 0x00F5A34C
   *
   * Publishes CMauiHistogram's method table as `moho.histogram_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiHistogram()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.histogram_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
      "CMauiHistogram",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDE930 (FUN_00BDE930) -- record at 0x00F5A380
   *
   * Publishes CMauiItemList's method table as `moho.item_list_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiItemList()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.item_list_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
      "CMauiItemList",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDEC30 (FUN_00BDEC30) -- record at 0x00F5A3B4
   *
   * Publishes CMauiMesh's method table as `moho.mesh_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiMesh()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.mesh_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
      "CMauiMesh",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDED50 (FUN_00BDED50) -- record at 0x00F5A3E8
   *
   * Publishes CMauiMovie's method table as `moho.movie_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiMovie()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.movie_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
      "CMauiMovie",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDEEC0 (FUN_00BDEEC0) -- record at 0x00F5A41C
   *
   * Publishes CMauiScrollbar's method table as `moho.scrollbar_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiScrollbar()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.scrollbar_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
      "CMauiScrollbar",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDF000 (FUN_00BDF000) -- record at 0x00F5A450
   *
   * Publishes CMauiText's method table as `moho.text_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCMauiText()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.text_methods",
      &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
      "CMauiText",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BE4F60 (FUN_00BE4F60) -- record at 0x00F5B1CC
   *
   * Publishes CUIMapPreview's method table as `moho.ui_map_preview_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCUIMapPreview()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.ui_map_preview_methods",
      &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
      "CUIMapPreview",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BE63F0 (FUN_00BE63F0) -- record at 0x00F5B558
   *
   * Publishes CLuaWldUIProvider's method table as `moho.WldUIProvider_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCLuaWldUIProvider()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.WldUIProvider_methods",
      &moho::CScrLuaMetatableFactory<moho::CLuaWldUIProvider>::Instance(),
      "CLuaWldUIProvider",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BE64E0 (FUN_00BE64E0) -- record at 0x00F5B570
   *
   * Publishes CUIWorldMesh's method table as `moho.world_mesh_methods`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCUIWorldMesh()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.world_mesh_methods",
      &moho::CScrLuaMetatableFactory<moho::CUIWorldMesh>::Instance(),
      "CUIWorldMesh",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BE6A50 (FUN_00BE6A50) -- record at 0x00F5B674
   *
   * Publishes CUIWorldView's method table as `moho.UIWorldView`.
   */
  moho::CScrLuaInitForm* RegisterLuaClassCUIWorldView()
  {
    static moho::CScrLuaClassBinder binder(
      moho::SCR_UserLuaInitSet(),
      "moho.UIWorldView",
      &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
      "CUIWorldView",
      ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDDA10 (FUN_00BDDA10) -- record at 0x00F5A208
   *
   * Declares CMauiBitmap as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiBitmap()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiBitmap>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiBitmap",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDDC60 (FUN_00BDDC60) -- record at 0x00F5A23C
   *
   * Declares CMauiBorder as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiBorder()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiBorder>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiBorder",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDE270 (FUN_00BDE270) -- record at 0x00F5A2C8
   *
   * Declares CMauiEdit as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiEdit()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiEdit",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDE5F0 (FUN_00BDE5F0) -- record at 0x00F5A2FC
   *
   * Declares CMauiFrame as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiFrame()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiFrame",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDE720 (FUN_00BDE720) -- record at 0x00F5A330
   *
   * Declares CMauiGroup as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiGroup()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiGroup>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiGroup",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDE820 (FUN_00BDE820) -- record at 0x00F5A364
   *
   * Declares CMauiHistogram as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiHistogram()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiHistogram>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiHistogram",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDE950 (FUN_00BDE950) -- record at 0x00F5A398
   *
   * Declares CMauiItemList as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiItemList()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiItemList>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiItemList",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDEC50 (FUN_00BDEC50) -- record at 0x00F5A3CC
   *
   * Declares CMauiMesh as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiMesh()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiMesh>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiMesh",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDED70 (FUN_00BDED70) -- record at 0x00F5A400
   *
   * Declares CMauiMovie as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiMovie()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiMovie",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDEEE0 (FUN_00BDEEE0) -- record at 0x00F5A434
   *
   * Declares CMauiScrollbar as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiScrollbar()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiScrollbar",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BDF020 (FUN_00BDF020) -- record at 0x00F5A468
   *
   * Declares CMauiText as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCMauiText()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CMauiText>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CMauiText",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BE4F80 (FUN_00BE4F80) -- record at 0x00F5B1E4
   *
   * Declares CUIMapPreview as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCUIMapPreview()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CUIMapPreview>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CUIMapPreview",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Address: 0x00BE6A70 (FUN_00BE6A70) -- record at 0x00F5B68C
   *
   * Declares CUIWorldView as deriving from CMauiControl for the Lua class
   * system, so `class.lua`'s `Flatten` reaches the control methods when it
   * converts the C class.
   */
  moho::CScrLuaInitForm* RegisterLuaBaseClassCUIWorldView()
  {
    static moho::CScrLuaBaseClassSpec spec(
      moho::SCR_UserLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::CUIWorldView>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
      "CUIWorldView",
      "derived from CMauiControl"
    );
    return &spec;
  }

  /**
   * Drives the class binders above. In the binary the CRT static-init array
   * runs each record's linking thunk before main; this object is that pass,
   * and the source-level invocation that keeps them linked in.
   */
  struct MauiLuaClassBinderBootstrap
  {
    MauiLuaClassBinderBootstrap()
    {
      (void)RegisterLuaClassCMauiBitmap();
      (void)RegisterLuaClassCMauiBorder();
      (void)RegisterLuaClassCMauiControl();
      (void)RegisterLuaClassCMauiCursor();
      (void)RegisterLuaClassCMauiLuaDragger();
      (void)RegisterLuaClassCMauiEdit();
      (void)RegisterLuaClassCMauiFrame();
      (void)RegisterLuaClassCMauiGroup();
      (void)RegisterLuaClassCMauiHistogram();
      (void)RegisterLuaClassCMauiItemList();
      (void)RegisterLuaClassCMauiMesh();
      (void)RegisterLuaClassCMauiMovie();
      (void)RegisterLuaClassCMauiScrollbar();
      (void)RegisterLuaClassCMauiText();
      (void)RegisterLuaClassCUIMapPreview();
      (void)RegisterLuaClassCLuaWldUIProvider();
      (void)RegisterLuaClassCUIWorldMesh();
      (void)RegisterLuaClassCUIWorldView();

      // The base-class specs: each appends the control method table into
      // its derived class table's array part.
      (void)RegisterLuaBaseClassCMauiBitmap();
      (void)RegisterLuaBaseClassCMauiBorder();
      (void)RegisterLuaBaseClassCMauiEdit();
      (void)RegisterLuaBaseClassCMauiFrame();
      (void)RegisterLuaBaseClassCMauiGroup();
      (void)RegisterLuaBaseClassCMauiHistogram();
      (void)RegisterLuaBaseClassCMauiItemList();
      (void)RegisterLuaBaseClassCMauiMesh();
      (void)RegisterLuaBaseClassCMauiMovie();
      (void)RegisterLuaBaseClassCMauiScrollbar();
      (void)RegisterLuaBaseClassCMauiText();
      (void)RegisterLuaBaseClassCUIMapPreview();
      (void)RegisterLuaBaseClassCUIWorldView();
    }
  };

  const MauiLuaClassBinderBootstrap gMauiLuaClassBinderBootstrap{};
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UiLuaFuncDefStartup
  {
    UiLuaFuncDefStartup()
    {
      (void)::moho::func__c_CreateCursor_LuaFuncDef();
      (void)::moho::func_CMauiCursorSetDefaultTexture_LuaFuncDef();
      (void)::moho::func_CMauiCursorSetNewTexture_LuaFuncDef();
      (void)::moho::func_CMauiCursorResetToDefault_LuaFuncDef();
      (void)::moho::func_CMauiCursorHide_LuaFuncDef();
      (void)::moho::func_CMauiCursorShow_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetNewTexture_LuaFuncDef();
      (void)::moho::func_CMauiBitmapInternalSetSolidColor_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetUV_LuaFuncDef();
      (void)::moho::func_CMauiBitmapUseAlphaHitTest_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetTiled_LuaFuncDef();
      (void)::moho::func_CMauiBitmapLoop_LuaFuncDef();
      (void)::moho::func_CMauiBitmapPlay_LuaFuncDef();
      (void)::moho::func_CMauiBitmapStop_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetFrame_LuaFuncDef();
      (void)::moho::func_CMauiBitmapGetFrame_LuaFuncDef();
      (void)::moho::func_CMauiBitMapGetNumFrames_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetFrameRate_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetForwardPattern_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetBackwardPattern_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetPingPongPattern_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetFramePattern_LuaFuncDef();
      (void)::moho::func_CMauiBitmapShareTextures_LuaFuncDef();
      (void)::moho::func_CMauiControlDestroy_LuaFuncDef();
      (void)::moho::func_CMauiControlGetParent_LuaFuncDef();
      (void)::moho::func_CMauiControlClearChildren_LuaFuncDef();
      (void)::moho::func_CMauiControlSetParent_LuaFuncDef();
      (void)::moho::func_CMauiControlDisableHitTest_LuaFuncDef();
      (void)::moho::func_CMauiControlEnableHitTest_LuaFuncDef();
      (void)::moho::func_CMauiControlIsHitTestDisabled_LuaFuncDef();
      (void)::moho::func_CMauiControlHide_LuaFuncDef();
      (void)::moho::func_CMauiControlShow_LuaFuncDef();
      (void)::moho::func_CMauiControlSetHidden_LuaFuncDef();
      (void)::moho::func_CMauiControlIsHidden_LuaFuncDef();
      (void)::moho::func_CMauiControlGetRenderPass_LuaFuncDef();
      (void)::moho::func_CMauiControlSetRenderPass_LuaFuncDef();
      // FAF community binary-patch addition, not part of the original 2007
      // registration sequence -- see cfunc_CUIWorldViewSetCustomRender.
      (void)::moho::func_CUIWorldViewSetCustomRender_LuaFuncDef();
      (void)::moho::func_CUIWorldViewProjectMultiple_LuaFuncDef();
      (void)::moho::func_CMauiBitmapSetColorMask_LuaFuncDef();
      (void)::moho::func_CMauiControlGetName_LuaFuncDef();
      (void)::moho::func_CMauiControlSetName_LuaFuncDef();
      (void)::moho::func_CMauiControlDump_LuaFuncDef();
      (void)::moho::func_CMauiControlGetCurrentFocusControl_LuaFuncDef();
      (void)::moho::func_CMauiControlAcquireKeyboardFocus_LuaFuncDef();
      (void)::moho::func_CMauiControlAbandonKeyboardFocus_LuaFuncDef();
      (void)::moho::func_CMauiControlNeedsFrameUpdate_LuaFuncDef();
      (void)::moho::func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef();
      (void)::moho::func_CMauiControlGetRootFrame_LuaFuncDef();
      (void)::moho::func_CMauiControlSetAlpha_LuaFuncDef();
      (void)::moho::func_CMauiControlGetAlpha_LuaFuncDef();
      (void)::moho::func_CMauiControlApplyFunction_LuaFuncDef();
      (void)::moho::func_CMauiControlHitTest_LuaFuncDef();
      (void)::moho::func_CMauiBorderSetNewTextures_LuaFuncDef();
      (void)::moho::func_CMauiBorderSetSolidColor_LuaFuncDef();
      (void)::moho::func_CMauiFrameGetTopmostDepth_LuaFuncDef();
      (void)::moho::func_CMauiFrameGetTargetHead_LuaFuncDef();
      (void)::moho::func_CMauiFrameSetTargetHead_LuaFuncDef();
      (void)::moho::func_PostDragger_LuaFuncDef();
      (void)::moho::func_CMauiLuaDraggerDestroy_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewFont_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewForegroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetForegroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewBackgroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetBackgroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditShowBackground_LuaFuncDef();
      (void)::moho::func_CMauiEditIsBackgroundVisible_LuaFuncDef();
      (void)::moho::func_CMauiEditClearText_LuaFuncDef();
      (void)::moho::func_CMauiEditSetText_LuaFuncDef();
      (void)::moho::func_CMauiEditGetText_LuaFuncDef();
      (void)::moho::func_CMauiEditSetCaretPosition_LuaFuncDef();
      (void)::moho::func_CMauiEditGetCaretPosition_LuaFuncDef();
      (void)::moho::func_CMauiEditShowCaret_LuaFuncDef();
      (void)::moho::func_CMauiEditIsCaretVisible_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewCaretColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetCaretColor_LuaFuncDef();
      (void)::moho::func_CMauiEditSetCaretCycle_LuaFuncDef();
      (void)::moho::func_CMauiEditSetMaxChars_LuaFuncDef();
      (void)::moho::func_CMauiEditGetMaxChars_LuaFuncDef();
      (void)::moho::func_CMauiEditIsEnabled_LuaFuncDef();
      (void)::moho::func_CMauiEditEnableInput_LuaFuncDef();
      (void)::moho::func_CMauiEditDisableInput_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetHighlightForegroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef();
      (void)::moho::func_CMauiEditGetFontHeight_LuaFuncDef();
      (void)::moho::func_CMauiEditAcquireFocus_LuaFuncDef();
      (void)::moho::func_CMauiEditAbandonFocus_LuaFuncDef();
      (void)::moho::func_CMauiEditSetDropShadow_LuaFuncDef();
      (void)::moho::func_CMauiEditGetStringAdvance_LuaFuncDef();
      (void)::moho::func_CMauiHistogramSetXIncrement_LuaFuncDef();
      (void)::moho::func_CMauiHistogramSetYIncrement_LuaFuncDef();
      (void)::moho::func_CMauiHistogramSetData_LuaFuncDef();
      (void)::moho::func_InternalCreateBitmap_LuaFuncDef();
      (void)::moho::func_InternalCreateFrame_LuaFuncDef();
      (void)::moho::func_InternalCreateDragger_LuaFuncDef();
      (void)::moho::func_InternalCreateBorder_LuaFuncDef();
      (void)::moho::func_InternalCreateEdit_LuaFuncDef();
      (void)::moho::func_InternalCreateGroup_LuaFuncDef();
      (void)::moho::func_InternalCreateHistogram_LuaFuncDef();
      (void)::moho::func_InternalCreateMesh_LuaFuncDef();
      (void)::moho::func_InternalCreateMovie_LuaFuncDef();
      (void)::moho::func_InternalCreateScrollbar_LuaFuncDef();
      (void)::moho::func_InternalCreateText_LuaFuncDef();
      (void)::moho::func_InternalCreateItemList_LuaFuncDef();
      (void)::moho::func_CMauiItemListSetNewFont_LuaFuncDef();
      (void)::moho::func_CMauiItemListSetNewColors_LuaFuncDef();
      (void)::moho::func_CMauiItemListSetSelection_LuaFuncDef();
      (void)::moho::func_CMauiItemListGetItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListGetItemCount_LuaFuncDef();
      (void)::moho::func_CMauiItemListEmpty_LuaFuncDef();
      (void)::moho::func_CMauiItemListScrollToTop_LuaFuncDef();
      (void)::moho::func_CMauiListItemScrollToBottom_LuaFuncDef();
      (void)::moho::func_CMauiItemListShowItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListGetRowHeight_LuaFuncDef();
      (void)::moho::func_CMauiItemListShowMouseoverItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListShowSelection_LuaFuncDef();
      (void)::moho::func_CMauiItemListNeedsScrollBar_LuaFuncDef();
      (void)::moho::func_CMauiItemListAddItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListModifyItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListDeleteItem_LuaFuncDef();
      (void)::moho::func_CMauiItemListDeleteAllItems_LuaFuncDef();
      (void)::moho::func_CMauiItemListGetSelection_LuaFuncDef();
      (void)::moho::func_CMauiItemListGetStringAdvance_LuaFuncDef();
      (void)::moho::func_CMauiMeshSetMesh_LuaFuncDef();
      (void)::moho::func_CMauiMeshSetOrientation_LuaFuncDef();
      (void)::moho::func_CMauiMovieInternalSet_LuaFuncDef();
      (void)::moho::func_CMauiMovieLoop_LuaFuncDef();
      (void)::moho::func_CMauiMoviePlay_LuaFuncDef();
      (void)::moho::func_CMauiMovieStop_LuaFuncDef();
      (void)::moho::func_CMauiMovieIsLoaded_LuaFuncDef();
      (void)::moho::func_CMauiMovieGetNumFrames_LuaFuncDef();
      (void)::moho::func_CMauiMovieGetFrameRate_LuaFuncDef();
      (void)::moho::func_CMauiScrollbarSetScrollable_LuaFuncDef();
      (void)::moho::func_CMauiScrollbarSetNewTextures_LuaFuncDef();
      (void)::moho::func_CMauiScrollbarDoScrollLines_LuaFuncDef();
      (void)::moho::func_CMauiScrollbarDoScrollPages_LuaFuncDef();
      (void)::moho::func_CMauiTextSetNewFont_LuaFuncDef();
      (void)::moho::func_CMauiTextSetText_LuaFuncDef();
      (void)::moho::func_CMauiTextGetText_LuaFuncDef();
      (void)::moho::func_CMauiTextSetNewColor_LuaFuncDef();
      (void)::moho::func_CMauiTextSetDropShadow_LuaFuncDef();
      (void)::moho::func_CMauiTextSetCenteredHorizontally_LuaFuncDef();
      (void)::moho::func_CMauiTextSetCenteredVertically_LuaFuncDef();
      (void)::moho::func_CMauiTextGetStringAdvance_LuaFuncDef();
      (void)::moho::func_CMauiTextSetNewClipToWidth_LuaFuncDef();
      (void)::moho::func_CMauiTextSetTextScale_LuaFuncDef();
      (void)::moho::func_CMauiTextGetTextScale_LuaFuncDef();
      (void)::moho::func_LoadFont_LuaFuncDef();
      (void)::moho::func_SetFrontEndData_LuaFuncDef();
      (void)::moho::func_GetFrontEndData_LuaFuncDef();
      (void)::moho::func_GetCursor_LuaFuncDef();
      (void)::moho::func_SetUIControlsAlpha_LuaFuncDef();
      (void)::moho::func_GetUIControlsAlpha_LuaFuncDef();
      (void)::moho::func_InternalCreateMapPreview_LuaFuncDef();
      (void)::moho::func_CUIMapPreviewSetTexture_LuaFuncDef();
      (void)::moho::func_CUIMapPreviewSetTextureFromMap_LuaFuncDef();
      (void)::moho::func_CUIMapPreviewClearTexture_LuaFuncDef();
      (void)::moho::func_CUIWorldViewSetCartographic_LuaFuncDef();
      (void)::moho::func_CUIWorldViewIsCartographic_LuaFuncDef();
      (void)::moho::func_CUIWorldViewEnableResourceRendering_LuaFuncDef();
      (void)::moho::func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef();
      (void)::moho::func_CUIWorldViewZoomScale_LuaFuncDef();
      (void)::moho::func_UnProject_LuaFuncDef();
      (void)::moho::func_CUIWorldViewProject_LuaFuncDef();
      (void)::moho::func_CUIWorldView__init_LuaFuncDef();
      (void)::moho::func_CUIWorldViewCameraReset_LuaFuncDef();
      (void)::moho::func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef();
      (void)::moho::func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef();
      (void)::moho::func_CUIWorldViewHasHighlightCommand_LuaFuncDef();
      (void)::moho::func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef();
      (void)::moho::func_CUIWorldViewUnlockInput_LuaFuncDef();
      (void)::moho::func_CUIWorldViewLockInput_LuaFuncDef();
      (void)::moho::func_CUIWorldViewIsInputLocked_LuaFuncDef();
      (void)::moho::func_CUIWorldViewSetHighlightEnabled_LuaFuncDef();
      (void)::moho::func_InternalCreateWldUIProvider_LuaFuncDef();
      (void)::moho::func_InternalCreateWorldMesh_LuaFuncDef();
      (void)::moho::func_CLuaWldUIProviderDestroy_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshDestroy_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetMesh_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetStance_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetHidden_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshIsHidden_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetColor_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshSetScale_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef();
      (void)::moho::func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef();
      (void)::moho::func_CUIWorldViewGetScreenPos_LuaFuncDef();
      (void)::moho::func_IsKeyDown_LuaFuncDef();
      (void)::moho::func_KeycodeMauiToMSW_LuaFuncDef();
      (void)::moho::func_KeycodeMSWToMaui_LuaFuncDef();
      (void)::moho::func_AnyInputCapture_LuaFuncDef();
      (void)::moho::func_GetInputCapture_LuaFuncDef();
      (void)::moho::func_AddInputCapture_LuaFuncDef();
      (void)::moho::func_RemoveInputCapture_LuaFuncDef();
      (void)::moho::func_AddBlinkyBox_LuaFuncDef();
      (void)::moho::func_AddCommandFeedbackBlip_LuaFuncDef();
    }
  };

  const UiLuaFuncDefStartup gUiLuaFuncDefStartup{};
}

namespace moho
{
namespace
{
    // 0x00E4F6E4: the "no water plane" sentinel elevation the skirt lift falls
    // back to when the map has water disabled - low enough that the max() below
    // always picks the terrain instead.
    constexpr float kNoWaterElevation = -10000.0f;

    // 0x00E4F714: the terrain clearance a skirt outline is lifted by so it does
    // not z-fight the ground it is drawn on.
    constexpr float kSkirtTerrainClearance = 0.1f;

    // 0x00E4F84C: the outline's world thickness at unit view depth; divided by
    // the point's post-projection W to keep the on-screen width constant.
    constexpr float kSkirtThicknessAtUnitDepth = 0.15000001f;
}


  /**
   * Address: 0x0085ABD0 (FUN_0085ABD0, Moho::DrawUnitSkirt)
   * Mangled:
   * ?DrawUnitSkirt@Moho@@YAXPBVCHeightField@1@PBVRUnitBlueprint@1@ABVGeomCamera3@1@ABV?$Vector3@M@Wm3@@PAVCWldSession@1@PAVCD3DPrimBatcher@1@I@Z
   *
   * IDA signature:
   * _WORD *__usercall Moho::DrawUnitSkirt@<eax>(
   *   CHeightField *a1@<eax>, RUnitBlueprint *a2@<edx>, GeomCamera3 *a3@<ebx>,
   *   Wm3::Vector3f *a4@<esi>, CWldSession *a5, CD3DPrimBatcher *a6, int col);
   *
   * What it does:
   * Draws one unit footprint skirt outline at `position`. The rectangle comes
   * from the blueprint's skirt extent; its height is lifted to whichever is
   * greatest of the caller's Y, the sampled terrain elevation plus a small
   * clearance, and the map's water plane. The outline thickness is scaled by
   * the point's post-projection depth so it keeps a constant on-screen width,
   * but never drops below `ui_FootprintMinThickness`.
   */
  void DrawUnitSkirt(
    const CHeightField* const heightField,
    const RUnitBlueprint* const blueprint,
    const GeomCamera3& camera,
    const Wm3::Vector3f& position,
    CWldSession* const session,
    CD3DPrimBatcher* const batcher,
    const std::uint32_t color
  )
  {
    const SCoordsVec2 groundPosition{position.x, position.z};
    const gpg::Rect2f skirt = blueprint->GetSkirtRect(groundPosition);

    const STIMap* const map = session->GetSTIMap();
    // Engine addition (water bodies): the level of the water under the skirt.
    const float waterElevation =
      map->HasWaterBodies() ? map->GetWaterElevationAt(position.x, position.z)
                            : (map->mWaterEnabled != 0 ? map->mWaterElevation : kNoWaterElevation);

    float skirtY = position.y;
    if (heightField != nullptr) {
      const float terrainY = heightField->GetElevation(position.x, position.z) + kSkirtTerrainClearance;
      skirtY = position.y > terrainY ? position.y : terrainY;
      if (waterElevation > skirtY) {
        skirtY = waterElevation;
      }
    }

    // Row 2 of the camera's viewport matrix dotted with the anchor point is the
    // post-projection W the binary divides the constant thickness by.
    const Vector4f& depthRow = camera.viewport.r[2];
    const float viewDepth = depthRow.x * position.x + depthRow.y * skirtY + depthRow.z * position.z + depthRow.w;

    float thicknessScale = kSkirtThicknessAtUnitDepth / viewDepth;
    if (ui_FootprintMinThickness > thicknessScale) {
      thicknessScale = ui_FootprintMinThickness;
    }

    const Wm3::Vector3f topLeft{skirt.x0, skirtY, skirt.z0};
    const Wm3::Vector3f widthAxis{skirt.x1 - skirt.x0, 0.0f, 0.0f};
    const Wm3::Vector3f depthAxis{0.0f, 0.0f, skirt.z1 - skirt.z0};

    DRAW_Rect(batcher, viewDepth * thicknessScale, depthAxis, widthAxis, topLeft, color, heightField, waterElevation);
  }

  /**
   * Address: 0x0085AD80 (FUN_0085AD80, Moho::DrawAllUnitSkirts)
   *
   * IDA signature:
   * void __thiscall Moho::DrawAllUnitSkirts(
   *   CD3DPrimBatcher *ka, CWldSession *a1, GeomCamera3 *j);
   *
   * What it does:
   * Draws a translucent magenta footprint skirt for every mobile-build order
   * still queued in the session's command manager, so a shift-queued build
   * chain shows where each structure will land. Each order's anchor comes from
   * its own issue-event history, and its blueprint from the order's constant
   * data - upcast through reflection because the order carries the generic
   * entity blueprint, not the unit one.
   */
  void DrawAllUnitSkirts(
    CD3DPrimBatcher* const batcher,
    CWldSession* const session,
    const GeomCamera3& camera
  )
  {
    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

    // Clear the composite-rebuild flag so the pass reuses the view/projection
    // set immediately below rather than rebuilding it per primitive.
    batcher->mRebuildComposite = 0;
    batcher->SetViewProjMatrix(camera);
    batcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

    // Translucent magenta - the "planned build" tint (0xAARRGGBB).
    constexpr std::uint32_t kPlannedBuildSkirtColor = 0xC00080FFu;

    for (const auto& [commandId, helper] : session->mCommandManager->mCommands) {
      static_cast<void>(commandId);
      if (helper == nullptr) {
        continue;
      }

      if (ResolveCommandIssueHelperCommandType(*helper) != EUnitCommandType::UNITCOMMAND_BuildMobile) {
        continue;
      }

      gpg::RRef blueprintRef{};
      blueprintRef = gpg::MakeRRef<moho::REntityBlueprint>(helper->mConstantData.blueprint);

      const Wm3::Vector3f position = ResolveCommandIssueHelperAnchorPosition(*helper);

      const gpg::RRef unitBlueprintRef = gpg::REF_UpcastPtr(blueprintRef, RUnitBlueprint::StaticGetClass());
      DrawUnitSkirt(
        nullptr,
        static_cast<const RUnitBlueprint*>(unitBlueprintRef.mObj),
        camera,
        position,
        session,
        batcher,
        kPlannedBuildSkirtColor
      );
    }

    batcher->Flush();
  }
}

/**
 * Address: 0x0086A350 (FUN_0086A350, ??0IWldUIProvider@Moho@@QAE@XZ)
 * Address: 0x0086A5C0 (FUN_0086A5C0, IWldUIProvider ctor lane)
 *
 * What it does:
 * Initializes one world-UI-provider base interface object.
 */
moho::IWldUIProvider::IWldUIProvider() = default;

/**
 * Address: 0x0078DEF0 (FUN_0078DEF0, Moho::CMauiLuaDragger::~CMauiLuaDragger)
 *
 * What it does:
 * Nothing of its own. The whole body the binary shows is the inlined base
 * teardown: `lea ecx, [esi+34h]` (0x0078DEF6) re-bases to the `IMauiDragger`
 * sub-object, 0x0078DEFD restores `??_7IMauiDragger@Moho@@6B@`, the loop at
 * 0x0078DF10 drains that base's `WeakObject` chain, and 0x0078DF24 tail-calls
 * `~CScriptObject` (0x004C7340). All four steps are compiler-emitted base
 * destruction here, so this body stays empty; it is kept out-of-line so the
 * address annotation has a definition to sit on.
 */
moho::CMauiLuaDragger::~CMauiLuaDragger() = default;

/**
 * Address: 0x0078CBF0 (FUN_0078CBF0, Moho::CMauiCursor::~CMauiCursor body)
 *
 * What it does:
 * Nothing of its own: the body is empty. The compiler releases
 * `mDefaultTexture`, then `mTexture` (reverse declaration order, EH states
 * 1 and 0 at 0x0078CC0B / 0x0078CC44), then runs ~CScriptObject.
 */
moho::CMauiCursor::~CMauiCursor() = default;

/**
 * Address: 0x0078DB20 (??1IMauiDragger@Moho@@UAE@XZ)
 * Mangled: ??1IMauiDragger@Moho@@UAE@XZ
 *
 * IDA signature:
 * void __thiscall Moho::IMauiDragger::~IMauiDragger(Moho::IMauiDragger *this@<ecx>);
 *
 * What it does:
 * Drops every weak reference still aimed at this dragger. The shipped body is
 * the vptr restore (`mov [ecx], offset ??_7IMauiDragger@Moho@@6B@`, emitted by
 * the compiler here) followed by the drain loop over the inherited
 * `WeakObject` head at `[ecx+4]`:
 *   0x0078DB30  mov  esi, [eax+4]   ; next = node->nextInOwner
 *   0x0078DB33  mov  [ecx+4], esi   ; head = next
 *   0x0078DB36  mov  [eax], edx     ; node->ownerLinkSlot = nullptr
 *   0x0078DB38  mov  [eax+4], edx   ; node->nextInOwner   = nullptr
 * which is the `WeakObject` base's destructor. Every derived dragger
 * destructor in the image inlines this same block rather than calling it.
 */
moho::IMauiDragger::~IMauiDragger() = default;

/**
 * Address: 0x008240C0 (FUN_008240C0, non-deleting destructor)
 * Deleting dtor: 0x008240A0 (slot +0x00 of ??_7UICommandDragger@Moho@@6B@)
 *
 * What it does:
 * Member and base teardown only: `mGraph`'s destructor releases the reference
 * `CWldSession::GetCommandGraph(true)` handed the constructor (0x008240E9
 * `mov edi, [esi+18h]`, 0x008240F6 `lock xadd [edi+4], -1`, then `dispose()`
 * and `destroy()` through control-block slots +4/+8), then `IMauiDragger`
 * restores its vtable and drains the inherited `WeakObject` chain.
 */
moho::UICommandDragger::~UICommandDragger() = default;

/**
 * Address: 0x00784B40 (FUN_00784B40, Moho::CMauiBorder::~CMauiBorder)
 *
 * What it does:
 * Nothing of its own: the compiler destroys the two lazy vars and the six
 * texture handles in reverse declaration order, then runs `~CMauiControl`.
 */
moho::CMauiBorder::~CMauiBorder() = default;

/**
 * Address: 0x00797840 (FUN_00797840, Moho::CMauiHistogram::~CMauiHistogram)
 *
 * IDA signature:
 * _DWORD* __usercall ~CMauiHistogram@<eax>(CMauiHistogram* this@<esi>);
 *
 * What it does:
 * Nothing of its own: the body is `mColumns`' destructor - each column
 * destroyed (0x0079785C, `destroy_range` 0x00798D10), the array freed and
 * first/last/end zeroed - then a tail jump into `~CMauiControl` (0x00797893).
 */
moho::CMauiHistogram::~CMauiHistogram() = default;

/**
 * Address: 0x0086A5D0 (??1CLuaWldUIProvider@Moho@@QAE@@Z, Moho::CLuaWldUIProvider::~CLuaWldUIProvider)
 * Mangled: ??1CLuaWldUIProvider@Moho@@QAE@@Z
 * Deleting destructor thunk: 0x0086A5A0 (Moho::CLuaWldUIProvider::dtr)
 *
 * IDA signature:
 * void __thiscall Moho::CLuaWldUIProvider::~CLuaWldUIProvider(Moho::CLuaWldUIProvider *a1);
 *
 * What it does:
 * Tears down the provider in reverse construction order. The member
 * `mPrefetchData` (an `fa::vector<boost::shared_ptr<PrefetchData>>`) is
 * destroyed first — its inlined destructor releases each cached shared handle
 * (refcount drop + weak-dispose through the boost detail vtable) and frees the
 * element buffer, matching `sub_4A89A0` + `operator delete` in the binary.
 * The `CScriptObject` base destructor and the trailing `IWldUIProvider`
 * vtable restore are then emitted automatically by the C++ front-end from the
 * multiple-inheritance dtor sequence. The body is therefore intentionally
 * empty: writing an explicit `mPrefetchData` teardown here would double-free,
 * because the compiler already emits the member destructor after this body.
 */
moho::CLuaWldUIProvider::~CLuaWldUIProvider() = default;

/**
 * Address: 0x00836040 (FUN_00836040, sub_836040)
 * Address: 0x00837D20 (FUN_00837D20, sub_837D20)
 *
 * What it does:
 * Releases the command-id vector buffer and clears its triple, then releases the
 * blueprint-id string buffer when it is heap-backed (`myRes >= 0x10`) and
 * restores empty SSO state. Both emissions are byte-identical; the legacy
 * container destructors this defaults to perform exactly those two steps in the
 * same order (`commands` at +0x20 first, `blueprintId` at +0x00 second).
 */
moho::FactoryQueueDisplayItem::~FactoryQueueDisplayItem() noexcept = default;

/**
 * Address: 0x00838C60 (FUN_00838C60, sub_838C60)
 *
 * What it does:
 * Nothing of its own; `wxEvtHandler::~wxEvtHandler` follows.
 */
moho::CUIKeyHandler::~CUIKeyHandler() = default;

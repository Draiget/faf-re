#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/command/CmdDefs.h"
#include "moho/misc/WeakObject.h"
#include "moho/misc/WeakPtr.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/sim/CWldSession.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/script/CScriptObject.h"
#include "Wm3Quaternion.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace gpg
{
  class RType;
  class RRef;
  template <class T>
  class MemBuffer;
} // namespace gpg

#ifndef FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_ENFORCE_STRICT_LAYOUT_ASSERTS 0
#endif

#ifndef FAF_RUNTIME_LAYOUT_ASSERT
#if FAF_ENFORCE_STRICT_LAYOUT_ASSERTS
#define FAF_RUNTIME_LAYOUT_ASSERT(...) static_assert(__VA_ARGS__)
#else
#define FAF_RUNTIME_LAYOUT_ASSERT(...)
#endif
#endif
namespace moho
{
  class CScrLuaInitForm;
  class CUIManager;
  class IClient;
  class IClientMgrUIInterface;
  class CUIWorldView;
  class CLuaWldUIProvider;
  class CUIWorldMesh;
  class CWldTerrainDecal;
  class RD3DTextureResource;
  class PrefetchData;
  class ID3DTextureSheet;
  class MeshInstance;
  class MeshMaterial;
  class CMauiCursor;
  class CMauiBitmap;
  class CMauiControl;
  class CMauiEdit;
  class CMauiEditClickDragger;
  class CMauiLuaDragger;
  class CMauiBorder;
  class CMauiFrame;
  class CMauiHistogram;
  class CMauiItemList;
  class CMauiMesh;
  class CMauiMovie;
  class CMauiScrollbar;
  class CMauiText;
  class CUIMapPreview;
  class CD3DFont;
  class CD3DPrimBatcher;
  class CD3DBatchTexture;
  class CameraImpl;
  class UserEntity;
  class UserUnit;
  class CWldSession;
  struct RMeshBlueprint;
  struct RUnitBlueprint;
  struct SClientBottleneckInfo;

  class IWldUIProvider
  {
  public:
    /**
     * Address: 0x0086A350 (FUN_0086A350, ??0IWldUIProvider@Moho@@QAE@XZ)
     * Address: 0x0086A5C0 (FUN_0086A5C0, IWldUIProvider ctor lane)
     *
     * What it does:
     * Initializes one world-UI-provider base interface object.
     */
    IWldUIProvider();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 0
     */
    virtual ~IWldUIProvider() = default;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 1
     */
    virtual void StartLoadingDialog() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 2
     */
    virtual void UpdateLoadingDialog(float deltaSeconds) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 3
     */
    virtual void StopLoadingDialog() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 4
     */
    virtual void StartWaitingDialog() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 5
     */
    virtual void UpdateWaitingDialog(float deltaSeconds) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 6
     */
    virtual void StopWaitingDialog() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 7
     */
    virtual void OnStart() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 8
     */
    virtual void CreateGameInterface(bool createGameInterface) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * VFTable SLOT: 9
     */
    virtual void DestroyGameInterface() = 0;
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(IWldUIProvider) == 0x4, "moho::IWldUIProvider size must be 0x4");

  /**
   * Lua-backed world UI provider that delegates lifecycle hooks into script.
   */
  class CLuaWldUIProvider final : public IWldUIProvider, public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0086A530 (??0CLuaWldUIProvider@Moho@@QAE@@Z, Moho::CLuaWldUIProvider::CLuaWldUIProvider)
     *
     * What it does:
     * Constructs one world-UI provider, binds the embedded script object, and
     * seeds the prefetch-texture cache lane to empty.
     */
    explicit CLuaWldUIProvider(LuaPlus::LuaObject* luaObject);

    /**
     * Address: 0x0086A5D0 (??1CLuaWldUIProvider@Moho@@QAE@@Z, Moho::CLuaWldUIProvider::~CLuaWldUIProvider)
     * Deleting destructor thunk: 0x0086A5A0 (Moho::CLuaWldUIProvider::dtr)
     *
     * What it does:
     * Releases cached prefetch handles, tears down the script subobject, and
     * restores the base provider vtable lane.
     */
    ~CLuaWldUIProvider() override;

    /**
     * Address: 0x0086A3A0 (FUN_0086A3A0, Moho::CLuaWldUIProvider::GetClass)
     *
     * What it does:
     * Returns the cached RTTI descriptor for this provider class.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0086A3C0 (FUN_0086A3C0, Moho::CLuaWldUIProvider::GetDerivedObjectRef)
     *
     * What it does:
     * Builds one reflected reference for this provider instance.
     */
    gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0086A650 (FUN_0086A650, Moho::CLuaWldUIProvider::StartLoadingDialog)
     *
     * What it does:
     * Dispatches the `StartLoadingDialog` Lua callback on the embedded script object.
     */
    void StartLoadingDialog() override;

    /**
     * Address: 0x0086A660 (FUN_0086A660, Moho::CLuaWldUIProvider::UpdateLoadingDialog)
     *
     * What it does:
     * Dispatches the `UpdateLoadingDialog` Lua callback with one float lane.
     */
    void UpdateLoadingDialog(float deltaSeconds) override;

    /**
     * Address: 0x0086A680 (FUN_0086A680, Moho::CLuaWldUIProvider::StopLoadingDialog)
     *
     * What it does:
     * Dispatches the `StopLoadingDialog` Lua callback on the embedded script object.
     */
    void StopLoadingDialog() override;

    /**
     * Address: 0x0086A690 (FUN_0086A690, Moho::CLuaWldUIProvider::StartWaitingDialog)
     *
     * What it does:
     * Dispatches the `StartWaitingDialog` Lua callback on the embedded script object.
     */
    void StartWaitingDialog() override;

    /**
     * Address: 0x0086A6A0 (FUN_0086A6A0, Moho::CLuaWldUIProvider::UpdateWaitingDialog)
     *
     * What it does:
     * Dispatches the `UpdateWaitingDialog` Lua callback with one float lane.
     */
    void UpdateWaitingDialog(float deltaSeconds) override;

    /**
     * Address: 0x0086A6C0 (FUN_0086A6C0, Moho::CLuaWldUIProvider::StopWaitingDialog)
     *
     * What it does:
     * Dispatches the `StopWaitingDialog` Lua callback on the embedded script object.
     */
    void StopWaitingDialog() override;

    /**
     * Address: 0x0086A6D0 (FUN_0086A6D0, Moho::CLuaWldUIProvider::OnStart)
     *
     * What it does:
     * Dispatches the `OnStart` Lua callback on the embedded script object.
     */
    void OnStart() override;

    /**
     * Address: 0x0086A6E0 (FUN_0086A6E0, Moho::CLuaWldUIProvider::CreateGameInterface)
     *
     * What it does:
     * Loads prefetch texture handles from Lua, caches them locally, then
     * dispatches the `CreateGameInterface` callback.
     */
    void CreateGameInterface(bool createGameInterface) override;

    /**
     * Address: 0x0086A8C0 (FUN_0086A8C0, Moho::CLuaWldUIProvider::DestroyGameInterface)
     *
     * What it does:
     * Dispatches the `DestroyGameInterface` Lua callback on the embedded script object.
     */
    void DestroyGameInterface() override;

  public:
    std::uint8_t mUnknown38[0x4]{}; // +0x38
    gpg::core::FastVector<boost::shared_ptr<PrefetchData>> mPrefetchData; // +0x3C
  };
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CLuaWldUIProvider, mUnknown38) == 0x38, "CLuaWldUIProvider::mUnknown38 offset must be 0x38");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CLuaWldUIProvider, mPrefetchData) == 0x3C, "CLuaWldUIProvider::mPrefetchData offset must be 0x3C");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CLuaWldUIProvider) == 0x48, "CLuaWldUIProvider size must be 0x48");

  enum EUIState : std::int32_t
  {
    UIS_none = 0,
    UIS_splash = 1,
    UIS_frontend = 2,
    UIS_game = 3,
    UIS_lobby = 4,
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(EUIState) == 0x4, "moho::EUIState size must be 0x4");

  extern EUIState sUIState;
  /**
   * Address: 0x010A645F (?cam_Free@Moho@@3_NA)
   *
   * What it does:
   * Global camera free-look toggle used by world-view dragger logic.
   */
  extern bool cam_Free;
  /**
   * Address: 0x00F57AA0 (?ren_BgLowerBound@Moho@@3MA)
   *
   * What it does:
   * Zoom threshold below which the world view stops treating a space-drag as a
   * camera rotation. `CUIWorldView::HandleEvent` compares it against
   * `CameraImpl::CameraGetTargetZoom()` at 0x00870998 and only spins the camera
   * while free-look is on or the camera is still zoomed in past this bound.
   *
   * Initial value read out of the shipped `.data` at VA 0x00F57AA0
   * (`00 00 fa 42` == 125.0f).
   */
  extern float ren_BgLowerBound;
  /**
   * Address: 0x010A6464 (?ui_DisableCursorFixing@Moho@@3_NA)
   *
   * What it does:
   * Global toggle lane that disables mouse recentering while UI drag-scrub
   * mode is active.
   */
  extern bool ui_DisableCursorFixing;
  /**
   * What it does:
   * Selects the sign the middle-mouse scrub accumulation is applied with,
   * driven by the `SetInvertMidMouseButton` Lua global.
   *
   * The shipped build implements this by rewriting two instructions in
   * `func_ProcessMouseScrubbing` (0x0086DFF0) in place - `add
   * mCurMouseScrub.x, eax` at 0x0086E01F and `add mCurMouseScrub.y, ecx` at
   * 0x0086E027 become `sub`. Self-patching absolute addresses of the original
   * image has no meaning in recovered source, so the same choice is carried as
   * a flag the scrub accumulation reads.
   */
  void UI_SetInvertMidMouseScrub(bool invert) noexcept;
  /**
   * Address: 0x00F57A90 (?ui_SelectTolerance@Moho@@3MA)
   *
   * World-view unit pick tolerance (pixels); seeded to 4.0, overridden from
   * `/lua/ui/controls/worldview.lua`'s WorldViewParams by CUIWorldView's ctor.
   */
  extern float ui_SelectTolerance;
  /**
   * Address: 0x00F57A94 (?ui_ExtractSnapTolerance@Moho@@3MA)
   *
   * World-view extractor snap tolerance (world units); seeded to 20.0,
   * overridden from WorldViewParams by CUIWorldView's ctor.
   */
  extern float ui_ExtractSnapTolerance;
  /**
   * Address: 0x00F57A98 (?ui_MinExtractSnapPixels@Moho@@3MA)
   *
   * Minimum on-screen extractor snap-search radius (pixels), clamping
   * `ui_ExtractSnapTolerance`'s depth-scaled projection in
   * `CUIWorldView::UpdateSelection`. Byte-verified shipped default is 20.0.
   */
  extern float ui_MinExtractSnapPixels;
  /**
   * Address: 0x00F57A9C (?ui_MaxExtractSnapPixels@Moho@@3MA)
   *
   * Maximum on-screen extractor snap-search radius (pixels), clamping
   * `ui_ExtractSnapTolerance`'s depth-scaled projection in
   * `CUIWorldView::UpdateSelection`. Byte-verified shipped default is 90.0.
   */
  extern float ui_MaxExtractSnapPixels;
  /**
   * Address: 0x00F57BD0 (?ui_FootprintMinThickness@Moho@@3MA)
   *
   * Minimum on-screen thickness (in the prim batcher's post-perspective units)
   * of the footprint outline `DrawUnitSkirt` emits, so a skirt stays visible
   * when the camera is far away. Registered as the `ui_FootprintMinThickness`
   * console variable by the `TConVar<float>` block at 0x00BE5370; the shipped
   * image seeds the storage with 2.0.
   */
  extern float ui_FootprintMinThickness;
  /**
   * Address: 0x00F57A88 (?cam_DefaultMiniLOD@Moho@@3MA)
   *
   * Default LOD scale (1.8) applied to a minimap CUIWorldView's camera.
   */
  extern float cam_DefaultMiniLOD;
  /**
   * Address: 0x010A63EE (?ui_WindowedAlwaysShowsCursor@Moho@@3_NA)
   *
   * What it does:
   * Forces cursor visibility when the primary render head runs fullscreen.
   */
  extern bool ui_WindowedAlwaysShowsCursor;
  /**
   * Address: 0x00F57A8D (?ui_DragSelect2D@Moho@@3_NA)
   *
   * What it does:
   * Selects which selection dragger `NewSelectionDragger` constructs for a
   * left-mouse drag in select mode: `SelectionDragger2D` (screen-space
   * rubber-band) when true, `SelectionDragger3D` (world-space volume,
   * highlighted with terrain decals) when false. Byte-verified shipped
   * default is `true` (raw PE byte at 0x00F57A8D = 0x01).
   */
  extern bool ui_DragSelect2D;

  /**
   * Address: 0x00F57AA4 (?ui_KeyboardPanSpeed@Moho@@3MA)
   *
   * What it does:
   * World-units-per-frame the world view pans when a scroll key is held or the
   * cursor sits on a screen edge. Byte-verified shipped default `90.0f`
   * (raw dword at 0x00F57AA4 = 0x42B40000).
   */
  extern float ui_KeyboardPanSpeed;

  /**
   * Address: 0x00F57AA8 (?ui_KeyboardPanAccelerateMultiplier@Moho@@3MA)
   *
   * What it does:
   * Factor `ui_KeyboardPanSpeed` is multiplied by while Ctrl is held.
   * Byte-verified shipped default `4.0f` (0x40800000).
   */
  extern float ui_KeyboardPanAccelerateMultiplier;

  /**
   * Address: 0x00F57AAC (?ui_KeyboardRotateSpeed@Moho@@3MA)
   *
   * What it does:
   * Spin delta the world view feeds `CameraImpl::CameraSpin` per frame while
   * Insert/Delete is held. Byte-verified shipped default `10.0f` (0x41200000).
   */
  extern float ui_KeyboardRotateSpeed;

  /**
   * Address: 0x00F57AB0 (?ui_KeyboardRotateAccelerateMultiplier@Moho@@3MA)
   *
   * What it does:
   * Factor `ui_KeyboardRotateSpeed` is multiplied by while Ctrl is held.
   * Byte-verified shipped default `2.0f` (0x40000000).
   */
  extern float ui_KeyboardRotateAccelerateMultiplier;

  /**
   * Address: 0x00F57A8C (?ui_ScreenEdgeScrollView@Moho@@3_NA)
   *
   * What it does:
   * Enables edge scrolling: with the cursor parked against a windowed head's
   * outer pixel row/column, the world view pans away from that edge.
   * Byte-verified shipped default `true` (raw byte at 0x00F57A8C = 0x01).
   */
  extern bool ui_ScreenEdgeScrollView;

  /**
   * Address: 0x00F57887 (?ui_ArrowKeysScrollView@Moho@@3_NA)
   *
   * What it does:
   * Enables arrow-key scrolling of the world view. Byte-verified shipped
   * default `true` (raw byte at 0x00F57887 = 0x01).
   */
  extern bool ui_ArrowKeysScrollView;

  extern IWldUIProvider* sWldUIProvider;

  enum EMauiEventType : std::int32_t
  {
    MET_Unknown = 0,
    MET_MouseMotion = 1,
    MET_MouseEnter = 2,
    MET_MouseHover = 3,
    MET_MouseExit = 4,
    MET_ButtonPress = 5,
    MET_ButtonDClick = 6,
    MET_ButtonRelease = 7,
    MET_WheelRotation = 8,
    MET_KeyUp = 9,
    MET_KeyDown = 10,
    MET_Char = 11,
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(EMauiEventType) == 0x4, "moho::EMauiEventType size must be 0x4");

  enum EMauiEventModifier : std::uint32_t
  {
    MEM_None = 0x00000000u,
    MEM_Shift = 0x00000001u,
    MEM_Ctrl = 0x00000002u,
    MEM_Alt = 0x00000004u,
    MEM_Left = 0x00000010u,
    MEM_Middle = 0x00000020u,
    MEM_Right = 0x00000040u,
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(EMauiEventModifier) == 0x4, "moho::EMauiEventModifier size must be 0x4");

  enum EMauiScrollAxis : std::int32_t;
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(EMauiScrollAxis) == 0x4, "moho::EMauiScrollAxis size must be 0x4");

  enum EMauiKeyCode : std::int32_t;
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(EMauiKeyCode) == 0x4, "moho::EMauiKeyCode size must be 0x4");

  struct SMauiScrollValues
  {
    float mMinRange = 0.0f;
    float mMaxRange = 0.0f;
    float mMinVisible = 0.0f;
    float mMaxVisible = 0.0f;
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SMauiScrollValues) == 0x10, "moho::SMauiScrollValues size must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiScrollValues, mMinRange) == 0x0, "SMauiScrollValues::mMinRange offset must be 0x0");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiScrollValues, mMaxRange) == 0x4, "SMauiScrollValues::mMaxRange offset must be 0x4");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiScrollValues, mMinVisible) == 0x8, "SMauiScrollValues::mMinVisible offset must be 0x8");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiScrollValues, mMaxVisible) == 0xC, "SMauiScrollValues::mMaxVisible offset must be 0xC");

  struct SMauiMousePos
  {
    float x = 0.0f;
    float y = 0.0f;
  };
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(SMauiMousePos) == 0x8, "moho::SMauiMousePos size must be 0x8");

  struct SMauiEventData
  {
    EMauiEventType mEventType = MET_Unknown;  // +0x00
    SMauiMousePos mMousePos{};                // +0x04
    std::int32_t mWheelRotation = 0;          // +0x0C
    std::int32_t mWheelData = 0;              // +0x10
    std::int32_t mKeyCode = 0;                // +0x14
    std::int32_t mRawKeyCode = 0;             // +0x18
    EMauiEventModifier mModifiers = MEM_None; // +0x1C
    CScriptObject* mSource = nullptr;         // +0x20
  };
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mEventType) == 0x0, "SMauiEventData::mEventType offset must be 0x0");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mMousePos) == 0x4, "SMauiEventData::mMousePos offset must be 0x4");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mWheelRotation) == 0xC, "SMauiEventData::mWheelRotation offset must be 0xC");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mWheelData) == 0x10, "SMauiEventData::mWheelData offset must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mKeyCode) == 0x14, "SMauiEventData::mKeyCode offset must be 0x14");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mRawKeyCode) == 0x18, "SMauiEventData::mRawKeyCode offset must be 0x18");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mModifiers) == 0x1C, "SMauiEventData::mModifiers offset must be 0x1C");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(SMauiEventData, mSource) == 0x20, "SMauiEventData::mSource offset must be 0x20");

  /**
   * Base of every MAUI pointer-drag handler.
   *
   * Layout is vptr (+0x00) followed by the inherited `WeakObject` sub-object
   * (+0x04), so the complete base is 8 bytes. The `WeakObject` base is proven
   * by the RTTI class-hierarchy descriptor behind
   * `??_7IMauiDragger@Moho@@6B@`: the COL at 0x00E9301C names
   * `.?AVIMauiDragger@Moho@@` and its base-class array lists
   * `.?AVWeakObject@Moho@@` at `mdisp=0x4`. `MOHO_EMPTY_BASES`-style layout
   * does not apply here - `WeakObject` carries one dword, and MSVC places the
   * newly introduced vfptr ahead of a non-polymorphic base, which is exactly
   * the `mdisp=0x4` the descriptor records.
   *
   * `??1IMauiDragger@Moho@@UAE@XZ` lives at 0x0078DB20 (IDA did not classify
   * it as a function, so it is read straight out of the shipped image) and is
   * nothing but the inlined `WeakObject` teardown after the vptr restore:
   *   0x0078DB20  mov  dword ptr [ecx], offset ??_7IMauiDragger@Moho@@6B@
   *   0x0078DB26  mov  eax, [ecx+4]          ; head = weakLinkHead_
   *   0x0078DB30  mov  esi, [eax+4]          ; next  = node->nextInOwner
   *   0x0078DB33  mov  [ecx+4], esi          ; head  = next
   *   0x0078DB36  mov  [eax], edx            ; node->ownerLinkSlot = nullptr
   *   0x0078DB38  mov  [eax+4], edx          ; node->nextInOwner   = nullptr
   *   0x0078DB3B  mov  eax, [ecx+4]          ; loop while head != nullptr
   * which is `WeakObject::DetachAllWeakReferences()` verbatim. Every derived
   * dragger the compiler inlined that same sequence into agrees on both the
   * `+0x04` displacement and the two-dword node shape:
   *   `Moho::IMauiDragger::dtr`      0x0078DB99 / 0x0078DBA2 (`[esi+4]`)
   *   `~UICommandDragger`            0x00824120 / 0x00824130 (`[esi+4]`)
   *   `~SelectionDragger`            0x00864086 / 0x00864090 (`[ecx+4]`)
   *   `~CMauiLuaDragger`             0x0078DF03 / 0x0078DF10 (`lea ecx,[esi+34h]`)
   * and the ctors clear the same lane before installing the derived vptr
   * (`mov [eax+4], 0` at 0x008637F0 for `SelectionDragger`,
   * `mov [esi+38h], eax` at 0x0078DE77 for `CMauiLuaDragger`,
   * `mov [esi+120h], ebx` at 0x007A04ED for `CMauiScrollbar`).
   *
   * The lane is the object's weak-reference chain, not a list of children:
   * `func_SetCurDragger` (0x0078E590) links the process-global current-dragger
   * weak node into it with `lea ecx,[eax+4]`, and
   * `func_GetCurrentDraggerFromMouseMoveLane` (0x0078DDC0) recovers the owner
   * with `add eax, -4`.
   *
   * None of the three drag entry points is pure. The shipped
   * `??_7IMauiDragger@Moho@@6B@` at 0x00E38DC0 carries a real body in every
   * slot (dwords read out of `.rdata` in the shipped image):
   *   +0x00  0x0078DB90  scalar deleting destructor
   *   +0x04  0x0078DB50  `DragMove`                  (empty body, `retn 4`)
   *   +0x08  0x0078DB60  `DragRelease`               (`delete this`)
   *   +0x0C  0x0078DB80  `OnCurrentDraggerReplaced`  (`delete this`)
   * `_purecall` is 0x00A82547 in this image (it is what fills the genuinely
   * pure `SelectionDragger` slots +0x10/+0x14/+0x18), and it appears in none
   * of these four slots.
   *
   * The vtable is destructor-anchored: `~IMauiDragger` at 0x0078DB20 opens
   * with `mov dword ptr [ecx], offset ??_7IMauiDragger@Moho@@6B@`, and
   * `~UICommandDragger` restores the same address at 0x0082411A when it
   * unwinds its own sub-object.
   *
   * Because the default bodies are inherited rather than pure, a derived
   * dragger that leaves a slot alone gets the base behavior. That is what the
   * shipped vtables show: `SelectionDragger` and `SelectionDragger2D` both
   * keep 0x0078DB50 in +0x04 / 0x0078DB80 in +0x0C.
   */
  class IMauiDragger : public WeakObject
  {
  public:
    /**
     * What it does:
     * Clears the inherited `WeakObject` head so a freshly built dragger owns
     * no weak references. Every derived constructor in the image inlines this
     * single store before installing its own vptr - `mov dword ptr [eax+4], 0`
     * at 0x008637F0 (`SelectionDragger`), `mov [esi+38h], eax` at 0x0078DE77
     * (`CMauiLuaDragger`, eax = 0), `mov [esi+120h], ebx` at 0x007A04ED
     * (`CMauiScrollbar`, ebx = 0).
     */
    IMauiDragger() noexcept
      : WeakObject{}
    {}

    /**
     * Address: 0x0078DB20 (??1IMauiDragger@Moho@@UAE@XZ)
     * Scalar deleting destructor: 0x0078DB90 (slot +0x00)
     * Mangled: ??1IMauiDragger@Moho@@UAE@XZ
     *
     * IDA signature:
     * void __thiscall Moho::IMauiDragger::~IMauiDragger(Moho::IMauiDragger *this@<ecx>);
     *
     * What it does:
     * Restores the base vtable and drains the inherited `WeakObject` chain that
     * lives directly behind the vptr, zeroing each node's owner slot and
     * forward link as it is unlinked.
     */
    virtual ~IMauiDragger();

    /**
     * Address: 0x0078DB50 (slot +0x04 of ??_7IMauiDragger@Moho@@6B@)
     * Mangled: ?DragMove@IMauiDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::IMauiDragger::DragMove(
     *     Moho::IMauiDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Nothing. The shipped body is a bare `retn 4` - a dragger that does not
     * care about intermediate motion simply inherits this.
     *
     * Dispatched through slot +0x04 by `func_OnMouseMove` (FUN_007A4970):
     * `0x007A4C8D: mov edx, [edx+4]` / `0x007A4C96: call edx`.
     */
    virtual void DragMove(const SMauiEventData* eventData);

    /**
     * Address: 0x0078DB60 (slot +0x08 of ??_7IMauiDragger@Moho@@6B@)
     * Mangled: ?DragRelease@IMauiDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::IMauiDragger::DragRelease(
     *     Moho::IMauiDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Destroys the dragger. The body is MSVC's `delete this` shape - a null
     * test on `this`, then a tail jump through vtable slot +0x00 with the
     * scalar-delete flag forced to 1 over the incoming event argument.
     *
     * Dispatched through slot +0x08 by `func_OnMouseMove` (FUN_007A4970):
     * `0x007A4C40: mov edx, [edx+8]` / `0x007A4C47: call edx`.
     */
    virtual void DragRelease(const SMauiEventData* eventData);

    /**
     * Address: 0x0078DB80 (slot +0x0C of ??_7IMauiDragger@Moho@@6B@)
     * Mangled: ?OnCurrentDraggerReplaced@IMauiDragger@Moho@@UAEXXZ
     *
     * IDA signature:
     * void __thiscall Moho::IMauiDragger::OnCurrentDraggerReplaced(
     *     Moho::IMauiDragger *this@<ecx>);
     *
     * What it does:
     * Destroys the dragger. A dragger that is displaced as the current one is
     * dropped on the spot unless it overrides this; the body is again MSVC's
     * `delete this` shape (null test, `push 1`, call through slot +0x00).
     *
     * Dispatched through slot +0x0C by `func_PostDragger` (FUN_0078DDE0):
     * `0x0078DE01: mov edx, [eax+0Ch]` / `0x0078DE04: call edx`.
     */
    virtual void OnCurrentDraggerReplaced();
  };
  static_assert(sizeof(IMauiDragger) == 0x8, "moho::IMauiDragger size must be 0x8");

  /**
   * The dragger `Dragger()` hands back to script, and the only dragger whose
   * drag callbacks live in Lua rather than in the engine. MAUI installs it as
   * the active dragger through `PostDragger`, then routes every subsequent
   * pointer motion, release and cancellation to the `OnMove` / `OnRelease` /
   * `OnCancel` entries on its Lua table.
   *
   * Every front-end button click completes through here: `lua/maui/button.lua`
   * has no `ButtonRelease` branch at all, it creates one of these on press and
   * hangs `self:OnClick(...)` off the dragger's `OnRelease`.
   *
   * Layout follows the binary: `CScriptObject` at +0x00 and the `IMauiDragger`
   * sub-object at +0x34. The constructor at 0x0078DE50 proves both, and proves
   * that +0x38 is nothing but the `IMauiDragger` base's own `WeakObject` lane
   * rather than a member of this class:
   *   0x0078DE77  mov  [esi+38h], eax   ; eax = 0, weakLinkHead_ = nullptr
   *   0x0078DE7A  mov  [esi+34h], offset ??_7IMauiDragger@Moho@@6B@
   * i.e. the inlined `IMauiDragger` base constructor writing its own two
   * dwords. The destructor at 0x0078DEF0 mirrors it, re-basing to the
   * sub-object first (`lea ecx,[esi+34h]`, 0x0078DEF6) and then running the
   * base teardown against `[ecx+4]`.
   */
  class CMauiLuaDragger final : public CScriptObject, public IMauiDragger
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0078DE50 (FUN_0078DE50, Moho::CMauiLuaDragger::CMauiLuaDragger)
     *
     * IDA signature:
     * Moho::CMauiLuaDragger *__stdcall Moho::CMauiLuaDragger::CMauiLuaDragger(
     *     Moho::CMauiLuaDragger *this, LuaPlus::LuaObject *a2);
     *
     * What it does:
     * Runs the `CScriptObject` base constructor, clears the dragger list-head
     * lane, and binds the Lua table that owns this dragger.
     */
    explicit CMauiLuaDragger(const LuaPlus::LuaObject& luaObject);

    /**
     * Address: 0x0078DEF0 (FUN_0078DEF0, Moho::CMauiLuaDragger::~CMauiLuaDragger)
     * Deleting destructor thunk: 0x0078DEC0 (FUN_0078DEC0, Moho::CMauiLuaDragger::dtr)
     *
     * What it does:
     * Detaches every node still linked to this dragger before the bases run.
     */
    ~CMauiLuaDragger() override;

    /**
     * Address: 0x0078DBD0 (FUN_0078DBD0, Moho::CMauiLuaDragger::StaticGetClass)
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0078DBF0 (FUN_0078DBF0, Moho::CMauiLuaDragger::GetClass)
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0078DC10 (FUN_0078DC10, Moho::CMauiLuaDragger::GetDerivedObjectRef)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle, which is
     * what lets `SCR_FromLua_CMauiLuaDragger` recognise the object.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0078DF30 (FUN_0078DF30, Moho::CMauiLuaDragger::OnMove)
     *
     * What it does:
     * Invokes the script callback `OnMove(self, x, y)`.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x0078DF50 (FUN_0078DF50, Moho::CMauiLuaDragger::OnRelease)
     *
     * What it does:
     * Invokes the script callback `OnRelease(self, x, y)` - the callback that
     * carries `Button:OnClick`.
     */
    void DragRelease(const SMauiEventData* eventData) override;

    /**
     * Address: 0x0078DF70 (FUN_0078DF70, Moho::CMauiLuaDragger::OnCancel)
     *
     * What it does:
     * Invokes the script callback `OnCancel(self)` when another dragger takes
     * over.
     */
    void OnCurrentDraggerReplaced() override;
  };

  // +0x00 CScriptObject (0x34), +0x34 IMauiDragger sub-object (vptr +0x34,
  // WeakObject::weakLinkHead_ +0x38) = 0x3C complete-object size.
  static_assert(sizeof(CMauiLuaDragger) == 0x3C, "moho::CMauiLuaDragger size must be 0x3C");

  struct CUIWorldViewBuildDragRuntimeView
  {
    /**
     * Address: 0x008529C0 (FUN_008529C0, struct_WorldView_object::struct_WorldView_object)
     *
     * What it does:
     * Initializes the world-view build-preview cache, invalid start/end
     * vectors, and empty preview mesh/material/decal state.
     */
    CUIWorldViewBuildDragRuntimeView();

    /**
     * Address: 0x00852B20 (FUN_00852B20, struct_WorldView_object::~struct_WorldView_object)
     *
     * What it does:
     * Clears preview meshes, releases the preview material, and destroys the
     * position tree sentinel/storage.
     */
    ~CUIWorldViewBuildDragRuntimeView();

    /**
     * Address: 0x008549B0 (FUN_008549B0, struct_WorldView_object::Destroy)
     *
     * What it does:
     * Clears active build-preview mesh/blueprint caches and destroys the
     * terrain decal used by the preview lane.
     */
    void ClearBuildPreviewCache();

    [[nodiscard]] boost::shared_ptr<MeshInstance> CreateBuildPreviewMeshInstance(RUnitBlueprint* blueprint);

    /**
     * Address: 0x00854130 (FUN_00854130, sub_854130)
     *
     * What it does:
     * Creates one `UnitPlace` build-preview mesh instance for a unit blueprint
     * and appends it to the preview mesh/blueprint caches.
     */
    void AppendBuildPreviewMesh(RUnitBlueprint* blueprint);

    /**
     * Address: 0x008544B0 (FUN_008544B0, sub_8544B0)
     *
     * What it does:
     * Replaces one cached build-preview mesh/blueprint slot with a freshly
     * created `UnitPlace` mesh instance for the provided unit blueprint.
     */
    void ReplaceBuildPreviewMesh(std::size_t index, RUnitBlueprint* blueprint);

    /**
     * Address: 0x008534F0 (FUN_008534F0, sub_8534F0)
     *
     * IDA signature:
     * void __stdcall sub_8534F0(int arg0);
     *
     * What it does:
     * Rebuilds the translucent "ghost" mesh shown at every queued mobile-build
     * order. Walks the session's command map, skips orders a unit under their
     * own cursor is already building, reuses the ghost already cached for an
     * order (un-hiding it) or creates a fresh `UnitPlace`-shaded one from the
     * order's blueprint, and stances each at the order's anchor. The rebuilt
     * lane is swapped into `mPreviewPositions`, so ghosts for orders that no
     * longer exist die with the map that is swapped out.
     */
    void RefreshQueuedBuildGhosts();

    /**
     * Address: 0x00852C10 (FUN_00852C10, sub_852C10)
     *
     * IDA signature:
     * void __stdcall sub_852C10(struct_WorldView_object *arg0);
     *
     * What it does:
     * Drives the whole build-drag preview for one frame. Re-reads what the
     * left mouse button would currently do, drops the cached preview meshes
     * whenever the build target or the command mode changed, refreshes the
     * queued-order ghosts, and - while a build mode is active and the drag
     * endpoints are valid - stamps one preview mesh per cell along the drag,
     * either once per active build-template entry or once for the single
     * blueprint being placed. Any preview meshes left over from a longer
     * previous drag are trimmed off the end.
     */
    void UpdateDragPreview();

    CWldSession* mSession = nullptr;                       // +0x00
    // The binary stores the *mesh* blueprint here, not the unit one:
    // FUN_00852C10 fills it from `mRules->GetMeshBlueprint(...)` at
    // 0x00852C75 and then divides `[+0x64,+0x68)` by 204 (0x00852CD4,
    // sizeof(RMeshBlueprintLOD)) to test whether the LOD chain is empty.
    RMeshBlueprint* mActiveBuildMesh = nullptr;             // +0x04
    msvc8::vector<boost::shared_ptr<MeshInstance>> mMeshes; // +0x08
    msvc8::vector<RUnitBlueprint*> mBlueprints;             // +0x18
    // The binary's "preview positions" lane is an ordinary MSVC8 std::map
    // keyed by the order's command id: node {left,parent,right} at 0x00..0x0B,
    // pair<const CmdId, shared_ptr<MeshInstance>> at 0x0C, _Color at 0x18 and
    // _Isnil at 0x19 - exactly msvc8::map's node shape.
    msvc8::map<CmdId, boost::shared_ptr<MeshInstance>> mPreviewPositions; // +0x28
    boost::shared_ptr<MeshMaterial> mUnitPlaceMaterial;     // +0x34
    CWldTerrainDecal* mDecal = nullptr;                     // +0x3C
    // Command *mode*, not caps: FUN_00852C10 copies `CommandModeData::mMode`
    // (its +0x00 lane) here at 0x00852C9C and gates the whole preview on it
    // being COMMOD_Build (2) or COMMOD_BuildAnchored (3) at 0x00852CAB.
    ECommandMode mActiveCommandMode = COMMOD_None;          // +0x40
    Wm3::Vector3f mStart{};                                 // +0x44
    Wm3::Vector3f mEnd{};                                   // +0x50
    bool mPreviewInvalid = false;                           // +0x5C
    bool mUnknown5D = false;                                // +0x5D
    std::uint8_t mPad5E[0x02]{};
  };
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mSession) == 0x00,
    "moho::CUIWorldViewBuildDragRuntimeView::mSession offset must be 0x00"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mActiveBuildMesh) == 0x04,
    "moho::CUIWorldViewBuildDragRuntimeView::mActiveBuildMesh offset must be 0x04"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mMeshes) == 0x08,
    "moho::CUIWorldViewBuildDragRuntimeView::mMeshes offset must be 0x08"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mBlueprints) == 0x18,
    "moho::CUIWorldViewBuildDragRuntimeView::mBlueprints offset must be 0x18"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mPreviewPositions) == 0x28,
    "moho::CUIWorldViewBuildDragRuntimeView::mPreviewPositions offset must be 0x28"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mUnitPlaceMaterial) == 0x34,
    "moho::CUIWorldViewBuildDragRuntimeView::mUnitPlaceMaterial offset must be 0x34"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mDecal) == 0x3C,
    "moho::CUIWorldViewBuildDragRuntimeView::mDecal offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mActiveCommandMode) == 0x40,
    "moho::CUIWorldViewBuildDragRuntimeView::mActiveCommandMode offset must be 0x40"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mStart) == 0x44,
    "moho::CUIWorldViewBuildDragRuntimeView::mStart offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mEnd) == 0x50,
    "moho::CUIWorldViewBuildDragRuntimeView::mEnd offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIWorldViewBuildDragRuntimeView, mPreviewInvalid) == 0x5C,
    "moho::CUIWorldViewBuildDragRuntimeView::mPreviewInvalid offset must be 0x5C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(CUIWorldViewBuildDragRuntimeView) == 0x60,
    "moho::CUIWorldViewBuildDragRuntimeView size must be 0x60"
  );

  /**
   * Drag-build dragger: the one MAUI installs while the player sweeps out a
   * run of buildings with the left button held.
   *
   * Slot map of `??_7UIBuildDragger@Moho@@6B@` (VA 0x00E42514, dwords read out
   * of the shipped image):
   *   +0x00  0x00823030  scalar deleting destructor (base teardown inlined -
   *                      the derived class adds no destructor work of its own,
   *                      the body is byte-identical to `IMauiDragger`'s
   *                      0x0078DB90 apart from the `operator delete` rel32)
   *   +0x04  0x00823BB0  `DragMove`                 (override)
   *   +0x08  0x00823BD0  `DragRelease`              (override)
   *   +0x0C  0x00823CA0  `OnCurrentDraggerReplaced` (override)
   *
   * Slot +0x08 (0x00823BD0) runs `ReleaseDrag`, then the build-order issuing
   * worker at 0x00823220 (recovered as the file-static `IssueBuildDragOrders`
   * in UiRuntimeTypes.cpp - it is `static` in the binary too: every other
   * member of this class carries a real symbol and that address carries none,
   * and it takes `this` in `edi` rather than `ecx`), then resets both
   * world-view preview lanes to the invalid-vector sentinel, then
   * `delete this`.
   */
  class UIBuildDragger : public IMauiDragger
  {
  public:
    /**
     * Address: 0x00822FA0 (FUN_00822FA0, ??0UIBuildDragger@Moho@@QAE@@Z)
     *
     * What it does:
     * Seeds build-drag start/end world positions from the current session
     * cursor world position and mirrors those lanes into the world-view state.
     */
    UIBuildDragger(CWldSession* session, CUIWorldViewBuildDragRuntimeView* worldView, CameraImpl* camera);

    /**
     * Address: 0x00823BB0 (FUN_00823BB0, slot +0x04 of ??_7UIBuildDragger@Moho@@6B@)
     * Mangled: ?DragMove@UIBuildDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::UIBuildDragger::DragMove(
     *     Moho::UIBuildDragger *this@<ecx>, Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Forwards one drag-move tick to the shared `ReleaseDrag` helper, which
     * re-resolves the active build blueprint and snaps `mEnd` to the cursor's
     * current world-surface intersection when the blueprint is a DRAGBUILD.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00823BD0 (FUN_00823BD0, slot +0x08 of ??_7UIBuildDragger@Moho@@6B@)
     * Mangled: ?DragRelease@UIBuildDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::UIBuildDragger::DragRelease(
     *     Moho::UIBuildDragger *this@<ecx>, Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Ends the build drag: snaps `mEnd` one last time through the shared
     * `ReleaseDrag` helper, converts the finished drag line into its run of
     * build orders, clears both world-view preview lanes back to the
     * invalid-vector sentinel so nothing keeps drawing, then deletes the
     * dragger.
     */
    void DragRelease(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00823CA0 (FUN_00823CA0, slot +0x0C of ??_7UIBuildDragger@Moho@@6B@)
     * Mangled: ?OnCurrentDraggerReplaced@UIBuildDragger@Moho@@UAEXXZ
     *
     * IDA signature:
     * void __thiscall Moho::UIBuildDragger::OnCurrentDraggerReplaced(
     *     Moho::UIBuildDragger *this@<ecx>);
     *
     * What it does:
     * Drops the dragger when something else becomes the current dragger. The
     * body is MSVC's `delete this` shape and is byte-for-byte the same as the
     * inherited `IMauiDragger::OnCurrentDraggerReplaced` at 0x0078DB80; the
     * linker kept both because this translation unit declared its own
     * override.
     */
    void OnCurrentDraggerReplaced() override;

    /**
     * Address: 0x008230A0 (FUN_008230A0, Moho::UIBuildDragger::ReleaseDrag)
     *
     * What it does:
     * Polls the left-mouse command mode for the active session cursor; if the
     * resolved blueprint is a member of the rules "DRAGBUILD" entity category,
     * unprojects the event's screen-space mouse position into the world-surface
     * intersection and, when valid, snaps `mEnd` to it and mirrors both
     * `mStart`/`mEnd` lanes into the bound world-view build-drag state. Shared
     * helper invoked by both the `DragMove` and `DragRelease` virtual override
     * lanes (`FUN_00823BB0` / `FUN_00823BD0`).
     */
    void ReleaseDrag(const SMauiEventData* eventData);

  public:
    // +0x00 vptr and +0x04 `WeakObject::weakLinkHead_` both belong to the
    // `IMauiDragger` base; this class's own storage starts at +0x08.
    CWldSession* mWldSession = nullptr;                     // +0x08
    CUIWorldViewBuildDragRuntimeView* mWldView = nullptr;   // +0x0C
    CameraImpl* mCam = nullptr;                             // +0x10
    Wm3::Vector3f mStart{};                                 // +0x14
    Wm3::Vector3f mEnd{};                                   // +0x20
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(UIBuildDragger, mWldSession) == 0x8, "moho::UIBuildDragger::mWldSession offset must be 0x8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(UIBuildDragger, mWldView) == 0xC, "moho::UIBuildDragger::mWldView offset must be 0xC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(UIBuildDragger, mCam) == 0x10, "moho::UIBuildDragger::mCam offset must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(UIBuildDragger, mStart) == 0x14, "moho::UIBuildDragger::mStart offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(UIBuildDragger, mEnd) == 0x20, "moho::UIBuildDragger::mEnd offset must be 0x20");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(UIBuildDragger) == 0x2C, "moho::UIBuildDragger size must be 0x2C");

  /**
   * The dragger MAUI installs while the player drags an existing command's
   * marker/waypoint on the command graph to redirect it. Both drag callbacks
   * funnel into the shared `func_ProcessCommandDrag` worker (CWldSession.cpp,
   * declared in CWldSession.h) - the class itself is thin cursor-tracking
   * state, matching `UIBuildDragger`'s own shape above.
   *
   * Slot map of `??_7UICommandDragger@Moho@@6B@`, read as raw dwords out of
   * the shipped image at VA 0x00E42600 (the address the constructor stores at
   * 0x0082401A):
   *   +0x00  0x008240A0  scalar deleting destructor - calls the non-deleting
   *                      body at 0x008240C0, then `operator delete` when the
   *                      caller passes bit0
   *   +0x04  0x008241B0  `DragMove`                 (override)
   *   +0x08  0x00824210  `DragRelease`              (override)
   *   +0x0C  0x00824290  `OnCurrentDraggerReplaced` (override - drops the
   *                      dragged command's highlight through 0x0082A030
   *                      before `delete this`)
   *
   * A previous pass recorded this slot map as `+0x00 0x00824120` with slot
   * +0x0C inherited. Both were wrong: 0x00824120 is an instruction *inside*
   * the non-deleting destructor at 0x008240C0 (the point where it restores
   * `??_7IMauiDragger@Moho@@6B@`), and slot +0x0C really does hold an
   * override. The addresses above were re-read byte-for-byte from
   * `bin/external/ForgedAlliance.exe`.
   *
   * Field evidence: both `DragMove` (0x008241B0) and `DragRelease`
   * (0x00824210) read `[this+0Ch]` as the camera (dispatched through its own
   * vtable slot +0x1C, `CameraScreenToSurface`), `[this+10h]` as the dragged
   * command's `CmdId` (passed to `func_ProcessCommandDrag`'s `arg4` and, in
   * `DragRelease`, to `func_OnCommandDragEnd`'s `isDragger`), and `[this+14h]`
   * as the owning `UICommandGraph*` (passed as `func_ProcessCommandDrag`'s
   * `arg0`). `DragRelease` additionally reads `[this+8]` at 0x00824260, then
   * dereferences its own `+0x10` (0x00824263) to reach `func_OnCommandDragEnd`'s
   * `state` argument - exactly `CWldSession::mState`'s own offset (see
   * CWldSession.h) - so `[this+8]` is `CWldSession* mSession`, matching
   * `UIBuildDragger::mWldSession`'s identical role at the identical offset.
   */
  class UICommandDragger : public IMauiDragger
  {
  public:
    /**
     * Address: 0x00823FE0 (FUN_00823FE0, ??0UICommandDragger@Moho@@QAE@@Z)
     *
     * IDA signature:
     * Moho::UICommandDragger *__stdcall Moho::UICommandDragger::UICommandDragger(
     *     Moho::UICommandDragger *this, Moho::CWldSession *session,
     *     Moho::CameraImpl *camera, int commandId);
     *
     * What it does:
     * Binds the dragger to the session, camera and the command id being
     * dragged, takes a counted reference on the session's UI command graph
     * (creating it when absent) and notifies the UI Lua layer that a command
     * drag has begun.
     */
    UICommandDragger(CWldSession* session, CameraImpl* camera, CmdId commandId);

    /**
     * Address: 0x008240C0 (FUN_008240C0, non-deleting destructor)
     * Deleting dtor: 0x008240A0 (slot +0x00 of ??_7UICommandDragger@Moho@@6B@)
     *
     * What it does:
     * Drops the counted reference the constructor took on the session's UI
     * command graph, then runs `IMauiDragger`'s own teardown (base vtable
     * restore plus the `WeakObject` chain drain).
     *
     * The graph release is not optional bookkeeping: 0x008240E9 loads
     * `[this+18h]` (the control-block half of `mGraph`) and 0x008240F6 does
     * `lock xadd [pn+4], -1`, followed by `dispose()` through vtable slot +4
     * and `destroy()` through slot +8 once the weak count also reaches zero -
     * i.e. exactly `boost::detail::sp_counted_base::release()`. The
     * constructor's own unwind funclet (0x00BC2238) releases the same lane
     * via `Moho::WeakPtr_UICommandGraph::Release` (0x00824060).
     */
    ~UICommandDragger() override;

    /**
     * Address: 0x008241B0 (FUN_008241B0, slot +0x04 of ??_7UICommandDragger@Moho@@6B@)
     * Mangled: ?DragMove@UICommandDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::UICommandDragger::DragMove(
     *     Moho::UICommandDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Unprojects the event's screen mouse position through the bound camera
     * into a world-surface point, then forwards it to `func_ProcessCommandDrag`
     * along with the dragged command's graph/id, `released = false`.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00824210 (FUN_00824210, slot +0x08 of ??_7UICommandDragger@Moho@@6B@)
     * Mangled: ?DragRelease@UICommandDragger@Moho@@UAEXPBUSMauiEventData@2@@Z
     *
     * IDA signature:
     * void __thiscall Moho::UICommandDragger::DragRelease(
     *     Moho::UICommandDragger *this@<ecx>, const Moho::SMauiEventData *eventData);
     *
     * What it does:
     * Unprojects the event's screen mouse position the same way `DragMove`
     * does, forwards it to `func_ProcessCommandDrag` with `released = true`,
     * notifies the UI Lua layer via `func_OnCommandDragEnd`, then deletes
     * this dragger (the inherited `IMauiDragger` `delete this` shape, slot
     * +0x00).
     */
    void DragRelease(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00824290 (FUN_00824290, slot +0x0C of ??_7UICommandDragger@Moho@@6B@)
     * Mangled: ?OnCurrentDraggerReplaced@UICommandDragger@Moho@@UAEXXZ
     *
     * IDA signature:
     * void __thiscall Moho::UICommandDragger::OnCurrentDraggerReplaced(
     *     Moho::UICommandDragger *this@<ecx>);
     *
     * What it does:
     * Unlike the sibling `UIBuildDragger::OnCurrentDraggerReplaced` (a bare
     * `delete this`), this override does real work first: it reads
     * `mCommandId`/`mGraph` (0x00824293/0x00824297) and calls
     * `Moho::ReanchorCommandGraphDrawNode` (0x0082A030, CWldSession.h/.cpp) to
     * drop the drag preview the abandoned drag left on the command's
     * `mMapAB0` draw node - re-anchoring it to the command's own real
     * position - before deleting this dragger (the inherited `IMauiDragger`
     * `delete this` shape, slot +0x00).
     */
    void OnCurrentDraggerReplaced() override;

  public:
    // +0x00 vptr and +0x04 WeakObject::weakLinkHead_ both belong to the
    // IMauiDragger base; this class's own storage starts at +0x08.
    CWldSession* mSession = nullptr;  // +0x08
    CameraImpl* mCam = nullptr;       // +0x0C
    CmdId mCommandId{};                // +0x10
    // The ctor (0x00823FE0) writes CWldSession::GetCommandGraph(bool)'s
    // hidden-return-value shared_ptr (px+pi, 8 bytes) directly into this
    // slot via `lea ecx,[esi+14h]` -- a raw pointer here would overflow the
    // object by 4 bytes. sizeof(UICommandDragger)==0x1C matches
    // operator new(0x1C) at the sole factory call site.
    boost::SharedPtrRaw<UICommandGraph> mGraph{}; // +0x14
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(UICommandDragger, mCam) == 0xC, "moho::UICommandDragger::mCam offset must be 0xC");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(UICommandDragger, mCommandId) == 0x10, "moho::UICommandDragger::mCommandId offset must be 0x10"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(UICommandDragger, mGraph) == 0x14, "moho::UICommandDragger::mGraph offset must be 0x14"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(UICommandDragger) == 0x1C, "moho::UICommandDragger size must be 0x1C");

  struct wxEvtHandlerRuntime
  {
    virtual ~wxEvtHandlerRuntime() = default;

    /**
     * Offers one wx event to this handler. Returns true when it was consumed.
     *
     * In the binary these handlers are real `wxEvtHandler`s carrying a
     * compiler-emitted event table, and wx walks it during `ProcessEvent`.
     * This tree models the pushed-handler chain itself (see
     * `WX_PushEventHandler`), so the table's job - match the event type, call
     * the bound sink - is done by the override instead.
     */
    virtual bool ProcessWxEvent(void* /*event*/) { return false; }
  };

  /**
   * Address context: `FUN_0084CB70` (`CUIManager::AddFrame`) allocates one
   * `CUIKeyHandler` object with `operator new(0x28)` and then pushes it onto
   * the input-window event-handler chain.
   */
  class CUIKeyHandlerRuntime final : public wxEvtHandlerRuntime
  {
  public:
    /**
     * Address: 0x00838C60 (FUN_00838C60, sub_838C60)
     *
     * What it does:
     * Runs the key-handler teardown lane and then falls through to the
     * wx-event-handler base cleanup.
     */
    ~CUIKeyHandlerRuntime() override;

    /**
     * Models the compiled `CUIKeyHandler` event table's dispatch role
     * directly (two rows: `wxEVT_KEY_UP` -> `OnKeyUp`, `wxEVT_KEY_DOWN` ->
     * `OnKeyDown`, binary table at `0x00F5B150`), the same approach
     * `CMauiWxEventMapperRuntime::ProcessWxEvent` uses for its own
     * keyboard rows.
     */
    bool ProcessWxEvent(void* event) override;

    /**
     * Address: 0x00838D10 (FUN_00838D10, Moho::CUIKeyHandler::OnKeyDown)
     *
     * IDA signature:
     * void __stdcall sub_838D10(int a1);
     *
     * What it does:
     * `wxEventTableEntry` key-press sink for the `CUIKeyHandler` event table
     * (binary `0x00F5B150`, row 2 of 2 -- row 1 at `0x00F5B158` is
     * `OnKeyUp`; both rows recovered by a raw dword byte-scan of the shipped
     * `.exe`, since IDA's own xref pass missed this table entirely -
     * `incoming_xrefs`/`callers` are empty for both sinks). Bails out when a
     * `CMauiControl` currently owns keyboard focus. Otherwise packs the wx
     * shift/ctrl/alt flags and raw key code into one `UiKeyMask` and looks it
     * up in `gUiKeyActionMap`: a hit runs the bound command string through
     * `Moho::CON_Execute`. A miss falls back to the two hardcoded shortcuts
     * (Enter opens game chat, `~` toggles the console) via
     * `Moho::UI_ActivateChat` / `Moho::MAUI_ToggleConsole`. Also consults
     * `gUiKeyRepeatMap` to suppress processing when the Win32 "previously
     * down" auto-repeat flag (`WM_KEYDOWN` lParam bit 30) is set for a key
     * this handler is not currently tracking as held.
     */
    void OnKeyDown(wxEventRuntime& keyEvent);

    /**
     * Address: 0x00838E30 (FUN_00838E30, sub_838E30)
     *
     * What it does:
     * `wxEventTableEntry` key-release sink for the `CUIKeyHandler` event
     * table (binary `0x00F5B150`, row 1 of 2). Unconditionally marks the wx
     * event skipped; `CUIKeyHandler` takes no other action on key-up.
     */
    void OnKeyUp(wxEventRuntime& keyEvent);

    std::uint8_t mUnknown04To27[0x24]{};
  };

  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CUIKeyHandlerRuntime) == 0x28, "moho::CUIKeyHandlerRuntime size must be 0x28");

  /**
   * Address: 0x010C1B48 (data segment global, 256 * 28 bytes = 0x1C00)
   *
   * Lookup table mapping wxKeyCode (0..255) to msvc8::string name. Populated
   * at startup by `IN_InitKeyHandler` with "Unknown%02X" placeholders, then
   * overwritten from `/lua/keymap/keyNames.lua` via `CUIKeyHandlerLoadKeyMappings`.
   * Consumed by `IN_FindKeyNameIndex` / `IN_FindKeyNameIndexCi` to translate
   * key-binding token strings into wx key codes.
   */
  extern msvc8::string in_keyNames[256];

  /**
   * Address: 0x00838F30 (FUN_00838F30, Moho::IN_FindKeyNameIndex)
   *
   * What it does:
   * Case-sensitive linear scan of `in_keyNames` for one key name; returns the
   * matching wxKeyCode (0..255) or -1 when no slot matches.
   */
  [[nodiscard]] int IN_FindKeyNameIndex(const msvc8::string& needle);

  /**
   * Address: 0x00838F80 (FUN_00838F80, Moho::IN_FindKeyNameIndexCi)
   *
   * What it does:
   * Case-insensitive linear scan of `in_keyNames` for one key name; returns
   * the matching wxKeyCode (0..255) or -1 when no slot matches.
   */
  [[nodiscard]] int IN_FindKeyNameIndexCi(const msvc8::string& needle);

  /**
   * Address: 0x00839EE0 (FUN_00839EE0, Moho::IN_DumpKeyNames)
   *
   * What it does:
   * The `IN_DumpKeyNames` console command ("Shows all the key names."):
   * prints every slot of `in_keyNames[0..255]` as `"%04d = %s"`. Takes no
   * command arguments (the incoming pointer is unused, matching the
   * binary's `CConFunc::Callback` shape).
   */
  void IN_DumpKeyNames(void* commandArgs);

  /**
   * Address: 0x00838C70 (FUN_00838C70, Moho::IN_InitKeyHandler)
   *
   * What it does:
   * Initializes `in_keyNames[0..255]` with "Unknown%02X" placeholder strings,
   * then loads engine key-name and key-map Lua data via
   * `CUIKeyHandlerLoadKeyMappings`. Returns `true` on completion (engine's
   * binary always reports success; failure paths emit warnings without aborting).
   */
  [[nodiscard]] bool IN_InitKeyHandler();

  /**
   * Address: 0x008394B0 (FUN_008394B0, Moho::CUIKeyHandler::SetKeyNameTable)
   *
   * What it does:
   * Iterates one Lua key-names table (string keys are hex code spellings like
   * "0x20", values are name strings) and overwrites `in_keyNames[parsedCode]`
   * for each entry. Skips entries whose parsed code is > 0xFF with a warning.
   *
   * Recovered as a file-scope free helper because the engine source models
   * `CUIKeyHandler` as a runtime free-function family rather than a class with
   * static methods (see also `AddUiKeyMapEntries` / `RemoveUiKeyMapEntries` /
   * `ClearUiKeyMaps`).
   */
  void CUIKeyHandlerSetKeyNameTable(const LuaPlus::LuaObject& keyNamesTable);

  /**
   * Address: 0x00839690 (FUN_00839690, Moho::CUIKeyHandler::LoadKeyMappings)
   *
   * What it does:
   * Imports `/lua/keymap/keyNames.lua`, passes its `keyNames` sub-table to
   * `CUIKeyHandlerSetKeyNameTable` to populate `in_keyNames`, then imports
   * `/lua/keymap/keymapper.lua`, invokes `GetKeyMappings()`, and feeds the
   * returned table to `AddUiKeyMapEntries`. Recovered as a file-scope free
   * helper for the same reason as `CUIKeyHandlerSetKeyNameTable`.
   */
  void CUIKeyHandlerLoadKeyMappings();

  /**
   * Address: 0x00839920 (FUN_00839920, Moho::IN_ParseKeyModifiers)
   *
   * What it does:
   * Parses one key-binding token string (`key[-modifier[-modifier...]]`) into
   * one packed keycode/modifier mask lane. The primary token is resolved
   * through `IN_FindKeyNameIndexCi` against the runtime-loaded `in_keyNames`
   * table; modifier tokens ("ALT", "CTRL"/"CONTROL", "SHIFT") OR their
   * corresponding high-bit flags into the result.
   */
  int IN_ParseKeyModifiers(const msvc8::string& keyBindingSpec);

  /**
   * Address: 0x00839F20 (FUN_00839F20, Moho::IN_BindKey)
   *
   * IDA signature:
   * void __cdecl Moho::IN_BindKey(std::vector<std::string>* commandArgs);
   *
   * What it does:
   * The `IN_BindKey` console command. Validates the token vector, parses token
   * 1 as a key mask, joins every token from index 2 with a trailing space, and
   * assigns the result to the key-action map. `register_CConFunc_IN_BindKey`
   * (0x00BE4850) takes this function's address when it registers the command,
   * which is why the declaration has to be visible from `CConCommand.cpp`.
   */
  void IN_BindKey(void* commandArgs);

  /**
   * Address: 0x0083A080 (FUN_0083A080, sub_83A080)
   *
   * IDA signature:
   * void __cdecl sub_83A080(std::vector<std::string>* commandArgs);
   *
   * What it does:
   * The `IN_SetKeyName` console command ("Set a key name to map to a key
   * code", per the PE .data image at the registrar's stru_F5B1AC). Parses
   * token 1 as a hex key code, rejects codes above 0xFF, then either renames
   * `in_keyNames[keyCode]` (when token 2's name isn't already used by
   * another key) or reports the name collision.
   * `register_CConFunc_IN_SetKeyName` (0x00BE48D0) takes this function's
   * address when it registers the command, which is why the declaration
   * has to be visible from `CConCommand.cpp`.
   */
  void IN_SetKeyName(void* commandArgs);

  /**
   * Address: 0x008365B0 (FUN_008365B0, cfunc_ClearCurrentFactoryForQueueDisplay)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_ClearCurrentFactoryForQueueDisplayL`.
   */
  int cfunc_ClearCurrentFactoryForQueueDisplay(lua_State* luaContext);

  /**
   * Address: 0x008365D0 (FUN_008365D0, func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
   *
   * What it does:
   * Publishes global `ClearCurrentFactoryForQueueDisplay()` Lua binder metadata.
   */
  CScrLuaInitForm* func_ClearCurrentFactoryForQueueDisplay_LuaFuncDef();

  /**
   * Address: 0x00836630 (FUN_00836630, cfunc_ClearCurrentFactoryForQueueDisplayL)
   */
  int cfunc_ClearCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BE4690 (FUN_00BE4690, register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef)
   */
  CScrLuaInitForm* register_ClearCurrentFactoryForQueueDisplay_LuaFuncDef();

  /**
   * Address: 0x0083A190 (FUN_0083A190, cfunc_IN_AddKeyMapTable)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to `cfunc_IN_AddKeyMapTableL`.
   */
  int cfunc_IN_AddKeyMapTable(lua_State* luaContext);

  /**
   * Address: 0x0083A1B0 (FUN_0083A1B0, func_IN_AddKeyMapTable_LuaFuncDef)
   *
   * What it does:
   * Publishes global `IN_AddKeyMapTable(keyMapTable)` Lua binder metadata.
   */
  CScrLuaInitForm* func_IN_AddKeyMapTable_LuaFuncDef();

  /**
   * Address: 0x0083A210 (FUN_0083A210, cfunc_IN_AddKeyMapTableL)
   */
  int cfunc_IN_AddKeyMapTableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BE4950 (FUN_00BE4950, register_IN_AddKeyMapTable_LuaFuncDef)
   */
  CScrLuaInitForm* register_IN_AddKeyMapTable_LuaFuncDef();

  /**
   * Address: 0x0083A2B0 (FUN_0083A2B0, cfunc_IN_RemoveKeyMapTable)
   *
   * What it does:
   * Unwraps raw Lua callback state and forwards to
   * `cfunc_IN_RemoveKeyMapTableL`.
   */
  int cfunc_IN_RemoveKeyMapTable(lua_State* luaContext);

  /**
   * Address: 0x0083A2D0 (FUN_0083A2D0, func_IN_RemoveKeyMapTable_LuaFuncDef)
   *
   * What it does:
   * Publishes global `IN_RemoveKeyMapTable(keyMapTable)` Lua binder metadata.
   */
  CScrLuaInitForm* func_IN_RemoveKeyMapTable_LuaFuncDef();

  /**
   * Address: 0x0083A330 (FUN_0083A330, cfunc_IN_RemoveKeyMapTableL)
   */
  int cfunc_IN_RemoveKeyMapTableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BE4960 (FUN_00BE4960, register_IN_RemoveKeyMapTable_LuaFuncDef)
   */
  CScrLuaInitForm* register_IN_RemoveKeyMapTable_LuaFuncDef();

  /**
   * Address: 0x0083A410 (FUN_0083A410, func_IN_ClearKeyMap_LuaFuncDef)
   *
   * What it does:
   * Publishes global `IN_ClearKeyMap()` Lua binder metadata.
   */
  CScrLuaInitForm* func_IN_ClearKeyMap_LuaFuncDef();

  /**
   * Address: 0x00BE4970 (FUN_00BE4970, register_IN_ClearKeyMap_LuaFuncDef)
   */
  CScrLuaInitForm* register_IN_ClearKeyMap_LuaFuncDef();

  /**
   * Binary-backed lazy-var wrapper stored with `LuaPlus::LuaObject` layout.
   */
  struct CScriptLazyVar_float
  {
    std::uint8_t mLuaObjectStorage[sizeof(LuaPlus::LuaObject)]{};

    /**
     * Address: 0x007836E0 (FUN_007836E0, ??0CScriptLazyVar_float@Moho@@QAE@@Z)
     *
     * What it does:
     * Imports `/lua/lazyvar.lua` and initializes this lazy-var from
     * `lazyvar.Create(0.0)`.
     */
    CScriptLazyVar_float() = default;
    explicit CScriptLazyVar_float(LuaPlus::LuaState* state);

    /**
     * Address: 0x00783840 (FUN_00783840, Moho::CScriptLazyVar_float::GetValue)
     *
     * What it does:
     * Resolves lazy-var value lane `1`, evaluating the lazy callback when the
     * lane is nil and coercing error/non-number paths back to `0.0`.
     */
    [[nodiscard]] static float GetValue(const CScriptLazyVar_float* value) noexcept;

    /**
     * Address: 0x007839E0 (FUN_007839E0, Moho::CScriptLazyVar_float::SetValue)
     *
     * What it does:
     * Calls the Lua-side `SetValue` method on this lazy-var with `next`.
     */
    static void SetValue(CScriptLazyVar_float* value, float next) noexcept;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(CScriptLazyVar_float) >= sizeof(LuaPlus::LuaObject),
    "moho::CScriptLazyVar_float must remain at least LuaObject-sized"
  );

  struct CMauiCursorLink
  {
    CMauiCursorLink** ownerHeadLink = nullptr;
    CMauiCursorLink* nextInOwnerChain = nullptr;

    void AssignCursor(CMauiCursor* cursor) noexcept;
    void Unlink() noexcept;
    [[nodiscard]] CMauiCursor* GetCursor() const noexcept;
  };

  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CMauiCursorLink) == 0x8, "moho::CMauiCursorLink size must be 0x8");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiCursorLink, ownerHeadLink) == 0x0, "moho::CMauiCursorLink::ownerHeadLink offset must be 0x0");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorLink, nextInOwnerChain) == 0x4,
    "moho::CMauiCursorLink::nextInOwnerChain offset must be 0x4"
  );

  class CMauiCursor : public CScriptObject
  {
  public:
    /**
     * Address: 0x0078CB50 (FUN_0078CB50, Moho::CMauiCursor::CMauiCursor)
     *
     * What it does:
     * Initializes cursor texture/hotspot runtime lanes and binds one Lua object
     * back-reference.
     */
    explicit CMauiCursor(LuaPlus::LuaObject* luaObject);

    /**
     * Address: 0x0078C9A0 (FUN_0078C9A0, Moho::CMauiCursor::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiCursor`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0078C9C0 (FUN_0078C9C0, Moho::CMauiCursor::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x0078CCA0 (FUN_0078CCA0, Moho::CMauiCursor::SetTexture)
     *
     * What it does:
     * Loads one cursor texture and assigns it to the active cursor texture lane.
     */
    void SetTexture(const char* texturePath);

    /**
     * Address: 0x0078CD80 (FUN_0078CD80, Moho::CMauiCursor::SetDefaultTexture)
     *
     * What it does:
     * Loads one default cursor texture and swaps both active/default lanes when
     * the active lane still points at the previous default.
     */
    void SetDefaultTexture(const char* texturePath);

    /**
     * Address: 0x0078CEA0 (FUN_0078CEA0, Moho::CMauiCursor::ResetToDefault)
     *
     * What it does:
     * Restores active cursor texture/hotspot lanes from default cursor state.
     */
    void ResetToDefault();

    /**
     * Address: 0x0078CBF0 (FUN_0078CBF0, Moho::CMauiCursor::~CMauiCursor body)
     * Address: 0x0078CBD0 (FUN_0078CBD0, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases active/default cursor texture weak-owner lanes and destroys
     * the embedded script object runtime base.
     */
    virtual ~CMauiCursor();

  private:
    /**
     * The cursor's own state block, +0x34 (right after the inherited
     * CScriptObject sub-object) through +0x57. Every field in it is reached
     * through the typed `CMauiCursorTextureRuntimeView` overlay
     * (mTexture/mDefaultTexture at +0x34/+0x3C, hotspot lanes through
     * +0x57) - reserved here rather than re-declared, matching
     * `CMauiControl::mControlStateStorage`. `AllocateZeroedUiObject<
     * CMauiCursor>(0x58u)` at the construction site sizes the allocation
     * explicitly, independent of `sizeof(CMauiCursor)`, but this storage
     * keeps that size assert honest and protects any future construction
     * path that relies on `sizeof(CMauiCursor)`/`operator new` directly.
     */
    std::uint8_t mCursorStateStorage[0x24];
  };

  static_assert(sizeof(CMauiCursor) == 0x58, "moho::CMauiCursor size must be 0x58");

  struct CMauiCursorRuntimeView
  {
    void* vftable = nullptr;
    CMauiCursorLink* ownerChainHead = nullptr;

    [[nodiscard]] static CMauiCursorRuntimeView* FromCursor(CMauiCursor* cursor) noexcept
    {
      return reinterpret_cast<CMauiCursorRuntimeView*>(cursor);
    }

    [[nodiscard]] static const CMauiCursorRuntimeView* FromCursor(const CMauiCursor* cursor) noexcept
    {
      return reinterpret_cast<const CMauiCursorRuntimeView*>(cursor);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorRuntimeView, ownerChainHead) == 0x4,
    "moho::CMauiCursorRuntimeView::ownerChainHead offset must be 0x4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CMauiCursorRuntimeView) == 0x8, "moho::CMauiCursorRuntimeView size must be 0x8");

  struct CMauiCursorTextureRuntimeView : CMauiCursorRuntimeView
  {
    std::uint8_t mUnknown08To33[0x2C]{};
    boost::shared_ptr<RD3DTextureResource> mTexture;        // +0x34
    boost::shared_ptr<RD3DTextureResource> mDefaultTexture; // +0x3C
    bool mIsDefaultTexture = false;                         // +0x44
    bool mIsShowing = false;                                // +0x45
    std::uint8_t mUnknown46To47[0x2]{};
    std::int32_t mHotspotX = 0;        // +0x48
    std::int32_t mHotspotY = 0;        // +0x4C
    std::int32_t mDefaultHotspotX = 0; // +0x50
    std::int32_t mDefaultHotspotY = 0; // +0x54

    [[nodiscard]] static CMauiCursorTextureRuntimeView* FromCursor(CMauiCursor* cursor) noexcept
    {
      return reinterpret_cast<CMauiCursorTextureRuntimeView*>(cursor);
    }

    [[nodiscard]] static const CMauiCursorTextureRuntimeView* FromCursor(const CMauiCursor* cursor) noexcept
    {
      return reinterpret_cast<const CMauiCursorTextureRuntimeView*>(cursor);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mTexture) == 0x34,
    "CMauiCursorTextureRuntimeView::mTexture offset must be 0x34"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultTexture) == 0x3C,
    "CMauiCursorTextureRuntimeView::mDefaultTexture offset must be 0x3C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mIsDefaultTexture) == 0x44,
    "CMauiCursorTextureRuntimeView::mIsDefaultTexture offset must be 0x44"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mIsShowing) == 0x45,
    "CMauiCursorTextureRuntimeView::mIsShowing offset must be 0x45"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mHotspotX) == 0x48,
    "CMauiCursorTextureRuntimeView::mHotspotX offset must be 0x48"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mHotspotY) == 0x4C,
    "CMauiCursorTextureRuntimeView::mHotspotY offset must be 0x4C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultHotspotX) == 0x50,
    "CMauiCursorTextureRuntimeView::mDefaultHotspotX offset must be 0x50"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultHotspotY) == 0x54,
    "CMauiCursorTextureRuntimeView::mDefaultHotspotY offset must be 0x54"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    sizeof(CMauiCursorTextureRuntimeView) == 0x58,
    "CMauiCursorTextureRuntimeView size must be 0x58"
  );

  class CMauiControl : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00782E90 (FUN_00782E90, Moho::CMauiControl::StaticGetClass)
     *
     * What it does:
     * Returns cached reflection type for `CMauiControl`, resolving via RTTI on
     * first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x007867B0 (FUN_007867B0, Moho::CMauiControl::CMauiControl)
     *
     * What it does:
     * Constructs one control from Lua object + parent lanes and stores one
     * control kind tag used by Lua-side MAUI initialization.
     */
    CMauiControl(LuaPlus::LuaObject* luaObject, CMauiControl* parent, msvc8::string controlKind);

    /**
     * Address: 0x00786D00 (FUN_00786D00, Moho::CMauiControl::~CMauiControl)
     * Address: 0x00786A60 (FUN_00786A60, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Invalidates parent ownership, destroys/unlinks child controls, tears down
     * control runtime lanes, then destroys embedded script-object state.
     */
    virtual ~CMauiControl();

    /**
     * Address: 0x00786EF0 (FUN_00786EF0, Moho::CMauiControl::Destroy)
     *
     * What it does:
     * Marks the control invisible/detached, queues it into the root-frame
     * deleted-control list, dispatches `OnDestroy`, then destroys children.
     */
    virtual void Destroy();

    /**
     * Address: 0x00787420 (FUN_00787420, Moho::CMauiControl::Frame)
     *
     * What it does:
     * Invokes script callback `OnFrame(deltaSeconds)` on this control object.
     */
    virtual void Frame(float deltaSeconds);

    /**
     * Address: 0x007871D0 (FUN_007871D0, Moho::CMauiControl::OnMinimized)
     *
     * What it does:
     * Propagates minimized-state notifications to direct/indirect children.
     */
    virtual void OnMinimized(bool minimized);

    /**
     * Address: 0x00786F60 (FUN_00786F60, Moho::CMauiControl::ClearChildren)
     *
     * What it does:
     * Unlinks each direct child from the intrusive child list and dispatches
     * virtual destroy on each child control.
     */
    virtual void ClearChildren();

    /**
     * Address: 0x00786FA0 (FUN_00786FA0, Moho::CMauiControl::Render)
     *
     * What it does:
     * Refreshes per-control resolved depth values for this subtree, rebuilds the
     * visible rendered-child lane when invalidated or depth-changed, then sorts
     * the lane by depth.
     */
    virtual void Render();

    /**
     * Address: 0x00787160 (FUN_00787160, Moho::CMauiControl::DoRender)
     *
     * What it does:
     * Default no-op render dispatch for controls that do not draw.
     */
    virtual void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask);

    /**
     * Address: 0x007871C0 (FUN_007871C0, Moho::CMauiControl::IsHidden)
     *
     * What it does:
     * Returns hidden-state lane for this control.
     */
    [[nodiscard]] virtual bool IsHidden();

    /**
     * Address: 0x00787170 (FUN_00787170, Moho::CMauiControl::SetHidden)
     *
     * What it does:
     * Calls `OnHide(hidden)` and, when not consumed, updates the hidden lane
     * and propagates the same hidden state to child controls.
     */
    virtual void SetHidden(bool hidden);

    /**
     * Address: 0x0078A700 (FUN_0078A700, Moho::CMauiControl::OnHide)
     *
     * What it does:
     * Invokes `OnHide(self, hidden)` script callback and returns Lua bool
     * result when callback is present.
     */
    [[nodiscard]] bool OnHide(const bool& hidden);

    /**
     * Address: 0x007876D0 (FUN_007876D0, Moho::CMauiControl::IsScrollable)
     *
     * What it does:
     * Converts axis enum to lexical token and queries script-side
     * `IsScrollable(axisText)` callback.
     */
    [[nodiscard]] virtual bool IsScrollable(EMauiScrollAxis axis);

    /**
     * Address: 0x0078AA00 (FUN_0078AA00, Moho::CMauiControl::GetIsScrollable)
     *
     * What it does:
     * Invokes `IsScrollable(self, axisText)` script callback and returns Lua
     * bool result when callback is present.
     */
    [[nodiscard]] bool GetIsScrollable(const char* axisLexical);

    /**
     * Address: 0x00787270 (FUN_00787270, Moho::CMauiControl::HitTest)
     *
     * What it does:
     * Returns whether `(x,y)` lies inside the control bounds.
     */
    [[nodiscard]] virtual bool HitTest(float x, float y);

    /**
     * Address: 0x00787210 (FUN_00787210, Moho::CMauiControl::DisableHitTest)
     *
     * What it does:
     * Sets hit-test disabled state and optionally applies it recursively to
     * child controls.
     */
    virtual void DisableHitTest(bool disableHitTest, bool applyChildren);

    /**
     * Address: 0x00787260 (FUN_00787260, Moho::CMauiControl::IsHitTestDisabled)
     *
     * What it does:
     * Returns hit-test disabled state for this control.
     */
    [[nodiscard]] virtual bool IsHitTestDisabled();

    /**
     * Address: 0x00787780 (FUN_00787780, Moho::CMauiControl::ScrollLines)
     *
     * What it does:
     * Invokes script callback `ScrollLines(axisText, amount)`.
     */
    virtual void ScrollLines(EMauiScrollAxis axis, float amount);

    /**
     * Address: 0x00787830 (FUN_00787830, Moho::CMauiControl::ScrollPages)
     *
     * What it does:
     * Invokes script callback `ScrollLines(axisText, amount)` for page-scroll
     * requests (binary callback name lane).
     */
    virtual void ScrollPages(EMauiScrollAxis axis, float amount);

    /**
     * Address: 0x007878E0 (FUN_007878E0, Moho::CMauiControl::ScrollSetTop)
     *
     * What it does:
     * Invokes script callback `ScrollSetTop(axisText, amount)`.
     */
    virtual void ScrollSetTop(EMauiScrollAxis axis, float amount);

    /**
     * Address: 0x007873A0 (FUN_007873A0, Moho::CMauiControl::HandleEvent)
     *
     * What it does:
     * Builds Lua event payload and invokes `HandleEvent(self, event)` callback.
     */
    [[nodiscard]] virtual bool HandleEvent(const SMauiEventData& eventData);

    /**
     * Address: 0x00787370 (FUN_00787370, Moho::CMauiControl::PostEvent)
     *
     * What it does:
     * Dispatches one event to this control and then walks parent controls
     * until one handler returns true.
     */
    void PostEvent(const SMauiEventData& eventData);

    /**
     * Address: 0x0077F690 (FUN_0077F690, Moho::CMauiControl::Left)
     *
     * What it does:
     * Returns writable reference to the left-edge lazy-var lane.
     */
    [[nodiscard]] CScriptLazyVar_float& Left();

    /**
     * Address: 0x0077F6A0 (FUN_0077F6A0, Moho::CMauiControl::Right)
     *
     * What it does:
     * Returns writable reference to the right-edge lazy-var lane.
     */
    [[nodiscard]] CScriptLazyVar_float& Right();

    /**
     * Address: 0x0077F6B0 (FUN_0077F6B0, Moho::CMauiControl::Top)
     *
     * What it does:
     * Returns writable reference to the top-edge lazy-var lane.
     */
    [[nodiscard]] CScriptLazyVar_float& Top();

    /**
     * Address: 0x0077F6C0 (FUN_0077F6C0, Moho::CMauiControl::Bottom)
     *
     * What it does:
     * Returns writable reference to the bottom-edge lazy-var lane.
     */
    [[nodiscard]] CScriptLazyVar_float& Bottom();

    /**
     * Address: 0x0077F6D0 (FUN_0077F6D0, Moho::CMauiControl::GetVertexAlpha)
     *
     * What it does:
     * Returns packed ARGB vertex-alpha color lane.
     */
    [[nodiscard]] std::uint32_t GetVertexAlpha();

    /**
     * Address: 0x0077F6E0 (FUN_0077F6E0, Moho::CMauiControl::SetNeedsFrameUpdate)
     *
     * What it does:
     * Updates frame-update-needed flag lane.
     */
    void SetNeedsFrameUpdate(bool needsFrameUpdate);

    /**
     * Address: 0x00786AA0 (FUN_00786AA0, Moho::CMauiControl::Invalidate)
     *
     * What it does:
     * Marks this control and its parent chain as invalidated.
     */
    void Invalidate();

    /**
     * Address: 0x00786AD0 (FUN_00786AD0, Moho::CMauiControl::SetParent)
     *
     * What it does:
     * Reparents this control into a new parent-child intrusive list lane and
     * invalidates affected controls.
     */
    void SetParent(CMauiControl* newParent);

    /**
     * Address: 0x00786E90 (FUN_00786E90, Moho::CMauiControl::DoInit)
     *
     * What it does:
     * Invokes script callback `OnInit` on this control object.
     */
    virtual void DoInit();

    /**
     * Address: 0x00786EA0 (FUN_00786EA0, Moho::CMauiControl::DepthFirstSuccessor)
     *
     * What it does:
     * Returns the next control in depth-first order, constrained to one root
     * subtree.
     */
    [[nodiscard]] CMauiControl* DepthFirstSuccessor(CMauiControl* subtreeRoot);

    /**
     * Address: 0x00786380 (FUN_00786380, Moho::CMauiControl::GetParent)
     *
     * What it does:
     * Returns owning parent control lane.
     */
    [[nodiscard]] CMauiControl* GetParent() const;

    /**
     * Address: 0x00786390 (FUN_00786390, Moho::CMauiControl::GetRootFrame)
     *
     * What it does:
     * Returns cached root-frame owner lane.
     */
    [[nodiscard]] CMauiFrame* GetRootFrame();

    /**
     * Address: 0x00786440 (FUN_00786440, Moho::CMauiControl::GetAlpha)
     *
     * What it does:
     * Returns current alpha lane used by control rendering.
     */
    [[nodiscard]] float GetAlpha();

    /**
     * Address: 0x00786450 (FUN_00786450, Moho::CMauiControl::IsInvisible)
     *
     * What it does:
     * Returns whether this control is currently marked invisible.
     */
    [[nodiscard]] bool IsInvisible();

    /**
     * Address: 0x007863F0 (FUN_007863F0, Moho::CMauiControl::SetAlpha)
     *
     * What it does:
     * Stores scalar alpha and updates packed vertex-alpha color lane.
     */
    void SetAlpha(float alpha);

    /**
     * Address: 0x0078EC10 (FUN_0078EC10, Moho::CMauiControl::AdjustARGBAlpha)
     *
     * What it does:
     * Replaces the input ARGB alpha channel with this control's current alpha
     * lane while preserving RGB channels.
     */
    [[nodiscard]] std::uint32_t AdjustARGBAlpha(std::uint32_t color);

    /**
     * Address: 0x00786460 (FUN_00786460, Moho::CMauiControl::SetRenderPass)
     *
     * What it does:
     * Updates integer render-pass lane.
     */
    void SetRenderPass(std::int32_t renderPass);

    /**
     * Address: 0x00786470 (FUN_00786470, Moho::CMauiControl::GetRenderPass)
     *
     * What it does:
     * Returns integer render-pass lane.
     */
    [[nodiscard]] std::int32_t GetRenderPass();

    /**
     * FAF community binary-patch addition, not part of the original 2007
     * binary (no `Address:` -- there is no shipped-1.5-era body to cite).
     * See `FAForever/FA-Binary-Patches` PRs #47/#111/#112, and
     * `gamedata/lua/ui/controls/components/worldviewshapecomponent.lua`
     * (`AddShape`/`RemoveShape`/`OnRenderWorld`), which is what this exists
     * to support. Enables or disables the per-frame `OnRenderWorld(delta)`
     * script callback for this control while it is being drawn.
     *
     * What it does:
     * Sets whether this control receives a custom per-frame render callback.
     */
    void SetCustomRender(bool enabled);

    /**
     * FAF community binary-patch addition (see `SetCustomRender`).
     *
     * What it does:
     * Returns whether this control's custom per-frame render callback is
     * currently enabled.
     */
    [[nodiscard]] bool GetCustomRender() const;

    /**
     * Address: 0x00786480 (FUN_00786480, Moho::CMauiControl::NeedsFrameUpdate)
     *
     * What it does:
     * Returns current frame-update-needed flag lane.
     */
    [[nodiscard]] bool NeedsFrameUpdate();

    /**
     * Address: 0x007874B0 (FUN_007874B0, Moho::CMauiControl::GetScrollValues)
     *
     * What it does:
     * Calls script callback `GetScrollValues(axisLexical)` and returns
     * `{minRange,maxRange,minVisible,maxVisible}` numeric lanes when all four
     * results are provided.
     */
    virtual SMauiScrollValues GetScrollValues(EMauiScrollAxis axis);

    /**
     * Address: 0x00787990 (FUN_00787990, Moho::CMauiControl::ApplyFunction)
     *
     * What it does:
     * Calls one Lua function with this control and each direct child control.
     */
    void ApplyFunction(const LuaPlus::LuaObject& functionObject);

    /**
     * Address: 0x00787440 (FUN_00787440, Moho::CMauiControl::LosingKeyboardFocus)
     *
     * What it does:
     * Invokes `OnLoseKeyboardFocus` callback on this control script object.
     */
    virtual void LosingKeyboardFocus();

    /**
     * Address: 0x00787450 (FUN_00787450, Moho::CMauiControl::OnKeyboardFocusChange)
     *
     * What it does:
     * Invokes `OnKeyboardFocusChange` callback on this control script object.
     */
    virtual void OnKeyboardFocusChange();

    /**
     * Address: 0x00787460 (FUN_00787460, Moho::CMauiControl::AcquireKeyboardFocus)
     *
     * What it does:
     * Routes one focus-acquire request through global MAUI focus ownership.
     */
    virtual void AcquireKeyboardFocus(bool blocksKeyDown);

    /**
     * Address: 0x00787480 (FUN_00787480, Moho::CMauiControl::AbandonKeyboardFocus)
     *
     * What it does:
     * Clears global keyboard focus when this control currently owns it.
     */
    virtual void AbandonKeyboardFocus();

    /**
     * Address: 0x0077F6F0 (FUN_0077F6F0, Moho::CMauiControl::GetDebugName)
     *
     * What it does:
     * Returns one copied debug-name string from the control runtime lane.
     */
    [[nodiscard]] msvc8::string GetDebugName();

    /**
     * Address: 0x0077F720 (FUN_0077F720, Moho::CMauiControl::SetDebugName)
     *
     * What it does:
     * Copies one debug-name string into the control debug-name lane.
     */
    void SetDebugName(msvc8::string debugName);

    /**
     * Address: 0x00786B40 (FUN_00786B40, Moho::CMauiControl::Dump)
     *
     * What it does:
     * Logs debug identity/state and resolved layout lazy-vars for this control.
     */
    virtual void Dump();

    /**
     * Address: 0x007872E0 (FUN_007872E0, Moho::CMauiControl::GetTopmostControl)
     *
     * What it does:
     * Scans one control subtree and returns topmost depth-matching visible
     * control under `(x,y)`.
     */
    [[nodiscard]] static CMauiControl* GetTopmostControl(CMauiControl* root, float x, float y);

  protected:
    /**
     * The control's own state block, +0x34 (right after the inherited
     * CScriptObject sub-object) through +0x11B. Every field in it is reached
     * through the typed `CMauiControl*RuntimeView` overlays -
     * `CMauiControlRuntimeView`/`CMauiControlHierarchyRuntimeView` for the
     * parent/children lists and layout lazy-vars (starting at +0x34, right
     * where this storage begins), and `CMauiControlExtendedRuntimeView` for
     * the render lanes - so it is reserved here rather than re-declared.
     *
     * Ground truth (`FUN_007867B0.c`) opens with
     * `Moho::CScriptObject::CScriptObject(this)` before touching any of these
     * fields, and `dumps/rtti_dump_all.hpp` lists CScriptObject as
     * CMauiControl's first real base (mdisp=0) - this storage's own
     * "+0x00..+0x33 unknown" prefix, before this class inherited
     * CScriptObject for real, was that exact sub-object modelled as raw
     * bytes instead of a base.
     *
     * Reserving it is not cosmetic. Without it a derived class that adds a
     * second base gets that base immediately after CScriptObject, straight on
     * top of the parent-list link: `CMauiScrollbar`'s `IMauiDragger` vptr
     * landed there and every scrollbar destroyed afterwards walked a vtable
     * address as if it were a weak-link node and faulted writing to .rdata.
     */
    std::uint8_t mControlStateStorage[0xE8];
  };

  static_assert(sizeof(CMauiControl) == 0x11C, "moho::CMauiControl size must be 0x11C");

  class CMauiEdit : public CMauiControl
  {
    // The embedded click-dragger sub-object routes its IMauiDragger::DragRelease
    // slot to the (private) CMauiEdit::DragRelease release hit-test lane.
    friend class CMauiEditClickDragger;

  public:
    /**
     * Address: 0x0078EFE0 (FUN_0078EFE0, Moho::CMauiEdit::CMauiEdit)
     *
     * What it does:
     * Constructs one edit control from Lua object + parent lanes and initializes
     * default edit/font/caret state.
     */
    CMauiEdit(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x0078EC80 (FUN_0078EC80, Moho::CMauiEdit::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiEdit`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0078ECA0 (FUN_0078ECA0, Moho::CMauiEdit::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x0078F720 (FUN_0078F720, Moho::CMauiEdit::Frame)
     *
     * What it does:
     * Dispatches script `OnFrame(delta)` and updates the caret blink-phase
     * alpha lane from configured on/off alpha cycle parameters.
     */
    void Frame(float deltaSeconds) override;

    /**
     * Address: 0x0078F820 (FUN_0078F820, Moho::CMauiEdit::DoRender)
     *
     * What it does:
     * Draws edit background, clipped text runs, selection highlight, drop
     * shadow, and caret geometry.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x00790470 (FUN_00790470, Moho::CMauiEdit::HandleEvent)
     *
     * What it does:
     * Routes mouse-button press/double-click lanes to click handling and
     * dispatches character events to edit-key processing.
     */
    [[nodiscard]] bool HandleEvent(const SMauiEventData& eventData) override;

    /**
     * Address: 0x0078F330 (FUN_0078F330, Moho::CMauiEdit::AbandonKeyboardFocus)
     *
     * What it does:
     * Hides caret rendering and clears global keyboard focus when this edit
     * control currently owns it.
     */
    void AbandonKeyboardFocus() override;

    /**
     * Address: 0x007915A0 (FUN_007915A0, Moho::CMauiEdit::LosingKeyboardFocus)
     *
     * What it does:
     * Drops keyboard focus through the virtual abandon lane, then dispatches
     * `OnLoseKeyboardFocus` script callback.
     */
    void LosingKeyboardFocus() override;

    /**
     * Address: 0x0078EDD0 (FUN_0078EDD0, Moho::CMauiEdit::GetText)
     *
     * What it does:
     * Returns one copy of the current edit text lane.
     */
    [[nodiscard]] msvc8::string GetText();

    /**
     * Address: 0x007906F0 (FUN_007906F0, Moho::CMauiEdit::GetSelection)
     *
     * What it does:
     * Returns the currently selected UTF-8 substring from the edit text lane.
     */
    [[nodiscard]] msvc8::string GetSelection();

    /**
     * Address: 0x0078F380 (FUN_0078F380, Moho::CMauiEdit::SetText)
     *
     * What it does:
     * Applies one UTF-8 text lane (clamped by max chars), refreshes caret/clip
     * state, and emits `OnTextChanged` callback when reentrancy guard allows.
     */
    void SetText(const msvc8::string& text);

    /**
     * Address: 0x0078F4C0 (FUN_0078F4C0, Moho::CMauiEdit::ClearText)
     *
     * What it does:
     * Clears current edit text/caret/selection lanes and emits
     * `OnTextChanged` when callback reentrancy guard allows.
     */
    void ClearText();

    /**
     * Address: 0x007911B0 (FUN_007911B0, Moho::CMauiEdit::SetCaretPosition)
     *
     * What it does:
     * Updates caret position and adjusts clip-left/right window when the caret
     * crosses the visible text range.
     */
    void SetCaretPosition(int position);

    /**
     * Address: 0x0078F570 (FUN_0078F570, Moho::CMauiEdit::SetMaxChars)
     *
     * What it does:
     * Stores one max-char limit and truncates current edit text to that UTF-8
     * character count when needed.
     */
    void SetMaxChars(int newMaxChars);

    /**
     * Address: 0x0078F280 (FUN_0078F280, Moho::CMauiEdit::Dump)
     *
     * What it does:
     * Logs base CMauiControl state, then logs CMauiEdit-specific colors,
     * background visibility, max-char limit, and current text content.
     */
    void Dump() override;

    /**
     * Address: 0x0078F1B0 (FUN_0078F1B0, Moho::CMauiEdit::~CMauiEdit)
     * Address: 0x0078F190 (FUN_0078F190, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     * Mangled: ??1CMauiEdit@Moho@@QAE@XZ
     *
     * What it does:
     * Releases edit text/font ownership lanes, clears click-dragger intrusive
     * link nodes, and then tears down the `CMauiControl` base.
     */
    ~CMauiEdit() override;

  private:
    /**
     * Address: 0x00790510 (FUN_00790510, Moho::CMauiEdit::NonTextKeyPressed)
     *
     * What it does:
     * Builds one Lua event payload and invokes `OnNonTextKeyPressed(key,event)`.
     */
    void NonTextKeyPressed(int keyCode, SMauiEventData* eventData);

    /**
     * Address: 0x007904D0 (FUN_007904D0, Moho::CMauiEdit::EnterPressed)
     *
     * What it does:
     * Invokes `OnEnterPressed(self, text)` and returns the script bool result.
     */
    [[nodiscard]] bool EnterPressed();

    /**
     * Address: 0x007904F0 (FUN_007904F0, Moho::CMauiEdit::EscPressed)
     *
     * What it does:
     * Invokes `OnEscPressed(self, text)` and returns the script bool result.
     */
    [[nodiscard]] bool EscPressed();

    /**
     * Address: 0x007907B0 (FUN_007907B0, IDA: Moho::CMauiEdit::ClearSelection)
     *
     * What it does:
     * Types one character over the current selection. IDA's name and signature
     * are both wrong - the function takes the character as a second stack
     * argument and inserts it; see the definition for the evidence.
     */
    void InsertChar(wchar_t character);

    /**
     * Address: 0x00790830 (FUN_00790830, Moho::CMauiEdit::ReplaceSelection)
     *
     * What it does:
     * Deletes the current selection lane and inserts replacement UTF-8 text
     * (clamped against max-char limit) at the caret.
     */
    void ReplaceSelection(const msvc8::string& replacementText);

    /**
     * Address: 0x00790590 (FUN_00790590, Moho::CMauiEdit::DeleteSelection)
     *
     * What it does:
     * Deletes the current UTF-8 selection range, updates caret/clip lanes, and
     * emits `OnTextChanged` unless callback suppression is requested.
     */
    void DeleteSelection(bool suppressCallback);

    /**
     * Address: 0x00790B40 (FUN_00790B40, Moho::CMauiEdit::DeleteCharAtCaret)
     *
     * What it does:
     * Deletes either the selected range or one UTF-8 character at/left of the
     * caret, then refreshes clip state and emits `OnTextChanged`.
     */
    void DeleteCharAtCaret(bool deleteToRight);

    /**
     * Address: 0x00791250 (FUN_00791250, Moho::CMauiEdit::MoveCaretLeft)
     *
     * What it does:
     * Moves caret left by `amount` UTF-8 characters, clamped to start of text.
     */
    void MoveCaretLeft(int amount);

    /**
     * Address: 0x00791270 (FUN_00791270, Moho::CMauiEdit::MoveCaretRight)
     *
     * What it does:
     * Moves caret right by `amount` UTF-8 characters via `SetCaretPosition`.
     */
    void MoveCaretRight(int amount);

    /**
     * Address: 0x00791290 (FUN_00791290, Moho::CMauiEdit::MoveSelectionLeft)
     *
     * What it does:
     * Extends or contracts current selection toward the left by `amount`
     * characters and updates caret/selection anchors accordingly.
     */
    void MoveSelectionLeft(int amount);

    /**
     * Address: 0x00791310 (FUN_00791310, Moho::CMauiEdit::MoveSelectionRight)
     *
     * What it does:
     * Extends or contracts current selection toward the right by `amount`
     * characters and updates caret/selection anchors accordingly.
     */
    void MoveSelectionRight(int amount);

    /**
     * Address: 0x007915C0 (FUN_007915C0, Moho::CMauiEdit::HandleClickEvent)
     *
     * What it does:
     * Handles left-button click/double-click lanes by focusing the control,
     * posting dragger capture, and updating caret/word-selection lanes.
     */
    void HandleClickEvent(SMauiEventData* eventData);

    /**
     * Address: 0x00791780 (FUN_00791780, Moho::CMauiEdit::HandleKeyEvent)
     *
     * What it does:
     * Processes keyboard edit operations (caret movement, selection growth,
     * delete/backspace, clipboard shortcuts, and text/non-text key dispatch).
     */
    void HandleKeyEvent(SMauiEventData* eventData);

    /**
     * Address: 0x007914C0 (FUN_007914C0, Moho::CMauiEdit::DragRelease)
     *
     * What it does:
     * Computes release hit-testing against the clipped edit text and clears the
     * selection lane when the drag did not move away from its start position.
     */
    void DragRelease(const SMauiEventData* eventData);

    /**
     * Address: 0x00794F20 (FUN_00794F20, Moho::CMauiEdit::TextChanged)
     *
     * What it does:
     * Invokes script callback `OnTextChanged(self, newText, oldText)` when
     * present while holding the weak-object callback guard lane.
     */
    void TextChanged(const msvc8::string& newText, const msvc8::string& oldText);
  };

  /**
   * The edit control's embedded click-dragger sub-object.
   *
   * Layout: this is the concrete `IMauiDragger`-derived object that the binary
   * embeds inside `CMauiEdit` at offset +0x11C (see
   * `CMauiEditRuntimeView::mClickDragger`). Constructing it installs the
   * CMauiEdit-specific IMauiDragger override vtable
   * `??_7CMauiEdit@Moho@@6BIMauiDragger@Moho@@@` (VA 0x00E395CC), reproducing the
   * secondary-vptr write at asm 0x0078F04A in the `CMauiEdit` constructor.
   *
   * Vtable slots (from the binary at VA 0x00E395CC):
   *   slot 0 (0x00795A00) scalar-deleting dtor thunk (compiler-generated)
   *   slot 1 (0x007913A0) DragMove   -> Moho::CMauiEditDragMove (FUN_007913A0)
   *   slot 2 (0x007914C0) DragRelease -> Moho::CMauiEdit::DragRelease
   *   slot 3 (0x00791590) OnCurrentDraggerReplaced -> no-op (FUN_00791590)
   *
   * Size is exactly 0x08 - both dwords come from the `IMauiDragger` base
   * (vtable @+0x00, `WeakObject::weakLinkHead_` @+0x04), so this class adds no
   * storage of its own. It occupies the same 8 bytes the raw
   * `mClickDraggerStorage[0x8]` overlay used; `CMauiEdit`'s total layout/size
   * is unchanged.
   */
  class CMauiEditClickDragger final : public IMauiDragger
  {
  public:
    CMauiEditClickDragger() = default;
    ~CMauiEditClickDragger() override = default;

    /**
     * Address: 0x007913A0 (FUN_007913A0, Moho::CMauiEdit::DragMove)
     *
     * Routes the click-dragger drag-move slot to the recovered
     * `Moho::CMauiEditDragMove` free function, which unadjusts this MI
     * sub-object pointer back to the owning `CMauiEdit`.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x007914C0 (FUN_007914C0, Moho::CMauiEdit::DragRelease)
     *
     * Routes the click-dragger release slot to the owning edit's
     * `CMauiEdit::DragRelease` after unadjusting this MI sub-object pointer.
     */
    void DragRelease(const SMauiEventData* eventData) override;

    /**
     * Address: 0x00791590 (FUN_00791590, Moho::CMauiEdit::OnCurrentDraggerReplaced)
     *
     * No-op replace hook for the edit's click-dragger lane.
     */
    void OnCurrentDraggerReplaced() override;

    // No storage of its own: the whole sub-object is the `IMauiDragger` base
    // (vptr +0x00, `WeakObject::weakLinkHead_` +0x04).
  };

  static_assert(sizeof(CMauiEditClickDragger) == 0x8, "moho::CMauiEditClickDragger size must be 0x8");

  class CMauiFrame : public CMauiControl
  {
  public:
    /**
     * Address: 0x00796360 (FUN_00796360, ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z)
     * Mangled: ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z
     *
     * LuaPlus::LuaObject* luaObject, CMauiControl* parent
     *
     * IDA signature:
     * Moho::CMauiFrame *__stdcall Moho::CMauiFrame::CMauiFrame(Moho::CMauiFrame *this, LuaPlus::LuaObject *luaObject, Moho::CMauiControl *parent);
     *
     * What it does:
     * Constructs one frame root lane, initializes weak-self/deleted-control
     * sentinel state, installs one wx event-mapper owned by the frame, and
     * marks this control as its own root-frame owner.
     */
    CMauiFrame(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x00796000 (FUN_00796000, Moho::CMauiFrame::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiFrame`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00796020 (FUN_00796020, Moho::CMauiFrame::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x00796460 (FUN_00796460, ??1CMauiFrame@Moho@@UAE@XZ)
     * Deleting thunk: 0x00796440 (FUN_00796440, Moho::CMauiFrame::dtr)
     *
     * What it does:
     * Purges pending deleted controls, releases one frame-owned wx event mapper,
     * unlinks the deleted-control sentinel, and then tears down base control
     * state.
     */
    ~CMauiFrame() override;

    /**
     * Address: 0x00796510 (FUN_00796510, Moho::CMauiFrame::PurgeDeleted)
     *
     * What it does:
     * Deletes all controls queued in this frame's deleted-control intrusive
     * list and restores the list to empty-sentinel state.
     */
    void PurgeDeleted();

    /**
     * Address: 0x007961B0 (FUN_007961B0, Moho::CMauiFrame::Create)
     *
     * What it does:
     * Imports `/lua/maui/frame.lua`, calls `Frame()`, converts the Lua return
     * payload to a `CMauiFrame*`, and returns it as shared ownership.
     */
    [[nodiscard]] static boost::shared_ptr<CMauiFrame> Create(LuaPlus::LuaState* state);

    /**
     * Address: 0x00796680 (FUN_00796680, Moho::CMauiFrame::GetTopmostDepth)
     *
     * What it does:
     * Scans descendants and returns maximum control depth lane.
     */
    [[nodiscard]] float GetTopmostDepth();

    /**
     * Address: 0x007966F0 (FUN_007966F0, Moho::CMauiFrame::DumpGraph)
     *
     * What it does:
     * Walks this frame subtree depth-first and calls `Dump()` for each control.
     */
    void DumpGraph();

    /**
     * Address: 0x00796550 (FUN_00796550, Moho::CMauiFrame::SetBounds)
     *
     * What it does:
     * Resets frame origin to `(0, 0)` and stores new width/height lazy-var
     * lanes from integer pixel bounds.
     */
    void SetBounds(int width, int height);

    /**
     * Address: 0x00796720 (FUN_00796720, Moho::CMauiFrame::Dump)
     *
     * What it does:
     * Logs base control debug state and this frame's event-handler lane id.
     */
    void Dump() override;

    /**
     * Address: 0x007870F0 (FUN_007870F0)
     *
     * What it does:
     * Walks this frame's flattened rendered-children lane and dispatches the
     * virtual render call for every visible child whose render-pass mask
     * intersects the requested draw mask.
     *
     * Not virtual, and deliberately NOT named DoRender. IDA labels 0x007870F0
     * "Moho::CMauiFrame::DoRender", but that name is inferred - the address
     * carries no mangled symbol, unlike the base
     * ?DoRender@CMauiControl@Moho@@UAEXPAVCD3DPrimBatcher@2@I@Z at 0x00787160.
     * 0x007870F0 has no data xrefs at all, so it is in no vtable; it is reached
     * by three direct calls, from CUIManager::RenderFrames (0x0084D5AE),
     * CUIManager::DrawUI (0x0084D62E) and CUIManager::DrawHead (0x0084D6AE).
     * It also takes `this` in edi rather than ecx, which a virtual member
     * would not. The DoRender slot of ??_7CMauiFrame@Moho@@6B@ holds
     * CMauiControl::DoRender - the no-op default - exactly as the base
     * declares it, so the frame does not override the virtual at all.
     *
     * That distinction is load-bearing. CMauiControl::Render seeds the
     * rendered-children lane with the subtree root itself, so a frame is always
     * the first entry in its own lane - confirmed live: a frame's lane held
     * three entries with entry 0 pointing back at the frame. The `[edx+18h]`
     * dispatch this function performs on each entry therefore reaches the frame
     * again and must land on the base no-op. Declaring this as an override of
     * DoRender sent it back here instead and the frame recursed into itself
     * until the stack gave out. Dropping `override` alone does not help - a
     * derived function with the base's signature overrides whether or not the
     * keyword is written - which is why this carries its own name.
     */
    void RenderChildControls(CD3DPrimBatcher* primBatcher, std::int32_t drawMask);

    /**
     * Address: 0x007965A0 (FUN_007965A0, Moho::CMauiFrame::Frame)
     *
     * IDA signature:
     * void __thiscall Moho::CMauiFrame::Frame(Moho::CMauiFrame *this, float deltaSeconds);
     *
     * What it does:
     * Pins this frame via a weak-to-shared upgrade through `mSelfWeak`, walks
     * each descendant control depth-first, dispatches the per-control `Frame`
     * virtual on every visible control that has `mNeedsFrameUpdate` set, then
     * purges any controls queued for deletion by this frame this cycle. The
     * pinning lock keeps the frame and its subtree alive across re-entrant
     * `Frame` callbacks that may add or remove controls.
     */
    void Frame(float deltaSeconds) override;

    /**
     * Address: 0x00796740 (FUN_00796740, Moho::CMauiFrame::DumpControlsUnder)
     *
     * What it does:
     * Walks this frame subtree depth-first, hit-tests each control at `(x,y)`,
     * and dumps every control that is under the cursor.
     */
    static void DumpControlsUnder(CMauiFrame* frame, float x, float y);
  };

  class CMauiBitmap : public CMauiControl
  {
  public:
    /**
     * Address: 0x0077F950 (FUN_0077F950, Moho::CMauiBitmap::CMauiBitmap)
     *
     * What it does:
     * Constructs one bitmap control from Lua object + parent lanes and
     * initializes bitmap lazy-var/render state.
     */
    CMauiBitmap(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x0077F7A0 (FUN_0077F7A0, Moho::CMauiBitmap::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiBitmap`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0077F7C0 (FUN_0077F7C0, Moho::CMauiBitmap::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x00780270 (FUN_00780270, Moho::CMauiBitmap::Frame)
     *
     * What it does:
     * Dispatches the bitmap `OnFrame` script callback and advances the active
     * animation timer, wrapping to `OnPatternEnd()` when the current frame
     * duration elapses.
     */
    void Frame(float deltaSeconds) override;

    /**
     * Address: 0x007800C0 (FUN_007800C0)
     *
     * What it does:
     * Stops animated playback and dispatches `OnAnimationStopped` when active
     * multi-frame texture state is present.
     */
    void StopAnimationPlayback();

    /**
     * Address: 0x0077FF70 (FUN_0077FF70, Moho::CMauiBitmap::HitTest)
     *
     * What it does:
     * Runs base control bounds hit-test, then applies bitmap hit-mask or
     * per-pixel alpha hit-testing lanes when configured.
     */
    [[nodiscard]] bool HitTest(float x, float y) override;

    /**
     * Address: 0x00780850 (FUN_00780850, Moho::CMauiBitmap::Draw)
     *
     * IDA signature:
     * void __thiscall Moho::CMauiBitmap::Draw(
     *     CMauiBitmap* this, CD3DPrimBatcher* primBatcher);
     *
     * What it does:
     * Renders the current animation frame's texture batch over the control
     * bounds, as a tiled quad when tiling is enabled or a UV-clipped quad
     * otherwise. No-op when no frames/textures are bound. Occupies the
     * CMauiControl::DoRender vtable slot (drawMask is unused).
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x0077FCF0 (FUN_0077FCF0, Moho::CMauiBitmap::ShareTextures)
     *
     * What it does:
     * Copies texture-batch lanes from `sourceBitmap` into this bitmap and
     * refreshes bitmap width/height lazy-vars from frame `0`.
     */
    void ShareTextures(CMauiBitmap* sourceBitmap);

    /**
     * Address: 0x0077FD90 (FUN_0077FD90, Moho::CMauiBitmap::SetTexture)
     *
     * What it does:
     * Appends one texture lane to this bitmap texture-batch list.
     */
    void SetTexture(const boost::shared_ptr<CD3DBatchTexture>& texture);

    /**
     * Address: 0x00780110 (FUN_00780110, Moho::CMauiBitmap::SetFrame)
     *
     * What it does:
     * Clamps requested frame index to available frame range and stores it.
     */
    std::int32_t SetFrame(std::int32_t frameIndex);

    /**
     * Address: 0x007802D0 (FUN_007802D0, Moho::CMauiBitmap::SetFramePattern)
     *
     * What it does:
     * Rebuilds frame-pattern lanes from Lua-provided frame-order values.
     */
    void SetFramePattern(const msvc8::vector<std::int32_t>& framePattern);

    /**
     * Address: 0x00780420 (FUN_00780420, Moho::CMauiBitmap::SetForwardPattern)
     *
     * What it does:
     * Rebuilds frame-pattern lanes to play texture batches forward.
     */
    void SetForwardPattern();

    /**
     * Address: 0x007804E0 (FUN_007804E0, Moho::CMauiBitmap::SetBackwardPattern)
     *
     * What it does:
     * Rebuilds frame-pattern lanes to play texture batches backward.
     */
    void SetBackwardPattern();

    /**
     * Address: 0x007805B0 (FUN_007805B0, Moho::CMauiBitmap::SetPingPongPattern)
     *
     * What it does:
     * Rebuilds one ping-pong frame sequence that returns to frame `0`.
     */
    void SetPingPongPattern();

    /**
     * Address: 0x00780700 (FUN_00780700, Moho::CMauiBitmap::SetLoopPingPongPattern)
     *
     * What it does:
     * Rebuilds one loop-friendly ping-pong sequence that excludes endpoint
     * duplicates.
     */
    void SetLoopPingPongPattern();

  private:
    /**
     * Address: 0x00780160 (FUN_00780160, Moho::CMauiBitmap::OnPatternEnd)
     *
     * What it does:
     * Advances frame-pattern playback, handles loop/end behavior, and emits
     * `OnAnimationFinished`/`OnAnimationFrame` callbacks.
     */
    void OnPatternEnd();

  public:
    /**
     * Address: 0x0077FBF0 (FUN_0077FBF0, Moho::CMauiBitmap::~CMauiBitmap body)
     * Deleting thunk: 0x0077FAA0 (FUN_0077FAA0, Moho::CMauiBitmap::dtr)
     *
     * What it does:
     * Releases hit-mask/animation/lazy-var/runtime texture lanes before base
     * `CMauiControl` teardown.
     */
    ~CMauiBitmap() override;

    /**
     * Address: 0x0077FAD0 (FUN_0077FAD0, Moho::CMauiBitmap::Dump)
     *
     * What it does:
     * Logs base CMauiControl state, then logs CMauiBitmap-specific texture
     * batch count, current bitmap width/height, UV rectangle, alpha hit-test
     * flag, and animation playback state.
     */
    void Dump() override;
  };

  class CMauiGroup : public CMauiControl
  {
  public:
    /**
     * Address: 0x00797280 (FUN_00797280, ??0CMauiGroup@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs one group control from Lua object + parent lanes.
     */
    CMauiGroup(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x007970F0 (FUN_007970F0, Moho::CMauiGroup::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiGroup`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00797110 (FUN_00797110, Moho::CMauiGroup::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x007972D0 (FUN_007972D0, Moho::CMauiGroup::dtr)
     *
     * What it does:
     * `CMauiGroup` adds no data members of its own, so the vtable-slot-2
     * scalar deleting destructor just tail-calls `CMauiControl::~CMauiControl`
     * then conditionally frees the object -- exactly what a defaulted
     * destructor produces for a derived class with no extra state.
     */
    ~CMauiGroup() override = default;

    /**
     * Address: 0x00797300 (FUN_00797300, Moho::CMauiGroup::Draw)
     *
     * What it does:
     * No-op draw lane used by the group control vtable.
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;
  };

  class CMauiHistogram : public CMauiControl
  {
  public:
    /**
     * Address: 0x007977A0 (FUN_007977A0, Moho::CMauiHistogram::CMauiHistogram)
     *
     * What it does:
     * Constructs one histogram control from Lua object + parent lanes and
     * initializes histogram graph/state defaults.
     */
    CMauiHistogram(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x007975F0 (FUN_007975F0, Moho::CMauiHistogram::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiHistogram`, resolved
     * via RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00797610 (FUN_00797610, Moho::CMauiHistogram::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x00797840 (FUN_00797840, Moho::CMauiHistogram::~CMauiHistogram)
     * Address: 0x00797820 (FUN_00797820, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases each histogram column's owned value buffer and the column array
     * itself, then resets the column-array lanes, before base teardown.
     */
    ~CMauiHistogram() override;

    /**
     * Address: 0x007978F0 (FUN_007978F0, Moho::CMauiHistogram::Draw)
     *
     * What it does:
     * No-op histogram draw lane retained for vtable/override compatibility.
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x00797900 (FUN_00797900, Moho::CMauiHistogram::Dump)
     *
     * What it does:
     * Logs base control debug state plus one histogram class banner line.
     */
    void Dump() override;

  };

  class CMauiItemList : public CMauiControl
  {
  public:
    /**
     * Address: 0x00799340 (FUN_00799340, Moho::CMauiItemList::CMauiItemList)
     *
     * What it does:
     * Constructs one item-list control from Lua object + parent lanes and
     * initializes default palette/selection/font state.
     */
    CMauiItemList(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x00799050 (FUN_00799050, Moho::CMauiItemList::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiItemList`, resolved
     * via RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00799070 (FUN_00799070, Moho::CMauiItemList::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x00799610 (FUN_00799610, Moho::CMauiItemList::SetFont)
     *
     * What it does:
     * Rebinds item-list font lane, falling back to default face/size when nil
     * is requested.
     */
    void SetFont(CD3DFont* font);

    /**
     * Address: 0x00799A50 (FUN_00799A50, Moho::CMauiItemList::Draw)
     *
     * IDA signature:
     * void __thiscall Moho::CMauiItemList::Draw(
     *     CMauiItemList* this, CD3DPrimBatcher* primBatcher, int drawMask);
     *
     * What it does:
     * Draws the list background quad, then optional mouse-over and selection
     * highlight row quads, then renders each visible item string with the
     * resolved (normal / highlight / selected) foreground color.
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x0079A730 (FUN_0079A730, Moho::CMauiItemList::LinesVisible)
     *
     * What it does:
     * Computes one visible-row count from current control/font metrics and
     * clamps scroll-position lane against available item count.
     */
    [[nodiscard]] std::int32_t LinesVisible();

    /**
     * Address: 0x0079A870 (FUN_0079A870, Moho::CMauiItemList::ScrollToBottom)
     *
     * What it does:
     * Scrolls to the bottommost list row by setting top-scroll to current
     * item count.
    */
    void ScrollToBottom();

    /**
     * Address: 0x0079A8C0 (FUN_0079A8C0, Moho::CMauiItemList::ShowItem)
     *
     * What it does:
     * Scrolls the item list so `index` is visible inside the current viewport.
     */
    void ShowItem(std::int32_t index);

    /**
     * Address: 0x0079A8F0 (FUN_0079A8F0, Moho::CMauiItemList::NeedsScrollBar)
     *
     * What it does:
     * Returns whether visible-row capacity is smaller than item count.
     */
    [[nodiscard]] bool NeedsScrollBar();

    /**
     * Address: 0x0079A560 (FUN_0079A560, Moho::CMauiItemList::GetScrollValues)
     *
     * What it does:
     * Returns item-list scroll extents and visible range for current
     * top-scroll lane.
     */
    [[nodiscard]] SMauiScrollValues GetScrollValues(EMauiScrollAxis axis) override;

    /**
     * Address: 0x0079A650 (FUN_0079A650, Moho::CMauiItemList::ScrollLines2)
     *
     * What it does:
     * Applies page-scroll delta from visible-row count and clamps top-scroll
     * lane to valid item-list bounds.
     */
    void ScrollPages(EMauiScrollAxis axis, float amount) override;

    /**
     * Address: 0x0079A5F0 (FUN_0079A5F0, Moho::CMauiItemList::ScrollLines)
     *
     * What it does:
     * Applies line-scroll delta and clamps top-scroll lane to valid
     * item-list bounds.
     */
    void ScrollLines(EMauiScrollAxis axis, float amount) override;

    /**
     * Address: 0x0079A6D0 (FUN_0079A6D0, Moho::CMauiItemList::ScrollSetTop)
     *
     * What it does:
     * Sets top-scroll lane from one absolute row index and clamps it to valid
     * item-list bounds.
     */
    void ScrollSetTop(EMauiScrollAxis axis, float amount) override;

    /**
     * Address: 0x00799870 (FUN_00799870, Moho::CMauiItemList::AddItem)
     *
     * What it does:
     * Adds one string lane to the item-list payload.
     */
    void AddItem(msvc8::string text);

    /**
     * Address: 0x00799780 (FUN_00799780, Moho::CMauiItemList::ModifyItem)
     *
     * What it does:
     * Replaces one existing item string lane by index and throws when index is
     * out of range.
     */
    void ModifyItem(std::uint32_t index, msvc8::string text);

    /**
     * Address: 0x00799940 (FUN_00799940, Moho::CMauiItemList::DeleteItem)
     *
     * What it does:
     * Removes one item lane by index and adjusts current selection to preserve
     * post-delete selection semantics.
     */
    void DeleteItem(std::int32_t index);

    /**
     * Address: 0x0079A0B0 (FUN_0079A0B0, Moho::CMauiItemList::GetItem)
     *
     * What it does:
     * Converts one Y-coordinate lane to an item index lane using current
     * top/scroll/font metrics and returns `-1` when no row is hit.
     */
    [[nodiscard]] std::int32_t GetItem(float yCoordinate);

    /**
     * Address: 0x00799560 (FUN_00799560, Moho::CMauiItemList::Dump)
     *
     * What it does:
     * Logs item-list palette lanes and current-selection text state.
     */
    void Dump() override;

    /**
     * Address: 0x0079A160 (FUN_0079A160, Moho::CMauiItemList::HandleEvent)
     *
     * What it does:
     * Routes mouse motion/exit/click/wheel and navigation key events into list
     * row-selection updates and emits matching `OnMouseoverItem` / `OnClick` /
     * `OnDoubleClick` / `OnKeySelect` script callbacks. Returns whether the
     * event was consumed by this control.
     */
    [[nodiscard]] bool HandleEvent(const SMauiEventData& eventData) override;

    /**
     * Address: 0x007994C0 (FUN_007994C0, sub_7994C0)
     * Address: 0x007994A0 (FUN_007994A0, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body below then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases list-item string storage and one intrusive font reference, then
     * continues base `CMauiControl` teardown.
     */
    ~CMauiItemList() override;
  };

  class CMauiMesh : public CMauiControl
  {
  public:
    /**
     * Address: 0x0079DDB0 (FUN_0079DDB0, Moho::CMauiMesh::CMauiMesh)
     *
     * What it does:
     * Constructs one mesh control from Lua object + parent lanes and initializes
     * mesh render/runtime state defaults.
     */
    CMauiMesh(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x0079E100 (FUN_0079E100, Moho::CMauiMesh::OnFrame)
     *
     * What it does:
     * Recreates mesh thumbnail texture-sheet storage when control dimensions
     * change, then refreshes mesh thumbnail rendering when mesh/rotation lanes
     * are marked dirty.
     *
     * The elided body invokes the following helper; with the body
     * stubbed in EngineMethodStubs2.cpp (typed
     * `CD3DDynamicTextureSheet` lock/get-size/unlock surface and
     * `REN_RequestThumbnail` chain still under recovery), this helper
     * is never invoked from the modern source and its role is absorbed
     * by the elision of the thumbnail refresh lane:
     *   - 0x0079E0B0 (`ZeroDynamicTextureSheetBuffer` — locks the
     *     dynamic texture sheet at `this->mTextureSheet`, memsets
     *     the locked buffer to zero, then unlocks; called before
     *     `REN_RequestThumbnail` to clear stale pixels)
     */
    void Frame(float deltaSeconds) override;

    /**
     * Address: 0x0079DF40 (FUN_0079DF40, Moho::CMauiMesh::SetMesh)
     *
     * What it does:
     * Replaces the active mesh blueprint lane from a Lua-supplied path.
     */
    void SetMesh(const char* meshBlueprintName);

    /**
     * Address: 0x0079E430 (FUN_0079E430, Moho::CMauiMesh::Draw)
     *
     * What it does:
     * Binds current mesh texture lane and draws one fullscreen quad over this
     * control rectangle with fixed UV mapping.
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x0079E580 (FUN_0079E580, Moho::CMauiMesh::Dump)
     *
     * What it does:
     * No-op dump lane retained for vtable/override compatibility.
     */
    void Dump() override;

    /**
       * Address: 0x0079E930 (FUN_0079E930)
     *
     * What it does:
     * Stores one new mesh orientation quaternion and marks this mesh as
     * rotated for frame updates.
     */
    void SetOrientation(const Wm3::Quaternionf& orientation);

    /**
     * Address: 0x0079DC10 (FUN_0079DC10, Moho::CMauiMesh::GetClass)
     *
     * What it does:
     * Returns the cached reflection descriptor for the CMauiMesh type, looked up
     * by RTTI on first use (overrides the base CMauiControl accessor with the
     * mesh-specific type cache).
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0079DC30 (FUN_0079DC30, Moho::CMauiMesh::GetDerivedObjectRef)
     *
     * What it does:
     * Packs {this, GetClass()} into a reflection reference handle.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x0079DE70 (FUN_0079DE70, Moho::CMauiMesh::dtr)
     * Address: 0x0079DE50 (FUN_0079DE50, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body below then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases the mesh preview texture shared-pointer lane and continues
     * base `CMauiControl` teardown.
     */
    ~CMauiMesh() override;
  };

  class CMauiMovie : public CMauiControl
  {
  public:
    /**
     * Address: 0x0079EE20 (FUN_0079EE20, Moho::CMauiMovie::CMauiMovie)
     *
     * What it does:
     * Constructs one movie control from Lua object + parent lanes and
     * initializes movie playback/runtime fields.
     */
    CMauiMovie(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x0079EC90 (FUN_0079EC90, Moho::CMauiMovie::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiMovie`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0079ECB0 (FUN_0079ECB0, Moho::CMauiMovie::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x0079EFE0 (FUN_0079EFE0, Moho::CMauiMovie::LoadFile)
     *
     * What it does:
     * Loads/attaches one movie resource and reports success.
     */
    [[nodiscard]] bool LoadFile(const char* filename);

    /**
     * Address: 0x0079F1C0 (FUN_0079F1C0, Moho::CMauiMovie::OnFrame)
     *
     * What it does:
     * Advances movie playback state for one frame tick and dispatches
     * `OnFrame`/`OnStopped`/`OnFinished`/`OnSubtitle` script callbacks.
     */
    void Frame(float deltaSeconds) override;

    /**
     * Address: 0x0079F310 (FUN_0079F310, Moho::CMauiMovie::Draw)
     *
     * What it does:
     * Draws current movie texture over control bounds while playback is active.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x0079F490 (FUN_0079F490, Moho::CMauiMovie::OnMinimized)
     *
     * What it does:
     * Stops active movie playback while minimized and resumes playback when the
     * control is restored from minimized state.
     */
    void OnMinimized(bool minimized) override;

    /**
       * Address: 0x0079F8F0 (FUN_0079F8F0)
     *
     * What it does:
     * Updates movie looping state used by playback runtime.
     */
    void Loop(bool shouldLoop);

    /**
       * Address: 0x0079FA40 (FUN_0079FA40)
     *
     * What it does:
     * Starts movie playback when an internal movie resource is attached.
     */
    void Play();

    /**
       * Address: 0x0079FBA0 (FUN_0079FBA0)
     *
     * What it does:
     * Stops movie playback when an internal movie resource is attached.
     */
    void Stop();

    /**
       * Address: 0x0079FCF0 (FUN_0079FCF0)
     *
     * What it does:
     * Returns whether an internal movie resource is attached and loaded.
     */
    [[nodiscard]] bool IsLoaded() const;

    /**
       * Address: 0x0079FE50 (FUN_0079FE50)
     *
     * What it does:
     * Returns frame count from the attached movie resource.
     */
    [[nodiscard]] std::int32_t GetNumFrames() const;

    /**
       * Address: 0x0079FFA0 (FUN_0079FFA0)
     *
     * What it does:
     * Returns playback frame rate from the attached movie resource.
     */
    [[nodiscard]] float GetFrameRate() const;

    /**
     * Address: 0x0079F500 (FUN_0079F500, Moho::CMauiMovie::Dump)
     *
     * What it does:
     * Logs this movie label and current playback state (`true`/`false`).
     */
    void Dump() override;

    /**
     * Address: 0x0079EF30 (FUN_0079EF30, Moho::CMauiMovie::~CMauiMovie)
     * Address: 0x0079EF10 (FUN_0079EF10, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Tears down one movie control in-place: destroys the two lazy-var lanes
     * (`mMovieHeightLV`, `mMovieWidthLV`), releases the subtitle-cache string
     * storage, deletes the movie-playback interface through its virtual
     * deleting destructor, then delegates to the `CMauiControl` base
     * teardown.
     */
    ~CMauiMovie() override;
  };

  class CMauiScrollbar : public CMauiControl, public IMauiDragger
  {
  public:
    /**
     * Address: 0x007A04B0 (FUN_007A04B0, Moho::CMauiScrollbar::CMauiScrollbar)
     *
     * What it does:
     * Constructs one scrollbar control from Lua object + parent lanes and
     * initializes scrollbar runtime state defaults.
     */
    CMauiScrollbar(LuaPlus::LuaObject* luaObject, CMauiControl* parent, EMauiScrollAxis axis);

    /**
     * Address: 0x007A0310 (FUN_007A0310, Moho::CMauiScrollbar::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiScrollbar`, resolved
     * via RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x007A0330 (FUN_007A0330, Moho::CMauiScrollbar::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x007A0740 (FUN_007A0740, Moho::CMauiScrollbar::SetTextures)
     *
     * What it does:
     * Replaces any non-null scrollbar texture lanes (background, thumb-middle,
     * thumb-top, thumb-bottom).
     */
    void SetTextures(
      const boost::shared_ptr<CD3DBatchTexture>& background,
      const boost::shared_ptr<CD3DBatchTexture>& thumbMiddle,
      const boost::shared_ptr<CD3DBatchTexture>& thumbTop,
      const boost::shared_ptr<CD3DBatchTexture>& thumbBottom
    );

    /**
     * Address: 0x007A0840 (FUN_007A0840, Moho::CMauiScrollbar::Draw)
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     *
     * What it does:
     * Draws the scrollbar background and textured thumb from the attached
     * scrollable control range.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x007A11C0 (FUN_007A11C0, Moho::CMauiScrollbar::HandleEvent)
     *
     * What it does:
     * Handles mouse press/wheel lanes for page-scroll and drag-capture against
     * the bound scrollable control.
     */
    [[nodiscard]] bool HandleEvent(const SMauiEventData& eventData) override;

    /**
     * Address: 0x007A1410 (FUN_007A1410, Moho::CMauiScrollbar::DragMove)
     *
     * What it does:
     * Converts drag delta in screen space into scroll-range movement and
     * updates the scrollable top value.
     */
    void DragMove(const SMauiEventData* eventData) override;

    /**
     * Address: 0x007A1500 (FUN_007A1500, Moho::CMauiScrollbar::DragRelease)
     *
     * What it does:
     * No-op release hook for scrollbar dragger lane.
     */
    void DragRelease(const SMauiEventData* eventData) override;

    /**
     * Address: 0x007A1510 (FUN_007A1510, Moho::CMauiScrollbar::DragCancel)
     *
     * What it does:
     * No-op cancel/replace hook for scrollbar dragger lane.
     */
    void OnCurrentDraggerReplaced() override;

    /**
     * Address: 0x007A0590 (FUN_007A0590, Moho::CMauiScrollbar::~CMauiScrollbar)
     * Deleting dtor: 0x007A0570 (FUN_007A0570, Moho::CMauiScrollbar::dtr)
     *
     * What it does:
     * Tears down one scrollbar control in-place in reverse construction order:
     * releases the four `CD3DBatchTexture` shared-pointer lanes (background,
     * thumb-middle, thumb-bottom, thumb-top), unlinks the bound scrollable
     * focus sentinel, restores the embedded `IMauiDragger` sub-object vtable and
     * detaches its dragger list, then chains into the base `CMauiControl` /
     * `IMauiDragger` teardown emitted by the compiler.
     */
    ~CMauiScrollbar() override;
  };

  // The `IMauiDragger` sub-object has to begin at +0x11C; that holds only
  // while `CMauiControl` reserves its full 0x11C. The constructor at
  // 0x007A04B0 writes both of the sub-object's dwords there -
  // `mov [esi+120h], ebx` (ebx = 0, 0x007A04ED) clears
  // `WeakObject::weakLinkHead_` and `mov [esi+11Ch], offset
  // ??_7IMauiDragger@Moho@@6B@` (0x007A04F3) installs the base vptr before
  // 0x007A0503 replaces it with the scrollbar's own thunk vtable - so the
  // class ends at 0x124. The remaining lanes up to the binary's 0x158
  // allocation live in `CMauiScrollbarRuntimeView`.
  static_assert(sizeof(CMauiScrollbar) == 0x124, "moho::CMauiScrollbar must place IMauiDragger at 0x11C");

  class CMauiText : public CMauiControl
  {
  public:
    /**
     * Address: 0x007A2BE0 (FUN_007A2BE0, Moho::CMauiText::CMauiText)
     *
     * What it does:
     * Constructs one text control from Lua object + parent lanes and initializes
     * text/font rendering state defaults.
     */
    CMauiText(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x007A29D0 (FUN_007A29D0, Moho::CMauiText::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CMauiText`, resolved via
     * RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x007A29F0 (FUN_007A29F0, Moho::CMauiText::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x007A2EA0 (FUN_007A2EA0, Moho::CMauiText::SetNewFont)
     *
     * What it does:
     * Rebinds text font lane and refreshes cached text/font metric lazy-vars.
     */
    void SetNewFont(CD3DFont* font);

    /**
     * Address: 0x007A2FA0 (FUN_007A2FA0, Moho::CMauiText::SetText)
     *
     * What it does:
     * Stores one new text lane and refreshes cached text-advance width when a
     * font is bound.
     */
    void SetText(const char* text);

    /**
     * Address: 0x007A2E40 (FUN_007A2E40, Moho::CMauiText::Dump)
     *
     * What it does:
     * Logs this text control label, ARGB color lane, and current text payload.
     */
    void Dump() override;

    /**
     * Address: 0x007A3040 (FUN_007A3040, Moho::CMauiText::Draw)
     *
     * IDA signature:
     * Wm3::Vector3f* __thiscall Moho::CMauiText::Draw(
     *   CMauiText* this, CD3DPrimBatcher* primBatcher, int drawMask);
     *
     * What it does:
     * Renders this control's text along screen axes: computes the horizontal
     * origin (optionally centered and back-shifted by half the measured advance)
     * and the baseline Y (optionally vertically centered), draws an optional
     * (+1,+1) drop shadow, then the main run with an alpha byte derived from
     * mAlpha. Occupies the CMauiControl::DoRender vtable slot; drawMask is
     * unused. No-op when no font is bound.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x007A2D60 (FUN_007A2D60, Moho::CMauiText::~CMauiText)
     * Deleting dtor: 0x007A2D40 (FUN_007A2D40, Moho::CMauiText::dtr)
     *
     * What it does:
     * Destroys the four text/font lazy-var LuaObject lanes, tidies the cached
     * text string, releases the intrusive font reference, and chains into the
     * base CMauiControl teardown.
     */
    ~CMauiText() override;
  };

  class CMauiBorder : public CMauiControl
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00784A10 (FUN_00784A10, Moho::CMauiBorder::CMauiBorder)
     *
     * What it does:
     * Constructs one border control from Lua object + parent lanes and
     * initializes border texture/lazy-var state.
     */
    CMauiBorder(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x00784B40 (FUN_00784B40, Moho::CMauiBorder::~CMauiBorder)
     * Address: 0x00784B20 (FUN_00784B20, vtable-slot-2 scalar deleting
     * destructor: tail-calls the body above then conditionally frees the
     * object -- ordinary C++ `delete` semantics, not modeled as a separate
     * function here)
     *
     * What it does:
     * Releases border lazy-var/object texture lanes before base
     * `CMauiControl` teardown.
     */
    ~CMauiBorder() override;

    /**
     * Address: 0x00784840 (FUN_00784840, Moho::CMauiBorder::StaticGetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for `CMauiBorder`.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00784860 (FUN_00784860, Moho::CMauiBorder::GetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for this `CMauiBorder` instance.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x00784880 (FUN_00784880, Moho::CMauiBorder::GetDerivedObjectRef)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x00784D60 (FUN_00784D60, Moho::CMauiBorder::SetTextures)
     *
     * What it does:
     * Replaces any non-null border texture lanes and updates border width/height
     * lazy-vars from the vertical and horizontal texture dimensions.
     */
    void SetTextures(
      const boost::shared_ptr<CD3DBatchTexture>& vert,
      const boost::shared_ptr<CD3DBatchTexture>& horz,
      const boost::shared_ptr<CD3DBatchTexture>& ul,
      const boost::shared_ptr<CD3DBatchTexture>& ur,
      const boost::shared_ptr<CD3DBatchTexture>& ll,
      const boost::shared_ptr<CD3DBatchTexture>& lr
    );

    /**
     * Address: 0x00784D00 (FUN_00784D00, Moho::CMauiBorder::Dump)
     *
     * What it does:
     * Logs this border label and current border width/height lazy-var values.
     */
    void Dump() override;

    /**
     * Address: 0x00784F50 (FUN_00784F50, Moho::CMauiBorder::Draw)
     *
     * What it does:
     * Draws textured border corners plus optional horizontal/vertical body strips
     * from lazy-var geometry lanes.
     *
     * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;
  };

  class CUIMapPreview : public CMauiControl
  {
  public:
    /**
     * Address: 0x00850770 (FUN_00850770, Moho::CUIMapPreview::CUIMapPreview)
     *
     * What it does:
     * Constructs one map-preview control from Lua object + parent lanes and
     * initializes preview texture state.
     */
    CUIMapPreview(LuaPlus::LuaObject* luaObject, CMauiControl* parent);

    /**
     * Address: 0x008505E0 (FUN_008505E0, Moho::CUIMapPreview::GetClass)
     * VFTable SLOT: 0
     *
     * What it does:
     * Returns the cached reflection descriptor for `CUIMapPreview`, resolved
     * via RTTI on first use.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x00850600 (FUN_00850600, Moho::CUIMapPreview::GetDerivedObjectRef)
     * VFTable SLOT: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /** Per-type cached reflection descriptor (lazy-initialized by GetClass). */
    static gpg::RType* sType;

    /**
     * Address: 0x008507F0 (FUN_008507F0, Moho::CUIMapPreview::~CUIMapPreview)
     *
     * What it does:
     * Releases the preview texture lane before the inherited control teardown
     * continues through `CMauiControl`.
     */
    ~CUIMapPreview() override;

    /**
     * Address: 0x008507D0 (FUN_008507D0, Moho::CUIMapPreview::Delete)
     *
     * What it does:
     * Mirrors the deleting-destructor thunk lane for map-preview controls and
     * optionally frees the storage block.
     */
    static CUIMapPreview* DeleteWithFlag(CUIMapPreview* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x00850870 (FUN_00850870, Moho::CUIMapPreview::SetTexture)
     *
     * What it does:
     * Clears existing preview texture ownership and loads one UI texture by
     * path through D3D device resources.
     */
    [[nodiscard]] bool SetTexture(const char* texturePath);

    /**
     * Address: 0x008509A0 (FUN_008509A0, Moho::CUIMapPreview::SetTextureFromMap)
     *
     * What it does:
     * Clears existing preview texture ownership and loads preview texture from
     * map preview chunk metadata.
     */
    [[nodiscard]] bool SetTextureFromMap(const char* mapPath);

    /**
     * Address: 0x00850AC0 (FUN_00850AC0, Moho::CUIMapPreview::ClearTexture)
     *
     * What it does:
     * Releases any currently bound map-preview texture ownership.
     */
    void ClearTexture();

    /**
     * Address: 0x00850B10 (FUN_00850B10, Moho::CUIMapPreview::Draw)
     *
     * IDA signature:
     * void __thiscall Moho::CUIMapPreview::Draw(
     *   CUIMapPreview* this, CD3DPrimBatcher* primBatcher, int drawMask);
     *
     * What it does:
     * Renders the bound preview texture as an aspect-fit (letterbox/pillarbox)
     * white-tinted textured quad centered inside the control bounds. No-op when
     * no texture is bound. Occupies the CMauiControl::DoRender vtable slot;
     * drawMask is unused.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;
  };

  struct CMauiControlRuntimeView
  {
    std::uint8_t mUnknown00To33[0x34]{};
    TDatListItem<CMauiControl, void> mParentList{}; // +0x34
    CMauiControl* mParent = nullptr; // +0x3C
    TDatList<CMauiControl, void> mChildrenList{}; // +0x40
    CScriptLazyVar_float mLeftLV;   // +0x48
    CScriptLazyVar_float mRightLV;  // +0x5C
    CScriptLazyVar_float mTopLV;    // +0x70
    CScriptLazyVar_float mBottomLV; // +0x84
    CScriptLazyVar_float mWidthLV;  // +0x98
    CScriptLazyVar_float mHeightLV; // +0xAC
    CScriptLazyVar_float mDepthLV;  // +0xC0

    [[nodiscard]] static CMauiControlRuntimeView* FromControl(CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlRuntimeView*>(control);
    }

    [[nodiscard]] static const CMauiControlRuntimeView* FromControl(const CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlRuntimeView*>(control);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlRuntimeView, mParentList) == 0x34,
    "CMauiControlRuntimeView::mParentList offset must be 0x34"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mParent) == 0x3C, "CMauiControlRuntimeView::mParent offset must be 0x3C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlRuntimeView, mChildrenList) == 0x40,
    "CMauiControlRuntimeView::mChildrenList offset must be 0x40"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mLeftLV) == 0x48, "CMauiControlRuntimeView::mLeftLV offset must be 0x48");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mRightLV) > offsetof(CMauiControlRuntimeView, mLeftLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mTopLV) > offsetof(CMauiControlRuntimeView, mRightLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mBottomLV) > offsetof(CMauiControlRuntimeView, mTopLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mWidthLV) > offsetof(CMauiControlRuntimeView, mBottomLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mHeightLV) > offsetof(CMauiControlRuntimeView, mWidthLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiControlRuntimeView, mDepthLV) == 0xC0, "CMauiControlRuntimeView::mDepthLV offset must be 0xC0");

  struct CMauiControlFrameUpdateRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To0EA[0x17]{};
    bool mNeedsFrameUpdate = false; // +0xEB

    [[nodiscard]] static CMauiControlFrameUpdateRuntimeView* FromControl(CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlFrameUpdateRuntimeView*>(control);
    }

    [[nodiscard]]
    static const CMauiControlFrameUpdateRuntimeView* FromControl(const CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlFrameUpdateRuntimeView*>(control);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlFrameUpdateRuntimeView, mNeedsFrameUpdate) == 0xEB,
    "CMauiControlFrameUpdateRuntimeView::mNeedsFrameUpdate offset must be 0xEB"
  );

  struct CMauiControlExtendedRuntimeView : CMauiControlRuntimeView
  {
    float mDepth = 0.0f; // +0xD4
    // +0xD8, 0x10 bytes. The MSVC8 vector stores its allocator as a real data
    // member ahead of the first/last/end triple, so the container starts at
    // 0xD8 and the pointers land at 0xDC/0xE0/0xE4 - it is not a 4-byte hole
    // followed by a 12-byte vector. Modelling it that way pushed every field
    // from mInvalidated onwards 4 bytes too high.
    msvc8::vector<CMauiControl*> mRenderedChildren{}; // +0xD8
    bool mInvalidated = false; // +0xE8
    bool mDisableHitTest = false; // +0xE9
    bool mIsHidden = false;       // +0xEA
    bool mNeedsFrameUpdate = false; // +0xEB
    bool mInvisible = false; // +0xEC
    std::uint8_t mUnknown0EDTo0EF[0x3]{};
    float mAlpha = 1.0f; // +0xF0
    std::uint32_t mVertexAlpha = 0; // +0xF4
    std::int32_t mRenderPass = 0; // +0xF8
    CMauiControl* mRootFrame = nullptr; // +0xFC
    msvc8::string mDebugName{}; // +0x100 .. 0x11B - last field of the control

    // NOTE: the control's own layout ends at 0x11C. The 0x18 bytes that used
    // to be modelled here (a 0x14 "unknown" run plus mEventMapper at 0x130)
    // are CMauiFrame's fields - see CMauiFrameRuntimeView - and claiming them
    // here made every derived view's fields overrun the object the binary
    // allocates (`operator new(0x134)` for a frame).

    [[nodiscard]] static CMauiControlExtendedRuntimeView* FromControl(CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlExtendedRuntimeView*>(control);
    }

    [[nodiscard]] static const CMauiControlExtendedRuntimeView* FromControl(const CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlExtendedRuntimeView*>(control);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mRenderPass) == 0xF8,
    "CMauiControlExtendedRuntimeView::mRenderPass offset must be 0xF8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mDisableHitTest) == 0xE9,
    "CMauiControlExtendedRuntimeView::mDisableHitTest offset must be 0xE9"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mInvalidated) == 0xE8,
    "CMauiControlExtendedRuntimeView::mInvalidated offset must be 0xE8"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mIsHidden) == 0xEA,
    "CMauiControlExtendedRuntimeView::mIsHidden offset must be 0xEA"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mNeedsFrameUpdate) == 0xEB,
    "CMauiControlExtendedRuntimeView::mNeedsFrameUpdate offset must be 0xEB"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mRenderedChildren) == 0xD8,
    "CMauiControlExtendedRuntimeView::mRenderedChildren offset must be 0xD8"
  );
  static_assert(sizeof(msvc8::vector<CMauiControl*>) == 0x10, "msvc8::vector must be 0x10");
  static_assert(
    sizeof(CMauiControlExtendedRuntimeView) == 0x11C,
    "CMauiControlExtendedRuntimeView size must be 0x11C - CMauiFrame's fields start there"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mDepth) == 0xD4,
    "CMauiControlExtendedRuntimeView::mDepth offset must be 0xD4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mInvisible) == 0xEC,
    "CMauiControlExtendedRuntimeView::mInvisible offset must be 0xEC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mAlpha) == 0xF0,
    "CMauiControlExtendedRuntimeView::mAlpha offset must be 0xF0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mVertexAlpha) == 0xF4,
    "CMauiControlExtendedRuntimeView::mVertexAlpha offset must be 0xF4"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mRootFrame) == 0xFC,
    "CMauiControlExtendedRuntimeView::mRootFrame offset must be 0xFC"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiControlExtendedRuntimeView, mDebugName) == 0x100,
    "CMauiControlExtendedRuntimeView::mDebugName offset must be 0x100"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(msvc8::string) == 0x1C, "msvc8::string size must be 0x1C");

  /**
   * Runtime view for global keyboard-focus tracking lane.
   *
   * `mFocusedControlPrevNextField` stores an encoded intrusive-link value:
   * - `0` means no focus owner.
   * - `4` means the list sentinel lane.
   * - any other value points to the focused control's embedded `mNext` lane.
   */
  struct CMauiCurrentFocusControlRuntimeView
  {
    std::uint32_t mFocusedControlPrevNextField = 0; // +0x0
    std::uint32_t mNextPrevNextField = 0;           // +0x4

    [[nodiscard]] CMauiControl* ResolveFocusedControl() const noexcept;
  };


  /**
   * `Moho::CRenderWorldView` - the `IRenderWorldView` half of `CUIWorldView`.
   *
   * `CUIWorldView` is a two-base class: `CMauiControl` at offset 0 (0x11C
   * bytes) and this one at offset 0x11C, which is where the constructor at
   * 0x0086E480 installs the second vtable (the store at 0x0086E4EF). Every
   * method the render vtable dispatches - `Render` at 0x0086EE00, `Func1` at
   * 0x0086ECB0, `RenderCommandGraph` at 0x0086ECD0, `GetCamera` at 0x0086EBF0
   * and the rest - is compiled against *this* sub-object pointer, not the
   * complete object: `GetCamera` reads `[this+4]`, `Func1` tests `[this+0x19]`
   * and hands `this+0xF8` to the build-drag update, `Render` reads the session
   * from `[this+0xEC]` and the hide-resources flag from `[this+0x15A]`. Those
   * are all fields of this class, which is why every field `CUIWorldView`
   * carries past `CMauiControl` lives here rather than on the derived class.
   *
   * Sub-object offset + 0x11C gives the complete-object offset, e.g. the
   * session at +0xEC here is +0x208 of a `CUIWorldView`.
   */
  class CRenderWorldView : public IRenderWorldView
  {
  public:
    CRenderWorldView() noexcept = default;
    // IRenderWorldView declares no virtual destructor - the render vtable is
    // exactly the 13 render slots - so this one is not virtual either.
    ~CRenderWorldView() noexcept = default;

    CRenderWorldView(const CRenderWorldView&) = delete;
    CRenderWorldView& operator=(const CRenderWorldView&) = delete;

    /**
     * Address: 0x0086EE00 (FUN_0086EE00, Moho::CRenderWorldView::Render)
     * Slot: 0
     *
     * IDA signature:
     * void __thiscall Moho::CRenderWorldView::Render(
     *   CRenderWorldView* this, CD3DPrimBatcher* batcher, int a4,
     *   CWldMap* map, float deltaT);
     *
     * What it does:
     * Draws every world-space overlay this view owns for one frame: resource
     * icons, strategic icons, projectile icons and arcs, mesh previews,
     * command splats and the economy overlay, then the command graph.
     */
    void Render(CD3DPrimBatcher* batcher, int renderPass, CWldMap* map, float deltaSeconds) override;

    /**
     * Address: 0x0086ECB0 (FUN_0086ECB0, Moho::CRenderWorldView::Func1)
     * Slot: 1
     *
     * What it does:
     * Per-frame pre-render hook: refreshes the build-drag ghost placement for
     * this view. Minimap views skip it.
     */
    void Func1() override;

    /**
     * Address: 0x0086ECD0 (FUN_0086ECD0, Moho::CRenderWorldView::RenderCommandGraph)
     * Slot: 2
     *
     * What it does:
     * With SHIFT held on a non-minimap view, draws the queued-order graph plus
     * the footprint skirts of every pending mobile-build order; otherwise drops
     * the cached graph handle. Always draws the local build-drag graph.
     */
    void RenderCommandGraph(CD3DPrimBatcher* batcher, int renderPass, CWldMap* map, float deltaSeconds) override;

    /**
     * Address: 0x0086EBF0 (FUN_0086EBF0, Moho::CRenderWorldView::GetCamera)
     * Slot: 3
     */
    [[nodiscard]] CameraImpl* GetCamera() override;

    /**
     * Address: 0x0086EBE0 (FUN_0086EBE0, Moho::CRenderWorldView::GetCameraView)
     * Slot: 4
     */
    [[nodiscard]] GeomCamera3* GetCameraView() override;

    /**
     * Address: 0x0086EC00 (FUN_0086EC00, Moho::CRenderWorldView::GetCameraOffset)
     * Slot: 5
     */
    [[nodiscard]] Wm3::Vector3f* GetCameraOffset() override;

    /**
     * Address: 0x0086EC10 (FUN_0086EC10, Moho::CRenderWorldView::CameraGetTargetZoom)
     * Slot: 6
     */
    [[nodiscard]] float CameraGetTargetZoom() override;

    /**
     * Address: 0x0086EC20 (FUN_0086EC20, Moho::CRenderWorldView::GetMaxZoom)
     * Slot: 7
     */
    [[nodiscard]] float GetMaxZoom() override;

    /**
     * Address: 0x0086EC30 (FUN_0086EC30, Moho::CRenderWorldView::CameraGetZoom)
     * Slot: 8
     */
    [[nodiscard]] float CameraGetZoom() override;

    /**
     * Address: 0x0086DC90 (FUN_0086DC90, Moho::CRenderWorldView::IsMiniMap)
     * Slot: 10
     */
    [[nodiscard]] bool IsMiniMap() override;

    /**
     * Address: 0x0086DC00 (FUN_0086DC00, Moho::CRenderWorldView::SetOrthographic)
     * Slot: 11
     *
     * What it does:
     * Stores the orthographic toggle and mirrors it to the camera: going
     * orthographic disables camera shake, leaving it re-enables shake.
     */
    void SetOrthographic(bool orthographicEnabled) override;

    /**
     * Address: 0x0086DC60 (FUN_0086DC60, Moho::CRenderWorldView::CanShake)
     * Slot: 12
     */
    [[nodiscard]] bool CanShake() override;

    CameraImpl* mCamera = nullptr;              // +0x04
    float mCachedViewLeft = 0.0f;               // +0x08
    float mCachedViewTop = 0.0f;                // +0x0C
    float mCachedViewRight = 0.0f;              // +0x10
    float mCachedViewBottom = 0.0f;             // +0x14
    bool mOrthographic = false;                 // +0x18
    bool mIsMiniMap = false;                    // +0x19
    bool mEnableResourceRendering = false;      // +0x1A
    std::uint8_t mPad1B = 0;                    // +0x1B
    std::int32_t mInputLocks = 0;               // +0x1C
    std::int32_t mWorldViewDepth = 0;           // +0x20
    std::int32_t mState = 0;                    // +0x24
    /// Event type of the last right-button action this view processed, stored
    /// at 0x00870F2C and tested `== MET_ButtonDClick` at 0x008710B8 so the
    /// release path can tell a double-click order from a single-click one.
    /// Was dead padding until `HandleEvent`'s two accesses were mapped.
    EMauiEventType mLastRightButtonEvent = MET_Unknown; // +0x28
    CommandModeData mLeftMouseCommand;          // +0x2C
    CommandModeData mCommandData;               // +0x8C
    CWldSession* mWldSession = nullptr;         // +0xEC
    boost::SharedPtrRaw<UICommandGraph> mComGraph; // +0xF0
    CUIWorldViewBuildDragRuntimeView mBuildDrag; // +0xF8
    bool mConvertToPatrolCursor = false;        // +0x158
    /// Set on MET_MouseEnter and cleared on MET_MouseExit by
    /// `CUIWorldView::HandleEvent` (0x008704E4 / 0x00870500): the cursor is
    /// inside this view.
    std::uint8_t mCursorInside = 0;             // +0x159
    /// Space-drag camera rotation in progress. Raised on the first rotating
    /// motion frame (0x00870A55) and dropped when the drag ends or the pointer
    /// leaves (0x0087051F / 0x00870A8F). `Render` reads it at 0x0086EE0B to
    /// suppress the resource-splat pass, which is what the previous name
    /// (`mHideResources`) described - the effect rather than the cause.
    bool mCameraRotationActive = false;         // +0x15A
    std::uint8_t mPad15B = 0;                   // +0x15B
    /// Cursor position the last rotation frame sampled, so the next frame can
    /// hand `CameraSpin` a delta. Read at 0x008709DE / 0x008709F1 and rewritten
    /// at 0x00870A5F / 0x00870A68 (CUIWorldView +0x278 / +0x27C).
    Wm3::Vector2f mLastCursorScreenPos{};       // +0x15C
    msvc8::string mCameraTrack;                 // +0x164
    CMauiCurrentFocusControlRuntimeView mOverlayLink; // +0x180
    bool mHighlightEnabled = true;              // +0x188
    bool mIconsVisible = true;                  // +0x189
    bool mGlobalCameraCommands = false;         // +0x18A
    std::uint8_t mPad18B = 0;                   // +0x18B
  };

  static_assert(offsetof(CRenderWorldView, mCamera) == 0x04, "CRenderWorldView::mCamera offset must be 0x04");
  static_assert(
    offsetof(CRenderWorldView, mCachedViewLeft) == 0x08,
    "CRenderWorldView::mCachedViewLeft offset must be 0x08"
  );
  static_assert(offsetof(CRenderWorldView, mOrthographic) == 0x18, "CRenderWorldView::mOrthographic offset must be 0x18");
  static_assert(offsetof(CRenderWorldView, mIsMiniMap) == 0x19, "CRenderWorldView::mIsMiniMap offset must be 0x19");
  static_assert(
    offsetof(CRenderWorldView, mEnableResourceRendering) == 0x1A,
    "CRenderWorldView::mEnableResourceRendering offset must be 0x1A"
  );
  static_assert(offsetof(CRenderWorldView, mInputLocks) == 0x1C, "CRenderWorldView::mInputLocks offset must be 0x1C");
  static_assert(
    offsetof(CRenderWorldView, mWorldViewDepth) == 0x20,
    "CRenderWorldView::mWorldViewDepth offset must be 0x20"
  );
  static_assert(offsetof(CRenderWorldView, mState) == 0x24, "CRenderWorldView::mState offset must be 0x24");
  static_assert(
    offsetof(CRenderWorldView, mLeftMouseCommand) == 0x2C,
    "CRenderWorldView::mLeftMouseCommand offset must be 0x2C"
  );
  static_assert(offsetof(CRenderWorldView, mCommandData) == 0x8C, "CRenderWorldView::mCommandData offset must be 0x8C");
  static_assert(offsetof(CRenderWorldView, mWldSession) == 0xEC, "CRenderWorldView::mWldSession offset must be 0xEC");
  static_assert(offsetof(CRenderWorldView, mComGraph) == 0xF0, "CRenderWorldView::mComGraph offset must be 0xF0");
  static_assert(offsetof(CRenderWorldView, mBuildDrag) == 0xF8, "CRenderWorldView::mBuildDrag offset must be 0xF8");
  static_assert(
    offsetof(CRenderWorldView, mConvertToPatrolCursor) == 0x158,
    "CRenderWorldView::mConvertToPatrolCursor offset must be 0x158"
  );
  static_assert(
    offsetof(CRenderWorldView, mCursorInside) == 0x159, "CRenderWorldView::mCursorInside offset must be 0x159"
  );
  static_assert(
    offsetof(CRenderWorldView, mCameraRotationActive) == 0x15A,
    "CRenderWorldView::mCameraRotationActive offset must be 0x15A"
  );
  static_assert(
    offsetof(CRenderWorldView, mLastCursorScreenPos) == 0x15C,
    "CRenderWorldView::mLastCursorScreenPos offset must be 0x15C"
  );
  static_assert(offsetof(CRenderWorldView, mCameraTrack) == 0x164, "CRenderWorldView::mCameraTrack offset must be 0x164");
  static_assert(offsetof(CRenderWorldView, mOverlayLink) == 0x180, "CRenderWorldView::mOverlayLink offset must be 0x180");
  static_assert(
    offsetof(CRenderWorldView, mHighlightEnabled) == 0x188,
    "CRenderWorldView::mHighlightEnabled offset must be 0x188"
  );
  static_assert(
    offsetof(CRenderWorldView, mGlobalCameraCommands) == 0x18A,
    "CRenderWorldView::mGlobalCameraCommands offset must be 0x18A"
  );
  static_assert(sizeof(CRenderWorldView) == 0x18C, "CRenderWorldView size must be 0x18C");

  /**
   * Address: 0x0085ABD0 (FUN_0085ABD0, Moho::DrawUnitSkirt)
   *
   * What it does:
   * Draws one unit footprint skirt outline: takes the blueprint's skirt rect
   * around `position`, lifts it to whichever is highest of the requested Y, the
   * terrain elevation + 0.1 and the map's water plane, then emits the outline
   * at a screen-space thickness that never falls below `ui_FootprintMinThickness`.
   */
  void DrawUnitSkirt(
    const CHeightField* heightField,
    const RUnitBlueprint* blueprint,
    const GeomCamera3& camera,
    const Wm3::Vector3f& position,
    CWldSession* session,
    CD3DPrimBatcher* batcher,
    std::uint32_t color
  );

  /**
   * Address: 0x0085AD80 (FUN_0085AD80, Moho::DrawAllUnitSkirts)
   *
   * What it does:
   * Draws a translucent magenta footprint skirt for every mobile-build order
   * currently queued in the session's command manager, so a shift-queued build
   * chain shows where each structure will land.
   */
  void DrawAllUnitSkirts(CD3DPrimBatcher* batcher, CWldSession* session, const GeomCamera3& camera);

  /**
   * The 3D world view: the control the game renders the world into.
   *
   * The binary's own vtable (`??_7CUIWorldView@Moho@@6B@`, VA 0x00E49074)
   * overrides exactly four of `CMauiControl`'s slots - `DoRender` (+0x18),
   * `SetHidden` (+0x1C), `HandleEvent` (+0x30) and `Frame` (+0x34) - plus the
   * reflection pair and the deleting destructor at the head; everything else is
   * inherited. The second vtable the constructor installs at +0x11C belongs to
   * the `IRenderWorldView` sub-object, which is still reached through
   * `CUIWorldViewRuntimeView::mRenderWorldView`.
   */
  /**
   * Second-base evidence (re-read out of `bin/external/ForgedAlliance.exe`):
   *
   * `CUIWorldView`'s complete-object locator at 0x00E9BCD8 lists nine entries
   * in its base-class array, the last of which is
   * `.?AVIRenderWorldView@Moho@@` at `mdisp = 0x11C`, and the constructor
   * (0x0086E4EF) installs `??_7CUIWorldView@Moho@@6BIRenderWorldView@Moho@@@`
   * - the derived class's override table for that secondary base - at
   * `[this+11Ch]`. The secondary locator behind it (0x00E490D8) records
   * `offset = 0x11C` and names `.?AVCUIWorldView@Moho@@`, so every field from
   * +0x120 up belongs to this class through that sub-object.
   *
   * `Moho::CRenderWorldView` is NOT a class in the shipped image - the string
   * `.?AVCRenderWorldView@Moho@@` does not appear anywhere in it. It is this
   * tree's name for exactly that `IRenderWorldView`-derived portion, and every
   * method it declares is a slot of the secondary vtable above (slot 0
   * 0x0086EE00 `Render`, slot 10 0x0086DC90 `IsMiniMap`, ...). Deriving from
   * it here is therefore layout-exact rather than an invention:
   * `sizeof(CMauiControl) == 0x11C` + `sizeof(CRenderWorldView) == 0x18C`
   * == 0x2A8, the size the sole allocation site asks the UI heap for.
   */
  class CUIWorldView : public CMauiControl, public CRenderWorldView
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0086DB70 (FUN_0086DB70, Moho::CUIWorldView::StaticGetClass)
     *
     * What it does:
     * Returns the cached reflection type for `CUIWorldView`, resolving it via
     * RTTI on first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x0086E480 (FUN_0086E480, Moho::CUIWorldView::CUIWorldView)
     *
     * What it does:
     * Constructs a world-view control in place: `CMauiControl` base, the render
     * and command-mode lanes, the camera (promoted to world camera or minimap
     * when asked), registration of the render-world-view with the global
     * viewport, then the `WorldViewParams` read from
     * `/lua/ui/controls/worldview.lua`.
     */
    CUIWorldView(
      LuaPlus::LuaObject* luaObject,
      CMauiControl* parent,
      const char* cameraName,
      int depth,
      bool isMiniMap,
      const char* cameraTrack
    );

    /**
     * Address: 0x0086EA40 (FUN_0086EA40, Moho::CUIWorldView::~CUIWorldView)
     * Deleting dtor: 0x0086EA20 (FUN_0086EA20, Moho::CUIWorldView::dtr)
     *
     * What it does:
     * Cancels any active dragger, unregisters the render-world-view from the
     * global viewport, unlinks the weak sentinel that tracks this view, then
     * releases the camera-track name, build-drag sub-object, command-graph
     * reference, both command-mode blocks and the camera.
     */
    ~CUIWorldView() override;

    /**
     * Address: 0x0086DB70 (FUN_0086DB70, Moho::CUIWorldView::GetClass)
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0086DB90 (FUN_0086DB90, Moho::CUIWorldView::GetDerivedObjectRef)
     *
     * VFTable SLOT: 1
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0086EF40 (FUN_0086EF40, Moho::CUIWorldView::DoRender)
     *
     * VFTable SLOT: 6 (+0x18)
     *
     * What it does:
     * Refreshes the world-view viewport bounds from the layout lazy-vars when
     * drawing world content, otherwise dispatches the overlay draw callback.
     */
    void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) override;

    /**
     * Address: 0x0086EC40 (FUN_0086EC40, Moho::CUIWorldView::SetHidden)
     *
     * VFTable SLOT: 7 (+0x1C)
     *
     * What it does:
     * Forwards the hidden state to the base and then removes (hiding) or adds
     * (showing) the render-world-view in the global viewport.
     */
    void SetHidden(bool hidden) override;

    /**
     * Address: 0x008704B0 (FUN_008704B0, Moho::CUIWorldView::HandleEvent)
     * Mangled: ?HandleEvent@CUIWorldView@Moho@@UAE_NABUSMauiEventData@2@@Z
     *
     * VFTable SLOT: 12 (+0x30)
     *
     * IDA signature:
     * bool __thiscall Moho::CUIWorldView::HandleEvent(
     *   Moho::CUIWorldView *this, const Moho::SMauiEventData *eventData);
     *
     * What it does:
     * The world view's whole pointer-input front end. Tracks cursor
     * enter/exit (dropping any in-progress camera rotation and mid-mouse
     * scrub on the way out), refreshes hover selection, and lets the
     * `CMauiControl` base and the input lock claim the event first. It then
     * raises the two command-graph hover banners - "double-click for
     * coordinated attack" when the hovered command is an Attack/FormAttack
     * none of the selection participates in, "click to convert moves into
     * patrol" when it is a Move/FormMove that can be restarted as patrol -
     * before dispatching, in the binary's own order: wheel rotation (command
     * mode, else camera pivot + zoom), motion (space-drag camera spin or
     * rotation revert, then camera pivot), middle-press (command mode, else a
     * `CameraDragger`), left double-click (finalize a pending drag formation,
     * else dispatch the left command or double-click-select), left press
     * (build/minimap/selection/reclaim dragger or left-command dispatch by
     * command mode), right double-click (coordinated-attack drag formation),
     * and right release (shift+ctrl strips the hovered command from every unit
     * under the cursor, otherwise the stored right-button command runs). Every
     * arm that ends a drag resets the session's formation state.
     */
    [[nodiscard]] bool HandleEvent(const SMauiEventData& eventData) override;

    /**
     * Address: 0x0086F520 (FUN_0086F520, Moho::CUIWorldView::UpdateSelection)
     *
     * IDA signature:
     * void __stdcall Moho::CUIWorldView::UpdateSelection(
     *   Moho::CUIWorldView *this, Wm3::Vector2f *mouse);
     *
     * What it does:
     * Rebuilds the world-view's hover/cursor state for one frame: raycasts
     * the mouse through the terrain to get the world hit point and,
     * whenever the raycast lands on the terrain, either persists that hit
     * directly (cursor left the view since the last update) or scores every
     * spatial-DB entity inside a screen-tolerance selection volume around
     * the cursor - filtered by `SELECTABLE`/`FERRYBEACON`/`UNTARGETABLE`
     * category, focus-army/playable-map visibility, and unit selection-mask
     * state - by projected screen distance to pick the closest hover
     * candidate, redirecting an unfinished unit's hover to its builder when
     * the blueprint upgrade-source name matches, or to a carrier/factory
     * attachment parent when the hovered entity is itself
     * transportation-attached. Updates the command-graph waypoint highlight
     * height, re-anchors the active build-template extractor preview onto
     * the nearest mass/hydro deposit when one is queued, and finally
     * persists the resolved cursor state into `mWldSession->CursorInfo()`.
     */
    void UpdateSelection(const Wm3::Vector2f& mouseScreenPos);

    /**
     * Address: 0x00871140 (FUN_00871140, Moho::CUIWorldView::Frame)
     *
     * IDA signature:
     * void __thiscall Moho::CUIWorldView::OnFrame(
     *   Moho::CUIWorldView *this, float deltaSeconds);
     *
     * VFTable SLOT: 13 (+0x34)
     *
     * What it does:
     * The world view's per-frame update hook. Processes any active
     * mid-mouse scrub, then - while the cursor is inside this view and not
     * scrubbing - refreshes hover selection and fires the `OnUpdateCursor`
     * script hook. While input is not locked, reverts an in-progress camera
     * rotation drag on Space release, and - for the view that owns global
     * camera commands - applies Insert/Delete keyboard camera spin,
     * keyboard/screen-edge/arrow-key camera pan, refreshes the
     * `OnIconsVisible` script hook on a visibility-state change, and fires
     * `OnFrame(deltaSeconds)`.
     */
    void Frame(float deltaSeconds) override;
  };

  // 0x11C (CMauiControl) + 0x18C (the IRenderWorldView sub-object at +0x11C)
  // == the 0x2A8 the Lua `__init` binder allocates for one world view.
  static_assert(sizeof(CUIWorldView) == 0x2A8, "CUIWorldView size must be 0x2A8");
  // The secondary base must land exactly on the +0x11C the constructor writes
  // its override table to (0x0086E4EF). MSVC lays non-virtual bases out in
  // declaration order, so this is `sizeof(CMauiControl)` - assert the two
  // agree rather than trusting the ordering silently.
  static_assert(
    sizeof(CMauiControl) == 0x11C,
    "CRenderWorldView sub-object must start at CUIWorldView+0x11C"
  );


  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CMauiCurrentFocusControlRuntimeView) == 0x8, "CMauiCurrentFocusControlRuntimeView size must be 0x8");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCurrentFocusControlRuntimeView, mFocusedControlPrevNextField) == 0x0,
    "CMauiCurrentFocusControlRuntimeView::mFocusedControlPrevNextField offset must be 0x0"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiCurrentFocusControlRuntimeView, mNextPrevNextField) == 0x4,
    "CMauiCurrentFocusControlRuntimeView::mNextPrevNextField offset must be 0x4"
  );

  extern CMauiCurrentFocusControlRuntimeView Maui_CurrentFocusControl;
  extern bool Maui_ControlHasFocus;

  /**
   * Address: 0x0079CC10 (FUN_0079CC10, Moho::MAUI_SetKeyboardFocus)
   *
   * What it does:
   * Updates global focus-owner intrusive link and notifies previous owner.
   */
  void MAUI_SetKeyboardFocus(CMauiControl* control, bool blocksKeyDown);

  /**
   * Address: 0x0079CB70 (FUN_0079CB70, Moho::MAUI_KeyIsDown)
   *
   * What it does:
   * Returns current key-down state for one Maui key code when the GAL window
   * is foreground and keyboard focus does not block global key polling.
   */
  [[nodiscard]] bool MAUI_KeyIsDown(EMauiKeyCode keyCode);

  struct CMauiFrameRuntimeView : CMauiControlExtendedRuntimeView
  {
    boost::weak_ptr<CMauiFrame> mSelfWeak; // +0x11C
    TDatList<CMauiControl, void> mDeletedControlList{}; // +0x124
    wxEvtHandlerRuntime* mEventHandler = nullptr;
    std::int32_t mTargetHead = -1;

    [[nodiscard]] static CMauiFrameRuntimeView* FromFrame(CMauiFrame* frame) noexcept
    {
      return reinterpret_cast<CMauiFrameRuntimeView*>(frame);
    }

    [[nodiscard]] static const CMauiFrameRuntimeView* FromFrame(const CMauiFrame* frame) noexcept
    {
      return reinterpret_cast<const CMauiFrameRuntimeView*>(frame);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiFrameRuntimeView, mSelfWeak) == 0x11C, "CMauiFrameRuntimeView::mSelfWeak offset must be 0x11C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiFrameRuntimeView, mDeletedControlList) == 0x124,
    "CMauiFrameRuntimeView::mDeletedControlList offset must be 0x124"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiFrameRuntimeView, mRenderPass) == 0xF8, "CMauiFrameRuntimeView::mRenderPass offset must be 0xF8");
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(boost::weak_ptr<CMauiFrame>) == 0x8, "boost::weak_ptr<CMauiFrame> size must be 0x8");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiFrameRuntimeView, mEventHandler) > offsetof(CMauiFrameRuntimeView, mSelfWeak));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiFrameRuntimeView, mTargetHead) > offsetof(CMauiFrameRuntimeView, mEventHandler));

  struct CMauiBitmapRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    // The MSVC8 vector is 0x10 bytes - it carries its allocator as a real data
    // member ahead of the first/last/end triple - so this container already
    // covers 0x11C..0x12B and the next field follows immediately. The 4 bytes
    // of padding that used to sit here double-counted that allocator word and
    // pushed every field from mBitmapWidthLV onwards 4 bytes too high, so a
    // bitmap wrote past the object the binary allocates for it and over its
    // neighbours. Same trap as the one called out on
    // CMauiControlExtendedRuntimeView::mRenderedChildren.
    msvc8::vector<boost::shared_ptr<CD3DBatchTexture>> mTextureBatches; // +0x11C
    CScriptLazyVar_float mBitmapWidthLV{};  // +0x12C
    CScriptLazyVar_float mBitmapHeightLV{}; // +0x140
    float mU0 = 0.0f; // +0x154
    float mV0 = 0.0f; // +0x158
    float mU1 = 0.0f; // +0x15C
    float mV1 = 0.0f; // +0x160
    void* mHitMask = nullptr; // +0x164
    bool mUseAlphaHitTest = false; // +0x168
    bool mIsTiled = false;         // +0x169
    std::uint8_t mUnknown16ATo16B[0x2]{};
    float mFrameDurationSeconds = 0.0f; // +0x16C
    bool mIsPlaying = false; // +0x170
    bool mDoLoop = false;    // +0x171
    std::uint8_t mUnknown172To173[0x2]{};
    std::int32_t mCurrentFrame = 0; // +0x174
    float mCurrentFrameTimeSeconds = 0.0f; // +0x178
    std::uint8_t mUnknown17CTo17F[0x4]{};
    msvc8::vector<std::int32_t> mFrames; // +0x180

    [[nodiscard]] static CMauiBitmapRuntimeView* FromBitmap(CMauiBitmap* bitmap) noexcept
    {
      return reinterpret_cast<CMauiBitmapRuntimeView*>(bitmap);
    }

    [[nodiscard]] static const CMauiBitmapRuntimeView* FromBitmap(const CMauiBitmap* bitmap) noexcept
    {
      return reinterpret_cast<const CMauiBitmapRuntimeView*>(bitmap);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mTextureBatches) == 0x11C,
    "CMauiBitmapRuntimeView::mTextureBatches offset must be 0x11C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mBitmapWidthLV) == 0x12C,
    "CMauiBitmapRuntimeView::mBitmapWidthLV offset must be 0x12C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mBitmapHeightLV) == 0x140,
    "CMauiBitmapRuntimeView::mBitmapHeightLV offset must be 0x140"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mU0) == 0x154, "CMauiBitmapRuntimeView::mU0 offset must be 0x154");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mV0) == 0x158, "CMauiBitmapRuntimeView::mV0 offset must be 0x158");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mU1) == 0x15C, "CMauiBitmapRuntimeView::mU1 offset must be 0x15C");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mV1) == 0x160, "CMauiBitmapRuntimeView::mV1 offset must be 0x160");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mHitMask) == 0x164, "CMauiBitmapRuntimeView::mHitMask offset must be 0x164");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mUseAlphaHitTest) == 0x168,
    "CMauiBitmapRuntimeView::mUseAlphaHitTest offset must be 0x168"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mIsTiled) == 0x169,
    "CMauiBitmapRuntimeView::mIsTiled offset must be 0x169"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mFrameDurationSeconds) == 0x16C,
    "CMauiBitmapRuntimeView::mFrameDurationSeconds offset must be 0x16C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mIsPlaying) == 0x170, "CMauiBitmapRuntimeView::mIsPlaying offset must be 0x170");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mDoLoop) == 0x171, "CMauiBitmapRuntimeView::mDoLoop offset must be 0x171");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mCurrentFrame) == 0x174, "CMauiBitmapRuntimeView::mCurrentFrame offset must be 0x174");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiBitmapRuntimeView, mCurrentFrameTimeSeconds) == 0x178,
    "CMauiBitmapRuntimeView::mCurrentFrameTimeSeconds offset must be 0x178"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBitmapRuntimeView, mFrames) == 0x180, "CMauiBitmapRuntimeView::mFrames offset must be 0x180");

  struct CMauiEditRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    CMauiEditClickDragger mClickDragger{}; // +0x11C (embedded IMauiDragger sub-object)
    CD3DFont* mFont = nullptr;          // +0x124
    std::uint32_t mForegroundColor = 0; // +0x128
    bool mBackgroundVisible = false;    // +0x12C
    std::uint8_t mUnknown12DTo12F[0x3]{};
    std::uint32_t mBackgroundColor = 0; // +0x130
    std::uint32_t mHighlightForegroundColor = 0; // +0x134
    std::uint32_t mHighlightBackgroundColor = 0; // +0x138
    bool mDropShadow = false;                    // +0x13C
    bool mIsEnabled = false;                     // +0x13D
    std::uint8_t mPad13ETo13F[0x2]{};
    msvc8::string mText{};              // +0x140
    std::int32_t mCaretPosition = 0;    // +0x15C
    bool mCaretVisible = false;         // +0x160
    std::uint8_t mUnknown161To163[0x3]{};
    std::uint32_t mCaretColor = 0;      // +0x164
    std::uint32_t mCaretCycleCurrentAlpha = 0; // +0x168
    float mCaretCycleSeconds = 0.0f;    // +0x16C
    std::uint32_t mCaretCycleOnAlpha = 0; // +0x170
    std::uint32_t mCaretCycleOffAlpha = 0; // +0x174
    float mCaretCycleTime = 0.0f;       // +0x178
    std::int32_t mClipOffset = 0;         // +0x17C
    std::int32_t mClipLength = 0;         // +0x180
    std::int32_t mSelectionStart = 0;     // +0x184
    std::int32_t mSelectionEnd = 0;       // +0x188
    std::int32_t mDragStart = 0;          // +0x18C
    bool mTextChangeCallbackInProgress = false; // +0x190
    std::uint8_t mPad191To193[0x3]{};
    std::int32_t mMaxChars = 0;           // +0x194

    [[nodiscard]] static CMauiEditRuntimeView* FromEdit(CMauiEdit* edit) noexcept
    {
      return reinterpret_cast<CMauiEditRuntimeView*>(edit);
    }

    [[nodiscard]] static const CMauiEditRuntimeView* FromEdit(const CMauiEdit* edit) noexcept
    {
      return reinterpret_cast<const CMauiEditRuntimeView*>(edit);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mFont) == 0x124,
    "CMauiEditRuntimeView::mFont offset must be 0x124"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mClickDragger) == 0x11C,
    "CMauiEditRuntimeView::mClickDragger offset must be 0x11C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mForegroundColor) == 0x128,
    "CMauiEditRuntimeView::mForegroundColor offset must be 0x128"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mBackgroundVisible) == 0x12C,
    "CMauiEditRuntimeView::mBackgroundVisible offset must be 0x12C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mBackgroundColor) == 0x130,
    "CMauiEditRuntimeView::mBackgroundColor offset must be 0x130"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mHighlightForegroundColor) == 0x134,
    "CMauiEditRuntimeView::mHighlightForegroundColor offset must be 0x134"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mHighlightBackgroundColor) == 0x138,
    "CMauiEditRuntimeView::mHighlightBackgroundColor offset must be 0x138"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mDropShadow) == 0x13C, "CMauiEditRuntimeView::mDropShadow offset must be 0x13C");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mIsEnabled) == 0x13D, "CMauiEditRuntimeView::mIsEnabled offset must be 0x13D");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mText) == 0x140, "CMauiEditRuntimeView::mText offset must be 0x140");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretPosition) == 0x15C,
    "CMauiEditRuntimeView::mCaretPosition offset must be 0x15C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mCaretVisible) == 0x160, "CMauiEditRuntimeView::mCaretVisible offset must be 0x160");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mCaretColor) == 0x164, "CMauiEditRuntimeView::mCaretColor offset must be 0x164");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretCycleCurrentAlpha) == 0x168,
    "CMauiEditRuntimeView::mCaretCycleCurrentAlpha offset must be 0x168"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretCycleSeconds) == 0x16C,
    "CMauiEditRuntimeView::mCaretCycleSeconds offset must be 0x16C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretCycleOnAlpha) == 0x170,
    "CMauiEditRuntimeView::mCaretCycleOnAlpha offset must be 0x170"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretCycleOffAlpha) == 0x174,
    "CMauiEditRuntimeView::mCaretCycleOffAlpha offset must be 0x174"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mCaretCycleTime) == 0x178,
    "CMauiEditRuntimeView::mCaretCycleTime offset must be 0x178"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mClipOffset) == 0x17C,
    "CMauiEditRuntimeView::mClipOffset offset must be 0x17C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mClipLength) == 0x180,
    "CMauiEditRuntimeView::mClipLength offset must be 0x180"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mSelectionStart) == 0x184,
    "CMauiEditRuntimeView::mSelectionStart offset must be 0x184"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mSelectionEnd) == 0x188,
    "CMauiEditRuntimeView::mSelectionEnd offset must be 0x188"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiEditRuntimeView, mDragStart) == 0x18C, "CMauiEditRuntimeView::mDragStart offset must be 0x18C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mTextChangeCallbackInProgress) == 0x190,
    "CMauiEditRuntimeView::mTextChangeCallbackInProgress offset must be 0x190"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiEditRuntimeView, mMaxChars) == 0x194,
    "CMauiEditRuntimeView::mMaxChars offset must be 0x194"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CMauiEditRuntimeView) == 0x198, "CMauiEditRuntimeView size must be 0x198");

  /**
   * One histogram data series ("column"). Layout: 0x14 bytes. Only the value
   * buffer at +0x08 owns heap storage; it is released (and the whole column
   * array freed) when the owning CMauiHistogram is destroyed, via
   * `ReleaseHistogramColumnValueBuffers` (FUN_00798D10, UiRuntimeTypes.cpp).
   */
  struct SHistogramColumn
  {
    std::uint32_t field_0x00 = 0;      // +0x00 (packed color from Moho::SCR_DecodeColor)
    std::uint32_t field_0x04 = 0;      // +0x04
    float* mValues = nullptr;          // +0x08 owned per-bar value buffer (begin)
    float* mValuesEnd = nullptr;       // +0x0C
    float* mValuesCapacity = nullptr;  // +0x10
  };
  static_assert(sizeof(SHistogramColumn) == 0x14, "SHistogramColumn size must be 0x14");
  static_assert(offsetof(SHistogramColumn, mValues) == 0x08, "SHistogramColumn::mValues offset must be 0x08");

  struct CMauiHistogramRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    std::int32_t mXIncrement = 0;              // +0x11C
    std::int32_t mYIncrement = 0;              // +0x120
    // +0x124 is a real field of this control that was missing from the model,
    // so the column-array triple below sat 4 bytes low and a histogram wrote
    // past the object the binary allocates for it. No histogram function in
    // the binary reads or writes +0x124 - the constructor at 0x007977A0 and
    // the destructor at 0x00797840 touch only 0x128/0x12C/0x130 - so its
    // meaning is still unknown. It is deliberately not modelled as an MSVC8
    // vector allocator proxy: SHistogramColumn keeps its own value buffer as a
    // bare begin/end/capacity triple with no proxy word (sizeof 0x14), so this
    // control does not use vectors for its arrays.
    std::uint8_t mUnknown124To127[0x4]{};      // +0x124
    SHistogramColumn* mDataStart = nullptr;    // +0x128 column-array begin (owned)
    SHistogramColumn* mDataEnd = nullptr;      // +0x12C column-array end
    SHistogramColumn* mDataCapacity = nullptr; // +0x130 column-array capacity

    [[nodiscard]] static CMauiHistogramRuntimeView* FromHistogram(CMauiHistogram* histogram) noexcept
    {
      return reinterpret_cast<CMauiHistogramRuntimeView*>(histogram);
    }

    [[nodiscard]] static const CMauiHistogramRuntimeView* FromHistogram(const CMauiHistogram* histogram) noexcept
    {
      return reinterpret_cast<const CMauiHistogramRuntimeView*>(histogram);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiHistogramRuntimeView, mXIncrement) == 0x11C,
    "CMauiHistogramRuntimeView::mXIncrement offset must be 0x11C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiHistogramRuntimeView, mYIncrement) == 0x120,
    "CMauiHistogramRuntimeView::mYIncrement offset must be 0x120"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiHistogramRuntimeView, mDataStart) == 0x128,
    "CMauiHistogramRuntimeView::mDataStart offset must be 0x128"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiHistogramRuntimeView, mDataEnd) == 0x12C,
    "CMauiHistogramRuntimeView::mDataEnd offset must be 0x12C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiHistogramRuntimeView, mDataCapacity) == 0x130,
    "CMauiHistogramRuntimeView::mDataCapacity offset must be 0x130"
  );

  struct CMauiItemListRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    CD3DFont* mFont = nullptr; // +0x11C
    std::uint32_t mForegroundColor = 0;         // +0x120
    std::uint32_t mBackgroundColor = 0;         // +0x124
    std::uint32_t mSelectedForegroundColor = 0; // +0x128
    std::uint32_t mSelectedBackgroundColor = 0; // +0x12C
    std::uint32_t mHighlightForegroundColor = 0; // +0x130
    std::uint32_t mHighlightBackgroundColor = 0; // +0x134
    msvc8::vector<msvc8::string> mItems; // +0x138
    std::int32_t mCurSelection = -1; // +0x148
    std::int32_t mHoverItem = -1; // +0x14C
    bool mShowSelection = false; // +0x150
    bool mShowMouseoverItem = false; // +0x151
    std::uint8_t mPad152To153[0x2]{};
    std::int32_t mScrollPosition = 0; // +0x154

    [[nodiscard]] static CMauiItemListRuntimeView* FromItemList(CMauiItemList* itemList) noexcept
    {
      return reinterpret_cast<CMauiItemListRuntimeView*>(itemList);
    }

    [[nodiscard]] static const CMauiItemListRuntimeView* FromItemList(const CMauiItemList* itemList) noexcept
    {
      return reinterpret_cast<const CMauiItemListRuntimeView*>(itemList);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(msvc8::vector<msvc8::string>) == 0x10, "msvc8::vector<msvc8::string> size must be 0x10");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiItemListRuntimeView, mFont) == 0x11C, "CMauiItemListRuntimeView::mFont offset must be 0x11C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mForegroundColor) == 0x120,
    "CMauiItemListRuntimeView::mForegroundColor offset must be 0x120"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mBackgroundColor) == 0x124,
    "CMauiItemListRuntimeView::mBackgroundColor offset must be 0x124"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mSelectedForegroundColor) == 0x128,
    "CMauiItemListRuntimeView::mSelectedForegroundColor offset must be 0x128"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mSelectedBackgroundColor) == 0x12C,
    "CMauiItemListRuntimeView::mSelectedBackgroundColor offset must be 0x12C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mHighlightForegroundColor) == 0x130,
    "CMauiItemListRuntimeView::mHighlightForegroundColor offset must be 0x130"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mHighlightBackgroundColor) == 0x134,
    "CMauiItemListRuntimeView::mHighlightBackgroundColor offset must be 0x134"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiItemListRuntimeView, mItems) == 0x138, "CMauiItemListRuntimeView::mItems offset must be 0x138");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mCurSelection) == 0x148,
    "CMauiItemListRuntimeView::mCurSelection offset must be 0x148"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mHoverItem) == 0x14C,
    "CMauiItemListRuntimeView::mHoverItem offset must be 0x14C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mShowSelection) == 0x150,
    "CMauiItemListRuntimeView::mShowSelection offset must be 0x150"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mShowMouseoverItem) == 0x151,
    "CMauiItemListRuntimeView::mShowMouseoverItem offset must be 0x151"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiItemListRuntimeView, mScrollPosition) == 0x154,
    "CMauiItemListRuntimeView::mScrollPosition offset must be 0x154"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(sizeof(CMauiItemListRuntimeView) == 0x158, "CMauiItemListRuntimeView size must be 0x158");

  struct CMauiTextRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    CD3DFont* mFont = nullptr; // +0x11C
    msvc8::string mText{}; // +0x120
    std::uint32_t mColor = 0; // +0x13C
    bool mDropShadow = false; // +0x140
    bool mClipToWidth = false; // +0x141
    bool mCenteredHorizontally = false; // +0x142
    bool mCenteredVertically = false; // +0x143
    CScriptLazyVar_float mTextAdvanceLV{}; // +0x144
    CScriptLazyVar_float mFontAscentLV{}; // +0x158
    CScriptLazyVar_float mFontDescentLV{}; // +0x16C
    CScriptLazyVar_float mFontExternalLeadingLV{}; // +0x180

    [[nodiscard]] static CMauiTextRuntimeView* FromText(CMauiText* text) noexcept
    {
      return reinterpret_cast<CMauiTextRuntimeView*>(text);
    }

    [[nodiscard]] static const CMauiTextRuntimeView* FromText(const CMauiText* text) noexcept
    {
      return reinterpret_cast<const CMauiTextRuntimeView*>(text);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiTextRuntimeView, mFont) == 0x11C, "CMauiTextRuntimeView::mFont offset must be 0x11C");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiTextRuntimeView, mText) == 0x120, "CMauiTextRuntimeView::mText offset must be 0x120");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiTextRuntimeView, mColor) == 0x13C, "CMauiTextRuntimeView::mColor offset must be 0x13C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mDropShadow) == 0x140,
    "CMauiTextRuntimeView::mDropShadow offset must be 0x140"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mClipToWidth) == 0x141,
    "CMauiTextRuntimeView::mClipToWidth offset must be 0x141"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mCenteredHorizontally) == 0x142,
    "CMauiTextRuntimeView::mCenteredHorizontally offset must be 0x142"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mCenteredVertically) == 0x143,
    "CMauiTextRuntimeView::mCenteredVertically offset must be 0x143"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mTextAdvanceLV) == 0x144,
    "CMauiTextRuntimeView::mTextAdvanceLV offset must be 0x144"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mFontAscentLV) == 0x158,
    "CMauiTextRuntimeView::mFontAscentLV offset must be 0x158"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mFontDescentLV) == 0x16C,
    "CMauiTextRuntimeView::mFontDescentLV offset must be 0x16C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiTextRuntimeView, mFontExternalLeadingLV) == 0x180,
    "CMauiTextRuntimeView::mFontExternalLeadingLV offset must be 0x180"
  );

  struct CMauiMeshRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    boost::shared_ptr<CD3DBatchTexture> mTexture; // +0x11C
    bool mIsRotated = false; // +0x124
    std::uint8_t mPad125To127[0x3]{};
    RMeshBlueprint* mMeshBlueprint = nullptr; // +0x128
    Wm3::Quaternionf mOrientation{}; // +0x12C
    std::int32_t mUnknown13C = 0; // +0x13C

    [[nodiscard]] static CMauiMeshRuntimeView* FromMesh(CMauiMesh* mesh) noexcept
    {
      return reinterpret_cast<CMauiMeshRuntimeView*>(mesh);
    }

    [[nodiscard]] static const CMauiMeshRuntimeView* FromMesh(const CMauiMesh* mesh) noexcept
    {
      return reinterpret_cast<const CMauiMeshRuntimeView*>(mesh);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiMeshRuntimeView, mIsRotated) == 0x124, "CMauiMeshRuntimeView::mIsRotated offset must be 0x124");
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiMeshRuntimeView, mTexture) == 0x11C, "CMauiMeshRuntimeView::mTexture offset must be 0x11C");
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiMeshRuntimeView, mMeshBlueprint) == 0x128,
    "CMauiMeshRuntimeView::mMeshBlueprint offset must be 0x128"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiMeshRuntimeView, mOrientation) == 0x12C,
    "CMauiMeshRuntimeView::mOrientation offset must be 0x12C"
  );
  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CMauiMeshRuntimeView, mUnknown13C) == 0x13C,
    "CMauiMeshRuntimeView::mUnknown13C offset must be 0x13C"
  );

  struct CMauiBorderRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To0F3[0x20]{};
    std::uint32_t mVertexAlpha = 0; // +0xF4
    std::uint8_t mUnknown0F8To11B[0x24]{};
    boost::shared_ptr<CD3DBatchTexture> mTex1;    // +0x11C
    boost::shared_ptr<CD3DBatchTexture> mTexHorz; // +0x124
    boost::shared_ptr<CD3DBatchTexture> mTexUL;   // +0x12C
    boost::shared_ptr<CD3DBatchTexture> mTexUR;   // +0x134
    boost::shared_ptr<CD3DBatchTexture> mTexLL;   // +0x13C
    boost::shared_ptr<CD3DBatchTexture> mTexLR;   // +0x144
    CScriptLazyVar_float mBorderWidthLV;          // +0x14C
    CScriptLazyVar_float mBorderHeightLV;         // +0x160

    [[nodiscard]] static CMauiBorderRuntimeView* FromBorder(CMauiBorder* border) noexcept
    {
      return reinterpret_cast<CMauiBorderRuntimeView*>(border);
    }

    [[nodiscard]] static const CMauiBorderRuntimeView* FromBorder(const CMauiBorder* border) noexcept
    {
      return reinterpret_cast<const CMauiBorderRuntimeView*>(border);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mVertexAlpha) > offsetof(CMauiControlRuntimeView, mHeightLV));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTex1) > offsetof(CMauiBorderRuntimeView, mVertexAlpha));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTexHorz) > offsetof(CMauiBorderRuntimeView, mTex1));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTexUL) > offsetof(CMauiBorderRuntimeView, mTexHorz));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTexUR) > offsetof(CMauiBorderRuntimeView, mTexUL));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTexLL) > offsetof(CMauiBorderRuntimeView, mTexUR));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mTexLR) > offsetof(CMauiBorderRuntimeView, mTexLL));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mBorderWidthLV) > offsetof(CMauiBorderRuntimeView, mTexLR));
  FAF_RUNTIME_LAYOUT_ASSERT(offsetof(CMauiBorderRuntimeView, mBorderHeightLV) > offsetof(CMauiBorderRuntimeView, mBorderWidthLV));

  struct CUIMapPreviewRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0D4To11B[0x48]{};
    boost::shared_ptr<ID3DTextureSheet> mTexture; // +0x11C

    [[nodiscard]] static CUIMapPreviewRuntimeView* FromMapPreview(CUIMapPreview* mapPreview) noexcept
    {
      return reinterpret_cast<CUIMapPreviewRuntimeView*>(mapPreview);
    }

    [[nodiscard]] static const CUIMapPreviewRuntimeView* FromMapPreview(const CUIMapPreview* mapPreview) noexcept
    {
      return reinterpret_cast<const CUIMapPreviewRuntimeView*>(mapPreview);
    }
  };

  FAF_RUNTIME_LAYOUT_ASSERT(
    offsetof(CUIMapPreviewRuntimeView, mTexture) == 0x11C,
    "CUIMapPreviewRuntimeView::mTexture offset must be 0x11C"
  );

  /**
   * Address: 0x008C65B0 (FUN_008C65B0, Moho::USER_GetLuaState)
   *
   * What it does:
   * Lazily initializes and returns the process user Lua state, wiring the user
   * task stage, script-disk watcher task, and core/user init-form execution.
   */
  [[nodiscard]] LuaPlus::LuaState* USER_GetLuaState();

  /**
   * Address: 0x0083CD30 (FUN_0083CD30, Moho::MAUI_StartMainScript)
   *
   * What it does:
   * Imports `/lua/ui/uimain.lua`, resolves `SetupUI`, and executes the entry
   * callback against the active UI Lua state.
   */
  [[nodiscard]] bool MAUI_StartMainScript();

  /**
   * Address: 0x0083D810 (FUN_0083D810, Moho::MAUI_ToggleConsole)
   *
   * What it does:
   * Imports `/lua/ui/uimain.lua`, resolves `ToggleConsole`, and executes the
   * callback against the active UI Lua state.
   */
  void MAUI_ToggleConsole();

  /**
   * Address: 0x0078CEF0 (FUN_0078CEF0, sub_78CEF0)
   *
   * What it does:
   * Commits pending cursor texture/visibility state to the D3D device when
   * the cursor default/show flags have changed.
   */
  void MAUI_UpdateCursor(CMauiCursor* cursor);
  void MAUI_ReleaseCursor(CMauiCursor* cursor);

  /**
   * Address: 0x0078CFD0 (FUN_0078CFD0, cfunc__c_CreateCursor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc__c_CreateCursorL`.
   */
  int cfunc__c_CreateCursor(lua_State* luaContext);

  /**
   * Address: 0x0078CFF0 (FUN_0078CFF0, func__c_CreateCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `_c_CreateCursor` into the user
   * Lua init-form registration set.
   */
  CScrLuaInitForm* func__c_CreateCursor_LuaFuncDef();

  /**
   * Address: 0x0078D050 (FUN_0078D050, cfunc__c_CreateCursorL)
   *
   * What it does:
   * Validates `(luaobj, spec)` argument shape, allocates one `CMauiCursor`
   * bound to the first Lua argument, and pushes the resulting cursor Lua
   * object back onto the stack.
   */
  int cfunc__c_CreateCursorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0083D670 (FUN_0083D670)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:NoteGameSpeedChanged(slotPlusOne, speed)`
   * against the active UI Lua state.
   */
  void UI_NoteGameSpeedChanged(std::int32_t slotZeroBased, std::int32_t gameSpeed);

  /**
   * Address: 0x0088BA50 (FUN_0088BA50, func_DriverNoteGameSpeedChanged)
   *
   * What it does:
   * Forwards game-speed UI notification only when a simulation driver is
   * active.
   */
  void UI_DriverNoteGameSpeedChanged(std::int32_t slotZeroBased, std::int32_t gameSpeed);

  /**
   * Address: 0x0088B9B0 (FUN_0088B9B0, Moho::CWldUiInterface::ReportBottleneck)
   *
   * What it does:
   * Forwards one assembled bottleneck snapshot into the GPGNet reporting lane.
   */
  /**
   * Address: 0x0088B810 (FUN_0088B810, Moho::CWldUiInterface::NoteDisconnect)
   *
   * What it does:
   * Posts the localized "%s disconnected." console notice for the given client
   * onto the main thread (CWldUiInterface's NoteDisconnect override).
   */
  void UI_NoteDisconnect(const IClient* client);

  /**
   * Address: 0x0088B880 (FUN_0088B880, Moho::CWldUiInterface::ReceiveChat)
   *
   * What it does:
   * Posts the received chat payload (decoded via func_ReceiveChat into the UI
   * Lua ReceiveChat callback) onto the main thread, tagged with the sender's
   * nickname. CWldUiInterface's ReceiveChat override.
   */
  void UI_ReceiveChat(const IClient* sender, gpg::MemBuffer<const char> data);

  /**
   * Address: 0x0088B960 (FUN_0088B960, Moho::CWldUiInterface::NoteGameSpeedChanged)
   *
   * What it does:
   * Posts the driver-gated game-speed-changed notice for this interface's local
   * player slot onto the main thread. CWldUiInterface's NoteGameSpeedChanged
   * override.
   */
  void UI_InterfaceNoteGameSpeedChanged(const IClientMgrUIInterface* self, std::int32_t gameSpeed);

  void UI_ReportBottleneck(const SClientBottleneckInfo& info);

  /**
   * Address: 0x0088B9C0 (FUN_0088B9C0, Moho::CWldUiInterface::ReportBottleneckCleared)
   *
   * What it does:
   * Reports that the current client bottleneck condition has been cleared.
   */
  void UI_ReportBottleneckCleared();

  /**
   * Address: 0x0083D740 (FUN_0083D740, ?UI_NoteGameOver@Moho@@YAXXZ)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:NoteGameOver()` through the active UI Lua
   * state.
   */
  void UI_NoteGameOver();

  /**
   * Address: 0x0083D9C0 (FUN_0083D9C0)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:OnApplicationResize(frameIdx, width, height)`.
   */
  void MAUI_OnApplicationResize(std::int32_t frameIdx, std::int32_t width, std::int32_t height);

  /**
   * Address: 0x0078D390 (FUN_0078D390, cfunc_CMauiCursorSetDefaultTexture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiCursorSetDefaultTextureL`.
   */
  int cfunc_CMauiCursorSetDefaultTexture(lua_State* luaContext);

  /**
   * Address: 0x0078D3B0 (FUN_0078D3B0, func_CMauiCursorSetDefaultTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiCursor:SetDefaultTexture(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiCursorSetDefaultTexture_LuaFuncDef();

  /**
   * Address: 0x0078D410 (FUN_0078D410, cfunc_CMauiCursorSetDefaultTextureL)
   *
   * What it does:
   * Reads one cursor object plus texture/hotspot Lua args and updates cursor
   * default texture/hotspot lanes.
   */
  int cfunc_CMauiCursorSetDefaultTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0078D130 (FUN_0078D130, cfunc_CMauiCursorSetNewTexture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiCursorSetNewTextureL`.
   */
  int cfunc_CMauiCursorSetNewTexture(lua_State* luaContext);

  /**
   * Address: 0x0078D150 (FUN_0078D150, func_CMauiCursorSetNewTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiCursor:SetNewTexture(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiCursorSetNewTexture_LuaFuncDef();

  /**
   * Address: 0x0078D1B0 (FUN_0078D1B0, cfunc_CMauiCursorSetNewTextureL)
   *
   * What it does:
   * Reads cursor texture/hotspot Lua args and applies them to one cursor.
   */
  int cfunc_CMauiCursorSetNewTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0078D5A0 (FUN_0078D5A0, cfunc_CMauiCursorResetToDefault)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiCursorResetToDefaultL`.
   */
  int cfunc_CMauiCursorResetToDefault(lua_State* luaContext);

  /**
   * Address: 0x0078D5C0 (FUN_0078D5C0, func_CMauiCursorResetToDefault_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiCursor:ResetToDefault()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiCursorResetToDefault_LuaFuncDef();

  /**
   * Address: 0x0078D620 (FUN_0078D620, cfunc_CMauiCursorResetToDefaultL)
   *
   * What it does:
   * Restores one cursor texture/hotspot state from default lanes.
   */
  int cfunc_CMauiCursorResetToDefaultL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0078D6C0 (FUN_0078D6C0, cfunc_CMauiCursorHide)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorHideL`.
   */
  int cfunc_CMauiCursorHide(lua_State* luaContext);

  /**
   * Address: 0x0078D6E0 (FUN_0078D6E0, func_CMauiCursorHide_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiCursor:Hide()` Lua binder metadata lane.
   */
  CScrLuaInitForm* func_CMauiCursorHide_LuaFuncDef();

  /**
   * Address: 0x0078D740 (FUN_0078D740, cfunc_CMauiCursorHideL)
   *
   * What it does:
   * Marks one cursor hidden in runtime texture-state lanes.
   */
  int cfunc_CMauiCursorHideL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0078D7F0 (FUN_0078D7F0, cfunc_CMauiCursorShow)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiCursorShowL`.
   */
  int cfunc_CMauiCursorShow(lua_State* luaContext);

  /**
   * Address: 0x0078D810 (FUN_0078D810, func_CMauiCursorShow_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiCursor:Show()` Lua binder metadata lane.
   */
  CScrLuaInitForm* func_CMauiCursorShow_LuaFuncDef();

  /**
   * Address: 0x0078D870 (FUN_0078D870, cfunc_CMauiCursorShowL)
   *
   * What it does:
   * Marks one cursor visible in runtime texture-state lanes.
   */
  int cfunc_CMauiCursorShowL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00787A50 (FUN_00787A50, cfunc_CMauiControlDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlDestroyL`.
   */
  int cfunc_CMauiControlDestroy(lua_State* luaContext);

  /**
   * Address: 0x00787A70 (FUN_00787A70, func_CMauiControlDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlDestroy_LuaFuncDef();

  /**
   * Address: 0x00787AD0 (FUN_00787AD0, cfunc_CMauiControlDestroyL)
   *
   * What it does:
   * Resolves optional `CMauiControl`, blocks root-frame destruction, and
   * destroys non-root controls.
   */
  int cfunc_CMauiControlDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00787BA0 (FUN_00787BA0, cfunc_CMauiControlGetParent)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetParentL`.
   */
  int cfunc_CMauiControlGetParent(lua_State* luaContext);

  /**
   * Address: 0x00787BC0 (FUN_00787BC0, func_CMauiControlGetParent_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetParent()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetParent_LuaFuncDef();

  /**
   * Address: 0x00787C20 (FUN_00787C20, cfunc_CMauiControlGetParentL)
   *
   * What it does:
   * Reads one `CMauiControl`, pushes parent control object when available, and
   * pushes `nil` otherwise.
   */
  int cfunc_CMauiControlGetParentL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00787CF0 (FUN_00787CF0, cfunc_CMauiControlClearChildren)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlClearChildrenL`.
   */
  int cfunc_CMauiControlClearChildren(lua_State* luaContext);

  /**
   * Address: 0x00787D10 (FUN_00787D10, func_CMauiControlClearChildren_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:ClearChildren()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlClearChildren_LuaFuncDef();

  /**
   * Address: 0x00787D70 (FUN_00787D70, cfunc_CMauiControlClearChildrenL)
   *
   * What it does:
   * Reads one `CMauiControl` and clears all child controls.
   */
  int cfunc_CMauiControlClearChildrenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00787E30 (FUN_00787E30, cfunc_CMauiControlSetParent)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetParentL`.
   */
  int cfunc_CMauiControlSetParent(lua_State* luaContext);

  /**
   * Address: 0x00787E50 (FUN_00787E50, func_CMauiControlSetParent_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetParent(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetParent_LuaFuncDef();

  /**
   * Address: 0x00787EB0 (FUN_00787EB0, cfunc_CMauiControlSetParentL)
   *
   * What it does:
   * Reads `CMauiControl` + parent control args, updates parent ownership, and
   * returns the control object lane.
   */
  int cfunc_CMauiControlSetParentL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00787FB0 (FUN_00787FB0, cfunc_CMauiControlDisableHitTest)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlDisableHitTestL`.
   */
  int cfunc_CMauiControlDisableHitTest(lua_State* luaContext);

  /**
   * Address: 0x00787FD0 (FUN_00787FD0, func_CMauiControlDisableHitTest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:DisableHitTest([recursive])` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlDisableHitTest_LuaFuncDef();

  /**
   * Address: 0x00788030 (FUN_00788030, cfunc_CMauiControlDisableHitTestL)
   *
   * What it does:
   * Reads one `CMauiControl` plus optional recursion boolean and disables hit
   * testing.
   */
  int cfunc_CMauiControlDisableHitTestL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788130 (FUN_00788130, cfunc_CMauiControlEnableHitTest)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlEnableHitTestL`.
   */
  int cfunc_CMauiControlEnableHitTest(lua_State* luaContext);

  /**
   * Address: 0x00788150 (FUN_00788150, func_CMauiControlEnableHitTest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:EnableHitTest([recursive])` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlEnableHitTest_LuaFuncDef();

  /**
   * Address: 0x007881B0 (FUN_007881B0, cfunc_CMauiControlEnableHitTestL)
   *
   * What it does:
   * Reads one `CMauiControl` plus optional recursion boolean and enables hit
   * testing.
   */
  int cfunc_CMauiControlEnableHitTestL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007882B0 (FUN_007882B0, cfunc_CMauiControlIsHitTestDisabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlIsHitTestDisabledL`.
   */
  int cfunc_CMauiControlIsHitTestDisabled(lua_State* luaContext);

  /**
   * Address: 0x007882D0 (FUN_007882D0, func_CMauiControlIsHitTestDisabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:IsHitTestDisabled()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlIsHitTestDisabled_LuaFuncDef();

  /**
   * Address: 0x00788330 (FUN_00788330, cfunc_CMauiControlIsHitTestDisabledL)
   *
   * What it does:
   * Reads one control and pushes `IsHitTestDisabled()` boolean result.
   */
  int cfunc_CMauiControlIsHitTestDisabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007883F0 (FUN_007883F0, cfunc_CMauiControlHide)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlHideL`.
   */
  int cfunc_CMauiControlHide(lua_State* luaContext);

  /**
   * Address: 0x00788410 (FUN_00788410, func_CMauiControlHide_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:Hide()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlHide_LuaFuncDef();

  /**
   * Address: 0x00788470 (FUN_00788470, cfunc_CMauiControlHideL)
   *
   * What it does:
   * Reads one `CMauiControl` and sets hidden-state to `true`.
   */
  int cfunc_CMauiControlHideL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788520 (FUN_00788520, cfunc_CMauiControlShow)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlShowL`.
   */
  int cfunc_CMauiControlShow(lua_State* luaContext);

  /**
   * Address: 0x00788540 (FUN_00788540, func_CMauiControlShow_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:Show()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlShow_LuaFuncDef();

  /**
   * Address: 0x007885A0 (FUN_007885A0, cfunc_CMauiControlShowL)
   *
   * What it does:
   * Reads one `CMauiControl` and sets hidden-state to `false`.
   */
  int cfunc_CMauiControlShowL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788650 (FUN_00788650, cfunc_CMauiControlSetHidden)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetHiddenL`.
   */
  int cfunc_CMauiControlSetHidden(lua_State* luaContext);

  /**
   * Address: 0x00788670 (FUN_00788670, func_CMauiControlSetHidden_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetHidden(hidden)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetHidden_LuaFuncDef();

  /**
   * Address: 0x007886D0 (FUN_007886D0, cfunc_CMauiControlSetHiddenL)
   *
   * What it does:
   * Reads one `CMauiControl` plus boolean hidden lane and applies it.
   */
  int cfunc_CMauiControlSetHiddenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788790 (FUN_00788790, cfunc_CMauiControlIsHidden)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlIsHiddenL`.
   */
  int cfunc_CMauiControlIsHidden(lua_State* luaContext);

  /**
   * Address: 0x007887B0 (FUN_007887B0, func_CMauiControlIsHidden_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:IsHidden()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlIsHidden_LuaFuncDef();

  /**
   * Address: 0x00788810 (FUN_00788810, cfunc_CMauiControlIsHiddenL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes its hidden-state to Lua.
   */
  int cfunc_CMauiControlIsHiddenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007888D0 (FUN_007888D0, cfunc_CMauiControlGetRenderPass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetRenderPassL`.
   */
  int cfunc_CMauiControlGetRenderPass(lua_State* luaContext);

  /**
   * Address: 0x007888F0 (FUN_007888F0, func_CMauiControlGetRenderPass_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetRenderPass()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetRenderPass_LuaFuncDef();

  /**
   * Address: 0x00788950 (FUN_00788950, cfunc_CMauiControlGetRenderPassL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes its render-pass lane to Lua.
   */
  int cfunc_CMauiControlGetRenderPassL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788A10 (FUN_00788A10, cfunc_CMauiControlSetRenderPass)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetRenderPassL`.
   */
  int cfunc_CMauiControlSetRenderPass(lua_State* luaContext);

  /**
   * Address: 0x00788A30 (FUN_00788A30, func_CMauiControlSetRenderPass_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetRenderPass(renderPass)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetRenderPass_LuaFuncDef();

  /**
   * Address: 0x00788A90 (FUN_00788A90, cfunc_CMauiControlSetRenderPassL)
   *
   * What it does:
   * Reads one `CMauiControl` plus integer render-pass lane from Lua and
   * stores it into the control runtime view.
   */
  int cfunc_CMauiControlSetRenderPassL(LuaPlus::LuaState* state);

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender)
   * -- no `Address:`, not part of the original 2007 binary.
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetCustomRenderL`.
   */
  int cfunc_CMauiControlSetCustomRender(lua_State* luaContext);

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender).
   *
   * What it does:
   * Publishes the `CMauiControl:SetCustomRender(enabled)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetCustomRender_LuaFuncDef();

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender).
   *
   * What it does:
   * Reads one `CMauiControl` plus a boolean from Lua and stores it into the
   * custom-render side table.
   */
  int cfunc_CMauiControlSetCustomRenderL(LuaPlus::LuaState* state);

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender)
   * -- no `Address:`, not part of the original 2007 binary.
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetCustomRenderL`.
   */
  int cfunc_CMauiControlGetCustomRender(lua_State* luaContext);

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender).
   *
   * What it does:
   * Publishes the `CMauiControl:GetCustomRender()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetCustomRender_LuaFuncDef();

  /**
   * FAF community binary-patch addition (see CMauiControl::SetCustomRender).
   *
   * What it does:
   * Reads one `CMauiControl` and pushes its custom-render flag to Lua.
   */
  int cfunc_CMauiControlGetCustomRenderL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788B90 (FUN_00788B90, cfunc_CMauiControlGetName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetNameL`.
   */
  int cfunc_CMauiControlGetName(lua_State* luaContext);

  /**
   * Address: 0x00788BB0 (FUN_00788BB0, func_CMauiControlGetName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetName()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetName_LuaFuncDef();

  /**
   * Address: 0x00788C10 (FUN_00788C10, cfunc_CMauiControlGetNameL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes its debug-name lane to Lua.
   */
  int cfunc_CMauiControlGetNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788D00 (FUN_00788D00, cfunc_CMauiControlSetName)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetNameL`.
   */
  int cfunc_CMauiControlSetName(lua_State* luaContext);

  /**
   * Address: 0x00788D20 (FUN_00788D20, func_CMauiControlSetName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetName(name)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetName_LuaFuncDef();

  /**
   * Address: 0x00788D80 (FUN_00788D80, cfunc_CMauiControlSetNameL)
   *
   * What it does:
   * Reads one `CMauiControl` plus debug-name string from Lua and stores it in
   * the control debug-name lane.
   */
  int cfunc_CMauiControlSetNameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788E90 (FUN_00788E90, cfunc_CMauiControlDump)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlDumpL`.
   */
  int cfunc_CMauiControlDump(lua_State* luaContext);

  /**
   * Address: 0x00788EB0 (FUN_00788EB0, func_CMauiControlDump_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:Dump()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlDump_LuaFuncDef();

  /**
   * Address: 0x00788F00 (FUN_00788F00, cfunc_CMauiControlDumpL)
   *
   * What it does:
   * Reads one `CMauiControl`, invokes `Dump()`, and returns the original
   * control object.
   */
  int cfunc_CMauiControlDumpL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00788FC0 (FUN_00788FC0, cfunc_CMauiControlGetCurrentFocusControl)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetCurrentFocusControlL`.
   */
  int cfunc_CMauiControlGetCurrentFocusControl(lua_State* luaContext);

  /**
   * Address: 0x00788FE0 (FUN_00788FE0, func_CMauiControlGetCurrentFocusControl_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetCurrentFocusControl()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetCurrentFocusControl_LuaFuncDef();

  /**
   * Address: 0x00789040 (FUN_00789040, cfunc_CMauiControlGetCurrentFocusControlL)
   *
   * What it does:
   * Pushes the currently focused control Lua object, or `nil` when no control
   * currently owns keyboard focus.
   */
  int cfunc_CMauiControlGetCurrentFocusControlL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007890B0 (FUN_007890B0, cfunc_CMauiControlAcquireKeyboardFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlAcquireKeyboardFocusL`.
   */
  int cfunc_CMauiControlAcquireKeyboardFocus(lua_State* luaContext);

  /**
   * Address: 0x007890D0 (FUN_007890D0, func_CMauiControlAcquireKeyboardFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:AcquireKeyboardFocus(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlAcquireKeyboardFocus_LuaFuncDef();

  /**
   * Address: 0x00789130 (FUN_00789130, cfunc_CMauiControlAcquireKeyboardFocusL)
   *
   * What it does:
   * Reads one `CMauiControl` plus boolean `blocksKeyDown` lane and forwards to
   * `CMauiControl::AcquireKeyboardFocus`.
   */
  int cfunc_CMauiControlAcquireKeyboardFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789210 (FUN_00789210, cfunc_CMauiControlAbandonKeyboardFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlAbandonKeyboardFocusL`.
   */
  int cfunc_CMauiControlAbandonKeyboardFocus(lua_State* luaContext);

  /**
   * Address: 0x00789230 (FUN_00789230, func_CMauiControlAbandonKeyboardFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:AbandonKeyboardFocus()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlAbandonKeyboardFocus_LuaFuncDef();

  /**
   * Address: 0x00789290 (FUN_00789290, cfunc_CMauiControlAbandonKeyboardFocusL)
   *
   * What it does:
   * Reads one `CMauiControl` and forwards to
   * `CMauiControl::AbandonKeyboardFocus`.
   */
  int cfunc_CMauiControlAbandonKeyboardFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789350 (FUN_00789350, cfunc_CMauiControlNeedsFrameUpdate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlNeedsFrameUpdateL`.
   */
  int cfunc_CMauiControlNeedsFrameUpdate(lua_State* luaContext);

  /**
   * Address: 0x00789370 (FUN_00789370, func_CMauiControlNeedsFrameUpdate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:NeedsFrameUpdate()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlNeedsFrameUpdate_LuaFuncDef();

  /**
   * Address: 0x007893D0 (FUN_007893D0, cfunc_CMauiControlNeedsFrameUpdateL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes its frame-update flag lane to Lua.
   */
  int cfunc_CMauiControlNeedsFrameUpdateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789490 (FUN_00789490, cfunc_CMauiControlSetNeedsFrameUpdate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetNeedsFrameUpdateL`.
   */
  int cfunc_CMauiControlSetNeedsFrameUpdate(lua_State* luaContext);

  /**
   * Address: 0x007894B0 (FUN_007894B0, func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetNeedsFrameUpdate(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef();

  /**
   * Address: 0x00789510 (FUN_00789510, cfunc_CMauiControlSetNeedsFrameUpdateL)
   *
   * What it does:
   * Resolves optional `CMauiControl` plus one boolean lane and updates the
   * control frame-update flag.
   */
  int cfunc_CMauiControlSetNeedsFrameUpdateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007895D0 (FUN_007895D0, cfunc_CMauiControlGetRootFrame)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetRootFrameL`.
   */
  int cfunc_CMauiControlGetRootFrame(lua_State* luaContext);

  /**
   * Address: 0x007895F0 (FUN_007895F0, func_CMauiControlGetRootFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetRootFrame()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetRootFrame_LuaFuncDef();

  /**
   * Address: 0x00789650 (FUN_00789650, cfunc_CMauiControlGetRootFrameL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes root-frame Lua object lane.
   */
  int cfunc_CMauiControlGetRootFrameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789A30 (FUN_00789A30, cfunc_CMauiControlGetAlpha)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlGetAlphaL`.
   */
  int cfunc_CMauiControlGetAlpha(lua_State* luaContext);

  /**
   * Address: 0x00789A50 (FUN_00789A50, func_CMauiControlGetAlpha_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:GetAlpha()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlGetAlpha_LuaFuncDef();

  /**
   * Address: 0x00789AB0 (FUN_00789AB0, cfunc_CMauiControlGetAlphaL)
   *
   * What it does:
   * Reads one `CMauiControl` and pushes current alpha lane to Lua.
   */
  int cfunc_CMauiControlGetAlphaL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789710 (FUN_00789710, cfunc_CMauiControlSetAlpha)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlSetAlphaL`.
   */
  int cfunc_CMauiControlSetAlpha(lua_State* luaContext);

  /**
   * Address: 0x00789730 (FUN_00789730, func_CMauiControlSetAlpha_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:SetAlpha(alpha[, children])` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlSetAlpha_LuaFuncDef();

  /**
   * Address: 0x00789790 (FUN_00789790, cfunc_CMauiControlSetAlphaL)
   *
   * What it does:
   * Reads alpha (and optional recursive flag) and updates one control or its
   * full descendant closure alpha lanes.
   */
  int cfunc_CMauiControlSetAlphaL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789B70 (FUN_00789B70, cfunc_CMauiControlApplyFunction)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlApplyFunctionL`.
   */
  int cfunc_CMauiControlApplyFunction(lua_State* luaContext);

  /**
   * Address: 0x00789B90 (FUN_00789B90, func_CMauiControlApplyFunction_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:ApplyFunction(func)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlApplyFunction_LuaFuncDef();

  /**
   * Address: 0x00789BF0 (FUN_00789BF0, cfunc_CMauiControlApplyFunctionL)
   *
   * What it does:
   * Reads one control plus Lua function object and applies it to control +
   * direct children.
   */
  int cfunc_CMauiControlApplyFunctionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00789CD0 (FUN_00789CD0, cfunc_CMauiControlHitTest)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiControlHitTestL`.
   */
  int cfunc_CMauiControlHitTest(lua_State* luaContext);

  /**
   * Address: 0x00789CF0 (FUN_00789CF0, func_CMauiControlHitTest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiControl:HitTest(x, y)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiControlHitTest_LuaFuncDef();

  /**
   * Address: 0x00789D50 (FUN_00789D50, cfunc_CMauiControlHitTestL)
   *
   * What it does:
   * Reads one control plus `(x,y)` numeric lanes and pushes hit-test result.
   */
  int cfunc_CMauiControlHitTestL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781440 (FUN_00781440, cfunc_CMauiBitmapInternalSetSolidColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapInternalSetSolidColorL`.
   */
  int cfunc_CMauiBitmapInternalSetSolidColor(lua_State* luaContext);

  /**
   * Address: 0x00781460 (FUN_00781460, func_CMauiBitmapInternalSetSolidColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:InternalSetSolidColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapInternalSetSolidColor_LuaFuncDef();

  /**
   * Address: 0x007814C0 (FUN_007814C0, cfunc_CMauiBitmapInternalSetSolidColorL)
   *
   * What it does:
   * Resolves one bitmap object plus one color lane and applies a one-frame
   * solid-color texture pattern.
   */
  int cfunc_CMauiBitmapInternalSetSolidColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007822C0 (FUN_007822C0, cfunc_CMauiBitMapGetNumFrames)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitMapGetNumFramesL`.
   */
  int cfunc_CMauiBitMapGetNumFrames(lua_State* luaContext);

  /**
   * Address: 0x007822E0 (FUN_007822E0, func_CMauiBitMapGetNumFrames_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:GetNumFrames()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitMapGetNumFrames_LuaFuncDef();

  /**
   * Address: 0x00782340 (FUN_00782340, cfunc_CMauiBitMapGetNumFramesL)
   *
   * What it does:
   * Resolves one bitmap object and pushes its frame-count lane.
   */
  int cfunc_CMauiBitMapGetNumFramesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00780ED0 (FUN_00780ED0, cfunc_CMauiBitmapSetNewTexture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetNewTextureL`.
   */
  int cfunc_CMauiBitmapSetNewTexture(lua_State* luaContext);

  /**
   * Address: 0x00780EF0 (FUN_00780EF0, func_CMauiBitmapSetNewTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetNewTexture(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetNewTexture_LuaFuncDef();

  /**
   * Address: 0x00780F50 (FUN_00780F50, cfunc_CMauiBitmapSetNewTextureL)
   *
   * What it does:
   * Rebuilds bitmap texture-batch lanes from one file path or frame-path table
   * and reapplies default forward frame pattern.
   */
  int cfunc_CMauiBitmapSetNewTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781690 (FUN_00781690, cfunc_CMauiBitmapSetUV)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetUVL`.
   */
  int cfunc_CMauiBitmapSetUV(lua_State* luaContext);

  /**
   * Address: 0x007816B0 (FUN_007816B0, func_CMauiBitmapSetUV_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetUV(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetUV_LuaFuncDef();

  /**
   * Address: 0x00781710 (FUN_00781710, cfunc_CMauiBitmapSetUVL)
   *
   * What it does:
   * Reads one bitmap plus `(u0,v0,u1,v1)` lanes, clamps each to `[0,1]`, and
   * updates UV runtime lanes.
   */
  int cfunc_CMauiBitmapSetUVL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781950 (FUN_00781950, cfunc_CMauiBitmapUseAlphaHitTest)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapUseAlphaHitTestL`.
   */
  int cfunc_CMauiBitmapUseAlphaHitTest(lua_State* luaContext);

  /**
   * Address: 0x00781970 (FUN_00781970, func_CMauiBitmapUseAlphaHitTest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:UseAlphaHitTest(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapUseAlphaHitTest_LuaFuncDef();

  /**
   * Address: 0x007819D0 (FUN_007819D0, cfunc_CMauiBitmapUseAlphaHitTestL)
   *
   * What it does:
   * Reads one bitmap plus boolean lane and updates alpha-hit-test state.
   */
  int cfunc_CMauiBitmapUseAlphaHitTestL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781AA0 (FUN_00781AA0, cfunc_CMauiBitmapSetTiled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapSetTiledL`.
   */
  int cfunc_CMauiBitmapSetTiled(lua_State* luaContext);

  /**
   * Address: 0x00781AC0 (FUN_00781AC0, func_CMauiBitmapSetTiled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetTiled(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetTiled_LuaFuncDef();

  /**
   * Address: 0x00781B20 (FUN_00781B20, cfunc_CMauiBitmapSetTiledL)
   *
   * What it does:
   * Reads one bitmap plus boolean lane and updates tiled-render state.
   */
  int cfunc_CMauiBitmapSetTiledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781BF0 (FUN_00781BF0, cfunc_CMauiBitmapLoop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapLoopL`.
   */
  int cfunc_CMauiBitmapLoop(lua_State* luaContext);

  /**
   * Address: 0x00781C10 (FUN_00781C10, func_CMauiBitmapLoop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:Loop(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapLoop_LuaFuncDef();

  /**
   * Address: 0x00781C70 (FUN_00781C70, cfunc_CMauiBitmapLoopL)
   *
   * What it does:
   * Reads one bitmap plus boolean lane and updates looping state.
   */
  int cfunc_CMauiBitmapLoopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781D40 (FUN_00781D40, cfunc_CMauiBitmapPlay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapPlayL`.
   */
  int cfunc_CMauiBitmapPlay(lua_State* luaContext);

  /**
   * Address: 0x00781D60 (FUN_00781D60, func_CMauiBitmapPlay_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:Play()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapPlay_LuaFuncDef();

  /**
   * Address: 0x00781DC0 (FUN_00781DC0, cfunc_CMauiBitmapPlayL)
   *
   * What it does:
   * Starts animated playback when the bitmap owns a multi-frame texture lane.
   */
  int cfunc_CMauiBitmapPlayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00781EA0 (FUN_00781EA0, cfunc_CMauiBitmapStop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapStopL`.
   */
  int cfunc_CMauiBitmapStop(lua_State* luaContext);

  /**
   * Address: 0x00781EC0 (FUN_00781EC0, func_CMauiBitmapStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:Stop()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapStop_LuaFuncDef();

  /**
   * Address: 0x00781F20 (FUN_00781F20, cfunc_CMauiBitmapStopL)
   *
   * What it does:
   * Stops animated playback and dispatches `OnAnimationStopped` when active.
   */
  int cfunc_CMauiBitmapStopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782000 (FUN_00782000, cfunc_CMauiBitmapSetFrame)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetFrameL`.
   */
  int cfunc_CMauiBitmapSetFrame(lua_State* luaContext);

  /**
   * Address: 0x00782020 (FUN_00782020, func_CMauiBitmapSetFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetFrame(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetFrame_LuaFuncDef();

  /**
   * Address: 0x00782080 (FUN_00782080, cfunc_CMauiBitmapSetFrameL)
   *
   * What it does:
   * Reads one `CMauiBitmap` plus frame index and applies clamped frame
   * selection.
   */
  int cfunc_CMauiBitmapSetFrameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782180 (FUN_00782180, cfunc_CMauiBitmapGetFrame)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiBitmapGetFrameL`.
   */
  int cfunc_CMauiBitmapGetFrame(lua_State* luaContext);

  /**
   * Address: 0x007821A0 (FUN_007821A0, func_CMauiBitmapGetFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:GetFrame()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapGetFrame_LuaFuncDef();

  /**
   * Address: 0x00782200 (FUN_00782200, cfunc_CMauiBitmapGetFrameL)
   *
   * What it does:
   * Reads one bitmap and pushes current frame index lane.
   */
  int cfunc_CMauiBitmapGetFrameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782420 (FUN_00782420, cfunc_CMauiBitmapSetFrameRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetFrameRateL`.
  */
  int cfunc_CMauiBitmapSetFrameRate(lua_State* luaContext);

  /**
   * Address: 0x00782440 (FUN_00782440, func_CMauiBitmapSetFrameRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetFrameRate(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetFrameRate_LuaFuncDef();

  /**
   * Address: 0x007824A0 (FUN_007824A0, cfunc_CMauiBitmapSetFrameRateL)
   *
   * What it does:
   * Reads one `CMauiBitmap` plus numeric frame-rate and updates its
   * frame-duration lane (`1.0 / fps`).
   */
  int cfunc_CMauiBitmapSetFrameRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007825A0 (FUN_007825A0, cfunc_CMauiBitmapSetForwardPattern)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetForwardPatternL`.
   */
  int cfunc_CMauiBitmapSetForwardPattern(lua_State* luaContext);

  /**
   * Address: 0x007825C0 (FUN_007825C0, func_CMauiBitmapSetForwardPattern_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetForwardPattern()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetForwardPattern_LuaFuncDef();

  /**
   * Address: 0x00782620 (FUN_00782620, cfunc_CMauiBitmapSetForwardPatternL)
   *
   * What it does:
   * Resolves one `CMauiBitmap` and rebuilds its forward frame pattern.
   */
  int cfunc_CMauiBitmapSetForwardPatternL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007826E0 (FUN_007826E0, cfunc_CMauiBitmapSetBackwardPattern)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetBackwardPatternL`.
   */
  int cfunc_CMauiBitmapSetBackwardPattern(lua_State* luaContext);

  /**
   * Address: 0x00782700 (FUN_00782700, func_CMauiBitmapSetBackwardPattern_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetBackwardPattern()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetBackwardPattern_LuaFuncDef();

  /**
   * Address: 0x00782760 (FUN_00782760, cfunc_CMauiBitmapSetBackwardPatternL)
   *
   * What it does:
   * Resolves one `CMauiBitmap` and rebuilds its backward frame pattern.
   */
  int cfunc_CMauiBitmapSetBackwardPatternL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782820 (FUN_00782820, cfunc_CMauiBitmapSetPingPongPattern)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetPingPongPatternL`.
   */
  int cfunc_CMauiBitmapSetPingPongPattern(lua_State* luaContext);

  /**
   * Address: 0x00782840 (FUN_00782840, func_CMauiBitmapSetPingPongPattern_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetPingPongPattern()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetPingPongPattern_LuaFuncDef();

  /**
   * Address: 0x007828A0 (FUN_007828A0, cfunc_CMauiBitmapSetPingPongPatternL)
   *
   * What it does:
   * Resolves one `CMauiBitmap` and rebuilds its ping-pong frame pattern.
   */
  int cfunc_CMauiBitmapSetPingPongPatternL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782960 (FUN_00782960, cfunc_CMauiBitmapSetLoopPingPongPattern)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetLoopPingPongPatternL`.
   */
  int cfunc_CMauiBitmapSetLoopPingPongPattern(lua_State* luaContext);

  /**
   * Address: 0x00782980 (FUN_00782980, func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetLoopPingPongPattern()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetLoopPingPongPattern_LuaFuncDef();

  /**
   * Address: 0x007829E0 (FUN_007829E0, cfunc_CMauiBitmapSetLoopPingPongPatternL)
   *
   * What it does:
   * Resolves one `CMauiBitmap` and rebuilds its loop ping-pong frame pattern.
   */
  int cfunc_CMauiBitmapSetLoopPingPongPatternL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782AA0 (FUN_00782AA0, cfunc_CMauiBitmapSetFramePattern)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapSetFramePatternL`.
   */
  int cfunc_CMauiBitmapSetFramePattern(lua_State* luaContext);

  /**
   * Address: 0x00782AC0 (FUN_00782AC0, func_CMauiBitmapSetFramePattern_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:SetFramePattern(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapSetFramePattern_LuaFuncDef();

  /**
   * Address: 0x00782B20 (FUN_00782B20, cfunc_CMauiBitmapSetFramePatternL)
   *
   * What it does:
   * Resolves one bitmap plus frame-index table and rebuilds frame-pattern
   * lanes.
   */
  int cfunc_CMauiBitmapSetFramePatternL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00782CE0 (FUN_00782CE0, cfunc_CMauiBitmapShareTextures)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBitmapShareTexturesL`.
   */
  int cfunc_CMauiBitmapShareTextures(lua_State* luaContext);

  /**
   * Address: 0x00782D00 (FUN_00782D00, func_CMauiBitmapShareTextures_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBitmap:ShareTextures(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBitmapShareTextures_LuaFuncDef();

  /**
   * Address: 0x00782D60 (FUN_00782D60, cfunc_CMauiBitmapShareTexturesL)
   *
   * What it does:
   * Reads two `CMauiBitmap` controls and shares texture-batch lanes from source
   * into destination bitmap runtime state.
   */
  int cfunc_CMauiBitmapShareTexturesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00785960 (FUN_00785960, cfunc_CMauiBorderSetNewTextures)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBorderSetNewTexturesL`.
   */
  int cfunc_CMauiBorderSetNewTextures(lua_State* luaContext);

  /**
   * Address: 0x007859E0 (FUN_007859E0, cfunc_CMauiBorderSetNewTexturesL)
   *
   * What it does:
   * Reads one `CMauiBorder` plus six optional texture-path lanes and forwards
   * resolved texture handles to `CMauiBorder::SetTextures`.
   */
  int cfunc_CMauiBorderSetNewTexturesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00785980 (FUN_00785980, func_CMauiBorderSetNewTextures_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBorder:SetNewTextures(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBorderSetNewTextures_LuaFuncDef();

  /**
   * Address: 0x00785FA0 (FUN_00785FA0, cfunc_CMauiBorderSetSolidColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiBorderSetSolidColorL`.
   */
  int cfunc_CMauiBorderSetSolidColor(lua_State* luaContext);

  /**
   * Address: 0x00786020 (FUN_00786020, cfunc_CMauiBorderSetSolidColorL)
   *
   * What it does:
   * Reads one `CMauiBorder` plus one color lane and assigns one shared
   * solid-color texture to all six border texture slots.
   */
  int cfunc_CMauiBorderSetSolidColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00785FC0 (FUN_00785FC0, func_CMauiBorderSetSolidColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiBorder:SetSolidColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiBorderSetSolidColor_LuaFuncDef();

  /**
   * Address: 0x00796900 (FUN_00796900, cfunc_CMauiFrameGetTopmostDepth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiFrameGetTopmostDepthL`.
   */
  int cfunc_CMauiFrameGetTopmostDepth(lua_State* luaContext);

  /**
   * Address: 0x00796920 (FUN_00796920, func_CMauiFrameGetTopmostDepth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiFrame:GetTopmostDepth()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiFrameGetTopmostDepth_LuaFuncDef();

  /**
   * Address: 0x00796980 (FUN_00796980, cfunc_CMauiFrameGetTopmostDepthL)
   *
   * What it does:
   * Reads one `CMauiFrame` and pushes the topmost depth lane.
   */
  int cfunc_CMauiFrameGetTopmostDepthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00796A50 (FUN_00796A50, cfunc_CMauiFrameGetTargetHead)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiFrameGetTargetHeadL`.
   */
  int cfunc_CMauiFrameGetTargetHead(lua_State* luaContext);

  /**
   * Address: 0x00796A70 (FUN_00796A70, func_CMauiFrameGetTargetHead_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiFrame:GetTargetHead()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiFrameGetTargetHead_LuaFuncDef();

  /**
   * Address: 0x00796AD0 (FUN_00796AD0, cfunc_CMauiFrameGetTargetHeadL)
   *
   * What it does:
   * Reads one `CMauiFrame` and pushes integer target-head lane.
   */
  int cfunc_CMauiFrameGetTargetHeadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00796B90 (FUN_00796B90, cfunc_CMauiFrameSetTargetHead)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiFrameSetTargetHeadL`.
   */
  int cfunc_CMauiFrameSetTargetHead(lua_State* luaContext);

  /**
   * Address: 0x00796BB0 (FUN_00796BB0, func_CMauiFrameSetTargetHead_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiFrame:SetTargetHead(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiFrameSetTargetHead_LuaFuncDef();

  /**
   * Address: 0x00796C10 (FUN_00796C10, cfunc_CMauiFrameSetTargetHeadL)
   *
   * What it does:
   * Reads one `CMauiFrame` plus numeric target-head lane and stores it into
   * the frame runtime view.
   */
  int cfunc_CMauiFrameSetTargetHeadL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00797AD0 (FUN_00797AD0, cfunc_CMauiHistogramSetXIncrement)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiHistogramSetXIncrementL`.
   */
  int cfunc_CMauiHistogramSetXIncrement(lua_State* luaContext);

  /**
   * Address: 0x00797AF0 (FUN_00797AF0, func_CMauiHistogramSetXIncrement_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiHistogram:SetXIncrement(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiHistogramSetXIncrement_LuaFuncDef();

  /**
   * Address: 0x00797B50 (FUN_00797B50, cfunc_CMauiHistogramSetXIncrementL)
   *
   * What it does:
   * Reads one `CMauiHistogram` plus integer X-increment lane and updates the
   * histogram runtime view.
   */
  int cfunc_CMauiHistogramSetXIncrementL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00797C50 (FUN_00797C50, cfunc_CMauiHistogramSetYIncrement)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiHistogramSetYIncrementL`.
   */
  int cfunc_CMauiHistogramSetYIncrement(lua_State* luaContext);

  /**
   * Address: 0x00797C70 (FUN_00797C70, func_CMauiHistogramSetYIncrement_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiHistogram:SetYIncrement(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiHistogramSetYIncrement_LuaFuncDef();

  /**
   * Address: 0x00797CD0 (FUN_00797CD0, cfunc_CMauiHistogramSetYIncrementL)
   *
   * What it does:
   * Reads one `CMauiHistogram` plus integer Y-increment lane and updates the
   * histogram runtime view.
   */
  int cfunc_CMauiHistogramSetYIncrementL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00797DD0 (FUN_00797DD0, cfunc_CMauiHistogramSetData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiHistogramSetDataL`.
   */
  int cfunc_CMauiHistogramSetData(lua_State* luaContext);

  /**
   * Address: 0x00797DF0 (FUN_00797DF0, func_CMauiHistogramSetData_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiHistogram:SetData(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiHistogramSetData_LuaFuncDef();

  /**
   * Address: 0x00797E50 (FUN_00797E50, cfunc_CMauiHistogramSetDataL)
   *
   * What it does:
   * Reads one `CMauiHistogram` plus data table and validates per-entry
   * color/data lanes.
   */
  int cfunc_CMauiHistogramSetDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0078DF80 (FUN_0078DF80, cfunc_CMauiLuaDraggerDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiLuaDraggerDestroyL`.
   */
  int cfunc_CMauiLuaDraggerDestroy(lua_State* luaContext);

  /**
   * Address: 0x0078DFA0 (FUN_0078DFA0, func_CMauiLuaDraggerDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiLuaDragger:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiLuaDraggerDestroy_LuaFuncDef();

  /**
   * Address: 0x0078E210 (FUN_0078E210, cfunc_PostDragger)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_PostDraggerL`.
   */
  int cfunc_PostDragger(lua_State* luaContext);

  /**
   * Address: 0x0078E230 (FUN_0078E230, func_PostDragger_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `PostDragger(originFrame, keycode, dragger)` Lua
   * binder.
   */
  CScrLuaInitForm* func_PostDragger_LuaFuncDef();

  /**
   * Address: 0x0078E290 (FUN_0078E290, cfunc_PostDraggerL)
   *
   * What it does:
   * Reads `(originFrame, keycode, dragger)` from Lua, normalizes keycode
   * routing values, and posts one dragger activation payload.
   */
  int cfunc_PostDraggerL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007921A0 (FUN_007921A0, cfunc_CMauiEditSetNewFont)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewFontL`.
   */
  int cfunc_CMauiEditSetNewFont(lua_State* luaContext);

  /**
   * Address: 0x007921C0 (FUN_007921C0, func_CMauiEditSetNewFont_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewFont(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewFont_LuaFuncDef();

  /**
   * Address: 0x007923C0 (FUN_007923C0, cfunc_CMauiEditSetNewForegroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewForegroundColorL`.
   */
  int cfunc_CMauiEditSetNewForegroundColor(lua_State* luaContext);

  /**
   * Address: 0x007923E0 (FUN_007923E0, func_CMauiEditSetNewForegroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewForegroundColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewForegroundColor_LuaFuncDef();

  /**
   * Address: 0x00792530 (FUN_00792530, cfunc_CMauiEditGetForegroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetForegroundColorL`.
   */
  int cfunc_CMauiEditGetForegroundColor(lua_State* luaContext);

  /**
   * Address: 0x00792550 (FUN_00792550, func_CMauiEditGetForegroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetForegroundColor()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetForegroundColor_LuaFuncDef();

  /**
   * Address: 0x00792690 (FUN_00792690, cfunc_CMauiEditSetNewBackgroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewBackgroundColorL`.
   */
  int cfunc_CMauiEditSetNewBackgroundColor(lua_State* luaContext);

  /**
   * Address: 0x007926B0 (FUN_007926B0, func_CMauiEditSetNewBackgroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewBackgroundColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewBackgroundColor_LuaFuncDef();

  /**
   * Address: 0x00792810 (FUN_00792810, cfunc_CMauiEditGetBackgroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetBackgroundColorL`.
   */
  int cfunc_CMauiEditGetBackgroundColor(lua_State* luaContext);

  /**
   * Address: 0x00792830 (FUN_00792830, func_CMauiEditGetBackgroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetBackgroundColor()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetBackgroundColor_LuaFuncDef();

  /**
   * Address: 0x00792970 (FUN_00792970, cfunc_CMauiEditShowBackground)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditShowBackgroundL`.
   */
  int cfunc_CMauiEditShowBackground(lua_State* luaContext);

  /**
   * Address: 0x00792990 (FUN_00792990, func_CMauiEditShowBackground_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:ShowBackground(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditShowBackground_LuaFuncDef();

  /**
   * Address: 0x00792AC0 (FUN_00792AC0, cfunc_CMauiEditIsBackgroundVisible)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditIsBackgroundVisibleL`.
   */
  int cfunc_CMauiEditIsBackgroundVisible(lua_State* luaContext);

  /**
   * Address: 0x00792AE0 (FUN_00792AE0, func_CMauiEditIsBackgroundVisible_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:IsBackgroundVisible()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditIsBackgroundVisible_LuaFuncDef();

  /**
   * Address: 0x00792C00 (FUN_00792C00, cfunc_CMauiEditClearText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditClearTextL`.
   */
  int cfunc_CMauiEditClearText(lua_State* luaContext);

  /**
   * Address: 0x00792C20 (FUN_00792C20, func_CMauiEditClearText_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:ClearText()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditClearText_LuaFuncDef();

  /**
   * Address: 0x00792C80 (FUN_00792C80, cfunc_CMauiEditClearTextL)
   *
   * What it does:
   * Reads one `CMauiEdit`, clears text/caret/selection lanes, and returns self.
   */
  int cfunc_CMauiEditClearTextL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00792D30 (FUN_00792D30, cfunc_CMauiEditSetText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetTextL`.
   */
  int cfunc_CMauiEditSetText(lua_State* luaContext);

  /**
   * Address: 0x00792D50 (FUN_00792D50, func_CMauiEditSetText_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetText(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetText_LuaFuncDef();

  /**
   * Address: 0x00792DB0 (FUN_00792DB0, cfunc_CMauiEditSetTextL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus text lane, applies text update, and returns self.
   */
  int cfunc_CMauiEditSetTextL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00792F00 (FUN_00792F00, cfunc_CMauiEditGetText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetTextL`.
   */
  int cfunc_CMauiEditGetText(lua_State* luaContext);

  /**
   * Address: 0x00792F20 (FUN_00792F20, func_CMauiEditGetText_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetText()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetText_LuaFuncDef();

  /**
   * Address: 0x00792F80 (FUN_00792F80, cfunc_CMauiEditGetTextL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes current text lane.
   */
  int cfunc_CMauiEditGetTextL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793340 (FUN_00793340, cfunc_CMauiEditSetCaretPosition)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetCaretPositionL`.
   */
  int cfunc_CMauiEditSetCaretPosition(lua_State* luaContext);

  /**
   * Address: 0x00793360 (FUN_00793360, func_CMauiEditSetCaretPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetCaretPosition(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetCaretPosition_LuaFuncDef();

  /**
   * Address: 0x007933C0 (FUN_007933C0, cfunc_CMauiEditSetCaretPositionL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus integer caret lane and updates caret/clip state.
   */
  int cfunc_CMauiEditSetCaretPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007934C0 (FUN_007934C0, cfunc_CMauiEditGetCaretPosition)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetCaretPositionL`.
   */
  int cfunc_CMauiEditGetCaretPosition(lua_State* luaContext);

  /**
   * Address: 0x007934E0 (FUN_007934E0, func_CMauiEditGetCaretPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetCaretPosition()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetCaretPosition_LuaFuncDef();

  /**
   * Address: 0x00793540 (FUN_00793540, cfunc_CMauiEditGetCaretPositionL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes current caret-position lane.
   */
  int cfunc_CMauiEditGetCaretPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793600 (FUN_00793600, cfunc_CMauiEditShowCaret)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditShowCaretL`.
   */
  int cfunc_CMauiEditShowCaret(lua_State* luaContext);

  /**
   * Address: 0x00793620 (FUN_00793620, func_CMauiEditShowCaret_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:ShowCaret(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditShowCaret_LuaFuncDef();

  /**
   * Address: 0x00793680 (FUN_00793680, cfunc_CMauiEditShowCaretL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus bool lane and updates caret-visibility lane.
   */
  int cfunc_CMauiEditShowCaretL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793750 (FUN_00793750, cfunc_CMauiEditIsCaretVisible)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditIsCaretVisibleL`.
   */
  int cfunc_CMauiEditIsCaretVisible(lua_State* luaContext);

  /**
   * Address: 0x00793770 (FUN_00793770, func_CMauiEditIsCaretVisible_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:IsCaretVisible()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditIsCaretVisible_LuaFuncDef();

  /**
   * Address: 0x007937D0 (FUN_007937D0, cfunc_CMauiEditIsCaretVisibleL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes caret-visible state.
   */
  int cfunc_CMauiEditIsCaretVisibleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793890 (FUN_00793890, cfunc_CMauiEditSetNewCaretColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewCaretColorL`.
   */
  int cfunc_CMauiEditSetNewCaretColor(lua_State* luaContext);

  /**
   * Address: 0x007938B0 (FUN_007938B0, func_CMauiEditSetNewCaretColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewCaretColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewCaretColor_LuaFuncDef();

  /**
   * Address: 0x00793910 (FUN_00793910, cfunc_CMauiEditSetNewCaretColorL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus color lane and updates caret RGB lane.
   */
  int cfunc_CMauiEditSetNewCaretColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793A00 (FUN_00793A00, cfunc_CMauiEditGetCaretColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetCaretColorL`.
   */
  int cfunc_CMauiEditGetCaretColor(lua_State* luaContext);

  /**
   * Address: 0x00793A20 (FUN_00793A20, func_CMauiEditGetCaretColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetCaretColor()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetCaretColor_LuaFuncDef();

  /**
   * Address: 0x00793A80 (FUN_00793A80, cfunc_CMauiEditGetCaretColorL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes encoded caret color.
   */
  int cfunc_CMauiEditGetCaretColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793B60 (FUN_00793B60, cfunc_CMauiEditSetCaretCycle)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetCaretCycleL`.
   */
  int cfunc_CMauiEditSetCaretCycle(lua_State* luaContext);

  /**
   * Address: 0x00793B80 (FUN_00793B80, func_CMauiEditSetCaretCycle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetCaretCycle(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetCaretCycle_LuaFuncDef();

  /**
   * Address: 0x00793BE0 (FUN_00793BE0, cfunc_CMauiEditSetCaretCycleL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus cycle+alpha lanes and stores caret-cycle state.
   */
  int cfunc_CMauiEditSetCaretCycleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793D70 (FUN_00793D70, cfunc_CMauiEditIsEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditIsEnabledL`.
   */
  int cfunc_CMauiEditIsEnabled(lua_State* luaContext);

  /**
   * Address: 0x00793D90 (FUN_00793D90, func_CMauiEditIsEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:IsEnabled()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditIsEnabled_LuaFuncDef();

  /**
   * Address: 0x00793DF0 (FUN_00793DF0, cfunc_CMauiEditIsEnabledL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes enabled-state lane.
   */
  int cfunc_CMauiEditIsEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793EB0 (FUN_00793EB0, cfunc_CMauiEditEnableInput)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditEnableInputL`.
   */
  int cfunc_CMauiEditEnableInput(lua_State* luaContext);

  /**
   * Address: 0x00793ED0 (FUN_00793ED0, func_CMauiEditEnableInput_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:EnableInput()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditEnableInput_LuaFuncDef();

  /**
   * Address: 0x00793F30 (FUN_00793F30, cfunc_CMauiEditEnableInputL)
   *
   * What it does:
   * Reads one `CMauiEdit`, enables input lane and shows caret, then returns self.
   */
  int cfunc_CMauiEditEnableInputL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793FF0 (FUN_00793FF0, cfunc_CMauiEditDisableInput)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditDisableInputL`.
   */
  int cfunc_CMauiEditDisableInput(lua_State* luaContext);

  /**
   * Address: 0x00794010 (FUN_00794010, func_CMauiEditDisableInput_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:DisableInput()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditDisableInput_LuaFuncDef();

  /**
   * Address: 0x00794070 (FUN_00794070, cfunc_CMauiEditDisableInputL)
   *
   * What it does:
   * Disables edit input/caret lanes, abandons keyboard focus, and returns self.
   */
  int cfunc_CMauiEditDisableInputL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794140 (FUN_00794140, cfunc_CMauiEditSetNewHighlightForegroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewHighlightForegroundColorL`.
   */
  int cfunc_CMauiEditSetNewHighlightForegroundColor(lua_State* luaContext);

  /**
   * Address: 0x00794160 (FUN_00794160, func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewHighlightForegroundColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef();

  /**
   * Address: 0x007941C0 (FUN_007941C0, cfunc_CMauiEditSetNewHighlightForegroundColorL)
   *
   * What it does:
   * Decodes one highlight-foreground color from Lua and stores it in edit
   * runtime lanes.
   */
  int cfunc_CMauiEditSetNewHighlightForegroundColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007942B0 (FUN_007942B0, cfunc_CMauiEditGetHighlightForegroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetHighlightForegroundColorL`.
   */
  int cfunc_CMauiEditGetHighlightForegroundColor(lua_State* luaContext);

  /**
   * Address: 0x007942D0 (FUN_007942D0, func_CMauiEditGetHighlightForegroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetHighlightForegroundColor()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetHighlightForegroundColor_LuaFuncDef();

  /**
   * Address: 0x00794330 (FUN_00794330, cfunc_CMauiEditGetHighlightForegroundColorL)
   *
   * What it does:
   * Reads one edit highlight-foreground color and pushes encoded Lua color.
   */
  int cfunc_CMauiEditGetHighlightForegroundColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794410 (FUN_00794410, cfunc_CMauiEditSetNewHighlightBackgroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetNewHighlightBackgroundColorL`.
   */
  int cfunc_CMauiEditSetNewHighlightBackgroundColor(lua_State* luaContext);

  /**
   * Address: 0x00794430 (FUN_00794430, func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetNewHighlightBackgroundColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef();

  /**
   * Address: 0x00794490 (FUN_00794490, cfunc_CMauiEditSetNewHighlightBackgroundColorL)
   *
   * What it does:
   * Decodes one highlight-background color from Lua and stores it in edit
   * runtime lanes.
   */
  int cfunc_CMauiEditSetNewHighlightBackgroundColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794580 (FUN_00794580, cfunc_CMauiEditGetHighlightBackgroundColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetHighlightBackgroundColorL`.
   */
  int cfunc_CMauiEditGetHighlightBackgroundColor(lua_State* luaContext);

  /**
   * Address: 0x007945A0 (FUN_007945A0, func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetHighlightBackgroundColor()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef();

  /**
   * Address: 0x00794600 (FUN_00794600, cfunc_CMauiEditGetHighlightBackgroundColorL)
   *
   * What it does:
   * Reads one edit highlight-background color and pushes encoded Lua color.
   */
  int cfunc_CMauiEditGetHighlightBackgroundColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007946E0 (FUN_007946E0, cfunc_CMauiEditGetFontHeight)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetFontHeightL`.
   */
  int cfunc_CMauiEditGetFontHeight(lua_State* luaContext);

  /**
   * Address: 0x00794700 (FUN_00794700, func_CMauiEditGetFontHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetFontHeight()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetFontHeight_LuaFuncDef();

  /**
   * Address: 0x00794760 (FUN_00794760, cfunc_CMauiEditGetFontHeightL)
   *
   * What it does:
   * Reads edit font lane and pushes integerized font height (`0` when missing).
   */
  int cfunc_CMauiEditGetFontHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793070 (FUN_00793070, cfunc_CMauiEditSetMaxChars)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetMaxCharsL`.
   */
  int cfunc_CMauiEditSetMaxChars(lua_State* luaContext);

  /**
   * Address: 0x00793090 (FUN_00793090, func_CMauiEditSetMaxChars_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetMaxChars(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditSetMaxChars_LuaFuncDef();

  /**
   * Address: 0x007930F0 (FUN_007930F0, cfunc_CMauiEditSetMaxCharsL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus integer arg, clamps minimum to 1, applies the
   * new max-char limit, and returns self.
   */
  int cfunc_CMauiEditSetMaxCharsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00793200 (FUN_00793200, cfunc_CMauiEditGetMaxChars)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetMaxCharsL`.
   */
  int cfunc_CMauiEditGetMaxChars(lua_State* luaContext);

  /**
   * Address: 0x00793220 (FUN_00793220, func_CMauiEditGetMaxChars_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetMaxChars()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiEditGetMaxChars_LuaFuncDef();

  /**
   * Address: 0x00793280 (FUN_00793280, cfunc_CMauiEditGetMaxCharsL)
   *
   * What it does:
   * Reads one `CMauiEdit` and pushes the current max-char limit.
   */
  int cfunc_CMauiEditGetMaxCharsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794840 (FUN_00794840, cfunc_CMauiEditAcquireFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditAcquireFocusL`.
   */
  int cfunc_CMauiEditAcquireFocus(lua_State* luaContext);

  /**
   * Address: 0x00794860 (FUN_00794860, func_CMauiEditAcquireFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:AcquireFocus()` Lua binder.
  */
  CScrLuaInitForm* func_CMauiEditAcquireFocus_LuaFuncDef();

  /**
   * Address: 0x007948C0 (FUN_007948C0, cfunc_CMauiEditAcquireFocusL)
   *
   * What it does:
   * Reads one `CMauiEdit`, enables caret+keyboard focus when edit is enabled,
   * and returns self.
   */
  int cfunc_CMauiEditAcquireFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794990 (FUN_00794990, cfunc_CMauiEditAbandonFocus)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditAbandonFocusL`.
   */
  int cfunc_CMauiEditAbandonFocus(lua_State* luaContext);

  /**
   * Address: 0x007949B0 (FUN_007949B0, func_CMauiEditAbandonFocus_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:AbandonFocus()` Lua binder.
  */
  CScrLuaInitForm* func_CMauiEditAbandonFocus_LuaFuncDef();

  /**
   * Address: 0x00794A10 (FUN_00794A10, cfunc_CMauiEditAbandonFocusL)
   *
   * What it does:
   * Reads one `CMauiEdit`, abandons keyboard focus, and returns self.
   */
  int cfunc_CMauiEditAbandonFocusL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794AD0 (FUN_00794AD0, cfunc_CMauiEditSetDropShadow)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditSetDropShadowL`.
   */
  int cfunc_CMauiEditSetDropShadow(lua_State* luaContext);

  /**
   * Address: 0x00794AF0 (FUN_00794AF0, func_CMauiEditSetDropShadow_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:SetDropShadow(...)` Lua binder.
  */
  CScrLuaInitForm* func_CMauiEditSetDropShadow_LuaFuncDef();

  /**
   * Address: 0x00794B50 (FUN_00794B50, cfunc_CMauiEditSetDropShadowL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus bool arg, stores drop-shadow flag, and returns
   * self.
   */
  int cfunc_CMauiEditSetDropShadowL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00794C20 (FUN_00794C20, cfunc_CMauiEditGetStringAdvance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiEditGetStringAdvanceL`.
   */
  int cfunc_CMauiEditGetStringAdvance(lua_State* luaContext);

  /**
   * Address: 0x00794C40 (FUN_00794C40, func_CMauiEditGetStringAdvance_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiEdit:GetStringAdvance(...)` Lua binder.
  */
  CScrLuaInitForm* func_CMauiEditGetStringAdvance_LuaFuncDef();

  /**
   * Address: 0x00794CA0 (FUN_00794CA0, cfunc_CMauiEditGetStringAdvanceL)
   *
   * What it does:
   * Reads one `CMauiEdit` plus string arg and returns measured text advance
   * from edit font lane.
   */
  int cfunc_CMauiEditGetStringAdvanceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00780D20 (FUN_00780D20, cfunc_InternalCreateBitmap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateBitmapL`.
   */
  int cfunc_InternalCreateBitmap(lua_State* luaContext);

  /**
   * Address: 0x00780D40 (FUN_00780D40, func_InternalCreateBitmap_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateBitmap(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateBitmap_LuaFuncDef();

  /**
   * Address: 0x00796790 (FUN_00796790, cfunc_InternalCreateFrame)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateFrameL`.
   */
  int cfunc_InternalCreateFrame(lua_State* luaContext);

  /**
   * Address: 0x007967B0 (FUN_007967B0, func_InternalCreateFrame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateFrame(luaobj)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateFrame_LuaFuncDef();

  /**
   * Address: 0x0078E0B0 (FUN_0078E0B0, cfunc_InternalCreateDragger)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateDraggerL`.
   */
  int cfunc_InternalCreateDragger(lua_State* luaContext);

  /**
   * Address: 0x0078E0D0 (FUN_0078E0D0, func_InternalCreateDragger_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateDragger(luaobj)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateDragger_LuaFuncDef();

  /**
   * Address: 0x007857B0 (FUN_007857B0, cfunc_InternalCreateBorder)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateBorderL`.
   */
  int cfunc_InternalCreateBorder(lua_State* luaContext);

  /**
   * Address: 0x007857D0 (FUN_007857D0, func_InternalCreateBorder_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateBorder(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateBorder_LuaFuncDef();

  /**
   * Address: 0x00791FF0 (FUN_00791FF0, cfunc_InternalCreateEdit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateEditL`.
   */
  int cfunc_InternalCreateEdit(lua_State* luaContext);

  /**
   * Address: 0x00792010 (FUN_00792010, func_InternalCreateEdit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateEdit(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateEdit_LuaFuncDef();

  /**
   * Address: 0x00797310 (FUN_00797310, cfunc_InternalCreateGroup)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateGroupL`.
   */
  int cfunc_InternalCreateGroup(lua_State* luaContext);

  /**
   * Address: 0x00797330 (FUN_00797330, func_InternalCreateGroup_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateGroup(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateGroup_LuaFuncDef();

  /**
   * Address: 0x00797390 (FUN_00797390, cfunc_InternalCreateGroupL)
   *
   * What it does:
   * Reads `(luaobj,parent)`, constructs one group control, dispatches `OnInit`,
   * and pushes the created control object.
   */
  int cfunc_InternalCreateGroupL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00797920 (FUN_00797920, cfunc_InternalCreateHistogram)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateHistogramL`.
   */
  int cfunc_InternalCreateHistogram(lua_State* luaContext);

  /**
   * Address: 0x00797940 (FUN_00797940, func_InternalCreateHistogram_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateHistogram(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateHistogram_LuaFuncDef();

  /**
   * Address: 0x007A1590 (FUN_007A1590, cfunc_InternalCreateScrollbar)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateScrollbarL`.
   */
  int cfunc_InternalCreateScrollbar(lua_State* luaContext);

  /**
   * Address: 0x007A15B0 (FUN_007A15B0, func_InternalCreateScrollbar_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateScrollbar(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateScrollbar_LuaFuncDef();

  /**
   * Address: 0x007A1610 (FUN_007A1610, cfunc_InternalCreateScrollbarL)
   *
   * What it does:
   * Reads `(luaobj,parent,axisText)`, constructs one scrollbar control,
   * dispatches `OnInit`, and pushes the created control object.
   */
  int cfunc_InternalCreateScrollbarL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079A960 (FUN_0079A960, cfunc_InternalCreateItemList)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateItemListL`.
   */
  int cfunc_InternalCreateItemList(lua_State* luaContext);

  /**
   * Address: 0x0079A980 (FUN_0079A980, func_InternalCreateItemList_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateItemList(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateItemList_LuaFuncDef();

  /**
   * Address: 0x0079A9E0 (FUN_0079A9E0, cfunc_InternalCreateItemListL)
   *
   * What it does:
   * Reads `(luaobj,parent)`, constructs one `CMauiItemList`, dispatches
   * `OnInit`, and pushes the created control object.
   */
  int cfunc_InternalCreateItemListL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079E590 (FUN_0079E590, cfunc_InternalCreateMesh)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateMeshL`.
   */
  int cfunc_InternalCreateMesh(lua_State* luaContext);

  /**
   * Address: 0x0079E5B0 (FUN_0079E5B0, func_InternalCreateMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateMesh(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateMesh_LuaFuncDef();

  /**
   * Address: 0x0079F540 (FUN_0079F540, cfunc_InternalCreateMovie)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateMovieL`.
   */
  int cfunc_InternalCreateMovie(lua_State* luaContext);

  /**
   * Address: 0x0079F560 (FUN_0079F560, func_InternalCreateMovie_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateMovie(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateMovie_LuaFuncDef();

  /**
   * Address: 0x007A3340 (FUN_007A3340, cfunc_InternalCreateText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateTextL`.
   */
  int cfunc_InternalCreateText(lua_State* luaContext);

  /**
   * Address: 0x007A3360 (FUN_007A3360, func_InternalCreateText_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateText(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateText_LuaFuncDef();

  /**
   * Address: 0x0086A8D0 (FUN_0086A8D0, cfunc_InternalCreateWldUIProvider)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateWldUIProviderL`.
   */
  int cfunc_InternalCreateWldUIProvider(lua_State* luaContext);

  /**
   * Address: 0x0086A8F0 (FUN_0086A8F0, func_InternalCreateWldUIProvider_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateWldUIProvider(luaobj)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateWldUIProvider_LuaFuncDef();

  /**
   * Address: 0x0086A950 (FUN_0086A950, cfunc_InternalCreateWldUIProviderL)
   *
   * What it does:
   * Constructs one `CLuaWldUIProvider` from a Lua object lane, pushes the
   * created script object, and updates global provider ownership.
   */
  int cfunc_InternalCreateWldUIProviderL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086BB30 (FUN_0086BB30, cfunc_InternalCreateWorldMesh)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateWorldMeshL`.
   */
  int cfunc_InternalCreateWorldMesh(lua_State* luaContext);

  /**
   * Address: 0x0086BB50 (FUN_0086BB50, func_InternalCreateWorldMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateWorldMesh(luaobj)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateWorldMesh_LuaFuncDef();

  /**
   * Address: 0x0086BBB0 (FUN_0086BBB0, cfunc_InternalCreateWorldMeshL)
   *
   * What it does:
   * Constructs one `CUIWorldMesh` from a Lua object lane and pushes the
   * created script object.
   */
  int cfunc_InternalCreateWorldMeshL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079AB10 (FUN_0079AB10, cfunc_CMauiItemListSetNewFont)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListSetNewFontL`.
   */
  int cfunc_CMauiItemListSetNewFont(lua_State* luaContext);

  /**
   * Address: 0x0079AB30 (FUN_0079AB30, func_CMauiItemListSetNewFont_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:SetNewFont(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListSetNewFont_LuaFuncDef();

  /**
   * Address: 0x0079AB90 (FUN_0079AB90, cfunc_CMauiItemListSetNewFontL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus `(family, pointsize)`, creates one font,
   * and applies it to item-list runtime state.
   */
  int cfunc_CMauiItemListSetNewFontL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B1E0 (FUN_0079B1E0, cfunc_CMauiItemListAddItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListAddItemL`.
   */
  int cfunc_CMauiItemListAddItem(lua_State* luaContext);

  /**
   * Address: 0x0079B200 (FUN_0079B200, func_CMauiItemListAddItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:AddItem(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListAddItem_LuaFuncDef();

  /**
   * Address: 0x0079B260 (FUN_0079B260, cfunc_CMauiItemListAddItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus string arg and appends one item.
   */
  int cfunc_CMauiItemListAddItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B370 (FUN_0079B370, cfunc_CMauiItemListModifyItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListModifyItemL`.
   */
  int cfunc_CMauiItemListModifyItem(lua_State* luaContext);

  /**
   * Address: 0x0079B390 (FUN_0079B390, func_CMauiItemListModifyItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ModifyItem(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListModifyItem_LuaFuncDef();

  /**
   * Address: 0x0079B3F0 (FUN_0079B3F0, cfunc_CMauiItemListModifyItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus `(index,text)` and updates one list item
   * when the provided index is non-negative.
   */
  int cfunc_CMauiItemListModifyItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B560 (FUN_0079B560, cfunc_CMauiItemListDeleteItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListDeleteItemL`.
   */
  int cfunc_CMauiItemListDeleteItem(lua_State* luaContext);

  /**
   * Address: 0x0079B580 (FUN_0079B580, func_CMauiItemListDeleteItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:DeleteItem(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListDeleteItem_LuaFuncDef();

  /**
   * Address: 0x0079B5E0 (FUN_0079B5E0, cfunc_CMauiItemListDeleteItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus one index and deletes that item when index
   * is non-negative.
   */
  int cfunc_CMauiItemListDeleteItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B6E0 (FUN_0079B6E0, cfunc_CMauiItemListDeleteAllItems)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListDeleteAllItemsL`.
   */
  int cfunc_CMauiItemListDeleteAllItems(lua_State* luaContext);

  /**
   * Address: 0x0079B700 (FUN_0079B700, func_CMauiItemListDeleteAllItems_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:DeleteAllItems()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListDeleteAllItems_LuaFuncDef();

  /**
   * Address: 0x0079B760 (FUN_0079B760, cfunc_CMauiItemListDeleteAllItemsL)
   *
   * What it does:
   * Clears all item lanes and resets current selection to no-selection.
   */
  int cfunc_CMauiItemListDeleteAllItemsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B840 (FUN_0079B840, cfunc_CMauiItemListGetSelection)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListGetSelectionL`.
   */
  int cfunc_CMauiItemListGetSelection(lua_State* luaContext);

  /**
   * Address: 0x0079B860 (FUN_0079B860, func_CMauiItemListGetSelection_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:GetSelection()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListGetSelection_LuaFuncDef();

  /**
   * Address: 0x0079B8C0 (FUN_0079B8C0, cfunc_CMauiItemListGetSelectionL)
   *
   * What it does:
   * Reads one `CMauiItemList` and pushes current selected-index lane.
   */
  int cfunc_CMauiItemListGetSelectionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079AD30 (FUN_0079AD30, cfunc_CMauiItemListSetNewColors)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListSetNewColorsL`.
   */
  int cfunc_CMauiItemListSetNewColors(lua_State* luaContext);

  /**
   * Address: 0x0079AD50 (FUN_0079AD50, func_CMauiItemListSetNewColors_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:SetNewColors(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListSetNewColors_LuaFuncDef();

  /**
   * Address: 0x0079ADB0 (FUN_0079ADB0, cfunc_CMauiItemListSetNewColorsL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus optional color lanes and updates the
   * item-list color palette runtime fields.
   */
  int cfunc_CMauiItemListSetNewColorsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B980 (FUN_0079B980, cfunc_CMauiItemListSetSelection)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListSetSelectionL`.
   */
  int cfunc_CMauiItemListSetSelection(lua_State* luaContext);

  /**
   * Address: 0x0079B9A0 (FUN_0079B9A0, func_CMauiItemListSetSelection_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:SetSelection(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListSetSelection_LuaFuncDef();

  /**
   * Address: 0x0079BA00 (FUN_0079BA00, cfunc_CMauiItemListSetSelectionL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus integer index and updates the current
   * selection lane when the index is in range.
   */
  int cfunc_CMauiItemListSetSelectionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079B040 (FUN_0079B040, cfunc_CMauiItemListGetItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListGetItemL`.
   */
  int cfunc_CMauiItemListGetItem(lua_State* luaContext);

  /**
   * Address: 0x0079B060 (FUN_0079B060, func_CMauiItemListGetItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:GetItem(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListGetItem_LuaFuncDef();

  /**
   * Address: 0x0079B0C0 (FUN_0079B0C0, cfunc_CMauiItemListGetItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus integer index and returns the selected item
   * string lane to Lua.
   */
  int cfunc_CMauiItemListGetItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079BB40 (FUN_0079BB40, cfunc_CMauiItemListGetItemCount)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListGetItemCountL`.
   */
  int cfunc_CMauiItemListGetItemCount(lua_State* luaContext);

  /**
   * Address: 0x0079BB60 (FUN_0079BB60, func_CMauiItemListGetItemCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:GetItemCount()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListGetItemCount_LuaFuncDef();

  /**
   * Address: 0x0079BBC0 (FUN_0079BBC0, cfunc_CMauiItemListGetItemCountL)
   *
   * What it does:
   * Reads one `CMauiItemList` and returns its current item count.
   */
  int cfunc_CMauiItemListGetItemCountL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079BCB0 (FUN_0079BCB0, cfunc_CMauiItemListEmpty)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListEmptyL`.
   */
  int cfunc_CMauiItemListEmpty(lua_State* luaContext);

  /**
   * Address: 0x0079BCD0 (FUN_0079BCD0, func_CMauiItemListEmpty_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:Empty()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListEmpty_LuaFuncDef();

  /**
   * Address: 0x0079BD30 (FUN_0079BD30, cfunc_CMauiItemListEmptyL)
   *
   * What it does:
   * Reads one `CMauiItemList` and returns whether the item storage is empty.
   */
  int cfunc_CMauiItemListEmptyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079BE10 (FUN_0079BE10, cfunc_CMauiItemListScrollToTop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListScrollToTopL`.
   */
  int cfunc_CMauiItemListScrollToTop(lua_State* luaContext);

  /**
   * Address: 0x0079BE30 (FUN_0079BE30, func_CMauiItemListScrollToTop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ScrollToTop()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListScrollToTop_LuaFuncDef();

  /**
   * Address: 0x0079BE90 (FUN_0079BE90, cfunc_CMauiItemListScrollToTopL)
   *
   * What it does:
   * Reads one `CMauiItemList` and scrolls to top.
   */
  int cfunc_CMauiItemListScrollToTopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079BF40 (FUN_0079BF40, cfunc_CMauiListItemScrollToBottom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiListItemScrollToBottomL`.
   */
  int cfunc_CMauiListItemScrollToBottom(lua_State* luaContext);

  /**
   * Address: 0x0079BF60 (FUN_0079BF60, func_CMauiListItemScrollToBottom_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ScrollToBottom()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiListItemScrollToBottom_LuaFuncDef();

  /**
   * Address: 0x0079BFC0 (FUN_0079BFC0, cfunc_CMauiListItemScrollToBottomL)
   *
   * What it does:
   * Reads one `CMauiItemList` and scrolls to bottom.
   */
  int cfunc_CMauiListItemScrollToBottomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C070 (FUN_0079C070, cfunc_CMauiItemListShowItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListShowItemL`.
   */
  int cfunc_CMauiItemListShowItem(lua_State* luaContext);

  /**
   * Address: 0x0079C090 (FUN_0079C090, func_CMauiItemListShowItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ShowItem(index)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListShowItem_LuaFuncDef();

  /**
   * Address: 0x0079C0F0 (FUN_0079C0F0, cfunc_CMauiItemListShowItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus integer index and scrolls when that row is
   * outside the current visible range.
   */
  int cfunc_CMauiItemListShowItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C200 (FUN_0079C200, cfunc_CMauiItemListGetRowHeight)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListGetRowHeightL`.
   */
  int cfunc_CMauiItemListGetRowHeight(lua_State* luaContext);

  /**
   * Address: 0x0079C220 (FUN_0079C220, func_CMauiItemListGetRowHeight_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:GetRowHeight()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListGetRowHeight_LuaFuncDef();

  /**
   * Address: 0x0079C280 (FUN_0079C280, cfunc_CMauiItemListGetRowHeightL)
   *
   * What it does:
   * Reads one `CMauiItemList` and returns line height from font metrics.
   */
  int cfunc_CMauiItemListGetRowHeightL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C4E0 (FUN_0079C4E0, cfunc_CMauiItemListShowMouseoverItem)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListShowMouseoverItemL`.
   */
  int cfunc_CMauiItemListShowMouseoverItem(lua_State* luaContext);

  /**
   * Address: 0x0079C500 (FUN_0079C500, func_CMauiItemListShowMouseoverItem_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ShowMouseoverItem(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListShowMouseoverItem_LuaFuncDef();

  /**
   * Address: 0x0079C560 (FUN_0079C560, cfunc_CMauiItemListShowMouseoverItemL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus boolean and toggles hover-item highlight.
   */
  int cfunc_CMauiItemListShowMouseoverItemL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C620 (FUN_0079C620, cfunc_CMauiItemListShowSelection)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListShowSelectionL`.
   */
  int cfunc_CMauiItemListShowSelection(lua_State* luaContext);

  /**
   * Address: 0x0079C640 (FUN_0079C640, func_CMauiItemListShowSelection_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:ShowSelection(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListShowSelection_LuaFuncDef();

  /**
   * Address: 0x0079C6A0 (FUN_0079C6A0, cfunc_CMauiItemListShowSelectionL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus boolean and toggles selection highlight.
   */
  int cfunc_CMauiItemListShowSelectionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C760 (FUN_0079C760, cfunc_CMauiItemListNeedsScrollBar)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListNeedsScrollBarL`.
   */
  int cfunc_CMauiItemListNeedsScrollBar(lua_State* luaContext);

  /**
   * Address: 0x0079C780 (FUN_0079C780, func_CMauiItemListNeedsScrollBar_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:NeedsScrollBar()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListNeedsScrollBar_LuaFuncDef();

  /**
   * Address: 0x0079C7E0 (FUN_0079C7E0, cfunc_CMauiItemListNeedsScrollBarL)
   *
   * What it does:
   * Reads one `CMauiItemList` and returns whether visible rows are fewer than
   * total item count.
   */
  int cfunc_CMauiItemListNeedsScrollBarL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079C350 (FUN_0079C350, cfunc_CMauiItemListGetStringAdvance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiItemListGetStringAdvanceL`.
   */
  int cfunc_CMauiItemListGetStringAdvance(lua_State* luaContext);

  /**
   * Address: 0x0079C370 (FUN_0079C370, func_CMauiItemListGetStringAdvance_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiItemList:GetStringAdvance(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiItemListGetStringAdvance_LuaFuncDef();

  /**
   * Address: 0x0079C3D0 (FUN_0079C3D0, cfunc_CMauiItemListGetStringAdvanceL)
   *
   * What it does:
   * Reads one `CMauiItemList` plus string arg and returns measured text
   * advance from the item-list font lane.
   */
  int cfunc_CMauiItemListGetStringAdvanceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079E740 (FUN_0079E740, cfunc_CMauiMeshSetMesh)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMeshSetMeshL`.
   */
  int cfunc_CMauiMeshSetMesh(lua_State* luaContext);

  /**
   * Address: 0x0079E760 (FUN_0079E760, func_CMauiMeshSetMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMesh:SetMesh(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMeshSetMesh_LuaFuncDef();

  /**
   * Address: 0x0079E7C0 (FUN_0079E7C0, cfunc_CMauiMeshSetMeshL)
   *
   * What it does:
   * Reads one `CMauiMesh` plus mesh-path string and calls `SetMesh`.
   */
  int cfunc_CMauiMeshSetMeshL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079E8B0 (FUN_0079E8B0, cfunc_CMauiMeshSetOrientation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiMeshSetOrientationL`.
   */
  int cfunc_CMauiMeshSetOrientation(lua_State* luaContext);

  /**
   * Address: 0x0079E8D0 (FUN_0079E8D0, func_CMauiMeshSetOrientation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMesh:SetOrientation(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMeshSetOrientation_LuaFuncDef();

  /**
    * Alias of FUN_0079E930 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMesh` plus quaternion arg and stores mesh orientation.
   */
  int cfunc_CMauiMeshSetOrientationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079F6F0 (FUN_0079F6F0, cfunc_CMauiMovieInternalSet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiMovieInternalSetL`.
   */
  int cfunc_CMauiMovieInternalSet(lua_State* luaContext);

  /**
   * Address: 0x0079F710 (FUN_0079F710, func_CMauiMovieInternalSet_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:InternalSet(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieInternalSet_LuaFuncDef();

  /**
   * Address: 0x0079F770 (FUN_0079F770, cfunc_CMauiMovieInternalSetL)
   *
   * What it does:
   * Reads one `CMauiMovie` plus filename string, calls `LoadFile`, and returns
   * one boolean success lane.
   */
  int cfunc_CMauiMovieInternalSetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079F870 (FUN_0079F870, cfunc_CMauiMovieLoop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieLoopL`.
   */
  int cfunc_CMauiMovieLoop(lua_State* luaContext);

  /**
   * Address: 0x0079F890 (FUN_0079F890, func_CMauiMovieLoop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:Loop(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieLoop_LuaFuncDef();

  /**
    * Alias of FUN_0079F8F0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` plus bool and updates loop state.
   */
  int cfunc_CMauiMovieLoopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079F9C0 (FUN_0079F9C0, cfunc_CMauiMoviePlay)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMoviePlayL`.
   */
  int cfunc_CMauiMoviePlay(lua_State* luaContext);

  /**
   * Address: 0x0079F9E0 (FUN_0079F9E0, func_CMauiMoviePlay_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:Play()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMoviePlay_LuaFuncDef();

  /**
    * Alias of FUN_0079FA40 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` and starts playback.
   */
  int cfunc_CMauiMoviePlayL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079FB20 (FUN_0079FB20, cfunc_CMauiMovieStop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieStopL`.
   */
  int cfunc_CMauiMovieStop(lua_State* luaContext);

  /**
   * Address: 0x0079FB40 (FUN_0079FB40, func_CMauiMovieStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:Stop()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieStop_LuaFuncDef();

  /**
    * Alias of FUN_0079FBA0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` and stops playback.
   */
  int cfunc_CMauiMovieStopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079FC70 (FUN_0079FC70, cfunc_CMauiMovieIsLoaded)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiMovieIsLoadedL`.
   */
  int cfunc_CMauiMovieIsLoaded(lua_State* luaContext);

  /**
   * Address: 0x0079FC90 (FUN_0079FC90, func_CMauiMovieIsLoaded_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:IsLoaded()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieIsLoaded_LuaFuncDef();

  /**
    * Alias of FUN_0079FCF0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` and returns its load state.
   */
  int cfunc_CMauiMovieIsLoadedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079FDD0 (FUN_0079FDD0, cfunc_CMauiMovieGetNumFrames)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiMovieGetNumFramesL`.
   */
  int cfunc_CMauiMovieGetNumFrames(lua_State* luaContext);

  /**
   * Address: 0x0079FDF0 (FUN_0079FDF0, func_CMauiMovieGetNumFrames_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:GetNumFrames()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieGetNumFrames_LuaFuncDef();

  /**
    * Alias of FUN_0079FE50 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` and returns frame count.
   */
  int cfunc_CMauiMovieGetNumFramesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079FF20 (FUN_0079FF20, cfunc_CMauiMovieGetFrameRate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiMovieGetFrameRateL`.
   */
  int cfunc_CMauiMovieGetFrameRate(lua_State* luaContext);

  /**
   * Address: 0x0079FF40 (FUN_0079FF40, func_CMauiMovieGetFrameRate_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiMovie:GetFrameRate()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiMovieGetFrameRate_LuaFuncDef();

  /**
    * Alias of FUN_0079FFA0 (non-canonical helper lane).
   *
   * What it does:
   * Reads one `CMauiMovie` and returns frame rate.
   */
  int cfunc_CMauiMovieGetFrameRateL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A17A0 (FUN_007A17A0, cfunc_CMauiScrollbarSetScrollable)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiScrollbarSetScrollableL`.
   */
  int cfunc_CMauiScrollbarSetScrollable(lua_State* luaContext);

  /**
   * Address: 0x007A17C0 (FUN_007A17C0, func_CMauiScrollbarSetScrollable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiScrollbar:SetScrollable(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiScrollbarSetScrollable_LuaFuncDef();

  /**
   * Address: 0x007A1820 (FUN_007A1820, cfunc_CMauiScrollbarSetScrollableL)
   *
   * What it does:
   * Reads one scrollbar and one control and binds scroll target.
   */
  int cfunc_CMauiScrollbarSetScrollableL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A1920 (FUN_007A1920, cfunc_CMauiScrollbarSetNewTextures)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiScrollbarSetNewTexturesL`.
   */
  int cfunc_CMauiScrollbarSetNewTextures(lua_State* luaContext);

  /**
   * Address: 0x007A1940 (FUN_007A1940, func_CMauiScrollbarSetNewTextures_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiScrollbar:SetNewTextures(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiScrollbarSetNewTextures_LuaFuncDef();

  /**
   * Address: 0x007A19A0 (FUN_007A19A0, cfunc_CMauiScrollbarSetNewTexturesL)
   *
   * What it does:
   * Reads one `CMauiScrollbar` plus four optional texture-path lanes and
   * forwards resolved textures (with warning-color fallbacks) to
   * `CMauiScrollbar::SetTextures`.
   */
  int cfunc_CMauiScrollbarSetNewTexturesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A2080 (FUN_007A2080, cfunc_CMauiScrollbarDoScrollLines)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiScrollbarDoScrollLinesL`.
   */
  int cfunc_CMauiScrollbarDoScrollLines(lua_State* luaContext);

  /**
   * Address: 0x007A20A0 (FUN_007A20A0, func_CMauiScrollbarDoScrollLines_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiScrollbar:DoScrollLines(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiScrollbarDoScrollLines_LuaFuncDef();

  /**
   * Address: 0x007A2100 (FUN_007A2100, cfunc_CMauiScrollbarDoScrollLinesL)
   *
   * What it does:
   * Reads one `CMauiScrollbar` plus numeric amount and forwards line-scroll to
   * its current scrollable control lane.
   */
  int cfunc_CMauiScrollbarDoScrollLinesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A2220 (FUN_007A2220, cfunc_CMauiScrollbarDoScrollPages)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiScrollbarDoScrollPagesL`.
   */
  int cfunc_CMauiScrollbarDoScrollPages(lua_State* luaContext);

  /**
   * Address: 0x007A2240 (FUN_007A2240, func_CMauiScrollbarDoScrollPages_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiScrollbar:DoScrollPages(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiScrollbarDoScrollPages_LuaFuncDef();

  /**
   * Address: 0x007A22A0 (FUN_007A22A0, cfunc_CMauiScrollbarDoScrollPagesL)
   *
   * What it does:
   * Reads one `CMauiScrollbar` plus numeric amount and forwards page-scroll to
   * its current scrollable control lane.
   */
  int cfunc_CMauiScrollbarDoScrollPagesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A34F0 (FUN_007A34F0, cfunc_CMauiTextSetNewFont)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetNewFontL`.
   */
  int cfunc_CMauiTextSetNewFont(lua_State* luaContext);

  /**
   * Address: 0x007A3510 (FUN_007A3510, func_CMauiTextSetNewFont_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetNewFont(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetNewFont_LuaFuncDef();

  /**
   * Address: 0x007A3570 (FUN_007A3570, cfunc_CMauiTextSetNewFontL)
   *
   * What it does:
   * Reads one `CMauiText` plus `(family, pointsize)`, creates one font, and
   * applies it to text runtime lanes.
   */
  int cfunc_CMauiTextSetNewFontL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3880 (FUN_007A3880, cfunc_CMauiTextGetText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextGetTextL`.
   */
  int cfunc_CMauiTextGetText(lua_State* luaContext);

  /**
   * Address: 0x007A38A0 (FUN_007A38A0, func_CMauiTextGetText_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:GetText()` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextGetText_LuaFuncDef();

  /**
   * Address: 0x007A3900 (FUN_007A3900, cfunc_CMauiTextGetTextL)
   *
   * What it does:
   * Reads one `CMauiText` and returns its current text lane.
   */
  int cfunc_CMauiTextGetTextL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A39F0 (FUN_007A39F0, cfunc_CMauiTextSetNewColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetNewColorL`.
   */
  int cfunc_CMauiTextSetNewColor(lua_State* luaContext);

  /**
   * Address: 0x007A3A10 (FUN_007A3A10, func_CMauiTextSetNewColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetNewColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetNewColor_LuaFuncDef();

  /**
   * Address: 0x007A3A70 (FUN_007A3A70, cfunc_CMauiTextSetNewColorL)
   *
   * What it does:
   * Reads one `CMauiText` plus color arg and updates text color lane.
   */
  int cfunc_CMauiTextSetNewColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3B60 (FUN_007A3B60, cfunc_CMauiTextSetDropShadow)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetDropShadowL`.
   */
  int cfunc_CMauiTextSetDropShadow(lua_State* luaContext);

  /**
   * Address: 0x007A3B80 (FUN_007A3B80, func_CMauiTextSetDropShadow_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetDropShadow(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetDropShadow_LuaFuncDef();

  /**
   * Address: 0x007A3BE0 (FUN_007A3BE0, cfunc_CMauiTextSetDropShadowL)
   *
   * What it does:
   * Reads one `CMauiText` plus bool and updates drop-shadow lane.
   */
  int cfunc_CMauiTextSetDropShadowL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3CB0 (FUN_007A3CB0, cfunc_CMauiTextSetCenteredHorizontally)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetCenteredHorizontallyL`.
   */
  int cfunc_CMauiTextSetCenteredHorizontally(lua_State* luaContext);

  /**
   * Address: 0x007A3CD0 (FUN_007A3CD0, func_CMauiTextSetCenteredHorizontally_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetCenteredHorizontally(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetCenteredHorizontally_LuaFuncDef();

  /**
   * Address: 0x007A3D30 (FUN_007A3D30, cfunc_CMauiTextSetCenteredHorizontallyL)
   *
   * What it does:
   * Reads one `CMauiText` plus bool and updates horizontal-centering lane.
   */
  int cfunc_CMauiTextSetCenteredHorizontallyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3E00 (FUN_007A3E00, cfunc_CMauiTextSetCenteredVertically)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetCenteredVerticallyL`.
   */
  int cfunc_CMauiTextSetCenteredVertically(lua_State* luaContext);

  /**
   * Address: 0x007A3E20 (FUN_007A3E20, func_CMauiTextSetCenteredVertically_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetCenteredVertically(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetCenteredVertically_LuaFuncDef();

  /**
   * Address: 0x007A3E80 (FUN_007A3E80, cfunc_CMauiTextSetCenteredVerticallyL)
   *
   * What it does:
   * Reads one `CMauiText` plus bool and updates vertical-centering lane.
   */
  int cfunc_CMauiTextSetCenteredVerticallyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A40E0 (FUN_007A40E0, cfunc_CMauiTextSetNewClipToWidth)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextSetNewClipToWidthL`.
   */
  int cfunc_CMauiTextSetNewClipToWidth(lua_State* luaContext);

  /**
   * Address: 0x007A4100 (FUN_007A4100, func_CMauiTextSetNewClipToWidth_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetNewClipToWidth(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetNewClipToWidth_LuaFuncDef();

  /**
   * Address: 0x007A4160 (FUN_007A4160, cfunc_CMauiTextSetNewClipToWidthL)
   *
   * What it does:
   * Reads one `CMauiText` plus bool and updates clip-to-width lane.
   */
  int cfunc_CMauiTextSetNewClipToWidthL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3710 (FUN_007A3710, cfunc_CMauiTextSetText)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CMauiTextSetTextL`.
   */
  int cfunc_CMauiTextSetText(lua_State* luaContext);

  /**
   * Address: 0x007A3730 (FUN_007A3730, func_CMauiTextSetText_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:SetText(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextSetText_LuaFuncDef();

  /**
   * Address: 0x007A3790 (FUN_007A3790, cfunc_CMauiTextSetTextL)
   *
   * What it does:
   * Reads one `CMauiText` plus text string and updates control text and
   * cached text advance.
   */
  int cfunc_CMauiTextSetTextL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A3F50 (FUN_007A3F50, cfunc_CMauiTextGetStringAdvance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CMauiTextGetStringAdvanceL`.
   */
  int cfunc_CMauiTextGetStringAdvance(lua_State* luaContext);

  /**
   * Address: 0x007A3F70 (FUN_007A3F70, func_CMauiTextGetStringAdvance_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CMauiText:GetStringAdvance(...)` Lua binder.
   */
  CScrLuaInitForm* func_CMauiTextGetStringAdvance_LuaFuncDef();

  /**
   * Address: 0x007A3FD0 (FUN_007A3FD0, cfunc_CMauiTextCMauiTextL)
   *
   * What it does:
   * Reads one `CMauiText` plus string arg and returns measured text advance
   * from the text-control font lane.
   */
  int cfunc_CMauiTextGetStringAdvanceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00850D20 (FUN_00850D20, cfunc_InternalCreateMapPreview)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_InternalCreateMapPreviewL`.
   */
  int cfunc_InternalCreateMapPreview(lua_State* luaContext);

  /**
   * Address: 0x00850D40 (FUN_00850D40, func_InternalCreateMapPreview_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `InternalCreateMapPreview(...)` Lua binder.
   */
  CScrLuaInitForm* func_InternalCreateMapPreview_LuaFuncDef();

  /**
   * Address: 0x00850ED0 (FUN_00850ED0, cfunc_CUIMapPreviewSetTexture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIMapPreviewSetTextureL`.
   */
  int cfunc_CUIMapPreviewSetTexture(lua_State* luaContext);

  /**
   * Address: 0x00850EF0 (FUN_00850EF0, func_CUIMapPreviewSetTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIMapPreview:SetTexture(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIMapPreviewSetTexture_LuaFuncDef();

  /**
   * Address: 0x00850F50 (FUN_00850F50, cfunc_CUIMapPreviewSetTextureL)
   *
   * What it does:
   * Reads one `CUIMapPreview` plus texture-path string and returns one success
   * boolean from `CUIMapPreview::SetTexture`.
   */
  int cfunc_CUIMapPreviewSetTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00851040 (FUN_00851040, cfunc_CUIMapPreviewSetTextureFromMap)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIMapPreviewSetTextureFromMapL`.
   */
  int cfunc_CUIMapPreviewSetTextureFromMap(lua_State* luaContext);

  /**
   * Address: 0x00851060 (FUN_00851060, func_CUIMapPreviewSetTextureFromMap_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIMapPreview:SetTextureFromMap(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIMapPreviewSetTextureFromMap_LuaFuncDef();

  /**
   * Address: 0x008510C0 (FUN_008510C0, cfunc_CUIMapPreviewSetTextureFromMapL)
   *
   * What it does:
   * Reads one `CUIMapPreview` plus map-path string and returns one success
   * boolean from `CUIMapPreview::SetTextureFromMap`.
   */
  int cfunc_CUIMapPreviewSetTextureFromMapL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008511B0 (FUN_008511B0, cfunc_CUIMapPreviewClearTexture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIMapPreviewClearTextureL`.
   */
  int cfunc_CUIMapPreviewClearTexture(lua_State* luaContext);

  /**
   * Address: 0x008511D0 (FUN_008511D0, func_CUIMapPreviewClearTexture_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIMapPreview:ClearTexture()` Lua binder.
   */
  CScrLuaInitForm* func_CUIMapPreviewClearTexture_LuaFuncDef();

  /**
   * Address: 0x00851230 (FUN_00851230, cfunc_CUIMapPreviewClearTextureL)
   *
   * What it does:
   * Reads one `CUIMapPreview` and clears its currently bound preview texture.
   */
  int cfunc_CUIMapPreviewClearTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00846760 (FUN_00846760, cfunc_SetFrontEndData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetFrontEndDataL`.
   */
  int cfunc_SetFrontEndData(lua_State* luaContext);

  /**
   * Address: 0x00846780 (FUN_00846780, func_SetFrontEndData_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `SetFrontEndData(...)` Lua binder.
   */
  CScrLuaInitForm* func_SetFrontEndData_LuaFuncDef();

  /**
   * Address: 0x008467E0 (FUN_008467E0, cfunc_SetFrontEndDataL)
   *
   * What it does:
   * Copies caller key/data lanes into user-state global `FrontEndData`.
   */
  int cfunc_SetFrontEndDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00846960 (FUN_00846960, cfunc_GetFrontEndData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetFrontEndDataL`.
   */
  int cfunc_GetFrontEndData(lua_State* luaContext);

  /**
   * Address: 0x00846980 (FUN_00846980, func_GetFrontEndData_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `GetFrontEndData(...)` Lua binder.
   */
  CScrLuaInitForm* func_GetFrontEndData_LuaFuncDef();

  /**
   * Address: 0x008469E0 (FUN_008469E0, cfunc_GetFrontEndDataL)
   *
   * What it does:
   * Resolves one key from caller Lua state against user-state `FrontEndData`
   * and pushes the copied lookup result back to caller state.
   */
  int cfunc_GetFrontEndDataL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0084DDE0 (FUN_0084DDE0, cfunc_GetCursor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetCursorL`.
   */
  int cfunc_GetCursor(lua_State* luaContext);

  /**
   * Address: 0x0084DE00 (FUN_0084DE00, func_GetCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `GetCursor()` Lua binder.
   */
  CScrLuaInitForm* func_GetCursor_LuaFuncDef();

  /**
   * Address: 0x0084DE60 (FUN_0084DE60, cfunc_GetCursorL)
   *
   * What it does:
   * Returns active UI cursor script object when present; otherwise pushes `nil`.
   */
  int cfunc_GetCursorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0084DEF0 (FUN_0084DEF0, cfunc_SetUIControlsAlpha)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SetUIControlsAlphaL`.
   */
  int cfunc_SetUIControlsAlpha(lua_State* luaContext);

  /**
   * Address: 0x0084DF10 (FUN_0084DF10, func_SetUIControlsAlpha_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `SetUIControlsAlpha(float)` Lua binder.
   */
  CScrLuaInitForm* func_SetUIControlsAlpha_LuaFuncDef();

  /**
   * Address: 0x0084DF70 (FUN_0084DF70, cfunc_SetUIControlsAlphaL)
   *
   * What it does:
   * Reads one float arg and updates active UI manager controls-alpha lane.
   */
  int cfunc_SetUIControlsAlphaL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0084E000 (FUN_0084E000, cfunc_GetUIControlsAlpha)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_GetUIControlsAlphaL`.
   */
  int cfunc_GetUIControlsAlpha(lua_State* luaContext);

  /**
   * Address: 0x0084E020 (FUN_0084E020, func_GetUIControlsAlpha_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `GetUIControlsAlpha()` Lua binder.
   */
  CScrLuaInitForm* func_GetUIControlsAlpha_LuaFuncDef();

  /**
   * Address: 0x0084E080 (FUN_0084E080, cfunc_GetUIControlsAlphaL)
   *
   * What it does:
   * Reads active UI controls-alpha lane and pushes it, or `nil` if unavailable.
   */
  int cfunc_GetUIControlsAlphaL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0084E140 (FUN_0084E140, func_FlushEvents_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `FlushEvents()` Lua binder metadata.
   */
  CScrLuaInitForm* func_FlushEvents_LuaFuncDef();

  /**
   * Address: 0x00BE4EC0 (FUN_00BE4EC0, register_FlushEvents_LuaFuncDef)
   */
  CScrLuaInitForm* register_FlushEvents_LuaFuncDef();

  /**
   * Address: 0x008725B0 (FUN_008725B0, cfunc_CUIWorldViewZoomScale)
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewZoomScaleL`.
   */
  int cfunc_CUIWorldViewZoomScale(lua_State* luaContext);

  /**
   * Address: 0x008725D0 (FUN_008725D0, func_CUIWorldViewZoomScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:ZoomScale(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewZoomScale_LuaFuncDef();

  /**
   * Address: 0x00872630 (FUN_00872630, cfunc_CUIWorldViewZoomScaleL)
   *
   * What it does:
   * Reads `CUIWorldView:ZoomScale` Lua args and forwards anchor and wheel
   * zoom lanes into the active world-view camera.
   */
  int cfunc_CUIWorldViewZoomScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00872C60 (FUN_00872C60, cfunc_UnProject)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnProjectL`.
   */
  int cfunc_UnProject(lua_State* luaContext);

  /**
   * Address: 0x00872C80 (FUN_00872C80, func_UnProject_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `UnProject(self, screenPos)` Lua binder.
   */
  CScrLuaInitForm* func_UnProject_LuaFuncDef();

  /**
   * Address: 0x00872CE0 (FUN_00872CE0, cfunc_UnProjectL)
   *
   * What it does:
   * Resolves one world-view camera and converts a screen-space `Vector2` into
   * a world-space `Vector3` surface point.
   */
  int cfunc_UnProjectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00872E20 (FUN_00872E20, cfunc_CUIWorldViewProject)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewProjectL`.
   */
  int cfunc_CUIWorldViewProject(lua_State* luaContext);

  /**
   * Address: 0x00872E40 (FUN_00872E40, func_CUIWorldViewProject_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:Project(self, worldPos)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewProject_LuaFuncDef();

  /**
   * Address: 0x00872EA0 (FUN_00872EA0, cfunc_CUIWorldViewProjectL)
   *
   * What it does:
   * Projects one world-space `Vector3` into world-view control-space
   * coordinates and returns one `Vector2` (or nil when camera is absent).
   */
  int cfunc_CUIWorldViewProjectL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00873170 (FUN_00873170, cfunc_CUIWorldViewSetCartographic)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewSetCartographicL`.
   */
  int cfunc_CUIWorldViewSetCartographic(lua_State* luaContext);

  /**
   * Address: 0x00873190 (FUN_00873190, func_CUIWorldViewSetCartographic_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:SetCartographic(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewSetCartographic_LuaFuncDef();

  /**
   * Address: 0x008731F0 (FUN_008731F0, cfunc_CUIWorldViewSetCartographicL)
   *
   * What it does:
   * Updates one world-view orthographic/cartographic render mode flag.
   */
  int cfunc_CUIWorldViewSetCartographicL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008732C0 (FUN_008732C0, cfunc_CUIWorldViewIsCartographic)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewIsCartographicL`.
   */
  int cfunc_CUIWorldViewIsCartographic(lua_State* luaContext);

  /**
   * Address: 0x008732E0 (FUN_008732E0, func_CUIWorldViewIsCartographic_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:IsCartographic()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewIsCartographic_LuaFuncDef();

  /**
   * Address: 0x00873340 (FUN_00873340, cfunc_CUIWorldViewIsCartographicL)
   *
   * What it does:
   * Returns whether one world-view currently renders in orthographic mode.
   */
  int cfunc_CUIWorldViewIsCartographicL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00873410 (FUN_00873410, cfunc_CUIWorldViewEnableResourceRendering)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewEnableResourceRenderingL`.
   */
  int cfunc_CUIWorldViewEnableResourceRendering(lua_State* luaContext);

  /**
   * Address: 0x00873430 (FUN_00873430, func_CUIWorldViewEnableResourceRendering_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:EnableResourceRendering(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewEnableResourceRendering_LuaFuncDef();

  /**
   * Address: 0x00873490 (FUN_00873490, cfunc_CUIWorldViewEnableResourceRenderingL)
   *
   * What it does:
   * Updates one world-view resource-rendering enable flag.
   */
  int cfunc_CUIWorldViewEnableResourceRenderingL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00873550 (FUN_00873550, cfunc_CUIWorldViewIsResourceRenderingEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewIsResourceRenderingEnabledL`.
   */
  int cfunc_CUIWorldViewIsResourceRenderingEnabled(lua_State* luaContext);

  /**
   * Address: 0x00873570 (FUN_00873570, func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:IsResourceRenderingEnabled()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewIsResourceRenderingEnabled_LuaFuncDef();

  /**
   * Address: 0x008735D0 (FUN_008735D0, cfunc_CUIWorldViewIsResourceRenderingEnabledL)
   *
   * What it does:
   * Returns whether one world-view has resource rendering enabled.
   */
  int cfunc_CUIWorldViewIsResourceRenderingEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871A20 (FUN_00871A20, cfunc_CUIWorldViewCameraReset)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewCameraResetL`.
   */
  int cfunc_CUIWorldViewCameraReset(lua_State* luaContext);

  /**
   * Address: 0x00871A40 (FUN_00871A40, func_CUIWorldViewCameraReset_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:CameraReset()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewCameraReset_LuaFuncDef();

  /**
   * Address: 0x00871710 (FUN_00871710, cfunc_CUIWorldView__initL)
   *
   * `CUIWorldView:__init(parent, cameraName, depth, isMiniMap, trackCamera)`
   * Lua constructor worker: validates 4-6 args, extracts the parent control,
   * resolves the minimap/track-camera options, allocates + constructs the
   * world-view control, runs DoInit(), and pushes it back to Lua.
   */
  int cfunc_CUIWorldView__initL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871690 (FUN_00871690, cfunc_CUIWorldView__init)
   *
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldView__initL`.
   */
  int cfunc_CUIWorldView__init(lua_State* luaContext);

  /**
   * Address: 0x008716B0 (FUN_008716B0, func_CUIWorldView__init_LuaFuncDef)
   *
   * Publishes the `CUIWorldView:__init(...)` Lua constructor binder.
   */
  CScrLuaInitForm* func_CUIWorldView__init_LuaFuncDef();

  /**
   * Address: 0x00871AA0 (FUN_00871AA0, cfunc_CUIWorldViewCameraResetL)
   *
   * What it does:
   * Resets one world-view camera and returns the world-view Lua object.
   */
  int cfunc_CUIWorldViewCameraResetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871B70 (FUN_00871B70, cfunc_CUIWorldViewGetsGlobalCameraCommands)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewGetsGlobalCameraCommandsL`.
   */
  int cfunc_CUIWorldViewGetsGlobalCameraCommands(lua_State* luaContext);

  /**
   * Address: 0x00871B90 (FUN_00871B90, func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:GetsGlobalCameraCommands(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewGetsGlobalCameraCommands_LuaFuncDef();

  /**
   * Address: 0x00871BF0 (FUN_00871BF0, cfunc_CUIWorldViewGetsGlobalCameraCommandsL)
   *
   * What it does:
   * Updates one world-view global-camera-command flag and returns the
   * world-view Lua object.
   */
  int cfunc_CUIWorldViewGetsGlobalCameraCommandsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871CC0 (FUN_00871CC0, cfunc_CUIWorldViewGetRightMouseButtonOrder)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewGetRightMouseButtonOrderL`.
   */
  int cfunc_CUIWorldViewGetRightMouseButtonOrder(lua_State* luaContext);

  /**
   * Address: 0x00871CE0 (FUN_00871CE0, func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:GetRightMouseButtonOrder()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewGetRightMouseButtonOrder_LuaFuncDef();

  /**
   * Address: 0x00871D40 (FUN_00871D40, cfunc_CUIWorldViewGetRightMouseButtonOrderL)
   *
   * What it does:
   * Resolves the active right-click action from world-session cursor context
   * and returns the order lexical token string (or nil when no order applies).
   */
  int cfunc_CUIWorldViewGetRightMouseButtonOrderL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871EC0 (FUN_00871EC0, cfunc_CUIWorldViewHasHighlightCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewHasHighlightCommandL`.
   */
  int cfunc_CUIWorldViewHasHighlightCommand(lua_State* luaContext);

  /**
   * Address: 0x00871EE0 (FUN_00871EE0, func_CUIWorldViewHasHighlightCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:HasHighlightCommand()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewHasHighlightCommand_LuaFuncDef();

  /**
   * Address: 0x00871F40 (FUN_00871F40, cfunc_CUIWorldViewHasHighlightCommandL)
   *
   * What it does:
   * Returns whether the active world-session cursor currently has one
   * highlight command id.
   */
  int cfunc_CUIWorldViewHasHighlightCommandL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00871FA0 (FUN_00871FA0, cfunc_CUIWorldShowConvertToPatrolCursor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldShowConvertToPatrolCursorL`.
   */
  int cfunc_CUIWorldShowConvertToPatrolCursor(lua_State* luaContext);

  /**
   * Address: 0x00871FC0 (FUN_00871FC0, func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:ShowConvertToPatrolCursor()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldShowConvertToPatrolCursor_LuaFuncDef();

  /**
   * Address: 0x00872020 (FUN_00872020, cfunc_CUIWorldShowConvertToPatrolCursorL)
   *
   * What it does:
   * Returns one world-view flag controlling patrol-convert cursor display.
   */
  int cfunc_CUIWorldShowConvertToPatrolCursorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008720E0 (FUN_008720E0, cfunc_CUIWorldViewUnlockInput)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewUnlockInputL`.
   */
  int cfunc_CUIWorldViewUnlockInput(lua_State* luaContext);

  /**
   * Address: 0x00872100 (FUN_00872100, func_CUIWorldViewUnlockInput_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:UnlockInput(camera)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewUnlockInput_LuaFuncDef();

  /**
   * Address: 0x00872160 (FUN_00872160, cfunc_CUIWorldViewUnlockInputL)
   *
   * What it does:
   * Decrements one world-view input-lock counter lane.
   */
  int cfunc_CUIWorldViewUnlockInputL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00872200 (FUN_00872200, cfunc_CUIWorldViewLockInput)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewLockInputL`.
   */
  int cfunc_CUIWorldViewLockInput(lua_State* luaContext);

  /**
   * Address: 0x00872220 (FUN_00872220, func_CUIWorldViewLockInput_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:LockInput(camera)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewLockInput_LuaFuncDef();

  /**
   * Address: 0x00872280 (FUN_00872280, cfunc_CUIWorldViewLockInputL)
   *
   * What it does:
   * Increments one world-view input-lock counter lane.
   */
  int cfunc_CUIWorldViewLockInputL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00872330 (FUN_00872330, cfunc_CUIWorldViewIsInputLocked)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewIsInputLockedL`.
   */
  int cfunc_CUIWorldViewIsInputLocked(lua_State* luaContext);

  /**
   * Address: 0x00872350 (FUN_00872350, func_CUIWorldViewIsInputLocked_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:IsInputLocked(camera)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewIsInputLocked_LuaFuncDef();

  /**
   * Address: 0x008723B0 (FUN_008723B0, cfunc_CUIWorldViewIsInputLockedL)
   *
   * What it does:
   * Returns whether one world-view input-lock counter lane is positive.
   */
  int cfunc_CUIWorldViewIsInputLockedL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00872470 (FUN_00872470, cfunc_CUIWorldViewSetHighlightEnabled)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewSetHighlightEnabledL`.
   */
  int cfunc_CUIWorldViewSetHighlightEnabled(lua_State* luaContext);

  /**
   * Address: 0x00872490 (FUN_00872490, func_CUIWorldViewSetHighlightEnabled_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:SetHighlightEnabled(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewSetHighlightEnabled_LuaFuncDef();

  /**
   * Address: 0x008724F0 (FUN_008724F0, cfunc_CUIWorldViewSetHighlightEnabledL)
   *
   * What it does:
   * Updates one world-view highlight-enabled boolean lane.
   */
  int cfunc_CUIWorldViewSetHighlightEnabledL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086AA50 (FUN_0086AA50, cfunc_CLuaWldUIProviderDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CLuaWldUIProviderDestroyL`.
   */
  int cfunc_CLuaWldUIProviderDestroy(lua_State* luaContext);

  /**
   * Address: 0x0086AA70 (FUN_0086AA70, func_CLuaWldUIProviderDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WldUIProvider:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_CLuaWldUIProviderDestroy_LuaFuncDef();

  /**
   * Address: 0x0086AAD0 (FUN_0086AAD0, cfunc_CLuaWldUIProviderDestroyL)
   *
   * What it does:
   * Resolves one optional world-ui provider object and destroys it when alive.
   */
  int cfunc_CLuaWldUIProviderDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086BC90 (FUN_0086BC90, cfunc_CUIWorldMeshDestroy)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshDestroyL`.
   */
  int cfunc_CUIWorldMeshDestroy(lua_State* luaContext);

  /**
   * Address: 0x0086BCB0 (FUN_0086BCB0, func_CUIWorldMeshDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:Destroy()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshDestroy_LuaFuncDef();

  /**
   * Address: 0x0086BDC0 (FUN_0086BDC0, cfunc_CUIWorldMeshSetMesh)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshSetMeshL`.
   */
  int cfunc_CUIWorldMeshSetMesh(lua_State* luaContext);

  /**
   * Address: 0x0086BDE0 (FUN_0086BDE0, func_CUIWorldMeshSetMesh_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetMesh(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetMesh_LuaFuncDef();

  /**
   * Address: 0x0086BF50 (FUN_0086BF50, cfunc_CUIWorldMeshSetStance)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshSetStanceL`.
   */
  int cfunc_CUIWorldMeshSetStance(lua_State* luaContext);

  /**
   * Address: 0x0086BF70 (FUN_0086BF70, func_CUIWorldMeshSetStance_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetStance(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetStance_LuaFuncDef();

  /**
   * Address: 0x0086C1D0 (FUN_0086C1D0, cfunc_CUIWorldMeshSetHidden)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshSetHiddenL`.
   */
  int cfunc_CUIWorldMeshSetHidden(lua_State* luaContext);

  /**
   * Address: 0x0086C1F0 (FUN_0086C1F0, func_CUIWorldMeshSetHidden_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetHidden(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetHidden_LuaFuncDef();

  /**
   * Address: 0x0086C310 (FUN_0086C310, cfunc_CUIWorldMeshIsHidden)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshIsHiddenL`.
   */
  int cfunc_CUIWorldMeshIsHidden(lua_State* luaContext);

  /**
   * Address: 0x0086C330 (FUN_0086C330, func_CUIWorldMeshIsHidden_LuaFuncDef)
   *
   * What it does:
   * Publishes the `bool WorldMesh:IsHidden()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshIsHidden_LuaFuncDef();

  /**
   * Address: 0x0086C450 (FUN_0086C450, cfunc_CUIWorldMeshSetAuxiliaryParameter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshSetAuxiliaryParameterL`.
   */
  int cfunc_CUIWorldMeshSetAuxiliaryParameter(lua_State* luaContext);

  /**
   * Address: 0x0086C470 (FUN_0086C470, func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetAuxiliaryParameter(float)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetAuxiliaryParameter_LuaFuncDef();

  /**
   * Address: 0x0086C5D0 (FUN_0086C5D0, cfunc_CUIWorldMeshSetFractionCompleteParameter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshSetFractionCompleteParameterL`.
   */
  int cfunc_CUIWorldMeshSetFractionCompleteParameter(lua_State* luaContext);

  /**
   * Address: 0x0086C5F0 (FUN_0086C5F0, func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetFractionCompleteParameter(float)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetFractionCompleteParameter_LuaFuncDef();

  /**
   * Address: 0x0086C750 (FUN_0086C750, cfunc_CUIWorldMeshSetFractionHealthParameter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshSetFractionHealthParameterL`.
   */
  int cfunc_CUIWorldMeshSetFractionHealthParameter(lua_State* luaContext);

  /**
   * Address: 0x0086C770 (FUN_0086C770, func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetFractionHealthParameter(float)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetFractionHealthParameter_LuaFuncDef();

  /**
   * Address: 0x0086C8D0 (FUN_0086C8D0, cfunc_CUIWorldMeshSetLifetimeParameter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshSetLifetimeParameterL`.
   */
  int cfunc_CUIWorldMeshSetLifetimeParameter(lua_State* luaContext);

  /**
   * Address: 0x0086C8F0 (FUN_0086C8F0, func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetLifetimeParameter(float)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetLifetimeParameter_LuaFuncDef();

  /**
   * Address: 0x0086CA50 (FUN_0086CA50, cfunc_CUIWorldMeshSetColor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshSetColorL`.
   */
  int cfunc_CUIWorldMeshSetColor(lua_State* luaContext);

  /**
   * Address: 0x0086CA70 (FUN_0086CA70, func_CUIWorldMeshSetColor_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetColor(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetColor_LuaFuncDef();

  /**
   * Address: 0x0086CBB0 (FUN_0086CBB0, cfunc_CUIWorldMeshSetScale)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldMeshSetScaleL`.
   */
  int cfunc_CUIWorldMeshSetScale(lua_State* luaContext);

  /**
   * Address: 0x0086CBD0 (FUN_0086CBD0, func_CUIWorldMeshSetScale_LuaFuncDef)
   *
   * What it does:
   * Publishes the `WorldMesh:SetScale(...)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshSetScale_LuaFuncDef();

  /**
   * Address: 0x0086CD40 (FUN_0086CD40, cfunc_CUIWorldMeshGetInterpolatedPosition)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshGetInterpolatedPositionL`.
   */
  int cfunc_CUIWorldMeshGetInterpolatedPosition(lua_State* luaContext);

  /**
   * Address: 0x0086CD60 (FUN_0086CD60, func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Vector WorldMesh:GetInterpolatedPosition()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshGetInterpolatedPosition_LuaFuncDef();

  /**
   * Address: 0x0086CF00 (FUN_0086CF00, cfunc_CUIWorldMeshGetInterpolatedSphere)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshGetInterpolatedSphereL`.
   */
  int cfunc_CUIWorldMeshGetInterpolatedSphere(lua_State* luaContext);

  /**
   * Address: 0x0086CF20 (FUN_0086CF20, func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Vector WorldMesh:GetInterpolatedSphere()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshGetInterpolatedSphere_LuaFuncDef();

  /**
   * Address: 0x0086D0F0 (FUN_0086D0F0, cfunc_CUIWorldMeshGetInterpolatedAlignedBox)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL`.
   */
  int cfunc_CUIWorldMeshGetInterpolatedAlignedBox(lua_State* luaContext);

  /**
   * Address: 0x0086D110 (FUN_0086D110, func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Vector WorldMesh:GetInterpolatedAlignedBox()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshGetInterpolatedAlignedBox_LuaFuncDef();

  /**
   * Address: 0x0086D320 (FUN_0086D320, cfunc_CUIWorldMeshGetInterpolatedOrientedBox)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL`.
   */
  int cfunc_CUIWorldMeshGetInterpolatedOrientedBox(lua_State* luaContext);

  /**
   * Address: 0x0086D340 (FUN_0086D340, func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Vector WorldMesh:GetInterpolatedOrientedBox()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshGetInterpolatedOrientedBox_LuaFuncDef();

  /**
   * Address: 0x0086D5E0 (FUN_0086D5E0, cfunc_CUIWorldMeshGetInterpolatedScroll)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CUIWorldMeshGetInterpolatedScrollL`.
   */
  int cfunc_CUIWorldMeshGetInterpolatedScroll(lua_State* luaContext);

  /**
   * Address: 0x0086D600 (FUN_0086D600, func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Vector WorldMesh:GetInterpolatedScroll()` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldMeshGetInterpolatedScroll_LuaFuncDef();

  /**
   * Address: 0x0086BD10 (FUN_0086BD10, cfunc_CUIWorldMeshDestroyL)
   *
   * What it does:
   * Resolves one optional `CUIWorldMesh` and destroys it when still alive.
   */
  int cfunc_CUIWorldMeshDestroyL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086BFD0 (FUN_0086BFD0, cfunc_CUIWorldMeshSetStanceL)
   *
   * What it does:
   * Updates world-mesh stance from `(position[, orientation])` by forwarding
   * one identical start/end transform to mesh-instance stance state.
   */
  int cfunc_CUIWorldMeshSetStanceL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C250 (FUN_0086C250, cfunc_CUIWorldMeshSetHiddenL)
   *
   * What it does:
   * Writes hidden flag lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetHiddenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C390 (FUN_0086C390, cfunc_CUIWorldMeshIsHiddenL)
   *
   * What it does:
   * Pushes current hidden flag from underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshIsHiddenL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C4D0 (FUN_0086C4D0, cfunc_CUIWorldMeshSetAuxiliaryParameterL)
   *
   * What it does:
   * Writes auxiliary scalar parameter lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetAuxiliaryParameterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C650 (FUN_0086C650, cfunc_CUIWorldMeshSetFractionCompleteParameterL)
   *
   * What it does:
   * Writes fraction-complete scalar parameter lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetFractionCompleteParameterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C7D0 (FUN_0086C7D0, cfunc_CUIWorldMeshSetFractionHealthParameterL)
   *
   * What it does:
   * Writes fraction-health scalar parameter lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetFractionHealthParameterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086C950 (FUN_0086C950, cfunc_CUIWorldMeshSetLifetimeParameterL)
   *
   * What it does:
   * Writes lifetime scalar parameter lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetLifetimeParameterL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086CAD0 (FUN_0086CAD0, cfunc_CUIWorldMeshSetColorL)
   *
   * What it does:
   * Decodes one Lua color payload and writes packed color lane on underlying
   * `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetColorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086CC30 (FUN_0086CC30, cfunc_CUIWorldMeshSetScaleL)
   *
   * What it does:
   * Writes local scale vector lane on underlying `MeshInstance`.
   */
  int cfunc_CUIWorldMeshSetScaleL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086CDC0 (FUN_0086CDC0, cfunc_CUIWorldMeshGetInterpolatedPositionL)
   *
   * What it does:
   * Reads one `CUIWorldMesh` and returns current interpolated world position
   * vector from underlying `MeshInstance` state.
   */
  int cfunc_CUIWorldMeshGetInterpolatedPositionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086CF80 (FUN_0086CF80, cfunc_CUIWorldMeshGetInterpolatedSphereL)
   *
   * What it does:
   * Reads one `CUIWorldMesh` and returns current interpolated bounding sphere
   * payload (`vector` center + `radius`) from `MeshInstance` state.
   */
  int cfunc_CUIWorldMeshGetInterpolatedSphereL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086D170 (FUN_0086D170, cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL)
   *
   * What it does:
   * Reads one `CUIWorldMesh` and returns current interpolated axis-aligned
   * bounds payload from `MeshInstance` state.
   */
  int cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086D3A0 (FUN_0086D3A0, cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL)
   *
   * What it does:
   * Reads one `CUIWorldMesh` and returns current interpolated oriented-box
   * payload from `MeshInstance` state.
   */
  int cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0086D660 (FUN_0086D660, cfunc_CUIWorldMeshGetInterpolatedScrollL)
   *
   * What it does:
   * Reads one `CUIWorldMesh` and returns current interpolated UV scroll vector
   * from underlying `MeshInstance` state.
   */
  int cfunc_CUIWorldMeshGetInterpolatedScrollL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007913A0 (FUN_007913A0, Moho::CMauiEdit::DragMove)
   *
   * What it does:
   * IMauiDragger::DragMove override for the edit's embedded click-dragger:
   * extends the text selection between the drag-start caret and the character
   * nearest the current mouse X. Recovered as a free function taking the
   * IMauiDragger sub-object (at CMauiEdit + 0x11C).
   */
  void CMauiEditDragMove(IMauiDragger* dragger, const SMauiEventData* eventData);

  /**
   * Address: 0x0086F090 (FUN_0086F090)
   *
   * What it does:
   * Publishes world-camera/minimap cursor telemetry into engine stats.
   */
  void UIWorldViewUpdateCursorEngineStats(CUIWorldView* worldView, const Wm3::Vec3f& cursorWorldPosition);

  /**
   * Address: 0x00872830 (FUN_00872830, cfunc_CUIWorldViewGetScreenPos)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CUIWorldViewGetScreenPosL`.
   */
  int cfunc_CUIWorldViewGetScreenPos(lua_State* luaContext);

  /**
   * Address: 0x00872850 (FUN_00872850, func_CUIWorldViewGetScreenPos_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CUIWorldView:GetScreenPos(unit)` Lua binder.
   */
  CScrLuaInitForm* func_CUIWorldViewGetScreenPos_LuaFuncDef();

  /**
   * Address: 0x0079D7A0 (FUN_0079D7A0, cfunc_IsKeyDown)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IsKeyDownL`.
   */
  int cfunc_IsKeyDown(lua_State* luaContext);

  /**
   * Address: 0x0079D7C0 (FUN_0079D7C0, func_IsKeyDown_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `IsKeyDown(keyCode)` Lua binder.
   */
  CScrLuaInitForm* func_IsKeyDown_LuaFuncDef();

  /**
   * Address: 0x0079D820 (FUN_0079D820, cfunc_IsKeyDownL)
   *
   * What it does:
   * Resolves one `EMauiKeyCode` enum from string and pushes key-down boolean.
   */
  int cfunc_IsKeyDownL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079D8D0 (FUN_0079D8D0, cfunc_KeycodeMauiToMSW)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_KeycodeMauiToMSWL`.
   */
  int cfunc_KeycodeMauiToMSW(lua_State* luaContext);

  /**
   * Address: 0x0079D8F0 (FUN_0079D8F0, func_KeycodeMauiToMSW_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `KeycodeMauiToMSW(int)` Lua binder.
   */
  CScrLuaInitForm* func_KeycodeMauiToMSW_LuaFuncDef();

  /**
   * Address: 0x0079D950 (FUN_0079D950, cfunc_KeycodeMauiToMSWL)
   *
   * What it does:
   * Converts one Maui key code to the matching MSW key code and pushes it.
   */
  int cfunc_KeycodeMauiToMSWL(LuaPlus::LuaState* state);

  /**
   * Address: 0x0079D9F0 (FUN_0079D9F0, cfunc_KeycodeMSWToMaui)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_KeycodeMSWToMauiL`.
   */
  int cfunc_KeycodeMSWToMaui(lua_State* luaContext);

  /**
   * Address: 0x0079DA10 (FUN_0079DA10, func_KeycodeMSWToMaui_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `KeycodeMSWToMaui(int)` Lua binder.
   */
  CScrLuaInitForm* func_KeycodeMSWToMaui_LuaFuncDef();

  /**
   * Address: 0x0079DA70 (FUN_0079DA70, cfunc_KeycodeMSWToMauiL)
   *
   * What it does:
   * Converts one MSW key code to the matching Maui key code and pushes it.
   */
  int cfunc_KeycodeMSWToMauiL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A5190 (FUN_007A5190, cfunc_AnyInputCapture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_AnyInputCaptureL`.
   */
  int cfunc_AnyInputCapture(lua_State* luaContext);

  /**
   * Address: 0x007A51B0 (FUN_007A51B0, func_AnyInputCapture_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `AnyInputCapture()` Lua binder.
   */
  CScrLuaInitForm* func_AnyInputCapture_LuaFuncDef();

  /**
   * Address: 0x007A5210 (FUN_007A5210, cfunc_AnyInputCaptureL)
   *
   * What it does:
   * Returns whether the global input-capture stack currently has any valid
   * control.
   */
  int cfunc_AnyInputCaptureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A5280 (FUN_007A5280, cfunc_GetInputCapture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetInputCaptureL`.
   */
  int cfunc_GetInputCapture(lua_State* luaContext);

  /**
   * Address: 0x007A52A0 (FUN_007A52A0, func_GetInputCapture_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `GetInputCapture()` Lua binder.
   */
  CScrLuaInitForm* func_GetInputCapture_LuaFuncDef();

  /**
   * Address: 0x007A5300 (FUN_007A5300, cfunc_GetInputCaptureL)
   *
   * What it does:
   * Returns the top control on the global input-capture stack, or `nil` when
   * no capture exists.
   */
  int cfunc_GetInputCaptureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A53B0 (FUN_007A53B0, func_AddInputCapture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `func_AddInputCaptureL`.
   */
  int func_AddInputCapture(lua_State* luaContext);

  /**
   * Address: 0x007A53D0 (FUN_007A53D0, func_AddInputCapture_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `AddInputCapture(control)` Lua binder.
   */
  CScrLuaInitForm* func_AddInputCapture_LuaFuncDef();

  /**
   * Address: 0x007A5430 (FUN_007A5430, func_AddInputCaptureL)
   *
   * What it does:
   * Reads one control arg and pushes it onto the global input-capture stack.
   */
  int func_AddInputCaptureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007A45D0 (FUN_007A45D0, func_RemoveInputCapture)
   *
   * What it does:
   * Removes the first matching control from the back of the global
   * input-capture stack.
   */
  void func_RemoveInputCapture(CMauiControl* control);

  /**
   * Address: 0x007A54E0 (FUN_007A54E0, cfunc_RemoveInputCapture)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_RemoveInputCaptureL`.
   */
  int cfunc_RemoveInputCapture(lua_State* luaContext);

  /**
   * Address: 0x007A5500 (FUN_007A5500, func_RemoveInputCapture_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `RemoveInputCapture(control)` Lua binder.
   */
  CScrLuaInitForm* func_RemoveInputCapture_LuaFuncDef();

  /**
   * Address: 0x007A5560 (FUN_007A5560, cfunc_RemoveInputCaptureL)
   *
   * What it does:
   * Reads one control arg and removes it from the global input-capture stack.
   */
  int cfunc_RemoveInputCaptureL(LuaPlus::LuaState* state);

  [[nodiscard]] bool UI_InitKeyHandler();
  void UI_ClearInputCapture();
  void UI_ClearCurrentDragger();

  /**
   * One row of the UI-side factory build-queue mirror.
   *
   * Layout proven from the emitted element helpers for the 0x30-stride lane at
   * `0x010C1A10`:
   *   +0x00 `msvc8::string blueprintId` - `0x00835D75` writes `myRes=0x0F` at
   *         `+0x18` and `mySize=0` at `+0x14`, and `0x00836108` reads
   *         `cmp [item+0x18], 0x10` before choosing `[item+0x04]` (heap) or
   *         `item+0x04` (SSO buffer) as the `c_str()` lane.
   *   +0x1C `std::int32_t count`         - `0x00835D8E` stores the ctor's count
   *         argument, `0x00836128` reads it for the Lua `count` field, and
   *         `0x00835F85` accumulates into it (`[itemEnd-0x14]`).
   *   +0x20 `msvc8::vector<CmdId> commands` - `0x00835D95..0x00835D9B` zero
   *         `+0x24/+0x28/+0x2C` (the `_Myfirst/_Mylast/_Myend` triple behind the
   *         proxy slot at `+0x20`), and `0x00835F92` takes `itemEnd-0x10` as the
   *         push-back target for the owning command's id.
   * The 0x30 stride itself is the `imul 2AAAAAABh / sar 3` element-count idiom
   * used at every queue site (e.g. `0x008362FD`, `0x00836CA6`).
   */
  struct FactoryQueueDisplayItem
  {
    /**
     * Address: 0x00835D50 (FUN_00835D50, sub_835D50)
     *
     * IDA signature:
     * struct_BuildQueueItem *__usercall sub_835D50@<eax>(struct_BuildQueueItem *result,
     *                                                    std::string *str1, int count);
     *
     * What it does:
     * Assigns the blueprint id into the embedded legacy string, stores the
     * queued count and zeroes the command-id vector's data triple.
     */
    FactoryQueueDisplayItem(const msvc8::string& sourceBlueprintId, std::int32_t sourceCount);

    /**
     * Address: 0x00837670 (FUN_00837670, sub_837670)
     *
     * IDA signature:
     * struct_BuildQueueItem *__usercall sub_837670@<eax>(struct_BuildQueueItem *dest,
     *                                                    struct_BuildQueueItem *src@<edi>);
     *
     * What it does:
     * Copy-constructs one queue row: legacy-string assign of the blueprint id,
     * raw count copy, then legacy-vector copy of the command-id lane.
     */
    FactoryQueueDisplayItem(const FactoryQueueDisplayItem& other);

    /**
     * Address: 0x00836040 (FUN_00836040, sub_836040)
     * Address: 0x00837D20 (FUN_00837D20, sub_837D20)
     *
     * What it does:
     * Releases the command-id vector buffer, clears its triple, then releases
     * the blueprint-id string buffer and restores empty SSO state.
     */
    ~FactoryQueueDisplayItem() noexcept;

    FactoryQueueDisplayItem() noexcept;
    FactoryQueueDisplayItem& operator=(const FactoryQueueDisplayItem& other);

    msvc8::string blueprintId;      // +0x00
    std::int32_t count;             // +0x1C
    msvc8::vector<CmdId> commands;  // +0x20
  };
  static_assert(offsetof(FactoryQueueDisplayItem, count) == 0x1C, "FactoryQueueDisplayItem::count offset must be 0x1C");
  static_assert(
    offsetof(FactoryQueueDisplayItem, commands) == 0x20,
    "FactoryQueueDisplayItem::commands offset must be 0x20"
  );
  static_assert(sizeof(FactoryQueueDisplayItem) == 0x30, "FactoryQueueDisplayItem size must be 0x30");

  using FactoryQueueDisplaySnapshot = msvc8::vector<FactoryQueueDisplayItem>;

  /**
   * Data: 0x010C1A10 - the UI-owned factory build-queue mirror.
   *
   * The whole 0x10-byte legacy vector object lives here: the proxy slot the
   * self-assignment guard compares against (`cmp ebp, offset 0x010C1A10` at
   * `0x00836C86`, and the `this` value returned at `0x00836CD2`), then
   * `_Myfirst` at `0x010C1A14` (`0x008362EC`), `_Mylast` at `0x010C1A18`
   * (`0x008362F5`) and `_Myend` at `0x010C1A1C` (`0x00836DA2`). IDA labels the
   * proxy slot `sCurrentBuildFactory._M_end_of_storage`; that is a mislabel -
   * every reference to `0x010C1A10` in the binary takes its address as the
   * vector object, never reads it as a `_M_end_of_storage` pointer, and the
   * `_Myfirst/_Mylast` pair it would bound sits *above* it, not below.
   *
   * Defined in `UiRuntimeTypes.cpp`, which owns the queue lane; the
   * `SetCurrentFactoryForQueueDisplay` Lua worker in `UserUnit.cpp` reads and
   * rebuilds it exactly as `0x008363E0` does.
   */
  extern FactoryQueueDisplaySnapshot sCurrentBuildQueue;

  /**
   * Data: 0x010C1A08 - weak link to the factory whose queue is mirrored.
   *
   * `0x008361B6` loads `+0x00` (the owner-link slot) and derives the owning
   * `UserUnit` with `lea ecx, [eax-8]`; `0x008364BD` writes `+0x04` (the
   * next-in-owner-chain lane) back into the owner slot while unlinking. Both
   * offsets and the `-8` owner decode are exactly `moho::WeakPtr<UserUnit>`
   * (`WeakPtrOwnerLinkOffset<UserUnit>::value == 0x08`), and the decompiler's
   * `sCurrentBuildFactory._M_start == (int *)8` guard at `0x008361C8` is that
   * type's sentinel-slot test.
   */
  extern WeakPtr<UserUnit> sCurrentBuildFactory;

  /**
   * Address: 0x00837070 (FUN_00837070, sub_837070)
   *
   * IDA signature:
   * struct_BuildQueueItem **__stdcall sub_837070(struct_BuildQueueItem **a1,
   *                                              struct_BuildQueueItem *result,
   *                                              struct_BuildQueueItem *src);
   *
   * What it does:
   * Compacts the current build-queue window by moving the half-open tail
   * `[sourceBegin, sCurrentBuildQueue.end)` down onto `destinationBegin`,
   * destroying the vacated tail and republishing `_Mylast`. Callers pass
   * `(_Myfirst, _Mylast)` to erase the whole queue.
   */
  FactoryQueueDisplayItem** RebaseFactoryQueueRangeAndTrimTail(
    FactoryQueueDisplayItem** outBegin,
    FactoryQueueDisplayItem* destinationBegin,
    FactoryQueueDisplayItem* sourceBegin
  );

  /**
   * Address: 0x00835DF0 (FUN_00835DF0, sub_835DF0)
   *
   * Defined in `UserUnit.cpp`, which owns the user command-queue and
   * command-issue-helper layouts this walks. Declared here because the queue
   * vector it fills is the UI-owned lane above, and because the binary passes
   * that vector in as a parameter (`ebx`) rather than reading a global.
   */
  void RebuildFactoryQueueDisplaySnapshot(FactoryQueueDisplaySnapshot& queue, WeakPtr<UserUnit>& factoryLink);

  /**
   * Address: 0x00836080 (FUN_00836080, func_AddScriptUIBuildQueueItem)
   *
   * Defined in `UserUnit.cpp` beside the queue-rebuild worker above; the queue
   * vector arrives in `esi` at both binary call sites (`0x0083621B` with a
   * stack-local snapshot, `0x0083654A` with `sCurrentBuildQueue`).
   */
  void BuildFactoryQueueLuaTable(
    const FactoryQueueDisplaySnapshot& queue,
    LuaPlus::LuaState* state,
    LuaPlus::LuaObject* outQueueTable
  );

  /**
   * Address: 0x00836180 (FUN_00836180)
   * Mangled: ?UI_FactoryCommandQueueHandlerBeat@Moho@@YAXXZ
   *
   * IDA signature:
   * void __cdecl Moho::UI_FactoryCommandQueueHandlerBeat();
   *
   * What it does:
   * Per-beat refresh of the factory build-queue mirror: rebuilds a snapshot for
   * the currently displayed factory, and when it differs from the published
   * queue republishes it and calls `/lua/ui/game/gamemain.lua:OnQueueChanged`
   * with the new queue table (or `nil` once the factory is gone).
   */
  void UI_FactoryCommandQueueHandlerBeat();

  /**
   * Address: 0x0083DCC0 (FUN_0083DCC0, ?UI_LuaBeat@Moho@@YA_NXZ)
   *
   * What it does:
   * Invokes `/lua/ui/game/gamemain.lua:OnBeat()` and reports success/failure.
   */
  [[nodiscard]] bool UI_LuaBeat();

  /**
   * Address: 0x0083E9A0 (FUN_0083E9A0, sub_83E9A0)
   *
   * What it does:
   * When UI state is `UIS_game`, builds one modifiers table and invokes
   * `/lua/ui/game/chat.lua:ActivateChat(modifiers)`.
   */
  void UI_ActivateChat(bool shiftDown, bool ctrlDown, bool altDown);

  /**
   * Address: 0x0083EBC0 (FUN_0083EBC0, func_ReceiveChat)
   *
   * What it does:
   * Decodes one serialized Lua payload from network chat bytes and invokes
   * `/lua/ui/game/gamemain.lua:ReceiveChat(senderName, payloadObject)`.
   *
   * Signature correction: the manager RTTI installed by the ReceiveChat
   * `boost::bind` chain (0x0088FC70, `get_functor_type_tag`) publishes this
   * function's pointer type as `void (__cdecl *)(gpg::StrArg, gpg::MemBuffer
   * <char const> const &)` -- `void` return (the binary body at 0x0083EBC0
   * never writes `eax` on its fall-through path) and `data` taken by const
   * reference. The RTTI's `gpg::StrArg` is the *class*-typed original (see
   * `gpg/core/utils/Logging.h`'s `LogScopeEntry` note and
   * `CGpgNetInterface.cpp`'s `MakeConnectThreadLaunchCallback`): this SDK's
   * `gpg::StrArg` is currently the simplified `= const char*` alias with no
   * implicit conversion from `msvc8::string`, so this parameter is kept as
   * `const msvc8::string&` -- matching that same already-documented,
   * evidenced gap rather than reintroducing the class here.
   */
  void func_ReceiveChat(const msvc8::string& senderName, const gpg::MemBuffer<const char>& data);

  /**
   * Address: 0x0083EDF0 (FUN_0083EDF0, ?UI_StopCursorText@Moho@@YAXXZ)
   *
   * What it does:
   * Invokes `/lua/ui/uimain.lua:StopCursorText()` through the active UI Lua
   * state.
   */
  void UI_StopCursorText();

  /**
   * Address: 0x007FDAF0 (FUN_007FDAF0, cfunc_AddBlinkyBox)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_AddBlinkyBoxL`.
   */
  int cfunc_AddBlinkyBox(lua_State* luaContext);

  /**
   * Address: 0x007FDB10 (FUN_007FDB10, func_AddBlinkyBox_LuaFuncDef)
   *
   * What it does:
   * Publishes global `AddBlinkyBox(entityId, onTime, offTime, totalTime)` Lua
   * binder metadata.
   */
  CScrLuaInitForm* func_AddBlinkyBox_LuaFuncDef();

  /**
   * Address: 0x007FDB70 (FUN_007FDB70, cfunc_AddBlinkyBoxL)
   *
   * What it does:
   * Resolves one entity id and pushes one blinky-box runtime entry with the
   * supplied on/off/total timing lanes.
   */
  int cfunc_AddBlinkyBoxL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007FD9F0 (FUN_007FD9F0, func_PushBlinkyBox)
   *
   * What it does:
   * Allocates and links one blinky-box runtime node onto the global intrusive
   * blinky list.
   */
  void func_PushBlinkyBox(UserEntity* entity, float onTime, float offTime, float totalTime);

  /**
   * Address: 0x007FDA90 (FUN_007FDA90)
   *
   * What it does:
   * Adds one user-unit lane into the global selection-bracket weak-set.
   */
  std::int32_t func_AddSelectionBracketUserUnit(UserUnit* unit);

  /**
   * Address: 0x007FDAB0 (FUN_007FDAB0)
   *
   * What it does:
   * Clears the global selection-bracket weak-set subtree and restores empty
   * head links.
   */
  std::int32_t func_ClearSelectionBracketUserUnits();

  /**
   * Address: 0x00857B60 (FUN_00857B60, cfunc_AddCommandFeedbackBlip)
   *
   * What it does:
   * Lua callback target for `func_AddCommandFeedbackBlip_LuaFuncDef`.
   */
  int cfunc_AddCommandFeedbackBlip(lua_State* luaContext);

  /**
   * Address: 0x00857B80 (FUN_00857B80, func_AddCommandFeedbackBlip_LuaFuncDef)
   *
   * What it does:
   * Publishes global `AddCommandFeedbackBlip(meshInfoTable, duration)` Lua
   * binder metadata.
   */
  CScrLuaInitForm* func_AddCommandFeedbackBlip_LuaFuncDef();

  /**
   * Address: 0x008586C0 (FUN_008586C0, Moho::RemoveCommandFeedbackBlips)
   *
   * What it does:
   * Removes expired command-feedback blip nodes from the global blip list.
   *
   * Notes:
   * Binary callsites pass an unused `0` dword lane.
   */
  void RemoveCommandFeedbackBlips(std::int32_t unused);

  /**
   * Address: 0x00857B00 (FUN_00857B00, Moho::UpdateCommandFeedbackBlips)
   *
   * What it does:
   * Advances command-feedback blip timers, destroys expired blip meshes, then
   * compacts expired nodes from the global list.
   */
  void UI_UpdateCommandFeedbackBlips(float deltaSeconds);
  void UI_DumpCurrentInputCapture();

  /**
   * Address: 0x00795BD0 (FUN_00795BD0, func_CreateLuaEvent)
   *
   * What it does:
   * Constructs one Lua event table from one raw Maui event payload and emits
   * type/mouse/key/modifier/control lanes for script callbacks.
   */
  [[nodiscard]] LuaPlus::LuaObject* CreateLuaEventObject(
    SMauiEventData* eventData,
    LuaPlus::LuaObject* outEvent,
    LuaPlus::LuaState* state
  );

  [[nodiscard]] wxEvtHandlerRuntime* UI_CreateKeyHandler();
  void WX_PushEventHandler(wxWindowBase* window, wxEvtHandlerRuntime* handler);

  /**
   * Binds a frame's MAUI event mapper to the input window it will receive
   * events from. No-op for handlers that are not event mappers.
   */
  void SetMauiEventMapperWindow(wxEvtHandlerRuntime* handler, wxWindowBase* window);

  /**
   * True while a MAUI event is being dispatched on this thread.
   *
   * The dispatch walks raw control pointers - `CMauiControl::PostEvent` reads a
   * control's parent before handing the event to script, then dispatches to that
   * parent afterwards - so nothing reachable from a dispatch may be freed until
   * it unwinds. `CMauiFrame::PurgeDeleted` already defers control deletes on
   * this; frame owners must defer theirs the same way.
   */
  [[nodiscard]] bool MAUI_EventDispatchInProgress() noexcept;
  [[nodiscard]] wxEvtHandlerRuntime* WX_PopEventHandler(wxWindowBase* window, bool deleteHandler);
  void WX_GetClientSize(wxWindowBase* window, std::int32_t& outWidth, std::int32_t& outHeight);
  void WX_ScreenToClient(wxWindowBase* window, std::int32_t& inOutX, std::int32_t& inOutY);
  [[nodiscard]] bool WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY);

  [[nodiscard]] const VMatrix4& UI_IdentityMatrix();

  /**
   * Address: 0x00855040 (FUN_00855040, msvc8::vector<boost::shared_ptr<MeshInstance>>::push_back)
   *
   * What it does:
   * Per-T canonical-template-helper binding for the engine-instantiated
   * `vector<shared_ptr<MeshInstance>>::push_back(const&)` fast/slow-path
   * body (8-byte element stride: shared_ptr `(px, pi)` pair). Used by
   * `CUIWorldViewBuildDragRuntimeView::AppendBuildPreviewMesh` to preserve
   * the MSVC8 per-T template emission symbol shape.
   */
  void PushBackMeshInstanceSharedPtrVector(
    msvc8::vector<boost::shared_ptr<MeshInstance>>& destination,
    const boost::shared_ptr<MeshInstance>& value);
} // namespace moho

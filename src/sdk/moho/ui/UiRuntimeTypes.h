#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "lua/LuaObject.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/d3d/CD3DDevice.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CUIManager;
  class RD3DTextureResource;
  class CMauiCursor;
  class CMauiControl;
  class CMauiBorder;
  class CMauiFrame;
  class CScriptObject;
  class CD3DPrimBatcher;
  class CD3DBatchTexture;

  enum EUIState : std::int32_t
  {
    UIS_none = 0,
    UIS_splash = 1,
    UIS_frontend = 2,
    UIS_lobby = 4,
  };
  static_assert(sizeof(EUIState) == 0x4, "moho::EUIState size must be 0x4");

  extern EUIState sUIState;

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
  static_assert(sizeof(EMauiEventType) == 0x4, "moho::EMauiEventType size must be 0x4");

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
  static_assert(sizeof(EMauiEventModifier) == 0x4, "moho::EMauiEventModifier size must be 0x4");

  struct SMauiMousePos
  {
    float x = 0.0f;
    float y = 0.0f;
  };
  static_assert(sizeof(SMauiMousePos) == 0x8, "moho::SMauiMousePos size must be 0x8");

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
  static_assert(offsetof(SMauiEventData, mEventType) == 0x0, "SMauiEventData::mEventType offset must be 0x0");
  static_assert(offsetof(SMauiEventData, mMousePos) == 0x4, "SMauiEventData::mMousePos offset must be 0x4");
  static_assert(offsetof(SMauiEventData, mWheelRotation) == 0xC, "SMauiEventData::mWheelRotation offset must be 0xC");
  static_assert(offsetof(SMauiEventData, mWheelData) == 0x10, "SMauiEventData::mWheelData offset must be 0x10");
  static_assert(offsetof(SMauiEventData, mKeyCode) == 0x14, "SMauiEventData::mKeyCode offset must be 0x14");
  static_assert(offsetof(SMauiEventData, mRawKeyCode) == 0x18, "SMauiEventData::mRawKeyCode offset must be 0x18");
  static_assert(offsetof(SMauiEventData, mModifiers) == 0x1C, "SMauiEventData::mModifiers offset must be 0x1C");
  static_assert(offsetof(SMauiEventData, mSource) == 0x20, "SMauiEventData::mSource offset must be 0x20");

  struct wxEvtHandlerRuntime
  {
    virtual ~wxEvtHandlerRuntime() = default;
  };

  /**
   * Address context: `FUN_0084CB70` (`CUIManager::AddFrame`) allocates one
   * `CUIKeyHandler` object with `operator new(0x28)` and then pushes it onto
   * the input-window event-handler chain.
   */
  class CUIKeyHandlerRuntime final : public wxEvtHandlerRuntime
  {
  public:
    std::uint8_t mUnknown04To27[0x24]{};
  };

  static_assert(sizeof(CUIKeyHandlerRuntime) == 0x28, "moho::CUIKeyHandlerRuntime size must be 0x28");

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

  static_assert(
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

  static_assert(sizeof(CMauiCursorLink) == 0x8, "moho::CMauiCursorLink size must be 0x8");
  static_assert(offsetof(CMauiCursorLink, ownerHeadLink) == 0x0, "moho::CMauiCursorLink::ownerHeadLink offset must be 0x0");
  static_assert(
    offsetof(CMauiCursorLink, nextInOwnerChain) == 0x4,
    "moho::CMauiCursorLink::nextInOwnerChain offset must be 0x4"
  );

  class CMauiCursor
  {
  public:
    virtual ~CMauiCursor() = default;
  };

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

  static_assert(
    offsetof(CMauiCursorRuntimeView, ownerChainHead) == 0x4,
    "moho::CMauiCursorRuntimeView::ownerChainHead offset must be 0x4"
  );
  static_assert(sizeof(CMauiCursorRuntimeView) == 0x8, "moho::CMauiCursorRuntimeView size must be 0x8");

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

  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mTexture) == 0x34,
    "CMauiCursorTextureRuntimeView::mTexture offset must be 0x34"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultTexture) == 0x3C,
    "CMauiCursorTextureRuntimeView::mDefaultTexture offset must be 0x3C"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mIsDefaultTexture) == 0x44,
    "CMauiCursorTextureRuntimeView::mIsDefaultTexture offset must be 0x44"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mIsShowing) == 0x45,
    "CMauiCursorTextureRuntimeView::mIsShowing offset must be 0x45"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mHotspotX) == 0x48,
    "CMauiCursorTextureRuntimeView::mHotspotX offset must be 0x48"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mHotspotY) == 0x4C,
    "CMauiCursorTextureRuntimeView::mHotspotY offset must be 0x4C"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultHotspotX) == 0x50,
    "CMauiCursorTextureRuntimeView::mDefaultHotspotX offset must be 0x50"
  );
  static_assert(
    offsetof(CMauiCursorTextureRuntimeView, mDefaultHotspotY) == 0x54,
    "CMauiCursorTextureRuntimeView::mDefaultHotspotY offset must be 0x54"
  );
  static_assert(
    sizeof(CMauiCursorTextureRuntimeView) == 0x58,
    "CMauiCursorTextureRuntimeView size must be 0x58"
  );

  class CMauiControl
  {
  public:
    virtual ~CMauiControl() = default;

    virtual void Destroy() = 0;
    virtual void Frame(float deltaSeconds) = 0;
    virtual void OnMinimized(bool minimized) = 0;
    virtual void ClearChildren() = 0;
    virtual void Render() = 0;
    virtual void DoRender(CD3DPrimBatcher* primBatcher, std::int32_t drawMask) = 0;

    [[nodiscard]] static CMauiControl* GetTopmostControl(CMauiControl* root, float x, float y);
  };

  class CMauiFrame : public CMauiControl
  {
  public:
    /**
     * Address: 0x007961B0 (FUN_007961B0, Moho::CMauiFrame::Create)
     *
     * What it does:
     * Imports `/lua/maui/frame.lua`, calls `Frame()`, converts the Lua return
     * payload to a `CMauiFrame*`, and returns it as shared ownership.
     */
    [[nodiscard]] static boost::shared_ptr<CMauiFrame> Create(LuaPlus::LuaState* state);
    static void DumpControlsUnder(CMauiFrame* frame, float x, float y);
  };

  class CMauiBorder : public CMauiControl
  {
  public:
    /**
     * Address: 0x00784F50 (FUN_00784F50, Moho::CMauiBorder::Draw)
     *
     * What it does:
     * Draws textured border corners plus optional horizontal/vertical body strips
     * from lazy-var geometry lanes.
     */
    void Draw(CD3DPrimBatcher* primBatcher, std::int32_t drawMask);
  };

  struct CMauiControlRuntimeView
  {
    std::uint8_t mUnknown00To47[0x48]{};
    CScriptLazyVar_float mLeftLV;   // +0x48
    CScriptLazyVar_float mRightLV;  // +0x5C
    CScriptLazyVar_float mTopLV;    // +0x70
    CScriptLazyVar_float mBottomLV; // +0x84
    CScriptLazyVar_float mWidthLV;  // +0x98
    CScriptLazyVar_float mHeightLV; // +0xAC

    [[nodiscard]] static CMauiControlRuntimeView* FromControl(CMauiControl* control) noexcept
    {
      return reinterpret_cast<CMauiControlRuntimeView*>(control);
    }

    [[nodiscard]] static const CMauiControlRuntimeView* FromControl(const CMauiControl* control) noexcept
    {
      return reinterpret_cast<const CMauiControlRuntimeView*>(control);
    }
  };

  static_assert(offsetof(CMauiControlRuntimeView, mLeftLV) == 0x48, "CMauiControlRuntimeView::mLeftLV offset must be 0x48");
  static_assert(offsetof(CMauiControlRuntimeView, mRightLV) > offsetof(CMauiControlRuntimeView, mLeftLV));
  static_assert(offsetof(CMauiControlRuntimeView, mTopLV) > offsetof(CMauiControlRuntimeView, mRightLV));
  static_assert(offsetof(CMauiControlRuntimeView, mBottomLV) > offsetof(CMauiControlRuntimeView, mTopLV));
  static_assert(offsetof(CMauiControlRuntimeView, mWidthLV) > offsetof(CMauiControlRuntimeView, mBottomLV));
  static_assert(offsetof(CMauiControlRuntimeView, mHeightLV) > offsetof(CMauiControlRuntimeView, mWidthLV));

  struct CMauiFrameRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0C0To0F7[0x38]{};
    std::int32_t mRenderPass = 0;
    std::uint8_t mUnknown0FCTo11B[0x20]{};
    boost::weak_ptr<CMauiFrame> mSelfWeak; // +0x11C
    std::uint8_t mUnknown124To12B[0x8]{};
    wxEvtHandlerRuntime* mEventHandler = nullptr;
    std::int32_t mEventMapper = -1;

    [[nodiscard]] static CMauiFrameRuntimeView* FromFrame(CMauiFrame* frame) noexcept
    {
      return reinterpret_cast<CMauiFrameRuntimeView*>(frame);
    }

    [[nodiscard]] static const CMauiFrameRuntimeView* FromFrame(const CMauiFrame* frame) noexcept
    {
      return reinterpret_cast<const CMauiFrameRuntimeView*>(frame);
    }
  };

  static_assert(offsetof(CMauiFrameRuntimeView, mRenderPass) > offsetof(CMauiControlRuntimeView, mHeightLV));
  static_assert(sizeof(boost::weak_ptr<CMauiFrame>) == 0x8, "boost::weak_ptr<CMauiFrame> size must be 0x8");
  static_assert(offsetof(CMauiFrameRuntimeView, mSelfWeak) > offsetof(CMauiFrameRuntimeView, mRenderPass));
  static_assert(offsetof(CMauiFrameRuntimeView, mEventHandler) > offsetof(CMauiFrameRuntimeView, mSelfWeak));
  static_assert(offsetof(CMauiFrameRuntimeView, mEventMapper) > offsetof(CMauiFrameRuntimeView, mEventHandler));

  struct CMauiBorderRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0C0To0F3[0x34]{};
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

  static_assert(offsetof(CMauiBorderRuntimeView, mVertexAlpha) > offsetof(CMauiControlRuntimeView, mHeightLV));
  static_assert(offsetof(CMauiBorderRuntimeView, mTex1) > offsetof(CMauiBorderRuntimeView, mVertexAlpha));
  static_assert(offsetof(CMauiBorderRuntimeView, mTexHorz) > offsetof(CMauiBorderRuntimeView, mTex1));
  static_assert(offsetof(CMauiBorderRuntimeView, mTexUL) > offsetof(CMauiBorderRuntimeView, mTexHorz));
  static_assert(offsetof(CMauiBorderRuntimeView, mTexUR) > offsetof(CMauiBorderRuntimeView, mTexUL));
  static_assert(offsetof(CMauiBorderRuntimeView, mTexLL) > offsetof(CMauiBorderRuntimeView, mTexUR));
  static_assert(offsetof(CMauiBorderRuntimeView, mTexLR) > offsetof(CMauiBorderRuntimeView, mTexLL));
  static_assert(offsetof(CMauiBorderRuntimeView, mBorderWidthLV) > offsetof(CMauiBorderRuntimeView, mTexLR));
  static_assert(offsetof(CMauiBorderRuntimeView, mBorderHeightLV) > offsetof(CMauiBorderRuntimeView, mBorderWidthLV));

  [[nodiscard]] LuaPlus::LuaState* USER_GetLuaState();
  [[nodiscard]] bool MAUI_StartMainScript();
  void MAUI_UpdateCursor(CMauiCursor* cursor);
  void MAUI_ReleaseCursor(CMauiCursor* cursor);

  /**
   * Address: 0x0078D410 (FUN_0078D410, cfunc_CMauiCursorSetDefaultTextureL)
   *
   * What it does:
   * Reads one cursor object plus texture/hotspot Lua args and updates cursor
   * default texture/hotspot lanes.
   */
  int cfunc_CMauiCursorSetDefaultTextureL(LuaPlus::LuaState* state);

  /**
   * Address: 0x008725B0 (FUN_008725B0, cfunc_CUIWorldViewZoomScale)
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to
   * `cfunc_CUIWorldViewZoomScaleL`.
   */
  int cfunc_CUIWorldViewZoomScale(lua_State* luaContext);

  /**
   * Address: 0x00872630 (FUN_00872630, cfunc_CUIWorldViewZoomScaleL)
   *
   * What it does:
   * Reads `CUIWorldView:ZoomScale` Lua args and forwards anchor and wheel
   * zoom lanes into the active world-view camera.
   */
  int cfunc_CUIWorldViewZoomScaleL(LuaPlus::LuaState* state);

  void MAUI_OnApplicationResize(std::int32_t frameIdx, std::int32_t width, std::int32_t height);

  [[nodiscard]] bool UI_InitKeyHandler();
  void UI_ClearInputCapture();
  void UI_ClearCurrentDragger();
  void UI_FactoryCommandQueueHandlerBeat();
  [[nodiscard]] bool UI_LuaBeat();
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
  [[nodiscard]] wxEvtHandlerRuntime* WX_PopEventHandler(wxWindowBase* window, bool deleteHandler);
  void WX_GetClientSize(wxWindowBase* window, std::int32_t& outWidth, std::int32_t& outHeight);
  void WX_ScreenToClient(wxWindowBase* window, std::int32_t& inOutX, std::int32_t& inOutY);
  [[nodiscard]] bool WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY);

  [[nodiscard]] const VMatrix4& UI_IdentityMatrix();
} // namespace moho

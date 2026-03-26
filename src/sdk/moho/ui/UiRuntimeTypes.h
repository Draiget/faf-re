#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
} // namespace LuaPlus

namespace moho
{
  class CUIManager;
  class CMauiCursor;
  class CMauiControl;
  class CMauiFrame;
  class CD3DPrimBatcher;

  enum EUIState : std::int32_t
  {
    UIS_none = 0,
    UIS_splash = 1,
    UIS_frontend = 2,
    UIS_lobby = 4,
  };
  static_assert(sizeof(EUIState) == 0x4, "moho::EUIState size must be 0x4");

  extern EUIState sUIState;

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
   * Address family:
   * - 0x00783840 (Moho::CScriptLazyVar_float::GetValue)
   * - 0x007839E0 (Moho::CScriptLazyVar_float::SetValue)
   */
  struct CScriptLazyVar_float
  {
    std::uint8_t mUnknown00To0F[0x10]{};
    float mCachedValue = 0.0f;

    [[nodiscard]] static float GetValue(const CScriptLazyVar_float* value) noexcept;
    static void SetValue(CScriptLazyVar_float* value, float next) noexcept;
  };

  static_assert(sizeof(CScriptLazyVar_float) == 0x14, "moho::CScriptLazyVar_float size must be 0x14");

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
    [[nodiscard]] static boost::shared_ptr<CMauiFrame> Create(LuaPlus::LuaState* state);
    static void DumpControlsUnder(CMauiFrame* frame, float x, float y);
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
  static_assert(offsetof(CMauiControlRuntimeView, mRightLV) == 0x5C, "CMauiControlRuntimeView::mRightLV offset must be 0x5C");
  static_assert(offsetof(CMauiControlRuntimeView, mTopLV) == 0x70, "CMauiControlRuntimeView::mTopLV offset must be 0x70");
  static_assert(
    offsetof(CMauiControlRuntimeView, mBottomLV) == 0x84,
    "CMauiControlRuntimeView::mBottomLV offset must be 0x84"
  );
  static_assert(offsetof(CMauiControlRuntimeView, mWidthLV) == 0x98, "CMauiControlRuntimeView::mWidthLV offset must be 0x98");
  static_assert(
    offsetof(CMauiControlRuntimeView, mHeightLV) == 0xAC,
    "CMauiControlRuntimeView::mHeightLV offset must be 0xAC"
  );

  struct CMauiFrameRuntimeView : CMauiControlRuntimeView
  {
    std::uint8_t mUnknown0C0To0F7[0x38]{};
    std::int32_t mRenderPass = 0;
    std::uint8_t mUnknown0FCTo12B[0x30]{};
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

  static_assert(offsetof(CMauiFrameRuntimeView, mRenderPass) == 0xF8, "CMauiFrameRuntimeView::mRenderPass offset must be 0xF8");
  static_assert(
    offsetof(CMauiFrameRuntimeView, mEventHandler) == 0x12C,
    "CMauiFrameRuntimeView::mEventHandler offset must be 0x12C"
  );
  static_assert(
    offsetof(CMauiFrameRuntimeView, mEventMapper) == 0x130,
    "CMauiFrameRuntimeView::mEventMapper offset must be 0x130"
  );

  [[nodiscard]] LuaPlus::LuaState* USER_GetLuaState();
  [[nodiscard]] bool MAUI_StartMainScript();
  void MAUI_UpdateCursor(CMauiCursor* cursor);
  void MAUI_ReleaseCursor(CMauiCursor* cursor);
  void MAUI_OnApplicationResize(std::int32_t frameIdx, std::int32_t width, std::int32_t height);

  [[nodiscard]] bool UI_InitKeyHandler();
  void UI_ClearInputCapture();
  void UI_ClearCurrentDragger();
  void UI_FactoryCommandQueueHandlerBeat();
  [[nodiscard]] bool UI_LuaBeat();
  void UI_UpdateCommandFeedbackBlips(float deltaSeconds);
  void UI_DumpCurrentInputCapture();

  [[nodiscard]] wxEvtHandlerRuntime* UI_CreateKeyHandler();
  void WX_PushEventHandler(wxWindowBase* window, wxEvtHandlerRuntime* handler);
  [[nodiscard]] wxEvtHandlerRuntime* WX_PopEventHandler(wxWindowBase* window, bool deleteHandler);
  void WX_GetClientSize(wxWindowBase* window, std::int32_t& outWidth, std::int32_t& outHeight);
  void WX_ScreenToClient(wxWindowBase* window, std::int32_t& inOutX, std::int32_t& inOutY);
  [[nodiscard]] bool WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY);

  [[nodiscard]] const VMatrix4& UI_IdentityMatrix();
} // namespace moho

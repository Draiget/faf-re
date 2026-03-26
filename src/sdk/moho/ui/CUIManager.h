#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/ui/IUIManager.h"

namespace moho
{
  class CUIManager final : public IUIManager
  {
  public:
    using FrameVector = gpg::fastvector_n<boost::shared_ptr<CMauiFrame>, 2>;
    using InputWindowVector = gpg::fastvector_n<wxWindowBase*, 2>;
    using HostWindowVector = gpg::fastvector_n<wxWindowBase*, 2>;

    /**
     * Address: 0x0084C9C0 (FUN_0084C9C0)
     *
     * What it does:
     * Initializes inline-storage vectors, cursor-link state, and defaults.
     */
    CUIManager();

    ~CUIManager() = default;

    /**
     * Address: 0x0084CA30 (FUN_0084CA30)
     *
     * What it does:
     * Core UI-manager teardown for cursor-link and frame shared-ownership lanes.
     */
    void DestroyCore();

    /**
     * Address: 0x0084CA90 (FUN_0084CA90)
     *
     * What it does:
     * Full deleting-destructor behavior before object deallocation.
     */
    void DeleteDtor();

    /**
     * Address: 0x0084CB30 (FUN_0084CB30)
     */
    bool Init() override;

    /**
     * Address: 0x0084CB70 (FUN_0084CB70)
     *
     * What it does:
     * Registers one input window for wx event-handler routing plus one host
     * window used for client-size driven UI frame initialization.
     */
    int AddFrame(wxWindowBase* inputWindow, wxWindowBase* eventHostWindow) override;

    /**
     * Address: 0x0084CC50 (FUN_0084CC50)
     */
    bool SetNewLuaState(LuaPlus::LuaState* state) override;

    /**
     * Address: 0x0084D150 (FUN_0084D150)
     */
    [[nodiscard]] bool HasFrames() const override;

    /**
     * Address: 0x0084D010 (FUN_0084D010)
     */
    void ClearFrames() override;

    /**
     * Address: 0x0084D160 (FUN_0084D160)
     */
    void UpdateFrameRate(float deltaSeconds) override;

    /**
     * Address: 0x0084D310 (FUN_0084D310)
     */
    [[nodiscard]] bool DoBeat() override;

    /**
     * Address: 0x0084D320 (FUN_0084D320)
     */
    void SetMinimized(bool minimized) override;

    /**
     * Address: 0x0084D360 (FUN_0084D360)
     */
    void ClearChildren(int frameIdx) override;

    /**
     * Address: 0x0084CFC0 (FUN_0084CFC0)
     */
    void OnResize(int frameIdx, int width, int height) override;

    /**
     * Address: 0x0084D3C0 (FUN_0084D3C0)
     */
    void SetUIControlsAlpha(float alpha) override;

    /**
     * Address: 0x0084D3D0 (FUN_0084D3D0)
     */
    [[nodiscard]] float GetUIControlsAlpha() const override;

    /**
     * Address: 0x0084D000 (FUN_0084D000)
     */
    void SetCursor(CMauiCursor* cursor) override;

    /**
     * Address: 0x0084C920 (FUN_0084C920)
     */
    [[nodiscard]] CMauiCursor* GetCursor() const override;

    /**
     * Address: 0x0084D520 (FUN_0084D520)
     */
    void ValidateFrame(int frameIdx) override;

    /**
     * Address: 0x0084D550 (FUN_0084D550)
     */
    void RenderFrames(int head, CD3DPrimBatcher* primBatcher) override;

    /**
     * Address: 0x0084D5D0 (FUN_0084D5D0)
     */
    void DrawUI(int head, CD3DPrimBatcher* primBatcher) override;

    /**
     * Address: 0x0084D650 (FUN_0084D650)
     */
    void DrawHead(int head, CD3DPrimBatcher* primBatcher) override;

    /**
     * Address: 0x0084D6D0 (FUN_0084D6D0)
     */
    void GetControlAtCursor(int* outViewport, float* outX, float* outY, CMauiControl** outControl) override;

    /**
     * Address: 0x0084D810 (FUN_0084D810)
     */
    void DumpControlsUnderMouse() override;

    /**
     * Address: 0x0084D8E0 (FUN_0084D8E0)
     */
    void DebugMouseOverControl(CD3DPrimBatcher* primBatcher) override;

  public:
    std::uint32_t mUnknown04 = 0;           // +0x04
    FrameVector mFrames;                    // +0x08
    CMauiCursorLink mCursorLink;            // +0x28
    LuaPlus::LuaState* mLuaState = nullptr; // +0x30
    std::uint32_t mUnknown34 = 0;           // +0x34
    InputWindowVector mInputWindows;        // +0x38
    HostWindowVector mHostWindows;          // +0x50
    float mUIControlsAlpha = 1.0f;          // +0x68
    float mUnknown6C = 0.0f;                // +0x6C
    float mGCTime = 0.0f;                   // +0x70
    std::uint32_t mUnknown74 = 0;           // +0x74
  };

  static_assert(sizeof(CUIManager::FrameVector) == 0x20, "moho::CUIManager::FrameVector size must be 0x20");
  static_assert(sizeof(CUIManager::InputWindowVector) == 0x18, "moho::CUIManager::InputWindowVector size must be 0x18");
  static_assert(sizeof(CUIManager::HostWindowVector) == 0x18, "moho::CUIManager::HostWindowVector size must be 0x18");

  static_assert(sizeof(CUIManager) == 0x78, "moho::CUIManager size must be 0x78");
} // namespace moho

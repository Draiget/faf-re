#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Entity;
  class IEffect;
  class Sim;
  class Unit;

  struct WEmitterTextControlVTable;
  struct WEmitterPreviewPanelVTable;
  struct WEmitterChoiceSelectionVTable;
  struct WEmitterMenuItem;
  struct WEmitterMenuItemNode;

  struct WEmitterTextControl
  {
    WEmitterTextControlVTable* mVTable = nullptr;

    [[nodiscard]] double ReadDouble() const noexcept;
  };
  static_assert(sizeof(WEmitterTextControl) == 0x04, "WEmitterTextControl size must be 0x04");

  struct WEmitterPreviewPanel
  {
    WEmitterPreviewPanelVTable* mVTable = nullptr;

    void SetRepeatTimeFrame(std::int32_t selector, std::int32_t frame) noexcept;
    void SetLifetimeFrame(std::int32_t frame) noexcept;
  };
  static_assert(sizeof(WEmitterPreviewPanel) == 0x04, "WEmitterPreviewPanel size must be 0x04");

  struct WEmitterChoiceSelectionSubobject
  {
    WEmitterChoiceSelectionVTable* mVTable = nullptr;
  };
  static_assert(sizeof(WEmitterChoiceSelectionSubobject) == 0x04, "WEmitterChoiceSelectionSubobject size must be 0x04");

  struct WEmitterChoiceControl
  {
    std::uint8_t mReserved000To12F[0x130]{};
    WEmitterChoiceSelectionSubobject mSelection;

    [[nodiscard]] std::int32_t GetSelection() const noexcept;
  };
  static_assert(
    offsetof(WEmitterChoiceControl, mSelection) == 0x130,
    "WEmitterChoiceControl::mSelection offset must be 0x130"
  );

  struct WEmitterCommandCheckSource
  {
    std::uint8_t mReserved00To43[0x44]{};
    WEmitterMenuItemNode* mFirstMenuItemNode = nullptr;

    [[nodiscard]] bool IsCommandChecked(std::int32_t commandId) const noexcept;
  };
  static_assert(
    offsetof(WEmitterCommandCheckSource, mFirstMenuItemNode) == 0x44,
    "WEmitterCommandCheckSource::mFirstMenuItemNode offset must be 0x44"
  );

  struct WEmitterCurveEditorVTable;

  struct WEmitterCurveEditor
  {
    WEmitterCurveEditorVTable* mVTable = nullptr;
    std::uint8_t mReserved004To137[0x134]{};
    SEfxCurve mCurve;
    std::uint8_t mReserved170To17F[0x10]{};
    float mCurveRangeMin = 0.0f;
    float mCurveRangeMid = 0.0f;
    float mCurveRangeMax = 0.0f;
    std::uint8_t mReserved18CTo190[0x5]{};
    std::uint8_t mCurveDirty = 0;

    void ResetCurveXRange(float rangeMax) noexcept;
    void MarkCurveClean() noexcept;
    [[nodiscard]] const SEfxCurve& Curve() const noexcept;
  };
  static_assert(offsetof(WEmitterCurveEditor, mCurve) == 0x138, "WEmitterCurveEditor::mCurve offset must be 0x138");
  static_assert(
    offsetof(WEmitterCurveEditor, mCurveRangeMin) == 0x180,
    "WEmitterCurveEditor::mCurveRangeMin offset must be 0x180"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mCurveRangeMax) == 0x188,
    "WEmitterCurveEditor::mCurveRangeMax offset must be 0x188"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mCurveDirty) == 0x191,
    "WEmitterCurveEditor::mCurveDirty offset must be 0x191"
  );

  struct WEmitterCurvePanel : WCurveEditorPanel
  {
    std::uint8_t mReserved004To133[0x130]{};
    WEmitterCurveEditor* mCurveEditor = nullptr;
  };
  static_assert(
    offsetof(WEmitterCurvePanel, mCurveEditor) == 0x134,
    "WEmitterCurvePanel::mCurveEditor offset must be 0x134"
  );

  struct WEmitterWx : WWinManagedFrame
  {
    /**
     * Address: 0x006672F0 (FUN_006672F0)
     *
     * What it does:
     * Recreates the preview emitter when needed, then pushes the current editor
     * scalar, flag, curve, texture, and ramp controls into the live effect.
     */
    void RefreshPreviewEmitter();

    Sim* mSim = nullptr;                                      // +0x17C
    Wm3::Vector3f mSpawnPosition{};                           // +0x180
    WEmitterTextControl* mLifetimeControl = nullptr;           // +0x18C
    WEmitterTextControl* mRepeatTimeControl = nullptr;         // +0x190
    std::uint32_t mReserved194 = 0;                            // +0x194
    std::uint32_t mReserved198 = 0;                            // +0x198
    std::uint32_t mReserved19C = 0;                            // +0x19C
    WEmitterTextControl* mTextureFrameCountControl = nullptr;  // +0x1A0
    WEmitterTextControl* mTextureStripCountControl = nullptr;  // +0x1A4
    WEmitterTextControl* mSortOrderControl = nullptr;          // +0x1A8
    WEmitterTextControl* mLodCutoffControl = nullptr;          // +0x1AC
    WEmitterTextControl* mToggleControl = nullptr;             // +0x1B0
    WEmitterPreviewPanel* mPreviewPanel = nullptr;             // +0x1B4
    WEmitterChoiceControl* mBlendModeChoice = nullptr;         // +0x1B8
    WEmitterChoiceControl* mFidelityChoice = nullptr;          // +0x1BC
    WEmitterTextControl* mTextureNameControl = nullptr;        // +0x1C0
    WEmitterTextControl* mRampNameControl = nullptr;           // +0x1C4
    wxStringRuntime mTexturePath{};                            // +0x1C8
    wxStringRuntime mRampTexturePath{};                        // +0x1CC
    wxStringRuntime mBlueprintFilePath{};                      // +0x1D0
    wxStringRuntime mBlueprintIdPath{};                        // +0x1D4
    double mCachedRepeatTime = 0.0;                            // +0x1D8
    std::uint8_t mRefreshGuard = 0;                            // +0x1E0
    std::uint8_t mReserved1E1To1E3[0x3]{};
    msvc8::vector<WEmitterCurvePanel*> mCurvePanels;           // +0x1E4
    WeakPtr<IEffect> mPreviewEffect;                           // +0x1F4
    WeakPtr<Unit> mAttachedUnit;                               // +0x1FC
    msvc8::string mBoneName;                                   // +0x204
    msvc8::string mBlueprintName;                              // +0x220
    void* mMenuBar = nullptr;                                  // +0x23C
    std::uint32_t mReserved240 = 0;                            // +0x240
    WEmitterCommandCheckSource* mEmitterFlagChecks = nullptr;  // +0x244
    WEmitterCommandCheckSource* mVisibilityFlagChecks = nullptr; // +0x248
    wxStringRuntime mTextureNameText{};                        // +0x24C
    wxStringRuntime mRampNameText{};                           // +0x250
    std::uint32_t mReserved254 = 0;                            // +0x254
  };

  static_assert(offsetof(WEmitterWx, mSim) == 0x17C, "WEmitterWx::mSim offset must be 0x17C");
  static_assert(
    offsetof(WEmitterWx, mSpawnPosition) == 0x180,
    "WEmitterWx::mSpawnPosition offset must be 0x180"
  );
  static_assert(
    offsetof(WEmitterWx, mLifetimeControl) == 0x18C,
    "WEmitterWx::mLifetimeControl offset must be 0x18C"
  );
  static_assert(
    offsetof(WEmitterWx, mRepeatTimeControl) == 0x190,
    "WEmitterWx::mRepeatTimeControl offset must be 0x190"
  );
  static_assert(
    offsetof(WEmitterWx, mPreviewPanel) == 0x1B4,
    "WEmitterWx::mPreviewPanel offset must be 0x1B4"
  );
  static_assert(
    offsetof(WEmitterWx, mTexturePath) == 0x1C8,
    "WEmitterWx::mTexturePath offset must be 0x1C8"
  );
  static_assert(
    offsetof(WEmitterWx, mCachedRepeatTime) == 0x1D8,
    "WEmitterWx::mCachedRepeatTime offset must be 0x1D8"
  );
  static_assert(
    offsetof(WEmitterWx, mRefreshGuard) == 0x1E0,
    "WEmitterWx::mRefreshGuard offset must be 0x1E0"
  );
  static_assert(
    offsetof(WEmitterWx, mCurvePanels) == 0x1E4,
    "WEmitterWx::mCurvePanels offset must be 0x1E4"
  );
  static_assert(
    offsetof(WEmitterWx, mPreviewEffect) == 0x1F4,
    "WEmitterWx::mPreviewEffect offset must be 0x1F4"
  );
  static_assert(
    offsetof(WEmitterWx, mAttachedUnit) == 0x1FC,
    "WEmitterWx::mAttachedUnit offset must be 0x1FC"
  );
  static_assert(offsetof(WEmitterWx, mBoneName) == 0x204, "WEmitterWx::mBoneName offset must be 0x204");
  static_assert(
    offsetof(WEmitterWx, mBlueprintName) == 0x220,
    "WEmitterWx::mBlueprintName offset must be 0x220"
  );
  static_assert(
    offsetof(WEmitterWx, mEmitterFlagChecks) == 0x244,
    "WEmitterWx::mEmitterFlagChecks offset must be 0x244"
  );
  static_assert(
    offsetof(WEmitterWx, mVisibilityFlagChecks) == 0x248,
    "WEmitterWx::mVisibilityFlagChecks offset must be 0x248"
  );
  static_assert(sizeof(WEmitterWx) == 0x258, "WEmitterWx size must be 0x258");
} // namespace moho

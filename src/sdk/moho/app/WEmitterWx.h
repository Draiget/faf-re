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

  /**
   * One vertical column of the curve envelope: a time on the horizontal axis
   * plus the value/tangent pair that gives the band its height there.
   */
  struct CurveEnvelopeColumn
  {
    float mTime = 0.0f;
    float mValue = 0.0f;
    float mTangent = 0.0f;
  };

  /** Envelope edge selectors taken by `ProjectCurvePointToScreen`. */
  inline constexpr std::int32_t kCurveEnvelopeUpperEdge = 0;
  inline constexpr std::int32_t kCurveEnvelopeCurveValue = 1;
  inline constexpr std::int32_t kCurveEnvelopeLowerEdge = 2;

  struct WEmitterCurveEditor
  {
    WEmitterCurveEditorVTable* mVTable = nullptr;
    std::uint8_t mReserved004To027[0x24]{};

    /** wx window id, used as the command id of the curve-changed event. */
    std::int32_t mWindowId = 0;
    std::uint8_t mReserved02CTo12F[0x104]{};

    /**
     * Cursor into `mCurve.mKeys` naming the key the user currently has
     * selected. Seeded to `mCurve.mKeys.begin()` by the constructor
     * (0x00661470) and by FUN_00661A90 (0x00661B37); "no selection" is
     * expressed as `mSelectedKey == mCurve.mKeys.end()`.
     */
    Wm3::Vector3f* mSelectedKey = nullptr;
    std::uint8_t mReserved134To137[0x4]{};
    SEfxCurve mCurve;

    /**
     * Time-axis pixels-per-unit, recomputed by the paint handler
     * (FUN_006621F0) as `clientWidth / (mViewTimeMax - mViewTimeMin)`.
     */
    float mViewTimeScale = 0.0f;

    /**
     * Value-axis units-per-pixel scale. Recomputed by the resize handler
     * (FUN_006621F0 stores the value span here, then divides the time span by
     * it) and used as the divisor that converts pixel / wheel deltas into
     * curve-value deltas (FUN_006617A0, FUN_00661820, FUN_00661900,
     * FUN_00661A90 all divide by `[this+0x174]`).
     */
    float mViewValueScale = 0.0f;

    /** Client size cached by the paint handler (FUN_006621F0). */
    std::int32_t mClientWidth = 0;
    std::int32_t mClientHeight = 0;

    /**
     * Visible view rectangle over the curve, stored interleaved as
     * (timeMin, valueMin, timeMax, valueMax). Proven by the `WCurveEditor`
     * constructor at 0x006613FA-0x0066142F, which seeds `[0x180] = 0.0f`,
     * `[0x188] = arg8`, `[0x184] = argC`, `[0x18C] = arg10`; and by the span
     * arithmetic in FUN_006621F0 (`[0x188]-[0x180]` paired with
     * `[0x18C]-[0x184]`).
     */
    float mViewTimeMin = 0.0f;
    float mViewValueMin = 0.0f;
    float mViewTimeMax = 0.0f;
    float mViewValueMax = 0.0f;
    std::uint8_t mReserved190[0x1]{};
    std::uint8_t mCurveDirty = 0;
    std::uint8_t mReserved192To193[0x2]{};

    /** Caption painted at the widget's top-left corner. */
    wxStringRuntime mCaption;

    void ResetCurveXRange(float rangeMax) noexcept;

    /**
     * Address: 0x006617A0 (FUN_006617A0)
     *
     * What it does:
     * `wxEventTableEntry` mouse-wheel sink at 0x00F59D44: zooms the value axis
     * about its centre, rejecting zooms that would collapse the visible span
     * below 0.1f, then raises the curve-changed notification.
     */
    void ZoomValueAxisByWheel(const wxEventRuntime& wheelEvent) noexcept;

    /**
     * Address: 0x00661100 (FUN_00661100)
     *
     * What it does:
     * Clears the dirty flag and posts a `wxEVT_COMMAND_BUTTON_CLICKED`
     * command event carrying this editor's window id, so the owning panel
     * learns the curve changed.
     */
    void PostCurveChangedCommand();

    /**
     * Address: 0x006614B0 (FUN_006614B0)
     *
     * What it does:
     * Moves the selected key to `(time, value, tangent)`, clamping the time
     * into the visible time range and against the neighbouring keys (to keep
     * keys sorted by time) and the value into the visible value range.
     */
    void MoveSelectedKeyTo(float time, float value, float tangent);

    /**
     * Address: 0x00661B90 (FUN_00661B90)
     *
     * What it does:
     * Paints one span of the curve's tangent envelope between the given key
     * and its neighbour (clamped to the visible time range at either end),
     * then draws the curve line across that span.
     */
    void DrawKeyEnvelopeSpan(void* dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x00662180 (FUN_00662180)
     *
     * What it does:
     * Draws one key's 5x5 grab handle, cyan when selected and red otherwise.
     */
    void DrawKeyHandle(void* dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x006621F0 (FUN_006621F0)
     *
     * What it does:
     * `wxEventTableEntry` paint sink: caches the client size, derives the view
     * scales, and paints the envelope spans, key handles and axis labels.
     */
    void OnPaint();

    /**
     * Address: 0x006612A0 (FUN_006612A0)
     *
     * What it does:
     * Projects one curve point to widget space. `edge` selects the upper
     * envelope edge (`value + tangent/2`), the curve value itself, or the
     * lower edge (`value - tangent/2`).
     */
    [[nodiscard]] wxPoint ProjectCurvePointToScreen(
      std::int32_t edge,
      const CurveEnvelopeColumn& column
    ) const noexcept;

    void MarkCurveClean() noexcept;
    [[nodiscard]] const SEfxCurve& Curve() const noexcept;
  };
  static_assert(offsetof(WEmitterCurveEditor, mCurve) == 0x138, "WEmitterCurveEditor::mCurve offset must be 0x138");
  static_assert(
    offsetof(WEmitterCurveEditor, mViewTimeScale) == 0x170,
    "WEmitterCurveEditor::mViewTimeScale offset must be 0x170"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mViewValueScale) == 0x174,
    "WEmitterCurveEditor::mViewValueScale offset must be 0x174"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mClientWidth) == 0x178,
    "WEmitterCurveEditor::mClientWidth offset must be 0x178"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mClientHeight) == 0x17C,
    "WEmitterCurveEditor::mClientHeight offset must be 0x17C"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mViewTimeMin) == 0x180,
    "WEmitterCurveEditor::mViewTimeMin offset must be 0x180"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mViewValueMin) == 0x184,
    "WEmitterCurveEditor::mViewValueMin offset must be 0x184"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mViewTimeMax) == 0x188,
    "WEmitterCurveEditor::mViewTimeMax offset must be 0x188"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mViewValueMax) == 0x18C,
    "WEmitterCurveEditor::mViewValueMax offset must be 0x18C"
  );
  static_assert(
    offsetof(WEmitterCurveEditor, mCurveDirty) == 0x191,
    "WEmitterCurveEditor::mCurveDirty offset must be 0x191"
  );

  struct WEmitterCurvePanel : WCurveEditorPanel
  {
    std::uint8_t mReserved004To133[0x130]{};
    WEmitterCurveEditor* mCurveEditor = nullptr;      // +0x134

    /**
     * The five numeric fields the panel keeps in sync with the editor. Their
     * wx command ids are consecutive from 622 (0x26E), which is how
     * FUN_00663650 selects between them.
     */
    WEmitterTextControl* mKeyTimeText = nullptr;      // +0x138, id 622
    WEmitterTextControl* mKeyValueText = nullptr;     // +0x13C, id 623
    WEmitterTextControl* mKeyTangentText = nullptr;   // +0x140, id 624
    WEmitterTextControl* mViewValueMinText = nullptr; // +0x144, id 625
    WEmitterTextControl* mViewValueMaxText = nullptr; // +0x148, id 626

    /** Set once the panel's fields are bound; commits are ignored until then. */
    std::uint8_t mFieldsLive = 0;                     // +0x14C

    /**
     * Address: 0x00663650 (FUN_00663650)
     *
     * What it does:
     * `wxEventTableEntry` sink shared by all five numeric fields: re-reads the
     * committed text, applies it to the selected key or the visible value
     * range, and mirrors the parsed value back into the field.
     */
    void OnCurveFieldCommitted(wxEventRuntime& commandEvent);

    /**
     * Address: 0x00663400 (FUN_00663400)
     *
     * What it does:
     * Pushes the editor's current key and view-range values back out into the
     * five numeric fields, formatted as `%f`.
     */
    void RefreshFieldsFromCurve();
  };
  static_assert(
    offsetof(WEmitterCurvePanel, mCurveEditor) == 0x134,
    "WEmitterCurvePanel::mCurveEditor offset must be 0x134"
  );
  static_assert(
    offsetof(WEmitterCurvePanel, mKeyTimeText) == 0x138,
    "WEmitterCurvePanel::mKeyTimeText offset must be 0x138"
  );
  static_assert(
    offsetof(WEmitterCurvePanel, mViewValueMaxText) == 0x148,
    "WEmitterCurvePanel::mViewValueMaxText offset must be 0x148"
  );
  static_assert(
    offsetof(WEmitterCurvePanel, mFieldsLive) == 0x14C,
    "WEmitterCurvePanel::mFieldsLive offset must be 0x14C"
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

    /**
     * Address: 0x00668180 (FUN_00668180)
     *
     * What it does:
     * `wxEventTableEntry` sink at 0x00F59DF8: re-syncs every curve panel's
     * numeric fields from its editor, then rebuilds the preview emitter.
     */
    void OnCurveEdited();

    /**
     * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
     *
     * IDA signature:
     * int __stdcall sub_666F40(WEmitterWx *this);
     *
     * What it does:
     * Complete-object destructor. Deletes every live curve panel, releases the
     * previewed effect through the sim effect-manager, releases the interlock
     * ref on the active sim driver, tears down the ramp/texture wx-string
     * caches, the blueprint/bone string lanes, the curve-panel vector storage,
     * the four blueprint/texture path lanes, unlinks the attached-unit and
     * preview-effect weak nodes, drains the managed-frame owner slots, and runs
     * the shared non-deleting frame teardown as a tail call. Teardown runs in
     * exact binary reverse-construction order.
     */
    ~WEmitterWx();

    /**
     * Address: 0x00669E10 (FUN_00669E10, Moho::WEmitterWx::dtr)
     * Slot: scalar-deleting destructor thunk
     *
     * IDA signature:
     * void *__thiscall Moho::WEmitterWx::dtr(WEmitterWx *this, char deleteFlags);
     *
     * What it does:
     * Scalar-deleting destructor thunk. Runs `~WEmitterWx()` teardown and
     * releases the object storage when `deleteFlags & 1` is set.
     */
    WEmitterWx* DeleteWithFlag(std::uint8_t deleteFlags) noexcept;

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

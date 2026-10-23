#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class TextWriter;
}

namespace moho
{
  class IEffect;
  class Sim;
  class Unit;
  class UserEntity;
  class WCurveEditorPanel;

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

  /**
   * VFTABLE: 0x00E2562C (??_7WCurveEditor@Moho@@6B@)
   *
   * The widget that edits one emitter curve (`SEfxCurve`): paints the keys
   * and the tangent envelope between them, drags keys with the left button and
   * tangents with the middle one, adds a key on a right click and removes the
   * nearest one on a control-right click, and zooms the value axis with the
   * wheel. Every change posts a button-clicked command with the editor's id,
   * which the owning WEmitterWx handles.
   *
   * RTTI: WCurveEditor > wxControl; slot 16 is the SetName override below.
   * GetEventTable (0x00662660) comes from DECLARE_EVENT_TABLE.
   */
  class WCurveEditor : public wxControl
  {
  public:
    /**
     * Cursor into `mCurve.mKeys` naming the key the user currently has
     * selected. Seeded to `mCurve.mKeys.begin()` by the constructor
     * (0x00661470) and by FUN_00661A90 (0x00661B37); "no selection" is
     * expressed as `mSelectedKey == mCurve.mKeys.end()`.
     */
    Wm3::Vector3f* mSelectedKey;                  // +0x130

    // Alignment padding: SEfxCurve's fastvector_n puts it on an 8-byte
    // boundary in the binary, which gpg::fastvector_n does not model yet.
    std::uint8_t mReserved134To137[0x4];

    SEfxCurve mCurve;                             // +0x138

    /**
     * Time-axis pixels per unit, recomputed by the paint handler
     * (FUN_006621F0) as `clientWidth / (mViewTimeMax - mViewTimeMin)`.
     */
    float mViewTimeScale;                         // +0x170

    /**
     * Value-axis pixels per unit, recomputed by the paint handler as
     * `clientHeight / (mViewValueMax - mViewValueMin)`; the mouse handlers
     * divide pixel and wheel deltas by it.
     */
    float mViewValueScale;                        // +0x174

    /** Client size cached by the paint handler (FUN_006621F0). */
    std::int32_t mClientWidth;                    // +0x178
    std::int32_t mClientHeight;                   // +0x17C

    /**
     * Visible view rectangle over the curve, stored interleaved as
     * (timeMin, valueMin, timeMax, valueMax). Proven by the constructor at
     * 0x006613FA-0x0066142F, which seeds `[0x180] = 0.0f`, `[0x188] = arg8`,
     * `[0x184] = argC`, `[0x18C] = arg10`; and by the span arithmetic in
     * FUN_006621F0 (`[0x188]-[0x180]` paired with `[0x18C]-[0x184]`).
     */
    float mViewTimeMin;                           // +0x180
    float mViewValueMin;                          // +0x184
    float mViewTimeMax;                           // +0x188
    float mViewValueMax;                          // +0x18C

    /** Set while the widget holds the mouse capture for a drag. */
    bool mMouseCaptured;                          // +0x190

    /** Set by an edit, cleared once the change has been posted or pushed. */
    bool mCurveDirty;                             // +0x191
    std::uint8_t mReserved192To193[0x2];

    /** Caption painted at the widget's top-left corner (SetName). */
    wxString mCaption;                            // +0x194

    /** Key this curve is written out under in a blueprint (WriteCurveScript). */
    wxString mScriptName;                         // +0x198

    /** Panel that owns this editor; refreshed after a curve assignment. */
    WCurveEditorPanel* mOwnerPanel;               // +0x19C

    /** Cursor position at the last button press or motion. */
    std::int32_t mLastMouseX;                     // +0x1A0
    std::int32_t mLastMouseY;                     // +0x1A4

    /** Which button is driving the current drag: 1 = left, 2 = middle. */
    std::int32_t mActiveDragButton;               // +0x1A8

    // Tail padding to the 8-byte class alignment (see mReserved134To137):
    // operator new(0x1B0) at 0x006626FF.
    std::uint8_t mReserved1ACTo1AF[0x4];

    /**
     * Address: 0x00661330 (FUN_00661330, Moho::WCurveEditor::WCurveEditor)
     * Mangled: ??0WCurveEditor@Moho@@QAE@@Z
     *
     * What it does:
     * Creates the control over `parent`, sets the view to
     * (0, viewValueMin) - (viewTimeMax, viewValueMax), rescales the empty curve
     * to [0, viewTimeMax] and gives it one key halfway along, selected, then
     * shows itself.
     */
    WCurveEditor(
      WCurveEditorPanel* parent,
      std::int32_t id,
      float viewTimeMax,
      float viewValueMin,
      float viewValueMax,
      float initialKeyValue,
      float initialKeyTangent
    );

    /**
     * Address: 0x00661700 (FUN_00661700)
     * Slot: 16 (wxWindowBase::SetName)
     *
     * What it does:
     * The window name is the caption painted in the corner.
     */
    void SetName(const wxString& name) override;

    /**
     * Address: 0x00661710 (FUN_00661710)
     *
     * What it does:
     * Sets the key the curve is written out under. The one call, in the
     * WEmitterWx constructor's curve loop (0x00666E3D), was inlined; nothing
     * in the image references this out-of-line copy.
     */
    void SetScriptName(const wxString& scriptName);

    /**
     * Address: 0x00661720 (FUN_00661720)
     *
     * What it does:
     * Makes the time axis [0, rangeMax] - the repeat time - and rescales the
     * curve's keys onto it, then repaints.
     */
    void ResetCurveXRange(float rangeMax);

    /**
     * Address: 0x006617A0 (FUN_006617A0)
     *
     * What it does:
     * Mouse wheel: zooms the value axis about its centre, rejecting zooms that
     * would shrink the visible span below 0.1, then repaints.
     */
    void ZoomValueAxisByWheel(wxMouseEvent& event);

    /**
     * Address: 0x00662570 (FUN_00662570, nullsub_1719)
     *
     * What it does:
     * Nothing (`ret 4`). The last row of the event table binds it to
     * wxEVT_ENTER_WINDOW, so entering the control is swallowed.
     */
    void IgnoreEvent(wxMouseEvent& event);

    /**
     * Address: 0x00661A50 (FUN_00661A50)
     *
     * What it does:
     * Ends a drag (left or middle button up): clears the drag button and, if
     * the mouse was captured, releases it and posts the curve-changed command;
     * then repaints.
     */
    void OnMouseUp(wxMouseEvent& event);

    /**
     * Address: 0x00661900 (FUN_00661900)
     *
     * What it does:
     * Drags the selected key: with the left button it follows the cursor,
     * clamped to the view and between its neighbours; with the middle button
     * the vertical motion widens or narrows its tangent (never below 0). Any
     * drag posts the curve-changed command and repaints; the cursor position
     * is always remembered for the next move.
     */
    void OnMouseMove(wxMouseEvent& event);

    /**
     * Address: 0x00661100 (FUN_00661100)
     *
     * What it does:
     * Clears the dirty flag and posts a wxEVT_COMMAND_BUTTON_CLICKED command
     * event carrying this editor's window id, so the owner learns the curve
     * changed.
     */
    void PostCurveChangedCommand();

    /**
     * Address: 0x006614B0 (FUN_006614B0)
     *
     * What it does:
     * Moves the selected key to `(time, value, tangent)` - nothing when there
     * is no selection - then posts the change and repaints.
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
    void DrawKeyEnvelopeSpan(wxDC& dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x00662180 (FUN_00662180)
     *
     * What it does:
     * Draws one key's 5x5 grab handle, cyan when selected and red otherwise.
     */
    void DrawKeyHandle(wxDC& dc, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x006621F0 (FUN_006621F0)
     *
     * What it does:
     * Paint handler: caches the client size, derives the view scales, and
     * paints the envelope spans, key handles, axis labels and caption.
     */
    void OnPaint(wxPaintEvent& event);

    /**
     * Address: 0x00661820 (FUN_00661820)
     *
     * What it does:
     * Left/middle button down: selects the key nearest the cursor, starts a
     * key or tangent drag, captures the mouse and repaints.
     */
    void OnMouseDown(wxMouseEvent& event);

    /**
     * Address: 0x00661A90 (FUN_00661A90)
     *
     * What it does:
     * Right button down: inserts a key at the cursor, or with control held
     * removes the nearest key (never the last one).
     */
    void OnCurveKeyEdit(wxMouseEvent& event);

    /**
     * Address: 0x006612A0 (FUN_006612A0)
     *
     * What it does:
     * Projects one curve point to widget space. `edge` selects the upper
     * envelope edge (`value + tangent/2`), the curve value itself, or the
     * lower edge (`value - tangent/2`).
     */
    [[nodiscard]] wxPoint ProjectCurvePointToScreen(std::int32_t edge, const CurveEnvelopeColumn& column) const;

    /**
     * Address: 0x00669E40 (FUN_00669E40)
     *
     * What it does:
     * Replaces the edited curve wholesale, drops the now-dangling selection,
     * notifies, and refreshes the owning panel's fields.
     */
    void AssignCurve(const SEfxCurve& source);

    /**
     * Address: 0x00661580 (FUN_00661580)
     *
     * What it does:
     * Writes this curve's block of an emitter blueprint: the script key, the
     * X range, then one `{ x=, y=, z= }` line per key.
     */
    void WriteCurveScript(gpg::TextWriter& writer) const;

    DECLARE_EVENT_TABLE()
  };
  static_assert(offsetof(WCurveEditor, mSelectedKey) == 0x130, "WCurveEditor::mSelectedKey offset must be 0x130");
  static_assert(offsetof(WCurveEditor, mCurve) == 0x138, "WCurveEditor::mCurve offset must be 0x138");
  static_assert(offsetof(WCurveEditor, mViewTimeScale) == 0x170, "WCurveEditor::mViewTimeScale offset must be 0x170");
  static_assert(offsetof(WCurveEditor, mClientWidth) == 0x178, "WCurveEditor::mClientWidth offset must be 0x178");
  static_assert(offsetof(WCurveEditor, mViewTimeMin) == 0x180, "WCurveEditor::mViewTimeMin offset must be 0x180");
  static_assert(offsetof(WCurveEditor, mViewValueMax) == 0x18C, "WCurveEditor::mViewValueMax offset must be 0x18C");
  static_assert(offsetof(WCurveEditor, mMouseCaptured) == 0x190, "WCurveEditor::mMouseCaptured offset must be 0x190");
  static_assert(offsetof(WCurveEditor, mCurveDirty) == 0x191, "WCurveEditor::mCurveDirty offset must be 0x191");
  static_assert(offsetof(WCurveEditor, mCaption) == 0x194, "WCurveEditor::mCaption offset must be 0x194");
  static_assert(offsetof(WCurveEditor, mScriptName) == 0x198, "WCurveEditor::mScriptName offset must be 0x198");
  static_assert(offsetof(WCurveEditor, mOwnerPanel) == 0x19C, "WCurveEditor::mOwnerPanel offset must be 0x19C");
  static_assert(offsetof(WCurveEditor, mLastMouseX) == 0x1A0, "WCurveEditor::mLastMouseX offset must be 0x1A0");
  static_assert(
    offsetof(WCurveEditor, mActiveDragButton) == 0x1A8,
    "WCurveEditor::mActiveDragButton offset must be 0x1A8"
  );
  static_assert(sizeof(WCurveEditor) == 0x1B0, "WCurveEditor size must be 0x1B0");

  /**
   * One `WCurveEditor` plus five numeric fields (key time/value/tangent,
   * visible value range) that mirror the selected key and let it be edited by
   * hand.
   *
   * RTTI: WCurveEditorPanel > wxPanel, with wxPanel's 132 vtable slots; its
   * own fields start at sizeof(wxPanel) = 0x134. The constructor (0x00662680)
   * proves every offset: 0x006626FF-0x0066271D zero the five text-control
   * pointers and the live flag, 0x0066277B writes the editor, 0x006633DD sets
   * the live flag. The destructors are the compiler's (0x00663870 is the
   * deleting one; 0x009AE6D0, which IDA attributed to this class, lies in the
   * wx library block). GetEventTable (0x006638A0) comes from
   * DECLARE_EVENT_TABLE below.
   */
  class WCurveEditorPanel : public wxPanel
  {
  public:
    WCurveEditor* mCurveEditor;    // +0x134

    /**
     * The five numeric fields the panel keeps in sync with the editor. Their
     * wx command ids are consecutive from 622 (0x26E), which is how
     * FUN_00663650 selects between them.
     */
    wxTextCtrl* mKeyTimeText;      // +0x138, id 622
    wxTextCtrl* mKeyValueText;     // +0x13C, id 623
    wxTextCtrl* mKeyTangentText;   // +0x140, id 624
    wxTextCtrl* mViewValueMinText; // +0x144, id 625
    wxTextCtrl* mViewValueMaxText; // +0x148, id 626

    /** Set once the panel's fields are bound; commits are ignored until then. */
    bool mFieldsLive;              // +0x14C

    /**
     * Address: 0x00662680 (FUN_00662680, Moho::WCurveEditorPanel::WCurveEditorPanel)
     * Mangled: ??0WCurveEditorPanel@Moho@@QAE@@Z
     *
     * What it does:
     * Creates the panel, then the editor (with the panel's id - the panel
     * itself takes the default), and lays them out: a row of five label +
     * number fields above the editor, which takes the rest.
     */
    WCurveEditorPanel(
      wxWindow* parent,
      std::int32_t childId,
      float viewTimeMax,
      float viewValueMin,
      float viewValueMax,
      float initialKeyValue,
      float initialKeyTangent
    );

    /**
     * Address: 0x00663650 (FUN_00663650)
     *
     * What it does:
     * Enter in any of the five fields: applies the committed text to the
     * selected key or the visible value range, and mirrors it into the field.
     */
    void OnCurveFieldCommitted(wxCommandEvent& event);

    /**
     * Address: 0x00663400 (FUN_00663400)
     *
     * What it does:
     * Pushes the editor's current key and view-range values back out into the
     * five numeric fields, formatted as `%f`.
     */
    void RefreshFieldsFromCurve();

    DECLARE_EVENT_TABLE()
  };
  static_assert(offsetof(WCurveEditorPanel, mCurveEditor) == 0x134, "WCurveEditorPanel::mCurveEditor offset must be 0x134");
  static_assert(offsetof(WCurveEditorPanel, mKeyTimeText) == 0x138, "WCurveEditorPanel::mKeyTimeText offset must be 0x138");
  static_assert(
    offsetof(WCurveEditorPanel, mViewValueMaxText) == 0x148,
    "WCurveEditorPanel::mViewValueMaxText offset must be 0x148"
  );
  static_assert(offsetof(WCurveEditorPanel, mFieldsLive) == 0x14C, "WCurveEditorPanel::mFieldsLive offset must be 0x14C");
  static_assert(sizeof(WCurveEditorPanel) == 0x150, "WCurveEditorPanel size must be 0x150");

  /**
   * VFTABLE: 0x00E25A64 (??_7WEmitterWx@Moho@@6B@)
   *
   * The emitter editor: a top-level frame (opened by the `EFX_CreateEmitterWindow`
   * console command) that edits one particle emitter live. Scalar parameters sit in
   * two rows of text fields and combo boxes, the texture and ramp in two labels, the
   * boolean parameters in the Options and LOD menus, and the 21 curves in a notebook
   * of `WCurveEditorPanel`s. Every edit is pushed straight into a preview effect
   * created in the running sim, either free-standing at the spawn position or
   * attached to a bone of the selected unit; File > Open/Save read and write
   * emitter blueprints.
   *
   * Event table 0x00DFEF80 = {&wxFrame::sm_eventTable, rows 0x00F59DF8}, from
   * DECLARE_EVENT_TABLE below.
   */
  class WEmitterWx : public WWinManagedFrame
  {
  public:
    /**
     * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
     * Mangled: ??0WEmitterWx@Moho@@QAE@@Z
     *
     * What it does:
     * Builds the 800x600 "Emitter Editor" frame. Takes an interlock reference on
     * the sim (released by the destructor), resolves `attachEntity` - a user-side
     * entity, whose id is looked up in the sim's entity database - to the unit the
     * preview attaches to, then builds the File/Options/LOD menus, their
     * accelerators, the preview effect, the two rows of parameter controls, the
     * time slider and the notebook of curve panels, and finally pushes everything
     * into the effect once.
     */
    WEmitterWx(UserEntity* attachEntity, const Wm3::Vector3f& spawnPosition, const char* boneName);

    /**
     * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
     * Address: 0x00669E10 (FUN_00669E10, scalar deleting destructor)
     *
     * What it does:
     * Deletes the curve panels, destroys the preview effect through its manager
     * and releases the sim interlock reference the constructor took. The members,
     * WeakObject and wxFrame are then torn down by the compiler.
     */
    ~WEmitterWx() override;

    /**
     * Address: 0x006672F0 (FUN_006672F0)
     *
     * What it does:
     * Pushes the editor state into the preview effect, recreating the effect
     * first if it has died. Nothing happens until the constructor has built the
     * controls it reads, nor while LoadFromEffect is writing them.
     */
    void RefreshPreviewEmitter();

    /**
     * Address: 0x00667860 (FUN_00667860)
     *
     * What it does:
     * The inverse of RefreshPreviewEmitter: reads the preview effect back into
     * the controls, the curve editors and the menus, with the refresh guard up so
     * none of those writes echo back into the effect.
     */
    void LoadFromEffect();

    /**
     * Address: 0x00668340 (FUN_00668340)
     *
     * What it does:
     * Writes the emitter as an `EmitterBlueprint { ... }` Lua script to `path`,
     * every parameter followed by each curve's own block.
     */
    void WriteBlueprintScript(const wxString& path, const wxString& blueprintId);

    /**
     * Address: 0x00668180 (FUN_00668180)
     *
     * What it does:
     * Shared by the text fields, the combo boxes and the curve editors: refreshes
     * every curve panel's fields, then the preview.
     */
    void OnSettingChanged(wxCommandEvent& event);

    /**
     * Address: 0x006681D0 (FUN_006681D0)
     *
     * What it does:
     * The "Playing" check box: sets the effect's tick increment to 1 or 0, which
     * runs or freezes the preview.
     */
    void OnPlayingToggled(wxCommandEvent& event);

    /**
     * Address: 0x00668240 (FUN_00668240)
     *
     * What it does:
     * Dragging the time slider scrubs the preview to that tick.
     */
    void OnTimeSliderTrack(wxScrollEvent& event);

    /**
     * Address: 0x00668290 (FUN_00668290)
     *
     * What it does:
     * Keeps the time slider on the preview's current tick, wrapped into the repeat
     * time once it has run past it.
     */
    void OnTimeSliderUpdateUI(wxUpdateUIEvent& event);

    /**
     * Address: 0x00668B00 (FUN_00668B00)
     *
     * What it does:
     * The menu handler: Open Blueprint (668), Save Blueprint (669), Save
     * Blueprint As (679), Open Texture (670), Open Ramp (671); the check items
     * 672-684 only need the preview refreshed, since wx has already toggled them.
     */
    void OnMenuCommand(wxCommandEvent& event);

  private:
    /**
     * Address: 0x006671C0 (FUN_006671C0)
     *
     * What it does:
     * The loaded blueprint's VFS name, or null while none is loaded.
     */
    [[nodiscard]] const char* BlueprintNameOrNull() const;

    /**
     * Address: 0x006671F0 (FUN_006671F0)
     *
     * What it does:
     * Parses `field`'s text as a number into one float parameter of the effect.
     */
    void ApplyTextFieldParam(wxTextCtrl* field, std::int32_t parameter);

    /**
     * Address: 0x00667290 (FUN_00667290)
     *
     * What it does:
     * Sets one boolean effect parameter to 1 or 0 from a check item of `menu`.
     */
    void ApplyMenuFlagParam(wxMenu* menu, std::int32_t commandId, std::int32_t parameter);

  public:
    Sim* mSim;                                  // +0x17C
    Wm3::Vector3f mSpawnPosition;               // +0x180
    wxTextCtrl* mLifetimeControl;               // +0x18C, id 556
    wxTextCtrl* mRepeatTimeControl;             // +0x190, id 557

    // Neither constructed nor read by any function in the binary.
    std::uint32_t mUnreferenced194[3];          // +0x194

    wxTextCtrl* mTextureFrameCountControl;      // +0x1A0, id 559
    wxTextCtrl* mTextureStripCountControl;      // +0x1A4, id 560
    wxTextCtrl* mSortOrderControl;              // +0x1A8, id 563
    wxTextCtrl* mLodCutoffControl;              // +0x1AC, id 565
    wxCheckBox* mPlayingCheckBox;               // +0x1B0, id 561
    wxSlider* mTimeSlider;                      // +0x1B4, id 562
    wxComboBox* mBlendModeChoice;               // +0x1B8, id 558
    wxComboBox* mFidelityChoice;                // +0x1BC, id 558 as well
    wxStaticText* mTextureNameControl;          // +0x1C0
    wxStaticText* mRampNameControl;             // +0x1C4
    wxString mTexturePath;                      // +0x1C8
    wxString mRampTexturePath;                  // +0x1CC

    // Where the blueprint and texture file dialogs open, and where they were
    // last closed.
    wxString mBlueprintDirectory;               // +0x1D0
    wxString mTextureDirectory;                 // +0x1D4

    // The repeat time last pushed into the effect and the curve editors' time
    // axes; -1 after the effect is recreated, so the next refresh pushes it again.
    double mCachedRepeatTime;                   // +0x1D8

    // Raised by LoadFromEffect so the control writes do not refresh the effect.
    bool mRefreshGuard;                         // +0x1E0

    msvc8::vector<WCurveEditorPanel*> mCurvePanels; // +0x1E4, one per EEmitterCurve
    WeakPtr<IEffect> mPreviewEffect;            // +0x1F4
    WeakPtr<Unit> mAttachedUnit;                // +0x1FC
    msvc8::string mBoneName;                    // +0x204
    msvc8::string mBlueprintName;               // +0x220, VFS name of the loaded blueprint
    wxMenuBar* mMenuBar;                        // +0x23C
    wxMenu* mFileMenu;                          // +0x240
    wxMenu* mOptionsMenu;                       // +0x244
    wxMenu* mLodMenu;                           // +0x248

    // The blueprint file last opened or saved: full path (also the title) and
    // bare file name.
    wxString mBlueprintPath;                    // +0x24C
    wxString mBlueprintFileName;                // +0x250

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(WEmitterWx, mSim) == 0x17C, "WEmitterWx::mSim offset must be 0x17C");
  static_assert(offsetof(WEmitterWx, mSpawnPosition) == 0x180, "WEmitterWx::mSpawnPosition offset must be 0x180");
  static_assert(offsetof(WEmitterWx, mLifetimeControl) == 0x18C, "WEmitterWx::mLifetimeControl offset must be 0x18C");
  static_assert(
    offsetof(WEmitterWx, mTextureFrameCountControl) == 0x1A0,
    "WEmitterWx::mTextureFrameCountControl offset must be 0x1A0"
  );
  static_assert(offsetof(WEmitterWx, mPlayingCheckBox) == 0x1B0, "WEmitterWx::mPlayingCheckBox offset must be 0x1B0");
  static_assert(offsetof(WEmitterWx, mTimeSlider) == 0x1B4, "WEmitterWx::mTimeSlider offset must be 0x1B4");
  static_assert(offsetof(WEmitterWx, mTexturePath) == 0x1C8, "WEmitterWx::mTexturePath offset must be 0x1C8");
  static_assert(offsetof(WEmitterWx, mCachedRepeatTime) == 0x1D8, "WEmitterWx::mCachedRepeatTime offset must be 0x1D8");
  static_assert(offsetof(WEmitterWx, mRefreshGuard) == 0x1E0, "WEmitterWx::mRefreshGuard offset must be 0x1E0");
  static_assert(offsetof(WEmitterWx, mCurvePanels) == 0x1E4, "WEmitterWx::mCurvePanels offset must be 0x1E4");
  static_assert(offsetof(WEmitterWx, mPreviewEffect) == 0x1F4, "WEmitterWx::mPreviewEffect offset must be 0x1F4");
  static_assert(offsetof(WEmitterWx, mAttachedUnit) == 0x1FC, "WEmitterWx::mAttachedUnit offset must be 0x1FC");
  static_assert(offsetof(WEmitterWx, mBoneName) == 0x204, "WEmitterWx::mBoneName offset must be 0x204");
  static_assert(offsetof(WEmitterWx, mBlueprintName) == 0x220, "WEmitterWx::mBlueprintName offset must be 0x220");
  static_assert(offsetof(WEmitterWx, mMenuBar) == 0x23C, "WEmitterWx::mMenuBar offset must be 0x23C");
  static_assert(offsetof(WEmitterWx, mLodMenu) == 0x248, "WEmitterWx::mLodMenu offset must be 0x248");
  static_assert(offsetof(WEmitterWx, mBlueprintPath) == 0x24C, "WEmitterWx::mBlueprintPath offset must be 0x24C");
  static_assert(offsetof(WEmitterWx, mBlueprintFileName) == 0x250, "WEmitterWx::mBlueprintFileName offset must be 0x250");
  static_assert(sizeof(WEmitterWx) == 0x258, "WEmitterWx size must be 0x258");
} // namespace moho

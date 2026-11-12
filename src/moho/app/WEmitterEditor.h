#pragma once

// The emitter editor (`EFX_CreateEmitterWindow`), recovered from the retail binary's emitter
// editor frame (0x00663900), curve panel (0x00662680) and curve control (0x00661330), which were
// windows of the binary's widget library. Dear ImGui in a window of its own since issue #414
// (platform/sdl/ToolWindow.h): the controls are drawn each frame, and the file dialogs are SDL3's,
// which answer later instead of blocking. The logic behind them, the curve editing, the preview effect and the
// blueprint format are the binary's.

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/WeakPtr.h"
#include "platform/sdl/ToolWindow.h"

namespace gpg
{
  class TextWriter;
}

struct ImDrawList;

namespace moho
{
  class IEffect;
  class Sim;
  class Unit;
  class UserEntity;
  class WCurveEditorPanel;
  class WEmitterEditor;

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

  /** A point in the curve editor's client area, in pixels from its top-left corner. */
  struct CurveScreenPoint
  {
    int x = 0;
    int y = 0;
  };

  /**
   * VFTABLE: 0x00E2562C (??_7WCurveEditor@Moho@@6B@) in the binary.
   *
   * The editor of one emitter curve (`SEfxCurve`): paints the keys and the tangent envelope
   * between them, drags keys with the left button and tangents with the middle one, adds a key
   * on a right click and removes the nearest one on a control-right click, and zooms the value
   * axis with the wheel. Every change tells the owning WEmitterEditor (the binary posted a
   * button-clicked command with the editor's id).
   *
   * The binary's was a wx control; this one is drawn by Draw into the ImGui window.
   */
  class WCurveEditor
  {
  public:
    /**
     * Address: 0x00661330 (FUN_00661330, Moho::WCurveEditor::WCurveEditor)
     *
     * What it does:
     * Sets the view to (0, viewValueMin) - (viewTimeMax, viewValueMax), rescales the empty
     * curve to [0, viewTimeMax] and gives it one key halfway along, selected.
     */
    WCurveEditor(
      WCurveEditorPanel* parent,
      float viewTimeMax,
      float viewValueMin,
      float viewValueMax,
      float initialKeyValue,
      float initialKeyTangent
    );

    /**
     * Address: 0x00661700 (FUN_00661700)
     *
     * What it does:
     * The window name was the caption painted in the corner.
     */
    void SetName(const std::string& name);

    /**
     * Address: 0x00661710 (FUN_00661710)
     *
     * What it does:
     * Sets the key the curve is written out under.
     */
    void SetScriptName(const std::string& scriptName);

    /**
     * Address: 0x00661720 (FUN_00661720)
     *
     * What it does:
     * Makes the time axis [0, rangeMax] - the repeat time - and rescales the curve's keys
     * onto it.
     */
    void ResetCurveXRange(float rangeMax);

    /**
     * Address: 0x006617A0 (FUN_006617A0)
     *
     * What it does:
     * Mouse wheel: zooms the value axis about its centre, rejecting zooms that would shrink the
     * visible span below 0.1. `wheelRotation` is in Windows' units, 120 a notch.
     */
    void ZoomValueAxisByWheel(int wheelRotation);

    /**
     * Address: 0x00661A50 (FUN_00661A50)
     *
     * What it does:
     * Ends a drag (left or middle button up): clears the drag button and, if the mouse was
     * captured, releases it and tells the owner the curve changed.
     */
    void OnMouseUp();

    /**
     * Address: 0x00661900 (FUN_00661900)
     *
     * What it does:
     * Drags the selected key: with the left button it follows the cursor, clamped to the view
     * and between its neighbours; with the middle button the vertical motion widens or narrows
     * its tangent (never below 0).
     */
    void OnMouseMove(int mouseX, int mouseY);

    /**
     * Address: 0x00661100 (FUN_00661100)
     *
     * What it does:
     * Clears the dirty flag and tells the owner the curve changed (the binary's
     * wxEVT_COMMAND_BUTTON_CLICKED command with this editor's id).
     */
    void PostCurveChangedCommand();

    /**
     * Address: 0x006614B0 (FUN_006614B0)
     *
     * What it does:
     * Moves the selected key to `(time, value, tangent)` - nothing when there is no selection -
     * then tells the owner.
     */
    void MoveSelectedKeyTo(float time, float value, float tangent);

    /**
     * Address: 0x00661B90 (FUN_00661B90)
     *
     * What it does:
     * Paints one span of the curve's tangent envelope between the given key and its neighbour
     * (clamped to the visible time range at either end), then the curve line across it.
     */
    void DrawKeyEnvelopeSpan(ImDrawList& drawList, float originX, float originY, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x00662180 (FUN_00662180)
     *
     * What it does:
     * Draws one key's 5x5 grab handle, cyan when selected and red otherwise.
     */
    void DrawKeyHandle(ImDrawList& drawList, float originX, float originY, const Wm3::Vector3f* key) const;

    /**
     * Address: 0x006621F0 (FUN_006621F0, OnPaint) with the binary's mouse handlers
     *
     * What it does:
     * Draws the editor `width` x `height` pixels at the cursor: caches the size, derives the
     * view scales, paints the envelope spans, key handles, axis labels and caption, and feeds
     * the mouse to OnMouseDown, OnMouseMove, OnMouseUp, OnCurveKeyEdit and ZoomValueAxisByWheel.
     */
    void Draw(int width, int height);

    /**
     * Address: 0x00661820 (FUN_00661820)
     *
     * What it does:
     * Left/middle button down: selects the key nearest the cursor and starts a key or tangent
     * drag, holding the mouse.
     */
    void OnMouseDown(int mouseX, int mouseY, bool middleButton);

    /**
     * Address: 0x00661A90 (FUN_00661A90)
     *
     * What it does:
     * Right button down: inserts a key at the cursor, or with control held removes the nearest
     * key (never the last one).
     */
    void OnCurveKeyEdit(int mouseX, int mouseY, bool controlDown);

    /**
     * Address: 0x006612A0 (FUN_006612A0)
     *
     * What it does:
     * Projects one curve point to client space. `edge` selects the upper envelope edge
     * (`value + tangent/2`), the curve value itself, or the lower edge (`value - tangent/2`).
     */
    [[nodiscard]] CurveScreenPoint
    ProjectCurvePointToScreen(std::int32_t edge, const CurveEnvelopeColumn& column) const;

    /**
     * Address: 0x00669E40 (FUN_00669E40)
     *
     * What it does:
     * Replaces the edited curve wholesale, drops the now-dangling selection, notifies, and
     * refreshes the owning panel's fields.
     */
    void AssignCurve(const SEfxCurve& source);

    /**
     * Address: 0x00661580 (FUN_00661580)
     *
     * What it does:
     * Writes this curve's block of an emitter blueprint: the script key, the X range, then one
     * `{ x=, y=, z= }` line per key.
     */
    void WriteCurveScript(gpg::TextWriter& writer) const;

    // Cursor into `mCurve.mKeys` naming the selected key; `mCurve.mKeys.end()` for none.
    Wm3::Vector3f* mSelectedKey = nullptr;
    SEfxCurve mCurve;
    // Pixels per unit on each axis, recomputed by Draw.
    float mViewTimeScale = 1.0f;
    float mViewValueScale = 1.0f;
    std::int32_t mClientWidth = 0;
    std::int32_t mClientHeight = 0;
    // The visible view rectangle over the curve.
    float mViewTimeMin = 0.0f;
    float mViewValueMin = 0.0f;
    float mViewTimeMax = 0.0f;
    float mViewValueMax = 0.0f;
    // Set while the editor holds the mouse for a drag.
    bool mMouseCaptured = false;
    // Set by an edit, cleared once the change has been posted or pushed.
    bool mCurveDirty = false;
    std::string mCaption;
    std::string mScriptName;
    WCurveEditorPanel* mOwnerPanel = nullptr;
    std::int32_t mLastMouseX = 0;
    std::int32_t mLastMouseY = 0;
    // Which button drives the current drag: 1 = left, 2 = middle.
    std::int32_t mActiveDragButton = 0;
  };

  /**
   * One `WCurveEditor` plus five numeric fields (key time/value/tangent, visible value range)
   * that mirror the selected key and let it be edited by hand. A panel window in the binary (0x00662680).
   */
  class WCurveEditorPanel
  {
  public:
    /**
     * Address: 0x00662680 (FUN_00662680, Moho::WCurveEditorPanel::WCurveEditorPanel)
     *
     * What it does:
     * Creates the editor and the row of five label + number fields above it.
     */
    WCurveEditorPanel(
      WEmitterEditor* owner,
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
     * Enter in one of the five fields (`field` 0..4: tick, value, range, window min, max):
     * applies the committed text to the selected key or the visible value range.
     */
    void OnCurveFieldCommitted(int field);

    /**
     * Address: 0x00663400 (FUN_00663400)
     *
     * What it does:
     * Pushes the editor's current key and view-range values back out into the five numeric
     * fields, formatted as `%f`.
     */
    void RefreshFieldsFromCurve();

    // The fields and the editor below them, `height` pixels in all.
    void Draw(int index, float height);

    WEmitterEditor* mOwner = nullptr;
    std::unique_ptr<WCurveEditor> mCurveEditor;
    // Tick, Value, Range, Window Min, Max.
    std::array<std::array<char, 32>, 5> mFields{};
    // Set once the fields are bound; commits are ignored until then.
    bool mFieldsLive = false;
  };

  /**
   * VFTABLE: 0x00E25A64 (??_7WEmitterWx@Moho@@6B@) in the binary.
   *
   * The emitter editor, opened by the `EFX_CreateEmitterWindow` console command, edits one
   * particle emitter live. Scalar parameters sit in two rows of text fields and combo boxes,
   * the texture and ramp in two labels, the boolean parameters in the Options and LOD menus, and
   * the 21 curves in tabs of `WCurveEditorPanel`s. Every edit is pushed straight into a preview
   * effect created in the running sim, either free-standing at the spawn position or attached to
   * a bone of the selected unit; File > Open/Save read and write emitter blueprints.
   *
   * Closing the window destroys the editor, as wx destroyed a closed frame; WINX_Exit destroys
   * those still open (DestroyAll), as it did the managed frames.
   */
  class WEmitterEditor final : public platform::tools::ToolWindow
  {
  public:
    /**
     * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
     *
     * What it does:
     * Builds the 800x600 "Emitter Editor" window. Takes an interlock reference on the sim
     * (released by the destructor), resolves `attachEntity` - a user-side entity, whose id is
     * looked up in the sim's entity database - to the unit the preview attaches to, then the
     * menus, the preview effect, the parameter controls, the time slider and the curve panels,
     * and finally pushes everything into the effect once.
     */
    WEmitterEditor(UserEntity* attachEntity, const Wm3::Vector3f& spawnPosition, const char* boneName);

    /**
     * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
     * Address: 0x00669E10 (FUN_00669E10, scalar deleting destructor)
     *
     * What it does:
     * Deletes the curve panels, destroys the preview effect through its manager and releases
     * the sim interlock reference the constructor took.
     */
    ~WEmitterEditor() override;

    // Destroys every emitter editor still open (WINX_Exit).
    static void DestroyAll();

    /**
     * Address: 0x006672F0 (FUN_006672F0)
     *
     * What it does:
     * Pushes the editor state into the preview effect, recreating the effect first if it has
     * died. Nothing happens until the constructor has built the controls it reads, nor while
     * LoadFromEffect is writing them.
     */
    void RefreshPreviewEmitter();

    /**
     * Address: 0x00667860 (FUN_00667860)
     *
     * What it does:
     * The inverse of RefreshPreviewEmitter: reads the preview effect back into the controls,
     * the curve editors and the menus, with the refresh guard up.
     */
    void LoadFromEffect();

    /**
     * Address: 0x00668340 (FUN_00668340)
     *
     * What it does:
     * Writes the emitter as an `EmitterBlueprint { ... }` Lua script to `path` (UTF-8), every
     * parameter followed by each curve's own block.
     */
    void WriteBlueprintScript(const fa::string& path, const fa::string& blueprintId);

    /**
     * Address: 0x00668180 (FUN_00668180)
     *
     * What it does:
     * Shared by the text fields, the combo boxes and the curve editors: refreshes every curve
     * panel's fields, then the preview.
     */
    void OnSettingChanged();

    /**
     * Address: 0x006681D0 (FUN_006681D0)
     *
     * What it does:
     * The "Playing" check box: sets the effect's tick increment to 1 or 0.
     */
    void OnPlayingToggled();

    /**
     * Address: 0x00668240 (FUN_00668240)
     *
     * What it does:
     * Dragging the time slider scrubs the preview to that tick.
     */
    void OnTimeSliderTrack();

    /**
     * Address: 0x00668290 (FUN_00668290)
     *
     * What it does:
     * Keeps the time slider on the preview's current tick, wrapped into the repeat time once it
     * has run past it.
     */
    void OnTimeSliderUpdateUI();

    // The binary's menu command ids (0x00668B00's switch).
    enum MenuCommand : std::int32_t
    {
      kMenuNew = 667,
      kMenuOpen = 668,
      kMenuSave = 669,
      kMenuOpenTexture = 670,
      kMenuOpenRamp = 671,
      kMenuLocalVelocity = 672,
      kMenuLocalAcceleration = 673,
      kMenuGravity = 674,
      kMenuAlignRotation = 675,
      kMenuInterpolateEmission = 676,
      kMenuAlignToBone = 677,
      kMenuFlat = 678,
      kMenuSaveAs = 679,
      kMenuEmitIfVisible = 680,
      kMenuCatchupEmit = 681,
      kMenuCreateIfVisible = 682,
      kMenuSnapToWaterline = 683,
      kMenuOnlyEmitOnWater = 684,
      kMenuParticleResistance = 685,
    };

    /**
     * Address: 0x00668B00 (FUN_00668B00)
     *
     * What it does:
     * The menu handler: Open Blueprint, Save Blueprint, Save Blueprint As, Open Texture, Open
     * Ramp; the check items only need the preview refreshed. The file dialogs answer later
     * (OnFileChosen continues each command).
     */
    void OnMenuCommand(std::int32_t command);

  protected:
    void Tick() override;
    void Draw() override;
    void OnCloseRequested() override;

  private:
    // What a file dialog was opened for.
    enum class FilePick : std::uint8_t
    {
      None,
      OpenBlueprint,
      SaveBlueprint,
      OpenTexture,
      OpenRamp,
    };

    // A file dialog's answer, written by SDL's callback (any thread) and read by Tick.
    struct PendingPick;

    [[nodiscard]] const char* BlueprintNameOrNull() const;

    /**
     * Address: 0x006671F0 (FUN_006671F0)
     *
     * What it does:
     * Parses `field`'s text as a number into one float parameter of the effect.
     */
    void ApplyTextFieldParam(const char* field, std::int32_t parameter);

    /**
     * Address: 0x00667290 (FUN_00667290)
     *
     * What it does:
     * Sets one boolean effect parameter to 1 or 0 from a check item of the menus.
     */
    void ApplyMenuFlagParam(std::int32_t commandId, std::int32_t parameter);

    [[nodiscard]] bool& MenuCheck(std::int32_t commandId);
    void ShowFileDialog(FilePick purpose, const char* title, const char* defaultDirectory, bool save);
    void OnFileChosen(FilePick purpose, const fa::string& path);
    void DrawMenuBar();
    void HandleShortcuts();

  public:
    Sim* mSim = nullptr;
    Wm3::Vector3f mSpawnPosition;
    // The text fields (the binary's window ids 556, 557, 559, 560, 563, 565).
    std::array<char, 32> mLifetimeText{};
    std::array<char, 32> mRepeatTimeText{};
    std::array<char, 32> mTextureFrameCountText{};
    std::array<char, 32> mTextureStripCountText{};
    std::array<char, 32> mSortOrderText{};
    std::array<char, 32> mLodCutoffText{};
    bool mPlaying = true;
    int mTimeSliderValue = 0;
    int mTimeSliderMax = 100;
    bool mControlsBuilt = false;
    int mBlendModeSelection = 3;
    int mFidelitySelection = 6;
    // UTF-8 VFS paths of the particle texture and the ramp.
    fa::string mTexturePath;
    fa::string mRampTexturePath;
    // Where the blueprint and texture file dialogs open, and where they were last closed.
    fa::string mBlueprintDirectory;
    fa::string mTextureDirectory;
    // The repeat time last pushed into the effect and the curve editors' time axes; -1 after
    // the effect is recreated, so the next refresh pushes it again.
    double mCachedRepeatTime = 1.0;
    // Raised by LoadFromEffect so the control writes do not refresh the effect.
    bool mRefreshGuard = false;
    std::vector<std::unique_ptr<WCurveEditorPanel>> mCurvePanels; // one per EEmitterCurve
    WeakPtr<IEffect> mPreviewEffect;
    WeakPtr<Unit> mAttachedUnit;
    fa::string mBoneName;
    fa::string mBlueprintName; // VFS name of the loaded blueprint
    // The Options and LOD menus' check items, by command id - kMenuLocalVelocity.
    std::array<bool, kMenuParticleResistance - kMenuLocalVelocity + 1> mMenuChecks{};
    // The blueprint file last opened or saved: full path (also the title) and bare file name.
    fa::string mBlueprintPath;
    fa::string mBlueprintFileName;

  private:
    std::shared_ptr<PendingPick> mPendingPick;
    FilePick mPickInFlight = FilePick::None;
    bool mCloseRequested = false;
  };
} // namespace moho

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
  class IUnit;
  class Sim;
  class Unit;
  class UserEntity;

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

  /**
   * `WCurveEditor` (curve widget), `WCurveEditorPanel` (key/range field
   * panel wrapping one editor) and their `CurveEnvelopeColumn` paint helper
   * are recovered in `moho/app/WxRuntimeTypes.h` alongside `WSupComFrame`
   * and friends - `WCurveEditorPanel` needs to be visible there so other
   * wx-runtime consumers can reference it without pulling in this
   * WEmitterWx-specific header. This pass connected the pre-existing
   * behavior methods below to the real constructors
   * (`Moho::WCurveEditor::WCurveEditor`, `Moho::WCurveEditorPanel::WCurveEditorPanel`);
   * they previously lived here under the working names `WEmitterCurveEditor`
   * / `WEmitterCurvePanel` before either constructor had callsite evidence
   * to recover against.
   */

  struct WEmitterWx : WWinManagedFrame
  {
    /**
     * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
     * Mangled: ??0WEmitterWx@Moho@@QAE@@Z
     *
     * IDA signature:
     * Moho::WEmitterWx *__thiscall Moho::WEmitterWx::WEmitterWx(
     *   UserEntity *attachEntity@<ecx>, Moho::WEmitterWx *this, float *spawnPosition,
     *   char *boneName);
     * (IDA's own `this`/`a2` labels are swapped from real C++ ABI, same as
     * `WCurveEditor::WCurveEditor` - `a2` on the stack is the actual
     * constructed object.)
     *
     * `attachEntity` is a *user-side* entity, not a sim-side `IUnit`: the sole
     * caller (`Moho::EFX_CreateEmitterWindow`, 0x00669EB0) decodes it out of
     * `sWldSession->mSelection`, whose weak-set nodes hold
     * `&UserEntity::mIUnitChainHead` (+0x08), and the constructor reads
     * `[attachEntity+0x44]` at 0x00663ACF - `UserEntity::mParams.mEntityId`.
     *
     * What it does:
     * Builds the top-level "Emitter Editor" frame (800x600,
     * `WWinManagedFrame::WWinManagedFrame`), resolves `attachEntity` into the
     * weak `mAttachedUnit` link by looking its entity id up in the active
     * sim's `CEntityDb` and taking that sim entity's `IsUnit()` view (unlinked
     * when `attachEntity` is null or the id is not a live sim unit), stores
     * `boneName` into `mBoneName` when given, seeds the default particle/ramp
     * texture paths, builds the File/Options/LOD menu bar (each item wired to
     * `OnMenuCommand` through the shared command-sink event table), resolves
     * the initial preview effect (attached-to-entity or free-standing at
     * `spawnPosition`), and lays out the scalar/flag/texture controls plus one
     * `WCurveEditorPanel` notebook tab per animatable curve before finishing
     * with a `RefreshPreviewEmitter` pass.
     */
    WEmitterWx(UserEntity* attachEntity, const Wm3::Vector3f& spawnPosition, const char* boneName);

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
     * Address: 0x00667860 (FUN_00667860)
     *
     * What it does:
     * Repopulates the editor UI from the live preview effect -- texture paths
     * and every curve panel -- guarded so the writes do not echo back.
     */
    void LoadFromEffect();

    /**
     * Address: 0x00668B00 (FUN_00668B00)
     *
     * What it does:
     * The emitter editor's menu/command sink: the file-open, texture-browse,
     * ramp-browse and save-as dialogs plus the parameter toggles, each
     * followed by a preview refresh.
     */
    void OnMenuCommand(wxEventRuntime& commandEvent);

  private:
    bool RunEmitterFileDialog(
      const char* vfsRoot,
      const wchar_t* title,
      const wchar_t* wildcard,
      wxStringRuntime& startingDirectory
    );

    void ToggleEffectParameterFlag(std::int32_t parameterIndex);

  public:

    /**
     * Address: 0x00668340 (FUN_00668340)
     *
     * What it does:
     * Writes the emitter blueprint out as a Lua script: opens the destination
     * file, formats the header, every parameter, both texture paths and each
     * curve block, then closes the stream.
     */
    void WriteBlueprintScript(const wchar_t* filePath, const wchar_t* blueprintId);

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
    msvc8::vector<WCurveEditorPanel*> mCurvePanels;             // +0x1E4
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

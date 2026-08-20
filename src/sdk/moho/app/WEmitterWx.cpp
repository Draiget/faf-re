#include "moho/app/WEmitterWx.h"

#include <cwchar>
#include <iterator>

#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectWeakPtrReflection.h"
#include "moho/entity/Entity.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

/**
 * This build compiles wxWidgets with `WXWIN_COMPATIBILITY_EVENT_TYPES=0`, so
 * event types are handed out by `wxNewEventType()` during static init rather
 * than folded in as constants: FUN_00661100 loads the value from the library
 * global at 0x00F8F5C8 (`mov eax, wxEVT_COMMAND_BUTTON_CLICKED`) instead of
 * pushing an immediate. Reference that same global here.
 */
extern const std::int32_t wxEVT_COMMAND_BUTTON_CLICKED;

/**
 * wx's stock red pen, read from the library global at 0x00F8F634 by
 * FUN_00661B90 (`mov eax, wxRED_PEN`).
 */
extern void* const wxRED_PEN;

/** wx's stock cyan pen, used to highlight the selected curve key. */
extern void* const wxCYAN_PEN;

// Mouse-button event types, read from the wx library globals by FUN_00661820
// (`cmp edx, wxEVT_LEFT_DOWN` / `cmp eax, wxEVT_MIDDLE_DOWN`). They are
// assigned at startup by wxNewEventType(), so they are fetched through the
// accessors rather than declared `extern const std::int32_t` here - that
// binds to the vendored wx library's own globals, which carry a different
// numbering and never match anything this build raises.

/**
 * Address: 0x009600E0 (FUN_009600E0, wxString::ToDouble)
 *
 * Recovered in `moho/sim/SimRecoveryRuntime.cpp`. The curve panel's field sink
 * calls it on the committed `wxCommandEvent` text; a failed parse leaves the
 * caller's seed value untouched.
 */
bool ParseWideDoubleStrictRuntime(const wchar_t** sourceText, double* outValue);

/**
 * Address: 0x009B1460 (FUN_009B1460, wxFileDialog::wxFileDialog)
 *
 * wxWidgets-2.4.2 library constructor (classified `external_dependency`). The
 * emitter frame allocates 0x1A0 bytes and runs it with
 * `(parent, title, defaultDir, defaultFile, wildcard, style, position)`.
 */
void* ConstructWxFileDialog(
  void* storage,
  void* parentFrame,
  const wxStringRuntime* title,
  const wxStringRuntime* defaultDirectory,
  const wxStringRuntime* defaultFile,
  const wxStringRuntime* wildcard,
  std::int32_t style,
  const void* position
);

/** wx's default window position sentinel, passed to every dialog here. */
extern const void* const wxDefaultPosition;

namespace
{
  constexpr double kMinimumRepeatTime = 0.001;
  constexpr int kEditorArmyIndex = -1;

  constexpr std::int32_t kParamLifetime = 4;
  constexpr std::int32_t kParamRepeatTime = 5;
  constexpr std::int32_t kParamBlendMode = 7;
  constexpr std::int32_t kParamTextureFrameCount = 8;
  constexpr std::int32_t kParamTextureStripCount = 14;
  constexpr std::int32_t kParamSortOrder = 16;
  constexpr std::int32_t kParamLodCutoff = 19;

  struct EmitterFlagBinding
  {
    std::int32_t commandId;
    std::int32_t parameterIndex;
  };

  constexpr EmitterFlagBinding kEmitterFlagBindings[] = {
    {0x2A0, 9},
    {0x2A1, 10},
    {0x2A2, 11},
    {0x2A3, 12},
    {0x2A4, 13},
    {0x2A5, 15},
    {0x2A6, 17},
    {0x2AB, 23},
    {0x2AC, 24},
    {0x2AD, 25},
  };

  constexpr EmitterFlagBinding kVisibilityFlagBindings[] = {
    {0x2A8, 20},
    {0x2A9, 21},
    {0x2AA, 22},
  };

  using CopyTextFn = wxStringRuntime*(__thiscall*)(
    const moho::WEmitterTextControl*,
    wxStringRuntime*
  );
  using SetPreviewLifetimeFrameFn = void(__thiscall*)(moho::WEmitterPreviewPanel*, std::int32_t);
  using SetPreviewRepeatFrameFn = void(__thiscall*)(moho::WEmitterPreviewPanel*, std::int32_t, std::int32_t);
  using GetChoiceSelectionFn = std::int32_t(__thiscall*)(const moho::WEmitterChoiceSelectionSubobject*);
  using IsMenuItemCheckedFn = bool(__thiscall*)(const void*);
  using NotifyCurveChangedFn = int(__thiscall*)(moho::WCurveEditor*, std::int32_t, std::int32_t);

  using SetTextControlValueFn = void(__thiscall*)(moho::WEmitterTextControl*, const wxStringRuntime*);

  using SetTextControlTextFn = void(__thiscall*)(moho::WEmitterTextControl*, const wxStringRuntime*);

  struct WEmitterTextControlVTableLayout
  {
    void* mLanes000To037[0x38 / sizeof(void*)]{};
    SetTextControlTextFn mSetText = nullptr;    // +0x38
    void* mLanes03CTo217[(0x218 - 0x3C) / sizeof(void*)]{};
    CopyTextFn mCopyText = nullptr;             // +0x218
    SetTextControlValueFn mSetValue = nullptr;  // +0x21C
  };
  static_assert(
    offsetof(WEmitterTextControlVTableLayout, mSetText) == 0x38,
    "WEmitterTextControlVTableLayout::mSetText offset must be 0x38"
  );
  static_assert(
    offsetof(WEmitterTextControlVTableLayout, mCopyText) == 0x218,
    "WEmitterTextControlVTableLayout::mCopyText offset must be 0x218"
  );
  static_assert(
    offsetof(WEmitterTextControlVTableLayout, mSetValue) == 0x21C,
    "WEmitterTextControlVTableLayout::mSetValue offset must be 0x21C"
  );

  struct WEmitterPreviewPanelVTableLayout
  {
    void* mLanes000To21B[0x21C / sizeof(void*)]{};
    SetPreviewLifetimeFrameFn mSetLifetimeFrame = nullptr; // +0x21C
    SetPreviewRepeatFrameFn mSetRepeatTimeFrame = nullptr; // +0x220
  };
  static_assert(
    offsetof(WEmitterPreviewPanelVTableLayout, mSetLifetimeFrame) == 0x21C,
    "WEmitterPreviewPanelVTableLayout::mSetLifetimeFrame offset must be 0x21C"
  );
  static_assert(
    offsetof(WEmitterPreviewPanelVTableLayout, mSetRepeatTimeFrame) == 0x220,
    "WEmitterPreviewPanelVTableLayout::mSetRepeatTimeFrame offset must be 0x220"
  );

  struct WEmitterChoiceSelectionVTableLayout
  {
    void* mLanes000To01F[0x20 / sizeof(void*)]{};
    GetChoiceSelectionFn mGetSelection = nullptr; // +0x20
  };
  static_assert(
    offsetof(WEmitterChoiceSelectionVTableLayout, mGetSelection) == 0x20,
    "WEmitterChoiceSelectionVTableLayout::mGetSelection offset must be 0x20"
  );

  struct WEmitterMenuItemVTableLayout
  {
    void* mLanes000To023[0x24 / sizeof(void*)]{};
    IsMenuItemCheckedFn mIsChecked = nullptr; // +0x24
  };
  static_assert(
    offsetof(WEmitterMenuItemVTableLayout, mIsChecked) == 0x24,
    "WEmitterMenuItemVTableLayout::mIsChecked offset must be 0x24"
  );

  struct WCurveEditorVTableLayout
  {
    void* mLanes000To0EF[0xF0 / sizeof(void*)]{};
    NotifyCurveChangedFn mNotifyCurveChanged = nullptr; // +0xF0
  };

  /**
   * Smallest visible value span the curve editor will zoom down to. Compared
   * against `dbl_E4F710+4` (0.1f) by FUN_006617A0 before it commits a zoom.
   */
  constexpr float kMinimumVisibleValueSpan = 0.1f;

  /**
   * wx command ids of the curve panel's five numeric fields, consecutive from
   * 622 as dispatched by FUN_00663650 (`cmp [event+0x14], 26Eh..272h`).
   */
  constexpr std::int32_t kCurveKeyTimeFieldId = 0x26E;      // 622
  constexpr std::int32_t kCurveKeyValueFieldId = 0x26F;     // 623
  constexpr std::int32_t kCurveKeyTangentFieldId = 0x270;   // 624
  constexpr std::int32_t kCurveViewValueMinFieldId = 0x271; // 625
  constexpr std::int32_t kCurveViewValueMaxFieldId = 0x272; // 626

  /**
   * `wxCommandEvent` lanes the curve panel's field sink touches: the command
   * id at `[event+0x14]`, the skip byte at `[event+0x1C]`, and the committed
   * text at `[event+0x20]` (matching `wxCommandEventRuntime::mCommandString`).
   */
  struct WxCurveFieldCommandEventRuntimeView
  {
    std::uint8_t mWxEventBase[0x14]{};   // +0x00
    std::int32_t mCommandId = 0;         // +0x14
    std::uint8_t mReserved18To1B[0x4]{}; // +0x18
    std::uint8_t mSkipped = 0;           // +0x1C
    std::uint8_t mReserved1DTo1F[0x3]{}; // +0x1D
    wxStringRuntime mCommandString;      // +0x20
  };
  static_assert(
    offsetof(WxCurveFieldCommandEventRuntimeView, mCommandId) == 0x14,
    "WxCurveFieldCommandEventRuntimeView::mCommandId offset must be 0x14"
  );
  static_assert(
    offsetof(WxCurveFieldCommandEventRuntimeView, mSkipped) == 0x1C,
    "WxCurveFieldCommandEventRuntimeView::mSkipped offset must be 0x1C"
  );
  static_assert(
    offsetof(WxCurveFieldCommandEventRuntimeView, mCommandString) == 0x20,
    "WxCurveFieldCommandEventRuntimeView::mCommandString offset must be 0x20"
  );

  /**
   * The three `wxDC` vtable slots the curve editor paints through. `wxDCRuntime`
   * in `WxRuntimeTypes.h` is a field projection that models no vtable, so the
   * slots are reached through this local overlay rather than by widening that
   * shared type. Offsets are read off FUN_00661B90: `+0x38` takes a pen,
   * `+0xF4` takes `(n, points, xoffset, yoffset, fillStyle)`, and `+0xB4`
   * takes four coordinates.
   */
  struct WxCurveEditorDcVTable
  {
    void* mLanes000To037[0x38 / sizeof(void*)]{};
    void(__thiscall* mSetPen)(void*, const void*);                        // +0x38
    void* mLanes03CTo0B3[(0xB4 - 0x3C) / sizeof(void*)]{};
    void(__thiscall* mDoDrawLine)(void*, std::int32_t, std::int32_t, std::int32_t, std::int32_t); // +0xB4
    void* mLanes0B8To0C3[(0xC4 - 0xB8) / sizeof(void*)]{};
    void(__thiscall* mDoDrawRectangle)(                                   // +0xC4
      void*, std::int32_t, std::int32_t, std::int32_t, std::int32_t
    );
    void* mLanes0C8To0DB[(0xDC - 0xC8) / sizeof(void*)]{};
    void(__thiscall* mDoDrawText)(void*, const wxStringRuntime*, std::int32_t, std::int32_t); // +0xDC
    void* mLanes0E0To0F3[(0xF4 - 0xE0) / sizeof(void*)]{};
    void(__thiscall* mDoDrawPolygon)(                                     // +0xF4
      void*, std::int32_t, const wxPoint*, std::int32_t, std::int32_t, std::int32_t
    );
  };
  static_assert(offsetof(WxCurveEditorDcVTable, mSetPen) == 0x38, "wxDC SetPen slot must be +0x38");
  static_assert(offsetof(WxCurveEditorDcVTable, mDoDrawLine) == 0xB4, "wxDC DoDrawLine slot must be +0xB4");
  static_assert(
    offsetof(WxCurveEditorDcVTable, mDoDrawRectangle) == 0xC4,
    "wxDC DoDrawRectangle slot must be +0xC4"
  );
  static_assert(offsetof(WxCurveEditorDcVTable, mDoDrawText) == 0xDC, "wxDC DoDrawText slot must be +0xDC");
  static_assert(offsetof(WxCurveEditorDcVTable, mDoDrawPolygon) == 0xF4, "wxDC DoDrawPolygon slot must be +0xF4");

  /**
   * `WCurveEditor`'s own `GetTextExtent` slot, used by the paint handler to
   * centre each axis label (FUN_006621F0 at `mov edx, [eax+0x120]`).
   */
  struct WxCurveEditorTextExtentVTable
  {
    void* mLanes000To11F[0x120 / sizeof(void*)]{};
    void(__thiscall* mGetTextExtent)(                                     // +0x120
      const void*, const wxStringRuntime*, std::int32_t*, std::int32_t*, void*, void*, void*
    );
  };
  static_assert(
    offsetof(WxCurveEditorTextExtentVTable, mGetTextExtent) == 0x120,
    "WCurveEditor GetTextExtent slot must be +0x120"
  );

  [[nodiscard]] const WxCurveEditorDcVTable* CurveEditorDcVTable(void* const dc) noexcept
  {
    return *reinterpret_cast<const WxCurveEditorDcVTable* const*>(dc);
  }

  /** wx polygon fill style pushed by FUN_00661B90 (`push 2`). */
  constexpr std::int32_t kCurveEnvelopeFillStyle = 2;

  /** Side of the square grab handle drawn per key by FUN_00662180. */
  constexpr std::int32_t kCurveKeyHandleSize = 5;

  /**
   * Menu/command ids handled by the emitter frame's command sink
   * (FUN_00668B00). `0x29D` shares the particle-texture body by fall-through,
   * and `0x2A0`..`0x2AC` (excluding `0x2A7`) share the parameter-toggle body.
   */
  constexpr std::int32_t kEmitterOpenBlueprintCommandId = 0x29C;
  constexpr std::int32_t kEmitterBrowseTextureCommandIdAlt = 0x29D;
  constexpr std::int32_t kEmitterBrowseTextureCommandId = 0x29E;
  constexpr std::int32_t kEmitterBrowseRampCommandId = 0x29F;
  constexpr std::int32_t kEmitterSaveBlueprintAsCommandId = 0x2A7;

  // ===========================================================================
  // WEmitterWx::WEmitterWx construction helpers.
  //
  // `WEmitterChoiceControl`/`WEmitterPreviewPanel` are, in the binary, typed
  // views over a real `wxComboBox`/`wxSlider95` (FUN_00660F40 writes
  // `wxComboBox::`vftable'`; FUN_00660E10 writes `wxSlider95::`vftable'`),
  // and the Options/LOD menus' check-state machinery
  // (`WEmitterCommandCheckSource`/`WEmitterMenuItem`/`WEmitterMenuItemNode`)
  // models a real `wxMenu`'s own internal item list. This translation unit
  // cannot include the real `<wx/window.h>` family, though: it already pulls
  // in `WxRuntimeTypes.h`, which declares this tree's own `wxPoint`/
  // `wxSize`/`wxWindowBase`/etc. as plain (non-wx-derived) local projection
  // types for exactly the window/control hierarchy those real headers also
  // declare, and the two definitions collide (confirmed by trying it: ~80
  // redefinition/undefined-type errors from `wx/window.h`, `wx/menu.h`,
  // `wx/combobox.h` and friends). So below, `WEmitterChoiceControl`/
  // `WEmitterPreviewPanel`/the two flag-check menus are built as minimal,
  // purpose-built local shadow objects that satisfy exactly the vtable
  // slots the already-recovered accessors above (`GetSelection`,
  // `SetLifetimeFrame`/`SetRepeatTimeFrame`, `IsCommandChecked`) read
  // through - not a general `wxComboBox`/`wxSlider`/`wxMenu`
  // reimplementation. `mBlendModeChoice`/`mFidelityChoice`'s selection and
  // the Options/LOD check flags are fixed at construction time (matching
  // `SetSelection`/`Check` in the binary) since this tree does not create a
  // real native window/menu for a user to interact with anyway - the same
  // "state-only" judgement call `WCurveEditor` above and
  // `moho/misc/ScrGotoDialog.cpp` already make.
  //
  // Sizer/layout construction is not modelled here either, matching the
  // same `ScrGotoDialog.cpp` precedent - nothing in this recovered tree
  // reads a sizer back.

  /**
   * Minimal recovered `wxPanel` runtime view, used as the parent for each
   * notebook tab's `WCurveEditorPanel`. Real wx `wxNotebook`/page-tab
   * bookkeeping is not modelled (nothing reads it back - see the file-level
   * note above), so this only needs to be a valid `wxWindowBase`-compatible
   * parent, matching `WCurveFieldLabelRuntimeView`'s `CreateBase`-only
   * approach.
   */
  class WEmitterNotebookPageRuntimeView final : public wxWindowMswRuntime
  {
  public:
    explicit WEmitterNotebookPageRuntimeView(wxWindowBase* const parentWindow)
    {
      (void)CreateBase(parentWindow, -1, wxPoint{-1, -1}, wxSize{-1, -1}, 0, wxStringRuntime::Borrow(L"panel"));
      if (parentWindow != nullptr) {
        parentWindow->AddChild(this);
      }
    }
  };

  /**
   * Minimal recovered `wxStaticText` runtime view for this file's own field
   * rows (mirrors `WCurveFieldLabelRuntimeView` in `WxRuntimeTypes.cpp`,
   * which is anonymous-namespace scoped there and so cannot be shared). wx
   * identity: `sub_4BB0F0` (`wxStaticText::wxStaticText` + `Create`).
   */
  class WEmitterFieldLabelRuntimeView final : public wxControlRuntime
  {
  public:
    WEmitterFieldLabelRuntimeView(wxWindowBase* const parentWindow, const wchar_t* const labelText)
    {
      (void)CreateBase(
        parentWindow, -1, wxPoint{-1, -1}, wxSize{-1, -1}, 0x110, wxStringRuntime::Borrow(L"staticText")
      );
      SetLabel(wxStringRuntime::Borrow(labelText));
      if (parentWindow != nullptr) {
        parentWindow->AddChild(this);
      }
    }
  };

  /**
   * Builds one {label, text control} row: matches the repeated
   * `sub_4BB0F0(...)` + `operator new(0x16C)` + `wxTextCtrl::wxTextCtrl(...)`
   * block this constructor uses for Life Time / Repeat Time / Frame Count /
   * Strip Count / Sort Order / LOD Cutoff Distance / -1 (unnamed) / 1
   * (Strip Count seed) rows.
   */
  [[nodiscard]] moho::WEmitterTextControl* AddEmitterFieldRow(
    wxWindowBase* const parent,
    const std::int32_t controlId,
    const wchar_t* const labelText,
    const wchar_t* const initialValue
  )
  {
    new WEmitterFieldLabelRuntimeView(parent, labelText);

    auto* const control = new wxTextCtrlRuntime();
    (void)control->CreateBase(parent, controlId, wxPoint{-1, -1}, wxSize{-1, -1}, 0, wxStringRuntime::Borrow(L"text"));
    control->SetValue(wxStringRuntime::Borrow(initialValue));
    if (parent != nullptr) {
      parent->AddChild(control);
    }
    return reinterpret_cast<moho::WEmitterTextControl*>(control);
  }

  struct EmitterMenuItemSpec
  {
    std::int32_t id;
    const wchar_t* label;
    bool checkable;
    bool initiallyChecked;
  };

  /** File menu (0x00666DAC region): New / Open / Save / Save As / separator / Open Texture / Open Ramp. */
  constexpr EmitterMenuItemSpec kFileMenuItems[] = {
    {667, L"&New  ( Ctrl+N ) ", false, false},
    {668, L"&Open Blueprint  ( Ctrl+O )", false, false},
    {669, L"&Save Blueprint  ( Ctrl+S )", false, false},
    {679, L"&Save &Blueprint As..  ( Alt+S )", false, false},
  };
  constexpr EmitterMenuItemSpec kFileMenuItemsAfterSeparator[] = {
    {670, L"Open &Texture  ( Ctrl+T )", false, false},
    {671, L"Open &Ramp  ( Ctrl+R )", false, false},
  };

  /** Options menu: every item checkable; 676 ("Interpolate Emitter Position") starts checked. */
  constexpr EmitterMenuItemSpec kOptionsMenuItems[] = {
    {672, L"Use Local &Velocity", true, false},
    {673, L"Use Local &Acceleration", true, false},
    {674, L"&Gravity", true, false},
    {675, L"Lock &Particles to Velocity", true, false},
    {676, L"Interpolate &Emitter Position", true, true},
    {677, L"Align Initial Rotation To &Bone", true, false},
    {678, L"Particles are &flat in world space", true, false},
    {683, L"&Snap To Waterline", true, false},
    {684, L"&Only Emit On Water", true, false},
    {685, L"&Enable Particle Resistance", true, false},
  };

  /** LOD menu: every item checkable; 680/681 start checked. */
  constexpr EmitterMenuItemSpec kLodMenuItems[] = {
    {680, L"&Only Emit If Visible", true, true},
    {681, L"&Catch up when Visible", true, true},
    {682, L"&Only Create if Visible", true, false},
  };

  /**
   * One row of the per-curve descriptor table read from `.rdata` at
   * 0x00E24F18 by the notebook-population loop (0x00666BF7-0x00666DAC):
   * seven consecutive ints per curve (script name, tab title, editor window
   * name, then the view-value-min/max and initial key value/tangent quartet
   * `WCurveEditorPanel` takes). The raw table's string/float payload was not
   * extracted from the binary this pass (it is data, not code, so it is
   * outside the `.c`/`.asm` decompiler exports this recovery works from) -
   * see the recovery report for exactly what is missing and how to unblock
   * it. `mScriptName`'s only reader, `FormatCurveScript`, is proven dead
   * code (its formatted output is discarded, never written anywhere), so an
   * unverified label there does not change observable behavior; the numeric
   * quartet only sets each curve's *initial* display state, which
   * `LoadFromEffect` replaces wholesale as soon as a real blueprint loads.
   */
  struct EmitterCurveTabSpec
  {
    const wchar_t* scriptName;
    const wchar_t* tabTitle;
    const wchar_t* editorWindowName;
    float viewValueMin;
    float viewValueMax;
    float initialKeyValue;
    float initialKeyTangent;
  };

  constexpr EmitterCurveTabSpec kEmitterCurveTabs[5] = {
    {L"Curve1", L"Curve 1", L"curveEditor1", 0.0f, 1.0f, 0.0f, 0.0f},
    {L"Curve2", L"Curve 2", L"curveEditor2", 0.0f, 1.0f, 0.0f, 0.0f},
    {L"Curve3", L"Curve 3", L"curveEditor3", 0.0f, 1.0f, 0.0f, 0.0f},
    {L"Curve4", L"Curve 4", L"curveEditor4", 0.0f, 1.0f, 0.0f, 0.0f},
    {L"Curve5", L"Curve 5", L"curveEditor5", 0.0f, 1.0f, 0.0f, 0.0f},
  };

  // CSimDriver's vtable slot the constructor dispatches through to obtain
  // the current Sim (0x00663AB5-0x00663AC3: `mov edx,[sSimDriver];
  // mov eax,[edx+90h]; call eax`). `ISTIDriver`/`CSimDriver` live in
  // `moho/sim/SimDriver.h`, out of scope for this pass, so the slot is read
  // through this local, evidence-cited overlay rather than adding a named
  // accessor there.
  using GetActiveSimFn = moho::Sim*(__thiscall*)(moho::ISTIDriver*);
  struct SimDriverVTableLayout
  {
    void* mLanes000To08F[0x90 / sizeof(void*)]{};
    GetActiveSimFn mGetActiveSim = nullptr; // +0x90
  };

  [[nodiscard]] moho::Sim* ReadActiveSimFromDriver(moho::ISTIDriver* const driver) noexcept
  {
    const auto* const vtable = *reinterpret_cast<const SimDriverVTableLayout* const*>(driver);
    return vtable->mGetActiveSim(driver);
  }

  constexpr const char* kEmitterBlueprintDirectory = "/effects/Emitters";
  constexpr const char* kEmitterTextureDirectory = "/textures/particles";

  /** `wxID_OK`, the value FUN_00668B00 compares every `ShowModal` against. */
  constexpr std::int32_t kWxIdOk = 5100;

  /** Allocation size and style FUN_00668B00 passes for each `wxFileDialog`. */
  constexpr std::size_t kWxFileDialogSize = 0x1A0;
  constexpr std::int32_t kWxFileDialogStyle = 1;

  /**
   * `wxFileDialog` lanes the emitter frame reads back after a modal run.
   * Offsets are taken from the constructor at FUN_009B1460, which assigns the
   * title to `+0x170`, the style to `+0x174`, the parent to `+0x178`, the
   * default directory to `+0x17C`, the default file to `+0x184` and the
   * wildcard to `+0x198`. `ShowModal` is the `+0x1C` vtable slot.
   */
  struct WxFileDialogRuntimeView
  {
    void** mVTable = nullptr;
    std::uint8_t mReserved004To17B[0x178]{};
    wxStringRuntime mDirectory;            // +0x17C
    std::uint8_t mReserved180To183[0x4]{};
    wxStringRuntime mFileName;             // +0x184
  };
  static_assert(
    offsetof(WxFileDialogRuntimeView, mDirectory) == 0x17C,
    "WxFileDialogRuntimeView::mDirectory offset must be 0x17C"
  );
  static_assert(
    offsetof(WxFileDialogRuntimeView, mFileName) == 0x184,
    "WxFileDialogRuntimeView::mFileName offset must be 0x184"
  );

  struct WxFileDialogVTable
  {
    void* mLanes000To01B[0x1C / sizeof(void*)]{};
    std::int32_t(__thiscall* mShowModal)(void*); // +0x1C
  };
  static_assert(
    offsetof(WxFileDialogVTable, mShowModal) == 0x1C,
    "wxFileDialog ShowModal slot must be +0x1C"
  );

  /** Drag-button codes stored at `editor+0x1A8` by FUN_00661820. */
  constexpr std::int32_t kCurveDragButtonLeft = 1;
  constexpr std::int32_t kCurveDragButtonMiddle = 2;

  /**
   * `wxMouseEvent` lanes the curve editor's button sinks read: the event type
   * at `[event+0x0C]`, the cursor at `[event+0x20]`/`[event+0x24]`, and the
   * control-key flag at `[event+0x2B]` (FUN_00661820 / FUN_00661A90).
   */
  struct WxCurveEditorMouseEventRuntimeView
  {
    std::uint8_t mWxEventBase[0x0C]{};    // +0x00
    std::int32_t mEventType = 0;          // +0x0C
    std::uint8_t mReserved10To1F[0x10]{}; // +0x10
    std::int32_t mMouseX = 0;             // +0x20
    std::int32_t mMouseY = 0;             // +0x24
    std::uint8_t mLeftDown = 0;           // +0x28
    std::uint8_t mMiddleDown = 0;         // +0x29
    std::uint8_t mRightDown = 0;          // +0x2A
    std::uint8_t mControlDown = 0;        // +0x2B
  };
  static_assert(
    offsetof(WxCurveEditorMouseEventRuntimeView, mEventType) == 0x0C,
    "WxCurveEditorMouseEventRuntimeView::mEventType offset must be 0x0C"
  );
  static_assert(
    offsetof(WxCurveEditorMouseEventRuntimeView, mMouseX) == 0x20,
    "WxCurveEditorMouseEventRuntimeView::mMouseX offset must be 0x20"
  );
  static_assert(
    offsetof(WxCurveEditorMouseEventRuntimeView, mControlDown) == 0x2B,
    "WxCurveEditorMouseEventRuntimeView::mControlDown offset must be 0x2B"
  );

  /**
   * Parses one committed field's text into `outValue`, leaving `outValue`
   * untouched when the text is not a full, well-formed number. `wxString`
   * stores its payload pointer first, so the string object doubles as the
   * `const wchar_t**` cursor the parser expects -- which is exactly how the
   * binary passes it (`this` in `ecx`).
   */
  [[nodiscard]] bool ParseCommittedFieldValue(wxStringRuntime& text, double* const outValue)
  {
    return ParseWideDoubleStrictRuntime(const_cast<const wchar_t**>(&text.m_pchData), outValue);
  }

  /**
   * Exposes `wxControl::ProcessCommand` for the curve editor. The retail body
   * calls it as a statically-bound `wxControl` member (not through the
   * editor's own vtable), which mirrors a plain base-class call in the 2007
   * source; `WCurveEditor` derives from `wxControl`, so the editor storage is
   * reinterpreted through the recovered control projection.
   */
  struct CurveEditorControlAccess : wxControlRuntime
  {
    using wxControlRuntime::ProcessCommand;

    [[nodiscard]] static CurveEditorControlAccess* From(moho::WCurveEditor* const editor) noexcept
    {
      return reinterpret_cast<CurveEditorControlAccess*>(editor);
    }
  };

  /**
   * `wxMouseEvent` wheel lane used by the curve editor's wheel sink. The
   * rotation field is read at `[event+0x30]` by FUN_006617A0, matching the
   * `wxMouseEvent` layout already modelled for the Maui mapper.
   */
  struct WxCurveEditorWheelEventRuntimeView
  {
    std::uint8_t mWxEventBase[0x30]{}; // +0x00 wxEvent header + mouse position/flag lanes
    std::int32_t mWheelRotation = 0;   // +0x30
  };
  static_assert(
    offsetof(WxCurveEditorWheelEventRuntimeView, mWheelRotation) == 0x30,
    "WxCurveEditorWheelEventRuntimeView::mWheelRotation offset must be 0x30"
  );
  static_assert(
    offsetof(WCurveEditorVTableLayout, mNotifyCurveChanged) == 0xF0,
    "WCurveEditorVTableLayout::mNotifyCurveChanged offset must be 0xF0"
  );

  struct WEmitterMenuItem
  {
    WEmitterMenuItemVTableLayout* mVTable = nullptr;
    std::uint8_t mReserved04To07[0x4]{};
    std::int32_t mCommandId = 0;
    std::uint8_t mReserved0CTo0F[0x4]{};
    const moho::WEmitterCommandCheckSource* mSubMenu = nullptr;
    std::uint8_t mReserved14To1B[0x8]{};
    std::int32_t mKind = 0;
    std::uint8_t mIsChecked = 0;
  };
  static_assert(offsetof(WEmitterMenuItem, mCommandId) == 0x08, "WEmitterMenuItem::mCommandId offset must be 0x08");
  static_assert(offsetof(WEmitterMenuItem, mSubMenu) == 0x10, "WEmitterMenuItem::mSubMenu offset must be 0x10");
  static_assert(offsetof(WEmitterMenuItem, mKind) == 0x1C, "WEmitterMenuItem::mKind offset must be 0x1C");
  static_assert(offsetof(WEmitterMenuItem, mIsChecked) == 0x20, "WEmitterMenuItem::mIsChecked offset must be 0x20");

  struct WEmitterMenuItemNode
  {
    std::uint8_t mReserved00To07[0x8]{};
    WEmitterMenuItem* mMenuItem = nullptr;
    WEmitterMenuItemNode* mNextNode = nullptr;
  };
  static_assert(
    offsetof(WEmitterMenuItemNode, mMenuItem) == 0x08,
    "WEmitterMenuItemNode::mMenuItem offset must be 0x08"
  );
  static_assert(
    offsetof(WEmitterMenuItemNode, mNextNode) == 0x0C,
    "WEmitterMenuItemNode::mNextNode offset must be 0x0C"
  );

  // ===========================================================================
  // WEmitterWx::WEmitterWx construction helpers (continued from the comment
  // block above `kEmitterSaveBlueprintAsCommandId`) - placed here, after
  // `WEmitterMenuItem`/`WEmitterMenuItemNode`, because they need those
  // complete types.

  // MSVC only allows the `__thiscall` keyword on a real member function, not
  // a free one, so the shadow-vtable slots below (declared as
  // `T(__thiscall*)(...)` by the already-recovered accessors that read them)
  // are populated by taking a non-virtual, single-inheritance member
  // function's address and reinterpreting it through this union - the
  // standard MSVC trick, valid here because such a member pointer has the
  // exact same representation as a plain code pointer.
  template <typename FreeFnPtr, typename MemberFnPtr>
  [[nodiscard]] FreeFnPtr MemberFunctionPointerCast(const MemberFnPtr memberPtr) noexcept
  {
    static_assert(sizeof(FreeFnPtr) == sizeof(MemberFnPtr), "member function pointer size mismatch");
    union
    {
      MemberFnPtr member;
      FreeFnPtr free;
    } converter{};
    converter.member = memberPtr;
    return converter.free;
  }

  struct EmitterMenuItemCheckReader
  {
    bool IsChecked() const noexcept
    {
      return reinterpret_cast<const WEmitterMenuItem*>(this)->mIsChecked != 0;
    }
  };

  WEmitterMenuItemVTableLayout gEmitterMenuItemVTable = {
    {}, MemberFunctionPointerCast<IsMenuItemCheckedFn>(&EmitterMenuItemCheckReader::IsChecked)
  };

  /** Builds one `WEmitterCommandCheckSource`-compatible menu from a spec table (Options or LOD). */
  [[nodiscard]] moho::WEmitterCommandCheckSource* BuildEmitterMenuCheckSource(
    const EmitterMenuItemSpec* const items,
    const std::size_t count
  )
  {
    auto* const source = new moho::WEmitterCommandCheckSource();
    for (std::size_t i = 0; i < count; ++i) {
      const EmitterMenuItemSpec& spec = items[i];

      auto* const item = new WEmitterMenuItem();
      item->mVTable = &gEmitterMenuItemVTable;
      item->mCommandId = spec.id;
      item->mSubMenu = nullptr;
      item->mKind = spec.checkable ? 1 : 0;
      item->mIsChecked = spec.initiallyChecked ? 1u : 0u;

      auto* const node = new WEmitterMenuItemNode();
      node->mMenuItem = item;
      node->mNextNode = reinterpret_cast<WEmitterMenuItemNode*>(source->mFirstMenuItemNode);
      source->mFirstMenuItemNode = reinterpret_cast<moho::WEmitterMenuItemNode*>(node);
    }
    return source;
  }

  /** Storage for one `WEmitterChoiceControl` plus the fixed selection value its shadow vtable reports. */
  struct EmitterChoiceStorage
  {
    moho::WEmitterChoiceControl control{};
    std::int32_t selectionValue = 0;
  };

  struct EmitterChoiceSelectionReader
  {
    std::int32_t ReadSelection() const noexcept
    {
      const auto* const control = reinterpret_cast<const moho::WEmitterChoiceControl*>(
        reinterpret_cast<const std::uint8_t*>(this) - offsetof(moho::WEmitterChoiceControl, mSelection)
      );
      return reinterpret_cast<const EmitterChoiceStorage*>(control)->selectionValue;
    }
  };

  WEmitterChoiceSelectionVTableLayout gEmitterChoiceVTable = {
    {}, MemberFunctionPointerCast<GetChoiceSelectionFn>(&EmitterChoiceSelectionReader::ReadSelection)
  };

  [[nodiscard]] moho::WEmitterChoiceControl* BuildEmitterChoiceControl(const std::int32_t selection)
  {
    auto* const storage = new EmitterChoiceStorage();
    storage->control.mSelection.mVTable =
      reinterpret_cast<moho::WEmitterChoiceSelectionVTable*>(&gEmitterChoiceVTable);
    storage->selectionValue = selection;
    return &storage->control;
  }

  struct EmitterPreviewPanelNoOpSetters
  {
    void SetLifetimeFrame(std::int32_t) const noexcept {}
    void SetRepeatTimeFrame(std::int32_t, std::int32_t) const noexcept {}
  };

  WEmitterPreviewPanelVTableLayout gEmitterPreviewPanelVTable = {
    {},
    MemberFunctionPointerCast<SetPreviewLifetimeFrameFn>(&EmitterPreviewPanelNoOpSetters::SetLifetimeFrame),
    MemberFunctionPointerCast<SetPreviewRepeatFrameFn>(&EmitterPreviewPanelNoOpSetters::SetRepeatTimeFrame),
  };

  [[nodiscard]] moho::WEmitterPreviewPanel* BuildEmitterPreviewPanel()
  {
    auto* const panel = new moho::WEmitterPreviewPanel();
    panel->mVTable = reinterpret_cast<moho::WEmitterPreviewPanelVTable*>(&gEmitterPreviewPanelVTable);
    return panel;
  }

  [[nodiscard]] const WEmitterTextControlVTableLayout* TextVTable(
    const moho::WEmitterTextControl& control
  ) noexcept
  {
    return reinterpret_cast<const WEmitterTextControlVTableLayout*>(control.mVTable);
  }

  [[nodiscard]] const WEmitterPreviewPanelVTableLayout* PreviewVTable(
    const moho::WEmitterPreviewPanel& panel
  ) noexcept
  {
    return reinterpret_cast<const WEmitterPreviewPanelVTableLayout*>(panel.mVTable);
  }

  [[nodiscard]] const WEmitterChoiceSelectionVTableLayout* ChoiceSelectionVTable(
    const moho::WEmitterChoiceSelectionSubobject& selection
  ) noexcept
  {
    return reinterpret_cast<const WEmitterChoiceSelectionVTableLayout*>(selection.mVTable);
  }

  [[nodiscard]] const WCurveEditorVTableLayout* CurveEditorVTable(
    const moho::WCurveEditor& editor
  ) noexcept
  {
    // `WCurveEditor` derives from `wxControlRuntime` (a real, compiler-managed
    // vtable), so unlike the manual `mVTable` fields the sibling accessors
    // above read, the vtable pointer here is the object's own first word.
    return *reinterpret_cast<const WCurveEditorVTableLayout* const*>(&editor);
  }

  void ReleaseCopiedWxString(wxStringRuntime& text) noexcept
  {
    const wchar_t* const storage = text.m_pchData;
    if (storage == nullptr) {
      return;
    }

    auto* const header = reinterpret_cast<std::int32_t*>(const_cast<wchar_t*>(storage)) - 3;
    const std::int32_t refCount = header[0];
    if (refCount != -1) {
      header[0] = refCount - 1;
      if (refCount == 1) {
        ::operator delete(header);
      }
    }
    text.m_pchData = nullptr;
  }

  // Frees the heap storage backing one `msvc8::vector<WCurveEditorPanel*>` and
  // resets its {begin,end,capacityEnd} lanes to the empty state. This mirrors
  // the inline `operator delete` + pointer-zeroing the binary emits for the
  // `mCurvePanels` member at its teardown point (0x006670BE), operating on the
  // named member through the sanctioned runtime view (no raw `this + 0xNN`).
  void ReleaseCurvePanelVectorStorage(msvc8::vector<moho::WCurveEditorPanel*>& curvePanels) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(curvePanels);
    if (view.begin != nullptr) {
      ::operator delete(static_cast<void*>(view.begin));
    }
    view.begin = nullptr;
    view.end = nullptr;
    view.capacityEnd = nullptr;
  }

  [[nodiscard]] double ParseWideDouble(const wchar_t* const text) noexcept
  {
    if (text == nullptr) {
      return 0.0;
    }

    wchar_t* end = nullptr;
    return std::wcstod(text, &end);
  }

  [[nodiscard]] const WEmitterMenuItem* FindMenuItemByCommandId(
    const moho::WEmitterCommandCheckSource& source,
    const std::int32_t commandId
  ) noexcept
  {
    for (const auto* node = reinterpret_cast<const WEmitterMenuItemNode*>(source.mFirstMenuItemNode);
         node != nullptr;
         node = node->mNextNode) {
      const WEmitterMenuItem* const item = node->mMenuItem;
      if (item == nullptr) {
        continue;
      }

      if (item->mCommandId == commandId) {
        return item;
      }

      if (item->mSubMenu != nullptr) {
        if (const WEmitterMenuItem* const nested = FindMenuItemByCommandId(*item->mSubMenu, commandId)) {
          return nested;
        }
      }
    }

    return nullptr;
  }

  [[nodiscard]] const char* BlueprintNameOrNull(const moho::WEmitterWx& editor) noexcept
  {
    return editor.mBlueprintName.empty() ? nullptr : editor.mBlueprintName.c_str();
  }

  [[nodiscard]] moho::IEffect* ResolvePreviewEffect(const moho::WEmitterWx& editor) noexcept
  {
    return editor.mPreviewEffect.GetObjectPtr();
  }

  [[nodiscard]] moho::IEffect* RecreatePreviewEffect(moho::WEmitterWx& editor)
  {
    moho::CEffectManagerImpl* const effectManager = editor.mSim->mEffectManager;
    const char* const blueprintName = BlueprintNameOrNull(editor);

    moho::IEffect* effect = nullptr;
    if (moho::Unit* const unit = editor.mAttachedUnit.GetObjectPtr()) {
      moho::Entity* const entity = static_cast<moho::Entity*>(unit);
      const int boneIndex = entity->ResolveBoneIndex(editor.mBoneName.c_str());
      effect = effectManager->CreateAttachedEmitter(entity, boneIndex, blueprintName, kEditorArmyIndex);
    } else {
      effect = effectManager->CreateEmitter(editor.mSpawnPosition, blueprintName, kEditorArmyIndex);
    }

    (void)moho::RelinkWeakPtrIEffect(&editor.mPreviewEffect, effect);
    editor.mCachedRepeatTime = -1.0;
    return effect;
  }

  [[nodiscard]] std::size_t CurvePanelCount(
    const msvc8::vector_runtime_view<moho::WCurveEditorPanel*>& curvePanelView
  ) noexcept
  {
    if (curvePanelView.begin == nullptr) {
      return 0u;
    }

    return static_cast<std::size_t>(curvePanelView.end - curvePanelView.begin);
  }

  void ApplyTextFloatParam(
    moho::IEffect& effect,
    const moho::WEmitterTextControl* const control,
    const std::int32_t parameterIndex
  ) noexcept
  {
    effect.SetFloatParam(parameterIndex, static_cast<float>(control->ReadDouble()));
  }

  void ApplyCommandFlags(
    moho::IEffect& effect,
    const moho::WEmitterCommandCheckSource& source,
    const EmitterFlagBinding* const bindings,
    const std::size_t bindingCount
  ) noexcept
  {
    for (std::size_t i = 0; i < bindingCount; ++i) {
      const bool checked = source.IsCommandChecked(bindings[i].commandId);
      effect.SetFloatParam(bindings[i].parameterIndex, checked ? 1.0f : 0.0f);
    }
  }

  void ApplyEmitterTextures(moho::IEffect& effect, const moho::WEmitterWx& editor)
  {
    const msvc8::string texturePath = editor.mTexturePath.ToUtf8();
    effect.OnInit(0, texturePath.c_str());

    const msvc8::string rampPath = editor.mRampTexturePath.ToUtf8();
    effect.OnInit(1, rampPath.c_str());
  }

  void ApplyCurvePayloads(moho::IEffect& effect, const moho::WEmitterWx& editor) noexcept
  {
    const auto& curvePanelView = msvc8::AsVectorRuntimeView(editor.mCurvePanels);
    const std::size_t curveCount = CurvePanelCount(curvePanelView);
    for (std::size_t i = 0; i < curveCount; ++i) {
      moho::WCurveEditor* const curveEditor = curvePanelView.begin[i]->mCurveEditor;
      curveEditor->MarkCurveClean();
      effect.SetNParam(
        static_cast<std::int32_t>(i),
        reinterpret_cast<const float*>(&curveEditor->Curve()),
        static_cast<std::int32_t>(sizeof(moho::SEfxCurve) / sizeof(float))
      );
    }
  }

  void ApplyRepeatTimeIfChanged(moho::IEffect& effect, moho::WEmitterWx& editor)
  {
    const double repeatTime = editor.mRepeatTimeControl->ReadDouble();
    if (repeatTime == editor.mCachedRepeatTime || repeatTime <= kMinimumRepeatTime) {
      return;
    }

    editor.mCachedRepeatTime = repeatTime;
    const float repeatTimeFloat = static_cast<float>(repeatTime);

    const auto& curvePanelView = msvc8::AsVectorRuntimeView(editor.mCurvePanels);
    const std::size_t curveCount = CurvePanelCount(curvePanelView);
    for (std::size_t i = 0; i < curveCount; ++i) {
      curvePanelView.begin[i]->mCurveEditor->ResetCurveXRange(repeatTimeFloat);
    }

    effect.SetFloatParam(kParamRepeatTime, repeatTimeFloat);
    editor.mPreviewPanel->SetRepeatTimeFrame(0, static_cast<std::int32_t>(repeatTime));
    editor.mPreviewPanel->SetLifetimeFrame(static_cast<std::int32_t>(effect.GetFloatParam(3)));
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00663900 (FUN_00663900, Moho::WEmitterWx::WEmitterWx)
   * Mangled: ??0WEmitterWx@Moho@@QAE@@Z
   *
   * What it does:
   * See the declaration's IDA-signature note for the parameter mapping.
   * Resolves `attachUnit` (when given) to a concrete `Unit*` through
   * `IUnit::IsUnit`, storing it as a weak link (an empty `attachUnit`, or one
   * that is not really backed by a `Unit`, leaves `mAttachedUnit` at its
   * freshly-constructed empty state - the binary's own "unlink from an empty
   * chain" branch for that case is a no-op on a brand-new object). Seeds the
   * default particle/ramp texture paths, builds the File/Options/LOD menu
   * bar (every Options/LOD item checkable, three pre-checked, matching
   * `kEmitterFlagBindings`/`kVisibilityFlagBindings` above 1:1), installs a
   * matching keyboard-accelerator table, resolves the initial preview effect
   * through `RecreatePreviewEffect` (attached-to-entity or free-standing at
   * `spawnPosition` - the same branch this constructor's own binary body
   * open-codes), and lays out the scalar/flag/texture controls plus one
   * `WCurveEditorPanel` notebook tab per animatable curve before finishing
   * with a `RefreshPreviewEmitter` pass.
   */
  WEmitterWx::WEmitterWx(IUnit* const attachUnit, const Wm3::Vector3f& spawnPosition, const char* const boneName)
    : WWinManagedFrame(
        nullptr, -1, wxStringRuntime::Borrow(L"Emitter Editor"), wxPoint{-1, -1}, wxSize{800, 600},
        541068864L, wxStringRuntime::Borrow(L"MohoFrame")
      )
  {
    mTexturePath.m_pchData = const_cast<wchar_t*>(wxEmptyString);
    mRampTexturePath.m_pchData = const_cast<wchar_t*>(wxEmptyString);
    mBlueprintFilePath.m_pchData = const_cast<wchar_t*>(wxEmptyString);
    mBlueprintIdPath.m_pchData = const_cast<wchar_t*>(wxEmptyString);
    mTextureNameText.m_pchData = const_cast<wchar_t*>(wxEmptyString);
    mRampNameText.m_pchData = const_cast<wchar_t*>(wxEmptyString);

    mSim = ReadActiveSimFromDriver(moho::SIM_GetActiveDriver());

    if (attachUnit != nullptr) {
      mAttachedUnit.Set(attachUnit->IsUnit());
    }
    if (boneName != nullptr) {
      mBoneName = msvc8::string(boneName);
    }

    wxStringFormat(&mTexturePath, L"%s", L"/textures/particles/smoke.dds");
    wxStringFormat(&mRampTexturePath, L"%s", L"/textures/particles/testramp.dds");

    // ----- Menu bar: File / Options / LOD -----
    // The File menu is not modelled (it is not `WEmitterCommandCheckSource`-
    // queried by anything and this build has no real native window/menu bar
    // to show it on - see the file-level note above `ReadEmitterMenuItemCheckedFlag`).
    // The Options/LOD menus are, because `RefreshPreviewEmitter` already
    // reads their check state through `mEmitterFlagChecks`/
    // `mVisibilityFlagChecks`.
    mEmitterFlagChecks = BuildEmitterMenuCheckSource(kOptionsMenuItems, std::size(kOptionsMenuItems));
    mVisibilityFlagChecks = BuildEmitterMenuCheckSource(kLodMenuItems, std::size(kLodMenuItems));
    mMenuBar = nullptr;

    // ----- Initial preview effect -----
    mSpawnPosition = spawnPosition;
    (void)RecreatePreviewEffect(*this);

    // ----- Scalar / flag / texture controls -----
    mLifetimeControl = AddEmitterFieldRow(this, 556, L"Life Time", L"-1");

    mCachedRepeatTime = 1.0;
    mRepeatTimeControl = AddEmitterFieldRow(this, 557, L"Repeat Time", L"50.0");

    new WEmitterFieldLabelRuntimeView(this, L"Blend Mode");
    mBlendModeChoice = BuildEmitterChoiceControl(3);

    mTextureFrameCountControl = AddEmitterFieldRow(this, 559, L"Frame Count", L"1");
    mTextureStripCountControl = AddEmitterFieldRow(this, 560, L"Strip Count", L"1");

    new WEmitterFieldLabelRuntimeView(this, L"Fidelity");
    mFidelityChoice = BuildEmitterChoiceControl(6);

    mSortOrderControl = AddEmitterFieldRow(this, 563, L"Sort Order", L"0");
    mLodCutoffControl = AddEmitterFieldRow(this, 565, L"LOD Cutoff Distance", L"100");

    // "Playing" toggle. Field type is `WEmitterTextControl*` in the binary's
    // own layout (not a dedicated checkbox type) and nothing recovered so
    // far reads it back, so it is built through the same text-control path
    // as the other fields rather than inventing an unused checkbox shadow.
    mToggleControl = AddEmitterFieldRow(this, 0x231, L"", L"1");

    new WEmitterFieldLabelRuntimeView(this, L"Texture:");
    auto* const textureNameControl = new wxTextCtrlRuntime();
    (void)textureNameControl->CreateBase(
      this, -1, wxPoint{-1, -1}, wxSize{-1, -1}, 0, wxStringRuntime::Borrow(L"text")
    );
    textureNameControl->SetValue(mTexturePath);
    this->AddChild(textureNameControl);
    mTextureNameControl = reinterpret_cast<WEmitterTextControl*>(textureNameControl);

    new WEmitterFieldLabelRuntimeView(this, L"Ramp:");
    auto* const rampNameControl = new wxTextCtrlRuntime();
    (void)rampNameControl->CreateBase(
      this, -1, wxPoint{-1, -1}, wxSize{-1, -1}, 0, wxStringRuntime::Borrow(L"text")
    );
    rampNameControl->SetValue(mRampTexturePath);
    this->AddChild(rampNameControl);
    mRampNameControl = reinterpret_cast<WEmitterTextControl*>(rampNameControl);

    // Preview scrub slider (`WEmitterPreviewPanel`, really a `wxSlider95` -
    // see FUN_00660E10's `*a1 = &wxSlider95::`vftable'`); see the file-level
    // note above for why this is a purpose-built shadow rather than a real
    // `wxSlider95`.
    mPreviewPanel = BuildEmitterPreviewPanel();

    // ----- Notebook: one tab per animatable curve -----
    for (const EmitterCurveTabSpec& tab : kEmitterCurveTabs) {
      auto* const page = new WEmitterNotebookPageRuntimeView(this);
      auto* const curvePanel = new WCurveEditorPanel(
        page, 605, static_cast<float>(mCachedRepeatTime), tab.viewValueMin, tab.viewValueMax, tab.initialKeyValue,
        tab.initialKeyTangent
      );
      curvePanel->mCurveEditor->mScriptName = wxStringRuntime::Borrow(tab.scriptName);

      mCurvePanels.push_back(curvePanel);
    }

    RefreshPreviewEmitter();
  }

  double WEmitterTextControl::ReadDouble() const noexcept
  {
    wxStringRuntime text{};
    wxStringRuntime* const returned = TextVTable(*this)->mCopyText(this, &text);
    const wxStringRuntime* const source = returned != nullptr ? returned : &text;
    const double value = ParseWideDouble(source->c_str());
    ReleaseCopiedWxString(text);
    return value;
  }

  void WEmitterPreviewPanel::SetRepeatTimeFrame(
    const std::int32_t selector,
    const std::int32_t frame
  ) noexcept
  {
    PreviewVTable(*this)->mSetRepeatTimeFrame(this, selector, frame);
  }

  void WEmitterPreviewPanel::SetLifetimeFrame(const std::int32_t frame) noexcept
  {
    PreviewVTable(*this)->mSetLifetimeFrame(this, frame);
  }

  std::int32_t WEmitterChoiceControl::GetSelection() const noexcept
  {
    return ChoiceSelectionVTable(mSelection)->mGetSelection(&mSelection);
  }

  bool WEmitterCommandCheckSource::IsCommandChecked(const std::int32_t commandId) const noexcept
  {
    const auto* const item = FindMenuItemByCommandId(*this, commandId);
    return item != nullptr && item->mVTable->mIsChecked(item);
  }

  void WCurveEditor::ResetCurveXRange(const float rangeMax) noexcept
  {
    mViewTimeMin = 0.0f;
    mViewTimeMax = rangeMax;
    RescaleEmitterCurveXRange(&mCurve, 0.0f, rangeMax);
    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
  }

  /**
   * Address: 0x006617A0 (FUN_006617A0)
   *
   * IDA signature:
   * int __thiscall sub_6617A0(WCurveEditor *this, wxMouseEvent *event);
   *
   * What it does:
   * `WCurveEditor` mouse-wheel sink, installed at 0x00F59D44 in the curve
   * editor's `wxEventTableEntry` array. Zooms the value (Y) axis about its
   * centre: one wheel notch is converted into a value delta of
   * `rotation / (mViewValueScale * 5.0f) * 0.5f`, which is added to the
   * visible minimum and subtracted from the visible maximum. The zoom is
   * rejected outright when it would collapse the visible value span below
   * `0.1f`, so the range is left untouched rather than clamped. On an accepted
   * zoom the new bounds are stored and the curve-changed notification
   * (vtable +0xF0) is raised with `(1, 0)`, exactly as `ResetCurveXRange`
   * does for the time axis.
   */
  void WCurveEditor::ZoomValueAxisByWheel(const wxEventRuntime& wheelEvent) noexcept
  {
    const auto& mouseEvent = reinterpret_cast<const WxCurveEditorWheelEventRuntimeView&>(wheelEvent);

    const float valueDelta =
      (static_cast<float>(mouseEvent.mWheelRotation) / (mViewValueScale * 5.0f)) * 0.5f;
    const float zoomedMin = mViewValueMin + valueDelta;
    const float zoomedMax = mViewValueMax - valueDelta;

    if (zoomedMax - zoomedMin < kMinimumVisibleValueSpan) {
      return;
    }

    mViewValueMin = zoomedMin;
    mViewValueMax = zoomedMax;
    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
  }

  /**
   * Address: 0x00661100 (FUN_00661100)
   *
   * IDA signature:
   * int __usercall sub_661100@<eax>(WCurveEditor *this@<esi>);
   *
   * What it does:
   * Clears the editor's dirty flag and raises a
   * `wxEVT_COMMAND_BUTTON_CLICKED` command event carrying the editor's own
   * window id, routed straight through `wxControl::ProcessCommand` (the
   * binary binds that call statically rather than dispatching virtually).
   * This is how the curve editor tells its owning panel that the curve
   * changed.
   */
  void WCurveEditor::PostCurveChangedCommand()
  {
    const std::int32_t commandId = mWindowId;
    mCurveDirty = 0;

    wxCommandEventRuntime changedEvent(wxEVT_COMMAND_BUTTON_CLICKED, commandId);
    CurveEditorControlAccess::From(this)->ProcessCommand(&changedEvent);
  }

  /**
   * Address: 0x006614B0 (FUN_006614B0)
   *
   * IDA signature:
   * int __userpurge sub_6614B0@<eax>(
   *   WCurveEditor *this@<eax>, float time@<xmm1>, float value, int tangent);
   *
   * What it does:
   * Moves the currently selected curve key. No-op when nothing is selected
   * (`mSelectedKey == mCurve.mKeys.end()`). The requested time is clamped
   * into the visible time range and then against the neighbouring keys, so
   * dragging a key can never reorder the key vector; the value is clamped
   * into the visible value range. The tangent lane is stored verbatim.
   * Afterwards the curve's Y bounds are recomputed and the curve-changed
   * command is posted, followed by the same `(1, 0)` notification
   * `ResetCurveXRange` raises.
   */
  void WCurveEditor::MoveSelectedKeyTo(
    const float time,
    const float value,
    const float tangent
  )
  {
    Wm3::Vector3f* const selected = mSelectedKey;
    if (selected == mCurve.mKeys.end()) {
      return;
    }

    float clampedTime = std::min(mViewTimeMax, time);
    clampedTime = std::max(mViewTimeMin, clampedTime);

    float clampedValue = std::min(mViewValueMax, value);
    clampedValue = std::max(mViewValueMin, clampedValue);

    // Keys are kept sorted by time, so the move is additionally fenced by the
    // immediate neighbours rather than being allowed to swap past them.
    if (selected != mCurve.mKeys.begin()) {
      clampedTime = std::max(selected[-1].x, clampedTime);
    }
    if (selected + 1 != mCurve.mKeys.end()) {
      clampedTime = std::min(selected[1].x, clampedTime);
    }

    selected->x = clampedTime;
    selected->y = clampedValue;
    selected->z = tangent;

    RecomputeEmitterCurveYBounds(mCurve);
    PostCurveChangedCommand();
    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
  }

  /**
   * Address: 0x00663650 (FUN_00663650)
   *
   * IDA signature:
   * void __thiscall sub_663650(WCurveEditorPanel *this, wxCommandEvent *event);
   *
   * What it does:
   * `wxEventTableEntry` sink shared by the panel's five numeric fields
   * (0x00F59D80..0x00F59DD0, one entry per command id 622..626). Commits are
   * ignored until the panel's fields are bound.
   *
   * It seeds the selected key's `(time, value, tangent)` -- or zeros when
   * nothing is selected -- then, for whichever field raised the event, parses
   * the committed text over that seed (a failed parse leaves the seed intact,
   * so a malformed entry reverts rather than zeroing the key) and mirrors the
   * text back into the control. The key is then re-applied through
   * `MoveSelectedKeyTo`, which re-clamps it.
   *
   * Ids 625/626 edit the visible value range instead. They are applied only
   * when the resulting span stays at or above 0.1f -- the same guard
   * `ZoomValueAxisByWheel` uses -- and share its `(1, 0)` notification.
   * The event is marked skipped on every path so wx continues its own
   * propagation.
   */
  void WCurveEditorPanel::OnCurveFieldCommitted(wxEventRuntime& commandEvent)
  {
    auto& fieldEvent = reinterpret_cast<WxCurveFieldCommandEventRuntimeView&>(commandEvent);
    if (mFieldsLive == 0) {
      fieldEvent.mSkipped = 1;
      return;
    }

    WCurveEditor* const editor = mCurveEditor;
    const Wm3::Vector3f* const keysEnd = editor->mCurve.mKeys.end();

    double keyTime = (editor->mSelectedKey == keysEnd) ? 0.0 : editor->mSelectedKey->x;
    double keyValue = (editor->mSelectedKey == keysEnd) ? 0.0 : editor->mSelectedKey->y;
    double keyTangent = (editor->mSelectedKey == keysEnd) ? 0.0 : editor->mSelectedKey->z;

    if (fieldEvent.mCommandId == kCurveKeyTimeFieldId) {
      (void)ParseCommittedFieldValue(fieldEvent.mCommandString, &keyTime);
      TextVTable(*mKeyTimeText)->mSetValue(mKeyTimeText, &fieldEvent.mCommandString);
    }
    if (fieldEvent.mCommandId == kCurveKeyValueFieldId) {
      (void)ParseCommittedFieldValue(fieldEvent.mCommandString, &keyValue);
      TextVTable(*mKeyValueText)->mSetValue(mKeyValueText, &fieldEvent.mCommandString);
    }
    if (fieldEvent.mCommandId == kCurveKeyTangentFieldId) {
      (void)ParseCommittedFieldValue(fieldEvent.mCommandString, &keyTangent);
      TextVTable(*mKeyTangentText)->mSetValue(mKeyTangentText, &fieldEvent.mCommandString);
    }

    editor->MoveSelectedKeyTo(
      static_cast<float>(keyTime), static_cast<float>(keyValue), static_cast<float>(keyTangent)
    );

    double viewValueMin = editor->mViewValueMin;
    double viewValueMax = editor->mViewValueMax;

    if (fieldEvent.mCommandId == kCurveViewValueMinFieldId) {
      (void)ParseCommittedFieldValue(fieldEvent.mCommandString, &viewValueMin);
      TextVTable(*mViewValueMinText)->mSetValue(mViewValueMinText, &fieldEvent.mCommandString);
    }
    if (fieldEvent.mCommandId == kCurveViewValueMaxFieldId) {
      (void)ParseCommittedFieldValue(fieldEvent.mCommandString, &viewValueMax);
      TextVTable(*mViewValueMaxText)->mSetValue(mViewValueMaxText, &fieldEvent.mCommandString);
    }

    if (viewValueMax - viewValueMin >= static_cast<double>(kMinimumVisibleValueSpan)) {
      editor->mViewValueMin = static_cast<float>(viewValueMin);
      editor->mViewValueMax = static_cast<float>(viewValueMax);
      (void)CurveEditorVTable(*editor)->mNotifyCurveChanged(editor, 1, 0);
    }

    fieldEvent.mSkipped = 1;
  }

  /**
   * Address: 0x00663400 (FUN_00663400)
   *
   * IDA signature:
   * void __usercall sub_663400(WCurveEditorPanel *this@<esi>);
   *
   * What it does:
   * The inverse of `OnCurveFieldCommitted`: pushes the editor's current values
   * back out into the five numeric fields. Each value is formatted with
   * `wxString::Format(L"%f", value)`, handed to the control's `+0x21C`
   * setter, and the temporary's copy-on-write reference is then dropped. The
   * three key fields show zero when no key is selected.
   */
  void WCurveEditorPanel::RefreshFieldsFromCurve()
  {
    const WCurveEditor* const editor = mCurveEditor;

    const auto pushField = [](WEmitterTextControl* const control, const float value) {
      wxStringRuntime formatted{};
      (void)wxStringFormat(&formatted, L"%f", static_cast<double>(value));
      TextVTable(*control)->mSetValue(control, &formatted);
      ReleaseCopiedWxString(formatted);
    };

    const Wm3::Vector3f* const keysEnd = editor->mCurve.mKeys.end();
    const Wm3::Vector3f* const selected = editor->mSelectedKey;

    pushField(mKeyTimeText, selected == keysEnd ? 0.0f : selected->x);
    pushField(mKeyValueText, selected == keysEnd ? 0.0f : selected->y);
    pushField(mKeyTangentText, selected == keysEnd ? 0.0f : selected->z);
    pushField(mViewValueMinText, editor->mViewValueMin);
    pushField(mViewValueMaxText, editor->mViewValueMax);
  }

  /**
   * Address: 0x00668180 (FUN_00668180)
   *
   * IDA signature:
   * int __thiscall sub_668180(WEmitterWx *this, wxEvent *event);
   *
   * What it does:
   * `wxEventTableEntry` sink at 0x00F59DF8. Re-syncs every curve panel's
   * numeric fields from its editor, then rebuilds the preview emitter so the
   * viewport reflects the edited curves.
   */
  /**
   * Address: 0x00667860 (FUN_00667860)
   *
   * IDA signature:
   * void __thiscall sub_667860(WEmitterWx *this, wxEvent *event);
   *
   * What it does:
   * The inverse of `RefreshPreviewEmitter`: repopulates the editor UI from the
   * live preview effect. No-op when no effect is bound (the retail body tests
   * the handle for null and for the `4` dead-weak sentinel). `mRefreshGuard` is
   * raised across the whole pass so the control-change events fired while the
   * fields are written do not bounce straight back into the effect.
   *
   * The two texture paths come back as UTF-8 through `GetStringParam`, are
   * widened, cached in the editor's own `wxString` lanes and pushed into their
   * controls through the `+0x38` setter; then every curve panel is handed its
   * curve from the effect via `AssignCurve`.
   */
  /**
   * Shared body of the four file-dialog cases in FUN_00668B00. The retail
   * switch open-codes this per case; the only differences are the VFS root,
   * the title and the wildcard, so the mechanics live here.
   *
   * Resolves `vfsRoot` through the VFS, seeds the dialog's starting directory
   * from it, runs the dialog modally and -- on `wxID_OK` -- writes the chosen
   * directory and file name back into the frame so the next browse reopens in
   * place.
   */
  bool WEmitterWx::RunEmitterFileDialog(
    const char* const vfsRoot,
    const wchar_t* const title,
    const wchar_t* const wildcard,
    wxStringRuntime& startingDirectory
  )
  {
    moho::SDiskFileInfo fileInfo{};
    msvc8::string resolvedRoot;
    (void)moho::DISK_GetVFS()->FindFile(&resolvedRoot, vfsRoot, &fileInfo);

    const std::wstring wideRoot = gpg::STR_Utf8ToWide(resolvedRoot.c_str());
    ReleaseCopiedWxString(startingDirectory);
    (void)wxStringFormat(&startingDirectory, L"%s", wideRoot.c_str());

    auto* const storage = static_cast<WxFileDialogRuntimeView*>(::operator new(kWxFileDialogSize, std::nothrow));
    if (storage == nullptr) {
      return false;
    }

    wxStringRuntime titleText{};
    wxStringRuntime defaultFile{};
    wxStringRuntime wildcardText{};
    (void)wxStringFormat(&titleText, L"%s", title);
    (void)wxStringFormat(&wildcardText, L"%s", wildcard);

    ConstructWxFileDialog(
      storage, this, &titleText, &startingDirectory, &defaultFile, &wildcardText,
      kWxFileDialogStyle, &wxDefaultPosition
    );

    ReleaseCopiedWxString(titleText);
    ReleaseCopiedWxString(defaultFile);
    ReleaseCopiedWxString(wildcardText);

    const auto* const dialogVTable = reinterpret_cast<const WxFileDialogVTable*>(storage->mVTable);
    if (dialogVTable->mShowModal(storage) != kWxIdOk) {
      return false;
    }

    ReleaseCopiedWxString(startingDirectory);
    (void)wxStringFormat(&startingDirectory, L"%s", storage->mDirectory.m_pchData);
    return true;
  }

  /**
   * Flips one boolean effect parameter, mirroring the shared toggle body the
   * retail switch reaches for every id in the `0x2A0`..`0x2AC` block.
   */
  void WEmitterWx::ToggleEffectParameterFlag(const std::int32_t parameterIndex)
  {
    IEffect* const effect = mPreviewEffect.GetObjectPtr();
    if (effect == nullptr) {
      return;
    }

    const bool wasSet = effect->GetFloatParam(parameterIndex) > 0.0f;
    effect->SetFloatParam(parameterIndex, wasSet ? 0.0f : 1.0f);
  }

  void WEmitterWx::LoadFromEffect()
  {
    IEffect* const effect = mPreviewEffect.GetObjectPtr();
    if (effect == nullptr) {
      return;
    }

    mRefreshGuard = 1;

    const auto pushPath = [](WEmitterTextControl* const control,
                             wxStringRuntime& cachedPath,
                             const msvc8::string* const utf8) {
      const std::wstring wide = gpg::STR_Utf8ToWide(utf8 != nullptr ? utf8->c_str() : "");
      ReleaseCopiedWxString(cachedPath);
      (void)wxStringFormat(&cachedPath, L"%s", wide.c_str());
      TextVTable(*control)->mSetText(control, &cachedPath);
    };

    pushPath(mTextureNameControl, mTexturePath, effect->GetStringParam(0));
    pushPath(mRampNameControl, mRampTexturePath, effect->GetStringParam(1));

    const auto& curvePanelView = msvc8::AsVectorRuntimeView(mCurvePanels);
    const std::size_t curveCount = CurvePanelCount(curvePanelView);
    for (std::size_t i = 0; i < curveCount; ++i) {
      WCurveEditor* const curveEditor = curvePanelView.begin[i]->mCurveEditor;
      const auto* const curve =
        reinterpret_cast<const SEfxCurve*>(effect->GetCurveParam(static_cast<std::int32_t>(i)));
      if (curve != nullptr) {
        curveEditor->AssignCurve(*curve);
      }
    }

    mRefreshGuard = 0;
  }

  /**
   * Address: 0x00668340 (FUN_00668340)
   *
   * IDA signature:
   * void __userpurge sub_668340(
   *   std::auto_ptr<gpg::Stream> scratch, const wchar_t **path,
   *   const wchar_t **blueprintId, int stream);
   *
   * What it does:
   * Writes the emitter blueprint out as a Lua script: opens the destination
   * through `Moho::DISK_OpenFileWrite`, formats the header, every scalar and
   * flag parameter, both texture paths and each curve panel's block, then lets
   * the stream close. With no live effect it warns and skips.
   *
   * As with `FormatCurveScript`, the retail body discards every formatted line
   * -- `gpg::STR_Printf` writes into a reused `msvc8::string` sret slot with no
   * reader -- while still creating and closing the file. Both the formatting
   * and the file open/close are preserved 1:1; see the escalation note for the
   * four-point evidence chain behind that reading.
   */
  void WEmitterWx::WriteBlueprintScript(const wchar_t* const filePath, const wchar_t* const blueprintId)
  {
    IEffect* const effect = mPreviewEffect.GetObjectPtr();
    if (effect == nullptr) {
      gpg::Warnf("Invalid effect. Skip saving blueprint!");
      return;
    }

    const msvc8::string utf8Path = gpg::STR_WideToUtf8(filePath);
    msvc8::auto_ptr<gpg::Stream> output = moho::DISK_OpenFileWrite(utf8Path.c_str());
    if (output.get() == nullptr) {
      return;
    }

    const auto flag = [effect](const std::int32_t parameterIndex) {
      return effect->GetFloatParam(parameterIndex) > 0.0f ? "true" : "false";
    };
    const auto scalar = [effect](const std::int32_t parameterIndex) {
      return static_cast<double>(effect->GetFloatParam(parameterIndex));
    };

    msvc8::string line = gpg::STR_Printf("EmitterBlueprint {\n");

    const msvc8::string utf8BlueprintId = gpg::STR_WideToUtf8(blueprintId);
    line = gpg::STR_Printf("\tBlueprintId = '%s',\n", utf8BlueprintId.c_str());

    line = gpg::STR_Printf("\tLifetime = %.2f,\n", scalar(kParamLifetime));
    line = gpg::STR_Printf("\tRepeattime = %.2f,\n", scalar(kParamRepeatTime));
    line = gpg::STR_Printf("\tTextureFramecount = %.2f,\n", scalar(kParamTextureFrameCount));
    line = gpg::STR_Printf("\tBlendmode = %.2f,\n", scalar(kParamBlendMode));
    line = gpg::STR_Printf("\tLocalVelocity = %s,\n", flag(9));
    line = gpg::STR_Printf("\tLocalAcceleration = %s,\n", flag(10));
    line = gpg::STR_Printf("\tGravity = %s,\n", flag(11));
    line = gpg::STR_Printf("\tAlignRotation = %s,\n", flag(12));
    line = gpg::STR_Printf("\tAlignToBone = %s,\n", flag(15));
    line = gpg::STR_Printf("\tFlat = %s,\n", flag(17));
    line = gpg::STR_Printf("\tLODCutoff = %.2f,\n", scalar(kParamLodCutoff));
    line = gpg::STR_Printf("\tEmitIfVisible = %s,\n", flag(20));
    line = gpg::STR_Printf("\tCatchupEmit = %s,\n", flag(21));
    line = gpg::STR_Printf("\tCreateIfVisible = %s,\n", flag(22));
    line = gpg::STR_Printf("\tSnapToWaterline = %s,\n", flag(23));
    line = gpg::STR_Printf("\tOnlyEmitOnWater = %s,\n", flag(24));
    line = gpg::STR_Printf("\tParticleResistance = %s,\n", flag(25));
    line = gpg::STR_Printf("\tInterpolateEmission = %s,\n", flag(13));
    line = gpg::STR_Printf("\tTextureStripcount = %.2f,\n", scalar(kParamTextureStripCount));
    line = gpg::STR_Printf("\tSortOrder = %.2f,\n", scalar(kParamSortOrder));

    // The three fidelity lines share one bitmask taken from the fidelity choice
    // control; the binary adds 1 to the raw selection before testing bits 0-2.
    const std::int32_t fidelityMask = mFidelityChoice->GetSelection() + 1;
    line = gpg::STR_Printf("\tLowFidelity = %s,\n", (fidelityMask & 1) != 0 ? "true" : "false");
    line = gpg::STR_Printf("\tMedFidelity = %s,\n", (fidelityMask & 2) != 0 ? "true" : "false");
    line = gpg::STR_Printf("\tHighFidelity = %s,\n", (fidelityMask & 4) != 0 ? "true" : "false");

    const msvc8::string texturePath = gpg::STR_WideToUtf8(mTexturePath.m_pchData);
    line = gpg::STR_Printf("\tTexture = [[%s]],\n", texturePath.c_str());
    const msvc8::string rampPath = gpg::STR_WideToUtf8(mRampTexturePath.m_pchData);
    line = gpg::STR_Printf("\tRampTexture = [[%s]],\n", rampPath.c_str());

    const auto& curvePanelView = msvc8::AsVectorRuntimeView(mCurvePanels);
    const std::size_t curveCount = CurvePanelCount(curvePanelView);
    for (std::size_t i = 0; i < curveCount; ++i) {
      curvePanelView.begin[i]->mCurveEditor->FormatCurveScript();
    }

    line = gpg::STR_Printf("}\n\n");
    (void)line;
  }

  /**
   * Address: 0x00668B00 (FUN_00668B00)
   *
   * IDA signature:
   * void __thiscall sub_668B00(WEmitterWx *this, wxCommandEvent *event);
   *
   * What it does:
   * The emitter editor's menu/command sink, and the head of this cluster. It
   * switches on the command id at `[event+0x14]`:
   *
   *  - `0x29C` open a blueprint: resolves `/effects/Emitters` through the VFS,
   *    runs a `wxFileDialog` titled "Select Blueprint" filtered to `*.bp`, and
   *    on accept reloads the editor from the chosen file. A file whose name is
   *    not `*.bp` is refused with "You didn't open a valid blueprint".
   *  - `0x29D` / `0x29E` browse for the particle texture, and `0x29F` for the
   *    ramp texture -- both rooted at `/textures/particles` and filtered to
   *    `*.dds`. `0x29D` reaches the particle body by fall-through, exactly as
   *    the retail switch does.
   *  - `0x2A7` save-as: "Choose a file to save as." over `/effects/Emitters`,
   *    rejecting a name that is not `*.bp` with "Since this is a blueprint you
   *    must save as *.bp" and an empty one with "Bad name!".
   *  - every other id in `0x2A0`..`0x2AC` is a parameter toggle, flipping the
   *    effect flag named by the shared binding tables.
   *
   * Each dialog stores its chosen directory back into the frame so the next
   * browse reopens where the user left off, and every path finishes by pushing
   * the editor state through `RefreshPreviewEmitter`.
   */
  void WEmitterWx::OnMenuCommand(wxEventRuntime& commandEventRef)
  {
    const auto& commandEvent =
      reinterpret_cast<const WxCurveFieldCommandEventRuntimeView&>(commandEventRef);

    switch (commandEvent.mCommandId) {
      case kEmitterOpenBlueprintCommandId:
        if (RunEmitterFileDialog(kEmitterBlueprintDirectory, L"Select Blueprint", L"*.bp",
                                 mBlueprintFilePath)) {
          LoadFromEffect();
        }
        break;

      case kEmitterBrowseTextureCommandIdAlt:
      case kEmitterBrowseTextureCommandId:
        if (RunEmitterFileDialog(kEmitterTextureDirectory, L"Select Particle Texture", L"*.dds",
                                 mBlueprintIdPath)) {
          TextVTable(*mTextureNameControl)->mSetText(mTextureNameControl, &mTexturePath);
        }
        break;

      case kEmitterBrowseRampCommandId:
        if (RunEmitterFileDialog(kEmitterTextureDirectory, L"Select Ramp Texture", L"*.dds",
                                 mBlueprintIdPath)) {
          TextVTable(*mRampNameControl)->mSetText(mRampNameControl, &mRampTexturePath);
        }
        break;

      case kEmitterSaveBlueprintAsCommandId:
        if (RunEmitterFileDialog(kEmitterBlueprintDirectory, L"Choose a file to save as.", L"*.bp",
                                 mBlueprintFilePath)) {
          WriteBlueprintScript(mBlueprintFilePath.m_pchData, mBlueprintIdPath.m_pchData);
        }
        break;

      default:
        for (const EmitterFlagBinding& binding : kEmitterFlagBindings) {
          if (binding.commandId == commandEvent.mCommandId) {
            ToggleEffectParameterFlag(binding.parameterIndex);
          }
        }
        for (const EmitterFlagBinding& binding : kVisibilityFlagBindings) {
          if (binding.commandId == commandEvent.mCommandId) {
            ToggleEffectParameterFlag(binding.parameterIndex);
          }
        }
        break;
    }

    RefreshPreviewEmitter();
  }

  void WEmitterWx::OnCurveEdited()
  {
    const auto& curvePanelView = msvc8::AsVectorRuntimeView(mCurvePanels);
    const std::size_t curveCount = CurvePanelCount(curvePanelView);
    for (std::size_t i = 0; i < curveCount; ++i) {
      curvePanelView.begin[i]->RefreshFieldsFromCurve();
    }

    RefreshPreviewEmitter();
  }

  /**
   * Address: 0x00661B90 (FUN_00661B90)
   *
   * IDA signature:
   * int __userpurge sub_661B90@<eax>(
   *   wxDC *dc@<edi>, WCurveEditor *editor@<esi>, Wm3::Vector3f **keyCursor);
   *
   * What it does:
   * Paints one span of the curve's tangent envelope in `wxRED_PEN`. The span
   * runs between two "columns" -- for an interior key, the previous key and
   * this key; at the first key the span is clamped to `mViewTimeMin`, and at
   * the end sentinel it is clamped to `mViewTimeMax` against the last key.
   *
   * Each column contributes three points through `ProjectCurvePointToScreen`:
   * the upper envelope edge (`value + tangent/2`), the curve value itself, and
   * the lower edge (`value - tangent/2`). Wound as
   * `upperX, upperY, midY, lowerY, lowerX, midX`, that is the six-vertex
   * hexagon the retail body fills, after which the two mid-points are joined
   * by a line so the curve itself is drawn over the band.
   */
  void WCurveEditor::DrawKeyEnvelopeSpan(void* const dc, const Wm3::Vector3f* const key) const
  {
    const auto* const dcVTable = CurveEditorDcVTable(dc);
    dcVTable->mSetPen(dc, wxRED_PEN);

    const Wm3::Vector3f* const keysBegin = mCurve.mKeys.begin();
    const Wm3::Vector3f* const keysEnd = mCurve.mKeys.end();

    // Resolve the span's two columns. `columnA` is drawn first in the winding.
    CurveEnvelopeColumn columnA{};
    CurveEnvelopeColumn columnB{};
    if (key == keysBegin) {
      columnA = {mViewTimeMin, key->y, key->z};
      columnB = {key->x, key->y, key->z};
    } else if (key == keysEnd) {
      const Wm3::Vector3f* const lastKey = key - 1;
      columnA = {lastKey->x, lastKey->y, lastKey->z};
      columnB = {mViewTimeMax, lastKey->y, lastKey->z};
    } else {
      const Wm3::Vector3f* const previousKey = key - 1;
      columnA = {previousKey->x, previousKey->y, previousKey->z};
      columnB = {key->x, key->y, key->z};
    }

    const wxPoint envelope[6] = {
      ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, columnA),
      ProjectCurvePointToScreen(kCurveEnvelopeUpperEdge, columnB),
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, columnB),
      ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, columnB),
      ProjectCurvePointToScreen(kCurveEnvelopeLowerEdge, columnA),
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, columnA),
    };
    dcVTable->mDoDrawPolygon(dc, 6, envelope, 0, 0, kCurveEnvelopeFillStyle);

    const wxPoint midB = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, columnB);
    const wxPoint midA = ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, columnA);
    dcVTable->mDoDrawLine(dc, midA.x, midA.y, midB.x, midB.y);
  }

  /**
   * Address: 0x006612A0 (FUN_006612A0)
   *
   * IDA signature:
   * int *__userpurge sub_6612A0@<eax>(
   *   int *out@<eax>, WCurveEditor *editor@<edx>, int edge@<ecx>,
   *   float time, float value, float tangent);
   *
   * What it does:
   * Projects one curve point into widget space. `edge` shifts the value by
   * half the tangent to reach the upper or lower envelope edge, or leaves it
   * alone for the curve itself. The horizontal axis maps time through
   * `mViewTimeScale` relative to `mViewTimeMin`; the vertical axis is
   * inverted, measuring down from the client height.
   */
  wxPoint WCurveEditor::ProjectCurvePointToScreen(
    const std::int32_t edge,
    const CurveEnvelopeColumn& column
  ) const noexcept
  {
    float value = column.mValue;
    if (edge == kCurveEnvelopeUpperEdge) {
      value = column.mValue + column.mTangent * 0.5f;
    } else if (edge == kCurveEnvelopeLowerEdge) {
      value = column.mValue - column.mTangent * 0.5f;
    }

    wxPoint projected{};
    projected.x = static_cast<std::int32_t>(mViewTimeScale * (column.mTime - mViewTimeMin));
    projected.y = static_cast<std::int32_t>(
      static_cast<float>(mClientHeight) - mViewValueScale * (value - mViewValueMin)
    );
    return projected;
  }

  /**
   * Address: 0x00662180 (FUN_00662180)
   *
   * IDA signature:
   * int __usercall sub_662180@<eax>(
   *   WCurveEditor *editor@<ebx>, Wm3::Vector3f **keyCursor@<edi>, wxDC *dc@<esi>);
   *
   * What it does:
   * Draws one key's grab handle: a 5x5 square centred on the key, cyan when
   * that key is the current selection and red otherwise.
   */
  void WCurveEditor::DrawKeyHandle(void* const dc, const Wm3::Vector3f* const key) const
  {
    const auto* const dcVTable = CurveEditorDcVTable(dc);
    dcVTable->mSetPen(dc, key == mSelectedKey ? wxCYAN_PEN : wxRED_PEN);

    const wxPoint handle =
      ProjectCurvePointToScreen(kCurveEnvelopeCurveValue, {key->x, key->y, key->z});
    dcVTable->mDoDrawRectangle(dc, handle.x, handle.y, kCurveKeyHandleSize, kCurveKeyHandleSize);
  }

  /**
   * Address: 0x006621F0 (FUN_006621F0)
   *
   * IDA signature:
   * void __thiscall sub_6621F0(WCurveEditor *this, wxPaintEvent *event);
   *
   * What it does:
   * `wxEventTableEntry` paint sink for the curve editor. Caches the client
   * size, derives the two pixel-per-unit view scales from it, then paints the
   * curve: one envelope span per key plus a closing span for the end
   * sentinel, a grab handle per key, and the four axis labels (`%.1f`) placed
   * against the edges using the control's own `GetTextExtent`, followed by the
   * editor's caption.
   */
  void WCurveEditor::OnPaint()
  {
    wxPaintDCRuntime paintDc(reinterpret_cast<wxWindowBase*>(this));
    void* const dc = &paintDc;

    std::int32_t clientWidth = 0;
    std::int32_t clientHeight = 0;
    paintDc.DoGetSize(&clientWidth, &clientHeight);
    mClientWidth = clientWidth;
    mClientHeight = clientHeight;

    mViewTimeScale = static_cast<float>(clientWidth) / (mViewTimeMax - mViewTimeMin);
    mViewValueScale = static_cast<float>(clientHeight) / (mViewValueMax - mViewValueMin);

    // One envelope span per key, then the closing span at the end sentinel.
    for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
      DrawKeyEnvelopeSpan(dc, key);
    }
    DrawKeyEnvelopeSpan(dc, mCurve.mKeys.end());

    for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
      DrawKeyHandle(dc, key);
    }

    const auto* const dcVTable = CurveEditorDcVTable(dc);
    const auto* const textVTable = *reinterpret_cast<const WxCurveEditorTextExtentVTable* const*>(this);

    wxStringRuntime label{};
    const auto drawLabel = [&](const float value, const bool horizontalCentre, const bool atFarEdge) {
      (void)wxStringFormat(&label, L"%.1f", static_cast<double>(value));

      std::int32_t textWidth = 0;
      std::int32_t textHeight = 0;
      textVTable->mGetTextExtent(this, &label, &textWidth, &textHeight, nullptr, nullptr, nullptr);

      const std::int32_t x = horizontalCentre ? (clientWidth / 2 - textWidth / 2)
                                              : (atFarEdge ? clientWidth - textWidth : 0);
      const std::int32_t y = horizontalCentre ? (atFarEdge ? clientHeight - textHeight : 0)
                                              : (clientHeight / 2 - textHeight / 2);
      dcVTable->mDoDrawText(dc, &label, x, y);
    };

    drawLabel(mViewTimeMin, false, false);  // left edge, vertically centred
    drawLabel(mViewTimeMax, false, true);   // right edge, vertically centred
    drawLabel(mViewValueMin, true, true);   // bottom edge, horizontally centred
    drawLabel(mViewValueMax, true, false);  // top edge, horizontally centred

    dcVTable->mDoDrawText(dc, &mCaption, 0, 0);

    ReleaseCopiedWxString(label);
  }

  /**
   * Address: 0x00661820 (FUN_00661820)
   *
   * IDA signature:
   * int __thiscall sub_661820(WCurveEditor *this, wxMouseEvent *event);
   *
   * What it does:
   * `wxEventTableEntry` button-down sink. Caches the cursor position, converts
   * it back into curve space (the inverse of `ProjectCurvePointToScreen`) and
   * selects the nearest key. Left and middle buttons additionally record which
   * button is driving the drag and post the curve-changed command. The mouse is
   * captured on the first press so the drag keeps receiving events outside the
   * widget, and the widget is then repainted.
   */
  void WCurveEditor::OnMouseDown(wxEventRuntime& mouseEventRef)
  {
    const auto& mouseEvent = reinterpret_cast<const WxCurveEditorMouseEventRuntimeView&>(mouseEventRef);

    mLastMouseX = mouseEvent.mMouseX;
    mLastMouseY = mouseEvent.mMouseY;

    const Wm3::Vector2f curvePoint{
      mViewTimeMin + static_cast<float>(mLastMouseX) / mViewTimeScale,
      mViewValueMin + static_cast<float>(mClientHeight - mLastMouseY) / mViewValueScale
    };
    mSelectedKey = FindNearestCurveKey(mCurve, curvePoint);

    if (mouseEvent.mEventType == moho::WX_GetWxEvtLeftDownType()) {
      mActiveDragButton = kCurveDragButtonLeft;
      PostCurveChangedCommand();
    }
    if (mouseEvent.mEventType == moho::WX_GetWxEvtMiddleDownType()) {
      mActiveDragButton = kCurveDragButtonMiddle;
      PostCurveChangedCommand();
    }

    if (mMouseCaptured == 0) {
      reinterpret_cast<wxWindowBase*>(this)->CaptureMouse();
      mMouseCaptured = 1;
    }

    reinterpret_cast<wxWindowBase*>(this)->Refresh(true, nullptr);
  }

  /**
   * Address: 0x00661A90 (FUN_00661A90)
   *
   * IDA signature:
   * int __thiscall sub_661A90(WCurveEditor *this, wxMouseEvent *event);
   *
   * What it does:
   * `wxEventTableEntry` sink for the key-editing click. The cursor position is
   * converted into curve space; a plain click inserts a key there (with a zero
   * tangent) and selects it, while a control-click deletes the nearest key --
   * but only while more than one key remains, so the curve can never be
   * emptied. Deleting re-derives the value bounds and falls the selection back
   * to the first key. Either way the curve-changed command and the `(1, 0)`
   * notification are raised.
   */
  void WCurveEditor::OnCurveKeyEdit(wxEventRuntime& mouseEventRef)
  {
    const auto& mouseEvent = reinterpret_cast<const WxCurveEditorMouseEventRuntimeView&>(mouseEventRef);

    Wm3::Vector3f curvePoint{};
    curvePoint.x = mViewTimeMin + static_cast<float>(mouseEvent.mMouseX) / mViewTimeScale;
    curvePoint.y = mViewValueMin + static_cast<float>(mClientHeight - mouseEvent.mMouseY) / mViewValueScale;

    const Wm3::Vector2f hitPoint{curvePoint.x, curvePoint.y};
    if (mouseEvent.mControlDown == 0) {
      curvePoint.z = 0.0f;
      InsertEmitterCurveKey(mCurve, curvePoint);
      mSelectedKey = FindNearestCurveKey(mCurve, hitPoint);
    } else if (mCurve.mKeys.end() - mCurve.mKeys.begin() > 1) {
      Wm3::Vector3f* const doomed = FindNearestCurveKey(mCurve, hitPoint);
      (void)EraseEmitterCurveKeyRange(doomed, doomed + 1, mCurve);
      RecomputeEmitterCurveYBounds(mCurve);
      mSelectedKey = mCurve.mKeys.begin();
    }

    PostCurveChangedCommand();
    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
  }

  /**
   * Address: 0x00669E40 (FUN_00669E40)
   *
   * IDA signature:
   * void __usercall sub_669E40(SEfxCurve *source@<eax>, WCurveEditor *this@<ecx>);
   *
   * What it does:
   * Replaces the edited curve wholesale -- bounds and keys -- then drops the
   * selection, which would otherwise dangle into the freed key storage, raises
   * the curve-changed notification and command, and refreshes the owning
   * panel's numeric fields. This is how a blueprint's curve reaches the editor.
   */
  void WCurveEditor::AssignCurve(const SEfxCurve& source)
  {
    mCurve = source;
    mSelectedKey = mCurve.mKeys.end();

    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
    PostCurveChangedCommand();
    mOwnerPanel->RefreshFieldsFromCurve();
  }

  /**
   * Address: 0x00661580 (FUN_00661580)
   *
   * IDA signature:
   * void __userpurge sub_661580(WCurveEditor *this@<edi>, msvc8::string *scratch);
   *
   * What it does:
   * Formats this curve as a Lua table -- the script key, an `XRange` taken from
   * the curve's own upper X bound, then one `{ x=, y=, z= }` line per key.
   *
   * The retail body then throws every line away: `gpg::STR_Printf` formats into
   * a caller-supplied `msvc8::string` sret slot (confirmed from FUN_00938F10,
   * which is a plain by-value formatter forwarding to `STR_Va`), the same slot
   * is reused for every line, and nothing ever reads it -- the write plumbing
   * of this exporter was removed while the formatting was left in place.
   * Preserved 1:1 so the string-allocation side effects match the binary,
   * following the ` DoPreload` marker convention in `moho/sim/CWldSession.cpp`.
   */
  void WCurveEditor::FormatCurveScript() const
  {
    const msvc8::string scriptName = gpg::STR_WideToUtf8(mScriptName.m_pchData);

    msvc8::string line = gpg::STR_Printf(
      "\t%s = {\n\t\tXRange = %.2f,\n\t\tKeys = {\n",
      scriptName.c_str(),
      static_cast<double>(mCurve.mBoundsMax.x)
    );

    for (const Wm3::Vector3f* key = mCurve.mKeys.begin(); key != mCurve.mKeys.end(); ++key) {
      line = gpg::STR_Printf(
        "\t\t\t{ x=%.3f,y=%.3f,z=%.3f },\n",
        static_cast<double>(key->x),
        static_cast<double>(key->y),
        static_cast<double>(key->z)
      );
    }

    line = gpg::STR_Printf("\t\t},\n\t},\n");
    (void)line;
  }

  void WCurveEditor::MarkCurveClean() noexcept
  {
    mCurveDirty = 0;
  }

  namespace
  {
    using CurveEditorWheelSinkFnPtr = void (WCurveEditor::*)(const wxEventRuntime&) noexcept;

    /**
     * Address: 0x00F59D44 (`WCurveEditor` wxEventTableEntry slot)
     *
     * What it does:
     * Holds the curve editor's wheel sink so the linker keeps it addressable
     * from this TU, mirroring the compiler-emitted `wxEventTable` array that
     * `WCurveEditor::GetEventTable` (0x00662660) publishes. In the original
     * 2007 source this entry is emitted by the wx `EVT_MOUSEWHEEL` macro.
     */
    struct WCurveEditorEventTableBindings
    {
      CurveEditorWheelSinkFnPtr onMouseWheel;
      void (WCurveEditor::*onPaint)();
      void (WCurveEditor::*onMouseDown)(wxEventRuntime&);
      void (WCurveEditor::*onCurveKeyEdit)(wxEventRuntime&);
    };

    const WCurveEditorEventTableBindings kWCurveEditorEventTableBindings = {
      &WCurveEditor::ZoomValueAxisByWheel,
      &WCurveEditor::OnPaint,
      &WCurveEditor::OnMouseDown,
      &WCurveEditor::OnCurveKeyEdit,
    };

    using CurvePanelFieldSinkFnPtr = void (WCurveEditorPanel::*)(wxEventRuntime&);

    /**
     * Address: 0x00F59D80 (`WCurveEditorPanel` wxEventTableEntry array)
     *
     * What it does:
     * Keeps the panel's field sink addressable from this TU. The binary's
     * table holds five consecutive entries -- one per field id 622..626 --
     * all pointing at the same handler, which is what the wx
     * `EVT_TEXT_ENTER` macro emits when the same method is bound to a range
     * of control ids.
     */
    struct WCurveEditorPanelEventTableBindings
    {
      CurvePanelFieldSinkFnPtr onCurveFieldCommitted;
    };

    const WCurveEditorPanelEventTableBindings kWCurveEditorPanelEventTableBindings = {
      &WCurveEditorPanel::OnCurveFieldCommitted,
    };

    [[maybe_unused]] [[nodiscard]] const void* PublishWCurveEditorPanelEventTableBindings() noexcept
    {
      return static_cast<const void*>(&kWCurveEditorPanelEventTableBindings);
    }

    /**
     * Address: 0x00F59DF8 (`WEmitterWx` wxEventTableEntry slot)
     *
     * What it does:
     * Keeps the emitter frame's curve-edited sink addressable from this TU,
     * mirroring the wx event-table entry the original source emitted for it.
     */
    struct WEmitterWxEventTableBindings
    {
      void (WEmitterWx::*onCurveEdited)();
      void (WEmitterWx::*onMenuCommand)(wxEventRuntime&);
    };

    const WEmitterWxEventTableBindings kWEmitterWxEventTableBindings = {
      &WEmitterWx::OnCurveEdited,
      &WEmitterWx::OnMenuCommand,
    };

    [[maybe_unused]] [[nodiscard]] const void* PublishWEmitterWxEventTableBindings() noexcept
    {
      return static_cast<const void*>(&kWEmitterWxEventTableBindings);
    }

    [[maybe_unused]] [[nodiscard]] const void* PublishWCurveEditorEventTableBindings() noexcept
    {
      return static_cast<const void*>(&kWCurveEditorEventTableBindings);
    }
  } // namespace

  const SEfxCurve& WCurveEditor::Curve() const noexcept
  {
    return mCurve;
  }

  /**
   * Address: 0x006672F0 (FUN_006672F0)
   *
   * What it does:
   * Recreates the preview emitter when needed, then pushes the current editor
   * scalar, flag, curve, texture, and ramp controls into the live effect.
   */
  void WEmitterWx::RefreshPreviewEmitter()
  {
    if (mRepeatTimeControl == nullptr || mPreviewPanel == nullptr || mRefreshGuard != 0) {
      return;
    }

    IEffect* effect = ResolvePreviewEffect(*this);
    if (effect == nullptr) {
      effect = RecreatePreviewEffect(*this);
    }
    if (effect == nullptr) {
      return;
    }

    effect->SetFloatParam(kParamBlendMode, static_cast<float>(mBlendModeChoice->GetSelection()));
    ApplyCommandFlags(*effect, *mEmitterFlagChecks, kEmitterFlagBindings, std::size(kEmitterFlagBindings));
    ApplyCommandFlags(*effect, *mVisibilityFlagChecks, kVisibilityFlagBindings, std::size(kVisibilityFlagBindings));

    ApplyRepeatTimeIfChanged(*effect, *this);

    ApplyTextFloatParam(*effect, mLifetimeControl, kParamLifetime);
    ApplyTextFloatParam(*effect, mTextureFrameCountControl, kParamTextureFrameCount);
    ApplyTextFloatParam(*effect, mSortOrderControl, kParamSortOrder);
    ApplyTextFloatParam(*effect, mLodCutoffControl, kParamLodCutoff);
    ApplyTextFloatParam(*effect, mTextureStripCountControl, kParamTextureStripCount);

    ApplyCurvePayloads(*effect, *this);
    ApplyEmitterTextures(*effect, *this);
  }

  /**
   * Address: 0x00666F40 (FUN_00666F40, Moho::WEmitterWx::~WEmitterWx)
   *
   * What it does:
   * Complete-object destructor. The MSVC vtable restore at function entry is
   * expressed implicitly by the C++ destructor; the remaining teardown runs in
   * exact binary reverse-construction order:
   *   1. delete every live curve panel via its scalar-deleting dtor,
   *   2. release the previewed effect through the sim effect-manager,
   *   3. drop the interlock ref on the active sim driver,
   *   4/5. release the ramp/texture wx-string caches,
   *   6/7. tidy the blueprint/bone SSO string lanes,
   *   8. unlink the attached-unit weak node,
   *   9. unlink the preview-effect weak node,
   *   10. free the curve-panel vector storage,
   *   11..14. release the four blueprint/texture path wx-string lanes,
   *   15. drain the managed-frame owner slots,
   *   16. run shared non-deleting frame teardown as a tail call.
   */
  WEmitterWx::~WEmitterWx()
  {
    // (1) Delete each live curve panel through its scalar-deleting destructor.
    const auto& curvePanelView = msvc8::AsVectorRuntimeView(mCurvePanels);
    for (WCurveEditorPanel* const* cursor = curvePanelView.begin; cursor != curvePanelView.end; ++cursor) {
      if (WCurveEditorPanel* const panel = *cursor) {
        (void)panel->DeleteWithFlag(1);
      }
    }

    // (2) Release the previewed effect through the sim effect-manager when the
    //     weak preview lane still references a live effect.
    if (mPreviewEffect.HasValue()) {
      mSim->mEffectManager->DestroyEffect(mPreviewEffect.GetObjectPtr());
    }

    // (3) Drop the interlock ref on the active sim driver (binary reads the
    //     process-global driver directly and dispatches slot 37).
    SIM_GetActiveDriver()->ReleaseInterlockRef();

    // (4/5) Release the ramp/texture wx-string caches (refcount decrement).
    ReleaseCopiedWxString(mRampNameText);
    ReleaseCopiedWxString(mTextureNameText);

    // (6/7) Tidy the blueprint/bone SSO string lanes.
    mBlueprintName.tidy(true, 0U);
    mBoneName.tidy(true, 0U);

    // (8) Unlink the attached-unit weak node from its owner chain.
    mAttachedUnit.UnlinkFromOwnerChain();

    // (9) Unlink the preview-effect weak node from its owner chain.
    mPreviewEffect.UnlinkFromOwnerChain();

    // (10) Free the curve-panel vector storage.
    ReleaseCurvePanelVectorStorage(mCurvePanels);

    // (11..14) Release the four blueprint/texture path wx-string lanes.
    ReleaseCopiedWxString(mBlueprintIdPath);
    ReleaseCopiedWxString(mBlueprintFilePath);
    ReleaseCopiedWxString(mRampTexturePath);
    ReleaseCopiedWxString(mTexturePath);

    // (15) Drain this frame's managed-owner slots.
    ReleaseManagedOwnerSlots();

    // (16) Run shared non-deleting frame teardown as a tail call. The binary
    //      treats this WEmitterWx as a top-level frame at teardown and passes
    //      the same object pointer to the shared frame-destroy lane.
    (void)WX_FrameDestroyWithoutDelete(reinterpret_cast<wxTopLevelWindowRuntime*>(this));
  }

  /**
   * Address: 0x00669E10 (FUN_00669E10, Moho::WEmitterWx::dtr)
   * Slot: scalar-deleting destructor thunk
   *
   * What it does:
   * Scalar-deleting destructor thunk. Runs `~WEmitterWx()` teardown and frees
   * the object storage when `deleteFlags & 1` is set.
   */
  WEmitterWx* WEmitterWx::DeleteWithFlag(const std::uint8_t deleteFlags) noexcept
  {
    this->~WEmitterWx();
    if ((deleteFlags & 1u) != 0u) {
      ::operator delete(this);
    }
    return this;
  }
} // namespace moho

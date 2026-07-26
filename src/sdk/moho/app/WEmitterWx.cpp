#include "moho/app/WEmitterWx.h"

#include <cwchar>
#include <iterator>

#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectWeakPtrReflection.h"
#include "moho/entity/Entity.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
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

/**
 * Address: 0x009600E0 (FUN_009600E0, wxString::ToDouble)
 *
 * Recovered in `moho/sim/SimRecoveryRuntime.cpp`. The curve panel's field sink
 * calls it on the committed `wxCommandEvent` text; a failed parse leaves the
 * caller's seed value untouched.
 */
bool ParseWideDoubleStrictRuntime(const wchar_t** sourceText, double* outValue);

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
  using NotifyCurveChangedFn = int(__thiscall*)(moho::WEmitterCurveEditor*, std::int32_t, std::int32_t);

  using SetTextControlValueFn = void(__thiscall*)(moho::WEmitterTextControl*, const wxStringRuntime*);

  struct WEmitterTextControlVTableLayout
  {
    void* mLanes000To217[0x218 / sizeof(void*)]{};
    CopyTextFn mCopyText = nullptr;             // +0x218
    SetTextControlValueFn mSetValue = nullptr;  // +0x21C
  };
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

  struct WEmitterCurveEditorVTableLayout
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

    [[nodiscard]] static CurveEditorControlAccess* From(moho::WEmitterCurveEditor* const editor) noexcept
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
    offsetof(WEmitterCurveEditorVTableLayout, mNotifyCurveChanged) == 0xF0,
    "WEmitterCurveEditorVTableLayout::mNotifyCurveChanged offset must be 0xF0"
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

  [[nodiscard]] const WEmitterCurveEditorVTableLayout* CurveEditorVTable(
    const moho::WEmitterCurveEditor& editor
  ) noexcept
  {
    return reinterpret_cast<const WEmitterCurveEditorVTableLayout*>(editor.mVTable);
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

  // Frees the heap storage backing one `msvc8::vector<WEmitterCurvePanel*>` and
  // resets its {begin,end,capacityEnd} lanes to the empty state. This mirrors
  // the inline `operator delete` + pointer-zeroing the binary emits for the
  // `mCurvePanels` member at its teardown point (0x006670BE), operating on the
  // named member through the sanctioned runtime view (no raw `this + 0xNN`).
  void ReleaseCurvePanelVectorStorage(msvc8::vector<moho::WEmitterCurvePanel*>& curvePanels) noexcept
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
    const msvc8::vector_runtime_view<moho::WEmitterCurvePanel*>& curvePanelView
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
      moho::WEmitterCurveEditor* const curveEditor = curvePanelView.begin[i]->mCurveEditor;
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

  void WEmitterCurveEditor::ResetCurveXRange(const float rangeMax) noexcept
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
  void WEmitterCurveEditor::ZoomValueAxisByWheel(const wxEventRuntime& wheelEvent) noexcept
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
  void WEmitterCurveEditor::PostCurveChangedCommand()
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
  void WEmitterCurveEditor::MoveSelectedKeyTo(
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
  void WEmitterCurvePanel::OnCurveFieldCommitted(wxEventRuntime& commandEvent)
  {
    auto& fieldEvent = reinterpret_cast<WxCurveFieldCommandEventRuntimeView&>(commandEvent);
    if (mFieldsLive == 0) {
      fieldEvent.mSkipped = 1;
      return;
    }

    WEmitterCurveEditor* const editor = mCurveEditor;
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
  void WEmitterCurvePanel::RefreshFieldsFromCurve()
  {
    const WEmitterCurveEditor* const editor = mCurveEditor;

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
  void WEmitterCurveEditor::DrawKeyEnvelopeSpan(void* const dc, const Wm3::Vector3f* const key) const
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
  wxPoint WEmitterCurveEditor::ProjectCurvePointToScreen(
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
  void WEmitterCurveEditor::DrawKeyHandle(void* const dc, const Wm3::Vector3f* const key) const
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
  void WEmitterCurveEditor::OnPaint()
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

  void WEmitterCurveEditor::MarkCurveClean() noexcept
  {
    mCurveDirty = 0;
  }

  namespace
  {
    using CurveEditorWheelSinkFnPtr = void (WEmitterCurveEditor::*)(const wxEventRuntime&) noexcept;

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
      void (WEmitterCurveEditor::*onPaint)();
    };

    const WCurveEditorEventTableBindings kWCurveEditorEventTableBindings = {
      &WEmitterCurveEditor::ZoomValueAxisByWheel,
      &WEmitterCurveEditor::OnPaint,
    };

    using CurvePanelFieldSinkFnPtr = void (WEmitterCurvePanel::*)(wxEventRuntime&);

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
      &WEmitterCurvePanel::OnCurveFieldCommitted,
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
    };

    const WEmitterWxEventTableBindings kWEmitterWxEventTableBindings = {
      &WEmitterWx::OnCurveEdited,
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

  const SEfxCurve& WEmitterCurveEditor::Curve() const noexcept
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
    for (WEmitterCurvePanel* const* cursor = curvePanelView.begin; cursor != curvePanelView.end; ++cursor) {
      if (WEmitterCurvePanel* const panel = *cursor) {
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

#include "moho/app/WEmitterWx.h"

#include <cwchar>
#include <iterator>

#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectWeakPtrReflection.h"
#include "moho/entity/Entity.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

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

  struct WEmitterTextControlVTableLayout
  {
    void* mLanes000To217[0x218 / sizeof(void*)]{};
    CopyTextFn mCopyText = nullptr; // +0x218
  };
  static_assert(
    offsetof(WEmitterTextControlVTableLayout, mCopyText) == 0x218,
    "WEmitterTextControlVTableLayout::mCopyText offset must be 0x218"
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
    mCurveRangeMin = 0.0f;
    mCurveRangeMax = rangeMax;
    RescaleEmitterCurveXRange(&mCurve, 0.0f, rangeMax);
    (void)CurveEditorVTable(*this)->mNotifyCurveChanged(this, 1, 0);
  }

  void WEmitterCurveEditor::MarkCurveClean() noexcept
  {
    mCurveDirty = 0;
  }

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
} // namespace moho

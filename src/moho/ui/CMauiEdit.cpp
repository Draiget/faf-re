#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCMauiEditSetNewFontHelpText = "Edit:SetNewFont(family, pointsize)";
  constexpr const char* kCMauiEditSetNewForegroundColorHelpText = "Edit:SetNewForegroundColor(color)";
  constexpr const char* kCMauiEditGetForegroundColorHelpText = "color Edit:GetForegroundColor()";
  constexpr const char* kCMauiEditSetNewBackgroundColorHelpText = "Edit:SetNewBackgroundColor(color)";
  constexpr const char* kCMauiEditGetBackgroundColorHelpText = "color Edit:GetBackgroundColor()";
  constexpr const char* kCMauiEditShowBackgroundHelpText = "Edit:ShowBackground(bool)";
  constexpr const char* kCMauiEditIsBackgroundVisibleHelpText = "bool Edit:IsBackgroundVisible()";
  constexpr const char* kCMauiEditClearTextHelpText = "Edit:ClearText()";
  constexpr const char* kCMauiEditSetTextHelpText = "Edit:SetText(string text)";
  constexpr const char* kCMauiEditGetTextHelpText = "string Edit:GetText()";
  constexpr const char* kCMauiEditSetCaretPositionHelpText = "SetCaretPosition(int)";
  constexpr const char* kCMauiEditGetCaretPositionHelpText = "int GetCaretPosition";
  constexpr const char* kCMauiEditShowCaretHelpText = "Edit:ShowCaret(bool)";
  constexpr const char* kCMauiEditIsCaretVisibleHelpText = "bool Edit:IsCaretVisible()";
  constexpr const char* kCMauiEditSetNewCaretColorHelpText = "Edit:SetNewCaretColor(color)";
  constexpr const char* kCMauiEditGetCaretColorHelpText = "color Edit:GetCaretColor()";
  constexpr const char* kCMauiEditSetCaretCycleHelpText =
    "edit:SetCaretCycle(float seconds, uint32 minAlpha, uint32 maxAlpha)";
  constexpr const char* kCMauiEditIsEnabledHelpText = "bool Edit:IsEnabled()";
  constexpr const char* kCMauiEditEnableInputHelpText = "Edit:EnableInput()";
  constexpr const char* kCMauiEditDisableInputHelpText = "Edit:Disable()";
  constexpr const char* kCMauiEditSetNewHighlightForegroundColorHelpText = "SetNewHightlightForegroundColor(color)";
  constexpr const char* kCMauiEditGetHighlightForegroundColorHelpText = "color GetHighlightForegroundColor()";
  constexpr const char* kCMauiEditSetNewHighlightBackgroundColorHelpText = "SetNewHighlightBackgroundColor(color)";
  constexpr const char* kCMauiEditGetHighlightBackgroundColorHelpText = "color GetHighlightBackgroundColor()";
  constexpr const char* kCMauiEditGetFontHeightHelpText = "int GetFontHeight()";
  constexpr const char* kCMauiEditSetMaxCharsHelpText = "Edit:SetMaxChars(int size)";
  constexpr const char* kCMauiEditGetMaxCharsHelpText = "int Edit:GetMaxChars()";
  constexpr const char* kCMauiEditAcquireFocusHelpText = "AcquireFocus()";
  constexpr const char* kCMauiEditAbandonFocusHelpText = "AbandonFocus()";
  constexpr const char* kCMauiEditSetDropShadowHelpText = "SetDropShadow(bool)";
  constexpr const char* kCMauiEditGetStringAdvanceHelpText =
    "number Edit:GetAdvance(string) - get the advance of a string using the same font as the control";
  constexpr const char* kInternalCreateEditHelpText = "InternalCreateEdit(luaobj,parent)";

  /**
   * Address: 0x0078ECE0 (FUN_0078ECE0)
   *
   * What it does:
   * Returns one text-advance measurement from the edit font lane and falls
   * back to `0.0f` when no font is bound.
   */
  [[nodiscard]] float MeasureEditStringAdvanceOrZero(
    CMauiEdit* const edit,
    const char* const text
  )
  {
    CD3DFont* const font = edit->mFont;
    if (font == nullptr) {
      return 0.0f;
    }
    return font->GetAdvance(text, 0);
  }
  /**
   * Address: 0x0078F310 (FUN_0078F310)
   *
   * What it does:
   * Shows the edit caret and assigns keyboard focus when the edit is enabled.
   */
  void AcquireEditKeyboardFocusIfEnabled(
    moho::CMauiEdit* const edit
  )
  {
    if (edit->mIsEnabled) {
      edit->mCaretVisible = true;
      moho::MAUI_SetKeyboardFocus(edit, true);
    }
  }
  /**
   * Address: 0x0078DC60 (FUN_0078DC60)
   *
   * What it does:
   * Returns CMauiEdit background-visible lane.
   */
  [[maybe_unused]] bool ReadEditBackgroundVisibleLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mBackgroundVisible;
  }

  /**
   * Address: 0x0078ECC0 (FUN_0078ECC0)
   *
   * What it does:
   * Stores edit drop-shadow enable lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditDropShadowLane(
    CMauiEdit* const edit,
    const bool enabled
  ) noexcept
  {
    edit->mDropShadow = enabled;
    return edit;
  }

  /**
   * Address: 0x0078ECD0 (FUN_0078ECD0)
   *
   * What it does:
   * Returns edit max-char limit lane.
   */
  [[maybe_unused]] std::int32_t ReadEditMaxCharsLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mMaxChars;
  }

  /**
   * Address: 0x0078ED10 (FUN_0078ED10)
   *
   * What it does:
   * Reads edit-bound font height lane (`0.0f` when font is missing).
   */
  [[maybe_unused]] float ReadEditFontHeightLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    const CD3DFont* const font = edit->mFont;
    return font != nullptr ? font->mHeight : 0.0f;
  }

  /**
   * Address: 0x0078ED30 (FUN_0078ED30)
   *
   * What it does:
   * Stores edit foreground color lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditForegroundColorLane(
    CMauiEdit* const edit,
    const std::uint32_t color
  ) noexcept
  {
    edit->mForegroundColor = color;
    return edit;
  }

  /**
   * Address: 0x0078ED40 (FUN_0078ED40)
   *
   * What it does:
   * Returns edit foreground color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditForegroundColorLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mForegroundColor;
  }

  /**
   * Address: 0x0078ED50 (FUN_0078ED50)
   *
   * What it does:
   * Stores edit background-visible lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditBackgroundVisibleLane(
    CMauiEdit* const edit,
    const bool visible
  ) noexcept
  {
    edit->mBackgroundVisible = visible;
    return edit;
  }

  /**
   * Address: 0x0078ED60 (FUN_0078ED60)
   *
   * What it does:
   * Returns edit background-visible lane.
   */
  [[maybe_unused]] bool ReadEditBackgroundVisibleLaneAlias(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mBackgroundVisible;
  }

  /**
   * Address: 0x0078ED70 (FUN_0078ED70)
   *
   * What it does:
   * Enables background rendering and stores edit background color lane.
   */
  [[maybe_unused]] CMauiEdit* EnableEditBackgroundAndWriteColor(
    CMauiEdit* const edit,
    const std::uint32_t color
  ) noexcept
  {
    edit->mBackgroundVisible = true;
    edit->mBackgroundColor = color;
    return edit;
  }

  /**
   * Address: 0x0078ED80 (FUN_0078ED80)
   *
   * What it does:
   * Returns edit background color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditBackgroundColorLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mBackgroundColor;
  }

  /**
   * Address: 0x0078ED90 (FUN_0078ED90)
   *
   * What it does:
   * Stores edit highlight-foreground color lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditHighlightForegroundColorLane(
    CMauiEdit* const edit,
    const std::uint32_t color
  ) noexcept
  {
    edit->mHighlightForegroundColor = color;
    return edit;
  }

  /**
   * Address: 0x0078EDA0 (FUN_0078EDA0)
   *
   * What it does:
   * Returns edit highlight-foreground color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditHighlightForegroundColorLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mHighlightForegroundColor;
  }

  /**
   * Address: 0x0078EDB0 (FUN_0078EDB0)
   *
   * What it does:
   * Stores edit highlight-background color lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditHighlightBackgroundColorLane(
    CMauiEdit* const edit,
    const std::uint32_t color
  ) noexcept
  {
    edit->mHighlightBackgroundColor = color;
    return edit;
  }

  /**
   * Address: 0x0078EDC0 (FUN_0078EDC0)
   *
   * What it does:
   * Returns edit highlight-background color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditHighlightBackgroundColorLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mHighlightBackgroundColor;
  }

  /**
   * Address: 0x0078EE00 (FUN_0078EE00)
   *
   * What it does:
   * Returns edit caret-position lane.
   */
  [[maybe_unused]] std::int32_t ReadEditCaretPositionLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mCaretPosition;
  }

  /**
   * Address: 0x0078EE10 (FUN_0078EE10)
   *
   * What it does:
   * Stores edit caret-visible lane.
   */
  [[maybe_unused]] CMauiEdit* WriteEditCaretVisibleLane(
    CMauiEdit* const edit,
    const bool visible
  ) noexcept
  {
    edit->mCaretVisible = visible;
    return edit;
  }

  /**
   * Address: 0x0078EE20 (FUN_0078EE20)
   *
   * What it does:
   * Returns edit caret-visible lane.
   */
  [[maybe_unused]] bool ReadEditCaretVisibleLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mCaretVisible;
  }

  /**
   * Address: 0x0078EE40 (FUN_0078EE40)
   *
   * What it does:
   * Returns edit caret color lane.
   */
  [[maybe_unused]] std::uint32_t ReadEditCaretColorLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mCaretColor;
  }

  /**
   * Address: 0x0078EE50 (FUN_0078EE50)
   *
   * What it does:
   * Returns edit input-enabled lane.
   */
  [[maybe_unused]] bool ReadEditInputEnabledLane(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mIsEnabled;
  }

  /**
   * Address: 0x0078EE70 (FUN_0078EE70)
   *
   * What it does:
   * Returns whether selection start/end lanes differ.
   */
  [[maybe_unused]] bool HasEditSelectionRange(
    const CMauiEdit* const edit
  ) noexcept
  {
    return edit->mSelectionStart != edit->mSelectionEnd;
  }

  /**
   * Address: 0x0078F360 (FUN_0078F360)
   *
   * What it does:
   * Writes edit input/caret-enabled lanes; when disabling, also abandons
   * keyboard focus through virtual dispatch path.
   */
  [[maybe_unused]] bool WriteEditInputEnabledAndCaretVisible(
    moho::CMauiEdit* const edit,
    const bool enabled
  )
  {
    edit->mIsEnabled = enabled;
    edit->mCaretVisible = enabled;
    if (!enabled) {
      edit->AbandonKeyboardFocus();
    }
    return enabled;
  }

  /**
   * Address: 0x00790580 (FUN_00790580)
   *
   * What it does:
   * Forwards one key code into `CScriptObject::RunScriptOnCharPressed`.
   */
  [[nodiscard]] bool RunScriptOnCharPressedThunk(
    moho::CScriptObject* const scriptObject,
    const int keyCode
  )
  {
    return scriptObject->RunScriptOnCharPressed(keyCode);
  }

  /**
   * Address: 0x00790F90 (FUN_00790F90, Moho::CMauiEdit::SetClipOffsetLeft)
   *
   * What it does:
   * Updates clip offset and recomputes visible UTF-8 clip length from current
   * edit text, font, and width lazy-var lane.
   */
  void SetEditClipOffsetLeft(
    CMauiEdit* const edit,
    int position
  )
  {
    if (!edit) {
      return;
    }

    edit->mClipOffset = position;
    CD3DFont* const font = edit->mFont;
    if (font == nullptr) {
      return;
    }

    const char* const text = edit->mText.c_str();
    const float advanceToOffset = font->GetAdvance(text, position);
    const float width = CScriptLazyVar_float::GetValue(&edit->mWidthLV);
    if (advanceToOffset <= width) {
      edit->mClipLength = gpg::STR_Utf8Len(text);
      return;
    }

    const int textLength = gpg::STR_Utf8Len(text);
    if (position > textLength) {
      position = textLength;
    }

    const int byteOffset = gpg::STR_Utf8ByteOffset(text, position);
    const char* const start = text + byteOffset;
    const char* cursor = start;
    float clippedAdvance = 0.0f;
    while (cursor != nullptr) {
      wchar_t decoded = 0;
      const char* const next = gpg::STR_DecodeUtf8Char(cursor, decoded);
      clippedAdvance += font->GetCharInfo(decoded).mAdvance;
      const float dynamicWidth = CScriptLazyVar_float::GetValue(&edit->mWidthLV);
      cursor = next;
      if (clippedAdvance > dynamicWidth || cursor == nullptr) {
        break;
      }
    }

    const std::size_t clippedBytes =
      (cursor != nullptr && cursor > start) ? static_cast<std::size_t>(cursor - start) : 0u;
    if (clippedBytes == 0u) {
      edit->mClipLength = 0;
      return;
    }

    const std::string clippedText(start, clippedBytes);
    edit->mClipLength = gpg::STR_Utf8Len(clippedText.c_str());
  }

  /**
   * Address: 0x00790D20 (FUN_00790D20, Moho::CMauiEdit::SetClipOffsetRight)
   *
   * What it does:
   * Recomputes clip window from the right side so the caret lane remains inside
   * the visible width while preserving right-side character count.
   */
  void SetEditClipOffsetRight(
    CMauiEdit* const edit,
    int charsAfterCaret
  )
  {
    if (edit == nullptr || edit->mFont == nullptr) {
      return;
    }

    const char* const text = edit->mText.c_str();
    const float advanceToRight = edit->mFont->GetAdvance(text, charsAfterCaret);
    const float width = CScriptLazyVar_float::GetValue(&edit->mWidthLV);
    if (advanceToRight <= width) {
      edit->mClipLength = gpg::STR_Utf8Len(text);
      return;
    }

    int textLength = gpg::STR_Utf8Len(text);
    if (charsAfterCaret > textLength) {
      charsAfterCaret = textLength;
    }

    const int caretPosition = textLength - charsAfterCaret;
    const int textByteLength = gpg::STR_Utf8ByteOffset(text, textLength);
    const int caretByteOffset = textByteLength - gpg::STR_Utf8ByteOffset(text, charsAfterCaret);

    const char* const start = text;
    const char* threshold = start + caretByteOffset;
    float clippedAdvance = 0.0f;
    if (threshold != start) {
      while (true) {
        const char* const previous = gpg::STR_PreviousUtf8Char(threshold, start);

        wchar_t decoded = 0;
        const char* const next = gpg::STR_DecodeUtf8Char(previous, decoded);
        clippedAdvance += edit->mFont->GetCharInfo(decoded).mAdvance;
        const float dynamicWidth = CScriptLazyVar_float::GetValue(&edit->mWidthLV);
        if (clippedAdvance > dynamicWidth) {
          threshold = next;
          break;
        }

        threshold = previous;
        if (threshold == start) {
          break;
        }
      }
    }

    const std::ptrdiff_t copiedBytes = static_cast<std::ptrdiff_t>(caretByteOffset) - (threshold - start);
    const std::size_t visibleBytes = copiedBytes > 0 ? static_cast<std::size_t>(copiedBytes) : 0u;
    const std::string visibleText(threshold, visibleBytes);

    edit->mClipLength = gpg::STR_Utf8Len(visibleText.c_str());
    edit->mClipOffset = caretPosition - edit->mClipLength;
  }

  void CopyUtf8TextToClipboard(
    const fa::string& text
  )
  {
    const std::wstring wideText = gpg::STR_Utf8ToWide(text.c_str());
    (void)moho::WIN_CopyToClipboard(wideText.c_str());
  }

  void CopyEditSelectionToClipboard(
    moho::CMauiEdit* const edit
  )
  {
    if (edit == nullptr) {
      return;
    }

    CopyUtf8TextToClipboard(edit->GetSelection());
  }


  /**
   * Address: 0x0078F620 (FUN_0078F620, Moho::CMauiEdit::ApplyFontAndRefreshClip)
   *
   * What it does:
   * Applies requested edit font (or default Courier New 14 fallback), adjusts
   * intrusive font ownership, and recomputes text clipping at current offset.
   */
  void ApplyEditFontAndRefreshClip(
    CMauiEdit* const edit,
    const boost::SharedPtrRaw<CD3DFont>& requestedFont
  )
  {
    if (!edit) {
      return;
    }

    if (requestedFont.px != nullptr) {
      AssignIntrusiveFont(edit->mFont, requestedFont.px);
    } else {
      boost::SharedPtrRaw<CD3DFont> defaultFont = CD3DFont::Create(14, "Courier New");
      AssignIntrusiveFont(edit->mFont, defaultFont.px);
      defaultFont.release();
    }

    SetEditClipOffsetLeft(edit, edit->mClipOffset);
  }

  void DrawSolidColorQuad(
    moho::CD3DPrimBatcher* const primBatcher,
    const std::uint32_t textureColor,
    const float left,
    const float top,
    const float right,
    const float bottom,
    const std::uint32_t vertexColor
  )
  {
    const boost::shared_ptr<moho::CD3DBatchTexture> texture = moho::CD3DBatchTexture::FromSolidColor(textureColor);
    primBatcher->SetTexture(texture);

    const moho::CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, vertexColor, 0.0f, 0.0f);
    const moho::CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, vertexColor, 1.0f, 0.0f);
    const moho::CD3DPrimBatcher::Vertex bottomRight = MakeBorderVertex(right, bottom, vertexColor, 1.0f, 1.0f);
    const moho::CD3DPrimBatcher::Vertex bottomLeft = MakeBorderVertex(left, bottom, vertexColor, 0.0f, 1.0f);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }

  void RenderEditTextAt(
    moho::CMauiEdit* const edit,
    moho::CD3DPrimBatcher* const primBatcher,
    const fa::string& text,
    const float x,
    const float y,
    const std::uint32_t color
  )
  {
    const Wm3::Vector3f origin{x, y, 0.0f};
    const Wm3::Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Wm3::Vector3f yAxis{0.0f, -1.0f, 0.0f};
    (void)edit->mFont->Render(
      text.c_str(),
      primBatcher,
      origin,
      xAxis,
      yAxis,
      edit->AdjustARGBAlpha(color),
      1.0f,
      std::numeric_limits<float>::quiet_NaN()
    );
  }

  float RenderEditTextRun(
    moho::CMauiEdit* const edit,
    moho::CD3DPrimBatcher* const primBatcher,
    const fa::string& text,
    const float x,
    const float baselineY,
    const std::uint32_t color
  )
  {
    const float advance = edit->mFont->GetAdvance(text.c_str(), 0);
    if (edit->mDropShadow) {
      RenderEditTextAt(edit, primBatcher, text, x + 1.0f, baselineY + 1.0f, color & 0xFF000000u);
    }
    RenderEditTextAt(edit, primBatcher, text, x, baselineY, color);
    return advance;
  }
}

gpg::RType* moho::CMauiEdit::sType = nullptr;

/**
 * Address: 0x007921A0 (FUN_007921A0, cfunc_CMauiEditSetNewFont)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetNewFontL`.
 */
int moho::cfunc_CMauiEditSetNewFont(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewFontL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007921C0 (FUN_007921C0, func_CMauiEditSetNewFont_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewFont(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewFont_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewFont",
    &moho::cfunc_CMauiEditSetNewFont,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewFontHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792220 (FUN_00792220, cfunc_CMauiEditSetNewFontL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus `(family, pointsize)`, creates one D3D font, and
 * applies it to edit runtime state.
 */
int moho::cfunc_CMauiEditSetNewFontL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kCMauiEditSetNewFontHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject familyArg(state, 2);
  const char* const familyName = lua_tostring(state->m_state, 2);
  if (familyName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&familyArg, "string");
  }

  LuaPlus::LuaStackObject pointSizeArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&pointSizeArg, "integer");
  }
  const int pointSize = static_cast<int>(lua_tonumber(state->m_state, 3));

  boost::SharedPtrRaw<CD3DFont> createdFont = CD3DFont::Create(pointSize, familyName);
  if (createdFont.px != nullptr) {
    ApplyEditFontAndRefreshClip(edit, createdFont);
    lua_settop(state->m_state, 1);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }

  createdFont.release();
  return 1;
}

/**
 * Address: 0x007923C0 (FUN_007923C0, cfunc_CMauiEditSetNewForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewForegroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewForegroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007923E0 (FUN_007923E0, func_CMauiEditSetNewForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewForegroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewForegroundColor",
    &moho::cfunc_CMauiEditSetNewForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792440 (FUN_00792440, cfunc_CMauiEditSetNewForegroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one color lane and stores foreground color.
 */
int moho::cfunc_CMauiEditSetNewForegroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetNewForegroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditForegroundColorLane(edit, SCR_DecodeColor(state, colorObject));

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792530 (FUN_00792530, cfunc_CMauiEditGetForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetForegroundColorL`.
 */
int moho::cfunc_CMauiEditGetForegroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792550 (FUN_00792550, func_CMauiEditGetForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetForegroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetForegroundColor",
    &moho::cfunc_CMauiEditGetForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007925B0 (FUN_007925B0, cfunc_CMauiEditGetForegroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded foreground color.
 */
int moho::cfunc_CMauiEditGetForegroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetForegroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject =
    SCR_EncodeColor(state, ReadEditForegroundColorLane(edit));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00792690 (FUN_00792690, cfunc_CMauiEditSetNewBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewBackgroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewBackgroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007926B0 (FUN_007926B0, func_CMauiEditSetNewBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewBackgroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewBackgroundColor",
    &moho::cfunc_CMauiEditSetNewBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792710 (FUN_00792710, cfunc_CMauiEditSetNewBackgroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one color lane, enables background rendering, and
 * stores background color.
 */
int moho::cfunc_CMauiEditSetNewBackgroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetNewBackgroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t backgroundColor = SCR_DecodeColor(state, colorObject);

  (void)EnableEditBackgroundAndWriteColor(edit, backgroundColor);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792810 (FUN_00792810, cfunc_CMauiEditGetBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetBackgroundColorL`.
 */
int moho::cfunc_CMauiEditGetBackgroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792830 (FUN_00792830, func_CMauiEditGetBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetBackgroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetBackgroundColor",
    &moho::cfunc_CMauiEditGetBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792890 (FUN_00792890, cfunc_CMauiEditGetBackgroundColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded background color.
 */
int moho::cfunc_CMauiEditGetBackgroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetBackgroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject =
    SCR_EncodeColor(state, ReadEditBackgroundColorLane(edit));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00792970 (FUN_00792970, cfunc_CMauiEditShowBackground)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditShowBackgroundL`.
 */
int moho::cfunc_CMauiEditShowBackground(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditShowBackgroundL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792990 (FUN_00792990, func_CMauiEditShowBackground_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ShowBackground(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditShowBackground_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowBackground",
    &moho::cfunc_CMauiEditShowBackground,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditShowBackgroundHelpText
  );
  return &binder;
}

/**
 * Address: 0x007929F0 (FUN_007929F0, cfunc_CMauiEditShowBackgroundL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus one boolean lane and updates background-visibility
 * state.
 */
int moho::cfunc_CMauiEditShowBackgroundL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditShowBackgroundHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject visibleArg(state, 2);
  (void)WriteEditBackgroundVisibleLane(edit, visibleArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792AC0 (FUN_00792AC0, cfunc_CMauiEditIsBackgroundVisible)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditIsBackgroundVisibleL`.
 */
int moho::cfunc_CMauiEditIsBackgroundVisible(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditIsBackgroundVisibleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792AE0 (FUN_00792AE0, func_CMauiEditIsBackgroundVisible_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsBackgroundVisible()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsBackgroundVisible_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsBackgroundVisible",
    &moho::cfunc_CMauiEditIsBackgroundVisible,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsBackgroundVisibleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792B40 (FUN_00792B40, cfunc_CMauiEditIsBackgroundVisibleL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes background visibility as one Lua boolean.
 */
int moho::cfunc_CMauiEditIsBackgroundVisibleL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditIsBackgroundVisibleHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushboolean(state->m_state, ReadEditBackgroundVisibleLaneAlias(edit));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00792C00 (FUN_00792C00, cfunc_CMauiEditClearText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditClearTextL`.
 */
int moho::cfunc_CMauiEditClearText(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditClearTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792C20 (FUN_00792C20, func_CMauiEditClearText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ClearText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditClearText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearText",
    &moho::cfunc_CMauiEditClearText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditClearTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792C80 (FUN_00792C80, cfunc_CMauiEditClearTextL)
 *
 * What it does:
 * Reads one `CMauiEdit`, clears text/caret/selection lanes, and returns self.
 */
int moho::cfunc_CMauiEditClearTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditClearTextHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  edit->ClearText();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792D30 (FUN_00792D30, cfunc_CMauiEditSetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetTextL`.
 */
int moho::cfunc_CMauiEditSetText(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792D50 (FUN_00792D50, func_CMauiEditSetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetText(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetText",
    &moho::cfunc_CMauiEditSetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792DB0 (FUN_00792DB0, cfunc_CMauiEditSetTextL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus text lane, applies text update, and returns self.
 */
int moho::cfunc_CMauiEditSetTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetTextHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
    text = "";
  }

  edit->SetText(fa::string(text));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00792F00 (FUN_00792F00, cfunc_CMauiEditGetText)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetTextL`.
 */
int moho::cfunc_CMauiEditGetText(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetTextL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792F20 (FUN_00792F20, func_CMauiEditGetText_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetText()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetText_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetText",
    &moho::cfunc_CMauiEditGetText,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetTextHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792F80 (FUN_00792F80, cfunc_CMauiEditGetTextL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current text lane.
 */
int moho::cfunc_CMauiEditGetTextL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetTextHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  const fa::string text = edit->GetText();
  lua_pushstring(state->m_state, text.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793340 (FUN_00793340, cfunc_CMauiEditSetCaretPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetCaretPositionL`.
 */
int moho::cfunc_CMauiEditSetCaretPosition(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetCaretPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793360 (FUN_00793360, func_CMauiEditSetCaretPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetCaretPosition(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetCaretPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCaretPosition",
    &moho::cfunc_CMauiEditSetCaretPosition,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetCaretPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x007933C0 (FUN_007933C0, cfunc_CMauiEditSetCaretPositionL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus integer caret lane and updates caret/clip state.
 */
int moho::cfunc_CMauiEditSetCaretPositionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetCaretPositionHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject caretArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&caretArg, "integer");
  }

  const int caretPosition = static_cast<int>(lua_tonumber(state->m_state, 2));
  edit->SetCaretPosition(caretPosition);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007934C0 (FUN_007934C0, cfunc_CMauiEditGetCaretPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetCaretPositionL`.
 */
int moho::cfunc_CMauiEditGetCaretPosition(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetCaretPositionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007934E0 (FUN_007934E0, func_CMauiEditGetCaretPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetCaretPosition()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetCaretPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetCaretPosition",
    &moho::cfunc_CMauiEditGetCaretPosition,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetCaretPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793540 (FUN_00793540, cfunc_CMauiEditGetCaretPositionL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current caret-position lane.
 */
int moho::cfunc_CMauiEditGetCaretPositionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetCaretPositionHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(ReadEditCaretPositionLane(edit)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793600 (FUN_00793600, cfunc_CMauiEditShowCaret)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditShowCaretL`.
 */
int moho::cfunc_CMauiEditShowCaret(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditShowCaretL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793620 (FUN_00793620, func_CMauiEditShowCaret_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:ShowCaret(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditShowCaret_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ShowCaret",
    &moho::cfunc_CMauiEditShowCaret,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditShowCaretHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793680 (FUN_00793680, cfunc_CMauiEditShowCaretL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus bool lane and updates caret-visibility lane.
 */
int moho::cfunc_CMauiEditShowCaretL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditShowCaretHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject visibleArg(state, 2);
  (void)WriteEditCaretVisibleLane(edit, visibleArg.GetBoolean());
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793750 (FUN_00793750, cfunc_CMauiEditIsCaretVisible)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditIsCaretVisibleL`.
 */
int moho::cfunc_CMauiEditIsCaretVisible(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditIsCaretVisibleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793770 (FUN_00793770, func_CMauiEditIsCaretVisible_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsCaretVisible()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsCaretVisible_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsCaretVisible",
    &moho::cfunc_CMauiEditIsCaretVisible,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsCaretVisibleHelpText
  );
  return &binder;
}

/**
 * Address: 0x007937D0 (FUN_007937D0, cfunc_CMauiEditIsCaretVisibleL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes caret-visible state.
 */
int moho::cfunc_CMauiEditIsCaretVisibleL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditIsCaretVisibleHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  lua_pushboolean(state->m_state, ReadEditCaretVisibleLane(edit));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793890 (FUN_00793890, cfunc_CMauiEditSetNewCaretColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetNewCaretColorL`.
 */
int moho::cfunc_CMauiEditSetNewCaretColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewCaretColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007938B0 (FUN_007938B0, func_CMauiEditSetNewCaretColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewCaretColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewCaretColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewCaretColor",
    &moho::cfunc_CMauiEditSetNewCaretColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewCaretColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0078EE30 (FUN_0078EE30)
 *
 * What it does:
 * Masks one caret color lane to RGB24 and stores it in edit runtime state.
 */
[[maybe_unused]] static std::uint32_t func_SetEditCaretColorRgb24(
  moho::CMauiEdit* const edit,
  const std::uint32_t color
) noexcept
{
  const std::uint32_t color24 = color & 0x00FFFFFFu;
  edit->mCaretColor = color24;
  return color24;
}

/**
 * Address: 0x00793910 (FUN_00793910, cfunc_CMauiEditSetNewCaretColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus color lane and updates caret RGB lane.
 */
int moho::cfunc_CMauiEditSetNewCaretColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetNewCaretColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  const std::uint32_t caretColor = SCR_DecodeColor(state, colorObject);
  (void)func_SetEditCaretColorRgb24(edit, caretColor);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793A00 (FUN_00793A00, cfunc_CMauiEditGetCaretColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetCaretColorL`.
 */
int moho::cfunc_CMauiEditGetCaretColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetCaretColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793A20 (FUN_00793A20, func_CMauiEditGetCaretColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetCaretColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetCaretColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetCaretColor",
    &moho::cfunc_CMauiEditGetCaretColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetCaretColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793A80 (FUN_00793A80, cfunc_CMauiEditGetCaretColorL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes encoded caret color.
 */
int moho::cfunc_CMauiEditGetCaretColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetCaretColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject = SCR_EncodeColor(state, ReadEditCaretColorLane(edit));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00793B60 (FUN_00793B60, cfunc_CMauiEditSetCaretCycle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetCaretCycleL`.
 */
int moho::cfunc_CMauiEditSetCaretCycle(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetCaretCycleL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793B80 (FUN_00793B80, func_CMauiEditSetCaretCycle_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetCaretCycle(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetCaretCycle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetCaretCycle",
    &moho::cfunc_CMauiEditSetCaretCycle,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetCaretCycleHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793BE0 (FUN_00793BE0, cfunc_CMauiEditSetCaretCycleL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus cycle+alpha lanes and stores caret-cycle state.
 */
int moho::cfunc_CMauiEditSetCaretCycleL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 4, kCMauiEditSetCaretCycleHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject cycleSecondsArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&cycleSecondsArg, "number");
  }

  const float cycleSeconds = lua_tonumber(state->m_state, 2);
  LuaPlus::LuaObject offAlphaObject(LuaPlus::LuaStackObject(state, 3));
  LuaPlus::LuaObject onAlphaObject(LuaPlus::LuaStackObject(state, 4));

  edit->mCaretCycleSeconds = cycleSeconds;
  edit->mCaretCycleOnAlpha = static_cast<std::uint8_t>(SCR_DecodeColor(state, onAlphaObject));
  edit->mCaretCycleOffAlpha = static_cast<std::uint8_t>(SCR_DecodeColor(state, offAlphaObject));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793070 (FUN_00793070, cfunc_CMauiEditSetMaxChars)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditSetMaxCharsL`.
 */
int moho::cfunc_CMauiEditSetMaxChars(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetMaxCharsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793090 (FUN_00793090, func_CMauiEditSetMaxChars_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetMaxChars(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetMaxChars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetMaxChars",
    &moho::cfunc_CMauiEditSetMaxChars,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetMaxCharsHelpText
  );
  return &binder;
}

/**
 * Address: 0x007930F0 (FUN_007930F0, cfunc_CMauiEditSetMaxCharsL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus integer arg, clamps minimum to 1, applies max-char
 * limit, and returns self.
 */
int moho::cfunc_CMauiEditSetMaxCharsL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetMaxCharsHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject maxCharsArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxCharsArg, "integer");
  }

  int maxChars = static_cast<int>(lua_tonumber(state->m_state, 2));
  if (maxChars < 1) {
    maxChars = 1;
  }

  edit->SetMaxChars(maxChars);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793200 (FUN_00793200, cfunc_CMauiEditGetMaxChars)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetMaxCharsL`.
 */
int moho::cfunc_CMauiEditGetMaxChars(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetMaxCharsL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793220 (FUN_00793220, func_CMauiEditGetMaxChars_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetMaxChars()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetMaxChars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetMaxChars",
    &moho::cfunc_CMauiEditGetMaxChars,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetMaxCharsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793280 (FUN_00793280, cfunc_CMauiEditGetMaxCharsL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes current max-char limit.
 */
int moho::cfunc_CMauiEditGetMaxCharsL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetMaxCharsHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(ReadEditMaxCharsLane(edit)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793D70 (FUN_00793D70, cfunc_CMauiEditIsEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditIsEnabledL`.
 */
int moho::cfunc_CMauiEditIsEnabled(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditIsEnabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793D90 (FUN_00793D90, func_CMauiEditIsEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:IsEnabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditIsEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsEnabled",
    &moho::cfunc_CMauiEditIsEnabled,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditIsEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793DF0 (FUN_00793DF0, cfunc_CMauiEditIsEnabledL)
 *
 * What it does:
 * Reads one `CMauiEdit` and pushes enabled-input state.
 */
int moho::cfunc_CMauiEditIsEnabledL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditIsEnabledHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);
  lua_pushboolean(state->m_state, ReadEditInputEnabledLane(edit));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00793EB0 (FUN_00793EB0, cfunc_CMauiEditEnableInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditEnableInputL`.
 */
int moho::cfunc_CMauiEditEnableInput(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditEnableInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00793ED0 (FUN_00793ED0, func_CMauiEditEnableInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:EnableInput()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditEnableInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EnableInput",
    &moho::cfunc_CMauiEditEnableInput,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditEnableInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00793F30 (FUN_00793F30, cfunc_CMauiEditEnableInputL)
 *
 * What it does:
 * Enables edit input/caret lanes and returns self.
 */
int moho::cfunc_CMauiEditEnableInputL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditEnableInputHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  (void)WriteEditInputEnabledAndCaretVisible(edit, true);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00793FF0 (FUN_00793FF0, cfunc_CMauiEditDisableInput)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditDisableInputL`.
 */
int moho::cfunc_CMauiEditDisableInput(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditDisableInputL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794010 (FUN_00794010, func_CMauiEditDisableInput_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:DisableInput()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditDisableInput_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DisableInput",
    &moho::cfunc_CMauiEditDisableInput,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditDisableInputHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794070 (FUN_00794070, cfunc_CMauiEditDisableInputL)
 *
 * What it does:
 * Disables edit input/caret lanes, abandons keyboard focus, and returns self.
 */
int moho::cfunc_CMauiEditDisableInputL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditDisableInputHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  (void)WriteEditInputEnabledAndCaretVisible(edit, false);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794140 (FUN_00794140, cfunc_CMauiEditSetNewHighlightForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewHighlightForegroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewHighlightForegroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewHighlightForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794160 (FUN_00794160, func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewHighlightForegroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewHighlightForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewHighlightForegroundColor",
    &moho::cfunc_CMauiEditSetNewHighlightForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewHighlightForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x007941C0 (FUN_007941C0, cfunc_CMauiEditSetNewHighlightForegroundColorL)
 *
 * What it does:
 * Decodes one highlight-foreground color from Lua and stores it in edit
 * runtime lanes.
 */
int moho::cfunc_CMauiEditSetNewHighlightForegroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetNewHighlightForegroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditHighlightForegroundColorLane(
    edit, SCR_DecodeColor(state, colorObject)
  );
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007942B0 (FUN_007942B0, cfunc_CMauiEditGetHighlightForegroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetHighlightForegroundColorL`.
 */
int moho::cfunc_CMauiEditGetHighlightForegroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetHighlightForegroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007942D0 (FUN_007942D0, func_CMauiEditGetHighlightForegroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetHighlightForegroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetHighlightForegroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetHighlightForegroundColor",
    &moho::cfunc_CMauiEditGetHighlightForegroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetHighlightForegroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794330 (FUN_00794330, cfunc_CMauiEditGetHighlightForegroundColorL)
 *
 * What it does:
 * Reads one edit highlight-foreground color and pushes encoded Lua color.
 */
int moho::cfunc_CMauiEditGetHighlightForegroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetHighlightForegroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject =
    SCR_EncodeColor(state, ReadEditHighlightForegroundColorLane(edit));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x00794410 (FUN_00794410, cfunc_CMauiEditSetNewHighlightBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetNewHighlightBackgroundColorL`.
 */
int moho::cfunc_CMauiEditSetNewHighlightBackgroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetNewHighlightBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794430 (FUN_00794430, func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetNewHighlightBackgroundColor(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetNewHighlightBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewHighlightBackgroundColor",
    &moho::cfunc_CMauiEditSetNewHighlightBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetNewHighlightBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794490 (FUN_00794490, cfunc_CMauiEditSetNewHighlightBackgroundColorL)
 *
 * What it does:
 * Decodes one highlight-background color from Lua and stores it in edit
 * runtime lanes.
 */
int moho::cfunc_CMauiEditSetNewHighlightBackgroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetNewHighlightBackgroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject(LuaPlus::LuaStackObject(state, 2));
  (void)WriteEditHighlightBackgroundColorLane(
    edit, SCR_DecodeColor(state, colorObject)
  );
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794580 (FUN_00794580, cfunc_CMauiEditGetHighlightBackgroundColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetHighlightBackgroundColorL`.
 */
int moho::cfunc_CMauiEditGetHighlightBackgroundColor(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetHighlightBackgroundColorL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007945A0 (FUN_007945A0, func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetHighlightBackgroundColor()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetHighlightBackgroundColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetHighlightBackgroundColor",
    &moho::cfunc_CMauiEditGetHighlightBackgroundColor,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetHighlightBackgroundColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794600 (FUN_00794600, cfunc_CMauiEditGetHighlightBackgroundColorL)
 *
 * What it does:
 * Reads one edit highlight-background color and pushes encoded Lua color.
 */
int moho::cfunc_CMauiEditGetHighlightBackgroundColorL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetHighlightBackgroundColorHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaObject colorObject =
    SCR_EncodeColor(state, ReadEditHighlightBackgroundColorLane(edit));
  colorObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x007946E0 (FUN_007946E0, cfunc_CMauiEditGetFontHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiEditGetFontHeightL`.
 */
int moho::cfunc_CMauiEditGetFontHeight(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetFontHeightL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794700 (FUN_00794700, func_CMauiEditGetFontHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetFontHeight()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetFontHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFontHeight",
    &moho::cfunc_CMauiEditGetFontHeight,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetFontHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794760 (FUN_00794760, cfunc_CMauiEditGetFontHeightL)
 *
 * What it does:
 * Reads edit font lane and pushes integerized font height (`0` when missing).
 */
int moho::cfunc_CMauiEditGetFontHeightL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditGetFontHeightHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  const float fontHeight = ReadEditFontHeightLane(edit);
  lua_pushnumber(state->m_state, static_cast<float>(static_cast<int>(fontHeight)));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00794840 (FUN_00794840, cfunc_CMauiEditAcquireFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditAcquireFocusL`.
 */
int moho::cfunc_CMauiEditAcquireFocus(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditAcquireFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794860 (FUN_00794860, func_CMauiEditAcquireFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:AcquireFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditAcquireFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AcquireFocus",
    &moho::cfunc_CMauiEditAcquireFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditAcquireFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x007948C0 (FUN_007948C0, cfunc_CMauiEditAcquireFocusL)
 *
 * What it does:
 * Reads one `CMauiEdit`, enables caret+keyboard focus when edit is enabled,
 * and returns self.
 */
int moho::cfunc_CMauiEditAcquireFocusL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditAcquireFocusHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  AcquireEditKeyboardFocusIfEnabled(edit);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794990 (FUN_00794990, cfunc_CMauiEditAbandonFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditAbandonFocusL`.
 */
int moho::cfunc_CMauiEditAbandonFocus(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditAbandonFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007949B0 (FUN_007949B0, func_CMauiEditAbandonFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:AbandonFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditAbandonFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AbandonFocus",
    &moho::cfunc_CMauiEditAbandonFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditAbandonFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794A10 (FUN_00794A10, cfunc_CMauiEditAbandonFocusL)
 *
 * What it does:
 * Reads one `CMauiEdit`, abandons keyboard focus, and returns self.
 */
int moho::cfunc_CMauiEditAbandonFocusL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiEditAbandonFocusHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  edit->AbandonKeyboardFocus();
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794AD0 (FUN_00794AD0, cfunc_CMauiEditSetDropShadow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditSetDropShadowL`.
 */
int moho::cfunc_CMauiEditSetDropShadow(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditSetDropShadowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794AF0 (FUN_00794AF0, func_CMauiEditSetDropShadow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:SetDropShadow(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditSetDropShadow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetDropShadow",
    &moho::cfunc_CMauiEditSetDropShadow,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditSetDropShadowHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794B50 (FUN_00794B50, cfunc_CMauiEditSetDropShadowL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus bool arg, stores drop-shadow flag, and returns
 * self.
 */
int moho::cfunc_CMauiEditSetDropShadowL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditSetDropShadowHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject dropShadowArg(state, 2);
  (void)WriteEditDropShadowLane(edit, dropShadowArg.GetBoolean());
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00794C20 (FUN_00794C20, cfunc_CMauiEditGetStringAdvance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiEditGetStringAdvanceL`.
 */
int moho::cfunc_CMauiEditGetStringAdvance(
  lua_State* const luaContext
)
{
  return cfunc_CMauiEditGetStringAdvanceL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00794C40 (FUN_00794C40, func_CMauiEditGetStringAdvance_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiEdit:GetStringAdvance(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiEditGetStringAdvance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetStringAdvance",
    &moho::cfunc_CMauiEditGetStringAdvance,
    &moho::CScrLuaMetatableFactory<moho::CMauiEdit>::Instance(),
    "CMauiEdit",
    kCMauiEditGetStringAdvanceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00794CA0 (FUN_00794CA0, cfunc_CMauiEditGetStringAdvanceL)
 *
 * What it does:
 * Reads one `CMauiEdit` plus string arg and returns measured text advance
 * from edit font lane.
 */
int moho::cfunc_CMauiEditGetStringAdvanceL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiEditGetStringAdvanceHelpText);

  LuaPlus::LuaObject editObject(LuaPlus::LuaStackObject(state, 1));
  CMauiEdit* const edit = SCR_FromLua_CMauiEdit(editObject, state);

  LuaPlus::LuaStackObject textArg(state, 2);
  const char* const text = lua_tostring(state->m_state, 2);
  if (text == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&textArg, "string");
  }

  const float advance = MeasureEditStringAdvanceOrZero(edit, text);
  lua_pushnumber(state->m_state, advance);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00791FF0 (FUN_00791FF0, cfunc_InternalCreateEdit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateEditL`.
 */
int moho::cfunc_InternalCreateEdit(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateEditL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00792010 (FUN_00792010, func_InternalCreateEdit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateEdit(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateEdit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateEdit",
    &moho::cfunc_InternalCreateEdit,
    nullptr,
    "<global>",
    kInternalCreateEditHelpText
  );
  return &binder;
}

/**
 * Address: 0x00792070 (FUN_00792070, cfunc_InternalCreateEditL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiEdit`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateEditL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateEditHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x198)`.
  auto* const edit = AllocateZeroedUiObject<CMauiEdit>(0x198u);
  new (edit) CMauiEdit(&luaObject, parentControl);
  edit->DoInit();
  edit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0078EFE0 (FUN_0078EFE0, Moho::CMauiEdit::CMauiEdit)
 * Mangled: ??0CMauiEdit@Moho@@QAE@PAVLuaObject@LuaPlus@@PAV01@@Z
 *
 * IDA signature:
 * Moho::CMauiEdit *__stdcall Moho::CMauiEdit::CMauiEdit(
 *     Moho::CMauiEdit *this, LuaPlus::LuaObject *a2, Moho::CD3DFont *p_capacity);
 *
 * What it does:
 * Constructs one edit control ("edit" control kind) from a Lua object plus
 * parent lanes, then initializes the full edit/font/caret/selection default
 * state and installs a default "Courier New" 14pt font. Field init order and
 * values mirror the binary exactly.
 *
 * The IMauiDragger base at +0x11C gets
 * Moho::CMauiEdit::`vftable'{for `Moho::IMauiDragger'} (asm 0x0078F04A, VA
 * 0x00E395CC) and a null weak-reference head (+0x120) from ordinary base
 * construction.
 */
moho::CMauiEdit::CMauiEdit(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "edit")
{

  mFont = nullptr;
  mForegroundColor = 0xFFFFFFFFu;
  mBackgroundVisible = true;
  mBackgroundColor = 0xFF000000u;
  mHighlightForegroundColor = 0xFF000000u;
  mHighlightBackgroundColor = 0xFFFFFFFFu;
  mDropShadow = false;
  mIsEnabled = true;
  // mText (+0x140) is already default-constructed (empty) by the runtime-view /
  // base construction; the binary's inline SSO reset is the empty-string init.

  mCaretCycleCurrentAlpha = 255u; // .c mCaretCurColor
  mCaretCycleSeconds = 1.5f;      // .c mCaretCycleSeconds
  mCaretCycleOnAlpha = 255u;      // .c mCaretCycleOnColor
  mCaretPosition = 0;
  mCaretVisible = false;
  mCaretColor = 16711422u;   // .c mCaretColor (0xFEFEFE)
  mCaretCycleOffAlpha = 62u; // .c mCaretCycleOffColor
  mCaretCycleTime = 0.0f;    // .c mCaretTime

  mClipOffset = 0;
  mClipLength = 0;
  mSelectionStart = 0;
  mSelectionEnd = 0;
  mDragStart = 0;
  mTextChangeCallbackInProgress = false; // .c mDoingCallback
  mMaxChars = 1024;

  // Create the default "Courier New" 14pt font and apply it. Mirrors the
  // sibling `cfunc_CMauiEditSetNewFontL` idiom: CD3DFont::Create ->
  // ApplyEditFontAndRefreshClip -> release(). The .c's middle `0.0f` argument to
  // sub_78F620 is the elided requested-clip-offset lane already handled inside
  // ApplyEditFontAndRefreshClip (FUN_0078F620).
  boost::SharedPtrRaw<CD3DFont> defaultFont = CD3DFont::Create(14, "Courier New");
  ApplyEditFontAndRefreshClip(this, defaultFont);
  defaultFont.release();

  mNeedsFrameUpdate = true;
}

/**
 * Address: 0x0078F1B0 (FUN_0078F1B0, Moho::CMauiEdit::~CMauiEdit)
 * Mangled: ??1CMauiEdit@Moho@@QAE@XZ
 *
 * What it does:
 * Releases edit text/font ownership lanes, clears click-dragger intrusive
 * link nodes, and then tears down the `CMauiControl` base.
 */
moho::CMauiEdit::~CMauiEdit()
{
  ReleaseIntrusiveFont(mFont);

  // asm 0x0078F230: the IMauiDragger base's vptr at +0x11C goes back to
  // ??_7IMauiDragger@Moho@@6B@, and 0x0078F236-0x0078F250 drain its
  // weak-reference head at +0x120. Both halves are `~IMauiDragger`
  // (0x0078DB20) inlined, which the compiler emits after this body along with
  // `mText`'s destruction; neither belongs here.
}

/**
 * Address: 0x0078F720 (FUN_0078F720, Moho::CMauiEdit::Frame)
 *
 * What it does:
 * Dispatches script `OnFrame(delta)` and updates the caret blink-phase alpha
 * lane from configured on/off alpha cycle parameters.
 */
void moho::CMauiEdit::Frame(
  const float deltaSeconds
)
{
  RunScriptNum("OnFrame", deltaSeconds);

  const float cycleSeconds = mCaretCycleSeconds;
  const float nextCycleTime = mCaretCycleTime + deltaSeconds;
  mCaretCycleTime = nextCycleTime;
  if (nextCycleTime > cycleSeconds) {
    mCaretCycleTime = 0.0f;
  }

  const float cycleBlendFactor = mCaretCycleTime <= (cycleSeconds * 0.5f)
    ? ((mCaretCycleTime / cycleSeconds) * 2.0f)
    : (((cycleSeconds - mCaretCycleTime) / cycleSeconds) * 2.0f);

  const int offAlpha = static_cast<int>(mCaretCycleOffAlpha);
  const int alphaDelta = static_cast<int>(mCaretCycleOnAlpha) - offAlpha;
  const int blendedAlpha = static_cast<int>(
    (static_cast<double>(alphaDelta) * static_cast<double>(cycleBlendFactor)) + static_cast<double>(offAlpha)
  );
  mCaretCycleCurrentAlpha = static_cast<std::uint32_t>(blendedAlpha);
}

/**
 * Address: 0x0078F820 (FUN_0078F820, Moho::CMauiEdit::DoRender)
 *
 * What it does:
 * Draws edit background, clipped text runs, selection highlight, drop shadow,
 * and caret geometry.
 */
void moho::CMauiEdit::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;
  if (primBatcher == nullptr) {
    return;
  }

  CD3DFont* const font = mFont;
  if (font == nullptr) {
    return;
  }

  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);

  if (mBackgroundVisible) {
    DrawSolidColorQuad(primBatcher, mBackgroundColor, left, top, right, bottom, mVertexAlpha);
  }

  const int clipStart = mClipOffset;
  const int clipEnd = clipStart + mClipLength;
  const float baselineY = top + font->mAscent;

  float penX = left;
  int firstRunEnd = mSelectionStart;
  if (firstRunEnd >= clipEnd) {
    firstRunEnd = clipEnd;
  }

  if (firstRunEnd > clipStart) {
    const fa::string runText = gpg::STR_Utf8SubString(mText.c_str(), clipStart, firstRunEnd - clipStart);
    penX += RenderEditTextRun(this, primBatcher, runText, penX, baselineY, mForegroundColor);
  }

  int selectedStart = mSelectionStart;
  if (selectedStart < clipStart) {
    selectedStart = clipStart;
  }

  int selectedEnd = mSelectionEnd;
  if (selectedEnd >= clipEnd) {
    selectedEnd = clipEnd;
  }

  if (selectedEnd > selectedStart) {
    const fa::string runText =
      gpg::STR_Utf8SubString(mText.c_str(), selectedStart, selectedEnd - selectedStart);
    const float runAdvance = font->GetAdvance(runText.c_str(), 0);

    if (mBackgroundVisible) {
      DrawSolidColorQuad(
        primBatcher,
        mHighlightBackgroundColor,
        penX,
        top,
        penX + runAdvance,
        bottom,
        mVertexAlpha
      );
    }

    penX +=
      RenderEditTextRun(this, primBatcher, runText, penX, baselineY, mHighlightForegroundColor);
  }

  int suffixStart = mSelectionEnd;
  if (suffixStart < clipStart) {
    suffixStart = clipStart;
  }

  if (clipEnd > suffixStart) {
    const fa::string runText = gpg::STR_Utf8SubString(mText.c_str(), suffixStart, clipEnd - suffixStart);
    (void)RenderEditTextRun(this, primBatcher, runText, penX, baselineY, mForegroundColor);
  }

  if (!mCaretVisible) {
    return;
  }

  const int caretPosition = mCaretPosition;
  if (caretPosition < clipStart || caretPosition > clipEnd) {
    return;
  }

  const fa::string caretPrefix =
    gpg::STR_Utf8SubString(mText.c_str(), clipStart, caretPosition - clipStart);
  const float caretX = left + font->GetAdvance(caretPrefix.c_str(), 0);
  const float caretBottom = top + font->mAscent + font->mDescent;
  const std::uint32_t caretColor = mCaretColor | (mCaretCycleCurrentAlpha << 24u);
  DrawSolidColorQuad(primBatcher, mForegroundColor, caretX, top, caretX + 1.0f, caretBottom, caretColor);
}

/**
 * Address: 0x00790470 (FUN_00790470, Moho::CMauiEdit::HandleEvent)
 *
 * What it does:
 * Routes button press/double-click lanes to click handling and dispatches
 * character events into edit-key processing.
 */
bool moho::CMauiEdit::HandleEvent(
  const SMauiEventData& eventData
)
{
  if (eventData.mEventType < MET_ButtonPress) {
    return false;
  }

  if (eventData.mEventType <= MET_ButtonDClick) {
    HandleClickEvent(const_cast<SMauiEventData*>(&eventData));
  } else if (eventData.mEventType == MET_Char) {
    HandleKeyEvent(const_cast<SMauiEventData*>(&eventData));
  }

  return false;
}

/**
 * Address: 0x0078F330 (FUN_0078F330, Moho::CMauiEdit::AbandonKeyboardFocus)
 *
 * What it does:
 * Hides caret rendering and clears keyboard focus when this edit currently
 * owns the global focus lane.
 */
void moho::CMauiEdit::AbandonKeyboardFocus()
{
  (void)WriteEditCaretVisibleLane(this, false);
  if (Maui_CurrentFocusControl.GetObjectPtr() == this) {
    MAUI_SetKeyboardFocus(nullptr, true);
  }
}
/**
 * Address: 0x007915A0 (FUN_007915A0, Moho::CMauiEdit::LosingKeyboardFocus)
 *
 * What it does:
 * Drops keyboard focus through the virtual abandon lane and emits
 * OnLoseKeyboardFocus.
 */
void moho::CMauiEdit::LosingKeyboardFocus()
{
  CMauiControl* const control = this;
  control->AbandonKeyboardFocus();
  (void)RunScript("OnLoseKeyboardFocus");
}

/**
 * Address: 0x007906F0 (FUN_007906F0, Moho::CMauiEdit::GetSelection)
 *
 * What it does:
 * Returns the currently selected UTF-8 substring from the edit text lane.
 */
fa::string moho::CMauiEdit::GetSelection()
{
  fa::string selectionText{};

  const int selectionStart = mSelectionStart;
  const int selectionEnd = mSelectionEnd;
  if (HasEditSelectionRange(this)) {
    selectionText = gpg::STR_Utf8SubString(mText.c_str(), selectionStart, selectionEnd - selectionStart);
  }

  return selectionText;
}

/**
 * Address: 0x007904D0 (FUN_007904D0, Moho::CMauiEdit::EnterPressed)
 *
 * What it does:
 * Invokes `OnEnterPressed(self, text)` and returns the script bool result.
 */
bool moho::CMauiEdit::EnterPressed()
{
  return RunScriptStringBool(
    "OnEnterPressed", std::string(mText.c_str())
  );
}

/**
 * Address: 0x007904F0 (FUN_007904F0, Moho::CMauiEdit::EscPressed)
 *
 * What it does:
 * Invokes `OnEscPressed(self, text)` and returns the script bool result.
 */
bool moho::CMauiEdit::EscPressed()
{
  return RunScriptStringBool(
    "OnEscPressed", std::string(mText.c_str())
  );
}

/**
 * Address: 0x007907B0 (FUN_007907B0, IDA: Moho::CMauiEdit::ClearSelection)
 *
 * IDA signature:
 * void __usercall Moho::CMauiEdit::ClearSelection(Moho::CMauiEdit *arg0, wchar_t ch);
 *
 * What it does:
 * Types one character: builds the two-wide-character buffer `{ch, 0}`, converts
 * it to UTF-8 and hands it to `ReplaceSelection`, which drops the current
 * selection and inserts the text in its place.
 *
 * IDA's name is wrong and its decompile drops the character - the function
 * `retn 8`s, and the prologue reads a 16-bit value out of the second argument
 * slot (`mov ax, [esp+28h+a3]`) straight into the buffer it converts. The one
 * call site, in `CMauiEdit::HandleKeyEvent`, pushes `word ptr [edi+0x14]` -
 * the low half of `SMauiEventData::mKeyCode`. Recovered as a no-argument
 * "clear" it inserted an empty string, so every keypress in an edit box
 * deleted the selection and typed nothing.
 */
void moho::CMauiEdit::InsertChar(
  const wchar_t character
)
{
  const wchar_t characterBuffer[2] = {character, L'\0'};
  ReplaceSelection(gpg::STR_WideToUtf8(characterBuffer));
}

/**
 * Address: 0x00790830 (FUN_00790830, Moho::CMauiEdit::ReplaceSelection)
 *
 * What it does:
 * Deletes current selection and inserts replacement UTF-8 text (clamped to
 * max-char lane), then emits `OnTextChanged` when callback guard allows.
 */
void moho::CMauiEdit::ReplaceSelection(
  const fa::string& replacementText
)
{

  fa::string insertText{};
  const int replacementLength = gpg::STR_Utf8Len(replacementText.c_str());
  const int currentLength = gpg::STR_Utf8Len(mText.c_str());
  if ((currentLength + replacementLength) <= mMaxChars) {
    insertText = replacementText;
  } else {
    if (currentLength >= mMaxChars) {
      return;
    }

    const int maxInsertChars = mMaxChars - currentLength;
    insertText = gpg::STR_Utf8SubString(replacementText.c_str(), 0, maxInsertChars);
  }

  DeleteSelection(false);
  const fa::string oldText = mText;

  if (insertText.size() != 0u) {
    const int caretPosition = mCaretPosition;
    if (caretPosition == gpg::STR_Utf8Len(mText.c_str())) {
      mText += insertText;
      const int insertedLength = gpg::STR_Utf8Len(insertText.c_str());
      mCaretPosition += insertedLength;
      mClipLength += insertedLength;
      SetEditClipOffsetRight(this, 0);
    } else {
      const int caretByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), caretPosition);
      (void)mText.replace(static_cast<std::size_t>(caretByteOffset), 0u, insertText.view());

      mCaretPosition += gpg::STR_Utf8Len(insertText.c_str());
      if (mCaretPosition >= (mClipOffset + mClipLength)) {
        const int nextTextLength = gpg::STR_Utf8Len(mText.c_str());
        SetEditClipOffsetRight(this, nextTextLength - mCaretPosition);
      } else {
        SetEditClipOffsetLeft(this, mClipOffset);
      }
    }
  }

  if (!mTextChangeCallbackInProgress) {
    mTextChangeCallbackInProgress = true;
    TextChanged(mText, oldText);
    mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x00790510 (FUN_00790510, Moho::CMauiEdit::NonTextKeyPressed)
 *
 * What it does:
 * Builds one Lua event payload and invokes `OnNonTextKeyPressed(key,event)`.
 */
void moho::CMauiEdit::NonTextKeyPressed(
  const int keyCode,
  SMauiEventData* const eventData
)
{
  LuaPlus::LuaState* const activeState =
    mLuaObj.GetActiveState();
  LuaPlus::LuaObject eventObject{};
  const LuaPlus::LuaObject* const createdEvent = CreateLuaEventObject(eventData, &eventObject, activeState);
  RunScriptIntObject("OnNonTextKeyPressed", keyCode, *createdEvent);
}

/**
 * Address: 0x00790590 (FUN_00790590, Moho::CMauiEdit::DeleteSelection)
 *
 * What it does:
 * Deletes the current UTF-8 selection range, updates caret/clip lanes, and
 * emits `OnTextChanged` unless callback suppression is requested.
 */
void moho::CMauiEdit::DeleteSelection(
  const bool suppressCallback
)
{
  if (mSelectionStart == mSelectionEnd) {
    return;
  }

  const fa::string oldText = mText;
  const int textLength = gpg::STR_Utf8Len(mText.c_str());
  if (mSelectionEnd > textLength) {
    mSelectionEnd = textLength;
  }

  const int selectionStart = mSelectionStart;
  mCaretPosition = selectionStart;

  const int selectionStartByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), selectionStart);
  const int selectionEndByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), mSelectionEnd);
  mText.erase(selectionStartByteOffset, selectionEndByteOffset - selectionStartByteOffset);

  if (mCaretPosition < mClipOffset) {
    mClipOffset = mCaretPosition;
  }

  mSelectionStart = 0;
  mSelectionEnd = 0;

  if (!suppressCallback && !mTextChangeCallbackInProgress) {
    mTextChangeCallbackInProgress = true;
    TextChanged(mText, oldText);
    mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078EDD0 (FUN_0078EDD0, Moho::CMauiEdit::GetText)
 *
 * What it does:
 * Returns one copy of the current edit text lane.
 */
fa::string moho::CMauiEdit::GetText()
{
  return mText;
}

/**
 * Address: 0x00790B40 (FUN_00790B40, Moho::CMauiEdit::DeleteCharAtCaret)
 *
 * What it does:
 * Deletes either the selected range or one UTF-8 character at/left of the
 * caret, then refreshes clip state and emits `OnTextChanged`.
 */
void moho::CMauiEdit::DeleteCharAtCaret(
  const bool deleteToRight
)
{
  const fa::string oldText = mText;

  if (mSelectionStart != mSelectionEnd) {
    DeleteSelection(false);
    SetEditClipOffsetLeft(this, mClipOffset);
  } else if (deleteToRight) {
    const int caretPosition = mCaretPosition;
    if (caretPosition != gpg::STR_Utf8Len(mText.c_str())) {
      const int deleteStartByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), caretPosition);
      const int deleteEndByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), caretPosition + 1);
      mText.erase(deleteStartByteOffset, deleteEndByteOffset - deleteStartByteOffset);
    }

    SetEditClipOffsetLeft(this, mClipOffset);
  } else if (mCaretPosition != 0) {
    const int deleteStartCharIndex = mCaretPosition - 1;
    const int deleteStartByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), deleteStartCharIndex);
    const int deleteEndByteOffset = gpg::STR_Utf8ByteOffset(mText.c_str(), mCaretPosition);
    mText.erase(deleteStartByteOffset, deleteEndByteOffset - deleteStartByteOffset);

    const int currentCaretPosition = mCaretPosition;
    if (currentCaretPosition != 0) {
      int caretStep = 1;
      if (currentCaretPosition <= 1) {
        caretStep = currentCaretPosition;
      }
      SetCaretPosition(currentCaretPosition - caretStep);
    }

    if (mCaretPosition != 0 && mCaretPosition == mClipOffset) {
      SetEditClipOffsetLeft(this, mClipOffset - 1);
    }
  }

  if (!mTextChangeCallbackInProgress) {
    mTextChangeCallbackInProgress = true;
    TextChanged(mText, oldText);
    mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x007911B0 (FUN_007911B0, Moho::CMauiEdit::SetCaretPosition)
 *
 * What it does:
 * Updates caret position and adjusts clip-left/right window when the caret
 * crosses the visible text range.
 */
void moho::CMauiEdit::SetCaretPosition(
  int position
)
{

  if (position < mCaretPosition) {
    mCaretPosition = position;
    if (position < mClipOffset) {
      SetEditClipOffsetLeft(this, position);
    }
    return;
  }

  if (position <= mCaretPosition) {
    return;
  }

  const int textLength = gpg::STR_Utf8Len(mText.c_str());
  if (position >= textLength) {
    position = textLength;
  }

  const int clipEnd = mClipOffset + mClipLength;
  mCaretPosition = position;
  if (position >= clipEnd) {
    SetEditClipOffsetRight(this, textLength - mCaretPosition);
  }
}

/**
 * Address: 0x00791250 (FUN_00791250, Moho::CMauiEdit::MoveCaretLeft)
 *
 * What it does:
 * Moves caret left by `amount` characters, clamped to the start-of-text lane.
 */
void moho::CMauiEdit::MoveCaretLeft(
  int amount
)
{
  const int caretPosition = mCaretPosition;
  if (caretPosition == 0) {
    return;
  }

  if (amount >= caretPosition) {
    amount = caretPosition;
  }

  SetCaretPosition(caretPosition - amount);
}

/**
 * Address: 0x00791270 (FUN_00791270, Moho::CMauiEdit::MoveCaretRight)
 *
 * What it does:
 * Moves caret right by `amount` UTF-8 characters through `SetCaretPosition`.
 */
void moho::CMauiEdit::MoveCaretRight(
  const int amount
)
{
  const int caretPosition = mCaretPosition;
  SetCaretPosition(caretPosition + amount);
}

/**
 * Address: 0x00791290 (FUN_00791290, Moho::CMauiEdit::MoveSelectionLeft)
 *
 * What it does:
 * Extends/contracts current selection toward the left by `amount` while
 * preserving anchor semantics used by keyboard-shift navigation.
 */
void moho::CMauiEdit::MoveSelectionLeft(
  int amount
)
{
  if (mSelectionStart == mSelectionEnd) {
    const int caretPosition = mCaretPosition;
    mSelectionStart = caretPosition;
    mSelectionEnd = caretPosition;
  }

  const int oldCaretPosition = mCaretPosition;
  if (oldCaretPosition != 0) {
    if (amount >= oldCaretPosition) {
      amount = oldCaretPosition;
    }
    SetCaretPosition(oldCaretPosition - amount);
  }

  const int newCaretPosition = mCaretPosition;
  if (oldCaretPosition == newCaretPosition) {
    return;
  }

  if (mSelectionStart == newCaretPosition) {
    mSelectionStart = 0;
    mSelectionEnd = 0;
  } else if (mSelectionStart >= newCaretPosition) {
    mSelectionStart = newCaretPosition;
  } else {
    mSelectionEnd = newCaretPosition;
  }
}

/**
 * Address: 0x00791310 (FUN_00791310, Moho::CMauiEdit::MoveSelectionRight)
 *
 * What it does:
 * Extends/contracts current selection toward the right by `amount` while
 * preserving anchor semantics used by keyboard-shift navigation.
 */
void moho::CMauiEdit::MoveSelectionRight(
  const int amount
)
{
  if (mSelectionStart == mSelectionEnd) {
    const int caretPosition = mCaretPosition;
    mSelectionStart = caretPosition;
    mSelectionEnd = caretPosition;
  }

  const int oldCaretPosition = mCaretPosition;
  SetCaretPosition(oldCaretPosition + amount);

  const int newCaretPosition = mCaretPosition;
  if (oldCaretPosition == newCaretPosition) {
    return;
  }

  if (mSelectionEnd == newCaretPosition) {
    mSelectionStart = 0;
    mSelectionEnd = 0;
  } else if (mSelectionEnd <= newCaretPosition) {
    mSelectionEnd = newCaretPosition;
  } else {
    mSelectionStart = newCaretPosition;
  }
}

/**
 * Address: 0x007915C0 (FUN_007915C0, Moho::CMauiEdit::HandleClickEvent)
 *
 * What it does:
 * Handles left-button click/double-click lanes by focusing the control,
 * posting dragger capture, and updating caret/word-selection lanes.
 */
void moho::CMauiEdit::HandleClickEvent(
  SMauiEventData* const eventData
)
{
  if ((eventData->mModifiers & MEM_Left) == 0) {
    return;
  }

  if (mIsEnabled) {
    mCaretVisible = true;
    MAUI_SetKeyboardFocus(this, true);
  }

  const float localMouseX = eventData->mMousePos.x - CScriptLazyVar_float::GetValue(&mLeftLV);
  fa::string clippedText =
    gpg::STR_Utf8SubString(mText.c_str(), mClipOffset, mClipLength);
  const int nearestCharacterIndex = mFont->GetNearestCharacterIndex(clippedText.c_str(), localMouseX);

  if (eventData->mEventType == MET_ButtonPress) {
    func_PostDragger(GetRootFrame(), static_cast<IMauiDragger*>(this), eventData);

    const int caretPosition = mClipOffset + nearestCharacterIndex;
    mDragStart = caretPosition;
    SetCaretPosition(caretPosition);
    return;
  }

  const int wordStartIndex = gpg::STR_GetWordStartIndex(clippedText, nearestCharacterIndex);
  const int selectionEndOffset = gpg::STR_GetNextWordStartIndex(clippedText, wordStartIndex);

  const int selectionStart = mClipOffset + wordStartIndex;
  const int selectionEnd = mClipOffset + selectionEndOffset;
  mSelectionStart = selectionStart;
  mSelectionEnd = selectionEnd;
  SetCaretPosition(selectionEnd);
}

/**
 * Address: 0x007913A0 (FUN_007913A0, Moho::CMauiEdit::DragMove)
 *
 * What it does:
 * IMauiDragger slot 1: maps the current mouse X to the nearest character index
 * in the clipped text, then extends the selection between the drag-start caret
 * and that index (clearing it when they coincide) and moves the caret to the
 * dragged-to position.
 */
void moho::CMauiEdit::DragMove(
  const SMauiEventData* const eventData
)
{
  const float localMouseX = eventData->mMousePos.x - CScriptLazyVar_float::GetValue(&mLeftLV);
  fa::string clippedText = gpg::STR_Utf8SubString(mText.c_str(), mClipOffset, mClipLength);
  const int caretIndex = mFont->GetNearestCharacterIndex(clippedText.c_str(), localMouseX) + mClipOffset;

  const int dragStart = mDragStart;
  if (caretIndex == dragStart) {
    mSelectionStart = 0;
    mSelectionEnd = 0;
    return;
  }

  if (caretIndex >= dragStart) {
    mSelectionStart = dragStart;
    mSelectionEnd = caretIndex;
  } else {
    mSelectionStart = caretIndex;
    mSelectionEnd = dragStart;
  }
  SetCaretPosition(caretIndex);
}

/**
 * Address: 0x00791590 (FUN_00791590, Moho::CMauiEdit::OnCurrentDraggerReplaced)
 *
 * What it does:
 * IMauiDragger slot 3: nothing - unlike the base, the edit is not deleted when
 * another dragger replaces it.
 */
void moho::CMauiEdit::OnCurrentDraggerReplaced() {}

/**
 * Address: 0x00791780 (FUN_00791780, Moho::CMauiEdit::HandleKeyEvent)
 *
 * What it does:
 * Processes edit keyboard lanes: caret/selection movement, delete/backspace,
 * clipboard shortcuts, and text/non-text callback dispatch.
 */
void moho::CMauiEdit::HandleKeyEvent(
  SMauiEventData* const eventData
)
{
  const int keyCode = eventData->mKeyCode;

  auto processDefaultKeyPath = [&]() {
    if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
      constexpr int kCtrlCChar = 3;
      constexpr int kCtrlVChar = 22;
      constexpr int kCtrlXChar = 24;

      switch (keyCode) {
      case kCtrlCChar:
        CopyEditSelectionToClipboard(this);
        break;
      case kCtrlVChar:
        ReplaceSelection(moho::WIN_GetClipboardText());
        break;
      case kCtrlXChar:
        CopyEditSelectionToClipboard(this);
        DeleteSelection(true);
        break;
      default:
        break;
      }
      return;
    }

    if (keyCode <= MKEY_START) {
      // Script gets first refusal on the character; returning true means it
      // handled the key itself and nothing is typed.
      if (!RunScriptOnCharPressedThunk(this, keyCode)) {
        InsertChar(static_cast<wchar_t>(static_cast<std::uint16_t>(keyCode)));
      }
      return;
    }

    [[maybe_unused]] bool isSpecial = false;
    const int translatedKeyCode = wxCharCodeWXToMSW(keyCode, &isSpecial);
    NonTextKeyPressed(translatedKeyCode, eventData);
  };

  if (keyCode > MKEY_END) {
    switch (static_cast<EMauiKeyCode>(keyCode)) {
    case MKEY_HOME:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        const int moveAmount = mCaretPosition;
        if (moveAmount != 0) {
          MoveSelectionLeft(moveAmount);
        }
      } else {
        mCaretPosition = 0;
        mSelectionStart = 0;
        mSelectionEnd = 0;
        SetEditClipOffsetLeft(this, 0);
      }
      break;

    case MKEY_LEFT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int moveAmount =
            mCaretPosition - gpg::STR_GetWordStartIndex(mText, mCaretPosition);
          if (moveAmount != 0) {
            MoveSelectionLeft(moveAmount);
          }
        } else {
          MoveSelectionLeft(1);
        }
      } else {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int wordStart = gpg::STR_GetWordStartIndex(mText, mCaretPosition);
          SetCaretPosition(wordStart);
        } else {
          MoveCaretLeft(1);
        }
        mSelectionStart = 0;
        mSelectionEnd = 0;
      }
      break;

    case MKEY_RIGHT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          const int nextWordStart = gpg::STR_GetNextWordStartIndex(mText, mCaretPosition);
          const int moveAmount = nextWordStart - mCaretPosition;
          if (moveAmount != 0) {
            MoveSelectionRight(moveAmount);
          }
        } else {
          MoveSelectionRight(1);
        }
      } else {
        int nextCaretPosition = mCaretPosition + 1;
        if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
          nextCaretPosition = gpg::STR_GetNextWordStartIndex(mText, mCaretPosition);
        }

        SetCaretPosition(nextCaretPosition);
        mSelectionStart = 0;
        mSelectionEnd = 0;
      }
      break;

    case MKEY_INSERT:
      if ((eventData->mModifiers & MEM_Shift) != 0u) {
        ReplaceSelection(moho::WIN_GetClipboardText());
      } else if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
        CopyEditSelectionToClipboard(this);
      }
      break;

    default:
      processDefaultKeyPath();
      break;
    }

    return;
  }

  if (keyCode == MKEY_END) {
    if ((eventData->mModifiers & MEM_Shift) != 0u) {
      const int textLength = gpg::STR_Utf8Len(mText.c_str());
      const int moveAmount = textLength - mCaretPosition;
      if (moveAmount != 0) {
        MoveSelectionRight(moveAmount);
      }
    } else {
      mCaretPosition = gpg::STR_Utf8Len(mText.c_str());
      mSelectionStart = 0;
      mSelectionEnd = 0;
      SetEditClipOffsetRight(this, 0);
    }
    return;
  }

  switch (static_cast<EMauiKeyCode>(keyCode)) {
  case MKEY_BACK:
    if ((eventData->mModifiers & MEM_Alt) != 0u) {
      return;
    }

    if ((eventData->mModifiers & MEM_Ctrl) == 0u) {
      DeleteCharAtCaret(false);
      DeleteSelection(true);
      return;
    }

    {
      const int moveAmount =
        mCaretPosition - gpg::STR_GetWordStartIndex(mText, mCaretPosition);
      if (moveAmount != 0) {
        MoveSelectionLeft(moveAmount);
      }
    }
    DeleteSelection(true);
    return;

  case MKEY_RETURN:
    if (!EnterPressed()) {
      if (mText.size() != 0u) {
        ClearText();
      } else {
        AbandonKeyboardFocus();
      }
    }
    return;

  case MKEY_ESCAPE:
    if (EscPressed()) {
      return;
    }

    if (mText.size() != 0u) {
      ClearText();
    } else {
      AbandonKeyboardFocus();
    }
    return;

  case MKEY_DELETE:
    if ((eventData->mModifiers & MEM_Shift) != 0u) {
      CopyEditSelectionToClipboard(this);
      DeleteSelection(true);
      return;
    }

    if ((eventData->mModifiers & MEM_Ctrl) != 0u) {
      const int moveAmount =
        gpg::STR_GetNextWordStartIndex(mText, mCaretPosition) - mCaretPosition;
      if (moveAmount != 0) {
        MoveSelectionRight(moveAmount);
      }
      DeleteSelection(true);
      return;
    }

    DeleteCharAtCaret(true);
    DeleteSelection(true);
    return;

  default:
    processDefaultKeyPath();
    return;
  }
}

/**
 * Address: 0x007914C0 (FUN_007914C0, Moho::CMauiEdit::DragRelease)
 *
 * What it does:
 * Computes the clipped text hit-test for a release event and clears selection
 * when the release landed back on the original drag start lane.
 */
void moho::CMauiEdit::DragRelease(
  const SMauiEventData* const eventData
)
{
  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float releaseX = eventData->mMousePos.x - left;

  fa::string clippedText =
    gpg::STR_Utf8SubString(mText.c_str(), mClipOffset, mClipLength);
  const int releaseCaret =
    mFont->GetNearestCharacterIndex(clippedText.c_str(), releaseX) + mClipOffset;

  if (releaseCaret == mDragStart) {
    mSelectionStart = 0;
    mSelectionEnd = 0;
  }
}

/**
 * Address: 0x00794F20 (FUN_00794F20, Moho::CMauiEdit::TextChanged)
 *
 * What it does:
 * A `RunScript` instantiation: invokes `OnTextChanged(self, newText, oldText)`
 * under the weak guard; a script error is reported through LogScriptWarning
 * (runtime_error, handler 0x0079505C).
 */
void moho::CMauiEdit::TextChanged(
  const fa::string& newText,
  const fa::string& oldText
)
{
  (void)RunScript("OnTextChanged", newText.c_str(), oldText.c_str());
}

/**
 * Address: 0x0078F380 (FUN_0078F380, Moho::CMauiEdit::SetText)
 *
 * What it does:
 * Applies one UTF-8 text lane (clamped by max chars), refreshes caret/clip
 * state, and emits `OnTextChanged` callback when reentrancy guard allows.
 */
void moho::CMauiEdit::SetText(
  const fa::string& text
)
{
  const fa::string previousText = mText;

  mText = gpg::STR_Utf8SubString(text.c_str(), 0, mMaxChars);
  mCaretPosition = gpg::STR_Utf8Len(mText.c_str());
  mClipOffset = 0;
  mClipLength = gpg::STR_Utf8Len(mText.c_str());
  SetEditClipOffsetRight(this, 0);

  if (!mTextChangeCallbackInProgress) {
    mTextChangeCallbackInProgress = true;
    TextChanged(mText, previousText);
    mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078F4C0 (FUN_0078F4C0, Moho::CMauiEdit::ClearText)
 *
 * What it does:
 * Clears current edit text/caret/selection lanes and emits `OnTextChanged`
 * when callback reentrancy guard allows.
 */
void moho::CMauiEdit::ClearText()
{
  const fa::string previousText = mText;

  mText.clear();
  mCaretPosition = 0;
  mClipLength = 0;
  mClipOffset = 0;
  mSelectionStart = 0;
  mSelectionEnd = 0;

  if (!mTextChangeCallbackInProgress) {
    mTextChangeCallbackInProgress = true;
    TextChanged(mText, previousText);
    mTextChangeCallbackInProgress = false;
  }
}

/**
 * Address: 0x0078F570 (FUN_0078F570, Moho::CMauiEdit::SetMaxChars)
 *
 * What it does:
 * Stores one max-char limit and truncates current edit text to that UTF-8
 * character count when needed.
 */
void moho::CMauiEdit::SetMaxChars(
  const int newMaxChars
)
{
  mMaxChars = newMaxChars;

  const int textLength = gpg::STR_Utf8Len(mText.c_str());
  if (newMaxChars < textLength) {
    mText = gpg::STR_Utf8SubString(mText.c_str(), 0, newMaxChars);
  }
}

/**
 * Address: 0x0078F280 (FUN_0078F280, Moho::CMauiEdit::Dump)
 *
 * What it does:
 * Logs the base CMauiControl state, then logs CMauiEdit-specific colors,
 * background visibility, max-char limit, and the current text content.
 */
void moho::CMauiEdit::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiEdit");

  const char* const showBackground = ReadEditBackgroundVisibleLane(this) ? "true" : "false";
  gpg::Logf(
    "FG Color = %#08X BG Color = %#08X HLFG Color = %#08X HLBG Color = %#08X Show BG = %s MaxChars = %d",
    mForegroundColor,
    mBackgroundColor,
    mHighlightForegroundColor,
    mHighlightBackgroundColor,
    showBackground,
    mMaxChars
  );
  gpg::Logf("Current Text = %s", mText.c_str());
}

/**
 * Address: 0x0078EC80 (FUN_0078EC80, Moho::CMauiEdit::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiEdit`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiEdit::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiEdit));
  }
  return sType;
}

/**
 * Address: 0x0078ECA0 (FUN_0078ECA0, Moho::CMauiEdit::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiEdit::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

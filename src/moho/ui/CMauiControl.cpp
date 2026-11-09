#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCMauiControlDestroyHelpText = "Control:Destroy() -- destroy a control.\n";
  constexpr const char* kCMauiControlClearChildrenHelpText = "ClearChildren()";
  constexpr const char* kCMauiControlSetParentHelpText =
    "Control:SetParent(newParentControl) -- change the control's parent";
  constexpr const char* kCMauiControlDisableHitTestHelpText =
    "Control:DisableHitTest([recursive]) -- hit testing will be skipped for this control";
  constexpr const char* kCMauiControlEnableHitTestHelpText =
    "Control:EnableHitTest([recursive]) -- hit testing will be checked for this control";
  constexpr const char* kCMauiControlIsHitTestDisabledHelpText =
    "Control:IsHitTestDisabled() -- determine if hit testing is disabled";
  constexpr const char* kCMauiControlApplyFunctionHelpText =
    "ApplyFunction(func) - applys a function to this control and all children, function will recieve the control "
    "object "
    "as the only parameter";
  constexpr const char* kCMauiControlHitTestHelpText =
    "bool HitTest(x, y) - given x,y coordinates, tells you if the control is under the coordinates";
  constexpr const char* kCMauiControlGetParentHelpText =
    "Control:GetParent() -- return the parent of this control, or nil if it doesn't have one.";
  constexpr const char* kCMauiControlHideHelpText = "Control:Hide() -- stop rendering and hit testing the control";
  constexpr const char* kCMauiControlShowHelpText = "Control:Show() -- start rendering and hit testing the control";
  constexpr const char* kCMauiControlSetHiddenHelpText = "Control:SetHidden() -- set the hidden state of the control";
  constexpr const char* kCMauiControlIsHiddenHelpText = "Control:IsHidden() -- determine if the control is hidden";
  constexpr const char* kCMauiControlGetRootFrameHelpText = "Frame GetRootFrame()";
  constexpr const char* kCMauiControlSetAlphaHelpText =
    "SetAlpha(float, children) - Set the alpha of a given control, if children is true, also sets childrens alpha";
  constexpr const char* kCMauiControlGetAlphaHelpText = "float GetAlpha()";
  constexpr const char* kCMauiControlGetRenderPassHelpText = "int GetRenderPass()";
  constexpr const char* kCMauiControlSetRenderPassHelpText = "int SetRenderPass()";
  constexpr const char* kCMauiControlGetNameHelpText = "string GetName()";
  constexpr const char* kCMauiControlSetNameHelpText = "SetName(string)";
  constexpr const char* kCMauiControlDumpHelpText = "Dump";
  constexpr const char* kCMauiControlGetCurrentFocusControlHelpText = "GetCurrentFocusControl()";
  constexpr const char* kCMauiControlAcquireKeyboardFocusHelpText = "AcquireKeyboardFocus(bool blocksKeyDown)";
  constexpr const char* kCMauiControlAbandonKeyboardFocusHelpText = "AbandonKeyboardFocus()";
  constexpr const char* kCMauiControlNeedsFrameUpdateHelpText = "bool NeedsFrameUpdate()";
  constexpr const char* kCMauiControlSetNeedsFrameUpdateHelpText = "SetNeedsFrameUpdate(bool needsIt)";
  constexpr const char* kGetInputCaptureHelpText =
    "control GetInputCapture() - returns the current capture control, or nil if none";
  constexpr const char* kAddInputCaptureHelpText = "AddInputCapture(control) - set a control as the current capture";
  constexpr const char* kRemoveInputCaptureHelpText =
    "RemoveInputCapture(control) - remove the control from the capture array (always first from back)";
  constexpr const char* kGetFrontEndDataHelpText = "GetFrontEndData(key)";
  constexpr const char* kGetScrollValuesResultWarning =
    "GetScrollValues must return 4 values, minRange, maxRange, minVisible, maxVisible)";
  constexpr const char* kCMauiControlNegativeAlphaWarning =
    "Attempting to set a negative alpha value (%d) on control %s, setting to 0";
  constexpr const char* kCMauiControlAboveOneAlphaWarning =
    "Attempting to set an alpha value higher than 1.0 (%d) on control %s, are you sure you wan to do that?";

  [[nodiscard]] std::uint32_t PackVertexAlphaFromScalar(
    const float alpha
  ) noexcept
  {
    const std::int32_t truncatedLane = static_cast<std::int32_t>(alpha * -255.0f);
    return 0x00FFFFFFu - (static_cast<std::uint32_t>(truncatedLane) << 24u);
  }

  [[nodiscard]] moho::CMauiControl* FirstChildControl(
    moho::CMauiControl* const control
  ) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&control->mChildrenList);
    CMauiControlListNode* const firstChildNode = control->mChildrenList.mNext;
    if (firstChildNode == sentinel) {
      return nullptr;
    }

    return ControlFromParentListNode(firstChildNode);
  }

  [[nodiscard]] moho::CMauiControl* NextSiblingControl(
    moho::CMauiControl* const control
  ) noexcept
  {
    if (control == nullptr) {
      return nullptr;
    }

    moho::CMauiControl* const parentControl = control->mParent;
    if (parentControl == nullptr) {
      return nullptr;
    }

    CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&parentControl->mChildrenList);
    CMauiControlListNode* const siblingNode = static_cast<CMauiControlListNode*>(control)->mNext;
    if (siblingNode == sentinel) {
      return nullptr;
    }

    return ControlFromParentListNode(siblingNode);
  }

  /**
   * Address: 0x007863B0 (FUN_007863B0)
   *
   * What it does:
   * Resolves one control's `Depth` lazy-var lane into the cached depth scalar
   * and reports whether the cached value changed.
   */
  [[nodiscard]] bool RefreshDepthLaneForControl(
    moho::CMauiControl* const control
  ) noexcept
  {
    if (control == nullptr) {
      return false;
    }

    const float resolvedDepth = moho::CScriptLazyVar_float::GetValue(&control->mDepthLV);
    if (control->mDepth == resolvedDepth) {
      return false;
    }

    control->mDepth = resolvedDepth;
    return true;
  }

  struct CMauiDepthTraversalCursor
  {
    moho::CMauiControl* mSubtreeRoot = nullptr;
    moho::CMauiControl* mCurrent = nullptr;
  };

  /**
   * Address: 0x007864C0 (FUN_007864C0)
   *
   * What it does:
   * Advances one `(subtreeRoot,current)` depth-first traversal cursor lane to
   * the next control and returns the updated cursor.
   */
  [[maybe_unused]] CMauiDepthTraversalCursor* AdvanceDepthTraversalCursor(
    CMauiDepthTraversalCursor* const cursor
  ) noexcept
  {
    if (cursor != nullptr && cursor->mCurrent != nullptr) {
      cursor->mCurrent = cursor->mCurrent->DepthFirstSuccessor(cursor->mSubtreeRoot);
    }
    return cursor;
  }

  [[nodiscard]] bool RefreshDepthLaneForSubtree(
    moho::CMauiControl* const subtreeRoot
  ) noexcept
  {
    bool depthChanged = false;
    CMauiDepthTraversalCursor traversalCursor{subtreeRoot, subtreeRoot};

    while (traversalCursor.mCurrent != nullptr) {
      moho::CMauiControl* const controlCursor = traversalCursor.mCurrent;
      if (controlCursor->IsHidden()) {
        (void)AdvanceDepthTraversalCursor(&traversalCursor);
        continue;
      }

      if (RefreshDepthLaneForControl(controlCursor)) {
        depthChanged = true;
      }

      (void)AdvanceDepthTraversalCursor(&traversalCursor);
    }

    return depthChanged;
  }
  void RebuildRenderedChildrenLane(
    moho::CMauiControl* const subtreeRoot
  )
  {
    subtreeRoot->mRenderedChildren.clear();

    for (moho::CMauiControl* controlCursor = subtreeRoot; controlCursor != nullptr;
         controlCursor = controlCursor->DepthFirstSuccessor(subtreeRoot)) {
      if (controlCursor->mInvisible) {
        continue;
      }

      subtreeRoot->mRenderedChildren.push_back(controlCursor);
    }
  }

  /**
   * Address: 0x0078C7E0 (FUN_0078C7E0)
   *
   * What it does:
   * Stable-sorts the rendered-child lane by each control's resolved depth.
   *
   * The binary's own `std::stable_sort` internals -- merge-sort recursion
   * setup + buffer-size calc (`FUN_0078AEE0`), its merge-step callee
   * (`FUN_0078B470`), the recursive divide/merge driver (`FUN_0078B7C0`),
   * the unbuffered-merge fallback (`FUN_0078BE00`), and the buffered-merge
   * thunk (`FUN_0078BD20`, forwarding to the comparator leaf recovered as
   * `wxMergeAscendingPointerRangesByFloatLaneD4A` in WxRuntimeTypes.cpp) --
   * are all satisfied by the `std::stable_sort` call below.
   *
   * Unlike `std::sort` (unstable, so a different valid implementation can
   * legally produce a different tie-break order for equal elements -- see
   * `legacy/algorithms/Sort.h`'s `fa::sort`, which therefore *is*
   * byte-faithfully reimplemented), `std::stable_sort`'s output order is
   * fully pinned by the standard's stability guarantee: for any input and
   * comparator, every conforming implementation -- MSVC8's 2007 one and a
   * modern one alike -- must produce the identical relative ordering of
   * equal elements. There is no algorithm-shape discrepancy a bespoke
   * reimplementation could fix, so the modern call below is a complete,
   * faithful equivalent, same pattern as this project's other STL-algorithm
   * citations (`std::sort`/`std::nth_element` in
   * CCommandLuaFunctionRegistrations.cpp/CWldSplat.cpp) -- CRT/STL-internal,
   * not engine code.
   */
  void SortRenderedChildrenByDepth(
    fa::vector<moho::CMauiControl*>& renderedChildren
  )
  {
    moho::CMauiControl** const begin = renderedChildren.begin();
    moho::CMauiControl** const end = renderedChildren.end();
    if (begin == nullptr || begin == end) {
      return;
    }

    std::stable_sort(
      begin, end, [](const moho::CMauiControl* const lhs, const moho::CMauiControl* const rhs) noexcept -> bool {
      if (lhs == nullptr || rhs == nullptr) {
        return lhs != nullptr && rhs == nullptr;
      }

      return lhs->mDepth < rhs->mDepth;
    }
    );
  }


  /**
   * Address: 0x007A4540 (FUN_007A4540, sub_7A4540)
   *
   * What it does:
   * Wraps one control into one temporary weak-owner link and appends that
   * weak reference to the global input-capture stack.
   */
  void AddInputCaptureControl(
    moho::CMauiControl* const control
  )
  {
    // A null control is pushed too; nothing in the binary filters it here.
    const moho::WeakPtr<moho::CMauiControl> capture(control);
    sInputCapture.push_back(capture);
  }

  /**
   * Address: 0x0078ACE0 (FUN_0078ACE0, func_GetCMauiControlOpt)
   *
   * What it does:
   * Resolves one optional `CMauiControl` from Lua object payload; raises Lua
   * errors for non-game-object or incorrect-type payloads and returns null for
   * destroyed objects.
   */
  [[nodiscard]]
  moho::CMauiControl* ResolveControlFromLuaObjectOptionalOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<moho::CMauiControl>());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiControl*>(upcast.mObj);
  }

  /**
   * Address: 0x0078A839 (FUN_0078A839)
   *
   * What it does:
   * Logs one `OnHide` Lua callback exception into script-warning output.
   */
  void LogOnHideCallbackException(
    moho::CScriptObject* const scriptObject,
    const std::exception& exception
  ) noexcept
  {
    if (scriptObject == nullptr) {
      return;
    }

    const char* const message = exception.what() != nullptr ? exception.what() : "";
    scriptObject->LogScriptWarning(scriptObject, "OnHide", message);
  }

  /**
   * Address: 0x0078AB39 (FUN_0078AB39)
   *
   * What it does:
   * Logs one `IsScrollable` Lua callback exception into script-warning output.
   */
  void LogIsScrollableCallbackException(
    moho::CScriptObject* const scriptObject,
    const std::exception& exception
  ) noexcept
  {
    if (scriptObject == nullptr) {
      return;
    }

    const char* const message = exception.what() != nullptr ? exception.what() : "";
    scriptObject->LogScriptWarning(scriptObject, "IsScrollable", message);
  }
}

gpg::RType* moho::CMauiControl::sType = nullptr;

/**
 * Address: 0x0079CC10 (FUN_0079CC10, Moho::MAUI_SetKeyboardFocus)
 *
 * What it does:
 * Rebinds global focus owner and notifies previous focus owner through
 * `LosingKeyboardFocus()`.
 */
void moho::MAUI_SetKeyboardFocus(
  CMauiControl* const control,
  const bool blocksKeyDown
)
{
  // The previous owner is held through a weak link for the notification
  // below: the copy goes onto that control's weak chain, so if the callback
  // destroys it the control's drain empties the link rather than leaving it
  // dangling, and the copy's destructor takes it off the chain again (the
  // 0x0079DB60 unlink the binary runs on the way out).
  const WeakPtr<CMauiControl> previousFocus(Maui_CurrentFocusControl);
  Maui_CurrentFocusControl.ResetFromObject(control);
  Maui_ControlHasFocus = blocksKeyDown;

  // The notification is OnKeyboardFocusChange, not LosingKeyboardFocus. The
  // binary calls through vtable+0x44, and the CMauiControl vtable has
  // LosingKeyboardFocus at +0x40 and OnKeyboardFocusChange at +0x44.
  //
  // The difference is not cosmetic. This runs unconditionally on the previous
  // owner, including when the previous owner is the control being focused -
  // which is the normal case, because a click on an edit box focuses it once
  // through the Lua binding and again from CMauiEdit::HandleClickEvent.
  // CMauiEdit overrides LosingKeyboardFocus to abandon focus, so calling that
  // one made the second acquire immediately clear the focus it had just set,
  // and every keystroke then found no focus control and went nowhere.
  if (CMauiControl* const previousOwner = previousFocus.GetObjectPtr(); previousOwner != nullptr) {
    previousOwner->OnKeyboardFocusChange();
  }
}

/**
 * Address: 0x00787A50 (FUN_00787A50, cfunc_CMauiControlDestroy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlDestroyL`.
 */
int moho::cfunc_CMauiControlDestroy(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlDestroyL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787A70 (FUN_00787A70, func_CMauiControlDestroy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Destroy()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDestroy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Destroy",
    &moho::cfunc_CMauiControlDestroy,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDestroyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787AD0 (FUN_00787AD0, cfunc_CMauiControlDestroyL)
 *
 * What it does:
 * Resolves optional `CMauiControl`, blocks root-frame destruction, and
 * destroys non-root controls.
 */
int moho::cfunc_CMauiControlDestroyL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlDestroyHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = ResolveControlFromLuaObjectOptionalOrError(controlObject, state);
  if (control != nullptr) {
    if (control == control->mRootFrame) {
      LuaPlus::LuaState::Error(state, "Cannot destroy the root frame");
    }
    control->Destroy();
  }

  return 1;
}

/**
 * Address: 0x00787BA0 (FUN_00787BA0, cfunc_CMauiControlGetParent)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetParentL`.
 */
int moho::cfunc_CMauiControlGetParent(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetParentL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787BC0 (FUN_00787BC0, func_CMauiControlGetParent_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetParent()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetParent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetParent",
    &moho::cfunc_CMauiControlGetParent,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetParentHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787C20 (FUN_00787C20, cfunc_CMauiControlGetParentL)
 *
 * What it does:
 * Reads one `CMauiControl`, pushes parent control object when available, and
 * pushes `nil` otherwise.
 */
int moho::cfunc_CMauiControlGetParentL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetParentHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  CMauiControl* const parent = control->GetParent();
  if (parent != nullptr) {
    parent->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x00787CF0 (FUN_00787CF0, cfunc_CMauiControlClearChildren)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlClearChildrenL`.
 */
int moho::cfunc_CMauiControlClearChildren(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlClearChildrenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787D10 (FUN_00787D10, func_CMauiControlClearChildren_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:ClearChildren()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlClearChildren_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearChildren",
    &moho::cfunc_CMauiControlClearChildren,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlClearChildrenHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787D70 (FUN_00787D70, cfunc_CMauiControlClearChildrenL)
 *
 * What it does:
 * Reads one `CMauiControl` and clears all child controls.
 */
int moho::cfunc_CMauiControlClearChildrenL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlClearChildrenHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->ClearChildren();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00787E30 (FUN_00787E30, cfunc_CMauiControlSetParent)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetParentL`.
 */
int moho::cfunc_CMauiControlSetParent(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetParentL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787E50 (FUN_00787E50, func_CMauiControlSetParent_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetParent(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetParent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetParent",
    &moho::cfunc_CMauiControlSetParent,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetParentHelpText
  );
  return &binder;
}

/**
 * Address: 0x00787EB0 (FUN_00787EB0, cfunc_CMauiControlSetParentL)
 *
 * What it does:
 * Reads `CMauiControl` + parent control args, updates parent ownership, and
 * returns the control object lane.
 */
int moho::cfunc_CMauiControlSetParentL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlSetParentHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);
  control->SetParent(parentControl);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00787FB0 (FUN_00787FB0, cfunc_CMauiControlDisableHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlDisableHitTestL`.
 */
int moho::cfunc_CMauiControlDisableHitTest(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlDisableHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00787FD0 (FUN_00787FD0, func_CMauiControlDisableHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:DisableHitTest([recursive])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDisableHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DisableHitTest",
    &moho::cfunc_CMauiControlDisableHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDisableHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788030 (FUN_00788030, cfunc_CMauiControlDisableHitTestL)
 *
 * What it does:
 * Reads one `CMauiControl` plus optional recursion boolean and disables hit
 * testing.
 */
int moho::cfunc_CMauiControlDisableHitTestL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kCMauiControlDisableHitTestHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(state->m_state, 2);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  bool applyChildren = false;
  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaStackObject recursiveArg(state, 2);
    applyChildren = LuaPlus::LuaStackObject::GetBoolean(&recursiveArg);
  }

  control->DisableHitTest(true, applyChildren);
  return 0;
}

/**
 * Address: 0x00788130 (FUN_00788130, cfunc_CMauiControlEnableHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlEnableHitTestL`.
 */
int moho::cfunc_CMauiControlEnableHitTest(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlEnableHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788150 (FUN_00788150, func_CMauiControlEnableHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:EnableHitTest([recursive])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlEnableHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EnableHitTest",
    &moho::cfunc_CMauiControlEnableHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlEnableHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x007881B0 (FUN_007881B0, cfunc_CMauiControlEnableHitTestL)
 *
 * What it does:
 * Reads one `CMauiControl` plus optional recursion boolean and enables hit
 * testing.
 */
int moho::cfunc_CMauiControlEnableHitTestL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kCMauiControlEnableHitTestHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(state->m_state, 2);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  bool applyChildren = false;
  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaStackObject recursiveArg(state, 2);
    applyChildren = LuaPlus::LuaStackObject::GetBoolean(&recursiveArg);
  }

  control->DisableHitTest(false, applyChildren);
  return 0;
}

/**
 * Address: 0x007882B0 (FUN_007882B0, cfunc_CMauiControlIsHitTestDisabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlIsHitTestDisabledL`.
 */
int moho::cfunc_CMauiControlIsHitTestDisabled(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlIsHitTestDisabledL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007882D0 (FUN_007882D0, func_CMauiControlIsHitTestDisabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:IsHitTestDisabled()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlIsHitTestDisabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsHitTestDisabled",
    &moho::cfunc_CMauiControlIsHitTestDisabled,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlIsHitTestDisabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788330 (FUN_00788330, cfunc_CMauiControlIsHitTestDisabledL)
 *
 * What it does:
 * Reads one control and pushes `IsHitTestDisabled()` boolean result.
 */
int moho::cfunc_CMauiControlIsHitTestDisabledL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlIsHitTestDisabledHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->IsHitTestDisabled());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007883F0 (FUN_007883F0, cfunc_CMauiControlHide)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlHideL`.
 */
int moho::cfunc_CMauiControlHide(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlHideL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788410 (FUN_00788410, func_CMauiControlHide_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Hide()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlHide_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Hide",
    &moho::cfunc_CMauiControlHide,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlHideHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788470 (FUN_00788470, cfunc_CMauiControlHideL)
 *
 * What it does:
 * Reads one `CMauiControl` and sets hidden-state to `true`.
 */
int moho::cfunc_CMauiControlHideL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlHideHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->SetHidden(true);
  return 0;
}

/**
 * Address: 0x00788520 (FUN_00788520, cfunc_CMauiControlShow)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlShowL`.
 */
int moho::cfunc_CMauiControlShow(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlShowL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788540 (FUN_00788540, func_CMauiControlShow_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Show()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlShow_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Show",
    &moho::cfunc_CMauiControlShow,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlShowHelpText
  );
  return &binder;
}

/**
 * Address: 0x007885A0 (FUN_007885A0, cfunc_CMauiControlShowL)
 *
 * What it does:
 * Reads one `CMauiControl` and sets hidden-state to `false`.
 */
int moho::cfunc_CMauiControlShowL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlShowHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->SetHidden(false);
  return 0;
}

/**
 * Address: 0x00788650 (FUN_00788650, cfunc_CMauiControlSetHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetHiddenL`.
 */
int moho::cfunc_CMauiControlSetHidden(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788670 (FUN_00788670, func_CMauiControlSetHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetHidden(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetHidden",
    &moho::cfunc_CMauiControlSetHidden,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x007886D0 (FUN_007886D0, cfunc_CMauiControlSetHiddenL)
 *
 * What it does:
 * Reads one `CMauiControl` plus boolean hidden lane and applies it.
 */
int moho::cfunc_CMauiControlSetHiddenL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlSetHiddenHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject hiddenArg(state, 2);
  const bool hidden = LuaPlus::LuaStackObject::GetBoolean(&hiddenArg);
  control->SetHidden(hidden);
  return 0;
}

/**
 * Address: 0x00788790 (FUN_00788790, cfunc_CMauiControlIsHidden)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlIsHiddenL`.
 */
int moho::cfunc_CMauiControlIsHidden(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlIsHiddenL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007887B0 (FUN_007887B0, func_CMauiControlIsHidden_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:IsHidden()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlIsHidden_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsHidden",
    &moho::cfunc_CMauiControlIsHidden,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlIsHiddenHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788810 (FUN_00788810, cfunc_CMauiControlIsHiddenL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its hidden-state to Lua.
 */
int moho::cfunc_CMauiControlIsHiddenL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlIsHiddenHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->IsHidden());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007888D0 (FUN_007888D0, cfunc_CMauiControlGetRenderPass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetRenderPassL`.
 */
int moho::cfunc_CMauiControlGetRenderPass(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetRenderPassL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007888F0 (FUN_007888F0, func_CMauiControlGetRenderPass_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetRenderPass()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetRenderPass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetRenderPass",
    &moho::cfunc_CMauiControlGetRenderPass,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetRenderPassHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788950 (FUN_00788950, cfunc_CMauiControlGetRenderPassL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its render-pass lane to Lua.
 */
int moho::cfunc_CMauiControlGetRenderPassL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetRenderPassHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushnumber(state->m_state, static_cast<float>(control->GetRenderPass()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00788A10 (FUN_00788A10, cfunc_CMauiControlSetRenderPass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetRenderPassL`.
 */
int moho::cfunc_CMauiControlSetRenderPass(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetRenderPassL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788A30 (FUN_00788A30, func_CMauiControlSetRenderPass_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetRenderPass(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetRenderPass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetRenderPass",
    &moho::cfunc_CMauiControlSetRenderPass,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetRenderPassHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788A90 (FUN_00788A90, cfunc_CMauiControlSetRenderPassL)
 *
 * What it does:
 * Reads one `CMauiControl` plus integer render-pass lane from Lua and stores
 * it into the control runtime view.
 */
int moho::cfunc_CMauiControlSetRenderPassL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlSetRenderPassHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject renderPassArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&renderPassArg, "integer");
  }

  control->SetRenderPass(static_cast<std::int32_t>(lua_tonumber(state->m_state, 2)));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788B90 (FUN_00788B90, cfunc_CMauiControlGetName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetNameL`.
 */
int moho::cfunc_CMauiControlGetName(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetNameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788BB0 (FUN_00788BB0, func_CMauiControlGetName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetName()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetName",
    &moho::cfunc_CMauiControlGetName,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788C10 (FUN_00788C10, cfunc_CMauiControlGetNameL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its debug-name lane to Lua.
 */
int moho::cfunc_CMauiControlGetNameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetNameHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  const fa::string debugName = control->GetDebugName();
  lua_pushstring(state->m_state, debugName.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00788D00 (FUN_00788D00, cfunc_CMauiControlSetName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetNameL`.
 */
int moho::cfunc_CMauiControlSetName(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetNameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788D20 (FUN_00788D20, func_CMauiControlSetName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetName(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetName",
    &moho::cfunc_CMauiControlSetName,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788D80 (FUN_00788D80, cfunc_CMauiControlSetNameL)
 *
 * What it does:
 * Reads one `CMauiControl` plus debug-name string from Lua and stores it in
 * the control debug-name lane.
 */
int moho::cfunc_CMauiControlSetNameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlSetNameHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject nameArg(state, 2);
  const char* debugName = lua_tostring(state->m_state, 2);
  if (debugName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&nameArg, "string");
    debugName = "";
  }

  control->SetDebugName(fa::string(debugName));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788E90 (FUN_00788E90, cfunc_CMauiControlDump)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiControlDumpL`.
 */
int moho::cfunc_CMauiControlDump(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlDumpL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788EB0 (FUN_00788EB0, func_CMauiControlDump_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:Dump()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlDump_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Dump",
    &moho::cfunc_CMauiControlDump,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlDumpHelpText
  );
  return &binder;
}

/**
 * Address: 0x00788F00 (FUN_00788F00, cfunc_CMauiControlDumpL)
 *
 * What it does:
 * Reads one `CMauiControl`, invokes `Dump()`, and returns the original control
 * object.
 */
int moho::cfunc_CMauiControlDumpL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlDumpHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->Dump();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00788FC0 (FUN_00788FC0, cfunc_CMauiControlGetCurrentFocusControl)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetCurrentFocusControlL`.
 */
int moho::cfunc_CMauiControlGetCurrentFocusControl(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetCurrentFocusControlL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00788FE0 (FUN_00788FE0, func_CMauiControlGetCurrentFocusControl_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetCurrentFocusControl()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetCurrentFocusControl_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetCurrentFocusControl",
    &moho::cfunc_CMauiControlGetCurrentFocusControl,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetCurrentFocusControlHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789040 (FUN_00789040, cfunc_CMauiControlGetCurrentFocusControlL)
 *
 * What it does:
 * Pushes the currently focused control Lua object, or `nil` when no control
 * currently owns keyboard focus.
 */
int moho::cfunc_CMauiControlGetCurrentFocusControlL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetCurrentFocusControlHelpText);

  CMauiControl* const focusedControl = Maui_CurrentFocusControl.GetObjectPtr();
  if (focusedControl != nullptr) {
    focusedControl->mLuaObj.PushStack(state);
    return 1;
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007890B0 (FUN_007890B0, cfunc_CMauiControlAcquireKeyboardFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlAcquireKeyboardFocusL`.
 */
int moho::cfunc_CMauiControlAcquireKeyboardFocus(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlAcquireKeyboardFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007890D0 (FUN_007890D0, func_CMauiControlAcquireKeyboardFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:AcquireKeyboardFocus(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlAcquireKeyboardFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AcquireKeyboardFocus",
    &moho::cfunc_CMauiControlAcquireKeyboardFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlAcquireKeyboardFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789130 (FUN_00789130, cfunc_CMauiControlAcquireKeyboardFocusL)
 *
 * What it does:
 * Reads one `CMauiControl` plus boolean `blocksKeyDown` lane and forwards to
 * `CMauiControl::AcquireKeyboardFocus`.
 */
int moho::cfunc_CMauiControlAcquireKeyboardFocusL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlAcquireKeyboardFocusHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject blocksKeyDownArg(state, 2);
  const bool blocksKeyDown = LuaPlus::LuaStackObject::GetBoolean(&blocksKeyDownArg);
  control->AcquireKeyboardFocus(blocksKeyDown);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789210 (FUN_00789210, cfunc_CMauiControlAbandonKeyboardFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlAbandonKeyboardFocusL`.
 */
int moho::cfunc_CMauiControlAbandonKeyboardFocus(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlAbandonKeyboardFocusL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789230 (FUN_00789230, func_CMauiControlAbandonKeyboardFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:AbandonKeyboardFocus()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlAbandonKeyboardFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AbandonKeyboardFocus",
    &moho::cfunc_CMauiControlAbandonKeyboardFocus,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlAbandonKeyboardFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789290 (FUN_00789290, cfunc_CMauiControlAbandonKeyboardFocusL)
 *
 * What it does:
 * Reads one `CMauiControl` and forwards to
 * `CMauiControl::AbandonKeyboardFocus`.
 */
int moho::cfunc_CMauiControlAbandonKeyboardFocusL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlAbandonKeyboardFocusHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  control->AbandonKeyboardFocus();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789350 (FUN_00789350, cfunc_CMauiControlNeedsFrameUpdate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlNeedsFrameUpdateL`.
 */
int moho::cfunc_CMauiControlNeedsFrameUpdate(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlNeedsFrameUpdateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789370 (FUN_00789370, func_CMauiControlNeedsFrameUpdate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:NeedsFrameUpdate()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlNeedsFrameUpdate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "NeedsFrameUpdate",
    &moho::cfunc_CMauiControlNeedsFrameUpdate,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlNeedsFrameUpdateHelpText
  );
  return &binder;
}

/**
 * Address: 0x007893D0 (FUN_007893D0, cfunc_CMauiControlNeedsFrameUpdateL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes its frame-update flag lane to Lua.
 */
int moho::cfunc_CMauiControlNeedsFrameUpdateL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlNeedsFrameUpdateHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushboolean(state->m_state, control->NeedsFrameUpdate());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00789490 (FUN_00789490, cfunc_CMauiControlSetNeedsFrameUpdate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetNeedsFrameUpdateL`.
 */
int moho::cfunc_CMauiControlSetNeedsFrameUpdate(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetNeedsFrameUpdateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007894B0 (FUN_007894B0, func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetNeedsFrameUpdate(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetNeedsFrameUpdate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNeedsFrameUpdate",
    &moho::cfunc_CMauiControlSetNeedsFrameUpdate,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetNeedsFrameUpdateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789510 (FUN_00789510, cfunc_CMauiControlSetNeedsFrameUpdateL)
 *
 * What it does:
 * Resolves optional `CMauiControl` plus one boolean lane and updates the
 * control frame-update flag.
 */
int moho::cfunc_CMauiControlSetNeedsFrameUpdateL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlSetNeedsFrameUpdateHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = ResolveControlFromLuaObjectOptionalOrError(controlObject, state);
  if (control != nullptr) {
    LuaPlus::LuaStackObject needsUpdateArg(state, 2);
    const bool needsUpdate = LuaPlus::LuaStackObject::GetBoolean(&needsUpdateArg);
    control->SetNeedsFrameUpdate(needsUpdate);
  }

  return 0;
}

/**
 * Address: 0x007895D0 (FUN_007895D0, cfunc_CMauiControlGetRootFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetRootFrameL`.
 */
int moho::cfunc_CMauiControlGetRootFrame(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetRootFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007895F0 (FUN_007895F0, func_CMauiControlGetRootFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetRootFrame()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetRootFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetRootFrame",
    &moho::cfunc_CMauiControlGetRootFrame,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetRootFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789650 (FUN_00789650, cfunc_CMauiControlGetRootFrameL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes root-frame Lua object lane.
 */
int moho::cfunc_CMauiControlGetRootFrameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetRootFrameHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  CMauiFrame* const rootFrame = control->GetRootFrame();
  (static_cast<CMauiControl*>(rootFrame))->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00789710 (FUN_00789710, cfunc_CMauiControlSetAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlSetAlphaL`.
 */
int moho::cfunc_CMauiControlSetAlpha(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlSetAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789730 (FUN_00789730, func_CMauiControlSetAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:SetAlpha(alpha[, children])` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlSetAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetAlpha",
    &moho::cfunc_CMauiControlSetAlpha,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlSetAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789790 (FUN_00789790, cfunc_CMauiControlSetAlphaL)
 *
 * What it does:
 * Reads alpha (and optional recursive flag) and updates one control or its
 * full descendant closure alpha lanes.
 */
int moho::cfunc_CMauiControlSetAlphaL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kCMauiControlSetAlphaHelpText, 2, 3, argumentCount
    );
  }

  lua_settop(state->m_state, 3);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject alphaArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&alphaArg, "number");
  }

  float alpha = static_cast<float>(lua_tonumber(state->m_state, 2));
  if (alpha < 0.0f) {
    const fa::string debugName = control->GetDebugName();
    gpg::Warnf(kCMauiControlNegativeAlphaWarning, static_cast<int>(alpha), debugName.c_str());
    alpha = 0.0f;
  } else if (alpha > 1.0f) {
    const fa::string debugName = control->GetDebugName();
    gpg::Warnf(kCMauiControlAboveOneAlphaWarning, static_cast<int>(alpha), debugName.c_str());
  }

  // FAF hot-patch (FA-Binary-Patches SetAlpha): 0x00789972 tests arg 3 with lua_toboolean
  // instead of "not nil", so SetAlpha(a, false) no longer recurses; 0x00789988 / 0x00789999
  // call _SetAlpha / _SetAlphaChildren, which replace only the vertex colour's alpha byte
  // (keeping each control's RGB, e.g. a SetColorMask colour) and cap it at 0xFF.
  const float scaledAlpha = 255.0f * alpha;
  const std::uint32_t alphaByte = scaledAlpha >= 255.0f ? 0xFFu : static_cast<std::uint32_t>(scaledAlpha);
  const auto applyAlpha = [alpha, alphaByte](CMauiControl& target) {
    target.mAlpha = alpha;
    target.mVertexAlpha = (target.mVertexAlpha & 0x00FFFFFFu) | (alphaByte << 24);
  };

  if (lua_toboolean(state->m_state, 3) != 0) {
    for (CMauiControl* traversalCursor = control; traversalCursor != nullptr;
         traversalCursor = traversalCursor->DepthFirstSuccessor(control)) {
      applyAlpha(*traversalCursor);
    }
  } else {
    applyAlpha(*control);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00789A30 (FUN_00789A30, cfunc_CMauiControlGetAlpha)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlGetAlphaL`.
 */
int moho::cfunc_CMauiControlGetAlpha(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlGetAlphaL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789A50 (FUN_00789A50, func_CMauiControlGetAlpha_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:GetAlpha()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlGetAlpha_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetAlpha",
    &moho::cfunc_CMauiControlGetAlpha,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlGetAlphaHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789AB0 (FUN_00789AB0, cfunc_CMauiControlGetAlphaL)
 *
 * What it does:
 * Reads one `CMauiControl` and pushes current alpha lane to Lua.
 */
int moho::cfunc_CMauiControlGetAlphaL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiControlGetAlphaHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  lua_pushnumber(state->m_state, control->GetAlpha());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00789B70 (FUN_00789B70, cfunc_CMauiControlApplyFunction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlApplyFunctionL`.
 */
int moho::cfunc_CMauiControlApplyFunction(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlApplyFunctionL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789B90 (FUN_00789B90, func_CMauiControlApplyFunction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:ApplyFunction(func)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlApplyFunction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ApplyFunction",
    &moho::cfunc_CMauiControlApplyFunction,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlApplyFunctionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789BF0 (FUN_00789BF0, cfunc_CMauiControlApplyFunctionL)
 *
 * What it does:
 * Reads one control plus Lua function object and applies it to control +
 * direct children.
 */
int moho::cfunc_CMauiControlApplyFunctionL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiControlApplyFunctionHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaObject functionObject(LuaPlus::LuaStackObject(state, 2));
  control->ApplyFunction(functionObject);
  return 0;
}

/**
 * Address: 0x00789CD0 (FUN_00789CD0, cfunc_CMauiControlHitTest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiControlHitTestL`.
 */
int moho::cfunc_CMauiControlHitTest(
  lua_State* const luaContext
)
{
  return cfunc_CMauiControlHitTestL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00789CF0 (FUN_00789CF0, func_CMauiControlHitTest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiControl:HitTest(x, y)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiControlHitTest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "HitTest",
    &moho::cfunc_CMauiControlHitTest,
    &moho::CScrLuaMetatableFactory<moho::CMauiControl>::Instance(),
    "CMauiControl",
    kCMauiControlHitTestHelpText
  );
  return &binder;
}

/**
 * Address: 0x00789D50 (FUN_00789D50, cfunc_CMauiControlHitTestL)
 *
 * What it does:
 * Reads one control plus `(x,y)` numeric lanes and pushes hit-test result.
 */
int moho::cfunc_CMauiControlHitTestL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kCMauiControlHitTestHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);

  LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&yArg, "number");
  }
  const float y = static_cast<float>(lua_tonumber(state->m_state, 3));

  LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(state->m_state, 2));

  lua_pushboolean(state->m_state, control->HitTest(x, y) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00846960 (FUN_00846960, cfunc_GetFrontEndData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFrontEndDataL`.
 */
int moho::cfunc_GetFrontEndData(
  lua_State* const luaContext
)
{
  return cfunc_GetFrontEndDataL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846980 (FUN_00846980, func_GetFrontEndData_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetFrontEndData(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetFrontEndData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "GetFrontEndData", &moho::cfunc_GetFrontEndData, nullptr, "<global>", kGetFrontEndDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008469E0 (FUN_008469E0, cfunc_GetFrontEndDataL)
 *
 * What it does:
 * Resolves one key from caller Lua state against user-state `FrontEndData`
 * and pushes the copied lookup result back to caller state.
 */
int moho::cfunc_GetFrontEndDataL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kGetFrontEndDataHelpText);

  LuaPlus::LuaState* const userState = USER_GetLuaState();
  LuaPlus::LuaObject frontEndData = userState->GetGlobals()["FrontEndData"];

  const LuaPlus::LuaObject keyObject(LuaPlus::LuaStackObject(state, 1));
  const LuaPlus::LuaObject keyOnUserState = SCR_Copy(keyObject, userState);
  const LuaPlus::LuaObject valueOnUserState = frontEndData.GetByObject(keyOnUserState);
  LuaPlus::LuaObject valueOnCallerState = SCR_Copy(valueOnUserState, state);
  valueOnCallerState.PushStack(state);
  return 1;
}

/**
 * Address: 0x00782E90 (FUN_00782E90, Moho::CMauiControl::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection type for `CMauiControl`, resolving via RTTI on
 * first use.
 */
gpg::RType* moho::CMauiControl::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiControl));
  }
  return sType;
}

/**
 * Address: 0x007867B0 (FUN_007867B0, Moho::CMauiControl::CMauiControl)
 *
 * What it does:
 * Initializes one control root lane from Lua object + parent, builds lazy-var
 * wrappers for layout fields, links into parent child-list when present, and
 * binds Lua field aliases (`Left/Right/Top/Bottom/Width/Height/Depth`).
 */
moho::CMauiControl::CMauiControl(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent,
  fa::string controlKind
)
  : CScriptObject()
  , TDatListItem<CMauiControl, void>()
  , mParent(parent)
  , mChildrenList()
  , mLeftLV(LuaStateOf(luaObject))
  , mRightLV(LuaStateOf(luaObject))
  , mTopLV(LuaStateOf(luaObject))
  , mBottomLV(LuaStateOf(luaObject))
  , mWidthLV(LuaStateOf(luaObject))
  , mHeightLV(LuaStateOf(luaObject))
  , mDepthLV(LuaStateOf(luaObject))
  , mDepth(0.0f)
  , mRenderedChildren()
  , mInvalidated(true)
  , mDisableHitTest(false)
  , mIsHidden(false)
  , mNeedsFrameUpdate(false)
  , mInvisible(false)
  , mAlpha(1.0f)
  , mVertexAlpha(0xFFFFFFFFu)
  , mRenderPass(0)
  , mRootFrame(nullptr)
  , mDebugName()
{
  mDebugName = controlKind;

  if (luaObject != nullptr) {
    SetLuaObject(*luaObject);
  }

  if (parent != nullptr) {
    ListLinkBefore(static_cast<CMauiControlListNode*>(&parent->mChildrenList));
    SetHidden(parent->IsHidden());

    mRenderPass = parent->mRenderPass;
    mRootFrame = parent->mRootFrame;
  }

  LuaPlus::LuaObject& controlLuaObject = mLuaObj;
  controlLuaObject.SetObject("Left", &mLeftLV);
  controlLuaObject.SetObject("Right", &mRightLV);
  controlLuaObject.SetObject("Top", &mTopLV);
  controlLuaObject.SetObject("Bottom", &mBottomLV);
  controlLuaObject.SetObject("Width", &mWidthLV);
  controlLuaObject.SetObject("Height", &mHeightLV);
  controlLuaObject.SetObject("Depth", &mDepthLV);

  mDepth = CScriptLazyVar_float::GetValue(&mDepthLV);
  if (mRenderedChildren.begin() != mRenderedChildren.end()) {
    mRenderedChildren.clear();
  }
}

/**
 * Address: 0x00786D00 (FUN_00786D00, Moho::CMauiControl::~CMauiControl)
 *
 * What it does:
 * Invalidates parent ownership, destroys/unlinks child controls, tears down
 * control runtime lanes, then destroys embedded script-object state.
 */
moho::CMauiControl::~CMauiControl()
{
  // Empty every weak link aimed at this control - the focus and mouse-over
  // links, and the one the mouse dispatcher keeps on its stack while script
  // runs - before the children go. ~CScriptObject drains the same chain, and
  // that is all the binary does; draining here as well is deliberate. Script
  // can destroy the control it is being dispatched to (the splash screen does
  // on the click that leaves it), and the children's destructors run before
  // ~CScriptObject would get to it.
  DetachAllWeakReferences();

  // FAF community binary-patch addition: forget this control's custom-render
  // flag (kept in a side table, see SetCustomRender), so a control allocated
  // at the same address later does not inherit it.
  SetCustomRender(false);

  // And drop any input-capture entry naming this control. The capture stack is
  // the hit-test root - ResolveTopInputCaptureControl feeds GetTopmostControl -
  // so an entry left behind after the control dies makes the next mouse event
  // walk a freed control tree and dispatch to whatever the reused memory looks
  // like. The splash screen reaches this: it captures its screen group, and
  // the group is destroyed on the click that leaves the splash.
  func_RemoveInputCapture(this);

  mInvalidated = true;

  if (CMauiControl* const parentControl = mParent; parentControl != nullptr) {
    parentControl->Invalidate();
  }

  CMauiControlListNode* const childSentinel = static_cast<CMauiControlListNode*>(&mChildrenList);
  while (childSentinel->mNext != childSentinel) {
    CMauiControlListNode* const childNode = childSentinel->mPrev;
    childNode->ListUnlink();
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      delete childControl;
    }
  }

  // `mDebugName` and `mRenderedChildren` are destroyed by the compiler after
  // this body. The lazy vars are still raw storage (`CScriptLazyVar_float`),
  // so their Lua objects are released by hand, last-declared first, as the
  // binary does.

  // `mChildrenList` (0x00786E44) and this control's own parent-list link
  // (0x00786E5C) unlink in their own destructors, then ~CScriptObject() runs:
  // CMauiControl derives from it for real, so the compiler chains the base
  // destructor.
}

/**
 * Address: 0x0077F690 (FUN_0077F690, Moho::CMauiControl::Left)
 *
 * What it does:
 * Returns writable reference to the left-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Left()
{
  return mLeftLV;
}

/**
 * Address: 0x0077F6A0 (FUN_0077F6A0, Moho::CMauiControl::Right)
 *
 * What it does:
 * Returns writable reference to the right-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Right()
{
  return mRightLV;
}

/**
 * Address: 0x0077F6B0 (FUN_0077F6B0, Moho::CMauiControl::Top)
 *
 * What it does:
 * Returns writable reference to the top-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Top()
{
  return mTopLV;
}

/**
 * Address: 0x0077F6C0 (FUN_0077F6C0, Moho::CMauiControl::Bottom)
 *
 * What it does:
 * Returns writable reference to the bottom-edge lazy-var lane.
 */
moho::CScriptLazyVar_float& moho::CMauiControl::Bottom()
{
  return mBottomLV;
}

/**
 * Address: 0x0077F6D0 (FUN_0077F6D0, Moho::CMauiControl::GetVertexAlpha)
 *
 * What it does:
 * Returns packed ARGB vertex-alpha color lane.
 */
std::uint32_t moho::CMauiControl::GetVertexAlpha()
{
  return mVertexAlpha;
}

/**
 * Address: 0x0077F6E0 (FUN_0077F6E0, Moho::CMauiControl::SetNeedsFrameUpdate)
 *
 * What it does:
 * Updates frame-update-needed flag lane.
 */
void moho::CMauiControl::SetNeedsFrameUpdate(
  const bool needsFrameUpdate
)
{
  mNeedsFrameUpdate = needsFrameUpdate;
}

/**
 * Address: 0x00786380 (FUN_00786380, Moho::CMauiControl::GetParent)
 *
 * What it does:
 * Returns owning parent control lane.
 */
moho::CMauiControl* moho::CMauiControl::GetParent() const
{
  return mParent;
}

/**
 * Address: 0x00786390 (FUN_00786390, Moho::CMauiControl::GetRootFrame)
 *
 * What it does:
 * Returns cached root-frame owner lane.
 */
moho::CMauiFrame* moho::CMauiControl::GetRootFrame()
{
  return static_cast<CMauiFrame*>(mRootFrame);
}

/**
 * Address: 0x007863F0 (FUN_007863F0, Moho::CMauiControl::SetAlpha)
 *
 * What it does:
 * Stores scalar alpha and updates packed vertex-alpha color lane.
 */
void moho::CMauiControl::SetAlpha(
  const float alpha
)
{
  mAlpha = alpha;
  mVertexAlpha = PackVertexAlphaFromScalar(alpha);
}

/**
 * Address: 0x0078EC10 (FUN_0078EC10, Moho::CMauiControl::AdjustARGBAlpha)
 *
 * What it does:
 * Replaces the input ARGB alpha channel with this control's current alpha lane
 * while preserving RGB channels.
 */
std::uint32_t moho::CMauiControl::AdjustARGBAlpha(
  const std::uint32_t color
)
{
  const float alpha = mAlpha;
  const std::int32_t alphaByteLane = static_cast<std::int32_t>(alpha * -255.0f);
  return (color & 0x00FFFFFFu) - (static_cast<std::uint32_t>(alphaByteLane) << 24u);
}

/**
 * Address: 0x00786440 (FUN_00786440, Moho::CMauiControl::GetAlpha)
 *
 * What it does:
 * Returns current alpha lane used by control rendering.
 */
float moho::CMauiControl::GetAlpha()
{
  return mAlpha;
}

/**
 * Address: 0x00786450 (FUN_00786450, Moho::CMauiControl::IsInvisible)
 *
 * What it does:
 * Returns whether this control is currently marked invisible.
 */
bool moho::CMauiControl::IsInvisible()
{
  return mInvisible;
}

/**
 * Address: 0x00786460 (FUN_00786460, Moho::CMauiControl::SetRenderPass)
 *
 * What it does:
 * Updates integer render-pass lane.
 */
void moho::CMauiControl::SetRenderPass(
  const std::int32_t renderPass
)
{
  mRenderPass = renderPass;
}

/**
 * Address: 0x00786470 (FUN_00786470, Moho::CMauiControl::GetRenderPass)
 *
 * What it does:
 * Returns integer render-pass lane.
 */
std::int32_t moho::CMauiControl::GetRenderPass()
{
  return mRenderPass;
}
namespace
{
  // FAF community binary-patch addition (see CMauiControl::SetCustomRender):
  // a side table keyed by control identity, deliberately kept OUTSIDE the
  // binary-layout-matching runtime-view structs above so it cannot disturb
  // any recovered offset or size assertion. Controls are never destroyed
  // from more than one thread at a time in this engine, matching every
  // other MAUI runtime-view lookup in this file.
  std::map<const moho::CMauiControl*, bool>& CustomRenderEnabledMap()
  {
    static std::map<const moho::CMauiControl*, bool> map;
    return map;
  }
}


void moho::CMauiControl::SetCustomRender(
  const bool enabled
)
{
  if (enabled) {
    CustomRenderEnabledMap()[this] = true;
  } else {
    CustomRenderEnabledMap().erase(this);
  }
}

bool moho::CMauiControl::GetCustomRender() const
{
  const auto& map = CustomRenderEnabledMap();
  const auto it = map.find(this);
  return it != map.end() && it->second;
}

/**
 * Address: 0x00786480 (FUN_00786480, Moho::CMauiControl::NeedsFrameUpdate)
 *
 * What it does:
 * Returns current frame-update-needed flag lane.
 */
bool moho::CMauiControl::NeedsFrameUpdate()
{
  return mNeedsFrameUpdate;
}

/**
 * Address: 0x00786AA0 (FUN_00786AA0, Moho::CMauiControl::Invalidate)
 *
 * What it does:
 * Marks this control and its parent chain as invalidated.
 */
void moho::CMauiControl::Invalidate()
{
  CMauiControl* controlCursor = this;
  while (controlCursor != nullptr) {
    controlCursor->mInvalidated = true;
    controlCursor = controlCursor->mParent;
  }
}

/**
 * Address: 0x00786AD0 (FUN_00786AD0, Moho::CMauiControl::SetParent)
 *
 * What it does:
 * Reparents this control into a new parent-child intrusive list lane and
 * invalidates affected controls.
 */
void moho::CMauiControl::SetParent(
  CMauiControl* const newParent
)
{
  CMauiControl* const currentParent = mParent;
  if (newParent == currentParent) {
    return;
  }

  mInvalidated = true;
  if (currentParent != nullptr) {
    currentParent->Invalidate();
  }

  ListUnlink();
  mParent = newParent;

  if (newParent != nullptr) {
    ListLinkBefore(&newParent->mChildrenList);
    Invalidate();
  }
}

/**
 * Address: 0x00786E90 (FUN_00786E90, Moho::CMauiControl::DoInit)
 *
 * What it does:
 * Invokes script callback `OnInit` on this control object.
 */
void moho::CMauiControl::DoInit()
{
  (void)RunScript("OnInit");
}

/**
 * Address: 0x00786EF0 (FUN_00786EF0, Moho::CMauiControl::Destroy)
 *
 * What it does:
 * Marks this control invalid/invisible, detaches parent ownership, moves the
 * control into the root-frame deleted-control list, dispatches `OnDestroy`,
 * and destroys all direct/indirect children.
 */
void moho::CMauiControl::Destroy()
{
  CMauiControl* const parentControl = mParent;

  mInvalidated = true;
  if (parentControl != nullptr) {
    parentControl->Invalidate();
  }

  CMauiFrame* const rootFrame = static_cast<CMauiFrame*>(mRootFrame);
  mInvisible = true;
  mParent = nullptr;

  if (this != rootFrame) {
    ListLinkBefore(static_cast<CMauiControlListNode*>(&rootFrame->mDeletedControlList));
  }

  (void)RunScript("OnDestroy");
  ClearChildren();
}

/**
 * Address: 0x00786F60 (FUN_00786F60, Moho::CMauiControl::ClearChildren)
 *
 * What it does:
 * Unlinks direct children one by one and dispatches virtual destroy on each.
 */
void moho::CMauiControl::ClearChildren()
{
  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&mChildrenList);

  while (sentinel->mNext != sentinel) {
    CMauiControlListNode* const childNode = sentinel->mNext;
    childNode->ListUnlink();
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      childControl->Destroy();
    }
  }
}

/**
 * Address: 0x00786FA0 (FUN_00786FA0, Moho::CMauiControl::Render)
 *
 * What it does:
 * Refreshes depth lanes for visible controls in this subtree and, when depth
 * changed or invalidated, rebuilds + depth-sorts the rendered-children lane.
 */
void moho::CMauiControl::Render()
{
  if (mInvisible) {
    return;
  }

  const bool depthChanged = RefreshDepthLaneForSubtree(this);
  if (!depthChanged && !mInvalidated) {
    return;
  }

  RebuildRenderedChildrenLane(this);
  SortRenderedChildrenByDepth(mRenderedChildren);
  mInvalidated = false;
}

/**
 * Address: 0x00786EA0 (FUN_00786EA0, Moho::CMauiControl::DepthFirstSuccessor)
 *
 * What it does:
 * Returns the next control in depth-first order, constrained to one root
 * subtree.
 */
moho::CMauiControl* moho::CMauiControl::DepthFirstSuccessor(
  CMauiControl* const subtreeRoot
)
{
  if (CMauiControl* const childControl = FirstChildControl(this); childControl != nullptr) {
    return childControl;
  }

  const CMauiControl* rootCursor = subtreeRoot;
  CMauiControl* traversalCursor = this;
  while (traversalCursor != nullptr && traversalCursor != rootCursor) {
    if (CMauiControl* const siblingControl = NextSiblingControl(traversalCursor); siblingControl != nullptr) {
      return siblingControl;
    }
    traversalCursor = traversalCursor->mParent;
  }

  return nullptr;
}

/**
 * Address: 0x00787170 (FUN_00787170, Moho::CMauiControl::SetHidden)
 *
 * What it does:
 * Calls `OnHide(hidden)` and, when callback does not consume the event,
 * updates hidden-state lane and applies the same value to children.
 */
void moho::CMauiControl::SetHidden(
  const bool hidden
)
{
  if (OnHide(hidden)) {
    return;
  }

  mIsHidden = hidden;

  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&mChildrenList);
  for (CMauiControlListNode* childNode = mChildrenList.mNext; childNode != sentinel;
       childNode = childNode->mNext) {
    if (CMauiControl* const childControl = ControlFromParentListNode(childNode); childControl != nullptr) {
      childControl->SetHidden(hidden);
    }
  }
}

/**
 * Address: 0x0078A700 (FUN_0078A700, Moho::CMauiControl::OnHide)
 *
 * What it does:
 * Invokes `OnHide(self, hidden)` Lua callback and returns callback bool result.
 */
bool moho::CMauiControl::OnHide(
  const bool& hidden
)
{
  CScriptObject* const scriptObject = this;
  const WeakPtr<CScriptObject> weakGuard(scriptObject);

  LuaPlus::LuaObject callbackObject{};
  scriptObject->FindScript(&callbackObject, "OnHide");
  if (!callbackObject) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<bool> callback(callbackObject);
    return callback(mLuaObj, hidden);
  } catch (const std::exception& exception) {
    LogOnHideCallbackException(weakGuard.GetObjectPtr(), exception);
  }

  return false;
}

/**
 * Address: 0x007876D0 (FUN_007876D0, Moho::CMauiControl::IsScrollable)
 *
 * What it does:
 * Converts axis enum to lexical token and forwards to `GetIsScrollable`.
 */
bool moho::CMauiControl::IsScrollable(
  const EMauiScrollAxis axis
)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axisCopy);
  const fa::string axisLexical = axisRef.GetLexical();
  return GetIsScrollable(axisLexical.c_str());
}

/**
 * Address: 0x0078AA00 (FUN_0078AA00, Moho::CMauiControl::GetIsScrollable)
 *
 * What it does:
 * Invokes `IsScrollable(self, axisText)` callback and returns its bool result.
 */
bool moho::CMauiControl::GetIsScrollable(
  const char* const axisLexical
)
{
  CScriptObject* const scriptObject = this;
  const WeakPtr<CScriptObject> weakGuard(scriptObject);

  LuaPlus::LuaObject callbackObject{};
  scriptObject->FindScript(&callbackObject, "IsScrollable");
  if (!callbackObject) {
    return false;
  }

  try {
    LuaPlus::LuaFunction<bool> callback(callbackObject);
    return callback(
      mLuaObj, axisLexical != nullptr ? axisLexical : ""
    );
  } catch (const std::exception& exception) {
    LogIsScrollableCallbackException(scriptObject, exception);
  } catch (...) {
    scriptObject->LogScriptWarning(scriptObject, "IsScrollable", "unknown exception");
  }

  return false;
}

/**
 * Address: 0x00787160 (FUN_00787160, Moho::CMauiControl::DoRender)
 *
 * What it does:
 * Default render lane for controls without concrete drawing logic.
 */
void moho::CMauiControl::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)primBatcher;
  (void)drawMask;
}

/**
 * Address: 0x007871C0 (FUN_007871C0, Moho::CMauiControl::IsHidden)
 *
 * What it does:
 * Returns hidden-state lane for this control.
 */
bool moho::CMauiControl::IsHidden()
{
  return mIsHidden;
}

/**
 * Address: 0x007871D0 (FUN_007871D0, Moho::CMauiControl::OnMinimized)
 *
 * What it does:
 * Propagates minimized-state notifications to direct/indirect children.
 */
void moho::CMauiControl::OnMinimized(
  const bool minimized
)
{
  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&mChildrenList);
  for (CMauiControlListNode* childNode = mChildrenList.mNext; childNode != sentinel;
       childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      childControl->OnMinimized(minimized);
    }
  }
}

/**
 * Address: 0x00787210 (FUN_00787210, Moho::CMauiControl::DisableHitTest)
 *
 * What it does:
 * Sets hit-test disabled state and optionally applies it recursively to child
 * controls.
 */
void moho::CMauiControl::DisableHitTest(
  const bool disableHitTest,
  const bool applyChildren
)
{
  mDisableHitTest = disableHitTest;

  if (!applyChildren) {
    return;
  }

  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&mChildrenList);
  for (CMauiControlListNode* childNode = mChildrenList.mNext; childNode != sentinel;
       childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      childControl->DisableHitTest(disableHitTest, true);
    }
  }
}

/**
 * Address: 0x00787260 (FUN_00787260, Moho::CMauiControl::IsHitTestDisabled)
 *
 * What it does:
 * Returns hit-test disabled state for this control.
 */
bool moho::CMauiControl::IsHitTestDisabled()
{
  return mDisableHitTest;
}

/**
 * Address: 0x00787780 (FUN_00787780, Moho::CMauiControl::ScrollLines)
 *
 * What it does:
 * Invokes script callback `ScrollLines(axisText, amount)`.
 */
void moho::CMauiControl::ScrollLines(
  const EMauiScrollAxis axis,
  const float amount
)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axisCopy);
  const fa::string axisLexical = axisRef.GetLexical();
  RunScriptStringNum("ScrollLines", axisLexical.c_str(), amount);
}

/**
 * Address: 0x00787830 (FUN_00787830, Moho::CMauiControl::ScrollPages)
 *
 * What it does:
 * Invokes script callback `ScrollLines(axisText, amount)` for page-scroll
 * requests (binary callback name lane).
 */
void moho::CMauiControl::ScrollPages(
  const EMauiScrollAxis axis,
  const float amount
)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axisCopy);
  const fa::string axisLexical = axisRef.GetLexical();
  RunScriptStringNum("ScrollLines", axisLexical.c_str(), amount);
}

/**
 * Address: 0x007878E0 (FUN_007878E0, Moho::CMauiControl::ScrollSetTop)
 *
 * What it does:
 * Invokes script callback `ScrollSetTop(axisText, amount)`.
 */
void moho::CMauiControl::ScrollSetTop(
  const EMauiScrollAxis axis,
  const float amount
)
{
  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axisCopy);
  const fa::string axisLexical = axisRef.GetLexical();
  RunScriptStringNum("ScrollSetTop", axisLexical.c_str(), amount);
}

/**
 * Address: 0x00787270 (FUN_00787270, Moho::CMauiControl::HitTest)
 *
 * What it does:
 * Returns whether `(x,y)` lies inside the control bounds.
 */
bool moho::CMauiControl::HitTest(
  const float x,
  const float y
)
{
  return x >= CScriptLazyVar_float::GetValue(&mLeftLV) &&
    CScriptLazyVar_float::GetValue(&mRightLV) > x &&
    y >= CScriptLazyVar_float::GetValue(&mTopLV) &&
    CScriptLazyVar_float::GetValue(&mBottomLV) > y;
}

/**
 * Address: 0x007872E0 (FUN_007872E0, Moho::CMauiControl::GetTopmostControl)
 *
 * What it does:
 * Scans one control subtree and returns topmost depth-matching visible control
 * under `(x,y)`.
 */
moho::CMauiControl* moho::CMauiControl::GetTopmostControl(
  CMauiControl* const root,
  const float x,
  const float y
)
{
  CMauiControl* topmostControl = nullptr;
  float topmostDepth = gpg::nInf;
  for (CMauiControl* controlCursor = root; controlCursor != nullptr;
       controlCursor = controlCursor->DepthFirstSuccessor(root)) {
    if (controlCursor->IsHidden() || controlCursor->IsHitTestDisabled() || !controlCursor->HitTest(x, y)) {
      continue;
    }

    const float controlDepth = controlCursor->mDepth;
    if (controlDepth > topmostDepth) {
      topmostControl = controlCursor;
      topmostDepth = controlDepth;
    }
  }

  return topmostControl;
}

/**
 * Address: 0x00787370 (FUN_00787370, Moho::CMauiControl::PostEvent)
 *
 * What it does:
 * Dispatches one event to this control and then walks parent controls until
 * one handler returns true.
 */
void moho::CMauiControl::PostEvent(
  const SMauiEventData& eventData
)
{
  // The parent is read before the handler runs, and dispatched to after it, so
  // every control on this walk must outlive the script the handler invokes.
  // Nothing reachable from a dispatch may be freed until it unwinds: control
  // deletes are deferred by CMauiFrame::PurgeDeleted, frame deletes by
  // CUIManager's retired-frame list. Both key off MAUI_EventDispatchInProgress.
  CMauiControl* parentControl = mParent;
  if (HandleEvent(eventData)) {
    return;
  }

  while (parentControl != nullptr) {
    CMauiControl* const controlCursor = parentControl;
    parentControl = parentControl->mParent;
    if (controlCursor->HandleEvent(eventData)) {
      break;
    }
  }
}

/**
 * Address: 0x007873A0 (FUN_007873A0, Moho::CMauiControl::HandleEvent)
 *
 * What it does:
 * Builds one Lua event payload object and invokes `HandleEvent(self,event)`.
 */
bool moho::CMauiControl::HandleEvent(
  const SMauiEventData& eventData
)
{
  LuaPlus::LuaState* const activeState =
    mLuaObj.GetActiveState();
  LuaPlus::LuaObject eventObject{};
  (void)CreateLuaEventObject(const_cast<SMauiEventData*>(&eventData), &eventObject, activeState);
  return RunScriptBool("HandleEvent", eventObject);
}

/**
 * Address: 0x00787420 (FUN_00787420, Moho::CMauiControl::Frame)
 *
 * What it does:
 * Invokes script callback `OnFrame(deltaSeconds)` on this control object.
 */
void moho::CMauiControl::Frame(
  const float deltaSeconds
)
{
  RunScriptNum("OnFrame", deltaSeconds);
}

/**
 * Address: 0x00787440 (FUN_00787440, Moho::CMauiControl::LosingKeyboardFocus)
 *
 * What it does:
 * Invokes `OnLoseKeyboardFocus` callback on this control script object.
 */
void moho::CMauiControl::LosingKeyboardFocus()
{
  (void)RunScript("OnLoseKeyboardFocus");
}

/**
 * Address: 0x00787450 (FUN_00787450, Moho::CMauiControl::OnKeyboardFocusChange)
 *
 * What it does:
 * Invokes `OnKeyboardFocusChange` callback on this control script object.
 */
void moho::CMauiControl::OnKeyboardFocusChange()
{
  (void)RunScript("OnKeyboardFocusChange");
}

/**
 * Address: 0x00787460 (FUN_00787460, Moho::CMauiControl::AcquireKeyboardFocus)
 *
 * What it does:
 * Routes one focus-acquire request through global MAUI focus owner lane.
 */
void moho::CMauiControl::AcquireKeyboardFocus(
  const bool blocksKeyDown
)
{
  MAUI_SetKeyboardFocus(this, blocksKeyDown);
}

/**
 * Address: 0x00787480 (FUN_00787480, Moho::CMauiControl::AbandonKeyboardFocus)
 *
 * What it does:
 * Clears global focus owner when this control currently owns focus.
 */
void moho::CMauiControl::AbandonKeyboardFocus()
{
  if (Maui_CurrentFocusControl.GetObjectPtr() == this) {
    MAUI_SetKeyboardFocus(nullptr, true);
  }
}

/**
 * Address: 0x007874B0 (FUN_007874B0, Moho::CMauiControl::GetScrollValues)
 *
 * What it does:
 * Calls script callback `GetScrollValues(axisLexical)` and returns
 * `{minRange,maxRange,minVisible,maxVisible}` numeric lanes when all four
 * results are provided.
 */
moho::SMauiScrollValues moho::CMauiControl::GetScrollValues(
  const EMauiScrollAxis axis
)
{
  SMauiScrollValues values{};
  CScriptObject* const scriptObject = this;
  LuaPlus::LuaState* const activeState =
    mLuaObj.GetActiveState();
  if (scriptObject == nullptr || activeState == nullptr || activeState->m_state == nullptr) {
    return values;
  }

  EMauiScrollAxis axisCopy = axis;
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axisCopy);
  const auto axisLexical = axisRef.GetLexical();

  LuaPlus::LuaObject axisArg{};
  axisArg.AssignString(activeState, axisLexical.c_str());

  LuaPlus::LuaObject arg2{};
  LuaPlus::LuaObject arg3{};
  LuaPlus::LuaObject arg4{};
  LuaPlus::LuaObject arg5{};
  gpg::core::FastVector<LuaPlus::LuaObject> results{};
  scriptObject->RunScriptMultiRet("GetScrollValues", results, axisArg, arg2, arg3, arg4, arg5);

  const auto resultCount = results.size();
  if (resultCount == 4) {
    values.mMinRange = static_cast<float>(results[0].ToNumber());
    values.mMaxRange = static_cast<float>(results[1].ToNumber());
    values.mMinVisible = static_cast<float>(results[2].ToNumber());
    values.mMaxVisible = static_cast<float>(results[3].ToNumber());
  } else {
    gpg::Warnf(kGetScrollValuesResultWarning);
  }

  return values;
}

/**
 * Address: 0x00787990 (FUN_00787990, Moho::CMauiControl::ApplyFunction)
 *
 * What it does:
 * Calls one Lua function with this control and each direct child control.
 */
void moho::CMauiControl::ApplyFunction(
  const LuaPlus::LuaObject& functionObject
)
{
  LuaPlus::LuaFunction<void> callback(functionObject);
  callback(mLuaObj);

  CMauiControlListNode* const sentinel = static_cast<CMauiControlListNode*>(&mChildrenList);
  for (CMauiControlListNode* childNode = mChildrenList.mNext; childNode != sentinel;
       childNode = childNode->mNext) {
    CMauiControl* const childControl = ControlFromParentListNode(childNode);
    if (childControl != nullptr) {
      callback(childControl->mLuaObj);
    }
  }
}

/**
 * Address: 0x0077F6F0 (FUN_0077F6F0, Moho::CMauiControl::GetDebugName)
 *
 * What it does:
 * Returns one copied debug-name string from the control runtime lane.
 */
fa::string moho::CMauiControl::GetDebugName()
{
  return mDebugName;
}

/**
 * Address: 0x0077F720 (FUN_0077F720, Moho::CMauiControl::SetDebugName)
 *
 * What it does:
 * Copies one debug-name string into the control debug-name lane.
 */
void moho::CMauiControl::SetDebugName(
  fa::string debugName
)
{
  mDebugName = debugName;
}

/**
 * Address: 0x00786B40 (FUN_00786B40, Moho::CMauiControl::Dump)
 *
 * What it does:
 * Logs debug identity/state and resolved layout lazy-vars for this control.
 */
void moho::CMauiControl::Dump()
{
  gpg::Logf("--");

  const char* parentName = "no parent";
  fa::string parentNameStorage{};
  if (mParent != nullptr) {
    parentNameStorage = mParent->GetDebugName();
    parentName = parentNameStorage.c_str();
  }

  gpg::Logf("CMauiControl name = %s, parent = %s", mDebugName.c_str(), parentName);

  const char* const frameUpdateLabel = mNeedsFrameUpdate ? "true" : "false";
  const char* const hiddenLabel = mIsHidden ? "true" : "false";
  const char* const disabledHitTestLabel = mDisableHitTest ? "true" : "false";
  gpg::Logf(
    "Disabled hit test = %s Hidden = %s Frame Update = %s Render Pass = %d Alpha = %.3f",
    disabledHitTestLabel,
    hiddenLabel,
    frameUpdateLabel,
    mRenderPass,
    mAlpha
  );

  if (!mIsHidden) {
    const float depth = CScriptLazyVar_float::GetValue(&mDepthLV);
    const float height = CScriptLazyVar_float::GetValue(&mHeightLV);
    const float width = CScriptLazyVar_float::GetValue(&mWidthLV);
    const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);
    const float top = CScriptLazyVar_float::GetValue(&mTopLV);
    const float right = CScriptLazyVar_float::GetValue(&mRightLV);
    const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
    gpg::Logf(
      "Left = %f Right = %.3f Top = %.3f Bottom = %.3f Width = %.3f Height = %.3f Depth = %.3f",
      left,
      right,
      top,
      bottom,
      width,
      height,
      depth
    );
  }
}

/**
 * Address: 0x007A5280 (FUN_007A5280, cfunc_GetInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetInputCaptureL`.
 */
int moho::cfunc_GetInputCapture(
  lua_State* const luaContext
)
{
  return cfunc_GetInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A52A0 (FUN_007A52A0, func_GetInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `GetInputCapture()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "GetInputCapture", &moho::cfunc_GetInputCapture, nullptr, "<global>", kGetInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5300 (FUN_007A5300, cfunc_GetInputCaptureL)
 *
 * What it does:
 * Returns the top control on the global input-capture stack, or `nil` when
 * no capture exists.
 */
int moho::cfunc_GetInputCaptureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetInputCaptureHelpText);

  if (CMauiControl* const control = ResolveTopInputCaptureControl()) {
    control->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
  }
  return 1;
}

/**
 * Address: 0x007A53B0 (FUN_007A53B0, func_AddInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `func_AddInputCaptureL`.
 */
int moho::func_AddInputCapture(
  lua_State* const luaContext
)
{
  return func_AddInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A53D0 (FUN_007A53D0, func_AddInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `AddInputCapture(control)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_AddInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(), "AddInputCapture", &moho::func_AddInputCapture, nullptr, "<global>", kAddInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5430 (FUN_007A5430, func_AddInputCaptureL)
 *
 * What it does:
 * Reads one control arg and pushes it onto the global input-capture stack.
 */
int moho::func_AddInputCaptureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kAddInputCaptureHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  AddInputCaptureControl(control);
  return 0;
}

/**
 * Address: 0x007A45D0 (FUN_007A45D0, func_RemoveInputCapture)
 *
 * What it does:
 * Removes the first matching control from the back of the global
 * input-capture stack.
 */
void moho::func_RemoveInputCapture(
  CMauiControl* const control
)
{
  if (control == nullptr) {
    return;
  }

  CompactInputCaptureStack();

  const std::size_t count = sInputCapture.size();
  if (sInputCapture.begin() == nullptr || count == 0) {
    return;
  }

  for (std::size_t i = count; i > 0; --i) {
    const std::size_t index = i - 1u;
    if (sInputCapture.begin()[index].GetObjectPtr() == control) {
      RemoveInputCaptureAt(index);
      return;
    }
  }
}

/**
 * Address: 0x007A54E0 (FUN_007A54E0, cfunc_RemoveInputCapture)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_RemoveInputCaptureL`.
 */
int moho::cfunc_RemoveInputCapture(
  lua_State* const luaContext
)
{
  return cfunc_RemoveInputCaptureL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A5500 (FUN_007A5500, func_RemoveInputCapture_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `RemoveInputCapture(control)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_RemoveInputCapture_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RemoveInputCapture",
    &moho::cfunc_RemoveInputCapture,
    nullptr,
    "<global>",
    kRemoveInputCaptureHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A5560 (FUN_007A5560, cfunc_RemoveInputCaptureL)
 *
 * What it does:
 * Reads one control arg and removes it from the global input-capture stack.
 */
int moho::cfunc_RemoveInputCaptureL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kRemoveInputCaptureHelpText);

  LuaPlus::LuaObject controlObject(LuaPlus::LuaStackObject(state, 1));
  CMauiControl* const control = SCR_FromLua_CMauiControl(controlObject, state);
  func_RemoveInputCapture(control);
  return 0;
}

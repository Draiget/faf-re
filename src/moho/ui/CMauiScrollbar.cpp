#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kInternalCreateScrollbarHelpText =
    "InternalCreateScrollbar(luaobj,parent,axis) -- for internal use by CreateScrollBar()";
  constexpr const char* kCMauiScrollbarSetNewTexturesHelpText =
    "SetNewTextures(backgroundTexture, thumbMiddleTexture, thumbTopTexture, thumbBottomTexture)";
  constexpr const char* kCMauiScrollbarSetScrollableHelpText =
    "Scrollbar:SetScrollable(scrollable) -- set the scrollable object connected to this scrollbar";
  constexpr const char* kCMauiScrollbarDoScrollLinesHelpText = "DoScrollLines(float)";
  constexpr const char* kCMauiScrollbarDoScrollPagesHelpText = "DoScrollPages(float)";

  struct ScrollbarQuadUvs
  {
    float mTopLeftU = 0.0f;
    float mTopLeftV = 0.0f;
    float mTopRightU = 1.0f;
    float mTopRightV = 0.0f;
    float mBottomRightU = 1.0f;
    float mBottomRightV = 1.0f;
    float mBottomLeftU = 0.0f;
    float mBottomLeftV = 1.0f;
  };

  [[nodiscard]] ScrollbarQuadUvs MakeScrollbarQuadUvs(
    const bool vertical
  ) noexcept
  {
    if (vertical) {
      return {};
    }

    return ScrollbarQuadUvs{
      0.0f,
      1.0f,
      0.0f,
      0.0f,
      1.0f,
      0.0f,
      1.0f,
      1.0f,
    };
  }

  void DrawScrollbarQuad(
    moho::CD3DPrimBatcher* const primBatcher,
    const boost::shared_ptr<moho::CD3DBatchTexture>& texture,
    const float left,
    const float top,
    const float right,
    const float bottom,
    const std::uint32_t color,
    const ScrollbarQuadUvs& uvs
  )
  {
    primBatcher->SetTexture(texture);

    const moho::CD3DPrimBatcher::Vertex topLeft = MakeBorderVertex(left, top, color, uvs.mTopLeftU, uvs.mTopLeftV);
    const moho::CD3DPrimBatcher::Vertex topRight = MakeBorderVertex(right, top, color, uvs.mTopRightU, uvs.mTopRightV);
    const moho::CD3DPrimBatcher::Vertex bottomRight =
      MakeBorderVertex(right, bottom, color, uvs.mBottomRightU, uvs.mBottomRightV);
    const moho::CD3DPrimBatcher::Vertex bottomLeft =
      MakeBorderVertex(left, bottom, color, uvs.mBottomLeftU, uvs.mBottomLeftV);
    primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
  }
}

gpg::RType* moho::CMauiScrollbar::sType = nullptr;

/**
 * Address: 0x007A1590 (FUN_007A1590, cfunc_InternalCreateScrollbar)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateScrollbarL`.
 */
int moho::cfunc_InternalCreateScrollbar(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateScrollbarL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A15B0 (FUN_007A15B0, func_InternalCreateScrollbar_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateScrollbar(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateScrollbar_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateScrollbar",
    &moho::cfunc_InternalCreateScrollbar,
    nullptr,
    "<global>",
    kInternalCreateScrollbarHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A1610 (FUN_007A1610, cfunc_InternalCreateScrollbarL)
 *
 * What it does:
 * Reads `(luaobj,parent,axisText)`, constructs one scrollbar control,
 * dispatches `OnInit`, and pushes the created control object.
 */
int moho::cfunc_InternalCreateScrollbarL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 3, kInternalCreateScrollbarHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaStackObject axisArg(state, 3);
  const char* const axisLexical = lua_tostring(state->m_state, 3);
  if (axisLexical == nullptr) {
    axisArg.TypeError("string");
  }

  EMauiScrollAxis axis = static_cast<EMauiScrollAxis>(0);
  gpg::RRef axisRef{};
  axisRef = gpg::MakeRRef<moho::EMauiScrollAxis>(&axis);
  (void)axisRef.SetLexical(axisLexical);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x158)`.
  auto* const scrollbar = AllocateZeroedUiObject<CMauiScrollbar>(0x158u);
  new (scrollbar) CMauiScrollbar(&luaObject, parentControl, axis);
  scrollbar->DoInit();
  scrollbar->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007A04B0 (FUN_007A04B0, Moho::CMauiScrollbar::CMauiScrollbar)
 *
 * What it does:
 * Constructs one scrollbar control from Lua object + parent lanes and
 * initializes draggable/texture/axis runtime state lanes.
 */
moho::CMauiScrollbar::CMauiScrollbar(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent,
  const EMauiScrollAxis axis
)
  : CMauiControl(luaObject, parent, "scrollbar")
{
  // asm 0x007A04ED clears the embedded `IMauiDragger` base's weak-reference
  // head at +0x120 and 0x007A04F3 installs its vptr at +0x11C; both are the
  // inlined `IMauiDragger` base constructor, which the compiler emits here.
  mScrollable = {};
  mThumbTop = {};
  mThumbBottom = {};
  mThumbMiddle = {};
  mBackground = {};
  mDragStart = 0.0f;
  mTopAtDragStart = 0.0f;
  mAxis = axis;
}

/**
 * Address: 0x007A0590 (FUN_007A0590, Moho::CMauiScrollbar::~CMauiScrollbar non-deleting body)
 * Deleting dtor: 0x007A0570 (FUN_007A0570, Moho::CMauiScrollbar::dtr)
 *
 * IDA signature:
 * _DWORD *__stdcall sub_7A0590(Moho::CMauiScrollbar *this);
 *
 * What it does:
 * Tears down one scrollbar control in-place in reverse construction order.
 * The binary sequence:
 *   1. Release the four `CD3DBatchTexture` shared-pointer lanes in reverse
 *      declaration order (`mBackground`, `mThumbMiddle`, `mThumbBottom`,
 *      `mThumbTop`) via each `shared_ptr` destructor's interlocked
 *      reference-count release at the count word (`+0x148/+0x140/+0x138/+0x130`).
 *   2. Unlink the bound scrollable focus sentinel (`mScrollable`, `+0x124`).
 *   3. Restore the embedded `IMauiDragger` sub-object vtable (`+0x11C`) and
 *      drain its `WeakObject` head (`+0x120`) - both are `~IMauiDragger`
 *      inlined, so the compiler emits them as part of base destruction.
 * The base `CMauiControl` / `IMauiDragger` teardown is then chained by the
 * compiler-emitted base-class destruction, mirroring the tail
 * `call CMauiControl::~CMauiControl` in the binary.
 *
 * The deleting-destructor slot (FUN_007A0570) — `~self(); if (flag & 1) delete this;`
 * — is auto-generated by MSVC once this virtual destructor is declared and is
 * the target invoked by the polymorphic `delete` of the `new CMauiScrollbar(...)`
 * created above (`cfunc_InternalCreateScrollbarL`), dispatched through the
 * virtual `~CMauiControl` slot.
 */
moho::CMauiScrollbar::~CMauiScrollbar()
{

  // The four texture lanes are real members now, so the compiler emits their
  // `~shared_ptr` after this body in reverse declaration order - the same
  // sequence the binary runs. Releasing them here as well would decrement
  // each refcount twice.

  // `mScrollable` is unlinked by its own destructor, after the textures -
  // the binary's order, since it is declared first.

  // ---- Step 3: the embedded IMauiDragger sub-object ----
  // The binary rewrites the sub-object vtable at +0x11C back to
  // `??_7IMauiDragger@Moho@@6B@` and drains its weak-reference head at +0x120.
  // Both are `~IMauiDragger` (0x0078DB20) inlined, so the compiler-emitted base
  // destruction covers them and nothing belongs in this body.
}

/**
 * Address: 0x007A0740 (FUN_007A0740, Moho::CMauiScrollbar::SetTextures)
 *
 * What it does:
 * Replaces any non-null scrollbar texture lanes (background, thumb-middle,
 * thumb-top, thumb-bottom).
 */
void moho::CMauiScrollbar::SetTextures(
  const boost::shared_ptr<CD3DBatchTexture>& background,
  const boost::shared_ptr<CD3DBatchTexture>& thumbMiddle,
  const boost::shared_ptr<CD3DBatchTexture>& thumbTop,
  const boost::shared_ptr<CD3DBatchTexture>& thumbBottom
)
{

  if (background.get() != nullptr) {
    mBackground = background;
  }
  if (thumbMiddle.get() != nullptr) {
    mThumbMiddle = thumbMiddle;
  }
  if (thumbTop.get() != nullptr) {
    mThumbTop = thumbTop;
  }
  if (thumbBottom.get() != nullptr) {
    mThumbBottom = thumbBottom;
  }
}

/**
 * Address: 0x007A0840 (FUN_007A0840, Moho::CMauiScrollbar::Draw)
 *
 * VFTable SLOT: 6 (+0x18) - the class's `DoRender` override.
 *
 * What it does:
 * Draws the scrollbar background and textured thumb from the attached
 * scrollable control range.
 *
 * Declared without `override` this was not the render slot at all, so the
 * scrollbar rendered through `CMauiControl::DoRender`, which draws nothing.
 * The arrow buttons above and below are separate Bitmap controls and kept
 * drawing, which is why the bar appeared as two arrows with a gap.
 */
void moho::CMauiScrollbar::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;
  if (primBatcher == nullptr) {
    return;
  }

  const bool vertical = mAxis == MSA_Vert;

  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);

  float minRange = 0.0f;
  float maxRange = 0.0f;
  float minVisible = 0.0f;
  float maxVisible = 0.0f;
  if (CMauiControl* const scrollableControl = mScrollable.GetObjectPtr(); scrollableControl != nullptr) {
    const SMauiScrollValues scrollValues = scrollableControl->GetScrollValues(mAxis);
    minRange = scrollValues.mMinRange;
    maxRange = scrollValues.mMaxRange;
    minVisible = scrollValues.mMinVisible;
    maxVisible = scrollValues.mMaxVisible;
  }

  const float trackStart = vertical ? top : left;
  const float trackEnd = vertical ? bottom : right;
  float thumbStart = trackStart;
  float thumbEnd = trackEnd;
  if (maxRange > minRange) {
    const float trackSpan = trackEnd - trackStart;
    const float rangeSpan = maxRange - minRange;
    thumbStart = (trackSpan * ((minVisible - minRange) / rangeSpan)) + trackStart;
    thumbEnd = (trackSpan * ((maxVisible - minRange) / rangeSpan)) + trackStart;
  }

  thumbStart = static_cast<float>(FloorFrndintAdjustDown(thumbStart));
  thumbEnd = static_cast<float>(FloorFrndintAdjustDown(thumbEnd));

  const ScrollbarQuadUvs uvs = MakeScrollbarQuadUvs(vertical);
  const std::uint32_t color = mVertexAlpha;

  if (mBackground) {
    DrawScrollbarQuad(primBatcher, mBackground, left, top, right, bottom, color, uvs);
  }

  if (!mThumbTop || !mThumbBottom || !mThumbMiddle) {
    return;
  }

  const float topCapLength = static_cast<float>(mThumbTop->mHeight);
  const float bottomCapLength = static_cast<float>(mThumbBottom->mHeight);
  const float capLength = topCapLength + bottomCapLength;
  if (capLength >= (thumbEnd - thumbStart)) {
    const float thumbCenter = thumbEnd - ((thumbEnd - thumbStart) * 0.5f);
    thumbStart = thumbCenter - topCapLength;
    thumbEnd = thumbCenter + bottomCapLength;
  }

  if (vertical) {
    DrawScrollbarQuad(
      primBatcher, mThumbTop, left, thumbStart, right, thumbStart + topCapLength, color, uvs
    );
    DrawScrollbarQuad(
      primBatcher, mThumbBottom, left, thumbEnd - bottomCapLength, right, thumbEnd, color, uvs
    );

    if (std::fabs(thumbEnd - thumbStart) > capLength) {
      DrawScrollbarQuad(
        primBatcher,
        mThumbMiddle,
        left,
        (thumbStart + topCapLength) - 1.0f,
        right,
        thumbEnd - bottomCapLength,
        color,
        uvs
      );
    }
    return;
  }

  DrawScrollbarQuad(
    primBatcher, mThumbTop, thumbStart - topCapLength, top, thumbStart, bottom, color, uvs
  );
  DrawScrollbarQuad(
    primBatcher, mThumbBottom, thumbEnd, top, thumbEnd + bottomCapLength, bottom, color, uvs
  );

  if (std::fabs(thumbEnd - thumbStart) > capLength) {
    DrawScrollbarQuad(
      primBatcher,
      mThumbMiddle,
      thumbStart - topCapLength,
      top,
      thumbEnd + bottomCapLength,
      bottom,
      color,
      uvs
    );
  }
}

/**
 * Address: 0x007A11C0 (FUN_007A11C0, Moho::CMauiScrollbar::HandleEvent)
 *
 * What it does:
 * Handles click/wheel scrollbar interaction lanes by translating mouse
 * position to page-step or drag-capture behavior on the bound scroll target.
 */
bool moho::CMauiScrollbar::HandleEvent(
  const SMauiEventData& eventData
)
{
  const EMauiEventType eventType = eventData.mEventType;
  CMauiControl* const scrollableControl = mScrollable.GetObjectPtr();

  if ((eventType == MET_ButtonPress || eventType == MET_ButtonDClick) && eventData.mKeyCode == kPostDraggerLeftButton) {
    if (scrollableControl != nullptr) {
      const EMauiScrollAxis axis = mAxis;

      const CScriptLazyVar_float* topLane = &mTopLV;
      const CScriptLazyVar_float* bottomLane = &mBottomLV;
      if (axis != MSA_Vert) {
        topLane = &mRightLV;
        bottomLane = &mLeftLV;
      }

      const float topEdge = CScriptLazyVar_float::GetValue(topLane);
      const float bottomEdge = CScriptLazyVar_float::GetValue(bottomLane);
      const float mousePosition = axis == MSA_Vert ? eventData.mMousePos.y : eventData.mMousePos.x;

      const SMauiScrollValues scrollValues = scrollableControl->GetScrollValues(axis);
      const float minRange = scrollValues.mMinRange;
      const float maxRange = scrollValues.mMaxRange;
      const float minVisible = scrollValues.mMinVisible;

      float thumbStart = topEdge;
      float thumbEnd = bottomEdge;
      if (maxRange > minRange) {
        const float trackSpan = bottomEdge - topEdge;
        const float rangeSpan = maxRange - minRange;
        thumbStart = (((scrollValues.mMinVisible - minRange) / rangeSpan) * trackSpan) + topEdge;
        thumbEnd = (((scrollValues.mMaxVisible - minRange) / rangeSpan) * trackSpan) + topEdge;
      }

      if (topEdge <= mousePosition) {
        if (thumbStart > mousePosition) {
          scrollableControl->ScrollPages(axis, -1.0f);
          return true;
        }

        if (thumbEnd > mousePosition) {
          mDragStart = mousePosition;
          mTopAtDragStart = minVisible;
          SMauiEventData mutableEventData = eventData;
          func_PostDragger(GetRootFrame(), static_cast<moho::IMauiDragger*>(this), &mutableEventData);
          return true;
        }

        if (bottomEdge > mousePosition) {
          scrollableControl->ScrollPages(axis, 1.0f);
        }
      }
    }

    return true;
  }

  if (eventType != MET_WheelRotation) {
    return false;
  }

  if (scrollableControl != nullptr && mAxis == MSA_Vert) {
    const float lineDelta = eventData.mWheelRotation <= 0 ? 1.0f : -1.0f;
    scrollableControl->ScrollLines(MSA_Vert, lineDelta);
  }

  return true;
}

/**
 * Address: 0x007A1410 (FUN_007A1410, Moho::CMauiScrollbar::DragMove)
 *
 * What it does:
 * Converts mouse drag delta into scroll-range displacement and updates
 * `ScrollSetTop` on the attached scrollable control.
 */
void moho::CMauiScrollbar::DragMove(
  const SMauiEventData* const eventData
)
{
  CMauiControl* const scrollableControl = mScrollable.GetObjectPtr();
  if (scrollableControl == nullptr) {
    return;
  }

  const EMauiScrollAxis axis = mAxis;
  const float mousePosition = axis == MSA_Vert ? eventData->mMousePos.y : eventData->mMousePos.x;
  const float delta = mousePosition - mDragStart;

  const SMauiScrollValues scrollValues = scrollableControl->GetScrollValues(axis);
  const float minRange = scrollValues.mMinRange;
  const float maxRange = scrollValues.mMaxRange;

  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float rangePerPixel = (maxRange - minRange) / (bottom - top);

  scrollableControl->ScrollSetTop(axis, (rangePerPixel * delta) + mTopAtDragStart);
}

/**
 * Address: 0x007A1500 (FUN_007A1500, Moho::CMauiScrollbar::DragRelease)
 *
 * What it does:
 * No-op drag release hook for the scrollbar dragger lane.
 */
void moho::CMauiScrollbar::DragRelease(
  const SMauiEventData* const
)
{}

/**
 * Address: 0x007A1510 (FUN_007A1510, Moho::CMauiScrollbar::DragCancel)
 *
 * What it does:
 * No-op replacement/cancel hook for the scrollbar dragger lane.
 */
void moho::CMauiScrollbar::OnCurrentDraggerReplaced() {}

/**
 * Address: 0x007A17A0 (FUN_007A17A0, cfunc_CMauiScrollbarSetScrollable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarSetScrollableL`.
 */
int moho::cfunc_CMauiScrollbarSetScrollable(
  lua_State* const luaContext
)
{
  return cfunc_CMauiScrollbarSetScrollableL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A17C0 (FUN_007A17C0, func_CMauiScrollbarSetScrollable_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:SetScrollable(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarSetScrollable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetScrollable",
    &moho::cfunc_CMauiScrollbarSetScrollable,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarSetScrollableHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A1820 (FUN_007A1820, cfunc_CMauiScrollbarSetScrollableL)
 *
 * What it does:
 * Reads one scrollbar and one control and binds scroll target link lanes.
 */
int moho::cfunc_CMauiScrollbarSetScrollableL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiScrollbarSetScrollableHelpText);

  const LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  const LuaPlus::LuaObject scrollableObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const scrollableControl = SCR_FromLua_CMauiControl(scrollableObject, state);

  scrollbar->mScrollable.ResetFromObject(scrollableControl);

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A1920 (FUN_007A1920, cfunc_CMauiScrollbarSetNewTextures)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarSetNewTexturesL`.
 */
int moho::cfunc_CMauiScrollbarSetNewTextures(
  lua_State* const luaContext
)
{
  return cfunc_CMauiScrollbarSetNewTexturesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A1940 (FUN_007A1940, func_CMauiScrollbarSetNewTextures_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:SetNewTextures(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarSetNewTextures_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetNewTextures",
    &moho::cfunc_CMauiScrollbarSetNewTextures,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarSetNewTexturesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A19A0 (FUN_007A19A0, cfunc_CMauiScrollbarSetNewTexturesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus four optional texture-path lanes and
 * forwards resolved textures (with warning-color fallbacks) to
 * `CMauiScrollbar::SetTextures`.
 */
int moho::cfunc_CMauiScrollbarSetNewTexturesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 5, kCMauiScrollbarSetNewTexturesHelpText);

  auto scrollbarObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  boost::shared_ptr<CD3DBatchTexture> backgroundTexture{};
  if (lua_type(state->m_state, 2) != LUA_TNIL) {
    LuaPlus::LuaStackObject textureArg(state, 2);
    const char* texturePath = lua_tostring(state->m_state, 2);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    backgroundTexture = CD3DBatchTexture::FromFile(texturePath, 1u);
    if (!backgroundTexture) {
      gpg::Warnf("Scrollbar:SetTextures couldn't load background: %s", texturePath);
      backgroundTexture = CD3DBatchTexture::FromSolidColor(0xFFAAAA00u);
    }
  }

  boost::shared_ptr<CD3DBatchTexture> thumbMiddleTexture{};
  if (lua_type(state->m_state, 3) != LUA_TNIL) {
    LuaPlus::LuaStackObject textureArg(state, 3);
    const char* texturePath = lua_tostring(state->m_state, 3);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    thumbMiddleTexture = CD3DBatchTexture::FromFile(texturePath, 1u);
    if (!thumbMiddleTexture) {
      gpg::Warnf("Scrollbar:SetTextures couldn't load thumbMiddle: %s", texturePath);
      thumbMiddleTexture = CD3DBatchTexture::FromSolidColor(0xFFAAAA00u);
    }
  }

  boost::shared_ptr<CD3DBatchTexture> thumbTopTexture{};
  if (lua_type(state->m_state, 4) != LUA_TNIL) {
    LuaPlus::LuaStackObject textureArg(state, 4);
    const char* texturePath = lua_tostring(state->m_state, 4);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    thumbTopTexture = CD3DBatchTexture::FromFile(texturePath, 1u);
    if (!thumbTopTexture) {
      gpg::Warnf("Scrollbar:SetTextures couldn't load thumbTop: %s", texturePath);
      thumbTopTexture = CD3DBatchTexture::FromSolidColor(0xFFAAAA00u);
    }
  }

  boost::shared_ptr<CD3DBatchTexture> thumbBottomTexture{};
  if (lua_type(state->m_state, 5) != LUA_TNIL) {
    LuaPlus::LuaStackObject textureArg(state, 5);
    const char* texturePath = lua_tostring(state->m_state, 5);
    if (texturePath == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&textureArg, "string");
      texturePath = "";
    }

    thumbBottomTexture = CD3DBatchTexture::FromFile(texturePath, 1u);
    if (!thumbBottomTexture) {
      gpg::Warnf("Scrollbar:SetTextures couldn't load thumbBottom: %s", texturePath);
      thumbBottomTexture = CD3DBatchTexture::FromSolidColor(0xFFAAAA00u);
    }
  }

  scrollbar->SetTextures(backgroundTexture, thumbMiddleTexture, thumbTopTexture, thumbBottomTexture);
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A2080 (FUN_007A2080, cfunc_CMauiScrollbarDoScrollLines)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarDoScrollLinesL`.
 */
int moho::cfunc_CMauiScrollbarDoScrollLines(
  lua_State* const luaContext
)
{
  return cfunc_CMauiScrollbarDoScrollLinesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A20A0 (FUN_007A20A0, func_CMauiScrollbarDoScrollLines_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:DoScrollLines(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarDoScrollLines_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DoScrollLines",
    &moho::cfunc_CMauiScrollbarDoScrollLines,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarDoScrollLinesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A2100 (FUN_007A2100, cfunc_CMauiScrollbarDoScrollLinesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus numeric amount and forwards line-scroll to
 * its current scrollable control lane.
 */
int moho::cfunc_CMauiScrollbarDoScrollLinesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiScrollbarDoScrollLinesHelpText);

  LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  if (CMauiControl* const scrollableControl = scrollbar->mScrollable.GetObjectPtr()) {
    LuaPlus::LuaStackObject amountArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&amountArg, "number");
    }

    const float amount = static_cast<float>(lua_tonumber(state->m_state, 2));
    scrollableControl->ScrollLines(scrollbar->mAxis, amount);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A2220 (FUN_007A2220, cfunc_CMauiScrollbarDoScrollPages)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiScrollbarDoScrollPagesL`.
 */
int moho::cfunc_CMauiScrollbarDoScrollPages(
  lua_State* const luaContext
)
{
  return cfunc_CMauiScrollbarDoScrollPagesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007A2240 (FUN_007A2240, func_CMauiScrollbarDoScrollPages_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiScrollbar:DoScrollPages(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiScrollbarDoScrollPages_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DoScrollPages",
    &moho::cfunc_CMauiScrollbarDoScrollPages,
    &moho::CScrLuaMetatableFactory<moho::CMauiScrollbar>::Instance(),
    "CMauiScrollbar",
    kCMauiScrollbarDoScrollPagesHelpText
  );
  return &binder;
}

/**
 * Address: 0x007A22A0 (FUN_007A22A0, cfunc_CMauiScrollbarDoScrollPagesL)
 *
 * What it does:
 * Reads one `CMauiScrollbar` plus numeric amount and forwards page-scroll to
 * its current scrollable control lane.
 */
int moho::cfunc_CMauiScrollbarDoScrollPagesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiScrollbarDoScrollPagesHelpText);

  LuaPlus::LuaObject scrollbarObject(LuaPlus::LuaStackObject(state, 1));
  CMauiScrollbar* const scrollbar = SCR_FromLua_CMauiScrollbar(scrollbarObject, state);

  if (CMauiControl* const scrollableControl = scrollbar->mScrollable.GetObjectPtr()) {
    LuaPlus::LuaStackObject amountArg(state, 2);
    if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&amountArg, "number");
    }

    const float amount = static_cast<float>(lua_tonumber(state->m_state, 2));
    scrollableControl->ScrollPages(scrollbar->mAxis, amount);
  }

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x007A0310 (FUN_007A0310, Moho::CMauiScrollbar::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiScrollbar`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiScrollbar::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiScrollbar));
  }
  return sType;
}

/**
 * Address: 0x007A0330 (FUN_007A0330, Moho::CMauiScrollbar::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiScrollbar::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

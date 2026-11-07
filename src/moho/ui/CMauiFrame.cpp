#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kCMauiFrameGetTopmostDepthHelpText = "float GetTopmostDepth()";
  constexpr const char* kCMauiFrameGetTargetHeadHelpText = "int GetTargetHead()";
  constexpr const char* kCMauiFrameSetTargetHeadHelpText = "CMauiFrame:SetTargetHead(targetHead)";
  constexpr const char* kInternalCreateFrameHelpText =
    "InternalCreateFrame(luaobj) -- For internal use by CreateFrame()";

  [[nodiscard]] moho::CMauiFrame* ResolveFrameFromLuaObjectOrError(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* state
  )
  {
    constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
    constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
    constexpr const char* kIncorrectGameObjectTypeError =
      "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kDestroyedGameObjectError);
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<moho::CMauiFrame>());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CMauiFrame*>(upcast.mObj);
  }

  /**
   * Address: 0x00796E50 (FUN_00796E50, sub_796E50)
   *
   * What it does:
   * Assigns one retained frame owner into one weak self-owner lane.
   */
  [[maybe_unused]] boost::weak_ptr<moho::CMauiFrame>* AssignFrameWeakSelfFromSharedOwner(
    const boost::shared_ptr<moho::CMauiFrame>& owner,
    boost::weak_ptr<moho::CMauiFrame>* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    *destination = owner;
    return destination;
  }
}

gpg::RType* moho::CMauiFrame::sType = nullptr;

/**
 * Address: 0x00796900 (FUN_00796900, cfunc_CMauiFrameGetTopmostDepth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameGetTopmostDepthL`.
 */
int moho::cfunc_CMauiFrameGetTopmostDepth(
  lua_State* const luaContext
)
{
  return cfunc_CMauiFrameGetTopmostDepthL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796920 (FUN_00796920, func_CMauiFrameGetTopmostDepth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:GetTopmostDepth()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameGetTopmostDepth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetTopmostDepth",
    &moho::cfunc_CMauiFrameGetTopmostDepth,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameGetTopmostDepthHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796980 (FUN_00796980, cfunc_CMauiFrameGetTopmostDepthL)
 *
 * What it does:
 * Reads one `CMauiFrame` and pushes the topmost depth lane.
 */
int moho::cfunc_CMauiFrameGetTopmostDepthL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiFrameGetTopmostDepthHelpText);

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);
  lua_pushnumber(state->m_state, frame->GetTopmostDepth());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00796A50 (FUN_00796A50, cfunc_CMauiFrameGetTargetHead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameGetTargetHeadL`.
 */
int moho::cfunc_CMauiFrameGetTargetHead(
  lua_State* const luaContext
)
{
  return cfunc_CMauiFrameGetTargetHeadL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796A70 (FUN_00796A70, func_CMauiFrameGetTargetHead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:GetTargetHead()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameGetTargetHead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetTargetHead",
    &moho::cfunc_CMauiFrameGetTargetHead,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameGetTargetHeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796AD0 (FUN_00796AD0, cfunc_CMauiFrameGetTargetHeadL)
 *
 * What it does:
 * Reads one `CMauiFrame` and pushes integer target-head lane.
 */
int moho::cfunc_CMauiFrameGetTargetHeadL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiFrameGetTargetHeadHelpText);

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);
  lua_pushnumber(state->m_state, static_cast<float>(frame->mTargetHead));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00796B90 (FUN_00796B90, cfunc_CMauiFrameSetTargetHead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiFrameSetTargetHeadL`.
 */
int moho::cfunc_CMauiFrameSetTargetHead(
  lua_State* const luaContext
)
{
  return cfunc_CMauiFrameSetTargetHeadL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00796BB0 (FUN_00796BB0, func_CMauiFrameSetTargetHead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiFrame:SetTargetHead(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiFrameSetTargetHead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetTargetHead",
    &moho::cfunc_CMauiFrameSetTargetHead,
    &moho::CScrLuaMetatableFactory<moho::CMauiFrame>::Instance(),
    "CMauiFrame",
    kCMauiFrameSetTargetHeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796C10 (FUN_00796C10, cfunc_CMauiFrameSetTargetHeadL)
 *
 * What it does:
 * Reads one `CMauiFrame` plus numeric target-head lane and stores it into the
 * frame runtime view.
 */
int moho::cfunc_CMauiFrameSetTargetHeadL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiFrameSetTargetHeadHelpText);

  LuaPlus::LuaObject frameObject(LuaPlus::LuaStackObject(state, 1));
  CMauiFrame* const frame = SCR_FromLua_CMauiFrame(frameObject, state);

  LuaPlus::LuaStackObject targetHeadArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&targetHeadArg, "number");
  }

  frame->mTargetHead = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));
  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x00796790 (FUN_00796790, cfunc_InternalCreateFrame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateFrameL`.
 */
int moho::cfunc_InternalCreateFrame(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateFrameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x007967B0 (FUN_007967B0, func_InternalCreateFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateFrame(luaobj)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateFrame",
    &moho::cfunc_InternalCreateFrame,
    nullptr,
    "<global>",
    kInternalCreateFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00796810 (FUN_00796810, cfunc_InternalCreateFrameL)
 *
 * What it does:
 * Reads `(luaobj)`, constructs one root `CMauiFrame` (no parent), dispatches
 * `DoInit`, and pushes the created control's Lua object.
 */
int moho::cfunc_InternalCreateFrameL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kInternalCreateFrameHelpText);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x134)`, i.e. `sizeof(CMauiFrame)`, then the
  // constructor in place.
  auto* const frame = AllocateZeroedUiObject<CMauiFrame>(0x134u);
  new (frame) CMauiFrame(&luaObject, nullptr);
  frame->DoInit();
  frame->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007870F0 (FUN_007870F0, Moho::CMauiFrame::DoRender)
 *
 * What it does:
 * Walks the rendered-child lane and dispatches `DoRender` for each visible
 * child whose render-pass mask intersects the requested draw mask.
 */
void moho::CMauiFrame::RenderChildControls(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  if (mInvisible) {
    return;
  }

  for (std::uint32_t childIndex = 0;; ++childIndex) {
    CMauiControl* const* const renderedBegin = mRenderedChildren.begin();
    if (renderedBegin == nullptr) {
      break;
    }

    const std::int32_t renderedCount = static_cast<std::int32_t>(mRenderedChildren.end() - renderedBegin);
    if (childIndex >= static_cast<std::uint32_t>(renderedCount)) {
      break;
    }

    CMauiControl* const childControl = renderedBegin[childIndex];
    if (childControl == nullptr || childControl->IsHidden()) {
      continue;
    }

    if ((drawMask & childControl->mRenderPass) == 0) {
      continue;
    }

    childControl->DoRender(primBatcher, drawMask);
  }
}

/**
 * Address: 0x00796360 (FUN_00796360, ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z)
 * Mangled: ??0CMauiFrame@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVCMauiControl@1@@Z
 *
 * LuaPlus::LuaObject* luaObject, CMauiControl* parent
 *
 * IDA signature:
 * Moho::CMauiFrame *__stdcall Moho::CMauiFrame::CMauiFrame(Moho::CMauiFrame *this, LuaPlus::LuaObject *luaObject,
 * Moho::CMauiControl *parent);
 *
 * What it does:
 * Builds one frame control lane, seeds weak-self + deleted-control sentinel
 * fields, creates one frame-owned wx event mapper, and marks this control as
 * requiring one frame update from itself as root owner.
 */
moho::CMauiFrame::CMauiFrame(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "frame")
{

  // Construct the weak self-reference; do not assign to it. This is fresh
  // memory - CMauiControl's ctor does not touch these bytes - so
  // weak_ptr::operator= would call weak_release() on whatever `pi_` happened
  // to hold and write through it. The binary zeroes the two words outright
  // (`this->mPtr.px = 0; this->mPtr.pn.pi_ = 0` at 0x00796360), which is the
  // same thing a placement-construct emits.
  new (&mSelfWeak) boost::weak_ptr<CMauiFrame>{};

  auto* const deletedListHead = static_cast<CMauiControlListNode*>(&mDeletedControlList);
  mDeletedControlList.mNext = deletedListHead;
  mDeletedControlList.mPrev = deletedListHead;

  mTargetHead = 0;
  mEventHandler = new CMauiWxEventMapper(this);

  mNeedsFrameUpdate = true;
  mRootFrame = this;
}

/**
 * Address: 0x00796460 (FUN_00796460, ??1CMauiFrame@Moho@@UAE@XZ)
 * Deleting thunk: 0x00796440 (FUN_00796440, Moho::CMauiFrame::dtr)
 *
 * What it does:
 * Purges pending deleted controls, releases one frame-owned wx event mapper,
 * unlinks the deleted-control sentinel, and then tears down base control
 * state.
 */
moho::CMauiFrame::~CMauiFrame()
{
  PurgeDeleted();

  if (mEventHandler != nullptr) {
    delete mEventHandler;
    mEventHandler = nullptr;
  }

  mSelfWeak = boost::weak_ptr<CMauiFrame>{};
}

/**
 * Address: 0x00796510 (FUN_00796510, Moho::CMauiFrame::PurgeDeleted)
 *
 * What it does:
 * Deletes all controls queued in this frame's deleted-control intrusive list
 * and restores the list to empty-sentinel state.
 */
void moho::CMauiFrame::PurgeDeleted()
{
  // Never free while an event is being dispatched: the walk in
  // CMauiControl::PostEvent holds raw parent pointers across the script call
  // that destroyed them. The controls stay on the deleted list and the next
  // tick collects them.
  if (MauiEventDispatchInProgress()) {
    return;
  }

  auto* const deletedListHead =
    static_cast<CMauiControlListNode*>(&mDeletedControlList);
  while (deletedListHead->mNext != deletedListHead) {
    CMauiControlListNode* const deletedNode = deletedListHead->mPrev;
    deletedNode->ListUnlink();

    if (CMauiControl* const deletedControl = ControlFromParentListNode(deletedNode); deletedControl != nullptr) {
      delete deletedControl;
    }
  }
}

/**
 * Address: 0x00796680 (FUN_00796680, Moho::CMauiFrame::GetTopmostDepth)
 *
 * What it does:
 * Scans descendants and returns maximum control depth lane.
 */
float moho::CMauiFrame::GetTopmostDepth()
{
  float topmostDepth = gpg::nInf;
  for (CMauiControl* controlCursor = DepthFirstSuccessor(this); controlCursor != nullptr;
       controlCursor = controlCursor->DepthFirstSuccessor(this)) {
    const float controlDepth =
      CScriptLazyVar_float::GetValue(&controlCursor->mDepthLV);
    if (topmostDepth <= controlDepth) {
      topmostDepth = controlDepth;
    }
  }
  return topmostDepth;
}

/**
 * Address: 0x007966F0 (FUN_007966F0, ?DumpGraph@CMauiFrame@Moho@@QAEXXZ)
 *
 * What it does:
 * Walks this frame subtree depth-first and invokes `Dump()` on each control.
 */
void moho::CMauiFrame::DumpGraph()
{
  for (CMauiControl* controlCursor = this; controlCursor != nullptr;
       controlCursor = controlCursor->DepthFirstSuccessor(this)) {
    controlCursor->Dump();
  }
}

/**
 * Address: 0x00796720 (FUN_00796720, Moho::CMauiFrame::Dump)
 *
 * What it does:
 * Logs base control debug state and this frame's event-handler address.
 */
void moho::CMauiFrame::Dump()
{
  CMauiControl::Dump();
  gpg::Logf(
    "Root Frame, head=%p\n", static_cast<const void*>(mEventHandler)
  );
}

/**
 * Address: 0x00796550 (FUN_00796550, Moho::CMauiFrame::SetBounds)
 *
 * What it does:
 * Resets frame origin to `(0,0)` and stores integer client-size bounds into
 * width/height lazy-var lanes.
 */
void moho::CMauiFrame::SetBounds(
  const int width,
  const int height
)
{
  CScriptLazyVar_float::SetValue(&mLeftLV, 0.0f);
  CScriptLazyVar_float::SetValue(&mTopLV, 0.0f);
  CScriptLazyVar_float::SetValue(&mWidthLV, static_cast<float>(width));
  CScriptLazyVar_float::SetValue(&mHeightLV, static_cast<float>(height));
}

/**
 * Address: 0x007965A0 (FUN_007965A0, Moho::CMauiFrame::Frame)
 *
 * IDA signature:
 * void __thiscall Moho::CMauiFrame::Frame(Moho::CMauiFrame *this, float deltaSeconds);
 *
 * What it does:
 * Pins this frame as a shared owner by upgrading `mSelfWeak` to a temporary
 * `shared_ptr` so the frame and its subtree survive re-entrant per-control
 * `Frame` callbacks. Walks descendants depth-first; for each visible control
 * whose `mNeedsFrameUpdate` is set, dispatches its virtual `Frame(deltaSeconds)`
 * override. Once the subtree finishes ticking, purges any controls queued for
 * deletion during this cycle (`PurgeDeleted`). Finally drops the pinning lock.
 */
void moho::CMauiFrame::Frame(
  const float deltaSeconds
)
{

  // Pin this frame's shared owner for the duration of the tick so descendants
  // cannot tear down the root while they're still iterating.
  boost::shared_ptr<CMauiFrame> selfLock(mSelfWeak);

  static int sProbeCalls = 0;
  static int sProbeBudget = 0;
  int probeVisited = 0;
  int probeTicked = 0;
  int probeInvisible = 0;

  CMauiControl* nextControl = DepthFirstSuccessor(this);
  while (nextControl != nullptr) {
    CMauiControl* const currentControl = nextControl;
    nextControl = currentControl->DepthFirstSuccessor(this);

    ++probeVisited;
    if (currentControl->mInvisible) {
      ++probeInvisible;
    }
    if (!currentControl->mInvisible && currentControl->mNeedsFrameUpdate) {
      ++probeTicked;
      currentControl->Frame(deltaSeconds);
    }
  }

  // Report the peak tree size seen since the last report too, so a large
  // in-game UI on a sibling frame cannot hide behind sampling aliasing.
  static int sProbePeakVisited = 0;
  if (probeVisited > sProbePeakVisited) {
    sProbePeakVisited = probeVisited;
  }

  if (probeVisited > 100) {
    static bool sDumpedTree = false;
    if (!sDumpedTree) {
      sDumpedTree = true;
      int dumped = 0;
      for (CMauiControl* cursor = DepthFirstSuccessor(this); cursor != nullptr && dumped < 40;
           cursor = cursor->DepthFirstSuccessor(this)) {
        const fa::string name = cursor->GetDebugName();
        char line[224];
        sprintf_s(
          line,
          sizeof(line),
          "[TREEDUMP] %02d name=%.50s pass=%d alpha=%d/1000 hidden=%d invis=%d depth=%d rendered=%d\n",
          dumped,
          name.c_str(),
          cursor->mRenderPass,
          static_cast<int>(cursor->mAlpha * 1000.0f),
          cursor->mIsHidden ? 1 : 0,
          cursor->mInvisible ? 1 : 0,
          static_cast<int>(cursor->mDepth),
          static_cast<int>(cursor->mRenderedChildren.size())
        );
        ::OutputDebugStringA(line);
        ++dumped;
      }
    }
  }

  if ((++sProbeCalls % 601) == 0 && sProbeBudget < 60) {
    ++sProbeBudget;
    char probeBuf[224];
    sprintf_s(
      probeBuf,
      sizeof(probeBuf),
      "[FRAMEDIAG] call=%d frame=%p visited=%d peak=%d ticked=%d invisible=%d delta=%d us\n",
      sProbeCalls,
      static_cast<const void*>(this),
      probeVisited,
      sProbePeakVisited,
      probeTicked,
      probeInvisible,
      static_cast<int>(deltaSeconds * 1000000.0f)
    );
    ::OutputDebugStringA(probeBuf);
  }

  PurgeDeleted();
  // selfLock dtor releases the pin here.
}

/**
 * Address: 0x007961B0 (FUN_007961B0, Moho::CMauiFrame::Create)
 *
 * What it does:
 * Imports `/lua/maui/frame.lua`, calls `Frame()`, converts the return payload
 * to `CMauiFrame*`, and initializes the frame's weak self-owner lane.
 */
boost::shared_ptr<moho::CMauiFrame> moho::CMauiFrame::Create(
  LuaPlus::LuaState* const state
)
{
  boost::shared_ptr<CMauiFrame> outFrame{};
  if (state == nullptr || state->m_state == nullptr) {
    return outFrame;
  }

  lua_State* const rawState = state->m_state;
  const int savedTop = lua_gettop(rawState);

  LuaPlus::LuaObject moduleObject = SCR_Import(state, "/lua/maui/frame.lua");
  LuaPlus::LuaObject frameFactory = moduleObject.GetByName("Frame");
  frameFactory.PushStack(state);

  const int callStatus = LuaCallProtected(rawState, 0, 1);
  if (callStatus != 0) {
    const char* errorText = lua_tostring(rawState, -1);
    if (errorText == nullptr) {
      LuaPlus::LuaStackObject errorObject(state, -1);
      errorObject.TypeError("string");
      errorText = "<non-string>";
    }
    gpg::Warnf("Error in CMauiFrame::Create(): %s", errorText);
    lua_settop(rawState, savedTop);
    return outFrame;
  }

  LuaPlus::LuaObject frameLuaObject(state, -1);
  CMauiFrame* const frame = ResolveFrameFromLuaObjectOrError(frameLuaObject, state);
  if (frame != nullptr) {
    outFrame = boost::shared_ptr<CMauiFrame>(frame);
    (void)AssignFrameWeakSelfFromSharedOwner(outFrame, &frame->mSelfWeak);
  }

  lua_settop(rawState, savedTop);
  return outFrame;
}

/**
 * Address: 0x00796740 (FUN_00796740, Moho::CMauiFrame::DumpControlsUnder)
 *
 * What it does:
 * Walks one frame subtree depth-first, hit-tests each control at `(x, y)`,
 * and calls `Dump()` on every control that matches.
 */
void moho::CMauiFrame::DumpControlsUnder(
  CMauiFrame* const frame,
  const float x,
  const float y
)
{
  for (CMauiControl* control = frame; control != nullptr; control = control->DepthFirstSuccessor(frame)) {
    if (control->HitTest(x, y)) {
      control->Dump();
    }
  }
}

/**
 * Address: 0x00796000 (FUN_00796000, Moho::CMauiFrame::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiFrame`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiFrame::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiFrame));
  }
  return sType;
}

/**
 * Address: 0x00796020 (FUN_00796020, Moho::CMauiFrame::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiFrame::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

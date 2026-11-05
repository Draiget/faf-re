#include "moho/ui/UiPrivate.h"

namespace
{
  constexpr const char* kInternalCreateMovieHelpText =
    "InternalCreateMovie(luaobj,parent) -- for internal use by CreateMovie()";
  constexpr const char* kCMauiMovieInternalSetHelpText = "bool Movie:InternalSet(filename)";
  constexpr const char* kCMauiMovieLoopHelpText = "Loop(bool)";
  constexpr const char* kCMauiMoviePlayHelpText = "Play()";
  constexpr const char* kCMauiMovieStopHelpText = "Stop()";
  constexpr const char* kCMauiMovieIsLoadedHelpText = "IsLoaded()";
  constexpr const char* kCMauiMovieGetNumFramesHelpText =
    "int GetNumFrames() - returns the number of frames in the movie";
  constexpr const char* kCMauiMovieGetFrameRateHelpText =
    "number GetFrameRate() - returns the frame rate of the movie in FPS";
}

gpg::RType* moho::CMauiMovie::sType = nullptr;

/**
 * Address: 0x0079F540 (FUN_0079F540, cfunc_InternalCreateMovie)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_InternalCreateMovieL`.
 */
int moho::cfunc_InternalCreateMovie(
  lua_State* const luaContext
)
{
  return cfunc_InternalCreateMovieL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F560 (FUN_0079F560, func_InternalCreateMovie_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `InternalCreateMovie(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_InternalCreateMovie_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalCreateMovie",
    &moho::cfunc_InternalCreateMovie,
    nullptr,
    "<global>",
    kInternalCreateMovieHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079F5C0 (FUN_0079F5C0, cfunc_InternalCreateMovieL)
 *
 * What it does:
 * Reads `(luaobj,parent)`, constructs one `CMauiMovie`, dispatches `OnInit`,
 * and pushes the created control object.
 */
int moho::cfunc_InternalCreateMovieL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kInternalCreateMovieHelpText);

  LuaPlus::LuaObject parentObject(LuaPlus::LuaStackObject(state, 2));
  CMauiControl* const parentControl = SCR_FromLua_CMauiControl(parentObject, state);

  LuaPlus::LuaObject luaObject(LuaPlus::LuaStackObject(state, 1));
  // Binary: `operator new(0x168)`.
  auto* const movie = AllocateZeroedUiObject<CMauiMovie>(0x168u);
  new (movie) CMauiMovie(&luaObject, parentControl);
  movie->DoInit();
  movie->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0079EE20 (FUN_0079EE20, Moho::CMauiMovie::CMauiMovie)
 *
 * What it does:
 * Constructs one movie control and initializes movie playback/subtitle/lazy-var
 * runtime lanes.
 */
moho::CMauiMovie::CMauiMovie(
  LuaPlus::LuaObject* const luaObject,
  CMauiControl* const parent
)
  : CMauiControl(luaObject, parent, "Movie")
  , mMovie(nullptr)
  , mIsPlaying(false)
  , mDoLoop(false)
  , mIsStopped(false)
  , mIsMinimized(false)
  , mSubtitleCache()
  , mMovieWidthLV(luaObject->m_state)
  , mMovieHeightLV(luaObject->m_state)
{
  LuaPlus::LuaObject& controlLuaObject = mLuaObj;
  controlLuaObject.SetObject("MovieWidth", mMovieWidthLV);
  controlLuaObject.SetObject("MovieHeight", mMovieHeightLV);
}

/**
 * Address: 0x0079EFE0 (FUN_0079EFE0, Moho::CMauiMovie::LoadFile)
 *
 * IDA signature:
 * char __userpurge Moho::CMauiMovie::LoadFile(Moho::CMauiMovie *this, const char *filename);
 *
 * What it does:
 * Creates a CMovie, swaps it into the control's movie slot (deleting any prior
 * movie), and opens the given file through CMovie::OpenMovie. On failure warns
 * and clears the slot; on success sets the debug name and publishes the movie
 * width/height into the two lazy-var lanes. The `/nomovie` switch disables it.
 */
bool moho::CMauiMovie::LoadFile(
  const char* const filename
)
{
  if (moho::CFG_GetArgOption("/nomovie", 0u, nullptr)) {
    return false;
  }


  // Allocate + construct a fresh CMovie (binary: CMovie::operator new).
  moho::CMovie* newMovie = nullptr;
  moho::CMovie::AllocateAndConstruct(&newMovie);

  // Swap it into the movie slot, deleting the previous movie (if distinct)
  // through the IMovie virtual deleting destructor.
  moho::CMovie* const previousMovie = mMovie;
  if (newMovie != previousMovie && previousMovie != nullptr) {
    delete previousMovie;
  }
  mMovie = newMovie;

  if (!newMovie->OpenMovie(filename)) {
    gpg::Warnf("Error opening movie %s", filename);
    if (mMovie != nullptr) {
      delete mMovie;
    }
    mMovie = nullptr;
    mIsPlaying = false;
    return false;
  }

  SetDebugName(gpg::STR_Printf("Movie filename = %s", filename));
  moho::CScriptLazyVar_float::SetValue(&mMovieWidthLV, static_cast<float>(newMovie->GetWidth()));
  moho::CScriptLazyVar_float::SetValue(&mMovieHeightLV, static_cast<float>(newMovie->GetHeight()));
  return true;
}

/**
 * Address: 0x0079EF30 (FUN_0079EF30, Moho::CMauiMovie::~CMauiMovie non-deleting body)
 *
 * IDA signature:
 * _DWORD *__stdcall sub_79EF30(Moho::CMauiMovie *this);
 *
 * What it does:
 * Tears down one movie control in-place in reverse construction order:
 * destroys `mMovieHeightLV` (+0x154), destroys `mMovieWidthLV` (+0x140),
 * releases `mSubtitleCache` string storage (+0x124), deletes the
 * `moho::CMovie* mMovie` (+0x11C) via its virtual deleting
 * destructor when non-null, and then chains into `CMauiControl::~CMauiControl`
 * through the compiler-emitted base-class teardown.
 */
moho::CMauiMovie::~CMauiMovie()
{
  // The binary deletes the movie last, after the lazy vars and the subtitle
  // string, as an owning-pointer member at +0x11C would. `mMovie` is a raw
  // pointer here, so the delete runs from the body, ahead of them.
  if (mMovie != nullptr) {
    delete mMovie;
    mMovie = nullptr;
  }
}

/**
 * Address: 0x0079F1C0 (FUN_0079F1C0, Moho::CMauiMovie::OnFrame)
 *
 * What it does:
 * Advances movie playback state and dispatches movie script callbacks.
 */
void moho::CMauiMovie::Frame(
  const float deltaSeconds
)
{
  if (mIsMinimized) {
    return;
  }

  CScriptObject* const scriptObject = this;
  if (!mIsPlaying) {
    mNeedsFrameUpdate = false;
    (void)scriptObject->RunScript("OnFinished");
    return;
  }

  scriptObject->RunScriptNum("OnFrame", deltaSeconds);

  if (mIsStopped) {
    mNeedsFrameUpdate = false;
    (void)scriptObject->RunScript("OnStopped");
    return;
  }

  moho::CMovie* const moviePlayback = mMovie;
  if (moviePlayback == nullptr) {
    return;
  }

  if (moviePlayback->HasPlaybackFinished()) {
    if (mDoLoop) {
      moviePlayback->StartMoviePlaybackFromName();
    } else {
      mIsPlaying = false;
      mNeedsFrameUpdate = false;
      (void)scriptObject->RunScript("OnFinished");
    }
    return;
  }

  moviePlayback->UpdatePlaybackFrame();

  const fa::string* const subtitle = moviePlayback->GetSubtitleText();
  if (subtitle != nullptr && mSubtitleCache.view() != subtitle->view()) {
    mSubtitleCache.assign_owned(subtitle->view());
    const char* subtitleText = subtitle->c_str();
    scriptObject->CallbackStr("OnSubtitle", &subtitleText);
  }
}

/**
 * Address: 0x0079F310 (FUN_0079F310, Moho::CMauiMovie::Draw)
 *
 * What it does:
 * Draws one movie texture quad when playback is active.
 */
void moho::CMauiMovie::DoRender(
  CD3DPrimBatcher* const primBatcher,
  const std::int32_t drawMask
)
{
  (void)drawMask;

  moho::CMovie* const moviePlayback = mMovie;
  if (moviePlayback == nullptr || !mIsPlaying) {
    return;
  }

  const float left = CScriptLazyVar_float::GetValue(&mLeftLV);
  const float top = CScriptLazyVar_float::GetValue(&mTopLV);
  const float right = CScriptLazyVar_float::GetValue(&mRightLV);
  const float bottom = CScriptLazyVar_float::GetValue(&mBottomLV);

  // Slot 14 hands back a retained (px, pi) pair, which the binary pushes as
  // two words into the sheet overload of SetTexture (0x00438870) - not the
  // CD3DBatchTexture overload.
  boost::shared_ptr<ID3DTextureSheet> movieSheet{};
  moviePlayback->GetTextureSheetHandle(&movieSheet);
  primBatcher->SetTexture(movieSheet);

  // 0x0079F3A2 `mov ebx, [ebx+0F4h]` loads the control's packed vertex colour
  // and 0x0079F403/F413/F423/F43F store it into all four vertices' mColor.
  // The UVs are the plain corner constants: `xorps xmm0,xmm0` supplies 0.0 and
  // `movss xmm1, ds:a7` (0x00DFEC20 = 1.0f) supplies 1.0.
  const std::uint32_t vertexColor = mVertexAlpha;

  CD3DPrimBatcher::Vertex topLeft{};
  topLeft.mX = left;
  topLeft.mY = top;
  topLeft.mZ = 0.0f;
  topLeft.mColor = vertexColor;
  topLeft.mU = 0.0f;
  topLeft.mV = 0.0f;

  CD3DPrimBatcher::Vertex topRight{};
  topRight.mX = right;
  topRight.mY = top;
  topRight.mZ = 0.0f;
  topRight.mColor = vertexColor;
  topRight.mU = 1.0f;
  topRight.mV = 0.0f;

  CD3DPrimBatcher::Vertex bottomRight{};
  bottomRight.mX = right;
  bottomRight.mY = bottom;
  bottomRight.mZ = 0.0f;
  bottomRight.mColor = vertexColor;
  bottomRight.mU = 1.0f;
  bottomRight.mV = 1.0f;

  CD3DPrimBatcher::Vertex bottomLeft{};
  bottomLeft.mX = left;
  bottomLeft.mY = bottom;
  bottomLeft.mZ = 0.0f;
  bottomLeft.mColor = vertexColor;
  bottomLeft.mU = 0.0f;
  bottomLeft.mV = 1.0f;

  primBatcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft);
}

/**
 * Address: 0x0079F490 (FUN_0079F490, Moho::CMauiMovie::OnMinimized)
 *
 * What it does:
 * Stops active movie playback while minimized and resumes playback when the
 * control is restored from minimized state.
 */
void moho::CMauiMovie::OnMinimized(
  const bool minimized
)
{

  if (minimized) {
    if (mIsPlaying && !mIsStopped) {
      moho::CMovie* const moviePlayback = mMovie;
      if (moviePlayback != nullptr) {
        moviePlayback->Stop();
        mIsMinimized = true;
        CMauiControl::OnMinimized(minimized);
        return;
      }
    }
  } else if (mIsMinimized) {
    mMovie->PlayMovie();
    mIsMinimized = false;
  }

  CMauiControl::OnMinimized(minimized);
}

/**
 * Address: 0x0079F8F0 (FUN_0079F8F0, cfunc_CMauiMovieLoopL)
 *
 * What it does:
 * Updates the movie loop flag lane used by playback runtime.
 */
void moho::CMauiMovie::Loop(
  const bool shouldLoop
)
{
  mDoLoop = shouldLoop;
}

/**
 * Address: 0x0079FA40 (FUN_0079FA40, cfunc_CMauiMoviePlayL)
 *
 * What it does:
 * Starts attached movie playback and updates control frame-update lanes.
 */
void moho::CMauiMovie::Play()
{
  moho::CMovie* const moviePlayback = mMovie;

  mIsPlaying = false;
  mNeedsFrameUpdate = true;
  if (moviePlayback != nullptr) {
    moviePlayback->PlayMovie();
    mIsPlaying = true;
    mIsStopped = false;
  }
}

/**
 * Address: 0x0079FBA0 (FUN_0079FBA0, cfunc_CMauiMovieStopL)
 *
 * What it does:
 * Stops attached movie playback and records stopped state.
 */
void moho::CMauiMovie::Stop()
{
  moho::CMovie* const moviePlayback = mMovie;
  if (moviePlayback != nullptr) {
    mIsStopped = true;
    moviePlayback->Stop();
  }
}

/**
 * Address: 0x0079FCF0 (FUN_0079FCF0, cfunc_CMauiMovieIsLoadedL)
 *
 * What it does:
 * Returns whether the attached movie resource exists and is loaded.
 */
bool moho::CMauiMovie::IsLoaded() const
{
  return mMovie != nullptr && mMovie->IsLoaded();
}

/**
 * Address: 0x0079FE50 (FUN_0079FE50, cfunc_CMauiMovieGetNumFramesL)
 *
 * What it does:
 * Returns frame count from attached movie playback resource.
 */
std::int32_t moho::CMauiMovie::GetNumFrames() const
{
  return mMovie->GetFrameCount();
}

/**
 * Address: 0x0079FFA0 (FUN_0079FFA0, cfunc_CMauiMovieGetFrameRateL)
 *
 * What it does:
 * Returns playback framerate from attached movie resource.
 */
float moho::CMauiMovie::GetFrameRate() const
{
  return mMovie->GetFrameRate();
}

/**
 * Address: 0x0079F500 (FUN_0079F500, Moho::CMauiMovie::Dump)
 *
 * What it does:
 * Logs this movie control label and current `mIsPlaying` state.
 */
void moho::CMauiMovie::Dump()
{
  CMauiControl::Dump();
  gpg::Logf("CMauiMovie");

  const char* const isPlaying = mIsPlaying ? "true" : "false";
  gpg::Logf("Is Playing = %s", isPlaying);
}

/**
 * Address: 0x0079F6F0 (FUN_0079F6F0, cfunc_CMauiMovieInternalSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieInternalSetL`.
 */
int moho::cfunc_CMauiMovieInternalSet(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieInternalSetL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F710 (FUN_0079F710, func_CMauiMovieInternalSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:InternalSet(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieInternalSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "InternalSet",
    &moho::cfunc_CMauiMovieInternalSet,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieInternalSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x0079F770 (FUN_0079F770, cfunc_CMauiMovieInternalSetL)
 *
 * What it does:
 * Reads one `CMauiMovie` plus filename string, calls `LoadFile`, and returns
 * one boolean success lane.
 */
int moho::cfunc_CMauiMovieInternalSetL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiMovieInternalSetHelpText);

  LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);

  LuaPlus::LuaStackObject filenameArg(state, 2);
  const char* filename = lua_tostring(state->m_state, 2);
  if (filename == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&filenameArg, "string");
    filename = "";
  }

  const bool loaded = movie->LoadFile(filename);
  lua_pushboolean(state->m_state, loaded);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079F870 (FUN_0079F870, cfunc_CMauiMovieLoop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieLoopL`.
 */
int moho::cfunc_CMauiMovieLoop(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieLoopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F890 (FUN_0079F890, func_CMauiMovieLoop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Loop(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieLoop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Loop",
    &moho::cfunc_CMauiMovieLoop,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieLoopHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079F8F0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` plus bool and updates loop state.
 */
int moho::cfunc_CMauiMovieLoopL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 2, kCMauiMovieLoopHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);

  LuaPlus::LuaStackObject loopArg(state, 2);
  movie->Loop(loopArg.GetBoolean());

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079F9C0 (FUN_0079F9C0, cfunc_CMauiMoviePlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMoviePlayL`.
 */
int moho::cfunc_CMauiMoviePlay(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMoviePlayL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079F9E0 (FUN_0079F9E0, func_CMauiMoviePlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Play()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMoviePlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Play",
    &moho::cfunc_CMauiMoviePlay,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMoviePlayHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079FA40 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and starts playback.
 */
int moho::cfunc_CMauiMoviePlayL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiMoviePlayHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  movie->Play();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079FB20 (FUN_0079FB20, cfunc_CMauiMovieStop)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieStopL`.
 */
int moho::cfunc_CMauiMovieStop(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieStopL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FB40 (FUN_0079FB40, func_CMauiMovieStop_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:Stop()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieStop_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Stop",
    &moho::cfunc_CMauiMovieStop,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieStopHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079FBA0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and stops playback.
 */
int moho::cfunc_CMauiMovieStopL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiMovieStopHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  movie->Stop();

  lua_settop(state->m_state, 1);
  return 1;
}

/**
 * Address: 0x0079FC70 (FUN_0079FC70, cfunc_CMauiMovieIsLoaded)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_CMauiMovieIsLoadedL`.
 */
int moho::cfunc_CMauiMovieIsLoaded(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieIsLoadedL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FC90 (FUN_0079FC90, func_CMauiMovieIsLoaded_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:IsLoaded()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieIsLoaded_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsLoaded",
    &moho::cfunc_CMauiMovieIsLoaded,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieIsLoadedHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079FCF0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns whether it has loaded movie content.
 */
int moho::cfunc_CMauiMovieIsLoadedL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiMovieIsLoadedHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushboolean(state->m_state, movie->IsLoaded());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079FDD0 (FUN_0079FDD0, cfunc_CMauiMovieGetNumFrames)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieGetNumFramesL`.
 */
int moho::cfunc_CMauiMovieGetNumFrames(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieGetNumFramesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FDF0 (FUN_0079FDF0, func_CMauiMovieGetNumFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:GetNumFrames()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieGetNumFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetNumFrames",
    &moho::cfunc_CMauiMovieGetNumFrames,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieGetNumFramesHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079FE50 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns frame-count numeric result.
 */
int moho::cfunc_CMauiMovieGetNumFramesL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiMovieGetNumFramesHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushnumber(state->m_state, static_cast<float>(movie->GetNumFrames()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079FF20 (FUN_0079FF20, cfunc_CMauiMovieGetFrameRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CMauiMovieGetFrameRateL`.
 */
int moho::cfunc_CMauiMovieGetFrameRate(
  lua_State* const luaContext
)
{
  return cfunc_CMauiMovieGetFrameRateL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x0079FF40 (FUN_0079FF40, func_CMauiMovieGetFrameRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CMauiMovie:GetFrameRate()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CMauiMovieGetFrameRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFrameRate",
    &moho::cfunc_CMauiMovieGetFrameRate,
    &moho::CScrLuaMetatableFactory<moho::CMauiMovie>::Instance(),
    "CMauiMovie",
    kCMauiMovieGetFrameRateHelpText
  );
  return &binder;
}

/**
 * Alias of FUN_0079FFA0 (non-canonical helper lane).
 *
 * What it does:
 * Reads one `CMauiMovie` and returns frame-rate numeric result.
 */
int moho::cfunc_CMauiMovieGetFrameRateL(
  LuaPlus::LuaState* const state
)
{
  moho::SCR_ExpectExactArgs(state, 1, kCMauiMovieGetFrameRateHelpText);

  const LuaPlus::LuaObject movieObject(LuaPlus::LuaStackObject(state, 1));
  const CMauiMovie* const movie = SCR_FromLua_CMauiMovie(movieObject, state);
  lua_pushnumber(state->m_state, movie->GetFrameRate());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0079EC90 (FUN_0079EC90, Moho::CMauiMovie::GetClass)
 *
 * What it does:
 * Returns the cached reflection descriptor for `CMauiMovie`, resolved via
 * RTTI on first use.
 */
gpg::RType* moho::CMauiMovie::GetClass() const
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(CMauiMovie));
  }
  return sType;
}

/**
 * Address: 0x0079ECB0 (FUN_0079ECB0, Moho::CMauiMovie::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef moho::CMauiMovie::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

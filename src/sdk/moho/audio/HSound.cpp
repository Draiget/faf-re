#include "moho/audio/HSound.h"

#include <cstdint>

#include "lua/LuaObject.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CSndParams.h"

namespace moho
{
  CScrLuaMetatableFactory<HSound> CScrLuaMetatableFactory<HSound>::sInstance{};
} // namespace moho

/**
 * Address: 0x10015880 (constructor shape)
 *
 * What it does:
 * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
 */
moho::CScrLuaMetatableFactory<moho::HSound>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::HSound>& moho::CScrLuaMetatableFactory<moho::HSound>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x004E1F20 (FUN_004E1F20, Moho::CScrLuaMetatableFactory<Moho::HSound>::Create)
 *
 * What it does:
 * Builds one simple metatable table for `HSound` userdata lanes.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::HSound>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

namespace moho
{
  /**
   * Address: 0x004E10F0 (FUN_004E10F0, ??0HSound@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one script-visible sound-handle object and binds the
   * owner `CSndParams` context used for loop-state checks.
   */
  HSound::HSound(CSndParams* const ownerParams)
    : CScriptEvent()
    , mSimLoopLink()
    , mLoopCue(nullptr)
    , mLoopOwnerContext(ownerParams)
    , mAffectsDucking(0u)
    , mOpaque55{}
  {}

  /**
   * Address: 0x004E1120 (FUN_004E1120, sub_4E1120)
   *
   * What it does:
   * Unlinks the handle from active loop-lists, tears down base script/event
   * state, and optionally releases object storage.
   */
  HSound* HSound::Destroy(const std::uint8_t flags)
  {
    mSimLoopLink.ListUnlink();

    this->CScriptEvent::~CScriptEvent();
    if ((flags & 0x1u) != 0u) {
      ::operator delete(this);
    }

    return this;
  }

  /**
   * Address: 0x004E1260 (FUN_004E1260, sub_4E1260)
   *
   * What it does:
   * Resolves loop-engine state and signals completion when the cue has stopped
   * or no longer has a valid engine/cue context.
   */
  bool HSound::UpdateLoopCompletionState()
  {
    if (mTriggered) {
      return false;
    }

    bool shouldSignal = true;
    if (mLoopCue != nullptr && mLoopOwnerContext != nullptr) {
      boost::shared_ptr<AudioEngine> engine{};
      mLoopOwnerContext->GetEngine(&engine);
      if (engine.get() != nullptr) {
        shouldSignal = engine->IsStopped(mLoopCue);
      }
    }

    if (!shouldSignal) {
      return false;
    }

    EventSetSignaled(true);
    return true;
  }

  /**
   * Address: 0x004E4E60 (FUN_004E4E60, func_CreateLuaHSound)
   *
   * What it does:
   * Obtains cached `HSound` metatable object from Lua object-factory storage.
   */
  LuaPlus::LuaObject* func_CreateLuaHSound(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    *object = CScrLuaMetatableFactory<HSound>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x004E1190 (FUN_004E1190, func_CreateLuaHSoundObject)
   *
   * What it does:
   * Constructs Lua object lanes and binds this `HSound` instance into script
   * userdata/object state.
   */
  void func_CreateLuaHSoundObject(LuaPlus::LuaState* const state, HSound* const sound)
  {
    if (state == nullptr || sound == nullptr) {
      return;
    }

    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg1{};
    LuaPlus::LuaObject klass{};
    (void)func_CreateLuaHSound(&klass, state);
    sound->CreateLuaObject(klass, arg1, arg2, arg3);
  }
} // namespace moho

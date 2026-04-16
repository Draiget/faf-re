#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/containers/TDatList.h"
#include "moho/script/CScriptEvent.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CSndParams;
  class IXACTCue;

  /**
   * Sound handle object shared by sim/user audio paths.
   *
   * Recovered facts:
   * - object size: 0x58
   * - RTTI exposes two HSound vtables (`col.offset` 0 and 16), indicating
   *   an internal secondary subobject/view
   * - intrusive loop-list node at +0x44 (used by CSimSoundManager)
   * - slot 0 is a deleting-style virtual entry in retail binaries
   *
   * Only fields consumed by recovered sim audio code are semantically named.
   */
  class HSound : public CScriptEvent
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x004E10F0 (FUN_004E10F0, ??0HSound@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds one script-backed loop-handle object and binds its owner
     * `CSndParams` context pointer for follow-up loop-state checks.
     */
    explicit HSound(CSndParams* ownerParams);

    /**
     * Address: 0x004E1120 (FUN_004E1120, sub_4E1120)
     *
     * What it does:
     * Unlinks this handle from the intrusive loop list, runs base
     * `CScriptEvent` teardown, and optionally frees object storage.
     */
    virtual HSound* Destroy(std::uint8_t flags);

  public:
    TDatListItem<HSound, void> mSimLoopLink; // +0x44
    IXACTCue* mLoopCue;                      // +0x4C
    CSndParams* mLoopOwnerContext;           // +0x50
    std::uint8_t mAffectsDucking;            // +0x54
    std::uint8_t mOpaque55[0x03];            // +0x55

    /**
     * Address: 0x004E1260 (FUN_004E1260, sub_4E1260)
     *
     * What it does:
     * Checks whether the active loop cue has stopped (or lost engine context)
     * and signals this task-event when the handle is complete.
     */
    [[nodiscard]] bool UpdateLoopCompletionState();
  };

  static_assert(sizeof(HSound) == 0x58, "HSound size must be 0x58");
  static_assert(offsetof(HSound, mSimLoopLink) == 0x44, "HSound::mSimLoopLink offset must be 0x44");
  static_assert(offsetof(HSound, mLoopCue) == 0x4C, "HSound::mLoopCue offset must be 0x4C");
  static_assert(offsetof(HSound, mLoopOwnerContext) == 0x50, "HSound::mLoopOwnerContext offset must be 0x50");
  static_assert(offsetof(HSound, mAffectsDucking) == 0x54, "HSound::mAffectsDucking offset must be 0x54");

  /**
   * VFTABLE: 0x00E0BAE8
   * COL: 0x00E72A04
   */
  template <>
  class CScrLuaMetatableFactory<HSound> final : public CScrLuaObjectFactory
  {
  public:
    static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x004E1F20 (FUN_004E1F20, Moho::CScrLuaMetatableFactory<Moho::HSound>::Create)
     *
     * What it does:
     * Builds the default metatable for `HSound` Lua userdata.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    CScrLuaMetatableFactory();
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<HSound>) == 0x8, "CScrLuaMetatableFactory<HSound> size must be 0x8");

  /**
   * Address: 0x004E4E60 (FUN_004E4E60, func_CreateLuaHSound)
   *
   * What it does:
   * Returns cached `HSound` metatable object from Lua object-factory storage.
   */
  LuaPlus::LuaObject* func_CreateLuaHSound(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x004E1190 (FUN_004E1190, func_CreateLuaHSoundObject)
   *
   * What it does:
   * Creates and binds Lua userdata/object state for one script-visible
   * `HSound` instance.
   */
  void func_CreateLuaHSoundObject(LuaPlus::LuaState* state, HSound* sound);
} // namespace moho

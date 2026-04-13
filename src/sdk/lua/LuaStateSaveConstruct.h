#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class WriteArchive;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace LuaPlus
{
  class LuaState;

  /**
   * VFTABLE: 0x00D44F4C
   * COL: 0x00E5189C
   */
  class LuaStateSaveConstruct
  {
  public:
    using construct_fn_t =
      void (*)(gpg::WriteArchive*, LuaState*, int version, int unkLane, gpg::SerSaveConstructArgsResult*);

    /**
     * Address: 0x0090BC50 (FUN_0090BC50, LuaPlus::LuaStateSaveConstruct::Construct)
     *
     * What it does:
     * Validates that the serialized LuaState is not the main-thread/root state
     * and marks save-construct ownership as unowned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      LuaState* state,
      int version,
      int unkLane,
      gpg::SerSaveConstructArgsResult* result
    );

  public:
    void* vftable_;                  // +0x00
    gpg::SerHelperBase* mNext;       // +0x04
    gpg::SerHelperBase* mPrev;       // +0x08
    construct_fn_t mConstruct;       // +0x0C
  };

  static_assert(offsetof(LuaStateSaveConstruct, vftable_) == 0x00, "LuaStateSaveConstruct::vftable_ offset must be 0x00");
  static_assert(offsetof(LuaStateSaveConstruct, mNext) == 0x04, "LuaStateSaveConstruct::mNext offset must be 0x04");
  static_assert(offsetof(LuaStateSaveConstruct, mPrev) == 0x08, "LuaStateSaveConstruct::mPrev offset must be 0x08");
  static_assert(offsetof(LuaStateSaveConstruct, mConstruct) == 0x0C, "LuaStateSaveConstruct::mConstruct offset must be 0x0C");
  static_assert(sizeof(LuaStateSaveConstruct) == 0x10, "LuaStateSaveConstruct size must be 0x10");
} // namespace LuaPlus


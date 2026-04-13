#include "lua/LuaStateSaveConstruct.h"

#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int flags);
  };
} // namespace gpg

namespace LuaPlus
{
  /**
   * Address: 0x0090BC50 (FUN_0090BC50, LuaPlus::LuaStateSaveConstruct::Construct)
   *
   * What it does:
   * Validates that the serialized LuaState is not the main-thread/root state
   * and marks save-construct ownership as unowned.
   */
  void LuaStateSaveConstruct::Construct(
    gpg::WriteArchive* const,
    LuaState* const state,
    const int,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    if (state->m_rootState == state) {
      throw gpg::SerializationError("Consistency check failed: !isMainThread");
    }

    result->SetUnowned(0u);
  }
} // namespace LuaPlus


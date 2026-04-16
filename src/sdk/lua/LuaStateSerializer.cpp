#include "lua/LuaStateSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

namespace
{
/**
 * Address: 0x0090BC90 (FUN_0090BC90)
 *
 * What it does:
 * Reads serialized root/active Lua-state pointer lanes and rebinds the target
 * `LuaState` wrapper to the restored active lane.
 */
void DeserializeLuaStatePointerPair(
	gpg::ReadArchive* const archive,
	LuaState* const state,
	const gpg::RRef* const ownerRef
)
{
	LuaState* rootState = nullptr;
	(void)archive->ReadPointer_LuaState(&rootState, ownerRef);

	gpg::RRef rootStateRef{};
	(void)gpg::RRef_lua_State(&rootStateRef, rootState->m_state);

	lua_State* activeState = nullptr;
	(void)archive->ReadPointer_lua_State(&activeState, &rootStateRef);
	state->SetState(activeState);
}
} // namespace

/**
 * Address: 0x0090B6F0
 */
void LuaStateSerializer::RegisterSerializeFunctions()
{
	gpg::RType* type = gpg::LookupRType(typeid(LuaState));
	GPG_ASSERT(type->serLoadFunc_ == nullptr);
	type->serLoadFunc_ = mSerLoadFunc;
	GPG_ASSERT(type->serSaveFunc_ == nullptr);
	type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x0090BD60 (FUN_0090BD60, LuaPlus::LuaStateSerializer::Deserialize)
 *
 * What it does:
 * Restores one LuaState wrapper by reading root/current pointer lanes and
 * rebinding via `LuaState::SetState`.
 */
void LuaStateSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	LuaState* const state,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	(void)version;
	DeserializeLuaStatePointerPair(archive, state, ownerRef);
}

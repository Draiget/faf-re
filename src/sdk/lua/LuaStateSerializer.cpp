#include "lua/LuaStateSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

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

	LuaState* rootState = nullptr;
	(void)archive->ReadPointer_LuaState(&rootState, ownerRef);

	gpg::RRef rootStateRef{};
	(void)gpg::RRef_lua_State(&rootStateRef, rootState->m_state);

	lua_State* activeState = nullptr;
	(void)archive->ReadPointer_lua_State(&activeState, &rootStateRef);
	state->SetState(activeState);
}

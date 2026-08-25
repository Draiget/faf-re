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

// Address: 0x00F8E5D0 -- process-global `LuaStateSerializer` singleton.
LuaStateSerializer gLuaStateSerializer;
} // namespace

/**
 * Address: 0x0090B980 (FUN_0090B980, LuaPlus::LuaStateSerializer::Serialize)
 *
 * What it does:
 * Forwards one LuaState save lane to `LuaState::MemberSerialize`.
 */
void LuaStateSerializer::Serialize(gpg::WriteArchive* const archive, LuaState* const state)
{
	LuaState::MemberSerialize(archive, state);
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

/**
 * Address: 0x00BEA000 (FUN_00BEA000, register_LuaStateSerializer, dynamic
 * initializer for the global `LuaStateSerializer` singleton)
 */
LuaStateSerializer::LuaStateSerializer()
	: mSerLoadFunc(reinterpret_cast<gpg::RType::load_func_t>(&LuaStateSerializer::Deserialize))
	, mSerSaveFunc(reinterpret_cast<gpg::RType::save_func_t>(&LuaStateSerializer::Serialize))
{}

/**
 * Address: 0x00C09880 (FUN_00C09880, ??1LuaStateSerializer@LuaPlus@@QAE@@Z)
 */
LuaStateSerializer::~LuaStateSerializer()
{
	ResetLinks();
}

/**
 * Address: 0x0090B6F0 (FUN_0090B6F0, LuaPlus::LuaStateSerializer::Init)
 *
 * What it does:
 * Binds LuaState load/save serializer callbacks into RTTI.
 */
void LuaStateSerializer::Init()
{
	gpg::RType* type = LuaState::sType;
	if (!type) {
		type = gpg::LookupRType(typeid(LuaState));
		LuaState::sType = type;
	}
	GPG_ASSERT(type->serLoadFunc_ == nullptr);
	type->serLoadFunc_ = mSerLoadFunc;
	GPG_ASSERT(type->serSaveFunc_ == nullptr);
	type->serSaveFunc_ = mSerSaveFunc;
}

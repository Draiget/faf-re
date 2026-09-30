#include "lua/LuaStateSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

namespace LuaPlus
{
	void LuaState::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
	{
		result.SetUnowned(gpg::MakeRRef(new LuaState(UNBOUND)), 0u);
	}

	/**
	 * Address: 0x0090BA20 (FUN_0090BA20)
	 */
	void LuaState::MemberSaveConstructArgs(
		gpg::WriteArchive&, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
	)
	{
		if (m_rootState == this) {
			throw gpg::SerializationError("Consistency check failed: !isMainThread");
		}
		result.SetUnowned(0u);
	}

	/**
	 * `gpg::SerSaveConstructHelper<LuaState>`, vtable 0x00D44F4C.
	 *
	 * Address: 0x00BE9F90 (FUN_00BE9F90 -- constructs the global and registers its destructor.)
	 * Address: 0x00C09820 (FUN_00C09820 -- the global's destructor.)
	 * Address: 0x0090B5F0 (FUN_0090B5F0 -- `Init`.)
	 * Address: 0x0090BC50 (FUN_0090BC50 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
	 */
	struct LuaStateSaveConstruct : gpg::SerSaveConstructHelper<LuaState>
	{};

	/**
	 * `gpg::SerConstructHelper<LuaState>`, vtable 0x00D44EE0.
	 *
	 * Address: 0x00BE9FC0 (FUN_00BE9FC0 -- constructs the global and registers its destructor.)
	 * Address: 0x00C09850 (FUN_00C09850 -- the global's destructor.)
	 * Address: 0x0090B670 (FUN_0090B670 -- `Init`.)
	 * Address: 0x0090B860 (FUN_0090B860 -- `Construct`, `MemberConstruct` inlined.)
	 * Address: 0x0090B1C0 (FUN_0090B1C0 -- `Delete`.)
	 */
	struct LuaStateConstruct : gpg::SerConstructHelper<LuaState>
	{};
} // namespace LuaPlus

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
	(void)archive->ReadPointer(&rootState, ownerRef);

	gpg::RRef rootStateRef{};
	rootStateRef = gpg::MakeRRef<lua_State>(rootState->m_state);

	lua_State* activeState = nullptr;
	(void)archive->ReadPointer(&activeState, &rootStateRef);
	state->SetState(activeState);
}

// Address: 0x00F8E5C0 -- process-global `LuaStateSaveConstruct` singleton.
LuaStateSaveConstruct gLuaStateSaveConstruct;

// Address: 0x00F8E5E4 -- process-global `LuaStateConstruct` singleton.
LuaStateConstruct gLuaStateConstruct;

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
LuaStateSerializer::~LuaStateSerializer() = default;

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

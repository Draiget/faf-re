
#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "gpg/core/reflection/Reflection.h"

using namespace LuaPlus;

namespace LuaPlus
{
	/**
	 * Address: 0x0090BC90 (FUN_0090BC90 -- an unreferenced out-of-line copy;
	 * `SerSaveLoadHelper<LuaState>::Deserialize` 0x0090BD60 inlines it.)
	 */
	void LuaState::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
	{
		LuaState* rootState = nullptr;
		archive->ReadPointer(&rootState, &ownerRef);

		const gpg::RRef rootThreadRef = gpg::MakeRRef(rootState->m_state);
		lua_State* thread = nullptr;
		archive->ReadPointer(&thread, &rootThreadRef);
		SetState(thread);
	}

	/**
	 * Address: 0x0090B8F0 (FUN_0090B8F0, LuaPlus::LuaState::MemberSerialize)
	 */
	void LuaState::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
	{
		archive->WritePointer(m_rootState, gpg::TrackedPointerState::Unowned, ownerRef);
		archive->WritePointer(m_state, gpg::TrackedPointerState::Unowned, gpg::MakeRRef(m_rootState->m_state));
	}

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
// Address: 0x00F8E5C0 -- process-global `LuaStateSaveConstruct` singleton.
LuaStateSaveConstruct gLuaStateSaveConstruct;

// Address: 0x00F8E5E4 -- process-global `LuaStateConstruct` singleton.
LuaStateConstruct gLuaStateConstruct;

} // namespace

namespace LuaPlus
{
	/**
	 * `gpg::SerSaveLoadHelper<LuaState>`, vtable 0x00D44F54.
	 *
	 * Address: 0x00BEA000 (FUN_00BEA000 -- constructs the global and registers its destructor.)
	 * Address: 0x00C09880 (FUN_00C09880 -- the global's destructor.)
	 * Address: 0x0090B6F0 (FUN_0090B6F0 -- `Init`.)
	 * Address: 0x0090BD60 (FUN_0090BD60 -- `Deserialize`, `MemberDeserialize` inlined.)
	 * Address: 0x0090B980 (FUN_0090B980 -- `Serialize`, a forward to `MemberSerialize`.)
	 */
	struct LuaStateSerializer : gpg::SerSaveLoadHelper<LuaState>
	{};
} // namespace LuaPlus

namespace
{
	// Address: 0x00F8E5D0 -- process-global `LuaStateSerializer` singleton.
	LuaPlus::LuaStateSerializer gLuaStateSerializer;
} // namespace

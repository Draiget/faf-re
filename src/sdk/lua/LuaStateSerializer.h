#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace LuaPlus
{
	class LuaState;

	/**
	 * VFTABLE: 0x00D44F54
	 * COL: 0x00E518F4
	 */
	class LuaStateSerializer : public gpg::SerHelperBase
	{
	public:
		/**
		 * Address: 0x00BEA000 (FUN_00BEA000, register_LuaStateSerializer,
		 * dynamic initializer for the global `LuaStateSerializer` singleton)
		 *
		 * What it does:
		 * Default-constructs the `gpg::SerHelperBase` base and binds the
		 * load/save callback fields.
		 */
		LuaStateSerializer();

		/**
		 * Address: 0x00C09880 (FUN_00C09880, ??1LuaStateSerializer@LuaPlus@@QAE@@Z)
		 */
		~LuaStateSerializer();

		/**
		 * Address: 0x0090B980 (FUN_0090B980, LuaPlus::LuaStateSerializer::Serialize)
		 *
		 * What it does:
		 * Forwards one LuaState save lane to `LuaState::MemberSerialize`.
		 */
		static void Serialize(gpg::WriteArchive* archive, LuaState* state);

		/**
		 * Address: 0x0090BD60 (FUN_0090BD60, LuaPlus::LuaStateSerializer::Deserialize)
		 *
		 * What it does:
		 * Restores one serialized LuaState wrapper by reading root/current pointer
		 * lanes and rebinding the wrapper through `LuaState::SetState`.
		 */
		static void Deserialize(gpg::ReadArchive* archive, LuaState* state, int version, const gpg::RRef* ownerRef);

		/**
		 * Address: 0x0090B6F0 (FUN_0090B6F0, LuaPlus::LuaStateSerializer::Init)
		 *
		 * This body is ICF-folded/shared with vtable slot 0 of the
		 * never-constructed `gpg::SerSaveLoadHelper<LuaState>` template
		 * instantiation (`??_7?$SerSaveLoadHelper@VLuaState@LuaPlus@@@gpg@@6B@`,
		 * confirmed to have zero vtable-writer ctors anywhere in the binary) --
		 * both compile to byte-identical code that caches `LuaState::sType`
		 * and binds `serLoadFunc_`/`serSaveFunc_` from the same +0x0C/+0x10
		 * field offsets. `LuaStateSerializer` itself is not derived through
		 * that template: its real ctor (0x00BEA000) writes
		 * `??_7LuaStateSerializer@LuaPlus@@6B@` directly onto the object with
		 * no intermediate `SerSaveLoadHelper<LuaState>` vtable write.
		 *
		 * What it does:
		 * Binds LuaState load/save serializer callbacks into RTTI.
		 */
		void Init() override;

	public:
		gpg::RType::load_func_t mSerLoadFunc; // +0x0C
		gpg::RType::save_func_t mSerSaveFunc; // +0x10
	};
	static_assert(offsetof(LuaStateSerializer, mSerLoadFunc) == 0x0C, "LuaStateSerializer::mSerLoadFunc offset must be 0x0C");
	static_assert(offsetof(LuaStateSerializer, mSerSaveFunc) == 0x10, "LuaStateSerializer::mSerSaveFunc offset must be 0x10");
	static_assert(sizeof(LuaStateSerializer) == 0x14, "LuaStateSerializer must be 0x14");
}

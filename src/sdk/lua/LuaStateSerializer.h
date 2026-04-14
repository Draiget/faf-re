#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace LuaPlus
{
	class LuaState;

	/**
	 * VFTABLE: 0x00D44F54
	 * COL: 0x00E518F4
	 */
	class LuaStateSerializer
	{
	public:
		/**
		 * Address: 0x0090B6F0
		 * Slot: 0
		 * Demangled: sub_90B6F0
		 */
		virtual void RegisterSerializeFunctions();

		/**
		 * Address: 0x0090BD60 (FUN_0090BD60, LuaPlus::LuaStateSerializer::Deserialize)
		 *
		 * What it does:
		 * Restores one serialized LuaState wrapper by reading root/current pointer
		 * lanes and rebinding the wrapper through `LuaState::SetState`.
		 */
		static void Deserialize(gpg::ReadArchive* archive, LuaState* state, int version, const gpg::RRef* ownerRef);

	public:
		void* mNext;
		void* mPrev;
		gpg::RType::load_func_t mSerLoadFunc;
		gpg::RType::save_func_t mSerSaveFunc;
	};
	static_assert(sizeof(LuaStateSerializer) == 0x14, "LuaStateSerializer must be 0x14");
}

#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace LuaPlus
{
	/**
	 * VFTABLE: 0x00D44F5C
	 * COL: 0x00E5194C
	 */
	class LuaObjectSerializer
	{
	public:
		/**
		 * Address: 0x0090B560
		 * Slot: 0
		 * Demangled: sub_90B560
		 */
		virtual void RegisterSerializeFunctions();

	public:
		void* mNext;
		void* mPrev;
		gpg::RType::load_func_t mSerLoadFunc;
		gpg::RType::save_func_t mSerSaveFunc;
	};
	static_assert(sizeof(LuaObjectSerializer) == 0x14, "LuaObjectSerializer must be 0x14");
}

#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace LuaPlus
{
	/**
	 * VFTABLE: 0x00D44F74
	 * COL: 0x00E519A4
	 *
	 * Source hints:
	 * - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
	 */
	class LuaStateTypeInfo : public gpg::RType
	{
	public:
		/**
		 * Address: 0x0090C210 (FUN_0090C210, LuaPlus::LuaStateTypeInfo::LuaStateTypeInfo)
		 *
		 * What it does:
		 * Constructs the LuaState runtime type descriptor and preregisters it
		 * with reflection registry using `typeid(LuaState)`.
		 */
		LuaStateTypeInfo();

		/**
		 * Address: 0x0090C2E0
		 * Slot: 2
		 * Demangled: LuaPlus::LuaStateTypeInfo scalar deleting destructor
		 */
		~LuaStateTypeInfo() override;

		/**
		 * Address: 0x0090C260
		 * Slot: 3
		 * Demangled: LuaPlus::LuaStateTypeInfo::GetName
		 */
		[[nodiscard]]
		const char* GetName() const override;

		/**
		 * Address: 0x0090C270
		 * Slot: 9
		 * Demangled: LuaPlus::LuaStateTypeInfo::Init
		 */
		void Init() override;
	};
	static_assert(sizeof(LuaStateTypeInfo) == 0x64, "LuaStateTypeInfo must be 0x64");
}

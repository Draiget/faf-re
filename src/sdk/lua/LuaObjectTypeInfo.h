#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace LuaPlus
{
	/**
	 * VFTABLE: 0x00D44F10
	 * COL: 0x00E5184C
	 *
	 * Source hints:
	 * - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
	 */
	class LuaObjectTypeInfo : public gpg::RType
	{
	public:
		/**
		 * Address: 0x0090BCE0
		 * Slot: 2
		 * Demangled: LuaPlus::LuaObjectTypeInfo scalar deleting destructor
		 */
		~LuaObjectTypeInfo() override;

		/**
		 * Address: 0x0090BBD0
		 * Slot: 3
		 * Demangled: LuaPlus::LuaObjectTypeInfo::GetName
		 */
		[[nodiscard]]
		const char* GetName() const override;

		/**
		 * Address: 0x0090BBE0
		 * Slot: 9
		 * Demangled: LuaPlus::LuaObjectTypeInfo::Init
		 */
		void Init() override;
	};
	static_assert(sizeof(LuaObjectTypeInfo) == 0x64, "LuaObjectTypeInfo must be 0x64");
}

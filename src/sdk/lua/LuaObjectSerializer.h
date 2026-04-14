#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
	class ReadArchive;
	class WriteArchive;
}

namespace LuaPlus
{
	class LuaObject;

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

		/**
		 * Address: 0x0090BA10 (FUN_0090BA10, LuaPlus::LuaObjectSerializer::Serialize)
		 *
		 * What it does:
		 * Forwards one LuaObject save lane to `LuaObject::MemberSerialize`.
		 */
		static void Serialize(gpg::WriteArchive* archive, LuaObject* object);

		/**
		 * Address: 0x0090BE70 (FUN_0090BE70, LuaPlus::LuaObjectSerializer::Deserialize)
		 *
		 * What it does:
		 * Forwards one LuaObject load lane to `LuaObject::MemberDeserialize`.
		 */
		static void Deserialize(gpg::ReadArchive* archive, LuaObject* object, int version, const gpg::RRef* ownerRef);

	public:
		void* mNext;
		void* mPrev;
		gpg::RType::load_func_t mSerLoadFunc;
		gpg::RType::save_func_t mSerSaveFunc;
	};
	static_assert(sizeof(LuaObjectSerializer) == 0x14, "LuaObjectSerializer must be 0x14");
}

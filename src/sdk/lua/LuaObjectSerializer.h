#pragma once

#include <cstddef>

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
	class LuaObjectSerializer : public gpg::SerHelperBase
	{
	public:
		/**
		 * Address: 0x00BE9F50 (FUN_00BE9F50, register_LuaObjectSerializer,
		 * dynamic initializer for the global `LuaObjectSerializer` singleton)
		 *
		 * What it does:
		 * Default-constructs the `gpg::SerHelperBase` base and binds the
		 * load/save callback fields.
		 */
		LuaObjectSerializer();

		/**
		 * Address: 0x00C098B0 (FUN_00C098B0, ??1LuaObjectSerializer@LuaPlus@@QAE@@Z)
		 */
		~LuaObjectSerializer();

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

		/**
		 * Address: 0x0090B560 (FUN_0090B560, LuaPlus::LuaObjectSerializer::Init)
		 *
		 * This body is ICF-folded/shared with the vtable slot 0 of the
		 * never-constructed `gpg::SerSaveLoadHelper<LuaObject>` template
		 * instantiation (`??_7?$SerSaveLoadHelper@VLuaObject@LuaPlus@@@gpg@@6B@`,
		 * confirmed to have zero vtable-writer ctors anywhere in the binary) --
		 * both compile to byte-identical code that caches `LuaObject::sType`
		 * and binds `serLoadFunc_`/`serSaveFunc_` from the same +0x0C/+0x10
		 * field offsets. `LuaObjectSerializer` itself is not derived through
		 * that template: its real ctor (0x00BE9F50) writes
		 * `??_7LuaObjectSerializer@LuaPlus@@6B@` directly onto the object with
		 * no intermediate `SerSaveLoadHelper<LuaObject>` vtable write.
		 *
		 * What it does:
		 * Binds LuaObject load/save serializer callbacks into RTTI.
		 */
		void Init() override;

	public:
		gpg::RType::load_func_t mSerLoadFunc; // +0x0C
		gpg::RType::save_func_t mSerSaveFunc; // +0x10
	};
	static_assert(offsetof(LuaObjectSerializer, mSerLoadFunc) == 0x0C, "LuaObjectSerializer::mSerLoadFunc offset must be 0x0C");
	static_assert(offsetof(LuaObjectSerializer, mSerSaveFunc) == 0x10, "LuaObjectSerializer::mSerSaveFunc offset must be 0x10");
	static_assert(sizeof(LuaObjectSerializer) == 0x14, "LuaObjectSerializer must be 0x14");
}

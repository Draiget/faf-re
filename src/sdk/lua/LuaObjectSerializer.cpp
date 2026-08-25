#include "lua/LuaObjectSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

namespace
{
	// Address: 0x00F8E5AC -- process-global `LuaObjectSerializer` singleton.
	LuaObjectSerializer gLuaObjectSerializer;
} // namespace

/**
 * Address: 0x0090BA10 (FUN_0090BA10, LuaPlus::LuaObjectSerializer::Serialize)
 *
 * What it does:
 * Forwards one LuaObject save lane to `LuaObject::MemberSerialize`.
 */
void LuaObjectSerializer::Serialize(gpg::WriteArchive* const archive, LuaObject* const object)
{
	LuaObject::MemberSerialize(archive, object);
}

/**
 * Address: 0x0090BE70 (FUN_0090BE70, LuaPlus::LuaObjectSerializer::Deserialize)
 *
 * What it does:
 * Forwards one LuaObject load lane to `LuaObject::MemberDeserialize`.
 */
void LuaObjectSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	LuaObject* const object,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	const gpg::RRef nullOwner{};
	LuaObject::MemberDeserialize(archive, object, version, ownerRef != nullptr ? *ownerRef : nullOwner);
}

/**
 * Address: 0x00BE9F50 (FUN_00BE9F50, register_LuaObjectSerializer, dynamic
 * initializer for the global `LuaObjectSerializer` singleton)
 */
LuaObjectSerializer::LuaObjectSerializer()
	: mSerLoadFunc(reinterpret_cast<gpg::RType::load_func_t>(&LuaObjectSerializer::Deserialize))
	, mSerSaveFunc(reinterpret_cast<gpg::RType::save_func_t>(&LuaObjectSerializer::Serialize))
{}

/**
 * Address: 0x00C098B0 (FUN_00C098B0, ??1LuaObjectSerializer@LuaPlus@@QAE@@Z)
 */
LuaObjectSerializer::~LuaObjectSerializer()
{
	ResetLinks();
}

/**
 * Address: 0x0090B560 (FUN_0090B560, LuaPlus::LuaObjectSerializer::Init)
 *
 * What it does:
 * Binds LuaObject load/save serializer callbacks into RTTI.
 */
void LuaObjectSerializer::Init()
{
	gpg::RType* type = LuaObject::sType;
	if (!type) {
		type = gpg::LookupRType(typeid(LuaObject));
		LuaObject::sType = type;
	}
	GPG_ASSERT(type->serLoadFunc_ == nullptr);
	type->serLoadFunc_ = mSerLoadFunc;
	GPG_ASSERT(type->serSaveFunc_ == nullptr);
	type->serSaveFunc_ = mSerSaveFunc;
}

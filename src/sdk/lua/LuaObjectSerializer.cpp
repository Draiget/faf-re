#include "lua/LuaObjectSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

/**
 * Address: 0x0090B560
 */
void LuaObjectSerializer::RegisterSerializeFunctions()
{
	gpg::RType* type = gpg::LookupRType(typeid(LuaObject));
	GPG_ASSERT(type->serLoadFunc_ == nullptr);
	type->serLoadFunc_ = mSerLoadFunc;
	GPG_ASSERT(type->serSaveFunc_ == nullptr);
	type->serSaveFunc_ = mSerSaveFunc;
}

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

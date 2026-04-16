#include "lua/LuaObjectTypeInfo.h"

#include <typeinfo>

#include "lua/LuaObject.h"

using namespace LuaPlus;

/**
 * Address: 0x0090BB80 (FUN_0090BB80, LuaPlus::LuaObjectTypeInfo::LuaObjectTypeInfo)
 */
LuaObjectTypeInfo::LuaObjectTypeInfo()
	: gpg::RType()
{
	gpg::PreRegisterRType(typeid(LuaObject), this);
}

/**
 * Address: 0x0090BCE0
 */
LuaObjectTypeInfo::~LuaObjectTypeInfo() = default;

/**
 * Address: 0x0090BBD0
 */
const char* LuaObjectTypeInfo::GetName() const
{
	return "LuaObject";
}

/**
 * Address: 0x0090BBE0
 */
void LuaObjectTypeInfo::Init()
{
	size_ = sizeof(LuaObject);
	gpg::RType::Init();
	Finish();
}

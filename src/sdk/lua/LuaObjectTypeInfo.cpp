#include "lua/LuaObjectTypeInfo.h"

#include "lua/LuaObject.h"

using namespace LuaPlus;

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

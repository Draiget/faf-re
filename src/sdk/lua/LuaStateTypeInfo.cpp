#include "lua/LuaStateTypeInfo.h"

#include <typeinfo>

#include "lua/LuaObject.h"

using namespace LuaPlus;

/**
 * Address: 0x0090C210 (FUN_0090C210, LuaPlus::LuaStateTypeInfo::LuaStateTypeInfo)
 */
LuaStateTypeInfo::LuaStateTypeInfo()
	: gpg::RType()
{
	gpg::PreRegisterRType(typeid(LuaState), this);
}

/**
 * Address: 0x0090C2E0
 */
LuaStateTypeInfo::~LuaStateTypeInfo() = default;

/**
 * Address: 0x0090C260
 */
const char* LuaStateTypeInfo::GetName() const
{
	return "LuaState";
}

/**
 * Address: 0x0090C270
 */
void LuaStateTypeInfo::Init()
{
	size_ = sizeof(LuaState);
	gpg::RType::Init();
	Finish();
}

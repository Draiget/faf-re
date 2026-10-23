#include "lua/LuaObjectTypeInfo.h"

#include <typeinfo>

#include "lua/LuaObject.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace LuaPlus;

/**
 * Address: 0x00BE9EF0 (FUN_00BE9EF0, register_LuaObjectTypeInfo)
 * Address: 0x00C098E0 (FUN_00C098E0, atexit destructor of the LuaObjectTypeInfo object)
 *
 * What it does:
 * Builds the static descriptor on the first call - construction is what
 * preregisters `LuaObject` - and returns it.
 */
gpg::RType* LuaPlus::register_LuaObjectTypeInfo()
{
	static LuaObjectTypeInfo sInstance;
	return &sInstance;
}

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

// Phase-1 pre-registration: publish the descriptor before any consumer calls
// gpg::LookupRType(typeid(LuaObject)). See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_LuaObjectTypeInfo_be9ef0, LuaPlus::register_LuaObjectTypeInfo)

#include "lua/LuaStateTypeInfo.h"

#include <typeinfo>

#include "lua/LuaObject.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace LuaPlus;

/**
 * Address: 0x00BEA040 (FUN_00BEA040, register_LuaStateTypeInfo)
 * Address: 0x00C09940 (FUN_00C09940, atexit destructor of the LuaStateTypeInfo object)
 *
 * What it does:
 * Builds the static descriptor on the first call - construction is what
 * preregisters `LuaState` - and returns it.
 */
gpg::RType* LuaPlus::register_LuaStateTypeInfo()
{
	static LuaStateTypeInfo sInstance;
	return &sInstance;
}

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

// Phase-1 pre-registration: publish the descriptor before any consumer calls
// gpg::LookupRType(typeid(LuaState)). See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_LuaStateTypeInfo_bea040, LuaPlus::register_LuaStateTypeInfo)

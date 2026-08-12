#include "lua/LuaObjectTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "lua/LuaObject.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

using namespace LuaPlus;

namespace
{
	gpg::StaticTypeInfoStorage<LuaPlus::LuaObjectTypeInfo> gLuaObjectTypeInfoStorage{};

	void CleanupLuaObjectTypeInfo()
	{
		gLuaObjectTypeInfoStorage.Destroy();
	}
}

/**
 * Address: 0x00BE9EF0 (FUN_00BE9EF0, register_LuaObjectTypeInfo)
 *
 * What it does:
 * Builds the static descriptor - construction is what preregisters
 * `LuaObject` - and schedules the destructor the binary passes to `atexit`.
 */
gpg::RType* LuaPlus::register_LuaObjectTypeInfo()
{
	const bool firstCall = !gLuaObjectTypeInfoStorage.IsConstructed();
	auto& typeInfo = gLuaObjectTypeInfoStorage.Ensure();
	if (firstCall) {
		(void)std::atexit(&CleanupLuaObjectTypeInfo);
	}

	return &typeInfo;
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

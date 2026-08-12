#include "lua/LuaStateTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "lua/LuaObject.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

using namespace LuaPlus;

namespace
{
	gpg::StaticTypeInfoStorage<LuaPlus::LuaStateTypeInfo> gLuaStateTypeInfoStorage{};

	void CleanupLuaStateTypeInfo()
	{
		gLuaStateTypeInfoStorage.Destroy();
	}
}

/**
 * Address: 0x00BEA040 (FUN_00BEA040, register_LuaStateTypeInfo)
 *
 * What it does:
 * Builds the static descriptor - construction is what preregisters
 * `LuaState` - and schedules the destructor the binary passes to `atexit`.
 */
gpg::RType* LuaPlus::register_LuaStateTypeInfo()
{
	const bool firstCall = !gLuaStateTypeInfoStorage.IsConstructed();
	auto& typeInfo = gLuaStateTypeInfoStorage.Ensure();
	if (firstCall) {
		(void)std::atexit(&CleanupLuaStateTypeInfo);
	}

	return &typeInfo;
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

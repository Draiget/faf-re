#include "lua/LuaStateSerializer.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"

using namespace LuaPlus;

/**
 * Address: 0x0090B6F0
 */
void LuaStateSerializer::RegisterSerializeFunctions()
{
	gpg::RType* type = gpg::LookupRType(typeid(LuaState));
	GPG_ASSERT(type->serLoadFunc_ == nullptr);
	type->serLoadFunc_ = mSerLoadFunc;
	GPG_ASSERT(type->serSaveFunc_ == nullptr);
	type->serSaveFunc_ = mSerSaveFunc;
}

#pragma once

#include "legacy/containers/String.h"

namespace LuaPlus
{
	class LuaState;
}

namespace moho
{
	/**
	 * Address: 0x004797B0
	 *
	 * @param state 
	 * @param key 
	 * @return 
	 */
	msvc8::string Loc(LuaPlus::LuaState* state, const char* key);
}

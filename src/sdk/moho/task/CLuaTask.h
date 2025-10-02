#pragma once

#include "CTask.h"

namespace LuaPlus
{
	class LuaState;
}

namespace moho
{
	class MOHO_EMPTY_BASES CLuaTask :
		public CTask
	{
	public:
		DWORD v1;
		LuaPlus::LuaState* newState;
		DWORD argN;
		DWORD v4;
	};
}

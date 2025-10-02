#pragma once

#include "CClientBase.h"

namespace moho
{
	class CLocalClient :
		public CClientBase
	{
		
	};
	static_assert(sizeof(CLocalClient) == 0xD8, "CLocalClient size must be 0xD8");
}

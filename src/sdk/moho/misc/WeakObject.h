#pragma once
#include <cstdint>

namespace moho
{
	class WeakObject
	{
	public:
		uint32_t cookie_;
	};
	static_assert(sizeof(WeakObject) == 4, "WeakObject must be 4 bytes");
}

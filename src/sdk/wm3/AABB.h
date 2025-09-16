#pragma once
#include "Vector3.h"

namespace moho
{
	/** Simple AABB helper for API */
	struct AABBf {
		Wm3::Vec3<float> min{};
		Wm3::Vec3<float> max{};
	};
}

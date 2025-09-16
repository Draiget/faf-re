#pragma once

namespace moho
{
	template<class T>
	struct Rect2
	{
		T x0;
		T z0;
		T x1;
		T z1;
	};

	using Rect2i = Rect2<int>;
	using Rect2f = Rect2<float>;
}

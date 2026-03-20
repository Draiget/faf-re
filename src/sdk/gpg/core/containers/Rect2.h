#pragma once

namespace gpg
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

namespace moho
{
	template<class T>
	using Rect2 = gpg::Rect2<T>;

	using Rect2i = gpg::Rect2i;
	using Rect2f = gpg::Rect2f;
}

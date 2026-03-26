#pragma once

namespace gpg
{
	class RType;

	template<class T>
	struct Rect2
	{
		inline static RType* sType = nullptr;

		T x0;
		T z0;
		T x1;
		T z1;
	};

	using Rect2i = Rect2<int>;
	using Rect2f = Rect2<float>;

	static_assert(sizeof(Rect2i) == 0x10, "Rect2i size must be 0x10");
	static_assert(sizeof(Rect2f) == 0x10, "Rect2f size must be 0x10");
}

namespace moho
{
	template<class T>
	using Rect2 = gpg::Rect2<T>;

	using Rect2i = gpg::Rect2i;
	using Rect2f = gpg::Rect2f;
}

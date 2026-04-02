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

		/**
		 * Address: 0x00416F40 (FUN_00416F40, gpg::Rect2i::IsRegular)
		 *
		 * What it does:
		 * Returns true when the rectangle does not have positive area.
		 */
		[[nodiscard]] bool IsRegular() const noexcept
		{
			return x0 >= x1 || z0 >= z1;
		}

		/**
		 * Address: 0x00416F60 (FUN_00416F60, gpg::Rect2i::Contains)
		 *
		 * What it does:
		 * Inclusive/exclusive point-in-rect test (`[x0,x1) x [z0,z1)`).
		 */
		[[nodiscard]] bool Contains(const T x, const T z) const noexcept
		{
			return x >= x0 && x < x1 && z >= z0 && z < z1;
		}

		/**
		 * Address: 0x00416C90 (FUN_00416C90, gpg::Rect2<float>::Overlaps)
		 * Address: 0x00416FC0 (FUN_00416FC0, strict Rect2 overlap)
		 *
		 * What it does:
		 * Returns true when two rectangles overlap with strict interior
		 * intersection and both have positive area.
		 */
		[[nodiscard]] bool Overlaps(const Rect2& other) const noexcept
		{
			return x0 < other.x1
				&& other.x0 < x1
				&& z0 < other.z1
				&& other.z0 < z1
				&& !IsRegular()
				&& !other.IsRegular();
		}

		/**
		 * Address: 0x00416CF0 (FUN_00416CF0, inclusive Rect2 overlap)
		 * Address: 0x00417010 (FUN_00417010, inclusive Rect2 overlap helper)
		 *
		 * What it does:
		 * Returns true when the rectangles overlap or touch edges, while still
		 * requiring both rectangles to have positive area.
		 */
		[[nodiscard]] bool OverlapsInclusive(const Rect2& other) const noexcept
		{
			return x0 <= other.x1
				&& other.x0 <= x1
				&& z0 <= other.z1
				&& other.z0 <= z1
				&& !IsRegular()
				&& !other.IsRegular();
		}

		/**
		 * Address: 0x00417060 (FUN_00417060, edge-touch helper)
		 *
		 * What it does:
		 * Returns true when two positive-area rectangles touch exactly on one
		 * border axis while overlapping on the other axis.
		 */
		[[nodiscard]] bool Touches(const Rect2& other) const noexcept
		{
			if (IsRegular() || other.IsRegular()) {
				return false;
			}

			if (x0 == other.x1 || x1 == other.x0) {
				return z0 <= other.z1 && z1 >= other.z0;
			}

			if (z0 == other.z1 || z1 == other.z0) {
				return x0 <= other.x1 && x1 >= other.x0;
			}

			return false;
		}

		/**
		 * Address: 0x004170F0 (FUN_004170F0, clip/intersection helper)
		 *
		 * What it does:
		 * Clips this rectangle to the overlap with `other`.
		 */
		Rect2& IntersectWith(const Rect2& other) noexcept
		{
			if (x0 < other.x0) {
				x0 = other.x0;
			}
			if (x1 > other.x1) {
				x1 = other.x1;
			}
			if (z0 < other.z0) {
				z0 = other.z0;
			}
			if (z1 > other.z1) {
				z1 = other.z1;
			}
			return *this;
		}
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

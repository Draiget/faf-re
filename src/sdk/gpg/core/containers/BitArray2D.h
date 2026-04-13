#pragma once
#include <cstdint>

namespace gpg
{
	class BitArray2D
	{
	public:
		int32_t* ptr;
		int32_t size;
		int32_t width;
		int32_t height;

		/**
		 * Address: 0x008D81F0 (FUN_008D81F0, ??0BitArray2D@gpg@@QAE@XZ)
		 *
		 * What it does:
		 * Initializes an empty bit-array view.
		 */
		BitArray2D();

		/**
		 * Address: 0x008D82F0 (FUN_008D82F0, ??0BitArray2D@gpg@@QAE@II@Z_0)
		 *
		 * What it does:
		 * Initializes an empty bit-array then resets it to the requested size.
		 */
		BitArray2D(unsigned int width, unsigned int height);

		/**
		 * Address: 0x008D8200 (FUN_008D8200, ??1BitArray2D@gpg@@QAE@XZ)
		 *
		 * What it does:
		 * Releases the backing allocation for packed bits.
		 */
		~BitArray2D();

		/**
		 * Address: 0x008D8210 (FUN_008D8210, ?Reset@BitArray2D@gpg@@QAEXII@Z)
		 *
		 * What it does:
		 * Resizes and clears the bit buffer for the given logical dimensions.
		 */
		void Reset(unsigned int newWidth, unsigned int newHeight);

		/**
		 * Address: 0x008D8370 (FUN_008D8370, ?FillRect@BitArray2D@gpg@@QAEXHHHH_N@Z)
		 *
		 * What it does:
		 * Sets/clears a rectangular region in bit-packed occupancy rows.
		 */
		void FillRect(int x0, int z0, int rectWidth, int rectHeight, bool fill);

		/**
		 * Address: 0x008D8270 (FUN_008D8270, ?AnyBitSet@BitArray2D@gpg@@QBE_NPAH0PAI@Z)
		 *
		 * What it does:
		 * Finds the next set bit near `progress`, returning x/z coordinates.
		 */
		[[nodiscard]] bool AnyBitSet(unsigned int* storeWidth, unsigned int* storeHeight, unsigned int* progress) const;

		/**
		 * Address: 0x008D8460 (FUN_008D8460, ?GetRectOr@BitArray2D@gpg@@QBE_NHHHH_N@Z)
		 *
		 * What it does:
		 * Returns true when any set bit intersects the queried rectangle.
		 * When `disallowNegative` is true, negative/out-of-range rectangle input
		 * is treated as occupied if it overlaps a non-empty area.
		 */
		[[nodiscard]] bool GetRectOr(int x0, int z0, int w, int h, bool disallowNegative) const;

		/**
		 * What it does:
		 * Returns true when `(x,z)` is out of bounds or the corresponding bit is set.
		 */
		[[nodiscard]] bool IsBitSetOrOutOfBounds(int x, int z) const;
	};

	static_assert(sizeof(BitArray2D) == 0x10, "BitArray2D size must be 0x10");
}

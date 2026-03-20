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
	};

	static_assert(sizeof(BitArray2D) == 0x10, "BitArray2D size must be 0x10");
}

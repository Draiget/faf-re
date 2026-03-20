#include "MeshFormatter.h"

#include <new>

namespace gpg::gal
{
	/**
	 * Address: 0x00A82547 (_purecall in MeshFormatter slot 0)
	 *
	 * std::uint8_t deleteFlags
	 *
	 * IDA signature:
	 * (pure virtual slot in base; concrete deleting thunks in derived classes:
	 *  0x00945600, 0x00945620, 0x0094D8F0, 0x0094D910)
	 *
	 * What it does:
	 * Provides shared delete-flag semantics for formatter implementations that
	 * choose to call the base slot-0 helper during teardown.
	 */
	MeshFormatter* MeshFormatter::Destroy(const std::uint8_t deleteFlags)
	{
		if ((deleteFlags & 1u) != 0u) {
			operator delete(this);
		}
		return this;
	}
}

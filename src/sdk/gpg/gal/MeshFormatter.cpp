#include "MeshFormatter.h"

#include <new>

namespace gpg::gal
{
	namespace
	{
		/**
		 * Address: 0x00944FF0 (FUN_00944FF0)
		 *
		 * What it does:
		 * Models one base `MeshFormatter` vtable-restore lane used by unwind tails.
		 */
		[[maybe_unused]] void RestoreMeshFormatterBaseVtableLane(MeshFormatter* const formatter) noexcept
		{
			// In lifted C++, base-vtable restoration is owned by constructor/destructor codegen.
			(void)formatter;
		}

		/**
		 * Address: 0x00945000 (FUN_00945000)
		 *
		 * What it does:
		 * Models the return-`this` form of the base `MeshFormatter` vtable-restore lane.
		 */
		[[maybe_unused]] MeshFormatter* RestoreMeshFormatterBaseVtableAndReturn(
			MeshFormatter* const formatter) noexcept
		{
			RestoreMeshFormatterBaseVtableLane(formatter);
			return formatter;
		}
	}

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

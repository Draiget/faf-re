#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/MeshFormatter.h"

namespace gpg::gal
{
	/**
	 * VFTABLE: 0x00D48998
	 * COL:     0x00E53994
	 */
	class Float16HardwareVertexFormatterD3D10 : public MeshFormatter
	{
	public:
		/**
		 * Address: 0x0094D910 (FUN_0094D910, scalar deleting destructor thunk)
		 * Slot: 0
		 */
		MeshFormatter* Destroy(std::uint8_t deleteFlags) override = 0;

		/**
		 * Address: 0x0094D790 (FUN_0094D790)
		 * Slot: 1
		 */
		[[nodiscard]] bool AllowMeshInstancing() override = 0;

		/**
		 * Address: 0x0094D930 (FUN_0094D930)
		 * Slot: 2
		 */
		[[nodiscard]] std::uintptr_t SelectVertexFormatToken(
			std::uintptr_t streamToken,
			std::int32_t layoutVariant) override = 0;

		/**
		 * Address: 0x0094D7C0 (FUN_0094D7C0)
		 * Slot: 3
		 */
		[[nodiscard]] std::uint32_t GetVertexStride(
			std::int32_t streamClass,
			std::int32_t sizeVariant) override = 0;

		/**
		 * Address: 0x0094D7E0 (FUN_0094D7E0)
		 * Slot: 4
		 */
		void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const void* sourceVertex,
			std::int32_t writeVariant) override = 0;
	};

	static_assert(
		sizeof(Float16HardwareVertexFormatterD3D10) == 0x4,
		"Float16HardwareVertexFormatterD3D10 size must be 0x4");
}

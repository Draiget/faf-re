#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/MeshFormatter.h"

namespace gpg::gal
{
	/**
	 * VFTABLE: 0x00D48980
	 * COL:     0x00E53948
	 */
	class HardwareVertexFormatterD3D10 : public MeshFormatter
	{
	public:
		/**
		 * Address: 0x0094D4F0 (FUN_0094D4F0, ??0HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
		 *
		 * What it does:
		 * Initializes one D3D10 hardware vertex-formatter instance.
		 */
		HardwareVertexFormatterD3D10();

		/**
		 * Address: 0x0094D8F0 (FUN_0094D8F0, scalar deleting destructor thunk)
		 * Slot: 0
		 */
		MeshFormatter* Destroy(std::uint8_t deleteFlags) override;

		/**
		 * Address: 0x0094D510 (FUN_0094D510)
		 * Slot: 1
		 */
		[[nodiscard]] bool AllowMeshInstancing() override;

		/**
		 * Address: 0x0094D960 (FUN_0094D960)
		 * Slot: 2
		 */
		[[nodiscard]] std::uintptr_t SelectVertexFormatToken(
			std::uintptr_t streamToken,
			std::int32_t layoutVariant) override;

		/**
		 * Address: 0x0094D530 (FUN_0094D530)
		 * Slot: 3
		 */
		[[nodiscard]] std::uint32_t GetVertexStride(
			std::int32_t streamClass,
			std::int32_t sizeVariant) override;

		/**
		 * Address: 0x0094D550 (FUN_0094D550)
		 * Slot: 4
		 */
		void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const void* sourceVertex,
			std::int32_t writeVariant) override;
	};

	static_assert(sizeof(HardwareVertexFormatterD3D10) == 0x4, "HardwareVertexFormatterD3D10 size must be 0x4");
}

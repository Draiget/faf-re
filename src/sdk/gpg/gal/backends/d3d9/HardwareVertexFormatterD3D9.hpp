#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/MeshFormatter.h"

namespace gpg::gal
{
	/**
	 * VFTABLE: 0x00D47F38
	 * COL:     0x00E534A4
	 */
	class HardwareVertexFormatterD3D9 : public MeshFormatter
	{
	public:
		/**
		 * Address: 0x00945600 (FUN_00945600, scalar deleting destructor thunk)
		 * Slot: 0
		 */
		MeshFormatter* Destroy(std::uint8_t deleteFlags) override;

		/**
		 * Address: 0x009451E0 (FUN_009451E0, ?AllowMeshInstancing@...)
		 * Slot: 1
		 */
		[[nodiscard]] bool AllowMeshInstancing() override;

		/**
		 * Address: 0x00945680 (FUN_00945680)
		 * Slot: 2
		 */
		[[nodiscard]] std::uintptr_t SelectVertexFormatToken(
			std::uintptr_t streamToken,
			std::int32_t layoutVariant) override;

		/**
		 * Address: 0x009451F0 (FUN_009451F0)
		 * Slot: 3
		 */
		[[nodiscard]] std::uint32_t GetVertexStride(
			std::int32_t streamClass,
			std::int32_t sizeVariant) override;

		/**
		 * Address: 0x00945210 (FUN_00945210)
		 * Slot: 4
		 */
		void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const void* sourceVertex,
			std::int32_t writeVariant) override;
	};

	static_assert(sizeof(HardwareVertexFormatterD3D9) == 0x4, "HardwareVertexFormatterD3D9 size must be 0x4");
}

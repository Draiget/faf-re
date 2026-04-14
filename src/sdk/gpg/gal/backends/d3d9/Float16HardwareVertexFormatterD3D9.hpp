#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/MeshFormatter.h"

namespace gpg::gal
{
	/**
	 * VFTABLE: 0x00D47F50
	 * COL:     0x00E534F0
	 */
	class Float16HardwareVertexFormatterD3D9 : public MeshFormatter
	{
	public:
		/**
		 * Address: 0x00945380 (FUN_00945380, ??0Float16HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
		 *
		 * What it does:
		 * Initializes one D3D9 float16 hardware vertex-formatter instance.
		 */
		Float16HardwareVertexFormatterD3D9();

		/**
		 * Address: 0x00945620 (FUN_00945620, scalar deleting destructor thunk)
		 * Slot: 0
		 */
		MeshFormatter* Destroy(std::uint8_t deleteFlags) override;

		/**
		 * Address: 0x009453A0 (FUN_009453A0)
		 * Slot: 1
		 */
		[[nodiscard]] bool AllowMeshInstancing() override;

		/**
		 * Address: 0x00945640 (FUN_00945640)
		 * Slot: 2
		 */
		[[nodiscard]] std::uintptr_t SelectVertexFormatToken(
			std::uintptr_t streamToken,
			std::int32_t layoutVariant) override;

		/**
		 * Address: 0x009453C0 (FUN_009453C0)
		 * Slot: 3
		 */
		[[nodiscard]] std::uint32_t GetVertexStride(
			std::int32_t streamClass,
			std::int32_t sizeVariant) override;

		/**
		 * Address: 0x009453F0 (FUN_009453F0)
		 * Slot: 4
		 */
		void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const void* sourceVertex,
			std::int32_t writeVariant) override;
	};

	static_assert(
		sizeof(Float16HardwareVertexFormatterD3D9) == 0x4,
		"Float16HardwareVertexFormatterD3D9 size must be 0x4");
}

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
		 * Address: 0x009451C0 (FUN_009451C0, ??0HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
		 *
		 * What it does:
		 * Initializes one D3D9 hardware vertex-formatter instance.
		 */
		HardwareVertexFormatterD3D9();

		/**
		 * Address: 0x009451D0 (FUN_009451D0)
		 * Address: 0x00945600 (FUN_00945600, slot 0: the scalar deleting destructor)
		 *
		 * What it does:
		 * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
		 */
		~HardwareVertexFormatterD3D9() override;

		/**
		 * Address: 0x009451E0 (FUN_009451E0, ?AllowMeshInstancing@...)
		 * Slot: 1
		 */
		[[nodiscard]] bool AllowMeshInstancing() override;

		/**
		 * Address: 0x00945680 (FUN_00945680)
		 * Slot: 2
		 */
		[[nodiscard]] boost::shared_ptr<VertexFormat> CreateVertexFormat(std::int32_t layoutVariant) override;

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
			const MeshVertex& sourceVertex,
			std::int32_t writeVariant) override;
	};

	static_assert(sizeof(HardwareVertexFormatterD3D9) == 0x4, "HardwareVertexFormatterD3D9 size must be 0x4");
}

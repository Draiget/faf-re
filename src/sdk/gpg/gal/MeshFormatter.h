#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "boost/shared_ptr.h"
#include "gpg/gal/MeshVertex.h"

namespace gpg::gal
{
	class VertexFormat;

	/**
	 * VFTABLE: 0x00D47F20
	 * COL:     0x00E5345C
	 */
	class MeshFormatter
	{
	public:
		/**
		 * Address: 0x00A82547 (_purecall in MeshFormatter slot 0)
		 * Slot: 0
		 *
		 * std::uint8_t deleteFlags
		 *
		 * What it does:
		 * Virtual deleting-style teardown entry implemented by concrete formatter
		 * backends (D3D9/D3D10 variants).
		 */
		virtual MeshFormatter* Destroy(std::uint8_t deleteFlags) = 0;

		/**
		 * Address: 0x00A82547 (_purecall in MeshFormatter slot 1)
		 * Slot: 1
		 *
		 * What it does:
		 * Reports whether this formatter can use the instancing-capable layout path.
		 */
		[[nodiscard]] virtual bool AllowMeshInstancing() = 0;

		/**
		 * Address: 0x00A82547 (_purecall in MeshFormatter slot 2)
		 * Slot: 2
		 *
		 * What it does:
		 * Creates, on the active device, the vertex format this formatter's
		 * records are laid out in (Device slot 14). `layoutVariant` selects
		 * format 16 over 15 on the D3D9 float16 formatter; the others ignore it.
		 */
		[[nodiscard]] virtual boost::shared_ptr<VertexFormat> CreateVertexFormat(std::int32_t layoutVariant) = 0;

		/**
		 * Address: 0x00A82547 (_purecall in MeshFormatter slot 3)
		 * Slot: 3
		 *
		 * std::int32_t streamClass, std::int32_t sizeVariant
		 *
		 * What it does:
		 * Returns packed vertex stride for the requested source stream/variant.
		 */
		[[nodiscard]] virtual std::uint32_t GetVertexStride(
			std::int32_t streamClass,
			std::int32_t sizeVariant) = 0;

		/**
		 * Address: 0x00A82547 (_purecall in MeshFormatter slot 4)
		 * Slot: 4
		 *
		 * What it does:
		 * Packs one half of `sourceVertex` into the vertex-buffer record at
		 * `destinationVertex`: the geometry fields for stream class 0, the
		 * instance fields otherwise. `writeVariant` selects format 16's extra
		 * per-vertex position stream on the float16 D3D9 formatter.
		 */
		virtual void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const MeshVertex& sourceVertex,
			std::int32_t writeVariant) = 0;

	protected:
		MeshFormatter() = default;
		~MeshFormatter() = default;
	};

	static_assert(sizeof(MeshFormatter) == 0x4, "MeshFormatter size must be 0x4");
	static_assert(std::is_polymorphic<MeshFormatter>::value, "MeshFormatter must remain polymorphic");

	/**
	 * Address: 0x008E7550 (FUN_008E7550, func_GetHardwareVertexFormatter)
	 *
	 * What it does:
	 * Returns the process-wide hardware vertex formatter for the active
	 * device, choosing it on first use (defined in the D3D9 backend TU).
	 */
	[[nodiscard]] MeshFormatter* GetHardwareVertexFormatter();
}

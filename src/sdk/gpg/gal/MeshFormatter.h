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
	 *
	 * Packs `MeshVertex` records into one backend's hardware vertex layout.
	 * There are four, a plain and a float16 one per backend, each a single
	 * global; `GetHardwareVertexFormatter` picks the one the mesh batches use.
	 */
	class MeshFormatter
	{
	public:
		/**
		 * Address: 0x00944FF0 (FUN_00944FF0)
		 * Slot: 0 (`_purecall` in this table; each formatter's own table holds its
		 * scalar deleting destructor: 0x00945600, 0x00945620, 0x0094D8F0, 0x0094D910)
		 *
		 * What it does:
		 * Reinstalls the base vtable. The four formatter destructors are the same
		 * two instructions (0x009451D0, 0x00945390, 0x0094D500, 0x0094D780).
		 */
		virtual ~MeshFormatter() = 0;

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
		/**
		 * Address: 0x00945000 (FUN_00945000)
		 *
		 * What it does:
		 * Installs the base vtable and returns `this`.
		 */
		MeshFormatter() = default;
	};

	static_assert(sizeof(MeshFormatter) == 0x4, "MeshFormatter size must be 0x4");
	static_assert(std::is_polymorphic<MeshFormatter>::value, "MeshFormatter must remain polymorphic");

	/**
	 * Address: 0x008E7540 (FUN_008E7540)
	 *
	 * What it does:
	 * Forgets the chosen hardware vertex formatter, so the next
	 * `GetHardwareVertexFormatter` chooses again. `mesh_Rebatch` calls it after
	 * changing the instancing and float16 switches.
	 */
	void ResetHardwareVertexFormatter();

	/**
	 * Address: 0x008E7550 (FUN_008E7550)
	 *
	 * What it does:
	 * Returns the hardware vertex formatter for the active device's API,
	 * choosing it on first use: the first of that API's formatters (float16,
	 * then plain) whose `AllowMeshInstancing` passes, or null when none does.
	 * Any other API throws "unknown graphics API", even with a formatter chosen.
	 */
	[[nodiscard]] MeshFormatter* GetHardwareVertexFormatter();

	/**
	 * Address: 0x00940820 (FUN_00940820)
	 *
	 * What it does:
	 * True when the `mesh_Rebatch` instancing switch is on and the active
	 * device instances in hardware. Both D3D9 formatters require it, and the
	 * mesh batch factory only builds a hardware batch when it holds; the D3D10
	 * formatters read the device context alone.
	 */
	[[nodiscard]] bool MeshInstancingEnabled();

	/**
	 * Address: 0x009407F0 (FUN_009407F0)
	 *
	 * What it does:
	 * True when the `mesh_Rebatch` float16 switch is on and the active device
	 * takes float16 vertex data. The D3D9 float16 formatter requires it.
	 */
	[[nodiscard]] bool MeshFloat16Enabled();

	/**
	 * The two `mesh_Rebatch` switches (0x00F324B5 instancing, 0x00F324B4
	 * float16), both on by default. The console command writes them directly
	 * and then calls `ResetHardwareVertexFormatter`.
	 */
	extern std::uint8_t sMeshAllowInstancing;
	extern std::uint8_t sMeshAllowFloat16;
}

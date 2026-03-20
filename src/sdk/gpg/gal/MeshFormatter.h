#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace gpg::gal
{
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
		 * std::uintptr_t streamToken, std::int32_t layoutVariant
		 *
		 * What it does:
		 * Selects/activates a backend vertex-format token and returns the input
		 * token for chaining.
		 */
		[[nodiscard]] virtual std::uintptr_t SelectVertexFormatToken(
			std::uintptr_t streamToken,
			std::int32_t layoutVariant) = 0;

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
		 * std::int32_t streamClass, void* destinationVertex,
		 * const void* sourceVertex, std::int32_t writeVariant
		 *
		 * What it does:
		 * Packs one source vertex payload into the backend-specific runtime layout.
		 */
		virtual void WriteFormattedVertex(
			std::int32_t streamClass,
			void* destinationVertex,
			const void* sourceVertex,
			std::int32_t writeVariant) = 0;

	protected:
		MeshFormatter() = default;
		~MeshFormatter() = default;
	};

	static_assert(sizeof(MeshFormatter) == 0x4, "MeshFormatter size must be 0x4");
	static_assert(std::is_polymorphic<MeshFormatter>::value, "MeshFormatter must remain polymorphic");
}

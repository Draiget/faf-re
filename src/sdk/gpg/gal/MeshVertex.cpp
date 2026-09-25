#include "gpg/gal/MeshFormatter.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/backends/d3d10/Float16HardwareVertexFormatterD3D10.hpp"
#include "gpg/gal/backends/d3d10/HardwareVertexFormatterD3D10.hpp"
#include "gpg/gal/backends/d3d9/Float16HardwareVertexFormatterD3D9.hpp"
#include "gpg/gal/backends/d3d9/HardwareVertexFormatterD3D9.hpp"

namespace gpg::gal
{
	namespace
	{
		// One of each formatter. The binary constructs them at startup in this
		// order (dynamic initializers 0x00BE9B00, 0x00BE9B20, 0x00BE9B40,
		// 0x00BE9B60) and destroys them at exit (0x00C09610..0x00C09640); they
		// sit at 0x00F8E298, 0x00F8E294, 0x00F8E290 and 0x00F8E28C.
		HardwareVertexFormatterD3D9 sHardwareVertexFormatterD3D9;
		Float16HardwareVertexFormatterD3D9 sFloat16HardwareVertexFormatterD3D9;
		HardwareVertexFormatterD3D10 sHardwareVertexFormatterD3D10;
		Float16HardwareVertexFormatterD3D10 sFloat16HardwareVertexFormatterD3D10;

		// Each API's candidates, best first, null-terminated (0x00F2E3D8 for
		// D3D9, 0x00F2E3E4 for D3D10).
		MeshFormatter* const sHardwareVertexFormattersD3D9[] = {
			&sFloat16HardwareVertexFormatterD3D9,
			&sHardwareVertexFormatterD3D9,
			nullptr,
		};
		MeshFormatter* const sHardwareVertexFormattersD3D10[] = {
			&sFloat16HardwareVertexFormatterD3D10,
			&sHardwareVertexFormatterD3D10,
			nullptr,
		};

		// The formatter in use (0x00F8E288); null until the first request.
		MeshFormatter* sCurHardwareVertexFormatter = nullptr;

		/**
		 * The body both API branches of `GetHardwareVertexFormatter` share: keep
		 * the chosen formatter, or walk `candidates` storing each one as the
		 * current formatter until one allows instancing. When none does the
		 * walk ends on the table's null terminator, which is what is returned
		 * (and kept, so the next call walks again).
		 */
		[[nodiscard]] MeshFormatter* ChooseHardwareVertexFormatter(MeshFormatter* const* candidates)
		{
			if (sCurHardwareVertexFormatter != nullptr) {
				return sCurHardwareVertexFormatter;
			}

			for (sCurHardwareVertexFormatter = *candidates; sCurHardwareVertexFormatter != nullptr;
				 sCurHardwareVertexFormatter = *++candidates) {
				if (sCurHardwareVertexFormatter->AllowMeshInstancing()) {
					break;
				}
			}
			return sCurHardwareVertexFormatter;
		}
	}

	/**
	 * Address: 0x008E7540 (FUN_008E7540)
	 *
	 * What it does:
	 * Clears the chosen formatter.
	 */
	void ResetHardwareVertexFormatter()
	{
		sCurHardwareVertexFormatter = nullptr;
	}

	/**
	 * Address: 0x008E7550 (FUN_008E7550)
	 *
	 * What it does:
	 * Switches on the active device's API before looking at the chosen
	 * formatter, so an unknown API throws even after a formatter was chosen.
	 */
	MeshFormatter* GetHardwareVertexFormatter()
	{
		switch (Device::GetInstance()->GetDeviceContext()->mDeviceType) {
		case DeviceApi::Direct3D9:
			return ChooseHardwareVertexFormatter(sHardwareVertexFormattersD3D9);
		case DeviceApi::Direct3D10:
			return ChooseHardwareVertexFormatter(sHardwareVertexFormattersD3D10);
		default:
			throw Error(
				msvc8::string("c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\MeshVertex.cpp"),
				92,
				msvc8::string("unknown graphics API"));
		}
	}
}

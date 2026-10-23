#include "MeshFormatter.h"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"

namespace gpg::gal
{
	std::uint8_t sMeshAllowFloat16 = 1U;
	std::uint8_t sMeshAllowInstancing = 1U;

	/**
	 * Address: 0x00944FF0 (FUN_00944FF0)
	 *
	 * What it does:
	 * Reinstalls the base vtable; nothing else to tear down.
	 */
	MeshFormatter::~MeshFormatter() = default;

	/**
	 * Address: 0x00940820 (FUN_00940820)
	 *
	 * What it does:
	 * Reads the device context first, then tests the switch and the context's
	 * hardware-instancing flag (+0x11).
	 */
	bool MeshInstancingEnabled()
	{
		const DeviceContext* const context = Device::GetInstance()->GetDeviceContext();
		return sMeshAllowInstancing != 0U && context->mHWBasedInstancing;
	}

	/**
	 * Address: 0x009407F0 (FUN_009407F0)
	 *
	 * What it does:
	 * Reads the device context first, then tests the switch and the context's
	 * float16 flag (+0x12).
	 */
	bool MeshFloat16Enabled()
	{
		const DeviceContext* const context = Device::GetInstance()->GetDeviceContext();
		return sMeshAllowFloat16 != 0U && context->mSupportsFloat16;
	}
}

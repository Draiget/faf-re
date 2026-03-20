#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
	/**
	 * Minimal recovered runtime view used by app bootstrap/frame code.
	 *
	 * This is intentionally narrow and should be replaced with full `gpg::gal`
	 * type reconstruction as those classes are lifted.
	 */
	struct HeadAppView
	{
		std::uint8_t reserved00_03[0x04];
		void* windowHandle;              // +0x04
		std::uint8_t reserved08_0B[0x04];
		std::uint8_t windowed;           // +0x0C
	};

	static_assert(offsetof(HeadAppView, windowHandle) == 0x04, "HeadAppView::windowHandle offset must be 0x04");
	static_assert(offsetof(HeadAppView, windowed) == 0x0C, "HeadAppView::windowed offset must be 0x0C");

	class DeviceContextAppView
	{
	public:
		const HeadAppView& GetHead(unsigned idx) const;
		std::uint32_t GetHeadCount() const;
	};

	class DeviceAppView
	{
	public:
		static bool IsReady();
		static DeviceAppView* GetInstance();

		virtual DeviceContextAppView* GetDeviceContext();
	};
}


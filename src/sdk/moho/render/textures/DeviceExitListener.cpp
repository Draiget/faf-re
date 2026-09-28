#include "moho/render/textures/DeviceExitListener.h"

#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kDeviceEventTypeExit = 1u;

    /**
     * Address: 0x00447460 (FUN_00447460)
     *
     * What it does:
     * Initializes one recovered `Listener<SD3DDeviceEvent const &>` intrusive
     * link node into singleton (self-linked) state.
     */
    [[nodiscard]] DeviceExitListener::DeviceListenerLink* InitializeDeviceListenerLink(
      DeviceExitListener::DeviceListenerLink* const link
    )
    {
      if (link != nullptr) {
        link->ListResetLinks();
      }
      return link;
    }
  } // namespace

  /**
   * Address: 0x00BC43F0 (FUN_00BC43F0, dynamic initializer for
   * `sDeviceExitListener`)
   * Address: 0x00BEF460 (FUN_00BEF460, dynamic atexit destructor for
   * `sDeviceExitListener`)
   *
   * What it does:
   * The initializer only registers the destructor with `atexit` (the null
   * pointer is already in .bss); the destructor deletes a listener still
   * alive at exit without clearing the slot, which is `~scoped_ptr`.
   */
  boost::scoped_ptr<DeviceExitListener> sDeviceExitListener;

  /**
   * Address: 0x004472B0 (FUN_004472B0, Moho::DeviceExitListener::DeviceExitListener)
   *
   * What it does:
   * Initializes device-list and tracked-texture intrusive heads, then links this
   * listener into the D3D-device event listener ring.
   */
  DeviceExitListener::DeviceExitListener()
    : mDeviceLink()
    , mTrackedTextures()
  {
    (void)InitializeDeviceListenerLink(&mDeviceLink);

    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      mDeviceLink.ListLinkBefore(reinterpret_cast<DeviceListenerLink*>(static_cast<Broadcaster*>(device)));
    }
  }

  /**
   * Address: 0x0044E6E0 (FUN_0044E6E0, ??1DeviceExitListener@Moho@@QAE@@Z)
   *
   * What it does:
   * `delete listener` in full: `mTrackedTextures` unlinks (0x0044E6E0), the
   * vptr drops to the `Listener` base's, `mDeviceLink` unlinks (0x0044E6FF),
   * then `operator delete`. Every step is compiler-emitted, so the body is
   * empty and the callers `delete`.
   */
  DeviceExitListener::~DeviceExitListener() = default;

  /**
   * Address: 0x00447330 (FUN_00447330, Moho::DeviceExitListener::Receive)
   *
   * SD3DDeviceEvent const &
   *
   * What it does:
   * On device-exit events, drops cached texture-sheet handles for all tracked
   * batch textures and destroys the global listener instance.
   */
  void DeviceExitListener::Receive(const SD3DDeviceEvent& event)
  {
    if (event.mEventType != kDeviceEventTypeExit || !event.mShouldReleaseTextures) {
      return;
    }

    for (CD3DBatchTexture* const texture : mTrackedTextures.owners()) {
      texture->ResetTextureSheet();
    }

    sDeviceExitListener.reset();
  }
} // namespace moho

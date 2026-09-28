#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/scoped_ptr.h"
#include "gpg/core/containers/DList.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class CD3DBatchTexture;

  struct SD3DDeviceEvent
  {
    std::uint32_t mEventType;       // +0x00
    bool mShouldReleaseTextures;    // +0x04
    std::uint8_t mPad05[0x03];      // +0x05
  };

  static_assert(sizeof(SD3DDeviceEvent) == 0x08, "SD3DDeviceEvent size must be 0x08");

  /**
   * VFTABLE: 0x00E02ABC
   * COL: 0x00E5FA0C
   */
  class DeviceExitListener
  {
  public:
    using DeviceListenerLink = TDatListItem<DeviceExitListener, void>;

    /**
     * Address: 0x004472B0 (FUN_004472B0, Moho::DeviceExitListener::DeviceExitListener)
     *
     * What it does:
     * Initializes device-list and tracked-texture intrusive heads, then links this
     * listener into the D3D-device event listener ring.
     */
    DeviceExitListener();

    /**
     * Address: 0x0044E6E0 (FUN_0044E6E0, ??1DeviceExitListener@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks tracked texture/device-list nodes and releases the listener heap
     * allocation through explicit destructor-call ownership paths.
     */
    ~DeviceExitListener();

    /**
     * Address: 0x00447330 (FUN_00447330, Moho::DeviceExitListener::Receive)
     *
     * SD3DDeviceEvent const &
     *
     * What it does:
     * On device-exit events, drops cached texture-sheet handles for all tracked
     * batch textures and destroys the global listener instance.
     */
    virtual void Receive(const SD3DDeviceEvent& event);

  public:
    DeviceListenerLink mDeviceLink;                  // +0x04
    gpg::DList<CD3DBatchTexture> mTrackedTextures; // +0x0C
  };

  static_assert(offsetof(DeviceExitListener, mDeviceLink) == 0x04, "DeviceExitListener::mDeviceLink offset must be 0x04");
  static_assert(
    offsetof(DeviceExitListener, mTrackedTextures) == 0x0C,
    "DeviceExitListener::mTrackedTextures offset must be 0x0C"
  );
  static_assert(sizeof(DeviceExitListener) == 0x14, "DeviceExitListener size must be 0x14");

  /**
   * The process-wide listener (0x010A7AC0), created by the first batch
   * texture that gets a device sheet and dropped when the device exits.
   * Every write is `scoped_ptr::reset`: the new pointer is stored before the
   * old listener is deleted (0x00447404, 0x00447399).
   */
  extern boost::scoped_ptr<DeviceExitListener> sDeviceExitListener;
} // namespace moho

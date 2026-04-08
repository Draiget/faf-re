#pragma once

#include <cstddef>
#include <cstdint>

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
    using BatchTextureLink = TDatListItem<CD3DBatchTexture, void>;

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
    DeviceListenerLink mDeviceLink;    // +0x04
    BatchTextureLink mTrackedTextures; // +0x0C
  };

  static_assert(offsetof(DeviceExitListener, mDeviceLink) == 0x04, "DeviceExitListener::mDeviceLink offset must be 0x04");
  static_assert(
    offsetof(DeviceExitListener, mTrackedTextures) == 0x0C,
    "DeviceExitListener::mTrackedTextures offset must be 0x0C"
  );
  static_assert(sizeof(DeviceExitListener) == 0x14, "DeviceExitListener size must be 0x14");

  /**
   * Address: 0x00BC43F0 (FUN_00BC43F0, register_sDeviceExitListener)
   *
   * What it does:
   * Registers one process-exit cleanup lane that releases the global
   * `sDeviceExitListener` instance when still present.
   */
  void register_sDeviceExitListener();

  extern DeviceExitListener* sDeviceExitListener;
} // namespace moho

#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/scoped_ptr.h"
#include "gpg/core/containers/DList.h"
#include "moho/misc/Listener.h"

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
   *
   * RTTI: `Listener<SD3DDeviceEvent const&>` at +0x00 (its node at +0x04).
   */
  class DeviceExitListener : public Listener<const SD3DDeviceEvent&>
  {
  public:
    /**
     * Address: 0x004472B0 (FUN_004472B0, Moho::DeviceExitListener::DeviceExitListener)
     *
     * What it does:
     * Starts with an empty texture list and subscribes to the D3D device's
     * events. The device is not null-checked (0x004472EF).
     */
    DeviceExitListener();

    /**
     * Address: 0x0044E6E0 (FUN_0044E6E0, ??1DeviceExitListener@Moho@@QAE@@Z)
     *
     * What it does:
     * `delete listener` in full: `mTrackedTextures` unlinks (0x0044E6E0), the
     * vptr drops to the `Listener` base's, the listener node unlinks
     * (0x0044E6FF), then `operator delete`. Every step is compiler-emitted.
     */
    ~DeviceExitListener();

    /**
     * Address: 0x00447330 (FUN_00447330, Moho::DeviceExitListener::Receive)
     * Slot: 0
     *
     * What it does:
     * On a device exit that releases textures, drops every tracked batch
     * texture's sheet and destroys the process-wide listener (itself).
     */
    void OnEvent(const SD3DDeviceEvent& event) override;

  public:
    gpg::DList<CD3DBatchTexture> mTrackedTextures; // +0x0C
  };

  static_assert(sizeof(DeviceExitListener) == 0x14, "DeviceExitListener size must be 0x14");

  /**
   * The process-wide listener (0x010A7AC0), created by the first batch
   * texture that gets a device sheet and dropped when the device exits.
   * Every write is `scoped_ptr::reset`: the new pointer is stored before the
   * old listener is deleted (0x00447404, 0x00447399).
   */
  extern boost::scoped_ptr<DeviceExitListener> sDeviceExitListener;
} // namespace moho

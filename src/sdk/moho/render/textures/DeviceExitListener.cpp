#include "moho/render/textures/DeviceExitListener.h"

#include <cstdlib>

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

    /**
     * Address: 0x00447470 (FUN_00447470)
     *
     * What it does:
     * Unlinks one recovered listener node from its current ring and resets it
     * to singleton state.
     */
    [[nodiscard]] DeviceExitListener::DeviceListenerLink* UnlinkAndResetDeviceListenerLink(
      DeviceExitListener::DeviceListenerLink* const link
    )
    {
      if (link != nullptr) {
        link->ListUnlink();
      }
      return link;
    }

    void DestroyDeviceExitListenerAtProcessExit()
    {
      DeviceExitListener* const previousListener = moho::sDeviceExitListener;
      moho::sDeviceExitListener = nullptr;
      if (previousListener != nullptr) {
        previousListener->~DeviceExitListener();
      }
    }

  } // namespace

  DeviceExitListener* sDeviceExitListener = nullptr;

  /**
   * Address: 0x00BC43F0 (FUN_00BC43F0, register_sDeviceExitListener)
   */
  void register_sDeviceExitListener()
  {
    (void)std::atexit(&DestroyDeviceExitListenerAtProcessExit);
  }

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
    mTrackedTextures.ListResetLinks();

    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      mDeviceLink.ListLinkBefore(reinterpret_cast<DeviceListenerLink*>(static_cast<Broadcaster*>(device)));
    }
  }

  /**
   * Address: 0x0044E6E0 (FUN_0044E6E0, ??1DeviceExitListener@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks tracked texture/device-list nodes and releases the listener heap
   * allocation through explicit destructor-call ownership paths.
   */
  DeviceExitListener::~DeviceExitListener()
  {
    mTrackedTextures.ListUnlink();
    (void)UnlinkAndResetDeviceListenerLink(&mDeviceLink);
    ::operator delete(static_cast<void*>(this));
  }

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

    BatchTextureLink* cursor = mTrackedTextures.mNext;
    while (cursor != &mTrackedTextures) {
      BatchTextureLink* const next = cursor->mNext;
      if (CD3DBatchTexture* const texture =
            TDatList<CD3DBatchTexture, void>::template owner_from_member<
              CD3DBatchTexture,
              CD3DBatchTexture::BatchTextureLink,
              &CD3DBatchTexture::mListLink>(cursor);
          texture != nullptr) {
        texture->ResetTextureSheet();
      }
      cursor = next;
    }

    DeviceExitListener* const previousListener = sDeviceExitListener;
    sDeviceExitListener = nullptr;
    if (previousListener != nullptr) {
      previousListener->~DeviceExitListener();
    }
  }
} // namespace moho

namespace
{
  struct DeviceExitListenerBootstrap
  {
    DeviceExitListenerBootstrap()
    {
      moho::register_sDeviceExitListener();
    }
  };

  DeviceExitListenerBootstrap gDeviceExitListenerBootstrap;
} // namespace

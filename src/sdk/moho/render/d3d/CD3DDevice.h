#pragma once

#include <cstdint>

namespace gpg::gal
{
  class DeviceD3D9;
} // namespace gpg::gal

namespace moho
{
  class ID3DDeviceResources;
  struct WRenViewport;

  /**
   * VFTABLE: 0x00E02214
   * COL:     0x00E5E54C
   */
  class CD3DDevice
  {
  public:
    /**
     * Address: 0x0042DBE0 (FUN_0042DBE0)
     *
     * What it does:
     * Owns the deleting-destructor entrypoint for the D3D device wrapper.
     */
    virtual ~CD3DDevice();

    /**
     * Address: 0x0042DBF0
     * Slot: 1
     * Demangled: Moho::CD3DDevice::GetDeviceD3D9
     */
    virtual gpg::gal::DeviceD3D9* GetDeviceD3D9() = 0;

    /**
     * Address: 0x0042DC10
     * Slot: 2
     * Demangled: Moho::CD3DDevice::SetRenViewport
     */
    virtual void SetRenViewport(WRenViewport* viewport) = 0;

    /**
     * Address: 0x0042E9D0
     * Slot: 3
     * Demangled: Moho::CD3DDevice::GetViewport
     *
     * What it does:
     * Returns the active render viewport object.
     */
    virtual void GetViewport() = 0;

    /**
     * Address: 0x0042E9E0
     * Slot: 4
     * Demangled: Moho::CD3DDevice::Refresh
     *
     * What it does:
     * Refreshes device-facing state after viewport/effect changes.
     */
    virtual void Refresh() = 0;

#define CD3DDEVICE_RESERVED_VFUNC(slot) virtual void VFunc##slot() = 0
    CD3DDEVICE_RESERVED_VFUNC(5);
    CD3DDEVICE_RESERVED_VFUNC(6);
    CD3DDEVICE_RESERVED_VFUNC(7);
    CD3DDEVICE_RESERVED_VFUNC(8);
    CD3DDEVICE_RESERVED_VFUNC(9);
    CD3DDEVICE_RESERVED_VFUNC(10);
    CD3DDEVICE_RESERVED_VFUNC(11);
    CD3DDEVICE_RESERVED_VFUNC(12);
#undef CD3DDEVICE_RESERVED_VFUNC

    /**
     * Address: 0x0042EE70
     * Slot: 13
     * Demangled: Moho::CD3DDevice::GetResources
     */
    virtual ID3DDeviceResources* GetResources() = 0;

#define CD3DDEVICE_RESERVED_VFUNC(slot) virtual void VFunc##slot() = 0
    CD3DDEVICE_RESERVED_VFUNC(14);
    CD3DDEVICE_RESERVED_VFUNC(15);
    CD3DDEVICE_RESERVED_VFUNC(16);
    CD3DDEVICE_RESERVED_VFUNC(17);
    CD3DDEVICE_RESERVED_VFUNC(18);

    /**
     * Address: 0x0042FD40
     * Slot: 19
     * Demangled: Moho::CD3DDevice::SetCurEffect
     *
     * What it does:
     * Selects one active effect object for subsequent draw dispatch.
     */
    virtual void SetCurEffect() = 0;

    /**
     * Address: 0x0042FD10
     * Slot: 20
     * Demangled: Moho::CD3DDevice::SelectFxFile
     *
     * What it does:
     * Selects one effect file by symbolic name.
     */
    virtual void SelectFxFile(const char* fxFileName) = 0;

    /**
     * Address: 0x0042FD60
     * Slot: 21
     * Demangled: Moho::CD3DDevice::SelectTechnique
     *
     * What it does:
     * Selects one technique from the active effect.
     */
    virtual void SelectTechnique(const char* techniqueName) = 0;

    CD3DDEVICE_RESERVED_VFUNC(22);
    CD3DDEVICE_RESERVED_VFUNC(23);
    CD3DDEVICE_RESERVED_VFUNC(24);
    CD3DDEVICE_RESERVED_VFUNC(25);
    CD3DDEVICE_RESERVED_VFUNC(26);
    CD3DDEVICE_RESERVED_VFUNC(27);
    CD3DDEVICE_RESERVED_VFUNC(28);
    CD3DDEVICE_RESERVED_VFUNC(29);
    CD3DDEVICE_RESERVED_VFUNC(30);
    CD3DDEVICE_RESERVED_VFUNC(31);
    CD3DDEVICE_RESERVED_VFUNC(32);
    CD3DDEVICE_RESERVED_VFUNC(33);
    CD3DDEVICE_RESERVED_VFUNC(34);
    CD3DDEVICE_RESERVED_VFUNC(35);
    CD3DDEVICE_RESERVED_VFUNC(36);
    CD3DDEVICE_RESERVED_VFUNC(37);
    CD3DDEVICE_RESERVED_VFUNC(38);
    CD3DDEVICE_RESERVED_VFUNC(39);
    CD3DDEVICE_RESERVED_VFUNC(40);
    CD3DDEVICE_RESERVED_VFUNC(41);
    CD3DDEVICE_RESERVED_VFUNC(42);
    CD3DDEVICE_RESERVED_VFUNC(43);
    CD3DDEVICE_RESERVED_VFUNC(44);
    CD3DDEVICE_RESERVED_VFUNC(45);
    CD3DDEVICE_RESERVED_VFUNC(46);
    CD3DDEVICE_RESERVED_VFUNC(47);
    CD3DDEVICE_RESERVED_VFUNC(48);
    CD3DDEVICE_RESERVED_VFUNC(49);
    CD3DDEVICE_RESERVED_VFUNC(50);
#undef CD3DDEVICE_RESERVED_VFUNC

    /**
     * Address: 0x004300D0
     * Slot: 51
     * Demangled: Moho::CD3DDevice::Clear2
     */
    virtual void Clear2(bool clear) = 0;

    /**
     * Address: 0x004300E0
     * Slot: 52
     * Demangled: Moho::CD3DDevice::Clear
     */
    virtual void Clear() = 0;
  };

  /**
   * Address: 0x00430590 (D3D_GetDevice)
   *
   * What it does:
   * Returns the global D3D device owner used by startup/render paths.
   */
  CD3DDevice* D3D_GetDevice();

  /**
   * Address: 0x007FA2C0 (FUN_007FA2C0, Moho::REN_Frame)
   *
   * int gameTick, float simDeltaSeconds, float frameSeconds
   *
   * What it does:
   * Updates render timing globals and publishes `Frame_Time` / `Frame_FPS`
   * stat counters.
   */
  void REN_Frame(int gameTick, float simDeltaSeconds, float frameSeconds);
} // namespace moho

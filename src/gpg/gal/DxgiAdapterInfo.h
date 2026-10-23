#pragma once

// FAF addition, not in the shipped binary.
//
// Fills the adapter and video-memory part of `DeviceRuntimeInfo` (`ren_Info`)
// through DXGI, for every backend that runs on a DXGI adapter: Direct3D 11 and
// 12 pass their own adapter, Direct3D 9 looks its adapter up by PCI ids.

#include <cstdint>

struct IDXGIAdapter;

namespace gpg::gal
{
  struct DeviceRuntimeInfo;

  /**
   * Description, PCI ids, driver version, dedicated and shared memory, and
   * (DXGI 1.4, Windows 10) the local and non-local budget and usage of
   * `adapter`. Returns false when `adapter` is null.
   */
  bool FillDxgiAdapterInfo(IDXGIAdapter* adapter, DeviceRuntimeInfo& out);

  /**
   * The same for the first DXGI adapter with these PCI ids, for a backend that
   * does not create its adapter through DXGI (Direct3D 9). Only the memory
   * fields that are still zero and the driver version when empty are filled,
   * so the caller's own adapter identifier wins. False when none matches.
   */
  bool FillDxgiAdapterMemoryByPciId(std::uint32_t vendorId, std::uint32_t deviceId, DeviceRuntimeInfo& out);
} // namespace gpg::gal

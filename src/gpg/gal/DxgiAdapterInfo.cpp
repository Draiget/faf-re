// FAF addition, not in the shipped binary (see DxgiAdapterInfo.h).

#include "gpg/gal/DxgiAdapterInfo.h"

#include <cstdio>
#include <string>

#include <dxgi1_4.h>
#include <wrl/client.h>

#include "gpg/gal/Device.hpp"

namespace gpg::gal
{
  namespace
  {
    [[nodiscard]] std::string Utf8(const wchar_t* const text)
    {
      const int bytes = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
      if (bytes <= 1) {
        return std::string();
      }
      std::string result(static_cast<std::size_t>(bytes - 1), '\0');
      (void)::WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), bytes, nullptr, nullptr);
      return result;
    }

    /** "a.b.c.d" from the 64-bit user-mode driver version DXGI and D3D9 both report. */
    [[nodiscard]] std::string DriverVersionText(const std::uint64_t version)
    {
      char text[48] = {};
      std::snprintf(
        text, sizeof(text), "%u.%u.%u.%u", static_cast<unsigned>((version >> 48) & 0xFFFFU),
        static_cast<unsigned>((version >> 32) & 0xFFFFU), static_cast<unsigned>((version >> 16) & 0xFFFFU),
        static_cast<unsigned>(version & 0xFFFFU)
      );
      return text;
    }

    void FillBudget(IDXGIAdapter* const adapter, DeviceRuntimeInfo& out)
    {
      Microsoft::WRL::ComPtr<IDXGIAdapter3> adapter3;
      if (FAILED(adapter->QueryInterface(IID_PPV_ARGS(adapter3.GetAddressOf())))) {
        return;
      }
      DXGI_QUERY_VIDEO_MEMORY_INFO local{};
      if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0U, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &local))) {
        out.localBudget = local.Budget;
        out.localUsage = local.CurrentUsage;
      }
      DXGI_QUERY_VIDEO_MEMORY_INFO nonLocal{};
      if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0U, DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, &nonLocal))) {
        out.nonLocalBudget = nonLocal.Budget;
        out.nonLocalUsage = nonLocal.CurrentUsage;
      }
    }

    [[nodiscard]] std::string DriverVersionOf(IDXGIAdapter* const adapter)
    {
      LARGE_INTEGER version{};
      if (SUCCEEDED(adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice), &version))) {
        return DriverVersionText(static_cast<std::uint64_t>(version.QuadPart));
      }
      return std::string();
    }
  } // namespace

  bool FillDxgiAdapterInfo(IDXGIAdapter* const adapter, DeviceRuntimeInfo& out)
  {
    if (adapter == nullptr) {
      return false;
    }
    DXGI_ADAPTER_DESC desc{};
    if (SUCCEEDED(adapter->GetDesc(&desc))) {
      out.adapter = Utf8(desc.Description).c_str();
      out.vendorId = desc.VendorId;
      out.deviceId = desc.DeviceId;
      out.dedicatedVideoMemory = desc.DedicatedVideoMemory;
      out.sharedSystemMemory = desc.SharedSystemMemory;
    }
    out.driverVersion = DriverVersionOf(adapter).c_str();
    FillBudget(adapter, out);
    return true;
  }

  bool FillDxgiAdapterMemoryByPciId(const std::uint32_t vendorId, const std::uint32_t deviceId, DeviceRuntimeInfo& out)
  {
    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    if (FAILED(::CreateDXGIFactory1(IID_PPV_ARGS(factory.GetAddressOf())))) {
      return false;
    }
    Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
    for (UINT index = 0U; factory->EnumAdapters1(index, adapter.ReleaseAndGetAddressOf()) != DXGI_ERROR_NOT_FOUND; ++index) {
      DXGI_ADAPTER_DESC1 desc{};
      if (FAILED(adapter->GetDesc1(&desc)) || desc.VendorId != vendorId || desc.DeviceId != deviceId) {
        continue;
      }
      if (out.dedicatedVideoMemory == 0U) {
        out.dedicatedVideoMemory = desc.DedicatedVideoMemory;
      }
      if (out.sharedSystemMemory == 0U) {
        out.sharedSystemMemory = desc.SharedSystemMemory;
      }
      if (out.driverVersion.empty()) {
        out.driverVersion = DriverVersionOf(adapter.Get()).c_str();
      }
      FillBudget(adapter.Get(), out);
      return true;
    }
    return false;
  }
} // namespace gpg::gal

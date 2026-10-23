#pragma once

// FAF addition, not in the shipped binary.
//
// The DXGI side of a modern gal backend: the factory, the adapters and their
// outputs, and the display modes those outputs list. Nothing here touches a
// Direct3D device, so the Direct3D 11 backend uses it today and a Direct3D 12
// backend can use it unchanged (D3D12 creates its device on one of these
// adapters and its swap chains on the same factory, see DxgiSwapChain.h).

#include <cstdint>
#include <string>
#include <vector>

#include <dxgi1_6.h>
#include <wrl/client.h>

namespace gpg::gal::dxgi
{
  /** One output (monitor) of an adapter and the modes it offers. */
  struct OutputInfo
  {
    Microsoft::WRL::ComPtr<IDXGIOutput> output;
    DXGI_OUTPUT_DESC desc{};
    std::vector<DXGI_MODE_DESC> modes; // every mode listed for `Factory::ModeFormat()`
  };

  /** One adapter, as `IDXGIFactory1::EnumAdapters1` lists it. */
  struct AdapterInfo
  {
    Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
    DXGI_ADAPTER_DESC1 desc{};
    std::vector<OutputInfo> outputs;

    [[nodiscard]] bool IsSoftware() const noexcept { return (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0U; }
    /** The adapter's description as UTF-8 for the log. */
    [[nodiscard]] std::string Name() const;
    /** Refresh rate in whole hertz for one mode; 0 when the mode leaves it open. */
    [[nodiscard]] static std::uint32_t RefreshHz(const DXGI_MODE_DESC& mode) noexcept;
  };

  /**
   * Owns the DXGI factory. `Create` asks for the newest interface the system
   * has and records what it can do: flip-model swap chains (DXGI 1.2,
   * Windows 8), FLIP_DISCARD (DXGI 1.4, Windows 10) and tearing presents
   * (DXGI 1.5), which a swap chain needs to present unsynchronised in a
   * window.
   */
  class Factory
  {
  public:
    Factory() = default;
    Factory(const Factory&) = delete;
    Factory& operator=(const Factory&) = delete;

    /** Creates the factory. Returns the failing HRESULT, or S_OK. */
    HRESULT Create();

    /**
     * Lists every hardware adapter, its outputs and their `modeFormat` modes.
     * Software adapters (WARP, the Basic Render Driver) are left out unless
     * nothing else exists.
     */
    void EnumerateAdapters(DXGI_FORMAT modeFormat);

    void Release() noexcept;

    [[nodiscard]] IDXGIFactory1* Get() const noexcept { return mFactory.Get(); }
    [[nodiscard]] IDXGIFactory2* Get2() const noexcept { return mFactory2.Get(); }
    [[nodiscard]] const std::vector<AdapterInfo>& Adapters() const noexcept { return mAdapters; }
    [[nodiscard]] DXGI_FORMAT ModeFormat() const noexcept { return mModeFormat; }

    [[nodiscard]] bool SupportsFlipSequential() const noexcept { return mFactory2 != nullptr; }
    [[nodiscard]] bool SupportsFlipDiscard() const noexcept { return mSupportsFlipDiscard; }
    [[nodiscard]] bool SupportsTearing() const noexcept { return mSupportsTearing; }

  private:
    Microsoft::WRL::ComPtr<IDXGIFactory1> mFactory;
    Microsoft::WRL::ComPtr<IDXGIFactory2> mFactory2;
    std::vector<AdapterInfo> mAdapters;
    DXGI_FORMAT mModeFormat = DXGI_FORMAT_R8G8B8A8_UNORM;
    bool mSupportsFlipDiscard = false;
    bool mSupportsTearing = false;
  };
} // namespace gpg::gal::dxgi

#include "DxgiFactory.h"

#include <Windows.h>

namespace gpg::gal::dxgi
{
  using Microsoft::WRL::ComPtr;

  std::string AdapterInfo::Name() const
  {
    char utf8[256]{};
    const int written =
      ::WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, utf8, static_cast<int>(sizeof(utf8)), nullptr, nullptr);
    return (written > 0) ? std::string(utf8) : std::string("unknown adapter");
  }

  std::uint32_t AdapterInfo::RefreshHz(const DXGI_MODE_DESC& mode) noexcept
  {
    const DXGI_RATIONAL& rate = mode.RefreshRate;
    if (rate.Denominator == 0U) {
      return rate.Numerator;
    }
    // Round, so 59.94 Hz lists as 60 the way D3D9 reports it.
    return (rate.Numerator + rate.Denominator / 2U) / rate.Denominator;
  }

  HRESULT Factory::Create()
  {
    Release();

    HRESULT result = ::CreateDXGIFactory1(IID_PPV_ARGS(&mFactory));
    if (FAILED(result)) {
      return result;
    }

    // DXGI 1.2 brought CreateSwapChainForHwnd and the flip model.
    static_cast<void>(mFactory.As(&mFactory2));

    // DXGI 1.4 (Windows 10) brought FLIP_DISCARD; IDXGIFactory4 is the marker.
    ComPtr<IDXGIFactory4> factory4;
    mSupportsFlipDiscard = SUCCEEDED(mFactory.As(&factory4));

    ComPtr<IDXGIFactory5> factory5;
    if (SUCCEEDED(mFactory.As(&factory5))) {
      BOOL allowTearing = FALSE;
      if (SUCCEEDED(factory5->CheckFeatureSupport(DXGI_FEATURE_PRESENT_ALLOW_TEARING, &allowTearing, sizeof(allowTearing)))) {
        mSupportsTearing = (allowTearing != FALSE);
      }
    }

    return S_OK;
  }

  void Factory::EnumerateAdapters(const DXGI_FORMAT modeFormat)
  {
    mAdapters.clear();
    mModeFormat = modeFormat;
    if (mFactory == nullptr) {
      return;
    }

    std::vector<AdapterInfo> software;
    for (UINT adapterIndex = 0U;; ++adapterIndex) {
      AdapterInfo info{};
      if (mFactory->EnumAdapters1(adapterIndex, &info.adapter) == DXGI_ERROR_NOT_FOUND) {
        break;
      }
      static_cast<void>(info.adapter->GetDesc1(&info.desc));

      for (UINT outputIndex = 0U;; ++outputIndex) {
        OutputInfo output{};
        if (info.adapter->EnumOutputs(outputIndex, &output.output) == DXGI_ERROR_NOT_FOUND) {
          break;
        }
        static_cast<void>(output.output->GetDesc(&output.desc));

        UINT modeCount = 0U;
        if (SUCCEEDED(output.output->GetDisplayModeList(modeFormat, 0U, &modeCount, nullptr)) && modeCount != 0U) {
          output.modes.resize(modeCount);
          if (FAILED(output.output->GetDisplayModeList(modeFormat, 0U, &modeCount, output.modes.data()))) {
            modeCount = 0U;
          }
          output.modes.resize(modeCount);
        }
        info.outputs.push_back(std::move(output));
      }

      if (info.IsSoftware()) {
        software.push_back(std::move(info));
      } else {
        mAdapters.push_back(std::move(info));
      }
    }

    if (mAdapters.empty()) {
      mAdapters = std::move(software);
    }
  }

  void Factory::Release() noexcept
  {
    mAdapters.clear();
    mFactory2.Reset();
    mFactory.Reset();
    mSupportsFlipDiscard = false;
    mSupportsTearing = false;
  }
} // namespace gpg::gal::dxgi

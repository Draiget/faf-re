#include "DxgiSwapChain.h"

#include "DxgiFactory.h"

namespace gpg::gal::dxgi
{
  using Microsoft::WRL::ComPtr;

  const char* SwapModelName(const SwapModel model) noexcept
  {
    switch (model) {
    case SwapModel::FlipDiscard:
      return "flip-discard";
    case SwapModel::FlipSequential:
      return "flip-sequential";
    case SwapModel::BltDiscard:
    default:
      return "discard (blt)";
    }
  }

  SwapChain::~SwapChain()
  {
    Release();
  }

  HRESULT SwapChain::Create(const Factory& factory, IUnknown* const device, const SwapChainDesc& desc)
  {
    Release();
    mDesc = desc;

    HRESULT result = E_FAIL;
    IDXGIFactory2* const factory2 = factory.Get2();

    // Flip model: no MSAA back buffer, at least two buffers. A full-screen
    // flip swap chain is created windowed and switched afterwards, which is
    // what DXGI recommends for both models.
    if (desc.allowFlipModel && factory2 != nullptr) {
      const SwapModel candidates[] = {SwapModel::FlipDiscard, SwapModel::FlipSequential};
      for (const SwapModel model : candidates) {
        if (model == SwapModel::FlipDiscard && !factory.SupportsFlipDiscard()) {
          continue;
        }

        const bool tearing = factory.SupportsTearing() && !desc.fullscreen;

        DXGI_SWAP_CHAIN_DESC1 chainDesc{};
        chainDesc.Width = desc.width;
        chainDesc.Height = desc.height;
        chainDesc.Format = desc.format;
        chainDesc.Stereo = FALSE;
        chainDesc.SampleDesc.Count = 1U;
        chainDesc.SampleDesc.Quality = 0U;
        chainDesc.BufferUsage = desc.usage;
        chainDesc.BufferCount = (desc.bufferCount < 2U) ? 2U : desc.bufferCount;
        chainDesc.Scaling = DXGI_SCALING_STRETCH;
        chainDesc.SwapEffect =
          (model == SwapModel::FlipDiscard) ? DXGI_SWAP_EFFECT_FLIP_DISCARD : DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
        chainDesc.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        chainDesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH |
          (tearing ? static_cast<UINT>(DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING) : 0U);

        DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreenDesc{};
        fullscreenDesc.RefreshRate.Numerator = desc.refreshHz;
        fullscreenDesc.RefreshRate.Denominator = (desc.refreshHz != 0U) ? 1U : 0U;
        fullscreenDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
        fullscreenDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
        fullscreenDesc.Windowed = TRUE;

        ComPtr<IDXGISwapChain1> chain1;
        result = factory2->CreateSwapChainForHwnd(device, desc.window, &chainDesc, &fullscreenDesc, nullptr, &chain1);
        if (SUCCEEDED(result)) {
          mSwapChain = chain1;
          mModel = model;
          mAllowTearing = tearing;
          mFlags = chainDesc.Flags;
          break;
        }
      }
    }

    if (mSwapChain == nullptr) {
      DXGI_SWAP_CHAIN_DESC chainDesc{};
      chainDesc.BufferDesc.Width = desc.width;
      chainDesc.BufferDesc.Height = desc.height;
      chainDesc.BufferDesc.Format = desc.format;
      chainDesc.BufferDesc.RefreshRate.Numerator = desc.fullscreen ? desc.refreshHz : 0U;
      chainDesc.BufferDesc.RefreshRate.Denominator = 1U;
      chainDesc.SampleDesc.Count = 1U;
      chainDesc.BufferUsage = desc.usage;
      chainDesc.BufferCount = 2U;
      chainDesc.OutputWindow = desc.window;
      chainDesc.Windowed = TRUE;
      chainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
      chainDesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

      result = factory.Get()->CreateSwapChain(device, &chainDesc, &mSwapChain);
      if (FAILED(result)) {
        return result;
      }
      mModel = SwapModel::BltDiscard;
      mAllowTearing = false;
      mFlags = chainDesc.Flags;
    }

    // The engine handles Alt+Enter itself (and D3D9 never saw it).
    static_cast<void>(factory.Get()->MakeWindowAssociation(desc.window, DXGI_MWA_NO_ALT_ENTER));

    if (desc.fullscreen) {
      // Failing to go exclusive (another app holds the output, a remote
      // session) leaves a working windowed swap chain.
      static_cast<void>(mSwapChain->SetFullscreenState(TRUE, nullptr));
    }

    return S_OK;
  }

  HRESULT SwapChain::Present(const bool vsync)
  {
    if (mSwapChain == nullptr) {
      return E_POINTER;
    }

    UINT flags = 0U;
    if (!vsync && mAllowTearing) {
      BOOL fullscreen = FALSE;
      static_cast<void>(mSwapChain->GetFullscreenState(&fullscreen, nullptr));
      if (fullscreen == FALSE) {
        flags |= DXGI_PRESENT_ALLOW_TEARING;
      }
    }
    return mSwapChain->Present(vsync ? 1U : 0U, flags);
  }

  HRESULT SwapChain::Resize(const std::uint32_t width, const std::uint32_t height)
  {
    if (mSwapChain == nullptr) {
      return E_POINTER;
    }
    mDesc.width = width;
    mDesc.height = height;
    return mSwapChain->ResizeBuffers(0U, width, height, DXGI_FORMAT_UNKNOWN, mFlags);
  }

  std::uint32_t SwapChain::CurrentBufferIndex() const
  {
    Microsoft::WRL::ComPtr<IDXGISwapChain3> chain3;
    if (mSwapChain != nullptr && SUCCEEDED(mSwapChain.As(&chain3))) {
      return chain3->GetCurrentBackBufferIndex();
    }
    return 0U;
  }

  std::uint32_t SwapChain::BufferCount() const
  {
    DXGI_SWAP_CHAIN_DESC desc{};
    if (mSwapChain != nullptr && SUCCEEDED(mSwapChain->GetDesc(&desc))) {
      return desc.BufferCount;
    }
    return 0U;
  }

  void SwapChain::Release() noexcept
  {
    if (mSwapChain != nullptr) {
      // A swap chain must leave exclusive full screen before it is released.
      BOOL fullscreen = FALSE;
      if (SUCCEEDED(mSwapChain->GetFullscreenState(&fullscreen, nullptr)) && fullscreen != FALSE) {
        static_cast<void>(mSwapChain->SetFullscreenState(FALSE, nullptr));
      }
    }
    mSwapChain.Reset();
    mModel = SwapModel::BltDiscard;
    mAllowTearing = false;
    mFlags = 0U;
  }
} // namespace gpg::gal::dxgi

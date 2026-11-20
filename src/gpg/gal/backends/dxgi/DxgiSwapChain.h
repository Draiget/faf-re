#pragma once

// FAF addition, not in the shipped binary.
//
// One window's swap chain, shared between the modern gal backends. The device
// argument is what DXGI wants for the API: the ID3D11Device for Direct3D 11,
// the direct command queue for Direct3D 12. The swap-chain model, the present
// flags and the resize rules are the same for both.

#include <cstdint>
#include <functional>

#include <dxgi1_6.h>
#include <wrl/client.h>

#include "DxgiSwapChainPolicy.h"

namespace gpg::gal
{
  class Head;
}

namespace gpg::gal::dxgi
{
  class Factory;

  /** How the swap chain presents, best first. */
  enum class SwapModel : std::uint8_t
  {
    FlipDiscard,    // DXGI 1.4, Windows 10
    FlipSequential, // DXGI 1.2, Windows 8
    BltDiscard,     // the legacy model the D3D10 backend used
  };

  [[nodiscard]] const char* SwapModelName(SwapModel model) noexcept;

  struct SwapChainDesc
  {
    HWND window = nullptr;
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    DXGI_FORMAT format = DXGI_FORMAT_R8G8B8A8_UNORM;
    bool fullscreen = false;
    std::uint32_t refreshHz = 0; // full-screen only; 0 lets DXGI pick
    DXGI_USAGE usage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    std::uint32_t bufferCount = 2;
    bool allowFlipModel = true; // false forces BltDiscard
  };

  /**
   * The swap chain one head asks for. `Head::mWindowed` is a full-screen flag
   * (the D3D10 backend writes DXGI's Windowed as its negation); a size of 0
   * stands for the window's client area.
   */
  [[nodiscard]] SwapChainDesc DescribeHeadChain(const Head& head, std::uint32_t bufferCount, bool allowFlipModel);

  /** True while the window is minimised (no client area to resize to). */
  [[nodiscard]] bool IsWindowMinimized(HWND window) noexcept;

  /** The result of one Present: the HRESULT and how the frame loop should read it. */
  struct PresentResult
  {
    HRESULT result = S_OK;
    PresentStatus status = PresentStatus::Presented;
  };

  class SwapChain
  {
  public:
    SwapChain() = default;
    SwapChain(const SwapChain&) = delete;
    SwapChain& operator=(const SwapChain&) = delete;
    ~SwapChain();

    /**
     * Creates the swap chain, trying FLIP_DISCARD, then FLIP_SEQUENTIAL, then
     * the legacy DISCARD model, and returns the last HRESULT. A windowed flip
     * swap chain gets the tearing flag when the factory supports it, so a
     * present without vsync is not held to the compositor's refresh.
     */
    HRESULT Create(const Factory& factory, IUnknown* device, const SwapChainDesc& desc);

    /**
     * Presents; `vsync` waits for one vertical blank. An occluded window
     * (success code), a mode change in progress and a tearing flag the
     * chain refuses are handled here; what is left (a lost device, a chain
     * that keeps refusing) is for the caller, see `PresentStatus`.
     */
    PresentResult Present(bool vsync);

    /**
     * Brings the chain to `wanted` the way `PlanReset` says: nothing when
     * only the vsync changed, ResizeBuffers for a windowed size change,
     * a new chain for a window-mode change. A failed resize is retried once
     * after `flushGpu` (the caller drains the GPU), then the chain is
     * recreated; a failed full-screen chain falls back to a windowed one, and
     * as the last resort the old chain is built again. Every reference to a
     * back buffer must be released before the call. Returns the failing
     * HRESULT only when no chain could be made.
     */
    HRESULT Reconfigure(
      const Factory& factory,
      IUnknown* device,
      const SwapChainDesc& wanted,
      bool force,
      bool minimized,
      const std::function<void()>& flushGpu,
      ResetAction* outAction = nullptr
    );

    /** Where the chain stands (the requested window mode, not what DXGI granted). */
    [[nodiscard]] ChainState State() const noexcept
    {
      return ChainState{mDesc.width, mDesc.height, mDesc.fullscreen, mDesc.fullscreen ? mDesc.refreshHz : 0U};
    }
    [[nodiscard]] bool TearingDisabled() const noexcept
    {
      return mTearingDisabled;
    }

    /**
     * Resizes the buffers to `width` x `height`. Every reference to a back
     * buffer (views included) must be released first.
     */
    HRESULT Resize(std::uint32_t width, std::uint32_t height);

    void Release() noexcept;

    [[nodiscard]] IDXGISwapChain* Get() const noexcept
    {
      return mSwapChain.Get();
    }
    [[nodiscard]] SwapModel Model() const noexcept
    {
      return mModel;
    }
    [[nodiscard]] bool IsFlipModel() const noexcept
    {
      return mModel != SwapModel::BltDiscard;
    }
    [[nodiscard]] bool AllowsTearing() const noexcept
    {
      return mAllowTearing;
    }

    template <class Buffer>
    HRESULT GetBuffer(
      Buffer** outBuffer
    ) const
    {
      return mSwapChain->GetBuffer(0U, IID_PPV_ARGS(outBuffer));
    }

    /** Buffer `index` (Direct3D 12 addresses each flip-model buffer itself). */
    template <class Buffer>
    HRESULT GetBuffer(
      const std::uint32_t index,
      Buffer** outBuffer
    ) const
    {
      return mSwapChain->GetBuffer(index, IID_PPV_ARGS(outBuffer));
    }

    /** The buffer the next frame draws into (IDXGISwapChain3); 0 before DXGI 1.4. */
    [[nodiscard]] std::uint32_t CurrentBufferIndex() const;

    /** How many buffers the chain has. */
    [[nodiscard]] std::uint32_t BufferCount() const;

  private:
    Microsoft::WRL::ComPtr<IDXGISwapChain> mSwapChain;
    SwapChainDesc mDesc{};
    SwapModel mModel = SwapModel::BltDiscard;
    bool mAllowTearing = false;
    bool mTearingDisabled = false; // the driver refused a tearing present: not tried again
    UINT mFlags = 0U;
    PresentStatus mLastPresent = PresentStatus::Presented;
    std::uint32_t mSkippedPresents = 0U;
  };
} // namespace gpg::gal::dxgi

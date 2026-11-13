#include "DxgiSwapChain.h"

#include <cstdlib>

#include <algorithm>

#include "DxgiFactory.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Head.hpp"

namespace gpg::gal::dxgi
{
  using Microsoft::WRL::ComPtr;

  const char* SwapModelName(
    const SwapModel model
  ) noexcept
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

  std::uint32_t FrameLatencySetting()
  {
    static const std::uint32_t setting = [] {
      const char* const value = std::getenv("FAF_GAL_FRAME_LATENCY");
      const long parsed = (value != nullptr) ? std::strtol(value, nullptr, 10) : 0L;
      return ClampFrameLatency(parsed, 3U);
    }();
    return setting;
  }

  SwapChainDesc DescribeHeadChain(
    const Head& head,
    const std::uint32_t bufferCount,
    const bool allowFlipModel
  )
  {
    SwapChainDesc desc{};
    desc.window = static_cast<HWND>(head.mWindow);
    desc.width = head.mWidth;
    desc.height = head.mHeight;
    desc.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.fullscreen = head.mWindowed;
    desc.refreshHz = head.framesPerSecond;
    desc.usage = DXGI_USAGE_RENDER_TARGET_OUTPUT | DXGI_USAGE_SHADER_INPUT;
    desc.bufferCount = bufferCount;
    desc.allowFlipModel = allowFlipModel;
    desc.frameLatency = FrameLatencySetting();
    if (desc.width == 0U || desc.height == 0U) {
      RECT client{};
      ::GetClientRect(desc.window, &client);
      desc.width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
      desc.height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
    }
    return desc;
  }

  bool IsWindowMinimized(
    const HWND window
  ) noexcept
  {
    return window != nullptr && ::IsIconic(window) != FALSE;
  }

  SwapChain::~SwapChain()
  {
    Release();
  }

  HRESULT SwapChain::Create(
    const Factory& factory,
    IUnknown* const device,
    const SwapChainDesc& desc
  )
  {
    Release();
    mDesc = desc;

    HRESULT result = E_FAIL;
    IDXGIFactory2* const factory2 = factory.Get2();

    // Flip model: no MSAA back buffer, at least two buffers. A full-screen
    // flip swap chain is created windowed and switched afterwards, which is
    // what DXGI recommends for both models. The optional flags (tearing, the
    // frame-latency object) are dropped one after the other when a driver
    // refuses the chain with them, before the next model is tried.
    if (desc.allowFlipModel && factory2 != nullptr) {
      const SwapModel candidates[] = {SwapModel::FlipDiscard, SwapModel::FlipSequential};
      for (const SwapModel model : candidates) {
        if (model == SwapModel::FlipDiscard && !factory.SupportsFlipDiscard()) {
          continue;
        }

        const bool wantTearing = factory.SupportsTearing() && !desc.fullscreen;
        const bool wantLatency = desc.frameLatency > 0U;
        // Attempt 0: everything asked for; 1: without the latency object;
        // 2: without tearing either. An attempt that would repeat the one
        // before (nothing left to drop) is skipped.
        for (int attempt = 0; attempt < 3 && mSwapChain == nullptr; ++attempt) {
          const bool latency = wantLatency && attempt < 1;
          const bool tearing = wantTearing && attempt < 2;
          if ((attempt == 1 && !wantLatency) || (attempt == 2 && !wantTearing)) {
            continue;
          }

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
            (tearing ? static_cast<UINT>(DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING) : 0U) |
            (latency ? static_cast<UINT>(DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT) : 0U);

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
            mDesc.bufferCount = chainDesc.BufferCount;
            if (latency) {
              ApplyFrameLatency();
            }
          } else {
            gpg::Warnf(
              "DXGI: %s swap chain %ux%u refused (HRESULT 0x%08lX)%s%s",
              SwapModelName(model),
              desc.width,
              desc.height,
              static_cast<unsigned long>(result),
              tearing ? ", with tearing" : "",
              latency ? ", with a frame-latency object" : ""
            );
          }
        }
        if (mSwapChain != nullptr) {
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
      mDesc.bufferCount = chainDesc.BufferCount;
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

  PresentResult SwapChain::Present(
    const bool vsync
  )
  {
    if (mSwapChain == nullptr) {
      return PresentResult{E_POINTER, PresentStatus::Failed};
    }

    // Exclusive full screen refuses a tearing present, and DXGI can leave
    // exclusive mode by itself (alt-tab), so the state is asked, not assumed.
    // Asked only when a tearing present is a candidate: the call takes DXGI's lock.
    BOOL fullscreen = FALSE;
    if (!vsync && mAllowTearing && !mTearingDisabled) {
      static_cast<void>(mSwapChain->GetFullscreenState(&fullscreen, nullptr));
    }
    UINT flags = PresentFlags(vsync, mAllowTearing, fullscreen != FALSE, mTearingDisabled);

    PresentResult present;
    present.result = mSwapChain->Present(vsync ? 1U : 0U, flags);
    present.status = ClassifyPresent(present.result);
    if (ShouldRetryWithoutTearing(present.status, flags)) {
      // A chain that cannot tear in this state (hybrid-GPU present path, a
      // driver that reports the feature and refuses it): present normally from
      // now on rather than fail every frame.
      gpg::Warnf(
        "DXGI: the tearing present was refused (0x%08lX); tearing is off for this swap chain",
        static_cast<unsigned long>(present.result)
      );
      mTearingDisabled = true;
      flags = 0U;
      present.result = mSwapChain->Present(vsync ? 1U : 0U, flags);
      present.status = ClassifyPresent(present.result);
    }

    if (present.status == PresentStatus::Occluded && mLastPresent != PresentStatus::Occluded) {
      gpg::Logf("DXGI: the window is occluded (presents do not wait while it is)");
    } else if (present.status == PresentStatus::Presented && mLastPresent == PresentStatus::Occluded) {
      gpg::Logf("DXGI: the window is visible again");
    } else if (present.status == PresentStatus::Skipped && mSkippedPresents++ < 8U) {
      gpg::Warnf("DXGI: present skipped (HRESULT 0x%08lX)", static_cast<unsigned long>(present.result));
    }
    mLastPresent = present.status;
    return present;
  }

  bool SwapChain::WaitForFrameLatency(
    const std::uint32_t timeoutMs
  )
  {
    if (
      mFrameLatencyObject == nullptr || mFrameLatencyTimeouts >= kFrameLatencyTimeoutLimit ||
      mLastPresent == PresentStatus::Occluded
    ) {
      return true;
    }
    const DWORD waited = ::WaitForSingleObjectEx(mFrameLatencyObject, timeoutMs, TRUE);
    if (waited == WAIT_TIMEOUT) {
      // Resizes and mode changes can leave the object unsignalled; it never holds the frame loop for long.
      if (++mFrameLatencyTimeouts >= kFrameLatencyTimeoutLimit) {
        gpg::Warnf(
          "DXGI: the frame-latency wait timed out %u times in a row; waiting is off for this swap chain",
          mFrameLatencyTimeouts
        );
      }
      return false;
    }
    mFrameLatencyTimeouts = 0U;
    return true;
  }

  void SwapChain::ApplyFrameLatency() noexcept
  {
    CloseFrameLatencyObject();
    mFrameLatencyTimeouts = 0U;
    ComPtr<IDXGISwapChain2> chain2;
    if (
      mSwapChain == nullptr || (mFlags & DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT) == 0U ||
      FAILED(mSwapChain.As(&chain2))
    ) {
      return;
    }
    const std::uint32_t latency = ClampFrameLatency(mDesc.frameLatency, mDesc.bufferCount);
    if (latency == 0U || FAILED(chain2->SetMaximumFrameLatency(latency))) {
      return;
    }
    mFrameLatencyObject = chain2->GetFrameLatencyWaitableObject();
    if (mFrameLatencyObject != nullptr) {
      gpg::Logf("DXGI: frame-latency wait on, at most %u frame(s) queued", latency);
    }
  }

  void SwapChain::CloseFrameLatencyObject() noexcept
  {
    if (mFrameLatencyObject != nullptr) {
      ::CloseHandle(mFrameLatencyObject);
      mFrameLatencyObject = nullptr;
    }
  }

  HRESULT SwapChain::Resize(
    const std::uint32_t width,
    const std::uint32_t height
  )
  {
    if (mSwapChain == nullptr) {
      return E_POINTER;
    }
    const HRESULT result = mSwapChain->ResizeBuffers(0U, width, height, DXGI_FORMAT_UNKNOWN, mFlags);
    if (SUCCEEDED(result)) {
      mDesc.width = width;
      mDesc.height = height;
      ApplyFrameLatency(); // the object is made again with the buffers
    }
    return result;
  }

  HRESULT SwapChain::Reconfigure(
    const Factory& factory,
    IUnknown* const device,
    const SwapChainDesc& wanted,
    const bool force,
    const bool minimized,
    const std::function<void()>& flushGpu,
    ResetAction* const outAction
  )
  {
    const ChainState wantedState{
      wanted.width, wanted.height, wanted.fullscreen, wanted.fullscreen ? wanted.refreshHz : 0U
    };
    ResetAction plan = PlanReset(State(), wantedState, minimized, force || mSwapChain == nullptr);
    if (outAction != nullptr) {
      *outAction = plan;
    }
    if (plan == ResetAction::None) {
      return S_OK;
    }

    if (plan == ResetAction::ResizeBuffers) {
      HRESULT result = Resize(wanted.width, wanted.height);
      if (SUCCEEDED(result)) {
        return result;
      }
      gpg::Warnf(
        "DXGI: ResizeBuffers to %ux%u failed (HRESULT 0x%08lX)",
        wanted.width,
        wanted.height,
        static_cast<unsigned long>(result)
      );
      if (ClassifyPresent(result) == PresentStatus::DeviceLost) {
        return result; // the device recovery decides
      }
      // Usually a back buffer still referenced by work in flight: drain and try once more.
      if (flushGpu) {
        flushGpu();
      }
      result = Resize(wanted.width, wanted.height);
      if (SUCCEEDED(result)) {
        gpg::Logf("DXGI: ResizeBuffers succeeded after the GPU was drained");
        return result;
      }
      gpg::Warnf(
        "DXGI: ResizeBuffers failed again (HRESULT 0x%08lX); creating a new swap chain",
        static_cast<unsigned long>(result)
      );
      if (ClassifyPresent(result) == PresentStatus::DeviceLost) {
        return result;
      }
      plan = ResetAction::Recreate;
      if (outAction != nullptr) {
        *outAction = plan;
      }
    }

    if (flushGpu) {
      flushGpu();
    }
    const SwapChainDesc previous = mDesc;
    HRESULT result = Create(factory, device, wanted);
    if (SUCCEEDED(result)) {
      return result;
    }
    gpg::Warnf("DXGI: creating the swap chain failed (HRESULT 0x%08lX)", static_cast<unsigned long>(result));
    if (ClassifyPresent(result) == PresentStatus::DeviceLost) {
      return result;
    }
    if (wanted.fullscreen) {
      SwapChainDesc windowed = wanted;
      windowed.fullscreen = false;
      result = Create(factory, device, windowed);
      if (SUCCEEDED(result)) {
        gpg::Warnf("DXGI: full screen is not available; the swap chain is windowed");
        return result;
      }
    }
    // Nothing for the new size: build what worked before, so that the game goes on.
    const HRESULT restored = Create(factory, device, previous);
    if (SUCCEEDED(restored)) {
      gpg::Warnf("DXGI: the previous swap chain (%ux%u) was built again", previous.width, previous.height);
      return restored;
    }
    return result;
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
    CloseFrameLatencyObject();
    mSwapChain.Reset();
    mModel = SwapModel::BltDiscard;
    mAllowTearing = false;
    mTearingDisabled = false;
    mFlags = 0U;
    mFrameLatencyTimeouts = 0U;
    mLastPresent = PresentStatus::Presented;
    mSkippedPresents = 0U;
  }
} // namespace gpg::gal::dxgi

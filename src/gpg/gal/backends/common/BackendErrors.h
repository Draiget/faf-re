#pragma once

// FAF addition, not in the shipped binary: error reporting shared by the
// gal backends added for Direct3D 11, Direct3D 12 and Vulkan.

#include <windows.h>

namespace gpg::gal::backend
{
  /** Throws a `gpg::gal::Error` naming `file` and `line`. */
  [[noreturn]] void ThrowError(const char* file, int line, const char* message);

  /** Throws a `gpg::gal::Error` carrying the HRESULT in hex and as text. */
  [[noreturn]] void ThrowHresult(const char* file, int line, HRESULT result);

  /**
   * Diagnostics: true when FAF_GAL_FAIL_SETUP asks the backend named `name`
   * ("d3d12", "vulkan") to fail its device creation - the value `1` (every
   * backend) or a list naming it ("d3d12,vulkan"). Exercises the renderer
   * fallback in CScApp::CreateDevice.
   */
  [[nodiscard]] bool SetupFailureRequested(const char* name);

  /**
   * The viewport origin shift that gives Direct3D 9's rasterization rules:
   * D3D9 puts pixel centres on integer coordinates, Direct3D 10+ and Vulkan
   * on halves. The engine draws for D3D9 - its UI projection
   * (CD3DPrimBatcher::SetToViewport) and full-screen passes carry D3D9's
   * half-pixel offset - so without the shift every UI quad lands half a texel
   * off and linear filtering pulls in the neighbouring font glyph. 0.5, or 0
   * with the diagnostic FAF_GAL_D3D10_PIXEL_CENTRES=1.
   */
  [[nodiscard]] float Direct3D9PixelCentreShift() noexcept;

  /** `ThrowHresult` when `result` failed. */
  inline void CheckHresult(const char* const file, const int line, const HRESULT result)
  {
    if (FAILED(result)) {
      ThrowHresult(file, line, result);
    }
  }
} // namespace gpg::gal::backend

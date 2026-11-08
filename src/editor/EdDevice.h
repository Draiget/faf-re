#pragma once

#include <cstdint>
#include <string>

#include <Windows.h>

#include "gpg/gal/DeviceContext.hpp"

namespace gpg::gal
{
  class Device;
}

namespace faf::editor
{
  /**
   * The editor's render device: one gal device on the editor window, Direct3D 12 or Vulkan.
   *
   * The order is Direct3D 12, then Vulkan; `/d3d12` or `/vulkan` asks for one alone. Unlike the
   * game (CScApp::CreateDevice) nothing older is tried: the editor has no Direct3D 9, 10 or 11.
   */
  class EdDevice
  {
  public:
    /** Creates the device on `window` with a back buffer of `width` x `height`; false when none started. */
    [[nodiscard]] bool Create(HWND window, std::uint32_t width, std::uint32_t height);

    /** Resizes the back buffer (the window's client area changed). */
    void Resize(std::uint32_t width, std::uint32_t height);

    /** Binds the back buffer, begins the scene, sets the whole-window viewport and clears it. */
    void BeginFrame(std::uint32_t clearColor);

    /** Ends the scene and presents. */
    void EndFrame();

    /** Destroys the device. */
    void Destroy();

    [[nodiscard]] gpg::gal::Device* Gal() const;
    [[nodiscard]] gpg::gal::DeviceApi Api() const noexcept { return mApi; }
    [[nodiscard]] const char* ApiName() const noexcept;
    [[nodiscard]] std::uint32_t Width() const noexcept { return mWidth; }
    [[nodiscard]] std::uint32_t Height() const noexcept { return mHeight; }

    /** Why `Create` failed, one line per renderer tried. */
    [[nodiscard]] const std::string& Failures() const noexcept { return mFailures; }

  private:
    gpg::gal::DeviceApi mApi = gpg::gal::DeviceApi::Unset;
    std::uint32_t mWidth = 0U;
    std::uint32_t mHeight = 0U;
    std::string mFailures;
  };

  /** "Direct3D 12", "Vulkan" (only these two are ever created here). */
  [[nodiscard]] const char* EditorApiName(gpg::gal::DeviceApi api) noexcept;
} // namespace faf::editor

#include "editor/EdDevice.h"

#include <algorithm>
#include <exception>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "moho/misc/StartupHelpers.h"

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::vector<gpg::gal::DeviceApi> AttemptOrder()
    {
      using gpg::gal::DeviceApi;
      if (moho::CFG_GetArgOption("/vulkan", 0, nullptr)) {
        return {DeviceApi::Vulkan};
      }
      if (moho::CFG_GetArgOption("/d3d12", 0, nullptr)) {
        return {DeviceApi::Direct3D12};
      }
      return {DeviceApi::Direct3D12, DeviceApi::Vulkan};
    }
  } // namespace

  const char* EditorApiName(const gpg::gal::DeviceApi api) noexcept
  {
    switch (api) {
    case gpg::gal::DeviceApi::Direct3D12:
      return "Direct3D 12";
    case gpg::gal::DeviceApi::Vulkan:
      return "Vulkan";
    default:
      return "none";
    }
  }

  bool EdDevice::Create(const HWND window, const std::uint32_t width, const std::uint32_t height)
  {
    mFailures.clear();
    for (const gpg::gal::DeviceApi api : AttemptOrder()) {
      gpg::gal::DeviceContext context(api);
      context.mVSync = !moho::CFG_GetArgOption("/novsync", 0, nullptr);
      context.mValidate = !moho::CFG_GetArgOption("/novalidate", 0, nullptr);

      gpg::gal::Head head{};
      // `mWindowed` is the full-screen flag (DeviceD3D12.cpp, `desc.fullscreen = head.mWindowed`):
      // the editor is always a window.
      head.mWindowed = false;
      head.mWidth = std::max(width, 1U);
      head.mHeight = std::max(height, 1U);
      head.framesPerSecond = 60U;
      head.mHandle = window;
      head.mWindow = window;
      context.AddHead(head);

      gpg::Logf("editor renderer: trying %s", EditorApiName(api));
      try {
        (void)gpg::gal::Device::Create(&context);
        mApi = api;
        mWidth = head.mWidth;
        mHeight = head.mHeight;
        gpg::Logf("editor renderer: %s ready", EditorApiName(api));
        return true;
      } catch (const gpg::gal::Error& error) {
        mFailures += std::string(EditorApiName(api)) + ": " + error.what() + "\n";
      } catch (const std::exception& error) {
        mFailures += std::string(EditorApiName(api)) + ": " + error.what() + "\n";
      }
      gpg::Warnf("editor renderer: %s is unavailable", EditorApiName(api));
    }
    return false;
  }

  void EdDevice::Resize(const std::uint32_t width, const std::uint32_t height)
  {
    gpg::gal::Device* const device = Gal();
    if (device == nullptr || width == 0U || height == 0U || (width == mWidth && height == mHeight)) {
      return;
    }
    gpg::gal::DeviceContext context = *device->GetDeviceContext();
    gpg::gal::Head& head = context.GetHead(0);
    head.mWidth = width;
    head.mHeight = height;
    device->Reset(&context);
    mWidth = width;
    mHeight = height;
  }

  void EdDevice::BeginFrame(const std::uint32_t clearColor)
  {
    gpg::gal::Device* const device = Gal();
    device->ClearTarget(device->GetHeadOutputContext(0U));
    device->BeginScene();
    D3DVIEWPORT9 viewport{};
    viewport.Width = mWidth;
    viewport.Height = mHeight;
    viewport.MinZ = 0.0f;
    viewport.MaxZ = 1.0f;
    device->SetViewport(&viewport);
    device->Clear(true, false, false, clearColor, 1.0f, 0);
  }

  void EdDevice::EndFrame()
  {
    gpg::gal::Device* const device = Gal();
    device->EndScene();
    device->Present();
  }

  void EdDevice::Destroy()
  {
    gpg::gal::Device::DestroyInstance();
    mApi = gpg::gal::DeviceApi::Unset;
  }

  gpg::gal::Device* EdDevice::Gal() const
  {
    return gpg::gal::Device::IsReady() ? gpg::gal::Device::GetInstance() : nullptr;
  }

  const char* EdDevice::ApiName() const noexcept
  {
    return EditorApiName(mApi);
  }
} // namespace faf::editor

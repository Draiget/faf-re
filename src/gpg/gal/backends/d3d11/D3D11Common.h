#pragma once

// FAF addition, not in the shipped binary: shared helpers of the Direct3D 11
// gal backend. Error reporting and the gal <-> DXGI format tables live in
// backends/common and backends/dxgi, shared with the Direct3D 12 backend.

#include <d3d11.h>

#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

namespace gpg::gal::d3d11
{
  using backend::CheckHresult;
  using backend::ThrowError;
  using backend::ThrowHresult;
  using dxgi::ComputeLevelLayout;
  using dxgi::DepthFormats;
  using dxgi::DepthStencilFormatToDxgi;
  using dxgi::DxgiToRenderTargetFormat;
  using dxgi::DxgiToTextureFormat;
  using dxgi::FormatElementBytes;
  using dxgi::IsBlockCompressed;
  using dxgi::LevelLayout;
  using dxgi::RenderTargetFormatToDxgi;
  using dxgi::TextureFormatToDxgi;
} // namespace gpg::gal::d3d11

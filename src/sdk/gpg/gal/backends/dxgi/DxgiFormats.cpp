// FAF addition, not in the shipped binary: see DxgiFormats.h.

#include "DxgiFormats.h"

namespace gpg::gal::dxgi
{
  namespace
  {
    struct FormatPair
    {
      std::uint32_t gal;
      DXGI_FORMAT dxgi;
    };

    // gal texture formats are the D3D9 ones (`kD3D9FormatToMohoPairs` in the
    // D3D9 backend): 1 R8G8B8, 2 A8R8G8B8, 3 X8R8G8B8, 4 R5G6B5, 5 A8, 6 L8,
    // 7 A8L8, 8..12 DXT1..DXT5, 13 R16F, 14 G16R16F, 15 A16B16G16R16F,
    // 16 R32F, 17 G32R32F, 18 A32B32G32R32F. The first entry for a gal format
    // is the one created; the rest only map back.
    constexpr FormatPair kTextureFormats[] = {
      {2U, DXGI_FORMAT_B8G8R8A8_UNORM},
      {3U, DXGI_FORMAT_B8G8R8X8_UNORM},
      {4U, DXGI_FORMAT_B5G6R5_UNORM},
      {5U, DXGI_FORMAT_A8_UNORM},
      {6U, DXGI_FORMAT_R8_UNORM},
      {7U, DXGI_FORMAT_R8G8_UNORM},
      {8U, DXGI_FORMAT_BC1_UNORM},
      {9U, DXGI_FORMAT_BC2_UNORM},
      {10U, DXGI_FORMAT_BC2_UNORM},
      {11U, DXGI_FORMAT_BC3_UNORM},
      {12U, DXGI_FORMAT_BC3_UNORM},
      {13U, DXGI_FORMAT_R16_FLOAT},
      {14U, DXGI_FORMAT_R16G16_FLOAT},
      {15U, DXGI_FORMAT_R16G16B16A16_FLOAT},
      {16U, DXGI_FORMAT_R32_FLOAT},
      {17U, DXGI_FORMAT_R32G32_FLOAT},
      {18U, DXGI_FORMAT_R32G32B32A32_FLOAT},
      // Map-back only.
      {2U, DXGI_FORMAT_R8G8B8A8_UNORM},
      {2U, DXGI_FORMAT_R8G8B8A8_UNORM_SRGB},
      {2U, DXGI_FORMAT_B8G8R8A8_UNORM_SRGB},
      {3U, DXGI_FORMAT_B8G8R8X8_UNORM_SRGB},
      {8U, DXGI_FORMAT_BC1_UNORM_SRGB},
      {9U, DXGI_FORMAT_BC2_UNORM_SRGB},
      {12U, DXGI_FORMAT_BC3_UNORM_SRGB},
      {6U, DXGI_FORMAT_BC4_UNORM},
      {7U, DXGI_FORMAT_BC5_UNORM},
      {2U, DXGI_FORMAT_B5G5R5A1_UNORM},
      {2U, DXGI_FORMAT_R10G10B10A2_UNORM},
      {2U, DXGI_FORMAT_B4G4R4A4_UNORM},
      {14U, DXGI_FORMAT_R16G16_UNORM},
      {15U, DXGI_FORMAT_R16G16B16A16_UNORM},
      {16U, DXGI_FORMAT_R16_UNORM},
    };

    constexpr FormatPair kRenderTargetFormats[] = {
      {1U, DXGI_FORMAT_R10G10B10A2_UNORM},
      {2U, DXGI_FORMAT_B8G8R8A8_UNORM},
      {3U, DXGI_FORMAT_B8G8R8X8_UNORM},
      {4U, DXGI_FORMAT_B5G5R5A1_UNORM},
      {5U, DXGI_FORMAT_B5G5R5A1_UNORM},
      {6U, DXGI_FORMAT_B5G6R5_UNORM},
      {7U, DXGI_FORMAT_R16G16_UNORM},
      {2U, DXGI_FORMAT_R8G8B8A8_UNORM},
    };
  } // namespace

  DXGI_FORMAT TextureFormatToDxgi(const std::uint32_t galFormat) noexcept
  {
    for (const FormatPair& pair : kTextureFormats) {
      if (pair.gal == galFormat) {
        return pair.dxgi;
      }
    }
    return DXGI_FORMAT_UNKNOWN;
  }

  std::uint32_t DxgiToTextureFormat(const DXGI_FORMAT format) noexcept
  {
    for (const FormatPair& pair : kTextureFormats) {
      if (pair.dxgi == format) {
        return pair.gal;
      }
    }
    return 20U;
  }

  DXGI_FORMAT RenderTargetFormatToDxgi(const std::uint32_t galFormat) noexcept
  {
    for (const FormatPair& pair : kRenderTargetFormats) {
      if (pair.gal == galFormat) {
        return pair.dxgi;
      }
    }
    return DXGI_FORMAT_UNKNOWN;
  }

  std::uint32_t DxgiToRenderTargetFormat(const DXGI_FORMAT format) noexcept
  {
    for (const FormatPair& pair : kRenderTargetFormats) {
      if (pair.dxgi == format) {
        return pair.gal;
      }
    }
    return 8U;
  }

  DepthFormats DepthStencilFormatToDxgi(const std::uint32_t galFormat, const bool sampled) noexcept
  {
    // gal depth formats are D3D9's (`kDepthStencilFormatToD3D`): 1 D32,
    // 2 D15S1, 3 D24S8, 4 D24X8, 5 D24X4S4, 6 D16. DXGI has D32, D24S8 and D16.
    DepthFormats formats{};
    switch (galFormat) {
    case 1U:
      formats = {DXGI_FORMAT_R32_TYPELESS, DXGI_FORMAT_D32_FLOAT, DXGI_FORMAT_R32_FLOAT};
      break;
    case 6U:
      formats = {DXGI_FORMAT_R16_TYPELESS, DXGI_FORMAT_D16_UNORM, DXGI_FORMAT_R16_UNORM};
      break;
    case 2U:
    case 3U:
    case 4U:
    case 5U:
    default:
      formats = {DXGI_FORMAT_R24G8_TYPELESS, DXGI_FORMAT_D24_UNORM_S8_UINT, DXGI_FORMAT_R24_UNORM_X8_TYPELESS};
      break;
    }
    if (!sampled) {
      formats.texture = formats.depthView;
      formats.shaderView = DXGI_FORMAT_UNKNOWN;
    }
    return formats;
  }

  bool IsBlockCompressed(const DXGI_FORMAT format) noexcept
  {
    return (format >= DXGI_FORMAT_BC1_TYPELESS && format <= DXGI_FORMAT_BC5_SNORM) ||
      (format >= DXGI_FORMAT_BC6H_TYPELESS && format <= DXGI_FORMAT_BC7_UNORM_SRGB);
  }

  std::uint32_t FormatElementBytes(const DXGI_FORMAT format) noexcept
  {
    switch (format) {
    case DXGI_FORMAT_R32G32B32A32_TYPELESS:
    case DXGI_FORMAT_R32G32B32A32_FLOAT:
    case DXGI_FORMAT_R32G32B32A32_UINT:
    case DXGI_FORMAT_R32G32B32A32_SINT:
      return 16U;
    case DXGI_FORMAT_R32G32B32_TYPELESS:
    case DXGI_FORMAT_R32G32B32_FLOAT:
    case DXGI_FORMAT_R32G32B32_UINT:
    case DXGI_FORMAT_R32G32B32_SINT:
      return 12U;
    case DXGI_FORMAT_R16G16B16A16_TYPELESS:
    case DXGI_FORMAT_R16G16B16A16_FLOAT:
    case DXGI_FORMAT_R16G16B16A16_UNORM:
    case DXGI_FORMAT_R16G16B16A16_UINT:
    case DXGI_FORMAT_R16G16B16A16_SNORM:
    case DXGI_FORMAT_R16G16B16A16_SINT:
    case DXGI_FORMAT_R32G32_TYPELESS:
    case DXGI_FORMAT_R32G32_FLOAT:
    case DXGI_FORMAT_R32G32_UINT:
    case DXGI_FORMAT_R32G32_SINT:
    case DXGI_FORMAT_BC1_TYPELESS:
    case DXGI_FORMAT_BC1_UNORM:
    case DXGI_FORMAT_BC1_UNORM_SRGB:
    case DXGI_FORMAT_BC4_TYPELESS:
    case DXGI_FORMAT_BC4_UNORM:
    case DXGI_FORMAT_BC4_SNORM:
      return 8U;
    case DXGI_FORMAT_BC2_TYPELESS:
    case DXGI_FORMAT_BC2_UNORM:
    case DXGI_FORMAT_BC2_UNORM_SRGB:
    case DXGI_FORMAT_BC3_TYPELESS:
    case DXGI_FORMAT_BC3_UNORM:
    case DXGI_FORMAT_BC3_UNORM_SRGB:
    case DXGI_FORMAT_BC5_TYPELESS:
    case DXGI_FORMAT_BC5_UNORM:
    case DXGI_FORMAT_BC5_SNORM:
    case DXGI_FORMAT_BC6H_TYPELESS:
    case DXGI_FORMAT_BC6H_UF16:
    case DXGI_FORMAT_BC6H_SF16:
    case DXGI_FORMAT_BC7_TYPELESS:
    case DXGI_FORMAT_BC7_UNORM:
    case DXGI_FORMAT_BC7_UNORM_SRGB:
      return 16U;
    case DXGI_FORMAT_R10G10B10A2_TYPELESS:
    case DXGI_FORMAT_R10G10B10A2_UNORM:
    case DXGI_FORMAT_R10G10B10A2_UINT:
    case DXGI_FORMAT_R11G11B10_FLOAT:
    case DXGI_FORMAT_R8G8B8A8_TYPELESS:
    case DXGI_FORMAT_R8G8B8A8_UNORM:
    case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
    case DXGI_FORMAT_R8G8B8A8_UINT:
    case DXGI_FORMAT_R8G8B8A8_SNORM:
    case DXGI_FORMAT_R8G8B8A8_SINT:
    case DXGI_FORMAT_R16G16_TYPELESS:
    case DXGI_FORMAT_R16G16_FLOAT:
    case DXGI_FORMAT_R16G16_UNORM:
    case DXGI_FORMAT_R16G16_UINT:
    case DXGI_FORMAT_R16G16_SNORM:
    case DXGI_FORMAT_R16G16_SINT:
    case DXGI_FORMAT_R32_TYPELESS:
    case DXGI_FORMAT_D32_FLOAT:
    case DXGI_FORMAT_R32_FLOAT:
    case DXGI_FORMAT_R32_UINT:
    case DXGI_FORMAT_R32_SINT:
    case DXGI_FORMAT_R24G8_TYPELESS:
    case DXGI_FORMAT_D24_UNORM_S8_UINT:
    case DXGI_FORMAT_R24_UNORM_X8_TYPELESS:
    case DXGI_FORMAT_B8G8R8A8_UNORM:
    case DXGI_FORMAT_B8G8R8X8_UNORM:
    case DXGI_FORMAT_B8G8R8A8_TYPELESS:
    case DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:
    case DXGI_FORMAT_B8G8R8X8_TYPELESS:
    case DXGI_FORMAT_B8G8R8X8_UNORM_SRGB:
      return 4U;
    case DXGI_FORMAT_R8G8_TYPELESS:
    case DXGI_FORMAT_R8G8_UNORM:
    case DXGI_FORMAT_R8G8_UINT:
    case DXGI_FORMAT_R8G8_SNORM:
    case DXGI_FORMAT_R8G8_SINT:
    case DXGI_FORMAT_R16_TYPELESS:
    case DXGI_FORMAT_R16_FLOAT:
    case DXGI_FORMAT_D16_UNORM:
    case DXGI_FORMAT_R16_UNORM:
    case DXGI_FORMAT_R16_UINT:
    case DXGI_FORMAT_R16_SNORM:
    case DXGI_FORMAT_R16_SINT:
    case DXGI_FORMAT_B5G6R5_UNORM:
    case DXGI_FORMAT_B5G5R5A1_UNORM:
    case DXGI_FORMAT_B4G4R4A4_UNORM:
      return 2U;
    case DXGI_FORMAT_R8_TYPELESS:
    case DXGI_FORMAT_R8_UNORM:
    case DXGI_FORMAT_R8_UINT:
    case DXGI_FORMAT_R8_SNORM:
    case DXGI_FORMAT_R8_SINT:
    case DXGI_FORMAT_A8_UNORM:
      return 1U;
    default:
      return 0U;
    }
  }

  LevelLayout ComputeLevelLayout(const DXGI_FORMAT format, const std::uint32_t width, const std::uint32_t height) noexcept
  {
    const std::uint32_t elementBytes = FormatElementBytes(format);
    LevelLayout layout{};
    if (IsBlockCompressed(format)) {
      const std::uint32_t blocksWide = (width + 3U) / 4U;
      layout.rowPitch = ((blocksWide != 0U) ? blocksWide : 1U) * elementBytes;
      const std::uint32_t blocksHigh = (height + 3U) / 4U;
      layout.rowCount = (blocksHigh != 0U) ? blocksHigh : 1U;
    } else {
      layout.rowPitch = ((width != 0U) ? width : 1U) * elementBytes;
      layout.rowCount = (height != 0U) ? height : 1U;
    }
    return layout;
  }
} // namespace gpg::gal::dxgi

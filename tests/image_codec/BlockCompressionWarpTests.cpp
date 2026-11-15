// FAF addition: BC1 to BC3 decoded on the CPU (gpg/gal/backends/common/BlockCompression.h) against WARP, Direct3D's
// software rasterizer, texel for texel. A compute shader on a WARP device loads every texel of a BC texture of
// random blocks into an R8G8B8A8 texture; the blocks force the cases that choose a decode's arithmetic often (equal
// endpoints, endpoints a bit apart, BC3's equal alphas); BC1's three-colour mode and BC3's six-alpha mode come with
// half the random blocks. Windows only, as the rest of faf_image_codec_tests; d3d11.dll and d3dcompiler_47.dll are
// loaded at run time, and the test skips without them.

#include <windows.h>

#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "gpg/gal/backends/common/BlockCompression.h"

namespace
{
  using Microsoft::WRL::ComPtr;

  constexpr char kLoadShader[] = "Texture2D<float4> source : register(t0);\n"
                                 "RWTexture2D<unorm float4> target : register(u0);\n"
                                 "[numthreads(8, 8, 1)] void main(uint3 id : SV_DispatchThreadID)\n"
                                 "{\n"
                                 "  target[id.xy] = source.Load(int3(id.xy, 0));\n"
                                 "}\n";

  struct Warp
  {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11ComputeShader> load;
  };

  /** A WARP device with the load shader; without a shader where d3d11.dll, WARP or d3dcompiler_47.dll is missing. */
  Warp MakeWarp()
  {
    Warp warp;
    const HMODULE d3d11 = ::LoadLibraryW(L"d3d11.dll");
    const HMODULE compiler = ::LoadLibraryW(L"d3dcompiler_47.dll");
    if (d3d11 == nullptr || compiler == nullptr) {
      return warp;
    }
    const auto create =
      reinterpret_cast<PFN_D3D11_CREATE_DEVICE>(reinterpret_cast<void*>(::GetProcAddress(d3d11, "D3D11CreateDevice")));
    const auto compile =
      reinterpret_cast<pD3DCompile>(reinterpret_cast<void*>(::GetProcAddress(compiler, "D3DCompile")));
    if (create == nullptr || compile == nullptr) {
      return warp;
    }
    const D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    if (
      FAILED(create(
        nullptr,
        D3D_DRIVER_TYPE_WARP,
        nullptr,
        0U,
        &level,
        1U,
        D3D11_SDK_VERSION,
        warp.device.GetAddressOf(),
        nullptr,
        warp.context.GetAddressOf()
      ))
    ) {
      return warp;
    }
    ComPtr<ID3DBlob> code;
    ComPtr<ID3DBlob> errors;
    if (
      FAILED(compile(
        kLoadShader,
        sizeof(kLoadShader) - 1U,
        "load",
        nullptr,
        nullptr,
        "main",
        "cs_5_0",
        0U,
        0U,
        code.GetAddressOf(),
        errors.GetAddressOf()
      )) ||
      FAILED(warp.device->CreateComputeShader(
        code->GetBufferPointer(), code->GetBufferSize(), nullptr, warp.load.GetAddressOf()
      ))
    ) {
      warp.load.Reset();
    }
    return warp;
  }

  /** `count` random blocks of `format`, three of every eight with one of the cases that choose the arithmetic. */
  std::vector<std::uint8_t> RandomBlocks(
    const DXGI_FORMAT format,
    const std::uint32_t count,
    std::mt19937& random
  )
  {
    const std::uint32_t blockBytes = (format == DXGI_FORMAT_BC1_UNORM) ? 8U : 16U;
    std::vector<std::uint8_t> blocks(static_cast<std::size_t>(count) * blockBytes);
    for (std::uint8_t& byte : blocks) {
      byte = static_cast<std::uint8_t>(random());
    }
    for (std::uint32_t block = 0U; block < count; ++block) {
      std::uint8_t* const at = blocks.data() + static_cast<std::size_t>(block) * blockBytes;
      std::uint8_t* const colour = at + (blockBytes - 8U);
      switch (random() % 8U) {
      case 0U: // equal colour endpoints
        colour[2] = colour[0];
        colour[3] = colour[1];
        break;
      case 1U: // BC3: equal alpha endpoints
        at[1] = at[0];
        break;
      case 2U: // colour endpoints one bit apart
        colour[2] = static_cast<std::uint8_t>(colour[0] ^ (1U << (random() % 8U)));
        colour[3] = colour[1];
        break;
      default:
        break;
      }
    }
    return blocks;
  }

  /** WARP's texels of `blocks`, a `width` x `height` level of `format`: R8G8B8A8, `width` * 4 bytes a row. */
  std::vector<std::uint8_t> DecodeOnWarp(
    const Warp& warp,
    const DXGI_FORMAT format,
    const std::vector<std::uint8_t>& blocks,
    const std::uint32_t width,
    const std::uint32_t height
  )
  {
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = format;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    const auto rowPitch = static_cast<UINT>(blocks.size() / (height / 4U));
    const D3D11_SUBRESOURCE_DATA initial{blocks.data(), rowPitch, 0U};
    ComPtr<ID3D11Texture2D> source;
    ComPtr<ID3D11ShaderResourceView> view;
    if (
      FAILED(warp.device->CreateTexture2D(&desc, &initial, source.GetAddressOf())) ||
      FAILED(warp.device->CreateShaderResourceView(source.Get(), nullptr, view.GetAddressOf()))
    ) {
      return {};
    }
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
    ComPtr<ID3D11Texture2D> target;
    ComPtr<ID3D11UnorderedAccessView> unordered;
    if (
      FAILED(warp.device->CreateTexture2D(&desc, nullptr, target.GetAddressOf())) ||
      FAILED(warp.device->CreateUnorderedAccessView(target.Get(), nullptr, unordered.GetAddressOf()))
    ) {
      return {};
    }
    desc.BindFlags = 0U;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Texture2D> staging;
    if (FAILED(warp.device->CreateTexture2D(&desc, nullptr, staging.GetAddressOf()))) {
      return {};
    }
    warp.context->CSSetShader(warp.load.Get(), nullptr, 0U);
    warp.context->CSSetShaderResources(0U, 1U, view.GetAddressOf());
    warp.context->CSSetUnorderedAccessViews(0U, 1U, unordered.GetAddressOf(), nullptr);
    warp.context->Dispatch(width / 8U, height / 8U, 1U);
    warp.context->CopyResource(staging.Get(), target.Get());
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (FAILED(warp.context->Map(staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped))) {
      return {};
    }
    std::vector<std::uint8_t> texels(static_cast<std::size_t>(width) * height * 4U);
    for (std::uint32_t y = 0U; y < height; ++y) {
      std::memcpy(
        texels.data() + static_cast<std::size_t>(y) * width * 4U,
        static_cast<const std::uint8_t*>(mapped.pData) + static_cast<std::size_t>(y) * mapped.RowPitch,
        static_cast<std::size_t>(width) * 4U
      );
    }
    warp.context->Unmap(staging.Get(), 0U);
    return texels;
  }
} // namespace

TEST(
  BlockCompressionWarp,
  DecodeIsWarpsTexelForTexel
)
{
  const Warp warp = MakeWarp();
  if (warp.load == nullptr) {
    GTEST_SKIP() << "no WARP device, or no d3dcompiler_47.dll";
  }
  constexpr std::uint32_t kBlocksWide = 256U;
  constexpr std::uint32_t kBlocksHigh = 64U;
  constexpr std::uint32_t kWidth = kBlocksWide * 4U;
  constexpr std::uint32_t kHeight = kBlocksHigh * 4U;
  std::mt19937 random(20261115U);
  for (const DXGI_FORMAT format : {DXGI_FORMAT_BC1_UNORM, DXGI_FORMAT_BC2_UNORM, DXGI_FORMAT_BC3_UNORM}) {
    const std::vector<std::uint8_t> blocks = RandomBlocks(format, kBlocksWide * kBlocksHigh, random);
    const std::vector<std::uint8_t> reference = DecodeOnWarp(warp, format, blocks, kWidth, kHeight);
    ASSERT_EQ(reference.size(), static_cast<std::size_t>(kWidth) * kHeight * 4U)
      << "WARP's decode of format " << format;
    std::vector<std::uint8_t> decoded(reference.size(), 0xCDU);
    const std::size_t rowPitch = blocks.size() / kBlocksHigh;
    gpg::gal::imaging::DecodeBc123(format, blocks.data(), rowPitch, kWidth, kHeight, decoded.data());
    std::size_t differing = 0U;
    std::string first;
    for (std::size_t texel = 0U; texel * 4U < decoded.size(); ++texel) {
      if (std::memcmp(decoded.data() + texel * 4U, reference.data() + texel * 4U, 4U) == 0) {
        continue;
      }
      if (differing++ == 0U) {
        char text[160]{};
        const std::uint8_t* const ours = decoded.data() + texel * 4U;
        const std::uint8_t* const theirs = reference.data() + texel * 4U;
        std::snprintf(
          text,
          sizeof(text),
          "texel (%zu, %zu): ours %u %u %u %u, WARP's %u %u %u %u",
          texel % kWidth,
          texel / kWidth,
          ours[0],
          ours[1],
          ours[2],
          ours[3],
          theirs[0],
          theirs[1],
          theirs[2],
          theirs[3]
        );
        first = text;
      }
    }
    EXPECT_EQ(differing, 0U) << "format " << format << " (" << kBlocksWide * kBlocksHigh << " blocks), first " << first;
  }
}

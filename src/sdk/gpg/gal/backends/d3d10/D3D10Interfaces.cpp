#include "AdapterD3D10.hpp"
#include "CubeRenderTargetD3D10.hpp"
#include "CursorD3D10.hpp"
#include "DepthStencilTargetD3D10.hpp"
#include "DeviceD3D10.hpp"
#include "EffectD3D10.hpp"
#include "EffectTechniqueD3D10.hpp"
#include "EffectVariableD3D10.hpp"
#include "Float16HardwareVertexFormatterD3D10.hpp"
#include "HardwareVertexFormatterD3D10.hpp"
#include "IndexBufferD3D10.hpp"
#include "PipelineStateD3D10.hpp"
#include "RenderTargetD3D10.hpp"
#include "TextureD3D10.hpp"
#include "VertexBufferD3D10.hpp"
#include "VertexFormatD3D10.hpp"

#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/PipelineState.hpp"
#include "gpg/gal/SafeRelease.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "platform/Platform.h"

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>

// D3DXFloat32To16Array: the float16 formatter packs its halves with it, as the
// D3D9 one does (both call the d3dx9 import at 0x00AC65C0).
#include <d3dx9math.h>

namespace gpg::gal
{
  namespace
  {

    struct DXGIFormatPair final
    {
      int dxgi = 0;
      int gal = 0;
    };

    constexpr std::uint32_t kHardwareVertexFormatToken = 14U;
    constexpr std::uint32_t kFloat16VertexFormatToken = 15U;
    constexpr std::uint32_t kHardwareVertexStrideBase = 0x48U;
    constexpr std::uint32_t kFloat16VertexStrideStream0 = 0x2CU;
    constexpr std::uint32_t kFloat16VertexStrideStream1 = 0x44U;



    constexpr DXGIFormatPair kTextureDxgiGalPairs[89] = {
      {0, 20},  {1, 20},  {2, 18},  {3, 20},  {4, 20},  {5, 20},  {6, 20},  {7, 20},  {8, 20},  {9, 20},
      {10, 15}, {11, 20}, {12, 20}, {13, 20}, {14, 20}, {15, 20}, {16, 17}, {17, 20}, {18, 20}, {19, 20},
      {20, 20}, {21, 20}, {22, 20}, {23, 20}, {24, 20}, {25, 20}, {26, 20}, {27, 20}, {28, 2},  {29, 20},
      {30, 2},  {31, 20}, {32, 20}, {33, 20}, {34, 14}, {35, 20}, {36, 20}, {37, 20}, {38, 20}, {39, 20},
      {40, 20}, {41, 16}, {42, 20}, {43, 20}, {44, 20}, {45, 20}, {46, 20}, {47, 20}, {48, 20}, {49, 7},
      {50, 20}, {51, 20}, {52, 20}, {53, 20}, {54, 13}, {55, 20}, {56, 20}, {57, 20}, {58, 20}, {59, 20},
      {60, 20}, {61, 6},  {62, 20}, {63, 20}, {64, 20}, {65, 5},  {66, 20}, {67, 20}, {68, 20}, {69, 20},
      {70, 20}, {71, 8},  {72, 20}, {73, 20}, {74, 9},  {75, 20}, {76, 20}, {77, 12}, {78, 20}, {79, 20},
      {80, 20}, {81, 20}, {82, 20}, {83, 20}, {84, 20}, {85, 4},  {86, 20}, {87, 20}, {88, 20},
    };

    constexpr DXGIFormatPair kRenderTargetDxgiGalPairs[10] = {
      {0, 0},
      {24, 1},
      {28, 2},
      {88, 3},
      {86, 4},
      {0, 5},
      {85, 6},
      {35, 7},
      {0, 8},
      {0, 0},
    };

    // Address: 0x00D43078 (DAT_00D43078)
    constexpr std::uint32_t kPrimitiveTopologyByToken[15] = {
      0U,
      1U,
      2U,
      3U,
      4U,
      5U,
      10U,
      11U,
      12U,
      13U,
      0U,
      1U,
      3U,
      3U,
      4U,
    };

    // Address: 0x00D430A0 (DAT_00D430A0)
    constexpr std::int32_t kImageFileFormatByToken[5] = {0, 1, 3, 3, 4};

    // Address: 0x00D487AC (DAT_00D487AC)
    constexpr std::uint32_t kDepthStencilDxgiByToken[8] = {
      0U,
      40U,
      0U,
      45U,
      46U,
      0U,
      55U,
      0U,
    };

    constexpr std::uint32_t kVendorIdNvidia = 4318U;
    constexpr UINT kD3D10FormatSupportRenderTarget = 0x4000U;
    constexpr UINT kD3D10FormatSupportTexture2D = 0x20U;

    struct RttVertex final
    {
      float x = 0.0f;
      float y = 0.0f;
      float z = 0.0f;
      float u = 0.0f;
      float v = 0.0f;
    };

    static_assert(sizeof(RttVertex) == 0x14, "RttVertex size must be 0x14");

    constexpr RttVertex kRttFullscreenVertices[4] = {
      {-1.0f, -1.0f, 0.0f, 0.0f, 1.0f},
      {1.0f, -1.0f, 0.0f, 1.0f, 1.0f},
      {-1.0f, 1.0f, 0.0f, 0.0f, 0.0f},
      {1.0f, 1.0f, 0.0f, 1.0f, 0.0f},
    };

    struct NvidiaSampleCandidate final
    {
      unsigned int sampleType = 0U;
      unsigned int sampleQuality = 0U;
      const char* label = nullptr;
    };

    constexpr NvidiaSampleCandidate kNvidiaSampleCandidates[] = {
      {2U, 0U, "2"},
      {4U, 0U, "4"},
      {4U, 2U, "8"},
      {8U, 0U, "8Q"},
      {4U, 4U, "16"},
      {8U, 2U, "16Q"},
    };

    constexpr char kSignaturePreambleEffectSource[] =
#include "D3D10SignatureEffectSource.inl"
      ;
    constexpr char kRttEffectSource[] =
#include "D3D10RTTEffectSource.inl"
      ;

    static_assert(
      sizeof(kSignaturePreambleEffectSource) == 7789,
      "kSignaturePreambleEffectSource size must be 7789 (source + NUL)"
    );
    static_assert(sizeof(kRttEffectSource) == 1041, "kRttEffectSource size must be 1041 (source + NUL)");

    constexpr DXGI_FORMAT kAdapterProbeFormats[8] = {
      static_cast<DXGI_FORMAT>(10),
      static_cast<DXGI_FORMAT>(24),
      static_cast<DXGI_FORMAT>(28),
      static_cast<DXGI_FORMAT>(29),
      static_cast<DXGI_FORMAT>(85),
      static_cast<DXGI_FORMAT>(86),
      static_cast<DXGI_FORMAT>(87),
      static_cast<DXGI_FORMAT>(88),
    };

    struct ShaderMacroPair final
    {
      const char* key = nullptr;
      const char* value = nullptr;
    };

    constexpr ShaderMacroPair kDeviceCreateEffectInjectedMacros[] = {
      {"technique", "technique10"},
      {"VERSION", "DIRECT3D10"},
      {"vs_1_1", "vs_4_0"},
      {"vs_1_3", "vs_4_0"},
      {"vs_1_4", "vs_4_0"},
      {"vs_2_0", "vs_4_0"},
      {"vs_3_0", "vs_4_0"},
      {"ps_1_1", "ps_4_0"},
      {"ps_1_3", "ps_4_0"},
      {"ps_1_4", "ps_4_0"},
      {"ps_2_0", "ps_4_0"},
      {"ps_2_a", "ps_4_0"},
      {"ps_2_b", "ps_4_0"},
      {"ps_3_0", "ps_4_0"},
      {"MipFilter", "Filter"},
      {"MinFilter", "Filter"},
      {"MagFilter", "Filter"},
      {"NONE", "MIN_MAG_MIP_POINT"},
      {"LINEAR", "MIN_MAG_MIP_LINEAR"},
      {"POINT", "MIN_MAG_MIP_POINT"},
    };
    constexpr std::size_t kDeviceCreateEffectInjectedMacroCount =
      sizeof(kDeviceCreateEffectInjectedMacros) / sizeof(kDeviceCreateEffectInjectedMacros[0]);

    // Address: 0x00D44940 (DAT_00D44940)
    constexpr std::uint32_t kVertexLayoutElementCountByFormat[24] = {
      1, 1, 2, 2, 3, 3, 3, 2, 3, 7, 1, 6, 3, 4, 17, 17, 18, 3, 8, 4, 6, 4, 0, 0,
    };

    // The per-format input layouts handed to `ID3D10Device::CreateInputLayout`.
    // The shipped image stores each semantic as a pointer into its own .rdata;
    // read back from ForgedAlliance.exe those are 0x00D433EC "TEXCOORD",
    // 0x00D433F8 "POSITION", 0x00D43C1C "BLENDINDICES", 0x00D43C2C "BINORMAL",
    // 0x00D43C38 "TANGENT", 0x00D43C40 "COLOR" and 0x00D43C48 "NORMAL". Format
    // and classification are the SDK enumerators for the values the binary
    // carries, so the tables compile to the same numbers.
    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format0[1] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format1[1] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format2[2] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format3[2] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format4[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32_FLOAT, 0U, 20U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format5[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format6[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"COLOR", 0U, DXGI_FORMAT_R8G8B8A8_UNORM, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format7[2] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format8[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format9[7] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 16U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 32U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 48U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format10[1] = {
      {"POSITION", 0U, DXGI_FORMAT_R16G16B16A16_UINT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format11[6] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 32U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 48U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 60U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 76U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format12[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format13[4] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 12U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 28U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 44U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format14[17] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TANGENT", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 28U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BINORMAL", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 40U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32B32A32_FLOAT, 0U, 52U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 0U, DXGI_FORMAT_R8_SINT, 0U, 68U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 1U, DXGI_FORMAT_R8_SINT, 0U, 69U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 2U, DXGI_FORMAT_R8_SINT, 0U, 70U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 3U, DXGI_FORMAT_R8_SINT, 0U, 71U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 12U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 24U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 36U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 5U, DXGI_FORMAT_R8G8B8A8_UINT, 1U, 48U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 6U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 52U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"COLOR", 0U, DXGI_FORMAT_R8G8B8A8_UNORM, 1U, 68U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 7U, DXGI_FORMAT_R32_FLOAT, 1U, 72U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format15[17] = {
      {"POSITION", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 8U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TANGENT", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BINORMAL", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 32U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 0U, DXGI_FORMAT_R8_SINT, 0U, 40U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 1U, DXGI_FORMAT_R8_SINT, 0U, 41U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 2U, DXGI_FORMAT_R8_SINT, 0U, 42U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 3U, DXGI_FORMAT_R8_SINT, 0U, 43U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 12U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 24U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 36U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 5U, DXGI_FORMAT_R8G8B8A8_UNORM, 1U, 48U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 6U, DXGI_FORMAT_R16G16B16A16_FLOAT, 1U, 52U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"COLOR", 0U, DXGI_FORMAT_R8G8B8A8_UNORM, 1U, 60U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 7U, DXGI_FORMAT_R32_FLOAT, 1U, 64U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format16[18] = {
      {"POSITION", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"NORMAL", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 8U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TANGENT", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 16U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BINORMAL", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 24U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R16G16B16A16_FLOAT, 0U, 32U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 0U, DXGI_FORMAT_R8_SINT, 0U, 40U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 1U, DXGI_FORMAT_R8_SINT, 0U, 41U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 2U, DXGI_FORMAT_R8_SINT, 0U, 42U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"BLENDINDICES", 3U, DXGI_FORMAT_R8_SINT, 0U, 43U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R16G16B16A16_FLOAT, 1U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32_FLOAT, 2U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32_FLOAT, 2U, 12U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32_FLOAT, 2U, 24U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32_FLOAT, 2U, 36U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 5U, DXGI_FORMAT_R8G8B8A8_UNORM, 2U, 48U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 6U, DXGI_FORMAT_R16G16B16A16_FLOAT, 2U, 52U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"COLOR", 0U, DXGI_FORMAT_R8G8B8A8_UNORM, 2U, 60U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 7U, DXGI_FORMAT_R32_FLOAT, 2U, 64U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format17[3] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R32G32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32_FLOAT, 1U, 8U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format18[8] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 1U, 16U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 24U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 40U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 52U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 4U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 68U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 5U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 80U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format19[4] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 1U, 16U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 24U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format20[6] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 16U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32_FLOAT, 1U, 28U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 2U, DXGI_FORMAT_R32G32_FLOAT, 1U, 36U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 3U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 44U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    constexpr D3D10_INPUT_ELEMENT_DESC kVertexLayoutElements_Format21[4] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 0U, D3D10_INPUT_PER_VERTEX_DATA, 0U},
      {"POSITION", 1U, DXGI_FORMAT_R32G32B32_FLOAT, 1U, 0U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 1U, 12U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
      {"TEXCOORD", 1U, DXGI_FORMAT_R32G32B32A32_FLOAT, 1U, 20U, D3D10_INPUT_PER_INSTANCE_DATA, 1U},
    };

    // Address: 0x00F311F8 (off_F311F8)
    constexpr const D3D10_INPUT_ELEMENT_DESC* kVertexLayoutElementsByFormat[24] = {
      kVertexLayoutElements_Format0,
      kVertexLayoutElements_Format1,
      kVertexLayoutElements_Format2,
      kVertexLayoutElements_Format3,
      kVertexLayoutElements_Format4,
      kVertexLayoutElements_Format5,
      kVertexLayoutElements_Format6,
      kVertexLayoutElements_Format7,
      kVertexLayoutElements_Format8,
      kVertexLayoutElements_Format9,
      kVertexLayoutElements_Format10,
      kVertexLayoutElements_Format11,
      kVertexLayoutElements_Format12,
      kVertexLayoutElements_Format13,
      kVertexLayoutElements_Format14,
      kVertexLayoutElements_Format15,
      kVertexLayoutElements_Format16,
      kVertexLayoutElements_Format17,
      kVertexLayoutElements_Format18,
      kVertexLayoutElements_Format19,
      kVertexLayoutElements_Format20,
      kVertexLayoutElements_Format21,
      nullptr,
      nullptr,
    };

    msvc8::string MakeShortString(const char* const text)
    {
      if (text == nullptr) {
        return msvc8::string();
      }

      const std::size_t length = std::strlen(text);
      return msvc8::string(text, length);
    }

    [[noreturn]] void ThrowGalError(const char* const file, const int line, const char* const message)
    {
      throw Error(MakeShortString(file), line, MakeShortString(message));
    }

    [[noreturn]] void ThrowGalErrorFromHresult(const char* const file, const int line, const HRESULT code)
    {
      throw Error(MakeShortString(file), line, MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code))));
    }

    msvc8::string MakeD3DErrorString(const HRESULT code)
    {
      return MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code)));
    }

    [[noreturn]] void ThrowDeviceD3D10Hresult(const int line, const HRESULT code)
    {
      throw Error(MakeShortString("DeviceD3D10.cpp"), line, MakeD3DErrorString(code));
    }

    [[noreturn]] void ThrowPipelineStateD3D10Hresult(const int line, const HRESULT code)
    {
      throw Error(MakeShortString("PipelineStateD3D10.cpp"), line, MakeD3DErrorString(code));
    }

    /**
     * Address: 0x008EA950 (FUN_008EA950)
     *
     * What it does:
     * Appends one validated multisample option (`type/quality/label`) into one
     * head capability list.
     */
    void AppendHeadSampleOption(
      Head& head, const unsigned int sampleType, const unsigned int sampleQuality, const char* const label
    )
    {
      HeadSampleOption option{};
      option.sampleType = sampleType;
      option.sampleQuality = sampleQuality;
      option.label.assign_owned((label != nullptr) ? label : "");
      head.mStrs.push_back(option);
    }

    std::uint32_t ConvertCursorPixelRgbaToBgra(const std::uint32_t rgba) noexcept
    {
      return (rgba & 0xFF000000U) | ((rgba & 0x000000FFU) << 16U) | (rgba & 0x0000FF00U) |
        ((rgba & 0x00FF0000U) >> 16U);
    }

    /**
     * Address: 0x008F8130 (FUN_008F8130)
     *
     * What it does:
     * Builds a 32x32 ARGB cursor icon from the cursor texture: locks level 0
     * read-only (flags 2), copies the rows bottom-up with red and blue
     * swapped, and unlocks through the by-value `Unlock` (slot 4). The texture
     * handle arrives by value; its release on the way out is the parameter's
     * destruction.
     */
    HICON BuildCursorIcon(const int hotspotX, const int hotspotY, const boost::shared_ptr<Texture> texture)
    {
      BITMAPV5HEADER bitmapInfo{};
      bitmapInfo.bV5Size = sizeof(BITMAPV5HEADER);
      bitmapInfo.bV5Width = 32L;
      bitmapInfo.bV5Height = 32L;
      bitmapInfo.bV5Planes = 1;
      bitmapInfo.bV5BitCount = 32;
      bitmapInfo.bV5Compression = BI_BITFIELDS;
      bitmapInfo.bV5RedMask = 0x00FF0000U;
      bitmapInfo.bV5GreenMask = 0x0000FF00U;
      bitmapInfo.bV5BlueMask = 0x000000FFU;
      bitmapInfo.bV5AlphaMask = 0xFF000000U;

      HDC const dc = ::GetDC(nullptr);
      void* dibPixels = nullptr;
      HBITMAP const colorBitmap = ::CreateDIBSection(
        dc, reinterpret_cast<const BITMAPINFO*>(&bitmapInfo), DIB_RGB_COLORS, &dibPixels, nullptr, 0U
      );
      ::ReleaseDC(nullptr, dc);

      const RECT wholeSurface{};
      const TextureLockRect transfer = texture->Lock(0, wholeSurface, 2);

      auto* const destinationPixels = reinterpret_cast<std::uint32_t*>(dibPixels);
      const auto* const sourceBytes = static_cast<const std::uint8_t*>(transfer.bits);
      const std::uint32_t rowPitchBytes = static_cast<std::uint32_t>(transfer.pitch);
      const auto* sourceRow = reinterpret_cast<const std::uint32_t*>(sourceBytes + (rowPitchBytes * 31U));

      for (std::uint32_t y = 0; y < 32U; ++y) {
        for (std::uint32_t x = 0; x < 32U; ++x) {
          destinationPixels[(y * 32U) + x] = ConvertCursorPixelRgbaToBgra(sourceRow[x]);
        }

        sourceRow =
          reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(sourceRow) - rowPitchBytes);
      }

      static_cast<void>(texture->Unlock(transfer));

      HBITMAP const maskBitmap = ::CreateBitmap(32, 32, 1U, 1U, nullptr);
      ICONINFO iconInfo{};
      iconInfo.fIcon = FALSE;
      iconInfo.xHotspot = static_cast<DWORD>(hotspotX);
      iconInfo.yHotspot = static_cast<DWORD>(hotspotY);
      iconInfo.hbmMask = maskBitmap;
      iconInfo.hbmColor = colorBitmap;

      HICON const iconHandle = ::CreateIconIndirect(&iconInfo);
      ::DeleteObject(colorBitmap);
      ::DeleteObject(maskBitmap);
      return iconHandle;
    }

    [[noreturn]] void ThrowInvalidTopologyError(const int line)
    {
      ThrowGalError("DeviceD3D10.cpp", line, "invalid topology specified");
    }

    std::uint32_t ResolvePrimitiveTopology(const std::uint32_t topologyToken) noexcept
    {
      return kPrimitiveTopologyByToken[topologyToken];
    }

    // `{proxy, first, last, end}` at 0x10 is `msvc8::vector<EffectMacro>`
    // itself, so the lane is the container, not a view over it.
    using EffectMacroVector = msvc8::vector<EffectMacro>;

    static_assert(sizeof(EffectMacroVector) == 0x10, "EffectMacroVector size must be 0x10");

    int ResolveImageFileFormatToken(const int token) noexcept
    {
      if ((token < 0) || (token >= 5)) {
        return 0;
      }

      return kImageFileFormatByToken[token];
    }

    /**
     * Address: 0x008F8890 (FUN_008F8890)
     *
     * DXGI_SWAP_CHAIN_DESC *,Head const *
     *
     * What it does:
     * Clears one swap-chain descriptor and populates presentation lanes from
     * one `Head` runtime view when a native window handle is present.
     */
    DXGI_SWAP_CHAIN_DESC*
    BuildSwapChainDescFromHead(DXGI_SWAP_CHAIN_DESC* const outDesc, const Head* const head)
    {
      std::memset(outDesc, 0, sizeof(DXGI_SWAP_CHAIN_DESC));
      if (head->mWindow == nullptr) {
        return outDesc;
      }

      outDesc->BufferDesc.Width = head->mWidth;
      outDesc->BufferDesc.Height = head->mHeight;
      outDesc->BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
      outDesc->BufferDesc.RefreshRate.Numerator = head->mWindowed ? head->framesPerSecond : 0U;
      outDesc->BufferDesc.RefreshRate.Denominator = 1U;
      outDesc->BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
      outDesc->BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
      outDesc->SampleDesc.Count = 1U;
      outDesc->SampleDesc.Quality = 0U;
      outDesc->BufferUsage = 48U;
      outDesc->BufferCount = 2U;
      outDesc->OutputWindow = static_cast<HWND>(head->mWindow);
      // Inverted on purpose: the binary writes DXGI's `Windowed` as
      // `mWindowed == 0`, and only takes the refresh rate above when
      // `mWindowed` is set -- a rate that matters only full-screen. So this
      // lane behaves as a full-screen flag whatever `Head` calls it.
      outDesc->Windowed = head->mWindowed ? FALSE : TRUE;
      outDesc->SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
      outDesc->Flags = 0U;
      return outDesc;
    }

    void* AllocateArrayOrThrow(const std::uint32_t count, const std::uint32_t elementSize)
    {
      if ((count != 0U) && ((std::numeric_limits<std::uint32_t>::max() / count) < elementSize)) {
        throw std::bad_alloc();
      }

      return ::operator new(static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize));
    }

    /**
     * Address: 0x008F8ED0 (FUN_008F8ED0)
     *
     * uint32_t
     *
     * What it does:
     * Allocates `count * 4` bytes with overflow guard and throws
     * `std::bad_alloc` on overflow.
     */
    void* AllocateStride04Array(const std::uint32_t count)
    {
      return AllocateArrayOrThrow(count, 0x04U);
    }

    /**
     * Address: 0x0094D490 (FUN_0094D490)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from one
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    const Matrix* CopyMatrix4x3Rows(
      float* const outRow0,
      float* const outRow1,
      float* const outRow2,
      float* const outRow3,
      const Matrix& matrix
    )
    {
      float* const outRows[4] = {outRow0, outRow1, outRow2, outRow3};
      for (int row = 0; row < 4; ++row) {
        outRows[row][0] = matrix.r[row].x;
        outRows[row][1] = matrix.r[row].y;
        outRows[row][2] = matrix.r[row].z;
      }

      return &matrix;
    }

    /**
     * Address: 0x008F71D0 (FUN_008F71D0)
     *
     * What it does:
     * Initializes one adapter-mode entry from `(format, output)`, resets its
     * embedded mode-vector lanes, and snapshots one output descriptor.
     */
    AdapterModeD3D10* InitializeAdapterModeEntry(
      AdapterModeD3D10* const entry,
      const std::uint32_t format,
      IDXGIOutput* const output
    )
    {
      entry->format_ = format;
      entry->output_ = output;
      entry->modes_.clear();
      entry->outputDesc_ = {};
      if (output != nullptr) {
        static_cast<void>(output->GetDesc(&entry->outputDesc_));
      }
      return entry;
    }

    /**
     * Address: 0x008F6230 (FUN_008F6230)
     *
     * What it does:
     * Releases retained output COM lanes for every cached adapter-mode entry,
     * then releases the retained DXGI adapter lane.
     */
    void ReleaseAdapterOutputAndDeviceRefs(AdapterD3D10* const adapter) noexcept
    {
      for (AdapterModeD3D10& mode : adapter->modes_) {
        SafeRelease(mode.output_);
      }
      SafeRelease(adapter->dxgiAdapter_);
    }

    // Defined later in this TU; used by the vector<void*>::_Insert_n grow lane below.
    [[noreturn]] void ThrowVectorTooLongLengthErrorB();

    int MapDxgiToGalRenderTargetFormat(const int dxgiFormat)
    {
      for (const DXGIFormatPair& pair : kRenderTargetDxgiGalPairs) {
        if (pair.dxgi == dxgiFormat) {
          return pair.gal;
        }
      }

      return 8;
    }

    /**
     * Address: 0x009033A0 (FUN_009033A0)
     *
     * What it does:
     * Converts DXGI texture-format tokens to GAL texture-format tokens through
     * the recovered 89-entry mapping table, with fallback format token `20`.
     */
    int MapDxgiToGalTextureFormat(const int dxgiFormat)
    {
      for (const DXGIFormatPair& pair : kTextureDxgiGalPairs) {
        if (pair.dxgi == dxgiFormat) {
          return pair.gal;
        }
      }

      return 20;
    }

    /**
     * Address: 0x00902D90 (FUN_00902D90, func_Fmt_Gal_to_DXGI)
     *
     * What it does:
     * Converts GAL render-target format token to DXGI format token through the
     * recovered 10-entry render-target mapping table.
     */
    int MapGalRenderTargetFormatToDxgi(const int galFormat)
    {
      for (const DXGIFormatPair& pair : kRenderTargetDxgiGalPairs) {
        if (pair.gal == galFormat) {
          return pair.dxgi;
        }
      }

      return 0;
    }

    /**
     * Address: 0x009033D0 (FUN_009033D0)
     *
     * What it does:
     * Converts GAL texture format token to its backing DXGI format token by scanning
     * the recovered 89-entry mapping table.
     */
    int MapGalTextureFormatToDxgi(const int galFormat)
    {
      for (const DXGIFormatPair& pair : kTextureDxgiGalPairs) {
        if (pair.gal == galFormat) {
          return pair.dxgi;
        }
      }

      return 0;
    }

    /**
     * Address: 0x0094B170 (FUN_0094B170)
     *
     * What it does:
     * Maps depth-stencil format token to DXGI format through the recovered
     * `DAT_00D487AC` lookup lane.
     */
    int ResolveDepthStencilFormatToDxgi(const int formatToken) noexcept
    {
      return static_cast<int>(kDepthStencilDxgiByToken[formatToken]);
    }

    /**
     * Address: 0x008FDA10 (FUN_008FDA10)
     *
     * What it does:
     * Resolves the retained signature-effect pass for one vertex format token and
     * writes pass-desc IA signature lanes for input-layout creation.
     */
    void GetVertexInputSignatureOrThrow(
      DeviceD3D10* const device, const int formatToken, D3D10_PASS_DESC* const outPassDesc
    )
    {
      ID3D10Effect* const signatureEffect = device->mSignatureEffect;
      if (signatureEffect == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1910, "internal D3D10 SignatureEffect error");
      }

      ID3D10EffectTechnique* const technique = signatureEffect->GetTechniqueByIndex(static_cast<UINT>(formatToken));
      if (technique == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1913, "invalid format/technique combination");
      }

      static_cast<void>(technique->GetPassByIndex(0U)->GetDesc(outPassDesc));
    }

    /**
     * Address: 0x009040D0 (FUN_009040D0)
     *
     * What it does:
     * Returns byte size per texel/block for recovered GAL texture format IDs.
     */
    unsigned int GetTextureFormatBlockBytes(const unsigned int format)
    {
      switch (format) {
      case 2:
      case 3:
      case 4:
        return 16U;

      case 6:
      case 7:
      case 8:
        return 12U;

      case 10:
      case 11:
      case 12:
      case 13:
      case 14:
      case 16:
      case 17:
      case 18:
        return 8U;

      case 28:
      case 30:
      case 31:
      case 32:
      case 34:
      case 35:
      case 36:
      case 37:
      case 38:
      case 41:
      case 42:
      case 43:
      case 68:
      case 69:
      case 87:
      case 88:
        return 4U;

      case 49:
      case 50:
      case 51:
      case 52:
      case 54:
      case 56:
      case 57:
      case 58:
      case 59:
      case 85:
      case 86:
        return 2U;

      default:
        return 0U;
      }
    }

    /**
     * Address: 0x008FD1B0 (FUN_008FD1B0)
     *
     * What it does:
     * Creates a staging texture copy (`usage=3`, `bind=0`, `cpuAccess=0x20000`) from
     * the source texture and issues a native D3D10 copy-resource from source to staging.
     */
    ID3D10Texture2D* CreateStagingTextureCopyOrThrow(Device* const device, ID3D10Texture2D* const sourceTexture)
    {
      D3D10_TEXTURE2D_DESC textureDesc{};
      sourceTexture->GetDesc(&textureDesc);
      textureDesc.Usage = D3D10_USAGE_STAGING;
      textureDesc.BindFlags = 0U;
      textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

      ID3D10Device* const nativeDevice = static_cast<DeviceD3D10*>(device)->mDevice;
      ID3D10Texture2D* stagingTexture = nullptr;
      const HRESULT createResult = nativeDevice->CreateTexture2D(&textureDesc, nullptr, &stagingTexture);
      if (createResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1635, createResult);
      }

      nativeDevice->CopyResource(stagingTexture, sourceTexture);
      return stagingTexture;
    }

    /**
     * Address: 0x00903E10 (FUN_00903E10)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `TextureD3D10`.
     */
    void DestroyTextureD3D10Body(TextureD3D10* const texture)
    {
      texture->DestroyState();
    }

    /**
     * Address: 0x00902EB0 (FUN_00902EB0)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `RenderTargetD3D10`.
     */
    void DestroyRenderTargetD3D10Body(RenderTargetD3D10* const renderTarget)
    {
      renderTarget->DestroyState();
    }

    /**
     * Address: 0x0094B210 (FUN_0094B210)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `DepthStencilTargetD3D10`.
     */
    void DestroyDepthStencilTargetD3D10Body(DepthStencilTargetD3D10* const depthStencilTarget)
    {
      depthStencilTarget->DestroyState();
    }

    /**
     * Address: 0x00904340 (FUN_00904340)
     *
     * What it does:
     * Validates one vertex-format token and returns the matching static
     * element-layout table pointer.
     */
    const D3D10_INPUT_ELEMENT_DESC* GetVertexLayoutElementsOrThrow(const std::uint32_t format)
    {
      if (format >= 24U) {
        ThrowGalError("VertexFormatD3D10.cpp", 426, "invalid vertex format specified");
      }

      return kVertexLayoutElementsByFormat[format];
    }

    /**
     * Address: 0x00904400 (FUN_00904400)
     *
     * What it does:
     * Validates one vertex-format token and returns the static element count.
     */
    std::uint32_t GetVertexLayoutElementCountOrThrow(const std::uint32_t format)
    {
      if (format >= 24U) {
        ThrowGalError("VertexFormatD3D10.cpp", 432, "invalid vertex format specified");
      }

      return kVertexLayoutElementCountByFormat[format];
    }

    void ReleaseSharedCount(boost::detail::sp_counted_base*& sharedCount) noexcept
    {
      if (sharedCount != nullptr) {
        sharedCount->release();
        sharedCount = nullptr;
      }
    }

    void AssignSharedCount(
      boost::detail::sp_counted_base*& destination, boost::detail::sp_counted_base* const source
    ) noexcept
    {
      if (source != nullptr) {
        source->add_ref_copy();
      }

      ReleaseSharedCount(destination);
      destination = source;
    }

    /**
     * Address: 0x008FAA50 (FUN_008FAA50)
     *
     * What it does:
     * Throws the legacy MSVC vector-length error used by effect-macro vector
     * growth helpers.
     */
    [[noreturn]] void ThrowVectorTooLongLengthErrorA()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x008FAAC0 (FUN_008FAAC0)
     *
     * What it does:
     * Throws the legacy MSVC vector-length error used by effect-macro vector
     * growth helpers.
     */
    [[noreturn]] void ThrowVectorTooLongLengthErrorB()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x008CB6B0 (FUN_008CB6B0)
     *
     * IDA signature:
     * void __noreturn sub_8CB6B0();
     *
     * What it does:
     * Throws the legacy MSVC `std::out_of_range("invalid vector<T> subscript")`
     * used by bounds-checked `operator[]` instantiations for the D3D device
     * caps / adapter-mode / antialiasing-option vectors.
     */
    [[noreturn]] void ThrowVectorSubscriptOutOfRange()
    {
      throw std::out_of_range("invalid vector<T> subscript");
    }

    /**
     * Address: 0x008F8CA0 (FUN_008F8CA0)
     *
     * What it does:
     * Returns one stable, process-lifetime zero-initialized wide-character
     * storage lane used by legacy helper paths.
     */
    wchar_t* GetLegacyWideZeroStorageLane() noexcept
    {
      static wchar_t sLegacyWideZeroStorage = L'\0';
      return &sLegacyWideZeroStorage;
    }

    /**
     * Address: 0x008F9920 (FUN_008F9920)
     *
     * What it does:
     * Clone entry that returns the same stable process-lifetime wide-zero
     * storage lane as `FUN_008F8CA0`.
     */
    wchar_t* GetLegacyWideZeroStorageLaneCloneA() noexcept
    {
      return GetLegacyWideZeroStorageLane();
    }

    struct RuntimeProxyVectorLane final
    {
      void* proxy = nullptr;          // +0x00
      std::uint8_t* first = nullptr;  // +0x04
      std::uint8_t* last = nullptr;   // +0x08
      std::uint8_t* end = nullptr;    // +0x0C
    };
    static_assert(sizeof(RuntimeProxyVectorLane) == 0x10, "RuntimeProxyVectorLane size must be 0x10");

    using RuntimeProxyVectorThrowFn = void (*)();
    using RuntimeProxyVectorAllocateFn = void* (*)(std::uint32_t);

    bool TryInitializeRuntimeProxyVectorLane(
      RuntimeProxyVectorLane* const lane,
      const std::uint32_t elementCount,
      const std::uint32_t maxElementCount,
      const std::uint32_t elementStrideBytes,
      RuntimeProxyVectorThrowFn throwTooLong,
      RuntimeProxyVectorAllocateFn allocateStorage
    )
    {
      lane->first = nullptr;
      lane->last = nullptr;
      lane->end = nullptr;

      if (elementCount == 0U) {
        return false;
      }

      if (elementCount > maxElementCount) {
        throwTooLong();
      }

      auto* const storage = static_cast<std::uint8_t*>(allocateStorage(elementCount));
      lane->first = storage;
      lane->last = storage;
      lane->end = storage + (static_cast<std::size_t>(elementStrideBytes) * static_cast<std::size_t>(elementCount));
      return true;
    }

    /**
     * Address: 0x008FDFC0 (FUN_008FDFC0)
     *
     * What it does:
     * Clears one proxy-vector lane and reserves `count` 4-byte entries with
     * legacy VC8 vector-length overflow semantics.
     */
    bool TryInitializeDwordProxyVectorLane(
      RuntimeProxyVectorLane* const lane,
      const std::uint32_t elementCount
    )
    {
      return TryInitializeRuntimeProxyVectorLane(
        lane,
        elementCount,
        0x3FFFFFFFU,
        0x04U,
        ThrowVectorTooLongLengthErrorB,
        AllocateStride04Array
      );
    }

  } // namespace

  /**
   * Address: 0x008F7AC0 (FUN_008F7AC0)
   *
   * IDXGIAdapter *
   *
   * What it does:
   * Initializes one adapter wrapper from one DXGI adapter pointer and captures
   * the adapter descriptor payload.
   */
  AdapterD3D10::AdapterD3D10(IDXGIAdapter* const dxgiAdapter)
    : dxgiAdapter_(dxgiAdapter)
    , description_()
    , modes_()
  {
    if (dxgiAdapter_ != nullptr) {
      static_cast<void>(dxgiAdapter_->GetDesc(&description_));
    }
  }

  /**
   * Address: 0x008FF450 (FUN_008FF450)
   *
   * What it does:
   * Copy-constructs one adapter wrapper by cloning descriptor payload and
   * deep-copying cached mode vectors from `other`.
   */
  AdapterD3D10::AdapterD3D10(const AdapterD3D10& other)
    : dxgiAdapter_(other.dxgiAdapter_)
    , description_(other.description_)
    , modes_(other.modes_)
  {}

  /**
   * Address: 0x008FF2F0 (FUN_008FF2F0)
   *
   * What it does:
   * Copy-assigns adapter pointer/descriptor lanes and deep-copies the cached
   * mode-vector lane from `other`.
   */
  AdapterD3D10& AdapterD3D10::operator=(const AdapterD3D10& other)
  {
    dxgiAdapter_ = other.dxgiAdapter_;
    description_ = other.description_;
    modes_ = other.modes_;
    return *this;
  }

  /**
   * Address: 0x008F7CF0 (FUN_008F7CF0, sub_8F7CF0)
   *
   * What it does:
   * Enumerates outputs and cached display-mode lists for the recovered DXGI
   * format probe set into the local mode cache.
   */
  int AdapterD3D10::ProbeOutputsAndModes()
  {
    IDXGIOutput* output = nullptr;
    const HRESULT result = dxgiAdapter_->EnumOutputs(0U, &output);
    if (result == DXGI_ERROR_NOT_FOUND) {
      return 0;
    }

    if (result >= 0) {
      // One entry per probe, built before the format loop and appended once
      // after it (0x008F7D8C-0x008F7DA2 sets it up, 0x008F7E85 pushes it).
      // `format_` is left at zero here — the binary never writes the probed
      // format into the entry; the entry describes the *output*, and every
      // format's modes accumulate into its single `modes_` lane.
      AdapterModeD3D10 modeEntry{};
      static_cast<void>(InitializeAdapterModeEntry(&modeEntry, 0U, output));

      for (const DXGI_FORMAT format : kAdapterProbeFormats) {
        UINT modeCount = 0U;
        if (output->GetDisplayModeList(format, 0U, &modeCount, nullptr) == DXGI_ERROR_NOT_FOUND) {
          break;
        }

        // The scratch buffer is allocated unconditionally on the count
        // result (0x008F7DFD-0x008F7E0C, including the `modeCount == 0`
        // case) and released before the next format probe; only the second
        // GetDisplayModeList's HRESULT gates the append loop (0x008F7E2A).
        auto* const scratch =
          static_cast<DXGI_MODE_DESC*>(::operator new(static_cast<std::size_t>(modeCount) * sizeof(DXGI_MODE_DESC)));
        if (output->GetDisplayModeList(format, 0U, &modeCount, scratch) >= 0) {
          for (UINT modeIndex = 0U; modeIndex < modeCount; ++modeIndex) {
            modeEntry.modes_.push_back(scratch[modeIndex]);
          }
        }
        ::operator delete[](scratch);
      }

      modes_.push_back(modeEntry);
    }

    return result;
  }

  /**
   * Address: 0x008F7BF0 (FUN_008F7BF0)
   *
   * What it does:
   * Owns the scalar-deleting destructor path for adapter wrappers and tears
   * down retained adapter-mode heap storage.
   */
  AdapterD3D10::~AdapterD3D10()
  {
    ReleaseAdapterOutputAndDeviceRefs(this);
    // Each entry's inner mode vector goes with the outer one; both are real
    // containers, so `modes_ = {}` is the whole teardown (0x008F76C0).
    modes_ = msvc8::vector<AdapterModeD3D10>{};
  }

  /**
   * Address: 0x00902CA0 (FUN_00902CA0)
   *
   * ID3D10Device *
   *
   * What it does:
   * Initializes one pipeline-state bundle from a native D3D10 device and
   * builds both recovered startup state packs.
   */
  PipelineStateD3D10::PipelineStateD3D10(ID3D10Device* const device)
    : device_(device)
    , samplerFilterToken_(15U)
    , rasterizerState1_(nullptr)
    , depthStencilState1_(nullptr)
    , blendState1_(nullptr)
    , samplerState1_(nullptr)
    , rasterizerState2_(nullptr)
    , depthStencilState2_(nullptr)
    , blendState2_(nullptr)
  {
    if (device_ != nullptr) {
      device_->AddRef();
    }
    CreateState1();
    CreateState2();
  }

  namespace
  {
    /**
     * The blend state both packs create (0x0090282B, 0x00902C0B): no
     * blending, colour writes on render target 0 only.
     */
    [[nodiscard]] D3D10_BLEND_DESC OpaqueBlendDesc()
    {
      D3D10_BLEND_DESC blendDesc{};
      blendDesc.AlphaToCoverageEnable = FALSE;
      blendDesc.SrcBlend = D3D10_BLEND_ONE;
      blendDesc.DestBlend = D3D10_BLEND_ZERO;
      blendDesc.BlendOp = D3D10_BLEND_OP_ADD;
      blendDesc.SrcBlendAlpha = D3D10_BLEND_ONE;
      blendDesc.DestBlendAlpha = D3D10_BLEND_ZERO;
      blendDesc.BlendOpAlpha = D3D10_BLEND_OP_ADD;
      blendDesc.RenderTargetWriteMask[0] = D3D10_COLOR_WRITE_ENABLE_ALL;
      return blendDesc;
    }

    /**
     * The depth-stencil state both packs create, differing only in
     * `depthFunc`: depth test and writes on, stencil off with zero masks.
     */
    [[nodiscard]] D3D10_DEPTH_STENCIL_DESC DepthWriteDesc(const D3D10_COMPARISON_FUNC depthFunc)
    {
      D3D10_DEPTH_STENCIL_DESC depthStencilDesc{};
      depthStencilDesc.DepthEnable = TRUE;
      depthStencilDesc.DepthWriteMask = D3D10_DEPTH_WRITE_MASK_ALL;
      depthStencilDesc.DepthFunc = depthFunc;
      depthStencilDesc.StencilEnable = FALSE;
      depthStencilDesc.StencilReadMask = 0U;
      depthStencilDesc.StencilWriteMask = 0U;
      depthStencilDesc.FrontFace.StencilFailOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilDepthFailOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilPassOp = D3D10_STENCIL_OP_KEEP;
      depthStencilDesc.FrontFace.StencilFunc = D3D10_COMPARISON_ALWAYS;
      depthStencilDesc.BackFace = depthStencilDesc.FrontFace;
      return depthStencilDesc;
    }
  } // namespace

  /**
   * Address: 0x009024F0 (FUN_009024F0)
   *
   * What it does:
   * Creates the pack `SetDeviceState` binds at start-up: solid, no culling,
   * counter-clockwise front faces, no depth clipping; depth writes with an
   * ALWAYS test; opaque blending; and a linear-min/mag, point-mip wrapping
   * sampler (MaxAnisotropy 1, ALWAYS comparison, black border, full LOD
   * range).
   */
  void PipelineStateD3D10::CreateState1()
  {
    D3D10_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D10_FILL_SOLID;
    rasterizerDesc.CullMode = D3D10_CULL_NONE;
    rasterizerDesc.FrontCounterClockwise = TRUE;
    rasterizerDesc.DepthBias = 0;
    rasterizerDesc.DepthBiasClamp = 0.0f;
    rasterizerDesc.SlopeScaledDepthBias = 0.0f;
    rasterizerDesc.DepthClipEnable = FALSE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState1_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(248, createRasterizerResult);
    }

    const D3D10_DEPTH_STENCIL_DESC depthStencilDesc = DepthWriteDesc(D3D10_COMPARISON_ALWAYS);
    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState1_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(251, createDepthStencilResult);
    }

    const D3D10_BLEND_DESC blendDesc = OpaqueBlendDesc();
    const HRESULT createBlendResult = device_->CreateBlendState(&blendDesc, &blendState1_);
    if (createBlendResult < 0) {
      ThrowPipelineStateD3D10Hresult(254, createBlendResult);
    }

    D3D10_SAMPLER_DESC samplerDesc{};
    samplerDesc.Filter = D3D10_FILTER_MIN_MAG_LINEAR_MIP_POINT;
    samplerDesc.AddressU = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressV = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressW = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.MipLODBias = 0.0f;
    samplerDesc.MaxAnisotropy = 1U;
    samplerDesc.ComparisonFunc = D3D10_COMPARISON_ALWAYS;
    samplerDesc.MinLOD = 0.0f;
    samplerDesc.MaxLOD = D3D10_FLOAT32_MAX;

    const HRESULT createSamplerResult = device_->CreateSamplerState(&samplerDesc, &samplerState1_);
    if (createSamplerResult < 0) {
      ThrowPipelineStateD3D10Hresult(257, createSamplerResult);
    }
  }

  /**
   * Address: 0x00902940 (FUN_00902940)
   *
   * What it does:
   * Creates the pack every effect technique begins with (`BeginTechnique`):
   * solid, back faces culled with clockwise fronts, no depth clipping; depth
   * writes with a LESS_EQUAL test; opaque blending.
   */
  void PipelineStateD3D10::CreateState2()
  {
    D3D10_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D10_FILL_SOLID;
    rasterizerDesc.CullMode = D3D10_CULL_BACK;
    rasterizerDesc.FrontCounterClockwise = FALSE;
    rasterizerDesc.DepthBias = 0;
    rasterizerDesc.DepthBiasClamp = 0.0f;
    rasterizerDesc.SlopeScaledDepthBias = 0.0f;
    rasterizerDesc.DepthClipEnable = FALSE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState2_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(321, createRasterizerResult);
    }

    const D3D10_DEPTH_STENCIL_DESC depthStencilDesc = DepthWriteDesc(D3D10_COMPARISON_LESS_EQUAL);
    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState2_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(324, createDepthStencilResult);
    }

    const D3D10_BLEND_DESC blendDesc = OpaqueBlendDesc();
    const HRESULT createBlendResult = device_->CreateBlendState(&blendDesc, &blendState2_);
    if (createBlendResult < 0) {
      ThrowPipelineStateD3D10Hresult(327, createBlendResult);
    }
  }

  /**
   * Address: 0x00902250 (FUN_00902250)
   *
   * What it does:
   * Applies the primary recovered pipeline-state pack onto the native
   * D3D10 device.
   */
  void PipelineStateD3D10::SetDeviceState()
  {
    device_->RSSetState(rasterizerState1_);
    device_->OMSetDepthStencilState(depthStencilState1_, 0U);
    device_->OMSetBlendState(blendState1_, nullptr, 0xFFFFFFFFU);

    ID3D10SamplerState* samplerState = samplerState1_;
    for (UINT slot = 0U; slot < 16U; ++slot) {
      device_->PSSetSamplers(slot, 1U, &samplerState);
    }
  }

  /**
   * Address: 0x009022E0 (FUN_009022E0)
   *
   * What it does:
   * Unbinds all 128 pixel-shader resource slots, one call per slot. Formerly
   * the free `ClearAllTextureShaderResourceSlots`, which returned the last
   * call's value - `PSSetShaderResources` returns nothing.
   */
  void PipelineStateD3D10::ClearTextures()
  {
    ID3D10ShaderResourceView* const noView = nullptr;
    for (UINT slot = 0U; slot < D3D10_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT; ++slot) {
      device_->PSSetShaderResources(slot, 1U, &noView);
    }
  }

  /**
   * Address: 0x00902320 (FUN_00902320)
   *
   * What it does:
   * Binds the secondary state pack. Formerly the free
   * `ApplyTechniqueStateBindings` over three hand-indexed vtable calls.
   */
  void PipelineStateD3D10::BeginTechnique()
  {
    device_->RSSetState(rasterizerState2_);
    device_->OMSetDepthStencilState(depthStencilState2_, 0U);
    device_->OMSetBlendState(blendState2_, nullptr, 0xFFFFFFFFU);
  }

  /**
   * Address: 0x00902360 (FUN_00902360)
   *
   * What it does:
   * Nothing. Formerly `nullsub_3640`.
   */
  void PipelineStateD3D10::EndTechnique() {}

  /**
   * Address: 0x009023F0 (FUN_009023F0)
   * Address: 0x009024D0 (FUN_009024D0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device and both state packs, then the `PipelineState` base
   * destructor runs (inlined, 0x009024B0).
   */
  PipelineStateD3D10::~PipelineStateD3D10()
  {
    SafeRelease(device_);
    SafeRelease(rasterizerState1_);
    SafeRelease(depthStencilState1_);
    SafeRelease(blendState1_);
    SafeRelease(samplerState1_);
    SafeRelease(rasterizerState2_);
    SafeRelease(depthStencilState2_);
    SafeRelease(blendState2_);
  }

  /**
   * Address: 0x0094D4F0 (FUN_0094D4F0, ??0HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes one D3D10 hardware-vertex formatter wrapper.
   */
  HardwareVertexFormatterD3D10::HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D500 (FUN_0094D500)
   * Address: 0x0094D8F0 (FUN_0094D8F0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
   */
  HardwareVertexFormatterD3D10::~HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D510 (FUN_0094D510)
   *
   * What it does:
   * Returns the active device context's hardware-instancing flag. Unlike the
   * D3D9 formatters it ignores the `mesh_Rebatch` switches.
   */
  bool HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    return Device::GetInstance()->GetDeviceContext()->mHWBasedInstancing;
  }

  /**
   * Address: 0x0094D960 (FUN_0094D960)
   *
   * What it does:
   * Creates vertex format 14 on the active device (slot 14, `[vtbl+0x38]`).
   */
  boost::shared_ptr<VertexFormat> HardwareVertexFormatterD3D10::CreateVertexFormat(const std::int32_t layoutVariant)
  {
    static_cast<void>(layoutVariant);
    return Device::GetInstance()->CreateVertexFormat(kHardwareVertexFormatToken);
  }

  /**
   * Address: 0x0094D530 (FUN_0094D530)
   *
   * What it does:
   * Returns packed hardware-vertex stride for the requested stream class.
   */
  std::uint32_t HardwareVertexFormatterD3D10::GetVertexStride(
    const std::int32_t streamClass,
    const std::int32_t sizeVariant
  )
  {
    static_cast<void>(sizeVariant);
    return kHardwareVertexStrideBase + ((streamClass != 0) ? 4U : 0U);
  }

  /**
   * Address: 0x0094D550 (FUN_0094D550)
   *
   * What it does:
   * Packs one mesh vertex into vertex format 14: the geometry record for
   * stream class 0 (position with w = 1), the instance record otherwise.
   */
  void HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const MeshVertex& source,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(writeVariant);

    if (streamClass != 0) {
      auto& destination = *static_cast<HardwareVertexInstance*>(destinationVertex);
      destination.instanceIndex = source.instanceIndex;
      destination.color = source.color;
      destination.shaderTime = source.shaderTime;
      static_cast<void>(CopyMatrix4x3Rows(
        destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
        source.transform
      ));
      destination.bonePaletteBase = source.bonePaletteBase;
      destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
      destination.scroll[0] = source.scroll[0];
      destination.scroll[1] = source.scroll[1];
      destination.dissolve = source.dissolve;
      destination.parameter = source.parameter;
      destination.meshColor = source.meshColor;
      return;
    }

    auto& destination = *static_cast<HardwareVertex*>(destinationVertex);
    destination.boneIndices[0] = source.boneIndices[0];
    destination.boneIndices[1] = source.boneIndices[1];
    destination.boneIndices[2] = source.boneIndices[2];
    destination.boneIndices[3] = source.boneIndices[3];
    destination.position[0] = source.position[0];
    destination.position[1] = source.position[1];
    destination.position[2] = source.position[2];
    destination.position[3] = 1.0f;
    destination.normal[0] = source.normal[0];
    destination.normal[1] = source.normal[1];
    destination.normal[2] = source.normal[2];
    destination.binormal[0] = source.binormal[0];
    destination.binormal[1] = source.binormal[1];
    destination.binormal[2] = source.binormal[2];
    destination.tangent[0] = source.tangent[0];
    destination.tangent[1] = source.tangent[1];
    destination.tangent[2] = source.tangent[2];
    destination.texCoords[0] = source.texCoord0[0];
    destination.texCoords[1] = source.texCoord0[1];
    destination.texCoords[2] = source.texCoord1[0];
    destination.texCoords[3] = source.texCoord1[1];
  }

  /**
   * Address: 0x0094D770 (FUN_0094D770, ??0Float16HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes one D3D10 float16 hardware-vertex formatter wrapper.
   */
  Float16HardwareVertexFormatterD3D10::Float16HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D780 (FUN_0094D780)
   * Address: 0x0094D910 (FUN_0094D910, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Nothing of its own; reinstalls the base `MeshFormatter` vtable.
   */
  Float16HardwareVertexFormatterD3D10::~Float16HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x0094D790 (FUN_0094D790)
   *
   * What it does:
   * Needs both of the active device context's flags, hardware instancing
   * (+0x11) and float16 (+0x12); ignores the `mesh_Rebatch` switches.
   */
  bool Float16HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    const DeviceContext* const context = Device::GetInstance()->GetDeviceContext();
    return context->mHWBasedInstancing && context->mSupportsFloat16;
  }

  /**
   * Address: 0x0094D930 (FUN_0094D930)
   *
   * What it does:
   * Creates vertex format 15 on the active device. Unlike the D3D9 float16
   * formatter it never picks 16: `layoutVariant` is ignored.
   */
  boost::shared_ptr<VertexFormat> Float16HardwareVertexFormatterD3D10::CreateVertexFormat(
    const std::int32_t layoutVariant
  )
  {
    static_cast<void>(layoutVariant);
    return Device::GetInstance()->CreateVertexFormat(kFloat16VertexFormatToken);
  }

  /**
   * Address: 0x0094D7C0 (FUN_0094D7C0)
   *
   * What it does:
   * Returns float16 packed stride for the requested stream class.
   */
  std::uint32_t Float16HardwareVertexFormatterD3D10::GetVertexStride(
    const std::int32_t streamClass,
    const std::int32_t sizeVariant
  )
  {
    static_cast<void>(sizeVariant);
    return (streamClass != 0) ? kFloat16VertexStrideStream1 : kFloat16VertexStrideStream0;
  }

  /**
   * Address: 0x0094D7E0 (FUN_0094D7E0)
   *
   * What it does:
   * Packs the instance half of one mesh vertex into the format 15 instance
   * record (half-precision scalars). The body never looks at `streamClass`
   * or `writeVariant` - the D3D10 float16 formatter only ever writes the
   * instance stream.
   */
  void Float16HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const MeshVertex& source,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(streamClass);
    static_cast<void>(writeVariant);

    auto& destination = *static_cast<Float16HardwareVertexInstance*>(destinationVertex);
    destination.instanceIndex = source.instanceIndex;
    destination.color = source.color;
    D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.shaderTime), &source.shaderTime, 1U);
    static_cast<void>(CopyMatrix4x3Rows(
      destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
      source.transform
    ));
    destination.bonePaletteBase = source.bonePaletteBase;
    destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
    D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.scroll[1]), &source.scroll[1], 1U);
    D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.scroll[0]), &source.scroll[0], 1U);
    destination.dissolve = source.dissolve;
    D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.parameter), &source.parameter, 1U);
    destination.meshColor = source.meshColor;
  }

  /**
   * Address: 0x00902D20 (FUN_00902D20, ??0RenderTargetD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Initializes default render-target context lanes and null resource pointers.
   */
  RenderTargetD3D10::RenderTargetD3D10()
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
  }

  /**
   * Address: 0x00902FE0 (FUN_00902FE0)
   *
   * void *,void *,void *
   *
   * What it does:
   * Initializes one render-target wrapper from retained texture/view pointers and
   * derives context width/height/format from the source texture descriptor.
   */
  RenderTargetD3D10::RenderTargetD3D10(
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    InitializeFromResource(renderTexture, renderTargetView, shaderResourceView);
  }

  /**
   * Address: 0x00903050 (FUN_00903050)
   *
   * RenderTargetContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one render-target wrapper from caller-provided context metadata and
   * retained texture/view pointers.
   */
  RenderTargetD3D10::RenderTargetD3D10(
    const RenderTargetContext* const context,
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , renderTexture_(nullptr)
    , renderTargetView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    DestroyState();
    context_.width_ = context->width_;
    context_.height_ = context->height_;
    context_.format_ = context->format_;
    renderTexture_ = renderTexture;
    renderTargetView_ = renderTargetView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x00902F10 (FUN_00902F10)
   *
   * void *,void *,void *
   *
   * What it does:
   * Reinitializes state from retained texture/view pointers and rebuilds context
   * width/height/format from texture descriptor lanes.
   */
  void RenderTargetD3D10::InitializeFromResource(
    ID3D10Texture2D* const renderTexture,
    ID3D10RenderTargetView* const renderTargetView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
  {
    DestroyState();

    D3D10_TEXTURE2D_DESC textureDesc{};
    renderTexture->GetDesc(&textureDesc);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalRenderTargetFormat(static_cast<int>(textureDesc.Format)));
    context_.width_ = textureDesc.Width;
    context_.height_ = textureDesc.Height;

    renderTexture_ = renderTexture;
    renderTargetView_ = renderTargetView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x009030E0 (FUN_009030E0)
   *
   * What it does:
   * Validates and returns the retained render-texture lane.
   */
  ID3D10Texture2D* RenderTargetD3D10::GetRenderTextureOrThrow()
  {
    if (renderTexture_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 100, "invalid render target");
    }

    return renderTexture_;
  }

  /**
   * Address: 0x00902FC0 (FUN_00902FC0)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_00902EB0`.
   */
  RenderTargetD3D10::~RenderTargetD3D10()
  {
    DestroyRenderTargetD3D10Body(this);
  }

  /**
   * Address: 0x00902D80 (FUN_00902D80)
   *
   * What it does:
   * Returns the embedded render-target context lane at `this+0x04`.
   */
  RenderTargetContext* RenderTargetD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00902D70 (FUN_00902D70)
   *
   * What it does:
   * D3D10 has no GDI-compatible surface to hand out (`xor eax,eax; ret`).
   */
  HDC RenderTargetD3D10::GetDC()
  {
    return nullptr;
  }

  /**
   * Address: 0x00902E30 (FUN_00902E30)
   *
   * What it does:
   * Releases retained D3D10 resource/view pointers and resets context lanes.
   */
  void RenderTargetD3D10::DestroyState()
  {
    SafeRelease(renderTexture_);
    SafeRelease(renderTargetView_);
    SafeRelease(shaderResourceView_);

    const RenderTargetContext resetContext{};
    context_.width_ = resetContext.width_;
    context_.height_ = resetContext.height_;
    context_.format_ = resetContext.format_;
  }

  /**
   * Address: 0x00903190 (FUN_00903190)
   *
   * What it does:
   * Validates and returns the retained render-target-view lane.
   */
  ID3D10RenderTargetView* RenderTargetD3D10::GetRenderTargetViewOrThrow()
  {
    if (renderTargetView_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 106, "invalid render target view");
    }

    return renderTargetView_;
  }

  /**
   * Address: 0x00903240 (FUN_00903240)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* RenderTargetD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("RenderTargetD3D10.cpp", 112, "invalid shader resource view");
    }

    return shaderResourceView_;
  }

  /**
   * Address: 0x008F7F30 (FUN_008F7F30)
   *
   * IDA signature:
   * char *__thiscall CubeRenderTargetD3D10::CubeRenderTargetD3D10(CubeRenderTargetD3D10 *this@<ecx>);
   *
   * What it does:
   * Default-initializes one `CubeRenderTargetD3D10` wrapper: applies its
   * vftable at `this+0x00` and default-constructs the embedded
   * `CubeRenderTargetContext` at `this+0x04`.
   */
  CubeRenderTargetD3D10::CubeRenderTargetD3D10()
    : context_()
  {
  }

  /**
   * Address: 0x008F7F80 (FUN_008F7F80)
   *
   * CubeRenderTargetContext const *
   *
   * What it does:
   * Initializes one cube-render-target wrapper and default-constructs context lane.
   */
  CubeRenderTargetD3D10::CubeRenderTargetD3D10(const CubeRenderTargetContext* const context)
    : context_()
  {
    static_cast<void>(context);
  }

  /**
   * Address: 0x008F8030 (FUN_008F8030)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates non-deleting body lanes.
   */
  CubeRenderTargetD3D10::~CubeRenderTargetD3D10() = default;

  /**
   * Address: 0x008F8020 (FUN_008F8020)
   *
   * What it does:
   * Returns the embedded cube-render-target context lane at `this+0x04`.
   */
  CubeRenderTargetContext* CubeRenderTargetD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094B100 (FUN_0094B100, DepthStencilTargetD3D10 default-state init lane)
   *
   * What it does:
   * Initializes one D3D10 depth-stencil target object to default context
   * values and null retained texture/view lanes.
   */
  [[nodiscard]] DepthStencilTargetD3D10* InitializeDepthStencilTargetD3D10DefaultState(
    DepthStencilTargetD3D10* const target
  )
  {
    target->context_ = DepthStencilTargetContext{};
    target->depthStencilTexture_ = nullptr;
    target->depthStencilView_ = nullptr;
    target->shaderResourceView_ = nullptr;
    return target;
  }

  /**
   * Address: 0x0094B2D0 (FUN_0094B2D0)
   *
   * DepthStencilTargetContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 depth-stencil wrapper from context + texture/DSV/SRV lanes.
   */
  DepthStencilTargetD3D10::DepthStencilTargetD3D10(
    const DepthStencilTargetContext* const context,
    ID3D10Texture2D* const depthStencilTexture,
    ID3D10DepthStencilView* const depthStencilView,
    ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , depthStencilTexture_(nullptr)
    , depthStencilView_(nullptr)
    , shaderResourceView_(nullptr)
  {
    (void)InitializeDepthStencilTargetD3D10DefaultState(this);
    DestroyState();
    context_.width_ = context->width_;
    context_.height_ = context->height_;
    context_.format_ = context->format_;
    context_.field0x10_ = context->field0x10_;
    depthStencilTexture_ = depthStencilTexture;
    depthStencilView_ = depthStencilView;
    shaderResourceView_ = shaderResourceView;
  }

  /**
   * Address: 0x0094B2B0 (FUN_0094B2B0)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_0094B210`.
   */
  DepthStencilTargetD3D10::~DepthStencilTargetD3D10()
  {
    DestroyDepthStencilTargetD3D10Body(this);
  }

  /**
   * Address: 0x0094B160 (FUN_0094B160)
   *
   * What it does:
   * Returns the embedded depth-stencil context lane at `this+0x04`.
   */
  DepthStencilTargetContext* DepthStencilTargetD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094B1A0 (FUN_0094B1A0)
   *
   * What it does:
   * Releases retained depth-stencil texture/view pointers and resets context lanes.
   */
  void DepthStencilTargetD3D10::DestroyState()
  {
    SafeRelease(depthStencilTexture_);
    SafeRelease(depthStencilView_);

    const DepthStencilTargetContext resetContext{};
    context_.width_ = resetContext.width_;
    context_.height_ = resetContext.height_;
    context_.format_ = resetContext.format_;
    context_.field0x10_ = resetContext.field0x10_;
  }

  /**
   * Address: 0x0094B370 (FUN_0094B370)
   *
   * What it does:
   * Validates and returns the retained depth-stencil-texture lane.
   */
  ID3D10Texture2D* DepthStencilTargetD3D10::GetDepthStencilTextureOrThrow()
  {
    if (depthStencilTexture_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 70, "invalid depth stencil texture");
    }

    return depthStencilTexture_;
  }

  /**
   * Address: 0x0094B420 (FUN_0094B420)
   *
   * What it does:
   * Validates and returns the retained depth-stencil-view lane.
   */
  ID3D10DepthStencilView* DepthStencilTargetD3D10::GetDepthStencilViewOrThrow()
  {
    if (depthStencilView_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 76, "invalid depth stencil view");
    }

    return depthStencilView_;
  }

  /**
   * Address: 0x0094B4D0 (FUN_0094B4D0)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* DepthStencilTargetD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("DepthStencilTargetD3D10.cpp", 82, "invalid shader resource view");
    }

    return shaderResourceView_;
  }

  /**
   * Address: 0x00903310 (FUN_00903310)
   *
   * What it does:
   * Initializes vtable/context lanes and clears retained texture lock/state members.
   */
  TextureD3D10::TextureD3D10()
    : context_()
    , texture_(nullptr)
    , stagingTexture_(nullptr)
    , shaderResourceView_(nullptr)
    , lockActive_(false)
    , lockPadding_{}
    , lockLevel_(0)
    , lockHistory_(nullptr)
    , contextFormatBackup_(0)
  {}

  /**
   * Address: 0x00904050 (FUN_00904050)
   *
   * TextureContext const *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 texture wrapper from caller context + retained texture/SRV
   * handles, then rebuilds mip/format-dependent lock state.
   */
  TextureD3D10::TextureD3D10(
    const TextureContext* const context, ID3D10Texture2D* const texture, ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , texture_(nullptr)
    , stagingTexture_(nullptr)
    , shaderResourceView_(nullptr)
    , lockActive_(false)
    , lockPadding_{}
    , lockLevel_(0)
    , lockHistory_(nullptr)
    , contextFormatBackup_(0)
  {
    InitializeState(context, texture, shaderResourceView);
  }

  /**
   * Address: 0x00904030 (FUN_00904030)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_00903E10`.
   */
  TextureD3D10::~TextureD3D10()
  {
    DestroyTextureD3D10Body(this);
  }

  /**
   * Address: 0x00903370 (FUN_00903370)
   *
   * What it does:
   * Returns the embedded texture-context lane at `this+0x04`.
   */
  TextureContext* TextureD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00903410 (FUN_00903410)
   *
   * What it does:
   * Maps one texture level and returns the mapping, also recorded in
   * `lockHistory_[level]`. D3D10 maps whole levels, so the rect is unused; a
   * read-only lock of a texture without CPU read access goes through a
   * staging copy.
   */
  TextureLockRect TextureD3D10::Lock(const int level, const RECT& rect, const int flags)
  {
    static_cast<void>(rect);

    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 59, "attempt to map invalid texture");
    }

    ID3D10Texture2D* const lockedTexture = texture_;

    if (level >= static_cast<int>(context_.mipmapLevels_)) {
      ThrowGalError("TextureD3D10.cpp", 60, "attempt to map invalid texture level");
    }

    if (lockActive_) {
      ThrowGalError("TextureD3D10.cpp", 61, "texture map/unmap mismatch");
    }

    if (stagingTexture_ != nullptr) {
      ThrowGalError("TextureD3D10.cpp", 62, "");
    }

    TextureLockRect lock{};
    lock.flags = flags;
    lock.level = level;

    D3D10_MAP mapMode = D3D10_MAP_WRITE_DISCARD;
    ID3D10Texture2D* mapTexture = lockedTexture;
    if (((flags & 1) == 0) && ((flags & 2) != 0)) {
      mapMode = D3D10_MAP_READ;

      D3D10_TEXTURE2D_DESC textureDesc{};
      lockedTexture->GetDesc(&textureDesc);
      if ((textureDesc.CPUAccessFlags & 0x20000U) == 0U) {
        Device* const device = Device::GetInstance();
        stagingTexture_ = CreateStagingTextureCopyOrThrow(device, lockedTexture);
        mapTexture = stagingTexture_;
      }
    }

    D3D10_MAPPED_TEXTURE2D mapped{};
    const HRESULT mapResult = mapTexture->Map(static_cast<UINT>(level), mapMode, 0U, &mapped);
    if (mapResult < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 96, mapResult);
    }

    lock.pitch = static_cast<int>(mapped.RowPitch);
    lock.bits = mapped.pData;
    lockHistory_[level] = lock;
    return lock;
  }

  /**
   * Address: 0x00903700 (FUN_00903700)
   *
   * What it does:
   * Unmaps one texture level and clears lock-tracking state lanes.
   */
  int TextureD3D10::Unlock(const int level)
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 137, "attempt to map invalid texture");
    }

    if (level >= static_cast<int>(context_.mipmapLevels_)) {
      ThrowGalError("TextureD3D10.cpp", 138, "attempt to map invalid texture level");
    }

    if (lockActive_) {
      ThrowGalError("TextureD3D10.cpp", 139, "texture map/unmap mismatch");
    }

    if (stagingTexture_ != nullptr) {
      stagingTexture_->Unmap(static_cast<UINT>(level));
    } else {
      texture_->Unmap(static_cast<UINT>(level));
    }

    // The binary returns what the staging copy's Release returned (or the null
    // pointer when there was none) and clears the lock state after it.
    int releaseResult = 0;
    if (stagingTexture_ != nullptr) {
      releaseResult = static_cast<int>(stagingTexture_->Release());
      stagingTexture_ = nullptr;
    }
    lockActive_ = false;
    lockLevel_ = 0;
    return releaseResult;
  }

  /**
   * Address: 0x00903390 (FUN_00903390)
   *
   * What it does:
   * Releases one mapping by unlocking its level - a virtual call to slot 3
   * (`mov eax,[ecx]; call [eax+0xC]`), `ret 0x10` for the by-value rect.
   */
  int TextureD3D10::Unlock(const TextureLockRect lock)
  {
    return Unlock(lock.level);
  }

  /**
   * Address: 0x009038D0 (FUN_009038D0)
   *
   * What it does:
   * Serializes texture bytes into the caller-provided memory buffer.
   */
  void TextureD3D10::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 172, "attempt to unlock invalid texture");
    }

    ID3D10Texture2D* const texture = texture_;

    auto* const device = static_cast<DeviceD3D10*>(Device::GetInstance());

    // An empty blob made first and released last; the encoded one below is
    // never released (the binary leaks it).
    ID3D10Blob* scratchBlob = nullptr;
    HRESULT result = device->CreateBlob(0U, &scratchBlob);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 177, result);
    }

    ID3D10Blob* encodedBlob = nullptr;
    result = device->SaveTextureToMemory(texture, D3DX10_IFF_DDS, &encodedBlob);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 178, result);
    }

    const unsigned int encodedSize = static_cast<unsigned int>(encodedBlob->GetBufferSize());
    if (outBuffer->Size() != encodedSize) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(encodedSize);
      *outBuffer = resizedBuffer;
    }

    std::memcpy(outBuffer->GetPtr(0U, 0U), encodedBlob->GetBufferPointer(), encodedSize);

    SafeRelease(scratchBlob);
  }

  /**
   * Address: 0x00903BE0 (FUN_00903BE0)
   *
   * What it does:
   * Validates and returns the retained texture lane.
   */
  ID3D10Texture2D* TextureD3D10::GetTextureOrThrow()
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 224, "invalid texture");
    }

    return texture_;
  }

  /**
   * Address: 0x00903CA0 (FUN_00903CA0)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* TextureD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 230, "invalid shader resource view");
    }

    return shaderResourceView_;
  }

  /**
   * Address: 0x00903D60 (FUN_00903D60)
   *
   * What it does:
   * Releases retained texture/state resources and resets texture context lanes.
   */
  void TextureD3D10::DestroyState()
  {
    if (lockActive_) {
      static_cast<void>(Unlock(lockLevel_));
    }

    if (lockHistory_ != nullptr) {
      delete[] lockHistory_;
    }

    SafeRelease(texture_);
    SafeRelease(shaderResourceView_);

    const TextureContext resetContext{};
    context_.AssignFrom(resetContext);
  }

  /**
   * Address: 0x00903E70 (FUN_00903E70)
   *
   * TextureContext const *,void *,void *
   *
   * What it does:
   * Rebuilds texture wrapper state from caller context + texture/SRV handles and
   * allocates per-level lock-history storage.
   */
  void TextureD3D10::InitializeState(
    const TextureContext* const context, ID3D10Texture2D* const texture, ID3D10ShaderResourceView* const shaderResourceView
  )
  {
    DestroyState();
    context_.AssignFrom(*context);
    shaderResourceView_ = shaderResourceView;
    texture_ = texture;

    D3D10_TEXTURE2D_DESC textureDesc{};
    texture_->GetDesc(&textureDesc);
    context_.mipmapLevels_ = textureDesc.MipLevels;
    context_.width_ = textureDesc.Width;
    context_.height_ = textureDesc.Height;

    if (context_.mipmapLevels_ < 1U) {
      ThrowGalError("TextureD3D10.cpp", 205, "invalid texture");
    }

    if (context_.dataCount_ != nullptr) {
      context_.dataCount_->release();
      context_.dataCount_ = nullptr;
    }
    context_.dataArray_ = nullptr;
    context_.dataBegin_ = 0U;
    context_.dataEnd_ = 0U;

    lockHistory_ = new TextureLockRect[context_.mipmapLevels_];
    contextFormatBackup_ = static_cast<int>(context_.format_);
    const int contextFormatBackupDxgi = MapGalTextureFormatToDxgi(contextFormatBackup_);
    static_cast<void>(contextFormatBackupDxgi);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalTextureFormat(static_cast<int>(textureDesc.Format)));
    const unsigned int formatBlockBytes = GetTextureFormatBlockBytes(context_.format_);
    static_cast<void>(formatBlockBytes);
    if (context_.format_ == 20U) {
      DestroyState();
      ThrowGalError("TextureD3D10.cpp", 213, "unsupported texture format");
    }
  }

  /**
   * Address: 0x00901B80 (FUN_00901B80)
   *
   * What it does:
   * Initializes one empty D3D10 index-buffer wrapper with default context and
   * cleared native/staging/lock tracking lanes.
   */
  IndexBufferD3D10::IndexBufferD3D10()
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {}

  /**
   * Address: 0x00901D60 (FUN_00901D60)
   *
   * IndexBufferContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 index-buffer wrapper from context + native/staging handles.
   */
  IndexBufferD3D10::IndexBufferD3D10(
    const IndexBufferContext* const context,
    ID3D10Device* const nativeDevice,
    ID3D10Buffer* const nativeBuffer,
    ID3D10Buffer* const stagingBuffer
  )
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {
    DestroyState();
    context_.format_ = context->format_;
    context_.size_ = context->size_;
    context_.type_ = context->type_;
    nativeBuffer_ = nativeBuffer;
    stagingBuffer_ = stagingBuffer;
    nativeDevice_ = nativeDevice;
    if (nativeDevice_ != nullptr) {
      nativeDevice_->AddRef();
    }
  }

  /**
   * Address: 0x00901C90 (FUN_00901C90)
   * Address: 0x00901D40 (FUN_00901D40, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device buffers and resets the context, then the
   * `IndexBuffer` base destructor runs (inlined, 0x00901CD3).
   */
  IndexBufferD3D10::~IndexBufferD3D10()
  {
    DestroyState();
  }

  /**
   * Address: 0x00901BE0 (FUN_00901BE0)
   *
   * What it does:
   * Returns the context the buffer was created from.
   */
  IndexBufferContext* IndexBufferD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00901E00 (FUN_00901E00)
   *
   * std::uint32_t,std::uint32_t,unsigned int
   *
   * What it does:
   * Maps the staging buffer with recovered map-flag conversion and returns mapped data.
   */
  std::int16_t*
  IndexBufferD3D10::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    static_cast<void>(offset);
    static_cast<void>(size);

    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 57, "attempt to map invalid vertex buffer");
    }

    if (stagingBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 58, "attempt to map invalid vertex buffer");
    }

    if (locked_) {
      ThrowGalError("IndexBufferD3D10.cpp", 59, "vertex buffer map/unmap mismatch");
    }

    const auto flags = static_cast<unsigned int>(lockFlags);
    unsigned int mapMode = ((flags * 2U) | (flags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    const HRESULT result = stagingBuffer_->Map(static_cast<D3D10_MAP>(mapMode), 0U, &mappedData_);
    if (result < 0) {
      ThrowGalErrorFromHresult("IndexBufferD3D10.cpp", 71, result);
    }

    locked_ = true;
    return reinterpret_cast<std::int16_t*>(mappedData_);
  }

  /**
   * Address: 0x00902020 (FUN_00902020)
   *
   * What it does:
   * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
   */
  void IndexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("IndexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    stagingBuffer_->Unmap();
    nativeDevice_->CopySubresourceRegion(nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
  }

  /**
   * Address: 0x00901C10 (FUN_00901C10)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void IndexBufferD3D10::DestroyState()
  {
    SafeRelease(nativeBuffer_);
    SafeRelease(stagingBuffer_);
    SafeRelease(nativeDevice_);
    locked_ = false;
    mappedData_ = nullptr;

    const IndexBufferContext resetContext{};
    context_.format_ = resetContext.format_;
    context_.size_ = resetContext.size_;
    context_.type_ = resetContext.type_;
  }

  /**
   * Address: 0x00902180 (FUN_00902180)
   *
   * What it does:
   * Validates and returns the retained native index-buffer handle lane.
   */
  ID3D10Buffer* IndexBufferD3D10::GetNativeBufferOrThrow()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 115, "invalid index buffer");
    }

    return nativeBuffer_;
  }

  /**
   * Address: 0x0094D990 (FUN_0094D990)
   *
   * What it does:
   * Initializes one empty D3D10 vertex-buffer wrapper with default context and
   * cleared native/staging/lock tracking lanes.
   */
  VertexBufferD3D10::VertexBufferD3D10()
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {}

  /**
   * Address: 0x0094DB50 (FUN_0094DB50)
   *
   * VertexBufferContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 vertex-buffer wrapper from context + native/staging handles.
   */
  VertexBufferD3D10::VertexBufferD3D10(
    const VertexBufferContext* const context,
    ID3D10Device* const nativeDevice,
    ID3D10Buffer* const nativeBuffer,
    ID3D10Buffer* const stagingBuffer
  )
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {
    DestroyState();
    context_.type_ = context->type_;
    context_.usage_ = context->usage_;
    context_.vertexCount_ = context->vertexCount_;
    context_.stride_ = context->stride_;
    nativeBuffer_ = nativeBuffer;
    stagingBuffer_ = stagingBuffer;
    nativeDevice_ = nativeDevice;
    if (nativeDevice_ != nullptr) {
      nativeDevice_->AddRef();
    }
  }

  /**
   * Address: 0x0094DA80 (FUN_0094DA80)
   * Address: 0x0094DB30 (FUN_0094DB30, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device buffers and resets the context, then the
   * `VertexBuffer` base destructor runs (inlined, 0x0094DAC3).
   */
  VertexBufferD3D10::~VertexBufferD3D10()
  {
    DestroyState();
  }

  /**
   * Address: 0x0094D9F0 (FUN_0094D9F0)
   *
   * What it does:
   * Returns the context the buffer was created from.
   */
  VertexBufferContext* VertexBufferD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094DC00 (FUN_0094DC00)
   *
   * std::uint32_t,std::uint32_t,unsigned int
   *
   * What it does:
   * Maps the staging buffer with recovered map-flag conversion and returns
   * mapped pointer plus caller byte offset.
   */
  void* VertexBufferD3D10::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    static_cast<void>(size);

    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 57, "attempt to map invalid vertex buffer");
    }

    if (stagingBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 58, "attempt to map invalid vertex buffer");
    }

    if (locked_) {
      ThrowGalError("VertexBufferD3D10.cpp", 59, "vertex buffer map/unmap mismatch");
    }

    const auto flags = static_cast<unsigned int>(lockFlags);
    unsigned int mapMode = ((flags * 2U) | (flags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    const HRESULT result = stagingBuffer_->Map(static_cast<D3D10_MAP>(mapMode), 0U, &mappedData_);
    if (result < 0) {
      ThrowGalErrorFromHresult("VertexBufferD3D10.cpp", 71, result);
    }

    locked_ = true;
    auto* const mappedBytes = reinterpret_cast<std::uint8_t*>(mappedData_);
    return mappedBytes + offset;
  }

  /**
   * Address: 0x0094DE30 (FUN_0094DE30)
   *
   * What it does:
   * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
   */
  void VertexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("VertexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    stagingBuffer_->Unmap();
    nativeDevice_->CopySubresourceRegion(nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
  }

  /**
   * Address: 0x0094DA00 (FUN_0094DA00)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void VertexBufferD3D10::DestroyState()
  {
    SafeRelease(nativeBuffer_);
    SafeRelease(stagingBuffer_);
    SafeRelease(nativeDevice_);
    locked_ = false;
    mappedData_ = nullptr;

    const VertexBufferContext resetContext{};
    context_.type_ = resetContext.type_;
    context_.usage_ = resetContext.usage_;
    context_.vertexCount_ = resetContext.vertexCount_;
    context_.stride_ = resetContext.stride_;
  }

  /**
   * Address: 0x0094DF90 (FUN_0094DF90)
   *
   * What it does:
   * Validates and returns the retained native vertex-buffer handle lane.
   */
  ID3D10Buffer* VertexBufferD3D10::GetNativeBufferOrThrow()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 115, "invalid vertex buffer");
    }

    return nativeBuffer_;
  }

  /**
   * Address: 0x008F8100 (FUN_008F8100)
   *
   * What it does:
   * Applies the non-deleting destructor body lanes for `CursorD3D10`.
   */
  void DestroyCursorD3D10Body(CursorD3D10* const cursor) noexcept
  {
    cursor->Destroy();
  }

  /**
   * Address: 0x008F8090 (FUN_008F8090)
   *
   * What it does:
   * Initializes one cursor wrapper and clears retained cursor/icon handle lanes.
   */
  CursorD3D10::CursorD3D10()
    : previousCursor_(nullptr)
    , cursorIcon_(nullptr)
  {}

  /**
   * Address: 0x008F80B0 (FUN_008F80B0)
   *
   * void *
   *
   * What it does:
   * Rebinds one cursor instance to `CursorD3D10` vtable ownership, clears the
   * icon lane, and preserves the existing retained cursor-handle lane.
   */
  CursorD3D10* InitializeCursorD3D10WithRetainedCursorLane(
    CursorD3D10* const cursor,
    void* const reserved
  ) noexcept
  {
    if (cursor == nullptr) {
      return nullptr;
    }

    const HCURSOR retainedCursor = cursor->previousCursor_;
    ::new (static_cast<void*>(cursor)) CursorD3D10();
    cursor->previousCursor_ = retainedCursor;
    static_cast<void>(reserved);
    return cursor;
  }

  /**
   * Address: 0x008F8360 (FUN_008F8360)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_008F8100`.
   */
  CursorD3D10::~CursorD3D10()
  {
    DestroyCursorD3D10Body(this);
  }

  /**
   * Address: 0x008F80D0 (FUN_008F80D0)
   *
   * What it does:
   * Restores the previous native cursor, destroys retained icon state, and
   * clears both cursor/icon handle lanes.
   */
  void CursorD3D10::Destroy()
  {
    ::SetCursor(previousCursor_);
    if (cursorIcon_ != nullptr) {
      ::DestroyIcon(cursorIcon_);
    }

    previousCursor_ = nullptr;
    cursorIcon_ = nullptr;
  }

  /**
   * Address: 0x008F83B0 (FUN_008F83B0)
   *
   * CursorContext const *
   *
   * What it does:
   * Resets prior cursor/icon state, builds one icon from caller cursor context,
   * applies it as the active native cursor, and stores the returned prior cursor.
   */
  HCURSOR CursorD3D10::SetCursor(const CursorContext* const context)
  {
    Destroy();

    cursorIcon_ = BuildCursorIcon(context->hotspotX_, context->hotspotY_, context->texture_);
    previousCursor_ = ::SetCursor(cursorIcon_);
    return previousCursor_;
  }

  /**
   * Address: 0x008F8430 (FUN_008F8430)
   *
   * What it does:
   * Validates icon initialization state and applies the retained icon as
   * current native cursor.
   */
  HCURSOR CursorD3D10::InitCursor()
  {
    if (cursorIcon_ == nullptr) {
      ThrowGalError("CursorD3D10.cpp", 70, "attempt to use uninitialized cursor");
    }

    return ::SetCursor(cursorIcon_);
  }

  /**
   * Address: 0x008F84F0 (FUN_008F84F0)
   *
   * bool
   *
   * What it does:
   * Validates icon initialization state and drives native show/hide cursor
   * count loops until the binary stop conditions are reached.
   */
  int CursorD3D10::ShowCursor(const bool show)
  {
    if (cursorIcon_ == nullptr) {
      ThrowGalError("CursorD3D10.cpp", 76, "attempt to use uninitialized cursor");
    }

    int result = 0;
    if (show) {
      do {
        result = ::ShowCursor(TRUE);
      } while (result < 0);
    } else {
      do {
        result = ::ShowCursor(FALSE);
      } while (result >= 0);
    }

    return result;
  }

  /**
   * Address: 0x00900450 (FUN_00900450)
   * Address: 0x009005E0 (FUN_009005E0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device objects and unloads the D3D10 modules; the member
   * destructors then run in reverse declaration order (cursor, pipeline
   * state, swap chains, adapters, device context, log, output context).
   */
  DeviceD3D10::~DeviceD3D10()
  {
    Shutdown();
  }

  /**
   * Address: 0x009001B0 (FUN_009001B0)
   *
   * What it does:
   * Releases the head targets, every swap chain and adapter in place (the
   * vectors keep their slots; the member destructors free them), the pipeline
   * state, the factory, the device, both helper effects and the RTT quad and
   * layout (not the RTT technique, which the effect owns), puts the cursor
   * back, resets the context, and unloads the three libraries. The exports
   * resolved from them are left as they were.
   */
  void DeviceD3D10::Shutdown()
  {
    delete[] mHeadOutputContexts;
    mHeadOutputContexts = nullptr;

    for (IDXGISwapChain*& swapChain : mSwapChains) {
      SafeRelease(swapChain);
    }

    for (AdapterD3D10& adapter : mAdapters) {
      ReleaseAdapterOutputAndDeviceRefs(&adapter);
    }

    mPipelineState.reset();

    SafeRelease(mDXGIFactory);
    SafeRelease(mDevice);
    SafeRelease(mSignatureEffect);
    SafeRelease(mRttEffect);
    SafeRelease(mRttQuadVertexBuffer);
    SafeRelease(mRttInputLayout);

    mCursor.Destroy();
    mDeviceContext = DeviceContext(DeviceApi::Unset);

    ::FreeLibrary(mDXGIModule);
    mDXGIModule = nullptr;
    ::FreeLibrary(mD3DX10Module);
    mD3DX10Module = nullptr;
    ::FreeLibrary(mD3D10Module);
    mD3D10Module = nullptr;
  }

  /**
   * Address: 0x008F8860 (FUN_008F8860)
   *
   * What it does:
   * Forwards to the linked `D3D10CreateBlob`.
   */
  HRESULT DeviceD3D10::CreateBlob(const SIZE_T size, ID3D10Blob** const outBlob)
  {
    return mD3D10CreateBlob(size, outBlob);
  }

  /**
   * Address: 0x008F8880 (FUN_008F8880)
   *
   * What it does:
   * Forwards to the linked `D3DX10SaveTextureToMemory`.
   */
  HRESULT DeviceD3D10::SaveTextureToMemory(
    ID3D10Resource* const texture, const D3DX10_IMAGE_FILE_FORMAT format, ID3D10Blob** const outBlob
  )
  {
    return mD3DX10SaveTextureToMemory(texture, format, outBlob);
  }

  /**
   * Address: 0x008FE5D0 (FUN_008FE5D0)
   *
   * What it does:
   * Installs the vtable, builds the output context at +0x04, zeroes the
   * module, export and COM lanes, builds the embedded `DeviceContext(Unset)` at
   * +0x60 and the cursor at +0x11C. Every one of those is a member
   * initializer on the class, so the body is empty: this used to be a free
   * factory that `new`ed an overlay and then reset each member by hand.
   */
  DeviceD3D10::DeviceD3D10() = default;

  /**
   * Address: 0x008F86B0 (FUN_008F86B0)
   *
   * What it does:
   * Returns the address of the retained device log-storage lane at `this+0x50`.
   */
  void* DeviceD3D10::GetLog()
  {
    return &mLog;
  }

  /**
   * Address: 0x008F86C0 (FUN_008F86C0)
   *
   * What it does:
   * `lea eax, [ecx+0x60]`: the address of the embedded context. (An earlier
   * recovery read the dword at +0x60 instead - the context's vptr.)
   */
  DeviceContext* DeviceD3D10::GetDeviceContext()
  {
    return &mDeviceContext;
  }

  /**
   * Address: 0x008F86D0 (FUN_008F86D0)
   *
   * What it does:
   * Returns the current thread-id snapshot lane from `this+0x4C`.
   */
  int DeviceD3D10::GetCurThreadId()
  {
    return mCurThreadId;
  }

  /**
   * Address: 0x008F86E0 (FUN_008F86E0)
   *
   * What it does:
   * Preserves the binary no-op virtual slot.
   */
  void DeviceD3D10::Func1() const {}

  /**
   * Address: 0x008F86F0 (FUN_008F86F0)
   *
   * int,int
   *
   * What it does:
   * Preserves the binary no-op adapter-modes slot (`retn 8` shape).
   */
  void DeviceD3D10::GetModesForAdapter(msvc8::vector<HeadAdapterMode>& /*outModes*/, const int /*adapterIndex*/)
  {
  }

  /**
   * Address: 0x008FD2E0 (FUN_008FD2E0)
   *
   * What it does:
   * Dynamically resolves required D3D10/D3DX10/DXGI module exports used by
   * backend startup.
   */
  void DeviceD3D10::DynamicLink()
  {

    mD3D10Module = ::LoadLibraryA("d3d10.dll");
    if (mD3D10Module == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1645, "unable to explicitly link to d3d10.dll");
    }

    mD3D10CreateDevice = reinterpret_cast<D3D10CreateDeviceFn>(::GetProcAddress(mD3D10Module, "D3D10CreateDevice"));
    mD3D10CreateBlob = reinterpret_cast<D3D10CreateBlobFn>(
      ::GetProcAddress(mD3D10Module, "D3D10CreateBlob")
    );

    mD3DX10Module = ::LoadLibraryA("d3dx10.dll");
    if (mD3DX10Module == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1650, "unable to explicitly link to d3dx10.dll");
    }

    mD3DX10CreateEffectFromMemory = reinterpret_cast<D3DX10CreateEffectFromMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10CreateEffectFromMemory")
    );
    mD3DX10CreateTextureFromMemory = reinterpret_cast<D3DX10CreateTextureFromMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10CreateTextureFromMemory")
    );
    mD3DX10SaveTextureToFileA = reinterpret_cast<D3DX10SaveTextureToFileFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10SaveTextureToFileA")
    );
    mD3DX10SaveTextureToMemory = reinterpret_cast<D3DX10SaveTextureToMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10SaveTextureToMemory")
    );

    mDXGIModule = ::LoadLibraryA("dxgi.dll");
    if (mDXGIModule == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1657, "unable to explicitly link to dxgi.dll");
    }

    mCreateDXGIFactory = reinterpret_cast<CreateDXGIFactoryFn>(::GetProcAddress(mDXGIModule, "CreateDXGIFactory"));
  }

  /**
   * Address: 0x00900A70 (FUN_00900A70)
   *
   * What it does:
   * Enumerates DXGI adapters, probes adapter output mode caches, and stores
   * valid adapters into the backend adapter list.
   */
  int DeviceD3D10::SetupDXGIDevice()
  {
    mAdapters.clear();

    auto* const dxgiFactory = mDXGIFactory;
    if (dxgiFactory == nullptr) {
      return E_POINTER;
    }

    IDXGIAdapter* adapter = nullptr;
    HRESULT result = dxgiFactory->EnumAdapters(0U, &adapter);
    for (unsigned int adapterIndex = 0U; result >= 0; ++adapterIndex) {
      AdapterD3D10 adapterEntry(adapter);
      if (adapterEntry.ProbeOutputsAndModes() >= 0) {
        mAdapters.push_back(adapterEntry);
      }

      adapter = nullptr;
      result = dxgiFactory->EnumAdapters(adapterIndex + 1U, &adapter);
    }

    return (result == DXGI_ERROR_NOT_FOUND) ? 0 : result;
  }

  /**
   * Address: 0x008FDB80 (FUN_008FDB80)
   *
   * What it does:
   * Builds RTT helper effect/state resources (effect, technique, quad VB,
   * and input layout) used by stretch-rect paths.
   */
  void DeviceD3D10::SetUpRTT()
  {
    auto* const device = mDevice;

    const HRESULT createEffectResult = mD3DX10CreateEffectFromMemory(
      kRttEffectSource,
      sizeof(kRttEffectSource),
      nullptr,
      nullptr,
      nullptr,
      D3D10_SHADER_ENABLE_STRICTNESS,
      0U,
      device,
      nullptr,
      nullptr,
      &mRttEffect,
      nullptr
    );
    if (createEffectResult < 0) {
      ThrowDeviceD3D10Hresult(1925, createEffectResult);
    }

    auto* const shaderEffect = mRttEffect;
    mRttTechnique = shaderEffect->GetTechniqueByName("RTT");

    D3D10_BUFFER_DESC vertexBufferDesc{};
    vertexBufferDesc.ByteWidth = sizeof(kRttFullscreenVertices);
    vertexBufferDesc.Usage = D3D10_USAGE_IMMUTABLE;
    vertexBufferDesc.BindFlags = D3D10_BIND_VERTEX_BUFFER;
    vertexBufferDesc.CPUAccessFlags = 0U;
    vertexBufferDesc.MiscFlags = 0U;

    D3D10_SUBRESOURCE_DATA initialData{};
    initialData.pSysMem = kRttFullscreenVertices;
    initialData.SysMemPitch = 0U;
    initialData.SysMemSlicePitch = 0U;

    ID3D10Buffer* quadVertexBuffer = nullptr;
    static_cast<void>(device->CreateBuffer(&vertexBufferDesc, &initialData, &quadVertexBuffer));
    SafeRelease(mRttQuadVertexBuffer);
    mRttQuadVertexBuffer = quadVertexBuffer;

    D3D10_INPUT_ELEMENT_DESC inputElements[2]{};
    inputElements[0].SemanticName = "POSITION";
    inputElements[0].SemanticIndex = 0U;
    inputElements[0].Format = DXGI_FORMAT_R32G32B32_FLOAT;
    inputElements[0].InputSlot = 0U;
    inputElements[0].AlignedByteOffset = 0U;
    inputElements[0].InputSlotClass = D3D10_INPUT_PER_VERTEX_DATA;
    inputElements[0].InstanceDataStepRate = 0U;

    inputElements[1].SemanticName = "TEXCOORD";
    inputElements[1].SemanticIndex = 0U;
    inputElements[1].Format = DXGI_FORMAT_R32G32_FLOAT;
    inputElements[1].InputSlot = 0U;
    inputElements[1].AlignedByteOffset = 12U;
    inputElements[1].InputSlotClass = D3D10_INPUT_PER_VERTEX_DATA;
    inputElements[1].InstanceDataStepRate = 0U;

    auto* const technique = mRttTechnique;
    auto* const pass = technique->GetPassByIndex(0U);
    D3D10_PASS_DESC passDesc{};
    static_cast<void>(pass->GetDesc(&passDesc));

    ID3D10InputLayout* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = device->CreateInputLayout(
      inputElements,
      2U,
      passDesc.pIAInputSignature,
      passDesc.IAInputSignatureSize,
      &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowDeviceD3D10Hresult(1970, createInputLayoutResult);
    }

    SafeRelease(mRttInputLayout);
    mRttInputLayout = inputLayout;
  }

  /**
   * Address: 0x008FF5B0 (FUN_008FF5B0)
   *
   * What it does:
   * Copies the requested device context into runtime, validates requested
   * head count, and populates per-head format/sample capability lanes.
   */
  std::uint32_t DeviceD3D10::CheckAvailableFormats(DeviceContext* const context)
  {
    mDeviceContext = *context;

    const std::uint32_t headCount = static_cast<std::uint32_t>(context->GetHeadCount());
    if (headCount > static_cast<std::uint32_t>(mAdapters.size())) {
      ThrowGalError("DeviceD3D10.cpp", 1695, "invalid head count specified in device context");
    }

    mDeviceContext.mMaxPrimitiveCount = 0x10000U;
    mDeviceContext.mMaxVertexCount = 0xFFFFU;
    mDeviceContext.mHWBasedInstancing = true;
    mDeviceContext.mVertexShaderProfile = 4;
    mDeviceContext.mPixelShaderProfile = 8;

    auto* const device = mDevice;
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      Head& head = mDeviceContext.GetHead(headIndex);
      const AdapterD3D10& adapter = mAdapters[headIndex];

      head.adapterModes.clear();
      for (const AdapterModeD3D10& adapterMode : adapter.modes_) {
        const DXGI_MODE_DESC* const modeBegin = adapterMode.modes_.begin();
        const DXGI_MODE_DESC* const modeEnd = adapterMode.modes_.end();
        for (const DXGI_MODE_DESC* mode = modeBegin; mode != modeEnd; ++mode) {
          HeadAdapterMode headMode{};
          headMode.width = mode->Width;
          headMode.height = mode->Height;
          headMode.refreshRate = (mode->RefreshRate.Denominator != 0U)
            ? (mode->RefreshRate.Numerator / mode->RefreshRate.Denominator)
            : mode->RefreshRate.Numerator;
          head.adapterModes.push_back(headMode);
        }
      }

      head.validFormats1.clear();
      for (int formatToken = 1; formatToken < 8; ++formatToken) {
        UINT supportFlags = 0U;
        const DXGI_FORMAT dxgiFormat = static_cast<DXGI_FORMAT>(MapGalRenderTargetFormatToDxgi(formatToken));
        if ((device->CheckFormatSupport(dxgiFormat, &supportFlags) >= 0) &&
            ((supportFlags & kD3D10FormatSupportRenderTarget) != 0U)) {
          head.validFormats1.push_back(formatToken);
        }
      }

      head.validFormats2.clear();
      for (int formatToken = 1; formatToken < 20; ++formatToken) {
        UINT supportFlags = 0U;
        const DXGI_FORMAT dxgiFormat = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(formatToken));
        if ((device->CheckFormatSupport(dxgiFormat, &supportFlags) >= 0) &&
            ((supportFlags & kD3D10FormatSupportTexture2D) != 0U)) {
          head.validFormats2.push_back(formatToken);
        }
      }

      head.mStrs.clear();
      if (adapter.description_.VendorId != kVendorIdNvidia) {
        for (unsigned int sampleCount = 2U; sampleCount <= 16U; ++sampleCount) {
          UINT qualityLevels = 0U;
          if ((device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, sampleCount, &qualityLevels) >= 0) &&
              (qualityLevels != 0U)) {
            char label[16]{};
            std::snprintf(label, sizeof(label), "%u", sampleCount);
            AppendHeadSampleOption(head, sampleCount, qualityLevels - 1U, label);
          }
        }
        continue;
      }

      for (const NvidiaSampleCandidate& candidate : kNvidiaSampleCandidates) {
        UINT qualityLevels = 0U;
        const HRESULT qualityResult =
          device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, candidate.sampleType, &qualityLevels);
        if ((qualityResult < 0) || (qualityLevels <= candidate.sampleQuality)) {
          continue;
        }

        if ((candidate.sampleType == 4U) && (candidate.sampleQuality == 4U)) {
          UINT quality16 = 0U;
          const HRESULT quality16Result =
            device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, 16U, &quality16);
          if ((quality16Result >= 0) && (quality16 > 16U)) {
            AppendHeadSampleOption(head, 16U, 16U, "16");
          }
          continue;
        }

        AppendHeadSampleOption(head, candidate.sampleType, candidate.sampleQuality, candidate.label);
      }
    }

    return headCount;
  }

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Asks the device whether the format's DXGI equivalent can be a 2D texture
   * that shaders sample.
   */
  bool DeviceD3D10::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
  {
    const auto dxgiFormat = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(static_cast<int>(textureFormat)));
    if (mDevice == nullptr || dxgiFormat == DXGI_FORMAT_UNKNOWN) {
      return false;
    }

    UINT support = 0U;
    return SUCCEEDED(mDevice->CheckFormatSupport(dxgiFormat, &support)) &&
           (support & D3D10_FORMAT_SUPPORT_TEXTURE2D) != 0U && (support & D3D10_FORMAT_SUPPORT_SHADER_SAMPLE) != 0U;
  }

  /**
   * Address: 0x008FD500 (FUN_008FD500)
   *
   * What it does:
   * Creates per-head backbuffer render/depth target wrappers and stores
   * them in the runtime output-context array.
   */
  void DeviceD3D10::CreateRenderTargets()
  {
    const std::uint32_t headCount = static_cast<std::uint32_t>(mDeviceContext.GetHeadCount());

    if (mHeadOutputContexts != nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1818, "internal D3D10 device initialization error");
    }

    OutputContext* const outputContexts = (headCount > 0U) ? new OutputContext[headCount] : nullptr;
    mHeadOutputContexts = outputContexts;

    auto* const device = mDevice;
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      auto* const swapChain = mSwapChains[headIndex];

      ID3D10Texture2D* backBuffer = nullptr;
      const HRESULT getBufferResult = swapChain->GetBuffer(0U, IID_PPV_ARGS(&backBuffer));
      if (getBufferResult < 0) {
        ThrowDeviceD3D10Hresult(1827, getBufferResult);
      }

      ID3D10RenderTargetView* renderTargetView = nullptr;
      const HRESULT createRtvResult = device->CreateRenderTargetView(backBuffer, nullptr, &renderTargetView);
      if (createRtvResult < 0) {
        ThrowDeviceD3D10Hresult(1835, createRtvResult);
      }

      D3D10_TEXTURE2D_DESC textureDesc{};
      backBuffer->GetDesc(&textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = textureDesc.Format;
      if (textureDesc.SampleDesc.Count > 1U) {
        shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2DMS;
      } else {
        shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
        shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
        shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;
      }

      ID3D10ShaderResourceView* shaderResourceView = nullptr;
      const HRESULT createSrvResult =
        device->CreateShaderResourceView(backBuffer, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowDeviceD3D10Hresult(1848, createSrvResult);
      }

      outputContexts[headIndex].surface.reset(new RenderTargetD3D10(backBuffer, renderTargetView, shaderResourceView));

      const DepthStencilTargetContext depthStencilContext(textureDesc.Width, textureDesc.Height, 3U, false);
      outputContexts[headIndex].depthStencil = CreateDepthStencilTarget(&depthStencilContext);
    }

    if (headCount > 0U) {
      static_cast<void>(ClearTarget(outputContexts));
    }
  }

  /**
   * Address: 0x00900B30 (FUN_00900B30)
   *
   * What it does:
   * Executes full D3D10 startup setup chain for one requested device
   * context (dynamic link, DXGI/device/swapchain/effects/state/capability
   * initialization).
   */
  void DeviceD3D10::Setup(DeviceContext* const context)
  {

    DynamicLink();
    mLog.clear();

    const HRESULT createFactoryResult = mCreateDXGIFactory(IID_PPV_ARGS(&mDXGIFactory));
    if (createFactoryResult < 0) {
      ThrowDeviceD3D10Hresult(610, createFactoryResult);
    }

    static_cast<void>(SetupDXGIDevice());
    if (mAdapters.empty()) {
      ThrowGalError("DeviceD3D10.cpp", 620, "unable to enumerate adapters");
    }

    const HRESULT createDeviceResult = mD3D10CreateDevice(
      mAdapters.front().dxgiAdapter_,
      D3D10_DRIVER_TYPE_HARDWARE,
      nullptr,
      0U,
      D3D10_SDK_VERSION,
      &mDevice
    );
    if (createDeviceResult < 0) {
      ThrowDeviceD3D10Hresult(622, createDeviceResult);
    }

    auto* const dxgiFactory = mDXGIFactory;
    for (unsigned int headIndex = 0U; headIndex < static_cast<unsigned int>(context->GetHeadCount()); ++headIndex) {
      const Head& head = context->GetHead(headIndex);
      DXGI_SWAP_CHAIN_DESC swapChainDesc{};
      BuildSwapChainDescFromHead(&swapChainDesc, &head);

      IDXGISwapChain* swapChain = nullptr;
      const HRESULT createSwapChainResult = dxgiFactory->CreateSwapChain(mDevice, &swapChainDesc, &swapChain);
      if (createSwapChainResult < 0) {
        ThrowDeviceD3D10Hresult(631, createSwapChainResult);
      }

      mSwapChains.push_back(swapChain);
    }

    const HRESULT createSignatureResult = mD3DX10CreateEffectFromMemory(
      kSignaturePreambleEffectSource,
      sizeof(kSignaturePreambleEffectSource),
      nullptr,
      nullptr,
      nullptr,
      D3D10_SHADER_ENABLE_STRICTNESS,
      0U,
      mDevice,
      nullptr,
      nullptr,
      &mSignatureEffect,
      nullptr
    );
    if (createSignatureResult < 0) {
      ThrowDeviceD3D10Hresult(641, createSignatureResult);
    }

    SetUpRTT();

    std::memset(mStreamFrequencies, 0, sizeof(mStreamFrequencies));
    mPipelineState.reset(new PipelineStateD3D10(mDevice));
    mPipelineState->SetDeviceState();

    static_cast<void>(CheckAvailableFormats(context));
    CreateRenderTargets();
  }

  /**
   * Address: 0x008FAB80 (FUN_008FAB80)
   *
   * What it does:
   * Validates one head index against the device context's head count
   * (`sizeof(Head)` is 0x80, the `>> 7` of `size()`) and returns that head's
   * output context from `mHeadOutputContexts`.
   */
  OutputContext* DeviceD3D10::GetHeadOutputContext(const unsigned int headIndex)
  {
    if (headIndex >= mDeviceContext.mHeads.size()) {
      ThrowGalError("DeviceD3D10.cpp", 727, "invalid head index specified");
    }

    return &mHeadOutputContexts[headIndex];
  }

  /**
   * Address: 0x008FAC50 (FUN_008FAC50)
   *
   * What it does:
   * The const overload of `GetHeadOutputContext`; same body.
   */
  const OutputContext* DeviceD3D10::GetHeadOutputContext(const unsigned int headIndex) const
  {
    if (headIndex >= mDeviceContext.mHeads.size()) {
      ThrowGalError("DeviceD3D10.cpp", 733, "invalid head index specified");
    }

    return &mHeadOutputContexts[headIndex];
  }

  /**
   * Address: 0x008FA220 (FUN_008FA220)
   *
   * What it does:
   * Returns a new reference to the device's pipeline state.
   */
  boost::shared_ptr<PipelineState> DeviceD3D10::GetPipelineState()
  {
    return mPipelineState;
  }

  /**
   * Address: 0x008FEA00 (FUN_008FEA00)
   * Slot: 9
   *
   * What it does:
   * Copies the context and defines the 20 D3D10 state macros on the copy
   * (`EffectContext::DefineMacro`, which throws on a duplicate key), then
   * compiles the caller's source with the copy's macros. The copy and the
   * error text go out of scope before the effect is wrapped (0x008FEF4D, then
   * `new` at 0x008FEF5A), and the define array is never freed -- the binary
   * has no `delete[]` for it on any path, the same as the D3D9 builder's.
   */
  boost::shared_ptr<Effect> DeviceD3D10::CreateEffect(const EffectContext& context)
  {
    ID3D10Effect* dxEffect = nullptr;
    {
      EffectContext localContext(context);
      for (std::size_t i = 0U; i < kDeviceCreateEffectInjectedMacroCount; ++i) {
        localContext.DefineMacro(
          kDeviceCreateEffectInjectedMacros[i].key,
          kDeviceCreateEffectInjectedMacros[i].value
        );
      }

      const std::size_t macroCount = localContext.mMacros.size();
      D3D10_SHADER_MACRO* defines = nullptr;
      if (macroCount != 0U) {
        defines = new D3D10_SHADER_MACRO[macroCount + 1U];

        std::size_t index = 0U;
        for (const EffectMacro& macro : localContext.mMacros) {
          defines[index].Name = macro.keyText_.c_str();
          defines[index].Definition = macro.valueText_.c_str();
          ++index;
        }

        defines[macroCount].Name = nullptr;
        defines[macroCount].Definition = nullptr;
      }

      ID3D10Blob* errorBlob = nullptr;
      if (context.mSourceType != 2U) {
        ThrowGalError("DeviceD3D10.cpp", 818, "invalid source defined for effect");
      }

      const char* const sourceData = context.mSourceBuffer.mBegin;
      const SIZE_T sourceBytes = static_cast<SIZE_T>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
      const HRESULT result = mD3DX10CreateEffectFromMemory(
        sourceData,
        sourceBytes,
        nullptr,
        defines,
        nullptr,
        D3D10_SHADER_ENABLE_BACKWARDS_COMPATIBILITY,
        0U,
        mDevice,
        nullptr,
        nullptr,
        &dxEffect,
        &errorBlob
      );

      msvc8::string reason("unknown error");
      if ((result < 0) && (errorBlob != nullptr)) {
        reason.assign_owned(static_cast<const char*>(errorBlob->GetBufferPointer()));
      }

      SafeRelease(errorBlob);

      if (result < 0) {
        msvc8::string message("unable to create effect: ");
        message = message + context.mSourcePath;
        message = message + " reason: ";
        message = message + reason;
        ThrowGalError("DeviceD3D10.cpp", 828, message.c_str());
      }
    }

    return boost::shared_ptr<Effect>(new EffectD3D10(context, dxEffect));
  }

  /**
   * Address: 0x008FAD20 (FUN_008FAD20)
   *
   * What it does:
   * Creates one texture (from in-memory file data, or empty at the context's
   * size and format) with its shader-resource view and wraps both in a
   * `TextureD3D10`.
   */
  boost::shared_ptr<Texture> DeviceD3D10::CreateTexture(const TextureContext* const context)
  {
    ID3D10Texture2D* nativeTexture = nullptr;
    ID3D10ShaderResourceView* shaderResourceView = nullptr;

    if (context->source_ != 1U) {
      if (context->source_ != 2U) {
        ThrowGalError("DeviceD3D10.cpp", 890, "invalid source specified for texture data");
      }

      D3D10_TEXTURE2D_DESC textureDesc{};
      textureDesc.Width = context->width_;
      textureDesc.Height = context->height_;
      textureDesc.MipLevels = (context->mipmapLevels_ != 0U) ? context->mipmapLevels_ : 1U;
      textureDesc.ArraySize = 1U;
      textureDesc.Format = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(static_cast<int>(context->format_)));
      if (textureDesc.Format == DXGI_FORMAT_B8G8R8A8_UNORM) {
        gpg::HandleAssertFailure(
          "DXGI_FORMAT_B8G8R8A8_UNORM != tex2ddesc.Format",
          872,
          "c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\DeviceD3D10.cpp"
        );
      }
      if (textureDesc.Format == DXGI_FORMAT_B8G8R8X8_UNORM) {
        gpg::HandleAssertFailure(
          "DXGI_FORMAT_B8G8R8X8_UNORM != tex2ddesc.Format",
          873,
          "c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\DeviceD3D10.cpp"
        );
      }
      textureDesc.SampleDesc.Count = 1U;
      textureDesc.SampleDesc.Quality = 0U;
      textureDesc.Usage = D3D10_USAGE_DYNAMIC;
      textureDesc.BindFlags = 8U;
      textureDesc.CPUAccessFlags = 0x10000U;
      textureDesc.MiscFlags = 0U;

      const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &nativeTexture);
      if (createTextureResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 886, createTextureResult);
      }
    } else {
      if (context->dataEnd_ == context->dataBegin_) {
        ThrowGalError("DeviceD3D10.cpp", 855, "attempt to create texture from uninitialized memory");
      }

      ID3D10Resource* textureResource = nullptr;
      const auto* const sourceData = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(context->dataBegin_));
      const SIZE_T sourceBytes = context->dataEnd_ - context->dataBegin_;
      const HRESULT createFromMemoryResult =
        mD3DX10CreateTextureFromMemory(mDevice, sourceData, sourceBytes, nullptr, nullptr, &textureResource);
      if (createFromMemoryResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 857, createFromMemoryResult);
      }

      if (textureResource != nullptr) {
        static_cast<void>(textureResource->QueryInterface(IID_PPV_ARGS(&nativeTexture)));
        SafeRelease(textureResource);
      }
    }

    if (nativeTexture != nullptr) {
      D3D10_TEXTURE2D_DESC textureDesc{};
      nativeTexture->GetDesc(&textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = DXGI_FORMAT_UNKNOWN;
      shaderResourceViewDesc.ViewDimension =
        (textureDesc.MiscFlags != 4U) ? D3D10_SRV_DIMENSION_TEXTURE2D : D3D10_SRV_DIMENSION_TEXTURECUBE;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

      const HRESULT createSrvResult =
        mDevice->CreateShaderResourceView(nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 912, createSrvResult);
      }
    }

    return boost::shared_ptr<Texture>(new TextureD3D10(context, nativeTexture, shaderResourceView));
  }

  /**
   * Address: 0x008FB1D0 (FUN_008FB1D0)
   *
   * What it does:
   * Creates one render-target/shader-resource 2D texture with its RTV and
   * SRV, sets a viewport covering it, and wraps all three in a
   * `RenderTargetD3D10`.
   */
  boost::shared_ptr<RenderTarget> DeviceD3D10::CreateRenderTarget(const RenderTargetContext* const context)
  {
    D3D10_TEXTURE2D_DESC textureDesc{};
    textureDesc.Width = context->width_;
    textureDesc.Height = context->height_;
    textureDesc.MipLevels = 1U;
    textureDesc.ArraySize = 1U;
    textureDesc.Format = static_cast<DXGI_FORMAT>(MapGalRenderTargetFormatToDxgi(static_cast<int>(context->format_)));
    textureDesc.SampleDesc.Count = 1U;
    textureDesc.SampleDesc.Quality = 0U;
    textureDesc.Usage = D3D10_USAGE_DEFAULT;
    textureDesc.BindFlags = 0x28U;
    textureDesc.CPUAccessFlags = 0U;
    textureDesc.MiscFlags = 0U;

    ID3D10Texture2D* nativeTexture = nullptr;
    const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &nativeTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 941, createTextureResult);
    }

    ID3D10RenderTargetView* renderTargetView = nullptr;
    const HRESULT createRtvResult = mDevice->CreateRenderTargetView(nativeTexture, nullptr, &renderTargetView);
    if (createRtvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 945, createRtvResult);
    }

    D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
    shaderResourceViewDesc.Format = textureDesc.Format;
    shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
    shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
    shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

    ID3D10ShaderResourceView* shaderResourceView = nullptr;
    const HRESULT createSrvResult =
      mDevice->CreateShaderResourceView(nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
    if (createSrvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 954, createSrvResult);
    }

    D3DVIEWPORT9 viewport{};
    viewport.Width = context->width_;
    viewport.Height = context->height_;
    viewport.MinZ = 0.0f;
    viewport.MaxZ = 1.0f;
    SetViewport(&viewport);

    return boost::shared_ptr<RenderTarget>(
      new RenderTargetD3D10(context, nativeTexture, renderTargetView, shaderResourceView)
    );
  }

  /**
   * Address: 0x008FA6B0 (FUN_008FA6B0)
   *
   * What it does:
   * Returns an empty `CubeRenderTargetD3D10`. Its constructor (0x008F7F80)
   * takes the context but only default-constructs its own copy, and the
   * D3D10 backend never creates a native cube texture.
   */
  boost::shared_ptr<CubeRenderTarget> DeviceD3D10::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
  {
    return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetD3D10(context));
  }

  /**
   * Address: 0x008FB570 (FUN_008FB570)
   *
   * What it does:
   * Creates one depth texture with its DSV (plus an SRV when the context asks
   * for a sampleable target) and wraps them in a `DepthStencilTargetD3D10`.
   */
  boost::shared_ptr<DepthStencilTarget> DeviceD3D10::CreateDepthStencilTarget(const DepthStencilTargetContext* const context)
  {
    const DXGI_FORMAT depthFormat =
      static_cast<DXGI_FORMAT>(ResolveDepthStencilFormatToDxgi(static_cast<int>(context->format_)));

    D3D10_TEXTURE2D_DESC textureDesc{};
    textureDesc.Width = context->width_;
    textureDesc.Height = context->height_;
    textureDesc.MipLevels = 1U;
    textureDesc.ArraySize = 1U;
    textureDesc.Format = depthFormat;
    textureDesc.SampleDesc.Count = 1U;
    textureDesc.SampleDesc.Quality = 0U;
    textureDesc.Usage = D3D10_USAGE_DEFAULT;
    textureDesc.BindFlags = context->field0x10_ ? 0x48U : 0x40U;
    textureDesc.CPUAccessFlags = 0U;
    textureDesc.MiscFlags = 0U;

    ID3D10Texture2D* depthTexture = nullptr;
    const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &depthTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 993, createTextureResult);
    }

    D3D10_DEPTH_STENCIL_VIEW_DESC depthStencilViewDesc{};
    depthStencilViewDesc.Format = depthFormat;
    depthStencilViewDesc.ViewDimension = D3D10_DSV_DIMENSION_TEXTURE2D;
    depthStencilViewDesc.Texture2D.MipSlice = 0U;

    ID3D10DepthStencilView* depthStencilView = nullptr;
    const HRESULT createDsvResult =
      mDevice->CreateDepthStencilView(depthTexture, &depthStencilViewDesc, &depthStencilView);
    if (createDsvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1001, createDsvResult);
    }

    ID3D10ShaderResourceView* shaderResourceView = nullptr;
    if (context->field0x10_) {
      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = depthFormat;
      shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = 1U;

      const HRESULT createSrvResult =
        mDevice->CreateShaderResourceView(depthTexture, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1013, createSrvResult);
      }
    }

    return boost::shared_ptr<DepthStencilTarget>(
      new DepthStencilTargetD3D10(context, depthTexture, depthStencilView, shaderResourceView)
    );
  }

  /**
   * Address: 0x008FE220 (FUN_008FE220)
   *
   * What it does:
   * Builds the input layout for gal vertex format `formatToken` against the
   * signature effect's pass for that format and wraps it in a
   * `VertexFormatD3D10`.
   */
  boost::shared_ptr<VertexFormat> DeviceD3D10::CreateVertexFormat(const std::uint32_t formatToken)
  {
    const D3D10_INPUT_ELEMENT_DESC* const elements = GetVertexLayoutElementsOrThrow(formatToken);
    const std::uint32_t elementCount = GetVertexLayoutElementCountOrThrow(formatToken);

    D3D10_PASS_DESC passDesc{};
    GetVertexInputSignatureOrThrow(this, static_cast<int>(formatToken), &passDesc);

    ID3D10InputLayout* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = mDevice->CreateInputLayout(
      elements, elementCount, passDesc.pIAInputSignature, passDesc.IAInputSignatureSize, &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1029, createInputLayoutResult);
    }

    return boost::shared_ptr<VertexFormat>(new VertexFormatD3D10(formatToken, inputLayout));
  }

  /**
   * Address: 0x008FB8D0 (FUN_008FB8D0)
   *
   * What it does:
   * Creates one GPU vertex buffer and the staging buffer `Lock` maps, and
   * wraps both in a `VertexBufferD3D10`.
   */
  boost::shared_ptr<VertexBuffer> DeviceD3D10::CreateVertexBuffer(const VertexBufferContext* const context)
  {
    const std::uint32_t byteWidth = context->vertexCount_ * context->stride_;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->usage_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 1U;
    gpuBufferDesc.CPUAccessFlags = (context->usage_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = mDevice->CreateBuffer(&gpuBufferDesc, nullptr, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1049, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = mDevice->CreateBuffer(&stagingBufferDesc, nullptr, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1056, createStagingBufferResult);
    }

    return boost::shared_ptr<VertexBuffer>(
      new VertexBufferD3D10(context, mDevice, gpuBuffer, stagingBuffer)
    );
  }

  /**
   * Address: 0x008FBB60 (FUN_008FBB60)
   *
   * What it does:
   * Creates one GPU index buffer and the staging buffer `Lock` maps, and
   * wraps both in an `IndexBufferD3D10`.
   */
  boost::shared_ptr<IndexBuffer> DeviceD3D10::CreateIndexBuffer(const IndexBufferContext* const context)
  {
    const std::uint32_t bytesPerIndex = (context->format_ == 1U) ? 2U : 4U;
    const std::uint32_t byteWidth = context->size_ * bytesPerIndex;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->type_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 2U;
    gpuBufferDesc.CPUAccessFlags = (context->type_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = mDevice->CreateBuffer(&gpuBufferDesc, nullptr, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1076, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = mDevice->CreateBuffer(&stagingBufferDesc, nullptr, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1083, createStagingBufferResult);
    }

    return boost::shared_ptr<IndexBuffer>(
      new IndexBufferD3D10(context, mDevice, gpuBuffer, stagingBuffer)
    );
  }

  /**
   * Address: 0x008FC540 (FUN_008FC540)
   *
   * What it does:
   * Reads one colour target back into a texture with one native
   * `CopyResource` from the target's texture into the destination's.
   */
  void DeviceD3D10::GetRenderTargetData(
    const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1230, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1231, "Missing dest   texture");
    }

    ID3D10Texture2D* const sourceResource = static_cast<RenderTargetD3D10*>(source.get())->GetRenderTextureOrThrow();
    ID3D10Texture2D* const destinationResource = static_cast<TextureD3D10*>(destination.get())->GetTextureOrThrow();
    mDevice->CopyResource(destinationResource, sourceResource);
  }

  /**
   * Address: 0x008FC290 (FUN_008FC290)
   *
   * What it does:
   * Copies from source to destination target directly when their size and
   * format match; otherwise draws the source's SRV into the destination's
   * RTV through the RTT effect. On D3D10 only the destination rectangle's
   * top-left corner is used.
   */
  void DeviceD3D10::StretchRect(
    const boost::shared_ptr<RenderTarget>& source,
    const boost::shared_ptr<RenderTarget>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1174, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1175, "Missing dest   texture");
    }

    auto* const sourceTarget = static_cast<RenderTargetD3D10*>(source.get());
    auto* const destinationTarget = static_cast<RenderTargetD3D10*>(destination.get());
    const RenderTargetContext* const sourceContext = sourceTarget->GetContext();
    const RenderTargetContext* const destinationContext = destinationTarget->GetContext();

    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<unsigned int>(destinationRect->left);
        destinationY = static_cast<unsigned int>(destinationRect->top);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const RECT* const rect = sourceRect;
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      ID3D10Texture2D* const sourceResource = sourceTarget->GetRenderTextureOrThrow();
      ID3D10Texture2D* const destinationResource = destinationTarget->GetRenderTextureOrThrow();
      mDevice->CopySubresourceRegion(
        destinationResource, 0U, destinationX, destinationY, 0U, sourceResource, 0U, sourceBoxPtr
      );
      return;
    }

    StretchRectBlit(
      destinationContext->width_,
      destinationContext->height_,
      destinationTarget->GetRenderTargetViewOrThrow(),
      sourceTarget->GetShaderResourceViewOrThrow()
    );
  }

  /**
   * Address: 0x008F8920 (FUN_008F8920)
   *
   * What it does:
   * Saves the viewport, covers the destination with one when there is a
   * destination, saves the bound targets, binds the RTT layout, quad strip and
   * destination, then draws the four-vertex strip once per RTT pass with
   * `g_txSource` set to `source`, and restores the viewport and targets.
   */
  void DeviceD3D10::StretchRectBlit(
    const UINT width, const UINT height, ID3D10RenderTargetView* const destination, ID3D10ShaderResourceView* const source
  )
  {
    D3D10_VIEWPORT savedViewport{};
    UINT savedViewportCount = 1U;
    mDevice->RSGetViewports(&savedViewportCount, &savedViewport);

    if (destination != nullptr) {
      D3D10_VIEWPORT fullViewport{};
      fullViewport.Width = width;
      fullViewport.Height = height;
      fullViewport.MinDepth = 0.0f;
      fullViewport.MaxDepth = 1.0f;
      mDevice->RSSetViewports(1U, &fullViewport);
    }

    ID3D10RenderTargetView* previousRenderTargetView = nullptr;
    ID3D10DepthStencilView* previousDepthStencilView = nullptr;
    mDevice->OMGetRenderTargets(1U, &previousRenderTargetView, &previousDepthStencilView);

    mDevice->IASetInputLayout(mRttInputLayout);
    const UINT stride = sizeof(RttVertex);
    const UINT offset = 0U;
    mDevice->IASetVertexBuffers(0U, 1U, &mRttQuadVertexBuffer, &stride, &offset);
    mDevice->IASetPrimitiveTopology(D3D10_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

    if (destination != nullptr) {
      ID3D10RenderTargetView* const renderTargets[1] = {destination};
      mDevice->OMSetRenderTargets(1U, renderTargets, nullptr);
    }

    D3D10_TECHNIQUE_DESC techniqueDesc{};
    mRttTechnique->GetDesc(&techniqueDesc);
    for (UINT passIndex = 0U; passIndex < techniqueDesc.Passes; ++passIndex) {
      mRttEffect->GetVariableByName("g_txSource")->AsShaderResource()->SetResource(source);
      mRttTechnique->GetPassByIndex(passIndex)->Apply(0U);
      mDevice->Draw(4U, 0U);
    }

    mDevice->RSSetViewports(1U, &savedViewport);
    mDevice->OMSetRenderTargets(1U, &previousRenderTargetView, previousDepthStencilView);
  }

  /**
   * Address: 0x008FBDF0 (FUN_008FBDF0)
   *
   * What it does:
   * Copies matching texture contexts directly; otherwise executes recovered
   * memory-encode/decode fallback before the final destination copy.
   */
  void DeviceD3D10::UpdateSurface(
    const boost::shared_ptr<Texture>& source,
    const boost::shared_ptr<Texture>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1091, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1092, "Missing dest   texture");
    }

    auto* const sourceTexture = static_cast<TextureD3D10*>(source.get());
    auto* const destinationTexture = static_cast<TextureD3D10*>(destination.get());
    const TextureContext* const sourceContext = sourceTexture->GetContext();
    const TextureContext* const destinationContext = destinationTexture->GetContext();
    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<unsigned int>(destinationRect->left);
        destinationY = static_cast<unsigned int>(destinationRect->top);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const RECT* const rect = sourceRect;
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      ID3D10Texture2D* const sourceResource = sourceTexture->GetTextureOrThrow();
      ID3D10Texture2D* const destinationResource = destinationTexture->GetTextureOrThrow();
      mDevice->CopySubresourceRegion(
        destinationResource, 0U, destinationX, destinationY, 0U, sourceResource, 0U, sourceBoxPtr
      );
      return;
    }

    ID3D10Blob* createBlobScratch = nullptr;
    HRESULT result = mD3D10CreateBlob(0U, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1109, result);
    }

    ID3D10Blob* encodedTextureBlob = nullptr;
    result = mD3DX10SaveTextureToMemory(sourceTexture->GetTextureOrThrow(), D3DX10_IFF_DDS, &encodedTextureBlob);
    if (result < 0) {
      SafeRelease(createBlobScratch);
      ThrowDeviceD3D10Hresult(1112, result);
    }

    // The SDK constructor's defaults (the out-of-line copy is 0x008F8670),
    // then one mip level of DXT5.
    D3DX10_IMAGE_LOAD_INFO loadInfo;
    loadInfo.MipLevels = 1U;
    loadInfo.Format = DXGI_FORMAT_BC3_UNORM;

    ID3D10Resource* recreatedTexture = nullptr;
    if (encodedTextureBlob != nullptr) {
      result = mD3DX10CreateTextureFromMemory(
        mDevice,
        encodedTextureBlob->GetBufferPointer(),
        encodedTextureBlob->GetBufferSize(),
        &loadInfo,
        nullptr,
        &recreatedTexture
      );
      if (result < 0) {
        SafeRelease(encodedTextureBlob);
        SafeRelease(createBlobScratch);
        ThrowDeviceD3D10Hresult(1130, result);
      }
    }

    if (recreatedTexture != nullptr) {
      mDevice->CopyResource(destinationTexture->GetTextureOrThrow(), recreatedTexture);
    }

    if (encodedTextureBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    SafeRelease(recreatedTexture);
    SafeRelease(encodedTextureBlob);
    SafeRelease(createBlobScratch);
  }

  /**
   * Address: 0x008FC9B0 (FUN_008FC9B0)
   *
   * What it does:
   * Writes one colour target's texture to `filePath`, mapping `fileFormat`
   * through the image-format table at `DAT_00D430A0`.
   */
  void DeviceD3D10::SaveRenderTarget(
    const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, const int fileFormat
  )
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormat);
    auto* const target = static_cast<RenderTargetD3D10*>(renderTarget.get());
    const HRESULT result = mD3DX10SaveTextureToFileA(
      target->GetRenderTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), filePath.c_str()
    );
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1286, result);
    }
  }

  /**
   * Address: 0x008FC6B0 (FUN_008FC6B0)
   *
   * What it does:
   * Encodes one texture in image format `fileFormat`: to `filePath` when
   * `outBuffer` is null, otherwise into `outBuffer` through a D3DX memory
   * blob.
   */
  void DeviceD3D10::SaveTexture(
    const boost::shared_ptr<Texture>& texture,
    const msvc8::string& filePath,
    const int fileFormat,
    gpg::MemBuffer<char>* const outBuffer
  )
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormat);
    auto* const sourceTexture = static_cast<TextureD3D10*>(texture.get());

    if (outBuffer == nullptr) {
      const HRESULT result = mD3DX10SaveTextureToFileA(
        sourceTexture->GetTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), filePath.c_str()
      );
      if (result < 0) {
        ThrowDeviceD3D10Hresult(1275, result);
      }
      return;
    }

    ID3D10Blob* createBlobScratch = nullptr;
    HRESULT result = mD3D10CreateBlob(0U, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1259, result);
    }

    ID3D10Blob* encodedBlob = nullptr;
    result = mD3DX10SaveTextureToMemory(
      sourceTexture->GetTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), &encodedBlob
    );
    if (result >= 0) {
      const std::size_t encodedBytes = encodedBlob->GetBufferSize();
      if (outBuffer->Size() != encodedBytes) {
        gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(encodedBytes);
        *outBuffer = resizedBuffer;
      }

      std::memcpy(outBuffer->GetPtr(0U, 0U), encodedBlob->GetBufferPointer(), encodedBytes);
    }

    if (encodedBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    SafeRelease(encodedBlob);
    SafeRelease(createBlobScratch);

    if (result < 0) {
      ThrowDeviceD3D10Hresult(1270, result);
    }
  }

  /**
   * Address: 0x008FCAC0 (FUN_008FCAC0)
   *
   * void const *,uint32_t,gpg::MemBuffer<char> *,uint32_t *,int *
   *
   * What it does:
   * Builds one texture resource from in-memory bytes, stages it for CPU read,
   * then copies mapped texture blocks into caller memory and writes width/height.
   */
  void DeviceD3D10::GetTexture2D(
    const void* const sourceData,
    const std::uint32_t sourceBytes,
    gpg::MemBuffer<char>* const outTextureData,
    std::uint32_t* const outWidth,
    int* const outHeight
  )
  {
    if (sourceData == nullptr) {
      return;
    }

    // The SDK constructor's defaults (inlined here), then one mip level of DXT5.
    D3DX10_IMAGE_LOAD_INFO loadInfo;
    loadInfo.MipLevels = 1U;
    loadInfo.Format = DXGI_FORMAT_BC3_UNORM;

    ID3D10Resource* decodedResource = nullptr;
    HRESULT result = mD3DX10CreateTextureFromMemory(mDevice, sourceData, sourceBytes, &loadInfo, nullptr, &decodedResource);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1317, result);
    }

    if (decodedResource == nullptr) {
      return;
    }

    ID3D10Texture2D* sourceTexture = nullptr;
    static_cast<void>(decodedResource->QueryInterface(IID_PPV_ARGS(&sourceTexture)));
    if (sourceTexture == nullptr) {
      // Kept from the binary: without the interface it uses the resource as a
      // 2D texture anyway.
      sourceTexture = static_cast<ID3D10Texture2D*>(decodedResource);
      sourceTexture->AddRef();
    }

    D3D10_TEXTURE2D_DESC textureDesc{};
    sourceTexture->GetDesc(&textureDesc);
    *outWidth = textureDesc.Width;
    *outHeight = static_cast<int>(textureDesc.Height);

    textureDesc.Usage = D3D10_USAGE_STAGING;
    textureDesc.BindFlags = 0U;
    textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

    ID3D10Texture2D* stagingTexture = nullptr;
    result = mDevice->CreateTexture2D(&textureDesc, nullptr, &stagingTexture);
    if (result < 0) {
      SafeRelease(sourceTexture);
      SafeRelease(decodedResource);
      ThrowDeviceD3D10Hresult(1343, result);
    }

    mDevice->CopyResource(stagingTexture, sourceTexture);

    D3D10_MAPPED_TEXTURE2D mappedTexture{};
    result = stagingTexture->Map(0U, D3D10_MAP_READ, 0U, &mappedTexture);
    if (result < 0) {
      SafeRelease(stagingTexture);
      SafeRelease(sourceTexture);
      SafeRelease(decodedResource);
      ThrowDeviceD3D10Hresult(1352, result);
    }

    const std::uint32_t rowBytes = 16U * ((textureDesc.Width + 3U) / 4U);
    const std::uint32_t rowCount = (textureDesc.Height + 3U) / 4U;
    const std::size_t requiredBytes = static_cast<std::size_t>(rowBytes) * static_cast<std::size_t>(rowCount);
    if (outTextureData->Size() != requiredBytes) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(requiredBytes);
      *outTextureData = resizedBuffer;
    }

    char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
    const auto* const sourceBytesPtr = reinterpret_cast<const std::uint8_t*>(mappedTexture.pData);
    if (static_cast<unsigned int>(mappedTexture.RowPitch) == rowBytes) {
      std::memcpy(destinationBytes, sourceBytesPtr, requiredBytes);
    } else {
      char* writeCursor = destinationBytes;
      for (std::uint32_t row = 0U; row < rowCount; ++row) {
        std::memcpy(writeCursor, sourceBytesPtr + (static_cast<std::size_t>(mappedTexture.RowPitch) * row), rowBytes);
        writeCursor += rowBytes;
      }
    }

    stagingTexture->Unmap(0U);
    SafeRelease(stagingTexture);
    SafeRelease(sourceTexture);
    SafeRelease(decodedResource);
  }

  /**
   * Address: 0x008FA260 (FUN_008FA260)
   *
   * boost::weak_ptr<void> *,boost::shared_ptr<void>
   *
   * What it does:
   * Clears caller weak-handle output lane and consumes one temporary shared
   * handle by value.
   */
  boost::weak_ptr<void>*
  DeviceD3D10::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
  {
    static_cast<void>(temporarySharedHandle);
    outWeakHandle->reset();
    return outWeakHandle;
  }

  /**
   * Address: 0x008F8700 (FUN_008F8700)
   *
   * What it does:
   * D3D10 cannot save a cube target: the body is a bare `ret 8`.
   */
  void DeviceD3D10::SaveCubeRenderTarget(
    const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const msvc8::string& filePath
  )
  {
    static_cast<void>(cubeTarget);
    static_cast<void>(filePath);
  }

  /**
   * Address: 0x008F8720 (FUN_008F8720)
   *
   * What it does:
   * Preserves the binary no-op virtual slot.
   */
  void DeviceD3D10::Reset() {}

  /**
   * Address: 0x008F8710 (FUN_008F8710)
   *
   * int
   *
   * What it does:
   * Preserves the binary no-op virtual slot (`retn 4` shape).
   */
  void DeviceD3D10::Reset(DeviceContext* const /*context*/)
  {
  }

  /**
   * Address: 0x008F8730 (FUN_008F8730)
   *
   * What it does:
   * Preserves the binary "device-ready" lane by returning success (`0`).
   */
  int DeviceD3D10::TestCooperativeLevel()
  {
    return 0;
  }

  /**
   * Address: 0x008F8740 (FUN_008F8740)
   *
   * What it does:
   * Preserves the binary no-op begin-scene slot.
   */
  void DeviceD3D10::BeginScene() {}

  /**
   * Address: 0x008F8750 (FUN_008F8750)
   *
   * What it does:
   * Preserves the binary no-op end-scene slot.
   */
  void DeviceD3D10::EndScene() {}

  /**
   * Address: 0x008F8760 (FUN_008F8760)
   *
   * CursorContext const *
   *
   * What it does:
   * Tail-delegates to the retained `CursorD3D10` lane at `this+0x11C` and
   * rebuilds/applies cursor icon state from caller context.
   */
  void DeviceD3D10::SetCursor(const CursorContext* const context)
  {
    static_cast<void>(mCursor.SetCursor(context));
  }

  /**
   * Address: 0x008F8770 (FUN_008F8770)
   *
   * What it does:
   * Tail-delegates to retained cursor lane initialization (`CursorD3D10::InitCursor`).
   */
  void DeviceD3D10::InitCursor()
  {
    static_cast<void>(mCursor.InitCursor());
  }

  /**
   * Address: 0x008F8780 (FUN_008F8780)
   *
   * bool
   *
   * What it does:
   * Tail-delegates to retained cursor show/hide loop control
   * (`CursorD3D10::ShowCursor`).
   */
  int DeviceD3D10::ShowCursor(const bool show)
  {
    return mCursor.ShowCursor(show);
  }

  /**
   * Address: 0x008F8790 (FUN_008F8790)
   *
   * void const *
   *
   * What it does:
   * Copies one caller viewport payload and binds it as the single native D3D10 viewport.
   */
  void DeviceD3D10::SetViewport(const D3DVIEWPORT9* const viewport)
  {
    D3D10_VIEWPORT viewportCopy{};
    viewportCopy.TopLeftX = static_cast<INT>(viewport->X);
    viewportCopy.TopLeftY = static_cast<INT>(viewport->Y);
    viewportCopy.Width = viewport->Width;
    viewportCopy.Height = viewport->Height;
    viewportCopy.MinDepth = viewport->MinZ;
    viewportCopy.MaxDepth = viewport->MaxZ;
    mDevice->RSSetViewports(1U, &viewportCopy);
  }

  /**
   * Address: 0x008F87F0 (FUN_008F87F0)
   *
   * void *
   *
   * What it does:
   * Fetches one native viewport payload and copies it back into caller memory.
   */
  void DeviceD3D10::GetViewport(D3DVIEWPORT9* const outViewport)
  {
    UINT viewportCount = 1U;
    D3D10_VIEWPORT viewport{};
    mDevice->RSGetViewports(&viewportCount, &viewport);

    outViewport->X = static_cast<DWORD>(viewport.TopLeftX);
    outViewport->Y = static_cast<DWORD>(viewport.TopLeftY);
    outViewport->Width = viewport.Width;
    outViewport->Height = viewport.Height;
    outViewport->MinZ = viewport.MinDepth;
    outViewport->MaxZ = viewport.MaxDepth;
  }

  /**
   * Address: 0x008FCEA0 (FUN_008FCEA0)
   *
   * What it does:
   * Presents each retained swap-chain slot and throws `gpg::gal::Error` on the
   * first failing HRESULT.
   */
  void DeviceD3D10::Present()
  {
    for (IDXGISwapChain* const swapChain : mSwapChains) {
      const HRESULT result = swapChain->Present(0U, 0U);
      if (result < 0) {
        throw Error(MakeShortString("DeviceD3D10.cpp"), 1415, MakeD3DErrorString(result));
      }
    }
  }

  /**
   * Address: 0x008FCF90 (FUN_008FCF90)
   *
   * What it does:
   * Validates the topology, binds the native primitive topology, then dispatches
   * `Draw` vs `DrawInstanced` using the instance count at `this+0xD8`.
   */
  void DeviceD3D10::DrawPrimitive(const DrawContext* const context)
  {
    // D3D10's Draw takes the vertex count as is (`mov edx,[edi+8]` at
    // 0x008FD05D); only the D3D9 backend converts it to primitives.
    if (context->topology_ == 0) {
      ThrowInvalidTopologyError(1561);
    }

    mDevice->IASetPrimitiveTopology(static_cast<D3D10_PRIMITIVE_TOPOLOGY>(ResolvePrimitiveTopology(context->topology_)));

    // Slot 0's frequency is the instance count (0x008FD049 reads this+0xD8).
    const UINT instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mDevice->DrawInstanced(context->vertexCount_, instanceCount, context->startVertex_, 0U);
    } else {
      mDevice->Draw(context->vertexCount_, context->startVertex_);
    }

    // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  /**
   * Address: 0x008FD0A0 (FUN_008FD0A0)
   *
   * What it does:
   * Validates the topology, binds the native primitive topology, then
   * dispatches `DrawIndexed` vs `DrawIndexedInstanced`.
   */
  void DeviceD3D10::DrawIndexedPrimitive(const DrawIndexedContext* const context)
  {
    // As above: DrawIndexed takes the index count as is (`mov edx,[edi+0x10]`
    // at 0x008FD16E).
    if (context->topology_ == 0) {
      ThrowInvalidTopologyError(1580);
    }

    mDevice->IASetPrimitiveTopology(static_cast<D3D10_PRIMITIVE_TOPOLOGY>(ResolvePrimitiveTopology(context->topology_)));

    // Slot 0's frequency is the instance count (0x008FD159 reads this+0xD8).
    const UINT instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mDevice->DrawIndexedInstanced(context->indexCount_, instanceCount, context->startIndex_, 0, 0U);
    } else {
      mDevice->DrawIndexed(context->indexCount_, context->startIndex_, 0);
    }

    // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  /**
   * Address: 0x008F94B0 (FUN_008F94B0)
   *
   * OutputContext const *
   *
   * What it does:
   * Copies one output-context snapshot into retained device state, resolves
   * active render/depth view handles, and dispatches native target clear.
   */
  void DeviceD3D10::ClearTarget(const OutputContext* const context)
  {
    Device::ClearTarget(context);

    ID3D10RenderTargetView* renderTargetView = nullptr;
    ID3D10DepthStencilView* depthStencilView = nullptr;

    if (context != nullptr) {
      if (context->surface.get() != nullptr) {
        renderTargetView = static_cast<RenderTargetD3D10*>(context->surface.get())->GetRenderTargetViewOrThrow();
      }

      if (context->depthStencil.get() != nullptr) {
        depthStencilView =
          static_cast<DepthStencilTargetD3D10*>(context->depthStencil.get())->GetDepthStencilViewOrThrow();
      }
    }

    mDevice->OMSetRenderTargets(1U, &renderTargetView, depthStencilView);
  }

  /**
   * Address: 0x008F9510 (FUN_008F9510)
   *
   * bool,bool,bool,uint32_t,float,int
   *
   * What it does:
   * Clears the bound colour view with the unpacked ARGB colour, and the
   * depth-stencil view with the depth/stencil flags that were asked for.
   */
  void DeviceD3D10::Clear(
    const bool clearColor,
    const bool clearDepth,
    const bool clearStencil,
    const std::uint32_t packedColor,
    const float depth,
    const int stencil
  )
  {
    ID3D10RenderTargetView* renderTargetView = nullptr;
    ID3D10DepthStencilView* depthStencilView = nullptr;

    if (outputContext_.surface.get() != nullptr) {
      renderTargetView = static_cast<RenderTargetD3D10*>(outputContext_.surface.get())->GetRenderTargetViewOrThrow();
    }

    if (outputContext_.depthStencil.get() != nullptr) {
      depthStencilView =
        static_cast<DepthStencilTargetD3D10*>(outputContext_.depthStencil.get())->GetDepthStencilViewOrThrow();
    }

    if (clearColor && (renderTargetView != nullptr)) {
      float clearColorRgba[4] = {
        static_cast<float>((packedColor >> 16U) & 0xFFU),
        static_cast<float>((packedColor >> 8U) & 0xFFU),
        static_cast<float>(packedColor & 0xFFU),
        static_cast<float>((packedColor >> 24U) & 0xFFU),
      };
      mDevice->ClearRenderTargetView(renderTargetView, clearColorRgba);
    }

    int clearMask = 0;
    if (clearDepth) {
      clearMask |= 1;
    }
    if (clearStencil) {
      clearMask |= 2;
    }

    if ((clearMask != 0) && (depthStencilView != nullptr)) {
      mDevice->ClearDepthStencilView(
        depthStencilView, static_cast<UINT>(clearMask), depth, static_cast<UINT8>(stencil)
      );
    }
  }

  /**
   * Address: 0x008FE6D0 (FUN_008FE6D0)
   *
   * What it does:
   * Preserves the binary no-op fog-state lane.
   */
  void DeviceD3D10::SetFogState(
    const bool /*enable*/,
    const Matrix* const /*projection*/,
    const float /*fogStart*/,
    const float /*fogEnd*/,
    const int /*fogColor*/
  )
  {
  }

  /**
   * Address: 0x008FE6E0 (FUN_008FE6E0)
   *
   * What it does:
   * Preserves the binary no-op wireframe-state lane.
   */
  void DeviceD3D10::SetWireframeState(const bool /*enabled*/)
  {
  }

  /**
   * Address: 0x008FE6F0 (FUN_008FE6F0)
   *
   * What it does:
   * Preserves the binary no-op color-write-state lane.
   */
  void DeviceD3D10::SetColorWriteState(const bool /*writeColor*/, const bool /*writeAlpha*/)
  {
  }

  /**
   * Address: 0x008F95F0 (FUN_008F95F0)
   *
   * What it does:
   * Clears shader-resource bindings for 128 texture slots on the retained
   * technique-state native device lane.
   */
  void DeviceD3D10::ClearTextures()
  {
    mPipelineState->ClearTextures();
  }

  /**
   * Address: 0x008F9600 (FUN_008F9600)
   *
   * What it does:
   * Binds `vertexFormat`'s input layout (through
   * `VertexFormatD3D10::ValidateLayoutOrThrow`, 0x008F962B).
   */
  void DeviceD3D10::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
  {
    mDevice->IASetInputLayout(static_cast<VertexFormatD3D10*>(vertexFormat.get())->ValidateLayoutOrThrow());
  }

  /**
   * Address: 0x008F9690 (FUN_008F9690)
   *
   * What it does:
   * Binds `vertexBuffer` on input slot `streamSlot`, starting `startVertex`
   * vertices in, and records `streamFrequencyToken` for the slot. D3D10 has
   * no stream frequency of its own: the draws read slot 0's value back as the
   * instance count.
   */
  void DeviceD3D10::SetVertexBuffer(
    const std::uint32_t streamSlot,
    const boost::shared_ptr<VertexBuffer> vertexBuffer,
    const int streamFrequencyToken,
    const int startVertex
  )
  {
    const VertexBufferContext* const context = vertexBuffer->GetContext();
    ID3D10Buffer* const nativeVertexBuffer = static_cast<VertexBufferD3D10*>(vertexBuffer.get())->GetNativeBufferOrThrow();
    const UINT stride = context->stride_;
    const UINT offset = static_cast<UINT>(startVertex * static_cast<int>(stride));
    mDevice->IASetVertexBuffers(streamSlot, 1U, &nativeVertexBuffer, &stride, &offset);

    mStreamFrequencies[streamSlot] = streamFrequencyToken;
  }

  /**
   * Address: 0x008F9760 (FUN_008F9760)
   *
   * What it does:
   * Binds `indexBuffer` as the index source at offset 0, 32-bit for index
   * format 2 and 16-bit otherwise.
   */
  void DeviceD3D10::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
  {
    const IndexBufferContext* const context = indexBuffer->GetContext();
    const DXGI_FORMAT indexFormat = (context->format_ == 2U) ? DXGI_FORMAT_R32_UINT : DXGI_FORMAT_R16_UINT;
    ID3D10Buffer* const nativeIndexBuffer = static_cast<IndexBufferD3D10*>(indexBuffer.get())->GetNativeBufferOrThrow();
    mDevice->IASetIndexBuffer(nativeIndexBuffer, indexFormat, 0U);
  }

  /**
   * Address: 0x008F9810 (FUN_008F9810)
   *
   * What it does:
   * `mov ecx, [ecx+0xB4]; jmp`: the pipeline state's `BeginTechnique`.
   */
  void DeviceD3D10::BeginTechnique()
  {
    mPipelineState->BeginTechnique();
  }

  /**
   * Address: 0x008F9820 (FUN_008F9820)
   *
   * What it does:
   * `mov ecx, [ecx+0xB4]; jmp`: the pipeline state's (empty) `EndTechnique`.
   */
  void DeviceD3D10::EndTechnique()
  {
    mPipelineState->EndTechnique();
  }

  /**
   * Address: 0x009045E0 (FUN_009045E0)
   *
   * unsigned int,void *
   *
   * What it does:
   * Initializes one D3D10 vertex-format wrapper from caller format/declaration
   * inputs and rebuilds per-stream stride lanes.
   */
  VertexFormatD3D10::VertexFormatD3D10(const std::uint32_t format, ID3D10InputLayout* const vertexDeclaration)
    : vertexDeclaration_(nullptr)
  {
    formatCode_ = 0x17U;
    Initialize(format, vertexDeclaration);
  }

  /**
   * Address: 0x009041E0 (FUN_009041E0)
   * Address: 0x00904260 (FUN_00904260, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the input layout and leaves format code `0x17`, then the
   * `VertexFormat` base destructor frees the stride vector (inlined,
   * 0x00904225).
   */
  VertexFormatD3D10::~VertexFormatD3D10()
  {
    ResetDeclaration();
  }

  /**
   * Address: 0x00904180 (FUN_00904180)
   *
   * What it does:
   * Releases the input layout and restores format code `0x17`.
   */
  void VertexFormatD3D10::ResetDeclaration()
  {
    SafeRelease(vertexDeclaration_);
    formatCode_ = 0x17U;
  }

  /**
   * Address: 0x00904280 (FUN_00904280)
   *
   * What it does:
   * Validates that one retained declaration handle is bound and returns it.
   */
  ID3D10InputLayout* VertexFormatD3D10::ValidateLayoutOrThrow()
  {
    if (vertexDeclaration_ == nullptr) {
      ThrowGalError("VertexFormatD3D10.cpp", 149, "invalid vertex layout");
    }

    return vertexDeclaration_;
  }

  /**
   * Address: 0x00904500 (FUN_00904500)
   *
   * unsigned int,void *
   *
   * What it does:
   * Rebinds declaration state, validates static table ownership for the format
   * token, and rebuilds per-stream stride lanes from recovered element records.
   */
  std::uint32_t VertexFormatD3D10::Initialize(const std::uint32_t format, ID3D10InputLayout* const vertexDeclaration)
  {
    ResetDeclaration();
    vertexDeclaration_ = vertexDeclaration;
    formatCode_ = format;

    const D3D10_INPUT_ELEMENT_DESC* const layoutElements = GetVertexLayoutElementsOrThrow(formatCode_);
    const std::uint32_t layoutElementCount = GetVertexLayoutElementCountOrThrow(formatCode_);

    streamStrides_.clear();

    std::uint32_t result = layoutElementCount;
    for (std::uint32_t index = 0; index < layoutElementCount; ++index) {
      const D3D10_INPUT_ELEMENT_DESC& element = layoutElements[index];
      if (streamStrides_.size() <= element.InputSlot) {
        streamStrides_.resize(element.InputSlot + 1U, 0U);
      }

      std::uint32_t& streamStride = streamStrides_[element.InputSlot];
      const std::uint32_t candidate = element.AlignedByteOffset + GetTextureFormatBlockBytes(element.Format);
      result = (streamStride > candidate) ? streamStride : candidate;
      streamStride = result;
    }

    return result;
  }

  /**
   * Address: 0x0094C070 (FUN_0094C070)
   *
   * EffectContext const &,void *
   *
   * What it does:
   * Starts from an empty context and a null effect, then adopts the caller's
   * through `SetEffect`.
   */
  EffectD3D10::EffectD3D10(const EffectContext& context, ID3D10Effect* const dxEffect)
  {
    SetEffect(context, dxEffect);
  }

  /**
   * Address: 0x0094BF10 (FUN_0094BF10)
   *
   * What it does:
   * Releases the native effect and assigns a fresh context over `context_`.
   */
  void EffectD3D10::Reset()
  {
    SafeRelease(dxEffect_);
    context_ = EffectContext();
  }

  /**
   * Address: 0x0094BFE0 (FUN_0094BFE0)
   *
   * What it does:
   * Resets, copies `context` into `context_`, adopts `dxEffect`, then empties
   * the copied source buffer (the four words at this+0x48..+0x54, releasing
   * the shared owner at +0x4C first).
   */
  void EffectD3D10::SetEffect(const EffectContext& context, ID3D10Effect* const dxEffect)
  {
    Reset();
    context_ = context;
    dxEffect_ = dxEffect;
    context_.mSourceBuffer.Reset();
  }

  /**
   * Address: 0x0094BF80 (FUN_0094BF80)
   * Address: 0x0094C050 (FUN_0094C050, the scalar deleting destructor)
   *
   * What it does:
   * `Reset()`; `context_` is then destroyed once, as a member (0x0093F950).
   */
  EffectD3D10::~EffectD3D10()
  {
    Reset();
  }

  /**
   * Address: 0x0094B5D0 (FUN_0094B5D0)
   *
   * What it does:
   * Returns the embedded effect-context lane at `this+0x04`.
   */
  EffectContext* EffectD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094BC60 (FUN_0094BC60)
   *
   * msvc8::vector<boost::shared_ptr<gpg::gal::EffectTechnique>> &
   *
   * What it does:
   * Walks the techniques by index and appends a wrapper for every valid one:
   * the same `push_back` emission as the D3D9 backend (0x00942860, called at
   * 0x0094BE69), on a temporary whose constructor the binary inlines around
   * `shared_count(EffectTechniqueD3D10*)` 0x0094B6C0.
   */
  void EffectD3D10::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 52, "invalid effect");
    }

    D3D10_EFFECT_DESC effectDesc{};
    HRESULT result = dxEffect_->GetDesc(&effectDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectD3D10.cpp", 57, result);
    }

    for (UINT index = 0U; index < effectDesc.Techniques; ++index) {
      ID3D10EffectTechnique* const techniqueHandle = dxEffect_->GetTechniqueByIndex(index);
      if ((techniqueHandle == nullptr) || !techniqueHandle->IsValid()) {
        continue;
      }

      D3D10_TECHNIQUE_DESC techniqueDesc{};
      result = techniqueHandle->GetDesc(&techniqueDesc);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectD3D10.cpp", 69, result);
      }

      outTechniques.push_back(
        boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D10(techniqueDesc.Name, dxEffect_, techniqueHandle))
      );
    }
  }

  /**
   * Address: 0x0094B8A0 (FUN_0094B8A0)
   *
   * char const *
   *
   * What it does:
   * Wraps the effect variable called `variableName`; throws when the effect
   * or the variable is missing.
   */
  boost::shared_ptr<EffectVariable> EffectD3D10::GetVariable(const char* const variableName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 79, "invalid effect");
    }

    ID3D10EffectVariable* const variableHandle = dxEffect_->GetVariableByName(variableName);
    if (variableHandle == nullptr) {
      char message[512] = {};
      std::snprintf(
        message, sizeof(message), "invalid effect variable requested: %s", (variableName != nullptr) ? variableName : ""
      );
      ThrowGalError("EffectD3D10.cpp", 82, message);
    }

    return boost::shared_ptr<EffectVariable>(new EffectVariableD3D10(variableName, dxEffect_, variableHandle));
  }

  /**
   * Address: 0x0094BA80 (FUN_0094BA80)
   *
   * char const *
   *
   * What it does:
   * Wraps the technique called `techniqueName`; throws when the effect or
   * the technique is missing.
   */
  boost::shared_ptr<EffectTechnique> EffectD3D10::GetTechnique(const char* const techniqueName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 89, "invalid effect");
    }

    ID3D10EffectTechnique* const techniqueHandle = dxEffect_->GetTechniqueByName(techniqueName);
    if (techniqueHandle == nullptr) {
      char message[512] = {};
      std::snprintf(
        message,
        sizeof(message),
        "invalid effect technique requested: %s",
        (techniqueName != nullptr) ? techniqueName : ""
      );
      ThrowGalError("EffectD3D10.cpp", 92, message);
    }

    return boost::shared_ptr<EffectTechnique>(new EffectTechniqueD3D10(techniqueName, dxEffect_, techniqueHandle));
  }

  /**
   * Address: 0x00900FF0 (FUN_00900FF0)
   *
   * char const *,void *,void *
   *
   * What it does:
   * Initializes wrapper state for one D3D10 technique and retains the backing
   * effect interface through `AddRef`.
   */
  EffectTechniqueD3D10::EffectTechniqueD3D10(
    const char* const name, ID3D10Effect* const dxEffect, ID3D10EffectTechnique* const techniqueHandle
  )
    : name_()
    , dxEffect_(dxEffect)
    , techniqueHandle_(techniqueHandle)
    , beginEndActive_(false)
    , beginEndPadding_{}
  {
    name_.assign_owned((name != nullptr) ? name : "");

    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 39, "invalid effect specified");
    }

    dxEffect_->AddRef();
  }

  /**
   * Address: 0x00900F50 (FUN_00900F50)
   * Address: 0x00900FD0 (FUN_00900FD0, the scalar deleting destructor)
   *
   * What it does:
   * Releases the native effect. The name then goes as a member; the technique
   * handle and the begin/end flag are left as they are.
   */
  EffectTechniqueD3D10::~EffectTechniqueD3D10()
  {
    SafeRelease(dxEffect_);
  }

  /**
   * Address: 0x00900EF0 (FUN_00900EF0)
   *
   * What it does:
   * Returns the wrapper's local technique name.
   */
  msvc8::string* EffectTechniqueD3D10::GetName()
  {
    return &name_;
  }

  /**
   * Address: 0x00901110 (FUN_00901110)
   *
   * What it does:
   * Begins technique execution on the active device and returns pass count.
   */
  int EffectTechniqueD3D10::BeginTechnique()
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 56, "invalid effect technique");
    }

    Device::GetInstance()->BeginTechnique();

    D3D10_TECHNIQUE_DESC techniqueDesc{};
    const HRESULT result = techniqueHandle_->GetDesc(&techniqueDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 67, result);
    }

    beginEndActive_ = true;
    return static_cast<int>(techniqueDesc.Passes);
  }

  /**
   * Address: 0x00901290 (FUN_00901290)
   *
   * What it does:
   * Ends the active technique lane and clears begin/end tracking.
   */
  void EffectTechniqueD3D10::EndTechnique()
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 77, "effect technique begin/end mismatch");
    }

    Device::GetInstance()->EndTechnique();
    beginEndActive_ = false;
  }

  /**
   * Address: 0x00901360 (FUN_00901360)
   *
   * What it does:
   * Applies a pass from the active D3D10 technique handle.
   */
  void EffectTechniqueD3D10::BeginPass(const int pass)
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 89, "effect technique begin/end mismatch");
    }

    const HRESULT result = techniqueHandle_->GetPassByIndex(static_cast<UINT>(pass))->Apply(0U);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 93, result);
    }
  }

  /**
   * Address: 0x009014D0 (FUN_009014D0)
   *
   * What it does:
   * Validates pass sequencing for the currently active technique.
   */
  void EffectTechniqueD3D10::EndPass()
  {
    if (!beginEndActive_) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 98, "effect technique begin/end mismatch");
    }
  }

  /**
   * Address: 0x00901580 (FUN_00901580)
   *
   * What it does:
   * Fetches a boolean annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 105, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    BOOL boolValue = FALSE;
    const HRESULT result = annotation->AsScalar()->GetBool(&boolValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 115, result);
    }

    *outValue = (boolValue == 1);
    return true;
  }

  /**
   * Address: 0x00901710 (FUN_00901710)
   *
   * What it does:
   * Fetches an integer annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 124, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetInt(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 133, result);
    }

    return true;
  }

  /**
   * Address: 0x00901880 (FUN_00901880)
   *
   * What it does:
   * Fetches a float annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 140, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetFloat(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 149, result);
    }

    return true;
  }

  /**
   * Address: 0x009019F0 (FUN_009019F0)
   *
   * What it does:
   * Fetches a string annotation by name from the current technique handle.
   */
  bool EffectTechniqueD3D10::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    if (techniqueHandle_ == nullptr) {
      ThrowGalError("EffectTechniqueD3D10.cpp", 156, "invalid effect technique");
    }

    ID3D10EffectVariable* const annotation = techniqueHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    LPCSTR text = nullptr;
    const HRESULT result = annotation->AsString()->GetString(&text);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 166, result);
    }

    outValue->assign_owned((text != nullptr) ? text : "");
    return true;
  }

  /**
   * Address: 0x0094C1F0 (FUN_0094C1F0)
   *
   * char const *,void *,void *
   *
   * What it does:
   * Initializes variable wrapper lanes and retains the backing effect interface.
   */
  EffectVariableD3D10::EffectVariableD3D10(
    const char* const name, ID3D10Effect* const dxEffect, ID3D10EffectVariable* const variableHandle
  )
    : name_()
    , dxEffect_(dxEffect)
    , variableHandle_(variableHandle)
  {
    name_.assign_owned((name != nullptr) ? name : "");

    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 39, "invalid effect specified");
    }

    dxEffect_->AddRef();
  }

  /**
   * Address: 0x0094C150 (FUN_0094C150)
   * Address: 0x0094C1D0 (FUN_0094C1D0, the scalar deleting destructor)
   *
   * What it does:
   * Releases the native effect. The name then goes as a member; the variable
   * handle is left as it is.
   */
  EffectVariableD3D10::~EffectVariableD3D10()
  {
    SafeRelease(dxEffect_);
  }

  /**
   * Address: 0x0094C0E0 (FUN_0094C0E0)
   *
   * What it does:
   * Returns the variable-name string lane.
   */
  msvc8::string* EffectVariableD3D10::GetName()
  {
    return &name_;
  }

  /**
   * Address: 0x0094C0F0 (FUN_0094C0F0)
   *
   * What it does:
   * D3D10 cube render-target slot keeps an empty body and only owns by-value
   * `shared_ptr` release semantics.
   */
  void EffectVariableD3D10::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
  {
    static_cast<void>(cubeTarget);
  }

  /**
   * Address: 0x0094CD00 (FUN_0094CD00)
   *
   * What it does:
   * Binds a render-target-backed shader-resource view into this effect slot.
   */
  void EffectVariableD3D10::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
  {
    ID3D10ShaderResourceView* const shaderResourceView = (renderTarget.get() != nullptr)
      ? static_cast<RenderTargetD3D10*>(renderTarget.get())->GetShaderResourceViewOrThrow()
      : nullptr;
    const HRESULT result = variableHandle_->AsShaderResource()->SetResource(shaderResourceView);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 144, result);
    }
  }

  /**
   * Address: 0x0094CBB0 (FUN_0094CBB0)
   *
   * What it does:
   * Binds a texture shader-resource view into this effect slot.
   */
  void EffectVariableD3D10::SetTexture(const boost::shared_ptr<Texture> texture)
  {
    ID3D10ShaderResourceView* const shaderResourceView =
      (texture.get() != nullptr) ? static_cast<TextureD3D10*>(texture.get())->GetShaderResourceViewOrThrow() : nullptr;
    const HRESULT result = variableHandle_->AsShaderResource()->SetResource(shaderResourceView);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 132, result);
    }
  }

  /**
   * Address: 0x0094C9B0 (FUN_0094C9B0)
   *
   * What it does:
   * Converts to matrix lane and writes one matrix payload.
   */
  void EffectVariableD3D10::SetMatrix4x4(const Matrix* const matrix)
  {
    const HRESULT result = variableHandle_->AsMatrix()->SetMatrix(const_cast<float*>(&matrix->r[0].x));
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 110, result);
    }
  }

  /**
   * Address: 0x0094C310 (FUN_0094C310)
   *
   * What it does:
   * Converts to scalar lane and writes a boolean value.
   */
  void EffectVariableD3D10::SetBool(const bool value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetBool(value ? TRUE : FALSE);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 60, result);
    }
  }

  /**
   * Address: 0x0094C400 (FUN_0094C400)
   *
   * What it does:
   * Converts to scalar lane and writes an integer value.
   */
  void EffectVariableD3D10::SetInt(const int value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetInt(value);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 66, result);
    }
  }

  /**
   * Address: 0x0094C4F0 (FUN_0094C4F0)
   *
   * What it does:
   * Converts to scalar lane and writes a float value.
   */
  void EffectVariableD3D10::SetFloat(const float value)
  {
    const HRESULT result = variableHandle_->AsScalar()->SetFloat(value);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 72, result);
    }
  }

  /**
   * Address: 0x0094C5E0 (FUN_0094C5E0)
   *
   * What it does:
   * Converts to vector lane and writes one vector payload.
   */
  void EffectVariableD3D10::SetVector(const float* const value)
  {
    const HRESULT result = variableHandle_->AsVector()->SetFloatVector(const_cast<float*>(value));
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 78, result);
    }
  }

  /**
   * Address: 0x0094C8C0 (FUN_0094C8C0)
   *
   * void const *,int
   *
   * What it does:
   * Writes `byteCount` raw bytes to the variable.
   */
  void EffectVariableD3D10::SetValue(const void* const data, const std::uint32_t byteCount)
  {
    const HRESULT result = variableHandle_->SetRawValue(const_cast<void*>(data), 0U, byteCount);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 103, result);
    }
  }

  /**
   * Address: 0x0094C7D0 (FUN_0094C7D0)
   *
   * int,void const *
   *
   * What it does:
   * Writes `count` floats as raw bytes (`count * 4`).
   */
  void EffectVariableD3D10::SetFloatArray(const std::uint32_t count, const float* const values)
  {
    const HRESULT result = variableHandle_->SetRawValue(const_cast<float*>(values), 0U, count * 4U);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 96, result);
    }
  }

  /**
   * Address: 0x0094CAA0 (FUN_0094CAA0)
   *
   * int,void const *
   *
   * What it does:
   * `AsMatrix()->SetMatrixArray`, handed the address of the `matrices`
   * parameter itself rather than its value (`lea edx, [esp+0xA8]` at
   * 0x0094CAD8; the D3D9 twin passes the pointer). When that fails it falls
   * back to `SetRawValue` with the pointer, but sized as `count` floats
   * (`count * 4` bytes), not `count` matrices. Kept as the binary has it.
   */
  void EffectVariableD3D10::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
  {
    auto* const parameterAddress = reinterpret_cast<float*>(const_cast<const Matrix**>(&matrices));
    HRESULT result = variableHandle_->AsMatrix()->SetMatrixArray(parameterAddress, 0U, count);
    if (result < 0) {
      result = variableHandle_->SetRawValue(const_cast<Matrix*>(matrices), 0U, count * 4U);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 121, result);
      }
    }
  }

  /**
   * Address: 0x0094C6D0 (FUN_0094C6D0)
   *
   * int,unsigned int
   *
   * What it does:
   * `AsVector()->SetFloatVectorArray`, handed the address of the `vectors4`
   * parameter itself rather than its value (`lea edx, [esp+0xA0]` at
   * 0x0094C704) -- the same slip as the D3D9 twin. Nothing in the binary
   * calls the slot.
   */
  void EffectVariableD3D10::SetVectorArray(const std::uint32_t count, const float* const vectors4)
  {
    auto* const parameterAddress = reinterpret_cast<float*>(const_cast<const float**>(&vectors4));
    const HRESULT result = variableHandle_->AsVector()->SetFloatVectorArray(parameterAddress, 0U, count);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 88, result);
    }
  }

  /**
   * Address: 0x0094CE50 (FUN_0094CE50)
   *
   * What it does:
   * Reads a boolean annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 154, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    BOOL boolValue = FALSE;
    const HRESULT result = annotation->AsScalar()->GetBool(&boolValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 164, result);
    }

    *outValue = (boolValue == 1);
    return true;
  }

  /**
   * Address: 0x0094CFE0 (FUN_0094CFE0)
   *
   * What it does:
   * Reads an integer annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 173, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetInt(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 182, result);
    }

    return true;
  }

  /**
   * Address: 0x0094D150 (FUN_0094D150)
   *
   * What it does:
   * Reads a float annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 189, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    const HRESULT result = annotation->AsScalar()->GetFloat(outValue);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 198, result);
    }

    return true;
  }

  /**
   * Address: 0x0094D2C0 (FUN_0094D2C0)
   *
   * What it does:
   * Reads a string annotation by name from this variable handle.
   */
  bool EffectVariableD3D10::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    if (variableHandle_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 205, "invalid effect variable");
    }

    ID3D10EffectVariable* const annotation = variableHandle_->GetAnnotationByName(annotationName.c_str());
    if ((annotation == nullptr) || !annotation->IsValid()) {
      return false;
    }

    LPCSTR text = nullptr;
    const HRESULT result = annotation->AsString()->GetString(&text);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectVariableD3D10.cpp", 215, result);
    }

    outValue->assign_owned((text != nullptr) ? text : "");
    return true;
  }

  /**
   * Address: 0x0094B5E0 (FUN_0094B5E0)
   *
   * What it does:
   * No-op D3D10 effect reset slot.
   */
  void EffectD3D10::OnReset() {}

  /**
   * Address: 0x0094B5F0 (FUN_0094B5F0)
   *
   * What it does:
   * No-op D3D10 effect lost-device slot.
   */
  void EffectD3D10::OnLost() {}
} // namespace gpg::gal

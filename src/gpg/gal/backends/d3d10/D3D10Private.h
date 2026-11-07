#pragma once

// Private to gpg/gal/backends/d3d10: helpers the pieces of the former D3D10Interfaces.cpp share.

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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>

// The float16 formatter packs with gpg::gal::FloatToHalf (gpg/gal/HalfFloat.h), D3DX9's
// conversion without D3DX (the binary calls the d3dx9 import at 0x00AC65C0).

namespace gpg::gal
{
namespace
{

    struct DXGIFormatPair final
    {
      int dxgi = 0;
      int gal = 0;
    };



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

    fa::string MakeShortString(const char* const text)
    {
      if (text == nullptr) {
        return fa::string();
      }

      const std::size_t length = std::strlen(text);
      return fa::string(text, length);
    }

    [[noreturn]] void ThrowGalError(const char* const file, const int line, const char* const message)
    {
      throw Error(MakeShortString(file), line, MakeShortString(message));
    }

    [[maybe_unused]] [[noreturn]] void ThrowGalErrorFromHresult(const char* const file, const int line, const HRESULT code)
    {
      throw Error(MakeShortString(file), line, MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code))));
    }

    [[maybe_unused]] fa::string MakeD3DErrorString(const HRESULT code)
    {
      return MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code)));
    }

    /**
     * Address: 0x0094D490 (FUN_0094D490)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from one
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    [[maybe_unused]] const Matrix* CopyMatrix4x3Rows(
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
     * Address: 0x008F6230 (FUN_008F6230)
     *
     * What it does:
     * Releases retained output COM lanes for every cached adapter-mode entry,
     * then releases the retained DXGI adapter lane.
     */
    [[maybe_unused]] void ReleaseAdapterOutputAndDeviceRefs(AdapterD3D10* const adapter) noexcept
    {
      for (AdapterModeD3D10& mode : adapter->modes_) {
        SafeRelease(mode.output_);
      }
      SafeRelease(adapter->dxgiAdapter_);
    }

    /**
     * Address: 0x009033D0 (FUN_009033D0)
     *
     * What it does:
     * Converts GAL texture format token to its backing DXGI format token by scanning
     * the recovered 89-entry mapping table.
     */
    [[maybe_unused]] int MapGalTextureFormatToDxgi(const int galFormat)
    {
      for (const DXGIFormatPair& pair : kTextureDxgiGalPairs) {
        if (pair.gal == galFormat) {
          return pair.dxgi;
        }
      }

      return 0;
    }

    /**
     * Address: 0x009040D0 (FUN_009040D0)
     *
     * What it does:
     * Returns byte size per texel/block for recovered GAL texture format IDs.
     */
    [[maybe_unused]] unsigned int GetTextureFormatBlockBytes(const unsigned int format)
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
     * Address: 0x00904340 (FUN_00904340)
     *
     * What it does:
     * Validates one vertex-format token and returns the matching static
     * element-layout table pointer.
     */
    [[maybe_unused]] const D3D10_INPUT_ELEMENT_DESC* GetVertexLayoutElementsOrThrow(const std::uint32_t format)
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
    [[maybe_unused]] std::uint32_t GetVertexLayoutElementCountOrThrow(const std::uint32_t format)
    {
      if (format >= 24U) {
        ThrowGalError("VertexFormatD3D10.cpp", 432, "invalid vertex format specified");
      }

      return kVertexLayoutElementCountByFormat[format];
    }
    /**
     * The blend state both packs create (0x0090282B, 0x00902C0B): no
     * blending, colour writes on render target 0 only.
     */
    [[maybe_unused]] [[nodiscard]] D3D10_BLEND_DESC OpaqueBlendDesc()
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
}


    // FAF addition, not in the shipped binary. GPG's D3D10 SetColorWriteState
    // and SetWireframeState (0x008FE6F0, 0x008FE6E0) are empty, so the engine's
    // colour-write masks (13 call sites) and wireframe toggle did nothing under
    // /D3D10. These hold what the engine last asked for; one device exists at a
    // time, and the binary-sized PipelineStateD3D10 has no room for them.
    extern UINT8 sColorWriteMask;
    extern bool sWireframe;
}


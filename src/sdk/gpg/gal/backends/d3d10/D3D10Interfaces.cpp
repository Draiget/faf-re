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
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/PipelineState.hpp"
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

namespace gpg::gal
{
  namespace
  {
    using release_fn = unsigned long(__stdcall*)(void*);
    using add_ref_fn = unsigned long(__stdcall*)(void*);
    using device_create_vertex_format_fn = void(__thiscall*)(Device*, void*, int);
    using device_begin_technique_fn = void(__thiscall*)(Device*);
    using device_end_technique_fn = void(__thiscall*)(Device*);
    using effect_get_desc_fn = HRESULT(__stdcall*)(void*, void*);
    using effect_get_technique_by_index_fn = void*(__stdcall*)(void*, unsigned int);
    using effect_get_technique_by_name_fn = void*(__stdcall*)(void*, const char*);
    using effect_get_variable_by_name_fn = void*(__stdcall*)(void*, const char*);
    using technique_get_annotation_by_name_fn = void*(__stdcall*)(void*, const char*);
    using technique_is_valid_fn = BOOL(__stdcall*)(void*);
    using technique_get_desc_fn = HRESULT(__stdcall*)(void*, void*);
    using technique_get_pass_counter_fn = void(__stdcall*)(void*, void*);
    using technique_get_pass_by_index_fn = void*(__stdcall*)(void*, int);
    using pass_get_desc_fn = HRESULT(__stdcall*)(void*, void*);
    using pass_apply_fn = HRESULT(__stdcall*)(void*, unsigned int);
    using variable_is_valid_fn = BOOL(__stdcall*)(void*);
    using variable_get_annotation_by_name_fn = void*(__stdcall*)(void*, const char*);
    using variable_as_scalar_fn = void*(__stdcall*)(void*);
    using variable_as_vector_fn = void*(__stdcall*)(void*);
    using variable_as_matrix_fn = void*(__stdcall*)(void*);
    using variable_as_string_fn = void*(__stdcall*)(void*);
    using variable_as_shader_resource_fn = void*(__stdcall*)(void*);
    using variable_set_raw_value_fn = HRESULT(__stdcall*)(void*, const void*, unsigned int, unsigned int);
    using scalar_get_bool_fn = HRESULT(__stdcall*)(void*, int*);
    using scalar_get_int_fn = HRESULT(__stdcall*)(void*, int*);
    using scalar_get_float_fn = HRESULT(__stdcall*)(void*, float*);
    using scalar_set_bool_fn = HRESULT(__stdcall*)(void*, BOOL);
    using scalar_set_int_fn = HRESULT(__stdcall*)(void*, int);
    using scalar_set_float_fn = HRESULT(__stdcall*)(void*, float);
    using matrix_set_matrix_fn = HRESULT(__stdcall*)(void*, const void*);
    using matrix_set_matrix_array_fn = HRESULT(__stdcall*)(void*, const void*, unsigned int, unsigned int);
    using vector_set_float_vector_fn = HRESULT(__stdcall*)(void*, const void*);
    using vector_set_array_fn = HRESULT(__stdcall*)(void*, const void*, unsigned int, unsigned int);
    using shader_resource_set_resource_fn = HRESULT(__stdcall*)(void*, void*);
    using string_get_string_fn = HRESULT(__stdcall*)(void*, const char**);
    using texture_get_desc_fn = void(__stdcall*)(void*, void*);
    using texture_map_fn = HRESULT(__stdcall*)(void*, int, unsigned int, unsigned int, void*);
    using texture_unmap_fn = void(__stdcall*)(void*, int);
    using device_native_create_buffer_fn = HRESULT(__stdcall*)(void*, const void*, const void*, void**);
    using device_native_create_texture2d_fn = HRESULT(__stdcall*)(void*, const void*, const void*, void**);
    using device_native_create_shader_resource_view_fn = HRESULT(__stdcall*)(void*, void*, const void*, void**);
    using device_native_create_render_target_view_fn = HRESULT(__stdcall*)(void*, void*, const void*, void**);
    using device_native_create_depth_stencil_view_fn = HRESULT(__stdcall*)(void*, void*, const void*, void**);
    using device_native_create_input_layout_fn =
      HRESULT(__stdcall*)(void*, const void*, unsigned int, const void*, std::size_t, void**);
    using device_native_copy_resource_fn = void(__stdcall*)(void*, void*, void*);
    using device_native_set_shader_resources_fn = int(__stdcall*)(void*, unsigned int, unsigned int, void* const*);
    using device_native_set_rasterizer_state_fn = void(__stdcall*)(void*, void*);
    using device_native_set_depth_stencil_state_fn = void(__stdcall*)(void*, void*, unsigned int);
    using device_native_set_blend_state_fn = int(__stdcall*)(void*, void*, const float*, unsigned int);
    using device_native_set_input_layout_fn = int(__stdcall*)(void*, void*);
    using device_native_set_vertex_buffers_fn =
      void(__stdcall*)(void*, unsigned int, unsigned int, void* const*, const unsigned int*, const unsigned int*);
    using device_native_set_index_buffer_fn = int(__stdcall*)(void*, void*, unsigned int, unsigned int);
    using device_native_clear_target_fn = int(__stdcall*)(void*, unsigned int, void* const*, void*);
    using device_native_clear_render_target_view_fn = void(__stdcall*)(void*, void*, const float*);
    using device_native_clear_depth_stencil_view_fn = int(__stdcall*)(void*, void*, unsigned int, float, unsigned int);
    using device_native_set_viewports_fn = int(__stdcall*)(void*, unsigned int, const void*);
    using device_native_get_viewports_fn = void(__stdcall*)(void*, unsigned int*, void*);
    using device_native_get_render_targets_fn = void(__stdcall*)(void*, unsigned int, void**, void**);
    using device_native_set_primitive_topology_fn = void(__stdcall*)(void*, unsigned int);
    using device_native_draw_fn = int(__stdcall*)(void*, unsigned int, unsigned int);
    using device_native_draw_instanced_fn =
      int(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, unsigned int);
    using device_native_draw_indexed_fn = int(__stdcall*)(void*, unsigned int, unsigned int, int);
    using device_native_draw_indexed_instanced_fn =
      int(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, int, unsigned int);
    using readback_get_size_fn = int(__stdcall*)(void*);
    using readback_get_data_fn = void*(__stdcall*)(void*);
    using device_native_copy_subresource_region_fn = int(__stdcall*)(
      void*, void*, unsigned int, unsigned int, unsigned int, unsigned int, void*, unsigned int, const D3D10_BOX*
    );
    using device_native_copy_resource_result_fn = int(__stdcall*)(void*, void*, void*);

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

    struct SourceMeshVertexRuntime final
    {
      std::uint8_t streamClassFlag = 0;  // +0x00
      std::uint8_t pad01_03[3]{};
      float streamScalar04 = 0.0f;       // +0x04
      std::uint32_t streamPacked08 = 0U; // +0x08
      float streamScalar0C = 0.0f;       // +0x0C
      float transform4x4[16]{};          // +0x10 .. +0x4F
      std::uint8_t streamFlag50 = 0;     // +0x50
      std::uint8_t streamColor51 = 0;    // +0x51
      std::uint8_t streamColor52 = 0;    // +0x52
      std::uint8_t streamColor53 = 0;    // +0x53
      std::uint8_t streamColor54 = 0;    // +0x54
      std::uint8_t pad55_57[3]{};
      float streamVec58[3]{};      // +0x58 .. +0x63
      float streamVec64[3]{};      // +0x64 .. +0x6F
      float streamVec70[3]{};      // +0x70 .. +0x7B
      float streamVec7C[3]{};      // +0x7C .. +0x87
      float streamVec88[3]{};      // +0x88 .. +0x93
      float streamScalar94 = 0.0f; // +0x94
      float streamScalar98 = 0.0f; // +0x98
      float streamScalar9C = 0.0f; // +0x9C
      float streamScalarA0 = 0.0f; // +0xA0
      std::uint8_t streamBoolA4 = 0; // +0xA4
      std::uint8_t padA5_A7[3]{};
      float streamScalarA8 = 0.0f; // +0xA8
      float streamScalarAC = 0.0f; // +0xAC
      std::uint8_t streamFlagB0 = 0; // +0xB0
      std::uint8_t padB1_B3[3]{};
      float streamScalarB4 = 0.0f; // +0xB4
    };

    struct HardwareVertexPackedStream0Runtime final
    {
      float lane00 = 0.0f; // +0x00
      float lane04 = 0.0f; // +0x04
      float lane08 = 0.0f; // +0x08
      float lane0C = 0.0f; // +0x0C
      float lane10 = 0.0f; // +0x10
      float lane14 = 0.0f; // +0x14
      float lane18 = 0.0f; // +0x18
      float lane1C = 0.0f; // +0x1C
      float lane20 = 0.0f; // +0x20
      float lane24 = 0.0f; // +0x24
      float lane28 = 0.0f; // +0x28
      float lane2C = 0.0f; // +0x2C
      float lane30 = 0.0f; // +0x30
      float lane34 = 0.0f; // +0x34
      float lane38 = 0.0f; // +0x38
      float lane3C = 0.0f; // +0x3C
      float lane40 = 0.0f; // +0x40
      std::uint8_t lane44 = 0; // +0x44
      std::uint8_t lane45 = 0; // +0x45
      std::uint8_t lane46 = 0; // +0x46
      std::uint8_t lane47 = 0; // +0x47
    };

    struct HardwareVertexPackedStream1Runtime final
    {
      float row0[3]{}; // +0x00
      float row1[3]{}; // +0x0C
      float row2[3]{}; // +0x18
      float row3[3]{}; // +0x24
      std::uint8_t lane30 = 0; // +0x30
      std::uint8_t lane31 = 0; // +0x31
      std::uint8_t lane32 = 0; // +0x32
      std::uint8_t lane33 = 0; // +0x33
      float lane34 = 0.0f; // +0x34
      float lane38 = 0.0f; // +0x38
      float lane3C = 0.0f; // +0x3C
      float lane40 = 0.0f; // +0x40
      std::uint32_t lane44 = 0U; // +0x44
      float lane48 = 0.0f; // +0x48
    };

    struct Float16VertexPackedStream1Runtime final
    {
      float row0[3]{}; // +0x00
      float row1[3]{}; // +0x0C
      float row2[3]{}; // +0x18
      float row3[3]{}; // +0x24
      std::uint8_t lane30 = 0; // +0x30
      std::uint8_t lane31 = 0; // +0x31
      std::uint8_t lane32 = 0; // +0x32
      std::uint8_t lane33 = 0; // +0x33
      std::uint16_t lane34 = 0; // +0x34
      std::uint16_t lane36 = 0; // +0x36
      std::uint16_t lane38 = 0; // +0x38
      std::uint16_t lane3A = 0; // +0x3A
      std::uint32_t lane3C = 0U; // +0x3C
      float lane40 = 0.0f; // +0x40
    };

    static_assert(
      offsetof(SourceMeshVertexRuntime, streamScalar04) == 0x04,
      "SourceMeshVertexRuntime::streamScalar04 offset must be 0x04"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, transform4x4) == 0x10,
      "SourceMeshVertexRuntime::transform4x4 offset must be 0x10"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamColor51) == 0x51,
      "SourceMeshVertexRuntime::streamColor51 offset must be 0x51"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamVec58) == 0x58, "SourceMeshVertexRuntime::streamVec58 offset must be 0x58"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamVec70) == 0x70, "SourceMeshVertexRuntime::streamVec70 offset must be 0x70"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamVec88) == 0x88, "SourceMeshVertexRuntime::streamVec88 offset must be 0x88"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamScalarA8) == 0xA8,
      "SourceMeshVertexRuntime::streamScalarA8 offset must be 0xA8"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamFlagB0) == 0xB0, "SourceMeshVertexRuntime::streamFlagB0 offset must be 0xB0"
    );
    static_assert(
      offsetof(SourceMeshVertexRuntime, streamScalarB4) == 0xB4,
      "SourceMeshVertexRuntime::streamScalarB4 offset must be 0xB4"
    );
    static_assert(sizeof(SourceMeshVertexRuntime) == 0xB8, "SourceMeshVertexRuntime size must be 0xB8");
    static_assert(
      offsetof(HardwareVertexPackedStream0Runtime, lane0C) == 0x0C,
      "HardwareVertexPackedStream0Runtime::lane0C offset must be 0x0C"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream0Runtime, lane28) == 0x28,
      "HardwareVertexPackedStream0Runtime::lane28 offset must be 0x28"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream0Runtime, lane44) == 0x44,
      "HardwareVertexPackedStream0Runtime::lane44 offset must be 0x44"
    );
    static_assert(sizeof(HardwareVertexPackedStream0Runtime) == 0x48, "HardwareVertexPackedStream0Runtime size must be 0x48");
    static_assert(
      offsetof(HardwareVertexPackedStream1Runtime, row1) == 0x0C,
      "HardwareVertexPackedStream1Runtime::row1 offset must be 0x0C"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream1Runtime, row2) == 0x18,
      "HardwareVertexPackedStream1Runtime::row2 offset must be 0x18"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream1Runtime, lane30) == 0x30,
      "HardwareVertexPackedStream1Runtime::lane30 offset must be 0x30"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream1Runtime, lane44) == 0x44,
      "HardwareVertexPackedStream1Runtime::lane44 offset must be 0x44"
    );
    static_assert(
      offsetof(HardwareVertexPackedStream1Runtime, lane48) == 0x48,
      "HardwareVertexPackedStream1Runtime::lane48 offset must be 0x48"
    );
    static_assert(sizeof(HardwareVertexPackedStream1Runtime) == 0x4C, "HardwareVertexPackedStream1Runtime size must be 0x4C");
    static_assert(
      offsetof(Float16VertexPackedStream1Runtime, row1) == 0x0C,
      "Float16VertexPackedStream1Runtime::row1 offset must be 0x0C"
    );
    static_assert(
      offsetof(Float16VertexPackedStream1Runtime, lane30) == 0x30,
      "Float16VertexPackedStream1Runtime::lane30 offset must be 0x30"
    );
    static_assert(
      offsetof(Float16VertexPackedStream1Runtime, lane34) == 0x34,
      "Float16VertexPackedStream1Runtime::lane34 offset must be 0x34"
    );
    static_assert(
      offsetof(Float16VertexPackedStream1Runtime, lane3C) == 0x3C,
      "Float16VertexPackedStream1Runtime::lane3C offset must be 0x3C"
    );
    static_assert(sizeof(Float16VertexPackedStream1Runtime) == 0x44, "Float16VertexPackedStream1Runtime size must be 0x44");

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

    void AddRefComLike(void* const object) noexcept
    {
      if (object == nullptr) {
        return;
      }

      auto** const vtable = *reinterpret_cast<void***>(object);
      auto* const addRef = reinterpret_cast<add_ref_fn>(vtable[1]);
      addRef(object);
    }

    /**
     * Address: 0x008F9470 (FUN_008F9470)
     *
     * What it does:
     * Releases one intrusive weak-ref token lane by decrementing strong count,
     * dispatching vtable release on transition to zero, then releasing weak count.
     */
    void ReleaseWeakRefToken(WeakRefCountedToken* const token) noexcept
    {
      if (token == nullptr) {
        return;
      }

      if (_InterlockedExchangeAdd(&token->strongCount, -1) == 1) {
        using weak_ref_vfunc = void(__thiscall*)(WeakRefCountedToken*);
        auto* const releaseStrong = reinterpret_cast<weak_ref_vfunc>(token->vtable[1]);
        releaseStrong(token);

        if (_InterlockedExchangeAdd(&token->weakCount, -1) == 1) {
          auto* const releaseWeak = reinterpret_cast<weak_ref_vfunc>(token->vtable[2]);
          releaseWeak(token);
        }
      }
    }

    void* GetDeviceLogStorage(DeviceD3D10* const device) noexcept
    {
      return &device->mLog;
    }

    /**
     * The binary's `GetDeviceContext` (0x008F86C0) is `lea eax,[ecx+0x60]` --
     * the address of the embedded context. This used to read the dword stored
     * at +0x60 instead, which is the context's vptr, so every caller got the
     * vtable address back as a `DeviceContext*`.
     */
    DeviceContext* GetDeviceContextLane(DeviceD3D10* const device) noexcept
    {
      return &device->mDeviceContext;
    }

    int GetDeviceCurrentThreadId(DeviceD3D10* const device) noexcept
    {
      return device->mCurThreadId;
    }

    CursorD3D10* GetDeviceCursorLane(DeviceD3D10* const device) noexcept
    {
      return &device->mCursor;
    }

    PipelineStateD3D10* GetDeviceTechniqueBindings(DeviceD3D10* const device) noexcept
    {
      return device->mPipelineState.get();
    }

    void* GetDeviceNativeHandle(DeviceD3D10* const device) noexcept
    {
      return device->mDevice;
    }

    void* GetDeviceSignatureEffect(DeviceD3D10* const device) noexcept
    {
      return device->mSignatureEffect;
    }

    void* GetDeviceStretchRectEffect(DeviceD3D10* const device) noexcept
    {
      return device->mRttEffect;
    }

    void* GetDeviceStretchRectTechnique(DeviceD3D10* const device) noexcept
    {
      return device->mRttTechnique;
    }

    void* GetDeviceStretchRectVertexBuffer(DeviceD3D10* const device) noexcept
    {
      return device->mRttQuadVertexBuffer;
    }

    void* GetDeviceStretchRectInputLayout(DeviceD3D10* const device) noexcept
    {
      return device->mRttInputLayout;
    }

    WeakRefCountedToken** GetDeviceVertexStreamRefArray(DeviceD3D10* const device) noexcept
    {
      return device->mVertexStreams;
    }

    /**
     * `DrawPrimitive` (0x008FD049) and `DrawIndexedPrimitive` (0x008FD159) read
     * this+0xD8 and draw instanced when it exceeds 1. Nothing else writes that
     * dword: it is slot 0 of `mVertexStreams`, filled by the stream setter
     * (`mov [esi+edi*4+0xD8], eax` at 0x008F970A) and cleared by `Setup`. So the
     * shipped engine reads stream 0's reference as its instance count. That is
     * kept exactly, because it is what the binary does; it is not a separate
     * field and must not be given one.
     */
    std::uint32_t GetDeviceInstanceCount(DeviceD3D10* const device) noexcept
    {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(device->mVertexStreams[0]));
    }

    msvc8::vector<IDXGISwapChain*>& GetDeviceSwapChains(DeviceD3D10* const device) noexcept
    {
      return device->mSwapChains;
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

    int InvokeNativeClearShaderResourceSlot(
      PipelineStateD3D10* const bindings, const unsigned int startSlot, void* const* const views
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->device_);
      auto* const setShaderResources = reinterpret_cast<device_native_set_shader_resources_fn>(vtable[4]);
      return setShaderResources(bindings->device_, startSlot, 1U, views);
    }

    void InvokeNativeSetRasterizerState(PipelineStateD3D10* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->device_);
      auto* const setRasterizerState = reinterpret_cast<device_native_set_rasterizer_state_fn>(vtable[29]);
      setRasterizerState(bindings->device_, bindings->rasterizerState2_);
    }

    void InvokeNativeSetDepthStencilState(PipelineStateD3D10* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->device_);
      auto* const setDepthStencilState = reinterpret_cast<device_native_set_depth_stencil_state_fn>(vtable[26]);
      setDepthStencilState(bindings->device_, bindings->depthStencilState2_, 0U);
    }

    int InvokeNativeSetBlendState(PipelineStateD3D10* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->device_);
      auto* const setBlendState = reinterpret_cast<device_native_set_blend_state_fn>(vtable[25]);
      return setBlendState(bindings->device_, bindings->blendState2_, nullptr, static_cast<unsigned int>(-1));
    }

    HRESULT InvokeNativeCreateBuffer(DeviceD3D10* const device, const void* const description, void** const outBuffer)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createBuffer = reinterpret_cast<device_native_create_buffer_fn>(vtable[71]);
      return createBuffer(nativeDevice, description, nullptr, outBuffer);
    }

    HRESULT
    InvokeNativeCreateTexture2D(DeviceD3D10* const device, const void* const description, void** const outTexture)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createTexture2D = reinterpret_cast<device_native_create_texture2d_fn>(vtable[73]);
      return createTexture2D(nativeDevice, description, nullptr, outTexture);
    }

    HRESULT InvokeNativeCreateShaderResourceView(
      DeviceD3D10* const device, void* const resource, const void* const description, void** const outShaderResourceView
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createShaderResourceView = reinterpret_cast<device_native_create_shader_resource_view_fn>(vtable[75]);
      return createShaderResourceView(nativeDevice, resource, description, outShaderResourceView);
    }

    HRESULT InvokeNativeCreateRenderTargetView(
      DeviceD3D10* const device, void* const resource, const void* const description, void** const outRenderTargetView
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createRenderTargetView = reinterpret_cast<device_native_create_render_target_view_fn>(vtable[76]);
      return createRenderTargetView(nativeDevice, resource, description, outRenderTargetView);
    }

    HRESULT InvokeNativeCreateDepthStencilView(
      DeviceD3D10* const device, void* const resource, const void* const description, void** const outDepthStencilView
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createDepthStencilView = reinterpret_cast<device_native_create_depth_stencil_view_fn>(vtable[77]);
      return createDepthStencilView(nativeDevice, resource, description, outDepthStencilView);
    }

    HRESULT InvokeNativeCreateInputLayout(
      DeviceD3D10* const device,
      const D3D10_INPUT_ELEMENT_DESC* const elements,
      const std::uint32_t elementCount,
      const void* const inputSignature,
      const std::size_t inputSignatureSize,
      void** const outInputLayout
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createInputLayout = reinterpret_cast<device_native_create_input_layout_fn>(vtable[42]);
      return createInputLayout(
        nativeDevice, elements, elementCount, inputSignature, inputSignatureSize, outInputLayout
      );
    }

    int InvokeNativeSetInputLayout(DeviceD3D10* const device, void* const inputLayout)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setInputLayout = reinterpret_cast<device_native_set_input_layout_fn>(vtable[11]);
      return setInputLayout(nativeDevice, inputLayout);
    }

    void InvokeNativeSetVertexBuffers(
      DeviceD3D10* const device,
      const unsigned int streamSlot,
      void* const* const buffers,
      const unsigned int* const strides,
      const unsigned int* const offsets
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setVertexBuffers = reinterpret_cast<device_native_set_vertex_buffers_fn>(vtable[12]);
      setVertexBuffers(nativeDevice, streamSlot, 1U, buffers, strides, offsets);
    }

    int InvokeNativeSetIndexBuffer(
      DeviceD3D10* const device, void* const indexBuffer, const unsigned int formatToken, const unsigned int offset
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setIndexBuffer = reinterpret_cast<device_native_set_index_buffer_fn>(vtable[13]);
      return setIndexBuffer(nativeDevice, indexBuffer, formatToken, offset);
    }

    int InvokeNativeClearTarget(
      DeviceD3D10* const device,
      const unsigned int renderTargetCount,
      void* const* const renderTargetViews,
      void* const depthStencilView
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const clearTarget = reinterpret_cast<device_native_clear_target_fn>(vtable[24]);
      return clearTarget(nativeDevice, renderTargetCount, renderTargetViews, depthStencilView);
    }

    void InvokeNativeClearRenderTargetView(
      DeviceD3D10* const device, void* const renderTargetView, const float* const clearColor
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const clearRenderTargetView = reinterpret_cast<device_native_clear_render_target_view_fn>(vtable[35]);
      clearRenderTargetView(nativeDevice, renderTargetView, clearColor);
    }

    int InvokeNativeClearDepthStencilView(
      DeviceD3D10* const device,
      void* const depthStencilView,
      const unsigned int clearMask,
      const float depth,
      const unsigned int stencil
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const clearDepthStencilView = reinterpret_cast<device_native_clear_depth_stencil_view_fn>(vtable[36]);
      return clearDepthStencilView(nativeDevice, depthStencilView, clearMask, depth, stencil);
    }

    int InvokeNativeSetViewport(DeviceD3D10* const device, const D3D10_VIEWPORT* const viewport)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setViewports = reinterpret_cast<device_native_set_viewports_fn>(vtable[30]);
      return setViewports(nativeDevice, 1U, viewport);
    }

    void InvokeNativeGetViewport(
      DeviceD3D10* const device, unsigned int* const viewportCount, D3D10_VIEWPORT* const outViewport
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const getViewports = reinterpret_cast<device_native_get_viewports_fn>(vtable[61]);
      getViewports(nativeDevice, viewportCount, outViewport);
    }

    void InvokeNativeGetRenderTargets(
      DeviceD3D10* const device,
      const unsigned int renderTargetCount,
      void** const outRenderTargetView,
      void** const outDepthStencilView
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const getRenderTargets = reinterpret_cast<device_native_get_render_targets_fn>(vtable[56]);
      getRenderTargets(nativeDevice, renderTargetCount, outRenderTargetView, outDepthStencilView);
    }

    void InvokeNativeCopySubresourceRegion(
      DeviceD3D10* const device,
      void* const destinationResource,
      const unsigned int destinationX,
      const unsigned int destinationY,
      void* const sourceResource,
      const D3D10_BOX* const sourceBox
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const copySubresourceRegion = reinterpret_cast<device_native_copy_subresource_region_fn>(vtable[32]);
      copySubresourceRegion(
        nativeDevice, destinationResource, 0U, destinationX, destinationY, 0U, sourceResource, 0U, sourceBox
      );
    }

    int InvokeNativeCopyResourceResult(
      DeviceD3D10* const device, void* const destinationResource, void* const sourceResource
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const copyResource = reinterpret_cast<device_native_copy_resource_result_fn>(vtable[33]);
      return copyResource(nativeDevice, destinationResource, sourceResource);
    }

    void InvokeNativeSetPrimitiveTopology(DeviceD3D10* const device, const std::uint32_t topology)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setPrimitiveTopology = reinterpret_cast<device_native_set_primitive_topology_fn>(vtable[18]);
      setPrimitiveTopology(nativeDevice, topology);
    }

    int InvokeNativeDraw(DeviceD3D10* const device, const std::uint32_t vertexCount, const std::uint32_t startVertex)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const draw = reinterpret_cast<device_native_draw_fn>(vtable[9]);
      return draw(nativeDevice, vertexCount, startVertex);
    }

    int InvokeNativeDrawInstanced(
      DeviceD3D10* const device,
      const std::uint32_t vertexCount,
      const std::uint32_t instanceCount,
      const std::uint32_t startVertex,
      const std::uint32_t startInstance
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const drawInstanced = reinterpret_cast<device_native_draw_instanced_fn>(vtable[15]);
      return drawInstanced(nativeDevice, vertexCount, instanceCount, startVertex, startInstance);
    }

    int InvokeNativeDrawIndexed(
      DeviceD3D10* const device, const std::uint32_t indexCount, const std::uint32_t startIndex, const int baseVertex
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const drawIndexed = reinterpret_cast<device_native_draw_indexed_fn>(vtable[8]);
      return drawIndexed(nativeDevice, indexCount, startIndex, baseVertex);
    }

    int InvokeNativeDrawIndexedInstanced(
      DeviceD3D10* const device,
      const std::uint32_t indexCount,
      const std::uint32_t instanceCount,
      const std::uint32_t startIndex,
      const int baseVertex,
      const std::uint32_t startInstance
    )
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const drawIndexedInstanced = reinterpret_cast<device_native_draw_indexed_instanced_fn>(vtable[14]);
      return drawIndexedInstanced(nativeDevice, indexCount, instanceCount, startIndex, baseVertex, startInstance);
    }

    void InvokeTechniqueGetPassCount(void* const technique, D3D10_TECHNIQUE_DESC* const outPassCount);
    void* InvokeEffectGetVariableByName(void* const effect, const char* const name);
    void* InvokeVariableAsShaderResource(void* const variable);
    HRESULT InvokeShaderResourceSetResource(void* const shaderResourceValue, void* const resourceView);
    void* InvokeTechniqueGetPassByIndex(void* const technique, const int pass);
    HRESULT InvokePassApply(void* const pass, const unsigned int flags);

    /**
     * Address: 0x008F8920 (FUN_008F8920)
     *
     * uint32_t,uint32_t,void *,void *
     *
     * What it does:
     * Applies the recovered SRV->RTV fullscreen blit fallback lane used by
     * `DeviceD3D10::StretchRect` when source/destination contexts differ.
     */
    int StretchRectFallbackBlit(
      DeviceD3D10* const device,
      const std::uint32_t destinationWidth,
      const std::uint32_t destinationHeight,
      void* const destinationRenderTargetView,
      void* const sourceShaderResourceView
    )
    {
      D3D10_VIEWPORT savedViewport{};
      unsigned int savedViewportCount = 1U;
      InvokeNativeGetViewport(device, &savedViewportCount, &savedViewport);

      if (destinationRenderTargetView != nullptr) {
        D3D10_VIEWPORT fullscreenViewport{};
        fullscreenViewport.Width = destinationWidth;
        fullscreenViewport.Height = destinationHeight;
        fullscreenViewport.MinDepth = 0.0f;
        fullscreenViewport.MaxDepth = 1.0f;
        InvokeNativeSetViewport(device, &fullscreenViewport);
      }

      void* previousRenderTargetView = nullptr;
      void* previousDepthStencilView = nullptr;
      InvokeNativeGetRenderTargets(device, 1U, &previousRenderTargetView, &previousDepthStencilView);

      InvokeNativeSetInputLayout(device, GetDeviceStretchRectInputLayout(device));

      void* vertexBuffer = GetDeviceStretchRectVertexBuffer(device);
      unsigned int stride = 0x14U;
      unsigned int offset = 0U;
      InvokeNativeSetVertexBuffers(device, 0U, &vertexBuffer, &stride, &offset);

      InvokeNativeSetPrimitiveTopology(device, 5U);

      if (destinationRenderTargetView != nullptr) {
        void* renderTargets[1] = {destinationRenderTargetView};
        static_cast<void>(InvokeNativeClearTarget(device, 1U, renderTargets, nullptr));
      }

      D3D10_TECHNIQUE_DESC passCountRuntime{};
      InvokeTechniqueGetPassCount(GetDeviceStretchRectTechnique(device), &passCountRuntime);

      for (unsigned int passIndex = 0U; passIndex < passCountRuntime.Passes; ++passIndex) {
        void* const sourceVariable = InvokeEffectGetVariableByName(GetDeviceStretchRectEffect(device), "g_txSource");
        void* const sourceAsShaderResource = InvokeVariableAsShaderResource(sourceVariable);
        static_cast<void>(InvokeShaderResourceSetResource(sourceAsShaderResource, sourceShaderResourceView));

        void* const pass =
          InvokeTechniqueGetPassByIndex(GetDeviceStretchRectTechnique(device), static_cast<int>(passIndex));
        static_cast<void>(InvokePassApply(pass, 0U));
        static_cast<void>(InvokeNativeDraw(device, 4U, 0U));
      }

      InvokeNativeSetViewport(device, &savedViewport);
      void* restoreRenderTargets[1] = {previousRenderTargetView};
      return InvokeNativeClearTarget(device, 1U, restoreRenderTargets, previousDepthStencilView);
    }

    /**
     * Address: 0x009022E0 (FUN_009022E0)
     *
     * What it does:
     * Clears 128 texture shader-resource slots on the retained native D3D10
     * device lane and returns the final native-call result code.
     */
    int ClearAllTextureShaderResourceSlots(PipelineStateD3D10* const bindings)
    {
      unsigned int slot = 0U;
      void* nullResourceView = nullptr;
      int result = 0;
      while (slot < 0x80U) {
        result = InvokeNativeClearShaderResourceSlot(bindings, slot, &nullResourceView);
        ++slot;
      }

      return result;
    }

    /**
     * Address: 0x00902320 (FUN_00902320)
     *
     * What it does:
     * Applies retained rasterizer/depth-stencil/blend state lanes to the
     * native D3D10 device for begin-technique dispatch.
     */
    int ApplyTechniqueStateBindings(PipelineStateD3D10* const bindings)
    {
      InvokeNativeSetRasterizerState(bindings);
      InvokeNativeSetDepthStencilState(bindings);
      return InvokeNativeSetBlendState(bindings);
    }

    /**
     * Address: 0x00902360 (FUN_00902360)
     *
     * What it does:
     * Preserves the binary empty helper lane used by end-technique dispatch.
     */
    void nullsub_3640() {}

    [[noreturn]] void ThrowInvalidTopologyError(const int line)
    {
      ThrowGalError("DeviceD3D10.cpp", line, "invalid topology specified");
    }

    std::uint32_t ResolvePrimitiveTopology(const std::uint32_t topologyToken) noexcept
    {
      return kPrimitiveTopologyByToken[topologyToken];
    }

    void InvokeDeviceCreateVertexFormat(Device* const device, void* const streamToken, const int formatToken)
    {
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const createVertexFormat = reinterpret_cast<device_create_vertex_format_fn>(vtable[14]);
      createVertexFormat(device, streamToken, formatToken);
    }

    void InvokeDeviceBeginTechnique(Device* const device)
    {
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const beginTechnique = reinterpret_cast<device_begin_technique_fn>(vtable[48]);
      beginTechnique(device);
    }

    void InvokeDeviceEndTechnique(Device* const device)
    {
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const endTechnique = reinterpret_cast<device_end_technique_fn>(vtable[49]);
      endTechnique(device);
    }

    HRESULT InvokeEffectGetDesc(void* const effect, D3D10_EFFECT_DESC* const outDesc)
    {
      auto** const vtable = *reinterpret_cast<void***>(effect);
      auto* const getDesc = reinterpret_cast<effect_get_desc_fn>(vtable[6]);
      return getDesc(effect, outDesc);
    }

    void* InvokeEffectGetTechniqueByIndex(void* const effect, const unsigned int index)
    {
      auto** const vtable = *reinterpret_cast<void***>(effect);
      auto* const getTechniqueByIndex = reinterpret_cast<effect_get_technique_by_index_fn>(vtable[12]);
      return getTechniqueByIndex(effect, index);
    }

    void* InvokeEffectGetTechniqueByName(void* const effect, const char* const name)
    {
      auto** const vtable = *reinterpret_cast<void***>(effect);
      auto* const getTechniqueByName = reinterpret_cast<effect_get_technique_by_name_fn>(vtable[13]);
      return getTechniqueByName(effect, name);
    }

    void* InvokeEffectGetVariableByName(void* const effect, const char* const name)
    {
      auto** const vtable = *reinterpret_cast<void***>(effect);
      auto* const getVariableByName = reinterpret_cast<effect_get_variable_by_name_fn>(vtable[10]);
      return getVariableByName(effect, name);
    }

    void* InvokeTechniqueGetAnnotationByName(void* const technique, const char* const name)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const getAnnotationByName = reinterpret_cast<technique_get_annotation_by_name_fn>(vtable[3]);
      return getAnnotationByName(technique, name);
    }

    BOOL InvokeTechniqueIsValid(void* const technique)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const isValid = reinterpret_cast<technique_is_valid_fn>(vtable[0]);
      return isValid(technique);
    }

    HRESULT InvokeTechniqueGetDesc(void* const technique, D3D10_TECHNIQUE_DESC* const outDesc)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const getDesc = reinterpret_cast<technique_get_desc_fn>(vtable[1]);
      return getDesc(technique, outDesc);
    }

    void* InvokeTechniqueGetPassByIndex(void* const technique, const int pass)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const getPassByIndex = reinterpret_cast<technique_get_pass_by_index_fn>(vtable[4]);
      return getPassByIndex(technique, pass);
    }

    void InvokeTechniqueGetPassCount(void* const technique, D3D10_TECHNIQUE_DESC* const outPassCount)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const getPassCount = reinterpret_cast<technique_get_pass_counter_fn>(vtable[1]);
      getPassCount(technique, outPassCount);
    }

    HRESULT InvokePassGetDesc(void* const pass, D3D10_PASS_DESC* const outDesc)
    {
      auto** const vtable = *reinterpret_cast<void***>(pass);
      auto* const getDesc = reinterpret_cast<pass_get_desc_fn>(vtable[1]);
      return getDesc(pass, outDesc);
    }

    HRESULT InvokePassApply(void* const pass, const unsigned int flags)
    {
      auto** const vtable = *reinterpret_cast<void***>(pass);
      auto* const apply = reinterpret_cast<pass_apply_fn>(vtable[7]);
      return apply(pass, flags);
    }

    BOOL InvokeVariableIsValid(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const isValid = reinterpret_cast<variable_is_valid_fn>(vtable[0]);
      return isValid(variable);
    }

    void* InvokeVariableGetAnnotationByName(void* const variable, const char* const name)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const getAnnotationByName = reinterpret_cast<variable_get_annotation_by_name_fn>(vtable[4]);
      return getAnnotationByName(variable, name);
    }

    void* InvokeVariableAsScalar(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const asScalar = reinterpret_cast<variable_as_scalar_fn>(vtable[10]);
      return asScalar(variable);
    }

    void* InvokeVariableAsString(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const asString = reinterpret_cast<variable_as_string_fn>(vtable[13]);
      return asString(variable);
    }

    void* InvokeVariableAsVector(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const asVector = reinterpret_cast<variable_as_vector_fn>(vtable[11]);
      return asVector(variable);
    }

    void* InvokeVariableAsMatrix(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const asMatrix = reinterpret_cast<variable_as_matrix_fn>(vtable[12]);
      return asMatrix(variable);
    }

    HRESULT InvokeVariableSetRawValue(
      void* const variable, const void* const data, const unsigned int offsetBytes, const unsigned int valueBytes
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const setRawValue = reinterpret_cast<variable_set_raw_value_fn>(vtable[23]);
      return setRawValue(variable, data, offsetBytes, valueBytes);
    }

    void* InvokeVariableAsShaderResource(void* const variable)
    {
      auto** const vtable = *reinterpret_cast<void***>(variable);
      auto* const asShaderResource = reinterpret_cast<variable_as_shader_resource_fn>(vtable[14]);
      return asShaderResource(variable);
    }

    HRESULT InvokeScalarGetBool(void* const scalar, int* const outValue)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const getBool = reinterpret_cast<scalar_get_bool_fn>(vtable[34]);
      return getBool(scalar, outValue);
    }

    HRESULT InvokeScalarSetBool(void* const scalar, const BOOL value)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const setBool = reinterpret_cast<scalar_set_bool_fn>(vtable[33]);
      return setBool(scalar, value);
    }

    HRESULT InvokeScalarGetInt(void* const scalar, int* const outValue)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const getInt = reinterpret_cast<scalar_get_int_fn>(vtable[30]);
      return getInt(scalar, outValue);
    }

    HRESULT InvokeScalarSetInt(void* const scalar, const int value)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const setInt = reinterpret_cast<scalar_set_int_fn>(vtable[29]);
      return setInt(scalar, value);
    }

    HRESULT InvokeScalarGetFloat(void* const scalar, float* const outValue)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const getFloat = reinterpret_cast<scalar_get_float_fn>(vtable[26]);
      return getFloat(scalar, outValue);
    }

    HRESULT InvokeScalarSetFloat(void* const scalar, const float value)
    {
      auto** const vtable = *reinterpret_cast<void***>(scalar);
      auto* const setFloat = reinterpret_cast<scalar_set_float_fn>(vtable[25]);
      return setFloat(scalar, value);
    }

    HRESULT InvokeVectorSetFloatVector(void* const vectorValue, const void* const data)
    {
      auto** const vtable = *reinterpret_cast<void***>(vectorValue);
      auto* const setFloatVector = reinterpret_cast<vector_set_float_vector_fn>(vtable[27]);
      return setFloatVector(vectorValue, data);
    }

    HRESULT InvokeMatrixSetMatrix(void* const matrixValue, const void* const data)
    {
      auto** const vtable = *reinterpret_cast<void***>(matrixValue);
      auto* const setMatrix = reinterpret_cast<matrix_set_matrix_fn>(vtable[25]);
      return setMatrix(matrixValue, data);
    }

    HRESULT InvokeMatrixSetMatrixArray(
      void* const matrixValue, const void* const data, const unsigned int offsetValues, const unsigned int valueCount
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(matrixValue);
      auto* const setMatrixArray = reinterpret_cast<matrix_set_matrix_array_fn>(vtable[27]);
      return setMatrixArray(matrixValue, data, offsetValues, valueCount);
    }

    HRESULT InvokeVectorSetArray(
      void* const vectorValue, const void* const data, const unsigned int offsetValues, const unsigned int valueCount
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(vectorValue);
      auto* const setArray = reinterpret_cast<vector_set_array_fn>(vtable[33]);
      return setArray(vectorValue, data, offsetValues, valueCount);
    }

    HRESULT InvokeShaderResourceSetResource(void* const shaderResourceValue, void* const resourceView)
    {
      auto** const vtable = *reinterpret_cast<void***>(shaderResourceValue);
      auto* const setResource = reinterpret_cast<shader_resource_set_resource_fn>(vtable[25]);
      return setResource(shaderResourceValue, resourceView);
    }

    HRESULT InvokeStringGetString(void* const stringVariable, const char** const outValue)
    {
      auto** const vtable = *reinterpret_cast<void***>(stringVariable);
      auto* const getString = reinterpret_cast<string_get_string_fn>(vtable[25]);
      return getString(stringVariable, outValue);
    }

    // `{proxy, first, last, end}` at 0x10 is `msvc8::vector<EffectMacro>`
    // itself, so the lane is the container, not a view over it.
    using EffectMacroVector = msvc8::vector<EffectMacro>;

    static_assert(sizeof(EffectMacroVector) == 0x10, "EffectMacroVector size must be 0x10");

    template <class T>
    void ReleaseComLike(T*& object) noexcept
    {
      void* rawObject = reinterpret_cast<void*>(object);
      if (rawObject == nullptr) {
        return;
      }

      auto** const vtable = *reinterpret_cast<void***>(rawObject);
      auto* const release = reinterpret_cast<release_fn>(vtable[2]);
      release(rawObject);
      object = nullptr;
    }

    template <class T>
    int ReleaseComLikeWithResult(T*& object) noexcept
    {
      void* rawObject = reinterpret_cast<void*>(object);
      if (rawObject == nullptr) {
        return 0;
      }

      auto** const vtable = *reinterpret_cast<void***>(rawObject);
      auto* const release = reinterpret_cast<release_fn>(vtable[2]);
      const int result = static_cast<int>(release(rawObject));
      object = nullptr;
      return result;
    }

    void InvokeTextureGetDesc(void* const texture, D3D10_TEXTURE2D_DESC* const outDesc)
    {
      auto** const vtable = *reinterpret_cast<void***>(texture);
      auto* const getDesc = reinterpret_cast<texture_get_desc_fn>(vtable[12]);
      getDesc(texture, outDesc);
    }

    HRESULT InvokeTextureMap(
      void* const texture, const int level, const unsigned int mapMode, D3D10_MAPPED_TEXTURE2D* const outMapped
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(texture);
      auto* const map = reinterpret_cast<texture_map_fn>(vtable[10]);
      return map(texture, level, mapMode, 0U, outMapped);
    }

    void InvokeTextureUnmap(void* const texture, const int level)
    {
      auto** const vtable = *reinterpret_cast<void***>(texture);
      auto* const unmap = reinterpret_cast<texture_unmap_fn>(vtable[11]);
      unmap(texture, level);
    }

    /**
     * Address: 0x008F8860 (FUN_008F8860)
     *
     * Device *,int,void **
     *
     * What it does:
     * Forwards one helper call through the retained function-pointer lane
     * at `Device+0x34`.
     */
    HRESULT InvokeDeviceHelper34(Device* const device, const int mode, void** const outValue)
    {
      // The binary thunk is `mov eax,[ecx+0x34]; jmp eax`: `this` is not an
      // argument, the export sees exactly the caller's two stack arguments.
      return reinterpret_cast<DeviceD3D10*>(device)->mD3D10CreateBlob(static_cast<std::uint32_t>(mode), outValue);
    }

    /**
     * Address: 0x008F8880 (FUN_008F8880)
     *
     * Device *,void *,int,void **
     *
     * What it does:
     * Forwards one helper call through the retained function-pointer lane
     * at `Device+0x44`.
     */
    HRESULT InvokeDeviceHelper44(Device* const device, void* const texture, const int mode, void** const outValue)
    {
      // `mov ecx,[ecx+0x44]; jmp ecx`: as above, three stack arguments and no `this`.
      return reinterpret_cast<DeviceD3D10*>(device)->mD3DX10SaveTextureToMemory(texture, mode, outValue);
    }

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

    int ReleaseComSlotAndNull(void** const slot) noexcept
    {
      if (slot == nullptr) {
        return 0;
      }

      void* object = *slot;
      if (object == nullptr) {
        *slot = nullptr;
        return 0;
      }

      auto** const vtable = *reinterpret_cast<void***>(object);
      auto* const release = reinterpret_cast<release_fn>(vtable[2]);
      const int result = static_cast<int>(release(object));
      *slot = nullptr;
      return result;
    }

    /**
     * Address: 0x008F5330 (FUN_008F5330)
     *
     * void **
     *
     * What it does:
     * Calls COM-like vtable slot `+0x08` (`Release`) when slot payload is
     * non-null, then clears the slot and returns the release/result lane.
     */
    int ReleaseComSlotVariant0(void** const slot) noexcept
    {
      void* const object = *slot;
      int result = static_cast<int>(reinterpret_cast<std::uintptr_t>(object));
      if (object != nullptr) {
        auto** const vtable = *reinterpret_cast<void***>(object);
        auto* const release = reinterpret_cast<release_fn>(vtable[2]);
        result = static_cast<int>(release(object));
      }
      *slot = nullptr;
      return result;
    }

    /**
     * Address: 0x008F8D90 (FUN_008F8D90)
     *
     * void **
     *
     * What it does:
     * Releases one COM-like pointer lane (if present) and clears the slot.
     */
    int ReleaseComSlotVariant1(void** const slot) noexcept
    {
      return ReleaseComSlotAndNull(slot);
    }

    /**
     * Address: 0x008F8DF0 (FUN_008F8DF0)
     *
     * void **
     *
     * What it does:
     * Releases one COM-like pointer lane (if present) and clears the slot.
     */
    int ReleaseComSlotVariant2(void** const slot) noexcept
    {
      return ReleaseComSlotAndNull(slot);
    }

    /**
     * Address: 0x008F8E10 (FUN_008F8E10)
     *
     * void **
     *
     * What it does:
     * Releases one COM-like pointer lane (if present) and clears the slot.
     */
    int ReleaseComSlotVariant3(void** const slot) noexcept
    {
      return ReleaseComSlotAndNull(slot);
    }

    /**
     * Address: 0x008F8E30 (FUN_008F8E30)
     *
     * void **
     *
     * What it does:
     * Releases one COM-like pointer lane (if present) and clears the slot.
     */
    int ReleaseComSlotVariant4(void** const slot) noexcept
    {
      return ReleaseComSlotAndNull(slot);
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

    DeviceD3D10::D3D10CreateBlobFn GetDeviceCreateBlobApi(DeviceD3D10* const device) noexcept
    {
      return device->mD3D10CreateBlob;
    }

    DeviceD3D10::D3DX10CreateEffectFromMemoryFn GetDeviceCreateEffectFromMemoryApi(DeviceD3D10* const device) noexcept
    {
      return device->mD3DX10CreateEffectFromMemory;
    }

    DeviceD3D10::D3DX10CreateTextureFromMemoryFn GetDeviceCreateTextureFromMemoryApi(DeviceD3D10* const device) noexcept
    {
      return device->mD3DX10CreateTextureFromMemory;
    }

    DeviceD3D10::D3DX10SaveTextureToFileFn GetDeviceSaveTextureToFileApi(DeviceD3D10* const device) noexcept
    {
      return device->mD3DX10SaveTextureToFileA;
    }

    DeviceD3D10::D3DX10SaveTextureToMemoryFn GetDeviceSaveTextureToMemoryApi(DeviceD3D10* const device) noexcept
    {
      return device->mD3DX10SaveTextureToMemory;
    }

    HRESULT InvokeCreateBlobApi(DeviceD3D10* const device, void** const outBlob)
    {
      return GetDeviceCreateBlobApi(device)(0U, outBlob);
    }

    HRESULT InvokeCreateEffectFromMemoryApi(
      DeviceD3D10* const device,
      const void* const sourceData,
      const std::uint32_t sourceBytes,
      const D3D10_SHADER_MACRO* const defines,
      ID3D10Effect** const outEffect,
      void** const outErrors
    )
    {
      return GetDeviceCreateEffectFromMemoryApi(device)(
        sourceData,
        sourceBytes,
        nullptr,
        defines,
        nullptr,
        0x1000U,
        0U,
        device->mDevice,
        nullptr,
        nullptr,
        outEffect,
        outErrors
      );
    }

    HRESULT InvokeCreateTextureFromMemoryApi(
      DeviceD3D10* const device,
      const void* const sourceData,
      const std::uint32_t sourceBytes,
      const void* const loadInfo,
      void** const outResource
    )
    {
      return GetDeviceCreateTextureFromMemoryApi(device)(
        GetDeviceNativeHandle(device), sourceData, sourceBytes, loadInfo, nullptr, outResource
      );
    }

    HRESULT InvokeSaveTextureToFileApi(
      DeviceD3D10* const device, void* const textureResource, const int fileFormat, const char* const filePath
    )
    {
      return GetDeviceSaveTextureToFileApi(device)(textureResource, fileFormat, filePath);
    }

    HRESULT InvokeSaveTextureToMemoryApi(
      DeviceD3D10* const device, void* const textureResource, const int fileFormat, void** const outReadback
    )
    {
      return GetDeviceSaveTextureToMemoryApi(device)(textureResource, fileFormat, outReadback);
    }

    int GetReadbackSize(void* const readback)
    {
      auto** const vtable = *reinterpret_cast<void***>(readback);
      auto* const getSize = reinterpret_cast<readback_get_size_fn>(vtable[4]);
      return getSize(readback);
    }

    void* GetReadbackData(void* const readback)
    {
      auto** const vtable = *reinterpret_cast<void***>(readback);
      auto* const getData = reinterpret_cast<readback_get_data_fn>(vtable[3]);
      return getData(readback);
    }

    HRESULT QueryInterfaceTexture2D(void* const resource, void** const outTexture2D)
    {
      auto** const vtable = *reinterpret_cast<void***>(resource);
      auto* const queryInterface = reinterpret_cast<HRESULT(__stdcall*)(void*, const IID&, void**)>(vtable[0]);
      return queryInterface(resource, IID_ID3D10Texture2D, outTexture2D);
    }

    std::uint16_t FallbackFloat32To16(const float value)
    {
      std::uint32_t bits = 0U;
      static_assert(sizeof(bits) == sizeof(value), "float/uint32_t size mismatch");
      std::memcpy(&bits, &value, sizeof(bits));

      const std::uint32_t sign = (bits >> 16U) & 0x8000U;
      std::int32_t exponent = static_cast<std::int32_t>((bits >> 23U) & 0xFFU) - 127 + 15;
      std::uint32_t mantissa = bits & 0x007FFFFFU;

      if (exponent <= 0) {
        if (exponent < -10) {
          return static_cast<std::uint16_t>(sign);
        }

        mantissa = (mantissa | 0x00800000U) >> static_cast<std::uint32_t>(1 - exponent);
        return static_cast<std::uint16_t>(sign | ((mantissa + 0x00001000U) >> 13U));
      }

      if (exponent >= 31) {
        return static_cast<std::uint16_t>(sign | 0x7C00U);
      }

      return static_cast<std::uint16_t>(sign | (static_cast<std::uint32_t>(exponent) << 10U) | ((mantissa + 0x00001000U) >> 13U));
    }

    void ConvertFloat32To16Array(std::uint16_t* const outValues, const float* const inValues, const unsigned int count)
    {
      for (unsigned int index = 0U; index < count; ++index) {
        outValues[index] = FallbackFloat32To16(inValues[index]);
      }
    }

    /**
     * Address: 0x0094D490 (FUN_0094D490)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from one
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    float* CopyMatrix4x3Rows(
      float* const outRow0,
      float* const outRow1,
      float* const outRow2,
      float* const outRow3,
      float* const sourceMatrix4x4
    )
    {
      outRow0[0] = sourceMatrix4x4[0];
      outRow0[1] = sourceMatrix4x4[1];
      outRow0[2] = sourceMatrix4x4[2];

      outRow1[0] = sourceMatrix4x4[4];
      outRow1[1] = sourceMatrix4x4[5];
      outRow1[2] = sourceMatrix4x4[6];

      outRow2[0] = sourceMatrix4x4[8];
      outRow2[1] = sourceMatrix4x4[9];
      outRow2[2] = sourceMatrix4x4[10];

      outRow3[0] = sourceMatrix4x4[12];
      outRow3[1] = sourceMatrix4x4[13];
      outRow3[2] = sourceMatrix4x4[14];

      return sourceMatrix4x4;
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
    int ReleaseAdapterOutputAndDeviceRefs(AdapterD3D10* const adapter) noexcept
    {
      for (AdapterModeD3D10& mode : adapter->modes_) {
        ReleaseComLike(mode.output_);
      }
      return ReleaseComLikeWithResult(adapter->dxgiAdapter_);
    }

    // Defined later in this TU; used by the vector<void*>::_Insert_n grow lane below.
    [[noreturn]] void ThrowVectorTooLongLengthErrorB();

    /**
     * Address: 0x008F8670 (FUN_008F8670)
     *
     * What it does:
     * Initializes one 13-lane texture-load info block with binary defaults.
     */
    std::int32_t* InitializeTextureLoadInfoDefaults(std::int32_t* const loadInfo) noexcept
    {
      loadInfo[0] = -1;
      loadInfo[1] = -1;
      loadInfo[2] = -1;
      loadInfo[3] = -1;
      loadInfo[4] = -1;
      loadInfo[5] = -1;
      loadInfo[6] = -1;
      loadInfo[7] = -1;
      loadInfo[8] = -1;
      loadInfo[9] = -3;
      loadInfo[10] = -1;
      loadInfo[11] = -1;
      loadInfo[12] = 0;
      return loadInfo;
    }

    /**
     * Address: 0x00901C90 (FUN_00901C90)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `IndexBufferD3D10`.
     */
    void DestroyIndexBufferD3D10Body(IndexBufferD3D10* const indexBuffer)
    {
      indexBuffer->DestroyState();
      indexBuffer->context_.~IndexBufferContext();
    }

    /**
     * Address: 0x0094DA80 (FUN_0094DA80)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `VertexBufferD3D10`.
     */
    void DestroyVertexBufferD3D10Body(VertexBufferD3D10* const vertexBuffer)
    {
      vertexBuffer->DestroyState();
      vertexBuffer->context_.~VertexBufferContext();
    }

    /**
     * Address: 0x00900F50 (FUN_00900F50)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `EffectTechniqueD3D10`.
     */
    void DestroyEffectTechniqueD3D10Body(EffectTechniqueD3D10* const technique) noexcept
    {
      ReleaseComLike(technique->dxEffect_);
      technique->techniqueHandle_ = nullptr;
      technique->name_.tidy(true, 0U);
      technique->beginEndActive_ = false;
    }

    /**
     * Address: 0x009023F0 (FUN_009023F0)
     *
     * What it does:
     * Releases retained D3D10 pipeline-state COM handles and clears local
     * state lanes.
     */
    void DestroyPipelineStateD3D10Body(PipelineStateD3D10* const pipelineState) noexcept
    {
      if (pipelineState == nullptr) {
        return;
      }

      ReleaseComLike(pipelineState->device_);
      pipelineState->device_ = nullptr;

      ReleaseComLike(pipelineState->rasterizerState1_);
      pipelineState->rasterizerState1_ = nullptr;
      ReleaseComLike(pipelineState->depthStencilState1_);
      pipelineState->depthStencilState1_ = nullptr;
      ReleaseComLike(pipelineState->blendState1_);
      pipelineState->blendState1_ = nullptr;
      ReleaseComLike(pipelineState->samplerState1_);
      pipelineState->samplerState1_ = nullptr;
      ReleaseComLike(pipelineState->rasterizerState2_);
      pipelineState->rasterizerState2_ = nullptr;
      ReleaseComLike(pipelineState->depthStencilState2_);
      pipelineState->depthStencilState2_ = nullptr;
      ReleaseComLike(pipelineState->blendState2_);
      pipelineState->blendState2_ = nullptr;
    }

    /**
     * Address: 0x00902240 (FUN_00902240)
     *
     * PipelineState *
     *
     * What it does:
     * ABI adapter lane for `PipelineState` constructor variants that return
     * `this` after the canonical base-constructor side effects (`FUN_00902230`).
     */
    PipelineState* ReturnPipelineStateCtorSelfAdapter(PipelineState* const pipelineState) noexcept
    {
      return pipelineState;
    }

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
      void* const signatureEffect = GetDeviceSignatureEffect(device);
      if (signatureEffect == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1910, "internal D3D10 SignatureEffect error");
      }

      void* const technique = InvokeEffectGetTechniqueByIndex(signatureEffect, static_cast<unsigned int>(formatToken));
      if (technique == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1913, "invalid format/technique combination");
      }

      void* const pass = InvokeTechniqueGetPassByIndex(technique, 0);
      static_cast<void>(InvokePassGetDesc(pass, outPassDesc));
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
    void* CreateStagingTextureCopyOrThrow(Device* const device, void* const sourceTexture)
    {
      D3D10_TEXTURE2D_DESC textureDesc{};
      InvokeTextureGetDesc(sourceTexture, &textureDesc);
      textureDesc.Usage = D3D10_USAGE_STAGING;
      textureDesc.BindFlags = 0U;
      textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

      ID3D10Device* const nativeDevice = reinterpret_cast<DeviceD3D10*>(device)->mDevice;
      auto** const nativeVtable = *reinterpret_cast<void***>(nativeDevice);

      void* stagingTexture = nullptr;
      auto* const createTexture2D = reinterpret_cast<device_native_create_texture2d_fn>(nativeVtable[73]);
      const HRESULT createResult = createTexture2D(nativeDevice, &textureDesc, nullptr, &stagingTexture);
      if (createResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1635, createResult);
      }

      auto* const copyResource = reinterpret_cast<device_native_copy_resource_fn>(nativeVtable[33]);
      copyResource(nativeDevice, stagingTexture, sourceTexture);
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

    std::uint32_t VertexStreamStrideCount(const VertexStreamStrideStorage& storage) noexcept
    {
      if ((storage.begin_ == nullptr) || (storage.end_ == nullptr)) {
        return 0U;
      }

      return static_cast<std::uint32_t>(storage.end_ - storage.begin_);
    }

    std::uint32_t VertexStreamStrideCapacity(const VertexStreamStrideStorage& storage) noexcept
    {
      if ((storage.begin_ == nullptr) || (storage.capacityEnd_ == nullptr)) {
        return 0U;
      }

      return static_cast<std::uint32_t>(storage.capacityEnd_ - storage.begin_);
    }

    void EnsureVertexStreamStrideCount(VertexStreamStrideStorage* const storage, const std::uint32_t requiredCount)
    {
      const std::uint32_t currentCount = VertexStreamStrideCount(*storage);
      if (requiredCount <= currentCount) {
        return;
      }

      const std::uint32_t currentCapacity = VertexStreamStrideCapacity(*storage);
      if (requiredCount > currentCapacity) {
        auto* const newBegin =
          static_cast<std::uint32_t*>(::operator new(static_cast<std::size_t>(requiredCount) * sizeof(std::uint32_t)));

        if ((storage->begin_ != nullptr) && (currentCount != 0U)) {
          std::memcpy(newBegin, storage->begin_, static_cast<std::size_t>(currentCount) * sizeof(std::uint32_t));
        }

        std::memset(
          newBegin + currentCount, 0, static_cast<std::size_t>(requiredCount - currentCount) * sizeof(std::uint32_t)
        );

        if (storage->begin_ != nullptr) {
          ::operator delete(storage->begin_);
        }

        storage->begin_ = newBegin;
        storage->end_ = newBegin + requiredCount;
        storage->capacityEnd_ = newBegin + requiredCount;
        return;
      }

      std::memset(storage->end_, 0, static_cast<std::size_t>(requiredCount - currentCount) * sizeof(std::uint32_t));
      storage->end_ = storage->begin_ + requiredCount;
    }

    /**
     * Address: 0x00904180 (FUN_00904180)
     *
     * What it does:
     * Releases the retained declaration handle lane and restores the format
     * token to the invalid/default sentinel (`0x17`).
     */
    void ResetVertexFormatDeclaration(VertexFormatD3D10* const vertexFormat) noexcept
    {
      ReleaseComLike(vertexFormat->vertexDeclaration_);
      vertexFormat->format_ = 0x17U;
    }

    /**
     * Address: 0x009041B0 (FUN_009041B0)
     *
     * What it does:
     * Releases heap storage for per-stream stride lanes and zeros begin/end/capacity.
     */
    void DestroyVertexFormatBaseBody(VertexFormatD3D10* const vertexFormat) noexcept
    {
      if (vertexFormat->streamStrides_.begin_ != nullptr) {
        ::operator delete(vertexFormat->streamStrides_.begin_);
      }

      vertexFormat->streamStrides_.begin_ = nullptr;
      vertexFormat->streamStrides_.end_ = nullptr;
      vertexFormat->streamStrides_.capacityEnd_ = nullptr;
    }

    /**
     * Address: 0x009041E0 (FUN_009041E0)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for
     * `VertexFormatD3D10` and then its base-format storage lane.
     */
    void DestroyVertexFormatD3D10Body(VertexFormatD3D10* const vertexFormat) noexcept
    {
      ResetVertexFormatDeclaration(vertexFormat);
      DestroyVertexFormatBaseBody(vertexFormat);
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
     * Address: 0x008F9D40 (FUN_008F9D40)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` lane from one raw
     * `VertexFormatD3D10*` pointee.
     */
    boost::detail::shared_count* ConstructSharedCountVertexFormatD3D10FromRaw(
      boost::detail::shared_count* const outCount, VertexFormatD3D10* const vertexFormat
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, vertexFormat);
    }

    /**
     * Address: 0x008F9DD0 (FUN_008F9DD0)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` lane from one raw
     * `VertexBufferD3D10*` pointee.
     */
    boost::detail::shared_count* ConstructSharedCountVertexBufferD3D10FromRaw(
      boost::detail::shared_count* const outCount, VertexBufferD3D10* const vertexBuffer
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, vertexBuffer);
    }

    /**
     * Address: 0x008F9E60 (FUN_008F9E60)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` lane from one raw
     * `IndexBufferD3D10*` pointee.
     */
    boost::detail::shared_count* ConstructSharedCountIndexBufferD3D10FromRaw(
      boost::detail::shared_count* const outCount, IndexBufferD3D10* const indexBuffer
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, indexBuffer);
    }

    /**
     * Address: 0x0094B750 (FUN_0094B750)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` lane from one raw
     * `EffectVariableD3D10*` pointee.
     */
    boost::detail::shared_count* ConstructSharedCountEffectVariableD3D10FromRaw(
      boost::detail::shared_count* const outCount, EffectVariableD3D10* const effectVariable
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, effectVariable);
    }

    /**
     * Address: 0x0094B6C0 (FUN_0094B6C0)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` lane from one raw
     * `EffectTechniqueD3D10*` pointee.
     */
    boost::detail::shared_count* ConstructSharedCountEffectTechniqueD3D10FromRaw(
      boost::detail::shared_count* const outCount, EffectTechniqueD3D10* const effectTechnique
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, effectTechnique);
    }

    /**
     * Address: 0x008F9A70 (FUN_008F9A70, boost::detail::shared_count_EffectD3D10::shared_count_EffectD3D10)
     *
     * What it does:
     * Allocates one 0x10-byte `sp_counted_impl_p<EffectD3D10>` control
     * block, publishes its vtable, sets use/weak count to one, and stores
     * the owned raw pointer - the control-block half of constructing one
     * `shared_ptr<EffectD3D10>`.
     */
    boost::detail::shared_count* ConstructSharedCountEffectD3D10FromRaw(
      boost::detail::shared_count* const outCount, EffectD3D10* const effect
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, effect);
    }

    /**
     * Address: 0x008FA3D0 (FUN_008FA3D0, boost::shared_ptr_EffectD3D10::shared_ptr_EffectD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<EffectD3D10>` from one raw pointer lane.
     * FUN_008FA3D0's own disassembly publishes `px` ("effect") first, then
     * builds the control block through one discrete `shared_count(T*)`
     * call (FUN_008F9A70 above - a real, separately-emitted call, not
     * inlined - also reached the same way from `DeviceD3D10::CreateEffect`'s
     * `reset()`) before a no-op `sp_enable_shared_from_this` (`EffectD3D10`
     * does not derive from `enable_shared_from_this`); reproduced
     * explicitly here instead of relying on boost's own converting
     * constructor.
     */
    boost::shared_ptr<EffectD3D10>* ConstructSharedEffectD3D10FromRaw(
      boost::shared_ptr<EffectD3D10>* const outEffect, EffectD3D10* const effect
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(outEffect, effect, ConstructSharedCountEffectD3D10FromRaw);
    }

    /**
     * Address: 0x008FA4C0 (FUN_008FA4C0, boost::shared_ptr_VertexFormatD3D10::shared_ptr_VertexFormatD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<VertexFormatD3D10>` from one raw pointer
     * lane. FUN_008FA4C0's own disassembly publishes `px` first, then
     * builds the control block through one discrete `shared_count(T*)`
     * call (FUN_008F9D40 above, `ConstructSharedCountVertexFormatD3D10FromRaw`
     * - a real, separately-emitted call, not inlined) before a no-op
     * `sp_enable_shared_from_this` (`VertexFormatD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<VertexFormatD3D10>* ConstructSharedVertexFormatD3D10FromRaw(
      boost::shared_ptr<VertexFormatD3D10>* const outVertexFormat,
      VertexFormatD3D10* const vertexFormat
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outVertexFormat, vertexFormat, ConstructSharedCountVertexFormatD3D10FromRaw
      );
    }

    /**
     * Address: 0x008FA4F0 (FUN_008FA4F0, boost::shared_ptr_VertexBufferD3D10::shared_ptr_VertexBufferD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<VertexBufferD3D10>` from one raw pointer
     * lane. FUN_008FA4F0's own disassembly publishes `px` first, then
     * builds the control block through one discrete `shared_count(T*)`
     * call (FUN_008F9DD0 above, `ConstructSharedCountVertexBufferD3D10FromRaw`
     * - a real, separately-emitted call, not inlined) before a no-op
     * `sp_enable_shared_from_this` (`VertexBufferD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<VertexBufferD3D10>* ConstructSharedVertexBufferD3D10FromRaw(
      boost::shared_ptr<VertexBufferD3D10>* const outVertexBuffer,
      VertexBufferD3D10* const vertexBuffer
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outVertexBuffer, vertexBuffer, ConstructSharedCountVertexBufferD3D10FromRaw
      );
    }

    /**
     * Address: 0x008FA520 (FUN_008FA520, boost::shared_ptr_IndexBufferD3D10::shared_ptr_IndexBufferD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<IndexBufferD3D10>` from one raw pointer
     * lane. FUN_008FA520's own disassembly publishes `px` first, then
     * builds the control block through one discrete `shared_count(T*)`
     * call (FUN_008F9E60 above, `ConstructSharedCountIndexBufferD3D10FromRaw`
     * - a real, separately-emitted call, not inlined) before a no-op
     * `sp_enable_shared_from_this` (`IndexBufferD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<IndexBufferD3D10>* ConstructSharedIndexBufferD3D10FromRaw(
      boost::shared_ptr<IndexBufferD3D10>* const outIndexBuffer,
      IndexBufferD3D10* const indexBuffer
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outIndexBuffer, indexBuffer, ConstructSharedCountIndexBufferD3D10FromRaw
      );
    }

    /**
     * Address: 0x0094B840 (FUN_0094B840, boost::shared_ptr_EffectTechniqueD3D10::shared_ptr_EffectTechniqueD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<EffectTechniqueD3D10>` from one raw
     * pointer lane. FUN_0094B840's own disassembly publishes `px` first,
     * then builds the control block through one discrete `shared_count(T*)`
     * call (FUN_0094B6C0 above, `ConstructSharedCountEffectTechniqueD3D10FromRaw`
     * - a real, separately-emitted call, not inlined) before a no-op
     * `sp_enable_shared_from_this` (`EffectTechniqueD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<EffectTechniqueD3D10>* ConstructSharedEffectTechniqueD3D10FromRaw(
      boost::shared_ptr<EffectTechniqueD3D10>* const outEffectTechnique,
      EffectTechniqueD3D10* const effectTechnique
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outEffectTechnique, effectTechnique, ConstructSharedCountEffectTechniqueD3D10FromRaw
      );
    }

    /**
     * Address: 0x0094B870 (FUN_0094B870, boost::shared_ptr_EffectVariableD3D10::shared_ptr_EffectVariableD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<EffectVariableD3D10>` from one raw
     * pointer lane. FUN_0094B870's own disassembly publishes `px` first,
     * then builds the control block through one discrete `shared_count(T*)`
     * call (FUN_0094B750 above, `ConstructSharedCountEffectVariableD3D10FromRaw`
     * - a real, separately-emitted call, not inlined) before a no-op
     * `sp_enable_shared_from_this` (`EffectVariableD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<EffectVariableD3D10>* ConstructSharedEffectVariableD3D10FromRaw(
      boost::shared_ptr<EffectVariableD3D10>* const outEffectVariable,
      EffectVariableD3D10* const effectVariable
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outEffectVariable, effectVariable, ConstructSharedCountEffectVariableD3D10FromRaw
      );
    }

    /**
     * Address: 0x008FA0E0 (FUN_008FA0E0, boost::detail::shared_count_PipelineStateD3D10::shared_count_PipelineStateD3D10)
     *
     * What it does:
     * Allocates one 0x10-byte `sp_counted_impl_p<PipelineStateD3D10>`
     * control block, publishes its vtable, sets use/weak count to one,
     * and stores the owned raw pointer - the control-block half of
     * constructing one `shared_ptr<PipelineStateD3D10>`.
     */
    boost::detail::shared_count* ConstructSharedCountPipelineStateD3D10FromRaw(
      boost::detail::shared_count* const outCount, PipelineStateD3D10* const pipelineState
    )
    {
      return boost::ConstructSharedCountFromRaw(outCount, pipelineState);
    }

    /**
     * Address: 0x008FA5F0 (FUN_008FA5F0, boost::shared_ptr_PipelineStateD3D10::shared_ptr_PipelineStateD3D10)
     *
     * What it does:
     * Constructs one `shared_ptr<PipelineStateD3D10>` from one raw pointer
     * lane. FUN_008FA5F0's own disassembly publishes `px` ("pipeline")
     * first, then builds the control block through one discrete
     * `shared_count(T*)` call (FUN_008FA0E0 above - a real, separately-
     * emitted call, not inlined - also reached the same way from
     * `AssignSharedPipelineStateD3D10FromRaw`'s `reset()`) before a no-op
     * `sp_enable_shared_from_this` (`PipelineStateD3D10` does not derive
     * from `enable_shared_from_this`); reproduced explicitly here instead
     * of relying on boost's own converting constructor.
     */
    boost::shared_ptr<PipelineStateD3D10>* ConstructSharedPipelineStateD3D10FromRaw(
      boost::shared_ptr<PipelineStateD3D10>* const outPipelineState, PipelineStateD3D10* const pipelineState
    )
    {
      return boost::ConstructSharedFromRawViaCountCtor(
        outPipelineState, pipelineState, ConstructSharedCountPipelineStateD3D10FromRaw
      );
    }

    /**
     * Address: 0x008FA760 (FUN_008FA760, boost::shared_ptr_PipelineStateD3D10::operator=)
     *
     * What it does:
     * Rebinds one `shared_ptr<PipelineStateD3D10>` from one raw pipeline-state
     * pointer and releases previous ownership.
     */
    boost::shared_ptr<PipelineStateD3D10>* AssignSharedPipelineStateD3D10FromRaw(
      boost::shared_ptr<PipelineStateD3D10>* const outPipelineState, PipelineStateD3D10* const pipelineState
    )
    {
      outPipelineState->reset(pipelineState);
      return outPipelineState;
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

    /**
     * Address: 0x0094C150 (FUN_0094C150)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `EffectVariableD3D10`.
     */
    void DestroyEffectVariableD3D10Body(EffectVariableD3D10* const variable) noexcept
    {
      ReleaseComLike(variable->dxEffect_);
      variable->variableHandle_ = nullptr;
      variable->name_.tidy(true, 0U);
    }

    /**
     * Address: 0x009001B0 (FUN_009001B0)
     *
     * What it does:
     * Releases startup/runtime-owned D3D10 device resources and resets recovered
     * context/module lanes.
     */
    BOOL ResetDeviceD3D10Runtime(DeviceD3D10* const backend)
    {
      if (backend == nullptr) {
        return FALSE;
      }

      if (backend->mHeadOutputContexts != nullptr) {
        delete[] backend->mHeadOutputContexts;
        backend->mHeadOutputContexts = nullptr;
      }

      for (IDXGISwapChain*& swapChain : backend->mSwapChains) {
        ReleaseComLike(swapChain);
      }
      backend->mSwapChains.clear();

      backend->mAdapters.clear();
      backend->mPipelineState.reset();

      ReleaseComLike(backend->mDXGIFactory);
      ReleaseComLike(backend->mDevice);
      ReleaseComLike(backend->mSignatureEffect);
      ReleaseComLike(backend->mRttEffect);
      ReleaseComLike(backend->mRttQuadVertexBuffer);
      ReleaseComLike(backend->mRttInputLayout);

      backend->mCursor.Destroy();
      backend->mDeviceContext = DeviceContext(0);
      backend->mLog.clear();
      backend->mCurThreadId = 0;

      ::FreeLibrary(backend->mDXGIModule);
      backend->mDXGIModule = nullptr;

      ::FreeLibrary(backend->mD3DX10Module);
      backend->mD3DX10Module = nullptr;

      const BOOL result = ::FreeLibrary(backend->mD3D10Module);
      backend->mD3D10Module = nullptr;

      backend->mD3D10CreateDevice = nullptr;
      backend->mD3D10CreateBlob = nullptr;
      backend->mD3DX10CreateEffectFromMemory = nullptr;
      backend->mD3DX10CreateTextureFromMemory = nullptr;
      backend->mD3DX10SaveTextureToFileA = nullptr;
      backend->mD3DX10SaveTextureToMemory = nullptr;
      backend->mCreateDXGIFactory = nullptr;
      return result;
    }

    /**
     * Address: 0x00900450 (FUN_00900450)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `DeviceD3D10` by running
     * runtime reset, then final member teardown/deallocation in binary order.
     */
    void DestroyDeviceD3D10Body(DeviceD3D10* const backend)
    {
      if (backend == nullptr) {
        return;
      }

      static_cast<void>(ResetDeviceD3D10Runtime(backend));
      backend->mCursor.~CursorD3D10();
      backend->mPipelineState.reset();
      backend->mSwapChains.tidy();
      backend->mAdapters.tidy();
      backend->mDeviceContext.~DeviceContext();
      backend->mLog.tidy();
      backend->mOutputContext.~OutputContext();
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
  AdapterD3D10::AdapterD3D10(void* const dxgiAdapter)
    : dxgiAdapter_(reinterpret_cast<IDXGIAdapter*>(dxgiAdapter))
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
    static_cast<void>(ReleaseAdapterOutputAndDeviceRefs(this));
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
    AddRefComLike(device_);
    CreateState1();
    CreateState2();
  }

  /**
   * Address: 0x009024F0 (FUN_009024F0)
   *
   * What it does:
   * Creates the primary rasterizer/depth-stencil/blend/sampler state pack.
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
    rasterizerDesc.DepthClipEnable = TRUE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState1_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(248, createRasterizerResult);
    }

    D3D10_DEPTH_STENCIL_DESC depthStencilDesc{};
    depthStencilDesc.DepthEnable = FALSE;
    depthStencilDesc.DepthWriteMask = D3D10_DEPTH_WRITE_MASK_ZERO;
    depthStencilDesc.DepthFunc = D3D10_COMPARISON_ALWAYS;
    depthStencilDesc.StencilEnable = TRUE;
    depthStencilDesc.StencilReadMask = D3D10_DEFAULT_STENCIL_READ_MASK;
    depthStencilDesc.StencilWriteMask = D3D10_DEFAULT_STENCIL_WRITE_MASK;
    depthStencilDesc.FrontFace.StencilFailOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilDepthFailOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilPassOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilFunc = D3D10_COMPARISON_ALWAYS;
    depthStencilDesc.BackFace = depthStencilDesc.FrontFace;

    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState1_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(251, createDepthStencilResult);
    }

    D3D10_BLEND_DESC blendDesc{};
    blendDesc.AlphaToCoverageEnable = FALSE;
    blendDesc.BlendEnable[0] = FALSE;
    blendDesc.SrcBlend = D3D10_BLEND_ONE;
    blendDesc.DestBlend = D3D10_BLEND_ZERO;
    blendDesc.BlendOp = D3D10_BLEND_OP_ADD;
    blendDesc.SrcBlendAlpha = D3D10_BLEND_ONE;
    blendDesc.DestBlendAlpha = D3D10_BLEND_ZERO;
    blendDesc.BlendOpAlpha = D3D10_BLEND_OP_ADD;
    blendDesc.RenderTargetWriteMask[0] = D3D10_COLOR_WRITE_ENABLE_ALL;

    const HRESULT createBlendResult = device_->CreateBlendState(&blendDesc, &blendState1_);
    if (createBlendResult < 0) {
      ThrowPipelineStateD3D10Hresult(254, createBlendResult);
    }

    D3D10_SAMPLER_DESC samplerDesc{};
    samplerDesc.Filter = D3D10_FILTER_MIN_MAG_POINT_MIP_LINEAR;
    samplerDesc.AddressU = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressV = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.AddressW = D3D10_TEXTURE_ADDRESS_WRAP;
    samplerDesc.MipLODBias = 0.0f;
    samplerDesc.MaxAnisotropy = 0U;
    samplerDesc.ComparisonFunc = D3D10_COMPARISON_NEVER;
    samplerDesc.BorderColor[0] = 0.0f;
    samplerDesc.BorderColor[1] = 0.0f;
    samplerDesc.BorderColor[2] = D3D10_FLOAT32_MAX;
    samplerDesc.BorderColor[3] = 0.0f;
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
   * Creates the secondary rasterizer/depth-stencil/blend state pack.
   */
  void PipelineStateD3D10::CreateState2()
  {
    D3D10_RASTERIZER_DESC rasterizerDesc{};
    rasterizerDesc.FillMode = D3D10_FILL_WIREFRAME;
    rasterizerDesc.CullMode = D3D10_CULL_NONE;
    rasterizerDesc.FrontCounterClockwise = TRUE;
    rasterizerDesc.DepthBias = 0;
    rasterizerDesc.DepthBiasClamp = 0.0f;
    rasterizerDesc.SlopeScaledDepthBias = 0.0f;
    rasterizerDesc.DepthClipEnable = TRUE;
    rasterizerDesc.ScissorEnable = FALSE;
    rasterizerDesc.MultisampleEnable = TRUE;
    rasterizerDesc.AntialiasedLineEnable = FALSE;

    const HRESULT createRasterizerResult = device_->CreateRasterizerState(&rasterizerDesc, &rasterizerState2_);
    if (createRasterizerResult < 0) {
      ThrowPipelineStateD3D10Hresult(321, createRasterizerResult);
    }

    D3D10_DEPTH_STENCIL_DESC depthStencilDesc{};
    depthStencilDesc.DepthEnable = FALSE;
    depthStencilDesc.DepthWriteMask = D3D10_DEPTH_WRITE_MASK_ZERO;
    depthStencilDesc.DepthFunc = D3D10_COMPARISON_ALWAYS;
    depthStencilDesc.StencilEnable = TRUE;
    depthStencilDesc.StencilReadMask = D3D10_DEFAULT_STENCIL_READ_MASK;
    depthStencilDesc.StencilWriteMask = D3D10_DEFAULT_STENCIL_WRITE_MASK;
    depthStencilDesc.FrontFace.StencilFailOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilDepthFailOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilPassOp = D3D10_STENCIL_OP_KEEP;
    depthStencilDesc.FrontFace.StencilFunc = D3D10_COMPARISON_ALWAYS;
    depthStencilDesc.BackFace = depthStencilDesc.FrontFace;

    const HRESULT createDepthStencilResult = device_->CreateDepthStencilState(&depthStencilDesc, &depthStencilState2_);
    if (createDepthStencilResult < 0) {
      ThrowPipelineStateD3D10Hresult(324, createDepthStencilResult);
    }

    D3D10_BLEND_DESC blendDesc{};
    blendDesc.AlphaToCoverageEnable = FALSE;
    blendDesc.BlendEnable[0] = FALSE;
    blendDesc.SrcBlend = D3D10_BLEND_ONE;
    blendDesc.DestBlend = D3D10_BLEND_ZERO;
    blendDesc.BlendOp = D3D10_BLEND_OP_ADD;
    blendDesc.SrcBlendAlpha = D3D10_BLEND_ONE;
    blendDesc.DestBlendAlpha = D3D10_BLEND_ZERO;
    blendDesc.BlendOpAlpha = D3D10_BLEND_OP_ADD;
    blendDesc.RenderTargetWriteMask[0] = D3D10_COLOR_WRITE_ENABLE_ALL;

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
   * Address: 0x009024D0 (FUN_009024D0)
   *
   * What it does:
   * Owns the scalar-deleting destructor path and releases retained D3D10
   * pipeline-state COM handle lanes.
   */
  PipelineStateD3D10::~PipelineStateD3D10()
  {
    DestroyPipelineStateD3D10Body(this);
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
   *
   * What it does:
   * Runs the non-deleting teardown body and restores the base
   * `MeshFormatter` vtable lane.
   */
  HardwareVertexFormatterD3D10::~HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x00C09630 (FUN_00C09630, ??1HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Preserves one startup-registered shutdown thunk lane by constructing one
   * typed adapter object and forwarding teardown into
   * `HardwareVertexFormatterD3D10::~HardwareVertexFormatterD3D10`
   * (`FUN_0094D500`).
   */
  void ShutdownHardwareVertexFormatterD3D10Adapter()
  {
    alignas(HardwareVertexFormatterD3D10) unsigned char formatterStorage[sizeof(HardwareVertexFormatterD3D10)]{};
    auto* const formatter = new (static_cast<void*>(formatterStorage)) HardwareVertexFormatterD3D10();
    formatter->~HardwareVertexFormatterD3D10();
  }

  /**
   * Address: 0x0094D8F0 (FUN_0094D8F0)
   *
   * What it does:
   * Owns the scalar-deleting destroy thunk for hardware formatter wrappers.
   */
  MeshFormatter* HardwareVertexFormatterD3D10::Destroy(const std::uint8_t deleteFlags)
  {
    this->~HardwareVertexFormatterD3D10();
    auto* const formatter = static_cast<MeshFormatter*>(this);
    if ((deleteFlags & 1U) != 0U) {
      ::operator delete(formatter);
    }

    return formatter;
  }

  /**
   * Address: 0x0094D510 (FUN_0094D510)
   *
   * What it does:
   * Reports whether hardware mesh instancing is enabled in the active
   * device-context capability lane.
   */
  bool HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    const DeviceContext* const context = reinterpret_cast<DeviceD3D10*>(Device::GetInstance())->GetDeviceContext();
    return context->mHWBasedInstancing;
  }

  /**
   * Address: 0x0094D960 (FUN_0094D960)
   *
   * What it does:
   * Selects hardware vertex-format token `14` and returns the input stream token.
   */
  std::uintptr_t HardwareVertexFormatterD3D10::SelectVertexFormatToken(
    const std::uintptr_t streamToken,
    const std::int32_t layoutVariant
  )
  {
    static_cast<void>(layoutVariant);
    Device* const device = Device::GetInstance();
    InvokeDeviceCreateVertexFormat(device, reinterpret_cast<void*>(streamToken), static_cast<int>(kHardwareVertexFormatToken));
    return streamToken;
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
   * Packs one source vertex into the runtime hardware-vertex stream layout.
   */
  void HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const void* const sourceVertex,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(writeVariant);

    const auto& source = *reinterpret_cast<const SourceMeshVertexRuntime*>(sourceVertex);
    if (streamClass != 0) {
      auto& destination = *reinterpret_cast<HardwareVertexPackedStream1Runtime*>(destinationVertex);
      destination.lane30 = source.streamClassFlag;
      destination.lane44 = source.streamPacked08;
      destination.lane34 = source.streamScalar0C;
      CopyMatrix4x3Rows(
        destination.row0, destination.row1, destination.row2, destination.row3, const_cast<float*>(source.transform4x4)
      );
      destination.lane31 = source.streamFlag50;
      destination.lane33 = (source.streamBoolA4 != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
      destination.lane3C = source.streamScalarA8;
      destination.lane40 = source.streamScalarAC;
      destination.lane32 = source.streamFlagB0;
      destination.lane38 = source.streamScalarB4;
      destination.lane48 = source.streamScalar04;
      return;
    }

    auto& destination = *reinterpret_cast<HardwareVertexPackedStream0Runtime*>(destinationVertex);
    destination.lane44 = source.streamColor51;
    destination.lane45 = source.streamColor52;
    destination.lane46 = source.streamColor53;
    destination.lane47 = source.streamColor54;
    destination.lane00 = source.streamVec58[0];
    destination.lane04 = source.streamVec58[1];
    destination.lane08 = source.streamVec58[2];
    destination.lane0C = 1.0f;
    destination.lane10 = source.streamVec70[0];
    destination.lane14 = source.streamVec70[1];
    destination.lane18 = source.streamVec70[2];
    destination.lane28 = source.streamVec7C[0];
    destination.lane2C = source.streamVec7C[1];
    destination.lane30 = source.streamVec7C[2];
    destination.lane1C = source.streamVec88[0];
    destination.lane20 = source.streamVec88[1];
    destination.lane24 = source.streamVec88[2];
    destination.lane34 = source.streamScalar94;
    destination.lane38 = source.streamScalar98;
    destination.lane3C = source.streamScalar9C;
    destination.lane40 = source.streamScalarA0;
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
   *
   * What it does:
   * Runs the non-deleting teardown body and restores the base
   * `MeshFormatter` vtable lane.
   */
  Float16HardwareVertexFormatterD3D10::~Float16HardwareVertexFormatterD3D10() = default;

  /**
   * Address: 0x00C09640 (FUN_00C09640, ??1Float16HardwareVertexFormatterD3D10@gal@gpg@@QAE@@Z)
   *
   * What it does:
   * Preserves one startup-registered shutdown thunk lane by constructing one
   * typed adapter object and forwarding teardown into
   * `Float16HardwareVertexFormatterD3D10::~Float16HardwareVertexFormatterD3D10`
   * (`FUN_0094D780`).
   */
  void ShutdownFloat16HardwareVertexFormatterD3D10Adapter()
  {
    alignas(Float16HardwareVertexFormatterD3D10)
      unsigned char formatterStorage[sizeof(Float16HardwareVertexFormatterD3D10)]{};
    auto* const formatter = new (static_cast<void*>(formatterStorage)) Float16HardwareVertexFormatterD3D10();
    formatter->~Float16HardwareVertexFormatterD3D10();
  }

  namespace
  {
    HardwareVertexFormatterD3D10 gHardwareVertexFormatterD3D10;
    Float16HardwareVertexFormatterD3D10 gFloat16HardwareVertexFormatterD3D10;
  } // namespace

  /**
   * Address: 0x00BE9B40 (FUN_00BE9B40, register_HardwareVertexFormatterD3D10)
   *
   * What it does:
   * Constructs the process-wide D3D10 hardware-vertex formatter instance and
   * installs its exit-time teardown (ShutdownHardwareVertexFormatterD3D10Adapter,
   * matching the same "typed adapter" teardown lane its D3D9 sibling and this
   * class's own destructor already model).
   */
  void register_HardwareVertexFormatterD3D10()
  {
    (void)gHardwareVertexFormatterD3D10;
    (void)std::atexit(&ShutdownHardwareVertexFormatterD3D10Adapter);
  }

  /**
   * Address: 0x00BE9B60 (FUN_00BE9B60, register_Float16HardwareVertexFormatterD3D10)
   *
   * What it does:
   * Constructs the process-wide D3D10 float16 hardware-vertex formatter
   * instance and installs its exit-time teardown
   * (ShutdownFloat16HardwareVertexFormatterD3D10Adapter).
   */
  void register_Float16HardwareVertexFormatterD3D10()
  {
    (void)gFloat16HardwareVertexFormatterD3D10;
    (void)std::atexit(&ShutdownFloat16HardwareVertexFormatterD3D10Adapter);
  }

  namespace
  {
    struct D3D10HardwareVertexFormatterBootstrap
    {
      D3D10HardwareVertexFormatterBootstrap()
      {
        register_HardwareVertexFormatterD3D10();
        register_Float16HardwareVertexFormatterD3D10();
      }
    };

    [[maybe_unused]] D3D10HardwareVertexFormatterBootstrap gD3D10HardwareVertexFormatterBootstrap;
  } // namespace

  /**
   * Address: 0x0094D910 (FUN_0094D910)
   *
   * What it does:
   * Owns the scalar-deleting destroy thunk for float16 formatter wrappers.
   */
  MeshFormatter* Float16HardwareVertexFormatterD3D10::Destroy(const std::uint8_t deleteFlags)
  {
    this->~Float16HardwareVertexFormatterD3D10();
    auto* const formatter = static_cast<MeshFormatter*>(this);
    if ((deleteFlags & 1U) != 0U) {
      ::operator delete(formatter);
    }

    return formatter;
  }

  /**
   * Address: 0x0094D790 (FUN_0094D790)
   *
   * What it does:
   * Reports whether float16 mesh instancing is enabled by both device-context
   * capability flags (`+0x11` and `+0x12`).
   */
  bool Float16HardwareVertexFormatterD3D10::AllowMeshInstancing()
  {
    Device* const device = Device::GetInstance();
    const DeviceContext* const context = reinterpret_cast<DeviceD3D10*>(device)->GetDeviceContext();
    return context->mHWBasedInstancing && context->mSupportsFloat16;
  }

  /**
   * Address: 0x0094D930 (FUN_0094D930)
   *
   * What it does:
   * Selects float16 vertex-format token `15` and returns the input stream token.
   */
  std::uintptr_t Float16HardwareVertexFormatterD3D10::SelectVertexFormatToken(
    const std::uintptr_t streamToken,
    const std::int32_t layoutVariant
  )
  {
    static_cast<void>(layoutVariant);
    Device* const device = Device::GetInstance();
    InvokeDeviceCreateVertexFormat(device, reinterpret_cast<void*>(streamToken), static_cast<int>(kFloat16VertexFormatToken));
    return streamToken;
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
   * Packs one source vertex into the runtime float16 stream-1 layout.
   */
  void Float16HardwareVertexFormatterD3D10::WriteFormattedVertex(
    const std::int32_t streamClass,
    void* const destinationVertex,
    const void* const sourceVertex,
    const std::int32_t writeVariant
  )
  {
    static_cast<void>(streamClass);
    static_cast<void>(writeVariant);

    const auto& source = *reinterpret_cast<const SourceMeshVertexRuntime*>(sourceVertex);
    auto& destination = *reinterpret_cast<Float16VertexPackedStream1Runtime*>(destinationVertex);
    destination.lane30 = source.streamClassFlag;
    destination.lane3C = source.streamPacked08;
    ConvertFloat32To16Array(&destination.lane34, &source.streamScalar0C, 1U);
    CopyMatrix4x3Rows(
      destination.row0, destination.row1, destination.row2, destination.row3, const_cast<float*>(source.transform4x4)
    );
    destination.lane31 = source.streamFlag50;
    destination.lane33 = (source.streamBoolA4 != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
    ConvertFloat32To16Array(&destination.lane3A, &source.streamScalarAC, 1U);
    ConvertFloat32To16Array(&destination.lane38, &source.streamScalarA8, 1U);
    destination.lane32 = source.streamFlagB0;
    ConvertFloat32To16Array(&destination.lane36, &source.streamScalarB4, 1U);
    destination.lane40 = source.streamScalar04;
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
    void* const renderTexture, void* const renderTargetView, void* const shaderResourceView
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
    void* const renderTexture,
    void* const renderTargetView,
    void* const shaderResourceView
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
    void* const renderTexture, void* const renderTargetView, void* const shaderResourceView
  )
  {
    DestroyState();

    D3D10_TEXTURE2D_DESC textureDesc{};
    InvokeTextureGetDesc(renderTexture, &textureDesc);
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
  void* RenderTargetD3D10::GetRenderTextureOrThrow()
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
    ReleaseComLike(renderTexture_);
    ReleaseComLike(renderTargetView_);
    ReleaseComLike(shaderResourceView_);

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
  void* RenderTargetD3D10::GetRenderTargetViewOrThrow()
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
  void* RenderTargetD3D10::GetShaderResourceViewOrThrow()
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
    void* const depthStencilTexture,
    void* const depthStencilView,
    void* const shaderResourceView
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
    ReleaseComLike(depthStencilTexture_);
    ReleaseComLike(depthStencilView_);

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
  void* DepthStencilTargetD3D10::GetDepthStencilTextureOrThrow()
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
  void* DepthStencilTargetD3D10::GetDepthStencilViewOrThrow()
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
  void* DepthStencilTargetD3D10::GetShaderResourceViewOrThrow()
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
  TextureD3D10::TextureD3D10(const TextureContext* const context, void* const texture, void* const shaderResourceView)
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

    void* const lockedTexture = texture_;

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

    unsigned int mapMode = 4U;
    void* mapTexture = lockedTexture;
    if (((flags & 1) == 0) && ((flags & 2) != 0)) {
      mapMode = 1U;

      D3D10_TEXTURE2D_DESC textureDesc{};
      InvokeTextureGetDesc(lockedTexture, &textureDesc);
      if ((textureDesc.CPUAccessFlags & 0x20000U) == 0U) {
        Device* const device = Device::GetInstance();
        stagingTexture_ = CreateStagingTextureCopyOrThrow(device, lockedTexture);
        mapTexture = stagingTexture_;
      }
    }

    D3D10_MAPPED_TEXTURE2D mapped{};
    const HRESULT mapResult = InvokeTextureMap(mapTexture, level, mapMode, &mapped);
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
      InvokeTextureUnmap(stagingTexture_, level);
    } else {
      InvokeTextureUnmap(texture_, level);
    }

    const int releaseResult = ReleaseComLikeWithResult(stagingTexture_);
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

    void* const texture = texture_;

    Device* const device = Device::GetInstance();

    void* helper34Object = nullptr;
    HRESULT result = InvokeDeviceHelper34(device, 0, &helper34Object);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 177, result);
    }

    void* readbackObject = nullptr;
    result = InvokeDeviceHelper44(device, texture, 4, &readbackObject);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 178, result);
    }

    const unsigned int readbackSize = static_cast<unsigned int>(GetReadbackSize(readbackObject));
    if (outBuffer->Size() != readbackSize) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(readbackSize);
      *outBuffer = resizedBuffer;
    }

    void* const sourceBytes = GetReadbackData(readbackObject);
    char* const destinationBytes = outBuffer->GetPtr(0U, 0U);
    std::memcpy(destinationBytes, sourceBytes, readbackSize);

    ReleaseComLike(helper34Object);
  }

  /**
   * Address: 0x00903BE0 (FUN_00903BE0)
   *
   * What it does:
   * Validates and returns the retained texture lane.
   */
  void* TextureD3D10::GetTextureOrThrow()
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
  void* TextureD3D10::GetShaderResourceViewOrThrow()
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

    ReleaseComLike(texture_);
    ReleaseComLike(shaderResourceView_);

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
    const TextureContext* const context, void* const texture, void* const shaderResourceView
  )
  {
    DestroyState();
    context_.AssignFrom(*context);
    shaderResourceView_ = shaderResourceView;
    texture_ = texture;

    D3D10_TEXTURE2D_DESC textureDesc{};
    InvokeTextureGetDesc(texture_, &textureDesc);
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
    void* const nativeDevice,
    void* const nativeBuffer,
    void* const stagingBuffer
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
    AddRefComLike(nativeDevice_);
  }

  /**
   * Address: 0x00901D40 (FUN_00901D40)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_00901C90`.
   */
  IndexBufferD3D10::~IndexBufferD3D10()
  {
    DestroyIndexBufferD3D10Body(this);
  }

  /**
   * Address: 0x00901BE0 (FUN_00901BE0)
   *
   * What it does:
   * Returns the embedded index-buffer context lane at `this+0x04`.
   */
  IndexBufferContext* IndexBufferD3D10::GetContextBuffer()
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
  IndexBufferD3D10::Lock(const std::uint32_t offset, const std::uint32_t size, const unsigned int lockFlags)
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

    unsigned int mapMode = ((lockFlags * 2U) | (lockFlags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    auto** const vtable = *reinterpret_cast<void***>(stagingBuffer_);
    auto* const map = reinterpret_cast<HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void**)>(vtable[10]);
    const HRESULT result = map(stagingBuffer_, mapMode, 0U, &mappedData_);
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
  int IndexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("IndexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    auto** const stagingVtable = *reinterpret_cast<void***>(stagingBuffer_);
    auto* const unmap = reinterpret_cast<void(__stdcall*)(void*)>(stagingVtable[11]);
    unmap(stagingBuffer_);

    auto** const nativeDeviceVtable = *reinterpret_cast<void***>(nativeDevice_);
    auto* const copySubresourceRegion =
      reinterpret_cast<device_native_copy_subresource_region_fn>(nativeDeviceVtable[32]);
    const int result = copySubresourceRegion(nativeDevice_, nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
    return result;
  }

  /**
   * Address: 0x00901C10 (FUN_00901C10)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void IndexBufferD3D10::DestroyState()
  {
    ReleaseComLike(nativeBuffer_);
    ReleaseComLike(stagingBuffer_);
    ReleaseComLike(nativeDevice_);
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
  void* IndexBufferD3D10::GetNativeBufferOrThrow()
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
    void* const nativeDevice,
    void* const nativeBuffer,
    void* const stagingBuffer
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
    AddRefComLike(nativeDevice_);
  }

  /**
   * Address: 0x0094DB30 (FUN_0094DB30)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_0094DA80`.
   */
  VertexBufferD3D10::~VertexBufferD3D10()
  {
    DestroyVertexBufferD3D10Body(this);
  }

  /**
   * Address: 0x0094D9F0 (FUN_0094D9F0)
   *
   * What it does:
   * Returns the embedded vertex-buffer context lane at `this+0x04`.
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
  void* VertexBufferD3D10::Lock(const std::uint32_t offset, const std::uint32_t size, const unsigned int lockFlags)
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

    unsigned int mapMode = ((lockFlags * 2U) | (lockFlags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    auto** const vtable = *reinterpret_cast<void***>(stagingBuffer_);
    auto* const map = reinterpret_cast<HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void**)>(vtable[10]);
    const HRESULT result = map(stagingBuffer_, mapMode, 0U, &mappedData_);
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
  int VertexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("VertexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    auto** const stagingVtable = *reinterpret_cast<void***>(stagingBuffer_);
    auto* const unmap = reinterpret_cast<void(__stdcall*)(void*)>(stagingVtable[11]);
    unmap(stagingBuffer_);

    auto** const nativeDeviceVtable = *reinterpret_cast<void***>(nativeDevice_);
    auto* const copySubresourceRegion =
      reinterpret_cast<device_native_copy_subresource_region_fn>(nativeDeviceVtable[32]);
    const int result = copySubresourceRegion(nativeDevice_, nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
    return result;
  }

  /**
   * Address: 0x0094DA00 (FUN_0094DA00)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void VertexBufferD3D10::DestroyState()
  {
    ReleaseComLike(nativeBuffer_);
    ReleaseComLike(stagingBuffer_);
    ReleaseComLike(nativeDevice_);
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
  void* VertexBufferD3D10::GetNativeBufferOrThrow()
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
    : cursorHandle_(nullptr)
    , iconHandle_(nullptr)
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

    const auto retainedCursorHandle = cursor->cursorHandle_;
    ::new (static_cast<void*>(cursor)) CursorD3D10();
    cursor->cursorHandle_ = retainedCursorHandle;
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
    ::SetCursor(reinterpret_cast<HCURSOR>(cursorHandle_));
    if (iconHandle_ != nullptr) {
      ::DestroyIcon(reinterpret_cast<HICON>(iconHandle_));
    }

    cursorHandle_ = nullptr;
    iconHandle_ = nullptr;
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
  void* CursorD3D10::SetCursor(const CursorContext* const context)
  {
    Destroy();

    iconHandle_ = BuildCursorIcon(context->hotspotX_, context->hotspotY_, context->texture_);
    cursorHandle_ = ::SetCursor(reinterpret_cast<HCURSOR>(iconHandle_));
    return cursorHandle_;
  }

  /**
   * Address: 0x008F8430 (FUN_008F8430)
   *
   * What it does:
   * Validates icon initialization state and applies the retained icon as
   * current native cursor.
   */
  void* CursorD3D10::InitCursor()
  {
    if (iconHandle_ == nullptr) {
      ThrowGalError("CursorD3D10.cpp", 70, "attempt to use uninitialized cursor");
    }

    return ::SetCursor(reinterpret_cast<HCURSOR>(iconHandle_));
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
    if (iconHandle_ == nullptr) {
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
   * Address: 0x009005E0 (FUN_009005E0)
   *
   * What it does:
   * Owns the deleting-destructor thunk path for D3D10 backend instances.
   */
  void DeviceD3D10::DestroyBackendObject()
  {
    DestroyDeviceD3D10Body(this);
    ::operator delete(static_cast<void*>(this));
  }

  /**
   * Address family:
   * - slot 37 runtime dispatch from `Device` surface
   *
   * What it does:
   * Preserves the unresolved no-argument context-export slot.
   */
  void DeviceD3D10::GetContext() {}

  /**
   * Address: 0x008FE5D0 (FUN_008FE5D0)
   *
   * What it does:
   * Installs the vtable, builds the output context at +0x04, zeroes the
   * module, export and COM lanes, builds the embedded `DeviceContext(0)` at
   * +0x60 and the cursor at +0x11C. Every one of those is a member
   * initializer on the class, so the body is empty: this used to be a free
   * factory that `new`ed an overlay and then reset each member by hand.
   */
  DeviceD3D10::DeviceD3D10() = default;

  /**
   * Address context: 0x008E6B60 (func_CreateDeviceD3D)
   *
   * What it does:
   * The D3D10 arm of the device factory: `push 0x128; call operator new`
   * then the constructor above.
   *
   * The cast is the one piece of this left unrecovered. The binary's
   * constructor installs `Device`'s vtable (0x00D42224) before its own, so
   * `DeviceD3D10` derives from `gpg::gal::Device`; ours does not yet, because
   * the two classes' virtual lists do not line up slot for slot and have to
   * be reconciled against both vtables first.
   */
  Device* CreateDeviceD3D10Backend()
  {
    return reinterpret_cast<Device*>(new DeviceD3D10());
  }

  /**
   * Address context: 0x008E6B60 (func_CreateDeviceD3D)
   *
   * What it does:
   * Copies startup device-context payload into recovered D3D10 backend context
   * lanes, records current thread ownership, and runs the backend startup
   * chain.
   *
   * The startup call is not optional decoration: `func_CreateDeviceD3D`
   * publishes the new backend into the `sDeviceD3D` singleton
   * (`mov sDeviceD3D, esi` at 0x008E6C78) and immediately calls
   * `gpg::gal::DeviceD3D10::Setup(context)` at 0x008E6C7E with the requested
   * `DeviceContext` in edi. Without it the whole D3D10 bring-up chain —
   * `SetupDXGIDevice` -> `AdapterD3D10::ProbeOutputsAndModes` -> the adapter
   * and display-mode append lanes — is never entered.
   */
  void InitializeDeviceD3D10Backend(Device* const device, DeviceContext* const context)
  {
    if ((device == nullptr) || (context == nullptr)) {
      return;
    }

    auto* const deviceD3D10 = reinterpret_cast<DeviceD3D10*>(device);
    deviceD3D10->mCurThreadId = static_cast<int>(::GetCurrentThreadId());
    deviceD3D10->mDeviceContext = *context;

    deviceD3D10->Setup(context);
  }

  /**
   * Address: 0x008F86B0 (FUN_008F86B0)
   *
   * What it does:
   * Returns the address of the retained device log-storage lane at `this+0x50`.
   */
  void* DeviceD3D10::GetLog()
  {
    return GetDeviceLogStorage(this);
  }

  /**
   * Address: 0x008F86C0 (FUN_008F86C0)
   *
   * What it does:
   * Returns the retained device-context pointer lane at `this+0x60`.
   */
  DeviceContext* DeviceD3D10::GetDeviceContext()
  {
    return GetDeviceContextLane(this);
  }

  /**
   * Address: 0x008F86D0 (FUN_008F86D0)
   *
   * What it does:
   * Returns the current thread-id snapshot lane from `this+0x4C`.
   */
  int DeviceD3D10::GetCurThreadId()
  {
    return GetDeviceCurrentThreadId(this);
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
  void DeviceD3D10::GetModesForAdapter(const int arg1, const int arg2)
  {
    static_cast<void>(arg1);
    static_cast<void>(arg2);
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
      0x800U,
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
    ReleaseComLike(mRttQuadVertexBuffer);
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

    ReleaseComLike(mRttInputLayout);
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
      const HRESULT getBufferResult = swapChain->GetBuffer(0U, IID_ID3D10Texture2D, reinterpret_cast<void**>(&backBuffer));
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

    // `CreateDXGIFactory` returns through `void**` in the SDK itself.
    const HRESULT createFactoryResult = mCreateDXGIFactory(IID_IDXGIFactory, reinterpret_cast<void**>(&mDXGIFactory));
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
      29U,
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
      const HRESULT createSwapChainResult = dxgiFactory->CreateSwapChain(
        reinterpret_cast<IUnknown*>(mDevice),
        &swapChainDesc,
        &swapChain
      );
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
      0x800U,
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

    std::memset(mVertexStreams, 0, sizeof(mVertexStreams));
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
   * boost::shared_ptr<gpg::gal::PipelineStateD3D10> *
   *
   * What it does:
   * Copies the retained pipeline-state shared-handle lane (`this+0xB4/+0xB8`)
   * into caller output and increments the control-block use count when present.
   */
  boost::shared_ptr<PipelineStateD3D10>*
  DeviceD3D10::GetPipelineState(boost::shared_ptr<PipelineStateD3D10>* const outPipelineState)
  {
    *outPipelineState = mPipelineState;
    return outPipelineState;
  }

  /**
   * Address: 0x008FEA00 (FUN_008FEA00)
   *
   * boost::shared_ptr<EffectD3D10> *,EffectContext *
   *
   * What it does:
   * Copy-constructs one local `EffectContext`, injects 20 D3D10-specific
   * effect-macro pairs via `EffectContext::DefineMacro` (which throws
   * `gpg::gal::Error` on a duplicate key), compiles the shader source
   * from the local context's macro lane, and returns a wrapped D3D10
   * effect handle.
   */
  boost::shared_ptr<EffectD3D10>*
  DeviceD3D10::CreateEffect(boost::shared_ptr<EffectD3D10>* const outEffect, EffectContext* const context)
  {
    // The binary allocates `EffectContext v27` on its own stack and
    // copy-constructs from the inbound argument. The public class
    // currently declares `sizeof(EffectContext) == 0x4`, so the actual
    // 0x64-byte payload is reserved via aligned storage (matching the
    // same workaround used by `EffectD3D10::context_`).
    struct ScopedLocalEffectContext final
    {
      using Storage = std::aligned_storage_t<0x64, alignof(void*)>;

      ~ScopedLocalEffectContext()
      {
        if (context != nullptr) {
          context->~EffectContext();
          context = nullptr;
        }
      }

      Storage storage{};
      EffectContext* context = nullptr;
    };

    ScopedLocalEffectContext localContextScope{};
    localContextScope.context =
      ::new (static_cast<void*>(&localContextScope.storage)) EffectContext(*context);
    EffectContext* const localContext = localContextScope.context;

    for (std::size_t i = 0U; i < kDeviceCreateEffectInjectedMacroCount; ++i) {
      localContext->DefineMacro(
        kDeviceCreateEffectInjectedMacros[i].key,
        kDeviceCreateEffectInjectedMacros[i].value
      );
    }

    // Per binary order: macro lane comes from the modified local copy,
    // but every other context lane (sourceType, sourcePath, source-byte
    // window) is read from the inbound caller-owned context — the local
    // copy is consumed for DefineMacro side effects only.
    const std::size_t totalMacroCount = localContext->mMacros.size();
    D3D10_SHADER_MACRO* defines = nullptr;
    if (totalMacroCount != 0U) {
      defines = new D3D10_SHADER_MACRO[totalMacroCount + 1U];

      std::size_t writeIndex = 0U;
      for (const EffectMacro& macro : localContext->mMacros) {
        defines[writeIndex].Name = macro.keyText_.c_str();
        defines[writeIndex].Definition = macro.valueText_.c_str();
        ++writeIndex;
      }

      defines[writeIndex].Name = nullptr;
      defines[writeIndex].Definition = nullptr;
    }

    if (context->mSourceType != 2U) {
      delete[] defines;
      ThrowGalError("DeviceD3D10.cpp", 818, "invalid source defined for effect");
    }

    const char* const sourceBegin = context->mSourceBuffer.mBegin;
    const char* const sourceEnd = context->mSourceBuffer.mEnd;
    const void* const sourceData = sourceBegin;
    const std::uint32_t sourceBytes =
      (sourceEnd >= sourceBegin) ? static_cast<std::uint32_t>(sourceEnd - sourceBegin) : 0U;

    ID3D10Effect* dxEffect = nullptr;
    void* errorBlob = nullptr;
    const HRESULT result =
      InvokeCreateEffectFromMemoryApi(this, sourceData, sourceBytes, defines, &dxEffect, &errorBlob);
    delete[] defines;

    msvc8::string reason("unknown error");
    if ((result < 0) && (errorBlob != nullptr)) {
      const char* const errorText = reinterpret_cast<const char*>(GetReadbackData(errorBlob));
      reason.assign_owned((errorText != nullptr) ? errorText : "unknown error");
    }

    ReleaseComLike(errorBlob);

    if (result < 0) {
      msvc8::string message("unable to create effect: ");
      message = message + context->mSourcePath;
      message = message + " reason: ";
      message = message + reason;
      ThrowGalError("DeviceD3D10.cpp", 828, message.c_str());
    }

    outEffect->reset(new EffectD3D10(context, dxEffect));
    return outEffect;
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
    void* nativeTexture = nullptr;
    void* shaderResourceView = nullptr;

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

      const HRESULT createTextureResult = InvokeNativeCreateTexture2D(this, &textureDesc, &nativeTexture);
      if (createTextureResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 886, createTextureResult);
      }
    } else {
      if (context->dataEnd_ == context->dataBegin_) {
        ThrowGalError("DeviceD3D10.cpp", 855, "attempt to create texture from uninitialized memory");
      }

      void* textureResource = nullptr;
      const auto* const sourceData = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(context->dataBegin_));
      const std::uint32_t sourceBytes = context->dataEnd_ - context->dataBegin_;
      const HRESULT createFromMemoryResult =
        InvokeCreateTextureFromMemoryApi(this, sourceData, sourceBytes, nullptr, &textureResource);
      if (createFromMemoryResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 857, createFromMemoryResult);
      }

      if (textureResource != nullptr) {
        static_cast<void>(QueryInterfaceTexture2D(textureResource, &nativeTexture));
        ReleaseComLike(textureResource);
      }
    }

    if (nativeTexture != nullptr) {
      D3D10_TEXTURE2D_DESC textureDesc{};
      InvokeTextureGetDesc(nativeTexture, &textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = DXGI_FORMAT_UNKNOWN;
      shaderResourceViewDesc.ViewDimension =
        (textureDesc.MiscFlags != 4U) ? D3D10_SRV_DIMENSION_TEXTURE2D : D3D10_SRV_DIMENSION_TEXTURECUBE;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

      const HRESULT createSrvResult =
        InvokeNativeCreateShaderResourceView(this, nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
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

    void* nativeTexture = nullptr;
    const HRESULT createTextureResult = InvokeNativeCreateTexture2D(this, &textureDesc, &nativeTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 941, createTextureResult);
    }

    void* renderTargetView = nullptr;
    const HRESULT createRtvResult = InvokeNativeCreateRenderTargetView(this, nativeTexture, nullptr, &renderTargetView);
    if (createRtvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 945, createRtvResult);
    }

    D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
    shaderResourceViewDesc.Format = textureDesc.Format;
    shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
    shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
    shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

    void* shaderResourceView = nullptr;
    const HRESULT createSrvResult =
      InvokeNativeCreateShaderResourceView(this, nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
    if (createSrvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 954, createSrvResult);
    }

    D3D10_VIEWPORT viewport{};
    viewport.Width = context->width_;
    viewport.Height = context->height_;
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;
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

    void* depthTexture = nullptr;
    const HRESULT createTextureResult = InvokeNativeCreateTexture2D(this, &textureDesc, &depthTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 993, createTextureResult);
    }

    D3D10_DEPTH_STENCIL_VIEW_DESC depthStencilViewDesc{};
    depthStencilViewDesc.Format = depthFormat;
    depthStencilViewDesc.ViewDimension = D3D10_DSV_DIMENSION_TEXTURE2D;
    depthStencilViewDesc.Texture2D.MipSlice = 0U;

    void* depthStencilView = nullptr;
    const HRESULT createDsvResult =
      InvokeNativeCreateDepthStencilView(this, depthTexture, &depthStencilViewDesc, &depthStencilView);
    if (createDsvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1001, createDsvResult);
    }

    void* shaderResourceView = nullptr;
    if (context->field0x10_) {
      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = depthFormat;
      shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = 1U;

      const HRESULT createSrvResult =
        InvokeNativeCreateShaderResourceView(this, depthTexture, &shaderResourceViewDesc, &shaderResourceView);
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
   * boost::shared_ptr<VertexFormatD3D10> *,std::uint32_t
   *
   * What it does:
   * Builds one input-layout declaration for the requested format token.
   */
  boost::shared_ptr<VertexFormatD3D10>* DeviceD3D10::CreateVertexFormat(
    boost::shared_ptr<VertexFormatD3D10>* const outVertexFormat, const std::uint32_t formatToken
  )
  {
    const D3D10_INPUT_ELEMENT_DESC* const elements = GetVertexLayoutElementsOrThrow(formatToken);
    const std::uint32_t elementCount = GetVertexLayoutElementCountOrThrow(formatToken);

    D3D10_PASS_DESC passDesc{};
    GetVertexInputSignatureOrThrow(this, static_cast<int>(formatToken), &passDesc);

    void* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = InvokeNativeCreateInputLayout(
      this, elements, elementCount, passDesc.pIAInputSignature, passDesc.IAInputSignatureSize, &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1029, createInputLayoutResult);
    }

    return ConstructSharedVertexFormatD3D10FromRaw(outVertexFormat, new VertexFormatD3D10(formatToken, inputLayout));
  }

  /**
   * Address: 0x008FB8D0 (FUN_008FB8D0)
   *
   * boost::shared_ptr<VertexBufferD3D10> *,VertexBufferContext const *
   *
   * What it does:
   * Creates one GPU vertex buffer plus staging/upload lanes from caller context.
   */
  boost::shared_ptr<VertexBufferD3D10>* DeviceD3D10::CreateVertexBuffer(
    boost::shared_ptr<VertexBufferD3D10>* const outVertexBuffer, const VertexBufferContext* const context
  )
  {
    const std::uint32_t byteWidth = context->vertexCount_ * context->stride_;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->usage_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 1U;
    gpuBufferDesc.CPUAccessFlags = (context->usage_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    void* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = InvokeNativeCreateBuffer(this, &gpuBufferDesc, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1049, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    void* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = InvokeNativeCreateBuffer(this, &stagingBufferDesc, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1056, createStagingBufferResult);
    }

    return ConstructSharedVertexBufferD3D10FromRaw(
      outVertexBuffer,
      new VertexBufferD3D10(context, GetDeviceNativeHandle(this), gpuBuffer, stagingBuffer)
    );
  }

  /**
   * Address: 0x008FBB60 (FUN_008FBB60)
   *
   * boost::shared_ptr<IndexBufferD3D10> *,IndexBufferContext const *
   *
   * What it does:
   * Creates one GPU index buffer plus staging/upload lanes from caller context.
   */
  boost::shared_ptr<IndexBufferD3D10>* DeviceD3D10::CreateIndexBuffer(
    boost::shared_ptr<IndexBufferD3D10>* const outIndexBuffer, const IndexBufferContext* const context
  )
  {
    const std::uint32_t bytesPerIndex = (context->format_ == 1U) ? 2U : 4U;
    const std::uint32_t byteWidth = context->size_ * bytesPerIndex;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->type_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 2U;
    gpuBufferDesc.CPUAccessFlags = (context->type_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    void* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = InvokeNativeCreateBuffer(this, &gpuBufferDesc, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1076, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    void* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = InvokeNativeCreateBuffer(this, &stagingBufferDesc, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1083, createStagingBufferResult);
    }

    return ConstructSharedIndexBufferD3D10FromRaw(
      outIndexBuffer,
      new IndexBufferD3D10(context, GetDeviceNativeHandle(this), gpuBuffer, stagingBuffer)
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

    void* const sourceResource = static_cast<RenderTargetD3D10*>(source.get())->GetRenderTextureOrThrow();
    void* const destinationResource = static_cast<TextureD3D10*>(destination.get())->GetTextureOrThrow();
    static_cast<void>(InvokeNativeCopyResourceResult(this, destinationResource, sourceResource));
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

      void* const sourceResource = sourceTarget->GetRenderTextureOrThrow();
      void* const destinationResource = destinationTarget->GetRenderTextureOrThrow();
      InvokeNativeCopySubresourceRegion(
        this, destinationResource, destinationX, destinationY, sourceResource, sourceBoxPtr
      );
      return;
    }

    void* const sourceShaderResourceView = sourceTarget->GetShaderResourceViewOrThrow();
    void* const destinationRenderTargetView = destinationTarget->GetRenderTargetViewOrThrow();
    static_cast<void>(StretchRectFallbackBlit(
      this,
      destinationContext->width_,
      destinationContext->height_,
      destinationRenderTargetView,
      sourceShaderResourceView
    ));
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

      void* const sourceResource = sourceTexture->GetTextureOrThrow();
      void* const destinationResource = destinationTexture->GetTextureOrThrow();
      InvokeNativeCopySubresourceRegion(
        this, destinationResource, destinationX, destinationY, sourceResource, sourceBoxPtr
      );
      return;
    }

    void* createBlobScratch = nullptr;
    HRESULT result = InvokeCreateBlobApi(this, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1109, result);
    }

    void* encodedTextureBlob = nullptr;
    result = InvokeSaveTextureToMemoryApi(this, sourceTexture->GetTextureOrThrow(), 4, &encodedTextureBlob);
    if (result < 0) {
      ReleaseComLike(createBlobScratch);
      ThrowDeviceD3D10Hresult(1112, result);
    }

    std::int32_t loadInfo[14];
    static_cast<void>(InitializeTextureLoadInfoDefaults(loadInfo));
    loadInfo[13] = -1;
    loadInfo[4] = 1;
    loadInfo[9] = 77;
    loadInfo[12] = 0;

    void* recreatedTexture = nullptr;
    if (encodedTextureBlob != nullptr) {
      result = InvokeCreateTextureFromMemoryApi(
        this,
        GetReadbackData(encodedTextureBlob),
        static_cast<std::uint32_t>(GetReadbackSize(encodedTextureBlob)),
        loadInfo,
        &recreatedTexture
      );
      if (result < 0) {
        ReleaseComLike(encodedTextureBlob);
        ReleaseComLike(createBlobScratch);
        ThrowDeviceD3D10Hresult(1130, result);
      }
    }

    if (recreatedTexture != nullptr) {
      InvokeNativeCopyResourceResult(this, destinationTexture->GetTextureOrThrow(), recreatedTexture);
    }

    if (encodedTextureBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    ReleaseComLike(recreatedTexture);
    ReleaseComLike(encodedTextureBlob);
    ReleaseComLike(createBlobScratch);
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
    const HRESULT result =
      InvokeSaveTextureToFileApi(this, target->GetRenderTextureOrThrow(), imageFileFormat, filePath.c_str());
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
      const HRESULT result =
        InvokeSaveTextureToFileApi(this, sourceTexture->GetTextureOrThrow(), imageFileFormat, filePath.c_str());
      if (result < 0) {
        ThrowDeviceD3D10Hresult(1275, result);
      }
      return;
    }

    void* createBlobScratch = nullptr;
    HRESULT result = InvokeCreateBlobApi(this, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1259, result);
    }

    void* readbackBlob = nullptr;
    result = InvokeSaveTextureToMemoryApi(this, sourceTexture->GetTextureOrThrow(), imageFileFormat, &readbackBlob);
    if (result >= 0) {
      const std::size_t readbackBytes = static_cast<std::size_t>(GetReadbackSize(readbackBlob));
      if (outBuffer->Size() != readbackBytes) {
        gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(readbackBytes);
        *outBuffer = resizedBuffer;
      }

      std::memcpy(outBuffer->GetPtr(0U, 0U), GetReadbackData(readbackBlob), readbackBytes);
    }

    if (readbackBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    ReleaseComLike(readbackBlob);
    ReleaseComLike(createBlobScratch);

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

    std::int32_t loadInfo[14];
    static_cast<void>(InitializeTextureLoadInfoDefaults(loadInfo));
    loadInfo[13] = -1;
    loadInfo[4] = 1;
    loadInfo[9] = 77;
    loadInfo[12] = 0;

    void* decodedResource = nullptr;
    HRESULT result = InvokeCreateTextureFromMemoryApi(this, sourceData, sourceBytes, loadInfo, &decodedResource);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1317, result);
    }

    if (decodedResource == nullptr) {
      return;
    }

    void* sourceTexture = nullptr;
    {
      auto** const resourceVtable = *reinterpret_cast<void***>(decodedResource);
      using query_interface_fn = HRESULT(__stdcall*)(void*, const IID*, void**);
      auto* const queryInterface = reinterpret_cast<query_interface_fn>(resourceVtable[0]);
      queryInterface(decodedResource, &IID_ID3D10Texture2D, &sourceTexture);
    }

    if (sourceTexture == nullptr) {
      sourceTexture = decodedResource;
      AddRefComLike(sourceTexture);
    }

    D3D10_TEXTURE2D_DESC textureDesc{};
    InvokeTextureGetDesc(sourceTexture, &textureDesc);
    *outWidth = textureDesc.Width;
    *outHeight = static_cast<int>(textureDesc.Height);

    textureDesc.Usage = D3D10_USAGE_STAGING;
    textureDesc.BindFlags = 0U;
    textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

    void* stagingTexture = nullptr;
    {
      void* const nativeDevice = GetDeviceNativeHandle(this);
      auto** const nativeVtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const createTexture2D = reinterpret_cast<device_native_create_texture2d_fn>(nativeVtable[73]);
      result = createTexture2D(nativeDevice, &textureDesc, nullptr, &stagingTexture);
      if (result < 0) {
        ReleaseComLike(sourceTexture);
        ReleaseComLike(decodedResource);
        ThrowDeviceD3D10Hresult(1343, result);
      }

      auto* const copyResource = reinterpret_cast<device_native_copy_resource_fn>(nativeVtable[33]);
      copyResource(nativeDevice, stagingTexture, sourceTexture);
    }

    D3D10_MAPPED_TEXTURE2D mappedTexture{};
    result = InvokeTextureMap(stagingTexture, 0, 1U, &mappedTexture);
    if (result < 0) {
      ReleaseComLike(stagingTexture);
      ReleaseComLike(sourceTexture);
      ReleaseComLike(decodedResource);
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

    InvokeTextureUnmap(stagingTexture, 0);
    ReleaseComLike(stagingTexture);
    ReleaseComLike(sourceTexture);
    ReleaseComLike(decodedResource);
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
  void DeviceD3D10::Func8() {}

  /**
   * Address: 0x008F8710 (FUN_008F8710)
   *
   * int
   *
   * What it does:
   * Preserves the binary no-op virtual slot (`retn 4` shape).
   */
  void DeviceD3D10::Func9(const int arg1)
  {
    static_cast<void>(arg1);
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
  void* DeviceD3D10::SetCursor(const CursorContext* const context)
  {
    return GetDeviceCursorLane(this)->SetCursor(context);
  }

  /**
   * Address: 0x008F8770 (FUN_008F8770)
   *
   * What it does:
   * Tail-delegates to retained cursor lane initialization (`CursorD3D10::InitCursor`).
   */
  void* DeviceD3D10::InitCursor()
  {
    return GetDeviceCursorLane(this)->InitCursor();
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
    return GetDeviceCursorLane(this)->ShowCursor(show);
  }

  /**
   * Address: 0x008F8790 (FUN_008F8790)
   *
   * void const *
   *
   * What it does:
   * Copies one caller viewport payload and binds it as the single native D3D10 viewport.
   */
  int DeviceD3D10::SetViewport(const void* const viewport)
  {
    const auto* const sourceViewport = reinterpret_cast<const D3D10_VIEWPORT*>(viewport);
    D3D10_VIEWPORT viewportCopy{};
    viewportCopy.TopLeftX = sourceViewport->TopLeftX;
    viewportCopy.TopLeftY = sourceViewport->TopLeftY;
    viewportCopy.Width = sourceViewport->Width;
    viewportCopy.Height = sourceViewport->Height;
    viewportCopy.MinDepth = sourceViewport->MinDepth;
    viewportCopy.MaxDepth = sourceViewport->MaxDepth;
    return InvokeNativeSetViewport(this, &viewportCopy);
  }

  /**
   * Address: 0x008F87F0 (FUN_008F87F0)
   *
   * void *
   *
   * What it does:
   * Fetches one native viewport payload and copies it back into caller memory.
   */
  void* DeviceD3D10::GetViewport(void* const outViewport)
  {
    unsigned int viewportCount = 1U;
    D3D10_VIEWPORT viewport{};
    InvokeNativeGetViewport(this, &viewportCount, &viewport);

    auto* const destinationViewport = reinterpret_cast<D3D10_VIEWPORT*>(outViewport);
    destinationViewport->TopLeftX = viewport.TopLeftX;
    destinationViewport->TopLeftY = viewport.TopLeftY;
    destinationViewport->Width = viewport.Width;
    destinationViewport->Height = viewport.Height;
    destinationViewport->MinDepth = viewport.MinDepth;
    destinationViewport->MaxDepth = viewport.MaxDepth;
    return outViewport;
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
   * void const *
   *
   * What it does:
   * Validates draw topology token, binds native primitive topology, then dispatches
   * `Draw` vs `DrawInstanced` using the recovered instance-count lane at `this+0xD8`.
   */
  int DeviceD3D10::DrawPrimitive(const void* const context)
  {
    const auto* const drawContext = static_cast<const DrawContext*>(context);
    // D3D10's Draw takes a vertex count; the binary hands it this lane unconverted
    // (`mov edx,[edi+8]` at 0x008FD05D), whatever the D3D9-facing name says.
    if (drawContext->topologyToken_ == 0U) {
      ThrowInvalidTopologyError(1561);
    }

    InvokeNativeSetPrimitiveTopology(this, ResolvePrimitiveTopology(drawContext->topologyToken_));
    const std::uint32_t instanceCount = GetDeviceInstanceCount(this);
    if (instanceCount > 1U) {
      return InvokeNativeDrawInstanced(this, drawContext->primitiveCountInput_, instanceCount, drawContext->startVertex_, 0U);
    }

    return InvokeNativeDraw(this, drawContext->primitiveCountInput_, drawContext->startVertex_);
  }

  /**
   * Address: 0x008FD0A0 (FUN_008FD0A0)
   *
   * void const *
   *
   * What it does:
   * Validates indexed draw topology token, binds native primitive topology, then
   * dispatches `DrawIndexed` vs `DrawIndexedInstanced`.
   */
  int DeviceD3D10::DrawIndexedPrimitive(const void* const context)
  {
    const auto* const drawContext = static_cast<const DrawIndexedContext*>(context);
    // As above: DrawIndexed takes an index count, and the binary passes this lane
    // through unconverted (`mov edx,[edi+0x10]` at 0x008FD16E).
    if (drawContext->topologyToken_ == 0U) {
      ThrowInvalidTopologyError(1580);
    }

    InvokeNativeSetPrimitiveTopology(this, ResolvePrimitiveTopology(drawContext->topologyToken_));
    const std::uint32_t instanceCount = GetDeviceInstanceCount(this);
    if (instanceCount > 1U) {
      return InvokeNativeDrawIndexedInstanced(
        this, drawContext->primitiveCountInput_, instanceCount, drawContext->startIndex_, 0, 0U
      );
    }

    return InvokeNativeDrawIndexed(this, drawContext->primitiveCountInput_, drawContext->startIndex_, 0);
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
  int DeviceD3D10::ClearTarget(const OutputContext* const context)
  {
    mOutputContext = *context;

    void* renderTargetView = nullptr;
    void* depthStencilView = nullptr;

    if (context != nullptr) {
      if (context->surface.get() != nullptr) {
        renderTargetView = static_cast<RenderTargetD3D10*>(context->surface.get())->GetRenderTargetViewOrThrow();
      }

      if (context->depthStencil.get() != nullptr) {
        depthStencilView =
          static_cast<DepthStencilTargetD3D10*>(context->depthStencil.get())->GetDepthStencilViewOrThrow();
      }
    }

    void* renderTargetViews[1] = {renderTargetView};
    return InvokeNativeClearTarget(this, 1U, renderTargetViews, depthStencilView);
  }

  /**
   * Address: 0x008F9510 (FUN_008F9510)
   *
   * bool,bool,bool,uint32_t,float,int
   *
   * What it does:
   * Clears active color and/or depth-stencil lanes based on caller boolean
   * mask inputs and returns the native depth-clear result when dispatched.
   */
  int DeviceD3D10::Clear(
    const bool clearColor,
    const bool clearDepth,
    const bool clearStencil,
    const std::uint32_t packedColor,
    const float depth,
    const int stencil
  )
  {
    void* renderTargetView = nullptr;
    void* depthStencilView = nullptr;

    if (mOutputContext.surface.get() != nullptr) {
      renderTargetView = static_cast<RenderTargetD3D10*>(mOutputContext.surface.get())->GetRenderTargetViewOrThrow();
    }

    if (mOutputContext.depthStencil.get() != nullptr) {
      depthStencilView =
        static_cast<DepthStencilTargetD3D10*>(mOutputContext.depthStencil.get())->GetDepthStencilViewOrThrow();
    }

    if (clearColor && (renderTargetView != nullptr)) {
      float clearColorRgba[4] = {
        static_cast<float>((packedColor >> 16U) & 0xFFU),
        static_cast<float>((packedColor >> 8U) & 0xFFU),
        static_cast<float>(packedColor & 0xFFU),
        static_cast<float>((packedColor >> 24U) & 0xFFU),
      };
      InvokeNativeClearRenderTargetView(this, renderTargetView, clearColorRgba);
    }

    int clearMask = 0;
    if (clearDepth) {
      clearMask |= 1;
    }
    if (clearStencil) {
      clearMask |= 2;
    }

    if ((clearMask != 0) && (depthStencilView != nullptr)) {
      return InvokeNativeClearDepthStencilView(
        this, depthStencilView, static_cast<unsigned int>(clearMask), depth, static_cast<unsigned int>(stencil)
      );
    }

    return clearMask;
  }

  /**
   * Address: 0x008FE6D0 (FUN_008FE6D0)
   *
   * What it does:
   * Preserves the binary no-op fog-state lane.
   */
  void DeviceD3D10::SetFogState(const int arg1, const int arg2, const int arg3, const int arg4, const int arg5)
  {
    static_cast<void>(arg1);
    static_cast<void>(arg2);
    static_cast<void>(arg3);
    static_cast<void>(arg4);
    static_cast<void>(arg5);
  }

  /**
   * Address: 0x008FE6E0 (FUN_008FE6E0)
   *
   * What it does:
   * Preserves the binary no-op wireframe-state lane.
   */
  void DeviceD3D10::SetWireframeState(const int arg1)
  {
    static_cast<void>(arg1);
  }

  /**
   * Address: 0x008FE6F0 (FUN_008FE6F0)
   *
   * What it does:
   * Preserves the binary no-op color-write-state lane.
   */
  void DeviceD3D10::SetColorWriteState(const int arg1, const int arg2)
  {
    static_cast<void>(arg1);
    static_cast<void>(arg2);
  }

  /**
   * Address: 0x008F95F0 (FUN_008F95F0)
   *
   * What it does:
   * Clears shader-resource bindings for 128 texture slots on the retained
   * technique-state native device lane.
   */
  int DeviceD3D10::ClearTextures()
  {
    return ClearAllTextureShaderResourceSlots(GetDeviceTechniqueBindings(this));
  }

  /**
   * Address: 0x008F9600 (FUN_008F9600)
   *
   * VertexFormatD3D10 *,WeakRefCountedToken *
   *
   * What it does:
   * Validates one vertex declaration, binds it on the native device input-layout
   * slot, and releases the previous weak-ref token when supplied.
   */
  int DeviceD3D10::SetVertexDeclaration(
    VertexFormatD3D10* const vertexFormat, WeakRefCountedToken* const previousFormatRef
  )
  {
    void* const declaration = vertexFormat->ValidateLayoutOrThrow();
    const int result = InvokeNativeSetInputLayout(this, declaration);
    ReleaseWeakRefToken(previousFormatRef);
    return result;
  }

  /**
   * Address: 0x008F9690 (FUN_008F9690)
   *
   * uint32_t,VertexBufferD3D10 *,WeakRefCountedToken *,WeakRefCountedToken *,int
   *
   * What it does:
   * Binds one vertex-buffer stream, updates the retained stream weak-ref slot,
   * and releases the previous weak-ref token.
   */
  WeakRefCountedToken* DeviceD3D10::Func15(
    const std::uint32_t streamSlot,
    VertexBufferD3D10* const vertexBuffer,
    WeakRefCountedToken* const previousStreamRef,
    WeakRefCountedToken* const currentStreamRef,
    const int startVertexMultiplier
  )
  {
    const VertexBufferContext* const context = vertexBuffer->GetContext();
    void* const nativeVertexBuffer = vertexBuffer->GetNativeBufferOrThrow();
    const unsigned int stride = context->stride_;
    const unsigned int offset = static_cast<unsigned int>(startVertexMultiplier * static_cast<int>(stride));

    void* buffers[1] = {nativeVertexBuffer};
    InvokeNativeSetVertexBuffers(this, streamSlot, buffers, &stride, &offset);

    GetDeviceVertexStreamRefArray(this)[streamSlot] = currentStreamRef;
    ReleaseWeakRefToken(previousStreamRef);
    return currentStreamRef;
  }

  /**
   * Address: 0x008F9760 (FUN_008F9760)
   *
   * IndexBufferD3D10 *,WeakRefCountedToken *
   *
   * What it does:
   * Selects the recovered DXGI index format token from index-buffer context,
   * binds the native index buffer with zero offset, then releases the prior
   * weak-ref token.
   */
  int DeviceD3D10::SetBufferIndices(IndexBufferD3D10* const indexBuffer, WeakRefCountedToken* const previousIndexRef)
  {
    const IndexBufferContext* const context = indexBuffer->GetContextBuffer();
    const unsigned int indexFormatToken = (context->format_ == 2U) ? DXGI_FORMAT_R32_UINT : DXGI_FORMAT_R16_UINT;
    void* const nativeIndexBuffer = indexBuffer->GetNativeBufferOrThrow();
    const int result = InvokeNativeSetIndexBuffer(this, nativeIndexBuffer, indexFormatToken, 0U);
    ReleaseWeakRefToken(previousIndexRef);
    return result;
  }

  /**
   * Address: 0x008F9810 (FUN_008F9810)
   *
   * What it does:
   * Applies recovered technique-state bindings onto the native D3D10 device.
   */
  int DeviceD3D10::BeginTechnique()
  {
    return ApplyTechniqueStateBindings(GetDeviceTechniqueBindings(this));
  }

  /**
   * Address: 0x008F9820 (FUN_008F9820)
   *
   * What it does:
   * Preserves the binary no-op end-technique lane (tail-jump to `nullsub_3640`).
   */
  int DeviceD3D10::EndTechnique()
  {
    static_cast<void>(GetDeviceTechniqueBindings(this));
    nullsub_3640();
    return 0;
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
  VertexFormatD3D10::VertexFormatD3D10(const std::uint32_t format, void* const vertexDeclaration)
    : format_(0x17U)
    , streamStrides_()
    , vertexDeclaration_(nullptr)
  {
    Initialize(format, vertexDeclaration);
  }

  /**
   * Address: 0x00904260 (FUN_00904260)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to
   * `FUN_009041E0`.
   */
  VertexFormatD3D10::~VertexFormatD3D10()
  {
    DestroyVertexFormatD3D10Body(this);
  }

  /**
   * Address: 0x00904280 (FUN_00904280)
   *
   * What it does:
   * Validates that one retained declaration handle is bound and returns it.
   */
  void* VertexFormatD3D10::ValidateLayoutOrThrow()
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
  std::uint32_t VertexFormatD3D10::Initialize(const std::uint32_t format, void* const vertexDeclaration)
  {
    ResetVertexFormatDeclaration(this);
    vertexDeclaration_ = vertexDeclaration;
    format_ = format;

    const D3D10_INPUT_ELEMENT_DESC* const layoutElements = GetVertexLayoutElementsOrThrow(format_);
    const std::uint32_t layoutElementCount = GetVertexLayoutElementCountOrThrow(format_);

    if (streamStrides_.begin_ != streamStrides_.end_) {
      streamStrides_.end_ = streamStrides_.begin_;
    }

    std::uint32_t result = layoutElementCount;
    for (std::uint32_t index = 0; index < layoutElementCount; ++index) {
      const D3D10_INPUT_ELEMENT_DESC& element = layoutElements[index];
      EnsureVertexStreamStrideCount(&streamStrides_, element.InputSlot + 1U);

      std::uint32_t* const streamStride = streamStrides_.begin_ + element.InputSlot;
      const std::uint32_t candidate = element.AlignedByteOffset + GetTextureFormatBlockBytes(element.Format);
      result = (*streamStride > candidate) ? *streamStride : candidate;
      *streamStride = result;
    }

    return result;
  }

  /**
   * Address: 0x0094C070 (FUN_0094C070)
   *
   * EffectContext const &,void *
   *
   * What it does:
   * Initializes EffectD3D10 context storage, then binds caller context/effect state.
   */
  EffectD3D10::EffectD3D10(EffectContext* const context, void* const dxEffect)
    : context_()
    , dxEffect_(nullptr)
  {
    AssignState(context, dxEffect);
  }

  /**
   * Address: 0x0094BF10 (FUN_0094BF10)
   *
   * What it does:
   * Releases the native effect and assigns a fresh context over `context_`.
   */
  void EffectD3D10::ResetState()
  {
    ReleaseComLike(dxEffect_);
    context_ = EffectContext();
  }

  /**
   * Address: 0x0094BFE0 (FUN_0094BFE0)
   *
   * What it does:
   * Resets, copies `source` into `context_`, adopts `dxEffect`, then empties the
   * copied source buffer (the four words at this+0x48..+0x54, releasing the
   * shared owner at +0x4C first).
   */
  void EffectD3D10::AssignState(const EffectContext* const source, void* const dxEffect)
  {
    ResetState();
    context_ = *source;
    dxEffect_ = dxEffect;
    context_.mSourceBuffer.Reset();
  }

  /**
   * Address: 0x0094BF80 (FUN_0094BF80)
   * Address: 0x0094C050 (FUN_0094C050, the scalar deleting destructor)
   *
   * What it does:
   * Resets the state; `context_` is then destroyed once, as a member
   * (0x0093F950). This body used to tear `context_` down by hand as well, so
   * the member destructor that followed ran over it a second time.
   */
  EffectD3D10::~EffectD3D10()
  {
    ResetState();
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
   * msvc8::vector<boost::shared_ptr<gpg::gal::EffectTechniqueD3D10>> &
   *
   * What it does:
   * Enumerates valid D3D10 techniques from the retained effect and appends wrapped
   * `EffectTechniqueD3D10` objects into the output vector.
   */
  void EffectD3D10::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechniqueD3D10>>& outTechniques)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 52, "invalid effect");
    }

    D3D10_EFFECT_DESC effectDesc{};
    HRESULT result = InvokeEffectGetDesc(dxEffect_, &effectDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectD3D10.cpp", 57, result);
    }

    for (unsigned int index = 0; index < effectDesc.Techniques; ++index) {
      void* const techniqueHandle = InvokeEffectGetTechniqueByIndex(dxEffect_, index);
      if ((techniqueHandle == nullptr) || (InvokeTechniqueIsValid(techniqueHandle) == FALSE)) {
        continue;
      }

      D3D10_TECHNIQUE_DESC techniqueDesc{};
      result = InvokeTechniqueGetDesc(techniqueHandle, &techniqueDesc);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectD3D10.cpp", 69, result);
      }

      outTechniques.push_back(
        boost::shared_ptr<EffectTechniqueD3D10>(
          new EffectTechniqueD3D10(techniqueDesc.Name, dxEffect_, techniqueHandle)
        )
      );
    }
  }

  /**
   * Address: 0x0094B8A0 (FUN_0094B8A0)
   *
   * char const *
   *
   * What it does:
   * Looks up an effect variable by name and returns a wrapped variable handle.
   */
  boost::shared_ptr<EffectVariableD3D10> EffectD3D10::SetMatrix(const char* const variableName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 79, "invalid effect");
    }

    void* const variableHandle = InvokeEffectGetVariableByName(dxEffect_, variableName);
    if (variableHandle == nullptr) {
      char message[512] = {};
      std::snprintf(
        message, sizeof(message), "invalid effect variable requested: %s", (variableName != nullptr) ? variableName : ""
      );
      ThrowGalError("EffectD3D10.cpp", 82, message);
    }

    boost::shared_ptr<EffectVariableD3D10> effectVariable;
    static_cast<void>(
      ConstructSharedEffectVariableD3D10FromRaw(
        &effectVariable, new EffectVariableD3D10(variableName, dxEffect_, variableHandle)
      )
    );
    return effectVariable;
  }

  /**
   * Address: 0x0094BA80 (FUN_0094BA80)
   *
   * char const *
   *
   * What it does:
   * Looks up an effect technique by name and returns a wrapped technique handle.
   */
  boost::shared_ptr<EffectTechniqueD3D10> EffectD3D10::SetTechnique(const char* const techniqueName)
  {
    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectD3D10.cpp", 89, "invalid effect");
    }

    void* const techniqueHandle = InvokeEffectGetTechniqueByName(dxEffect_, techniqueName);
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

    boost::shared_ptr<EffectTechniqueD3D10> effectTechnique;
    static_cast<void>(
      ConstructSharedEffectTechniqueD3D10FromRaw(
        &effectTechnique, new EffectTechniqueD3D10(techniqueName, dxEffect_, techniqueHandle)
      )
    );
    return effectTechnique;
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
  EffectTechniqueD3D10::EffectTechniqueD3D10(const char* const name, void* const dxEffect, void* const techniqueHandle)
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

    AddRefComLike(dxEffect_);
  }

  /**
   * Address: 0x00900FD0 (FUN_00900FD0)
   *
   * What it does:
   * Owns the deleting-destructor thunk path and tears down retained technique state.
   */
  EffectTechniqueD3D10::~EffectTechniqueD3D10()
  {
    DestroyEffectTechniqueD3D10Body(this);
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

    Device* const device = Device::GetInstance();
    InvokeDeviceBeginTechnique(device);

    D3D10_TECHNIQUE_DESC techniqueDesc{};
    const HRESULT result = InvokeTechniqueGetDesc(techniqueHandle_, &techniqueDesc);
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

    Device* const device = Device::GetInstance();
    InvokeDeviceEndTechnique(device);
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

    void* const passHandle = InvokeTechniqueGetPassByIndex(techniqueHandle_, pass);
    const HRESULT result = InvokePassApply(passHandle, 0U);
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

    void* const variable = InvokeTechniqueGetAnnotationByName(techniqueHandle_, annotationName.c_str());
    if ((variable == nullptr) || (InvokeVariableIsValid(variable) == FALSE)) {
      return false;
    }

    int boolValue = 0;
    void* const scalar = InvokeVariableAsScalar(variable);
    const HRESULT result = InvokeScalarGetBool(scalar, &boolValue);
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

    void* const variable = InvokeTechniqueGetAnnotationByName(techniqueHandle_, annotationName.c_str());
    if ((variable == nullptr) || (InvokeVariableIsValid(variable) == FALSE)) {
      return false;
    }

    void* const scalar = InvokeVariableAsScalar(variable);
    const HRESULT result = InvokeScalarGetInt(scalar, outValue);
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

    void* const variable = InvokeTechniqueGetAnnotationByName(techniqueHandle_, annotationName.c_str());
    if ((variable == nullptr) || (InvokeVariableIsValid(variable) == FALSE)) {
      return false;
    }

    void* const scalar = InvokeVariableAsScalar(variable);
    const HRESULT result = InvokeScalarGetFloat(scalar, outValue);
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

    void* const variable = InvokeTechniqueGetAnnotationByName(techniqueHandle_, annotationName.c_str());
    if ((variable == nullptr) || (InvokeVariableIsValid(variable) == FALSE)) {
      return false;
    }

    const char* text = nullptr;
    void* const stringVariable = InvokeVariableAsString(variable);
    const HRESULT result = InvokeStringGetString(stringVariable, &text);
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
  EffectVariableD3D10::EffectVariableD3D10(const char* const name, void* const dxEffect, void* const variableHandle)
    : name_()
    , dxEffect_(dxEffect)
    , variableHandle_(variableHandle)
  {
    name_.assign_owned((name != nullptr) ? name : "");

    if (dxEffect_ == nullptr) {
      ThrowGalError("EffectVariableD3D10.cpp", 39, "invalid effect specified");
    }

    AddRefComLike(dxEffect_);
  }

  /**
   * Address: 0x0094C1D0 (FUN_0094C1D0)
   *
   * What it does:
   * Owns deleting-destructor behavior and delegates body lanes to `FUN_0094C150`.
   */
  EffectVariableD3D10::~EffectVariableD3D10()
  {
    DestroyEffectVariableD3D10Body(this);
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
  void EffectVariableD3D10::Func2(boost::shared_ptr<CubeRenderTargetD3D10> cubeRenderTarget)
  {
    (void)cubeRenderTarget;
  }

  /**
   * Address: 0x0094CD00 (FUN_0094CD00)
   *
   * What it does:
   * Binds a render-target-backed shader-resource view into this effect slot.
   */
  void EffectVariableD3D10::Func3(boost::shared_ptr<RenderTargetD3D10> renderTarget)
  {
    void* const shaderResourceVariable = InvokeVariableAsShaderResource(variableHandle_);
    void* const shaderResourceView =
      (renderTarget.get() != nullptr) ? renderTarget->GetShaderResourceViewOrThrow() : nullptr;
    const HRESULT result = InvokeShaderResourceSetResource(shaderResourceVariable, shaderResourceView);
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
    void* const shaderResourceVariable = InvokeVariableAsShaderResource(variableHandle_);
    void* const shaderResourceView =
      (texture.get() != nullptr) ? static_cast<TextureD3D10*>(texture.get())->GetShaderResourceViewOrThrow() : nullptr;
    const HRESULT result = InvokeShaderResourceSetResource(shaderResourceVariable, shaderResourceView);
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
  void EffectVariableD3D10::SetMatrix4x4(const void* const matrix4x4)
  {
    void* const matrixValue = InvokeVariableAsMatrix(variableHandle_);
    const HRESULT result = InvokeMatrixSetMatrix(matrixValue, matrix4x4);
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
    void* const scalar = InvokeVariableAsScalar(variableHandle_);
    const HRESULT result = InvokeScalarSetBool(scalar, value ? TRUE : FALSE);
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
    void* const scalar = InvokeVariableAsScalar(variableHandle_);
    const HRESULT result = InvokeScalarSetInt(scalar, value);
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
    void* const scalar = InvokeVariableAsScalar(variableHandle_);
    const HRESULT result = InvokeScalarSetFloat(scalar, value);
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
  void EffectVariableD3D10::SetVector(const void* const value)
  {
    void* const vectorValue = InvokeVariableAsVector(variableHandle_);
    const HRESULT result = InvokeVectorSetFloatVector(vectorValue, value);
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
   * Writes raw value payload bytes from caller memory (`byteCount`).
   */
  void EffectVariableD3D10::SetPtr(const void* const data, const int byteCount)
  {
    const HRESULT result = InvokeVariableSetRawValue(variableHandle_, data, 0U, static_cast<unsigned int>(byteCount));
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
   * Writes raw variable bytes from caller memory (`floatCount * 4`).
   */
  void EffectVariableD3D10::SetMem(const int floatCount, const void* const values)
  {
    const HRESULT result =
      InvokeVariableSetRawValue(variableHandle_, values, 0U, static_cast<unsigned int>(floatCount * 4));
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
   * Writes count-based matrix/float payload through matrix lane with
   * raw-value fallback.
   */
  void EffectVariableD3D10::Func8(const int valueCount, const void* const values)
  {
    void* const matrixValue = InvokeVariableAsMatrix(variableHandle_);
    HRESULT result = InvokeMatrixSetMatrixArray(matrixValue, &values, 0U, static_cast<unsigned int>(valueCount));
    if (result < 0) {
      result = InvokeVariableSetRawValue(variableHandle_, values, 0U, static_cast<unsigned int>(valueCount * 4));
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
   * Writes vector-lane payload bytes using one 32-bit value lane.
   */
  void EffectVariableD3D10::Func9(const int valueCount, const std::uint32_t value)
  {
    void* const vectorValue = InvokeVariableAsVector(variableHandle_);
    const HRESULT result = InvokeVectorSetArray(vectorValue, &value, 0U, static_cast<unsigned int>(valueCount));
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

    void* const annotation = InvokeVariableGetAnnotationByName(variableHandle_, annotationName.c_str());
    if ((annotation == nullptr) || (InvokeVariableIsValid(annotation) == FALSE)) {
      return false;
    }

    int boolValue = 0;
    void* const scalar = InvokeVariableAsScalar(annotation);
    const HRESULT result = InvokeScalarGetBool(scalar, &boolValue);
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

    void* const annotation = InvokeVariableGetAnnotationByName(variableHandle_, annotationName.c_str());
    if ((annotation == nullptr) || (InvokeVariableIsValid(annotation) == FALSE)) {
      return false;
    }

    void* const scalar = InvokeVariableAsScalar(annotation);
    const HRESULT result = InvokeScalarGetInt(scalar, outValue);
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

    void* const annotation = InvokeVariableGetAnnotationByName(variableHandle_, annotationName.c_str());
    if ((annotation == nullptr) || (InvokeVariableIsValid(annotation) == FALSE)) {
      return false;
    }

    void* const scalar = InvokeVariableAsScalar(annotation);
    const HRESULT result = InvokeScalarGetFloat(scalar, outValue);
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

    void* const annotation = InvokeVariableGetAnnotationByName(variableHandle_, annotationName.c_str());
    if ((annotation == nullptr) || (InvokeVariableIsValid(annotation) == FALSE)) {
      return false;
    }

    const char* text = nullptr;
    void* const stringVariable = InvokeVariableAsString(annotation);
    const HRESULT result = InvokeStringGetString(stringVariable, &text);
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

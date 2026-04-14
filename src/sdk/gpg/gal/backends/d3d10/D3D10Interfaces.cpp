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
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/core/utils/Global.h"
#include "platform/Platform.h"

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>

namespace gpg::gal
{
  struct CursorPixelSourceRuntime
  {
    void** vtable = nullptr; // +0x00
  };

  namespace
  {
    using release_fn = unsigned long(__stdcall*)(void*);
    using add_ref_fn = unsigned long(__stdcall*)(void*);
    using cursor_source_lock_fn = void(__thiscall*)(CursorPixelSourceRuntime*, void*, int, std::uint32_t*, int);
    using cursor_source_unlock_fn =
      void(__thiscall*)(CursorPixelSourceRuntime*, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t);
    using device_get_context_fn = void*(__thiscall*)(Device*);
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
    using texture_virtual_unlock_fn = int(__thiscall*)(TextureD3D10*, int);
    using texture_get_desc_fn = void(__stdcall*)(void*, void*);
    using texture_map_fn = HRESULT(__stdcall*)(void*, int, unsigned int, unsigned int, void*);
    using texture_unmap_fn = void(__stdcall*)(void*, int);
    using device_helper34_fn = HRESULT(__thiscall*)(Device*, int, void**);
    using device_helper44_fn = HRESULT(__thiscall*)(Device*, void*, int, void**);
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
    using swap_chain_present_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int);
    using index_buffer_get_context_fn = void*(__thiscall*)(IndexBufferD3D10*);
    using vertex_buffer_get_context_fn = void*(__thiscall*)(VertexBufferD3D10*);
    using readback_get_size_fn = int(__stdcall*)(void*);
    using readback_get_data_fn = void*(__stdcall*)(void*);
    using device_create_blob_api_fn = HRESULT(__stdcall*)(std::uint32_t, void**);
    using device_create_effect_from_memory_api_fn = HRESULT(__stdcall*)(
      const void*,
      std::size_t,
      const char*,
      const D3D10_SHADER_MACRO*,
      void*,
      unsigned int,
      unsigned int,
      void*,
      void*,
      void*,
      void**,
      void**
    );
    using device_create_texture_from_memory_api_fn =
      HRESULT(__stdcall*)(void*, const void*, std::uint32_t, const void*, void*, void**);
    using device_save_texture_to_file_api_fn = HRESULT(__stdcall*)(void*, int, const char*);
    using device_save_texture_to_memory_api_fn = HRESULT(__stdcall*)(void*, int, void**);
    using create_dxgi_factory_api_fn = HRESULT(__stdcall*)(const IID&, void**);
    using d3d10_create_device_api_fn =
      HRESULT(__stdcall*)(IDXGIAdapter*, D3D10_DRIVER_TYPE, HMODULE, UINT, UINT, ID3D10Device**);
    using device_native_copy_subresource_region_fn = int(__stdcall*)(
      void*, void*, unsigned int, unsigned int, unsigned int, unsigned int, void*, unsigned int, const D3D10_BOX*
    );
    using device_native_copy_resource_result_fn = int(__stdcall*)(void*, void*, void*);

    struct D3D10EffectDescRuntime final
    {
      std::uint8_t pad00_13[0x14]{};     // +0x00 .. +0x13
      std::uint32_t techniqueCount = 0U; // +0x14
    };

    struct D3D10TechniqueDescRuntime final
    {
      const char* name = nullptr;   // +0x00
      std::uint32_t passCount = 0U; // +0x04
    };

    struct TextureDescRuntime final
    {
      std::uint32_t width = 0U;          // +0x00
      std::uint32_t height = 0U;         // +0x04
      std::uint32_t mipLevels = 0U;      // +0x08
      std::uint32_t arraySize = 0U;      // +0x0C
      std::uint32_t format = 0U;         // +0x10
      std::uint32_t sampleCount = 0U;    // +0x14
      std::uint32_t sampleQuality = 0U;  // +0x18
      std::uint32_t usage = 0U;          // +0x1C
      std::uint32_t bindFlags = 0U;      // +0x20
      std::uint32_t cpuAccessFlags = 0U; // +0x24
      std::uint32_t miscFlags = 0U;      // +0x28
    };

    struct TextureMapResultRuntime final
    {
      void* bits = nullptr; // +0x00
      int pitch = 0;        // +0x04
    };

    struct DXGIFormatPair final
    {
      int dxgi = 0;
      int gal = 0;
    };

    struct VertexLayoutElementRuntime final
    {
      std::uint32_t semanticNameToken = 0U; // +0x00
      std::uint32_t semanticIndex = 0U;     // +0x04
      std::uint32_t format = 0U;            // +0x08
      std::uint32_t inputSlot = 0U;         // +0x0C
      std::uint32_t alignedByteOffset = 0U; // +0x10
      std::uint32_t inputSlotClass = 0U;    // +0x14
      std::uint32_t stepRate = 0U;          // +0x18
    };

    struct IndexBufferContextRuntime final
    {
      std::uint32_t pad00 = 0U;  // +0x00
      std::uint32_t format = 0U; // +0x04
    };

    struct VertexBufferContextRuntime final
    {
      std::uint8_t pad00_0F[0x10]{}; // +0x00 .. +0x0F
      std::uint32_t stride = 0U;     // +0x10
    };

    struct D3D10PassDescRuntime final
    {
      const char* name = nullptr;           // +0x00
      std::uint32_t annotationCount = 0U;   // +0x04
      const void* inputSignature = nullptr; // +0x08
      std::size_t inputSignatureSize = 0U;  // +0x0C
      std::uint32_t stencilRef = 0U;        // +0x10
      std::uint32_t sampleMask = 0U;        // +0x14
      float blendFactor[4]{};               // +0x18
    };

    struct DeviceTechniqueBindingsRuntime final
    {
      std::uint8_t pad00_03[0x04]{};     // +0x00 .. +0x03
      void* nativeDevice = nullptr;      // +0x04
      std::uint8_t pad08_1B[0x14]{};     // +0x08 .. +0x1B
      void* rasterizerState = nullptr;   // +0x1C
      void* depthStencilState = nullptr; // +0x20
      void* blendState = nullptr;        // +0x24
    };

    struct DeviceD3D10RuntimeView final
    {
      std::uint8_t pad00_B3[0xB4]{};                                    // +0x00 .. +0xB3
      DeviceTechniqueBindingsRuntime* techniqueBindings = nullptr;      // +0xB4 (pipeline-state px lane)
      boost::detail::sp_counted_base* techniqueBindingsCount = nullptr; // +0xB8 (pipeline-state pi lane)
      std::uint8_t padBC_BF[0x04]{};                                    // +0xBC .. +0xBF
      void* nativeDevice = nullptr;                                     // +0xC0
      void* signatureEffect = nullptr;                                  // +0xC4
      void* stretchRectEffect = nullptr;                                // +0xC8
      void* stretchRectTechnique = nullptr;                             // +0xCC
      void* stretchRectVertexBuffer = nullptr;                          // +0xD0
      void* stretchRectInputLayout = nullptr;                           // +0xD4
      WeakRefCountedToken* vertexStreamRefs[1]{};                       // +0xD8 (start of stream-ref array)
    };

    struct DeviceOutputContextRuntime final
    {
      std::uint8_t pad00_03[0x04]{}; // +0x00 .. +0x03
      OutputContext outputContext{}; // +0x04
    };

    struct OutputContextD3D10RuntimeView final
    {
      void* vtable = nullptr;                                    // +0x00
      boost::shared_ptr<CubeRenderTargetD3D10> cubeTarget;       // +0x04
      std::int32_t face = 0;                                     // +0x0C
      boost::shared_ptr<RenderTargetD3D10> renderTarget;         // +0x10
      boost::shared_ptr<DepthStencilTargetD3D10> depthStencil;   // +0x18
    };

    struct DeviceD3D10IntroRuntime final
    {
      std::uint8_t pad00_4B[0x4C]{};          // +0x00 .. +0x4B
      int currentThreadId = 0;                // +0x4C
      std::uint8_t logStorage[0x10]{};        // +0x50 .. +0x5F
      DeviceContext* deviceContext = nullptr; // +0x60
    };

    struct DeviceCursorLaneRuntime final
    {
      std::uint8_t pad00_11B[0x11C]{}; // +0x00 .. +0x11B
      CursorD3D10 cursor{};            // +0x11C
    };

    struct DeviceHeadArrayRuntime final
    {
      std::uint8_t pad00_117[0x118]{}; // +0x00 .. +0x117
      void* headsBase = nullptr;       // +0x118
    };

    struct DeviceContextHeadRangeRuntime final
    {
      std::uint8_t pad00_27[0x28]{};            // +0x00 .. +0x27
      const std::uint8_t* headsBegin = nullptr; // +0x28
      const std::uint8_t* headsEnd = nullptr;   // +0x2C
    };

    struct HeadRuntime final
    {
      void* vtable = nullptr;             // +0x00
      std::uint8_t pad04_07[0x04]{};      // +0x04 .. +0x07
      HWND window = nullptr;              // +0x08
      std::uint8_t windowed = 0U;         // +0x0C
      std::uint8_t pad0D_0F[0x03]{};      // +0x0D .. +0x0F
      std::uint32_t width = 0U;           // +0x10
      std::uint32_t height = 0U;          // +0x14
      std::uint32_t framesPerSecond = 0U; // +0x18
    };

    struct CursorPixelTransferTokenRuntime final
    {
      std::uint32_t token0 = 0U;        // +0x00
      std::uint32_t token1 = 0U;        // +0x04
      std::uint32_t rowPitchBytes = 0U; // +0x08
      std::uint32_t dataPointer = 0U;   // +0x0C
    };

    struct ViewportRuntime final
    {
      std::int32_t topLeftX = 0; // +0x00
      std::int32_t topLeftY = 0; // +0x04
      std::uint32_t width = 0U;  // +0x08
      std::uint32_t height = 0U; // +0x0C
      float minDepth = 0.0f;     // +0x10
      float maxDepth = 0.0f;     // +0x14
    };

    struct DeviceSwapChainRangeRuntime final
    {
      std::uint8_t pad00_A7[0xA8]{};    // +0x00 .. +0xA7
      void** swapChainsBegin = nullptr; // +0xA8
      void** swapChainsEnd = nullptr;   // +0xAC
    };

    struct DrawPrimitiveContextRuntime final
    {
      std::uint32_t pad00 = 0U;         // +0x00
      std::uint32_t topologyToken = 0U; // +0x04
      std::uint32_t vertexCount = 0U;   // +0x08
      std::uint32_t startVertex = 0U;   // +0x0C
    };

    struct DrawIndexedPrimitiveContextRuntime final
    {
      std::uint32_t pad00 = 0U;         // +0x00
      std::uint32_t topologyToken = 0U; // +0x04
      std::uint32_t pad08 = 0U;         // +0x08
      std::uint32_t pad0C = 0U;         // +0x0C
      std::uint32_t indexCount = 0U;    // +0x10
      std::uint32_t startIndex = 0U;    // +0x14
    };

    struct TechniquePassCountRuntime final
    {
      std::uint32_t pad00 = 0U;     // +0x00
      std::uint32_t passCount = 0U; // +0x04
    };

    constexpr std::uint32_t kHardwareVertexFormatToken = 14U;
    constexpr std::uint32_t kFloat16VertexFormatToken = 15U;
    constexpr std::uint32_t kHardwareVertexStrideBase = 0x48U;
    constexpr std::uint32_t kFloat16VertexStrideStream0 = 0x2CU;
    constexpr std::uint32_t kFloat16VertexStrideStream1 = 0x44U;

    struct DeviceContextRuntimeFlags final
    {
      std::uint8_t pad00_10[0x11]{};
      std::uint8_t hwBasedInstancing = 0; // +0x11
      std::uint8_t meshFloat16 = 0;       // +0x12
    };

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

    class DeviceD3D10BackendObject final : public DeviceD3D10
    {
    public:
      OutputContext outputContext_{};                                     // +0x04
      HMODULE d3dModulePrimary_ = nullptr;                                // +0x24
      HMODULE d3dModuleSecondary_ = nullptr;                              // +0x28
      HMODULE dxgiModule_ = nullptr;                                      // +0x2C
      void* createDeviceApi_ = nullptr;                                   // +0x30
      device_create_blob_api_fn createBlobApi_ = nullptr;                 // +0x34
      device_create_effect_from_memory_api_fn createEffectFromMemoryApi_ = nullptr; // +0x38
      device_create_texture_from_memory_api_fn createTextureFromMemoryApi_ = nullptr; // +0x3C
      device_save_texture_to_file_api_fn saveTextureToFileApi_ = nullptr; // +0x40
      device_save_texture_to_memory_api_fn saveTextureToMemoryApi_ = nullptr; // +0x44
      void* createDxgiFactoryApi_ = nullptr;                              // +0x48
      int currentThreadId_ = 0;                                           // +0x4C
      msvc8::vector<msvc8::string> logStorage_{};                         // +0x50
      DeviceContext deviceContext_{0};                                    // +0x60
      msvc8::vector<AdapterD3D10> adapters_{};                            // +0x94
      msvc8::vector<void*> swapChains_{};                                 // +0xA4
      boost::shared_ptr<PipelineStateD3D10> pipelineState_{};             // +0xB4
      void* dxgiFactory_ = nullptr;                                       // +0xBC
      void* d3dDevice_ = nullptr;                                         // +0xC0
      void* effectPreamble_ = nullptr;                                    // +0xC4
      void* shaderPreamble_ = nullptr;                                    // +0xC8
      void* rttTechnique_ = nullptr;                                      // +0xCC
      void* stretchRectBuffer_ = nullptr;                                 // +0xD0
      void* stretchRectInputLayout_ = nullptr;                            // +0xD4
      std::uint32_t streamStateD8_[16]{};                                 // +0xD8 .. +0x117
      void* outputContexts_ = nullptr;                                    // +0x118
      CursorD3D10 cursor_{};                                              // +0x11C
    };

    static_assert(
      offsetof(D3D10EffectDescRuntime, techniqueCount) == 0x14,
      "D3D10EffectDescRuntime::techniqueCount offset must be 0x14"
    );
    static_assert(sizeof(D3D10EffectDescRuntime) == 0x18, "D3D10EffectDescRuntime size must be 0x18");
    static_assert(
      offsetof(D3D10TechniqueDescRuntime, passCount) == 0x04, "D3D10TechniqueDescRuntime::passCount offset must be 0x04"
    );
    static_assert(sizeof(D3D10TechniqueDescRuntime) == 0x08, "D3D10TechniqueDescRuntime size must be 0x08");
    static_assert(offsetof(TextureDescRuntime, format) == 0x10, "TextureDescRuntime::format offset must be 0x10");
    static_assert(offsetof(TextureDescRuntime, usage) == 0x1C, "TextureDescRuntime::usage offset must be 0x1C");
    static_assert(offsetof(TextureDescRuntime, bindFlags) == 0x20, "TextureDescRuntime::bindFlags offset must be 0x20");
    static_assert(
      offsetof(TextureDescRuntime, cpuAccessFlags) == 0x24, "TextureDescRuntime::cpuAccessFlags offset must be 0x24"
    );
    static_assert(offsetof(TextureDescRuntime, miscFlags) == 0x28, "TextureDescRuntime::miscFlags offset must be 0x28");
    static_assert(sizeof(TextureDescRuntime) == 0x2C, "TextureDescRuntime size must be 0x2C");
    static_assert(sizeof(TextureMapResultRuntime) == 0x08, "TextureMapResultRuntime size must be 0x08");
    static_assert(
      offsetof(VertexLayoutElementRuntime, format) == 0x08, "VertexLayoutElementRuntime::format offset must be 0x08"
    );
    static_assert(
      offsetof(VertexLayoutElementRuntime, inputSlot) == 0x0C,
      "VertexLayoutElementRuntime::inputSlot offset must be 0x0C"
    );
    static_assert(
      offsetof(VertexLayoutElementRuntime, alignedByteOffset) == 0x10,
      "VertexLayoutElementRuntime::alignedByteOffset offset must be 0x10"
    );
    static_assert(sizeof(VertexLayoutElementRuntime) == 0x1C, "VertexLayoutElementRuntime size must be 0x1C");
    static_assert(
      offsetof(IndexBufferContextRuntime, format) == 0x04, "IndexBufferContextRuntime::format offset must be 0x04"
    );
    static_assert(sizeof(IndexBufferContextRuntime) == 0x08, "IndexBufferContextRuntime size must be 0x08");
    static_assert(
      offsetof(VertexBufferContextRuntime, stride) == 0x10, "VertexBufferContextRuntime::stride offset must be 0x10"
    );
    static_assert(sizeof(VertexBufferContextRuntime) == 0x14, "VertexBufferContextRuntime size must be 0x14");
    static_assert(
      offsetof(D3D10PassDescRuntime, inputSignature) == 0x08, "D3D10PassDescRuntime::inputSignature offset must be 0x08"
    );
    static_assert(
      offsetof(D3D10PassDescRuntime, inputSignatureSize) == 0x0C,
      "D3D10PassDescRuntime::inputSignatureSize offset must be 0x0C"
    );
    static_assert(sizeof(D3D10PassDescRuntime) == 0x28, "D3D10PassDescRuntime size must be 0x28");
    static_assert(
      offsetof(DeviceTechniqueBindingsRuntime, nativeDevice) == 0x04,
      "DeviceTechniqueBindingsRuntime::nativeDevice offset must be 0x04"
    );
    static_assert(
      offsetof(DeviceTechniqueBindingsRuntime, rasterizerState) == 0x1C,
      "DeviceTechniqueBindingsRuntime::rasterizerState offset must be 0x1C"
    );
    static_assert(
      offsetof(DeviceTechniqueBindingsRuntime, depthStencilState) == 0x20,
      "DeviceTechniqueBindingsRuntime::depthStencilState offset must be 0x20"
    );
    static_assert(
      offsetof(DeviceTechniqueBindingsRuntime, blendState) == 0x24,
      "DeviceTechniqueBindingsRuntime::blendState offset must be 0x24"
    );
    static_assert(sizeof(DeviceTechniqueBindingsRuntime) == 0x28, "DeviceTechniqueBindingsRuntime size must be 0x28");
    static_assert(
      offsetof(DeviceD3D10RuntimeView, techniqueBindings) == 0xB4,
      "DeviceD3D10RuntimeView::techniqueBindings offset must be 0xB4"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, techniqueBindingsCount) == 0xB8,
      "DeviceD3D10RuntimeView::techniqueBindingsCount offset must be 0xB8"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, nativeDevice) == 0xC0, "DeviceD3D10RuntimeView::nativeDevice offset must be 0xC0"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, signatureEffect) == 0xC4,
      "DeviceD3D10RuntimeView::signatureEffect offset must be 0xC4"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, stretchRectEffect) == 0xC8,
      "DeviceD3D10RuntimeView::stretchRectEffect offset must be 0xC8"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, stretchRectTechnique) == 0xCC,
      "DeviceD3D10RuntimeView::stretchRectTechnique offset must be 0xCC"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, stretchRectVertexBuffer) == 0xD0,
      "DeviceD3D10RuntimeView::stretchRectVertexBuffer offset must be 0xD0"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, stretchRectInputLayout) == 0xD4,
      "DeviceD3D10RuntimeView::stretchRectInputLayout offset must be 0xD4"
    );
    static_assert(
      offsetof(DeviceD3D10RuntimeView, vertexStreamRefs) == 0xD8,
      "DeviceD3D10RuntimeView::vertexStreamRefs offset must be 0xD8"
    );
    static_assert(
      offsetof(DeviceOutputContextRuntime, outputContext) == 0x04,
      "DeviceOutputContextRuntime::outputContext offset must be 0x04"
    );
    static_assert(sizeof(DeviceOutputContextRuntime) == 0x24, "DeviceOutputContextRuntime size must be 0x24");
    static_assert(
      offsetof(DeviceD3D10IntroRuntime, currentThreadId) == 0x4C,
      "DeviceD3D10IntroRuntime::currentThreadId offset must be 0x4C"
    );
    static_assert(
      offsetof(DeviceD3D10IntroRuntime, logStorage) == 0x50, "DeviceD3D10IntroRuntime::logStorage offset must be 0x50"
    );
    static_assert(
      offsetof(DeviceD3D10IntroRuntime, deviceContext) == 0x60,
      "DeviceD3D10IntroRuntime::deviceContext offset must be 0x60"
    );
    static_assert(
      offsetof(DeviceCursorLaneRuntime, cursor) == 0x11C, "DeviceCursorLaneRuntime::cursor offset must be 0x11C"
    );
    static_assert(
      offsetof(DeviceHeadArrayRuntime, headsBase) == 0x118, "DeviceHeadArrayRuntime::headsBase offset must be 0x118"
    );
    static_assert(sizeof(DeviceHeadArrayRuntime) == 0x11C, "DeviceHeadArrayRuntime size must be 0x11C");
    static_assert(
      offsetof(DeviceContextHeadRangeRuntime, headsBegin) == 0x28,
      "DeviceContextHeadRangeRuntime::headsBegin offset must be 0x28"
    );
    static_assert(
      offsetof(DeviceContextHeadRangeRuntime, headsEnd) == 0x2C,
      "DeviceContextHeadRangeRuntime::headsEnd offset must be 0x2C"
    );
    static_assert(sizeof(DeviceContextHeadRangeRuntime) == 0x30, "DeviceContextHeadRangeRuntime size must be 0x30");
    static_assert(offsetof(HeadRuntime, window) == 0x08, "HeadRuntime::window offset must be 0x08");
    static_assert(offsetof(HeadRuntime, windowed) == 0x0C, "HeadRuntime::windowed offset must be 0x0C");
    static_assert(offsetof(HeadRuntime, width) == 0x10, "HeadRuntime::width offset must be 0x10");
    static_assert(offsetof(HeadRuntime, height) == 0x14, "HeadRuntime::height offset must be 0x14");
    static_assert(offsetof(HeadRuntime, framesPerSecond) == 0x18, "HeadRuntime::framesPerSecond offset must be 0x18");
    static_assert(sizeof(HeadRuntime) == 0x1C, "HeadRuntime size must be 0x1C");
    static_assert(sizeof(CursorPixelTransferTokenRuntime) == 0x10, "CursorPixelTransferTokenRuntime size must be 0x10");
    static_assert(offsetof(ViewportRuntime, width) == 0x08, "ViewportRuntime::width offset must be 0x08");
    static_assert(offsetof(ViewportRuntime, minDepth) == 0x10, "ViewportRuntime::minDepth offset must be 0x10");
    static_assert(sizeof(ViewportRuntime) == 0x18, "ViewportRuntime size must be 0x18");
    static_assert(
      offsetof(DeviceSwapChainRangeRuntime, swapChainsBegin) == 0xA8,
      "DeviceSwapChainRangeRuntime::swapChainsBegin offset must be 0xA8"
    );
    static_assert(
      offsetof(DeviceSwapChainRangeRuntime, swapChainsEnd) == 0xAC,
      "DeviceSwapChainRangeRuntime::swapChainsEnd offset must be 0xAC"
    );
    static_assert(
      offsetof(DrawPrimitiveContextRuntime, topologyToken) == 0x04,
      "DrawPrimitiveContextRuntime::topologyToken offset must be 0x04"
    );
    static_assert(
      offsetof(DrawPrimitiveContextRuntime, vertexCount) == 0x08,
      "DrawPrimitiveContextRuntime::vertexCount offset must be 0x08"
    );
    static_assert(sizeof(DrawPrimitiveContextRuntime) == 0x10, "DrawPrimitiveContextRuntime size must be 0x10");
    static_assert(
      offsetof(DrawIndexedPrimitiveContextRuntime, topologyToken) == 0x04,
      "DrawIndexedPrimitiveContextRuntime::topologyToken offset must be 0x04"
    );
    static_assert(
      offsetof(DrawIndexedPrimitiveContextRuntime, indexCount) == 0x10,
      "DrawIndexedPrimitiveContextRuntime::indexCount offset must be 0x10"
    );
    static_assert(
      offsetof(DrawIndexedPrimitiveContextRuntime, startIndex) == 0x14,
      "DrawIndexedPrimitiveContextRuntime::startIndex offset must be 0x14"
    );
    static_assert(
      sizeof(DrawIndexedPrimitiveContextRuntime) == 0x18, "DrawIndexedPrimitiveContextRuntime size must be 0x18"
    );
    static_assert(
      offsetof(TechniquePassCountRuntime, passCount) == 0x04, "TechniquePassCountRuntime::passCount offset must be 0x04"
    );
    static_assert(sizeof(TechniquePassCountRuntime) == 0x08, "TechniquePassCountRuntime size must be 0x08");
    static_assert(
      offsetof(DeviceContextRuntimeFlags, hwBasedInstancing) == 0x11,
      "DeviceContextRuntimeFlags::hwBasedInstancing offset must be 0x11"
    );
    static_assert(
      offsetof(DeviceContextRuntimeFlags, meshFloat16) == 0x12, "DeviceContextRuntimeFlags::meshFloat16 offset must be 0x12"
    );
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
    static_assert(
      offsetof(OutputContextD3D10RuntimeView, cubeTarget) == 0x04,
      "OutputContextD3D10RuntimeView::cubeTarget offset must be 0x04"
    );
    static_assert(
      offsetof(OutputContextD3D10RuntimeView, face) == 0x0C,
      "OutputContextD3D10RuntimeView::face offset must be 0x0C"
    );
    static_assert(
      offsetof(OutputContextD3D10RuntimeView, renderTarget) == 0x10,
      "OutputContextD3D10RuntimeView::renderTarget offset must be 0x10"
    );
    static_assert(
      offsetof(OutputContextD3D10RuntimeView, depthStencil) == 0x18,
      "OutputContextD3D10RuntimeView::depthStencil offset must be 0x18"
    );
    static_assert(sizeof(OutputContextD3D10RuntimeView) == 0x20, "OutputContextD3D10RuntimeView size must be 0x20");
    static_assert(
      offsetof(DeviceD3D10BackendObject, outputContext_) == 0x04,
      "DeviceD3D10BackendObject::outputContext_ offset must be 0x04"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, d3dModulePrimary_) == 0x24,
      "DeviceD3D10BackendObject::d3dModulePrimary_ offset must be 0x24"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, logStorage_) == 0x50,
      "DeviceD3D10BackendObject::logStorage_ offset must be 0x50"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, deviceContext_) == 0x60,
      "DeviceD3D10BackendObject::deviceContext_ offset must be 0x60"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, adapters_) == 0x94,
      "DeviceD3D10BackendObject::adapters_ offset must be 0x94"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, swapChains_) == 0xA4,
      "DeviceD3D10BackendObject::swapChains_ offset must be 0xA4"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, pipelineState_) == 0xB4,
      "DeviceD3D10BackendObject::pipelineState_ offset must be 0xB4"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, d3dDevice_) == 0xC0,
      "DeviceD3D10BackendObject::d3dDevice_ offset must be 0xC0"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, streamStateD8_) == 0xD8,
      "DeviceD3D10BackendObject::streamStateD8_ offset must be 0xD8"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, outputContexts_) == 0x118,
      "DeviceD3D10BackendObject::outputContexts_ offset must be 0x118"
    );
    static_assert(
      offsetof(DeviceD3D10BackendObject, cursor_) == 0x11C,
      "DeviceD3D10BackendObject::cursor_ offset must be 0x11C"
    );
    static_assert(sizeof(DeviceD3D10BackendObject) == 0x128, "DeviceD3D10BackendObject size must be 0x128");

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

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format0[1] = {
      {0x00D433F8U, 0U, 16U, 0U, 0U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format1[1] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format2[2] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 6U, 0U, 12U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format3[2] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 12U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format4[3] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 1U, 16U, 0U, 20U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format5[3] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 6U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 24U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format6[3] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D43C40U, 0U, 28U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 16U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format7[2] = {
      {0x00D433F8U, 0U, 2U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 16U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format8[3] = {
      {0x00D433F8U, 0U, 2U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 16U, 0U, 0U},
      {0x00D433ECU, 1U, 16U, 0U, 24U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format9[7] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 6U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 0U, 16U, 0U, 24U, 0U, 0U},
      {0x00D433ECU, 1U, 2U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 2U, 2U, 1U, 16U, 1U, 1U},
      {0x00D433ECU, 3U, 2U, 1U, 32U, 1U, 1U},
      {0x00D433ECU, 4U, 2U, 1U, 48U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format10[1] = {
      {0x00D433F8U, 0U, 12U, 0U, 0U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format11[6] = {
      {0x00D433F8U, 0U, 2U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 2U, 0U, 16U, 0U, 0U},
      {0x00D433ECU, 1U, 2U, 0U, 32U, 0U, 0U},
      {0x00D433ECU, 2U, 6U, 0U, 48U, 0U, 0U},
      {0x00D433ECU, 3U, 2U, 0U, 60U, 0U, 0U},
      {0x00D433ECU, 4U, 6U, 0U, 76U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format12[3] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 6U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 1U, 6U, 0U, 24U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format13[4] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D433ECU, 0U, 2U, 0U, 12U, 0U, 0U},
      {0x00D433ECU, 1U, 2U, 0U, 28U, 0U, 0U},
      {0x00D433ECU, 2U, 2U, 0U, 44U, 0U, 0U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format14[17] = {
      {0x00D433F8U, 0U, 2U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 6U, 0U, 16U, 0U, 0U},
      {0x00D43C38U, 0U, 6U, 0U, 28U, 0U, 0U},
      {0x00D43C2CU, 0U, 6U, 0U, 40U, 0U, 0U},
      {0x00D433ECU, 0U, 2U, 0U, 52U, 0U, 0U},
      {0x00D43C1CU, 0U, 64U, 0U, 68U, 0U, 0U},
      {0x00D43C1CU, 1U, 64U, 0U, 69U, 0U, 0U},
      {0x00D43C1CU, 2U, 64U, 0U, 70U, 0U, 0U},
      {0x00D43C1CU, 3U, 64U, 0U, 71U, 0U, 0U},
      {0x00D433ECU, 1U, 6U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 2U, 6U, 1U, 12U, 1U, 1U},
      {0x00D433ECU, 3U, 6U, 1U, 24U, 1U, 1U},
      {0x00D433ECU, 4U, 6U, 1U, 36U, 1U, 1U},
      {0x00D433ECU, 5U, 30U, 1U, 48U, 1U, 1U},
      {0x00D433ECU, 6U, 2U, 1U, 52U, 1U, 1U},
      {0x00D43C40U, 0U, 28U, 1U, 68U, 1U, 1U},
      {0x00D433ECU, 7U, 41U, 1U, 72U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format15[17] = {
      {0x00D433F8U, 0U, 10U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 10U, 0U, 8U, 0U, 0U},
      {0x00D43C38U, 0U, 10U, 0U, 16U, 0U, 0U},
      {0x00D43C2CU, 0U, 10U, 0U, 24U, 0U, 0U},
      {0x00D433ECU, 0U, 10U, 0U, 32U, 0U, 0U},
      {0x00D43C1CU, 0U, 64U, 0U, 40U, 0U, 0U},
      {0x00D43C1CU, 1U, 64U, 0U, 41U, 0U, 0U},
      {0x00D43C1CU, 2U, 64U, 0U, 42U, 0U, 0U},
      {0x00D43C1CU, 3U, 64U, 0U, 43U, 0U, 0U},
      {0x00D433ECU, 1U, 6U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 2U, 6U, 1U, 12U, 1U, 1U},
      {0x00D433ECU, 3U, 6U, 1U, 24U, 1U, 1U},
      {0x00D433ECU, 4U, 6U, 1U, 36U, 1U, 1U},
      {0x00D433ECU, 5U, 28U, 1U, 48U, 1U, 1U},
      {0x00D433ECU, 6U, 10U, 1U, 52U, 1U, 1U},
      {0x00D43C40U, 0U, 28U, 1U, 60U, 1U, 1U},
      {0x00D433ECU, 7U, 41U, 1U, 64U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format16[18] = {
      {0x00D433F8U, 0U, 10U, 0U, 0U, 0U, 0U},
      {0x00D43C48U, 0U, 10U, 0U, 8U, 0U, 0U},
      {0x00D43C38U, 0U, 10U, 0U, 16U, 0U, 0U},
      {0x00D43C2CU, 0U, 10U, 0U, 24U, 0U, 0U},
      {0x00D433ECU, 0U, 10U, 0U, 32U, 0U, 0U},
      {0x00D43C1CU, 0U, 64U, 0U, 40U, 0U, 0U},
      {0x00D43C1CU, 1U, 64U, 0U, 41U, 0U, 0U},
      {0x00D43C1CU, 2U, 64U, 0U, 42U, 0U, 0U},
      {0x00D43C1CU, 3U, 64U, 0U, 43U, 0U, 0U},
      {0x00D433F8U, 1U, 10U, 1U, 0U, 0U, 0U},
      {0x00D433ECU, 1U, 6U, 2U, 0U, 1U, 1U},
      {0x00D433ECU, 2U, 6U, 2U, 12U, 1U, 1U},
      {0x00D433ECU, 3U, 6U, 2U, 24U, 1U, 1U},
      {0x00D433ECU, 4U, 6U, 2U, 36U, 1U, 1U},
      {0x00D433ECU, 5U, 28U, 2U, 48U, 1U, 1U},
      {0x00D433ECU, 6U, 10U, 2U, 52U, 1U, 1U},
      {0x00D43C40U, 0U, 28U, 2U, 60U, 1U, 1U},
      {0x00D433ECU, 7U, 41U, 2U, 64U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format17[3] = {
      {0x00D433F8U, 0U, 6U, 0U, 0U, 0U, 0U},
      {0x00D433F8U, 1U, 16U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 1U, 16U, 1U, 8U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format18[8] = {
      {0x00D433F8U, 0U, 16U, 0U, 0U, 0U, 0U},
      {0x00D433F8U, 1U, 2U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 0U, 16U, 1U, 16U, 1U, 1U},
      {0x00D433ECU, 1U, 2U, 1U, 24U, 1U, 1U},
      {0x00D433ECU, 2U, 6U, 1U, 40U, 1U, 1U},
      {0x00D433ECU, 3U, 2U, 1U, 52U, 1U, 1U},
      {0x00D433ECU, 4U, 6U, 1U, 68U, 1U, 1U},
      {0x00D433ECU, 5U, 6U, 1U, 80U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format19[4] = {
      {0x00D433F8U, 0U, 16U, 0U, 0U, 0U, 0U},
      {0x00D433F8U, 1U, 2U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 0U, 16U, 1U, 16U, 1U, 1U},
      {0x00D433ECU, 1U, 2U, 1U, 24U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format20[6] = {
      {0x00D433F8U, 0U, 16U, 0U, 0U, 0U, 0U},
      {0x00D433F8U, 1U, 2U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 0U, 6U, 1U, 16U, 1U, 1U},
      {0x00D433ECU, 1U, 16U, 1U, 28U, 1U, 1U},
      {0x00D433ECU, 2U, 16U, 1U, 36U, 1U, 1U},
      {0x00D433ECU, 3U, 2U, 1U, 44U, 1U, 1U},
    };

    constexpr VertexLayoutElementRuntime kVertexLayoutElements_Format21[4] = {
      {0x00D433F8U, 0U, 16U, 0U, 0U, 0U, 0U},
      {0x00D433F8U, 1U, 6U, 1U, 0U, 1U, 1U},
      {0x00D433ECU, 0U, 16U, 1U, 12U, 1U, 1U},
      {0x00D433ECU, 1U, 2U, 1U, 20U, 1U, 1U},
    };

    // Address: 0x00F311F8 (off_F311F8)
    constexpr const VertexLayoutElementRuntime* kVertexLayoutElementsByFormat[24] = {
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

    DeviceD3D10RuntimeView* ViewDeviceRuntime(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<DeviceD3D10RuntimeView*>(device);
    }

    DeviceD3D10BackendObject* AsDeviceD3D10BackendObject(DeviceD3D10* const device) noexcept
    {
      return static_cast<DeviceD3D10BackendObject*>(device);
    }

    OutputContext* GetDeviceOutputContext(DeviceD3D10* const device) noexcept
    {
      return &reinterpret_cast<DeviceOutputContextRuntime*>(device)->outputContext;
    }

    void* GetDeviceLogStorage(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<void*>(reinterpret_cast<DeviceD3D10IntroRuntime*>(device)->logStorage);
    }

    DeviceContext* GetDeviceContextLane(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<DeviceD3D10IntroRuntime*>(device)->deviceContext;
    }

    int GetDeviceCurrentThreadId(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<DeviceD3D10IntroRuntime*>(device)->currentThreadId;
    }

    CursorD3D10* GetDeviceCursorLane(DeviceD3D10* const device) noexcept
    {
      return &reinterpret_cast<DeviceCursorLaneRuntime*>(device)->cursor;
    }

    DeviceTechniqueBindingsRuntime* GetDeviceTechniqueBindings(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->techniqueBindings;
    }

    boost::detail::sp_counted_base* GetDeviceTechniqueBindingsCount(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->techniqueBindingsCount;
    }

    void* GetDeviceNativeHandle(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->nativeDevice;
    }

    void* GetDeviceSignatureEffect(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->signatureEffect;
    }

    void* GetDeviceStretchRectEffect(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->stretchRectEffect;
    }

    void* GetDeviceStretchRectTechnique(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->stretchRectTechnique;
    }

    void* GetDeviceStretchRectVertexBuffer(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->stretchRectVertexBuffer;
    }

    void* GetDeviceStretchRectInputLayout(DeviceD3D10* const device) noexcept
    {
      return ViewDeviceRuntime(device)->stretchRectInputLayout;
    }

    void* GetDeviceHeadArrayBase(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<DeviceHeadArrayRuntime*>(device)->headsBase;
    }

    std::uint32_t GetDeviceHeadCount(DeviceD3D10* const device) noexcept
    {
      const DeviceContext* const context = GetDeviceContextLane(device);
      if (context == nullptr) {
        return 0U;
      }

      const auto* const headRange = reinterpret_cast<const DeviceContextHeadRangeRuntime*>(context);
      if ((headRange->headsBegin == nullptr) || (headRange->headsEnd == nullptr)) {
        return 0U;
      }

      if (headRange->headsEnd < headRange->headsBegin) {
        return 0U;
      }

      return static_cast<std::uint32_t>((headRange->headsEnd - headRange->headsBegin) >> 7U);
    }

    WeakRefCountedToken** GetDeviceVertexStreamRefArray(DeviceD3D10* const device) noexcept
    {
      auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(ViewDeviceRuntime(device));
      return reinterpret_cast<WeakRefCountedToken**>(runtimeBytes + offsetof(DeviceD3D10RuntimeView, vertexStreamRefs));
    }

    std::uint32_t GetDeviceInstanceCount(DeviceD3D10* const device) noexcept
    {
      auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(device);
      return *reinterpret_cast<const std::uint32_t*>(runtimeBytes + 0xD8);
    }

    DeviceSwapChainRangeRuntime* GetDeviceSwapChainRange(DeviceD3D10* const device) noexcept
    {
      return reinterpret_cast<DeviceSwapChainRangeRuntime*>(device);
    }

    std::uint32_t ConvertCursorPixelRgbaToBgra(const std::uint32_t rgba) noexcept
    {
      return (rgba & 0xFF000000U) | ((rgba & 0x000000FFU) << 16U) | (rgba & 0x0000FF00U) |
        ((rgba & 0x00FF0000U) >> 16U);
    }

    void BeginCursorPixelTransfer(
      CursorPixelSourceRuntime* const source, CursorPixelTransferTokenRuntime& transfer, std::uint32_t (&metadata)[4]
    )
    {
      auto* const beginTransfer = reinterpret_cast<cursor_source_lock_fn>(source->vtable[2]);
      beginTransfer(source, &transfer, 0, metadata, 2);
    }

    void EndCursorPixelTransfer(CursorPixelSourceRuntime* const source, const CursorPixelTransferTokenRuntime& transfer)
    {
      auto* const endTransfer = reinterpret_cast<cursor_source_unlock_fn>(source->vtable[4]);
      endTransfer(source, transfer.token0, transfer.token1, transfer.rowPitchBytes, transfer.dataPointer);
    }

    /**
     * Address: 0x008F8130 (FUN_008F8130)
     *
     * int,int,CursorPixelSourceRuntime *,boost::detail::sp_counted_base *
     *
     * What it does:
     * Builds a 32x32 ARGB cursor icon from one runtime pixel source, applying
     * channel-swap and bottom-up row conversion, then releases one retained
     * shared-count lane before returning the icon handle.
     */
    void* BuildCursorIcon(
      const int hotspotX,
      const int hotspotY,
      CursorPixelSourceRuntime* const source,
      boost::detail::sp_counted_base* const sharedCount
    )
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

      CursorPixelTransferTokenRuntime transfer{};
      std::uint32_t transferMetadata[4]{};
      BeginCursorPixelTransfer(source, transfer, transferMetadata);

      auto* const destinationPixels = reinterpret_cast<std::uint32_t*>(dibPixels);
      const auto* const sourceBytes =
        reinterpret_cast<const std::uint8_t*>(static_cast<std::uintptr_t>(transfer.dataPointer));
      const std::uint32_t rowPitchBytes = transfer.rowPitchBytes;
      const auto* sourceRow = reinterpret_cast<const std::uint32_t*>(sourceBytes + (rowPitchBytes * 31U));

      for (std::uint32_t y = 0; y < 32U; ++y) {
        for (std::uint32_t x = 0; x < 32U; ++x) {
          destinationPixels[(y * 32U) + x] = ConvertCursorPixelRgbaToBgra(sourceRow[x]);
        }

        sourceRow =
          reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const std::uint8_t*>(sourceRow) - rowPitchBytes);
      }

      EndCursorPixelTransfer(source, transfer);

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

      if (sharedCount != nullptr) {
        sharedCount->release();
      }

      return iconHandle;
    }

    void* GetDeviceActiveRenderTargetContextRaw(DeviceD3D10* const device) noexcept
    {
      auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(device);
      return *reinterpret_cast<void**>(runtimeBytes + 0x14);
    }

    void* GetDeviceActiveDepthStencilContextRaw(DeviceD3D10* const device) noexcept
    {
      auto* const runtimeBytes = reinterpret_cast<std::uint8_t*>(device);
      return *reinterpret_cast<void**>(runtimeBytes + 0x1C);
    }

    IndexBufferContextRuntime* InvokeIndexBufferGetContext(IndexBufferD3D10* const indexBuffer)
    {
      auto** const vtable = *reinterpret_cast<void***>(indexBuffer);
      auto* const getContext = reinterpret_cast<index_buffer_get_context_fn>(vtable[1]);
      return reinterpret_cast<IndexBufferContextRuntime*>(getContext(indexBuffer));
    }

    VertexBufferContextRuntime* InvokeVertexBufferGetContext(VertexBufferD3D10* const vertexBuffer)
    {
      auto** const vtable = *reinterpret_cast<void***>(vertexBuffer);
      auto* const getContext = reinterpret_cast<vertex_buffer_get_context_fn>(vtable[1]);
      return reinterpret_cast<VertexBufferContextRuntime*>(getContext(vertexBuffer));
    }

    int InvokeNativeClearShaderResourceSlot(
      DeviceTechniqueBindingsRuntime* const bindings, const unsigned int startSlot, void* const* const views
    )
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->nativeDevice);
      auto* const setShaderResources = reinterpret_cast<device_native_set_shader_resources_fn>(vtable[4]);
      return setShaderResources(bindings->nativeDevice, startSlot, 1U, views);
    }

    void InvokeNativeSetRasterizerState(DeviceTechniqueBindingsRuntime* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->nativeDevice);
      auto* const setRasterizerState = reinterpret_cast<device_native_set_rasterizer_state_fn>(vtable[29]);
      setRasterizerState(bindings->nativeDevice, bindings->rasterizerState);
    }

    void InvokeNativeSetDepthStencilState(DeviceTechniqueBindingsRuntime* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->nativeDevice);
      auto* const setDepthStencilState = reinterpret_cast<device_native_set_depth_stencil_state_fn>(vtable[26]);
      setDepthStencilState(bindings->nativeDevice, bindings->depthStencilState, 0U);
    }

    int InvokeNativeSetBlendState(DeviceTechniqueBindingsRuntime* const bindings)
    {
      auto** const vtable = *reinterpret_cast<void***>(bindings->nativeDevice);
      auto* const setBlendState = reinterpret_cast<device_native_set_blend_state_fn>(vtable[25]);
      return setBlendState(bindings->nativeDevice, bindings->blendState, nullptr, static_cast<unsigned int>(-1));
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
      const VertexLayoutElementRuntime* const elements,
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

    int InvokeNativeSetViewport(DeviceD3D10* const device, const ViewportRuntime* const viewport)
    {
      void* const nativeDevice = GetDeviceNativeHandle(device);
      auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
      auto* const setViewports = reinterpret_cast<device_native_set_viewports_fn>(vtable[30]);
      return setViewports(nativeDevice, 1U, viewport);
    }

    void InvokeNativeGetViewport(
      DeviceD3D10* const device, unsigned int* const viewportCount, ViewportRuntime* const outViewport
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

    HRESULT InvokeSwapChainPresent(void* const swapChain, const unsigned int syncInterval, const unsigned int flags)
    {
      auto** const vtable = *reinterpret_cast<void***>(swapChain);
      auto* const present = reinterpret_cast<swap_chain_present_fn>(vtable[8]);
      return present(swapChain, syncInterval, flags);
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

    void InvokeTechniqueGetPassCount(void* const technique, TechniquePassCountRuntime* const outPassCount);
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
      ViewportRuntime savedViewport{};
      unsigned int savedViewportCount = 1U;
      InvokeNativeGetViewport(device, &savedViewportCount, &savedViewport);

      if (destinationRenderTargetView != nullptr) {
        ViewportRuntime fullscreenViewport{};
        fullscreenViewport.width = destinationWidth;
        fullscreenViewport.height = destinationHeight;
        fullscreenViewport.minDepth = 0.0f;
        fullscreenViewport.maxDepth = 1.0f;
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

      TechniquePassCountRuntime passCountRuntime{};
      InvokeTechniqueGetPassCount(GetDeviceStretchRectTechnique(device), &passCountRuntime);

      for (unsigned int passIndex = 0U; passIndex < passCountRuntime.passCount; ++passIndex) {
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
    int ClearAllTextureShaderResourceSlots(DeviceTechniqueBindingsRuntime* const bindings)
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
    int ApplyTechniqueStateBindings(DeviceTechniqueBindingsRuntime* const bindings)
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

    void* InvokeDeviceGetContext(Device* const device)
    {
      auto** const vtable = *reinterpret_cast<void***>(device);
      auto* const getContext = reinterpret_cast<device_get_context_fn>(vtable[2]);
      return getContext(device);
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

    HRESULT InvokeEffectGetDesc(void* const effect, D3D10EffectDescRuntime* const outDesc)
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

    HRESULT InvokeTechniqueGetDesc(void* const technique, D3D10TechniqueDescRuntime* const outDesc)
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

    void InvokeTechniqueGetPassCount(void* const technique, TechniquePassCountRuntime* const outPassCount)
    {
      auto** const vtable = *reinterpret_cast<void***>(technique);
      auto* const getPassCount = reinterpret_cast<technique_get_pass_counter_fn>(vtable[1]);
      getPassCount(technique, outPassCount);
    }

    HRESULT InvokePassGetDesc(void* const pass, D3D10PassDescRuntime* const outDesc)
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

    struct EffectContextLane54Runtime final
    {
      void* proxy = nullptr;        // +0x00
      EffectMacro* first = nullptr; // +0x04
      EffectMacro* last = nullptr;  // +0x08
      EffectMacro* end = nullptr;   // +0x0C
    };

    struct EffectContextRuntime final
    {
      void* vftable = nullptr;                                 // +0x00
      std::uint32_t field04 = 0U;                              // +0x04
      std::uint8_t field08 = 0U;                               // +0x08
      std::uint8_t pad09_0B[3]{};                              // +0x09 .. +0x0B
      msvc8::string field0C{};                                 // +0x0C
      msvc8::string field28{};                                 // +0x28
      std::uint32_t field44 = 0U;                              // +0x44
      boost::detail::sp_counted_base* sharedCount48 = nullptr; // +0x48
      std::uint32_t field4C = 0U;                              // +0x4C
      std::uint32_t field50 = 0U;                              // +0x50
      EffectContextLane54Runtime lane54{};                     // +0x54
    };

    static_assert(offsetof(EffectContextRuntime, field04) == 0x04, "EffectContextRuntime::field04 offset must be 0x04");
    static_assert(offsetof(EffectContextRuntime, field08) == 0x08, "EffectContextRuntime::field08 offset must be 0x08");
    static_assert(offsetof(EffectContextRuntime, field0C) == 0x0C, "EffectContextRuntime::field0C offset must be 0x0C");
    static_assert(offsetof(EffectContextRuntime, field28) == 0x28, "EffectContextRuntime::field28 offset must be 0x28");
    static_assert(offsetof(EffectContextRuntime, field44) == 0x44, "EffectContextRuntime::field44 offset must be 0x44");
    static_assert(
      offsetof(EffectContextRuntime, sharedCount48) == 0x48, "EffectContextRuntime::sharedCount48 offset must be 0x48"
    );
    static_assert(offsetof(EffectContextRuntime, field4C) == 0x4C, "EffectContextRuntime::field4C offset must be 0x4C");
    static_assert(offsetof(EffectContextRuntime, field50) == 0x50, "EffectContextRuntime::field50 offset must be 0x50");
    static_assert(offsetof(EffectContextRuntime, lane54) == 0x54, "EffectContextRuntime::lane54 offset must be 0x54");
    static_assert(sizeof(EffectContextLane54Runtime) == 0x10, "EffectContextLane54Runtime size must be 0x10");
    static_assert(sizeof(EffectContextRuntime) == 0x64, "EffectContextRuntime size must be 0x64");

    EffectContextRuntime* AsEffectContextRuntime(EffectD3D10* const effect) noexcept
    {
      return reinterpret_cast<EffectContextRuntime*>(&effect->context_);
    }

    const EffectContextRuntime* AsEffectContextRuntime(const EffectContext* const context) noexcept
    {
      return reinterpret_cast<const EffectContextRuntime*>(context);
    }

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

    void InvokeTextureGetDesc(void* const texture, TextureDescRuntime* const outDesc)
    {
      auto** const vtable = *reinterpret_cast<void***>(texture);
      auto* const getDesc = reinterpret_cast<texture_get_desc_fn>(vtable[12]);
      getDesc(texture, outDesc);
    }

    HRESULT InvokeTextureMap(
      void* const texture, const int level, const unsigned int mapMode, TextureMapResultRuntime* const outMapped
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
      auto* const helper = *reinterpret_cast<device_helper34_fn*>(reinterpret_cast<std::uint8_t*>(device) + 0x34);
      return helper(device, mode, outValue);
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
      auto* const helper = *reinterpret_cast<device_helper44_fn*>(reinterpret_cast<std::uint8_t*>(device) + 0x44);
      return helper(device, texture, mode, outValue);
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
    [[maybe_unused]] DXGI_SWAP_CHAIN_DESC*
    BuildSwapChainDescFromHeadRuntime(DXGI_SWAP_CHAIN_DESC* const outDesc, const void* const headRaw)
    {
      std::memset(outDesc, 0, sizeof(DXGI_SWAP_CHAIN_DESC));
      const auto* const runtime = reinterpret_cast<const HeadRuntime*>(headRaw);
      if (runtime->window == nullptr) {
        return outDesc;
      }

      outDesc->BufferDesc.Width = runtime->width;
      outDesc->BufferDesc.Height = runtime->height;
      outDesc->BufferDesc.Format = static_cast<DXGI_FORMAT>(0x1C);
      outDesc->BufferDesc.RefreshRate.Numerator = (runtime->windowed != 0U) ? runtime->framesPerSecond : 0U;
      outDesc->BufferDesc.RefreshRate.Denominator = 1U;
      outDesc->BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
      outDesc->BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
      outDesc->SampleDesc.Count = 1U;
      outDesc->SampleDesc.Quality = 0U;
      outDesc->BufferUsage = 48U;
      outDesc->BufferCount = 2U;
      outDesc->OutputWindow = runtime->window;
      outDesc->Windowed = (runtime->windowed == 0U);
      outDesc->SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
      outDesc->Flags = 0U;
      return outDesc;
    }

    /**
     * Address: 0x008F8AF0 (FUN_008F8AF0)
     *
     * void const *
     *
     * What it does:
     * Returns `(end-begin)/0x13C` for one runtime span payload when the
     * begin pointer lane is non-null.
     */
    [[maybe_unused]] int CountEntriesStride13C(const void* const runtimeSpan) noexcept
    {
      const auto* const lanes = reinterpret_cast<const std::uintptr_t*>(runtimeSpan);
      const std::uintptr_t begin = lanes[1];
      if (begin == 0U) {
        return 0;
      }

      const std::uintptr_t end = lanes[2];
      return static_cast<int>((end - begin) / 0x13CU);
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
     * Address: 0x008F8D90 (FUN_008F8D90)
     *
     * void **
     *
     * What it does:
     * Releases one COM-like pointer lane (if present) and clears the slot.
     */
    [[maybe_unused]] int ReleaseComSlotVariant1(void** const slot) noexcept
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
    [[maybe_unused]] int ReleaseComSlotVariant2(void** const slot) noexcept
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
    [[maybe_unused]] int ReleaseComSlotVariant3(void** const slot) noexcept
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
    [[maybe_unused]] int ReleaseComSlotVariant4(void** const slot) noexcept
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
     * Address: 0x008F8E70 (FUN_008F8E70)
     *
     * uint32_t
     *
     * What it does:
     * Allocates `count * 0x13C` bytes with overflow guard and throws
     * `std::bad_alloc` on overflow.
     */
    [[maybe_unused]] void* AllocateStride13CArray(const std::uint32_t count)
    {
      return AllocateArrayOrThrow(count, 0x13CU);
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
    [[maybe_unused]] void* AllocateStride04Array(const std::uint32_t count)
    {
      return AllocateArrayOrThrow(count, 0x04U);
    }

    device_create_blob_api_fn GetDeviceCreateBlobApi(DeviceD3D10* const device) noexcept
    {
      return *reinterpret_cast<device_create_blob_api_fn*>(reinterpret_cast<std::uint8_t*>(device) + 0x34);
    }

    device_create_effect_from_memory_api_fn GetDeviceCreateEffectFromMemoryApi(DeviceD3D10* const device) noexcept
    {
      return *reinterpret_cast<device_create_effect_from_memory_api_fn*>(
        reinterpret_cast<std::uint8_t*>(device) + 0x38
      );
    }

    device_create_texture_from_memory_api_fn GetDeviceCreateTextureFromMemoryApi(DeviceD3D10* const device) noexcept
    {
      return *reinterpret_cast<device_create_texture_from_memory_api_fn*>(
        reinterpret_cast<std::uint8_t*>(device) + 0x3C
      );
    }

    device_save_texture_to_file_api_fn GetDeviceSaveTextureToFileApi(DeviceD3D10* const device) noexcept
    {
      return *reinterpret_cast<device_save_texture_to_file_api_fn*>(reinterpret_cast<std::uint8_t*>(device) + 0x40);
    }

    device_save_texture_to_memory_api_fn GetDeviceSaveTextureToMemoryApi(DeviceD3D10* const device) noexcept
    {
      return *reinterpret_cast<device_save_texture_to_memory_api_fn*>(reinterpret_cast<std::uint8_t*>(device) + 0x44);
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
      void** const outEffect,
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
        GetDeviceNativeHandle(device),
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
     * Address: 0x008F7550 (FUN_008F7550)
     *
     * What it does:
     * Tears down per-mode dynamic storage lanes for each adapter-mode entry
     * in `[begin, end)`.
     */
    void DestroyAdapterModeRuntimeRange(AdapterModeD3D10* begin, AdapterModeD3D10* const end)
    {
      while (begin != end) {
        auto& modesRuntime = msvc8::AsVectorRuntimeView(begin->modes_);
        if (modesRuntime.begin != nullptr) {
          ::operator delete(modesRuntime.begin);
        }

        modesRuntime.begin = nullptr;
        modesRuntime.end = nullptr;
        modesRuntime.capacityEnd = nullptr;
        ++begin;
      }
    }

    /**
     * Address: 0x008F7B30 (FUN_008F7B30, gpg::gal::AdapterD3D10 destructor body)
     *
     * What it does:
     * Destroys per-entry mode vectors, frees the outer adapter-mode storage,
     * and clears begin/end/capacity lanes.
     */
    void DestroyAdapterModeVectorStorage(msvc8::vector<AdapterModeD3D10>& modes) noexcept
    {
      auto& runtime = msvc8::AsVectorRuntimeView(modes);
      if (runtime.begin != nullptr) {
        DestroyAdapterModeRuntimeRange(runtime.begin, runtime.end);
        ::operator delete(runtime.begin);
      }

      runtime.begin = nullptr;
      runtime.end = nullptr;
      runtime.capacityEnd = nullptr;
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

    int MapDxgiToGalRenderTargetFormat(const int dxgiFormat)
    {
      for (const DXGIFormatPair& pair : kRenderTargetDxgiGalPairs) {
        if (pair.dxgi == dxgiFormat) {
          return pair.gal;
        }
      }

      return 8;
    }

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
      DeviceD3D10* const device, const int formatToken, D3D10PassDescRuntime* const outPassDesc
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
      TextureDescRuntime textureDesc{};
      InvokeTextureGetDesc(sourceTexture, &textureDesc);
      textureDesc.usage = 3U;
      textureDesc.bindFlags = 0U;
      textureDesc.cpuAccessFlags = 0x20000U;

      void* const nativeDevice = *reinterpret_cast<void**>(reinterpret_cast<std::uint8_t*>(device) + 0xC0);
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
     * Address: 0x009032F0 (FUN_009032F0)
     *
     * What it does:
     * Represents the base-vftable unwind lane used by `TextureD3D10` destructor SEH
     * tails in the binary.
     */
    void ApplyTextureBaseVftableLane(TextureD3D10* const texture)
    {
      static_cast<void>(texture);
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
      ApplyTextureBaseVftableLane(texture);
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
    const VertexLayoutElementRuntime* GetVertexLayoutElementsOrThrow(const std::uint32_t format)
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
     * Address: 0x008FA550 (FUN_008FA550, boost::shared_ptr_RenderTargetD3D10::operator=)
     *
     * What it does:
     * Rebinds one `shared_ptr<RenderTargetD3D10>` from one raw render-target
     * pointer and releases previous ownership.
     */
    boost::shared_ptr<RenderTargetD3D10>* AssignSharedRenderTargetD3D10FromRaw(
      boost::shared_ptr<RenderTargetD3D10>* const outRenderTarget, RenderTargetD3D10* const renderTarget
    )
    {
      outRenderTarget->reset(renderTarget);
      return outRenderTarget;
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

    std::size_t EffectMacroCount(const EffectContextLane54Runtime& runtime) noexcept
    {
      if (runtime.first == nullptr) {
        return 0U;
      }

      return static_cast<std::size_t>(runtime.last - runtime.first);
    }

    std::size_t EffectMacroCapacity(const EffectContextLane54Runtime& runtime) noexcept
    {
      if (runtime.first == nullptr) {
        return 0U;
      }

      return static_cast<std::size_t>(runtime.end - runtime.first);
    }

    void DestroyEffectMacroRange(EffectMacro* first, EffectMacro* last) noexcept
    {
      while (first != last) {
        first->~EffectMacro();
        ++first;
      }
    }

    void DestroyEffectMacroStorage(EffectContextLane54Runtime& runtime) noexcept
    {
      if (runtime.first != nullptr) {
        DestroyEffectMacroRange(runtime.first, runtime.last);
        ::operator delete(static_cast<void*>(runtime.first));
      }

      runtime.first = nullptr;
      runtime.last = nullptr;
      runtime.end = nullptr;
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

    bool TryReserveEffectMacroStorage(EffectContextLane54Runtime& runtime, const std::size_t elementCount) noexcept
    {
      if (elementCount == 0U) {
        runtime.first = nullptr;
        runtime.last = nullptr;
        runtime.end = nullptr;
        return false;
      }

      if (elementCount > 0x04444444U) {
        ThrowVectorTooLongLengthErrorA();
      }

      try {
        auto* const storage = static_cast<EffectMacro*>(::operator new(sizeof(EffectMacro) * elementCount));
        runtime.first = storage;
        runtime.last = storage;
        runtime.end = storage + elementCount;
        return true;
      } catch (...) {
        runtime.first = nullptr;
        runtime.last = nullptr;
        runtime.end = nullptr;
        return false;
      }
    }

    EffectMacro* CopyAssignEffectMacroRange(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      const EffectMacro* read = sourceFirst;
      EffectMacro* write = destinationFirst;
      while (read != sourceLast) {
        write->keyText_.assign(read->keyText_, 0U, msvc8::string::npos);
        write->valueText_.assign(read->valueText_, 0U, msvc8::string::npos);
        ++read;
        ++write;
      }

      return write;
    }

    /**
     * Address: 0x008FAB30 (FUN_008FAB30)
     *
     * What it does:
     * Conditionally copy-constructs one `EffectMacro` entry at destination and
     * returns destination.
     */
    EffectMacro* ConstructEffectMacroIfPresent(EffectMacro* const destination, const EffectMacro& source)
    {
      if (destination != nullptr) {
        ::new (static_cast<void*>(destination)) EffectMacro(source);
      }

      return destination;
    }

    /**
     * Address: 0x0093F810 (FUN_0093F810)
     *
     * What it does:
     * Copy-constructs one contiguous uninitialized destination range from one
     * source `[first,last)` effect-macro range.
     */
    EffectMacro* UninitializedCopyEffectMacroRangeCore(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      const EffectMacro* read = sourceFirst;
      EffectMacro* write = destinationFirst;
      try {
        while (read != sourceLast) {
          ConstructEffectMacroIfPresent(write, *read);
          ++read;
          ++write;
        }
      }
      catch (...) {
        DestroyEffectMacroRange(destinationFirst, write);
        throw;
      }

      return write;
    }

    /**
     * Address: 0x0093FA10 (FUN_0093FA10)
     *
     * What it does:
     * Copy-constructs `count` effect-macro entries from one source entry into
     * contiguous uninitialized destination lanes.
     */
    [[maybe_unused]] EffectMacro* UninitializedFillEffectMacroRangeCore(
      EffectMacro* destinationFirst, std::size_t count, const EffectMacro& source
    )
    {
      EffectMacro* write = destinationFirst;
      try {
        while (count != 0U) {
          ConstructEffectMacroIfPresent(write, source);
          ++write;
          --count;
        }
      }
      catch (...) {
        DestroyEffectMacroRange(destinationFirst, write);
        throw;
      }

      return write;
    }

    EffectMacro* UninitializedCopyEffectMacroRange(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      return UninitializedCopyEffectMacroRangeCore(sourceFirst, sourceLast, destinationFirst);
    }

    /**
     * Address: 0x0093FB20 (FUN_0093FB20)
     *
     * What it does:
     * Dispatch bridge into the core uninitialized `EffectMacro` range-copy
     * helper.
     */
    [[maybe_unused]] EffectMacro* UninitializedCopyEffectMacroRangeDispatchA(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      return UninitializedCopyEffectMacroRangeCore(sourceFirst, sourceLast, destinationFirst);
    }

    /**
     * Address: 0x0093FBC0 (FUN_0093FBC0)
     *
     * What it does:
     * Dispatch bridge into the core uninitialized `EffectMacro` range-copy
     * helper.
     */
    [[maybe_unused]] EffectMacro* UninitializedCopyEffectMacroRangeDispatchB(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      return UninitializedCopyEffectMacroRangeCore(sourceFirst, sourceLast, destinationFirst);
    }

    /**
     * Address: 0x0093FC50 (FUN_0093FC50)
     *
     * What it does:
     * Dispatch bridge into the core uninitialized `EffectMacro` fill helper.
     */
    [[maybe_unused]] EffectMacro* UninitializedFillEffectMacroRangeDispatchA(
      EffectMacro* destinationFirst, const std::size_t count, const EffectMacro& source
    )
    {
      return UninitializedFillEffectMacroRangeCore(destinationFirst, count, source);
    }

    /**
     * Address: 0x0093FC90 (FUN_0093FC90)
     *
     * What it does:
     * Dispatch bridge into the core uninitialized `EffectMacro` range-copy
     * helper.
     */
    [[maybe_unused]] EffectMacro* UninitializedCopyEffectMacroRangeDispatchC(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      return UninitializedCopyEffectMacroRangeCore(sourceFirst, sourceLast, destinationFirst);
    }

    /**
     * Address: 0x0093FE80 (FUN_0093FE80)
     *
     * What it does:
     * Dispatch bridge into the core uninitialized `EffectMacro` range-copy
     * helper.
     */
    [[maybe_unused]] EffectMacro* UninitializedCopyEffectMacroRangeDispatchD(
      const EffectMacro* sourceFirst, const EffectMacro* sourceLast, EffectMacro* destinationFirst
    )
    {
      return UninitializedCopyEffectMacroRangeCore(sourceFirst, sourceLast, destinationFirst);
    }

    void AssignEffectContextLane54(EffectContextLane54Runtime& destination, const EffectContextLane54Runtime& source)
    {
      if (&destination == &source) {
        return;
      }

      const std::size_t sourceCount = EffectMacroCount(source);
      if (sourceCount == 0U) {
        DestroyEffectMacroRange(destination.first, destination.last);
        destination.last = destination.first;
        return;
      }

      const std::size_t destinationSize = EffectMacroCount(destination);
      if (sourceCount > destinationSize) {
        const std::size_t destinationCapacity = EffectMacroCapacity(destination);
        if (sourceCount <= destinationCapacity) {
          EffectMacro* const splitSource = source.first + destinationSize;
          CopyAssignEffectMacroRange(source.first, splitSource, destination.first);
          destination.last = UninitializedCopyEffectMacroRange(splitSource, source.last, destination.last);
          return;
        }

        DestroyEffectMacroStorage(destination);
        if (TryReserveEffectMacroStorage(destination, sourceCount)) {
          destination.last = UninitializedCopyEffectMacroRange(source.first, source.last, destination.first);
        }
        return;
      }

      EffectMacro* const compactedEnd = CopyAssignEffectMacroRange(source.first, source.last, destination.first);
      DestroyEffectMacroRange(compactedEnd, destination.last);
      destination.last = destination.first + sourceCount;
    }

    EffectContextRuntime*
    CopyEffectContextRuntime(EffectContextRuntime* const destination, const EffectContextRuntime* const source)
    {
      if (destination == source) {
        return destination;
      }

      destination->field04 = source->field04;
      destination->field08 = source->field08;
      destination->field0C.assign(source->field0C, 0U, msvc8::string::npos);
      destination->field28.assign(source->field28, 0U, msvc8::string::npos);
      destination->field44 = source->field44;
      AssignSharedCount(destination->sharedCount48, source->sharedCount48);
      destination->field4C = source->field4C;
      destination->field50 = source->field50;
      AssignEffectContextLane54(destination->lane54, source->lane54);
      return destination;
    }

    void InitializeEffectContextRuntimeStorage(EffectContextRuntime& context)
    {
      context.field04 = 0U;
      context.field08 = 0U;
      context.pad09_0B[0] = 0U;
      context.pad09_0B[1] = 0U;
      context.pad09_0B[2] = 0U;
      ::new (static_cast<void*>(&context.field0C)) msvc8::string();
      ::new (static_cast<void*>(&context.field28)) msvc8::string();
      context.field44 = 0U;
      context.sharedCount48 = nullptr;
      context.field4C = 0U;
      context.field50 = 0U;
      context.lane54 = {};
    }

    void DestroyEffectContextRuntimeStorage(EffectContextRuntime& context) noexcept
    {
      ReleaseSharedCount(context.sharedCount48);
      DestroyEffectMacroStorage(context.lane54);
      context.field0C.tidy(true, 0U);
      context.field28.tidy(true, 0U);
      context.field44 = 0U;
      context.field4C = 0U;
      context.field50 = 0U;
      context.lane54.proxy = nullptr;
    }

    /**
     * Address: 0x0094B580 (FUN_0094B580)
     *
     * What it does:
     * Initializes EffectD3D10 runtime storage lanes and clears retained effect handle.
     */
    void InitializeEffectD3D10Object(EffectD3D10* const effect)
    {
      InitializeEffectContextRuntimeStorage(*AsEffectContextRuntime(effect));
      effect->dxEffect_ = nullptr;
    }

    /**
     * Address: 0x0094BF10 (FUN_0094BF10)
     *
     * What it does:
     * Releases retained effect object and resets embedded `EffectContext` state lanes.
     */
    void DestroyEffectD3D10State(EffectD3D10* const effect)
    {
      ReleaseComLike(effect->dxEffect_);

      const EffectContextRuntime resetContext{};
      CopyEffectContextRuntime(AsEffectContextRuntime(effect), &resetContext);
    }

    /**
     * Address: 0x0094BF80 (FUN_0094BF80)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `EffectD3D10`.
     */
    void DestroyEffectD3D10Body(EffectD3D10* const effect)
    {
      DestroyEffectD3D10State(effect);
      DestroyEffectContextRuntimeStorage(*AsEffectContextRuntime(effect));
    }

    /**
     * Address: 0x0094BFE0 (FUN_0094BFE0)
     *
     * What it does:
     * Rebuilds effect state from caller-provided context/effect handles and clears
     * context runtime shared-count lanes (`+0x48/+0x4C/+0x50`).
     */
    void InitializeEffectD3D10State(
      EffectD3D10* const effect, const EffectContext* const sourceContext, void* const dxEffect
    )
    {
      DestroyEffectD3D10State(effect);

      EffectContextRuntime* const runtime = AsEffectContextRuntime(effect);
      CopyEffectContextRuntime(runtime, AsEffectContextRuntime(sourceContext));
      effect->dxEffect_ = dxEffect;

      runtime->field44 = 0U;
      ReleaseSharedCount(runtime->sharedCount48);
      runtime->field4C = 0U;
      runtime->field50 = 0U;
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

    template <class T>
    void DestroyVectorOwnedStorage(msvc8::vector<T>& storage) noexcept
    {
      T* const begin = storage.begin();
      storage.clear();
      if (begin != nullptr) {
        ::operator delete(static_cast<void*>(begin));
      }
      storage.reset_range_lanes_preserve_proxy();
    }

    /**
     * Address: 0x008FA920 (FUN_008FA920)
     *
     * What it does:
     * Runs `AdapterD3D10` range destruction for one retained adapter vector and
     * releases the owned storage lane while preserving the proxy lane.
     */
    void DestroyDeviceAdapterStorage(msvc8::vector<AdapterD3D10>& adapters) noexcept
    {
      DestroyVectorOwnedStorage(adapters);
    }

    /**
     * Address: 0x008FAA40 (FUN_008FAA40)
     *
     * What it does:
     * Preserves the one-jump thunk lane into `DestroyDeviceAdapterStorage`.
     */
    void DestroyDeviceAdapterStorageThunk(msvc8::vector<AdapterD3D10>& adapters) noexcept
    {
      DestroyDeviceAdapterStorage(adapters);
    }

    /**
     * Address: 0x009001B0 (FUN_009001B0)
     *
     * What it does:
     * Releases startup/runtime-owned D3D10 device resources and resets recovered
     * context/module lanes.
     */
    BOOL ResetDeviceD3D10Runtime(DeviceD3D10BackendObject* const backend)
    {
      if (backend == nullptr) {
        return FALSE;
      }

      if (backend->outputContexts_ != nullptr) {
        delete[] reinterpret_cast<OutputContext*>(backend->outputContexts_);
        backend->outputContexts_ = nullptr;
      }

      void** const swapChainsBegin = backend->swapChains_.begin();
      void** const swapChainsEnd = backend->swapChains_.end();
      if ((swapChainsBegin != nullptr) && (swapChainsEnd != nullptr)) {
        for (void** it = swapChainsBegin; it != swapChainsEnd; ++it) {
          void* swapChain = *it;
          ReleaseComLike(swapChain);
          *it = nullptr;
        }
      }
      backend->swapChains_.clear();

      backend->adapters_.clear();
      backend->pipelineState_.reset();

      ReleaseComLike(backend->dxgiFactory_);
      ReleaseComLike(backend->d3dDevice_);
      ReleaseComLike(backend->effectPreamble_);
      ReleaseComLike(backend->shaderPreamble_);
      ReleaseComLike(backend->stretchRectBuffer_);
      ReleaseComLike(backend->stretchRectInputLayout_);

      backend->cursor_.Destroy();
      backend->deviceContext_ = DeviceContext(0);
      backend->logStorage_.clear();
      backend->currentThreadId_ = 0;

      ::FreeLibrary(backend->dxgiModule_);
      backend->dxgiModule_ = nullptr;

      ::FreeLibrary(backend->d3dModuleSecondary_);
      backend->d3dModuleSecondary_ = nullptr;

      const BOOL result = ::FreeLibrary(backend->d3dModulePrimary_);
      backend->d3dModulePrimary_ = nullptr;

      backend->createDeviceApi_ = nullptr;
      backend->createBlobApi_ = nullptr;
      backend->createEffectFromMemoryApi_ = nullptr;
      backend->createTextureFromMemoryApi_ = nullptr;
      backend->saveTextureToFileApi_ = nullptr;
      backend->saveTextureToMemoryApi_ = nullptr;
      backend->createDxgiFactoryApi_ = nullptr;
      return result;
    }

    /**
     * Address: 0x00900450 (FUN_00900450)
     *
     * What it does:
     * Executes non-deleting destructor body lanes for `DeviceD3D10` by running
     * runtime reset, then final member teardown/deallocation in binary order.
     */
    void DestroyDeviceD3D10Body(DeviceD3D10BackendObject* const backend)
    {
      if (backend == nullptr) {
        return;
      }

      static_cast<void>(ResetDeviceD3D10Runtime(backend));
      backend->cursor_.~CursorD3D10();
      backend->pipelineState_.reset();
      DestroyVectorOwnedStorage(backend->swapChains_);
      DestroyDeviceAdapterStorageThunk(backend->adapters_);
      backend->deviceContext_.~DeviceContext();
      DestroyVectorOwnedStorage(backend->logStorage_);
      backend->outputContext_.~OutputContext();
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
   * Address: 0x008F7CF0 (FUN_008F7CF0, sub_8F7CF0)
   *
   * What it does:
   * Enumerates outputs and cached display-mode lists for the recovered DXGI
   * format probe set into the local mode cache.
   */
  int AdapterD3D10::ProbeOutputsAndModes()
  {
    modes_.clear();
    if (dxgiAdapter_ == nullptr) {
      return E_POINTER;
    }

    IDXGIOutput* output = nullptr;
    HRESULT result = dxgiAdapter_->EnumOutputs(0U, &output);
    if (result == DXGI_ERROR_NOT_FOUND) {
      return 0;
    }

    for (unsigned int outputIndex = 0U; result >= 0; ++outputIndex) {
      DXGI_OUTPUT_DESC outputDesc{};
      static_cast<void>(output->GetDesc(&outputDesc));

      for (const DXGI_FORMAT format : kAdapterProbeFormats) {
        UINT modeCount = 0U;
        const HRESULT countResult = output->GetDisplayModeList(format, 0U, &modeCount, nullptr);
        if (countResult == DXGI_ERROR_NOT_FOUND) {
          break;
        }

        AdapterModeD3D10 modeEntry{};
        modeEntry.format_ = static_cast<std::uint32_t>(format);
        modeEntry.output_ = output;
        modeEntry.outputDesc_ = outputDesc;
        modeEntry.outputDescPad_ = 0U;

        if ((countResult >= 0) && (modeCount != 0U)) {
          modeEntry.modes_.resize(modeCount);
          DXGI_MODE_DESC* const modeList = modeEntry.modes_.begin();
          const HRESULT fillResult = output->GetDisplayModeList(format, 0U, &modeCount, modeList);
          if (fillResult < 0) {
            modeEntry.modes_.clear();
          } else if (modeEntry.modes_.size() > modeCount) {
            modeEntry.modes_.resize(modeCount);
          }
        }

        modes_.push_back(modeEntry);
      }

      result = dxgiAdapter_->EnumOutputs(outputIndex + 1U, &output);
    }

    return (result == DXGI_ERROR_NOT_FOUND) ? 0 : result;
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
    DestroyAdapterModeVectorStorage(modes_);
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
   * Address: 0x0094D8F0 (FUN_0094D8F0)
   *
   * What it does:
   * Owns the scalar-deleting destroy thunk for hardware formatter wrappers.
   */
  MeshFormatter* HardwareVertexFormatterD3D10::Destroy(const std::uint8_t deleteFlags)
  {
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
    Device* const device = Device::GetInstance();
    const auto* const context = reinterpret_cast<const DeviceContextRuntimeFlags*>(InvokeDeviceGetContext(device));
    return context->hwBasedInstancing != 0U;
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
   * Address: 0x0094D910 (FUN_0094D910)
   *
   * What it does:
   * Owns the scalar-deleting destroy thunk for float16 formatter wrappers.
   */
  MeshFormatter* Float16HardwareVertexFormatterD3D10::Destroy(const std::uint8_t deleteFlags)
  {
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
    const auto* const context = reinterpret_cast<const DeviceContextRuntimeFlags*>(InvokeDeviceGetContext(device));
    return (context->hwBasedInstancing != 0U) && (context->meshFloat16 != 0U);
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

    TextureDescRuntime textureDesc{};
    InvokeTextureGetDesc(renderTexture, &textureDesc);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalRenderTargetFormat(static_cast<int>(textureDesc.format)));
    context_.width_ = textureDesc.width;
    context_.height_ = textureDesc.height;

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
   * D3D10 render-target slot returns null surface-level payload.
   */
  void* RenderTargetD3D10::GetSurfaceLevel0()
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
   * Maps one texture level and writes map metadata (`flags/level/pitch/bits`)
   * into caller output and cached per-level lock lanes.
   */
  TextureLockRectD3D10*
  TextureD3D10::Lock(TextureLockRectD3D10* const outRect, const int level, const RECT* const rect, const int flags)
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

    outRect->flags = flags;
    outRect->level = level;

    unsigned int mapMode = 4U;
    void* mapTexture = lockedTexture;
    if (((flags & 1) == 0) && ((flags & 2) != 0)) {
      mapMode = 1U;

      TextureDescRuntime textureDesc{};
      InvokeTextureGetDesc(lockedTexture, &textureDesc);
      if ((textureDesc.cpuAccessFlags & 0x20000U) == 0U) {
        Device* const device = Device::GetInstance();
        stagingTexture_ = CreateStagingTextureCopyOrThrow(device, lockedTexture);
        mapTexture = stagingTexture_;
      }
    }

    TextureMapResultRuntime mapped{};
    const HRESULT mapResult = InvokeTextureMap(mapTexture, level, mapMode, &mapped);
    if (mapResult < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 96, mapResult);
    }

    outRect->pitch = mapped.pitch;
    outRect->bits = mapped.bits;
    lockHistory_[level] = *outRect;
    return outRect;
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
   * Forwards to vtable-slot unlock path using the second stack argument.
   */
  int TextureD3D10::Func1(const int arg1, const int level, const int arg3, const int arg4)
  {
    static_cast<void>(arg1);
    static_cast<void>(arg3);
    static_cast<void>(arg4);

    auto** const vtable = *reinterpret_cast<void***>(this);
    auto* const thunk = reinterpret_cast<texture_virtual_unlock_fn>(vtable[3]);
    return thunk(this, level);
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
      auto** const vtable = *reinterpret_cast<void***>(this);
      auto* const unlockThunk = reinterpret_cast<texture_virtual_unlock_fn>(vtable[3]);
      unlockThunk(this, lockLevel_);
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

    TextureDescRuntime textureDesc{};
    InvokeTextureGetDesc(texture_, &textureDesc);
    context_.mipmapLevels_ = textureDesc.mipLevels;
    context_.width_ = textureDesc.width;
    context_.height_ = textureDesc.height;

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

    lockHistory_ = new TextureLockRectD3D10[context_.mipmapLevels_];
    contextFormatBackup_ = static_cast<int>(context_.format_);
    const int contextFormatBackupDxgi = MapGalTextureFormatToDxgi(contextFormatBackup_);
    static_cast<void>(contextFormatBackupDxgi);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalTextureFormat(static_cast<int>(textureDesc.format)));
    const unsigned int formatBlockBytes = GetTextureFormatBlockBytes(context_.format_);
    static_cast<void>(formatBlockBytes);
    if (context_.format_ == 20U) {
      DestroyState();
      ThrowGalError("TextureD3D10.cpp", 213, "unsupported texture format");
    }
  }

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
    DestroyState();
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
    context_.width_ = context->width_;
    context_.height_ = context->height_;
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
    DestroyState();
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
    context_.width_ = resetContext.width_;
    context_.height_ = resetContext.height_;
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

    boost::detail::sp_counted_base* const cursorControl = context->cursorControl_;
    if (cursorControl != nullptr) {
      cursorControl->add_ref_copy();
    }

    iconHandle_ = BuildCursorIcon(context->hotspotX_, context->hotspotY_, context->pixelSource_, cursorControl);
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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    DestroyDeviceD3D10Body(backend);
    ::operator delete(static_cast<void*>(backend));
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
   * Allocates and initializes one D3D10 backend object with recovered
   * constructor-default runtime lanes.
   */
  Device* CreateDeviceD3D10Backend()
  {
    auto* const backend = new DeviceD3D10BackendObject();

    backend->outputContext_.cubeTarget.reset();
    backend->outputContext_.face = 0;
    backend->outputContext_.surface.reset();
    backend->outputContext_.texture.reset();

    backend->currentThreadId_ = 0;
    backend->logStorage_.clear();
    backend->deviceContext_ = DeviceContext(0);
    backend->adapters_.clear();
    backend->swapChains_.clear();
    backend->pipelineState_.reset();

    backend->dxgiFactory_ = nullptr;
    backend->d3dDevice_ = nullptr;
    backend->effectPreamble_ = nullptr;
    backend->shaderPreamble_ = nullptr;
    backend->rttTechnique_ = nullptr;
    backend->stretchRectBuffer_ = nullptr;
    backend->stretchRectInputLayout_ = nullptr;
    backend->outputContexts_ = nullptr;
    std::memset(backend->streamStateD8_, 0, sizeof(backend->streamStateD8_));

    return reinterpret_cast<Device*>(backend);
  }

  /**
   * Address context: 0x008E6B60 (func_CreateDeviceD3D)
   *
   * What it does:
   * Copies startup device-context payload into recovered D3D10 backend context
   * lanes and records current thread ownership.
   */
  void InitializeDeviceD3D10Backend(Device* const device, const DeviceContext* const context)
  {
    if ((device == nullptr) || (context == nullptr)) {
      return;
    }

    auto* const backend = AsDeviceD3D10BackendObject(reinterpret_cast<DeviceD3D10*>(device));
    backend->currentThreadId_ = static_cast<int>(::GetCurrentThreadId());
    backend->deviceContext_ = *context;
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
  void DeviceD3D10::Func1() {}

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
    auto* const backend = AsDeviceD3D10BackendObject(this);

    backend->d3dModulePrimary_ = ::LoadLibraryA("d3d10.dll");
    if (backend->d3dModulePrimary_ == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1645, "unable to explicitly link to d3d10.dll");
    }

    backend->createDeviceApi_ = reinterpret_cast<void*>(::GetProcAddress(backend->d3dModulePrimary_, "D3D10CreateDevice"));
    backend->createBlobApi_ = reinterpret_cast<device_create_blob_api_fn>(
      ::GetProcAddress(backend->d3dModulePrimary_, "D3D10CreateBlob")
    );

    backend->d3dModuleSecondary_ = ::LoadLibraryA("d3dx10.dll");
    if (backend->d3dModuleSecondary_ == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1650, "unable to explicitly link to d3dx10.dll");
    }

    backend->createEffectFromMemoryApi_ = reinterpret_cast<device_create_effect_from_memory_api_fn>(
      ::GetProcAddress(backend->d3dModuleSecondary_, "D3DX10CreateEffectFromMemory")
    );
    backend->createTextureFromMemoryApi_ = reinterpret_cast<device_create_texture_from_memory_api_fn>(
      ::GetProcAddress(backend->d3dModuleSecondary_, "D3DX10CreateTextureFromMemory")
    );
    backend->saveTextureToFileApi_ = reinterpret_cast<device_save_texture_to_file_api_fn>(
      ::GetProcAddress(backend->d3dModuleSecondary_, "D3DX10SaveTextureToFileA")
    );
    backend->saveTextureToMemoryApi_ = reinterpret_cast<device_save_texture_to_memory_api_fn>(
      ::GetProcAddress(backend->d3dModuleSecondary_, "D3DX10SaveTextureToMemory")
    );

    backend->dxgiModule_ = ::LoadLibraryA("dxgi.dll");
    if (backend->dxgiModule_ == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1657, "unable to explicitly link to dxgi.dll");
    }

    backend->createDxgiFactoryApi_ = reinterpret_cast<void*>(::GetProcAddress(backend->dxgiModule_, "CreateDXGIFactory"));
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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    backend->adapters_.clear();

    auto* const dxgiFactory = reinterpret_cast<IDXGIFactory*>(backend->dxgiFactory_);
    if (dxgiFactory == nullptr) {
      return E_POINTER;
    }

    IDXGIAdapter* adapter = nullptr;
    HRESULT result = dxgiFactory->EnumAdapters(0U, &adapter);
    for (unsigned int adapterIndex = 0U; result >= 0; ++adapterIndex) {
      AdapterD3D10 adapterEntry(adapter);
      if (adapterEntry.ProbeOutputsAndModes() >= 0) {
        backend->adapters_.push_back(adapterEntry);
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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    auto* const device = reinterpret_cast<ID3D10Device*>(backend->d3dDevice_);

    const HRESULT createEffectResult = backend->createEffectFromMemoryApi_(
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
      &backend->shaderPreamble_,
      nullptr
    );
    if (createEffectResult < 0) {
      ThrowDeviceD3D10Hresult(1925, createEffectResult);
    }

    auto* const shaderEffect = reinterpret_cast<ID3D10Effect*>(backend->shaderPreamble_);
    backend->rttTechnique_ = shaderEffect->GetTechniqueByName("RTT");

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
    ReleaseComLike(backend->stretchRectBuffer_);
    backend->stretchRectBuffer_ = quadVertexBuffer;

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

    auto* const technique = reinterpret_cast<ID3D10EffectTechnique*>(backend->rttTechnique_);
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

    ReleaseComLike(backend->stretchRectInputLayout_);
    backend->stretchRectInputLayout_ = inputLayout;
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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    backend->deviceContext_ = *context;

    const std::uint32_t headCount = static_cast<std::uint32_t>(context->GetHeadCount());
    if (headCount > static_cast<std::uint32_t>(backend->adapters_.size())) {
      ThrowGalError("DeviceD3D10.cpp", 1695, "invalid head count specified in device context");
    }

    backend->deviceContext_.mMaxPrimitiveCount = 0x10000U;
    backend->deviceContext_.mMaxVertexCount = 0xFFFFU;
    backend->deviceContext_.mHWBasedInstancing = true;
    backend->deviceContext_.mVertexShaderProfile = 4;
    backend->deviceContext_.mPixelShaderProfile = 8;

    auto* const device = reinterpret_cast<ID3D10Device*>(backend->d3dDevice_);
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      Head& head = backend->deviceContext_.GetHead(headIndex);
      const AdapterD3D10& adapter = backend->adapters_[headIndex];

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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    const std::uint32_t headCount = static_cast<std::uint32_t>(backend->deviceContext_.GetHeadCount());

    if (backend->outputContexts_ != nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1818, "internal D3D10 device initialization error");
    }

    OutputContext* const outputContexts = (headCount > 0U) ? new OutputContext[headCount] : nullptr;
    backend->outputContexts_ = outputContexts;

    auto* const outputContextsRuntime = reinterpret_cast<OutputContextD3D10RuntimeView*>(outputContexts);
    auto* const device = reinterpret_cast<ID3D10Device*>(backend->d3dDevice_);
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      auto* const swapChain = reinterpret_cast<IDXGISwapChain*>(backend->swapChains_[headIndex]);

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

      outputContextsRuntime[headIndex].renderTarget.reset(
        new RenderTargetD3D10(backBuffer, renderTargetView, shaderResourceView)
      );

      DepthStencilTargetContext depthStencilContext(textureDesc.Width, textureDesc.Height, 3U, false);
      boost::shared_ptr<DepthStencilTargetD3D10> depthStencilTarget;
      CreateDepthStencilTarget(&depthStencilTarget, &depthStencilContext);
      outputContextsRuntime[headIndex].depthStencil = depthStencilTarget;
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
    auto* const backend = AsDeviceD3D10BackendObject(this);

    DynamicLink();
    backend->logStorage_.clear();

    const auto* const createDxgiFactory = reinterpret_cast<create_dxgi_factory_api_fn>(backend->createDxgiFactoryApi_);
    const HRESULT createFactoryResult = createDxgiFactory(IID_IDXGIFactory, &backend->dxgiFactory_);
    if (createFactoryResult < 0) {
      ThrowDeviceD3D10Hresult(610, createFactoryResult);
    }

    static_cast<void>(SetupDXGIDevice());
    if (backend->adapters_.empty()) {
      ThrowGalError("DeviceD3D10.cpp", 620, "unable to enumerate adapters");
    }

    const auto* const createDevice = reinterpret_cast<d3d10_create_device_api_fn>(backend->createDeviceApi_);
    const HRESULT createDeviceResult = createDevice(
      backend->adapters_.front().dxgiAdapter_,
      D3D10_DRIVER_TYPE_HARDWARE,
      nullptr,
      0U,
      29U,
      reinterpret_cast<ID3D10Device**>(&backend->d3dDevice_)
    );
    if (createDeviceResult < 0) {
      ThrowDeviceD3D10Hresult(622, createDeviceResult);
    }

    auto* const dxgiFactory = reinterpret_cast<IDXGIFactory*>(backend->dxgiFactory_);
    for (unsigned int headIndex = 0U; headIndex < static_cast<unsigned int>(context->GetHeadCount()); ++headIndex) {
      const Head& head = context->GetHead(headIndex);
      DXGI_SWAP_CHAIN_DESC swapChainDesc{};
      BuildSwapChainDescFromHeadRuntime(&swapChainDesc, &head);

      IDXGISwapChain* swapChain = nullptr;
      const HRESULT createSwapChainResult = dxgiFactory->CreateSwapChain(
        reinterpret_cast<IUnknown*>(backend->d3dDevice_),
        &swapChainDesc,
        &swapChain
      );
      if (createSwapChainResult < 0) {
        ThrowDeviceD3D10Hresult(631, createSwapChainResult);
      }

      backend->swapChains_.push_back(swapChain);
    }

    const HRESULT createSignatureResult = backend->createEffectFromMemoryApi_(
      kSignaturePreambleEffectSource,
      sizeof(kSignaturePreambleEffectSource),
      nullptr,
      nullptr,
      nullptr,
      0x800U,
      0U,
      reinterpret_cast<ID3D10Device*>(backend->d3dDevice_),
      nullptr,
      nullptr,
      &backend->effectPreamble_,
      nullptr
    );
    if (createSignatureResult < 0) {
      ThrowDeviceD3D10Hresult(641, createSignatureResult);
    }

    SetUpRTT();

    std::memset(backend->streamStateD8_, 0, sizeof(backend->streamStateD8_));
    backend->pipelineState_.reset(new PipelineStateD3D10(reinterpret_cast<ID3D10Device*>(backend->d3dDevice_)));
    backend->pipelineState_->SetDeviceState();

    static_cast<void>(CheckAvailableFormats(context));
    CreateRenderTargets();
  }

  /**
   * Address: 0x008FAB80 (FUN_008FAB80)
   *
   * unsigned int
   *
   * What it does:
   * Validates one head index against the retained `DeviceContext` head count and
   * returns the `this+0x118` head-array lane offset (`index * 0x20`).
   */
  void* DeviceD3D10::GetHead2(const unsigned int headIndex)
  {
    const unsigned int headCount = GetDeviceHeadCount(this);
    if (headIndex >= headCount) {
      ThrowGalError("DeviceD3D10.cpp", 727, "invalid head index specified");
    }

    auto* const headArrayBase = reinterpret_cast<std::uint8_t*>(GetDeviceHeadArrayBase(this));
    return headArrayBase + (headIndex * 0x20U);
  }

  /**
   * Address: 0x008FAC50 (FUN_008FAC50)
   *
   * unsigned int
   *
   * What it does:
   * Validates one head index against the retained `DeviceContext` head count and
   * returns the `this+0x118` head-array lane offset (`index * 0x20`).
   */
  void* DeviceD3D10::GetHead1(const unsigned int headIndex)
  {
    const unsigned int headCount = GetDeviceHeadCount(this);
    if (headIndex >= headCount) {
      ThrowGalError("DeviceD3D10.cpp", 733, "invalid head index specified");
    }

    auto* const headArrayBase = reinterpret_cast<std::uint8_t*>(GetDeviceHeadArrayBase(this));
    return headArrayBase + (headIndex * 0x20U);
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
    auto* const backend = AsDeviceD3D10BackendObject(this);
    *outPipelineState = backend->pipelineState_;
    return outPipelineState;
  }

  /**
   * Address: 0x008FEA00 (FUN_008FEA00)
   *
   * boost::shared_ptr<EffectD3D10> *,EffectContext *
   *
   * What it does:
   * Compiles one effect from source memory with recovered macro-injection lanes
   * and returns a wrapped D3D10 effect handle.
   */
  boost::shared_ptr<EffectD3D10>*
  DeviceD3D10::CreateEffect(boost::shared_ptr<EffectD3D10>* const outEffect, EffectContext* const context)
  {
    const EffectContextRuntime* const runtime = AsEffectContextRuntime(context);
    if (runtime->field04 != 2U) {
      ThrowGalError("DeviceD3D10.cpp", 818, "invalid source defined for effect");
    }

    const std::size_t sourceMacroCount = EffectMacroCount(runtime->lane54);
    const std::size_t totalMacroCount = sourceMacroCount + kDeviceCreateEffectInjectedMacroCount;
    D3D10_SHADER_MACRO* defines = nullptr;
    if (totalMacroCount != 0U) {
      defines = new D3D10_SHADER_MACRO[totalMacroCount + 1U];

      std::size_t writeIndex = 0U;
      for (EffectMacro* read = runtime->lane54.first; read != runtime->lane54.last; ++read, ++writeIndex) {
        defines[writeIndex].Name = read->keyText_.c_str();
        defines[writeIndex].Definition = read->valueText_.c_str();
      }

      for (std::size_t i = 0U; i < kDeviceCreateEffectInjectedMacroCount; ++i, ++writeIndex) {
        defines[writeIndex].Name = kDeviceCreateEffectInjectedMacros[i].key;
        defines[writeIndex].Definition = kDeviceCreateEffectInjectedMacros[i].value;
      }

      defines[writeIndex].Name = nullptr;
      defines[writeIndex].Definition = nullptr;
    }

    const auto* const sourceData = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(runtime->field4C));
    const std::uint32_t sourceBytes =
      (runtime->field50 >= runtime->field4C) ? (runtime->field50 - runtime->field4C) : 0U;

    void* dxEffect = nullptr;
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
      message = message + runtime->field0C;
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
   * boost::shared_ptr<TextureD3D10> *,TextureContext const *
   *
   * What it does:
   * Creates one texture resource from context source lanes and returns the wrapped
   * texture + shader-resource-view payload.
   */
  boost::shared_ptr<TextureD3D10>*
  DeviceD3D10::CreateTexture(boost::shared_ptr<TextureD3D10>* const outTexture, const TextureContext* const context)
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
      TextureDescRuntime textureDesc{};
      InvokeTextureGetDesc(nativeTexture, &textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = DXGI_FORMAT_UNKNOWN;
      shaderResourceViewDesc.ViewDimension =
        (textureDesc.miscFlags != 4U) ? D3D10_SRV_DIMENSION_TEXTURE2D : D3D10_SRV_DIMENSION_TEXTURECUBE;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.mipLevels;

      const HRESULT createSrvResult =
        InvokeNativeCreateShaderResourceView(this, nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 912, createSrvResult);
      }
    }

    outTexture->reset(new TextureD3D10(context, nativeTexture, shaderResourceView));
    return outTexture;
  }

  /**
   * Address: 0x008FB1D0 (FUN_008FB1D0)
   *
   * boost::shared_ptr<RenderTargetD3D10> *,RenderTargetContext const *
   *
   * What it does:
   * Creates one 2D render-target texture + RTV/SRV pair from caller context lanes.
   */
  boost::shared_ptr<RenderTargetD3D10>* DeviceD3D10::CreateVolumeTexture(
    boost::shared_ptr<RenderTargetD3D10>* const outRenderTarget, const RenderTargetContext* const context
  )
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

    ViewportRuntime viewport{};
    viewport.width = context->width_;
    viewport.height = context->height_;
    viewport.minDepth = 0.0f;
    viewport.maxDepth = 1.0f;
    SetViewport(&viewport);

    outRenderTarget->reset(new RenderTargetD3D10(context, nativeTexture, renderTargetView, shaderResourceView));
    return outRenderTarget;
  }

  /**
   * Address: 0x008FA6B0 (FUN_008FA6B0)
   *
   * boost::shared_ptr<CubeRenderTargetD3D10> *,CubeRenderTargetContext const *
   *
   * What it does:
   * Allocates one cube-render-target wrapper and returns it through caller shared output.
   */
  boost::shared_ptr<CubeRenderTargetD3D10>* DeviceD3D10::CreateCubeRenderTarget(
    boost::shared_ptr<CubeRenderTargetD3D10>* const outCubeRenderTarget, const CubeRenderTargetContext* const context
  )
  {
    outCubeRenderTarget->reset(new CubeRenderTargetD3D10(context));
    return outCubeRenderTarget;
  }

  /**
   * Address: 0x008FB570 (FUN_008FB570)
   *
   * boost::shared_ptr<DepthStencilTargetD3D10> *,DepthStencilTargetContext const *
   *
   * What it does:
   * Creates one depth-stencil texture + DSV/SRV lane and returns wrapped ownership.
   */
  boost::shared_ptr<DepthStencilTargetD3D10>* DeviceD3D10::CreateDepthStencilTarget(
    boost::shared_ptr<DepthStencilTargetD3D10>* const outDepthStencilTarget,
    const DepthStencilTargetContext* const context
  )
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

    outDepthStencilTarget->reset(
      new DepthStencilTargetD3D10(context, depthTexture, depthStencilView, shaderResourceView)
    );
    return outDepthStencilTarget;
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
    const VertexLayoutElementRuntime* const elements = GetVertexLayoutElementsOrThrow(formatToken);
    const std::uint32_t elementCount = GetVertexLayoutElementCountOrThrow(formatToken);

    D3D10PassDescRuntime passDesc{};
    GetVertexInputSignatureOrThrow(this, static_cast<int>(formatToken), &passDesc);

    void* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = InvokeNativeCreateInputLayout(
      this, elements, elementCount, passDesc.inputSignature, passDesc.inputSignatureSize, &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1029, createInputLayoutResult);
    }

    outVertexFormat->reset(new VertexFormatD3D10(formatToken, inputLayout));
    return outVertexFormat;
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
    const std::uint32_t byteWidth = context->width_ * context->height_;

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

    outVertexBuffer->reset(new VertexBufferD3D10(context, GetDeviceNativeHandle(this), gpuBuffer, stagingBuffer));
    return outVertexBuffer;
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

    outIndexBuffer->reset(new IndexBufferD3D10(context, GetDeviceNativeHandle(this), gpuBuffer, stagingBuffer));
    return outIndexBuffer;
  }

  /**
   * Address: 0x008FC540 (FUN_008FC540)
   *
   * gpg::gal::RenderTargetD3D10 **,gpg::gal::TextureD3D10 **
   *
   * What it does:
   * Validates source/destination texture wrappers and dispatches one native
   * copy-resource lane on the retained D3D10 device.
   */
  int DeviceD3D10::CreateRenderTarget(RenderTargetD3D10** const sourceTexture, TextureD3D10** const destinationTexture)
  {
    if ((sourceTexture == nullptr) || (*sourceTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1230, "Missing source texture");
    }

    if ((destinationTexture == nullptr) || (*destinationTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1231, "Missing dest   texture");
    }

    void* const sourceResource = (*sourceTexture)->GetRenderTextureOrThrow();
    void* const destinationResource = (*destinationTexture)->GetTextureOrThrow();
    return InvokeNativeCopyResourceResult(this, destinationResource, sourceResource);
  }

  /**
   * Address: 0x008FC290 (FUN_008FC290)
   *
   * gpg::gal::RenderTargetD3D10 **,gpg::gal::RenderTargetD3D10 **,void const *,void const *
   *
   * What it does:
   * Copies from source to destination render target when contexts match; otherwise
   * falls back to the shader-resource/render-target-view blit lane.
   */
  void DeviceD3D10::StretchRect(
    RenderTargetD3D10** const sourceTexture,
    RenderTargetD3D10** const destinationTexture,
    const void* const sourceRect,
    const void* const destinationPoint
  )
  {
    if ((sourceTexture == nullptr) || (*sourceTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1174, "Missing source texture");
    }

    if ((destinationTexture == nullptr) || (*destinationTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1175, "Missing dest   texture");
    }

    const RenderTargetContext* const sourceContext = (*sourceTexture)->GetContext();
    const RenderTargetContext* const destinationContext = (*destinationTexture)->GetContext();

    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationPoint != nullptr) {
        const auto* const point = reinterpret_cast<const POINT*>(destinationPoint);
        destinationX = static_cast<unsigned int>(point->x);
        destinationY = static_cast<unsigned int>(point->y);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const auto* const rect = reinterpret_cast<const RECT*>(sourceRect);
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      void* const sourceResource = (*sourceTexture)->GetRenderTextureOrThrow();
      void* const destinationResource = (*destinationTexture)->GetRenderTextureOrThrow();
      InvokeNativeCopySubresourceRegion(
        this, destinationResource, destinationX, destinationY, sourceResource, sourceBoxPtr
      );
      return;
    }

    void* const sourceShaderResourceView = (*sourceTexture)->GetShaderResourceViewOrThrow();
    void* const destinationRenderTargetView = (*destinationTexture)->GetRenderTargetViewOrThrow();
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
   * gpg::gal::TextureD3D10 **,gpg::gal::TextureD3D10 **,void const *,void const *
   *
   * What it does:
   * Copies matching texture contexts directly; otherwise executes recovered
   * memory-encode/decode fallback before the final destination copy.
   */
  void DeviceD3D10::UpdateSurface(
    TextureD3D10** const sourceTexture,
    TextureD3D10** const destinationTexture,
    const void* const sourceRect,
    const void* const destinationPoint
  )
  {
    if ((sourceTexture == nullptr) || (*sourceTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1091, "Missing source texture");
    }

    if ((destinationTexture == nullptr) || (*destinationTexture == nullptr)) {
      ThrowGalError("DeviceD3D10.cpp", 1092, "Missing dest   texture");
    }

    const TextureContext* const sourceContext = (*sourceTexture)->GetContext();
    const TextureContext* const destinationContext = (*destinationTexture)->GetContext();
    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationPoint != nullptr) {
        const auto* const point = reinterpret_cast<const POINT*>(destinationPoint);
        destinationX = static_cast<unsigned int>(point->x);
        destinationY = static_cast<unsigned int>(point->y);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const auto* const rect = reinterpret_cast<const RECT*>(sourceRect);
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      void* const sourceResource = (*sourceTexture)->GetTextureOrThrow();
      void* const destinationResource = (*destinationTexture)->GetTextureOrThrow();
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
    result = InvokeSaveTextureToMemoryApi(this, (*sourceTexture)->GetTextureOrThrow(), 4, &encodedTextureBlob);
    if (result < 0) {
      ReleaseComLike(createBlobScratch);
      ThrowDeviceD3D10Hresult(1112, result);
    }

    std::int32_t loadInfo[14];
    for (std::int32_t& value : loadInfo) {
      value = -1;
    }
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
      InvokeNativeCopyResourceResult(this, (*destinationTexture)->GetTextureOrThrow(), recreatedTexture);
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
   * gpg::gal::RenderTargetD3D10 **,msvc8::string const &,int
   *
   * What it does:
   * Saves one render-target texture lane to a file path using the recovered
   * image-format token map from `DAT_00D430A0`.
   */
  void
  DeviceD3D10::Func4(RenderTargetD3D10** const renderTarget, const msvc8::string& filePath, const int fileFormatToken)
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormatToken);
    const HRESULT result =
      InvokeSaveTextureToFileApi(this, (*renderTarget)->GetRenderTextureOrThrow(), imageFileFormat, filePath.c_str());
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1286, result);
    }
  }

  /**
   * Address: 0x008FC6B0 (FUN_008FC6B0)
   *
   * gpg::gal::TextureD3D10 **,msvc8::string const &,int,gpg::MemBuffer<char> *
   *
   * What it does:
   * Saves one texture to file when `outBuffer==nullptr`; otherwise serializes
   * into caller memory buffer using the recovered blob helper lane.
   */
  void DeviceD3D10::Func5(
    TextureD3D10** const texture,
    const msvc8::string& filePath,
    const int fileFormatToken,
    gpg::MemBuffer<char>* const outBuffer
  )
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormatToken);
    TextureD3D10* const sourceTexture = *texture;

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
    for (std::int32_t& value : loadInfo) {
      value = -1;
    }
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

    TextureDescRuntime textureDesc{};
    InvokeTextureGetDesc(sourceTexture, &textureDesc);
    *outWidth = textureDesc.width;
    *outHeight = static_cast<int>(textureDesc.height);

    textureDesc.usage = 3U;
    textureDesc.bindFlags = 0U;
    textureDesc.cpuAccessFlags = 0x20000U;

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

    TextureMapResultRuntime mappedTexture{};
    result = InvokeTextureMap(stagingTexture, 0, 1U, &mappedTexture);
    if (result < 0) {
      ReleaseComLike(stagingTexture);
      ReleaseComLike(sourceTexture);
      ReleaseComLike(decodedResource);
      ThrowDeviceD3D10Hresult(1352, result);
    }

    const std::uint32_t rowBytes = 16U * ((textureDesc.width + 3U) / 4U);
    const std::uint32_t rowCount = (textureDesc.height + 3U) / 4U;
    const std::size_t requiredBytes = static_cast<std::size_t>(rowBytes) * static_cast<std::size_t>(rowCount);
    if (outTextureData->Size() != requiredBytes) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(requiredBytes);
      *outTextureData = resizedBuffer;
    }

    char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
    const auto* const sourceBytesPtr = reinterpret_cast<const std::uint8_t*>(mappedTexture.bits);
    if (static_cast<unsigned int>(mappedTexture.pitch) == rowBytes) {
      std::memcpy(destinationBytes, sourceBytesPtr, requiredBytes);
    } else {
      char* writeCursor = destinationBytes;
      for (std::uint32_t row = 0U; row < rowCount; ++row) {
        std::memcpy(writeCursor, sourceBytesPtr + (static_cast<std::size_t>(mappedTexture.pitch) * row), rowBytes);
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
   * int,int
   *
   * What it does:
   * Preserves the binary no-op virtual slot (`retn 8` shape).
   */
  void DeviceD3D10::Func3(const int arg1, const int arg2)
  {
    static_cast<void>(arg1);
    static_cast<void>(arg2);
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
    const auto* const sourceViewport = reinterpret_cast<const ViewportRuntime*>(viewport);
    ViewportRuntime viewportCopy{};
    viewportCopy.topLeftX = sourceViewport->topLeftX;
    viewportCopy.topLeftY = sourceViewport->topLeftY;
    viewportCopy.width = sourceViewport->width;
    viewportCopy.height = sourceViewport->height;
    viewportCopy.minDepth = sourceViewport->minDepth;
    viewportCopy.maxDepth = sourceViewport->maxDepth;
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
    ViewportRuntime viewport{};
    InvokeNativeGetViewport(this, &viewportCount, &viewport);

    auto* const destinationViewport = reinterpret_cast<ViewportRuntime*>(outViewport);
    destinationViewport->topLeftX = viewport.topLeftX;
    destinationViewport->topLeftY = viewport.topLeftY;
    destinationViewport->width = viewport.width;
    destinationViewport->height = viewport.height;
    destinationViewport->minDepth = viewport.minDepth;
    destinationViewport->maxDepth = viewport.maxDepth;
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
    DeviceSwapChainRangeRuntime* const swapChainRange = GetDeviceSwapChainRange(this);
    for (void** it = swapChainRange->swapChainsBegin; it != swapChainRange->swapChainsEnd; ++it) {
      const HRESULT result = InvokeSwapChainPresent(*it, 0U, 0U);
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
    const auto* const drawContext = reinterpret_cast<const DrawPrimitiveContextRuntime*>(context);
    if (drawContext->topologyToken == 0U) {
      ThrowInvalidTopologyError(1561);
    }

    InvokeNativeSetPrimitiveTopology(this, ResolvePrimitiveTopology(drawContext->topologyToken));
    const std::uint32_t instanceCount = GetDeviceInstanceCount(this);
    if (instanceCount > 1U) {
      return InvokeNativeDrawInstanced(this, drawContext->vertexCount, instanceCount, drawContext->startVertex, 0U);
    }

    return InvokeNativeDraw(this, drawContext->vertexCount, drawContext->startVertex);
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
    const auto* const drawContext = reinterpret_cast<const DrawIndexedPrimitiveContextRuntime*>(context);
    if (drawContext->topologyToken == 0U) {
      ThrowInvalidTopologyError(1580);
    }

    InvokeNativeSetPrimitiveTopology(this, ResolvePrimitiveTopology(drawContext->topologyToken));
    const std::uint32_t instanceCount = GetDeviceInstanceCount(this);
    if (instanceCount > 1U) {
      return InvokeNativeDrawIndexedInstanced(
        this, drawContext->indexCount, instanceCount, drawContext->startIndex, 0, 0U
      );
    }

    return InvokeNativeDrawIndexed(this, drawContext->indexCount, drawContext->startIndex, 0);
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
    *GetDeviceOutputContext(this) = *context;

    void* renderTargetView = nullptr;
    void* depthStencilView = nullptr;

    if (context != nullptr) {
      const auto& runtime = *reinterpret_cast<const OutputContextD3D10RuntimeView*>(context);
      if (runtime.renderTarget.get() != nullptr) {
        renderTargetView = runtime.renderTarget->GetRenderTargetViewOrThrow();
      }

      if (runtime.depthStencil.get() != nullptr) {
        depthStencilView = runtime.depthStencil->GetDepthStencilViewOrThrow();
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

    void* const renderTargetContextRaw = GetDeviceActiveRenderTargetContextRaw(this);
    if (renderTargetContextRaw != nullptr) {
      renderTargetView = reinterpret_cast<RenderTargetD3D10*>(renderTargetContextRaw)->GetRenderTargetViewOrThrow();
    }

    void* const depthStencilContextRaw = GetDeviceActiveDepthStencilContextRaw(this);
    if (depthStencilContextRaw != nullptr) {
      depthStencilView =
        reinterpret_cast<DepthStencilTargetD3D10*>(depthStencilContextRaw)->GetDepthStencilViewOrThrow();
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
    VertexBufferContextRuntime* const context = InvokeVertexBufferGetContext(vertexBuffer);
    void* const nativeVertexBuffer = vertexBuffer->GetNativeBufferOrThrow();
    const unsigned int stride = context->stride;
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
    IndexBufferContextRuntime* const context = InvokeIndexBufferGetContext(indexBuffer);
    const unsigned int indexFormatToken = (context->format == 2U) ? 0x2AU : 0x39U;
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

    const VertexLayoutElementRuntime* const layoutElements = GetVertexLayoutElementsOrThrow(format_);
    const std::uint32_t layoutElementCount = GetVertexLayoutElementCountOrThrow(format_);

    if (streamStrides_.begin_ != streamStrides_.end_) {
      streamStrides_.end_ = streamStrides_.begin_;
    }

    std::uint32_t result = layoutElementCount;
    for (std::uint32_t index = 0; index < layoutElementCount; ++index) {
      const VertexLayoutElementRuntime& element = layoutElements[index];
      EnsureVertexStreamStrideCount(&streamStrides_, element.inputSlot + 1U);

      std::uint32_t* const streamStride = streamStrides_.begin_ + element.inputSlot;
      const std::uint32_t candidate = element.alignedByteOffset + GetTextureFormatBlockBytes(element.format);
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
    , contextPad_{}
    , dxEffect_(nullptr)
  {
    InitializeEffectD3D10Object(this);
    InitializeEffectD3D10State(this, context, dxEffect);
  }

  /**
   * Address: 0x0094C050 (FUN_0094C050)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates teardown to `FUN_0094BF80`.
   */
  EffectD3D10::~EffectD3D10()
  {
    DestroyEffectD3D10Body(this);
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

    D3D10EffectDescRuntime effectDesc{};
    HRESULT result = InvokeEffectGetDesc(dxEffect_, &effectDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectD3D10.cpp", 57, result);
    }

    for (unsigned int index = 0; index < effectDesc.techniqueCount; ++index) {
      void* const techniqueHandle = InvokeEffectGetTechniqueByIndex(dxEffect_, index);
      if ((techniqueHandle == nullptr) || (InvokeTechniqueIsValid(techniqueHandle) == FALSE)) {
        continue;
      }

      D3D10TechniqueDescRuntime techniqueDesc{};
      result = InvokeTechniqueGetDesc(techniqueHandle, &techniqueDesc);
      if (result < 0) {
        ThrowGalErrorFromHresult("EffectD3D10.cpp", 69, result);
      }

      outTechniques.push_back(
        boost::shared_ptr<EffectTechniqueD3D10>(
          new EffectTechniqueD3D10(techniqueDesc.name, dxEffect_, techniqueHandle)
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

    return boost::shared_ptr<EffectVariableD3D10>(new EffectVariableD3D10(variableName, dxEffect_, variableHandle));
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

    return boost::shared_ptr<EffectTechniqueD3D10>(new EffectTechniqueD3D10(techniqueName, dxEffect_, techniqueHandle));
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
    ReleaseComLike(dxEffect_);
    techniqueHandle_ = nullptr;
    beginEndActive_ = false;
    name_.tidy(true, 0U);
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

    D3D10TechniqueDescRuntime techniqueDesc{};
    const HRESULT result = InvokeTechniqueGetDesc(techniqueHandle_, &techniqueDesc);
    if (result < 0) {
      ThrowGalErrorFromHresult("EffectTechniqueD3D10.cpp", 67, result);
    }

    beginEndActive_ = true;
    return static_cast<int>(techniqueDesc.passCount);
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
  void EffectVariableD3D10::SetTexture(boost::shared_ptr<TextureD3D10> texture)
  {
    void* const shaderResourceVariable = InvokeVariableAsShaderResource(variableHandle_);
    void* const shaderResourceView = (texture.get() != nullptr) ? texture->GetShaderResourceViewOrThrow() : nullptr;
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

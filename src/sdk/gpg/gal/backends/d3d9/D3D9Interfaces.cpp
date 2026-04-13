#include "AdapterD3D9.hpp"
#include "AdapterModeD3D9.hpp"
#include "CubeRenderTargetD3D9.hpp"
#include "DepthStencilTargetD3D9.hpp"
#include "DeviceD3D9.hpp"
#include "EffectD3D9.hpp"
#include "EffectTechniqueD3D9.hpp"
#include "EffectVariableD3D9.hpp"
#include "Float16HardwareVertexFormatterD3D9.hpp"
#include "HardwareVertexFormatterD3D9.hpp"
#include "IndexBufferD3D9.hpp"
#include "PipelineStateD3D9.hpp"
#include "RenderTargetD3D9.hpp"
#include "StateManagerD3D9.hpp"
#include "TextureD3D9.hpp"
#include "VertexBufferD3D9.hpp"
#include "VertexFormatD3D9.hpp"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/OutputContext.hpp"

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"

#include <bit>
#include <cstdio>
#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace gpg::gal
{
#include <d3d9caps.h>

    namespace
    {
        using release_fn = unsigned long(__stdcall*)(void*);
        using lock_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void**, unsigned int);
        using unlock_fn = HRESULT(__stdcall*)(void*);
        using lock_rect_fn = HRESULT(__stdcall*)(void*, int, void*, const RECT*, unsigned int);
        using unlock_rect_fn = HRESULT(__stdcall*)(void*, int);
        using get_surface_level_fn = HRESULT(__stdcall*)(void*, unsigned int, void**);
        using get_cube_map_surface_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void**);
        using d3dx_create_buffer_fn = HRESULT(WINAPI*)(unsigned int, void**);
        using d3dx_save_surface_to_file_in_memory_fn = HRESULT(WINAPI*)(void**, unsigned int, void*, const void*, const RECT*);
        using d3dx_save_surface_to_file_a_fn = HRESULT(WINAPI*)(const char*, unsigned int, void*, const void*, const RECT*);
        using d3dx_save_texture_to_file_a_fn = HRESULT(WINAPI*)(const char*, unsigned int, void*, const void*);
        using d3dx_load_surface_from_surface_fn =
            HRESULT(WINAPI*)(void*, const void*, const RECT*, void*, const void*, const RECT*, unsigned int, std::uint32_t);
        using d3dx_float32_to16_array_fn = std::uint16_t*(WINAPI*)(std::uint16_t*, const float*, unsigned int);
        using d3dx_get_image_info_from_file_in_memory_fn = HRESULT(WINAPI*)(const void*, unsigned int, void*);
        using d3dx_create_texture_fn = HRESULT(WINAPI*)(void*, unsigned int, unsigned int, unsigned int, unsigned int, std::uint32_t, D3DPOOL, void**);
        using d3dx_create_texture_from_file_in_memory_ex_fn = HRESULT(WINAPI*)(
            void*,
            const void*,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            std::uint32_t,
            D3DPOOL,
            unsigned int,
            unsigned int,
            std::uint32_t,
            const void*,
            void*,
            void**
        );
        using d3dx_create_volume_texture_from_file_in_memory_ex_fn = HRESULT(WINAPI*)(
            void*,
            const void*,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            std::uint32_t,
            D3DPOOL,
            unsigned int,
            unsigned int,
            std::uint32_t,
            const void*,
            void*,
            void**
        );
        using d3dx_create_cube_texture_from_file_in_memory_ex_fn = HRESULT(WINAPI*)(
            void*,
            const void*,
            unsigned int,
            unsigned int,
            unsigned int,
            unsigned int,
            std::uint32_t,
            D3DPOOL,
            unsigned int,
            unsigned int,
            std::uint32_t,
            const void*,
            void*,
            void**
        );
        using d3dx_get_vertex_shader_profile_fn = const char*(WINAPI*)(void*);
        using d3dx_get_pixel_shader_profile_fn = const char*(WINAPI*)(void*);
        using d3dx_buffer_get_pointer_fn = void*(__stdcall*)(void*);
        using d3dx_buffer_get_size_fn = unsigned int(__stdcall*)(void*);
        using effect_get_parameter_by_name_fn = void*(__stdcall*)(void*, void*, const char*);
        using effect_get_annotation_by_name_fn = void*(__stdcall*)(void*, void*, const char*);
        using effect_get_technique_by_name_fn = void*(__stdcall*)(void*, const char*);
        using effect_find_next_valid_technique_fn = HRESULT(__stdcall*)(void*, void*, void**);
        using effect_set_technique_fn = HRESULT(__stdcall*)(void*, void*);
        using effect_set_value_fn = HRESULT(__stdcall*)(void*, void*, const void*, unsigned int);
        using effect_set_bool_fn = HRESULT(__stdcall*)(void*, void*, int);
        using effect_set_int_fn = HRESULT(__stdcall*)(void*, void*, int);
        using effect_set_float_fn = HRESULT(__stdcall*)(void*, void*, float);
        using effect_set_float_array_fn = HRESULT(__stdcall*)(void*, void*, const float*, unsigned int);
        using effect_set_vector_fn = HRESULT(__stdcall*)(void*, void*, const void*);
        using effect_set_vector_array_fn = HRESULT(__stdcall*)(void*, void*, const void*, unsigned int);
        using effect_set_matrix_fn = HRESULT(__stdcall*)(void*, void*, const void*);
        using effect_set_matrix_array_fn = HRESULT(__stdcall*)(void*, void*, const void*, unsigned int);
        using effect_set_texture_fn = HRESULT(__stdcall*)(void*, void*, void*);
        using effect_get_technique_desc_fn = HRESULT(__stdcall*)(void*, void*, void*);
        using effect_begin_technique_fn = HRESULT(__stdcall*)(void*, unsigned int*, unsigned int);
        using effect_end_technique_fn = HRESULT(__stdcall*)(void*);
        using effect_begin_pass_fn = HRESULT(__stdcall*)(void*, unsigned int);
        using effect_end_pass_fn = HRESULT(__stdcall*)(void*);
        using effect_get_bool_fn = HRESULT(__stdcall*)(void*, void*, int*);
        using effect_get_int_fn = HRESULT(__stdcall*)(void*, void*, int*);
        using effect_get_float_fn = HRESULT(__stdcall*)(void*, void*, float*);
        using effect_get_string_fn = HRESULT(__stdcall*)(void*, void*, const char**);
        using effect_set_state_manager_fn = HRESULT(__stdcall*)(void*, void*);
        using effect_on_reset_device_fn = HRESULT(__stdcall*)(void*);
        using effect_on_lost_device_fn = HRESULT(__stdcall*)(void*);
        using device_get_context_fn = void*(__thiscall*)(Device*);
        using device_get_pipeline_state_fn = void(__thiscall*)(Device*, boost::shared_ptr<PipelineStateD3D9>*);
        using device_create_vertex_format_fn = void(__thiscall*)(Device*, void*, int);
        using device_begin_technique_fn = void(__thiscall*)(Device*);
        using device_end_technique_fn = void(__thiscall*)(Device*);
        using d3d9_device_show_cursor_fn = int(__stdcall*)(void*, int);
        using d3d9_device_create_texture_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, unsigned int, std::uint32_t, D3DPOOL, void**, void*);
        using d3d9_device_create_cube_texture_fn =
            HRESULT(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, std::uint32_t, D3DPOOL, void**, void*);
        using d3d9_device_create_depth_stencil_surface_fn =
            HRESULT(__stdcall*)(void*, unsigned int, unsigned int, std::uint32_t, unsigned int, unsigned int, int, void**, void*);
        using d3d9_device_get_back_buffer_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, void**);
        using d3d9_device_reset_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_get_device_caps_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_create_query_fn = HRESULT(__stdcall*)(void*, unsigned int, void**);
        using d3d9_device_set_render_state_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int);
        using d3d9_device_create_vertex_declaration_fn = HRESULT(__stdcall*)(void*, const void*, void**);
        using d3d9_device_create_vertex_buffer_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, unsigned int, D3DPOOL, void**, void*);
        using d3d9_device_create_index_buffer_fn =
            HRESULT(__stdcall*)(void*, unsigned int, unsigned int, std::uint32_t, D3DPOOL, void**, void*);
        using d3d9_device_get_render_target_data_fn = HRESULT(__stdcall*)(void*, void*, void*);
        using d3d9_device_stretch_rect_fn = HRESULT(__stdcall*)(void*, void*, const RECT*, void*, const RECT*, unsigned int);
        using d3d9_device_test_cooperative_level_fn = HRESULT(__stdcall*)(void*);
        using d3d9_device_begin_scene_fn = HRESULT(__stdcall*)(void*);
        using d3d9_device_end_scene_fn = HRESULT(__stdcall*)(void*);
        using d3d9_device_present_fn = HRESULT(__stdcall*)(void*, const RECT*, const RECT*, void*, const void*);
        using d3d9_device_set_cursor_properties_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void*);
        using d3d9_device_set_viewport_fn = HRESULT(__stdcall*)(void*, const void*);
        using d3d9_device_get_viewport_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_get_render_target_fn = HRESULT(__stdcall*)(void*, unsigned int, void**);
        using d3d9_device_set_render_target_fn = HRESULT(__stdcall*)(void*, unsigned int, void*);
        using d3d9_device_get_depth_stencil_surface_fn = HRESULT(__stdcall*)(void*, void**);
        using d3d9_device_set_depth_stencil_surface_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_clear_fn = HRESULT(__stdcall*)(void*, unsigned int, const void*, unsigned int, std::uint32_t, float, unsigned int);
        using d3d9_device_set_vertex_declaration_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_set_stream_source_fn = HRESULT(__stdcall*)(void*, unsigned int, void*, unsigned int, unsigned int);
        using d3d9_device_set_stream_source_freq_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int);
        using d3d9_device_set_indices_fn = HRESULT(__stdcall*)(void*, void*);
        using d3d9_device_draw_primitive_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, unsigned int);
        using d3d9_device_draw_indexed_primitive_fn =
            HRESULT(__stdcall*)(void*, unsigned int, int, unsigned int, unsigned int, unsigned int, unsigned int);
        using surface_get_desc_fn = HRESULT(__stdcall*)(void*, void*);
        using surface_lock_rect_fn = HRESULT(__stdcall*)(void*, void*, const RECT*, unsigned int);
        using surface_unlock_rect_fn = HRESULT(__stdcall*)(void*);
        using query_issue_fn = HRESULT(__stdcall*)(void*, unsigned int);
        using query_get_data_fn = HRESULT(__stdcall*)(void*, void*, unsigned int, unsigned int);
        using texture_get_level_desc_fn = HRESULT(__stdcall*)(void*, unsigned int, void*);
        using texture_get_level_count_fn = unsigned int(__stdcall*)(void*);
        using texture_virtual_unlock_fn = HRESULT(__thiscall*)(TextureD3D9*, int);
        using d3d9_check_device_format_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, std::uint32_t, unsigned int, unsigned int, std::uint32_t);
        using d3d9_check_device_multisample_type_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, std::uint32_t, int, unsigned int, unsigned int*);
        using d3d9_get_adapter_identifier_fn = HRESULT(__stdcall*)(void*, unsigned int, unsigned int, void*);

        constexpr unsigned int kD3DLockNoOverwrite = 0x10U;
        constexpr unsigned int kD3DLockReadOnly = 0x1000U;
        constexpr unsigned int kD3DLockDiscard = 0x2000U;
        constexpr unsigned int kD3DSurfaceLockReadOnly = 0x10U;
        constexpr unsigned int kD3DXIFFDDS = 4U;
        constexpr unsigned int kD3DXDefault = 0xFFFFFFFFU;
        constexpr unsigned int kD3DTexFilterPoint = 1U;
        constexpr unsigned int kD3DTexFilterLinear = 2U;
        constexpr unsigned int kD3DDevTypeHal = 1U;
        constexpr unsigned int kD3DBackBufferTypeMono = 0U;
        constexpr unsigned int kD3DSwapEffectDiscard = 1U;
        constexpr unsigned int kD3DRenderStatePointSize = 0x9AU;
        constexpr unsigned int kD3DRTypeSurface = 1U;
        constexpr unsigned int kD3DRTypeTexture = 3U;
        constexpr std::uint32_t kD3DFormatUnknown = 0U;
        constexpr std::uint32_t kD3DFormatA8R8G8B8 = 0x15U;
        constexpr std::uint32_t kD3DFormatX8R8G8B8 = 0x16U;
        constexpr std::uint32_t kD3DFormatD24S8 = 0x4BU;
        constexpr std::uint32_t kVertexShaderModel20 = 0xFFFE0200U;
        constexpr std::uint32_t kVertexShaderModel30 = 0xFFFE0300U;
        constexpr std::uint32_t kPixelShaderModel20 = 0xFFFF0200U;
        constexpr std::uint32_t kDeclTypeFloat16_2 = 0x100U;
        constexpr std::uint32_t kDeclTypeFloat16_4 = 0x200U;
        constexpr std::uint32_t kVendorIdNvidia = 4318U;
        constexpr std::uint32_t kVendorIdAti = 32902U;
        constexpr std::uint32_t kAtiDeviceRadeonX800 = 10626U;
        constexpr std::uint32_t kAtiDeviceRadeonX850 = 10658U;
        constexpr std::uint32_t kAtiDeviceRadeonX1650 = 10754U;
        constexpr std::uint32_t kInstancingFourCC = 0x54534E49U; // 'TSNI'
        constexpr std::uint32_t kPresentIntervalImmediate = 0x80000000U;
        constexpr std::uint32_t kD3DFormatDXT5 = 0x35545844U;
        constexpr unsigned int kD3DQueryIssueBegin = 1U;
        constexpr unsigned int kD3DGetDataFlush = 1U;
        constexpr unsigned int kD3DQueryTypeEvent = 8U;
        constexpr unsigned int kD3DClearTarget = 0x1U;
        constexpr unsigned int kD3DClearZBuffer = 0x2U;
        constexpr unsigned int kD3DClearStencil = 0x4U;
        constexpr unsigned int kD3DStreamSourceIndexedData = 0x40000000U;
        constexpr unsigned int kD3DStreamSourceInstancedData = 0x80000000U;
        constexpr unsigned int kD3DTransformProjection = 3U;
        constexpr unsigned int kD3DFillMode = 0x08U;
        constexpr unsigned int kD3DFillModeWireframe = 2U;
        constexpr unsigned int kD3DFillModeSolid = 3U;
        constexpr unsigned int kD3DRenderStateAlphaBlendEnable = 0x1BU;
        constexpr unsigned int kD3DRenderStateFogEnable = 0x1CU;
        constexpr unsigned int kD3DRenderStateFogColor = 0x22U;
        constexpr unsigned int kD3DRenderStateFogTableMode = 0x23U;
        constexpr unsigned int kD3DRenderStateFogStart = 0x24U;
        constexpr unsigned int kD3DRenderStateFogEnd = 0x25U;
        constexpr unsigned int kD3DRenderStateRangeFogEnable = 0x30U;
        constexpr unsigned int kD3DRenderStateStencilEnable = 0x34U;
        constexpr unsigned int kD3DRenderStateZEnable = 0x07U;
        constexpr unsigned int kD3DRenderStateZFunc = 0x17U;
        constexpr unsigned int kD3DRenderStateAlphaTestEnable = 0x0FU;
        constexpr unsigned int kD3DRenderStateZWriteEnable = 0x0EU;
        constexpr unsigned int kD3DRenderStateColorWriteEnable = 0xA8U;
        constexpr unsigned int kD3DRenderStateDepthBias = 0xC3U;
        constexpr unsigned int kD3DRenderStateCullMode = 0x16U;
        constexpr unsigned int kD3DCullCounterClockwise = 1U;
        constexpr unsigned int kD3DCmpLessEqual = 4U;
        constexpr unsigned int kD3DFogModeLinear = 3U;
        constexpr int kCubeFaceCount = 6;
        constexpr std::uint32_t kD3DDeviceLost = 0x88760868U;
        constexpr std::uint32_t kD3DDeviceNotReset = 0x88760869U;
        constexpr HRESULT kMissingD3DXCall = static_cast<HRESULT>(0x80004005L);
        constexpr std::uint32_t kFloat16VertexStrideTableDefault[2] = {0x2CU, 0x44U};  // Address: 0x00F3275C
        constexpr std::uint32_t kFloat16VertexStrideTableCompact[2] = {0x2CU, 0x08U}; // Address: 0x00F32764
        // Address: 0x00D421CC (DAT_00D421CC)
        constexpr unsigned int kPrimitiveTypeByToken[11] = {
            1U,
            1U,
            2U,
            3U,
            4U,
            5U,
            0U,
            1U,
            2U,
            3U,
            4U,
        };
        std::uint8_t sMeshAllowFloat16 = 1U;
        std::uint8_t sMeshAllowInstancing = 1U;

        struct DeviceD3D9RuntimeView final
        {
            std::uint8_t pad00_23[0x24]{};
            int curThreadId = 0;                                  // +0x24
            msvc8::vector<AdapterD3D9> adapters{};                // +0x28
            DeviceContext deviceContext{};                         // +0x38
            boost::shared_ptr<PipelineStateD3D9> pipelineState{}; // +0x6C
            void* idirect = nullptr;                              // +0x74
            void* nativeDevice = nullptr;                         // +0x78
            void* headsBase = nullptr;                            // +0x7C
            void* frameEventQuery = nullptr;                      // +0x80
        };

        static_assert(offsetof(DeviceD3D9RuntimeView, curThreadId) == 0x24, "DeviceD3D9RuntimeView::curThreadId offset must be 0x24");
        static_assert(offsetof(DeviceD3D9RuntimeView, adapters) == 0x28, "DeviceD3D9RuntimeView::adapters offset must be 0x28");
        static_assert(
            offsetof(DeviceD3D9RuntimeView, deviceContext) == 0x38,
            "DeviceD3D9RuntimeView::deviceContext offset must be 0x38"
        );
        static_assert(offsetof(DeviceD3D9RuntimeView, pipelineState) == 0x6C, "DeviceD3D9RuntimeView::pipelineState offset must be 0x6C");
        static_assert(offsetof(DeviceD3D9RuntimeView, idirect) == 0x74, "DeviceD3D9RuntimeView::idirect offset must be 0x74");
        static_assert(offsetof(DeviceD3D9RuntimeView, nativeDevice) == 0x78, "DeviceD3D9RuntimeView::nativeDevice offset must be 0x78");
        static_assert(offsetof(DeviceD3D9RuntimeView, headsBase) == 0x7C, "DeviceD3D9RuntimeView::headsBase offset must be 0x7C");
        static_assert(
            offsetof(DeviceD3D9RuntimeView, frameEventQuery) == 0x80,
            "DeviceD3D9RuntimeView::frameEventQuery offset must be 0x80"
        );

        class DeviceD3D9BackendObject final : public DeviceD3D9
        {
        public:
            std::uint8_t pad04_23[0x20]{};
            int curThreadId = 0;
            msvc8::vector<AdapterD3D9> adapters{};
            DeviceContext deviceContext{0};
            boost::shared_ptr<PipelineStateD3D9> pipelineState{};
            void* idirect = nullptr;
            void* nativeDevice = nullptr;
            void* headsBase = nullptr;
            void* frameEventQuery = nullptr;
        };

#if defined(MOHO_ABI_MSVC8_COMPAT)
        static_assert(sizeof(DeviceD3D9BackendObject) == 0x84, "DeviceD3D9BackendObject size must be 0x84");
#endif

        struct OutputContextD3D9RuntimeView final
        {
            std::uint8_t pad00_03[0x04]{};
            boost::shared_ptr<CubeRenderTargetD3D9> cubeTarget{};    // +0x04
            std::int32_t face = 0;                                    // +0x0C
            boost::shared_ptr<RenderTargetD3D9> renderTarget{};       // +0x10
            boost::shared_ptr<DepthStencilTargetD3D9> depthStencil{}; // +0x18
        };

        static_assert(
            offsetof(OutputContextD3D9RuntimeView, cubeTarget) == 0x04,
            "OutputContextD3D9RuntimeView::cubeTarget offset must be 0x04"
        );
        static_assert(
            offsetof(OutputContextD3D9RuntimeView, face) == 0x0C,
            "OutputContextD3D9RuntimeView::face offset must be 0x0C"
        );
        static_assert(
            offsetof(OutputContextD3D9RuntimeView, renderTarget) == 0x10,
            "OutputContextD3D9RuntimeView::renderTarget offset must be 0x10"
        );
        static_assert(
            offsetof(OutputContextD3D9RuntimeView, depthStencil) == 0x18,
            "OutputContextD3D9RuntimeView::depthStencil offset must be 0x18"
        );
        static_assert(sizeof(OutputContextD3D9RuntimeView) == 0x20, "OutputContextD3D9RuntimeView size must be 0x20");

        struct DrawPrimitiveContextRuntime final
        {
            std::uint32_t pad00 = 0U;                // +0x00
            std::uint32_t topologyToken = 0U;        // +0x04
            std::uint32_t primitiveCountInput = 0U;  // +0x08
            std::uint32_t startVertex = 0U;          // +0x0C
        };

        struct DrawIndexedPrimitiveContextRuntime final
        {
            std::uint32_t pad00 = 0U;                // +0x00
            std::uint32_t topologyToken = 0U;        // +0x04
            std::uint32_t minVertexIndex = 0U;       // +0x08
            std::uint32_t vertexCount = 0U;          // +0x0C
            std::uint32_t primitiveCountInput = 0U;  // +0x10
            std::uint32_t startIndex = 0U;           // +0x14
            std::int32_t baseVertexIndex = 0;        // +0x18
        };

        static_assert(
            offsetof(DrawPrimitiveContextRuntime, topologyToken) == 0x04,
            "DrawPrimitiveContextRuntime::topologyToken offset must be 0x04"
        );
        static_assert(
            offsetof(DrawPrimitiveContextRuntime, primitiveCountInput) == 0x08,
            "DrawPrimitiveContextRuntime::primitiveCountInput offset must be 0x08"
        );
        static_assert(
            offsetof(DrawPrimitiveContextRuntime, startVertex) == 0x0C,
            "DrawPrimitiveContextRuntime::startVertex offset must be 0x0C"
        );
        static_assert(sizeof(DrawPrimitiveContextRuntime) == 0x10, "DrawPrimitiveContextRuntime size must be 0x10");
        static_assert(
            offsetof(DrawIndexedPrimitiveContextRuntime, topologyToken) == 0x04,
            "DrawIndexedPrimitiveContextRuntime::topologyToken offset must be 0x04"
        );
        static_assert(
            offsetof(DrawIndexedPrimitiveContextRuntime, primitiveCountInput) == 0x10,
            "DrawIndexedPrimitiveContextRuntime::primitiveCountInput offset must be 0x10"
        );
        static_assert(
            offsetof(DrawIndexedPrimitiveContextRuntime, startIndex) == 0x14,
            "DrawIndexedPrimitiveContextRuntime::startIndex offset must be 0x14"
        );
        static_assert(
            offsetof(DrawIndexedPrimitiveContextRuntime, baseVertexIndex) == 0x18,
            "DrawIndexedPrimitiveContextRuntime::baseVertexIndex offset must be 0x18"
        );
        static_assert(
            sizeof(DrawIndexedPrimitiveContextRuntime) == 0x1C,
            "DrawIndexedPrimitiveContextRuntime size must be 0x1C"
        );

        msvc8::vector<msvc8::string> gD3D9LogStorage{};

        struct D3DXTechniqueDescRuntime final
        {
            const char* name = nullptr; // +0x00
        };

        struct D3DXImageInfoRuntime final
        {
            unsigned int width = 0U;      // +0x00
            unsigned int height = 0U;     // +0x04
            unsigned int depth = 0U;      // +0x08
            unsigned int mipLevels = 0U;  // +0x0C
            std::uint32_t format = 0U;    // +0x10
            unsigned int resourceType = 0U; // +0x14
            unsigned int imageFileFormat = 0U; // +0x18
        };

        struct D3DSurfaceDescRuntime final
        {
            std::uint32_t format = 0U;       // +0x00
            unsigned int resourceType = 0U;  // +0x04
            unsigned int usage = 0U;         // +0x08
            D3DPOOL pool = D3DPOOL_DEFAULT;  // +0x0C
            unsigned int multisampleType = 0U; // +0x10
            unsigned int multisampleQuality = 0U; // +0x14
            unsigned int width = 0U;         // +0x18
            unsigned int height = 0U;        // +0x1C
        };

        struct D3DPresentParametersRuntime final
        {
            unsigned int backBufferWidth = 0U;           // +0x00
            unsigned int backBufferHeight = 0U;          // +0x04
            std::uint32_t backBufferFormat = 0U;         // +0x08
            unsigned int backBufferCount = 0U;           // +0x0C
            unsigned int multiSampleType = 0U;           // +0x10
            unsigned int multiSampleQuality = 0U;        // +0x14
            unsigned int swapEffect = 0U;                // +0x18
            void* deviceWindow = nullptr;                // +0x1C
            int windowed = 0;                            // +0x20
            int enableAutoDepthStencil = 0;             // +0x24
            std::uint32_t autoDepthStencilFormat = 0U;  // +0x28
            unsigned int flags = 0U;                    // +0x2C
            unsigned int fullScreenRefreshRateInHz = 0U;// +0x30
            unsigned int presentationInterval = 0U;     // +0x34
        };

        static_assert(sizeof(D3DPresentParametersRuntime) == 0x38, "D3DPresentParametersRuntime size must be 0x38");

        struct D3DLockedRectRuntime final
        {
            int pitch = 0;    // +0x00
            void* bits = nullptr; // +0x04
        };

        static_assert(sizeof(D3DLockedRectRuntime) == 0x08, "D3DLockedRectRuntime size must be 0x08");

        struct SourceMeshVertexRuntime final
        {
            std::uint8_t streamClassFlag = 0;    // +0x00
            std::uint8_t pad01_03[3]{};
            float streamScalar04 = 0.0f;         // +0x04
            std::uint32_t streamPacked08 = 0U;   // +0x08
            float streamScalar0C = 0.0f;         // +0x0C
            float transform4x4[16]{};            // +0x10 .. +0x4F
            std::uint8_t streamFlag50 = 0;       // +0x50
            std::uint8_t streamColor51 = 0;      // +0x51
            std::uint8_t streamColor52 = 0;      // +0x52
            std::uint8_t streamColor53 = 0;      // +0x53
            std::uint8_t streamColor54 = 0;      // +0x54
            std::uint8_t pad55_57[3]{};
            float streamVec58[3]{};              // +0x58 .. +0x63
            float streamVec64[3]{};              // +0x64 .. +0x6F
            float streamVec70[3]{};              // +0x70 .. +0x7B
            float streamVec7C[3]{};              // +0x7C .. +0x87
            float streamVec88[3]{};              // +0x88 .. +0x93
            float streamScalar94 = 0.0f;         // +0x94
            float streamScalar98 = 0.0f;         // +0x98
            float streamScalar9C = 0.0f;         // +0x9C
            float streamScalarA0 = 0.0f;         // +0xA0
            std::uint8_t streamBoolA4 = 0;       // +0xA4
            std::uint8_t padA5_A7[3]{};
            float streamScalarA8 = 0.0f;         // +0xA8
            float streamScalarAC = 0.0f;         // +0xAC
            std::uint8_t streamFlagB0 = 0;       // +0xB0
            std::uint8_t padB1_B3[3]{};
            float streamScalarB4 = 0.0f;         // +0xB4
        };

        struct HardwareVertexPackedStream0Runtime final
        {
            float lane00 = 0.0f;                 // +0x00
            float lane04 = 0.0f;                 // +0x04
            float lane08 = 0.0f;                 // +0x08
            float lane0C = 0.0f;                 // +0x0C
            float lane10 = 0.0f;                 // +0x10
            float lane14 = 0.0f;                 // +0x14
            float lane18 = 0.0f;                 // +0x18
            float lane1C = 0.0f;                 // +0x1C
            float lane20 = 0.0f;                 // +0x20
            float lane24 = 0.0f;                 // +0x24
            float lane28 = 0.0f;                 // +0x28
            float lane2C = 0.0f;                 // +0x2C
            float lane30 = 0.0f;                 // +0x30
            float lane34 = 0.0f;                 // +0x34
            float lane38 = 0.0f;                 // +0x38
            float lane3C = 0.0f;                 // +0x3C
            float lane40 = 0.0f;                 // +0x40
            std::uint8_t lane44 = 0;             // +0x44
            std::uint8_t lane45 = 0;             // +0x45
            std::uint8_t lane46 = 0;             // +0x46
            std::uint8_t lane47 = 0;             // +0x47
        };

        struct HardwareVertexPackedStream1Runtime final
        {
            float row0[3]{};                     // +0x00
            float row1[3]{};                     // +0x0C
            float row2[3]{};                     // +0x18
            float row3[3]{};                     // +0x24
            std::uint8_t lane30 = 0;             // +0x30
            std::uint8_t lane31 = 0;             // +0x31
            std::uint8_t lane32 = 0;             // +0x32
            std::uint8_t lane33 = 0;             // +0x33
            float lane34 = 0.0f;                 // +0x34
            float lane38 = 0.0f;                 // +0x38
            float lane3C = 0.0f;                 // +0x3C
            float lane40 = 0.0f;                 // +0x40
            std::uint32_t lane44 = 0U;           // +0x44
            float lane48 = 0.0f;                 // +0x48
        };

        struct Float16VertexPackedStream0Runtime final
        {
            std::uint16_t lane00[3]{};           // +0x00
            std::uint16_t pad06 = 0;             // +0x06
            std::uint16_t lane08[3]{};           // +0x08
            std::uint16_t pad0E = 0;             // +0x0E
            std::uint16_t lane10[3]{};           // +0x10
            std::uint16_t pad16 = 0;             // +0x16
            std::uint16_t lane18[3]{};           // +0x18
            std::uint16_t pad1E = 0;             // +0x1E
            std::uint16_t lane20 = 0;            // +0x20
            std::uint16_t lane22 = 0;            // +0x22
            std::uint16_t lane24 = 0;            // +0x24
            std::uint16_t lane26 = 0;            // +0x26
            std::uint8_t lane28 = 0;             // +0x28
            std::uint8_t lane29 = 0;             // +0x29
            std::uint8_t lane2A = 0;             // +0x2A
            std::uint8_t lane2B = 0;             // +0x2B
        };

        struct Float16VertexPackedStream1Runtime final
        {
            float row0[3]{};                     // +0x00
            float row1[3]{};                     // +0x0C
            float row2[3]{};                     // +0x18
            float row3[3]{};                     // +0x24
            std::uint8_t lane30 = 0;             // +0x30
            std::uint8_t lane31 = 0;             // +0x31
            std::uint8_t lane32 = 0;             // +0x32
            std::uint8_t lane33 = 0;             // +0x33
            std::uint16_t lane34 = 0;            // +0x34
            std::uint16_t lane36 = 0;            // +0x36
            std::uint16_t lane38 = 0;            // +0x38
            std::uint16_t lane3A = 0;            // +0x3A
            std::uint32_t lane3C = 0U;           // +0x3C
            float lane40 = 0.0f;                 // +0x40
        };

        static_assert(offsetof(SourceMeshVertexRuntime, streamScalar04) == 0x04, "SourceMeshVertexRuntime::streamScalar04 offset must be 0x04");
        static_assert(offsetof(SourceMeshVertexRuntime, transform4x4) == 0x10, "SourceMeshVertexRuntime::transform4x4 offset must be 0x10");
        static_assert(offsetof(SourceMeshVertexRuntime, streamColor51) == 0x51, "SourceMeshVertexRuntime::streamColor51 offset must be 0x51");
        static_assert(offsetof(SourceMeshVertexRuntime, streamVec58) == 0x58, "SourceMeshVertexRuntime::streamVec58 offset must be 0x58");
        static_assert(offsetof(SourceMeshVertexRuntime, streamVec70) == 0x70, "SourceMeshVertexRuntime::streamVec70 offset must be 0x70");
        static_assert(offsetof(SourceMeshVertexRuntime, streamVec88) == 0x88, "SourceMeshVertexRuntime::streamVec88 offset must be 0x88");
        static_assert(offsetof(SourceMeshVertexRuntime, streamScalarA8) == 0xA8, "SourceMeshVertexRuntime::streamScalarA8 offset must be 0xA8");
        static_assert(offsetof(SourceMeshVertexRuntime, streamFlagB0) == 0xB0, "SourceMeshVertexRuntime::streamFlagB0 offset must be 0xB0");
        static_assert(offsetof(SourceMeshVertexRuntime, streamScalarB4) == 0xB4, "SourceMeshVertexRuntime::streamScalarB4 offset must be 0xB4");
        static_assert(sizeof(SourceMeshVertexRuntime) == 0xB8, "SourceMeshVertexRuntime size must be 0xB8");

        static_assert(offsetof(HardwareVertexPackedStream0Runtime, lane0C) == 0x0C, "HardwareVertexPackedStream0Runtime::lane0C offset must be 0x0C");
        static_assert(offsetof(HardwareVertexPackedStream0Runtime, lane28) == 0x28, "HardwareVertexPackedStream0Runtime::lane28 offset must be 0x28");
        static_assert(offsetof(HardwareVertexPackedStream0Runtime, lane44) == 0x44, "HardwareVertexPackedStream0Runtime::lane44 offset must be 0x44");
        static_assert(sizeof(HardwareVertexPackedStream0Runtime) == 0x48, "HardwareVertexPackedStream0Runtime size must be 0x48");

        static_assert(offsetof(HardwareVertexPackedStream1Runtime, row1) == 0x0C, "HardwareVertexPackedStream1Runtime::row1 offset must be 0x0C");
        static_assert(offsetof(HardwareVertexPackedStream1Runtime, row2) == 0x18, "HardwareVertexPackedStream1Runtime::row2 offset must be 0x18");
        static_assert(offsetof(HardwareVertexPackedStream1Runtime, lane30) == 0x30, "HardwareVertexPackedStream1Runtime::lane30 offset must be 0x30");
        static_assert(offsetof(HardwareVertexPackedStream1Runtime, lane44) == 0x44, "HardwareVertexPackedStream1Runtime::lane44 offset must be 0x44");
        static_assert(offsetof(HardwareVertexPackedStream1Runtime, lane48) == 0x48, "HardwareVertexPackedStream1Runtime::lane48 offset must be 0x48");
        static_assert(sizeof(HardwareVertexPackedStream1Runtime) == 0x4C, "HardwareVertexPackedStream1Runtime size must be 0x4C");

        static_assert(offsetof(Float16VertexPackedStream0Runtime, lane08) == 0x08, "Float16VertexPackedStream0Runtime::lane08 offset must be 0x08");
        static_assert(offsetof(Float16VertexPackedStream0Runtime, lane10) == 0x10, "Float16VertexPackedStream0Runtime::lane10 offset must be 0x10");
        static_assert(offsetof(Float16VertexPackedStream0Runtime, lane18) == 0x18, "Float16VertexPackedStream0Runtime::lane18 offset must be 0x18");
        static_assert(offsetof(Float16VertexPackedStream0Runtime, lane20) == 0x20, "Float16VertexPackedStream0Runtime::lane20 offset must be 0x20");
        static_assert(offsetof(Float16VertexPackedStream0Runtime, lane28) == 0x28, "Float16VertexPackedStream0Runtime::lane28 offset must be 0x28");
        static_assert(sizeof(Float16VertexPackedStream0Runtime) == 0x2C, "Float16VertexPackedStream0Runtime size must be 0x2C");

        static_assert(offsetof(Float16VertexPackedStream1Runtime, row1) == 0x0C, "Float16VertexPackedStream1Runtime::row1 offset must be 0x0C");
        static_assert(offsetof(Float16VertexPackedStream1Runtime, lane30) == 0x30, "Float16VertexPackedStream1Runtime::lane30 offset must be 0x30");
        static_assert(offsetof(Float16VertexPackedStream1Runtime, lane34) == 0x34, "Float16VertexPackedStream1Runtime::lane34 offset must be 0x34");
        static_assert(offsetof(Float16VertexPackedStream1Runtime, lane3C) == 0x3C, "Float16VertexPackedStream1Runtime::lane3C offset must be 0x3C");
        static_assert(sizeof(Float16VertexPackedStream1Runtime) == 0x44, "Float16VertexPackedStream1Runtime size must be 0x44");

        struct D3DXExports final
        {
            d3dx_create_buffer_fn createBuffer = nullptr;
            d3dx_save_surface_to_file_in_memory_fn saveSurfaceToFileInMemory = nullptr;
            d3dx_save_surface_to_file_a_fn saveSurfaceToFileA = nullptr;
            d3dx_save_texture_to_file_a_fn saveTextureToFileA = nullptr;
            d3dx_load_surface_from_surface_fn loadSurfaceFromSurface = nullptr;
            d3dx_float32_to16_array_fn float32To16Array = nullptr;
            d3dx_get_image_info_from_file_in_memory_fn getImageInfoFromFileInMemory = nullptr;
            d3dx_create_texture_fn createTexture = nullptr;
            d3dx_create_texture_from_file_in_memory_ex_fn createTextureFromFileInMemoryEx = nullptr;
            d3dx_create_volume_texture_from_file_in_memory_ex_fn createVolumeTextureFromFileInMemoryEx = nullptr;
            d3dx_create_cube_texture_from_file_in_memory_ex_fn createCubeTextureFromFileInMemoryEx = nullptr;
            d3dx_get_vertex_shader_profile_fn getVertexShaderProfile = nullptr;
            d3dx_get_pixel_shader_profile_fn getPixelShaderProfile = nullptr;
        };

        void ReleaseComLike(void*& object) noexcept;

        class ComObjectScope final
        {
        public:
            ComObjectScope() noexcept = default;

            ~ComObjectScope()
            {
                ReleaseComLike(pointer_);
            }

            ComObjectScope(const ComObjectScope&) = delete;
            ComObjectScope& operator=(const ComObjectScope&) = delete;

            void* get() const noexcept
            {
                return pointer_;
            }

            void** out() noexcept
            {
                return &pointer_;
            }

            void* release() noexcept
            {
                void* const released = pointer_;
                pointer_ = nullptr;
                return released;
            }

            void reset(void* const pointer = nullptr) noexcept
            {
                ReleaseComLike(pointer_);
                pointer_ = pointer;
            }

        private:
            void* pointer_ = nullptr;
        };

        void ReleaseComLike(void*& object) noexcept
        {
            if (object == nullptr)
            {
                return;
            }

            auto** const vtable = *reinterpret_cast<void***>(object);
            auto* const release = reinterpret_cast<release_fn>(vtable[2]);
            release(object);
            object = nullptr;
        }

        HRESULT InvokeLock(
            void* const object,
            const unsigned int offset,
            const unsigned int size,
            void** const outData,
            const unsigned int lockFlags
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(object);
            auto* const lock = reinterpret_cast<lock_fn>(vtable[11]);
            return lock(object, offset, size, outData, lockFlags);
        }

        HRESULT InvokeUnlock(void* const object)
        {
            auto** const vtable = *reinterpret_cast<void***>(object);
            auto* const unlock = reinterpret_cast<unlock_fn>(vtable[12]);
            return unlock(object);
        }

        HRESULT InvokeLockRect(
            void* const texture,
            const int level,
            void* const outLockedRect,
            const RECT* const rect,
            const unsigned int flags
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(texture);
            auto* const lockRect = reinterpret_cast<lock_rect_fn>(vtable[19]);
            return lockRect(texture, level, outLockedRect, rect, flags);
        }

        HRESULT InvokeUnlockRect(void* const texture, const int level)
        {
            auto** const vtable = *reinterpret_cast<void***>(texture);
            auto* const unlockRect = reinterpret_cast<unlock_rect_fn>(vtable[20]);
            return unlockRect(texture, level);
        }

        D3DXExports ResolveD3DXExports() noexcept
        {
            D3DXExports exports{};

#if defined(_WIN32)
            d3dx_float32_to16_array_fn fallbackFloat32To16Array = nullptr;
            constexpr const char* kD3dxCandidates[] = {
                "d3dx9_43.dll",
                "d3dx9_42.dll",
                "d3dx9_41.dll",
                "d3dx9_40.dll",
                "d3dx9_39.dll",
                "d3dx9_38.dll",
                "d3dx9_37.dll",
                "d3dx9_36.dll",
                "d3dx9_35.dll",
                "d3dx9_34.dll",
                "d3dx9_33.dll",
                "d3dx9_32.dll",
                "d3dx9_31.dll",
                "d3dx9_30.dll",
                "d3dx9_29.dll",
                "d3dx9_28.dll",
                "d3dx9_27.dll",
                "d3dx9_26.dll",
                "d3dx9_25.dll",
                "d3dx9_24.dll",
            };

            for (const char* const candidate : kD3dxCandidates)
            {
                HMODULE module = ::GetModuleHandleA(candidate);
                if (module == nullptr)
                {
                    module = ::LoadLibraryA(candidate);
                }

                if (module == nullptr)
                {
                    continue;
                }

                exports.createBuffer = reinterpret_cast<d3dx_create_buffer_fn>(::GetProcAddress(module, "D3DXCreateBuffer"));
                exports.saveSurfaceToFileInMemory = reinterpret_cast<d3dx_save_surface_to_file_in_memory_fn>(
                    ::GetProcAddress(module, "D3DXSaveSurfaceToFileInMemory")
                );
                exports.saveSurfaceToFileA = reinterpret_cast<d3dx_save_surface_to_file_a_fn>(
                    ::GetProcAddress(module, "D3DXSaveSurfaceToFileA")
                );
                exports.saveTextureToFileA = reinterpret_cast<d3dx_save_texture_to_file_a_fn>(
                    ::GetProcAddress(module, "D3DXSaveTextureToFileA")
                );
                exports.loadSurfaceFromSurface = reinterpret_cast<d3dx_load_surface_from_surface_fn>(
                    ::GetProcAddress(module, "D3DXLoadSurfaceFromSurface")
                );
                exports.float32To16Array = reinterpret_cast<d3dx_float32_to16_array_fn>(
                    ::GetProcAddress(module, "D3DXFloat32To16Array")
                );
                exports.getImageInfoFromFileInMemory =
                    reinterpret_cast<d3dx_get_image_info_from_file_in_memory_fn>(
                        ::GetProcAddress(module, "D3DXGetImageInfoFromFileInMemory")
                    );
                exports.createTexture =
                    reinterpret_cast<d3dx_create_texture_fn>(::GetProcAddress(module, "D3DXCreateTexture"));
                exports.createTextureFromFileInMemoryEx =
                    reinterpret_cast<d3dx_create_texture_from_file_in_memory_ex_fn>(
                        ::GetProcAddress(module, "D3DXCreateTextureFromFileInMemoryEx")
                    );
                exports.createVolumeTextureFromFileInMemoryEx =
                    reinterpret_cast<d3dx_create_volume_texture_from_file_in_memory_ex_fn>(
                        ::GetProcAddress(module, "D3DXCreateVolumeTextureFromFileInMemoryEx")
                    );
                exports.createCubeTextureFromFileInMemoryEx =
                    reinterpret_cast<d3dx_create_cube_texture_from_file_in_memory_ex_fn>(
                        ::GetProcAddress(module, "D3DXCreateCubeTextureFromFileInMemoryEx")
                    );
                exports.getVertexShaderProfile = reinterpret_cast<d3dx_get_vertex_shader_profile_fn>(
                    ::GetProcAddress(module, "D3DXGetVertexShaderProfile")
                );
                exports.getPixelShaderProfile = reinterpret_cast<d3dx_get_pixel_shader_profile_fn>(
                    ::GetProcAddress(module, "D3DXGetPixelShaderProfile")
                );
                if ((fallbackFloat32To16Array == nullptr) && (exports.float32To16Array != nullptr))
                {
                    fallbackFloat32To16Array = exports.float32To16Array;
                }

                if ((exports.createBuffer != nullptr) && (exports.saveSurfaceToFileInMemory != nullptr))
                {
                    if (exports.float32To16Array == nullptr)
                    {
                        exports.float32To16Array = fallbackFloat32To16Array;
                    }
                    return exports;
                }

                exports = D3DXExports{};
            }

            exports.float32To16Array = fallbackFloat32To16Array;
#endif

            return exports;
        }

        const D3DXExports& GetD3DXExports() noexcept
        {
            static const D3DXExports exports = ResolveD3DXExports();
            return exports;
        }

        HRESULT InvokeD3DXCreateBuffer(const unsigned int size, void** const outBuffer)
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.createBuffer == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.createBuffer(size, outBuffer);
        }

        HRESULT InvokeD3DXSaveSurfaceToFileInMemoryEx(
            void** const outBuffer,
            const unsigned int fileFormat,
            void* const sourceSurface
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.saveSurfaceToFileInMemory == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.saveSurfaceToFileInMemory(outBuffer, fileFormat, sourceSurface, nullptr, nullptr);
        }

        HRESULT InvokeD3DXSaveSurfaceToFileInMemory(void** const outBuffer, void* const sourceSurface)
        {
            return InvokeD3DXSaveSurfaceToFileInMemoryEx(outBuffer, kD3DXIFFDDS, sourceSurface);
        }

        HRESULT InvokeD3DXSaveSurfaceToFileA(
            const char* const filePath,
            const unsigned int fileFormat,
            void* const sourceSurface
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.saveSurfaceToFileA == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.saveSurfaceToFileA(filePath, fileFormat, sourceSurface, nullptr, nullptr);
        }

        HRESULT InvokeD3DXSaveTextureToFileA(
            const char* const filePath,
            const unsigned int fileFormat,
            void* const sourceTexture
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.saveTextureToFileA == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.saveTextureToFileA(filePath, fileFormat, sourceTexture, nullptr);
        }

        HRESULT InvokeD3DXLoadSurfaceFromSurface(
            void* const destinationSurface,
            const RECT* const destinationRect,
            void* const sourceSurface,
            const RECT* const sourceRect,
            const unsigned int filter,
            const std::uint32_t colorKey
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.loadSurfaceFromSurface == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.loadSurfaceFromSurface(
                destinationSurface,
                nullptr,
                destinationRect,
                sourceSurface,
                nullptr,
                sourceRect,
                filter,
                colorKey
            );
        }

        HRESULT InvokeD3DXGetImageInfoFromFileInMemory(
            const void* const sourceData,
            const unsigned int sourceSize,
            D3DXImageInfoRuntime* const outInfo
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.getImageInfoFromFileInMemory == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.getImageInfoFromFileInMemory(sourceData, sourceSize, outInfo);
        }

        HRESULT InvokeD3DXCreateTexture(
            void* const nativeDevice,
            const unsigned int width,
            const unsigned int height,
            const unsigned int mipLevels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            void** const outTexture
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.createTexture == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.createTexture(nativeDevice, width, height, mipLevels, usage, format, pool, outTexture);
        }

        HRESULT InvokeD3DXCreateTextureFromFileInMemoryEx(
            void* const nativeDevice,
            const void* const sourceData,
            const unsigned int sourceSize,
            const unsigned int width,
            const unsigned int height,
            const unsigned int mipLevels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            const unsigned int filter,
            const unsigned int mipFilter,
            const std::uint32_t colorKey,
            const D3DXImageInfoRuntime* const sourceInfo,
            void* const palette,
            void** const outTexture
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.createTextureFromFileInMemoryEx == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.createTextureFromFileInMemoryEx(
                nativeDevice,
                sourceData,
                sourceSize,
                width,
                height,
                mipLevels,
                usage,
                format,
                pool,
                filter,
                mipFilter,
                colorKey,
                sourceInfo,
                palette,
                outTexture
            );
        }

        HRESULT InvokeD3DXCreateVolumeTextureFromFileInMemoryEx(
            void* const nativeDevice,
            const void* const sourceData,
            const unsigned int sourceSize,
            const unsigned int width,
            const unsigned int height,
            const unsigned int depth,
            const unsigned int mipLevels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            const unsigned int filter,
            const unsigned int mipFilter,
            const std::uint32_t colorKey,
            const D3DXImageInfoRuntime* const sourceInfo,
            void* const palette,
            void** const outTexture
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.createVolumeTextureFromFileInMemoryEx == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.createVolumeTextureFromFileInMemoryEx(
                nativeDevice,
                sourceData,
                sourceSize,
                width,
                height,
                depth,
                mipLevels,
                usage,
                format,
                pool,
                filter,
                mipFilter,
                colorKey,
                sourceInfo,
                palette,
                outTexture
            );
        }

        HRESULT InvokeD3DXCreateCubeTextureFromFileInMemoryEx(
            void* const nativeDevice,
            const void* const sourceData,
            const unsigned int sourceSize,
            const unsigned int edgeLength,
            const unsigned int mipLevels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            const unsigned int filter,
            const unsigned int mipFilter,
            const std::uint32_t colorKey,
            const D3DXImageInfoRuntime* const sourceInfo,
            void* const palette,
            void** const outTexture
        )
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.createCubeTextureFromFileInMemoryEx == nullptr)
            {
                return kMissingD3DXCall;
            }

            return exports.createCubeTextureFromFileInMemoryEx(
                nativeDevice,
                sourceData,
                sourceSize,
                edgeLength,
                mipLevels,
                usage,
                format,
                pool,
                filter,
                mipFilter,
                colorKey,
                sourceInfo,
                palette,
                outTexture
            );
        }

        const char* InvokeD3DXGetVertexShaderProfile(void* const nativeDevice) noexcept
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.getVertexShaderProfile == nullptr)
            {
                return nullptr;
            }

            return exports.getVertexShaderProfile(nativeDevice);
        }

        const char* InvokeD3DXGetPixelShaderProfile(void* const nativeDevice) noexcept
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.getPixelShaderProfile == nullptr)
            {
                return nullptr;
            }

            return exports.getPixelShaderProfile(nativeDevice);
        }

        std::uint16_t FallbackFloat32To16(const float value)
        {
            std::uint32_t bits = 0U;
            static_assert(sizeof(bits) == sizeof(value), "float/uint32_t size mismatch");
            std::memcpy(&bits, &value, sizeof(bits));

            const std::uint32_t sign = (bits >> 16U) & 0x8000U;
            std::int32_t exponent = static_cast<std::int32_t>((bits >> 23U) & 0xFFU) - 127 + 15;
            std::uint32_t mantissa = bits & 0x007FFFFFU;

            if (exponent <= 0)
            {
                if (exponent < -10)
                {
                    return static_cast<std::uint16_t>(sign);
                }

                mantissa = (mantissa | 0x00800000U) >> static_cast<std::uint32_t>(1 - exponent);
                return static_cast<std::uint16_t>(sign | ((mantissa + 0x00001000U) >> 13U));
            }

            if (exponent >= 31)
            {
                return static_cast<std::uint16_t>(sign | 0x7C00U);
            }

            return static_cast<std::uint16_t>(sign | (static_cast<std::uint32_t>(exponent) << 10U) | ((mantissa + 0x00001000U) >> 13U));
        }

        void InvokeD3DXFloat32To16Array(std::uint16_t* const outValues, const float* const inValues, const unsigned int count)
        {
            const D3DXExports& exports = GetD3DXExports();
            if (exports.float32To16Array != nullptr)
            {
                static_cast<void>(exports.float32To16Array(outValues, inValues, count));
                return;
            }

            for (unsigned int index = 0U; index < count; ++index)
            {
                outValues[index] = FallbackFloat32To16(inValues[index]);
            }
        }

        HRESULT InvokeGetSurfaceLevel(void* const texture, const unsigned int level, void** const outSurface)
        {
            auto** const vtable = *reinterpret_cast<void***>(texture);
            auto* const getSurfaceLevel = reinterpret_cast<get_surface_level_fn>(vtable[18]);
            return getSurfaceLevel(texture, level, outSurface);
        }

        HRESULT InvokeGetCubeMapSurface(
            void* const cubeTexture,
            const unsigned int cubeFace,
            const unsigned int level,
            void** const outSurface
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(cubeTexture);
            auto* const getCubeMapSurface = reinterpret_cast<get_cube_map_surface_fn>(vtable[18]);
            return getCubeMapSurface(cubeTexture, cubeFace, level, outSurface);
        }

        HRESULT InvokeTextureGetLevelDesc(
            void* const texture,
            const unsigned int level,
            D3DSurfaceDescRuntime* const outSurfaceDesc
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(texture);
            auto* const getLevelDesc = reinterpret_cast<texture_get_level_desc_fn>(vtable[17]);
            return getLevelDesc(texture, level, outSurfaceDesc);
        }

        unsigned int InvokeTextureGetLevelCount(void* const texture)
        {
            auto** const vtable = *reinterpret_cast<void***>(texture);
            auto* const getLevelCount = reinterpret_cast<texture_get_level_count_fn>(vtable[13]);
            return getLevelCount(texture);
        }

        HRESULT InvokeSurfaceGetDesc(void* const surface, D3DSurfaceDescRuntime* const outSurfaceDesc)
        {
            auto** const vtable = *reinterpret_cast<void***>(surface);
            auto* const getDesc = reinterpret_cast<surface_get_desc_fn>(vtable[12]);
            return getDesc(surface, outSurfaceDesc);
        }

        HRESULT InvokeSurfaceLockRect(
            void* const surface,
            D3DLockedRectRuntime* const outLockedRect,
            const RECT* const rect,
            const unsigned int flags
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(surface);
            auto* const lockRect = reinterpret_cast<surface_lock_rect_fn>(vtable[13]);
            return lockRect(surface, outLockedRect, rect, flags);
        }

        HRESULT InvokeSurfaceUnlockRect(void* const surface)
        {
            auto** const vtable = *reinterpret_cast<void***>(surface);
            auto* const unlockRect = reinterpret_cast<surface_unlock_rect_fn>(vtable[14]);
            return unlockRect(surface);
        }

        void* GetSurfaceLevel0FromTexture(void* const texture)
        {
            if (texture == nullptr)
            {
                return nullptr;
            }

            void* surface = nullptr;
            static_cast<void>(InvokeGetSurfaceLevel(texture, 0U, &surface));
            return surface;
        }

        unsigned int GetD3DXBufferSize(void* const d3dxBuffer)
        {
            auto** const vtable = *reinterpret_cast<void***>(d3dxBuffer);
            auto* const getBufferSize = reinterpret_cast<d3dx_buffer_get_size_fn>(vtable[4]);
            return getBufferSize(d3dxBuffer);
        }

        void* GetD3DXBufferPointer(void* const d3dxBuffer)
        {
            auto** const vtable = *reinterpret_cast<void***>(d3dxBuffer);
            auto* const getBufferPointer = reinterpret_cast<d3dx_buffer_get_pointer_fn>(vtable[3]);
            return getBufferPointer(d3dxBuffer);
        }

        void* InvokeEffectGetAnnotationByName(void* const effect, void* const handle, const char* const name)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getAnnotationByName = reinterpret_cast<effect_get_annotation_by_name_fn>(vtable[19]);
            return getAnnotationByName(effect, handle, name);
        }

        void* InvokeEffectGetTechniqueByName(void* const effect, const char* const name)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getTechniqueByName = reinterpret_cast<effect_get_technique_by_name_fn>(vtable[13]);
            return getTechniqueByName(effect, name);
        }

        void* InvokeEffectGetParameterByName(void* const effect, void* const parentHandle, const char* const name)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getParameterByName = reinterpret_cast<effect_get_parameter_by_name_fn>(vtable[9]);
            return getParameterByName(effect, parentHandle, name);
        }

        HRESULT InvokeEffectFindNextValidTechnique(void* const effect, void* const techniqueHandle, void** const outNextTechniqueHandle)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const findNextValidTechnique = reinterpret_cast<effect_find_next_valid_technique_fn>(vtable[61]);
            return findNextValidTechnique(effect, techniqueHandle, outNextTechniqueHandle);
        }

        HRESULT InvokeEffectGetTechniqueDesc(
            void* const effect,
            void* const techniqueHandle,
            D3DXTechniqueDescRuntime* const outDesc
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getTechniqueDesc = reinterpret_cast<effect_get_technique_desc_fn>(vtable[5]);
            return getTechniqueDesc(effect, techniqueHandle, outDesc);
        }

        HRESULT InvokeEffectSetTechnique(void* const effect, void* const techniqueHandle)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setTechnique = reinterpret_cast<effect_set_technique_fn>(vtable[58]);
            return setTechnique(effect, techniqueHandle);
        }

        HRESULT InvokeEffectSetValue(void* const effect, void* const parameterHandle, const void* const value, const unsigned int byteCount)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setValue = reinterpret_cast<effect_set_value_fn>(vtable[20]);
            return setValue(effect, parameterHandle, value, byteCount);
        }

        HRESULT InvokeEffectSetBool(void* const effect, void* const parameterHandle, const bool value)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setBool = reinterpret_cast<effect_set_bool_fn>(vtable[22]);
            return setBool(effect, parameterHandle, value ? 1 : 0);
        }

        HRESULT InvokeEffectSetInt(void* const effect, void* const parameterHandle, const int value)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setInt = reinterpret_cast<effect_set_int_fn>(vtable[26]);
            return setInt(effect, parameterHandle, value);
        }

        HRESULT InvokeEffectSetFloat(void* const effect, void* const parameterHandle, const float value)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setFloat = reinterpret_cast<effect_set_float_fn>(vtable[30]);
            return setFloat(effect, parameterHandle, value);
        }

        HRESULT InvokeEffectSetFloatArray(
            void* const effect,
            void* const parameterHandle,
            const float* const values,
            const unsigned int floatCount
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setFloatArray = reinterpret_cast<effect_set_float_array_fn>(vtable[32]);
            return setFloatArray(effect, parameterHandle, values, floatCount);
        }

        HRESULT InvokeEffectSetMatrix(void* const effect, void* const parameterHandle, const void* const matrix4x4)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setMatrix = reinterpret_cast<effect_set_matrix_fn>(vtable[38]);
            return setMatrix(effect, parameterHandle, matrix4x4);
        }

        HRESULT InvokeEffectSetVector(void* const effect, void* const parameterHandle, const void* const vector4)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setVector = reinterpret_cast<effect_set_vector_fn>(vtable[34]);
            return setVector(effect, parameterHandle, vector4);
        }

        HRESULT InvokeEffectSetVectorArray(
            void* const effect,
            void* const parameterHandle,
            const void* const vectors4,
            const unsigned int vectorCount
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setVectorArray = reinterpret_cast<effect_set_vector_array_fn>(vtable[36]);
            return setVectorArray(effect, parameterHandle, vectors4, vectorCount);
        }

        HRESULT InvokeEffectSetMatrixArray(
            void* const effect,
            void* const parameterHandle,
            const void* const matrices4x4,
            const unsigned int matrixCount
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setMatrixArray = reinterpret_cast<effect_set_matrix_array_fn>(vtable[40]);
            return setMatrixArray(effect, parameterHandle, matrices4x4, matrixCount);
        }

        HRESULT InvokeEffectSetTexture(void* const effect, void* const parameterHandle, void* const texture)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setTexture = reinterpret_cast<effect_set_texture_fn>(vtable[52]);
            return setTexture(effect, parameterHandle, texture);
        }

        HRESULT InvokeEffectBeginTechnique(void* const effect, unsigned int* const outPassCount, const unsigned int flags)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const beginTechnique = reinterpret_cast<effect_begin_technique_fn>(vtable[63]);
            return beginTechnique(effect, outPassCount, flags);
        }

        HRESULT InvokeEffectEndTechnique(void* const effect)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const endTechnique = reinterpret_cast<effect_end_technique_fn>(vtable[67]);
            return endTechnique(effect);
        }

        HRESULT InvokeEffectBeginPass(void* const effect, const unsigned int pass)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const beginPass = reinterpret_cast<effect_begin_pass_fn>(vtable[64]);
            return beginPass(effect, pass);
        }

        HRESULT InvokeEffectEndPass(void* const effect)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const endPass = reinterpret_cast<effect_end_pass_fn>(vtable[66]);
            return endPass(effect);
        }

        HRESULT InvokeEffectGetBool(void* const effect, void* const annotationHandle, int* const outValue)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getBool = reinterpret_cast<effect_get_bool_fn>(vtable[23]);
            return getBool(effect, annotationHandle, outValue);
        }

        HRESULT InvokeEffectGetInt(void* const effect, void* const annotationHandle, int* const outValue)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getInt = reinterpret_cast<effect_get_int_fn>(vtable[27]);
            return getInt(effect, annotationHandle, outValue);
        }

        HRESULT InvokeEffectGetFloat(void* const effect, void* const annotationHandle, float* const outValue)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getFloat = reinterpret_cast<effect_get_float_fn>(vtable[31]);
            return getFloat(effect, annotationHandle, outValue);
        }

        HRESULT InvokeEffectGetString(void* const effect, void* const annotationHandle, const char** const outValue)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const getString = reinterpret_cast<effect_get_string_fn>(vtable[51]);
            return getString(effect, annotationHandle, outValue);
        }

        HRESULT InvokeEffectSetStateManager(void* const effect, void* const stateManager)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const setStateManager = reinterpret_cast<effect_set_state_manager_fn>(vtable[71]);
            return setStateManager(effect, stateManager);
        }

        HRESULT InvokeEffectOnResetDevice(void* const effect)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const onResetDevice = reinterpret_cast<effect_on_reset_device_fn>(vtable[70]);
            return onResetDevice(effect);
        }

        HRESULT InvokeEffectOnLostDevice(void* const effect)
        {
            auto** const vtable = *reinterpret_cast<void***>(effect);
            auto* const onLostDevice = reinterpret_cast<effect_on_lost_device_fn>(vtable[69]);
            return onLostDevice(effect);
        }

        void* InvokeDeviceGetContext(Device* const device)
        {
            auto** const vtable = *reinterpret_cast<void***>(device);
            auto* const getContext = reinterpret_cast<device_get_context_fn>(vtable[2]);
            return getContext(device);
        }

        void InvokeDeviceGetPipelineState(Device* const device, boost::shared_ptr<PipelineStateD3D9>* const outPipelineState)
        {
            auto** const vtable = *reinterpret_cast<void***>(device);
            auto* const getPipelineState = reinterpret_cast<device_get_pipeline_state_fn>(vtable[8]);
            getPipelineState(device, outPipelineState);
        }

        void InvokeDeviceCreateVertexFormat(Device* const device, void* const outVertexFormatToken, const int formatCode)
        {
            auto** const vtable = *reinterpret_cast<void***>(device);
            auto* const createVertexFormat = reinterpret_cast<device_create_vertex_format_fn>(vtable[14]);
            createVertexFormat(device, outVertexFormatToken, formatCode);
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

        DeviceD3D9RuntimeView& AsDeviceD3D9Runtime(DeviceD3D9& device) noexcept
        {
            return *reinterpret_cast<DeviceD3D9RuntimeView*>(&device);
        }

        const DeviceD3D9RuntimeView& AsDeviceD3D9Runtime(const DeviceD3D9& device) noexcept
        {
            return *reinterpret_cast<const DeviceD3D9RuntimeView*>(&device);
        }

        const OutputContextD3D9RuntimeView& AsOutputContextD3D9Runtime(const OutputContext& context) noexcept
        {
            return *reinterpret_cast<const OutputContextD3D9RuntimeView*>(&context);
        }

        DeviceContext* GetEmbeddedDeviceContext(DeviceD3D9* const device) noexcept
        {
            return &AsDeviceD3D9Runtime(*device).deviceContext;
        }

        int InvokeNativeD3D9ShowCursor(void* const nativeDevice, const bool show)
        {
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const showCursor = reinterpret_cast<d3d9_device_show_cursor_fn>(vtable[12]);
            return showCursor(nativeDevice, show ? 1 : 0);
        }

        std::uint32_t GetDeviceContextHeadCount(const DeviceContext* const context) noexcept
        {
            if (context == nullptr)
            {
                return 0U;
            }

            return static_cast<std::uint32_t>(context->GetHeadCount());
        }

        std::uint32_t GetDeviceHeadCount(DeviceD3D9* const device) noexcept
        {
            return GetDeviceContextHeadCount(GetEmbeddedDeviceContext(device));
        }

        void* GetDeviceHeadArrayBase(DeviceD3D9* const device) noexcept
        {
            return AsDeviceD3D9Runtime(*device).headsBase;
        }

        std::uint32_t GetD3DFormat(std::uint32_t formatToken);
        std::uint32_t FormatToD3DFormat(std::uint32_t formatToken);
        std::uint32_t FormatGalToD3D(std::uint32_t mohoFormat);

        HRESULT InvokeNativeCreateTexture(
            DeviceD3D9* const device,
            const unsigned int width,
            const unsigned int height,
            const unsigned int levels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            void** const outTexture
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createTexture = reinterpret_cast<d3d9_device_create_texture_fn>(vtable[23]);
            return createTexture(nativeDevice, width, height, levels, usage, format, pool, outTexture, nullptr);
        }

        HRESULT InvokeNativeCreateCubeTexture(
            DeviceD3D9* const device,
            const unsigned int edgeLength,
            const unsigned int levels,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            void** const outTexture
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createCubeTexture = reinterpret_cast<d3d9_device_create_cube_texture_fn>(vtable[25]);
            return createCubeTexture(nativeDevice, edgeLength, levels, usage, format, pool, outTexture, nullptr);
        }

        HRESULT InvokeNativeCreateDepthStencilSurface(
            DeviceD3D9* const device,
            const unsigned int width,
            const unsigned int height,
            const std::uint32_t format,
            const unsigned int multiSampleType,
            const unsigned int multiSampleQuality,
            void** const outSurface
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createDepthStencilSurface =
                reinterpret_cast<d3d9_device_create_depth_stencil_surface_fn>(vtable[29]);
            return createDepthStencilSurface(
                nativeDevice,
                width,
                height,
                format,
                multiSampleType,
                multiSampleQuality,
                0,
                outSurface,
                nullptr
            );
        }

        HRESULT InvokeNativeCreateVertexDeclaration(
            DeviceD3D9* const device,
            const void* const vertexElements,
            void** const outDeclaration
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createVertexDeclaration =
                reinterpret_cast<d3d9_device_create_vertex_declaration_fn>(vtable[86]);
            return createVertexDeclaration(nativeDevice, vertexElements, outDeclaration);
        }

        HRESULT InvokeNativeCreateVertexBuffer(
            DeviceD3D9* const device,
            const unsigned int length,
            const unsigned int usage,
            const unsigned int fvf,
            const D3DPOOL pool,
            void** const outBuffer
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createVertexBuffer = reinterpret_cast<d3d9_device_create_vertex_buffer_fn>(vtable[26]);
            return createVertexBuffer(nativeDevice, length, usage, fvf, pool, outBuffer, nullptr);
        }

        HRESULT InvokeNativeCreateIndexBuffer(
            DeviceD3D9* const device,
            const unsigned int length,
            const unsigned int usage,
            const std::uint32_t format,
            const D3DPOOL pool,
            void** const outBuffer
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createIndexBuffer = reinterpret_cast<d3d9_device_create_index_buffer_fn>(vtable[27]);
            return createIndexBuffer(nativeDevice, length, usage, format, pool, outBuffer, nullptr);
        }

        HRESULT InvokeNativeGetBackBuffer(
            DeviceD3D9* const device,
            const unsigned int swapChainIndex,
            const unsigned int backBufferIndex,
            const unsigned int backBufferType,
            void** const outBackBuffer
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getBackBuffer = reinterpret_cast<d3d9_device_get_back_buffer_fn>(vtable[18]);
            return getBackBuffer(nativeDevice, swapChainIndex, backBufferIndex, backBufferType, outBackBuffer);
        }

        HRESULT InvokeNativeReset(DeviceD3D9* const device, void* const presentParameters)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const reset = reinterpret_cast<d3d9_device_reset_fn>(vtable[16]);
            return reset(nativeDevice, presentParameters);
        }

        HRESULT InvokeNativeGetDeviceCaps(DeviceD3D9* const device, void* const outCaps)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getDeviceCaps = reinterpret_cast<d3d9_device_get_device_caps_fn>(vtable[7]);
            return getDeviceCaps(nativeDevice, outCaps);
        }

        HRESULT InvokeNativeCreateQuery(DeviceD3D9* const device, const unsigned int queryType, void** const outQuery)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const createQuery = reinterpret_cast<d3d9_device_create_query_fn>(vtable[118]);
            return createQuery(nativeDevice, queryType, outQuery);
        }

        HRESULT InvokeNativeSetRenderState(
            DeviceD3D9* const device,
            const unsigned int state,
            const unsigned int value
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setRenderState = reinterpret_cast<d3d9_device_set_render_state_fn>(vtable[57]);
            return setRenderState(nativeDevice, state, value);
        }

        HRESULT InvokeNativeCheckDeviceFormat(
            DeviceD3D9* const device,
            const unsigned int adapter,
            const unsigned int deviceType,
            const std::uint32_t adapterFormat,
            const unsigned int usage,
            const unsigned int resourceType,
            const std::uint32_t checkFormat
        )
        {
            void* const idirect = AsDeviceD3D9Runtime(*device).idirect;
            auto** const vtable = *reinterpret_cast<void***>(idirect);
            auto* const checkDeviceFormat = reinterpret_cast<d3d9_check_device_format_fn>(vtable[10]);
            return checkDeviceFormat(idirect, adapter, deviceType, adapterFormat, usage, resourceType, checkFormat);
        }

        HRESULT InvokeNativeCheckDeviceMultiSampleType(
            DeviceD3D9* const device,
            const unsigned int adapter,
            const unsigned int deviceType,
            const std::uint32_t surfaceFormat,
            const bool windowed,
            const unsigned int multiSampleType,
            unsigned int* const outQualityLevels
        )
        {
            void* const idirect = AsDeviceD3D9Runtime(*device).idirect;
            auto** const vtable = *reinterpret_cast<void***>(idirect);
            auto* const checkMultiSample = reinterpret_cast<d3d9_check_device_multisample_type_fn>(vtable[11]);
            return checkMultiSample(
                idirect,
                adapter,
                deviceType,
                surfaceFormat,
                windowed ? 1 : 0,
                multiSampleType,
                outQualityLevels
            );
        }

        HRESULT InvokeNativeGetAdapterIdentifier(
            DeviceD3D9* const device,
            const unsigned int adapter,
            const unsigned int flags,
            void* const outIdentifier
        )
        {
            void* const idirect = AsDeviceD3D9Runtime(*device).idirect;
            auto** const vtable = *reinterpret_cast<void***>(idirect);
            auto* const getAdapterIdentifier = reinterpret_cast<d3d9_get_adapter_identifier_fn>(vtable[5]);
            return getAdapterIdentifier(idirect, adapter, flags, outIdentifier);
        }

        HRESULT InvokeNativeGetRenderTargetData(
            DeviceD3D9* const device,
            void* const sourceSurface,
            void* const destinationSurface
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getRenderTargetData = reinterpret_cast<d3d9_device_get_render_target_data_fn>(vtable[32]);
            return getRenderTargetData(nativeDevice, sourceSurface, destinationSurface);
        }

        HRESULT InvokeNativeStretchRect(
            DeviceD3D9* const device,
            void* const sourceSurface,
            const RECT* const sourceRect,
            void* const destinationSurface,
            const RECT* const destinationRect,
            const unsigned int filter
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const stretchRect = reinterpret_cast<d3d9_device_stretch_rect_fn>(vtable[34]);
            return stretchRect(nativeDevice, sourceSurface, sourceRect, destinationSurface, destinationRect, filter);
        }

        HRESULT InvokeNativeTestCooperativeLevel(DeviceD3D9* const device)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const testCooperativeLevel = reinterpret_cast<d3d9_device_test_cooperative_level_fn>(vtable[3]);
            return testCooperativeLevel(nativeDevice);
        }

        HRESULT InvokeNativeBeginScene(DeviceD3D9* const device)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const beginScene = reinterpret_cast<d3d9_device_begin_scene_fn>(vtable[41]);
            return beginScene(nativeDevice);
        }

        HRESULT InvokeNativeEndScene(DeviceD3D9* const device)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const endScene = reinterpret_cast<d3d9_device_end_scene_fn>(vtable[42]);
            return endScene(nativeDevice);
        }

        HRESULT InvokeNativePresent(DeviceD3D9* const device)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const present = reinterpret_cast<d3d9_device_present_fn>(vtable[17]);
            return present(nativeDevice, nullptr, nullptr, nullptr, nullptr);
        }

        HRESULT InvokeNativeSetCursorProperties(
            DeviceD3D9* const device,
            const unsigned int hotspotX,
            const unsigned int hotspotY,
            void* const cursorSurface
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setCursorProperties = reinterpret_cast<d3d9_device_set_cursor_properties_fn>(vtable[10]);
            return setCursorProperties(nativeDevice, hotspotX, hotspotY, cursorSurface);
        }

        HRESULT InvokeNativeSetViewport(DeviceD3D9* const device, const void* const viewport)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setViewport = reinterpret_cast<d3d9_device_set_viewport_fn>(vtable[47]);
            return setViewport(nativeDevice, viewport);
        }

        HRESULT InvokeNativeGetViewport(DeviceD3D9* const device, void* const outViewport)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getViewport = reinterpret_cast<d3d9_device_get_viewport_fn>(vtable[48]);
            return getViewport(nativeDevice, outViewport);
        }

        HRESULT InvokeNativeGetRenderTarget(DeviceD3D9* const device, const unsigned int index, void** const outRenderTarget)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getRenderTarget = reinterpret_cast<d3d9_device_get_render_target_fn>(vtable[38]);
            return getRenderTarget(nativeDevice, index, outRenderTarget);
        }

        HRESULT InvokeNativeSetRenderTarget(DeviceD3D9* const device, const unsigned int index, void* const renderTarget)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setRenderTarget = reinterpret_cast<d3d9_device_set_render_target_fn>(vtable[37]);
            return setRenderTarget(nativeDevice, index, renderTarget);
        }

        HRESULT InvokeNativeGetDepthStencilSurface(DeviceD3D9* const device, void** const outDepthStencilSurface)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const getDepthStencilSurface = reinterpret_cast<d3d9_device_get_depth_stencil_surface_fn>(vtable[39]);
            return getDepthStencilSurface(nativeDevice, outDepthStencilSurface);
        }

        HRESULT InvokeNativeSetDepthStencilSurface(DeviceD3D9* const device, void* const depthStencilSurface)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setDepthStencilSurface = reinterpret_cast<d3d9_device_set_depth_stencil_surface_fn>(vtable[40]);
            return setDepthStencilSurface(nativeDevice, depthStencilSurface);
        }

        HRESULT InvokeNativeClear(
            DeviceD3D9* const device,
            const unsigned int count,
            const void* const rects,
            const unsigned int flags,
            const std::uint32_t color,
            const float depth,
            const unsigned int stencil
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const clear = reinterpret_cast<d3d9_device_clear_fn>(vtable[43]);
            return clear(nativeDevice, count, rects, flags, color, depth, stencil);
        }

        HRESULT InvokeNativeSetVertexDeclaration(DeviceD3D9* const device, void* const vertexDeclaration)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setVertexDeclaration = reinterpret_cast<d3d9_device_set_vertex_declaration_fn>(vtable[87]);
            return setVertexDeclaration(nativeDevice, vertexDeclaration);
        }

        HRESULT InvokeNativeSetStreamSource(
            DeviceD3D9* const device,
            const unsigned int streamSlot,
            void* const streamData,
            const unsigned int offsetInBytes,
            const unsigned int stride
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setStreamSource = reinterpret_cast<d3d9_device_set_stream_source_fn>(vtable[100]);
            return setStreamSource(nativeDevice, streamSlot, streamData, offsetInBytes, stride);
        }

        HRESULT InvokeNativeSetStreamSourceFreq(
            DeviceD3D9* const device,
            const unsigned int streamSlot,
            const unsigned int setting
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setStreamSourceFreq = reinterpret_cast<d3d9_device_set_stream_source_freq_fn>(vtable[102]);
            return setStreamSourceFreq(nativeDevice, streamSlot, setting);
        }

        HRESULT InvokeNativeSetIndices(DeviceD3D9* const device, void* const indexBuffer)
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const setIndices = reinterpret_cast<d3d9_device_set_indices_fn>(vtable[104]);
            return setIndices(nativeDevice, indexBuffer);
        }

        HRESULT InvokeNativeDrawPrimitive(
            DeviceD3D9* const device,
            const unsigned int primitiveType,
            const unsigned int startVertex,
            const unsigned int primitiveCount
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const drawPrimitive = reinterpret_cast<d3d9_device_draw_primitive_fn>(vtable[81]);
            return drawPrimitive(nativeDevice, primitiveType, startVertex, primitiveCount);
        }

        HRESULT InvokeNativeDrawIndexedPrimitive(
            DeviceD3D9* const device,
            const unsigned int primitiveType,
            const int baseVertexIndex,
            const unsigned int minVertexIndex,
            const unsigned int vertexCount,
            const unsigned int startIndex,
            const unsigned int primitiveCount
        )
        {
            void* const nativeDevice = AsDeviceD3D9Runtime(*device).nativeDevice;
            auto** const vtable = *reinterpret_cast<void***>(nativeDevice);
            auto* const drawIndexedPrimitive = reinterpret_cast<d3d9_device_draw_indexed_primitive_fn>(vtable[82]);
            return drawIndexedPrimitive(
                nativeDevice,
                primitiveType,
                baseVertexIndex,
                minVertexIndex,
                vertexCount,
                startIndex,
                primitiveCount
            );
        }

        HRESULT InvokeQueryIssue(void* const query, const unsigned int issueFlags)
        {
            auto** const vtable = *reinterpret_cast<void***>(query);
            auto* const issue = reinterpret_cast<query_issue_fn>(vtable[6]);
            return issue(query, issueFlags);
        }

        HRESULT InvokeQueryGetData(
            void* const query,
            void* const outData,
            const unsigned int dataSize,
            const unsigned int getDataFlags
        )
        {
            auto** const vtable = *reinterpret_cast<void***>(query);
            auto* const getData = reinterpret_cast<query_get_data_fn>(vtable[7]);
            return getData(query, outData, dataSize, getDataFlags);
        }

        unsigned int MapImageFormatTokenToD3DX(const int token) noexcept
        {
            // DAT_00D421E4 image-format map lane (D3DXIMAGE_FILEFORMAT-compatible values).
            static constexpr unsigned int kD3DXImageFormats[] = {
                0U, // BMP
                1U, // JPG
                2U, // TGA
                3U, // PNG
                4U, // DDS
                5U, // PPM
                6U, // DIB
                7U, // HDR
                8U, // PFM
            };

            constexpr unsigned int kFormatCount =
                static_cast<unsigned int>(sizeof(kD3DXImageFormats) / sizeof(kD3DXImageFormats[0]));

            if ((token < 0) || (static_cast<unsigned int>(token) >= kFormatCount))
            {
                return kD3DXIFFDDS;
            }

            return kD3DXImageFormats[token];
        }

        unsigned int AlignToDword(const unsigned int value) noexcept
        {
            return (value + 3U) & ~3U;
        }

        const char* GetStringDataRaw(const msvc8::string& text) noexcept
        {
            return (text.myRes < 16U) ? text.bx.buf : text.bx.ptr;
        }

        msvc8::string MakeShortString(const char* const text)
        {
            if (text == nullptr)
            {
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

        int ResolveVertexShaderProfileToken(const char* const profileName) noexcept
        {
            static constexpr const char* kVertexProfiles[] = {
                "undefined",
                "vs_1_1",
                "vs_2_0",
                "vs_2_a",
                "vs_3_0",
            };

            if (profileName == nullptr)
            {
                return 2;
            }

            for (int index = 0; index < static_cast<int>(sizeof(kVertexProfiles) / sizeof(kVertexProfiles[0])); ++index)
            {
                if (std::strcmp(profileName, kVertexProfiles[index]) == 0)
                {
                    return index;
                }
            }

            return 2;
        }

        int ResolvePixelShaderProfileToken(const char* const profileName) noexcept
        {
            static constexpr const char* kPixelProfiles[] = {
                "undefined",
                "ps_1_1",
                "ps_1_2",
                "ps_1_3",
                "ps_1_4",
                "ps_2_0",
                "ps_2_a",
                "ps_2_b",
                "ps_3_0",
            };

            if (profileName == nullptr)
            {
                return 5;
            }

            for (int index = 0; index < static_cast<int>(sizeof(kPixelProfiles) / sizeof(kPixelProfiles[0])); ++index)
            {
                if (std::strcmp(profileName, kPixelProfiles[index]) == 0)
                {
                    return index;
                }
            }

            return 5;
        }

        /**
         * Address: 0x008F1480 (FUN_008F1480, func_CheckAdapters)
         *
         * What it does:
         * Validates setup adapter selection against the requested device-context
         * head configuration.
         */
        [[maybe_unused]] void CheckAdapterSelectionForSetup(DeviceD3D9& device, const DeviceContext& context)
        {
            device.Func1();

            const DeviceD3D9RuntimeView& runtime = AsDeviceD3D9Runtime(device);
            const unsigned int headCount = static_cast<unsigned int>(context.GetHeadCount());
            const unsigned int adapterCount = static_cast<unsigned int>(runtime.adapters.size());

            if (headCount > adapterCount)
            {
                ThrowGalError("DeviceD3D9.cpp", 1229, "invalid head count");
            }

            if ((headCount > 1U) && (context.mAdapter != 0U))
            {
                ThrowGalError("DeviceD3D9.cpp", 1235, "invalid primary adapter index");
            }
        }

        void CheckHardwareInstancingSupport(DeviceD3D9& device, const D3DCAPS9& caps)
        {
            auto& runtime = AsDeviceD3D9Runtime(device);
            DeviceContext& context = runtime.deviceContext;

            context.mHWBasedInstancing = true;
            if (caps.VertexShaderVersion < kVertexShaderModel30)
            {
                const HRESULT instancingFormatResult = InvokeNativeCheckDeviceFormat(
                    &device,
                    static_cast<unsigned int>(context.mAdapter),
                    kD3DDevTypeHal,
                    kD3DFormatX8R8G8B8,
                    0U,
                    kD3DRTypeSurface,
                    kInstancingFourCC
                );

                if (instancingFormatResult >= 0)
                {
                    const HRESULT pointSizeResult =
                        InvokeNativeSetRenderState(&device, kD3DRenderStatePointSize, kInstancingFourCC);
                    if (pointSizeResult < 0)
                    {
                        context.mHWBasedInstancing = false;
                    }
                }
                else
                {
                    bool supportedAdapterFallback = false;
                    const auto adapterIndex = static_cast<std::size_t>(context.mAdapter);
                    if (adapterIndex < runtime.adapters.size())
                    {
                        const AdapterD3D9& adapter = runtime.adapters[adapterIndex];
                        supportedAdapterFallback =
                            (adapter.vendorId == kVendorIdAti) &&
                            ((adapter.deviceId == kAtiDeviceRadeonX800) || (adapter.deviceId == kAtiDeviceRadeonX850) ||
                             (adapter.deviceId == kAtiDeviceRadeonX1650));
                    }

                    if (!supportedAdapterFallback)
                    {
                        context.mHWBasedInstancing = false;
                    }
                }
            }

            if (context.mValidate && !context.mHWBasedInstancing)
            {
                ThrowGalError("DeviceD3D9.cpp", 1434, "device does not support hardware based instancing");
            }
        }

        unsigned int ResolvePrimitiveType(const unsigned int topologyToken) noexcept
        {
            if (topologyToken < (sizeof(kPrimitiveTypeByToken) / sizeof(kPrimitiveTypeByToken[0])))
            {
                return kPrimitiveTypeByToken[topologyToken];
            }

            return 0U;
        }

        /**
         * Address: 0x0093F180 (FUN_0093F180)
         *
         * What it does:
         * Validates draw-count payload against primitive topology and converts
         * vertex/input counts to native primitive counts.
         */
        unsigned int ComputePrimitiveCountForTopology(
            const unsigned int primitiveType,
            const unsigned int primitiveCountInput
        )
        {
            switch (primitiveType)
            {
                case 1U:
                    return primitiveCountInput;
                case 2U:
                    if ((primitiveCountInput & 1U) != 0U)
                    {
                        ThrowGalError("DrawContext.cpp", 35, "invalid number of vertices in line list");
                    }
                    return (primitiveCountInput >> 1U);
                case 3U:
                    if (primitiveCountInput <= 1U)
                    {
                        ThrowGalError("DrawContext.cpp", 39, "invalid number of vertices in line strip");
                    }
                    return (primitiveCountInput - 1U);
                case 4U:
                    if ((primitiveCountInput % 3U) != 0U)
                    {
                        ThrowGalError("DrawContext.cpp", 43, "invalid number of vertices in triangle list");
                    }
                    return (primitiveCountInput / 3U);
                case 5U:
                    if (primitiveCountInput <= 2U)
                    {
                        ThrowGalError("DrawContext.cpp", 47, "invalid number of vertices in triangle list");
                    }
                    return (primitiveCountInput - 2U);
                default:
                    ThrowGalError("DrawContext.cpp", 51, "unknown topology specified");
            }
        }

        /**
         * Address: 0x0093F470 (FUN_0093F470)
         *
         * What it does:
         * Returns recovered primitive-count conversion for non-indexed draw payload.
         */
        unsigned int GetDrawPrimitiveCount(const DrawPrimitiveContextRuntime& context)
        {
            return ComputePrimitiveCountForTopology(context.topologyToken, context.primitiveCountInput);
        }

        /**
         * Address: 0x0093F490 (FUN_0093F490)
         *
         * What it does:
         * Returns recovered primitive-count conversion for indexed draw payload.
         */
        unsigned int GetDrawIndexedPrimitiveCount(const DrawIndexedPrimitiveContextRuntime& context)
        {
            return ComputePrimitiveCountForTopology(context.topologyToken, context.primitiveCountInput);
        }

        boost::shared_ptr<EffectD3D9> LockEffectOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = weakEffect.lock();
            if (!effect)
            {
                ThrowGalError("EffectTechniqueD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }

        boost::shared_ptr<EffectD3D9> LockEffectVariableOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = weakEffect.lock();
            if (!effect)
            {
                ThrowGalError("EffectVariableD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }

        boost::shared_ptr<EffectTechniqueD3D9> CreateEffectTechniqueWrapper(
            const char* const name,
            const boost::weak_ptr<EffectD3D9>& effect,
            void* const handle
        )
        {
            boost::shared_ptr<EffectTechniqueD3D9> technique(new EffectTechniqueD3D9());
            technique->name_.assign_owned(name != nullptr ? name : "");
            technique->effect_ = effect;
            technique->handle_ = handle;
            technique->beginEndActive_ = false;
            return technique;
        }

        boost::shared_ptr<EffectVariableD3D9> CreateEffectVariableWrapper(
            const char* const name,
            const boost::weak_ptr<EffectD3D9>& effect,
            void* const handle
        )
        {
            return boost::shared_ptr<EffectVariableD3D9>(new EffectVariableD3D9(name, effect, handle));
        }

        unsigned int ToIndexBufferLockFlags(const MohoD3DLockFlags flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::NoOverwrite)) != 0U)
            {
                converted |= kD3DLockNoOverwrite;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= kD3DLockDiscard;
            }

            return converted;
        }

        unsigned int ToVertexBufferLockFlags(const MohoD3DLockFlags flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::NoOverwrite)) != 0U)
            {
                converted |= kD3DLockNoOverwrite;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= kD3DLockDiscard;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::ReadOnly)) != 0U)
            {
                converted |= kD3DLockReadOnly;
            }

            return converted;
        }

        unsigned int ToTextureLockFlags(const int flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::NoOverwrite)) != 0U)
            {
                converted |= kD3DLockNoOverwrite;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= kD3DLockDiscard;
            }

            return converted;
        }

        struct D3D9FormatToMohoPair final
        {
            std::uint32_t d3dFormat = 0U;
            std::uint32_t mohoFormat = 0U;
        };

        // Address: 0x00D47FF0 (DAT_00D47FF0)
        constexpr D3D9FormatToMohoPair kD3D9FormatToMohoPairs[60] = {
            {0x00000000U, 0x00000014U},
            {0x00000014U, 0x00000001U},
            {0x00000015U, 0x00000002U},
            {0x00000016U, 0x00000003U},
            {0x00000017U, 0x00000004U},
            {0x00000018U, 0x00000014U},
            {0x00000019U, 0x00000014U},
            {0x0000001AU, 0x00000014U},
            {0x0000001BU, 0x00000014U},
            {0x0000001CU, 0x00000005U},
            {0x0000001DU, 0x00000014U},
            {0x0000001EU, 0x00000014U},
            {0x0000001FU, 0x00000014U},
            {0x00000020U, 0x00000014U},
            {0x00000021U, 0x00000014U},
            {0x00000022U, 0x00000014U},
            {0x00000023U, 0x00000014U},
            {0x00000024U, 0x00000014U},
            {0x00000028U, 0x00000014U},
            {0x00000029U, 0x00000014U},
            {0x00000032U, 0x00000006U},
            {0x00000033U, 0x00000007U},
            {0x00000034U, 0x00000014U},
            {0x0000003CU, 0x00000014U},
            {0x0000003DU, 0x00000014U},
            {0x0000003EU, 0x00000014U},
            {0x0000003FU, 0x00000014U},
            {0x00000040U, 0x00000014U},
            {0x00000043U, 0x00000014U},
            {0x59565955U, 0x00000014U},
            {0x47424752U, 0x00000014U},
            {0x32595559U, 0x00000014U},
            {0x42475247U, 0x00000014U},
            {0x31545844U, 0x00000008U},
            {0x32545844U, 0x00000009U},
            {0x33545844U, 0x0000000AU},
            {0x34545844U, 0x0000000BU},
            {0x35545844U, 0x0000000CU},
            {0x00000046U, 0x00000014U},
            {0x00000047U, 0x00000014U},
            {0x00000049U, 0x00000014U},
            {0x0000004BU, 0x00000014U},
            {0x0000004DU, 0x00000014U},
            {0x0000004FU, 0x00000014U},
            {0x00000050U, 0x00000014U},
            {0x00000052U, 0x00000014U},
            {0x00000053U, 0x00000014U},
            {0x00000051U, 0x00000014U},
            {0x00000064U, 0x00000014U},
            {0x00000065U, 0x00000014U},
            {0x00000066U, 0x00000014U},
            {0x0000006EU, 0x00000014U},
            {0x3154454DU, 0x00000014U},
            {0x0000006FU, 0x0000000DU},
            {0x00000070U, 0x0000000EU},
            {0x00000071U, 0x0000000FU},
            {0x00000072U, 0x00000010U},
            {0x00000073U, 0x00000011U},
            {0x00000074U, 0x00000012U},
            {0x00000075U, 0x00000014U},
        };

        // Address: 0x00D42E84 (`gpg::gal::sGalFormatToD3D`)
        // Address: 0x00D47C8C (`dword_D47C8C`) -- identical cube-target format map.
        constexpr std::uint32_t kGalFormatToD3D[9] = {
            0x00000000U,
            0x00000023U,
            0x00000015U,
            0x00000016U,
            0x00000019U,
            0x00000018U,
            0x00000017U,
            0x00000022U,
            0x00000000U,
        };

        // Address: 0x00D42194 (`gpg::gal::D3DFormats`)
        constexpr std::uint32_t kDepthStencilFormatToD3D[8] = {
            0x00000000U,
            0x00000047U,
            0x00000049U,
            0x0000004BU,
            0x0000004DU,
            0x0000004FU,
            0x00000050U,
            0x00000000U,
        };

        /**
         * Address: 0x008F52F0 (FUN_008F52F0)
         *
         * int
         *
         * What it does:
         * Maps gal texture-format token to D3D9 format via `sGalFormatToD3D`.
         */
        [[maybe_unused]] std::uint32_t GetD3DFormat(const std::uint32_t formatToken)
        {
            return (formatToken < static_cast<std::uint32_t>(sizeof(kGalFormatToD3D) / sizeof(kGalFormatToD3D[0])))
                     ? kGalFormatToD3D[formatToken]
                     : 0U;
        }

        /**
         * Address: 0x008E7F50 (FUN_008E7F50)
         *
         * int
         *
         * What it does:
         * Maps depth-stencil format token to D3D9 depth format via `D3DFormats`.
         */
        [[maybe_unused]] std::uint32_t FormatToD3DFormat(const std::uint32_t formatToken)
        {
            return (formatToken <
                    static_cast<std::uint32_t>(sizeof(kDepthStencilFormatToD3D) / sizeof(kDepthStencilFormatToD3D[0])))
                     ? kDepthStencilFormatToD3D[formatToken]
                     : 0U;
        }

        /**
         * Address: 0x0094A0D0 (FUN_0094A0D0)
         *
         * What it does:
         * Converts a D3D9 format token to the legacy Moho format enum via the
         * static pair table at `DAT_00D47FF0`.
         */
        [[maybe_unused]] std::uint32_t FormatD3D9ToMoho(const std::uint32_t d3dFormat)
        {
            for (const D3D9FormatToMohoPair& pair : kD3D9FormatToMohoPairs)
            {
                if (pair.d3dFormat == d3dFormat)
                {
                    return pair.mohoFormat;
                }
            }

            return 0x14U;
        }

        /**
         * Address: 0x0094A100 (FUN_0094A100)
         *
         * What it does:
         * Converts a legacy Moho format token back to its paired D3D9 format value.
         */
        [[maybe_unused]] std::uint32_t FormatGalToD3D(const std::uint32_t mohoFormat)
        {
            for (const D3D9FormatToMohoPair& pair : kD3D9FormatToMohoPairs)
            {
                if (pair.mohoFormat == mohoFormat)
                {
                    return pair.d3dFormat;
                }
            }

            return 0U;
        }

        using EffectTechniqueSharedRef = boost::shared_ptr<EffectTechniqueD3D9>;

        struct EffectContextLane54Runtime final
        {
            void* proxy = nullptr;          // +0x00
            EffectMacro* first = nullptr;   // +0x04
            EffectMacro* last = nullptr;    // +0x08
            EffectMacro* end = nullptr;     // +0x0C
        };

        struct EffectTechniqueVectorRuntime final
        {
            void* proxy = nullptr;                     // +0x00
            EffectTechniqueSharedRef* first = nullptr; // +0x04
            EffectTechniqueSharedRef* last = nullptr;  // +0x08
            EffectTechniqueSharedRef* end = nullptr;   // +0x0C
        };

        struct EffectContextRuntime final
        {
            void* vftable = nullptr;                               // +0x00
            std::uint32_t field04 = 0U;                           // +0x04
            std::uint8_t field08 = 0U;                            // +0x08
            std::uint8_t pad09_0B[3]{};                           // +0x09 .. +0x0B
            msvc8::string field0C{};                              // +0x0C
            msvc8::string field28{};                              // +0x28
            std::uint32_t field44 = 0U;                           // +0x44
            boost::detail::sp_counted_base* sharedCount48 = nullptr; // +0x48
            std::uint32_t field4C = 0U;                           // +0x4C
            std::uint32_t field50 = 0U;                           // +0x50
            EffectContextLane54Runtime lane54{};                  // +0x54
        };

        static_assert(offsetof(EffectContextRuntime, field04) == 0x04, "EffectContextRuntime::field04 offset must be 0x04");
        static_assert(offsetof(EffectContextRuntime, field08) == 0x08, "EffectContextRuntime::field08 offset must be 0x08");
        static_assert(offsetof(EffectContextRuntime, field0C) == 0x0C, "EffectContextRuntime::field0C offset must be 0x0C");
        static_assert(offsetof(EffectContextRuntime, field28) == 0x28, "EffectContextRuntime::field28 offset must be 0x28");
        static_assert(offsetof(EffectContextRuntime, field44) == 0x44, "EffectContextRuntime::field44 offset must be 0x44");
        static_assert(offsetof(EffectContextRuntime, sharedCount48) == 0x48, "EffectContextRuntime::sharedCount48 offset must be 0x48");
        static_assert(offsetof(EffectContextRuntime, field4C) == 0x4C, "EffectContextRuntime::field4C offset must be 0x4C");
        static_assert(offsetof(EffectContextRuntime, field50) == 0x50, "EffectContextRuntime::field50 offset must be 0x50");
        static_assert(offsetof(EffectContextRuntime, lane54) == 0x54, "EffectContextRuntime::lane54 offset must be 0x54");
        static_assert(sizeof(EffectTechniqueSharedRef) == 0x08, "EffectTechniqueSharedRef size must be 0x08");
        static_assert(sizeof(EffectContextLane54Runtime) == 0x10, "EffectContextLane54Runtime size must be 0x10");
        static_assert(sizeof(EffectTechniqueVectorRuntime) == 0x10, "EffectTechniqueVectorRuntime size must be 0x10");
        static_assert(sizeof(EffectContextRuntime) == 0x64, "EffectContextRuntime size must be 0x64");

        EffectContextRuntime* AsEffectContextRuntime(EffectD3D9* const effect) noexcept
        {
            return reinterpret_cast<EffectContextRuntime*>(&effect->effectContext_);
        }

        const EffectContextRuntime* AsEffectContextRuntime(const EffectContext* const context) noexcept
        {
            return reinterpret_cast<const EffectContextRuntime*>(context);
        }

        void ReleaseSharedCount(boost::detail::sp_counted_base*& sharedCount) noexcept
        {
            if (sharedCount != nullptr)
            {
                sharedCount->release();
                sharedCount = nullptr;
            }
        }

        void AssignSharedCount(
            boost::detail::sp_counted_base*& destination,
            boost::detail::sp_counted_base* const source
        ) noexcept
        {
            if (source != nullptr)
            {
                source->add_ref_copy();
            }

            ReleaseSharedCount(destination);
            destination = source;
        }

        std::size_t EffectMacroCount(const EffectContextLane54Runtime& runtime) noexcept
        {
            if (runtime.first == nullptr)
            {
                return 0U;
            }

            return static_cast<std::size_t>(runtime.last - runtime.first);
        }

        std::size_t EffectMacroCapacity(const EffectContextLane54Runtime& runtime) noexcept
        {
            if (runtime.first == nullptr)
            {
                return 0U;
            }

            return static_cast<std::size_t>(runtime.end - runtime.first);
        }

        void DestroyEffectMacroRange(EffectMacro* first, EffectMacro* last) noexcept
        {
            while (first != last)
            {
                first->~EffectMacro();
                ++first;
            }
        }

        /**
         * Address family:
         * - 0x00432290 (FUN_00432290, shared vector tear-down helper)
         * - 0x00942380 lane in d3d9 runtime
         *
         * What it does:
         * Destroys all `EffectMacro` elements, frees vector storage, and clears
         * first/last/end pointers.
         */
        void DestroyEffectMacroStorage(EffectContextLane54Runtime& runtime) noexcept
        {
            if (runtime.first != nullptr)
            {
                DestroyEffectMacroRange(runtime.first, runtime.last);
                ::operator delete(static_cast<void*>(runtime.first));
            }

            runtime.first = nullptr;
            runtime.last = nullptr;
            runtime.end = nullptr;
        }

        [[noreturn]] void ThrowEffectMacroVectorLengthError()
        {
            throw std::length_error("effect-macro vector too long");
        }

        /**
         * Address family:
         * - 0x00432240 (FUN_00432240, shared vector reserve helper)
         * - 0x00942330 lane in d3d9 runtime
         *
         * What it does:
         * Reserves contiguous `EffectMacro` storage for `elementCount` entries
         * and initializes first/last/end pointers.
         */
        bool TryReserveEffectMacroStorage(
            EffectContextLane54Runtime& runtime,
            const std::size_t elementCount
        )
        {
            if (elementCount == 0U)
            {
                runtime.first = nullptr;
                runtime.last = nullptr;
                runtime.end = nullptr;
                return false;
            }

            if (elementCount > 0x04444444U)
            {
                ThrowEffectMacroVectorLengthError();
            }

            try
            {
                auto* const storage = static_cast<EffectMacro*>(::operator new(sizeof(EffectMacro) * elementCount));
                runtime.first = storage;
                runtime.last = storage;
                runtime.end = storage + elementCount;
                return true;
            }
            catch (...)
            {
                runtime.first = nullptr;
                runtime.last = nullptr;
                runtime.end = nullptr;
                return false;
            }
        }

        /**
         * Address: 0x00942440 (FUN_00942440)
         *
         * What it does:
         * Performs element-wise copy-assignment over `[sourceFirst,sourceLast)` for
         * `EffectMacro` lanes using string `assign` on both text fields.
         */
        EffectMacro* CopyAssignEffectMacroRange(
            EffectMacro* sourceFirst,
            EffectMacro* sourceLast,
            EffectMacro* destinationFirst
        )
        {
            EffectMacro* read = sourceFirst;
            EffectMacro* write = destinationFirst;
            while (read != sourceLast)
            {
                write->keyText_.assign(read->keyText_, 0U, msvc8::string::npos);
                write->valueText_.assign(read->valueText_, 0U, msvc8::string::npos);
                ++read;
                ++write;
            }

            return write;
        }

        /**
         * Address: 0x00942770 (FUN_00942770)
         *
         * What it does:
         * Thin bridge wrapper for `CopyAssignEffectMacroRange(...)`.
         */
        EffectMacro* CopyAssignEffectMacroRangeBridge(
            EffectMacro* sourceFirst,
            EffectMacro* sourceLast,
            EffectMacro* destinationFirst
        )
        {
            return CopyAssignEffectMacroRange(sourceFirst, sourceLast, destinationFirst);
        }

        /**
         * Address: 0x009428F0 (FUN_009428F0)
         *
         * What it does:
         * Copy-constructs `EffectMacro` objects into uninitialized destination storage.
         */
        EffectMacro* UninitializedCopyEffectMacroRange(
            const EffectMacro* sourceFirst,
            const EffectMacro* sourceLast,
            EffectMacro* destinationFirst
        )
        {
            const EffectMacro* read = sourceFirst;
            EffectMacro* write = destinationFirst;
            while (read != sourceLast)
            {
                ::new (static_cast<void*>(write)) EffectMacro(*read);
                ++read;
                ++write;
            }

            return write;
        }

        /**
         * Address: 0x009427F0 (FUN_009427F0)
         *
         * What it does:
         * Erases `[first,last)` from lane-54 storage by compacting tail elements left
         * and destroying vacated objects.
         */
        EffectMacro** EraseEffectMacroTailRange(
            EffectContextLane54Runtime& runtime,
            EffectMacro** outResult,
            EffectMacro* first,
            EffectMacro* last
        )
        {
            EffectMacro* result = first;
            if (first != last)
            {
                EffectMacro* const compactedEnd = CopyAssignEffectMacroRange(last, runtime.last, first);
                DestroyEffectMacroRange(compactedEnd, runtime.last);
                runtime.last = compactedEnd;
                result = first;
            }

            *outResult = result;
            return outResult;
        }

        std::size_t EffectTechniqueCount(const EffectTechniqueVectorRuntime& runtime) noexcept
        {
            if (runtime.first == nullptr)
            {
                return 0U;
            }

            return static_cast<std::size_t>(runtime.last - runtime.first);
        }

        std::size_t EffectTechniqueCapacity(const EffectTechniqueVectorRuntime& runtime) noexcept
        {
            if (runtime.first == nullptr)
            {
                return 0U;
            }

            return static_cast<std::size_t>(runtime.end - runtime.first);
        }

        /**
         * Address: 0x00942410 (FUN_00942410)
         *
         * What it does:
         * Copy-assigns a `boost::shared_ptr<EffectTechniqueD3D9>` range into
         * destination storage and returns the resulting end pointer.
         */
        EffectTechniqueSharedRef* CopyAssignEffectTechniqueRange(
            EffectTechniqueSharedRef* sourceFirst,
            EffectTechniqueSharedRef* sourceLast,
            EffectTechniqueSharedRef* destinationFirst
        )
        {
            EffectTechniqueSharedRef* read = sourceFirst;
            EffectTechniqueSharedRef* write = destinationFirst;
            while (read != sourceLast)
            {
                *write = *read;
                ++read;
                ++write;
            }

            return write;
        }

        [[noreturn]] void ThrowEffectTechniqueVectorLengthError()
        {
            throw std::length_error("effect-technique vector too long");
        }

        /**
         * Address: 0x00942490 (FUN_00942490)
         *
         * What it does:
         * Inserts `insertCount` copies of `value` at `insertPosition` in the
         * effect-technique shared-pointer vector runtime.
         */
        void InsertEffectTechniqueCopies(
            EffectTechniqueVectorRuntime& runtime,
            EffectTechniqueSharedRef* insertPosition,
            const std::uint32_t insertCount,
            const EffectTechniqueSharedRef& value
        )
        {
            if (insertCount == 0U)
            {
                return;
            }

            auto& vector = *reinterpret_cast<msvc8::vector<EffectTechniqueSharedRef>*>(&runtime);
            const std::size_t currentSize = vector.size();
            const std::size_t insertSize = static_cast<std::size_t>(insertCount);
            if ((0x1FFFFFFFU - currentSize) < insertSize)
            {
                ThrowEffectTechniqueVectorLengthError();
            }

            std::size_t insertIndex = 0U;
            if (vector.begin() != nullptr && insertPosition != nullptr)
            {
                insertIndex = static_cast<std::size_t>(insertPosition - vector.begin());
            }

            const std::size_t newSize = currentSize + insertSize;
            const std::size_t currentCapacity = vector.capacity();
            std::size_t grownCapacity = currentCapacity + (currentCapacity >> 1U);
            if (grownCapacity < newSize)
            {
                grownCapacity = newSize;
            }

            msvc8::vector<EffectTechniqueSharedRef> rebuilt{};
            rebuilt.reserve(grownCapacity);
            rebuilt.resize(newSize);

            EffectTechniqueSharedRef* const sourceBegin = vector.begin();
            EffectTechniqueSharedRef* const rebuiltBegin = rebuilt.begin();
            if (sourceBegin != nullptr && insertIndex > 0U)
            {
                static_cast<void>(
                    CopyAssignEffectTechniqueRange(sourceBegin, sourceBegin + insertIndex, rebuiltBegin)
                );
            }

            for (std::size_t index = 0; index < insertSize; ++index)
            {
                rebuiltBegin[insertIndex + index] = value;
            }

            if (sourceBegin != nullptr && insertIndex < currentSize)
            {
                static_cast<void>(
                    CopyAssignEffectTechniqueRange(
                        sourceBegin + insertIndex,
                        sourceBegin + currentSize,
                        rebuiltBegin + insertIndex + insertSize
                    )
                );
            }

            vector = std::move(rebuilt);
        }

        /**
         * Address: 0x00942860 (FUN_00942860)
         *
         * What it does:
         * Appends one effect-technique shared-pointer entry to the caller vector.
         */
        EffectTechniqueSharedRef* AppendEffectTechniqueSharedRef(
            msvc8::vector<EffectTechniqueSharedRef>& vector,
            const EffectTechniqueSharedRef& value
        )
        {
            auto& runtime = *reinterpret_cast<EffectTechniqueVectorRuntime*>(&vector);

            const std::size_t size = EffectTechniqueCount(runtime);
            const std::size_t capacity = EffectTechniqueCapacity(runtime);
            if (runtime.first == nullptr || size >= capacity)
            {
                InsertEffectTechniqueCopies(runtime, runtime.last, 1U, value);
                return runtime.last - 1;
            }

            EffectTechniqueSharedRef* const slot = runtime.last;
            ::new (static_cast<void*>(slot)) EffectTechniqueSharedRef(value);
            runtime.last = slot + 1;
            return slot;
        }

        /**
         * Address: 0x00942B60 (FUN_00942B60)
         *
         * What it does:
         * Assigns the trailing context lane rooted at `EffectContext+0x54`.
         */
        void AssignEffectContextLane54(
            EffectContextLane54Runtime& destination,
            const EffectContextLane54Runtime& source
        )
        {
            if (&destination == &source)
            {
                return;
            }

            const std::size_t sourceCount = EffectMacroCount(source);
            if (sourceCount == 0U)
            {
                EffectMacro* eraseResult = destination.first;
                EraseEffectMacroTailRange(destination, &eraseResult, destination.first, destination.last);
                return;
            }

            const std::size_t destinationSize = EffectMacroCount(destination);
            if (sourceCount > destinationSize)
            {
                const std::size_t destinationCapacity = EffectMacroCapacity(destination);
                if (sourceCount <= destinationCapacity)
                {
                    EffectMacro* const splitSource = source.first + destinationSize;
                    CopyAssignEffectMacroRangeBridge(source.first, splitSource, destination.first);
                    destination.last = UninitializedCopyEffectMacroRange(splitSource, source.last, destination.last);
                    return;
                }

                DestroyEffectMacroStorage(destination);
                if (TryReserveEffectMacroStorage(destination, sourceCount))
                {
                    destination.last = UninitializedCopyEffectMacroRange(source.first, source.last, destination.first);
                }
                return;
            }

            EffectMacro* const compactedEnd = CopyAssignEffectMacroRange(source.first, source.last, destination.first);
            DestroyEffectMacroRange(compactedEnd, destination.last);
            destination.last = destination.first + sourceCount;
        }

        /**
         * Address: 0x00942CF0 (FUN_00942CF0)
         *
         * What it does:
         * Copies the recoverable `EffectContext` lanes into destination context storage.
         */
        EffectContextRuntime* CopyEffectContextRuntime(
            EffectContextRuntime* const destination,
            const EffectContextRuntime* const source
        )
        {
            if (destination == source)
            {
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
         * Address: 0x00942D60 (FUN_00942D60)
         *
         * What it does:
         * Releases retained effect resources and resets the embedded context state.
         */
        void DestroyEffectD3D9State(EffectD3D9* const effect)
        {
            ReleaseComLike(effect->dxEffect_);

            const EffectContextRuntime resetContext{};
            EffectContextRuntime* const runtime = AsEffectContextRuntime(effect);
            CopyEffectContextRuntime(runtime, &resetContext);
        }

        /**
         * Address: 0x00942E50 (FUN_00942E50)
         *
         * What it does:
         * Rebuilds effect state from caller-provided context/effect handles.
         */
        void InitializeEffectD3D9State(
            EffectD3D9* const effect,
            const EffectContext* const sourceContext,
            void* const dxEffect
        )
        {
            DestroyEffectD3D9State(effect);

            EffectContextRuntime* const runtime = AsEffectContextRuntime(effect);
            CopyEffectContextRuntime(runtime, AsEffectContextRuntime(sourceContext));
            effect->dxEffect_ = dxEffect;

            runtime->field44 = 0U;
            ReleaseSharedCount(runtime->sharedCount48);
            runtime->field4C = 0U;
            runtime->field50 = 0U;
        }

        /**
         * Address: 0x00942DD0 (FUN_00942DD0)
         *
         * What it does:
         * Executes the recovered non-deleting destructor body lanes for `EffectD3D9`.
         */
        void DestroyEffectD3D9Body(EffectD3D9* const effect)
        {
            DestroyEffectD3D9State(effect);
            DestroyEffectContextRuntimeStorage(*AsEffectContextRuntime(effect));
            effect->selfWeak_.reset();
        }

        /**
         * Address: 0x00942FC0 (FUN_00942FC0)
         *
         * What it does:
         * Executes the recovered `EffectVariableD3D9` destructor-body lanes.
         */
        void DestroyEffectVariableD3D9Body(EffectVariableD3D9* const effectVariable) noexcept
        {
            effectVariable->effect_.reset();
            effectVariable->name_.tidy(true, 0U);
        }

        /**
         * Address: 0x00942F60 (FUN_00942F60)
         *
         * What it does:
         * Models the tiny base-vftable unwind helper lane used by SEH tails.
         */
        void ApplyEffectVariableBaseVftableLane([[maybe_unused]] EffectVariableD3D9* const effectVariable) noexcept
        {
            // Modeled implicitly by normal C++ destruction; no explicit runtime write needed here.
        }

        /**
         * Address: 0x00946BE0 (FUN_00946BE0)
         * Mangled: ??_DPipelineStateD3D9@gal@gpg@@QAEXXZ
         *
         * What it does:
         * Releases the backend pipeline-state handle retained at `+0x04`.
         */
        void DestroyPipelineStateD3D9Body(PipelineStateD3D9* const pipelineState) noexcept
        {
            ReleaseComLike(pipelineState->stateManager_);
        }

        /**
         * Address: 0x0094ACC0 (FUN_0094ACC0)
         * Mangled: ??_DVertexFormatD3D9@gal@gpg@@QAEXXZ
         *
         * What it does:
         * Releases D3D9 declaration state, restores base format code, and tears down
         * the heap lane that stores vertex element metadata.
         */
        void DestroyVertexFormatD3D9Body(VertexFormatD3D9* const vertexFormat) noexcept
        {
            ReleaseComLike(vertexFormat->vertexDeclaration_);
            vertexFormat->formatCode_ = 0x17U;

            if (vertexFormat->elementArrayBegin_ != nullptr)
            {
                ::operator delete(vertexFormat->elementArrayBegin_);
            }

            vertexFormat->elementArrayProxy_ = nullptr;
            vertexFormat->elementArrayBegin_ = nullptr;
            vertexFormat->elementArrayEnd_ = nullptr;
            vertexFormat->elementArrayCapacityEnd_ = nullptr;
        }

        /**
         * Address: 0x008F57B0 (FUN_008F57B0)
         * Mangled: ??1VertexBufferD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Releases the backend vertex-buffer handle and restores embedded context metadata.
         */
        void DestroyVertexBufferD3D9Body(VertexBufferD3D9* const vertexBuffer) noexcept
        {
            ReleaseComLike(vertexBuffer->d3dVertexBuffer_);

            const VertexBufferContext resetContext{};
            vertexBuffer->context_.type_ = resetContext.type_;
            vertexBuffer->context_.usage_ = resetContext.usage_;
            vertexBuffer->context_.width_ = resetContext.width_;
            vertexBuffer->context_.height_ = resetContext.height_;
        }

        /**
         * Address: 0x008F4C80 (FUN_008F4C80)
         * Mangled: ??1IndexBufferD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Releases the retained index-buffer handle and restores embedded context metadata.
         */
        void DestroyIndexBufferD3D9Body(IndexBufferD3D9* const indexBuffer) noexcept
        {
            ReleaseComLike(indexBuffer->d3dIndexBuffer_);

            const IndexBufferContext resetContext{};
            indexBuffer->context_.format_ = resetContext.format_;
            indexBuffer->context_.size_ = resetContext.size_;
            indexBuffer->context_.type_ = resetContext.type_;
        }

        /**
         * Address: 0x008F5350 (FUN_008F5350)
         * Mangled: ??_DRenderTargetD3D9@gal@gpg@@QAEXXZ
         *
         * What it does:
         * Releases retained render-target resource handles and resets the local context lane.
         */
        void ResetRenderTargetD3D9State(RenderTargetD3D9* const renderTarget) noexcept
        {
            ReleaseComLike(renderTarget->renderTexture_);
            ReleaseComLike(renderTarget->renderSurface_);

            const RenderTargetContext resetContext{};
            renderTarget->context_.width_ = resetContext.width_;
            renderTarget->context_.height_ = resetContext.height_;
            renderTarget->context_.format_ = resetContext.format_;
        }

        /**
         * Address: 0x008F53B0 (FUN_008F53B0)
         * Mangled: ??1RenderTargetD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Routes render-target destruction through the reset helper path.
         */
        void DestroyRenderTargetD3D9Body(RenderTargetD3D9* const renderTarget) noexcept
        {
            ResetRenderTargetD3D9State(renderTarget);
        }

        /**
         * Address: 0x008E7FD0 (FUN_008E7FD0)
         * Mangled: ??1DepthStencilTargetD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Releases retained depth-stencil surface state and restores context metadata.
         */
        void DestroyDepthStencilTargetD3D9Body(DepthStencilTargetD3D9* const depthStencilTarget) noexcept
        {
            ReleaseComLike(depthStencilTarget->depthStencilSurface_);

            const DepthStencilTargetContext resetContext{};
            depthStencilTarget->context_.width_ = resetContext.width_;
            depthStencilTarget->context_.height_ = resetContext.height_;
            depthStencilTarget->context_.format_ = resetContext.format_;
            depthStencilTarget->context_.field0x10_ = resetContext.field0x10_;
        }

        /**
         * Address: 0x009412B0 (FUN_009412B0)
         * Mangled: ??_DCubeRenderTargetD3D9@gal@gpg@@QAEXXZ
         *
         * What it does:
         * Releases cube render-target resource handles and restores context metadata.
         */
        void ResetCubeRenderTargetD3D9State(CubeRenderTargetD3D9* const cubeRenderTarget) noexcept
        {
            ReleaseComLike(cubeRenderTarget->cubeTexture_);

            for (auto& faceSurface : cubeRenderTarget->faceSurfaces_)
            {
                ReleaseComLike(faceSurface);
            }

            const CubeRenderTargetContext resetContext{};
            cubeRenderTarget->context_.dimension_ = resetContext.dimension_;
            cubeRenderTarget->context_.format_ = resetContext.format_;
        }

        /**
         * Address: 0x00941330 (FUN_00941330)
         * Mangled: ??1CubeRenderTargetD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Routes cube render-target destruction through the reset helper path.
         */
        void DestroyCubeRenderTargetD3D9Body(CubeRenderTargetD3D9* const cubeRenderTarget) noexcept
        {
            ResetCubeRenderTargetD3D9State(cubeRenderTarget);
        }

        /**
         * Address: 0x00941390 (FUN_00941390)
         * Mangled: sub_941390
         *
         * What it does:
         * Resets cube-target state, applies one context + cube-texture payload,
         * and acquires one level-0 face surface for each cube face.
         */
        void AssignCubeRenderTargetD3D9State(
            CubeRenderTargetD3D9* const cubeRenderTarget,
            const CubeRenderTargetContext* const context,
            void* const cubeTexture
        ) noexcept
        {
            ResetCubeRenderTargetD3D9State(cubeRenderTarget);

            cubeRenderTarget->context_.dimension_ = context->dimension_;
            cubeRenderTarget->context_.format_ = context->format_;
            cubeRenderTarget->cubeTexture_ = cubeTexture;

            for (unsigned int faceIndex = 0; faceIndex < kCubeFaceCount; ++faceIndex)
            {
                void* faceSurface = nullptr;
                static_cast<void>(InvokeGetCubeMapSurface(cubeRenderTarget->cubeTexture_, faceIndex, 0U, &faceSurface));
                cubeRenderTarget->faceSurfaces_[faceIndex] = faceSurface;
            }
        }

        /**
         * Address: 0x008F3A20 (FUN_008F3A20)
         * Mangled: ??1EffectTechniqueD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Releases weak-control ownership and clears the local technique-name string.
         */
        void DestroyEffectTechniqueD3D9Body(EffectTechniqueD3D9* const technique) noexcept
        {
            technique->effect_.reset();
            technique->handle_ = nullptr;
            technique->beginEndActive_ = false;
            technique->name_.tidy(true, 0U);
        }

        /**
         * Address: 0x0094AA90 (FUN_0094AA90)
         * Mangled: ??1TextureD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Routes texture-destruction body behavior through the reset helper path.
         */
        void DestroyTextureD3D9Body(TextureD3D9* const texture)
        {
            texture->Reset();
        }
    }

    /**
     * Address: 0x00940820 (FUN_00940820)
     *
     * What it does:
     * Reports whether runtime mesh instancing is enabled in both global and
     * device-context capability lanes.
     */
    BOOL func_AllowMeshInstancing()
    {
        Device* const device = Device::GetInstance();
        auto* const deviceContext = static_cast<const DeviceContext*>(InvokeDeviceGetContext(device));
        return (sMeshAllowInstancing != 0U) && deviceContext->mHWBasedInstancing;
    }

    /**
     * Address: 0x009407F0 (FUN_009407F0)
     *
     * What it does:
     * Reports whether float16 mesh formatting is enabled in both global and
     * device-context capability lanes.
     */
    BOOL func_AllowMeshFloat16()
    {
        Device* const device = Device::GetInstance();
        auto* const deviceContext = static_cast<const DeviceContext*>(InvokeDeviceGetContext(device));
        return (sMeshAllowFloat16 != 0U) && deviceContext->mSupportsFloat16;
    }

    /**
     * Address: 0x00945160 (FUN_00945160)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from a
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    static void CopyMatrix4x3Rows(
        float* const outRow0,
        float* const outRow1,
        float* const outRow2,
        float* const outRow3,
        const float* const sourceMatrix4x4
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
    }

    /**
     * Address: 0x00945080 (FUN_00945080)
     *
     * What it does:
     * Packs two input float lanes into two float16 lanes.
     */
    static void PackFloat2ToHalf2(std::uint16_t* const outHalf2, const float* const inFloat2)
    {
        InvokeD3DXFloat32To16Array(&outHalf2[0], &inFloat2[0], 1U);
        InvokeD3DXFloat32To16Array(&outHalf2[1], &inFloat2[1], 1U);
    }

    /**
     * Address: 0x009450E0 (FUN_009450E0)
     *
     * What it does:
     * Packs three input float lanes into three float16 lanes.
     */
    static void PackFloat3ToHalf3(std::uint16_t* const outHalf3, const float* const inFloat3)
    {
        InvokeD3DXFloat32To16Array(&outHalf3[0], &inFloat3[0], 1U);
        InvokeD3DXFloat32To16Array(&outHalf3[1], &inFloat3[1], 1U);
        InvokeD3DXFloat32To16Array(&outHalf3[2], &inFloat3[2], 1U);
    }

    /**
     * Address: 0x00945600 (FUN_00945600)
     *
     * What it does:
     * Owns the scalar-deleting destroy thunk for hardware-vertex formatter instances.
     */
    MeshFormatter* HardwareVertexFormatterD3D9::Destroy(const std::uint8_t deleteFlags)
    {
        auto* const formatter = static_cast<MeshFormatter*>(this);
        if ((deleteFlags & 1U) != 0U)
        {
            ::operator delete(formatter);
        }

        return formatter;
    }

    /**
     * Address: 0x009451E0 (FUN_009451E0)
     *
     * What it does:
     * Reports whether the hardware formatter can use mesh instancing.
     */
    bool HardwareVertexFormatterD3D9::AllowMeshInstancing()
    {
        return func_AllowMeshInstancing() != FALSE;
    }

    /**
     * Address: 0x00945680 (FUN_00945680)
     *
     * What it does:
     * Requests hardware vertex-format token `14` and returns the input stream token.
     */
    std::uintptr_t HardwareVertexFormatterD3D9::SelectVertexFormatToken(
        const std::uintptr_t streamToken,
        const std::int32_t /*layoutVariant*/
    )
    {
        Device* const device = Device::GetInstance();
        InvokeDeviceCreateVertexFormat(device, reinterpret_cast<void*>(streamToken), 14);
        return streamToken;
    }

    /**
     * Address: 0x009451F0 (FUN_009451F0)
     *
     * What it does:
     * Returns packed hardware-vertex stride for the requested stream class.
     */
    std::uint32_t HardwareVertexFormatterD3D9::GetVertexStride(
        const std::int32_t streamClass,
        const std::int32_t /*sizeVariant*/
    )
    {
        return static_cast<std::uint32_t>(0x48 + ((streamClass != 0) ? 4 : 0));
    }

    /**
     * Address: 0x00945620 (FUN_00945620)
     *
     * What it does:
     * Owns the scalar-deleting destroy thunk for float16 hardware-vertex formatter instances.
     */
    MeshFormatter* Float16HardwareVertexFormatterD3D9::Destroy(const std::uint8_t deleteFlags)
    {
        auto* const formatter = static_cast<MeshFormatter*>(this);
        if ((deleteFlags & 1U) != 0U)
        {
            ::operator delete(formatter);
        }

        return formatter;
    }

    /**
     * Address: 0x009453A0 (FUN_009453A0)
     *
     * What it does:
     * Reports whether float16 formatter instancing is allowed by both runtime gates.
     */
    bool Float16HardwareVertexFormatterD3D9::AllowMeshInstancing()
    {
        return (func_AllowMeshInstancing() != FALSE) && (func_AllowMeshFloat16() != FALSE);
    }

    /**
     * Address: 0x00945640 (FUN_00945640)
     *
     * What it does:
     * Selects float16 vertex-format token (`15`/`16`) and returns the input stream token.
     */
    std::uintptr_t Float16HardwareVertexFormatterD3D9::SelectVertexFormatToken(
        const std::uintptr_t streamToken,
        const std::int32_t layoutVariant
    )
    {
        Device* const device = Device::GetInstance();
        const int formatCode = (layoutVariant != 0) ? 16 : 15;
        InvokeDeviceCreateVertexFormat(device, reinterpret_cast<void*>(streamToken), formatCode);
        return streamToken;
    }

    /**
     * Address: 0x009453C0 (FUN_009453C0)
     *
     * What it does:
     * Returns float16 packed stride from runtime stride lookup tables.
     */
    std::uint32_t Float16HardwareVertexFormatterD3D9::GetVertexStride(
        const std::int32_t streamClass,
        const std::int32_t sizeVariant
    )
    {
        const auto* const table = (sizeVariant != 0) ? kFloat16VertexStrideTableCompact : kFloat16VertexStrideTableDefault;
        return table[static_cast<std::size_t>(streamClass)];
    }

    /**
     * Address: 0x00945210 (FUN_00945210)
     *
     * What it does:
     * Packs one source vertex into the runtime hardware-vertex stream layout.
     */
    void HardwareVertexFormatterD3D9::WriteFormattedVertex(
        const std::int32_t streamClass,
        void* const destinationVertex,
        const void* const sourceVertex,
        const std::int32_t /*writeVariant*/
    )
    {
        const auto& source = *reinterpret_cast<const SourceMeshVertexRuntime*>(sourceVertex);
        if (streamClass != 0)
        {
            auto& destination = *reinterpret_cast<HardwareVertexPackedStream1Runtime*>(destinationVertex);
            destination.lane30 = source.streamClassFlag;
            destination.lane48 = source.streamScalar04;
            destination.lane44 = source.streamPacked08;
            destination.lane34 = source.streamScalar0C;
            CopyMatrix4x3Rows(destination.row0, destination.row1, destination.row2, destination.row3, source.transform4x4);
            destination.lane31 = source.streamFlag50;
            destination.lane33 = (source.streamBoolA4 != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
            destination.lane3C = source.streamScalarA8;
            destination.lane40 = source.streamScalarAC;
            destination.lane32 = source.streamFlagB0;
            destination.lane38 = source.streamScalarB4;
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
     * Address: 0x009453F0 (FUN_009453F0)
     *
     * What it does:
     * Packs one source vertex into the runtime float16 stream layout.
     */
    void Float16HardwareVertexFormatterD3D9::WriteFormattedVertex(
        const std::int32_t streamClass,
        void* const destinationVertex,
        const void* const sourceVertex,
        const std::int32_t writeVariant
    )
    {
        const auto& source = *reinterpret_cast<const SourceMeshVertexRuntime*>(sourceVertex);
        if (streamClass != 0)
        {
            if ((writeVariant != 0) && (streamClass == 1))
            {
                PackFloat3ToHalf3(reinterpret_cast<std::uint16_t*>(destinationVertex), source.streamVec64);
                return;
            }

            auto& destination = *reinterpret_cast<Float16VertexPackedStream1Runtime*>(destinationVertex);
            destination.lane30 = source.streamClassFlag;
            destination.lane40 = source.streamScalar04;
            destination.lane3C = source.streamPacked08;
            InvokeD3DXFloat32To16Array(&destination.lane34, &source.streamScalar0C, 1U);
            CopyMatrix4x3Rows(destination.row0, destination.row1, destination.row2, destination.row3, source.transform4x4);
            destination.lane31 = source.streamFlag50;
            destination.lane33 = (source.streamBoolA4 != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
            PackFloat2ToHalf2(&destination.lane38, &source.streamScalarA8);
            destination.lane32 = source.streamFlagB0;
            InvokeD3DXFloat32To16Array(&destination.lane36, &source.streamScalarB4, 1U);
            return;
        }

        auto& destination = *reinterpret_cast<Float16VertexPackedStream0Runtime*>(destinationVertex);
        destination.lane28 = source.streamColor51;
        destination.lane29 = source.streamColor52;
        destination.lane2A = source.streamColor53;
        destination.lane2B = source.streamColor54;

        PackFloat3ToHalf3(destination.lane00, source.streamVec58);
        PackFloat3ToHalf3(destination.lane08, source.streamVec70);
        PackFloat3ToHalf3(destination.lane18, source.streamVec7C);
        PackFloat3ToHalf3(destination.lane10, source.streamVec88);

        InvokeD3DXFloat32To16Array(&destination.lane20, &source.streamScalar94, 1U);
        InvokeD3DXFloat32To16Array(&destination.lane22, &source.streamScalar98, 1U);
        InvokeD3DXFloat32To16Array(&destination.lane24, &source.streamScalar9C, 1U);
        InvokeD3DXFloat32To16Array(&destination.lane26, &source.streamScalarA0, 1U);
    }

    /**
     * Address: 0x00940C90 (FUN_00940C90)
     * Scalar-deleting wrapper: 0x008F0040 (FUN_008F0040)
     *
     * What it does:
     * Destroys adapter mode list and all descriptive string lanes.
     */
    AdapterD3D9::~AdapterD3D9() = default;

    /**
     * Address: 0x008E8E40 (FUN_008E8E40)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for adapter-mode wrapper instances.
     */
    AdapterModeD3D9::~AdapterModeD3D9() = default;

    /**
     * Address: 0x008F37F0 (FUN_008F37F0)
     *
     * What it does:
     * Applies D3D9 backend teardown lanes and deletes one startup-allocated
     * backend object instance.
     */
    void DeviceD3D9::DestroyBackendObject()
    {
        auto& runtime = AsDeviceD3D9Runtime(*this);

        runtime.pipelineState.reset();

        delete[] reinterpret_cast<OutputContext*>(runtime.headsBase);
        runtime.headsBase = nullptr;

        ReleaseComLike(runtime.frameEventQuery);
        ReleaseComLike(runtime.nativeDevice);
        ReleaseComLike(runtime.idirect);

        runtime.adapters.clear();
        runtime.deviceContext = DeviceContext(0);
        runtime.curThreadId = 0;

        delete static_cast<DeviceD3D9BackendObject*>(this);
    }

    /**
     * Address: 0x008E81D0 (FUN_008E81D0)
     *
     * What it does:
     * Returns the global D3D9 log-storage lane used by this backend.
     */
    void* DeviceD3D9::GetLog()
    {
        return &gD3D9LogStorage;
    }

    /**
     * Address: 0x008E81E0 (FUN_008E81E0)
     *
     * What it does:
     * Dispatches `Func1` pre-hook and returns the embedded device-context lane.
     */
    DeviceContext* DeviceD3D9::GetDeviceContext()
    {
        Func1();
        return GetEmbeddedDeviceContext(this);
    }

    /**
     * Address: 0x008E81F0 (FUN_008E81F0)
     *
     * What it does:
     * Returns the retained current thread-id lane at `this+0x24`.
     */
    int DeviceD3D9::GetCurThreadId()
    {
        return AsDeviceD3D9Runtime(*this).curThreadId;
    }

    /**
     * Address: 0x008E8200 (FUN_008E8200)
     *
     * What it does:
     * Preserves the binary no-op virtual pre-hook slot.
     */
    void DeviceD3D9::Func1()
    {
    }

    /**
     * Address: 0x008F0170 (FUN_008F0170)
     *
     * What it does:
     * Preserves the currently unresolved adapter-mode projection slot.
     */
    void DeviceD3D9::GetModesForAdapter()
    {
    }

    /**
     * Address: 0x008E9B00 (FUN_008E9B00)
     *
     * boost::shared_ptr<gpg::gal::PipelineStateD3D9> *
     *
     * What it does:
     * Dispatches `Func1` pre-hook and copies retained pipeline-state shared ownership.
     */
    boost::shared_ptr<PipelineStateD3D9>*
    DeviceD3D9::GetPipelineState(boost::shared_ptr<PipelineStateD3D9>* const outPipelineState)
    {
        Func1();
        *outPipelineState = AsDeviceD3D9Runtime(*this).pipelineState;
        return outPipelineState;
    }

    /**
     * Address: 0x008F13D0 (FUN_008F13D0)
     *
     * What it does:
     * Preserves the unresolved effect-creation slot until full typed
     * `EffectContext` startup wiring is lifted.
     */
    void DeviceD3D9::CreateEffect()
    {
    }

    /**
     * Address family:
     * - slot 44 runtime dispatch from `Device` surface
     *
     * What it does:
     * Preserves the unresolved no-argument context-export slot.
     */
    void DeviceD3D9::GetContext()
    {
    }

    /**
     * Address: 0x008EFD50 (FUN_008EFD50)
     *
     * What it does:
     * Allocates and initializes one D3D9 backend object with recovered default
     * runtime lanes for startup dispatch.
     */
    Device* CreateDeviceD3D9Backend()
    {
        auto* const backend = new DeviceD3D9BackendObject();
        auto& runtime = AsDeviceD3D9Runtime(*backend);
        runtime.curThreadId = 0;
        runtime.adapters.clear();
        runtime.deviceContext = DeviceContext(0);
        runtime.pipelineState.reset();
        runtime.idirect = nullptr;
        runtime.nativeDevice = nullptr;
        runtime.headsBase = nullptr;
        runtime.frameEventQuery = nullptr;
        return reinterpret_cast<Device*>(backend);
    }

    /**
     * Address context: 0x008F3320 (FUN_008F3320)
     *
     * What it does:
     * Copies startup device-context payload into the recovered embedded D3D9
     * context lane and records the current thread id.
     */
    void InitializeDeviceD3D9Backend(Device* const device, const DeviceContext* const context)
    {
        if ((device == nullptr) || (context == nullptr))
        {
            return;
        }

        auto* const backend = reinterpret_cast<DeviceD3D9*>(device);
        auto& runtime = AsDeviceD3D9Runtime(*backend);
        runtime.curThreadId = static_cast<int>(::GetCurrentThreadId());
        runtime.deviceContext = *context;
    }

    /**
     * Address: 0x008E9B40 (FUN_008E9B40)
     *
     * boost::weak_ptr<void> *,boost::shared_ptr<void>
     *
     * What it does:
     * Dispatches `Func1`, clears caller weak-handle output, and consumes one
     * temporary shared-handle argument by value.
     */
    boost::weak_ptr<void>*
    DeviceD3D9::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
    {
        Func1();
        static_cast<void>(temporarySharedHandle);
        outWeakHandle->reset();
        return outWeakHandle;
    }

    /**
     * Address: 0x008E8210 (FUN_008E8210)
     *
     * What it does:
     * Forwards the embedded device-context lane to slot-26 virtual dispatch.
     */
    int DeviceD3D9::Func8()
    {
        return Func9(GetEmbeddedDeviceContext(this));
    }

    /**
     * Address: 0x008E8220 (FUN_008E8220)
     *
     * What it does:
     * Preserves the binary no-op cursor-init slot body.
     */
    void DeviceD3D9::InitCursor()
    {
    }

    /**
     * Address: 0x008E8230 (FUN_008E8230)
     *
     * bool
     *
     * What it does:
     * Dispatches `Func1` pre-hook then forwards to native D3D9 `ShowCursor`.
     */
    int DeviceD3D9::ShowCursor(const bool show)
    {
        Func1();
        return InvokeNativeD3D9ShowCursor(AsDeviceD3D9Runtime(*this).nativeDevice, show);
    }

    /**
     * Address: 0x008E82B0 (FUN_008E82B0)
     *
     * What it does:
     * Builds one present-parameter block for the requested head index.
     */
    D3DPRESENT_PARAMETERS* DeviceD3D9::GetHeadParameters(
        D3DPRESENT_PARAMETERS* const outParameters,
        const DeviceContext* const context,
        const unsigned int headIndex
    )
    {
        Func1();

        const Head& head = context->GetHead(headIndex);
        std::memset(outParameters, 0, sizeof(D3DPRESENT_PARAMETERS));
        if (head.mWindow != nullptr)
        {
            outParameters->BackBufferWidth = head.mWidth;
            outParameters->BackBufferHeight = head.mHeight;
            outParameters->BackBufferFormat = static_cast<D3DFORMAT>(kD3DFormatA8R8G8B8);
            outParameters->BackBufferCount = 1U;
            outParameters->MultiSampleType = static_cast<D3DMULTISAMPLE_TYPE>(head.antialiasingHigh);
            outParameters->MultiSampleQuality = head.antialiasingLow;
            outParameters->SwapEffect = static_cast<D3DSWAPEFFECT>(kD3DSwapEffectDiscard);
            outParameters->hDeviceWindow =
                (headIndex == 0U && head.mWindowed) ? reinterpret_cast<HWND>(head.mHandle) : reinterpret_cast<HWND>(head.mWindow);
            outParameters->Windowed = head.mWindowed ? 0 : 1;
            outParameters->EnableAutoDepthStencil = 0;
            outParameters->AutoDepthStencilFormat = static_cast<D3DFORMAT>(kD3DFormatUnknown);
            outParameters->Flags = 0U;
            outParameters->FullScreen_RefreshRateInHz = head.mWindowed ? head.framesPerSecond : 0U;
            outParameters->PresentationInterval =
                ((headIndex == 0U) && context->mVSync) ? 1U : kPresentIntervalImmediate;
        }

        return outParameters;
    }

    /**
     * Address: 0x008E8F00 (FUN_008E8F00)
     *
     * What it does:
     * Builds present-parameter blocks for all heads in one device-context payload.
     */
    void DeviceD3D9::GetDeviceParameters(D3DPRESENT_PARAMETERS* const outParameters, const DeviceContext* const context)
    {
        Func1();

        const unsigned int headCount = static_cast<unsigned int>(context->GetHeadCount());
        for (unsigned int headIndex = 0; headIndex < headCount; ++headIndex)
        {
            static_cast<void>(GetHeadParameters(&outParameters[headIndex], context, headIndex));
        }
    }

    /**
     * Address: 0x008EEB80 (FUN_008EEB80)
     *
     * What it does:
     * Rebuilds per-head output/depth wrappers after one native device reset.
     */
    void DeviceD3D9::CreateHeads()
    {
        Func1();
        auto& runtime = AsDeviceD3D9Runtime(*this);

        const unsigned int headCount = static_cast<unsigned int>(runtime.deviceContext.GetHeadCount());
        if (runtime.headsBase != nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1444, "internal D3D9 device initialization error");
        }

        OutputContext* const heads = (headCount > 0U) ? new OutputContext[headCount] : nullptr;
        runtime.headsBase = heads;
        auto* const outputHeads = reinterpret_cast<OutputContextD3D9RuntimeView*>(heads);

        for (unsigned int headIndex = 0; headIndex < headCount; ++headIndex)
        {
            ComObjectScope backBuffer{};
            const HRESULT getBackBufferResult =
                InvokeNativeGetBackBuffer(this, headIndex, 0U, kD3DBackBufferTypeMono, backBuffer.out());
            if (getBackBufferResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1451, getBackBufferResult);
            }

            Clear(true, false, false, 0U, 0.0f, 0);
            static_cast<void>(InvokeNativePresent(this));

            D3DSurfaceDescRuntime surfaceDesc{};
            static_cast<void>(InvokeSurfaceGetDesc(backBuffer.get(), &surfaceDesc));

            ComObjectScope depthStencilSurface{};
            const HRESULT createDepthResult = InvokeNativeCreateDepthStencilSurface(
                this,
                surfaceDesc.width,
                surfaceDesc.height,
                kD3DFormatD24S8,
                surfaceDesc.multisampleType,
                surfaceDesc.multisampleQuality,
                depthStencilSurface.out()
            );
            if (createDepthResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1462, createDepthResult);
            }

            RenderTargetD3D9* const renderTarget = new RenderTargetD3D9();
            renderTarget->context_.width_ = surfaceDesc.width;
            renderTarget->context_.height_ = surfaceDesc.height;
            renderTarget->context_.format_ = FormatD3D9ToMoho(surfaceDesc.format);
            renderTarget->renderTexture_ = nullptr;
            renderTarget->renderSurface_ = backBuffer.release();
            outputHeads[headIndex].renderTarget.reset(renderTarget);

            const DepthStencilTargetContext depthStencilContext(surfaceDesc.width, surfaceDesc.height, 3U, false);
            DepthStencilTargetD3D9* const depthStencilTarget =
                new DepthStencilTargetD3D9(&depthStencilContext, depthStencilSurface.release());
            outputHeads[headIndex].depthStencil.reset(depthStencilTarget);
        }
    }

    /**
     * Address: 0x008F2080 (FUN_008F2080)
     *
     * What it does:
     * Copies device-context capabilities, probes format/multisample support, and
     * updates shader/capability profile fields.
     */
    int DeviceD3D9::BuildDeviceCapabilities(const DeviceContext* const context)
    {
        Func1();
        auto& runtime = AsDeviceD3D9Runtime(*this);
        runtime.deviceContext = *context;

        const unsigned int headCount = static_cast<unsigned int>(context->GetHeadCount());
        if (headCount > runtime.adapters.size())
        {
            ThrowGalError("DeviceD3D9.cpp", 1250, "invalid head count specified in device context");
        }

        for (unsigned int adapterIndex = 0; adapterIndex < headCount; ++adapterIndex)
        {
            Head& head = runtime.deviceContext.mHeads[adapterIndex];
            const AdapterD3D9& adapter = runtime.adapters[adapterIndex];

            head.adapterModes.clear();
            for (const AdapterModeD3D9& mode : adapter.modes)
            {
                HeadAdapterMode mappedMode{};
                mappedMode.width = mode.width_;
                mappedMode.height = mode.height_;
                mappedMode.refreshRate = mode.refreshRate_;
                head.adapterModes.push_back(mappedMode);
            }

            head.validFormats1.clear();
            for (int formatToken = 1; formatToken < 8; ++formatToken)
            {
                const HRESULT result = InvokeNativeCheckDeviceFormat(
                    this,
                    adapterIndex,
                    kD3DDevTypeHal,
                    kD3DFormatX8R8G8B8,
                    1U,
                    kD3DRTypeTexture,
                    GetD3DFormat(static_cast<std::uint32_t>(formatToken))
                );
                if (result >= 0)
                {
                    head.validFormats1.push_back(formatToken);
                }
            }

            head.validFormats2.clear();
            for (int formatToken = 1; formatToken < 20; ++formatToken)
            {
                const HRESULT result = InvokeNativeCheckDeviceFormat(
                    this,
                    adapterIndex,
                    kD3DDevTypeHal,
                    kD3DFormatX8R8G8B8,
                    0U,
                    kD3DRTypeTexture,
                    FormatGalToD3D(static_cast<std::uint32_t>(formatToken))
                );
                if (result >= 0)
                {
                    head.validFormats2.push_back(formatToken);
                }
            }

            D3DADAPTER_IDENTIFIER9 adapterIdentifier{};
            static_cast<void>(InvokeNativeGetAdapterIdentifier(this, 0U, 0U, &adapterIdentifier));

            head.mStrs.clear();
            if (adapterIdentifier.VendorId != kVendorIdNvidia)
            {
                for (unsigned int sampleType = 2U; sampleType <= 16U; ++sampleType)
                {
                    const HRESULT result = InvokeNativeCheckDeviceMultiSampleType(
                        this,
                        adapterIndex,
                        kD3DDevTypeHal,
                        kD3DFormatA8R8G8B8,
                        !head.mWindowed,
                        sampleType,
                        nullptr
                    );
                    if (result < 0)
                    {
                        continue;
                    }

                    HeadSampleOption option{};
                    option.sampleType = sampleType;
                    option.sampleQuality = 0U;
                    char label[16] = {};
                    std::snprintf(label, sizeof(label), "%u", sampleType);
                    option.label.assign_owned(label);
                    head.mStrs.push_back(option);
                }
            }
            else
            {
                struct SampleCandidate final
                {
                    unsigned int sampleType = 0U;
                    unsigned int sampleQuality = 0U;
                    const char* label = nullptr;
                };

                static constexpr SampleCandidate kNvidiaSampleCandidates[] = {
                    {2U, 0U, "2"},
                    {4U, 0U, "4"},
                    {4U, 2U, "8"},
                    {8U, 0U, "8Q"},
                    {4U, 4U, "16"},
                    {8U, 2U, "16Q"},
                };

                for (const SampleCandidate& candidate : kNvidiaSampleCandidates)
                {
                    unsigned int qualityLevels = 0U;
                    const HRESULT checkResult = InvokeNativeCheckDeviceMultiSampleType(
                        this,
                        adapterIndex,
                        kD3DDevTypeHal,
                        kD3DFormatA8R8G8B8,
                        !head.mWindowed,
                        candidate.sampleType,
                        &qualityLevels
                    );

                    if ((checkResult < 0) || (qualityLevels <= candidate.sampleQuality))
                    {
                        continue;
                    }

                    if (candidate.sampleType == 4U && candidate.sampleQuality == 4U)
                    {
                        const HRESULT sixteenSampleResult = InvokeNativeCheckDeviceMultiSampleType(
                            this,
                            adapterIndex,
                            kD3DDevTypeHal,
                            kD3DFormatA8R8G8B8,
                            !head.mWindowed,
                            16U,
                            nullptr
                        );
                        if (sixteenSampleResult >= 0)
                        {
                            HeadSampleOption option{};
                            option.sampleType = 16U;
                            option.sampleQuality = 0U;
                            option.label.assign_owned("16");
                            head.mStrs.push_back(option);
                        }
                        continue;
                    }

                    HeadSampleOption option{};
                    option.sampleType = candidate.sampleType;
                    option.sampleQuality = candidate.sampleQuality;
                    option.label.assign_owned(candidate.label);
                    head.mStrs.push_back(option);
                }
            }
        }

        D3DCAPS9 caps{};
        const HRESULT capsResult = InvokeNativeGetDeviceCaps(this, &caps);
        if (capsResult < 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1343, "unable to retreive device caps");
        }

        CheckHardwareInstancingSupport(*this, caps);

        runtime.deviceContext.mSupportsFloat16 =
            ((caps.DeclTypes & kDeclTypeFloat16_2) != 0U) && ((caps.DeclTypes & kDeclTypeFloat16_4) != 0U);
        runtime.deviceContext.mMaxPrimitiveCount = caps.MaxPrimitiveCount;
        runtime.deviceContext.mMaxVertexCount = caps.MaxVertexIndex;

        if (runtime.deviceContext.mValidate && (caps.VertexShaderVersion < kVertexShaderModel20))
        {
            ThrowGalError("DeviceD3D9.cpp", 1355, "Vertex shader 2.0 required");
        }

        if (runtime.deviceContext.mValidate && (caps.PixelShaderVersion < kPixelShaderModel20))
        {
            ThrowGalError("DeviceD3D9.cpp", 1361, "Pixel shader 2.0 required");
        }

        runtime.deviceContext.mVertexShaderProfile =
            ResolveVertexShaderProfileToken(InvokeD3DXGetVertexShaderProfile(runtime.nativeDevice));
        runtime.deviceContext.mPixelShaderProfile =
            ResolvePixelShaderProfileToken(InvokeD3DXGetPixelShaderProfile(runtime.nativeDevice));
        return runtime.deviceContext.mPixelShaderProfile;
    }

    /**
     * Address: 0x008F3070 (FUN_008F3070)
     *
     * What it does:
     * Resets the native D3D9 device using caller context payload, then rebuilds
     * capabilities, head resources, pipeline state, and frame event-query state.
     */
    int DeviceD3D9::Func9(DeviceContext* const context)
    {
        auto& runtime = AsDeviceD3D9Runtime(*this);

        if (runtime.pipelineState.get() != nullptr)
        {
            static_cast<void>(runtime.pipelineState->ClearTextures());
        }
        runtime.pipelineState.reset();

        delete[] reinterpret_cast<OutputContext*>(runtime.headsBase);
        runtime.headsBase = nullptr;

        ReleaseComLike(runtime.frameEventQuery);

        const unsigned int headCount = static_cast<unsigned int>(context->GetHeadCount());
        std::vector<D3DPRESENT_PARAMETERS> parameters(headCount);
        if (headCount > 0U)
        {
            GetDeviceParameters(parameters.data(), context);
        }

        const HRESULT resetResult = InvokeNativeReset(this, parameters.empty() ? nullptr : parameters.data());
        if (resetResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 866, resetResult);
        }

        static_cast<void>(BuildDeviceCapabilities(context));
        CreateHeads();

        runtime.pipelineState.reset(new PipelineStateD3D9(runtime.nativeDevice));
        if (runtime.pipelineState.get() != nullptr)
        {
            static_cast<void>(runtime.pipelineState->InitState());
        }

        return InvokeNativeCreateQuery(this, kD3DQueryTypeEvent, &runtime.frameEventQuery);
    }

    namespace
    {
        constexpr unsigned int kD3DResourceTypeTexture2D = 3U;
        constexpr unsigned int kD3DResourceTypeVolumeTexture = 4U;
        constexpr unsigned int kD3DResourceTypeCubeTexture = 5U;
        constexpr std::uint32_t kD3DFormatIndex16 = 101U;
        constexpr std::uint32_t kD3DFormatIndex32 = 102U;

        struct D3DVertexElementRuntime final
        {
            std::uint16_t stream = 0U;
            std::uint16_t offset = 0U;
            std::uint8_t type = 0U;
            std::uint8_t method = 0U;
            std::uint8_t usage = 0U;
            std::uint8_t usageIndex = 0U;
        };

        // Fallback declaration lane while full `vertexFormats` table lifting is pending.
        constexpr D3DVertexElementRuntime kFallbackVertexElements[2] = {
            {0U, 0U, 2U, 0U, 0U, 0U},
            {0xFFU, 0U, 17U, 0U, 0U, 0U},
        };

        const D3DVertexElementRuntime* GetVertexFormatElementsOrThrow(const std::uint32_t formatCode)
        {
            if (formatCode >= 24U)
            {
                ThrowGalError("VertexFormatD3D9.cpp", 389, "invalid vertex format specified");
            }

            return kFallbackVertexElements;
        }

        void ClearTextureContextData(TextureContext& context) noexcept
        {
            if (context.dataCount_ != nullptr)
            {
                context.dataCount_->release();
            }

            context.dataArray_ = nullptr;
            context.dataCount_ = nullptr;
            context.dataBegin_ = 0U;
            context.dataEnd_ = 0U;
        }
    }

    /**
     * Address: 0x008EAB20 (FUN_008EAB20)
     *
     * unsigned int
     *
     * What it does:
     * Validates one head index and returns the retained head lane pointer from
     * the head-array base at `this+0x7C`.
     */
    Head* DeviceD3D9::GetHead2(const unsigned int headIndex)
    {
        Func1();
        const unsigned int headCount = GetDeviceHeadCount(this);
        if (headIndex >= headCount)
        {
            ThrowGalError("DeviceD3D9.cpp", 295, "invalid head index specified");
        }

        auto* const headArrayBase = reinterpret_cast<std::uint8_t*>(GetDeviceHeadArrayBase(this));
        return reinterpret_cast<Head*>(headArrayBase + (headIndex * 0x20U));
    }

    /**
     * Address: 0x008EABF0 (FUN_008EABF0)
     *
     * unsigned int
     *
     * What it does:
     * Validates one head index and returns the retained head lane pointer from
     * the head-array base at `this+0x7C`.
     */
    Head* DeviceD3D9::GetHead1(const unsigned int headIndex)
    {
        Func1();
        const unsigned int headCount = GetDeviceHeadCount(this);
        if (headIndex >= headCount)
        {
            ThrowGalError("DeviceD3D9.cpp", 303, "invalid head index specified");
        }

        auto* const headArrayBase = reinterpret_cast<std::uint8_t*>(GetDeviceHeadArrayBase(this));
        return reinterpret_cast<Head*>(headArrayBase + (headIndex * 0x20U));
    }

    /**
     * Address: 0x008EACC0 (FUN_008EACC0)
     *
     * boost::shared_ptr<gpg::gal::TextureD3D9> *,gpg::gal::TextureContext const *
     *
     * What it does:
     * Creates one D3D9 texture from memory/context source lanes, normalizes the
     * resulting texture-context metadata, and returns wrapped shared ownership.
     */
    boost::shared_ptr<TextureD3D9>*
    DeviceD3D9::CreateTexture(boost::shared_ptr<TextureD3D9>* const outTexture, const TextureContext* const context)
    {
        Func1();

        TextureContext textureContext{};
        textureContext.AssignFrom(*context);
        ClearTextureContextData(textureContext);

        const auto* const sourceData = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(context->dataBegin_));
        const unsigned int sourceBytes = context->dataEnd_ - context->dataBegin_;

        void* nativeTexture = nullptr;
        if (context->source_ == 2U)
        {
            const unsigned int mappedFormat = FormatGalToD3D(context->format_);

            unsigned int usageFlags = (context->usage_ == 2U) ? 0x200U : 0U;
            D3DPOOL pool = (context->usage_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;
            if (context->usage_ == 3U)
            {
                pool = D3DPOOL_SYSTEMMEM;
            }
            if ((context->mipmapLevels_ == 0U) && (context->usage_ != 2U))
            {
                usageFlags |= 0x400U;
            }

            const HRESULT createResult = InvokeD3DXCreateTexture(
                AsDeviceD3D9Runtime(*this).nativeDevice,
                context->width_,
                context->height_,
                context->mipmapLevels_,
                usageFlags,
                mappedFormat,
                pool,
                &nativeTexture
            );
            if (createResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 477, createResult);
            }

            D3DSurfaceDescRuntime surfaceDesc{};
            const HRESULT levelDescResult = InvokeTextureGetLevelDesc(nativeTexture, 0U, &surfaceDesc);
            if (levelDescResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 481, levelDescResult);
            }

            textureContext.type_ = 1U;
            textureContext.mipmapLevels_ = InvokeTextureGetLevelCount(nativeTexture);
            textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.format);
            textureContext.width_ = surfaceDesc.width;
            textureContext.height_ = surfaceDesc.height;
        }
        else if (context->source_ == 1U)
        {
            if (context->dataEnd_ == context->dataBegin_)
            {
                ThrowGalError("DeviceD3D9.cpp", 350, "attempt to create texture from uninitialized memory");
            }

            D3DXImageInfoRuntime imageInfo{};
            const HRESULT imageInfoResult = InvokeD3DXGetImageInfoFromFileInMemory(sourceData, sourceBytes, &imageInfo);
            if (imageInfoResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 354, imageInfoResult);
            }

            if (imageInfo.resourceType == kD3DResourceTypeCubeTexture)
            {
                const unsigned int edgeLength = (context->width_ != 0U) ? context->width_ : kD3DXDefault;
                const HRESULT createResult = InvokeD3DXCreateCubeTextureFromFileInMemoryEx(
                    AsDeviceD3D9Runtime(*this).nativeDevice,
                    sourceData,
                    sourceBytes,
                    edgeLength,
                    kD3DXDefault,
                    0U,
                    FormatGalToD3D(context->format_),
                    D3DPOOL_MANAGED,
                    kD3DXDefault,
                    kD3DXDefault,
                    0U,
                    nullptr,
                    nullptr,
                    &nativeTexture
                );
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 410, createResult);
                }

                D3DSurfaceDescRuntime surfaceDesc{};
                const HRESULT levelDescResult = InvokeTextureGetLevelDesc(nativeTexture, 0U, &surfaceDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 414, levelDescResult);
                }

                textureContext.type_ = 2U;
                textureContext.mipmapLevels_ = InvokeTextureGetLevelCount(nativeTexture);
                textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.format);
                textureContext.width_ = surfaceDesc.width;
                textureContext.height_ = surfaceDesc.height;
            }
            else if (imageInfo.resourceType == kD3DResourceTypeVolumeTexture)
            {
                const HRESULT createResult = InvokeD3DXCreateVolumeTextureFromFileInMemoryEx(
                    AsDeviceD3D9Runtime(*this).nativeDevice,
                    sourceData,
                    sourceBytes,
                    kD3DXDefault,
                    kD3DXDefault,
                    kD3DXDefault,
                    kD3DXDefault,
                    0U,
                    FormatGalToD3D(context->format_),
                    D3DPOOL_MANAGED,
                    kD3DXDefault,
                    kD3DXDefault,
                    0U,
                    nullptr,
                    nullptr,
                    &nativeTexture
                );
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 442, createResult);
                }

                D3DSurfaceDescRuntime surfaceDesc{};
                const HRESULT levelDescResult = InvokeTextureGetLevelDesc(nativeTexture, 0U, &surfaceDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 446, levelDescResult);
                }

                textureContext.type_ = 3U;
                textureContext.mipmapLevels_ = InvokeTextureGetLevelCount(nativeTexture);
                textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.format);
                textureContext.width_ = surfaceDesc.width;
                textureContext.height_ = surfaceDesc.height;
            }
            else if (imageInfo.resourceType == kD3DResourceTypeTexture2D)
            {
                const unsigned int width = (context->width_ != 0U) ? context->width_ : kD3DXDefault;
                const unsigned int height = (context->height_ != 0U) ? context->height_ : kD3DXDefault;
                const unsigned int filter = ((context->reserved0x44_ & 0x1FU) << 26U) | 5U;

                const HRESULT createResult = InvokeD3DXCreateTextureFromFileInMemoryEx(
                    AsDeviceD3D9Runtime(*this).nativeDevice,
                    sourceData,
                    sourceBytes,
                    width,
                    height,
                    kD3DXDefault,
                    0U,
                    FormatGalToD3D(context->format_),
                    D3DPOOL_MANAGED,
                    filter,
                    0U,
                    0U,
                    nullptr,
                    nullptr,
                    &nativeTexture
                );
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 377, createResult);
                }

                D3DSurfaceDescRuntime surfaceDesc{};
                const HRESULT levelDescResult = InvokeTextureGetLevelDesc(nativeTexture, 0U, &surfaceDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 381, levelDescResult);
                }

                textureContext.type_ = 1U;
                textureContext.mipmapLevels_ = InvokeTextureGetLevelCount(nativeTexture);
                textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.format);
                textureContext.width_ = surfaceDesc.width;
                textureContext.height_ = surfaceDesc.height;
            }
            else
            {
                ThrowGalError("DeviceD3D9.cpp", 458, "unknown texture type");
            }
        }
        else
        {
            ThrowGalError("DeviceD3D9.cpp", 493, "invalid source specified for texture data");
        }

        TextureD3D9* const texture = new TextureD3D9();
        texture->context_.AssignFrom(textureContext);
        texture->texture_ = nativeTexture;
        texture->locking_ = false;
        texture->level_ = 0;
        outTexture->reset(texture);
        return outTexture;
    }

    /**
     * Address: 0x008EB610 (FUN_008EB610)
     *
     * boost::shared_ptr<gpg::gal::RenderTargetD3D9> *,gpg::gal::RenderTargetContext const *
     *
     * What it does:
     * Creates one D3D9 render-target texture and returns wrapped ownership.
     */
    boost::shared_ptr<RenderTargetD3D9>* DeviceD3D9::CreateVolumeTexture(
        boost::shared_ptr<RenderTargetD3D9>* const outRenderTarget,
        const RenderTargetContext* const context
    )
    {
        Func1();

        void* renderTexture = nullptr;
        const HRESULT createResult = InvokeNativeCreateTexture(
            this,
            context->width_,
            context->height_,
            1U,
            1U,
            GetD3DFormat(context->format_),
            D3DPOOL_DEFAULT,
            &renderTexture
        );
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 508, createResult);
        }

        RenderTargetD3D9* const renderTarget = new RenderTargetD3D9();
        renderTarget->context_ = *context;
        renderTarget->renderTexture_ = renderTexture;
        renderTarget->renderSurface_ = GetSurfaceLevel0FromTexture(renderTexture);
        outRenderTarget->reset(renderTarget);
        return outRenderTarget;
    }

    /**
     * Address: 0x008EB780 (FUN_008EB780)
     *
     * boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9> *,gpg::gal::CubeRenderTargetContext const *
     *
     * What it does:
     * Creates one D3D9 cube texture target and returns wrapped ownership.
     */
    boost::shared_ptr<CubeRenderTargetD3D9>* DeviceD3D9::CreateCubeRenderTarget(
        boost::shared_ptr<CubeRenderTargetD3D9>* const outCubeRenderTarget,
        const CubeRenderTargetContext* const context
    )
    {
        Func1();

        void* cubeTexture = nullptr;
        const HRESULT createResult = InvokeNativeCreateCubeTexture(
            this,
            context->dimension_,
            1U,
            1U,
            GetD3DFormat(context->format_),
            D3DPOOL_DEFAULT,
            &cubeTexture
        );
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 521, createResult);
        }

        CubeRenderTargetD3D9* const cubeRenderTarget = new CubeRenderTargetD3D9(context, cubeTexture);

        outCubeRenderTarget->reset(cubeRenderTarget);
        return outCubeRenderTarget;
    }

    /**
     * Address: 0x008EB8E0 (FUN_008EB8E0)
     *
     * boost::shared_ptr<gpg::gal::DepthStencilTargetD3D9> *,gpg::gal::DepthStencilTargetContext const *
     *
     * What it does:
     * Creates one D3D9 depth-stencil surface and returns wrapped ownership.
     */
    boost::shared_ptr<DepthStencilTargetD3D9>* DeviceD3D9::CreateDepthStencilTarget(
        boost::shared_ptr<DepthStencilTargetD3D9>* const outDepthStencilTarget,
        const DepthStencilTargetContext* const context
    )
    {
        Func1();

        void* depthStencilSurface = nullptr;
        const HRESULT createResult = InvokeNativeCreateDepthStencilSurface(
            this,
            context->width_,
            context->height_,
            FormatToD3DFormat(context->format_),
            0U,
            0U,
            &depthStencilSurface
        );
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 534, createResult);
        }

        DepthStencilTargetD3D9* const depthStencilTarget = new DepthStencilTargetD3D9(context, depthStencilSurface);
        outDepthStencilTarget->reset(depthStencilTarget);
        return outDepthStencilTarget;
    }

    /**
     * Address: 0x008EBA50 (FUN_008EBA50)
     *
     * boost::shared_ptr<gpg::gal::VertexFormatD3D9> *,std::uint32_t
     *
     * What it does:
     * Validates one format token, builds one vertex declaration lane, and returns
     * wrapped format ownership.
     */
    boost::shared_ptr<VertexFormatD3D9>* DeviceD3D9::CreateVertexFormat(
        boost::shared_ptr<VertexFormatD3D9>* const outVertexFormat,
        const std::uint32_t formatCode
    )
    {
        Func1();

        void* vertexDeclaration = nullptr;
        const HRESULT createResult = InvokeNativeCreateVertexDeclaration(
            this,
            GetVertexFormatElementsOrThrow(formatCode),
            &vertexDeclaration
        );
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 546, createResult);
        }

        VertexFormatD3D9* const vertexFormat = new VertexFormatD3D9();
        vertexFormat->formatCode_ = formatCode;
        vertexFormat->elementArrayProxy_ = nullptr;
        vertexFormat->elementArrayBegin_ = nullptr;
        vertexFormat->elementArrayEnd_ = nullptr;
        vertexFormat->elementArrayCapacityEnd_ = nullptr;
        vertexFormat->vertexDeclaration_ = vertexDeclaration;
        outVertexFormat->reset(vertexFormat);
        return outVertexFormat;
    }

    /**
     * Address: 0x008EBBB0 (FUN_008EBBB0)
     *
     * boost::shared_ptr<gpg::gal::VertexBufferD3D9> *,gpg::gal::VertexBufferContext const *
     *
     * What it does:
     * Creates one D3D9 vertex buffer from caller context lanes and returns wrapped ownership.
     */
    boost::shared_ptr<VertexBufferD3D9>* DeviceD3D9::CreateVertexBuffer(
        boost::shared_ptr<VertexBufferD3D9>* const outVertexBuffer,
        const VertexBufferContext* const context
    )
    {
        Func1();

        const unsigned int byteWidth = context->width_ * context->height_;
        const unsigned int usageFlags = ((context->usage_ == 2U) ? 0x200U : 0U) | 0x8U;
        const D3DPOOL pool = (context->usage_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;

        void* nativeVertexBuffer = nullptr;
        const HRESULT createResult =
            InvokeNativeCreateVertexBuffer(this, byteWidth, usageFlags, 0U, pool, &nativeVertexBuffer);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 560, createResult);
        }

        VertexBufferD3D9* const vertexBuffer = new VertexBufferD3D9();
        vertexBuffer->context_ = *context;
        vertexBuffer->d3dVertexBuffer_ = nativeVertexBuffer;
        vertexBuffer->locked_ = false;
        vertexBuffer->mappedData_ = nullptr;
        outVertexBuffer->reset(vertexBuffer);
        return outVertexBuffer;
    }

    /**
     * Address: 0x008EBD30 (FUN_008EBD30)
     *
     * boost::shared_ptr<gpg::gal::IndexBufferD3D9> *,gpg::gal::IndexBufferContext const *
     *
     * What it does:
     * Validates index-format context lanes, creates one D3D9 index buffer, and
     * returns wrapped ownership.
     */
    boost::shared_ptr<IndexBufferD3D9>* DeviceD3D9::CreateIndexBuffer(
        boost::shared_ptr<IndexBufferD3D9>* const outIndexBuffer,
        const IndexBufferContext* const context
    )
    {
        Func1();

        if (context->format_ == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 569, "undefined index buffer format");
        }

        const unsigned int bytesPerIndex = (context->format_ == 1U) ? 2U : 4U;
        const unsigned int byteSize = context->size_ * bytesPerIndex;
        const unsigned int usageFlags = ((context->type_ == 2U) ? 0x200U : 0U) | 0x8U;
        const std::uint32_t d3dFormat = (context->format_ == 1U) ? kD3DFormatIndex16 : kD3DFormatIndex32;
        const D3DPOOL pool = (context->type_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;

        void* nativeIndexBuffer = nullptr;
        const HRESULT createResult =
            InvokeNativeCreateIndexBuffer(this, byteSize, usageFlags, d3dFormat, pool, &nativeIndexBuffer);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 581, createResult);
        }

        IndexBufferD3D9* const indexBuffer = new IndexBufferD3D9();
        indexBuffer->context_ = *context;
        indexBuffer->d3dIndexBuffer_ = nativeIndexBuffer;
        indexBuffer->locked_ = false;
        indexBuffer->indexData_ = nullptr;
        outIndexBuffer->reset(indexBuffer);
        return outIndexBuffer;
    }

    /**
     * Address: 0x008EC440 (FUN_008EC440)
     *
     * gpg::gal::RenderTargetD3D9 **,boost::shared_ptr<gpg::gal::TextureD3D9> *
     *
     * What it does:
     * Validates source/destination texture handles, resolves destination level-0
     * surface, and dispatches native `GetRenderTargetData`.
     */
    void DeviceD3D9::CreateRenderTarget(
        RenderTargetD3D9** const sourceTexture,
        boost::shared_ptr<TextureD3D9>* const destinationTexture
    )
    {
        Func1();

        if ((sourceTexture == nullptr) || (*sourceTexture == nullptr))
        {
            ThrowGalError("DeviceD3D9.cpp", 645, "Missing source texture");
        }

        if ((destinationTexture == nullptr) || !destinationTexture->get())
        {
            ThrowGalError("DeviceD3D9.cpp", 646, "Missing dest   texture");
        }

        void* const sourceSurface = (*sourceTexture)->GetRenderSurface();

        ComObjectScope destinationSurface{};
        const HRESULT getSurfaceResult =
            InvokeGetSurfaceLevel(destinationTexture->get()->GetTexture1(), 0U, destinationSurface.out());
        if (getSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 656, getSurfaceResult);
        }

        const HRESULT copyResult = InvokeNativeGetRenderTargetData(this, sourceSurface, destinationSurface.get());
        if (copyResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 661, copyResult);
        }
    }

    /**
     * Address: 0x008EC250 (FUN_008EC250)
     *
     * gpg::gal::RenderTargetD3D9 **,gpg::gal::RenderTargetD3D9 **,void const *,void const *
     *
     * What it does:
     * Validates source/destination render-surface handles and dispatches one native
     * `IDirect3DDevice9::StretchRect` copy lane.
     */
    void DeviceD3D9::StretchRect(
        RenderTargetD3D9** const sourceTexture,
        RenderTargetD3D9** const destinationTexture,
        const void* const sourceRect,
        const void* const destinationRect
    )
    {
        Func1();

        if (*sourceTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 624, "Missing source texture");
        }

        if (*destinationTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 625, "Missing dest   texture");
        }

        const HRESULT stretchResult = InvokeNativeStretchRect(
            this,
            (*sourceTexture)->GetRenderSurface(),
            reinterpret_cast<const RECT*>(sourceRect),
            (*destinationTexture)->GetRenderSurface(),
            reinterpret_cast<const RECT*>(destinationRect),
            kD3DTexFilterLinear
        );
        if (stretchResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 637, stretchResult);
        }
    }

    /**
     * Address: 0x008EBF70 (FUN_008EBF70)
     *
     * gpg::gal::TextureD3D9 **,gpg::gal::TextureD3D9 **,void const *,void const *
     *
     * What it does:
     * Resolves level-0 source/destination texture surfaces then copies source
     * texels into destination via `D3DXLoadSurfaceFromSurface`.
     */
    void DeviceD3D9::UpdateSurface(
        TextureD3D9** const sourceTexture,
        TextureD3D9** const destinationTexture,
        const void* const sourceRect,
        const void* const destinationRect
    )
    {
        Func1();

        if (*sourceTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 592, "Missing source texture");
        }

        if (*destinationTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 593, "Missing dest   texture");
        }

        ComObjectScope sourceSurface{};
        const HRESULT getSourceSurfaceResult = InvokeGetSurfaceLevel((*sourceTexture)->GetTexture1(), 0U, sourceSurface.out());
        if (getSourceSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 599, getSourceSurfaceResult);
        }

        ComObjectScope destinationSurface{};
        const HRESULT getDestinationSurfaceResult =
            InvokeGetSurfaceLevel((*destinationTexture)->GetTexture1(), 0U, destinationSurface.out());
        if (getDestinationSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 605, getDestinationSurfaceResult);
        }

        const HRESULT copyResult = InvokeD3DXLoadSurfaceFromSurface(
            destinationSurface.get(),
            reinterpret_cast<const RECT*>(destinationRect),
            sourceSurface.get(),
            reinterpret_cast<const RECT*>(sourceRect),
            0xFFFFFFFFU,
            0U
        );
        if (copyResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 610, copyResult);
        }
    }

    /**
     * Address: 0x008ECB50 (FUN_008ECB50)
     *
     * gpg::gal::TextureD3D9 **,msvc8::string const &
     *
     * What it does:
     * Saves one cube-texture lane to file as DDS.
     */
    void DeviceD3D9::Func3(TextureD3D9** const texture, const msvc8::string& filePath)
    {
        Func1();

        if (filePath.myRes == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 736, "Missing file");
        }

        void* const nativeTexture = const_cast<char*>((*texture)->GetLocation());
        if (nativeTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 741, "unable to get concrete cube texture");
        }

        const HRESULT saveResult =
            InvokeD3DXSaveTextureToFileA(GetStringDataRaw(filePath), kD3DXIFFDDS, nativeTexture);
        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 745, saveResult);
        }
    }

    /**
     * Address: 0x008EC970 (FUN_008EC970)
     *
     * gpg::gal::RenderTargetD3D9 **,msvc8::string const &,int
     *
     * What it does:
     * Saves one render-target surface to file with the requested image-format token.
     */
    void DeviceD3D9::Func4(
        RenderTargetD3D9** const renderTarget,
        const msvc8::string& filePath,
        const int fileFormatToken
    )
    {
        Func1();

        if (filePath.myRes == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 715, "Missing file");
        }

        if (((*renderTarget)->GetRenderSurface()) == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 720, "Unable to get back buffer surface");
        }

        const HRESULT saveResult = InvokeD3DXSaveSurfaceToFileA(
            GetStringDataRaw(filePath),
            MapImageFormatTokenToD3DX(fileFormatToken),
            (*renderTarget)->GetRenderSurface()
        );
        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 728, saveResult);
        }
    }

    /**
     * Address: 0x008EC6A0 (FUN_008EC6A0)
     *
     * gpg::gal::TextureD3D9 **,msvc8::string const &,int,gpg::MemBuffer<char> *
     *
     * What it does:
     * Saves one texture surface either to file or caller memory buffer depending on
     * whether `outBuffer` is non-null.
     */
    void DeviceD3D9::Func5(
        TextureD3D9** const texture,
        const msvc8::string& filePath,
        const int fileFormatToken,
        gpg::MemBuffer<char>* const outBuffer
    )
    {
        Func1();

        ComObjectScope sourceSurface{};
        const HRESULT getSurfaceResult = InvokeGetSurfaceLevel((*texture)->GetTexture1(), 0U, sourceSurface.out());
        if (getSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 681, getSurfaceResult);
        }

        const unsigned int fileFormat = MapImageFormatTokenToD3DX(fileFormatToken);
        HRESULT saveResult = 0;

        if (outBuffer != nullptr)
        {
            ComObjectScope fileBuffer{};
            const HRESULT createBufferResult = InvokeD3DXCreateBuffer(0U, fileBuffer.out());
            if (createBufferResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 690, createBufferResult);
            }

            saveResult = InvokeD3DXSaveSurfaceToFileInMemoryEx(fileBuffer.out(), fileFormat, sourceSurface.get());
            if (saveResult >= 0)
            {
                const unsigned int serializedSize = GetD3DXBufferSize(fileBuffer.get());
                if (outBuffer->Size() != serializedSize)
                {
                    gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(serializedSize);
                    *outBuffer = resizedBuffer;
                }

                void* const sourceBytes = GetD3DXBufferPointer(fileBuffer.get());
                char* const destinationBytes = outBuffer->GetPtr(0U, 0U);
                std::memcpy(destinationBytes, sourceBytes, serializedSize);
            }
        }
        else
        {
            saveResult = InvokeD3DXSaveSurfaceToFileA(GetStringDataRaw(filePath), fileFormat, sourceSurface.get());
        }

        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 707, saveResult);
        }
    }

    /**
     * Address: 0x008ECD20 (FUN_008ECD20)
     *
     * void const *,std::uint32_t,gpg::MemBuffer<char> *,std::uint32_t *,int *
     *
     * What it does:
     * Decodes texture payload bytes from memory, normalizes to DXT5 blocks when
     * needed, then exports packed blocks and decoded width/height lanes.
     */
    void DeviceD3D9::GetTexture2D(
        const void* const sourceData,
        const std::uint32_t sourceBytes,
        gpg::MemBuffer<char>* const outTextureData,
        std::uint32_t* const outWidth,
        int* const outHeight
    )
    {
        Func1();

        if (sourceData == nullptr)
        {
            return;
        }

        void* sourceTexture = nullptr;
        HRESULT createResult = InvokeD3DXCreateTextureFromFileInMemoryEx(
            AsDeviceD3D9Runtime(*this).nativeDevice,
            sourceData,
            sourceBytes,
            kD3DXDefault,
            kD3DXDefault,
            1U,
            0U,
            2U,
            D3DPOOL_MANAGED,
            1U,
            0U,
            0U,
            nullptr,
            nullptr,
            &sourceTexture
        );
        if (createResult < 0)
        {
            createResult = InvokeD3DXCreateTextureFromFileInMemoryEx(
                AsDeviceD3D9Runtime(*this).nativeDevice,
                sourceData,
                sourceBytes,
                kD3DXDefault,
                kD3DXDefault,
                1U,
                0U,
                2U,
                D3DPOOL_MANAGED,
                1U,
                0U,
                0U,
                nullptr,
                nullptr,
                &sourceTexture
            );
            if (createResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 779, createResult);
            }
        }

        ComObjectScope sourceTextureScope{};
        *sourceTextureScope.out() = sourceTexture;

        ComObjectScope sourceSurface{};
        const HRESULT getSourceSurfaceResult = InvokeGetSurfaceLevel(sourceTextureScope.get(), 0U, sourceSurface.out());
        if (getSourceSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 782, getSourceSurfaceResult);
        }

        D3DSurfaceDescRuntime sourceDesc{};
        const HRESULT getDescResult = InvokeSurfaceGetDesc(sourceSurface.get(), &sourceDesc);
        if (getDescResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 785, getDescResult);
        }

        *outWidth = sourceDesc.width;
        *outHeight = static_cast<int>(sourceDesc.height);

        void* decodeSurface = sourceSurface.get();
        ComObjectScope decodeTexture{};
        ComObjectScope decodeSurfaceScope{};

        if (sourceDesc.format != kD3DFormatDXT5)
        {
            const HRESULT createDecodeTextureResult = InvokeNativeCreateTexture(
                this,
                AlignToDword(sourceDesc.width),
                AlignToDword(sourceDesc.height),
                1U,
                0U,
                kD3DFormatDXT5,
                D3DPOOL_MANAGED,
                decodeTexture.out()
            );
            if (createDecodeTextureResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 801, createDecodeTextureResult);
            }

            const HRESULT getDecodeSurfaceResult = InvokeGetSurfaceLevel(decodeTexture.get(), 0U, decodeSurfaceScope.out());
            if (getDecodeSurfaceResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 804, getDecodeSurfaceResult);
            }

            const HRESULT loadResult = InvokeD3DXLoadSurfaceFromSurface(
                decodeSurfaceScope.get(),
                nullptr,
                sourceSurface.get(),
                nullptr,
                kD3DTexFilterPoint,
                0U
            );
            if (loadResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 809, loadResult);
            }

            decodeSurface = decodeSurfaceScope.get();
        }

        D3DLockedRectRuntime lockedRect{};
        const HRESULT lockResult = InvokeSurfaceLockRect(decodeSurface, &lockedRect, nullptr, kD3DSurfaceLockReadOnly);
        if (lockResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 817, lockResult);
        }

        const unsigned int alignedWidth = AlignToDword(*outWidth);
        const unsigned int alignedHeight = AlignToDword(static_cast<unsigned int>(*outHeight));
        const std::size_t bytesPerRow = static_cast<std::size_t>(alignedWidth >> 2U) * 16U;
        const std::size_t rowCount = static_cast<std::size_t>(alignedHeight >> 2U);
        const std::size_t totalBytes = bytesPerRow * rowCount;

        if (outTextureData->Size() != totalBytes)
        {
            gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(totalBytes);
            *outTextureData = resizedBuffer;
        }

        char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
        const char* const sourceBytesPtr = static_cast<const char*>(lockedRect.bits);
        if (static_cast<std::size_t>(lockedRect.pitch) == bytesPerRow)
        {
            std::memcpy(destinationBytes, sourceBytesPtr, totalBytes);
        }
        else
        {
            for (std::size_t rowIndex = 0; rowIndex < rowCount; ++rowIndex)
            {
                std::memcpy(
                    destinationBytes + (rowIndex * bytesPerRow),
                    sourceBytesPtr + (rowIndex * static_cast<std::size_t>(lockedRect.pitch)),
                    bytesPerRow
                );
            }
        }

        const HRESULT unlockResult = InvokeSurfaceUnlockRect(decodeSurface);
        if (unlockResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 833, unlockResult);
        }
    }

    /**
     * Address: 0x008ED360 (FUN_008ED360)
     *
     * What it does:
     * Probes cooperative-level state and maps D3D lost/reset status into
     * backend result tokens.
     */
    int DeviceD3D9::TestCooperativeLevel()
    {
        Func1();
        const HRESULT result = InvokeNativeTestCooperativeLevel(this);
        if (static_cast<std::uint32_t>(result) == kD3DDeviceLost)
        {
            return 2;
        }

        if (static_cast<std::uint32_t>(result) == kD3DDeviceNotReset)
        {
            return 1;
        }

        if (result == 0)
        {
            return 0;
        }

        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 901, result);
        }

        return 2;
    }

    /**
     * Address: 0x008ED450 (FUN_008ED450)
     *
     * What it does:
     * Begins one native scene and issues one begin-event query lane.
     */
    int DeviceD3D9::BeginScene()
    {
        Func1();
        const HRESULT result = InvokeNativeBeginScene(this);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 913, result);
        }

        void* const frameEventQuery = AsDeviceD3D9Runtime(*this).frameEventQuery;
        if (frameEventQuery == nullptr)
        {
            return 0;
        }

        return InvokeQueryIssue(frameEventQuery, kD3DQueryIssueBegin);
    }

    /**
     * Address: 0x008ED550 (FUN_008ED550)
     *
     * What it does:
     * Ends one native D3D9 scene and throws on failure.
     */
    void DeviceD3D9::EndScene()
    {
        Func1();
        const HRESULT result = InvokeNativeEndScene(this);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 926, result);
        }
    }

    /**
     * Address: 0x008ED640 (FUN_008ED640)
     *
     * What it does:
     * Drains the frame-event query to completion then presents one native frame.
     */
    void DeviceD3D9::Present()
    {
        Func1();
        void* const frameEventQuery = AsDeviceD3D9Runtime(*this).frameEventQuery;
        while (InvokeQueryGetData(frameEventQuery, nullptr, 0U, kD3DGetDataFlush) == 1)
        {
        }

        const HRESULT result = InvokeNativePresent(this);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 937, result);
        }
    }

    /**
     * Address: 0x008ED750 (FUN_008ED750)
     *
     * CursorContext const *
     *
     * What it does:
     * Resolves one cursor texture level-0 surface and binds hotspot/surface cursor state.
     */
    void DeviceD3D9::SetCursor(const CursorContext* const context)
    {
        Func1();

        auto* const cursorTexture = reinterpret_cast<TextureD3D9*>(context->pixelSource_);
        ComObjectScope cursorSurface{};
        const HRESULT getSurfaceResult = InvokeGetSurfaceLevel(cursorTexture->GetTexture1(), 0U, cursorSurface.out());
        if (getSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 949, getSurfaceResult);
        }

        const HRESULT setCursorResult = InvokeNativeSetCursorProperties(
            this,
            static_cast<unsigned int>(context->hotspotX_),
            static_cast<unsigned int>(context->hotspotY_),
            cursorSurface.get()
        );
        if (setCursorResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 952, setCursorResult);
        }
    }

    /**
     * Address: 0x008ED910 (FUN_008ED910)
     *
     * void const *
     *
     * What it does:
     * Binds one viewport payload on the native D3D9 device.
     */
    void DeviceD3D9::SetViewport(const void* const viewport)
    {
        Func1();
        const HRESULT result = InvokeNativeSetViewport(this, viewport);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 973, result);
        }
    }

    /**
     * Address: 0x008EDA00 (FUN_008EDA00)
     *
     * void *
     *
     * What it does:
     * Reads one native viewport payload into caller-provided storage.
     */
    void DeviceD3D9::GetViewport(void* const outViewport)
    {
        Func1();
        const HRESULT result = InvokeNativeGetViewport(this, outViewport);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 981, result);
        }
    }

    /**
     * Address: 0x008EDAF0 (FUN_008EDAF0)
     *
     * OutputContext const *
     *
     * What it does:
     * Applies render-target/depth-stencil bindings from one output-context payload.
     */
    void DeviceD3D9::ClearTarget(const OutputContext* const context)
    {
        Func1();

        const auto& runtimeContext = AsOutputContextD3D9Runtime(*context);

        ComObjectScope currentRenderTarget{};
        InvokeNativeGetRenderTarget(this, 0U, currentRenderTarget.out());

        if (runtimeContext.renderTarget.get() != nullptr)
        {
            void* const targetSurface = runtimeContext.renderTarget->GetRenderSurface();
            if (currentRenderTarget.get() != targetSurface)
            {
                const HRESULT setResult = InvokeNativeSetRenderTarget(this, 0U, targetSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1004, setResult);
                }
            }
        }
        else if (runtimeContext.cubeTarget.get() != nullptr)
        {
            void* const targetSurface = runtimeContext.cubeTarget->GetSurface(runtimeContext.face);
            if (currentRenderTarget.get() != targetSurface)
            {
                const HRESULT setResult = InvokeNativeSetRenderTarget(this, 0U, targetSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1017, setResult);
                }
            }
        }
        else if (currentRenderTarget.get() != nullptr)
        {
            const HRESULT setResult = InvokeNativeSetRenderTarget(this, 0U, nullptr);
            if (setResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1024, setResult);
            }
        }

        ComObjectScope currentDepthStencilSurface{};
        InvokeNativeGetDepthStencilSurface(this, currentDepthStencilSurface.out());

        if (runtimeContext.depthStencil.get() != nullptr)
        {
            void* const depthStencilSurface = runtimeContext.depthStencil->GetSurface();
            if (currentDepthStencilSurface.get() != depthStencilSurface)
            {
                const HRESULT setResult = InvokeNativeSetDepthStencilSurface(this, depthStencilSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1043, setResult);
                }
            }
        }
        else if (currentDepthStencilSurface.get() != nullptr)
        {
            const HRESULT setResult = InvokeNativeSetDepthStencilSurface(this, nullptr);
            if (setResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1049, setResult);
            }
        }
    }

    /**
     * Address: 0x008EDE30 (FUN_008EDE30)
     *
     * bool,bool,bool,std::uint32_t,float,int
     *
     * What it does:
     * Builds native clear mask bits from caller booleans and dispatches one D3D clear.
     */
    void DeviceD3D9::Clear(
        const bool clearTarget,
        const bool clearZbuffer,
        const bool clearStencil,
        const std::uint32_t color,
        const float depth,
        const int stencil
    )
    {
        Func1();
        if (!clearTarget && !clearZbuffer && !clearStencil)
        {
            return;
        }

        unsigned int clearMask = 0U;
        if (clearTarget)
        {
            clearMask |= kD3DClearTarget;
        }
        if (clearZbuffer)
        {
            clearMask |= kD3DClearZBuffer;
        }
        if (clearStencil)
        {
            clearMask |= kD3DClearStencil;
        }

        const HRESULT result = InvokeNativeClear(this, 0U, nullptr, clearMask, color, depth, static_cast<unsigned int>(stencil));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1066, result);
        }
    }

    /**
     * Address: 0x008EDF70 (FUN_008EDF70)
     *
     * boost::shared_ptr<gpg::gal::VertexFormatD3D9>
     *
     * What it does:
     * Binds one caller-provided vertex declaration on the native D3D9 device lane.
     */
    void DeviceD3D9::SetVertexDeclaration(boost::shared_ptr<VertexFormatD3D9> vertexFormat)
    {
        Func1();
        const HRESULT result = InvokeNativeSetVertexDeclaration(this, vertexFormat.get()->vertexDeclaration_);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1082, result);
        }
    }

    /**
     * Address: 0x008EE0B0 (FUN_008EE0B0)
     *
     * std::uint32_t,boost::shared_ptr<gpg::gal::VertexBufferD3D9>,int,int
     *
     * What it does:
     * Binds one vertex stream source and applies stream-frequency mode bits from
     * vertex-buffer context lanes.
     */
    void DeviceD3D9::SetVertexBuffer(
        const std::uint32_t streamSlot,
        boost::shared_ptr<VertexBufferD3D9> vertexBuffer,
        const int streamFrequencyToken,
        const int streamOffsetMultiplier
    )
    {
        Func1();

        VertexBufferContext* const vertexContext = vertexBuffer->GetContext();
        const unsigned int stride = vertexContext->height_;
        const unsigned int offsetInBytes = static_cast<unsigned int>(streamOffsetMultiplier) * stride;
        const HRESULT setStreamResult =
            InvokeNativeSetStreamSource(this, streamSlot, vertexBuffer->d3dVertexBuffer_, offsetInBytes, stride);
        if (setStreamResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1093, setStreamResult);
        }

        unsigned int frequencySetting = 1U;
        if (vertexContext->type_ == 2U)
        {
            frequencySetting = static_cast<unsigned int>(streamFrequencyToken) | kD3DStreamSourceIndexedData;
        }
        else if (vertexContext->type_ == 3U)
        {
            frequencySetting = kD3DStreamSourceInstancedData | 1U;
        }

        const HRESULT setFrequencyResult = InvokeNativeSetStreamSourceFreq(this, streamSlot, frequencySetting);
        if (setFrequencyResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1102, setFrequencyResult);
        }
    }

    /**
     * Address: 0x008EE2E0 (FUN_008EE2E0)
     *
     * boost::shared_ptr<gpg::gal::IndexBufferD3D9>
     *
     * What it does:
     * Dispatches pre-hook then binds one index-buffer handle on the native D3D9
     * device lane.
     */
    void DeviceD3D9::SetBufferIndices(boost::shared_ptr<IndexBufferD3D9> indexBuffer)
    {
        Func1();

        const HRESULT result = InvokeNativeSetIndices(this, indexBuffer->d3dIndexBuffer_);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1112, result);
        }
    }

    /**
     * Address: 0x008EE420 (FUN_008EE420)
     *
     * bool,void const *,float,float,int
     *
     * What it does:
     * Validates retained pipeline state then forwards one fog-state payload.
     */
    void DeviceD3D9::SetFogState(
        const bool enable,
        const void* const projection,
        const float fogStart,
        const float fogEnd,
        const int fogColor
    )
    {
        Func1();

        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1120, "unable to set distance fog state, invalid pipeline state");
        }

        pipelineState->SetFogState(enable, projection, fogStart, fogEnd, fogColor);
    }

    /**
     * Address: 0x008EE510 (FUN_008EE510)
     *
     * bool
     *
     * What it does:
     * Validates retained pipeline state and applies recovered wireframe fill mode.
     */
    int DeviceD3D9::SetWireframeState(const bool enabled)
    {
        Func1();

        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1130, "unable to set wireframe state, invalid pipeline state");
        }

        return pipelineState->SetWireframeState(enabled);
    }

    /**
     * Address: 0x008EE5E0 (FUN_008EE5E0)
     *
     * bool,bool
     *
     * What it does:
     * Validates retained pipeline state and applies recovered color-write mask.
     */
    int DeviceD3D9::SetColorWriteState(const bool arg1, const bool arg2)
    {
        Func1();

        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1140, "unable to set color write state, invalid pipeline state");
        }

        return pipelineState->SetColorWriteState(arg1, arg2);
    }

    /**
     * Address: 0x008EE6B0 (FUN_008EE6B0)
     *
     * void const *
     *
     * What it does:
     * Validates draw topology, binds recovered primitive type, and dispatches one
     * native non-indexed draw.
     */
    int DeviceD3D9::DrawPrimitive(const void* const context)
    {
        Func1();

        const auto* const drawContext = reinterpret_cast<const DrawPrimitiveContextRuntime*>(context);
        if (drawContext->topologyToken == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 1149, "invalid topology specified");
        }

        const unsigned int primitiveType = ResolvePrimitiveType(drawContext->topologyToken);
        const unsigned int primitiveCount = GetDrawPrimitiveCount(*drawContext);
        const HRESULT result = InvokeNativeDrawPrimitive(
            this,
            primitiveType,
            drawContext->startVertex,
            primitiveCount
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1152, result);
        }

        return result;
    }

    /**
     * Address: 0x008EE850 (FUN_008EE850)
     *
     * void const *
     *
     * What it does:
     * Validates indexed draw topology, binds recovered primitive type, and
     * dispatches one native indexed draw.
     */
    int DeviceD3D9::DrawIndexedPrimitive(const void* const context)
    {
        Func1();

        const auto* const drawContext = reinterpret_cast<const DrawIndexedPrimitiveContextRuntime*>(context);
        if (drawContext->topologyToken == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 1159, "invalid topology specified");
        }

        const unsigned int primitiveType = ResolvePrimitiveType(drawContext->topologyToken);
        const unsigned int primitiveCount = GetDrawIndexedPrimitiveCount(*drawContext);
        const HRESULT result = InvokeNativeDrawIndexedPrimitive(
            this,
            primitiveType,
            drawContext->baseVertexIndex,
            drawContext->minVertexIndex,
            drawContext->vertexCount,
            drawContext->startIndex,
            primitiveCount
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1162, result);
        }

        return result;
    }

    /**
     * Address: 0x008EEA00 (FUN_008EEA00)
     *
     * What it does:
     * Validates retained pipeline state then forwards begin-technique state setup.
     */
    void DeviceD3D9::BeginTechnique()
    {
        Func1();

        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1170, "unable to begin technique, invalid pipeline state");
        }

        pipelineState->BeginTechnique();
    }

    /**
     * Address: 0x008EEAC0 (FUN_008EEAC0)
     *
     * What it does:
     * Validates retained pipeline state then forwards end-technique cleanup.
     */
    void DeviceD3D9::EndTechnique()
    {
        Func1();

        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1180, "unable to end technique, invalid pipeline state");
        }

        pipelineState->EndTechnique();
    }

    /**
     * Address: 0x008E8EE0 (FUN_008E8EE0)
     *
     * What it does:
     * Dispatches `Func1` pre-hook then clears bound textures through pipeline-state helper.
     */
    int DeviceD3D9::ClearTextures()
    {
        Func1();
        PipelineStateD3D9* const pipelineState = AsDeviceD3D9Runtime(*this).pipelineState.get();
        return pipelineState->ClearTextures();
    }

    /**
     * Address: 0x009460A0 (FUN_009460A0)
     *
     * bool,void const *,float,float,int
     *
     * What it does:
     * Applies fog enable/disable state and projection-fog payload lanes on the
     * retained state manager.
     */
    void PipelineStateD3D9::SetFogState(
        const bool enable,
        const void* const projection,
        const float fogStart,
        const float fogEnd,
        const int fogColor
    )
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        if (enable)
        {
            static_cast<void>(stateManager->SetTransform(kD3DTransformProjection, projection));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogEnable),
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateRangeFogEnable),
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogColor),
                static_cast<unsigned int>(fogColor)
            ));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogTableMode),
                kD3DFogModeLinear
            ));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogStart),
                std::bit_cast<unsigned int>(fogStart)
            ));
            static_cast<void>(stateManager->SetRenderState(
                static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogEnd),
                std::bit_cast<unsigned int>(fogEnd)
            ));
            return;
        }

        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateFogEnable),
            0U
        ));

        float projectionIdentity[4][4] = {};
        projectionIdentity[0][0] = 1.0f;
        projectionIdentity[1][1] = 1.0f;
        projectionIdentity[2][2] = 1.0f;
        projectionIdentity[3][3] = 1.0f;
        static_cast<void>(stateManager->SetTransform(kD3DTransformProjection, projectionIdentity));
    }

    /**
     * Address: 0x009461C0 (FUN_009461C0)
     *
     * What it does:
     * Selects and applies recovered D3D9 fill mode for wireframe toggle lanes.
     */
    int PipelineStateD3D9::SetWireframeState(const bool enabled)
    {
        const unsigned int fillMode = enabled ? kD3DFillModeWireframe : kD3DFillModeSolid;
        return GetStateManager()->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DFillMode),
            fillMode
        );
    }

    /**
     * Address: 0x009461F0 (FUN_009461F0)
     *
     * What it does:
     * Rebuilds and applies retained color-write mask from two recovered toggle
     * lanes.
     */
    int PipelineStateD3D9::SetColorWriteState(const bool arg1, const bool arg2)
    {
        if (arg1)
        {
            colorWriteEnable_ = arg2 ? 0x0FU : 0x07U;
        }
        else
        {
            colorWriteEnable_ = arg2 ? 0x08U : 0x0FU;
        }

        return GetStateManager()->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateColorWriteEnable),
            colorWriteEnable_
        );
    }

    /**
     * Address: 0x00946260 (FUN_00946260)
     *
     * What it does:
     * Reapplies retained technique begin-state render-state defaults.
     */
    void PipelineStateD3D9::BeginTechnique()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateColorWriteEnable),
            colorWriteEnable_
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateAlphaBlendEnable),
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateAlphaTestEnable),
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateStencilEnable),
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateZEnable),
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateZFunc),
            kD3DCmpLessEqual
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateZWriteEnable),
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateDepthBias),
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            static_cast<StateManagerD3D9::render_state_type>(kD3DRenderStateCullMode),
            kD3DCullCounterClockwise
        ));
    }

    /**
     * Address: 0x00946300 (FUN_00946300)
     *
     * What it does:
     * Preserves the binary no-op end-technique lane.
     */
    void PipelineStateD3D9::EndTechnique() {}

    /**
     * Address: 0x00946240 (FUN_00946240)
     *
     * What it does:
     * Clears all 16 texture stages through the retained D3D9 state manager.
     */
    int PipelineStateD3D9::ClearTextures()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        int result = 0;
        for (unsigned int stageIndex = 0; stageIndex < 16U; ++stageIndex)
        {
            result = stateManager->SetTexture(stageIndex, nullptr);
        }
        return result;
    }

    /**
     * Address: 0x00946310 (FUN_00946310)
     *
     * What it does:
     * Returns the retained D3D9 state-manager interface pointer.
     */
    StateManagerD3D9* PipelineStateD3D9::GetStateManager()
    {
        return reinterpret_cast<StateManagerD3D9*>(stateManager_);
    }

    /**
     * Address: 0x008F3AA0 (FUN_008F3AA0)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_008F3A20` body semantics.
     */
    EffectTechniqueD3D9::~EffectTechniqueD3D9()
    {
        DestroyEffectTechniqueD3D9Body(this);
    }

    /**
     * Address: 0x008F3850 (FUN_008F3850)
     *
     * What it does:
     * Returns the local technique-name string lane.
     */
    msvc8::string* EffectTechniqueD3D9::GetName()
    {
        return &name_;
    }

    /**
     * Address: 0x008F3C40 (FUN_008F3C40)
     *
     * What it does:
     * Validates begin/end state, binds this technique on the effect, then begins the technique pass chain.
     */
    int EffectTechniqueD3D9::BeginTechnique()
    {
        if (beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 50, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 53);
        void* const dxEffect = effect->GetDxEffect();
        const HRESULT setTechniqueResult = InvokeEffectSetTechnique(dxEffect, handle_);
        if (setTechniqueResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 58, setTechniqueResult);
        }

        Device* const device = Device::GetInstance();
        InvokeDeviceBeginTechnique(device);

        unsigned int passCount = 0U;
        const HRESULT beginResult = InvokeEffectBeginTechnique(dxEffect, &passCount, 1U);
        if (beginResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 67, beginResult);
        }

        beginEndActive_ = true;
        return static_cast<int>(passCount);
    }

    /**
     * Address: 0x008F3EA0 (FUN_008F3EA0)
     *
     * What it does:
     * Validates begin/end state, ends the active technique, and clears local begin/end tracking.
     */
    void EffectTechniqueD3D9::EndTechnique()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 76, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 79);
        const HRESULT result = InvokeEffectEndTechnique(effect->GetDxEffect());
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 84, result);
        }

        Device* const device = Device::GetInstance();
        InvokeDeviceEndTechnique(device);
        beginEndActive_ = false;
    }

    /**
     * Address: 0x00942EE0 (FUN_00942EE0)
     *
     * What it does:
     * Initializes weak-self/context/effect lanes and binds caller-provided context/effect state.
     */
    EffectD3D9::EffectD3D9(EffectContext* const context, void* const dxEffect)
        : selfWeak_(),
          effectContext_(),
          effectContextPad_{},
          dxEffect_(nullptr)
    {
        InitializeEffectContextRuntimeStorage(*AsEffectContextRuntime(this));
        InitializeEffectD3D9State(this, context, dxEffect);
    }

    /**
     * Address: 0x00942EC0 (FUN_00942EC0)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates teardown to `FUN_00942DD0` body lanes.
     */
    EffectD3D9::~EffectD3D9()
    {
        DestroyEffectD3D9Body(this);
    }

    /**
     * Address: 0x009415B0 (FUN_009415B0)
     *
     * What it does:
     * Returns the embedded effect-context lane.
     */
    EffectContext* EffectD3D9::GetContext()
    {
        return &effectContext_;
    }

    /**
     * Address: 0x00942350 (FUN_00942350)
     *
     * What it does:
     * Returns the retained D3DX effect interface and throws when missing.
     */
    void* EffectD3D9::GetDxEffect()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 137, "attempt to retrieve invalid effect");
        }

        return dxEffect_;
    }

    /**
     * Address: 0x00942920 (FUN_00942920)
     *
     * What it does:
     * Enumerates valid D3DX techniques and appends wrapped technique objects.
     */
    HRESULT EffectD3D9::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechniqueD3D9>>& outTechniques)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 58, "invalid effect");
        }

        void* techniqueHandle = nullptr;
        HRESULT result = InvokeEffectFindNextValidTechnique(dxEffect_, nullptr, &techniqueHandle);
        while (result >= 0)
        {
            if (techniqueHandle == nullptr)
            {
                break;
            }

            D3DXTechniqueDescRuntime techniqueDesc{};
            result = InvokeEffectGetTechniqueDesc(dxEffect_, techniqueHandle, &techniqueDesc);
            if (result < 0)
            {
                ThrowGalErrorFromHresult("EffectD3D9.cpp", 66, result);
            }

            const EffectTechniqueSharedRef wrapper =
                CreateEffectTechniqueWrapper(techniqueDesc.name, selfWeak_, techniqueHandle);
            static_cast<void>(AppendEffectTechniqueSharedRef(outTechniques, wrapper));
            result = InvokeEffectFindNextValidTechnique(dxEffect_, techniqueHandle, &techniqueHandle);
        }

        return result;
    }

    /**
     * Address: 0x00941D70 (FUN_00941D70)
     *
     * What it does:
     * Looks up an effect parameter by name and returns a wrapped effect-variable object.
     */
    boost::shared_ptr<EffectVariableD3D9> EffectD3D9::SetMatrix(const char* const variableName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 76, "invalid effect");
        }

        void* const parameterHandle = InvokeEffectGetParameterByName(dxEffect_, nullptr, variableName);
        if (parameterHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect variable requested: %s",
                (variableName != nullptr) ? variableName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 79, message);
        }

        return CreateEffectVariableWrapper(variableName, selfWeak_, parameterHandle);
    }

    /**
     * Address: 0x00941F60 (FUN_00941F60)
     *
     * What it does:
     * Looks up a technique by name and returns a wrapped technique handle.
     */
    boost::shared_ptr<EffectTechniqueD3D9> EffectD3D9::SetTechnique(const char* const techniqueName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 86, "invalid effect");
        }

        void* const techniqueHandle = InvokeEffectGetTechniqueByName(dxEffect_, techniqueName);
        if (techniqueHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect technique requested: %s",
                (techniqueName != nullptr) ? techniqueName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 89, message);
        }

        return CreateEffectTechniqueWrapper(techniqueName, selfWeak_, techniqueHandle);
    }

    /**
     * Address: 0x00942150 (FUN_00942150)
     *
     * What it does:
     * Rebinds the effect state manager from current pipeline state and forwards reset notification to D3DX.
     */
    void EffectD3D9::OnReset()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 96, "invalid effect");
        }

        Device* const device = Device::GetInstance();
        boost::shared_ptr<PipelineStateD3D9> pipelineState;
        InvokeDeviceGetPipelineState(device, &pipelineState);

        StateManagerD3D9* const stateManager = pipelineState->GetStateManager();
        static_cast<void>(InvokeEffectSetStateManager(dxEffect_, stateManager));
        static_cast<void>(InvokeEffectOnResetDevice(dxEffect_));
    }

    /**
     * Address: 0x00942290 (FUN_00942290)
     *
     * What it does:
     * Forwards device-lost notification to the retained D3DX effect.
     */
    HRESULT EffectD3D9::OnLost()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 108, "invalid effect");
        }

        return InvokeEffectOnLostDevice(dxEffect_);
    }

    /**
     * Address: 0x00943060 (FUN_00943060)
     *
     * What it does:
     * Stores variable-name/effect-handle lanes and validates weak-effect liveness.
     */
    EffectVariableD3D9::EffectVariableD3D9(
        const char* const variableName,
        const boost::weak_ptr<EffectD3D9>& effect,
        void* const handle
    )
        : name_(variableName != nullptr ? variableName : "", (variableName != nullptr) ? std::strlen(variableName) : 0U),
          effect_(effect),
          handle_(handle)
    {
        if (effect_.use_count() <= 0)
        {
            ThrowGalError("EffectVariableD3D9.cpp", 37, "invalid effect specified");
        }
    }

    /**
     * Address: 0x00943040 (FUN_00943040)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_00942FC0` body semantics.
     */
    EffectVariableD3D9::~EffectVariableD3D9()
    {
        DestroyEffectVariableD3D9Body(this);
        ApplyEffectVariableBaseVftableLane(this);
    }

    /**
     * Address: 0x00942F80 (FUN_00942F80)
     *
     * What it does:
     * Returns the local variable-name string lane.
     */
    msvc8::string* EffectVariableD3D9::Func1()
    {
        return &name_;
    }

    /**
     * Address: 0x009431E0 (FUN_009431E0)
     *
     * What it does:
     * Writes one boolean parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::Func7(const bool value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 52);
        const HRESULT result = InvokeEffectSetBool(effect->GetDxEffect(), handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 57, result);
        }
    }

    /**
     * Address: 0x009433A0 (FUN_009433A0)
     *
     * What it does:
     * Writes one integer parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::Func6(const int value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 63);
        const HRESULT result = InvokeEffectSetInt(effect->GetDxEffect(), handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 68, result);
        }
    }

    /**
     * Address: 0x00943710 (FUN_00943710)
     *
     * What it does:
     * Writes a single vector4 payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::Func4(const void* const vector4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 85);
        const HRESULT result = InvokeEffectSetVector(effect->GetDxEffect(), handle_, vector4);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 90, result);
        }
    }

    /**
     * Address: 0x009438D0 (FUN_009438D0)
     *
     * What it does:
     * Writes a vector-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::Func9(const std::uint32_t vectorCount, const void* const vectors4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 96);
        const HRESULT result = InvokeEffectSetVectorArray(effect->GetDxEffect(), handle_, vectors4, vectorCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 101, result);
        }
    }

    /**
     * Address: 0x00943550 (FUN_00943550)
     *
     * What it does:
     * Writes one float parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetFloat(const float value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 74);
        const HRESULT result = InvokeEffectSetFloat(effect->GetDxEffect(), handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 79, result);
        }
    }

    /**
     * Address: 0x00943A90 (FUN_00943A90)
     *
     * What it does:
     * Writes a float-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMem(const std::uint32_t floatCount, const float* const values)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 107);
        const HRESULT result = InvokeEffectSetFloatArray(effect->GetDxEffect(), handle_, values, floatCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 112, result);
        }
    }

    /**
     * Address: 0x00943C50 (FUN_00943C50)
     *
     * What it does:
     * Writes an untyped byte payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetPtr(const void* const data, const std::uint32_t byteCount)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 118);
        const HRESULT result = InvokeEffectSetValue(effect->GetDxEffect(), handle_, data, byteCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 123, result);
        }
    }

    /**
     * Address: 0x00943E10 (FUN_00943E10)
     *
     * What it does:
     * Writes a 4x4 matrix payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMatrix4x4(const void* const matrix4x4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 129);
        const HRESULT result = InvokeEffectSetMatrix(effect->GetDxEffect(), handle_, matrix4x4);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 134, result);
        }
    }

    /**
     * Address: 0x00943FD0 (FUN_00943FD0)
     *
     * What it does:
     * Writes a matrix-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::Func8(const std::uint32_t matrixCount, const void* const matrices4x4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 140);
        const HRESULT result = InvokeEffectSetMatrixArray(effect->GetDxEffect(), handle_, matrices4x4, matrixCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 145, result);
        }
    }

    /**
     * Address: 0x009441A0 (FUN_009441A0)
     *
     * What it does:
     * Binds a texture wrapper lane (2D/volume/cube) to the backing D3DX effect parameter.
     */
    void EffectVariableD3D9::SetTexture(boost::shared_ptr<TextureD3D9> texture)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 151);
        void* textureHandle = nullptr;

        if (texture)
        {
            textureHandle = texture->GetTexture1();
            if (textureHandle == nullptr)
            {
                textureHandle = texture->GetTexture2();
            }
            if (textureHandle == nullptr)
            {
                textureHandle = texture->GetTexture3();
            }
        }

        const HRESULT result = InvokeEffectSetTexture(effect->GetDxEffect(), handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 183, result);
        }
    }

    /**
     * Address: 0x00944420 (FUN_00944420)
     *
     * What it does:
     * Binds a render-target surface lane to the backing D3DX effect parameter.
     */
    void EffectVariableD3D9::Func3(boost::shared_ptr<RenderTargetD3D9> renderTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 189);
        void* const textureHandle = (renderTarget.get() != nullptr) ? renderTarget->GetRenderSurface() : nullptr;

        const HRESULT result = InvokeEffectSetTexture(effect->GetDxEffect(), handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 201, result);
        }
    }

    /**
     * Address: 0x00944630 (FUN_00944630)
     *
     * What it does:
     * Binds a cube-render-target texture lane to the backing D3DX effect parameter.
     */
    void EffectVariableD3D9::Func2(boost::shared_ptr<CubeRenderTargetD3D9> cubeRenderTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 207);
        void* const textureHandle = (cubeRenderTarget.get() != nullptr) ? cubeRenderTarget->cubeTexture_ : nullptr;

        const HRESULT result = InvokeEffectSetTexture(effect->GetDxEffect(), handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 219, result);
        }
    }

    /**
     * Address: 0x00944840 (FUN_00944840)
     *
     * What it does:
     * Retrieves a boolean annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::Func10(bool* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 225);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        int rawValue = 0;
        const HRESULT result = InvokeEffectGetBool(dxEffect, annotationHandle, &rawValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 235, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x00944A10 (FUN_00944A10)
     *
     * What it does:
     * Retrieves an integer annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::Func11(int* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 245);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = InvokeEffectGetInt(dxEffect, annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 254, result);
        }

        return true;
    }

    /**
     * Address: 0x00944BD0 (FUN_00944BD0)
     *
     * What it does:
     * Retrieves a float annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::Func12(float* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 262);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = InvokeEffectGetFloat(dxEffect, annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 271, result);
        }

        return true;
    }

    /**
     * Address: 0x00944D90 (FUN_00944D90)
     *
     * What it does:
     * Retrieves a string annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::Func13(msvc8::string* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 279);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const char* annotationText = nullptr;
        const HRESULT result = InvokeEffectGetString(dxEffect, annotationHandle, &annotationText);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 289, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }

    /**
     * Address: 0x008F4080 (FUN_008F4080)
     *
     * What it does:
     * Begins the selected pass on the active technique.
     */
    void EffectTechniqueD3D9::BeginPass(const int pass)
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 94, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 97);
        const HRESULT result = InvokeEffectBeginPass(effect->GetDxEffect(), static_cast<unsigned int>(pass));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 102, result);
        }
    }

    /**
     * Address: 0x008F4260 (FUN_008F4260)
     *
     * What it does:
     * Ends the currently active pass on the technique.
     */
    void EffectTechniqueD3D9::EndPass()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 107, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 110);
        const HRESULT result = InvokeEffectEndPass(effect->GetDxEffect());
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 115, result);
        }
    }

    /**
     * Address: 0x008F4430 (FUN_008F4430)
     *
     * What it does:
     * Looks up and reads a bool annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 121);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        int rawValue = 0;
        const HRESULT result = InvokeEffectGetBool(dxEffect, annotationHandle, &rawValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 131, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x008F4600 (FUN_008F4600)
     *
     * What it does:
     * Looks up and reads an integer annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 141);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = InvokeEffectGetInt(dxEffect, annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 150, result);
        }

        return true;
    }

    /**
     * Address: 0x008F47C0 (FUN_008F47C0)
     *
     * What it does:
     * Looks up and reads a float annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 158);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = InvokeEffectGetFloat(dxEffect, annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 167, result);
        }

        return true;
    }

    /**
     * Address: 0x008F4980 (FUN_008F4980)
     *
     * What it does:
     * Looks up and reads a string annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 175);
        void* const dxEffect = effect->GetDxEffect();
        void* const annotationHandle = InvokeEffectGetAnnotationByName(dxEffect, handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const char* annotationText = nullptr;
        const HRESULT result = InvokeEffectGetString(dxEffect, annotationHandle, &annotationText);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 185, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }

    /**
     * Address: 0x008F4D80 (FUN_008F4D80)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_008F4C80` body semantics.
     */
    IndexBufferD3D9::~IndexBufferD3D9()
    {
        DestroyIndexBufferD3D9Body(this);
    }

    /**
     * Address: 0x008F5450 (FUN_008F5450)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to render-target teardown helpers.
     */
    RenderTargetD3D9::~RenderTargetD3D9()
    {
        DestroyRenderTargetD3D9Body(this);
    }

    /**
     * Address: 0x008F52C0 (FUN_008F52C0)
     *
     * What it does:
     * Returns the embedded render-target context lane at `this+0x04`.
     */
    RenderTargetContext* RenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F52E0 (FUN_008F52E0)
     *
     * What it does:
     * Returns the retained render-target surface pointer lane at `this+0x18`.
     */
    void* RenderTargetD3D9::GetRenderSurface()
    {
        return renderSurface_;
    }

    /**
     * Address: 0x008F5300 (FUN_008F5300)
     *
     * What it does:
     * Returns surface level 0 from the retained render-target texture handle.
     */
    void* RenderTargetD3D9::GetSurfaceLevel0()
    {
        return GetSurfaceLevel0FromTexture(renderTexture_);
    }

    /**
     * Address: 0x008E8110 (FUN_008E8110, gpg::gal::DepthStencilTargetD3D9::DepthStencilTargetD3D9)
     *
     * What it does:
     * Initializes one depth-stencil target object, default-constructs the
     * embedded context lane, and binds the provided context/surface payload.
     */
    DepthStencilTargetD3D9::DepthStencilTargetD3D9(
        const DepthStencilTargetContext* const context,
        void* const depthStencilSurface
    )
        : context_()
        , depthStencilSurface_(nullptr)
    {
        (void)SetSurface(context, depthStencilSurface);
    }

    /**
     * Address: 0x008E80F0 (FUN_008E80F0)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to depth-stencil teardown helpers.
     */
    DepthStencilTargetD3D9::~DepthStencilTargetD3D9()
    {
        DestroyDepthStencilTargetD3D9Body(this);
    }

    /**
     * Address: 0x008E7F00 (FUN_008E7F00)
     *
     * What it does:
     * Returns the embedded depth-stencil context lane at `this+0x04`.
     */
    DepthStencilTargetContext* DepthStencilTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008E7F40 (FUN_008E7F40)
     *
     * What it does:
     * Returns the retained native depth-stencil surface lane at `this+0x18`.
     */
    void* DepthStencilTargetD3D9::GetSurface() const
    {
        return depthStencilSurface_;
    }

    /**
     * Address: 0x008E8070 (FUN_008E8070, gpg::gal::DepthStencilTargetD3D9::SetSurface)
     *
     * What it does:
     * Releases the previously retained depth-stencil surface (if any),
     * resets context lanes to defaults, then installs the provided
     * context/surface payload.
     */
    void* DepthStencilTargetD3D9::SetSurface(
        const DepthStencilTargetContext* const context,
        void* const depthStencilSurface
    )
    {
        ReleaseComLike(depthStencilSurface_);

        const DepthStencilTargetContext resetContext{};
        context_.width_ = resetContext.width_;
        context_.height_ = resetContext.height_;
        context_.format_ = resetContext.format_;
        context_.field0x10_ = resetContext.field0x10_;

        context_.width_ = context->width_;
        context_.height_ = context->height_;
        context_.format_ = context->format_;
        context_.field0x10_ = context->field0x10_;
        depthStencilSurface_ = depthStencilSurface;
        return depthStencilSurface_;
    }

    /**
     * Address: 0x00941450 (FUN_00941450, gpg::gal::CubeRenderTargetD3D9::CubeRenderTargetD3D9)
     *
     * What it does:
     * Initializes cube-target state, applies one context/texture payload, and
     * acquires one face-surface handle per cube face.
     */
    CubeRenderTargetD3D9::CubeRenderTargetD3D9(
        const CubeRenderTargetContext* const context,
        void* const cubeTexture
    )
        : context_()
        , cubeTexture_(nullptr)
        , faceSurfaces_{}
    {
        AssignCubeRenderTargetD3D9State(this, context, cubeTexture);
    }

    /**
     * Address: 0x00941430 (FUN_00941430)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to cube-target teardown helpers.
     */
    CubeRenderTargetD3D9::~CubeRenderTargetD3D9()
    {
        DestroyCubeRenderTargetD3D9Body(this);
    }

    /**
     * Address: 0x00941240 (FUN_00941240)
     *
     * What it does:
     * Returns the embedded cube render-target context lane at `this+0x04`.
     */
    CubeRenderTargetContext* CubeRenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x009414D0 (FUN_009414D0)
     *
     * int
     *
     * What it does:
     * Validates one cube face index and returns its retained native face surface lane.
     */
    void* CubeRenderTargetD3D9::GetSurface(const int face) const
    {
        if ((face < 0) || (face >= kCubeFaceCount))
        {
            ThrowGalError("CubeRenderTargetD3D9.cpp", 104, "invalid cube face index specified");
        }

        return faceSurfaces_[face];
    }

    /**
     * Address: 0x008F4BE0 (FUN_008F4BE0)
     *
     * What it does:
     * Returns the embedded index-buffer context block at `this+0x04`.
     */
    IndexBufferContext* IndexBufferD3D9::GetContextBuffer()
    {
        return &context_;
    }

    /**
     * Address: 0x008F4E10 (FUN_008F4E10)
     *
     * What it does:
     * Locks the retained D3D9 index buffer and returns mapped index data.
     */
    std::int16_t* IndexBufferD3D9::Lock(
        const unsigned int offset,
        const unsigned int size,
        const MohoD3DLockFlags lockFlags
    )
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IdxBufD3D9.cpp", 56, "lock invalid");
        }

        if (locked_)
        {
            ThrowGalError("IdxBufD3D9.cpp", 57, "lock mismatch");
        }

        const HRESULT result = InvokeLock(
            d3dIndexBuffer_,
            offset,
            size,
            reinterpret_cast<void**>(&indexData_),
            ToIndexBufferLockFlags(lockFlags)
        );

        if (result < 0)
        {
            ThrowGalErrorFromHresult("IdxBufD3D9.cpp", 65, result);
        }

        locked_ = true;
        return indexData_;
    }

    /**
     * Address: 0x008F4FF0 (FUN_008F4FF0)
     *
     * What it does:
     * Unlocks the retained D3D9 index buffer and clears lock-tracking state.
     */
    HRESULT IndexBufferD3D9::Unlock()
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IdxBufD3D9.cpp", 73, "unlock invalid");
        }

        if (!locked_)
        {
            ThrowGalError("IdxBufD3D9.cpp", 74, "lock mismatch");
        }

        const HRESULT result = InvokeUnlock(d3dIndexBuffer_);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("IdxBufD3D9.cpp", 77, result);
        }

        locked_ = false;
        indexData_ = nullptr;
        return result;
    }

    /**
     * Address: 0x008F5190 (FUN_008F5190, gpg::gal::IndexBufferD3D9::GetBuffer)
     *
     * What it does:
     * Returns the retained D3D9 index-buffer handle and throws when unset.
     */
    void* IndexBufferD3D9::GetBuffer()
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IndexBufferD3D9.cpp", 105, "invalid index buffer");
        }

        return d3dIndexBuffer_;
    }

    /**
     * Address: 0x0094A030 (FUN_0094A030)
     *
     * What it does:
     * Initializes vtable/context/resource state for a new D3D9 texture wrapper.
     */
    TextureD3D9::TextureD3D9() = default;

    /**
     * Address: 0x0094AB60 (FUN_0094AB60)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_0094AA90` body semantics.
     */
    TextureD3D9::~TextureD3D9()
    {
        DestroyTextureD3D9Body(this);
    }

    /**
     * Address: 0x0094A080 (FUN_0094A080)
     *
     * What it does:
     * Returns the embedded texture-context state block at `this+0x04`.
     */
    TextureContext* TextureD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x00941270 (FUN_00941270)
     *
     * What it does:
     * Returns the raw location string pointer from the embedded texture context.
     */
    const char* TextureD3D9::GetLocation() const
    {
        return context_.location_.raw_data_unsafe();
    }

    /**
     * Address: 0x0094A0A0 (FUN_0094A0A0)
     *
     * What it does:
     * Returns the retained D3D texture pointer when the context type is 2D (`1`).
     */
    void* TextureD3D9::GetTexture1() const
    {
        if (context_.type_ == 1U)
        {
            return texture_;
        }

        return nullptr;
    }

    /**
     * Address: 0x0094A0B0 (FUN_0094A0B0)
     *
     * What it does:
     * Returns the retained D3D texture pointer when the context type is volume (`2`).
     */
    void* TextureD3D9::GetTexture2() const
    {
        if (context_.type_ == 2U)
        {
            return texture_;
        }

        return nullptr;
    }

    /**
     * Address: 0x0094A0C0 (FUN_0094A0C0)
     *
     * What it does:
     * Returns the retained D3D texture pointer when the context type is cube (`3`).
     */
    void* TextureD3D9::GetTexture3() const
    {
        if (context_.type_ == 3U)
        {
            return texture_;
        }

        return nullptr;
    }

    /**
     * Address: 0x0094A150 (FUN_0094A150)
     *
     * What it does:
     * Locks texture level/rect range and returns mapped pitch/data in caller output.
     */
    TextureLockRect* TextureD3D9::Lock(TextureLockRect* const outRect, const int level, const RECT* const rect, const int flags)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 62, "lock invalid tex");
        }

        if (level >= static_cast<int>(context_.mipmapLevels_))
        {
            ThrowGalError("TexD3D9.cpp", 63, "lock invalid lvl");
        }

        if (locking_)
        {
            ThrowGalError("TexD3D9.cpp", 64, "tex lock mismatch");
        }

        if (context_.type_ != 1U)
        {
            ThrowGalError("TexD3D9.cpp", 65, "lock only 2D");
        }

        struct LockedRectView
        {
            int pitch;
            void* bits;
        } lockedRect{};

        RECT copiedRect{};
        const RECT* d3dRect = nullptr;
        if (rect != nullptr)
        {
            copiedRect = *rect;
            d3dRect = (copiedRect.right != copiedRect.left) ? &copiedRect : nullptr;
        }

        const HRESULT result = InvokeLockRect(
            texture_,
            level,
            &lockedRect,
            d3dRect,
            ToTextureLockFlags(flags)
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 80, result);
        }

        level_ = level;
        outRect->level = level;
        outRect->flags = flags;
        outRect->bits = lockedRect.bits;
        locking_ = true;
        outRect->pitch = lockedRect.pitch;
        return outRect;
    }

    /**
     * Address: 0x0094A410 (FUN_0094A410)
     *
     * What it does:
     * Unlocks the active texture level and clears lock-tracking state.
     */
    HRESULT TextureD3D9::Unlock(const int level)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 116, "unlock invalid");
        }

        if (level != level_)
        {
            ThrowGalError("TexD3D9.cpp", 117, "unlock bad lvl");
        }

        if (!locking_)
        {
            ThrowGalError("TexD3D9.cpp", 118, "tex lock mismatch");
        }

        void* const unlockTexture = (context_.type_ == 1U) ? texture_ : nullptr;
        const HRESULT result = InvokeUnlockRect(unlockTexture, level);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 123, result);
        }

        locking_ = false;
        level_ = 0;
        return result;
    }

    /**
     * Address: 0x0094A090 (FUN_0094A090)
     *
     * What it does:
     * Forwards to vtable-slot unlock path using the second stack argument.
     */
    int TextureD3D9::Func1(const int arg1, const int level, const int arg3, const int arg4)
    {
        static_cast<void>(arg1);
        static_cast<void>(arg3);
        static_cast<void>(arg4);

        auto** const vtable = *reinterpret_cast<void***>(this);
        auto* const thunk = reinterpret_cast<texture_virtual_unlock_fn>(vtable[3]);
        return thunk(this, level);
    }

    /**
     * Address: 0x0094A630 (FUN_0094A630)
     *
     * What it does:
     * Serializes level-0 texture surface bytes into the caller-provided memory buffer.
     */
    void TextureD3D9::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 131, "attempt to unlock invalid texture");
        }

        if (context_.type_ != 1U)
        {
            ThrowGalError("TexD3D9.cpp", 132, "currently allowed to only save 2D textures");
        }

        ComObjectScope sourceSurface{};
        const HRESULT getSurfaceResult = InvokeGetSurfaceLevel(texture_, 0U, sourceSurface.out());
        if (getSurfaceResult < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 136, getSurfaceResult);
        }

        ComObjectScope fileBuffer{};
        const HRESULT createBufferResult = InvokeD3DXCreateBuffer(0U, fileBuffer.out());
        if (createBufferResult < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 139, createBufferResult);
        }

        const HRESULT saveResult = InvokeD3DXSaveSurfaceToFileInMemory(fileBuffer.out(), sourceSurface.get());
        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 140, saveResult);
        }

        const unsigned int serializedSize = GetD3DXBufferSize(fileBuffer.get());
        if (outBuffer->Size() != serializedSize)
        {
            gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(serializedSize);
            *outBuffer = resizedBuffer;
        }

        void* const sourceBytes = GetD3DXBufferPointer(fileBuffer.get());
        char* const destinationBytes = outBuffer->GetPtr(0U, 0U);
        std::memcpy(destinationBytes, sourceBytes, serializedSize);
    }

    /**
     * Address: 0x0094A980 (FUN_0094A980)
     *
     * What it does:
     * Resets texture resources and reinitializes context state.
     */
    void TextureD3D9::Reset()
    {
        if (locking_)
        {
            Unlock(level_);
        }

        const auto type = context_.type_;
        const bool knownType = (type == 1U) || (type == 2U) || (type == 3U);
        if (!knownType && texture_ != nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 198, "unknown tex type");
        }

        ReleaseComLike(texture_);

        const TextureContext resetContext{};
        context_.AssignFrom(resetContext);
        texture_ = nullptr;
    }

    /**
     * Address: 0x00949F80 (FUN_00949F80)
     *
     * What it does:
     * Initializes pipeline-state defaults and binds one state-manager instance
     * to the supplied native D3D9 device.
     */
    PipelineStateD3D9::PipelineStateD3D9(void* const nativeDevice)
    {
        stateManager_ = nullptr;
        colorWriteEnable_ = 0x0FU;

        StateManagerD3D9* const stateManager = new StateManagerD3D9(nativeDevice);
        stateManager_ = stateManager;
        if (stateManager != nullptr)
        {
            static_cast<void>(stateManager->AddRef());
        }
    }

    /**
     * Address: 0x00945730 (FUN_00945730)
     *
     * What it does:
     * Reapplies baseline D3D9 render/sampler/texture-stage state defaults.
     */
    int PipelineStateD3D9::InitState()
    {
        auto* const stateManager = GetStateManager();
        if (stateManager == nullptr)
        {
            return -1;
        }

        const auto setRenderState = [stateManager](const unsigned int state, const unsigned int value) {
            static_cast<void>(stateManager->SetRenderState(static_cast<StateManagerD3D9::render_state_type>(state), value));
        };
        const auto setRenderStateFlt = [stateManager](const unsigned int state, const float value) {
            static_cast<void>(stateManager->SetRenderStateFlt(static_cast<StateManagerD3D9::render_state_type>(state), value));
        };
        const auto setSamplerState = [stateManager](
                                         const unsigned int sampler,
                                         const unsigned int state,
                                         const unsigned int value
                                     ) {
            static_cast<void>(
                stateManager->SetSamplerState(sampler, static_cast<StateManagerD3D9::sampler_state_type>(state), value)
            );
        };
        const auto setTextureStageState = [stateManager](
                                               const unsigned int stage,
                                               const unsigned int state,
                                               const unsigned int value
                                           ) {
            return stateManager->SetTextureStageState(
                stage,
                static_cast<StateManagerD3D9::texture_stage_state_type>(state),
                value
            );
        };
        const auto setTextureStageStateFlt = [stateManager](
                                                  const unsigned int stage,
                                                  const unsigned int state,
                                                  const float value
                                              ) {
            static_cast<void>(
                stateManager->SetTextureStageStateFlt(
                    stage,
                    static_cast<StateManagerD3D9::texture_stage_state_type>(state),
                    value
                )
            );
        };

        static constexpr struct RenderStateInit final
        {
            unsigned int state = 0U;
            unsigned int value = 0U;
        } kRenderStates[] = {
            {7U, 1U},
            {8U, 3U},
            {9U, 2U},
            {14U, 1U},
            {15U, 0U},
            {16U, 1U},
            {19U, 2U},
            {20U, 1U},
            {22U, 1U},
            {23U, 8U},
            {24U, 0U},
            {25U, 8U},
            {26U, 0U},
            {27U, 0U},
            {28U, 0U},
            {29U, 0U},
            {34U, 0U},
            {35U, 0U},
            {48U, 0U},
            {52U, 0U},
            {53U, 1U},
            {54U, 1U},
            {55U, 1U},
            {56U, 8U},
            {57U, 0U},
            {58U, 0xFFFFFFFFU},
            {59U, 0xFFFFFFFFU},
            {60U, 0U},
            {128U, 0U},
            {129U, 0U},
            {130U, 0U},
            {131U, 0U},
            {132U, 0U},
            {133U, 0U},
            {134U, 0U},
            {135U, 0U},
            {136U, 1U},
            {137U, 1U},
            {139U, 0U},
            {140U, 0U},
            {141U, 1U},
            {142U, 0U},
            {143U, 1U},
            {145U, 1U},
            {146U, 2U},
            {147U, 0U},
            {148U, 0U},
            {151U, 0U},
            {152U, 0U},
            {156U, 0U},
            {157U, 0U},
            {161U, 1U},
            {162U, 0xFFFFFFFFU},
            {163U, 0U},
            {167U, 0U},
            {168U, 0x0FU},
            {171U, 1U},
            {172U, 3U},
            {173U, 1U},
            {174U, 0U},
            {176U, 0U},
            {184U, 0U},
            {185U, 0U},
            {186U, 1U},
            {187U, 1U},
            {188U, 1U},
            {189U, 8U},
            {190U, 0x0FU},
            {191U, 0x0FU},
            {192U, 0x0FU},
            {193U, 0xFFFFFFFFU},
            {194U, 0U},
            {198U, 0U},
            {199U, 0U},
            {200U, 0U},
            {201U, 0U},
            {202U, 0U},
            {203U, 0U},
            {204U, 0U},
            {205U, 0U},
            {206U, 0U},
            {207U, 2U},
            {208U, 1U},
            {209U, 1U},
        };

        static constexpr struct RenderStateFloatInit final
        {
            unsigned int state = 0U;
            float value = 0.0f;
        } kRenderStateFloats[] = {
            {36U, 0.0f},
            {37U, 1.0f},
            {38U, 1.0f},
            {154U, 1.0f},
            {155U, 1.0f},
            {158U, 1.0f},
            {159U, 0.0f},
            {160U, 0.0f},
            {166U, 64.0f},
            {170U, 0.0f},
            {175U, 0.0f},
            {178U, 1.0f},
            {179U, 1.0f},
            {180U, 1.0f},
            {181U, 1.0f},
            {182U, 1.0f},
            {183U, 1.0f},
            {195U, 0.0f},
        };

        for (const auto& state : kRenderStates)
        {
            setRenderState(state.state, state.value);
        }

        for (const auto& state : kRenderStateFloats)
        {
            setRenderStateFlt(state.state, state.value);
        }

        for (unsigned int sampler = 0U; sampler < 16U; ++sampler)
        {
            setSamplerState(sampler, 1U, 1U);
            setSamplerState(sampler, 2U, 1U);
            setSamplerState(sampler, 3U, 1U);
            setSamplerState(sampler, 4U, 0U);
            setSamplerState(sampler, 5U, 2U);
            setSamplerState(sampler, 6U, 2U);
            setSamplerState(sampler, 7U, 0U);
            setSamplerState(sampler, 8U, 0U);
            setSamplerState(sampler, 9U, 0U);
            setSamplerState(sampler, 10U, 1U);
            setSamplerState(sampler, 11U, 0U);
            setSamplerState(sampler, 12U, 0U);
            setSamplerState(sampler, 13U, 256U);
        }

        for (unsigned int stage = 0U; stage < 8U; ++stage)
        {
            static_cast<void>(setTextureStageState(stage, 1U, 1U));
            static_cast<void>(setTextureStageState(stage, 2U, 2U));
            static_cast<void>(setTextureStageState(stage, 3U, 1U));
            static_cast<void>(setTextureStageState(stage, 4U, 1U));
            static_cast<void>(setTextureStageState(stage, 5U, 2U));
            static_cast<void>(setTextureStageState(stage, 6U, 1U));
            setTextureStageStateFlt(stage, 7U, 0.0f);
            setTextureStageStateFlt(stage, 8U, 0.0f);
            setTextureStageStateFlt(stage, 9U, 0.0f);
            setTextureStageStateFlt(stage, 10U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 11U, stage));
            setTextureStageStateFlt(stage, 22U, 0.0f);
            setTextureStageStateFlt(stage, 23U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 24U, 0U));
            static_cast<void>(setTextureStageState(stage, 26U, 1U));
            static_cast<void>(setTextureStageState(stage, 27U, 1U));
            static_cast<void>(setTextureStageState(stage, 28U, 1U));
            static_cast<void>(setTextureStageState(stage, 32U, 0U));
        }

        static_cast<void>(setTextureStageState(0U, 1U, 4U));
        return setTextureStageState(0U, 4U, 2U);
    }

    /**
     * Address: 0x00946F10 (FUN_00946F10)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_00946BE0` body semantics.
     */
    PipelineStateD3D9::~PipelineStateD3D9()
    {
        DestroyPipelineStateD3D9Body(this);
    }

    /**
     * Address: 0x008F58C0 (FUN_008F58C0)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_008F57B0` body semantics.
     */
    VertexBufferD3D9::~VertexBufferD3D9()
    {
        DestroyVertexBufferD3D9Body(this);
    }

    /**
     * Address: 0x008F5700 (FUN_008F5700)
     *
     * What it does:
     * Returns the embedded vertex-buffer context block at `this+0x04`.
     */
    VertexBufferContext* VertexBufferD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F5950 (FUN_008F5950)
     *
     * What it does:
     * Locks the retained D3D9 vertex buffer and returns mapped vertex data.
     */
    void* VertexBufferD3D9::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VtxBufD3D9.cpp", 56, "lock invalid");
        }

        if (locked_)
        {
            ThrowGalError("VtxBufD3D9.cpp", 57, "lock mismatch");
        }

        const HRESULT result = InvokeLock(
            d3dVertexBuffer_,
            offset,
            size,
            &mappedData_,
            ToVertexBufferLockFlags(lockFlags)
        );

        if (result < 0)
        {
            ThrowGalErrorFromHresult("VtxBufD3D9.cpp", 65, result);
        }

        locked_ = true;
        return mappedData_;
    }

    /**
     * Address: 0x008F5B40 (FUN_008F5B40)
     *
     * What it does:
     * Unlocks the retained D3D9 vertex buffer and clears lock-tracking state.
     */
    HRESULT VertexBufferD3D9::Unlock()
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VtxBufD3D9.cpp", 73, "unlock invalid");
        }

        if (!locked_)
        {
            ThrowGalError("VtxBufD3D9.cpp", 74, "lock mismatch");
        }

        const HRESULT result = InvokeUnlock(d3dVertexBuffer_);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("VtxBufD3D9.cpp", 77, result);
        }

        locked_ = false;
        mappedData_ = nullptr;
        return result;
    }

    /**
     * Address: 0x008F5CE0 (FUN_008F5CE0, gpg::gal::VertexBufferD3D9::GetD3D)
     *
     * What it does:
     * Returns the retained D3D9 vertex-buffer handle and throws when unset.
     */
    void* VertexBufferD3D9::GetD3D()
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VertexBufferD3D9.cpp", 105, "invalid vertex buffer");
        }

        return d3dVertexBuffer_;
    }

    /**
     * Address: 0x0094AD40 (FUN_0094AD40)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_0094ACC0` body semantics.
     */
    VertexFormatD3D9::~VertexFormatD3D9()
    {
        DestroyVertexFormatD3D9Body(this);
    }

    /**
     * Address: 0x0094AD60 (FUN_0094AD60, gpg::gal::VertexFormatD3D9::GetDeclaration)
     *
     * What it does:
     * Returns the retained D3D9 vertex-declaration handle and throws when unset.
     */
    void* VertexFormatD3D9::GetDeclaration()
    {
        if (vertexDeclaration_ == nullptr)
        {
            ThrowGalError("VertexFormatD3D9.cpp", 120, "invalid vertex format");
        }

        return vertexDeclaration_;
    }
}

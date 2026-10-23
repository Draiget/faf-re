// FAF addition, not in the shipped binary: the Direct3D 12 gal device.

#include "DeviceD3D12.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <d3dcompiler.h>
#include <dxgi1_6.h>
#include <psapi.h>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/TextureContext.h"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/common/RuntimeInfo.h"
#include "gpg/gal/backends/d3d11/D3D11VertexLayouts.h"
#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using backend::CheckHresult;
  using backend::ThrowError;

  namespace
  {
    struct MacroPair
    {
      const char* name;
      const char* value;
    };

    // The Direct3D 10 effect dialect: DeviceD3D10::CreateEffect's twenty
    // macros (0x008FEA00), plus one naming this backend.
    constexpr MacroPair kInjectedMacros[] = {
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
      {"DIRECT3D12", "1"},
    };

    // D3D10's primitive topology per gal token (0x00D43078).
    constexpr D3D_PRIMITIVE_TOPOLOGY kTopologyByToken[15] = {
      D3D_PRIMITIVE_TOPOLOGY_UNDEFINED,
      D3D_PRIMITIVE_TOPOLOGY_POINTLIST,
      D3D_PRIMITIVE_TOPOLOGY_LINELIST,
      D3D_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
      D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP,
      D3D_PRIMITIVE_TOPOLOGY_LINELIST_ADJ,
      D3D_PRIMITIVE_TOPOLOGY_LINESTRIP_ADJ,
      D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST_ADJ,
      D3D_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP_ADJ,
      D3D_PRIMITIVE_TOPOLOGY_UNDEFINED,
      D3D_PRIMITIVE_TOPOLOGY_POINTLIST,
      D3D_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
    };

    constexpr D3D12_RESOURCE_STATES kShaderRead =
      D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE | D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE;
    constexpr std::uint32_t kViewsPerFrame = 262144U;
    constexpr std::uint32_t kSamplerHeapSize = 2048U;
    constexpr std::uint32_t kMissingInputSlot = 15U;

    constexpr char kBlitSource[] = R"hlsl(
struct BlitVertex { float4 position : SV_Position; float2 uv : TEXCOORD0; };
BlitVertex BlitVS(uint id : SV_VertexID)
{
    BlitVertex o;
    float2 p = float2((id << 1) & 2, id & 2);
    o.position = float4(p * float2(2, -2) + float2(-1, 1), 0, 1);
    o.uv = p;
    return o;
}
Texture2D faf_source : register(t0);
SamplerState faf_linear : register(s0);
float4 BlitPS(BlitVertex v) : SV_Target0 { return faf_source.Sample(faf_linear, v.uv); }
float4 SolidPS(float4 position : SV_Position) : SV_Target0 { return float4(1, 0, 1, 1); }
)hlsl";

    [[nodiscard]] bool CommandLineHas(const char* const option)
    {
      std::string commandLine = ::GetCommandLineA();
      std::string needle = option;
      const auto lower = [](std::string& text) {
        std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      };
      lower(commandLine);
      lower(needle);
      return commandLine.find(needle) != std::string::npos;
    }

    /** The command a DRED breadcrumb records, for the device-removed report. */
    [[nodiscard]] const char* BreadcrumbOpName(const D3D12_AUTO_BREADCRUMB_OP op) noexcept
    {
      switch (op) {
      case D3D12_AUTO_BREADCRUMB_OP_SETMARKER:
        return "SetMarker";
      case D3D12_AUTO_BREADCRUMB_OP_DRAWINSTANCED:
        return "DrawInstanced";
      case D3D12_AUTO_BREADCRUMB_OP_DRAWINDEXEDINSTANCED:
        return "DrawIndexedInstanced";
      case D3D12_AUTO_BREADCRUMB_OP_EXECUTEINDIRECT:
        return "ExecuteIndirect";
      case D3D12_AUTO_BREADCRUMB_OP_DISPATCH:
        return "Dispatch";
      case D3D12_AUTO_BREADCRUMB_OP_COPYBUFFERREGION:
        return "CopyBufferRegion";
      case D3D12_AUTO_BREADCRUMB_OP_COPYTEXTUREREGION:
        return "CopyTextureRegion";
      case D3D12_AUTO_BREADCRUMB_OP_COPYRESOURCE:
        return "CopyResource";
      case D3D12_AUTO_BREADCRUMB_OP_CLEARRENDERTARGETVIEW:
        return "ClearRenderTargetView";
      case D3D12_AUTO_BREADCRUMB_OP_CLEARDEPTHSTENCILVIEW:
        return "ClearDepthStencilView";
      case D3D12_AUTO_BREADCRUMB_OP_RESOURCEBARRIER:
        return "ResourceBarrier";
      case D3D12_AUTO_BREADCRUMB_OP_PRESENT:
        return "Present";
      case D3D12_AUTO_BREADCRUMB_OP_RESOLVEQUERYDATA:
        return "ResolveQueryData";
      case D3D12_AUTO_BREADCRUMB_OP_WRITEBUFFERIMMEDIATE:
        return "WriteBufferImmediate";
      default:
        return "other";
      }
    }

    [[nodiscard]] bool IsRgbaTexture(Texture& texture)
    {
      const DXGI_FORMAT format = static_cast<TextureD3D12&>(texture).Desc().Format;
      return format == DXGI_FORMAT_R8G8B8A8_UNORM || format == DXGI_FORMAT_R8G8B8A8_UNORM_SRGB;
    }

    /**
     * The instance count of stream 0's frequency token. The mesh batches pass
     * a plain count (the D3D10 convention); D3D9-style callers pass
     * D3DSTREAMSOURCE_INDEXEDDATA (0x40000000) | count, and a stream marked
     * D3DSTREAMSOURCE_INSTANCEDATA (0x80000000) is per-instance data, not a
     * count. The RangeRenderer's token taken raw drew 2^30 instances (a TDR).
     */
    [[nodiscard]] UINT InstanceCount(const std::int32_t token) noexcept
    {
      const auto bits = static_cast<std::uint32_t>(token);
      if ((bits & 0x80000000U) != 0U) {
        return 1U;
      }
      return std::max<UINT>(bits & 0x3FFFFFFFU, 1U);
    }

    [[nodiscard]] D3D12_PRIMITIVE_TOPOLOGY_TYPE TopologyType(const D3D_PRIMITIVE_TOPOLOGY topology) noexcept
    {
      switch (topology) {
      case D3D_PRIMITIVE_TOPOLOGY_POINTLIST:
        return D3D12_PRIMITIVE_TOPOLOGY_TYPE_POINT;
      case D3D_PRIMITIVE_TOPOLOGY_LINELIST:
      case D3D_PRIMITIVE_TOPOLOGY_LINESTRIP:
      case D3D_PRIMITIVE_TOPOLOGY_LINELIST_ADJ:
      case D3D_PRIMITIVE_TOPOLOGY_LINESTRIP_ADJ:
        return D3D12_PRIMITIVE_TOPOLOGY_TYPE_LINE;
      default:
        return D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
      }
    }

    /** Appends the bytes of plain values to a cache key. */
    class KeyWriter
    {
    public:
      template <class T>
      void Add(const T& value)
      {
        const auto* const bytes = reinterpret_cast<const char*>(&value);
        mKey.append(bytes, sizeof(T));
      }
      [[nodiscard]] std::string& Key() noexcept { return mKey; }

    private:
      std::string mKey;
    };

    void AddBlend(KeyWriter& key, const effects::BlendDesc& blend)
    {
      key.Add(blend.alphaToCoverage);
      key.Add(blend.enable);
      key.Add(blend.srcBlend);
      key.Add(blend.destBlend);
      key.Add(blend.blendOp);
      key.Add(blend.srcBlendAlpha);
      key.Add(blend.destBlendAlpha);
      key.Add(blend.blendOpAlpha);
      key.Add(blend.writeMask);
    }

    void AddDepth(KeyWriter& key, const effects::DepthStencilDesc& depth)
    {
      key.Add(depth.depthEnable);
      key.Add(depth.depthWrite);
      key.Add(depth.depthFunc);
      key.Add(depth.stencilEnable);
      key.Add(depth.stencilReadMask);
      key.Add(depth.stencilWriteMask);
      for (const effects::StencilFaceDesc* face : {&depth.front, &depth.back}) {
        key.Add(face->failOp);
        key.Add(face->depthFailOp);
        key.Add(face->passOp);
        key.Add(face->func);
      }
    }

    void AddRasterizer(KeyWriter& key, const effects::RasterizerDesc& rasterizer)
    {
      key.Add(rasterizer.fillMode);
      key.Add(rasterizer.cullMode);
      key.Add(rasterizer.frontCounterClockwise);
      key.Add(rasterizer.depthBias);
      key.Add(rasterizer.depthBiasClamp);
      key.Add(rasterizer.slopeScaledDepthBias);
      key.Add(rasterizer.depthClipEnable);
      key.Add(rasterizer.multisampleEnable);
      key.Add(rasterizer.antialiasedLineEnable);
    }

    /** The state every technique begins with (D3D10 `CreateState2`, 0x00902940). */
    void TechniquePack(effects::BlendDesc& blend, effects::DepthStencilDesc& depth, effects::RasterizerDesc& rasterizer)
    {
      blend = effects::BlendDesc{};
      depth = effects::DepthStencilDesc{};
      rasterizer = effects::RasterizerDesc{};
    }

    void WriteBmp(const char* const path, const imaging::Image& image)
    {
      if (image.subresources.empty() || dxgi::FormatElementBytes(image.format) != 4U || dxgi::IsBlockCompressed(image.format)) {
        return;
      }
      const imaging::Image::Subresource& top = image.subresources.front();
      BITMAPFILEHEADER fileHeader{};
      BITMAPINFOHEADER infoHeader{};
      infoHeader.biSize = sizeof(infoHeader);
      infoHeader.biWidth = static_cast<LONG>(top.width);
      infoHeader.biHeight = -static_cast<LONG>(top.height);
      infoHeader.biPlanes = 1;
      infoHeader.biBitCount = 32;
      infoHeader.biCompression = BI_RGB;
      const DWORD imageBytes = top.width * top.height * 4U;
      fileHeader.bfType = 0x4D42;
      fileHeader.bfOffBits = sizeof(fileHeader) + sizeof(infoHeader);
      fileHeader.bfSize = fileHeader.bfOffBits + imageBytes;
      if (FILE* const file = std::fopen(path, "wb")) {
        std::fwrite(&fileHeader, sizeof(fileHeader), 1U, file);
        std::fwrite(&infoHeader, sizeof(infoHeader), 1U, file);
        for (std::uint32_t row = 0U; row < top.height; ++row) {
          std::fwrite(image.bytes.data() + top.offset + static_cast<std::size_t>(row) * top.rowPitch, 4U, top.width, file);
        }
        std::fclose(file);
        gpg::Logf("D3D12: dump %s", path);
      }
    }
  } // namespace

  /** Holds off upload-pressure submissions while a draw is being prepared. */
  struct DeviceD3D12::DrawPreparation
  {
    explicit DrawPreparation(bool& flag) noexcept
      : mFlag(flag)
    {
      mFlag = true;
    }
    ~DrawPreparation() { mFlag = false; }
    DrawPreparation(const DrawPreparation&) = delete;
    DrawPreparation& operator=(const DrawPreparation&) = delete;

  private:
    bool& mFlag;
  };

  /** Per-effect data this backend keeps on the EffectProgram. */
  struct DeviceD3D12::ProgramState
  {
    D3D12_GPU_DESCRIPTOR_HANDLE samplers{};
    std::int32_t viewportParameter = -1;
    float lastViewport[4]{-1.0f, -1.0f, -1.0f, -1.0f};

    std::uint64_t constantsVersion = 0;
    std::uint64_t constantsSerial = 0;
    D3D12_GPU_VIRTUAL_ADDRESS constants = 0;
    const std::uint8_t* constantsCpu = nullptr;

    std::uint64_t tableFrame = ~0ULL;
    std::uint64_t tableEpoch = ~0ULL;
    std::uint64_t textureVersion = 0;
    const RenderTarget* tableSurface = nullptr; // the colour target bound when the table was built
    D3D12_GPU_DESCRIPTOR_HANDLE table{};
    std::shared_ptr<const std::vector<effects::TextureBinding>> tableBindings;
  };

  // ---------------------------------------------------------------------------
  // Construction and setup

  DeviceD3D12::DeviceD3D12()
    : mCursor(&IsRgbaTexture)
  {}

  DeviceD3D12::~DeviceD3D12()
  {
    Shutdown();
  }

  void DeviceD3D12::Shutdown() noexcept
  {
    if (mQueue != nullptr && mFence != nullptr) {
      try {
        mList->Close();
        // Let the GPU finish everything recorded and submitted.
        const std::uint64_t serial = ++mSubmittedSerial;
        mQueue->Signal(mFence.Get(), serial);
        WaitForSerial(serial);
      } catch (...) {
      }
    }
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    mPass = BoundPass{};
    for (StreamBinding& stream : mStreams) {
      stream = StreamBinding{};
    }
    mIndexBuffer.reset();
    mSwapChains.clear();
    mGarbage.clear();
    mPipelines.clear();
    mBlitPipelines.clear();
    mPipelineState.reset();
    mCursor.Destroy();
    mUpload.Release();
    mRtvPool.Release();
    mDsvPool.Release();
    mSrvPool.Release();
    mSamplerHeap.Release();
    mNullViewHeap.Reset();
    for (Frame& frame : mFrames) {
      frame.allocator.Reset();
      frame.views.Release();
    }
    ReleaseGpuDrivenObjects();
    mRootSignature.Reset();
    mDrawMarkers = nullptr;
    mDrawMarkerBuffer.Reset();
    mList2.Reset();
    mList.Reset();
    mQueue.Reset();
    mFence.Reset();
    if (mFenceEvent != nullptr) {
      ::CloseHandle(mFenceEvent);
      mFenceEvent = nullptr;
    }
    mInfoQueue.Reset();
    mDevice.Reset();
    mFactory.Release();
    mLibrary.Unload();
    mDeviceContext = DeviceContext(DeviceApi::Unset);
  }

  void DeviceD3D12::CreateDevice()
  {
    const dxgi::AdapterInfo& adapter = mFactory.Adapters()[mAdapterIndex];
    // /d3d12gbv: the debug layer with GPU-based validation (resource states
    // and descriptors checked as the GPU uses them; very slow).
    const bool gpuValidation = CommandLineHas("/d3d12gbv");
    const bool debugLayer = gpuValidation || CommandLineHas("/d3d12debug");
    if (debugLayer && mLibrary.getDebugInterface != nullptr) {
      ComPtr<ID3D12Debug> debug;
      if (SUCCEEDED(mLibrary.getDebugInterface(IID_PPV_ARGS(&debug)))) {
        debug->EnableDebugLayer();
        ComPtr<ID3D12Debug1> debug1;
        if (gpuValidation && SUCCEEDED(debug.As(&debug1))) {
          debug1->SetEnableGPUBasedValidation(TRUE);
          gpg::Logf("D3D12: GPU-based validation on");
        }
      } else {
        gpg::Warnf("D3D12: the debug layer is not installed");
      }
    }
    // Device Removed Extended Data: breadcrumbs of the GPU's progress through
    // each command list and the allocation a page fault hit, read back by
    // ReportDeviceRemoved. Costs a few percent, so on with the debug layer or
    // /d3d12dred only.
    if ((debugLayer || CommandLineHas("/d3d12dred")) && mLibrary.getDebugInterface != nullptr) {
      ComPtr<ID3D12DeviceRemovedExtendedDataSettings> dred;
      if (SUCCEEDED(mLibrary.getDebugInterface(IID_PPV_ARGS(&dred)))) {
        dred->SetAutoBreadcrumbsEnablement(D3D12_DRED_ENABLEMENT_FORCED_ON);
        dred->SetPageFaultEnablement(D3D12_DRED_ENABLEMENT_FORCED_ON);
        // Breadcrumb contexts (the marker strings), where the runtime has them.
        ComPtr<ID3D12DeviceRemovedExtendedDataSettings1> dred1;
        if (SUCCEEDED(dred.As(&dred1))) {
          dred1->SetBreadcrumbContextEnablement(D3D12_DRED_ENABLEMENT_FORCED_ON);
        }
        mDredEnabled = true;
        gpg::Logf("D3D12: device removed extended data on");
      }
    }
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__, mLibrary.createDevice(adapter.adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&mDevice))
    );
    if (debugLayer) {
      static_cast<void>(mDevice.As(&mInfoQueue));
    }

    D3D12_FEATURE_DATA_D3D12_OPTIONS options{};
    static_cast<void>(mDevice->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS, &options, sizeof(options)));
    gpg::Logf(
      "D3D12: device created on adapter %u '%s' (vendor 0x%04X device 0x%04X, %u MB VRAM), resource binding tier %d%s",
      mAdapterIndex, adapter.Name().c_str(), adapter.desc.VendorId, adapter.desc.DeviceId,
      static_cast<unsigned>(adapter.desc.DedicatedVideoMemory >> 20U), static_cast<int>(options.ResourceBindingTier),
      (mInfoQueue != nullptr) ? ", debug layer" : ""
    );
  }

  void DeviceD3D12::CreateQueueAndFrames()
  {
    D3D12_COMMAND_QUEUE_DESC queueDesc{};
    queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    CheckHresult("DeviceD3D12.cpp", __LINE__, mDevice->CreateCommandQueue(&queueDesc, IID_PPV_ARGS(&mQueue)));
    CheckHresult("DeviceD3D12.cpp", __LINE__, mDevice->CreateFence(0U, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&mFence)));
    mFenceEvent = ::CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (mFenceEvent == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "unable to create the fence event");
    }
    for (Frame& frame : mFrames) {
      CheckHresult(
        "DeviceD3D12.cpp", __LINE__, mDevice->CreateCommandAllocator(D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&frame.allocator))
      );
      frame.views.Initialize(mDevice.Get(), D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, kViewsPerFrame);
    }
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommandList(0U, D3D12_COMMAND_LIST_TYPE_DIRECT, mFrames[0].allocator.Get(), nullptr, IID_PPV_ARGS(&mList))
    );
    // Created recording; BeginRecording resets it.
    CheckHresult("DeviceD3D12.cpp", __LINE__, mList->Close());
    CreateDrawMarkers();

    mUpload.Initialize(mDevice.Get());
    mRtvPool.Initialize(mDevice.Get(), D3D12_DESCRIPTOR_HEAP_TYPE_RTV, 256U);
    mDsvPool.Initialize(mDevice.Get(), D3D12_DESCRIPTOR_HEAP_TYPE_DSV, 256U);
    mSrvPool.Initialize(mDevice.Get(), D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, 4096U);
    mSamplerHeap.Initialize(mDevice.Get(), D3D12_DESCRIPTOR_HEAP_TYPE_SAMPLER, kSamplerHeapSize);

    // Null views: one per dimension, then a run of 2D ones to pad tables.
    D3D12_DESCRIPTOR_HEAP_DESC nullDesc{};
    nullDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    nullDesc.NumDescriptors = 3U + effects::kMaxTextureSlots;
    CheckHresult("DeviceD3D12.cpp", __LINE__, mDevice->CreateDescriptorHeap(&nullDesc, IID_PPV_ARGS(&mNullViewHeap)));
    const UINT increment = mDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    const D3D12_CPU_DESCRIPTOR_HANDLE start = mNullViewHeap->GetCPUDescriptorHandleForHeapStart();
    for (UINT index = 0U; index < nullDesc.NumDescriptors; ++index) {
      D3D12_SHADER_RESOURCE_VIEW_DESC view{};
      view.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
      view.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
      if (index == 1U) {
        view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURECUBE;
        view.TextureCube.MipLevels = 1U;
      } else if (index == 2U) {
        view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE3D;
        view.Texture3D.MipLevels = 1U;
      } else {
        view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
        view.Texture2D.MipLevels = 1U;
      }
      D3D12_CPU_DESCRIPTOR_HANDLE handle = start;
      handle.ptr += static_cast<SIZE_T>(index) * increment;
      mDevice->CreateShaderResourceView(nullptr, &view, handle);
      if (index < 3U) {
        mNullViews[index] = handle;
      } else if (index == 3U) {
        mNullViewRun = handle;
      }
    }
  }

  void DeviceD3D12::CreateRootSignature()
  {
    D3D12_DESCRIPTOR_RANGE textures{};
    textures.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    textures.NumDescriptors = effects::kMaxTextureSlots;
    textures.OffsetInDescriptorsFromTableStart = 0U;
    D3D12_DESCRIPTOR_RANGE samplers{};
    samplers.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SAMPLER;
    samplers.NumDescriptors = effects::kMaxSamplerSlots;
    samplers.OffsetInDescriptorsFromTableStart = 0U;

    D3D12_ROOT_PARAMETER parameters[3]{};
    parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    parameters[0].Descriptor.ShaderRegister = 0U;
    parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[1].DescriptorTable.NumDescriptorRanges = 1U;
    parameters[1].DescriptorTable.pDescriptorRanges = &textures;
    parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[2].DescriptorTable.NumDescriptorRanges = 1U;
    parameters[2].DescriptorTable.pDescriptorRanges = &samplers;
    parameters[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    D3D12_ROOT_SIGNATURE_DESC desc{};
    desc.NumParameters = 3U;
    desc.pParameters = parameters;
    desc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT;

    ComPtr<ID3DBlob> serialized;
    ComPtr<ID3DBlob> errors;
    const HRESULT result = mLibrary.serializeRootSignature(&desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors);
    if (FAILED(result)) {
      const std::string message = "unable to build the root signature: " +
        ((errors != nullptr) ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize()) : std::string());
      ThrowError("DeviceD3D12.cpp", __LINE__, message.c_str());
    }
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateRootSignature(0U, serialized->GetBufferPointer(), serialized->GetBufferSize(), IID_PPV_ARGS(&mRootSignature))
    );
  }

  void DeviceD3D12::CreateSwapChains(const DeviceContext& context)
  {
    mSwapChains.clear();
    for (int headIndex = 0; headIndex < context.GetHeadCount(); ++headIndex) {
      const Head& head = context.GetHead(static_cast<std::uint32_t>(headIndex));
      dxgi::SwapChainDesc desc{};
      desc.window = static_cast<HWND>(head.mWindow);
      desc.width = head.mWidth;
      desc.height = head.mHeight;
      desc.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      // `Head::mWindowed` is a full-screen flag (see DeviceD3D11::CreateSwapChains).
      desc.fullscreen = head.mWindowed;
      desc.refreshHz = head.framesPerSecond;
      desc.usage = DXGI_USAGE_RENDER_TARGET_OUTPUT | DXGI_USAGE_SHADER_INPUT;
      desc.bufferCount = d3d12::kFramesInFlight;
      desc.allowFlipModel = true; // Direct3D 12 has only the flip model
      if (desc.width == 0U || desc.height == 0U) {
        RECT client{};
        ::GetClientRect(desc.window, &client);
        desc.width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        desc.height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }
      auto swapChain = std::make_unique<dxgi::SwapChain>();
      CheckHresult("DeviceD3D12.cpp", __LINE__, swapChain->Create(mFactory, mQueue.Get(), desc));
      if (!swapChain->IsFlipModel()) {
        ThrowError("DeviceD3D12.cpp", __LINE__, "no flip-model swap chain for Direct3D 12");
      }
      gpg::Logf(
        "D3D12: head %d swap chain %ux%u %s, %s, %u buffers%s", headIndex, desc.width, desc.height,
        desc.fullscreen ? "full screen" : "windowed", dxgi::SwapModelName(swapChain->Model()), swapChain->BufferCount(),
        swapChain->AllowsTearing() ? ", tearing allowed" : ""
      );
      mSwapChains.push_back(std::move(swapChain));
    }
  }

  void DeviceD3D12::CreateRenderTargets()
  {
    mHeadOutputContexts.clear();
    mHeadOutputContexts.resize(mSwapChains.size());
    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      const dxgi::SwapChain& swapChain = *mSwapChains[headIndex];
      std::vector<RenderTargetD3D12::Buffer> buffers;
      for (std::uint32_t index = 0U; index < swapChain.BufferCount(); ++index) {
        RenderTargetD3D12::Buffer buffer;
        CheckHresult("DeviceD3D12.cpp", __LINE__, swapChain.GetBuffer(index, buffer.resource.resource.GetAddressOf()));
        static_cast<void>(buffer.resource.resource->SetName((L"back buffer " + std::to_wstring(index)).c_str()));
        buffer.resource.state = D3D12_RESOURCE_STATE_PRESENT;
        buffer.renderTargetView = mRtvPool.Allocate();
        mDevice->CreateRenderTargetView(buffer.resource.resource.Get(), nullptr, buffer.renderTargetView);
        buffer.shaderResourceView = mSrvPool.Allocate();
        mDevice->CreateShaderResourceView(buffer.resource.resource.Get(), nullptr, buffer.shaderResourceView);
        buffers.push_back(std::move(buffer));
      }
      OutputContext& output = mHeadOutputContexts[headIndex];
      auto* const target = new RenderTargetD3D12(std::move(buffers), &swapChain);
      output.surface.reset(target);
      const RenderTargetContext* const targetContext = target->GetContext();
      const DepthStencilTargetContext depthContext(targetContext->width_, targetContext->height_, 3U, false);
      output.depthStencil = CreateDepthStencilTarget(&depthContext);
      gpg::Logf("D3D12: head %u back buffer target %p (%ux%u)", static_cast<unsigned>(headIndex), target, targetContext->width_,
                targetContext->height_);
    }
    if (!mHeadOutputContexts.empty()) {
      ClearTarget(&mHeadOutputContexts.front());
      D3DVIEWPORT9 viewport{};
      const RenderTargetContext* const context = mHeadOutputContexts.front().surface->GetContext();
      viewport.Width = context->width_;
      viewport.Height = context->height_;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceD3D12::ReleaseRenderTargets() noexcept
  {
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    mTargetsDirty = true;
    try {
      // Twice: the targets just released retire with the recording serial.
      Submit(true);
      Submit(true);
    } catch (...) {
    }
  }

  void DeviceD3D12::CheckAvailableFormats(DeviceContext* const context)
  {
    const DeviceApi api = context->mDeviceType;
    mDeviceContext = *context;
    mDeviceContext.mDeviceType = api;
    // The D3D10 backend's capabilities (`CheckAvailableFormats`, 0x008FF5B0).
    mDeviceContext.mMaxPrimitiveCount = 0x10000U;
    mDeviceContext.mMaxVertexCount = 0xFFFFU;
    mDeviceContext.mHWBasedInstancing = true;
    mDeviceContext.mVertexShaderProfile = 4;
    mDeviceContext.mPixelShaderProfile = 8;

    const auto supports = [&](const DXGI_FORMAT format, const D3D12_FORMAT_SUPPORT1 wanted) {
      D3D12_FEATURE_DATA_FORMAT_SUPPORT support{};
      support.Format = format;
      return format != DXGI_FORMAT_UNKNOWN &&
        SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_FORMAT_SUPPORT, &support, sizeof(support))) &&
        (support.Support1 & wanted) == wanted;
    };

    const dxgi::AdapterInfo& adapter = mFactory.Adapters()[mAdapterIndex];
    for (int headIndex = 0; headIndex < mDeviceContext.GetHeadCount(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
      head.adapterModes.clear();
      for (const dxgi::OutputInfo& output : adapter.outputs) {
        for (const DXGI_MODE_DESC& mode : output.modes) {
          head.adapterModes.push_back(HeadAdapterMode{mode.Width, mode.Height, dxgi::AdapterInfo::RefreshHz(mode)});
        }
      }
      head.validFormats1.clear();
      for (std::int32_t format = 1; format < 8; ++format) {
        if (supports(dxgi::RenderTargetFormatToDxgi(static_cast<std::uint32_t>(format)), D3D12_FORMAT_SUPPORT1_RENDER_TARGET)) {
          head.validFormats1.push_back(format);
        }
      }
      head.validFormats2.clear();
      for (std::int32_t format = 1; format < 20; ++format) {
        if (supports(dxgi::TextureFormatToDxgi(static_cast<std::uint32_t>(format)), D3D12_FORMAT_SUPPORT1_TEXTURE2D)) {
          head.validFormats2.push_back(format);
        }
      }
      // No MSAA back buffer on this backend (flip model), so no antialiasing options.
      head.mStrs.clear();
    }
  }

  void DeviceD3D12::CreateBuiltInPipelines()
  {
    effects::ShaderCompiler& compiler = effects::ShaderCompiler::Instance();
    effects::ShaderEntry vertex{effects::ShaderStage::Vertex, "BlitVS", "", "BlitVS"};
    effects::ShaderEntry pixel{effects::ShaderStage::Pixel, "BlitPS", "", "BlitPS"};
    effects::CompiledShader vs = compiler.Compile(kBlitSource, vertex, effects::ShaderTarget::Dxil);
    effects::CompiledShader ps = compiler.Compile(kBlitSource, pixel, effects::ShaderTarget::Dxil);
    if (!vs.succeeded || !ps.succeeded) {
      const std::string message = "unable to compile the blit shaders: " + vs.messages + ps.messages;
      ThrowError("DeviceD3D12.cpp", __LINE__, message.c_str());
    }
    mBlitVertexShader = std::move(vs.code);
    mBlitPixelShader = std::move(ps.code);
    // Diagnostics: FAF_GAL_SOLID_PS=1 draws every pass in magenta (geometry check).
    if (const char* const solid = std::getenv("FAF_GAL_SOLID_PS"); solid != nullptr && solid[0] == '1') {
      effects::ShaderEntry solidEntry{effects::ShaderStage::Pixel, "SolidPS", "", "SolidPS"};
      effects::CompiledShader solidShader = compiler.Compile(kBlitSource, solidEntry, effects::ShaderTarget::Dxil);
      if (solidShader.succeeded) {
        mSolidPixelShader = std::move(solidShader.code);
      }
    }

    effects::SamplerDesc linearClamp;
    linearClamp.filter = 0x15U; // MIN_MAG_MIP_LINEAR
    linearClamp.addressU = linearClamp.addressV = linearClamp.addressW = 3U; // CLAMP
    mBlitSamplers = SamplerTable({linearClamp});
  }

  void DeviceD3D12::Setup(DeviceContext* const context)
  {
    mCurThreadId = static_cast<int>(::GetCurrentThreadId());
    mLog.clear();

    if (backend::SetupFailureRequested("d3d12")) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "device creation failed on request (FAF_GAL_FAIL_SETUP)");
    }
    if (!mLibrary.Load()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Direct3D 12 is not available (d3d12.dll)");
    }
    effects::ShaderCompiler& compiler = effects::ShaderCompiler::Instance();
    if (!compiler.Available()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, compiler.LoadError().c_str());
    }
    if (imaging::ImageCodec::Instance() == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "no texture decoder (d3dx11_43.dll and a WARP device are needed)");
    }

    CheckHresult("DeviceD3D12.cpp", __LINE__, mFactory.Create());
    mFactory.EnumerateAdapters(DXGI_FORMAT_B8G8R8A8_UNORM);
    if (mFactory.Adapters().empty()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "unable to enumerate adapters");
    }
    const auto adapterCount = static_cast<std::int32_t>(mFactory.Adapters().size());
    mAdapterIndex = (context->mAdapter >= 0 && context->mAdapter < adapterCount) ? static_cast<std::uint32_t>(context->mAdapter) : 0U;

    CreateDevice();
    CreateQueueAndFrames();
    CreateRootSignature();
    BeginRecording();
    CreateSwapChains(*context);
    CreateBuiltInPipelines();
    CreateGpuDrivenObjects();

    std::fill(std::begin(mStreamFrequencies), std::end(mStreamFrequencies), 0);
    mPipelineState.reset(new PipelineStateD3D12());
    ResetState();

    CheckAvailableFormats(context);
    CreateRenderTargets();

    gpg::Logf(
      "D3D12: ready (%d head(s), effects through the FAF effect layer, %s, shader cache %s, vsync %s)",
      mDeviceContext.GetHeadCount(), compiler.Version().c_str(),
      effects::ShaderCacheDirectory().empty() ? "off" : effects::ShaderCacheDirectory().c_str(), mDeviceContext.mVSync ? "on" : "off"
    );
    // ren_Info's facts, logged once here until the console command lands.
    DeviceRuntimeInfo info;
    if (GetRuntimeInfo(info)) {
      common::LogRuntimeInfo("D3D12", info);
    }
  }

  bool DeviceD3D12::GetRuntimeInfo(DeviceRuntimeInfo& out)
  {
    if (mDevice == nullptr || mAdapterIndex >= mFactory.Adapters().size()) {
      return false;
    }
    const dxgi::AdapterInfo& adapter = mFactory.Adapters()[mAdapterIndex];
    out.api = "D3D12";
    out.adapter = adapter.Name().c_str();
    out.vendorId = adapter.desc.VendorId;
    out.deviceId = adapter.desc.DeviceId;
    out.dedicatedVideoMemory = adapter.desc.DedicatedVideoMemory;
    out.sharedSystemMemory = adapter.desc.SharedSystemMemory;

    // The user-mode driver version; DXGI reports it for the IDXGIDevice interface.
    LARGE_INTEGER driverVersion{};
    if (SUCCEEDED(adapter.adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice), &driverVersion))) {
      out.driverVersion = common::FormatWindowsDriverVersion(static_cast<std::uint64_t>(driverVersion.QuadPart)).c_str();
    }

    static constexpr D3D_FEATURE_LEVEL kLevels[] = {
      D3D_FEATURE_LEVEL_12_1, D3D_FEATURE_LEVEL_12_0, D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0,
    };
    D3D12_FEATURE_DATA_FEATURE_LEVELS levels{};
    levels.NumFeatureLevels = static_cast<UINT>(std::size(kLevels));
    levels.pFeatureLevelsRequested = kLevels;
    char featureLevel[48] = "11_0";
    if (SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_FEATURE_LEVELS, &levels, sizeof(levels)))) {
      const unsigned level = static_cast<unsigned>(levels.MaxSupportedFeatureLevel);
      std::snprintf(featureLevel, sizeof(featureLevel), "%u_%u", (level >> 12U) & 0xFU, (level >> 8U) & 0xFU);
    }
    // The query answers the highest model up to the one asked for, and fails
    // for a model newer than the runtime knows: ask from 6.7 down.
    D3D12_FEATURE_DATA_SHADER_MODEL shaderModel{};
    bool shaderModelKnown = false;
    for (int model = 0x67; model >= 0x60 && !shaderModelKnown; --model) {
      shaderModel.HighestShaderModel = static_cast<D3D_SHADER_MODEL>(model);
      shaderModelKnown = SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_SHADER_MODEL, &shaderModel, sizeof(shaderModel)));
    }
    if (shaderModelKnown) {
      const unsigned model = static_cast<unsigned>(shaderModel.HighestShaderModel);
      char withModel[64]{};
      std::snprintf(withModel, sizeof(withModel), "%s, SM %u.%u", featureLevel, (model >> 4U) & 0xFU, model & 0xFU);
      out.featureLevel = withModel;
    } else {
      out.featureLevel = featureLevel;
    }

    ComPtr<IDXGIAdapter3> adapter3;
    if (SUCCEEDED(adapter.adapter.As(&adapter3))) {
      DXGI_QUERY_VIDEO_MEMORY_INFO memory{};
      if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0U, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &memory))) {
        out.localBudget = memory.Budget;
        out.localUsage = memory.CurrentUsage;
      }
      if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0U, DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, &memory))) {
        out.nonLocalBudget = memory.Budget;
        out.nonLocalUsage = memory.CurrentUsage;
      }
    }

    if (!mSwapChains.empty()) {
      const dxgi::SwapChain& swapChain = *mSwapChains.front();
      DXGI_SWAP_CHAIN_DESC desc{};
      static_cast<void>(swapChain.Get()->GetDesc(&desc));
      char text[160]{};
      std::snprintf(
        text, sizeof(text), "%ux%u %s %u buffers%s%s", desc.BufferDesc.Width, desc.BufferDesc.Height,
        dxgi::SwapModelName(swapChain.Model()), swapChain.BufferCount(), swapChain.AllowsTearing() ? ", tearing" : "",
        (mSwapChains.size() > 1U) ? ", more heads" : ""
      );
      out.swapChain = text;
    }
    out.vsync = mDeviceContext.mVSync;
    out.gpuDrivenFeatures = GetGpuDrivenFeatures();
    return true;
  }

  void DeviceD3D12::ResetState()
  {
    // The start-up pack (D3D10 `CreateState1`, 0x009024F0): no culling,
    // counter-clockwise front faces, depth test ALWAYS.
    mCurrent = BlendState{};
    mCurrent.rasterizer.cullMode = 1U;
    mCurrent.rasterizer.frontCounterClockwise = true;
    mCurrent.depthStencil.depthFunc = 8U;
  }

  // ---------------------------------------------------------------------------
  // Submission

  void DeviceD3D12::BeginRecording()
  {
    Frame& frame = mFrames[mFrameIndex];
    CheckHresult("DeviceD3D12.cpp", __LINE__, mList->Reset(frame.allocator.Get(), nullptr));
    BindFrameState();
  }

  void DeviceD3D12::BindFrameState()
  {
    ID3D12DescriptorHeap* const heaps[2] = {mFrames[mFrameIndex].views.Heap(), mSamplerHeap.Heap()};
    mList->SetDescriptorHeaps(2U, heaps);
    mList->SetGraphicsRootSignature(mRootSignature.Get());
    mTargetsDirty = true;
    mFrameStateDirty = true;
  }

  void DeviceD3D12::CheckDeviceHresult(const int line, const HRESULT result, const char* const during)
  {
    if (SUCCEEDED(result)) {
      return;
    }
    // After a removal calls fail with DEVICE_REMOVED, or with plain E_FAIL
    // (a Close of a list the failed Present never reset): ask the device.
    const HRESULT reason = (mDevice != nullptr) ? mDevice->GetDeviceRemovedReason() : S_OK;
    if (result == DXGI_ERROR_DEVICE_REMOVED || result == DXGI_ERROR_DEVICE_RESET || result == DXGI_ERROR_DEVICE_HUNG || FAILED(reason)) {
      ReportDeviceRemoved(during);
      // A removed device and everything made on it are gone; nothing more
      // can be drawn. Stop here with the cause, through the engine's crash
      // report, rather than failing every later call until something
      // unrelated gives up.
      gpg::Die(
        "The Direct3D 12 device was removed during %s: %s (0x%08lX). The graphics driver reset the GPU, "
        "so the game cannot continue. The log has the reason%s.",
        during, ::gpg::D3DErrorToString(static_cast<long>(FAILED(reason) ? reason : result)),
        static_cast<unsigned long>(FAILED(reason) ? reason : result),
        mDredEnabled ? " and the GPU's last breadcrumbs" : "; /d3d12dred also records where the GPU stopped"
      );
    }
    CheckHresult("DeviceD3D12.cpp", line, result);
  }

  void DeviceD3D12::ReportDeviceRemoved(const char* const during)
  {
    if (mRemovalReported || mDevice == nullptr) {
      return;
    }
    mRemovalReported = true;
    const HRESULT reason = mDevice->GetDeviceRemovedReason();
    gpg::Warnf(
      "D3D12: device removed during %s, frame %u: reason 0x%08lX (%s)", during, mFrameNumber,
      static_cast<unsigned long>(reason), ::gpg::D3DErrorToString(static_cast<long>(reason))
    );
    LogDebugMessages();

    ComPtr<ID3D12DeviceRemovedExtendedData> dred;
    if (FAILED(mDevice.As(&dred))) {
      gpg::Warnf("D3D12: no breadcrumbs - run with /d3d12dred (or /d3d12debug) to record them");
      return;
    }
    // The lists the GPU had started and not finished, by operation (and the
    // marker string, where the runtime records breadcrumb contexts); the
    // lists queued behind them (nothing done yet) are only counted. A list
    // stops at the first barrier after a faulting draw, so the culprit is
    // usually before the STOPPED line: the draw markers below name it.
    std::uint32_t queued = 0U;
    const auto reportList = [&](const UINT32* const last, const UINT32 count, const D3D12_AUTO_BREADCRUMB_OP* const history,
                                const D3D12_DRED_BREADCRUMB_CONTEXT* const contexts, const UINT contextCount) {
      const UINT32 completed = (last != nullptr) ? *last : 0U;
      if (completed >= count) {
        return; // the GPU finished this list
      }
      if (completed == 0U) {
        ++queued;
        return;
      }
      gpg::Warnf("D3D12 breadcrumbs: a command list stopped after %u of %u operations", completed, count);
      const UINT32 first = (completed > 12U) ? completed - 12U : 0U;
      const UINT32 end = std::min(count, completed + 4U);
      for (UINT32 index = first; index < end; ++index) {
        const wchar_t* context = nullptr;
        for (UINT entry = 0U; entry < contextCount; ++entry) {
          if (contexts[entry].BreadcrumbIndex <= index && contexts[entry].pContextString != nullptr) {
            context = contexts[entry].pContextString;
          }
        }
        gpg::Warnf(
          "  %s #%u: %s%s%ls", (index < completed) ? "done   " : ((index == completed) ? "STOPPED" : "pending"), index,
          BreadcrumbOpName(history[index]), (context != nullptr) ? "  in " : "", (context != nullptr) ? context : L""
        );
      }
    };
    ComPtr<ID3D12DeviceRemovedExtendedData1> dred1;
    D3D12_DRED_AUTO_BREADCRUMBS_OUTPUT1 crumbs1{};
    D3D12_DRED_AUTO_BREADCRUMBS_OUTPUT crumbs{};
    if (SUCCEEDED(mDevice.As(&dred1)) && SUCCEEDED(dred1->GetAutoBreadcrumbsOutput1(&crumbs1))) {
      for (const D3D12_AUTO_BREADCRUMB_NODE1* node = crumbs1.pHeadAutoBreadcrumbNode; node != nullptr; node = node->pNext) {
        reportList(node->pLastBreadcrumbValue, node->BreadcrumbCount, node->pCommandHistory, node->pBreadcrumbContexts, node->BreadcrumbContextsCount);
      }
    } else if (SUCCEEDED(dred->GetAutoBreadcrumbsOutput(&crumbs))) {
      for (const D3D12_AUTO_BREADCRUMB_NODE* node = crumbs.pHeadAutoBreadcrumbNode; node != nullptr; node = node->pNext) {
        reportList(node->pLastBreadcrumbValue, node->BreadcrumbCount, node->pCommandHistory, nullptr, 0U);
      }
    }
    gpg::Warnf("D3D12 breadcrumbs: %u more command list(s) queued, not started", queued);
    // The draw markers: every command after the last one finished was still
    // running, or waiting, when the GPU stopped; the first of them is the one
    // that faulted or hung.
    if (mDrawMarkers != nullptr) {
      const std::uint32_t reached = mDrawMarkers[0];
      const std::uint32_t finished = mDrawMarkers[1];
      gpg::Warnf("D3D12 draw markers: %u recorded, the GPU reached %u and finished %u", mDrawMarkerId, reached, finished);
      for (std::uint32_t id = finished + 1U; id <= reached && id <= finished + 12U; ++id) {
        gpg::Warnf("  unfinished #%u: %s", id, mDrawMarkerNames[id % std::size(mDrawMarkerNames)].c_str());
      }
      for (std::uint32_t id = (finished > 4U) ? finished - 4U : 1U; id <= finished; ++id) {
        gpg::Warnf("  finished   #%u: %s", id, mDrawMarkerNames[id % std::size(mDrawMarkerNames)].c_str());
      }
    }
    D3D12_DRED_PAGE_FAULT_OUTPUT fault{};
    if (SUCCEEDED(dred->GetPageFaultAllocationOutput(&fault)) && fault.PageFaultVA != 0U) {
      gpg::Warnf("D3D12 page fault at GPU address 0x%016llX", static_cast<unsigned long long>(fault.PageFaultVA));
      for (const D3D12_DRED_ALLOCATION_NODE* node = fault.pHeadExistingAllocationNode; node != nullptr; node = node->pNext) {
        gpg::Warnf("  live allocation there: %s (type %d)", (node->ObjectNameA != nullptr) ? node->ObjectNameA : "unnamed", static_cast<int>(node->AllocationType));
      }
      for (const D3D12_DRED_ALLOCATION_NODE* node = fault.pHeadRecentFreedAllocationNode; node != nullptr; node = node->pNext) {
        gpg::Warnf("  recently freed there: %s (type %d)", (node->ObjectNameA != nullptr) ? node->ObjectNameA : "unnamed", static_cast<int>(node->AllocationType));
      }
    }
  }

  void DeviceD3D12::MarkDraw(const char* const name)
  {
    if (!mDredEnabled) {
      return;
    }
    wchar_t text[96]{};
    std::size_t length = 0U;
    for (const char* c = (name != nullptr) ? name : ""; *c != 0 && length + 1U < std::size(text); ++c) {
      text[length++] = static_cast<wchar_t>(static_cast<unsigned char>(*c));
    }
    // Metadata 0: a UTF-16 string, as PIX writes one.
    mList->SetMarker(0U, text, static_cast<UINT>((length + 1U) * sizeof(wchar_t)));
    if (mList2 != nullptr && mDrawMarkers != nullptr) {
      const std::uint32_t id = ++mDrawMarkerId;
      mDrawMarkerNames[id % std::size(mDrawMarkerNames)] = (name != nullptr) ? name : "";
      const D3D12_WRITEBUFFERIMMEDIATE_PARAMETER reached{mDrawMarkerBuffer->GetGPUVirtualAddress(), id};
      const D3D12_WRITEBUFFERIMMEDIATE_MODE mode = D3D12_WRITEBUFFERIMMEDIATE_MODE_MARKER_IN;
      mList2->WriteBufferImmediate(1U, &reached, &mode);
    }
  }

  void DeviceD3D12::FinishDraw()
  {
    if (mList2 == nullptr || mDrawMarkers == nullptr) {
      return;
    }
    const D3D12_WRITEBUFFERIMMEDIATE_PARAMETER finished{
      mDrawMarkerBuffer->GetGPUVirtualAddress() + sizeof(std::uint32_t), mDrawMarkerId
    };
    const D3D12_WRITEBUFFERIMMEDIATE_MODE mode = D3D12_WRITEBUFFERIMMEDIATE_MODE_MARKER_OUT;
    mList2->WriteBufferImmediate(1U, &finished, &mode);
  }

  void DeviceD3D12::CreateDrawMarkers()
  {
    if (!mDredEnabled || FAILED(mList.As(&mList2))) {
      return;
    }
    // Write-back system memory: still readable after the device is removed.
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_CUSTOM;
    heap.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_WRITE_BACK;
    heap.MemoryPoolPreference = D3D12_MEMORY_POOL_L0;
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = 256U;
    desc.Height = 1U;
    desc.DepthOrArraySize = 1U;
    desc.MipLevels = 1U;
    desc.SampleDesc.Count = 1U;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    void* mapped = nullptr;
    if (FAILED(mDevice->CreateCommittedResource(
          &heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&mDrawMarkerBuffer)
        )) ||
        FAILED(mDrawMarkerBuffer->Map(0U, nullptr, &mapped))) {
      mDrawMarkerBuffer.Reset();
      return;
    }
    static_cast<void>(mDrawMarkerBuffer->SetName(L"draw markers"));
    mDrawMarkers = static_cast<volatile std::uint32_t*>(mapped);
    mDrawMarkers[0] = 0U;
    mDrawMarkers[1] = 0U;
  }

  void DeviceD3D12::Submit(const bool wait)
  {
    FlushBarriers();
    CheckDeviceHresult(__LINE__, mList->Close(), "command list close");
    ID3D12CommandList* const lists[1] = {mList.Get()};
    mQueue->ExecuteCommandLists(1U, lists);
    const std::uint64_t serial = ++mSubmittedSerial;
    CheckDeviceHresult(__LINE__, mQueue->Signal(mFence.Get(), serial), "queue signal");
    mFrames[mFrameIndex].serial = serial;
    if (wait) {
      WaitForSerial(serial);
    }
    // A submission in the middle of a pass (an upload between BeginPass and
    // the draw) leaves the pass's draws for the next list.
    if (CarryBoundPass()) {
      ++mCarriedPasses;
    }
    CollectCompleted();
    // Recording goes on into the same allocator: it is reset only when this
    // frame slot comes round again and its last submission has completed.
    CheckHresult("DeviceD3D12.cpp", __LINE__, mList->Reset(mFrames[mFrameIndex].allocator.Get(), nullptr));
    BindFrameState();
  }

  bool DeviceD3D12::CarryBoundPass()
  {
    // The pass's $Globals snapshot was uploaded into memory tagged with the
    // submission it was taken in. Once that submission completes the page is
    // handed out again (or released, past the idle reserve) while the pass's
    // remaining draws, now in the next list, still read it. D3D9 keeps the
    // snapshot BeginPass took for every draw of the pass; so does this copy.
    if (!mPass.valid || mPass.constantsCpu == nullptr || mPass.constantsSerial == RecordingSerial()) {
      return false;
    }
    const std::uint64_t bytes = (static_cast<std::uint64_t>(mPass.constantsBytes) + 255U) & ~static_cast<std::uint64_t>(255U);
    const d3d12::UploadAllocation upload = mUpload.Allocate(bytes, D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT, RecordingSerial());
    std::memcpy(upload.cpu, mPass.constantsCpu, mPass.constantsBytes);
    // Only the bound pass moves: its effect may be gone by now (the next draw
    // binds a new pass), and the program's cached snapshot is uploaded again
    // by its next BindPass in this submission.
    mPass.constants = upload.gpu;
    mPass.constantsCpu = upload.cpu;
    mPass.constantsSerial = RecordingSerial();
    return true;
  }

  void DeviceD3D12::RefreshStalePass()
  {
    // A texture table lives in its frame's view arena, which the next frame
    // does not bind and a full arena starts over: a draw with a pass bound
    // before either would read descriptors that are no longer there.
    if (!mPass.valid || (mPass.tableFrame == mFrameCount && mPass.tableEpoch == mArenaEpoch)) {
      return;
    }
    static int logged = 0;
    if (logged++ < 4) {
      gpg::Logf("D3D12: %s draws with a pass bound before its view arena started over; binding it again", mPass.technique);
    }
    const BoundPass previous = mPass;
    BindPass(*mPass.program, mPass.techniqueIndex, mPass.passIndex);
    // The constants stay the snapshot BeginPass took (carried into this submission).
    if (previous.constantsCpu != nullptr && previous.constantsSerial == RecordingSerial()) {
      mPass.constants = previous.constants;
      mPass.constantsCpu = previous.constantsCpu;
      mPass.constantsBytes = previous.constantsBytes;
      mPass.constantsSerial = previous.constantsSerial;
    }
  }

  void DeviceD3D12::WaitForSerial(const std::uint64_t serial)
  {
    if (serial == 0U || mFence->GetCompletedValue() >= serial) {
      return;
    }
    CheckDeviceHresult(__LINE__, mFence->SetEventOnCompletion(serial, mFenceEvent), "fence wait");
    // A removed device signals every fence (the completed value reads as
    // UINT64_MAX), so this never hangs; a GPU that stops making progress
    // without being removed is reported every 10 seconds instead of hanging
    // the game silently.
    while (::WaitForSingleObject(mFenceEvent, 10000U) == WAIT_TIMEOUT) {
      const HRESULT reason = mDevice->GetDeviceRemovedReason();
      gpg::Warnf(
        "D3D12: still waiting for the GPU after 10 s (fence at %llu, waiting for %llu, device 0x%08lX)",
        static_cast<unsigned long long>(mFence->GetCompletedValue()), static_cast<unsigned long long>(serial),
        static_cast<unsigned long>(reason)
      );
      if (FAILED(reason)) {
        CheckDeviceHresult(__LINE__, reason, "fence wait");
      }
    }
  }

  void DeviceD3D12::CollectCompleted()
  {
    const std::uint64_t completed = mFence->GetCompletedValue();
    if (completed < mSubmittedSerial) {
      mMostInFlight = std::max(mMostInFlight, mSubmittedSerial - completed);
    }
    mUpload.Retire(completed);
    std::size_t kept = 0U;
    for (std::size_t index = 0U; index < mGarbage.size(); ++index) {
      Garbage& garbage = mGarbage[index];
      if (garbage.serial <= completed) {
        if (garbage.descriptor.ptr != 0U) {
          switch (garbage.type) {
          case D3D12_DESCRIPTOR_HEAP_TYPE_RTV:
            mRtvPool.Free(garbage.descriptor);
            break;
          case D3D12_DESCRIPTOR_HEAP_TYPE_DSV:
            mDsvPool.Free(garbage.descriptor);
            break;
          default:
            mSrvPool.Free(garbage.descriptor);
            break;
          }
        }
        continue; // the resource reference drops with the entry
      }
      if (kept != index) {
        mGarbage[kept] = std::move(garbage);
      }
      ++kept;
    }
    mGarbage.resize(kept);
  }

  d3d12::UploadAllocation DeviceD3D12::AllocateUpload(const std::uint64_t bytes, const std::uint64_t alignment)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    // Loading screens upload hundreds of megabytes between presents: hand
    // the GPU what is recorded once a lot is waiting, and wait for it when
    // the upload memory in flight grows past a bound (x86 address space).
    static std::uint64_t sinceSubmit = 0U;
    sinceSubmit += mUpload.TakeAllocatedBytes();
    // Never in the middle of preparing a draw: buffers already prepared
    // must stay in the list they were prepared for.
#if defined(_M_IX86)
    constexpr std::uint64_t kDefaultSubmitAfter = 48ULL << 20U;
    constexpr std::uint64_t kWaitAbove = 128ULL << 20U;
#else
    constexpr std::uint64_t kDefaultSubmitAfter = 96ULL << 20U;
    constexpr std::uint64_t kWaitAbove = 384ULL << 20U;
#endif
    // Diagnostics: FAF_GAL_UPLOAD_SUBMIT_KB=<n> hands the GPU the recorded
    // commands after every n KB of uploads instead, which exercises the
    // mid-frame submission paths.
    static const std::uint64_t kSubmitAfter = [] {
      const char* const value = std::getenv("FAF_GAL_UPLOAD_SUBMIT_KB");
      const long kilobytes = (value != nullptr) ? std::strtol(value, nullptr, 10) : 0L;
      return (kilobytes > 0L) ? static_cast<std::uint64_t>(kilobytes) << 10U : kDefaultSubmitAfter;
    }();
    if (sinceSubmit > kSubmitAfter && !mPreparingDraw) {
      sinceSubmit = 0U;
      ++mUploadSubmits;
      Submit(mUpload.BusyBytes() > kWaitAbove);
    }
    return mUpload.Allocate(bytes, alignment, RecordingSerial());
  }

  void DeviceD3D12::Transition(d3d12::TrackedResource& resource, const D3D12_RESOURCE_STATES state)
  {
    if (resource.resource == nullptr || resource.state == state) {
      return;
    }
    // A read state that already includes the wanted bits needs no barrier.
    if (state != D3D12_RESOURCE_STATE_COMMON && (resource.state & state) == state &&
        (resource.state & (D3D12_RESOURCE_STATE_RENDER_TARGET | D3D12_RESOURCE_STATE_DEPTH_WRITE | D3D12_RESOURCE_STATE_COPY_DEST)) == 0) {
      return;
    }
    D3D12_RESOURCE_BARRIER barrier{};
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Transition.pResource = resource.resource.Get();
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = resource.state;
    barrier.Transition.StateAfter = state;
    mPendingBarriers.push_back(barrier);
    resource.state = state;
  }

  void DeviceD3D12::FlushBarriers()
  {
    if (!mPendingBarriers.empty()) {
      mList->ResourceBarrier(static_cast<UINT>(mPendingBarriers.size()), mPendingBarriers.data());
      mPendingBarriers.clear();
    }
  }

  void DeviceD3D12::UploadBuffer(d3d12::TrackedResource& destination, const std::uint64_t offset, const void* const data, const std::uint64_t bytes)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const d3d12::UploadAllocation upload = AllocateUpload(bytes, 16U);
    std::memcpy(upload.cpu, data, static_cast<std::size_t>(bytes));
    Transition(destination, D3D12_RESOURCE_STATE_COPY_DEST);
    FlushBarriers();
    MarkDraw("buffer upload");
    mList->CopyBufferRegion(destination.resource.Get(), offset, upload.resource, upload.offset, bytes);
    FinishDraw();
  }

  bool DeviceD3D12::CopyVertexBufferRegion(
    VertexBuffer& destination, const std::uint32_t destinationOffset, VertexBuffer& source, const std::uint32_t sourceOffset,
    const std::uint32_t byteCount
  )
  {
    BufferStorageD3D12& to = static_cast<VertexBufferD3D12&>(destination).Storage();
    BufferStorageD3D12& from = static_cast<VertexBufferD3D12&>(source).Storage();
    d3d12::TrackedResource* const target = to.CopyDestination();
    // A dynamic destination lives in upload memory the CPU rewrites; only
    // default-heap buffers take GPU copies.
    if (&to == &from || byteCount == 0U || target == nullptr || static_cast<std::uint64_t>(destinationOffset) + byteCount > to.ByteWidth() ||
        static_cast<std::uint64_t>(sourceOffset) + byteCount > from.ByteWidth()) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    // The source first: a dynamic buffer may take a new upload copy, and that
    // allocation can hand the recorded commands to the GPU.
    ID3D12Resource* sourceResource = nullptr;
    std::uint64_t sourceBase = 0U;
    from.PrepareForCopySource(*this, sourceResource, sourceBase);
    if (sourceResource == nullptr) {
      return false;
    }
    // In command order: earlier draws reading the destination are recorded
    // before this barrier, and later draws move it back to VERTEX_AND_CONSTANT
    // in PrepareForDraw.
    Transition(*target, D3D12_RESOURCE_STATE_COPY_DEST);
    FlushBarriers();
    mList->CopyBufferRegion(target->resource.Get(), destinationOffset, sourceResource, sourceBase + sourceOffset, byteCount);
    return true;
  }

  void DeviceD3D12::UploadSubresource(
    d3d12::TrackedResource& destination, const std::uint32_t subresource, const void* const data, const std::uint32_t rowPitch
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const D3D12_RESOURCE_DESC desc = destination.resource->GetDesc();
    D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
    UINT rows = 0U;
    UINT64 rowBytes = 0U;
    UINT64 total = 0U;
    mDevice->GetCopyableFootprints(&desc, subresource, 1U, 0U, &footprint, &rows, &rowBytes, &total);

    const d3d12::UploadAllocation upload = AllocateUpload(total, D3D12_TEXTURE_DATA_PLACEMENT_ALIGNMENT);
    const auto* const source = static_cast<const std::uint8_t*>(data);
    const std::size_t copyBytes = static_cast<std::size_t>(std::min<UINT64>(rowBytes, rowPitch));
    for (UINT slice = 0U; slice < footprint.Footprint.Depth; ++slice) {
      for (UINT row = 0U; row < rows; ++row) {
        std::memcpy(
          upload.cpu + static_cast<std::size_t>(slice) * footprint.Footprint.RowPitch * rows +
            static_cast<std::size_t>(row) * footprint.Footprint.RowPitch,
          source + (static_cast<std::size_t>(slice) * rows + row) * rowPitch, copyBytes
        );
      }
    }

    Transition(destination, D3D12_RESOURCE_STATE_COPY_DEST);
    FlushBarriers();
    D3D12_TEXTURE_COPY_LOCATION target{};
    target.pResource = destination.resource.Get();
    target.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    target.SubresourceIndex = subresource;
    D3D12_TEXTURE_COPY_LOCATION origin{};
    origin.pResource = upload.resource;
    origin.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    origin.PlacedFootprint = footprint;
    origin.PlacedFootprint.Offset = upload.offset;
    MarkDraw("texture upload");
    mList->CopyTextureRegion(&target, 0U, 0U, 0U, &origin, nullptr);
    FinishDraw();
  }

  void DeviceD3D12::ReadSubresource(
    d3d12::TrackedResource& source, const std::uint32_t subresource, std::vector<std::uint8_t>& bytes, std::uint32_t& rowPitch
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const D3D12_RESOURCE_DESC desc = source.resource->GetDesc();
    D3D12_PLACED_SUBRESOURCE_FOOTPRINT footprint{};
    UINT rows = 0U;
    UINT64 rowBytes = 0U;
    UINT64 total = 0U;
    mDevice->GetCopyableFootprints(&desc, subresource, 1U, 0U, &footprint, &rows, &rowBytes, &total);

    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC bufferDesc{};
    bufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    bufferDesc.Width = total;
    bufferDesc.Height = 1U;
    bufferDesc.DepthOrArraySize = 1U;
    bufferDesc.MipLevels = 1U;
    bufferDesc.SampleDesc.Count = 1U;
    bufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ComPtr<ID3D12Resource> readback;
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &bufferDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&readback))
    );

    Transition(source, D3D12_RESOURCE_STATE_COPY_SOURCE);
    FlushBarriers();
    D3D12_TEXTURE_COPY_LOCATION target{};
    target.pResource = readback.Get();
    target.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
    target.PlacedFootprint = footprint;
    D3D12_TEXTURE_COPY_LOCATION origin{};
    origin.pResource = source.resource.Get();
    origin.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
    origin.SubresourceIndex = subresource;
    mList->CopyTextureRegion(&target, 0U, 0U, 0U, &origin, nullptr);
    Submit(true);

    rowPitch = static_cast<std::uint32_t>(rowBytes);
    bytes.resize(static_cast<std::size_t>(rowBytes) * rows);
    void* mapped = nullptr;
    const D3D12_RANGE readRange{0U, static_cast<SIZE_T>(total)};
    CheckHresult("DeviceD3D12.cpp", __LINE__, readback->Map(0U, &readRange, &mapped));
    for (UINT row = 0U; row < rows; ++row) {
      std::memcpy(bytes.data() + static_cast<std::size_t>(row) * rowBytes,
                  static_cast<const std::uint8_t*>(mapped) + static_cast<std::size_t>(row) * footprint.Footprint.RowPitch,
                  static_cast<std::size_t>(rowBytes));
    }
    const D3D12_RANGE noWrite{0U, 0U};
    readback->Unmap(0U, &noWrite);
  }

  void DeviceD3D12::ReadTexture(d3d12::TrackedResource& source, imaging::Image& image)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const D3D12_RESOURCE_DESC desc = source.resource->GetDesc();
    if (desc.Dimension != D3D12_RESOURCE_DIMENSION_TEXTURE2D) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "only 2D textures can be read back");
    }
    image.Allocate(desc.Format, static_cast<std::uint32_t>(desc.Width), desc.Height, desc.MipLevels, desc.DepthOrArraySize);
    const UINT count = static_cast<UINT>(image.subresources.size());
    std::vector<D3D12_PLACED_SUBRESOURCE_FOOTPRINT> footprints(count);
    std::vector<UINT> rows(count);
    std::vector<UINT64> rowBytes(count);
    UINT64 total = 0U;
    mDevice->GetCopyableFootprints(&desc, 0U, count, 0U, footprints.data(), rows.data(), rowBytes.data(), &total);

    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC bufferDesc{};
    bufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    bufferDesc.Width = total;
    bufferDesc.Height = 1U;
    bufferDesc.DepthOrArraySize = 1U;
    bufferDesc.MipLevels = 1U;
    bufferDesc.SampleDesc.Count = 1U;
    bufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ComPtr<ID3D12Resource> readback;
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &bufferDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&readback))
    );
    Transition(source, D3D12_RESOURCE_STATE_COPY_SOURCE);
    FlushBarriers();
    for (UINT index = 0U; index < count; ++index) {
      D3D12_TEXTURE_COPY_LOCATION target{};
      target.pResource = readback.Get();
      target.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
      target.PlacedFootprint = footprints[index];
      D3D12_TEXTURE_COPY_LOCATION origin{};
      origin.pResource = source.resource.Get();
      origin.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
      origin.SubresourceIndex = index;
      mList->CopyTextureRegion(&target, 0U, 0U, 0U, &origin, nullptr);
    }
    Submit(true);

    void* mapped = nullptr;
    const D3D12_RANGE readRange{0U, static_cast<SIZE_T>(total)};
    CheckHresult("DeviceD3D12.cpp", __LINE__, readback->Map(0U, &readRange, &mapped));
    for (UINT index = 0U; index < count; ++index) {
      const imaging::Image::Subresource& subresource = image.subresources[index];
      const std::size_t copyBytes = std::min<std::size_t>(subresource.rowPitch, static_cast<std::size_t>(rowBytes[index]));
      for (UINT row = 0U; row < rows[index] && row < subresource.rowCount; ++row) {
        std::memcpy(image.bytes.data() + subresource.offset + static_cast<std::size_t>(row) * subresource.rowPitch,
                    static_cast<const std::uint8_t*>(mapped) + footprints[index].Offset +
                      static_cast<std::size_t>(row) * footprints[index].Footprint.RowPitch,
                    copyBytes);
      }
    }
    const D3D12_RANGE noWrite{0U, 0U};
    readback->Unmap(0U, &noWrite);
  }

  void DeviceD3D12::Retire(ComPtr<ID3D12Resource> resource)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    Garbage garbage;
    garbage.serial = RecordingSerial();
    garbage.resource = std::move(resource);
    mGarbage.push_back(std::move(garbage));
  }

  void DeviceD3D12::RetireDescriptor(const D3D12_DESCRIPTOR_HEAP_TYPE type, const D3D12_CPU_DESCRIPTOR_HANDLE handle)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    Garbage garbage;
    garbage.serial = RecordingSerial();
    garbage.type = type;
    garbage.descriptor = handle;
    mGarbage.push_back(std::move(garbage));
  }

  D3D12_CPU_DESCRIPTOR_HANDLE DeviceD3D12::AllocateDescriptor(const D3D12_DESCRIPTOR_HEAP_TYPE type)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    switch (type) {
    case D3D12_DESCRIPTOR_HEAP_TYPE_RTV:
      return mRtvPool.Allocate();
    case D3D12_DESCRIPTOR_HEAP_TYPE_DSV:
      return mDsvPool.Allocate();
    default:
      return mSrvPool.Allocate();
    }
  }

  D3D12_GPU_DESCRIPTOR_HANDLE DeviceD3D12::AllocateTable(const std::uint32_t count, D3D12_CPU_DESCRIPTOR_HANDLE& cpu)
  {
    D3D12_GPU_DESCRIPTOR_HANDLE gpu{};
    if (!mFrames[mFrameIndex].views.Allocate(count, cpu, gpu)) {
      // The frame's view heap is full: let the GPU finish, then start it over.
      gpg::Warnf("D3D12: frame descriptor heap full; waiting for the GPU");
      Submit(true);
      mFrames[mFrameIndex].views.Reset();
      ++mArenaEpoch;
      if (!mFrames[mFrameIndex].views.Allocate(count, cpu, gpu)) {
        ThrowError("DeviceD3D12.cpp", __LINE__, "descriptor table larger than the frame heap");
      }
    }
    return gpu;
  }

  D3D12_GPU_DESCRIPTOR_HANDLE DeviceD3D12::SamplerTable(const std::vector<effects::SamplerDesc>& samplers)
  {
    std::vector<D3D12_SAMPLER_DESC> descs(effects::kMaxSamplerSlots);
    for (std::uint32_t index = 0U; index < effects::kMaxSamplerSlots; ++index) {
      D3D12_SAMPLER_DESC& desc = descs[index];
      effects::SamplerDesc source;
      if (index < samplers.size()) {
        source = samplers[index];
      }
      desc.Filter = static_cast<D3D12_FILTER>(source.filter);
      desc.AddressU = static_cast<D3D12_TEXTURE_ADDRESS_MODE>(source.addressU);
      desc.AddressV = static_cast<D3D12_TEXTURE_ADDRESS_MODE>(source.addressV);
      desc.AddressW = static_cast<D3D12_TEXTURE_ADDRESS_MODE>(source.addressW);
      desc.MipLODBias = source.mipLodBias;
      desc.MaxAnisotropy = std::clamp<UINT>(source.maxAnisotropy, 1U, 16U);
      desc.ComparisonFunc = D3D12_COMPARISON_FUNC_NEVER;
      for (int component = 0; component < 4; ++component) {
        desc.BorderColor[component] = source.borderColor[component];
      }
      desc.MinLOD = source.minLod;
      desc.MaxLOD = source.maxLod;
    }
    const std::string key(reinterpret_cast<const char*>(descs.data()), descs.size() * sizeof(D3D12_SAMPLER_DESC));
    const auto found = mSamplerTables.find(key);
    if (found != mSamplerTables.end()) {
      return found->second;
    }
    D3D12_CPU_DESCRIPTOR_HANDLE cpu{};
    D3D12_GPU_DESCRIPTOR_HANDLE gpu{};
    if (!mSamplerHeap.Allocate(effects::kMaxSamplerSlots, cpu, gpu)) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "sampler heap exhausted");
    }
    for (std::uint32_t index = 0U; index < effects::kMaxSamplerSlots; ++index) {
      D3D12_CPU_DESCRIPTOR_HANDLE handle = cpu;
      handle.ptr += static_cast<SIZE_T>(index) * mSamplerHeap.Increment();
      mDevice->CreateSampler(&descs[index], handle);
    }
    mSamplerTables.emplace(key, gpu);
    return gpu;
  }

  // ---------------------------------------------------------------------------
  // Device slots

  void* DeviceD3D12::GetLog()
  {
    return &mLog;
  }

  DeviceContext* DeviceD3D12::GetDeviceContext()
  {
    return &mDeviceContext;
  }

  int DeviceD3D12::GetCurThreadId()
  {
    return mCurThreadId;
  }

  void DeviceD3D12::Func1() const {}

  void DeviceD3D12::GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, const int adapterIndex)
  {
    outModes.clear();
    const auto& adapters = mFactory.Adapters();
    if (adapterIndex < 0 || adapterIndex >= static_cast<int>(adapters.size())) {
      return;
    }
    for (const dxgi::OutputInfo& output : adapters[static_cast<std::size_t>(adapterIndex)].outputs) {
      for (const DXGI_MODE_DESC& mode : output.modes) {
        outModes.push_back(HeadAdapterMode{mode.Width, mode.Height, dxgi::AdapterInfo::RefreshHz(mode)});
      }
    }
  }

  OutputContext* DeviceD3D12::GetHeadOutputContext(const unsigned int headIndex)
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  const OutputContext* DeviceD3D12::GetHeadOutputContext(const unsigned int headIndex) const
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  boost::shared_ptr<PipelineState> DeviceD3D12::GetPipelineState()
  {
    return mPipelineState;
  }

  boost::shared_ptr<Effect> DeviceD3D12::CreateEffect(const EffectContext& context)
  {
    if (context.mSourceType != 2U) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid source defined for effect");
    }
    EffectContext localContext(context);
    for (const MacroPair& macro : kInjectedMacros) {
      localContext.DefineMacro(macro.name, macro.value);
    }
    std::vector<D3D_SHADER_MACRO> defines;
    defines.reserve(localContext.mMacros.size() + 1U);
    for (const EffectMacro& macro : localContext.mMacros) {
      defines.push_back(D3D_SHADER_MACRO{macro.keyText_.c_str(), macro.valueText_.c_str()});
    }
    defines.push_back(D3D_SHADER_MACRO{nullptr, nullptr});

    const DWORD started = ::GetTickCount();
    const char* const sourceName = context.mSourcePath.c_str();
    const char* const sourceData = context.mSourceBuffer.mBegin;
    const std::size_t sourceBytes = static_cast<std::size_t>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
    ComPtr<ID3DBlob> preprocessed;
    ComPtr<ID3DBlob> errors;
    if (FAILED(::D3DPreprocess(sourceData, sourceBytes, sourceName, defines.data(), nullptr, &preprocessed, &errors))) {
      const std::string message = std::string("unable to preprocess effect: ") + sourceName + " reason: " +
        ((errors != nullptr) ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize()) : std::string());
      ThrowError("DeviceD3D12.cpp", __LINE__, message.c_str());
    }
    d3d11::TranslatedEffectSource translated = d3d11::TranslateEffectSource(
      std::string_view(static_cast<const char*>(preprocessed->GetBufferPointer()), preprocessed->GetBufferSize() - 1U), true,
      // No original source: the D3D9 alpha test is applied by the effect layer (EffectDescription),
      // and running the translator's copy as well would test twice.
      std::string_view{}
    );
    for (const std::string& note : translated.notes) {
      gpg::Logf("D3D12: %s: %s", sourceName, note.c_str());
    }

    std::shared_ptr<effects::EffectProgram> program;
    try {
      program = std::make_shared<effects::EffectProgram>(
        sourceName, std::move(translated.source), effects::ShaderTarget::Dxil, std::string_view(sourceData, sourceBytes)
      );
    } catch (const std::exception& error) {
      const std::string message = std::string("unable to create effect: ") + sourceName + " reason: " + error.what();
      ThrowError("DeviceD3D12.cpp", __LINE__, message.c_str());
    }
    if (const char* const precompile = std::getenv("FAF_SHADER_PRECOMPILE"); precompile != nullptr && precompile[0] == '1') {
      program->CompileAll();
    }
    gpg::Logf(
      "D3D12: effect %s: %u techniques, %u entry points, %u bytes of parameters (%lu ms)", sourceName,
      static_cast<unsigned>(program->Description().techniques.size()), static_cast<unsigned>(program->Modern().entries.size()),
      static_cast<unsigned>(program->Parameters().Constants().size()), ::GetTickCount() - started
    );
    return boost::shared_ptr<Effect>(new ProgramEffect(context, program, *this));
  }

  boost::shared_ptr<Texture> DeviceD3D12::CreateTexture(const TextureContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC desc{};
    desc.SampleDesc.Count = 1U;
    d3d12::TrackedResource resource;
    bool cube = false;
    bool contentsFromEngine = false;
    imaging::Image image;

    if (context->source_ == 2U) {
      desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
      desc.Width = std::max(context->width_, 1U);
      desc.Height = std::max(context->height_, 1U);
      desc.DepthOrArraySize = 1U;
      desc.MipLevels = static_cast<UINT16>((context->mipmapLevels_ != 0U) ? context->mipmapLevels_ : 1U);
      desc.Format = dxgi::TextureFormatToDxgi(context->format_);
      if (desc.Format == DXGI_FORMAT_UNKNOWN) {
        char message[128]{};
        std::snprintf(message, sizeof(message), "unsupported texture format %u", context->format_);
        ThrowError("DeviceD3D12.cpp", __LINE__, message);
      }
      contentsFromEngine = true; // committed resources start zeroed, as the CPU copy does
    } else if (context->source_ == 1U) {
      if (context->dataBuffer_.mEnd == context->dataBuffer_.mBegin) {
        ThrowError("DeviceD3D12.cpp", __LINE__, "attempt to create texture from uninitialized memory");
      }
      imaging::DecodeOptions options;
      // The texture-quality option skips top mip levels (D3D9's
      // D3DX_SKIP_DDS_MIP_LEVELS, `reserved0x44_`).
      options.skipMipLevels = context->reserved0x44_ & 0x1FU;
      const HRESULT result =
        imaging::ImageCodec::Instance()->Decode(context->dataBuffer_.mBegin, context->DataSizeBytes(), options, image);
      if (FAILED(result)) {
        char message[640]{};
        std::snprintf(message, sizeof(message), "unable to load texture %s: HRESULT 0x%08lX", context->location_.c_str(),
                      static_cast<unsigned long>(result));
        ThrowError("DeviceD3D12.cpp", __LINE__, message);
      }
      desc.Dimension = image.volume ? D3D12_RESOURCE_DIMENSION_TEXTURE3D : D3D12_RESOURCE_DIMENSION_TEXTURE2D;
      desc.Width = image.width;
      desc.Height = image.height;
      desc.DepthOrArraySize = static_cast<UINT16>(image.volume ? image.depth : image.arraySize);
      desc.MipLevels = static_cast<UINT16>(image.mipLevels);
      desc.Format = image.format;
      cube = image.cube;
      if (image.format == DXGI_FORMAT_R8_UNORM || image.format == DXGI_FORMAT_R8G8_UNORM || image.format == DXGI_FORMAT_A8_UNORM) {
        static int logged = 0;
        if (logged++ < 40) {
          gpg::Logf("D3D12: texture %s decoded as DXGI format %d", context->location_.c_str(), static_cast<int>(image.format));
        }
      }
    } else {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid source specified for texture data");
    }

    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr,
                                       IID_PPV_ARGS(&resource.resource))
    );
    resource.state = D3D12_RESOURCE_STATE_COPY_DEST;
    {
      const std::string_view location = context->location_.view();
      const std::wstring name(location.begin(), location.end());
      static_cast<void>(resource.resource->SetName(name.empty() ? L"engine texture" : name.c_str()));
    }

    for (std::uint32_t index = 0U; index < image.subresources.size(); ++index) {
      const imaging::Image::Subresource& subresource = image.subresources[index];
      UploadSubresource(resource, index, image.bytes.data() + subresource.offset, subresource.rowPitch);
    }

    D3D12_SHADER_RESOURCE_VIEW_DESC view{};
    view.Format = desc.Format;
    view.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    if (desc.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE3D) {
      view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE3D;
      view.Texture3D.MipLevels = desc.MipLevels;
    } else if (cube) {
      view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURECUBE;
      view.TextureCube.MipLevels = desc.MipLevels;
    } else if (desc.DepthOrArraySize > 1U) {
      view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2DARRAY;
      view.Texture2DArray.MipLevels = desc.MipLevels;
      view.Texture2DArray.ArraySize = desc.DepthOrArraySize;
    } else {
      view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
      view.Texture2D.MipLevels = desc.MipLevels;
    }
    const D3D12_CPU_DESCRIPTOR_HANDLE handle = mSrvPool.Allocate();
    mDevice->CreateShaderResourceView(resource.resource.Get(), &view, handle);
    return boost::shared_ptr<Texture>(new TextureD3D12(*context, std::move(resource), handle, cube, contentsFromEngine));
  }

  boost::shared_ptr<RenderTarget> DeviceD3D12::CreateRenderTarget(const RenderTargetContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = std::max(context->width_, 1U);
    desc.Height = std::max(context->height_, 1U);
    desc.DepthOrArraySize = 1U;
    desc.MipLevels = 1U;
    desc.Format = dxgi::RenderTargetFormatToDxgi(context->format_);
    if (desc.Format == DXGI_FORMAT_UNKNOWN) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "unsupported render target format");
    }
    desc.SampleDesc.Count = 1U;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_RENDER_TARGET;
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_CLEAR_VALUE clear{};
    clear.Format = desc.Format;

    RenderTargetD3D12::Buffer buffer;
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, kShaderRead, &clear, IID_PPV_ARGS(&buffer.resource.resource))
    );
    static_cast<void>(buffer.resource.resource->SetName(
      (L"render target " + std::to_wstring(desc.Width) + L"x" + std::to_wstring(desc.Height)).c_str()
    ));
    buffer.resource.state = kShaderRead;
    buffer.renderTargetView = mRtvPool.Allocate();
    mDevice->CreateRenderTargetView(buffer.resource.resource.Get(), nullptr, buffer.renderTargetView);
    buffer.shaderResourceView = mSrvPool.Allocate();
    mDevice->CreateShaderResourceView(buffer.resource.resource.Get(), nullptr, buffer.shaderResourceView);

    // As DeviceD3D10::CreateRenderTarget (0x008FB1D0): a viewport covering the new target.
    D3DVIEWPORT9 viewport{};
    viewport.Width = static_cast<DWORD>(desc.Width);
    viewport.Height = desc.Height;
    viewport.MaxZ = 1.0f;
    SetViewport(&viewport);

    std::vector<RenderTargetD3D12::Buffer> buffers;
    buffers.push_back(std::move(buffer));
    return boost::shared_ptr<RenderTarget>(new RenderTargetD3D12(std::move(buffers), nullptr));
  }

  boost::shared_ptr<CubeRenderTarget> DeviceD3D12::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
  {
    return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetD3D12(*context));
  }

  boost::shared_ptr<DepthStencilTarget> DeviceD3D12::CreateDepthStencilTarget(const DepthStencilTargetContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const bool sampled = context->field0x10_;
    const dxgi::DepthFormats formats = dxgi::DepthStencilFormatToDxgi(context->format_, sampled);
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = std::max(context->width_, 1U);
    desc.Height = std::max(context->height_, 1U);
    desc.DepthOrArraySize = 1U;
    desc.MipLevels = 1U;
    desc.Format = formats.texture;
    desc.SampleDesc.Count = 1U;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_DEPTH_STENCIL | (sampled ? D3D12_RESOURCE_FLAG_NONE : D3D12_RESOURCE_FLAG_DENY_SHADER_RESOURCE);
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_CLEAR_VALUE clear{};
    clear.Format = formats.depthView;
    clear.DepthStencil.Depth = 1.0f;

    d3d12::TrackedResource resource;
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      mDevice->CreateCommittedResource(&heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_DEPTH_WRITE, &clear,
                                       IID_PPV_ARGS(&resource.resource))
    );
    static_cast<void>(resource.resource->SetName(
      (L"depth stencil " + std::to_wstring(desc.Width) + L"x" + std::to_wstring(desc.Height)).c_str()
    ));
    resource.state = D3D12_RESOURCE_STATE_DEPTH_WRITE;

    D3D12_DEPTH_STENCIL_VIEW_DESC depthDesc{};
    depthDesc.Format = formats.depthView;
    depthDesc.ViewDimension = D3D12_DSV_DIMENSION_TEXTURE2D;
    const D3D12_CPU_DESCRIPTOR_HANDLE depthView = mDsvPool.Allocate();
    mDevice->CreateDepthStencilView(resource.resource.Get(), &depthDesc, depthView);
    D3D12_CPU_DESCRIPTOR_HANDLE shaderView{};
    if (sampled) {
      D3D12_SHADER_RESOURCE_VIEW_DESC view{};
      view.Format = formats.shaderView;
      view.ViewDimension = D3D12_SRV_DIMENSION_TEXTURE2D;
      view.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
      view.Texture2D.MipLevels = 1U;
      shaderView = mSrvPool.Allocate();
      mDevice->CreateShaderResourceView(resource.resource.Get(), &view, shaderView);
    }
    return boost::shared_ptr<DepthStencilTarget>(
      new DepthStencilTargetD3D12(*context, std::move(resource), depthView, shaderView, formats.depthView)
    );
  }

  boost::shared_ptr<VertexFormat> DeviceD3D12::CreateVertexFormat(const std::uint32_t formatCode)
  {
    if (formatCode >= d3d11::kVertexFormatCount || d3d11::VertexLayoutElements(formatCode).empty()) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid vertex format specified");
    }
    return boost::shared_ptr<VertexFormat>(new VertexFormatD3D12(formatCode));
  }

  boost::shared_ptr<VertexBuffer> DeviceD3D12::CreateVertexBuffer(const VertexBufferContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    return boost::shared_ptr<VertexBuffer>(new VertexBufferD3D12(*context));
  }

  boost::shared_ptr<IndexBuffer> DeviceD3D12::CreateIndexBuffer(const IndexBufferContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    return boost::shared_ptr<IndexBuffer>(new IndexBufferD3D12(*context));
  }

  void DeviceD3D12::GetRenderTargetData(const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination)
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const target = static_cast<TextureD3D12*>(destination.get());
    RenderTargetD3D12::Buffer& buffer = static_cast<RenderTargetD3D12*>(source.get())->Current();
    Transition(buffer.resource, D3D12_RESOURCE_STATE_COPY_SOURCE);
    Transition(target->Resource(), D3D12_RESOURCE_STATE_COPY_DEST);
    FlushBarriers();
    mList->CopyResource(target->Resource().resource.Get(), buffer.resource.resource.Get());
    target->DiscardCpuCopy();
  }

  void DeviceD3D12::StretchRect(
    const boost::shared_ptr<RenderTarget>& source,
    const boost::shared_ptr<RenderTarget>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const sourceTarget = static_cast<RenderTargetD3D12*>(source.get());
    auto* const destinationTarget = static_cast<RenderTargetD3D12*>(destination.get());
    const RenderTargetContext* const sourceContext = sourceTarget->GetContext();
    const RenderTargetContext* const destinationContext = destinationTarget->GetContext();
    RenderTargetD3D12::Buffer& from = sourceTarget->Current();
    RenderTargetD3D12::Buffer& to = destinationTarget->Current();

    if (sourceContext->width_ == destinationContext->width_ && sourceContext->height_ == destinationContext->height_ &&
        sourceTarget->Format() == destinationTarget->Format()) {
      // As D3D10: a direct copy; only the destination rect's corner is used.
      Transition(from.resource, D3D12_RESOURCE_STATE_COPY_SOURCE);
      Transition(to.resource, D3D12_RESOURCE_STATE_COPY_DEST);
      FlushBarriers();
      D3D12_TEXTURE_COPY_LOCATION target{};
      target.pResource = to.resource.resource.Get();
      target.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
      D3D12_TEXTURE_COPY_LOCATION origin{};
      origin.pResource = from.resource.resource.Get();
      origin.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
      D3D12_BOX box{};
      const D3D12_BOX* boxPointer = nullptr;
      if (sourceRect != nullptr) {
        box.left = static_cast<UINT>(sourceRect->left);
        box.top = static_cast<UINT>(sourceRect->top);
        box.right = static_cast<UINT>(sourceRect->right);
        box.bottom = static_cast<UINT>(sourceRect->bottom);
        box.front = 0U;
        box.back = 1U;
        boxPointer = &box;
      }
      const UINT x = (destinationRect != nullptr) ? static_cast<UINT>(destinationRect->left) : 0U;
      const UINT y = (destinationRect != nullptr) ? static_cast<UINT>(destinationRect->top) : 0U;
      MarkDraw("StretchRect copy");
      mList->CopyTextureRegion(&target, x, y, 0U, &origin, boxPointer);
      FinishDraw();
      return;
    }
    BlitTexture(from.shaderResourceView, from.resource, to, destinationTarget->Format(), destinationContext->width_, destinationContext->height_);
  }

  void DeviceD3D12::BlitTexture(
    const D3D12_CPU_DESCRIPTOR_HANDLE source,
    d3d12::TrackedResource& sourceResource,
    RenderTargetD3D12::Buffer& destination,
    const DXGI_FORMAT destinationFormat,
    const std::uint32_t width,
    const std::uint32_t height
  )
  {
    ComPtr<ID3D12PipelineState>& pipeline = mBlitPipelines[destinationFormat];
    if (pipeline == nullptr) {
      D3D12_GRAPHICS_PIPELINE_STATE_DESC desc{};
      desc.pRootSignature = mRootSignature.Get();
      desc.VS = {mBlitVertexShader.data(), mBlitVertexShader.size()};
      desc.PS = {mBlitPixelShader.data(), mBlitPixelShader.size()};
      desc.BlendState.RenderTarget[0].SrcBlend = D3D12_BLEND_ONE;
      desc.BlendState.RenderTarget[0].DestBlend = D3D12_BLEND_ZERO;
      desc.BlendState.RenderTarget[0].BlendOp = D3D12_BLEND_OP_ADD;
      desc.BlendState.RenderTarget[0].SrcBlendAlpha = D3D12_BLEND_ONE;
      desc.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_ZERO;
      desc.BlendState.RenderTarget[0].BlendOpAlpha = D3D12_BLEND_OP_ADD;
      desc.BlendState.RenderTarget[0].LogicOp = D3D12_LOGIC_OP_NOOP;
      desc.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;
      desc.SampleMask = 0xFFFFFFFFU;
      desc.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
      desc.RasterizerState.CullMode = D3D12_CULL_MODE_NONE;
      desc.RasterizerState.DepthClipEnable = FALSE;
      desc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
      desc.NumRenderTargets = 1U;
      desc.RTVFormats[0] = destinationFormat;
      desc.SampleDesc.Count = 1U;
      CheckHresult("DeviceD3D12.cpp", __LINE__, mDevice->CreateGraphicsPipelineState(&desc, IID_PPV_ARGS(&pipeline)));
    }

    D3D12_CPU_DESCRIPTOR_HANDLE cpu{};
    const D3D12_GPU_DESCRIPTOR_HANDLE table = AllocateTable(effects::kMaxTextureSlots, cpu);
    mDevice->CopyDescriptorsSimple(1U, cpu, source, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    D3D12_CPU_DESCRIPTOR_HANDLE rest = cpu;
    rest.ptr += mFrames[mFrameIndex].views.Increment();
    mDevice->CopyDescriptorsSimple(effects::kMaxTextureSlots - 1U, rest, mNullViewRun, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);

    Transition(sourceResource, kShaderRead);
    Transition(destination.resource, D3D12_RESOURCE_STATE_RENDER_TARGET);
    FlushBarriers();
    mList->OMSetRenderTargets(1U, &destination.renderTargetView, FALSE, nullptr);
    const D3D12_VIEWPORT viewport{0.0f, 0.0f, static_cast<float>(width), static_cast<float>(height), 0.0f, 1.0f};
    const D3D12_RECT scissor{0, 0, static_cast<LONG>(width), static_cast<LONG>(height)};
    mList->RSSetViewports(1U, &viewport);
    mList->RSSetScissorRects(1U, &scissor);
    mList->SetPipelineState(pipeline.Get());
    mList->SetGraphicsRootConstantBufferView(0U, 0U);
    mList->SetGraphicsRootDescriptorTable(1U, table);
    mList->SetGraphicsRootDescriptorTable(2U, mBlitSamplers);
    mList->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    MarkDraw("StretchRect blit");
    mList->DrawInstanced(3U, 1U, 0U, 0U);
    FinishDraw();
    mTargetsDirty = true;
  }

  void DeviceD3D12::UpdateSurface(
    const boost::shared_ptr<Texture>& source,
    const boost::shared_ptr<Texture>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "Missing dest   texture");
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const sourceTexture = static_cast<TextureD3D12*>(source.get());
    auto* const destinationTexture = static_cast<TextureD3D12*>(destination.get());
    const D3D12_RESOURCE_DESC& sourceDesc = sourceTexture->Desc();
    const D3D12_RESOURCE_DESC& destinationDesc = destinationTexture->Desc();

    if (sourceDesc.Width == destinationDesc.Width && sourceDesc.Height == destinationDesc.Height &&
        sourceDesc.Format == destinationDesc.Format) {
      Transition(sourceTexture->Resource(), D3D12_RESOURCE_STATE_COPY_SOURCE);
      Transition(destinationTexture->Resource(), D3D12_RESOURCE_STATE_COPY_DEST);
      FlushBarriers();
      D3D12_TEXTURE_COPY_LOCATION target{};
      target.pResource = destinationTexture->Resource().resource.Get();
      target.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
      D3D12_TEXTURE_COPY_LOCATION origin{};
      origin.pResource = sourceTexture->Resource().resource.Get();
      origin.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
      D3D12_BOX box{};
      const D3D12_BOX* boxPointer = nullptr;
      if (sourceRect != nullptr) {
        box.left = static_cast<UINT>(sourceRect->left);
        box.top = static_cast<UINT>(sourceRect->top);
        box.right = static_cast<UINT>(sourceRect->right);
        box.bottom = static_cast<UINT>(sourceRect->bottom);
        box.front = 0U;
        box.back = 1U;
        boxPointer = &box;
      }
      const UINT x = (destinationRect != nullptr) ? static_cast<UINT>(destinationRect->left) : 0U;
      const UINT y = (destinationRect != nullptr) ? static_cast<UINT>(destinationRect->top) : 0U;
      MarkDraw("UpdateSurface copy");
      mList->CopyTextureRegion(&target, x, y, 0U, &origin, boxPointer);
      FinishDraw();
      destinationTexture->DiscardCpuCopy();
      return;
    }

    // D3D10's fallback (0x008FBDF0) re-encodes the source; it is reloaded in
    // the destination's size, format and level count (see DeviceD3D11).
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    imaging::Image sourceImage;
    ReadTexture(sourceTexture->Resource(), sourceImage);
    std::vector<std::uint8_t> encoded;
    CheckHresult("DeviceD3D12.cpp", __LINE__, codec->Encode(sourceImage, imaging::FileFormat::Dds, encoded));
    imaging::DecodeOptions options;
    options.format = destinationDesc.Format;
    options.width = static_cast<std::uint32_t>(destinationDesc.Width);
    options.height = destinationDesc.Height;
    options.mipLevels = destinationDesc.MipLevels;
    imaging::Image converted;
    CheckHresult("DeviceD3D12.cpp", __LINE__, codec->Decode(encoded.data(), encoded.size(), options, converted));
    for (std::uint32_t level = 0U; level < converted.mipLevels && level < destinationDesc.MipLevels; ++level) {
      const imaging::Image::Subresource& subresource = converted.subresources[level];
      UploadSubresource(destinationTexture->Resource(), level, converted.bytes.data() + subresource.offset, subresource.rowPitch);
    }
    destinationTexture->DiscardCpuCopy();
  }

  void DeviceD3D12::SaveCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const msvc8::string& filePath)
  {
    static_cast<void>(cubeTarget);
    static_cast<void>(filePath);
  }

  void DeviceD3D12::SaveRenderTarget(const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, const int fileFormat)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    imaging::Image image;
    ReadTexture(static_cast<RenderTargetD3D12*>(renderTarget.get())->Current().resource, image);
    CheckHresult(
      "DeviceD3D12.cpp", __LINE__,
      imaging::ImageCodec::Instance()->EncodeToFile(image, imaging::ImageCodec::FromGalFormat(fileFormat), filePath.c_str())
    );
  }

  void DeviceD3D12::SaveTexture(
    const boost::shared_ptr<Texture>& texture, const msvc8::string& filePath, const int fileFormat, gpg::MemBuffer<char>* const outBuffer
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    auto* const sourceTexture = static_cast<TextureD3D12*>(texture.get());
    imaging::Image image;
    ReadTexture(sourceTexture->Resource(), image);
    image.cube = sourceTexture->IsCube();
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    if (outBuffer == nullptr) {
      CheckHresult("DeviceD3D12.cpp", __LINE__, codec->EncodeToFile(image, imaging::ImageCodec::FromGalFormat(fileFormat), filePath.c_str()));
      return;
    }
    std::vector<std::uint8_t> encoded;
    CheckHresult("DeviceD3D12.cpp", __LINE__, codec->Encode(image, imaging::ImageCodec::FromGalFormat(fileFormat), encoded));
    if (outBuffer->Size() != encoded.size()) {
      *outBuffer = gpg::AllocMemBuffer(encoded.size());
    }
    std::copy(encoded.begin(), encoded.end(), outBuffer->GetPtr(0U, 0U));
  }

  void DeviceD3D12::GetTexture2D(
    const void* const sourceData, const std::uint32_t sourceBytes, gpg::MemBuffer<char>* const outTextureData, std::uint32_t* const outWidth,
    int* const outHeight
  )
  {
    if (sourceData == nullptr) {
      return;
    }
    // As D3D10 (0x008FCAC0): one level of BC3.
    imaging::DecodeOptions options;
    options.format = DXGI_FORMAT_BC3_UNORM;
    options.mipLevels = 1U;
    imaging::Image image;
    CheckHresult("DeviceD3D12.cpp", __LINE__, imaging::ImageCodec::Instance()->Decode(sourceData, sourceBytes, options, image));
    *outWidth = image.width;
    *outHeight = static_cast<int>(image.height);
    const imaging::Image::Subresource& top = image.subresources.front();
    const std::size_t requiredBytes = top.slicePitch;
    if (outTextureData->Size() != requiredBytes) {
      *outTextureData = gpg::AllocMemBuffer(requiredBytes);
    }
    std::memcpy(outTextureData->GetPtr(0U, 0U), image.bytes.data() + top.offset, requiredBytes);
  }

  boost::weak_ptr<void>* DeviceD3D12::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
  {
    static_cast<void>(temporarySharedHandle);
    outWeakHandle->reset();
    return outWeakHandle;
  }

  void DeviceD3D12::Reset(DeviceContext* const context)
  {
    if (mDevice == nullptr) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    gpg::Logf("D3D12: Reset requested");
    if (context != nullptr && context != &mDeviceContext) {
      mDeviceContext.mVSync = context->mVSync;
      const int heads = std::min(context->GetHeadCount(), mDeviceContext.GetHeadCount());
      for (int headIndex = 0; headIndex < heads; ++headIndex) {
        const Head& requested = context->GetHead(static_cast<std::uint32_t>(headIndex));
        Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
        head.mWidth = requested.mWidth;
        head.mHeight = requested.mHeight;
      }
    }
    ReleaseRenderTargets();
    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
      std::uint32_t width = head.mWidth;
      std::uint32_t height = head.mHeight;
      if (width == 0U || height == 0U) {
        RECT client{};
        ::GetClientRect(static_cast<HWND>(head.mWindow), &client);
        width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }
      const HRESULT result = mSwapChains[headIndex]->Resize(width, height);
      if (FAILED(result)) {
        gpg::Warnf("D3D12: resizing head %u to %ux%u failed (HRESULT 0x%08lX)", static_cast<unsigned>(headIndex), width, height,
                   static_cast<unsigned long>(result));
      }
    }
    ResetState();
    CreateRenderTargets();
  }

  void DeviceD3D12::Reset()
  {
    Reset(&mDeviceContext);
  }

  int DeviceD3D12::TestCooperativeLevel()
  {
    return 0;
  }

  void DeviceD3D12::BeginScene() {}

  void DeviceD3D12::EndScene() {}

  void DeviceD3D12::Trace(const char* const format, ...)
  {
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    gpg::Logf("D3D12 trace f%u: %s", mFrameNumber, line);
  }

  void DeviceD3D12::LogDebugMessages()
  {
    if (mInfoQueue == nullptr) {
      return;
    }
    const UINT64 count = mInfoQueue->GetNumStoredMessages();
    for (UINT64 index = 0U; index < count; ++index) {
      SIZE_T length = 0U;
      if (FAILED(mInfoQueue->GetMessage(index, nullptr, &length)) || length == 0U) {
        continue;
      }
      std::vector<char> storage(length);
      auto* const message = reinterpret_cast<D3D12_MESSAGE*>(storage.data());
      if (FAILED(mInfoQueue->GetMessage(index, message, &length)) || message->Severity > D3D12_MESSAGE_SEVERITY_WARNING) {
        continue;
      }
      if (mLoggedMessages.insert(static_cast<int>(message->ID)).second && mLoggedMessages.size() < 200U) {
        gpg::Warnf("D3D12 debug layer: %.*s", static_cast<int>(message->DescriptionByteLength), message->pDescription);
      }
    }
    mInfoQueue->ClearStoredMessages();
  }

  void DeviceD3D12::LogMemoryIfDue()
  {
    // Diagnostics: with FAF_GAL_MEMORY_LOG=<seconds>, the backend's CPU-side
    // memory (buffer and texture copies, upload pages) and the process's
    // private bytes are logged that often.
    static const DWORD interval = [] {
      const char* const value = std::getenv("FAF_GAL_MEMORY_LOG");
      const long seconds = (value != nullptr) ? std::strtol(value, nullptr, 10) : 0L;
      return static_cast<DWORD>((seconds > 0L) ? seconds * 1000L : 0L);
    }();
    static DWORD last = 0U;
    const DWORD now = ::GetTickCount();
    if (interval == 0U || (last != 0U && now - last < interval)) {
      return;
    }
    last = now;
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    static_cast<void>(::K32GetProcessMemoryInfo(
      ::GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)
    ));
    // The address space left, and its largest free block (what a 32-bit
    // process runs out of first).
    std::uint64_t freeBytes = 0U;
    std::uint64_t largestFree = 0U;
    MEMORY_BASIC_INFORMATION region{};
    for (const std::uint8_t* address = nullptr; ::VirtualQuery(address, &region, sizeof(region)) == sizeof(region);) {
      if (region.State == MEM_FREE) {
        freeBytes += region.RegionSize;
        largestFree = std::max<std::uint64_t>(largestFree, region.RegionSize);
      }
      const std::uint8_t* const next = static_cast<const std::uint8_t*>(region.BaseAddress) + region.RegionSize;
      if (next <= address) {
        break;
      }
      address = next;
    }
    constexpr double kMiB = 1.0 / (1024.0 * 1024.0);
    gpg::Logf(
      "D3D12 memory: buffer copies %.1f MB, texture copies %.1f MB, upload pages %.1f MB (%zu), %zu pipelines, %zu retiring, "
      "%llu upload-pressure submissions, %llu passes carried over one, at most %llu submissions in flight; process private "
      "%.1f MB, address space free %.1f MB (largest block %.1f MB)",
      static_cast<double>(backend::LockShadow::TotalBytes()) * kMiB, static_cast<double>(TextureD3D12::CpuCopyBytes()) * kMiB,
      static_cast<double>(mUpload.PageBytes()) * kMiB, mUpload.PageCount(), mPipelines.size(), mGarbage.size(),
      static_cast<unsigned long long>(mUploadSubmits), static_cast<unsigned long long>(mCarriedPasses),
      static_cast<unsigned long long>(mMostInFlight), static_cast<double>(counters.PrivateUsage) * kMiB,
      static_cast<double>(freeBytes) * kMiB, static_cast<double>(largestFree) * kMiB
    );
    mMostInFlight = 0U;
  }

  void DeviceD3D12::DumpBackBufferIfDue()
  {
    // Diagnostics: with FAF_GAL_DUMP_DIR set, head 0's back buffer is written
    // there as a BMP every FAF_GAL_DUMP_SECONDS (default 10) seconds.
    static const char* const directory = std::getenv("FAF_GAL_DUMP_DIR");
    if (directory == nullptr || directory[0] == 0 || mHeadOutputContexts.empty()) {
      return;
    }
    static const DWORD interval = [] {
      const char* const seconds = std::getenv("FAF_GAL_DUMP_SECONDS");
      const long value = (seconds != nullptr) ? std::strtol(seconds, nullptr, 10) : 10L;
      return static_cast<DWORD>((value > 0L) ? value * 1000L : 10000L);
    }();
    const DWORD now = ::GetTickCount();
    if (mLastDumpTick != 0U && now - mLastDumpTick < interval) {
      return;
    }
    if (mLastDumpTick == 0U) {
      mFirstDumpTick = now;
    }
    mLastDumpTick = now;
    char path[MAX_PATH]{};
    std::snprintf(path, sizeof(path), "%s/d3d12_%06lu.bmp", directory, static_cast<unsigned long>((now - mFirstDumpTick) / 1000U));
    imaging::Image image;
    ReadTexture(static_cast<RenderTargetD3D12*>(mHeadOutputContexts.front().surface.get())->Current().resource, image);
    WriteBmp(path, image);
  }

  void DeviceD3D12::Present()
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    ++mFrameNumber;
    {
      static const long start = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_START");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : -1L;
      }();
      static const long frames = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_FRAMES");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : 1L;
      }();
      mTracing = start >= 0L && static_cast<long>(mFrameNumber) >= start && static_cast<long>(mFrameNumber) < start + frames;
      // FAF_GAL_TRACE_FILE=path: the frame after that file appears is traced (and the file removed).
      static const char* const traceFile = std::getenv("FAF_GAL_TRACE_FILE");
      if (traceFile != nullptr && (mFrameNumber % 30U) == 0U && ::GetFileAttributesA(traceFile) != INVALID_FILE_ATTRIBUTES) {
        ::DeleteFileA(traceFile);
        mTracing = true;
      }
    }
    DumpBackBufferIfDue();
    LogDebugMessages();
    LogMemoryIfDue();

    EndProfileFrame();
    for (OutputContext& output : mHeadOutputContexts) {
      Transition(static_cast<RenderTargetD3D12*>(output.surface.get())->Current().resource, D3D12_RESOURCE_STATE_PRESENT);
    }
    FlushBarriers();
    CheckDeviceHresult(__LINE__, mList->Close(), "command list close");
    ID3D12CommandList* const lists[1] = {mList.Get()};
    mQueue->ExecuteCommandLists(1U, lists);

    const bool vsync = mDeviceContext.mVSync;
    for (const std::unique_ptr<dxgi::SwapChain>& swapChain : mSwapChains) {
      CheckDeviceHresult(__LINE__, swapChain->Present(vsync), "present");
    }
    const std::uint64_t serial = ++mSubmittedSerial;
    CheckDeviceHresult(__LINE__, mQueue->Signal(mFence.Get(), serial), "queue signal");
    mFrames[mFrameIndex].serial = serial;
    static_cast<void>(CarryBoundPass());

    // The next frame slot: wait for the GPU to finish what it last recorded.
    mFrameIndex = (mFrameIndex + 1U) % d3d12::kFramesInFlight;
    ++mFrameCount;
    WaitForSerial(mFrames[mFrameIndex].serial);
    CollectCompleted();
    CheckHresult("DeviceD3D12.cpp", __LINE__, mFrames[mFrameIndex].allocator->Reset());
    mFrames[mFrameIndex].views.Reset();
    BeginRecording();
    if (mSkippedDraws != 0U) {
      static int logged = 0;
      if (logged++ < 10) {
        gpg::Warnf("D3D12: %u draw(s) skipped in frame %u (pass without shaders)", mSkippedDraws, mFrameNumber);
      }
      mSkippedDraws = 0U;
    }
  }

  void DeviceD3D12::SetCursor(const CursorContext* const context)
  {
    static_cast<void>(mCursor.SetCursor(*context));
  }

  void DeviceD3D12::InitCursor()
  {
    static_cast<void>(mCursor.InitCursor());
  }

  int DeviceD3D12::ShowCursor(const bool show)
  {
    return mCursor.ShowCursor(show);
  }

  void DeviceD3D12::SetViewport(const D3DVIEWPORT9* const viewport)
  {
    mViewport = *viewport;
    mTargetsDirty = true;
  }

  void DeviceD3D12::GetViewport(D3DVIEWPORT9* const outViewport)
  {
    *outViewport = mViewport;
  }

  void DeviceD3D12::ClearTarget(const OutputContext* const context)
  {
    const RenderTarget* const previousSurface = outputContext_.surface.get();
    Device::ClearTarget(context);
    mTargetsDirty = true;
    // D3D9's SetRenderTarget resets the viewport to the whole new target, and
    // DeviceD3D9::ClearTarget calls it only when the colour target changes
    // (0x008EDB37). The engine relies on both: it clears the 1024x1024
    // shadow map before setting any viewport, and it rebinds a target it is
    // already drawing into while keeping its own viewport. D3D10 dropped this.
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    if (outputContext_.surface != nullptr && outputContext_.surface.get() != previousSurface) {
      width = outputContext_.surface->GetContext()->width_;
      height = outputContext_.surface->GetContext()->height_;
    }
    if (width != 0U && height != 0U) {
      D3DVIEWPORT9 viewport{};
      viewport.Width = width;
      viewport.Height = height;
      viewport.MinZ = 0.0f;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceD3D12::BindTargets()
  {
    D3D12_CPU_DESCRIPTOR_HANDLE renderTarget{};
    D3D12_CPU_DESCRIPTOR_HANDLE depthStencil{};
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    if (outputContext_.surface != nullptr) {
      auto* const target = static_cast<RenderTargetD3D12*>(outputContext_.surface.get());
      RenderTargetD3D12::Buffer& buffer = target->Current();
      Transition(buffer.resource, D3D12_RESOURCE_STATE_RENDER_TARGET);
      renderTarget = buffer.renderTargetView;
      width = target->GetContext()->width_;
      height = target->GetContext()->height_;
    }
    if (outputContext_.depthStencil != nullptr) {
      auto* const depth = static_cast<DepthStencilTargetD3D12*>(outputContext_.depthStencil.get());
      Transition(depth->Resource(), D3D12_RESOURCE_STATE_DEPTH_WRITE);
      depthStencil = depth->DepthView();
      if (width == 0U) {
        width = depth->GetContext()->width_;
        height = depth->GetContext()->height_;
      }
    }
    if (!mTargetsDirty && renderTarget.ptr == mBoundRenderTarget.ptr && depthStencil.ptr == mBoundDepthStencil.ptr) {
      return;
    }
    mTargetsDirty = false;
    mBoundRenderTarget = renderTarget;
    mBoundDepthStencil = depthStencil;
    mList->OMSetRenderTargets(
      (renderTarget.ptr != 0U) ? 1U : 0U, (renderTarget.ptr != 0U) ? &renderTarget : nullptr, FALSE,
      (depthStencil.ptr != 0U) ? &depthStencil : nullptr
    );
    // Shifted by half a pixel: Direct3D 9's pixel centres (Direct3D9PixelCentreShift).
    const float shift = backend::Direct3D9PixelCentreShift();
    const D3D12_VIEWPORT viewport{
      static_cast<float>(mViewport.X) + shift, static_cast<float>(mViewport.Y) + shift, static_cast<float>(mViewport.Width),
      static_cast<float>(mViewport.Height), mViewport.MinZ, mViewport.MaxZ,
    };
    mList->RSSetViewports(1U, &viewport);
    // Direct3D 9 clips to the viewport; the scissor does the same here.
    const LONG right = std::min<LONG>(static_cast<LONG>(mViewport.X + mViewport.Width), static_cast<LONG>(width));
    const LONG bottom = std::min<LONG>(static_cast<LONG>(mViewport.Y + mViewport.Height), static_cast<LONG>(height));
    const D3D12_RECT scissor{static_cast<LONG>(mViewport.X), static_cast<LONG>(mViewport.Y), std::max<LONG>(right, 0), std::max<LONG>(bottom, 0)};
    mList->RSSetScissorRects(1U, &scissor);
  }

  void DeviceD3D12::Clear(
    const bool clearColor, const bool clearDepth, const bool clearStencil, const std::uint32_t packedColor, const float depth, const int stencil
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    constexpr float kScale = 1.0f / 255.0f;
    static const bool clearTest = std::getenv("FAF_GAL_CLEAR_TEST") != nullptr;
    const std::uint32_t shownColor = clearTest ? 0xFF00FF00U : packedColor;
    static_cast<void>(shownColor);
    const float rgba[4] = {
      static_cast<float>((shownColor >> 16U) & 0xFFU) * kScale,
      static_cast<float>((shownColor >> 8U) & 0xFFU) * kScale,
      static_cast<float>(shownColor & 0xFFU) * kScale,
      static_cast<float>((shownColor >> 24U) & 0xFFU) * kScale,
    };
    if (mTracing) {
      Trace("Clear color %d depth %d stencil %d 0x%08X rt %p", clearColor ? 1 : 0, clearDepth ? 1 : 0, clearStencil ? 1 : 0, packedColor,
            outputContext_.surface.get());
    }
    BindTargets();
    FlushBarriers();
    // D3D9's Clear covers the viewport, not the whole target; the clear
    // rectangles of Direct3D 12 do exactly that.
    // Clipped to the bound targets: the engine often clears a 1024x1024
    // shadow target while the 1280x720 screen viewport is still set, and a
    // clear rectangle reaching past the resource is not one Direct3D 12 takes.
    LONG targetWidth = 0x7FFFFFFF;
    LONG targetHeight = 0x7FFFFFFF;
    if (outputContext_.surface != nullptr) {
      targetWidth = static_cast<LONG>(outputContext_.surface->GetContext()->width_);
      targetHeight = static_cast<LONG>(outputContext_.surface->GetContext()->height_);
    }
    if (outputContext_.depthStencil != nullptr) {
      targetWidth = std::min<LONG>(targetWidth, static_cast<LONG>(outputContext_.depthStencil->GetContext()->width_));
      targetHeight = std::min<LONG>(targetHeight, static_cast<LONG>(outputContext_.depthStencil->GetContext()->height_));
    }
    const D3D12_RECT rect{
      std::min<LONG>(static_cast<LONG>(mViewport.X), targetWidth),
      std::min<LONG>(static_cast<LONG>(mViewport.Y), targetHeight),
      std::min<LONG>(static_cast<LONG>(mViewport.X + mViewport.Width), targetWidth),
      std::min<LONG>(static_cast<LONG>(mViewport.Y + mViewport.Height), targetHeight),
    };
    if (rect.right <= rect.left || rect.bottom <= rect.top) {
      return;
    }
    if (clearColor && mBoundRenderTarget.ptr != 0U) {
      mList->ClearRenderTargetView(mBoundRenderTarget, rgba, 1U, &rect);
    }
    D3D12_CLEAR_FLAGS flags{};
    if (clearDepth) {
      flags |= D3D12_CLEAR_FLAG_DEPTH;
    }
    if (clearStencil) {
      flags |= D3D12_CLEAR_FLAG_STENCIL;
    }
    if (flags != 0 && mBoundDepthStencil.ptr != 0U) {
      mList->ClearDepthStencilView(mBoundDepthStencil, flags, depth, static_cast<UINT8>(stencil), 1U, &rect);
    }
  }

  void DeviceD3D12::ClearTextures() {}

  void DeviceD3D12::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
  {
    RecordStateChange();
    mBoundFormat = vertexFormat->formatCode_;
  }

  void DeviceD3D12::SetVertexBuffer(
    const std::uint32_t streamSlot, const boost::shared_ptr<VertexBuffer> vertexBuffer, const int streamFrequencyToken, const int startVertex
  )
  {
    RecordStateChange();
    if (streamSlot >= std::size(mStreams)) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid vertex stream");
    }
    StreamBinding& stream = mStreams[streamSlot];
    stream.buffer = vertexBuffer;
    stream.stride = vertexBuffer->GetContext()->stride_;
    stream.offset = static_cast<std::uint32_t>(startVertex) * stream.stride;
    // As D3D10: slot 0's frequency is the instance count the draws use.
    mStreamFrequencies[streamSlot] = streamFrequencyToken;
  }

  void DeviceD3D12::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
  {
    RecordStateChange();
    mIndexBuffer = indexBuffer;
  }

  void DeviceD3D12::SetFogState(const bool, const Matrix* const, const float, const float, const int) {}

  void DeviceD3D12::SetWireframeState(const bool enabled)
  {
    mWireframe = enabled;
  }

  void DeviceD3D12::SetColorWriteState(const bool writeColor, const bool writeAlpha)
  {
    // The D3D9 backend's mask (`PipelineStateD3D9::SetColorWriteState`).
    if (writeColor) {
      mColorWriteMask = writeAlpha ? 0x0FU : 0x07U;
    } else {
      mColorWriteMask = writeAlpha ? 0x08U : 0x0FU;
    }
  }

  void DeviceD3D12::BeginTechnique()
  {
    TechniquePack(mCurrent.blend, mCurrent.depthStencil, mCurrent.rasterizer);
    std::fill(std::begin(mCurrent.blendFactor), std::end(mCurrent.blendFactor), 0.0f);
    mCurrent.sampleMask = 0xFFFFFFFFU;
    mCurrent.stencilRef = 0U;
  }

  void DeviceD3D12::EndTechnique() {}

  // ---------------------------------------------------------------------------
  // Passes and draws

  DeviceD3D12::ProgramState& DeviceD3D12::StateFor(effects::EffectProgram& program)
  {
    std::shared_ptr<void>& slot = program.BackendState();
    if (slot == nullptr) {
      auto state = std::make_shared<ProgramState>();
      state->samplers = SamplerTable(program.Description().samplers);
      state->viewportParameter = program.FindParameter("faf_ViewportSize");
      slot = state;
    }
    return *static_cast<ProgramState*>(slot.get());
  }

  void DeviceD3D12::BindPass(effects::EffectProgram& program, const std::uint32_t technique, const std::uint32_t pass)
  {
    RecordStateChange();
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const effects::Pass& passDesc = program.Description().techniques[technique].passes[pass];

    // Pass states persist into later passes, as D3D9 render states and
    // Effects 11's Apply leave them.
    if (passDesc.blend.has_value()) {
      mCurrent.blend = *passDesc.blend;
      std::copy(std::begin(passDesc.blendFactor), std::end(passDesc.blendFactor), std::begin(mCurrent.blendFactor));
      mCurrent.sampleMask = passDesc.sampleMask;
    }
    if (passDesc.depthStencil.has_value()) {
      mCurrent.depthStencil = *passDesc.depthStencil;
      mCurrent.stencilRef = passDesc.stencilRef;
    }
    if (passDesc.rasterizer.has_value()) {
      mCurrent.rasterizer = *passDesc.rasterizer;
    }

    BoundPass bound;
    bound.program = &program;
    bound.technique = program.Description().techniques[technique].name.c_str();
    bound.state = mCurrent;
    // FAF's colour-write and wireframe overrides, only where the pass sets no
    // state of its own (see PipelineStateD3D11::ApplyOverrides).
    if (!passDesc.blend.has_value() && mColorWriteMask != 0x0FU && bound.state.blend.writeMask == 0x0FU) {
      bound.state.blend.writeMask = mColorWriteMask;
    }
    if (!passDesc.rasterizer.has_value() && mWireframe && bound.state.rasterizer.fillMode == 3U) {
      bound.state.rasterizer.fillMode = 2U;
    }

    const effects::PassEntries& entries = program.Entries(technique, pass);
    if (entries.vertex >= 0) {
      bound.vertexShader = &program.Shader(static_cast<std::uint32_t>(entries.vertex));
    }
    if (entries.pixel >= 0) {
      bound.pixelShader = &program.Shader(static_cast<std::uint32_t>(entries.pixel));
    }
    bound.valid = bound.vertexShader != nullptr && bound.vertexShader->succeeded &&
      (bound.pixelShader == nullptr || bound.pixelShader->succeeded);

    ProgramState& state = StateFor(program);
    effects::ParameterStore& parameters = program.Parameters();
    if (state.viewportParameter >= 0) {
      // The fixed-function vertex emulation (EffectSourceD3D11.h). It adds the
      // D3D10 half pixel itself, so the origin takes the viewport's shift too.
      const float shift = backend::Direct3D9PixelCentreShift();
      const float size[4] = {
        static_cast<float>(mViewport.X) + shift, static_cast<float>(mViewport.Y) + shift,
        (mViewport.Width != 0U) ? 1.0f / static_cast<float>(mViewport.Width) : 0.0f,
        (mViewport.Height != 0U) ? 1.0f / static_cast<float>(mViewport.Height) : 0.0f,
      };
      if (!std::equal(std::begin(size), std::end(size), std::begin(state.lastViewport))) {
        std::copy(std::begin(size), std::end(size), std::begin(state.lastViewport));
        parameters.SetVector(static_cast<std::uint32_t>(state.viewportParameter), size);
      }
    }

    // $Globals, snapshotted as D3D9's BeginPass and Effects 11's Apply do.
    const std::span<const std::uint8_t> constants = parameters.Constants();
    if (!constants.empty()) {
      if (state.constants == 0U || state.constantsVersion != parameters.Version() || state.constantsSerial != RecordingSerial()) {
        const std::uint64_t bytes = (constants.size() + 255U) & ~static_cast<std::uint64_t>(255U);
        const d3d12::UploadAllocation upload = AllocateUpload(bytes, D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT);
        std::memcpy(upload.cpu, constants.data(), constants.size());
        state.constants = upload.gpu;
        state.constantsCpu = upload.cpu;
        state.constantsVersion = parameters.Version();
        state.constantsSerial = RecordingSerial();
      }
      bound.constants = state.constants;
      bound.constantsCpu = state.constantsCpu;
      bound.constantsBytes = static_cast<std::uint32_t>(constants.size());
      bound.constantsSerial = state.constantsSerial;
    }

    // The texture table: rebuilt when a binding changed or the frame moved on.
    if (state.tableFrame != mFrameCount || state.tableEpoch != mArenaEpoch || state.textureVersion != parameters.TextureVersion() ||
        state.tableSurface != outputContext_.surface.get()) {
      const auto& slots = program.Modern().textures;
      const auto& slotParameters = program.TextureSlotParameters();
      auto bindings = std::make_shared<std::vector<effects::TextureBinding>>();
      bindings->reserve(slots.size());
      D3D12_CPU_DESCRIPTOR_HANDLE cpu{};
      const D3D12_GPU_DESCRIPTOR_HANDLE table = AllocateTable(effects::kMaxTextureSlots, cpu);
      const UINT increment = mFrames[mFrameIndex].views.Increment();
      std::uint32_t written = 0U;
      for (std::size_t index = 0U; index < slots.size() && index < effects::kMaxTextureSlots; ++index) {
        const effects::TextureSlot& slot = slots[index];
        const std::int32_t parameter = slotParameters[index];
        const effects::TextureBinding binding =
          (parameter >= 0) ? parameters.Binding(static_cast<std::uint32_t>(parameter)) : effects::TextureBinding{};
        D3D12_CPU_DESCRIPTOR_HANDLE view = mNullViews[static_cast<int>(slot.dimension)];
        if (binding.texture != nullptr) {
          auto* const texture = static_cast<TextureD3D12*>(binding.texture.get());
          const bool matches = (slot.dimension == effects::TextureDimension::TextureCube) ? texture->IsCube()
            : (slot.dimension == effects::TextureDimension::Texture3D)                   ? texture->IsVolume()
                                                                                         : (!texture->IsCube() && !texture->IsVolume());
          if (matches) {
            view = texture->View();
          }
        } else if (binding.renderTarget != nullptr && slot.dimension == effects::TextureDimension::Texture2D) {
          if (binding.renderTarget.get() == outputContext_.surface.get()) {
            // The pass draws into the target it samples. Direct3D 10 and 11
            // unbind such a view (the shader reads zero); do the same.
            static std::set<std::string> logged;
            const std::string& techniqueName = program.Description().techniques[technique].name;
            if (logged.size() < 32U && logged.insert(techniqueName).second) {
              gpg::Logf("D3D12: %s samples its own colour target; bound as a null view", techniqueName.c_str());
            }
            bindings->push_back(effects::TextureBinding{});
            written = static_cast<std::uint32_t>(index + 1U);
            D3D12_CPU_DESCRIPTOR_HANDLE destination = cpu;
            destination.ptr += static_cast<SIZE_T>(index) * increment;
            mDevice->CopyDescriptorsSimple(1U, destination, view, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
            continue;
          }
          view = static_cast<RenderTargetD3D12*>(binding.renderTarget.get())->Current().shaderResourceView;
        }
        D3D12_CPU_DESCRIPTOR_HANDLE destination = cpu;
        destination.ptr += static_cast<SIZE_T>(index) * increment;
        mDevice->CopyDescriptorsSimple(1U, destination, view, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
        bindings->push_back(binding);
        written = static_cast<std::uint32_t>(index + 1U);
      }
      if (written < effects::kMaxTextureSlots) {
        D3D12_CPU_DESCRIPTOR_HANDLE rest = cpu;
        rest.ptr += static_cast<SIZE_T>(written) * increment;
        mDevice->CopyDescriptorsSimple(effects::kMaxTextureSlots - written, rest, mNullViewRun, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
      }
      state.table = table;
      state.tableBindings = std::move(bindings);
      state.tableFrame = mFrameCount;
      state.tableEpoch = mArenaEpoch;
      state.textureVersion = parameters.TextureVersion();
      state.tableSurface = outputContext_.surface.get();
    }
    bound.textures = state.table;
    bound.tableFrame = state.tableFrame;
    bound.tableEpoch = state.tableEpoch;
    bound.sampled = state.tableBindings;
    bound.samplers = state.samplers;
    bound.techniqueIndex = technique;
    bound.passIndex = pass;
    if (mTracing) {
      Trace(
        "BindPass %s technique %s pass %u valid %d vs %d ps %d constants %u textures %u", program.Name().c_str(),
        program.Description().techniques[technique].name.c_str(), pass, bound.valid ? 1 : 0, entries.vertex, entries.pixel,
        static_cast<unsigned>(constants.size()), static_cast<unsigned>(program.Modern().textures.size())
      );
    }
    mPass = std::move(bound);
  }

  void DeviceD3D12::UnbindPass() {}

  void DeviceD3D12::TransitionSampled(const std::vector<effects::TextureBinding>& bindings)
  {
    for (const effects::TextureBinding& binding : bindings) {
      if (binding.texture != nullptr) {
        Transition(static_cast<TextureD3D12*>(binding.texture.get())->Resource(), kShaderRead);
      } else if (binding.renderTarget != nullptr) {
        RenderTargetD3D12::Buffer& buffer = static_cast<RenderTargetD3D12*>(binding.renderTarget.get())->Current();
        if (buffer.renderTargetView.ptr == mBoundRenderTarget.ptr) {
          static int warned = 0;
          if (warned++ < 4) {
            gpg::Warnf("D3D12: technique %s samples the target it draws into (%p); the read is undefined", mPass.technique,
                       binding.renderTarget.get());
          }
          continue;
        }
        Transition(buffer.resource, kShaderRead);
      }
    }
  }

  ID3D12PipelineState* DeviceD3D12::PipelineFor(const BoundPass& pass, const D3D12_PRIMITIVE_TOPOLOGY_TYPE topologyType)
  {
    DXGI_FORMAT renderFormat = DXGI_FORMAT_UNKNOWN;
    DXGI_FORMAT depthFormat = DXGI_FORMAT_UNKNOWN;
    if (outputContext_.surface != nullptr) {
      renderFormat = static_cast<RenderTargetD3D12*>(outputContext_.surface.get())->Format();
    }
    if (outputContext_.depthStencil != nullptr) {
      depthFormat = static_cast<DepthStencilTargetD3D12*>(outputContext_.depthStencil.get())->DepthFormat();
    }

    KeyWriter key;
    key.Add(pass.vertexShader->key);
    key.Add((pass.pixelShader != nullptr) ? pass.pixelShader->key : 0ULL);
    key.Add(mBoundFormat);
    AddBlend(key, pass.state.blend);
    key.Add(pass.state.sampleMask);
    AddDepth(key, pass.state.depthStencil);
    AddRasterizer(key, pass.state.rasterizer);
    key.Add(renderFormat);
    key.Add(depthFormat);
    key.Add(topologyType);
    auto found = mPipelines.find(key.Key());
    if (found != mPipelines.end()) {
      return found->second.Get();
    }

    // The input layout: the vertex format's elements, plus one element on an
    // unbound slot (which reads zero) for every input the shader takes that
    // the format lacks - D3D9 fed those as zero too (see DeviceD3D11).
    std::vector<D3D12_INPUT_ELEMENT_DESC> elements;
    const std::span<const D3D11_INPUT_ELEMENT_DESC> formatElements =
      (mBoundFormat < d3d11::kVertexFormatCount) ? d3d11::VertexLayoutElements(mBoundFormat) : std::span<const D3D11_INPUT_ELEMENT_DESC>{};
    for (const D3D11_INPUT_ELEMENT_DESC& element : formatElements) {
      elements.push_back(D3D12_INPUT_ELEMENT_DESC{
        element.SemanticName, element.SemanticIndex, element.Format, element.InputSlot, element.AlignedByteOffset,
        static_cast<D3D12_INPUT_CLASSIFICATION>(element.InputSlotClass), element.InstanceDataStepRate,
      });
    }
    for (const effects::ShaderInput& input : pass.vertexShader->inputs) {
      if (input.systemValue) {
        continue;
      }
      const bool provided = std::any_of(formatElements.begin(), formatElements.end(), [&](const D3D11_INPUT_ELEMENT_DESC& element) {
        return element.SemanticIndex == input.index && ::_stricmp(element.SemanticName, input.semantic.c_str()) == 0;
      });
      if (provided) {
        continue;
      }
      elements.push_back(D3D12_INPUT_ELEMENT_DESC{
        input.semantic.c_str(), input.index,
        (input.component == effects::ShaderInput::Component::Uint)   ? DXGI_FORMAT_R32G32B32A32_UINT
          : (input.component == effects::ShaderInput::Component::Sint) ? DXGI_FORMAT_R32G32B32A32_SINT
                                                                       : DXGI_FORMAT_R32G32B32A32_FLOAT,
        kMissingInputSlot, 0U, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0U,
      });
    }

    const effects::BlendDesc& blend = pass.state.blend;
    const effects::DepthStencilDesc& depth = pass.state.depthStencil;
    const effects::RasterizerDesc& rasterizer = pass.state.rasterizer;
    D3D12_GRAPHICS_PIPELINE_STATE_DESC desc{};
    desc.pRootSignature = mRootSignature.Get();
    desc.VS = {pass.vertexShader->code.data(), pass.vertexShader->code.size()};
    if (pass.pixelShader != nullptr) {
      desc.PS = {pass.pixelShader->code.data(), pass.pixelShader->code.size()};
    }
    if (!mSolidPixelShader.empty()) {
      desc.PS = {mSolidPixelShader.data(), mSolidPixelShader.size()};
    }
    desc.BlendState.AlphaToCoverageEnable = blend.alphaToCoverage ? TRUE : FALSE;
    D3D12_RENDER_TARGET_BLEND_DESC& target = desc.BlendState.RenderTarget[0];
    target.BlendEnable = blend.enable ? TRUE : FALSE;
    target.SrcBlend = static_cast<D3D12_BLEND>(blend.srcBlend);
    target.DestBlend = static_cast<D3D12_BLEND>(blend.destBlend);
    target.BlendOp = static_cast<D3D12_BLEND_OP>(blend.blendOp);
    target.SrcBlendAlpha = static_cast<D3D12_BLEND>(blend.srcBlendAlpha);
    target.DestBlendAlpha = static_cast<D3D12_BLEND>(blend.destBlendAlpha);
    target.BlendOpAlpha = static_cast<D3D12_BLEND_OP>(blend.blendOpAlpha);
    target.LogicOp = D3D12_LOGIC_OP_NOOP;
    target.RenderTargetWriteMask = blend.writeMask;
    desc.SampleMask = pass.state.sampleMask;
    desc.RasterizerState.FillMode = static_cast<D3D12_FILL_MODE>(rasterizer.fillMode);
    desc.RasterizerState.CullMode = static_cast<D3D12_CULL_MODE>(rasterizer.cullMode);
    desc.RasterizerState.FrontCounterClockwise = rasterizer.frontCounterClockwise ? TRUE : FALSE;
    desc.RasterizerState.DepthBias = rasterizer.depthBias;
    desc.RasterizerState.DepthBiasClamp = rasterizer.depthBiasClamp;
    desc.RasterizerState.SlopeScaledDepthBias = rasterizer.slopeScaledDepthBias;
    // Direct3D 9 always clips against the near and far planes. The D3D10
    // state packs (d3d10states.compat) turn depth clipping off, which in the
    // shadow pass lets casters outside the light's depth range clamp onto
    // the map as extra shadows; the D3D9 behaviour is kept. Diagnostics:
    // FAF_GAL_D3D10_DEPTH_CLIP=1 takes the packs' setting instead.
    static const bool packDepthClip = std::getenv("FAF_GAL_D3D10_DEPTH_CLIP") != nullptr;
    desc.RasterizerState.DepthClipEnable = (!packDepthClip || rasterizer.depthClipEnable) ? TRUE : FALSE;
    desc.RasterizerState.MultisampleEnable = rasterizer.multisampleEnable ? TRUE : FALSE;
    desc.RasterizerState.AntialiasedLineEnable = rasterizer.antialiasedLineEnable ? TRUE : FALSE;
    if (depthFormat != DXGI_FORMAT_UNKNOWN) {
      desc.DepthStencilState.DepthEnable = depth.depthEnable ? TRUE : FALSE;
      desc.DepthStencilState.DepthWriteMask = depth.depthWrite ? D3D12_DEPTH_WRITE_MASK_ALL : D3D12_DEPTH_WRITE_MASK_ZERO;
      desc.DepthStencilState.DepthFunc = static_cast<D3D12_COMPARISON_FUNC>(depth.depthFunc);
      desc.DepthStencilState.StencilEnable = depth.stencilEnable ? TRUE : FALSE;
      desc.DepthStencilState.StencilReadMask = depth.stencilReadMask;
      desc.DepthStencilState.StencilWriteMask = depth.stencilWriteMask;
      const auto face = [](const effects::StencilFaceDesc& source) {
        return D3D12_DEPTH_STENCILOP_DESC{
          static_cast<D3D12_STENCIL_OP>(source.failOp), static_cast<D3D12_STENCIL_OP>(source.depthFailOp),
          static_cast<D3D12_STENCIL_OP>(source.passOp), static_cast<D3D12_COMPARISON_FUNC>(source.func),
        };
      };
      desc.DepthStencilState.FrontFace = face(depth.front);
      desc.DepthStencilState.BackFace = face(depth.back);
    }
    desc.InputLayout = {elements.data(), static_cast<UINT>(elements.size())};
    desc.IBStripCutValue = D3D12_INDEX_BUFFER_STRIP_CUT_VALUE_DISABLED;
    desc.PrimitiveTopologyType = topologyType;
    desc.NumRenderTargets = (renderFormat != DXGI_FORMAT_UNKNOWN) ? 1U : 0U;
    desc.RTVFormats[0] = renderFormat;
    desc.DSVFormat = depthFormat;
    desc.SampleDesc.Count = 1U;

    ComPtr<ID3D12PipelineState> pipeline;
    const HRESULT result = mDevice->CreateGraphicsPipelineState(&desc, IID_PPV_ARGS(&pipeline));
    if (FAILED(result)) {
      static int logged = 0;
      if (logged++ < 16) {
        gpg::Warnf(
          "D3D12: pipeline for %s (vertex format %u) failed: HRESULT 0x%08lX", pass.program->Name().c_str(), mBoundFormat,
          static_cast<unsigned long>(result)
        );
      }
    }
    // A failure is cached too, so a broken pass costs one attempt.
    return mPipelines.emplace(std::move(key.Key()), pipeline).first->second.Get();
  }

  bool DeviceD3D12::PrepareDraw(const std::uint32_t topologyToken)
  {
    if (topologyToken == 0U || topologyToken >= std::size(kTopologyByToken)) {
      ThrowError("DeviceD3D12.cpp", __LINE__, "invalid topology specified");
    }
    if (!mPass.valid) {
      ++mSkippedDraws;
      return false;
    }
    const D3D_PRIMITIVE_TOPOLOGY topology = kTopologyByToken[topologyToken];
    if (mTracing) {
      Trace(
        "draw topology %u format %u rt %p ds %p viewport %lu,%lu %lux%lu z %g..%g", topologyToken, mBoundFormat,
        outputContext_.surface.get(), outputContext_.depthStencil.get(), mViewport.X, mViewport.Y, mViewport.Width, mViewport.Height,
        mViewport.MinZ, mViewport.MaxZ
      );
    }
    BindTargets();
    if (mPass.sampled != nullptr) {
      TransitionSampled(*mPass.sampled);
    }
    ID3D12PipelineState* const pipeline = PipelineFor(mPass, TopologyType(topology));
    if (pipeline == nullptr) {
      ++mSkippedDraws;
      return false;
    }

    // Vertex streams: every slot the format uses, and the zero slot.
    D3D12_VERTEX_BUFFER_VIEW views[16]{};
    UINT slotCount = 0U;
    const std::span<const D3D11_INPUT_ELEMENT_DESC> formatElements =
      (mBoundFormat < d3d11::kVertexFormatCount) ? d3d11::VertexLayoutElements(mBoundFormat) : std::span<const D3D11_INPUT_ELEMENT_DESC>{};
    for (const D3D11_INPUT_ELEMENT_DESC& element : formatElements) {
      slotCount = std::max<UINT>(slotCount, element.InputSlot + 1U);
    }
    for (UINT slot = 0U; slot < slotCount; ++slot) {
      StreamBinding& stream = mStreams[slot];
      if (stream.buffer == nullptr) {
        continue;
      }
      BufferStorageD3D12& storage = static_cast<VertexBufferD3D12*>(stream.buffer.get())->Storage();
      const D3D12_GPU_VIRTUAL_ADDRESS address = storage.PrepareForDraw(*this);
      views[slot].BufferLocation = address + stream.offset;
      views[slot].SizeInBytes = (storage.ByteWidth() > stream.offset) ? storage.ByteWidth() - stream.offset : 0U;
      views[slot].StrideInBytes = stream.stride;
    }
    FlushBarriers();
    mList->IASetVertexBuffers(0U, slotCount, views);
    const D3D12_VERTEX_BUFFER_VIEW zero{};
    mList->IASetVertexBuffers(kMissingInputSlot, 1U, &zero);

    mList->SetPipelineState(pipeline);
    mList->SetGraphicsRootConstantBufferView(0U, mPass.constants);
    mList->SetGraphicsRootDescriptorTable(1U, mPass.textures);
    mList->SetGraphicsRootDescriptorTable(2U, mPass.samplers);
    mList->IASetPrimitiveTopology(topology);
    mList->OMSetBlendFactor(mPass.state.blendFactor);
    mList->OMSetStencilRef(mPass.state.stencilRef);
    if (mDredEnabled) {
      MarkDraw((mPass.program->Name().substr(mPass.program->Name().find_last_of("\\/") + 1U) + ":" + mPass.technique).c_str());
    }
    return true;
  }

  void DeviceD3D12::DrawIndexedPrimitive(const DrawIndexedContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    if (mIndexBuffer == nullptr) {
      return;
    }
    RefreshStalePass(); // before anything is prepared: binding may submit
    const DrawPreparation preparing(mPreparingDraw);
    auto* const indexBuffer = static_cast<IndexBufferD3D12*>(mIndexBuffer.get());
    const D3D12_GPU_VIRTUAL_ADDRESS indexAddress = indexBuffer->Storage().PrepareForDraw(*this);
    if (!PrepareDraw(static_cast<std::uint32_t>(context->topology_))) {
      return;
    }
    const D3D12_INDEX_BUFFER_VIEW indexView{indexAddress, indexBuffer->Storage().ByteWidth(), indexBuffer->IndexFormat()};
    mList->IASetIndexBuffer(&indexView);
    // D3D10 passes base vertex 0 (0x008FD16E); D3D9 passes BaseVertexIndex.
    const UINT instances = InstanceCount(mStreamFrequencies[0]);
    mList->DrawIndexedInstanced(context->indexCount_, instances, context->startIndex_, context->baseVertexIndex_, 0U);
    FinishDraw();
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  void DeviceD3D12::DrawPrimitive(const DrawContext* const context)
  {
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    RefreshStalePass(); // before anything is prepared: binding may submit
    const DrawPreparation preparing(mPreparingDraw);
    if (!PrepareDraw(static_cast<std::uint32_t>(context->topology_))) {
      return;
    }
    const UINT instances = InstanceCount(mStreamFrequencies[0]);
    mList->DrawInstanced(context->vertexCount_, instances, context->startVertex_, 0U);
    FinishDraw();
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  bool DeviceD3D12::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
  {
    const DXGI_FORMAT format = dxgi::TextureFormatToDxgi(textureFormat);
    if (mDevice == nullptr || format == DXGI_FORMAT_UNKNOWN) {
      return false;
    }
    D3D12_FEATURE_DATA_FORMAT_SUPPORT support{};
    support.Format = format;
    return SUCCEEDED(mDevice->CheckFeatureSupport(D3D12_FEATURE_FORMAT_SUPPORT, &support, sizeof(support))) &&
      (support.Support1 & D3D12_FORMAT_SUPPORT1_TEXTURE2D) != 0 && (support.Support1 & D3D12_FORMAT_SUPPORT1_SHADER_SAMPLE) != 0;
  }
} // namespace gpg::gal

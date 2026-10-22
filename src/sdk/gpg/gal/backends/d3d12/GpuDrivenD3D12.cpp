// FAF addition, not in the shipped binary (see GpuDrivenD3D12.h): DeviceD3D12's
// GPU-driven members - buffers shaders read and compute shaders write,
// engine-owned programs that pull their vertices from them, compute
// dispatches, indirect draws, and the render profiler's GPU timestamps.

#include "GpuDrivenD3D12.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "DeviceD3D12.h"
#include "ResourcesD3D12.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/effects/ShaderCompiler.h"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using backend::CheckHresult;
  using backend::ThrowError;

  namespace
  {
    constexpr D3D12_RESOURCE_STATES kBufferRead =
      D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE | D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
    constexpr D3D12_RESOURCE_STATES kTextureRead =
      D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE | D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
    constexpr std::uint32_t kReadSlots = kGpuMaxReadBuffers + kGpuMaxTextures; // t0..t5

    /** The Direct3D 12 device, while it exists (buffers can outlive it at exit). */
    [[nodiscard]] DeviceD3D12* ActiveDevice() noexcept
    {
      Device* const device = Device::GetInstance();
      if (device == nullptr) {
        return nullptr;
      }
      const DeviceContext* const context = device->GetDeviceContext();
      return (context != nullptr && context->mDeviceType == DeviceApi::Direct3D12) ? static_cast<DeviceD3D12*>(device) : nullptr;
    }

    [[nodiscard]] D3D12_COMPARISON_FUNC ToD3D12(const GpuCompare compare) noexcept
    {
      // GpuCompare follows D3D12_COMPARISON_FUNC's order, one below it.
      return static_cast<D3D12_COMPARISON_FUNC>(static_cast<int>(compare) + 1);
    }

    [[nodiscard]] D3D12_STENCIL_OP ToD3D12(const GpuStencilOp op) noexcept
    {
      switch (op) {
      case GpuStencilOp::Zero:
        return D3D12_STENCIL_OP_ZERO;
      case GpuStencilOp::Replace:
        return D3D12_STENCIL_OP_REPLACE;
      case GpuStencilOp::IncrementSaturate:
        return D3D12_STENCIL_OP_INCR_SAT;
      case GpuStencilOp::DecrementSaturate:
        return D3D12_STENCIL_OP_DECR_SAT;
      case GpuStencilOp::Invert:
        return D3D12_STENCIL_OP_INVERT;
      case GpuStencilOp::Increment:
        return D3D12_STENCIL_OP_INCR;
      case GpuStencilOp::Decrement:
        return D3D12_STENCIL_OP_DECR;
      case GpuStencilOp::Keep:
      default:
        return D3D12_STENCIL_OP_KEEP;
      }
    }

    [[nodiscard]] D3D12_DEPTH_STENCILOP_DESC ToD3D12(const GpuStencilFace& face) noexcept
    {
      return D3D12_DEPTH_STENCILOP_DESC{ToD3D12(face.fail), ToD3D12(face.depthFail), ToD3D12(face.pass), ToD3D12(face.func)};
    }

    [[nodiscard]] std::vector<std::uint8_t> CompileStage(const GpuProgramDesc& desc, const char* const entry, const wchar_t* const profile)
    {
      const effects::ShaderCompiler& compiler = effects::ShaderCompiler::Instance();
      // HLSL 2018 and no row-major default: the sources are written for FXC
      // (the D3D11 backend compiles them with d3dcompiler).
      const effects::CompiledShader compiled =
        compiler.CompileRaw(std::string_view(desc.source, desc.sourceBytes), entry, profile, {L"-HV", L"2018"});
      if (!compiled.succeeded) {
        gpg::Warnf("D3D12: GPU program %s, %ls %s does not compile: %s", desc.name, profile, entry, compiled.messages.c_str());
        return {};
      }
      return compiled.code;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // GpuBufferD3D12

  GpuBufferD3D12::GpuBufferD3D12(DeviceD3D12& device, const GpuBufferDesc& desc)
    : GpuBuffer(desc)
  {
    const bool indirect = desc.kind == GpuBufferKind::IndirectArgs;
    const std::uint32_t stride = indirect ? 16U : std::max(desc.stride, 4U);
    const std::uint32_t capacity = std::max(desc.capacity, 1U);
    mDesc.stride = stride;
    mDesc.capacity = capacity;
    mByteWidth = static_cast<std::uint64_t>(stride) * capacity;

    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC resourceDesc{};
    resourceDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    resourceDesc.Width = mByteWidth;
    resourceDesc.Height = 1U;
    resourceDesc.DepthOrArraySize = 1U;
    resourceDesc.MipLevels = 1U;
    resourceDesc.SampleDesc.Count = 1U;
    resourceDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    resourceDesc.Flags = desc.shaderWrite ? D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS : D3D12_RESOURCE_FLAG_NONE;
    CheckHresult(
      "GpuDrivenD3D12.cpp", __LINE__,
      device.Native()->CreateCommittedResource(
        &heap, D3D12_HEAP_FLAG_NONE, &resourceDesc, D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&mResource.resource)
      )
    );
    mResource.state = D3D12_RESOURCE_STATE_COMMON;

    // Indirect arguments are a ByteAddressBuffer to the shaders, the rest structured.
    D3D12_SHADER_RESOURCE_VIEW_DESC view{};
    view.ViewDimension = D3D12_SRV_DIMENSION_BUFFER;
    view.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    if (indirect) {
      view.Format = DXGI_FORMAT_R32_TYPELESS;
      view.Buffer.NumElements = static_cast<UINT>(mByteWidth / 4U);
      view.Buffer.Flags = D3D12_BUFFER_SRV_FLAG_RAW;
    } else {
      view.Format = DXGI_FORMAT_UNKNOWN;
      view.Buffer.NumElements = capacity;
      view.Buffer.StructureByteStride = stride;
    }
    mShaderView = device.AllocateDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    device.Native()->CreateShaderResourceView(mResource.resource.Get(), &view, mShaderView);

    if (desc.shaderWrite) {
      D3D12_UNORDERED_ACCESS_VIEW_DESC write{};
      write.ViewDimension = D3D12_UAV_DIMENSION_BUFFER;
      if (indirect) {
        write.Format = DXGI_FORMAT_R32_TYPELESS;
        write.Buffer.NumElements = static_cast<UINT>(mByteWidth / 4U);
        write.Buffer.Flags = D3D12_BUFFER_UAV_FLAG_RAW;
      } else {
        write.Format = DXGI_FORMAT_UNKNOWN;
        write.Buffer.NumElements = capacity;
        write.Buffer.StructureByteStride = stride;
      }
      mWriteView = device.AllocateDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
      device.Native()->CreateUnorderedAccessView(mResource.resource.Get(), nullptr, &write, mWriteView);
    }
  }

  GpuBufferD3D12::~GpuBufferD3D12()
  {
    if (DeviceD3D12* const device = ActiveDevice()) {
      if (mResource.resource != nullptr) {
        device->Retire(std::move(mResource.resource));
      }
      if (mShaderView.ptr != 0U) {
        device->RetireDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, mShaderView);
      }
      if (mWriteView.ptr != 0U) {
        device->RetireDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, mWriteView);
      }
    }
  }

  // Programs are created once by their renderers and live as long as the
  // device; their pipelines are released with them.
  GpuProgramD3D12::~GpuProgramD3D12() = default;

  // ---------------------------------------------------------------------------
  // Device set-up

  void DeviceD3D12::CreateGpuDrivenObjects()
  {
    // One root signature per sampler kind: b0 root CBV, t0..t5 table, u0..u1 table, s0 static.
    D3D12_DESCRIPTOR_RANGE reads{};
    reads.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
    reads.NumDescriptors = kReadSlots;
    D3D12_DESCRIPTOR_RANGE writes{};
    writes.RangeType = D3D12_DESCRIPTOR_RANGE_TYPE_UAV;
    writes.NumDescriptors = kGpuMaxWriteBuffers;
    D3D12_ROOT_PARAMETER parameters[3]{};
    parameters[0].ParameterType = D3D12_ROOT_PARAMETER_TYPE_CBV;
    parameters[0].Descriptor.ShaderRegister = 0U;
    parameters[0].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[1].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[1].DescriptorTable.NumDescriptorRanges = 1U;
    parameters[1].DescriptorTable.pDescriptorRanges = &reads;
    parameters[1].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;
    parameters[2].ParameterType = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
    parameters[2].DescriptorTable.NumDescriptorRanges = 1U;
    parameters[2].DescriptorTable.pDescriptorRanges = &writes;
    parameters[2].ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

    for (std::uint32_t kind = 0U; kind < 3U; ++kind) {
      D3D12_STATIC_SAMPLER_DESC sampler{};
      sampler.Filter = (static_cast<GpuSampler>(kind) == GpuSampler::PointClamp) ? D3D12_FILTER_MIN_MAG_MIP_POINT
                                                                                 : D3D12_FILTER_MIN_MAG_MIP_LINEAR;
      const D3D12_TEXTURE_ADDRESS_MODE address =
        (static_cast<GpuSampler>(kind) == GpuSampler::LinearWrap) ? D3D12_TEXTURE_ADDRESS_MODE_WRAP : D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
      sampler.AddressU = address;
      sampler.AddressV = address;
      sampler.AddressW = address;
      sampler.MaxAnisotropy = 1U;
      sampler.ComparisonFunc = D3D12_COMPARISON_FUNC_NEVER;
      sampler.MaxLOD = D3D12_FLOAT32_MAX;
      sampler.ShaderRegister = 0U;
      sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_ALL;

      D3D12_ROOT_SIGNATURE_DESC desc{};
      desc.NumParameters = 3U;
      desc.pParameters = parameters;
      desc.NumStaticSamplers = 1U;
      desc.pStaticSamplers = &sampler;
      ComPtr<ID3DBlob> serialized;
      ComPtr<ID3DBlob> errors;
      if (FAILED(mLibrary.serializeRootSignature(&desc, D3D_ROOT_SIGNATURE_VERSION_1, &serialized, &errors))) {
        gpg::Warnf("D3D12: no root signature for GPU-driven programs; they stay off");
        return;
      }
      CheckHresult(
        "GpuDrivenD3D12.cpp", __LINE__,
        mDevice->CreateRootSignature(0U, serialized->GetBufferPointer(), serialized->GetBufferSize(), IID_PPV_ARGS(&mGpuRootSignatures[kind]))
      );
    }

    D3D12_INDIRECT_ARGUMENT_DESC draw{};
    draw.Type = D3D12_INDIRECT_ARGUMENT_TYPE_DRAW;
    D3D12_COMMAND_SIGNATURE_DESC signature{};
    signature.ByteStride = sizeof(D3D12_DRAW_ARGUMENTS);
    signature.NumArgumentDescs = 1U;
    signature.pArgumentDescs = &draw;
    CheckHresult("GpuDrivenD3D12.cpp", __LINE__, mDevice->CreateCommandSignature(&signature, nullptr, IID_PPV_ARGS(&mDrawIndirectSignature)));

    // Null views for unbound buffer slots (a texture-typed null view is not a buffer).
    D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heapDesc.NumDescriptors = 2U;
    CheckHresult("GpuDrivenD3D12.cpp", __LINE__, mDevice->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&mGpuNullHeap)));
    mNullBufferView = mGpuNullHeap->GetCPUDescriptorHandleForHeapStart();
    mNullWriteView = mNullBufferView;
    mNullWriteView.ptr += mDevice->GetDescriptorHandleIncrementSize(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    D3D12_SHADER_RESOURCE_VIEW_DESC nullView{};
    nullView.Format = DXGI_FORMAT_R32_UINT;
    nullView.ViewDimension = D3D12_SRV_DIMENSION_BUFFER;
    nullView.Shader4ComponentMapping = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
    nullView.Buffer.NumElements = 1U;
    mDevice->CreateShaderResourceView(nullptr, &nullView, mNullBufferView);
    D3D12_UNORDERED_ACCESS_VIEW_DESC nullWrite{};
    nullWrite.Format = DXGI_FORMAT_R32_UINT;
    nullWrite.ViewDimension = D3D12_UAV_DIMENSION_BUFFER;
    nullWrite.Buffer.NumElements = 1U;
    mDevice->CreateUnorderedAccessView(nullptr, nullptr, &nullWrite, mNullWriteView);

    // CopyVertexBufferRegion is CopyBufferRegion on the direct list.
    mGpuFeatures = kGpuFeatureVertexPulling | kGpuFeatureCompute | kGpuFeatureIndirectDraw | kGpuFeatureBufferCopy;

    // Timestamps: two per region (and two for the frame) in each of kProfileFrames frames.
    UINT64 frequency = 0U;
    D3D12_QUERY_HEAP_DESC queries{};
    queries.Type = D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
    queries.Count = kProfileFrames * 2U * (kMaxTimedRegionsPerFrame + 1U);
    D3D12_HEAP_PROPERTIES readbackHeap{};
    readbackHeap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC readbackDesc{};
    readbackDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    readbackDesc.Width = static_cast<UINT64>(queries.Count) * sizeof(UINT64);
    readbackDesc.Height = 1U;
    readbackDesc.DepthOrArraySize = 1U;
    readbackDesc.MipLevels = 1U;
    readbackDesc.SampleDesc.Count = 1U;
    readbackDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    if (SUCCEEDED(mQueue->GetTimestampFrequency(&frequency)) && frequency != 0U &&
        SUCCEEDED(mDevice->CreateQueryHeap(&queries, IID_PPV_ARGS(&mTimestampHeap))) &&
        SUCCEEDED(mDevice->CreateCommittedResource(
          &readbackHeap, D3D12_HEAP_FLAG_NONE, &readbackDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&mTimestampReadback)
        ))) {
      mTimestampToMilliseconds = 1000.0 / static_cast<double>(frequency);
      mGpuFeatures |= kGpuFeatureTimestamps;
    }
  }

  void DeviceD3D12::ReleaseGpuDrivenObjects() noexcept
  {
    mGpuFeatures = 0U;
    for (ComPtr<ID3D12RootSignature>& signature : mGpuRootSignatures) {
      signature.Reset();
    }
    mDrawIndirectSignature.Reset();
    mGpuNullHeap.Reset();
    mTimestampHeap.Reset();
    mTimestampReadback.Reset();
    for (ProfileFrame& frame : mProfileFrames) {
      frame = ProfileFrame{};
    }
    mOpenRegions.clear();
  }

  // ---------------------------------------------------------------------------
  // Buffers and programs

  std::uint32_t DeviceD3D12::GetGpuDrivenFeatures() const
  {
    return mGpuFeatures;
  }

  std::uint32_t DeviceD3D12::GetGpuDrivenVerified() const
  {
    // Each passed its parity checks on Direct3D 12 (docs/RENDERER_BACKENDS.md, GPU-driven paths):
    // FAF_ICON_GPU_CHECK readback with selection changes (30k overview and view, 0 differ), a paused
    // same-process A/B against the path off (world, brackets, icons and minimap pixel-identical) and
    // the hovered-unit states against Direct3D 11; projectile icons by a paused A/B of the 2k air
    // fight at zooms 160 and 400 (only the pause button and chat line differ). Not
    // kGpuPathParticleBatch: the paused A/B still shows extra particle specks with it on, as on
    // Direct3D 11.
    return kGpuPathStrategicIcons | kGpuPathIconClassify | kGpuPathFogOfWar | kGpuPathSelectBrackets | kGpuPathProjectileIcons;
  }

  boost::shared_ptr<GpuBuffer> DeviceD3D12::CreateGpuBuffer(const GpuBufferDesc& desc)
  {
    if ((mGpuFeatures & kGpuFeatureVertexPulling) == 0U) {
      return {};
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    return boost::shared_ptr<GpuBuffer>(new GpuBufferD3D12(*this, desc));
  }

  void DeviceD3D12::UpdateGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, const void* const data)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || data == nullptr || firstElement >= desc.capacity) {
      return;
    }
    const std::uint32_t elements = std::min(count, desc.capacity - firstElement);
    const std::uint64_t bytes = static_cast<std::uint64_t>(elements) * desc.stride;
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    UploadBuffer(static_cast<GpuBufferD3D12&>(buffer).Resource(), static_cast<std::uint64_t>(firstElement) * desc.stride, data, bytes);
    RecordUpload(bytes);
  }

  bool DeviceD3D12::ReadGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, void* const out)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || out == nullptr || firstElement >= desc.capacity || count > desc.capacity - firstElement) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const std::uint64_t bytes = static_cast<std::uint64_t>(count) * desc.stride;
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_READBACK;
    D3D12_RESOURCE_DESC readbackDesc{};
    readbackDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    readbackDesc.Width = bytes;
    readbackDesc.Height = 1U;
    readbackDesc.DepthOrArraySize = 1U;
    readbackDesc.MipLevels = 1U;
    readbackDesc.SampleDesc.Count = 1U;
    readbackDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ComPtr<ID3D12Resource> readback;
    if (FAILED(mDevice->CreateCommittedResource(
          &heap, D3D12_HEAP_FLAG_NONE, &readbackDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&readback)
        ))) {
      return false;
    }
    d3d12::TrackedResource& source = static_cast<GpuBufferD3D12&>(buffer).Resource();
    Transition(source, D3D12_RESOURCE_STATE_COPY_SOURCE);
    FlushBarriers();
    mList->CopyBufferRegion(readback.Get(), 0U, source.resource.Get(), static_cast<UINT64>(firstElement) * desc.stride, bytes);
    Submit(true);
    void* mapped = nullptr;
    const D3D12_RANGE readRange{0U, static_cast<SIZE_T>(bytes)};
    if (FAILED(readback->Map(0U, &readRange, &mapped))) {
      return false;
    }
    std::memcpy(out, mapped, static_cast<std::size_t>(bytes));
    const D3D12_RANGE noWrite{0U, 0U};
    readback->Unmap(0U, &noWrite);
    return true;
  }

  boost::shared_ptr<GpuProgram> DeviceD3D12::CreateGpuProgram(const GpuProgramDesc& desc)
  {
    if ((mGpuFeatures & kGpuFeatureVertexPulling) == 0U || desc.source == nullptr) {
      return {};
    }
    boost::shared_ptr<GpuProgramD3D12> program(new GpuProgramD3D12());
    program->mDesc = desc;
    program->mName = (desc.name != nullptr) ? desc.name : "";
    program->mDesc.name = nullptr;
    program->mDesc.source = nullptr;
    program->mDesc.sourceBytes = 0U;

    if (desc.computeEntry != nullptr) {
      program->mComputeCode = CompileStage(desc, desc.computeEntry, L"cs_6_0");
      if (program->mComputeCode.empty()) {
        return {};
      }
      D3D12_COMPUTE_PIPELINE_STATE_DESC pipeline{};
      pipeline.pRootSignature = mGpuRootSignatures[static_cast<int>(desc.sampler)].Get();
      pipeline.CS = {program->mComputeCode.data(), program->mComputeCode.size()};
      const std::lock_guard<std::recursive_mutex> lock(mMutex);
      if (FAILED(mDevice->CreateComputePipelineState(&pipeline, IID_PPV_ARGS(&program->mCompute)))) {
        gpg::Warnf("D3D12: GPU program %s: no compute pipeline", program->mName.c_str());
        return {};
      }
      return program;
    }

    if (desc.vertexEntry == nullptr || desc.pixelEntry == nullptr) {
      return {};
    }
    program->mVertexCode = CompileStage(desc, desc.vertexEntry, L"vs_6_0");
    program->mPixelCode = CompileStage(desc, desc.pixelEntry, L"ps_6_0");
    if (program->mVertexCode.empty() || program->mPixelCode.empty()) {
      return {};
    }
    return program;
  }

  ID3D12PipelineState* DeviceD3D12::GpuPipelineFor(GpuProgramD3D12& program)
  {
    DXGI_FORMAT renderFormat = DXGI_FORMAT_UNKNOWN;
    DXGI_FORMAT depthFormat = DXGI_FORMAT_UNKNOWN;
    if (outputContext_.surface != nullptr) {
      renderFormat = static_cast<RenderTargetD3D12*>(outputContext_.surface.get())->Format();
    }
    if (outputContext_.depthStencil != nullptr) {
      depthFormat = static_cast<DepthStencilTargetD3D12*>(outputContext_.depthStencil.get())->DepthFormat();
    }
    const GpuProgramDesc& state = program.mDesc;
    // inheritDepthStencil: the depth-stencil state the engine's passes left
    // bound (they persist, as D3D9 render states do), baked in at the draw.
    const bool inherit = state.inheritDepthStencil && depthFormat != DXGI_FORMAT_UNKNOWN;
    const std::uint64_t depthKey = inherit ? mCurrent.depthStencil.PackedKey() : 0U;
    ComPtr<ID3D12PipelineState>& pipeline = program.mPipelines[{renderFormat, depthFormat, depthKey}];
    if (pipeline != nullptr) {
      return pipeline.Get();
    }

    D3D12_GRAPHICS_PIPELINE_STATE_DESC desc{};
    desc.pRootSignature = mGpuRootSignatures[static_cast<int>(state.sampler)].Get();
    desc.VS = {program.mVertexCode.data(), program.mVertexCode.size()};
    desc.PS = {program.mPixelCode.data(), program.mPixelCode.size()};
    D3D12_RENDER_TARGET_BLEND_DESC& target = desc.BlendState.RenderTarget[0];
    target.BlendEnable = (state.blend != GpuBlend::Opaque) ? TRUE : FALSE;
    target.SrcBlend = (state.blend != GpuBlend::Opaque) ? D3D12_BLEND_SRC_ALPHA : D3D12_BLEND_ONE;
    target.DestBlend = (state.blend == GpuBlend::AlphaBlend) ? D3D12_BLEND_INV_SRC_ALPHA
      : (state.blend == GpuBlend::Additive)                   ? D3D12_BLEND_ONE
                                                              : D3D12_BLEND_ZERO;
    target.BlendOp = D3D12_BLEND_OP_ADD;
    target.SrcBlendAlpha = D3D12_BLEND_ONE;
    target.DestBlendAlpha = D3D12_BLEND_ZERO;
    target.BlendOpAlpha = D3D12_BLEND_OP_ADD;
    target.LogicOp = D3D12_LOGIC_OP_NOOP;
    target.RenderTargetWriteMask = state.colorWriteMask;
    desc.SampleMask = 0xFFFFFFFFU;
    desc.RasterizerState.FillMode = D3D12_FILL_MODE_SOLID;
    desc.RasterizerState.CullMode = state.cullBackFaces ? D3D12_CULL_MODE_BACK : D3D12_CULL_MODE_NONE;
    desc.RasterizerState.FrontCounterClockwise = FALSE;
    desc.RasterizerState.DepthClipEnable = state.depthClip ? TRUE : FALSE;
    desc.RasterizerState.MultisampleEnable = TRUE;
    if (inherit) {
      const effects::DepthStencilDesc& depth = mCurrent.depthStencil;
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
      desc.DSVFormat = depthFormat;
    } else if (depthFormat != DXGI_FORMAT_UNKNOWN) {
      desc.DepthStencilState.DepthEnable = state.depthTest ? TRUE : FALSE;
      desc.DepthStencilState.DepthWriteMask = state.depthWrite ? D3D12_DEPTH_WRITE_MASK_ALL : D3D12_DEPTH_WRITE_MASK_ZERO;
      desc.DepthStencilState.DepthFunc = ToD3D12(state.depthFunc);
      desc.DepthStencilState.StencilEnable = state.stencil.enable ? TRUE : FALSE;
      desc.DepthStencilState.StencilReadMask = state.stencil.readMask;
      desc.DepthStencilState.StencilWriteMask = state.stencil.writeMask;
      desc.DepthStencilState.FrontFace = ToD3D12(state.stencil.front);
      desc.DepthStencilState.BackFace = ToD3D12(state.stencil.back);
      desc.DSVFormat = depthFormat;
    }
    desc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
    desc.NumRenderTargets = (renderFormat != DXGI_FORMAT_UNKNOWN) ? 1U : 0U;
    desc.RTVFormats[0] = renderFormat;
    desc.SampleDesc.Count = 1U;
    if (FAILED(mDevice->CreateGraphicsPipelineState(&desc, IID_PPV_ARGS(&pipeline)))) {
      gpg::Warnf("D3D12: GPU program %s: no pipeline for render format %d, depth format %d", program.mName.c_str(),
                 static_cast<int>(renderFormat), static_cast<int>(depthFormat));
      return nullptr;
    }
    return pipeline.Get();
  }

  void DeviceD3D12::PrepareGpuBindings(
    const GpuBindings& bindings, const bool compute, D3D12_GPU_VIRTUAL_ADDRESS& constants, D3D12_GPU_DESCRIPTOR_HANDLE& readTable,
    D3D12_GPU_DESCRIPTOR_HANDLE& writeTable
  )
  {
    // Uploads first: an allocation may hand the recorded commands to the GPU.
    constants = 0U;
    if (bindings.constants != nullptr && bindings.constantBytes != 0U) {
      const std::uint32_t bytes = std::min(bindings.constantBytes, kGpuMaxConstantBytes);
      const d3d12::UploadAllocation upload = AllocateUpload((bytes + 255U) & ~255U, D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT);
      std::memcpy(upload.cpu, bindings.constants, bytes);
      constants = upload.gpu;
      RecordUpload(bytes);
    } else {
      const d3d12::UploadAllocation upload = AllocateUpload(256U, D3D12_CONSTANT_BUFFER_DATA_PLACEMENT_ALIGNMENT);
      std::memset(upload.cpu, 0, 256U);
      constants = upload.gpu;
    }

    D3D12_CPU_DESCRIPTOR_HANDLE cpu{};
    readTable = AllocateTable(kReadSlots, cpu);
    const UINT increment = mFrames[mFrameIndex].views.Increment();
    const D3D12_RESOURCE_STATES bufferRead = compute ? D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE : kBufferRead;
    for (std::uint32_t slot = 0U; slot < kReadSlots; ++slot) {
      D3D12_CPU_DESCRIPTOR_HANDLE view = (slot < kGpuMaxReadBuffers) ? mNullBufferView : mNullViews[0];
      if (slot < kGpuMaxReadBuffers) {
        if (auto* const buffer = static_cast<GpuBufferD3D12*>(bindings.readBuffers[slot])) {
          view = buffer->ShaderView();
          Transition(buffer->Resource(), bufferRead);
        }
      } else if (auto* const texture = static_cast<TextureD3D12*>(bindings.textures[slot - kGpuMaxReadBuffers])) {
        view = texture->View();
        Transition(texture->Resource(), kTextureRead);
      }
      D3D12_CPU_DESCRIPTOR_HANDLE destination = cpu;
      destination.ptr += static_cast<SIZE_T>(slot) * increment;
      mDevice->CopyDescriptorsSimple(1U, destination, view, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    }

    writeTable = AllocateTable(kGpuMaxWriteBuffers, cpu);
    for (std::uint32_t slot = 0U; slot < kGpuMaxWriteBuffers; ++slot) {
      D3D12_CPU_DESCRIPTOR_HANDLE view = mNullWriteView;
      if (auto* const buffer = static_cast<GpuBufferD3D12*>(bindings.writeBuffers[slot]); buffer != nullptr && compute) {
        if (buffer->WriteView().ptr != 0U) {
          view = buffer->WriteView();
          Transition(buffer->Resource(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
        }
      }
      D3D12_CPU_DESCRIPTOR_HANDLE destination = cpu;
      destination.ptr += static_cast<SIZE_T>(slot) * increment;
      mDevice->CopyDescriptorsSimple(1U, destination, view, D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    }
  }

  void DeviceD3D12::DrawGpuProgram(const GpuDrawCall& call)
  {
    auto* const program = static_cast<GpuProgramD3D12*>(call.program);
    if (program == nullptr || program->mVertexCode.empty()) {
      return;
    }
    if (call.indirectArgs == nullptr && (call.vertexCountPerInstance == 0U || call.instanceCount == 0U)) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);

    D3D12_GPU_VIRTUAL_ADDRESS constants = 0U;
    D3D12_GPU_DESCRIPTOR_HANDLE readTable{};
    D3D12_GPU_DESCRIPTOR_HANDLE writeTable{};
    PrepareGpuBindings(call.bindings, false, constants, readTable, writeTable);

    // No upload may hand the commands to the GPU while the draw is half bound.
    struct Preparing
    {
      bool& flag;
      explicit Preparing(bool& value) noexcept : flag(value) { flag = true; }
      ~Preparing() { flag = false; }
    } preparing{mPreparingDraw};
    D3D12_GPU_VIRTUAL_ADDRESS indexAddress = 0U;
    auto* const indices = static_cast<IndexBufferD3D12*>(call.indexBuffer);
    if (indices != nullptr) {
      indexAddress = indices->Storage().PrepareForDraw(*this);
    }
    if (call.indirectArgs != nullptr) {
      Transition(static_cast<GpuBufferD3D12*>(call.indirectArgs)->Resource(), D3D12_RESOURCE_STATE_INDIRECT_ARGUMENT);
    }
    BindTargets();
    ID3D12PipelineState* const pipeline = GpuPipelineFor(*program);
    if (pipeline == nullptr) {
      return;
    }
    FlushBarriers();

    mList->SetGraphicsRootSignature(mGpuRootSignatures[static_cast<int>(program->mDesc.sampler)].Get());
    mList->SetPipelineState(pipeline);
    mList->SetGraphicsRootConstantBufferView(0U, constants);
    mList->SetGraphicsRootDescriptorTable(1U, readTable);
    mList->SetGraphicsRootDescriptorTable(2U, writeTable);
    mList->IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    mList->OMSetStencilRef(program->mDesc.inheritDepthStencil ? mCurrent.stencilRef : program->mDesc.stencil.reference);
    RecordStateChange();

    if (indices != nullptr) {
      const D3D12_INDEX_BUFFER_VIEW indexView{indexAddress, indices->Storage().ByteWidth(), indices->IndexFormat()};
      mList->IASetIndexBuffer(&indexView);
      mList->DrawIndexedInstanced(call.vertexCountPerInstance, call.instanceCount, 0U, 0, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    } else if (call.indirectArgs != nullptr) {
      mList->ExecuteIndirect(
        mDrawIndirectSignature.Get(), 1U, static_cast<GpuBufferD3D12*>(call.indirectArgs)->Resource().resource.Get(),
        call.indirectArgsOffset, nullptr, 0U
      );
      RecordDraw(0U, 0U);
    } else {
      mList->DrawInstanced(call.vertexCountPerInstance, call.instanceCount, 0U, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    }

    // The effect draws that follow set their pipeline, tables, stencil
    // reference and index buffer each time, but not the root signature.
    mList->SetGraphicsRootSignature(mRootSignature.Get());
  }

  void DeviceD3D12::DispatchGpuProgram(const GpuDispatch& dispatch)
  {
    auto* const program = static_cast<GpuProgramD3D12*>(dispatch.program);
    if (program == nullptr || program->mCompute == nullptr) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    D3D12_GPU_VIRTUAL_ADDRESS constants = 0U;
    D3D12_GPU_DESCRIPTOR_HANDLE readTable{};
    D3D12_GPU_DESCRIPTOR_HANDLE writeTable{};
    PrepareGpuBindings(dispatch.bindings, true, constants, readTable, writeTable);
    FlushBarriers();

    mList->SetComputeRootSignature(mGpuRootSignatures[static_cast<int>(program->mDesc.sampler)].Get());
    mList->SetPipelineState(program->mCompute.Get());
    mList->SetComputeRootConstantBufferView(0U, constants);
    mList->SetComputeRootDescriptorTable(1U, readTable);
    mList->SetComputeRootDescriptorTable(2U, writeTable);
    mList->Dispatch(dispatch.groupsX, dispatch.groupsY, dispatch.groupsZ);
    RecordStateChange();

    // What the dispatch wrote is complete before anything reads or writes it again.
    for (GpuBuffer* const written : dispatch.bindings.writeBuffers) {
      if (auto* const buffer = static_cast<GpuBufferD3D12*>(written); buffer != nullptr && buffer->WriteView().ptr != 0U) {
        D3D12_RESOURCE_BARRIER barrier{};
        barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_UAV;
        barrier.UAV.pResource = buffer->Resource().resource.Get();
        mPendingBarriers.push_back(barrier);
      }
    }
    FlushBarriers();
  }

  // ---------------------------------------------------------------------------
  // Timestamps

  void DeviceD3D12::BeginProfileRegion(const std::uint32_t region)
  {
    if ((mGpuFeatures & kGpuFeatureTimestamps) == 0U) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (frame.pending) {
      // The GPU is kProfileFrames frames behind: this frame goes unmeasured.
      return;
    }
    const UINT base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
    if (!frame.open) {
      frame.open = true;
      frame.usedPairs = 1U;
      frame.regions.clear();
      mOpenRegions.clear();
      mList->EndQuery(mTimestampHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, base);
    }
    if (frame.usedPairs > kMaxTimedRegionsPerFrame) {
      mOpenRegions.push_back(0xFFFFFFFFU);
      return;
    }
    const std::uint32_t pair = frame.usedPairs++;
    mList->EndQuery(mTimestampHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, base + 2U * pair);
    mOpenRegions.push_back(static_cast<std::uint32_t>(frame.regions.size()));
    frame.regions.push_back(TimedRegion{region, pair});
  }

  void DeviceD3D12::EndProfileRegion(const std::uint32_t region)
  {
    static_cast<void>(region);
    if ((mGpuFeatures & kGpuFeatureTimestamps) == 0U) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (!frame.open || mOpenRegions.empty()) {
      return;
    }
    const std::uint32_t timed = mOpenRegions.back();
    mOpenRegions.pop_back();
    if (timed != 0xFFFFFFFFU) {
      const UINT base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
      mList->EndQuery(mTimestampHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, base + 2U * frame.regions[timed].pair + 1U);
    }
  }

  void DeviceD3D12::EndProfileFrame()
  {
    if ((mGpuFeatures & kGpuFeatureTimestamps) == 0U) {
      return;
    }
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (frame.open) {
      const UINT base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
      mList->EndQuery(mTimestampHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, base + 1U);
      mList->ResolveQueryData(
        mTimestampHeap.Get(), D3D12_QUERY_TYPE_TIMESTAMP, base, 2U * frame.usedPairs, mTimestampReadback.Get(),
        static_cast<UINT64>(base) * sizeof(UINT64)
      );
      frame.open = false;
      frame.pending = true;
      frame.serial = RecordingSerial();
      mOpenRegions.clear();
      mProfileFrame = (mProfileFrame + 1U) % kProfileFrames;
    }
    CollectProfileFrames();
  }

  void DeviceD3D12::CollectProfileFrames()
  {
    const std::uint64_t completed = mFence->GetCompletedValue();
    RenderProfiler& profiler = RenderProfiler::Get();
    for (std::uint32_t index = 0U; index < kProfileFrames; ++index) {
      ProfileFrame& frame = mProfileFrames[index];
      if (!frame.pending || frame.serial > completed) {
        continue;
      }
      frame.pending = false;
      const UINT base = index * 2U * (kMaxTimedRegionsPerFrame + 1U);
      const D3D12_RANGE range{static_cast<SIZE_T>(base) * sizeof(UINT64), static_cast<SIZE_T>(base + 2U * frame.usedPairs) * sizeof(UINT64)};
      void* mapped = nullptr;
      if (FAILED(mTimestampReadback->Map(0U, &range, &mapped))) {
        continue;
      }
      const auto* const stamps = static_cast<const UINT64*>(mapped) + base;
      if (stamps[1] >= stamps[0]) {
        profiler.AddGpuFrameTime(static_cast<double>(stamps[1] - stamps[0]) * mTimestampToMilliseconds);
      }
      for (const TimedRegion& timed : frame.regions) {
        const UINT64 begin = stamps[2U * timed.pair];
        const UINT64 end = stamps[2U * timed.pair + 1U];
        if (end >= begin) {
          profiler.AddGpuTime(timed.region, static_cast<double>(end - begin) * mTimestampToMilliseconds);
        }
      }
      const D3D12_RANGE noWrite{0U, 0U};
      mTimestampReadback->Unmap(0U, &noWrite);
    }
  }
} // namespace gpg::gal

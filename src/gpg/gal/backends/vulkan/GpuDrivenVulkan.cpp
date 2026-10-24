// FAF addition, not in the shipped binary (see GpuDrivenVulkan.h): DeviceVulkan's
// GPU-driven members - buffers shaders read and compute shaders write,
// engine-owned programs that pull their vertices from them, compute
// dispatches, indirect draws, and the render profiler's GPU timestamps.

#include "GpuDrivenVulkan.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "DeviceVulkan.h"
#include "ResourcesVulkan.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/RenderProfiler.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/effects/ShaderCompiler.h"

namespace gpg::gal
{
  using backend::ThrowError;
  using vulkan::CheckVk;
  using vulkan::Vk;

  namespace
  {
    // Bindings of the GPU-driven descriptor set (GpuDrivenVulkan.h).
    constexpr std::uint32_t kConstantBinding = 0U;
    constexpr std::uint32_t kFirstReadBinding = 1U;     // t0..t3
    constexpr std::uint32_t kFirstTextureBinding = 5U;  // t4..t5
    constexpr std::uint32_t kFirstWriteBinding = 7U;    // u0..u1
    constexpr std::uint32_t kSamplerBinding = 9U;       // s0
    constexpr std::uint32_t kBindingCount = 10U;
    constexpr VkDeviceSize kNullBufferBytes = 256U;

    /** The Vulkan device, while it exists (buffers and programs can outlive it at exit). */
    [[nodiscard]] DeviceVulkan* ActiveDevice() noexcept
    {
      Device* const device = Device::GetInstance();
      if (device == nullptr) {
        return nullptr;
      }
      const DeviceContext* const context = device->GetDeviceContext();
      return (context != nullptr && context->mDeviceType == DeviceApi::Vulkan) ? static_cast<DeviceVulkan*>(device) : nullptr;
    }

    [[nodiscard]] VkCompareOp ToVulkan(const GpuCompare compare) noexcept
    {
      // GpuCompare and VkCompareOp list the comparisons in the same order.
      return static_cast<VkCompareOp>(static_cast<int>(compare));
    }

    [[nodiscard]] VkStencilOp ToVulkan(const GpuStencilOp op) noexcept
    {
      switch (op) {
      case GpuStencilOp::Zero:
        return VK_STENCIL_OP_ZERO;
      case GpuStencilOp::Replace:
        return VK_STENCIL_OP_REPLACE;
      case GpuStencilOp::IncrementSaturate:
        return VK_STENCIL_OP_INCREMENT_AND_CLAMP;
      case GpuStencilOp::DecrementSaturate:
        return VK_STENCIL_OP_DECREMENT_AND_CLAMP;
      case GpuStencilOp::Invert:
        return VK_STENCIL_OP_INVERT;
      case GpuStencilOp::Increment:
        return VK_STENCIL_OP_INCREMENT_AND_WRAP;
      case GpuStencilOp::Decrement:
        return VK_STENCIL_OP_DECREMENT_AND_WRAP;
      case GpuStencilOp::Keep:
      default:
        return VK_STENCIL_OP_KEEP;
      }
    }

    [[nodiscard]] VkStencilOpState ToVulkan(const GpuStencilFace& face, const GpuStencil& stencil) noexcept
    {
      VkStencilOpState state{};
      state.failOp = ToVulkan(face.fail);
      state.passOp = ToVulkan(face.pass);
      state.depthFailOp = ToVulkan(face.depthFail);
      state.compareOp = ToVulkan(face.func);
      state.compareMask = stencil.readMask;
      state.writeMask = stencil.writeMask;
      state.reference = stencil.reference;
      return state;
    }

    /** An effect pass's stencil face (D3D numbering, 1-based) with the engine's masks and reference. */
    [[nodiscard]] VkStencilOpState ToVulkan(
      const effects::StencilFaceDesc& face, const effects::DepthStencilDesc& depth, const std::uint32_t reference
    ) noexcept
    {
      const auto op = [](const std::uint8_t value) {
        return (value >= 1U && value <= 8U) ? static_cast<VkStencilOp>(value - 1U) : VK_STENCIL_OP_KEEP;
      };
      VkStencilOpState state{};
      state.failOp = op(face.failOp);
      state.passOp = op(face.passOp);
      state.depthFailOp = op(face.depthFailOp);
      state.compareOp = (face.func >= 1U && face.func <= 8U) ? static_cast<VkCompareOp>(face.func - 1U) : VK_COMPARE_OP_ALWAYS;
      state.compareMask = depth.stencilReadMask;
      state.writeMask = depth.stencilWriteMask;
      state.reference = reference;
      return state;
    }

    [[nodiscard]] VkShaderModule CompileModule(
      VkDevice device, const GpuProgramDesc& desc, const char* const entry, const wchar_t* const profile, const bool vertex
    )
    {
      // HLSL 2018 as the sources are written for FXC; Direct3D's cbuffer
      // packing (scalar block layout is on); the GpuDriven.h registers moved
      // to the set's bindings; D3D's clip-space y.
      std::vector<std::wstring> arguments{
        L"-HV", L"2018", L"-spirv", L"-fvk-use-dx-layout", L"-fspv-target-env=vulkan1.1",
        L"-fvk-b-shift", L"0", L"0", L"-fvk-t-shift", L"1", L"0", L"-fvk-u-shift", L"7", L"0", L"-fvk-s-shift", L"9", L"0",
      };
      if (vertex) {
        arguments.push_back(L"-fvk-invert-y");
      }
      const effects::CompiledShader compiled =
        effects::ShaderCompiler::Instance().CompileRaw(std::string_view(desc.source, desc.sourceBytes), entry, profile, arguments);
      if (!compiled.succeeded) {
        gpg::Warnf("Vulkan: GPU program %s, %ls %s does not compile: %s", desc.name, profile, entry, compiled.messages.c_str());
        return VK_NULL_HANDLE;
      }
      VkShaderModuleCreateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
      info.codeSize = compiled.code.size();
      info.pCode = reinterpret_cast<const std::uint32_t*>(compiled.code.data());
      VkShaderModule module = VK_NULL_HANDLE;
      if (Vk().vkCreateShaderModule(device, &info, nullptr, &module) != VK_SUCCESS) {
        gpg::Warnf("Vulkan: GPU program %s, %s: no shader module", desc.name, entry);
        return VK_NULL_HANDLE;
      }
      return module;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // GpuBufferVulkan / GpuProgramVulkan

  GpuBufferVulkan::GpuBufferVulkan(DeviceVulkan& device, const GpuBufferDesc& desc)
    : GpuBuffer(desc)
  {
    const bool indirect = desc.kind == GpuBufferKind::IndirectArgs;
    const std::uint32_t stride = indirect ? 16U : std::max(desc.stride, 4U);
    const std::uint32_t capacity = std::max(desc.capacity, 1U);
    mDesc.stride = stride;
    mDesc.capacity = capacity;
    VkBufferUsageFlags usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    if (indirect) {
      usage |= VK_BUFFER_USAGE_INDIRECT_BUFFER_BIT;
    }
    mBuffer = device.CreateDeviceBuffer(static_cast<VkDeviceSize>(stride) * capacity, usage);
  }

  GpuBufferVulkan::~GpuBufferVulkan()
  {
    if (DeviceVulkan* const device = ActiveDevice(); device != nullptr && mBuffer.buffer != VK_NULL_HANDLE) {
      device->Retire(mBuffer);
    }
  }

  GpuProgramVulkan::~GpuProgramVulkan()
  {
    if (DeviceVulkan* const device = ActiveDevice()) {
      device->RetireProgram(*this);
    }
  }

  // ---------------------------------------------------------------------------
  // Device set-up

  void DeviceVulkan::CreateGpuDrivenObjects()
  {
    VkDescriptorSetLayoutBinding bindings[kBindingCount]{};
    for (std::uint32_t binding = 0U; binding < kBindingCount; ++binding) {
      bindings[binding].binding = binding;
      bindings[binding].descriptorCount = 1U;
      bindings[binding].stageFlags = VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT | VK_SHADER_STAGE_COMPUTE_BIT;
      bindings[binding].descriptorType = (binding == kConstantBinding)       ? VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER
        : (binding >= kFirstTextureBinding && binding < kFirstWriteBinding) ? VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE
        : (binding == kSamplerBinding)                                        ? VK_DESCRIPTOR_TYPE_SAMPLER
                                                                              : VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    VkDescriptorSetLayoutCreateInfo layout{};
    layout.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout.bindingCount = kBindingCount;
    layout.pBindings = bindings;
    CheckVk("GpuDrivenVulkan.cpp", __LINE__, Vk().vkCreateDescriptorSetLayout(mDevice, &layout, nullptr, &mGpuSetLayout));
    VkPipelineLayoutCreateInfo pipelineLayout{};
    pipelineLayout.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayout.setLayoutCount = 1U;
    pipelineLayout.pSetLayouts = &mGpuSetLayout;
    CheckVk("GpuDrivenVulkan.cpp", __LINE__, Vk().vkCreatePipelineLayout(mDevice, &pipelineLayout, nullptr, &mGpuPipelineLayout));

    for (std::uint32_t kind = 0U; kind < 3U; ++kind) {
      VkSamplerCreateInfo sampler{};
      sampler.sType = VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO;
      const bool point = static_cast<GpuSampler>(kind) == GpuSampler::PointClamp;
      sampler.magFilter = point ? VK_FILTER_NEAREST : VK_FILTER_LINEAR;
      sampler.minFilter = point ? VK_FILTER_NEAREST : VK_FILTER_LINEAR;
      sampler.mipmapMode = point ? VK_SAMPLER_MIPMAP_MODE_NEAREST : VK_SAMPLER_MIPMAP_MODE_LINEAR;
      const VkSamplerAddressMode address =
        (static_cast<GpuSampler>(kind) == GpuSampler::LinearWrap) ? VK_SAMPLER_ADDRESS_MODE_REPEAT : VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
      sampler.addressModeU = address;
      sampler.addressModeV = address;
      sampler.addressModeW = address;
      sampler.maxLod = VK_LOD_CLAMP_NONE;
      CheckVk("GpuDrivenVulkan.cpp", __LINE__, Vk().vkCreateSampler(mDevice, &sampler, nullptr, &mGpuSamplers[kind]));
    }

    mGpuNullBuffer = CreateDeviceBuffer(kNullBufferBytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT);
    // CopyVertexBufferRegion is vkCmdCopyBuffer between transfer barriers.
    mGpuFeatures = kGpuFeatureVertexPulling | kGpuFeatureCompute | kGpuFeatureIndirectDraw | kGpuFeatureBufferCopy;

    // Timestamps, when the queue supports them in graphics and compute work.
    if (mProperties.limits.timestampComputeAndGraphics == VK_TRUE && mProperties.limits.timestampPeriod > 0.0f) {
      VkQueryPoolCreateInfo pool{};
      pool.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
      pool.queryType = VK_QUERY_TYPE_TIMESTAMP;
      pool.queryCount = kProfileFrames * 2U * (kMaxTimedRegionsPerFrame + 1U);
      if (Vk().vkCreateQueryPool(mDevice, &pool, nullptr, &mTimestampPool) == VK_SUCCESS) {
        mTimestampToMilliseconds = static_cast<double>(mProperties.limits.timestampPeriod) / 1.0e6;
        mGpuFeatures |= kGpuFeatureTimestamps;
      }
    }
  }

  void DeviceVulkan::ReleaseGpuDrivenObjects() noexcept
  {
    mGpuFeatures = 0U;
    if (mDevice == VK_NULL_HANDLE) {
      return;
    }
    for (Frame& frame : mFrames) {
      for (VkDescriptorPool pool : frame.gpuPools) {
        Vk().vkDestroyDescriptorPool(mDevice, pool, nullptr);
      }
      frame.gpuPools.clear();
      frame.gpuPool = 0U;
    }
    if (mTimestampPool != VK_NULL_HANDLE) {
      Vk().vkDestroyQueryPool(mDevice, mTimestampPool, nullptr);
      mTimestampPool = VK_NULL_HANDLE;
    }
    for (VkSampler& sampler : mGpuSamplers) {
      if (sampler != VK_NULL_HANDLE) {
        Vk().vkDestroySampler(mDevice, sampler, nullptr);
        sampler = VK_NULL_HANDLE;
      }
    }
    if (mGpuNullBuffer.buffer != VK_NULL_HANDLE) {
      Vk().vkDestroyBuffer(mDevice, mGpuNullBuffer.buffer, nullptr);
      mMemory.Free(mGpuNullBuffer.memory);
      mGpuNullBuffer = vulkan::TrackedBuffer{};
    }
    if (mGpuPipelineLayout != VK_NULL_HANDLE) {
      Vk().vkDestroyPipelineLayout(mDevice, mGpuPipelineLayout, nullptr);
      mGpuPipelineLayout = VK_NULL_HANDLE;
    }
    if (mGpuSetLayout != VK_NULL_HANDLE) {
      Vk().vkDestroyDescriptorSetLayout(mDevice, mGpuSetLayout, nullptr);
      mGpuSetLayout = VK_NULL_HANDLE;
    }
    for (ProfileFrame& frame : mProfileFrames) {
      frame = ProfileFrame{};
    }
    mOpenRegions.clear();
  }

  void DeviceVulkan::RetireProgram(GpuProgramVulkan& program)
  {
    // The GPU may still run the program's pipelines: wait for what was submitted.
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    if (mDevice == VK_NULL_HANDLE) {
      return;
    }
    Vk().vkDeviceWaitIdle(mDevice);
    for (auto& [formats, pipeline] : program.mPipelines) {
      static_cast<void>(formats);
      Vk().vkDestroyPipeline(mDevice, pipeline, nullptr);
    }
    program.mPipelines.clear();
    for (VkPipeline* const pipeline : {&program.mComputePipeline}) {
      if (*pipeline != VK_NULL_HANDLE) {
        Vk().vkDestroyPipeline(mDevice, *pipeline, nullptr);
        *pipeline = VK_NULL_HANDLE;
      }
    }
    for (VkShaderModule* const module : {&program.mVertex, &program.mPixel, &program.mCompute}) {
      if (*module != VK_NULL_HANDLE) {
        Vk().vkDestroyShaderModule(mDevice, *module, nullptr);
        *module = VK_NULL_HANDLE;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Buffers and programs

  std::uint32_t DeviceVulkan::GetGpuDrivenFeatures() const
  {
    return mGpuFeatures;
  }

  std::uint32_t DeviceVulkan::GetGpuDrivenVerified() const
  {
    // Each passed its parity checks on Vulkan (docs/RENDERER_BACKENDS.md, GPU-driven paths):
    // FAF_ICON_GPU_CHECK readback with selection changes (also under synchronization validation,
    // 0 differ), a paused same-process A/B against the path off (world, brackets, icons and minimap
    // pixel-identical) and the hovered-unit states against Direct3D 11, the last once CompactIconsCS
    // stopped racing the hovered record; projectile icons by a paused A/B of the 2k air fight at
    // zooms 160 and 400 (pixel-identical at 400, only UI at 160). Not kGpuPathParticleBatch: the
    // paused A/B still shows extra particle specks with it on, as on Direct3D 11.
    // World shapes (ren_GpuShapes): a paused same-process A/B of FAF's shapes plus a 2,000-segment
    // UI_DrawLine stroke against the path off, pixel-identical outside two animated unit glows.
    return kGpuPathStrategicIcons | kGpuPathIconClassify | kGpuPathFogOfWar | kGpuPathSelectBrackets | kGpuPathProjectileIcons |
      kGpuPathWorldShapes;
  }

  boost::shared_ptr<GpuBuffer> DeviceVulkan::CreateGpuBuffer(const GpuBufferDesc& desc)
  {
    if ((mGpuFeatures & kGpuFeatureVertexPulling) == 0U) {
      return {};
    }
    return boost::shared_ptr<GpuBuffer>(new GpuBufferVulkan(*this, desc));
  }

  void DeviceVulkan::UpdateGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, const void* const data)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || data == nullptr || firstElement >= desc.capacity) {
      return;
    }
    const std::uint32_t elements = std::min(count, desc.capacity - firstElement);
    const VkDeviceSize bytes = static_cast<VkDeviceSize>(elements) * desc.stride;
    UploadBuffer(static_cast<GpuBufferVulkan&>(buffer).Buffer(), static_cast<VkDeviceSize>(firstElement) * desc.stride, data, bytes);
    RecordUpload(bytes);
  }

  bool DeviceVulkan::ReadGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, void* const out)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || out == nullptr || firstElement >= desc.capacity || count > desc.capacity - firstElement) {
      return false;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const VkDeviceSize bytes = static_cast<VkDeviceSize>(count) * desc.stride;
    vulkan::TrackedBuffer readback;
    VkBufferCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    info.size = bytes;
    info.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (Vk().vkCreateBuffer(mDevice, &info, nullptr, &readback.buffer) != VK_SUCCESS) {
      return false;
    }
    VkMemoryRequirements requirements{};
    Vk().vkGetBufferMemoryRequirements(mDevice, readback.buffer, &requirements);
    readback.memory = mMemory.Allocate(requirements, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, true);
    CheckVk("GpuDrivenVulkan.cpp", __LINE__, Vk().vkBindBufferMemory(mDevice, readback.buffer, readback.memory.memory, readback.memory.offset));

    EndRendering();
    GpuWriteBarrier();
    const VkBufferCopy region{static_cast<VkDeviceSize>(firstElement) * desc.stride, 0U, bytes};
    Vk().vkCmdCopyBuffer(mCommands, static_cast<GpuBufferVulkan&>(buffer).Buffer().buffer, readback.buffer, 1U, &region);
    Submit(true, false);
    std::memcpy(out, readback.memory.mapped, static_cast<std::size_t>(bytes));
    Vk().vkDestroyBuffer(mDevice, readback.buffer, nullptr);
    mMemory.Free(readback.memory);
    return true;
  }

  boost::shared_ptr<GpuProgram> DeviceVulkan::CreateGpuProgram(const GpuProgramDesc& desc)
  {
    if ((mGpuFeatures & kGpuFeatureVertexPulling) == 0U || desc.source == nullptr) {
      return {};
    }
    boost::shared_ptr<GpuProgramVulkan> program(new GpuProgramVulkan());
    program->mDesc = desc;
    program->mName = (desc.name != nullptr) ? desc.name : "";
    program->mDesc.name = nullptr;
    program->mDesc.source = nullptr;
    program->mDesc.sourceBytes = 0U;

    if (desc.computeEntry != nullptr) {
      program->mComputeEntry = desc.computeEntry;
      program->mCompute = CompileModule(mDevice, desc, desc.computeEntry, L"cs_6_0", false);
      if (program->mCompute == VK_NULL_HANDLE) {
        return {};
      }
      VkComputePipelineCreateInfo pipeline{};
      pipeline.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
      pipeline.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
      pipeline.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
      pipeline.stage.module = program->mCompute;
      pipeline.stage.pName = program->mComputeEntry.c_str(); // DXC keeps the HLSL entry name
      pipeline.layout = mGpuPipelineLayout;
      if (Vk().vkCreateComputePipelines(mDevice, mPipelineCache, 1U, &pipeline, nullptr, &program->mComputePipeline) != VK_SUCCESS) {
        gpg::Warnf("Vulkan: GPU program %s: no compute pipeline", program->mName.c_str());
        return {};
      }
      return program;
    }

    if (desc.vertexEntry == nullptr || desc.pixelEntry == nullptr) {
      return {};
    }
    program->mVertexEntry = desc.vertexEntry;
    program->mPixelEntry = desc.pixelEntry;
    program->mVertex = CompileModule(mDevice, desc, desc.vertexEntry, L"vs_6_0", true);
    program->mPixel = CompileModule(mDevice, desc, desc.pixelEntry, L"ps_6_0", false);
    if (program->mVertex == VK_NULL_HANDLE || program->mPixel == VK_NULL_HANDLE) {
      return {};
    }
    return program;
  }

  VkPipeline DeviceVulkan::GpuPipelineFor(GpuProgramVulkan& program)
  {
    VkFormat colorFormat = VK_FORMAT_UNDEFINED;
    vulkan::TrackedImage* colorImage = nullptr;
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    static_cast<void>(TargetView(colorFormat, colorImage, width, height));
    VkFormat depthFormat = VK_FORMAT_UNDEFINED;
    if (outputContext_.depthStencil != nullptr) {
      depthFormat = static_cast<DepthStencilTargetVulkan*>(outputContext_.depthStencil.get())->Image().format;
    }
    const GpuProgramDesc& state = program.mDesc;
    // inheritDepthStencil: the depth-stencil state (and stencil reference,
    // which these pipelines bake in) that the engine's passes left bound.
    const bool inherit = state.inheritDepthStencil && depthFormat != VK_FORMAT_UNDEFINED;
    const effects::DepthStencilDesc& current = mCurrent.depthStencil;
    const std::uint64_t depthKey =
      inherit ? (current.PackedKey() | (static_cast<std::uint64_t>(mCurrent.stencilRef & 0xFFU) << 56U)) : 0U;
    VkPipeline& pipeline = program.mPipelines[{colorFormat, depthFormat, depthKey}];
    if (pipeline != VK_NULL_HANDLE) {
      return pipeline;
    }

    VkPipelineShaderStageCreateInfo stages[2]{};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = program.mVertex;
    stages[0].pName = program.mVertexEntry.c_str();
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = program.mPixel;
    stages[1].pName = program.mPixelEntry.c_str();
    VkPipelineVertexInputStateCreateInfo vertexInput{};
    vertexInput.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    VkPipelineInputAssemblyStateCreateInfo inputAssembly{};
    inputAssembly.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    inputAssembly.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkPipelineViewportStateCreateInfo viewport{};
    viewport.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    viewport.viewportCount = 1U;
    viewport.scissorCount = 1U;
    VkPipelineRasterizationStateCreateInfo raster{};
    raster.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    // Depth clamping needs the depthClamp feature, which the device does not
    // enable; every current program clips, as D3D9 does.
    raster.depthClampEnable = VK_FALSE;
    raster.polygonMode = VK_POLYGON_MODE_FILL;
    raster.cullMode = state.cullBackFaces ? VK_CULL_MODE_BACK_BIT : VK_CULL_MODE_NONE;
    // -fvk-invert-y keeps D3D's screen positions: GpuDriven.h's clockwise front faces.
    raster.frontFace = VK_FRONT_FACE_CLOCKWISE;
    raster.lineWidth = 1.0f;
    VkPipelineMultisampleStateCreateInfo multisample{};
    multisample.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    multisample.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    VkPipelineDepthStencilStateCreateInfo depthStencil{};
    depthStencil.sType = VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO;
    if (inherit) {
      depthStencil.depthTestEnable = current.depthEnable ? VK_TRUE : VK_FALSE;
      depthStencil.depthWriteEnable = (current.depthEnable && current.depthWrite) ? VK_TRUE : VK_FALSE;
      depthStencil.depthCompareOp =
        (current.depthFunc >= 1U && current.depthFunc <= 8U) ? static_cast<VkCompareOp>(current.depthFunc - 1U) : VK_COMPARE_OP_ALWAYS;
      depthStencil.stencilTestEnable = (current.stencilEnable && vulkan::HasStencil(depthFormat)) ? VK_TRUE : VK_FALSE;
      depthStencil.front = ToVulkan(current.front, current, mCurrent.stencilRef);
      depthStencil.back = ToVulkan(current.back, current, mCurrent.stencilRef);
    } else if (depthFormat != VK_FORMAT_UNDEFINED) {
      depthStencil.depthTestEnable = state.depthTest ? VK_TRUE : VK_FALSE;
      depthStencil.depthWriteEnable = (state.depthTest && state.depthWrite) ? VK_TRUE : VK_FALSE;
      depthStencil.depthCompareOp = ToVulkan(state.depthFunc);
      depthStencil.stencilTestEnable = (state.stencil.enable && vulkan::HasStencil(depthFormat)) ? VK_TRUE : VK_FALSE;
      depthStencil.front = ToVulkan(state.stencil.front, state.stencil);
      depthStencil.back = ToVulkan(state.stencil.back, state.stencil);
    }
    VkPipelineColorBlendAttachmentState attachment{};
    attachment.blendEnable = (state.blend != GpuBlend::Opaque) ? VK_TRUE : VK_FALSE;
    attachment.srcColorBlendFactor = (state.blend != GpuBlend::Opaque) ? VK_BLEND_FACTOR_SRC_ALPHA : VK_BLEND_FACTOR_ONE;
    attachment.dstColorBlendFactor = (state.blend == GpuBlend::AlphaBlend) ? VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA
      : (state.blend == GpuBlend::Additive)                                 ? VK_BLEND_FACTOR_ONE
                                                                            : VK_BLEND_FACTOR_ZERO;
    attachment.colorBlendOp = VK_BLEND_OP_ADD;
    attachment.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
    attachment.dstAlphaBlendFactor = VK_BLEND_FACTOR_ZERO;
    attachment.alphaBlendOp = VK_BLEND_OP_ADD;
    attachment.colorWriteMask = state.colorWriteMask;
    VkPipelineColorBlendStateCreateInfo colorBlend{};
    colorBlend.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    colorBlend.attachmentCount = (colorFormat != VK_FORMAT_UNDEFINED) ? 1U : 0U;
    colorBlend.pAttachments = &attachment;
    const VkDynamicState dynamicStates[2] = {VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR};
    VkPipelineDynamicStateCreateInfo dynamic{};
    dynamic.sType = VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO;
    dynamic.dynamicStateCount = 2U;
    dynamic.pDynamicStates = dynamicStates;
    VkPipelineRenderingCreateInfo rendering{};
    rendering.sType = VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO;
    rendering.colorAttachmentCount = (colorFormat != VK_FORMAT_UNDEFINED) ? 1U : 0U;
    rendering.pColorAttachmentFormats = &colorFormat;
    rendering.depthAttachmentFormat = depthFormat;
    rendering.stencilAttachmentFormat = vulkan::HasStencil(depthFormat) ? depthFormat : VK_FORMAT_UNDEFINED;
    VkGraphicsPipelineCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    info.pNext = &rendering;
    info.stageCount = 2U;
    info.pStages = stages;
    info.pVertexInputState = &vertexInput;
    info.pInputAssemblyState = &inputAssembly;
    info.pViewportState = &viewport;
    info.pRasterizationState = &raster;
    info.pMultisampleState = &multisample;
    info.pDepthStencilState = &depthStencil;
    info.pColorBlendState = &colorBlend;
    info.pDynamicState = &dynamic;
    info.layout = mGpuPipelineLayout;
    if (Vk().vkCreateGraphicsPipelines(mDevice, mPipelineCache, 1U, &info, nullptr, &pipeline) != VK_SUCCESS) {
      gpg::Warnf("Vulkan: GPU program %s: no pipeline for colour format %d, depth format %d", program.mName.c_str(),
                 static_cast<int>(colorFormat), static_cast<int>(depthFormat));
      pipeline = VK_NULL_HANDLE;
      return VK_NULL_HANDLE;
    }
    return pipeline;
  }

  void DeviceVulkan::GpuWriteBarrier()
  {
    VkMemoryBarrier2 barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER_2;
    barrier.srcStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.srcAccessMask = VK_ACCESS_2_MEMORY_WRITE_BIT;
    barrier.dstStageMask = VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
    barrier.dstAccessMask = VK_ACCESS_2_MEMORY_READ_BIT | VK_ACCESS_2_MEMORY_WRITE_BIT;
    VkDependencyInfo dependency{};
    dependency.sType = VK_STRUCTURE_TYPE_DEPENDENCY_INFO;
    dependency.memoryBarrierCount = 1U;
    dependency.pMemoryBarriers = &barrier;
    Vk().vkCmdPipelineBarrier2(mCommands, &dependency);
  }

  VkDescriptorSet DeviceVulkan::PrepareGpuBindings(const GpuBindings& bindings, const GpuSampler sampler, const bool compute)
  {
    // The set, from this frame's GPU-driven pools.
    Frame& frame = mFrames[mFrameIndex];
    VkDescriptorSet set = VK_NULL_HANDLE;
    for (;;) {
      if (frame.gpuPool == frame.gpuPools.size()) {
        const VkDescriptorPoolSize sizes[4] = {
          {VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1024U},
          {VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1024U * 6U},
          {VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1024U * 2U},
          {VK_DESCRIPTOR_TYPE_SAMPLER, 1024U},
        };
        VkDescriptorPoolCreateInfo info{};
        info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
        info.maxSets = 1024U;
        info.poolSizeCount = 4U;
        info.pPoolSizes = sizes;
        VkDescriptorPool pool = VK_NULL_HANDLE;
        CheckVk("GpuDrivenVulkan.cpp", __LINE__, Vk().vkCreateDescriptorPool(mDevice, &info, nullptr, &pool));
        frame.gpuPools.push_back(pool);
      }
      VkDescriptorSetAllocateInfo info{};
      info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
      info.descriptorPool = frame.gpuPools[frame.gpuPool];
      info.descriptorSetCount = 1U;
      info.pSetLayouts = &mGpuSetLayout;
      if (Vk().vkAllocateDescriptorSets(mDevice, &info, &set) == VK_SUCCESS) {
        break;
      }
      ++frame.gpuPool;
    }

    // b0 from the upload ring (the 256-byte alignment covers minUniformBufferOffsetAlignment).
    const std::uint32_t constantBytes =
      (bindings.constants != nullptr) ? std::min(bindings.constantBytes, kGpuMaxConstantBytes) : 0U;
    const VkDeviceSize uploadBytes = std::max<VkDeviceSize>((constantBytes + 255U) & ~255U, 256U);
    const vulkan::UploadAllocation upload = AllocateUpload(uploadBytes, 256U);
    std::memset(upload.cpu, 0, static_cast<std::size_t>(uploadBytes));
    if (constantBytes != 0U) {
      std::memcpy(upload.cpu, bindings.constants, constantBytes);
      RecordUpload(constantBytes);
    }

    VkDescriptorBufferInfo buffers[1U + kGpuMaxReadBuffers + kGpuMaxWriteBuffers]{};
    VkDescriptorImageInfo images[kGpuMaxTextures + 1U]{};
    VkWriteDescriptorSet writes[kBindingCount]{};
    for (std::uint32_t binding = 0U; binding < kBindingCount; ++binding) {
      writes[binding].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
      writes[binding].dstSet = set;
      writes[binding].dstBinding = binding;
      writes[binding].descriptorCount = 1U;
    }
    buffers[0] = {upload.buffer, upload.offset, uploadBytes};
    writes[kConstantBinding].descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
    writes[kConstantBinding].pBufferInfo = &buffers[0];
    for (std::uint32_t slot = 0U; slot < kGpuMaxReadBuffers; ++slot) {
      VkDescriptorBufferInfo& info = buffers[1U + slot];
      if (auto* const buffer = static_cast<GpuBufferVulkan*>(bindings.readBuffers[slot])) {
        info = {buffer->Buffer().buffer, 0U, VK_WHOLE_SIZE};
      } else {
        info = {mGpuNullBuffer.buffer, 0U, VK_WHOLE_SIZE};
      }
      writes[kFirstReadBinding + slot].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
      writes[kFirstReadBinding + slot].pBufferInfo = &info;
    }
    for (std::uint32_t slot = 0U; slot < kGpuMaxTextures; ++slot) {
      VkDescriptorImageInfo& info = images[slot];
      info.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
      if (auto* const texture = static_cast<TextureVulkan*>(bindings.textures[slot])) {
        Transition(texture->Image(), VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
        info.imageView = texture->View();
      } else {
        info.imageView = mNullViews[0];
      }
      writes[kFirstTextureBinding + slot].descriptorType = VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE;
      writes[kFirstTextureBinding + slot].pImageInfo = &info;
    }
    for (std::uint32_t slot = 0U; slot < kGpuMaxWriteBuffers; ++slot) {
      VkDescriptorBufferInfo& info = buffers[1U + kGpuMaxReadBuffers + slot];
      auto* const buffer = static_cast<GpuBufferVulkan*>(bindings.writeBuffers[slot]);
      info = (buffer != nullptr && compute) ? VkDescriptorBufferInfo{buffer->Buffer().buffer, 0U, VK_WHOLE_SIZE}
                                            : VkDescriptorBufferInfo{mGpuNullBuffer.buffer, 0U, VK_WHOLE_SIZE};
      writes[kFirstWriteBinding + slot].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
      writes[kFirstWriteBinding + slot].pBufferInfo = &info;
    }
    images[kGpuMaxTextures].sampler = mGpuSamplers[static_cast<int>(sampler)];
    writes[kSamplerBinding].descriptorType = VK_DESCRIPTOR_TYPE_SAMPLER;
    writes[kSamplerBinding].pImageInfo = &images[kGpuMaxTextures];
    Vk().vkUpdateDescriptorSets(mDevice, kBindingCount, writes, 0U, nullptr);
    return set;
  }

  void DeviceVulkan::DrawGpuProgram(const GpuDrawCall& call)
  {
    auto* const program = static_cast<GpuProgramVulkan*>(call.program);
    if (program == nullptr || program->mVertex == VK_NULL_HANDLE) {
      return;
    }
    if (call.indirectArgs == nullptr && (call.vertexCountPerInstance == 0U || call.instanceCount == 0U)) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    mPreparingDraw = true;
    const VkDescriptorSet set = PrepareGpuBindings(call.bindings, program->mDesc.sampler, false);
    VkBuffer indexBuffer = VK_NULL_HANDLE;
    VkDeviceSize indexOffset = 0U;
    auto* const indices = static_cast<IndexBufferVulkan*>(call.indexBuffer);
    if (indices != nullptr) {
      indices->Storage().PrepareForDraw(*this, indexBuffer, indexOffset);
    }
    const VkPipeline pipeline = GpuPipelineFor(*program);
    mPreparingDraw = false;
    if (pipeline == VK_NULL_HANDLE) {
      return;
    }
    BeginRendering();

    Vk().vkCmdBindPipeline(mCommands, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
    Vk().vkCmdBindDescriptorSets(mCommands, VK_PIPELINE_BIND_POINT_GRAPHICS, mGpuPipelineLayout, 0U, 1U, &set, 0U, nullptr);
    // The engine's viewport with Direct3D 9's pixel centres, clipped as an effect draw is.
    VkViewport viewport{
      static_cast<float>(mViewport.X) + backend::Direct3D9PixelCentreShift(),
      static_cast<float>(mViewport.Y) + backend::Direct3D9PixelCentreShift(), static_cast<float>(mViewport.Width),
      static_cast<float>(mViewport.Height), mViewport.MinZ, mViewport.MaxZ,
    };
    if (viewport.width <= 0.0f || viewport.height <= 0.0f) {
      viewport.width = static_cast<float>(mRenderingWidth);
      viewport.height = static_cast<float>(mRenderingHeight);
    }
    Vk().vkCmdSetViewport(mCommands, 0U, 1U, &viewport);
    const std::int32_t right = std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.X + mViewport.Width), static_cast<std::int32_t>(mRenderingWidth));
    const std::int32_t bottom =
      std::min<std::int32_t>(static_cast<std::int32_t>(mViewport.Y + mViewport.Height), static_cast<std::int32_t>(mRenderingHeight));
    VkRect2D scissor{};
    scissor.offset = {static_cast<std::int32_t>(mViewport.X), static_cast<std::int32_t>(mViewport.Y)};
    scissor.extent = {
      static_cast<std::uint32_t>(std::max(right - scissor.offset.x, 0)), static_cast<std::uint32_t>(std::max(bottom - scissor.offset.y, 0)),
    };
    Vk().vkCmdSetScissor(mCommands, 0U, 1U, &scissor);
    RecordStateChange();

    if (indices != nullptr) {
      Vk().vkCmdBindIndexBuffer(mCommands, indexBuffer, indexOffset, indices->IndexType());
      Vk().vkCmdDrawIndexed(mCommands, call.vertexCountPerInstance, call.instanceCount, 0U, 0, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    } else if (call.indirectArgs != nullptr) {
      Vk().vkCmdDrawIndirect(
        mCommands, static_cast<GpuBufferVulkan*>(call.indirectArgs)->Buffer().buffer, call.indirectArgsOffset, 1U, 16U
      );
      RecordDraw(0U, 0U);
    } else {
      Vk().vkCmdDraw(mCommands, call.vertexCountPerInstance, call.instanceCount, 0U, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    }
  }

  void DeviceVulkan::DispatchGpuProgram(const GpuDispatch& dispatch)
  {
    auto* const program = static_cast<GpuProgramVulkan*>(dispatch.program);
    if (program == nullptr || program->mComputePipeline == VK_NULL_HANDLE) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mMutex);
    const VkDescriptorSet set = PrepareGpuBindings(dispatch.bindings, program->mDesc.sampler, true);
    // Compute runs outside a rendering scope; earlier writes (uploads, draws) come first.
    EndRendering();
    GpuWriteBarrier();
    Vk().vkCmdBindPipeline(mCommands, VK_PIPELINE_BIND_POINT_COMPUTE, program->mComputePipeline);
    Vk().vkCmdBindDescriptorSets(mCommands, VK_PIPELINE_BIND_POINT_COMPUTE, mGpuPipelineLayout, 0U, 1U, &set, 0U, nullptr);
    Vk().vkCmdDispatch(mCommands, dispatch.groupsX, dispatch.groupsY, dispatch.groupsZ);
    RecordStateChange();
    // What it wrote is visible to the draws (and indirect arguments) after it.
    GpuWriteBarrier();
  }

  // ---------------------------------------------------------------------------
  // Timestamps

  void DeviceVulkan::BeginProfileRegion(const std::uint32_t region)
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
    const std::uint32_t base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
    if (!frame.open) {
      // Queries are reset outside a rendering scope.
      EndRendering();
      Vk().vkCmdResetQueryPool(mCommands, mTimestampPool, base, 2U * (kMaxTimedRegionsPerFrame + 1U));
      frame.open = true;
      frame.usedPairs = 1U;
      frame.regions.clear();
      mOpenRegions.clear();
      Vk().vkCmdWriteTimestamp2(mCommands, VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT, mTimestampPool, base);
    }
    if (frame.usedPairs > kMaxTimedRegionsPerFrame) {
      mOpenRegions.push_back(0xFFFFFFFFU);
      return;
    }
    const std::uint32_t pair = frame.usedPairs++;
    Vk().vkCmdWriteTimestamp2(mCommands, VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT, mTimestampPool, base + 2U * pair);
    mOpenRegions.push_back(static_cast<std::uint32_t>(frame.regions.size()));
    frame.regions.push_back(TimedRegion{region, pair});
  }

  void DeviceVulkan::EndProfileRegion(const std::uint32_t region)
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
      const std::uint32_t base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
      Vk().vkCmdWriteTimestamp2(
        mCommands, VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT, mTimestampPool, base + 2U * frame.regions[timed].pair + 1U
      );
    }
  }

  void DeviceVulkan::EndProfileFrame()
  {
    if ((mGpuFeatures & kGpuFeatureTimestamps) == 0U) {
      return;
    }
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (frame.open) {
      const std::uint32_t base = mProfileFrame * 2U * (kMaxTimedRegionsPerFrame + 1U);
      Vk().vkCmdWriteTimestamp2(mCommands, VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT, mTimestampPool, base + 1U);
      frame.open = false;
      frame.pending = true;
      frame.serial = RecordingSerial();
      mOpenRegions.clear();
      mProfileFrame = (mProfileFrame + 1U) % kProfileFrames;
    }
    CollectProfileFrames();
  }

  void DeviceVulkan::CollectProfileFrames()
  {
    std::uint64_t completed = 0U;
    if (Vk().vkGetSemaphoreCounterValue(mDevice, mTimeline, &completed) != VK_SUCCESS) {
      return;
    }
    RenderProfiler& profiler = RenderProfiler::Get();
    std::vector<std::uint64_t> stamps;
    for (std::uint32_t index = 0U; index < kProfileFrames; ++index) {
      ProfileFrame& frame = mProfileFrames[index];
      if (!frame.pending || frame.serial > completed) {
        continue;
      }
      frame.pending = false;
      const std::uint32_t base = index * 2U * (kMaxTimedRegionsPerFrame + 1U);
      stamps.assign(2U * frame.usedPairs, 0U);
      const VkResult result = Vk().vkGetQueryPoolResults(
        mDevice, mTimestampPool, base, 2U * frame.usedPairs, stamps.size() * sizeof(std::uint64_t), stamps.data(), sizeof(std::uint64_t),
        VK_QUERY_RESULT_64_BIT
      );
      if (result != VK_SUCCESS) {
        continue;
      }
      if (stamps[1] >= stamps[0]) {
        profiler.AddGpuFrameTime(static_cast<double>(stamps[1] - stamps[0]) * mTimestampToMilliseconds);
      }
      for (const TimedRegion& timed : frame.regions) {
        const std::uint64_t begin = stamps[2U * timed.pair];
        const std::uint64_t end = stamps[2U * timed.pair + 1U];
        if (end >= begin) {
          profiler.AddGpuTime(timed.region, static_cast<double>(end - begin) * mTimestampToMilliseconds);
        }
      }
    }
  }
} // namespace gpg::gal

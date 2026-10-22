#pragma once

// FAF addition, not in the shipped binary.
//
// The Vulkan gal backend. Effects go through the engine's effect layer
// (gpg/gal/effects) exactly as on Direct3D 12, compiled to SPIR-V by DXC:
//
//   - descriptor set 0 holds an effect's texture views (bindings 0..63) and
//     samplers (64..127); set 1 holds $Globals, one uniform buffer per pass;
//   - a pipeline cache keyed by the pass's shaders, the vertex format, the
//     blend / depth / rasterizer state, the target formats and the topology;
//     vertex inputs and the vertex-to-pixel interface are matched by HLSL
//     semantic (Vulkan matches locations, which DXC numbers per shader);
//   - dynamic rendering (Vulkan 1.3), timeline-semaphore frame pacing,
//     kFramesInFlight frames of command pools and descriptor pools;
//   - the window surface comes from VulkanSurface (the one platform unit).
//
// Selected with /vulkan; any failure in `Setup` throws a gal Error and
// CScApp::CreateDevice falls back to Direct3D 9.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "ResourcesVulkan.h"
#include "VulkanCore.h"
#include "GpuDrivenVulkan.h"
#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/backends/common/WindowsCursor.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "gpg/gal/effects/SpirvReflect.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  namespace imaging
  {
    struct Image;
  }

  class DeviceVulkan final : public Device, public effects::PassBinder
  {
  public:
    DeviceVulkan();
    ~DeviceVulkan() override;

    /** Brings the device up for `context`; throws a gal Error on any failure. */
    void Setup(DeviceContext* context);

    void* GetLog() override;
    DeviceContext* GetDeviceContext() override;
    int GetCurThreadId() override;
    void Func1() const override;
    void GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, int adapterIndex) override;
    OutputContext* GetHeadOutputContext(unsigned int headIndex) override;
    const OutputContext* GetHeadOutputContext(unsigned int headIndex) const override;
    boost::shared_ptr<PipelineState> GetPipelineState() override;
    boost::shared_ptr<Effect> CreateEffect(const EffectContext& context) override;
    boost::shared_ptr<Texture> CreateTexture(const TextureContext* context) override;
    boost::shared_ptr<RenderTarget> CreateRenderTarget(const RenderTargetContext* context) override;
    boost::shared_ptr<CubeRenderTarget> CreateCubeRenderTarget(const CubeRenderTargetContext* context) override;
    boost::shared_ptr<DepthStencilTarget> CreateDepthStencilTarget(const DepthStencilTargetContext* context) override;
    boost::shared_ptr<VertexFormat> CreateVertexFormat(std::uint32_t formatCode) override;
    boost::shared_ptr<VertexBuffer> CreateVertexBuffer(const VertexBufferContext* context) override;
    boost::shared_ptr<IndexBuffer> CreateIndexBuffer(const IndexBufferContext* context) override;
    void GetRenderTargetData(const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination) override;
    void StretchRect(
      const boost::shared_ptr<RenderTarget>& source,
      const boost::shared_ptr<RenderTarget>& destination,
      const RECT* sourceRect,
      const RECT* destinationRect
    ) override;
    void UpdateSurface(
      const boost::shared_ptr<Texture>& source,
      const boost::shared_ptr<Texture>& destination,
      const RECT* sourceRect,
      const RECT* destinationRect
    ) override;
    void SaveCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const msvc8::string& filePath) override;
    void SaveRenderTarget(const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, int fileFormat) override;
    void SaveTexture(
      const boost::shared_ptr<Texture>& texture, const msvc8::string& filePath, int fileFormat, gpg::MemBuffer<char>* outBuffer
    ) override;
    void GetTexture2D(
      const void* sourceData, std::uint32_t sourceBytes, gpg::MemBuffer<char>* outTextureData, std::uint32_t* outWidth, int* outHeight
    ) override;
    boost::weak_ptr<void>* Func7(boost::weak_ptr<void>* outWeakHandle, boost::shared_ptr<void> temporarySharedHandle) override;
    void Reset(DeviceContext* context) override;
    void Reset() override;
    int TestCooperativeLevel() override;
    void BeginScene() override;
    void EndScene() override;
    void Present() override;
    void SetCursor(const CursorContext* context) override;
    void InitCursor() override;
    int ShowCursor(bool show) override;
    void SetViewport(const D3DVIEWPORT9* viewport) override;
    void GetViewport(D3DVIEWPORT9* outViewport) override;
    void ClearTarget(const OutputContext* context) override;
    void Clear(bool clearColor, bool clearDepth, bool clearStencil, std::uint32_t packedColor, float depth, int stencil) override;
    void ClearTextures() override;
    void SetVertexDeclaration(boost::shared_ptr<VertexFormat> vertexFormat) override;
    void SetVertexBuffer(
      std::uint32_t streamSlot, boost::shared_ptr<VertexBuffer> vertexBuffer, int streamFrequencyToken, int startVertex
    ) override;
    void SetBufferIndices(boost::shared_ptr<IndexBuffer> indexBuffer) override;
    void SetFogState(bool enable, const Matrix* projection, float fogStart, float fogEnd, int fogColor) override;
    void SetWireframeState(bool enabled) override;
    void SetColorWriteState(bool writeColor, bool writeAlpha) override;
    void DrawIndexedPrimitive(const DrawIndexedContext* context) override;
    void DrawPrimitive(const DrawContext* context) override;
    void BeginTechnique() override;
    void EndTechnique() override;
    bool GetRuntimeInfo(DeviceRuntimeInfo& out) override;

    // GPU-driven additions (GpuDrivenVulkan.cpp)
    [[nodiscard]] std::uint32_t GetGpuDrivenFeatures() const override;
    boost::shared_ptr<GpuBuffer> CreateGpuBuffer(const GpuBufferDesc& desc) override;
    void UpdateGpuBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, const void* data) override;
    boost::shared_ptr<GpuProgram> CreateGpuProgram(const GpuProgramDesc& desc) override;
    void DrawGpuProgram(const GpuDrawCall& call) override;
    void DispatchGpuProgram(const GpuDispatch& dispatch) override;
    void BeginProfileRegion(std::uint32_t region) override;
    void EndProfileRegion(std::uint32_t region) override;
    bool ReadGpuBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, void* out) override;
    bool CopyVertexBufferRegion(
      VertexBuffer& destination, std::uint32_t destinationOffset, VertexBuffer& source, std::uint32_t sourceOffset, std::uint32_t byteCount
    ) override;
    /** Destroys a GPU program's modules and pipelines once the GPU is done with them. */
    void RetireProgram(GpuProgramVulkan& program);

    // effects::PassBinder
    void BindPass(effects::EffectProgram& program, std::uint32_t technique, std::uint32_t pass) override;
    void UnbindPass() override;

    [[nodiscard]] bool SupportsVertexTextureFormat(std::uint32_t textureFormat);

    // ---- services for the resources ----------------------------------------
    [[nodiscard]] VkDevice Native() const noexcept { return mDevice; }
    [[nodiscard]] std::recursive_mutex& Mutex() noexcept { return mMutex; }
    [[nodiscard]] std::uint64_t RecordingSerial() const noexcept { return mSubmittedSerial + 1U; }
    /** The image of swap chain `swapChain` the frame draws into. */
    [[nodiscard]] std::uint32_t AcquiredImage(std::uint32_t swapChain);

    [[nodiscard]] vulkan::UploadAllocation AllocateUpload(VkDeviceSize bytes, VkDeviceSize alignment);
    [[nodiscard]] vulkan::TrackedBuffer CreateDeviceBuffer(VkDeviceSize bytes, VkBufferUsageFlags usage);
    void UploadBuffer(vulkan::TrackedBuffer& destination, VkDeviceSize offset, const void* data, VkDeviceSize bytes);
    /** Uploads one level of one layer; `data` holds tightly packed rows (blocks for BC formats). */
    void UploadImageLevel(vulkan::TrackedImage& destination, DXGI_FORMAT format, std::uint32_t level, std::uint32_t layer, const void* data);
    void ReadImageLevel(vulkan::TrackedImage& source, DXGI_FORMAT format, std::uint32_t level, std::uint32_t layer, std::vector<std::uint8_t>& bytes);
    void ReadImage(vulkan::TrackedImage& source, DXGI_FORMAT format, imaging::Image& image);
    /** Destroys the image (and its view) once the GPU is done with the commands recorded so far. */
    void Retire(vulkan::TrackedImage& image, VkImageView view);
    void Retire(vulkan::TrackedBuffer& buffer);

  private:
    struct RenderState
    {
      effects::BlendDesc blend;
      float blendFactor[4]{};
      std::uint32_t sampleMask = 0xFFFFFFFFU;
      effects::DepthStencilDesc depthStencil;
      std::uint32_t stencilRef = 0;
      effects::RasterizerDesc rasterizer;
    };

    struct BoundPass
    {
      bool valid = false;
      effects::EffectProgram* program = nullptr;
      const effects::CompiledEntry* vertexShader = nullptr;
      const effects::CompiledEntry* pixelShader = nullptr;
      RenderState state;
      VkDescriptorSet textures = VK_NULL_HANDLE;
      VkDescriptorSet constants = VK_NULL_HANDLE;
      std::shared_ptr<const std::vector<effects::TextureBinding>> sampled;
    };

    struct ProgramState;

    struct SwapChain
    {
      VkSurfaceKHR surface = VK_NULL_HANDLE;
      VkSwapchainKHR swapchain = VK_NULL_HANDLE;
      VkFormat format = VK_FORMAT_UNDEFINED;
      VkExtent2D extent{};
      VkPresentModeKHR presentMode = VK_PRESENT_MODE_FIFO_KHR;
      std::vector<VkImage> images;
      std::vector<VkSemaphore> renderFinished; // one per image
      std::uint32_t acquired = 0;
      bool hasImage = false;
      bool acquireWaitPending = false; // the next submission waits for the acquire
      void* window = nullptr;
    };

    struct Frame
    {
      VkCommandPool pool = VK_NULL_HANDLE;
      std::vector<VkCommandBuffer> buffers;
      std::uint32_t used = 0;
      std::uint64_t serial = 0;
      std::vector<VkDescriptorPool> descriptorPools;
      std::uint32_t descriptorPool = 0;
      std::vector<VkSemaphore> acquire; // one per swap chain
      std::vector<VkDescriptorPool> gpuPools; // GPU-driven sets (GpuDrivenVulkan.cpp)
      std::uint32_t gpuPool = 0;
    };

    struct Garbage
    {
      std::uint64_t serial = 0;
      VkImage image = VK_NULL_HANDLE;
      VkImageView view = VK_NULL_HANDLE;
      VkBuffer buffer = VK_NULL_HANDLE;
      vulkan::Allocation memory;
    };

    void CreateInstance();
    void PickPhysicalDevice(std::int32_t adapter);
    void CreateLogicalDevice();
    void CreateFrames();
    void CreateLayouts();
    void CreateNullImages();
    void CreateSwapChains(const DeviceContext& context);
    void CreateSwapChain(SwapChain& swapChain, std::uint32_t width, std::uint32_t height);
    void DestroySwapChain(SwapChain& swapChain, bool keepSurface) noexcept;
    void CreateRenderTargets();
    void ReleaseRenderTargets() noexcept;
    void CheckAvailableFormats(DeviceContext* context);
    void Shutdown() noexcept;
    void ResetState();

    void BeginCommandBuffer();
    void Submit(bool wait, bool present);
    void WaitForSerial(std::uint64_t serial);
    void CollectCompleted();
    void AcquireNextImages();

    void EndRendering();
    void BeginRendering();
    void Transition(vulkan::TrackedImage& image, VkImageLayout layout);
    /** To TRANSFER_DST for a copy into `image`, or a barrier after the transfer write that left it there. */
    void TransitionForTransferWrite(vulkan::TrackedImage& image);
    void TransitionSampled(const std::vector<effects::TextureBinding>& bindings);
    void TransferBarrier();

    [[nodiscard]] ProgramState& StateFor(effects::EffectProgram& program);
    [[nodiscard]] VkDescriptorSet AllocateSet(VkDescriptorSetLayout layout);
    [[nodiscard]] VkSampler SamplerFor(const effects::SamplerDesc& desc);
    [[nodiscard]] VkShaderModule ModuleFor(const effects::CompiledEntry& entry, const effects::CompiledEntry* vertex);
    [[nodiscard]] const effects::SpirvInterface& InterfaceOf(const effects::CompiledEntry& entry);
    [[nodiscard]] VkPipeline PipelineFor(const BoundPass& pass, VkPrimitiveTopology topology);
    [[nodiscard]] bool PrepareDraw(std::uint32_t topologyToken, bool indexed);
    [[nodiscard]] VkImageView TargetView(VkFormat& format, vulkan::TrackedImage*& image, std::uint32_t& width, std::uint32_t& height);
    void Trace(const char* format, ...);
    void DumpBackBufferIfDue();
    // ---- GPU-driven programs (GpuDrivenVulkan.cpp) ------------------------------
    void CreateGpuDrivenObjects();
    void ReleaseGpuDrivenObjects() noexcept;
    /** Writes one descriptor set (b0 uploaded, t0..t5, u0..u1, s0) for a GPU-driven call. */
    [[nodiscard]] VkDescriptorSet PrepareGpuBindings(const GpuBindings& bindings, GpuSampler sampler, bool compute);
    [[nodiscard]] VkPipeline GpuPipelineFor(GpuProgramVulkan& program);
    /** A full memory barrier: what the GPU-driven call wrote is visible to everything after it. */
    void GpuWriteBarrier();
    /** Closes the frame's timestamps (before the frame's last submission) and collects finished frames. */
    void EndProfileFrame();
    void CollectProfileFrames();

    void CopyImage(vulkan::TrackedImage& source, vulkan::TrackedImage& destination, const RECT* sourceRect, const RECT* destinationRect, bool scale);

    // ---- core objects --------------------------------------------------------
    int mCurThreadId = 0;
    msvc8::vector<msvc8::string> mLog{};
    DeviceContext mDeviceContext{DeviceApi::Unset};
    std::recursive_mutex mMutex;
    VkInstance mInstance = VK_NULL_HANDLE;
    VkDebugUtilsMessengerEXT mMessenger = VK_NULL_HANDLE;
    VkPhysicalDevice mPhysical = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties mProperties{};
    std::vector<VkPhysicalDevice> mPhysicalDevices;
    VkDevice mDevice = VK_NULL_HANDLE;
    std::uint32_t mQueueFamily = 0;
    VkQueue mQueue = VK_NULL_HANDLE;
    VkSemaphore mTimeline = VK_NULL_HANDLE;
    std::uint64_t mSubmittedSerial = 0;
    bool mAnisotropy = false;
    bool mWireframeSupported = false;
    bool mMemoryBudget = false; // VK_EXT_memory_budget enabled
    std::string mDriverName;    // VkPhysicalDeviceDriverProperties driverName + driverInfo
    VkFormat mDepthStencilFormat = VK_FORMAT_D24_UNORM_S8_UINT;

    vulkan::MemoryAllocator mMemory;
    vulkan::UploadAllocator mUpload;
    Frame mFrames[vulkan::kFramesInFlight];
    std::uint32_t mFrameIndex = 0;
    std::uint64_t mFrameCount = 0;
    VkCommandBuffer mCommands = VK_NULL_HANDLE;
    std::vector<Garbage> mGarbage;

    VkDescriptorSetLayout mTextureLayout = VK_NULL_HANDLE;
    VkDescriptorSetLayout mConstantLayout = VK_NULL_HANDLE;
    VkPipelineLayout mPipelineLayout = VK_NULL_HANDLE;
    VkPipelineCache mPipelineCache = VK_NULL_HANDLE;
    vulkan::TrackedImage mNullImages[3];   // 2D, cube, 3D
    VkImageView mNullViews[3]{};
    vulkan::TrackedBuffer mZeroBuffer;     // feeds the vertex inputs a format lacks
    VkSampler mDefaultSampler = VK_NULL_HANDLE;
    std::map<std::string, VkSampler> mSamplers;
    std::unordered_map<std::uint64_t, VkShaderModule> mModules;
    std::map<std::pair<std::uint64_t, std::uint64_t>, VkShaderModule> mLinkedModules;
    std::unordered_map<std::uint64_t, effects::SpirvInterface> mInterfaces;
    std::unordered_map<std::string, VkPipeline> mPipelines;

    // ---- heads ---------------------------------------------------------------
    std::vector<SwapChain> mSwapChains;
    std::vector<OutputContext> mHeadOutputContexts;
    boost::shared_ptr<PipelineStateVulkan> mPipelineState;
    WindowsCursor mCursor;

    // ---- state ---------------------------------------------------------------
    RenderState mCurrent;
    BoundPass mPass;
    std::uint8_t mColorWriteMask = 0x0F;
    bool mWireframe = false;
    D3DVIEWPORT9 mViewport{};
    std::uint32_t mBoundFormat = 0xFFFFFFFFU;
    struct StreamBinding
    {
      boost::shared_ptr<VertexBuffer> buffer;
      std::uint32_t offset = 0;
      std::uint32_t stride = 0;
    };
    StreamBinding mStreams[16];
    std::int32_t mStreamFrequencies[16]{};
    std::uint32_t mDrawInstanceLimit = ~0U; ///< set by PrepareDraw: the instances the bound instance streams hold
    boost::shared_ptr<IndexBuffer> mIndexBuffer;
    bool mPreparingDraw = false;

    // Dynamic rendering: what the open rendering scope draws into.
    bool mRendering = false;
    VkImageView mRenderingColor = VK_NULL_HANDLE;
    VkImageView mRenderingDepth = VK_NULL_HANDLE;
    std::uint32_t mRenderingWidth = 0;
    std::uint32_t mRenderingHeight = 0;
    bool mViewportDirty = true;

    // ---- GPU-driven programs -------------------------------------------------
    std::uint32_t mGpuFeatures = 0U;
    VkDescriptorSetLayout mGpuSetLayout = VK_NULL_HANDLE;
    VkPipelineLayout mGpuPipelineLayout = VK_NULL_HANDLE;
    VkSampler mGpuSamplers[3]{}; // by GpuSampler
    vulkan::TrackedBuffer mGpuNullBuffer; // unbound t0..t3 and u0..u1

    struct TimedRegion
    {
      std::uint32_t region = 0U;
      std::uint32_t pair = 0U;
    };
    struct ProfileFrame
    {
      std::vector<TimedRegion> regions;
      std::uint32_t usedPairs = 0U; // pair 0 is the frame itself
      std::uint64_t serial = 0U;
      bool open = false;
      bool pending = false;
    };
    static constexpr std::uint32_t kProfileFrames = 4U;
    static constexpr std::uint32_t kMaxTimedRegionsPerFrame = 160U;
    VkQueryPool mTimestampPool = VK_NULL_HANDLE;
    double mTimestampToMilliseconds = 0.0;
    ProfileFrame mProfileFrames[kProfileFrames];
    std::uint32_t mProfileFrame = 0U;
    std::vector<std::uint32_t> mOpenRegions;

    // ---- diagnostics ---------------------------------------------------------
    std::uint32_t mFrameNumber = 0;
    bool mTracing = false;
    DWORD mFirstDumpTick = 0;
    DWORD mLastDumpTick = 0;
    std::uint32_t mSkippedDraws = 0;
  };
} // namespace gpg::gal

#pragma once

// FAF addition, not in the shipped binary.
//
// The Direct3D 12 gal backend. It runs the same effects as the Direct3D 11
// backend - preprocessed with the D3D10 macros and rewritten by the D3D11
// override layer - but through the engine's own effect layer
// (gpg/gal/effects): the effect description gives the techniques, passes and
// states, the generated HLSL is compiled to DXIL by DXC.
//
//   - one root signature for every effect: $Globals as a root CBV (b0), a
//     table of texture views (t0..), a table of samplers (s0..);
//   - a pipeline-state cache keyed by the pass's shaders, the vertex format,
//     the blend / depth / rasterizer state and the target formats;
//   - an upload allocator for constants, dynamic buffers and texture data;
//   - kFramesInFlight frames, each with its command allocator and a fence.
//
// Selected with /d3d12; any failure in `Setup` throws a gal Error and
// CScApp::CreateDevice falls back to Direct3D 9.

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <d3d12.h>
#include <wrl/client.h>

#include "D3D12Core.h"
#include "GpuDrivenD3D12.h"
#include "PipelineCacheD3D12.h"
#include "ResourcesD3D12.h"
#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/backends/common/WindowsCursor.h"
#include "gpg/gal/backends/dxgi/DxgiFactory.h"
#include "gpg/gal/backends/dxgi/DxgiSwapChain.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  namespace imaging
  {
    struct Image;
  }

  class DeviceD3D12 final : public Device, public effects::PassBinder
  {
  public:
    DeviceD3D12();
    ~DeviceD3D12() override;

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

    // GPU-driven additions (GpuDrivenD3D12.cpp)
    [[nodiscard]] std::uint32_t GetGpuDrivenFeatures() const override;
    [[nodiscard]] std::uint32_t GetGpuDrivenVerified() const override;
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

    // effects::PassBinder
    void BindPass(effects::EffectProgram& program, std::uint32_t technique, std::uint32_t pass) override;
    void UnbindPass() override;

    [[nodiscard]] bool SupportsVertexTextureFormat(std::uint32_t textureFormat);

    // ---- services for the resources ----------------------------------------
    [[nodiscard]] ID3D12Device* Native() const noexcept { return mDevice.Get(); }
    /** Engine addition (gal::gPlacedResources): where static buffers are placed. */
    [[nodiscard]] d3d12::PlacedHeapAllocator& PlacedBuffers() noexcept { return mPlacedBuffers; }
    [[nodiscard]] std::recursive_mutex& Mutex() noexcept { return mMutex; }
    /** The submission the commands being recorded belong to. */
    [[nodiscard]] std::uint64_t RecordingSerial() const noexcept { return mSubmittedSerial + 1U; }

    [[nodiscard]] d3d12::UploadAllocation AllocateUpload(std::uint64_t bytes, std::uint64_t alignment);
    void Transition(d3d12::TrackedResource& resource, D3D12_RESOURCE_STATES state);
    void FlushBarriers();
    /** Copies `bytes` of `data` into `destination` at `offset` (a default-heap buffer). */
    void UploadBuffer(d3d12::TrackedResource& destination, std::uint64_t offset, const void* data, std::uint64_t bytes);
    /** Uploads one subresource of a texture, rows `rowPitch` bytes apart in `data`. */
    void UploadSubresource(d3d12::TrackedResource& destination, std::uint32_t subresource, const void* data, std::uint32_t rowPitch);
    /** Reads one subresource back (submits and waits for the GPU). */
    void ReadSubresource(d3d12::TrackedResource& source, std::uint32_t subresource, std::vector<std::uint8_t>& bytes, std::uint32_t& rowPitch);
    /** Reads a whole 2D texture (every level of every slice) into `image`. */
    void ReadTexture(d3d12::TrackedResource& source, imaging::Image& image);
    /** Keeps `resource` and frees `descriptors` once the GPU is done with the commands recorded so far. */
    void Retire(Microsoft::WRL::ComPtr<ID3D12Resource> resource);
    void RetireDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE type, D3D12_CPU_DESCRIPTOR_HANDLE handle);
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE AllocateDescriptor(D3D12_DESCRIPTOR_HEAP_TYPE type);

  private:
    struct BlendState
    {
      effects::BlendDesc blend;
      float blendFactor[4]{};
      std::uint32_t sampleMask = 0xFFFFFFFFU;
      effects::DepthStencilDesc depthStencil;
      std::uint32_t stencilRef = 0;
      effects::RasterizerDesc rasterizer;
    };

    /** Everything a pass fixed when it began (BindPass). */
    struct BoundPass
    {
      bool valid = false;
      effects::EffectProgram* program = nullptr;
      const effects::CompiledEntry* vertexShader = nullptr;
      const effects::CompiledEntry* pixelShader = nullptr;
      BlendState state;
      D3D12_GPU_VIRTUAL_ADDRESS constants = 0;
      const std::uint8_t* constantsCpu = nullptr; // the same snapshot, CPU side (upload memory)
      std::uint32_t constantsBytes = 0;
      std::uint64_t constantsSerial = 0;          // the submission whose upload memory holds it
      D3D12_GPU_DESCRIPTOR_HANDLE textures{};
      std::uint64_t tableFrame = 0;               // the frame's view arena the table is in
      std::uint64_t tableEpoch = 0;
      D3D12_GPU_DESCRIPTOR_HANDLE samplers{};
      std::shared_ptr<const std::vector<effects::TextureBinding>> sampled; // what the texture table holds
      std::uint32_t techniqueIndex = 0;
      std::uint32_t passIndex = 0;
      const char* technique = ""; // diagnostics
    };

    struct ProgramState; // per-effect backend data (samplers)
    struct DrawPreparation;

    void CreateDevice();
    void CreateQueueAndFrames();
    void CreateRootSignature();
    void CreateSwapChains(const DeviceContext& context);
    void CreateRenderTargets();
    void ReleaseRenderTargets() noexcept;
    void CheckAvailableFormats(DeviceContext* context);
    void CreateBuiltInPipelines();
    void Shutdown() noexcept;

    /** Closes and executes the recording list; `wait` blocks until the GPU finished it. */
    void Submit(bool wait);
    void BeginRecording();
    void WaitForSerial(std::uint64_t serial);
    void CollectCompleted();
    void BindFrameState();
    /**
     * Copies the bound pass's constant snapshot into the submission now being
     * recorded; called after a submission, before CollectCompleted can hand
     * out or release the upload memory the snapshot was taken into. True when
     * the pass had constants from an earlier submission.
     */
    bool CarryBoundPass();
    /** Binds the current pass again when its texture table is in a view arena since started over. */
    void RefreshStalePass();

    [[nodiscard]] ProgramState& StateFor(effects::EffectProgram& program);
    [[nodiscard]] ID3D12PipelineState* PipelineFor(const BoundPass& pass, D3D12_PRIMITIVE_TOPOLOGY_TYPE topologyType);
    [[nodiscard]] bool PrepareDraw(std::uint32_t topologyToken);
    void BindTargets();
    [[nodiscard]] D3D12_GPU_DESCRIPTOR_HANDLE AllocateTable(std::uint32_t count, D3D12_CPU_DESCRIPTOR_HANDLE& cpu);
    [[nodiscard]] D3D12_GPU_DESCRIPTOR_HANDLE SamplerTable(const std::vector<effects::SamplerDesc>& samplers);
    void TransitionSampled(const std::vector<effects::TextureBinding>& bindings);
    void ResetState();
    void Trace(const char* format, ...);
    void LogDebugMessages();
    /** CheckHresult, logging the device-removed reason and breadcrumbs first when the device is gone. */
    void CheckDeviceHresult(int line, HRESULT result, const char* during);
    /** Logs why the device was removed, its debug messages and DRED breadcrumbs / page fault (once). */
    void ReportDeviceRemoved(const char* during);
    /**
     * With DRED on: a marker naming the draw, dispatch or copy recorded next
     * (its breadcrumb context), and a numbered marker the GPU writes as it
     * reaches that command; FinishDraw writes it again once the command is done.
     */
    void MarkDraw(const char* name);
    void FinishDraw();
    void CreateDrawMarkers();
    void DumpBackBufferIfDue();
    void LogMemoryIfDue();

    // ---- GPU-driven programs (GpuDrivenD3D12.cpp) ------------------------------
    void CreateGpuDrivenObjects();
    void ReleaseGpuDrivenObjects() noexcept;
    /** Uploads b0 and fills the SRV and UAV tables of one GPU-driven call. */
    void PrepareGpuBindings(
      const GpuBindings& bindings, bool compute, D3D12_GPU_VIRTUAL_ADDRESS& constants, D3D12_GPU_DESCRIPTOR_HANDLE& readTable,
      D3D12_GPU_DESCRIPTOR_HANDLE& writeTable
    );
    [[nodiscard]] ID3D12PipelineState* GpuPipelineFor(GpuProgramD3D12& program);
    /** Closes the frame's timestamps (before Present) and collects finished frames. */
    void EndProfileFrame();
    void CollectProfileFrames();

    void BlitTexture(
      D3D12_CPU_DESCRIPTOR_HANDLE source,
      d3d12::TrackedResource& sourceResource,
      RenderTargetD3D12::Buffer& destination,
      DXGI_FORMAT destinationFormat,
      std::uint32_t width,
      std::uint32_t height
    );

    // ---- core objects --------------------------------------------------------
    d3d12::Library mLibrary;
    int mCurThreadId = 0;
    msvc8::vector<msvc8::string> mLog{};
    DeviceContext mDeviceContext{DeviceApi::Unset};
    dxgi::Factory mFactory;
    std::uint32_t mAdapterIndex = 0;
    Microsoft::WRL::ComPtr<ID3D12Device> mDevice;
    Microsoft::WRL::ComPtr<ID3D12InfoQueue> mInfoQueue;
    Microsoft::WRL::ComPtr<ID3D12CommandQueue> mQueue;
    Microsoft::WRL::ComPtr<ID3D12GraphicsCommandList> mList;
    Microsoft::WRL::ComPtr<ID3D12Fence> mFence;
    HANDLE mFenceEvent = nullptr;
    std::uint64_t mSubmittedSerial = 0;
    std::recursive_mutex mMutex;

    struct Frame
    {
      Microsoft::WRL::ComPtr<ID3D12CommandAllocator> allocator;
      std::uint64_t serial = 0; // the last submission recorded with this allocator
      d3d12::DescriptorArena views;
    };
    Frame mFrames[d3d12::kFramesInFlight];
    std::uint32_t mFrameIndex = 0;
    std::uint64_t mFrameCount = 0;

    struct Garbage
    {
      std::uint64_t serial = 0;
      Microsoft::WRL::ComPtr<ID3D12Resource> resource;
      D3D12_DESCRIPTOR_HEAP_TYPE type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
      D3D12_CPU_DESCRIPTOR_HANDLE descriptor{};
    };
    std::vector<Garbage> mGarbage;

    d3d12::UploadAllocator mUpload;
    d3d12::PlacedHeapAllocator mPlacedTextures; // engine addition: gal::gPlacedResources
    d3d12::PlacedHeapAllocator mPlacedBuffers;
    d3d12::DescriptorPool mRtvPool;
    d3d12::DescriptorPool mDsvPool;
    d3d12::DescriptorPool mSrvPool;
    d3d12::DescriptorArena mSamplerHeap; // shader visible, filled once per effect
    D3D12_CPU_DESCRIPTOR_HANDLE mNullViews[3]{}; // Texture2D, TextureCube, Texture3D
    D3D12_CPU_DESCRIPTOR_HANDLE mNullViewRun{};  // kMaxTextureSlots null 2D views in a row
    Microsoft::WRL::ComPtr<ID3D12DescriptorHeap> mNullViewHeap;
    Microsoft::WRL::ComPtr<ID3D12RootSignature> mRootSignature;
    std::vector<D3D12_RESOURCE_BARRIER> mPendingBarriers;

    // ---- heads ---------------------------------------------------------------
    std::vector<std::unique_ptr<dxgi::SwapChain>> mSwapChains;
    std::vector<OutputContext> mHeadOutputContexts;
    boost::shared_ptr<PipelineStateD3D12> mPipelineState;
    WindowsCursor mCursor;

    // ---- pipeline state ------------------------------------------------------
    std::unordered_map<std::string, Microsoft::WRL::ComPtr<ID3D12PipelineState>> mPipelines;
    d3d12::PipelineCache mPipelineCache; // engine addition: mPipelines' entries kept on disk across sessions
    std::map<std::string, D3D12_GPU_DESCRIPTOR_HANDLE> mSamplerTables; // by content
    std::uint64_t mArenaEpoch = 0; // bumped when a frame's view arena is emptied mid-frame
    BlendState mCurrent;      // what passes leave behind (D3D9's persistent render states)
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
    boost::shared_ptr<IndexBuffer> mIndexBuffer;
    bool mFrameStateDirty = true;
    bool mPreparingDraw = false;

    // Built-in blit (StretchRect between targets of different size or format).
    std::string mBlitShaderKey;
    std::vector<std::uint8_t> mBlitVertexShader;
    std::vector<std::uint8_t> mBlitPixelShader;
    std::vector<std::uint8_t> mSolidPixelShader; // diagnostics (FAF_GAL_SOLID_PS)
    std::map<DXGI_FORMAT, Microsoft::WRL::ComPtr<ID3D12PipelineState>> mBlitPipelines;
    D3D12_GPU_DESCRIPTOR_HANDLE mBlitSamplers{};
    // What was last bound to the output merger and rasterizer (skips repeats).
    D3D12_CPU_DESCRIPTOR_HANDLE mBoundRenderTarget{};
    D3D12_CPU_DESCRIPTOR_HANDLE mBoundDepthStencil{};
    bool mTargetsDirty = true;

    // ---- GPU-driven programs -------------------------------------------------
    std::uint32_t mGpuFeatures = 0U;
    Microsoft::WRL::ComPtr<ID3D12RootSignature> mGpuRootSignatures[3]; // by GpuSampler
    Microsoft::WRL::ComPtr<ID3D12CommandSignature> mDrawIndirectSignature;
    Microsoft::WRL::ComPtr<ID3D12DescriptorHeap> mGpuNullHeap;
    D3D12_CPU_DESCRIPTOR_HANDLE mNullBufferView{}; // unbound t0..t3
    D3D12_CPU_DESCRIPTOR_HANDLE mNullWriteView{};  // unbound u0..u1

    struct TimedRegion
    {
      std::uint32_t region = 0U;
      std::uint32_t pair = 0U;
    };
    struct ProfileFrame
    {
      std::vector<TimedRegion> regions;
      std::uint32_t usedPairs = 0U; // pair 0 is the frame itself
      std::uint64_t serial = 0U;    // the submission that resolved it
      bool open = false;
      bool pending = false;
    };
    static constexpr std::uint32_t kProfileFrames = 4U;
    static constexpr std::uint32_t kMaxTimedRegionsPerFrame = 160U;
    Microsoft::WRL::ComPtr<ID3D12QueryHeap> mTimestampHeap;
    Microsoft::WRL::ComPtr<ID3D12Resource> mTimestampReadback;
    double mTimestampToMilliseconds = 0.0;
    ProfileFrame mProfileFrames[kProfileFrames];
    std::uint32_t mProfileFrame = 0U;
    std::vector<std::uint32_t> mOpenRegions; // indices into the current frame's regions

    // ---- diagnostics ---------------------------------------------------------
    std::uint32_t mFrameNumber = 0;
    bool mTracing = false;
    std::set<int> mLoggedMessages;
    bool mRemovalReported = false;
    bool mDredEnabled = false;
    // With DRED: numbered markers around each draw, dispatch and copy, written
    // by the GPU into system memory that survives a device removal (reached
    // at [0], finished at [1]).
    Microsoft::WRL::ComPtr<ID3D12GraphicsCommandList2> mList2;
    Microsoft::WRL::ComPtr<ID3D12Resource> mDrawMarkerBuffer;
    volatile std::uint32_t* mDrawMarkers = nullptr;
    std::uint32_t mDrawMarkerId = 0;
    std::string mDrawMarkerNames[4096];
    std::uint64_t mUploadSubmits = 0; // submissions forced by upload pressure (FAF_GAL_MEMORY_LOG)
    std::uint64_t mCarriedPasses = 0; // bound passes whose constants followed them into the next submission
    std::uint64_t mMostInFlight = 0;  // submissions the GPU had not finished, at most, since the last memory log
    DWORD mFirstDumpTick = 0;
    DWORD mLastDumpTick = 0;
    std::uint32_t mSkippedDraws = 0;
  };
} // namespace gpg::gal

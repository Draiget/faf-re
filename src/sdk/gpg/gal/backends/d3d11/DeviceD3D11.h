#pragma once

// FAF addition, not in the shipped binary.
//
// The Direct3D 11 gal backend. It follows the D3D10 backend (DeviceD3D10)
// slot by slot - the same effect dialect (d3d10states.compat, technique10,
// shader model 4), the same vertex layouts and the same state packs - on an
// ID3D11Device with its immediate context, Effects 11 for the .fx files and
// a flip-model DXGI swap chain per head. Selected with /d3d11; any failure in
// `Setup` throws a gal Error and CScApp::CreateDevice falls back to D3D9.

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include <d3d11.h>
#include <d3d11sdklayers.h>
#include <wrl/client.h>

#include "GpuDrivenD3D11.h"
#include "PipelineStateD3D11.h"
#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/backends/dxgi/DxgiFactory.h"
#include "gpg/gal/backends/dxgi/DxgiSwapChain.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

struct ID3DX11Effect;
struct ID3DX11EffectTechnique;

namespace gpg::gal
{
  class D3DX11Library;

  class DeviceD3D11 final : public Device
  {
  public:
    DeviceD3D11();
    ~DeviceD3D11() override;

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
    void GetRenderTargetData(
      const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination
    ) override;
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
    void SaveRenderTarget(
      const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, int fileFormat
    ) override;
    void SaveTexture(
      const boost::shared_ptr<Texture>& texture,
      const msvc8::string& filePath,
      int fileFormat,
      gpg::MemBuffer<char>* outBuffer
    ) override;
    void GetTexture2D(
      const void* sourceData,
      std::uint32_t sourceBytes,
      gpg::MemBuffer<char>* outTextureData,
      std::uint32_t* outWidth,
      int* outHeight
    ) override;
    boost::weak_ptr<void>* Func7(boost::weak_ptr<void>* outWeakHandle, boost::shared_ptr<void> temporarySharedHandle) override;
    /** Resizes every head's swap chain to the context's head sizes and rebuilds the back-buffer targets. */
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

    // GPU-driven additions (gpg/gal/GpuDriven.h), implemented by GpuDrivenD3D11.
    [[nodiscard]] std::uint32_t GetGpuDrivenFeatures() const override;
    boost::shared_ptr<GpuBuffer> CreateGpuBuffer(const GpuBufferDesc& desc) override;
    void UpdateGpuBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, const void* data) override;
    boost::shared_ptr<GpuProgram> CreateGpuProgram(const GpuProgramDesc& desc) override;
    void DrawGpuProgram(const GpuDrawCall& call) override;
    void DispatchGpuProgram(const GpuDispatch& dispatch) override;
    void BeginProfileRegion(std::uint32_t region) override;
    void EndProfileRegion(std::uint32_t region) override;
    bool GetRuntimeInfo(DeviceRuntimeInfo& out) override;
    bool ReadGpuBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, void* out) override;
    bool CopyVertexBufferRegion(
      VertexBuffer& destination,
      std::uint32_t destinationOffset,
      VertexBuffer& source,
      std::uint32_t sourceOffset,
      std::uint32_t byteCount
    ) override;

    /**
     * Diagnostics: with FAF_GAL_TRACE_START / FAF_GAL_TRACE_FRAMES set, the
     * calls of that many frames from that frame on go to the log.
     */
    [[nodiscard]] bool Tracing() const noexcept { return mTracing; }
    void Trace(const char* format, ...);
    /** Diagnostics: writes the bound colour target to FAF_GAL_DUMP_DIR. */
    void DumpBoundTarget(const char* label);

    /** The vertex shader of the pass just applied (EffectTechniqueD3D11::BeginPass). */
    void SetPassVertexShader(const void* bytecode, SIZE_T length);

    /** As DeviceD3D10::SupportsVertexTextureFormat: any 2D-sampleable format. */
    [[nodiscard]] bool SupportsVertexTextureFormat(std::uint32_t textureFormat);

    [[nodiscard]] ID3D11Device* NativeDevice() const noexcept { return mDevice.Get(); }
    [[nodiscard]] ID3D11DeviceContext* Immediate() const noexcept { return mImmediate.Get(); }
    [[nodiscard]] PipelineStateD3D11& Pipeline() const noexcept { return *mPipelineState; }

    /** Encodes `resource` as image file format `d3dxFormat` (D3DX11_IMAGE_FILE_FORMAT). */
    HRESULT EncodeTexture(ID3D11Resource* resource, int d3dxFormat, ID3D10Blob** outBlob);

  private:
    void CreateDevice();
    void CreateSwapChains(const DeviceContext& context);
    void CreateHelperEffects();
    void CreateInputLayouts();
    Microsoft::WRL::ComPtr<ID3D10Blob> BuildInputSignature(std::uint32_t formatCode);
    void CheckAvailableFormats(DeviceContext* context);
    void CreateRenderTargets();
    void ReleaseRenderTargets() noexcept;
    void Shutdown() noexcept;
    void BindOutputContext();
    void DumpBackBufferIfDue();
    void CreateClearResources();
    [[nodiscard]] bool ViewportCoversTargets() const;
    void ClearViewportWithDraw(bool clearColor, bool clearDepth, bool clearStencil, const float* rgba, float depth, int stencil);
    void DumpTexture(ID3D11Texture2D* texture, const char* path);
    void PrepareInputLayout();
    Microsoft::WRL::ComPtr<ID3D11InputLayout> CreateShaderInputLayout(std::uint32_t format, const void* bytecode, SIZE_T length);

    struct ShaderLayoutKey
    {
      std::uint32_t format = 0;
      std::uint8_t checksum[16]{}; // the vertex shader's DXBC hash
      bool operator<(const ShaderLayoutKey& other) const noexcept
      {
        if (format != other.format) {
          return format < other.format;
        }
        return std::memcmp(checksum, other.checksum, sizeof(checksum)) < 0;
      }
    };
    void LogDebugLayerMessages();
    void StretchRectBlit(UINT width, UINT height, ID3D11RenderTargetView* destination, ID3D11ShaderResourceView* source);

    /**
     * Compiles one effect as fx_4_0 (the D3D10 dialect) and loads it into
     * Effects 11. The compiled blob is cached beside the D3D9 cache file,
     * keyed by a hash of the source, the macros and the compiler settings.
     */
    Microsoft::WRL::ComPtr<ID3DX11Effect> CompileEffect(
      const char* source,
      std::size_t sourceBytes,
      const char* sourceName,
      const D3D_SHADER_MACRO* defines,
      const char* cachePath
    );

    int mCurThreadId = 0;
    msvc8::vector<msvc8::string> mLog{};
    DeviceContext mDeviceContext{DeviceApi::Unset};
    dxgi::Factory mFactory;
    std::uint32_t mAdapterIndex = 0;
    std::vector<std::unique_ptr<dxgi::SwapChain>> mSwapChains;
    Microsoft::WRL::ComPtr<ID3D11Device> mDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mImmediate;
    D3D_FEATURE_LEVEL mFeatureLevel = D3D_FEATURE_LEVEL_10_0;
    std::unique_ptr<D3DX11Library> mD3DX11;
    boost::shared_ptr<PipelineStateD3D11> mPipelineState;
    Microsoft::WRL::ComPtr<ID3DX11Effect> mSignatureEffect;
    Microsoft::WRL::ComPtr<ID3DX11Effect> mRttEffect;
    ID3DX11EffectTechnique* mRttTechnique = nullptr;
    Microsoft::WRL::ComPtr<ID3D11Buffer> mRttQuadVertexBuffer;
    Microsoft::WRL::ComPtr<ID3D11InputLayout> mRttInputLayout;
    Microsoft::WRL::ComPtr<ID3D11InputLayout> mInputLayouts[24]; // one per gal vertex format
    std::map<ShaderLayoutKey, Microsoft::WRL::ComPtr<ID3D11InputLayout>> mShaderInputLayouts;
    std::uint32_t mBoundFormat = 0xFFFFFFFFU;
    const void* mPassVertexShader = nullptr;
    SIZE_T mPassVertexShaderLength = 0U;
    bool mInputLayoutDirty = true;
    // The viewport-sized clear (ClearViewportWithDraw).
    Microsoft::WRL::ComPtr<ID3D11VertexShader> mClearVertexShader;
    Microsoft::WRL::ComPtr<ID3D11PixelShader> mClearPixelShader;
    Microsoft::WRL::ComPtr<ID3D11Buffer> mClearConstants;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> mClearRasterizer;
    Microsoft::WRL::ComPtr<ID3D11BlendState> mClearBlend[2];
    Microsoft::WRL::ComPtr<ID3D11DepthStencilState> mClearDepthStencil[4];
    std::uint32_t mFrameIndex = 0U;
    bool mTracing = false;
    std::uint32_t mDumpSequence = 0U;
    std::int32_t mStreamFrequencies[16]{};
    std::vector<OutputContext> mHeadOutputContexts;
    CursorD3D11 mCursor;
    DWORD mFirstDumpTick = 0U;
    DWORD mLastDumpTick = 0U;
    Microsoft::WRL::ComPtr<ID3D11InfoQueue> mInfoQueue; // with /d3d11debug
    std::set<int> mLoggedDebugMessages;
    std::unique_ptr<GpuDrivenD3D11> mGpuDriven;
    // GetTexture2D's decoder: a WARP device of its own (the prefetch thread calls it).
    std::mutex mDecodeMutex;
    Microsoft::WRL::ComPtr<ID3D11Device> mDecodeDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mDecodeContext;
  };
} // namespace gpg::gal

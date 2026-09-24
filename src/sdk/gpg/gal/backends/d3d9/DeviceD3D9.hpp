// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstdint>

#include <d3d9.h>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/backends/d3d9/AdapterD3D9.hpp"
#include "gpg/gal/backends/d3d9/AdapterModeD3D9.hpp"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg {
namespace gal {
    class Head;
    class DeviceContext;
    class Device;
    class CursorContext;
    class OutputContext;
    class CubeRenderTargetContext;
    class DepthStencilTargetContext;
    class EffectContext;
    class IndexBufferContext;
    class RenderTargetContext;
    class TextureContext;
    class VertexBufferContext;
    class CubeRenderTargetD3D9;
    class DepthStencilTargetD3D9;
    class EffectD3D9;
    class IndexBufferD3D9;
    class PipelineStateD3D9;
    class RenderTargetD3D9;
    class TextureD3D9;
    class VertexBufferD3D9;
    class VertexFormatD3D9;

    /**
     * VFTABLE: 0x00D4273C
     * COL:  0x00E5084C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\DeviceD3D9.cpp
     */
    class DeviceD3D9 : public Device {
    public:
      /**
       * Address: 0x008EFD50 (FUN_008EFD50)
       *
       * What it does:
       * Builds an empty device; `Setup` brings it up.
       */
      DeviceD3D9();

      /**
       * Address: 0x008F3270 (FUN_008F3270)
       * Address: 0x008F37F0 (FUN_008F37F0, slot 0: the scalar deleting destructor)
       *
       * What it does:
       * Runs `Shutdown`, then destroys the members.
       */
      ~DeviceD3D9() override;
      /**
       * Address: 0x008E81D0 (FUN_008E81D0)
       * Slot: 1
       * Demangled: gpg::gal::DeviceD3D9::GetLog
       *
       * What it does:
       * Returns the global D3D9 log-storage lane used by this backend.
       */
      virtual void* GetLog() override;
      /**
       * Address: 0x008E81E0 (FUN_008E81E0)
       * Slot: 2
       * Demangled: gpg::gal::DeviceD3D9::GetDeviceContext
       *
       * What it does:
       * Dispatches `Func1` pre-hook and returns the embedded device-context lane.
       */
      virtual DeviceContext* GetDeviceContext() override;
      /**
       * Address: 0x008E81F0 (FUN_008E81F0)
       * Slot: 3
       * Demangled: gpg::gal::DeviceD3D9::GetCurThreadId
       *
       * What it does:
       * Returns the retained current thread-id lane at `this+0x24`.
       */
      virtual int GetCurThreadId() override;
      /**
       * Address: 0x008E8200 (FUN_008E8200)
       * Slot: 4
       * Demangled: gpg::gal::DeviceD3D9::Func1
       *
       * What it does:
       * Preserves the binary no-op virtual pre-hook slot.
       */
      void Func1() const override;
      /**
       * Address: 0x008F0170
       * Slot: 5
       * Demangled: gpg::gal::DeviceD3D9::GetModesForAdapter
       */
      void GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, int adapterIndex) override;
      /**
       * Address: 0x008EAB20 (FUN_008EAB20)
       * Slot: 7
       *
       * What it does:
       * Returns head `headIndex`'s output context from the array at `this+0x7C`.
       */
      OutputContext* GetHeadOutputContext(unsigned int headIndex) override;
      /**
       * Address: 0x008EABF0 (FUN_008EABF0)
       * Slot: 6
       *
       * What it does:
       * The const overload of slot 7.
       */
      const OutputContext* GetHeadOutputContext(unsigned int headIndex) const override;
      /**
       * Address: 0x008E9B00 (FUN_008E9B00)
       * Slot: 8
       *
       * What it does:
       * Runs the `Func1` pre-hook and returns the device's pipeline state.
       */
      boost::shared_ptr<PipelineState> GetPipelineState() override;
      /**
       * Address: 0x008F13D0 (FUN_008F13D0)
       * Slot: 9
       * Demangled: gpg::gal::DeviceD3D9::CreateEffect
       *
       * What it does:
       * Runs the `Func1` pre-hook, then builds the effect from the compiled
       * cache (`CreateEffectFromCachedBinary`) when `context.mUseCache` is set
       * and from source (`CreateEffectFromSourceBuffer`) otherwise.
       */
      boost::shared_ptr<Effect> CreateEffect(const EffectContext& context) override;
      /**
       * Address: 0x008EACC0 (FUN_008EACC0)
       * Slot: 10
       *
       * What it does:
       * Creates one D3D9 texture (empty, or decoded from in-memory file data)
       * and wraps it in a `TextureD3D9`.
       */
      boost::shared_ptr<Texture> CreateTexture(const TextureContext* context) override;
      /**
       * Address: 0x008EB610 (FUN_008EB610)
       * Slot: 11
       *
       * What it does:
       * Creates one `D3DUSAGE_RENDERTARGET` texture of the context's size and
       * format in the default pool and wraps it in a `RenderTargetD3D9`.
       */
      boost::shared_ptr<RenderTarget> CreateRenderTarget(const RenderTargetContext* context) override;
      /**
       * Address: 0x008EB780 (FUN_008EB780)
       * Slot: 12
       *
       * What it does:
       * Creates one render-target cube texture and wraps it in a
       * `CubeRenderTargetD3D9`.
       */
      boost::shared_ptr<CubeRenderTarget> CreateCubeRenderTarget(const CubeRenderTargetContext* context) override;
      /**
       * Address: 0x008EB8E0 (FUN_008EB8E0)
       * Slot: 13
       *
       * What it does:
       * Creates one depth/stencil surface and wraps it in a
       * `DepthStencilTargetD3D9`.
       */
      boost::shared_ptr<DepthStencilTarget> CreateDepthStencilTarget(
          const DepthStencilTargetContext* context
       ) override;
      /**
       * Address: 0x008EBA50 (FUN_008EBA50)
       * Slot: 14
       *
       * What it does:
       * Creates the D3D9 vertex declaration for gal vertex format
       * `formatCode` and wraps it in a `VertexFormatD3D9`.
       */
      boost::shared_ptr<VertexFormat> CreateVertexFormat(std::uint32_t formatCode) override;
      /**
       * Address: 0x008EBBB0 (FUN_008EBBB0)
       * Slot: 15
       *
       * What it does:
       * Creates one D3D9 vertex buffer described by `context`.
       */
      boost::shared_ptr<VertexBuffer> CreateVertexBuffer(const VertexBufferContext* context) override;
      /**
       * Address: 0x008EBD30 (FUN_008EBD30)
       * Slot: 16
       *
       * What it does:
       * Creates one D3D9 index buffer described by `context`.
       */
      boost::shared_ptr<IndexBuffer> CreateIndexBuffer(const IndexBufferContext* context) override;
      /**
       * Address: 0x008EC440 (FUN_008EC440)
       * Slot: 17
       *
       * What it does:
       * Reads a colour target back into a system-memory texture:
       * `IDirect3DDevice9::GetRenderTargetData` from the target's surface
       * into level 0 of `destination`.
       */
      void GetRenderTargetData(
          const boost::shared_ptr<RenderTarget>& source,
          const boost::shared_ptr<Texture>& destination
       ) override;
      /**
       * Address: 0x008EC250 (FUN_008EC250)
       * Slot: 18
       *
       * What it does:
       * Blits one colour target's surface into another with linear filtering.
       */
      void StretchRect(
          const boost::shared_ptr<RenderTarget>& source,
          const boost::shared_ptr<RenderTarget>& destination,
          const RECT* sourceRect,
          const RECT* destinationRect
       ) override;
      /**
       * Address: 0x008EBF70 (FUN_008EBF70)
       * Slot: 19
       *
       * What it does:
       * Copies a region of one texture's level 0 into another through
       * `D3DXLoadSurfaceFromSurface`.
       */
      void UpdateSurface(
          const boost::shared_ptr<Texture>& source,
          const boost::shared_ptr<Texture>& destination,
          const RECT* sourceRect,
          const RECT* destinationRect
       ) override;
      /**
       * Address: 0x008ECB50 (FUN_008ECB50)
       * Slot: 20
       *
       * What it does:
       * Writes one cube render target's texture to `filePath` as DDS.
       */
      void SaveCubeRenderTarget(
          const boost::shared_ptr<CubeRenderTarget>& cubeTarget,
          const msvc8::string& filePath
       ) override;
      /**
       * Address: 0x008EC970 (FUN_008EC970)
       * Slot: 21
       *
       * What it does:
       * Writes one colour target's surface to `filePath` in image format
       * `fileFormat`.
       */
      void SaveRenderTarget(
          const boost::shared_ptr<RenderTarget>& renderTarget,
          const msvc8::string& filePath,
          int fileFormat
       ) override;
      /**
       * Address: 0x008EC6A0 (FUN_008EC6A0)
       * Slot: 22
       *
       * What it does:
       * Encodes one texture's level 0 to `filePath`, or into `outBuffer` when
       * it is non-null.
       */
      void SaveTexture(
          const boost::shared_ptr<Texture>& texture,
          const msvc8::string& filePath,
          int fileFormat,
          gpg::MemBuffer<char>* outBuffer
       ) override;
      /**
       * Address: 0x008ECD20 (FUN_008ECD20)
       * Slot: 23
       * Demangled: gpg::gal::DeviceD3D9::GetTexture2D
       *
       * What it does:
       * Decodes one texture payload from memory and exports block-compressed bytes.
       */
      virtual void GetTexture2D(
          const void* sourceData,
          std::uint32_t sourceBytes,
          gpg::MemBuffer<char>* outTextureData,
          std::uint32_t* outWidth,
          int* outHeight
       ) override;
      /**
       * Address: 0x008E9B40 (FUN_008E9B40)
       * Slot: 24
       * Demangled: gpg::gal::DeviceD3D9::Func7
       *
       * What it does:
       * Dispatches `Func1`, clears caller weak-handle output, and consumes one temporary
       * shared-handle argument by value.
       */
      virtual boost::weak_ptr<void>* Func7(
          boost::weak_ptr<void>* outWeakHandle,
          boost::shared_ptr<void> temporarySharedHandle
       ) override;
      /**
       * Address: 0x008F3070 (FUN_008F3070)
       * Slot: 26
       *
       * DeviceContext *
       *
       * What it does:
       * Resets the native D3D9 device for `context`, then rebuilds the
       * capabilities, the heads, the pipeline state and the frame event query.
       */
      void Reset(DeviceContext* context) override;
      /**
       * Address: 0x008E8210 (FUN_008E8210)
       * Slot: 25
       *
       * What it does:
       * `Reset(&mDeviceContext)`, through the slot.
       */
      void Reset() override;
      /**
       * Address: 0x008ED360 (FUN_008ED360)
       * Slot: 27
       * Demangled: gpg::gal::DeviceD3D9::TestCooperativeLevel
       *
       * What it does:
       * Probes native cooperative-level state and maps D3D9 result values into backend
       * status tokens (`0`, `1`, `2`).
       */
      virtual int TestCooperativeLevel() override;
      /**
       * Address: 0x008ED450 (FUN_008ED450)
       * Slot: 28
       * Demangled: gpg::gal::DeviceD3D9::BeginScene
       *
       * What it does:
       * Begins one native D3D9 scene and issues one begin marker on the retained frame
       * event query when available.
       */
      void BeginScene() override;
      /**
       * Address: 0x008ED550 (FUN_008ED550)
       * Slot: 29
       * Demangled: gpg::gal::DeviceD3D9::EndScene
       *
       * What it does:
       * Ends one native D3D9 scene and throws on failing HRESULT.
       */
      virtual void EndScene() override;
      /**
       * Address: 0x008ED640 (FUN_008ED640)
       * Slot: 30
       * Demangled: gpg::gal::DeviceD3D9::Present
       *
       * What it does:
       * Flushes pending frame-event query data then presents the native swap chain.
       */
      virtual void Present() override;
      /**
       * Address: 0x008ED750 (FUN_008ED750)
       * Slot: 31
       * Demangled: gpg::gal::DeviceD3D9::SetCursor
       *
       * CursorContext const *
       *
       * What it does:
       * Resolves one level-0 cursor surface from context texture lanes and binds cursor
       * hotspot/surface properties on the native device.
       */
      virtual void SetCursor(const CursorContext* context) override;
      /**
       * Address: 0x008E8220 (FUN_008E8220)
       * Slot: 32
       * Demangled: gpg::gal::DeviceD3D9::InitCursor
       *
       * What it does:
       * Preserves the binary no-op cursor-init slot body.
       */
      void InitCursor() override;
      /**
       * Address: 0x008E8230 (FUN_008E8230)
       * Slot: 33
       * Demangled: gpg::gal::DeviceD3D9::ShowCursor
       *
       * bool
       *
       * What it does:
       * Dispatches `Func1` pre-hook then forwards to native D3D9 `ShowCursor`.
       */
      virtual int ShowCursor(bool show) override;
      /**
       * Address: 0x008ED910 (FUN_008ED910)
       * Slot: 34
       * Demangled: gpg::gal::DeviceD3D9::SetViewport
       *
       * void const *
       *
       * What it does:
       * Binds one viewport payload on the native D3D9 device lane.
       */
      void SetViewport(const D3DVIEWPORT9* viewport) override;
      /**
       * Address: 0x008EDA00 (FUN_008EDA00)
       * Slot: 35
       * Demangled: gpg::gal::DeviceD3D9::GetViewport
       *
       * void *
       *
       * What it does:
       * Reads one native D3D9 viewport into caller-provided payload storage.
       */
      void GetViewport(D3DVIEWPORT9* outViewport) override;
      /**
       * Address: 0x008EDAF0 (FUN_008EDAF0)
       * Slot: 36
       * Demangled: gpg::gal::DeviceD3D9::ClearTarget
       *
       * OutputContext const *
       *
       * What it does:
       * Applies output target/depth-stencil surface bindings from one output-context
       * payload onto the native D3D9 device.
       */
      virtual void ClearTarget(const OutputContext* context) override;
      // Slot 37 is gpg::gal::Device::GetContext (0x008E6810). Both
      // ??_7Device@gal@gpg@@6B@ and ??_7DeviceD3D9@gal@gpg@@6B@ carry that
      // same address there, so the backend inherits it rather than
      // overriding - redeclaring it here only added a second virtual.
      /**
       * Address: 0x008EDE30 (FUN_008EDE30)
       * Slot: 38
       * Demangled: gpg::gal::DeviceD3D9::Clear
       *
       * bool,bool,bool,std::uint32_t,float,int
       *
       * What it does:
       * Derives native D3D clear-mask bits from caller booleans and dispatches one clear
       * with packed color/depth/stencil payload.
       */
      virtual void Clear(
          bool clearTarget,
          bool clearZbuffer,
          bool clearStencil,
          std::uint32_t color,
          float depth,
          int stencil
       ) override;
      /**
       * Address: 0x008E8EE0 (FUN_008E8EE0)
       * Slot: 39
       * Demangled: gpg::gal::DeviceD3D9::ClearTextures
       *
       * What it does:
       * Dispatches `Func1` pre-hook then clears bound textures through pipeline-state helper.
       */
      void ClearTextures() override;
      /**
       * Address: 0x008EDF70 (FUN_008EDF70)
       * Slot: 40
       *
       * What it does:
       * Binds `vertexFormat`'s D3D9 vertex declaration.
       */
      void SetVertexDeclaration(boost::shared_ptr<VertexFormat> vertexFormat) override;
      /**
       * Address: 0x008EE0B0 (FUN_008EE0B0)
       * Slot: 41
       *
       * What it does:
       * Binds one vertex stream and sets its instancing frequency.
       */
      void SetVertexBuffer(
          std::uint32_t streamSlot,
          boost::shared_ptr<VertexBuffer> vertexBuffer,
          int streamFrequencyToken,
          int startVertex
       ) override;
      /**
       * Address: 0x008EE2E0 (FUN_008EE2E0)
       * Slot: 42
       *
       * What it does:
       * Binds `indexBuffer` as the device's index source.
       */
      void SetBufferIndices(boost::shared_ptr<IndexBuffer> indexBuffer) override;
      /**
       * Address: 0x008EE420 (FUN_008EE420)
       * Slot: 43
       * Demangled: gpg::gal::DeviceD3D9::SetFogState
       *
       * bool,void const *,float,float,int
       *
       * What it does:
       * Validates retained pipeline state and forwards one fog-state payload to
       * the pipeline-state owner.
       */
      virtual void SetFogState(
          bool enable,
          const Matrix* projection,
          float fogStart,
          float fogEnd,
          int fogColor
       ) override;
      /**
       * Address: 0x008EE510 (FUN_008EE510)
       * Slot: 44
       * Demangled: gpg::gal::DeviceD3D9::SetWireframeState
       *
       * bool
       *
       * What it does:
       * Validates retained pipeline state and forwards one wireframe-mode toggle.
       */
      void SetWireframeState(bool enabled) override;
      /**
       * Address: 0x008EE5E0 (FUN_008EE5E0)
       * Slot: 45
       * Demangled: gpg::gal::DeviceD3D9::SetColorWriteState
       *
       * bool,bool
       *
       * What it does:
       * Validates retained pipeline state and forwards recovered color-write mask
       * toggles.
       */
      void SetColorWriteState(bool writeColor, bool writeAlpha) override;
      /**
       * Address: 0x008EE850 (FUN_008EE850)
       * Slot: 46
       * Demangled: gpg::gal::DeviceD3D9::DrawIndexedPrimitive
       *
       * What it does:
       * Validates the topology and issues one indexed draw.
       */
      int DrawIndexedPrimitive(const DrawIndexedContext* context) override;
      /**
       * Address: 0x008EE6B0 (FUN_008EE6B0)
       * Slot: 47
       * Demangled: gpg::gal::DeviceD3D9::DrawPrimitive
       *
       * What it does:
       * Validates the topology and issues one non-indexed draw.
       */
      int DrawPrimitive(const DrawContext* context) override;
      /**
       * Address: 0x008EEA00 (FUN_008EEA00)
       * Slot: 48
       * Demangled: gpg::gal::DeviceD3D9::BeginTechnique
       *
       * What it does:
       * Validates retained pipeline state then forwards begin-technique state
       * setup.
       */
      virtual void BeginTechnique() override;
      /**
       * Address: 0x008EEAC0 (FUN_008EEAC0)
       * Slot: 49
       * Demangled: gpg::gal::DeviceD3D9::EndTechnique
       *
       * What it does:
       * Validates retained pipeline state then forwards end-technique cleanup.
       */
      virtual void EndTechnique() override;

      /**
       * Address: 0x008F3320 (FUN_008F3320)
       *
       * What it does:
       * Brings the device up for `context`: Direct3D, the device, adapters,
       * capabilities, heads, pipeline state and the frame event query.
       */
      void Setup(const DeviceContext* context);

      /**
       * Address: 0x008F2F70 (FUN_008F2F70)
       *
       * What it does:
       * Releases everything `Setup` built and empties the device context.
       */
      void Shutdown();

      /**
       * Address: 0x008E82B0 (FUN_008E82B0)
       *
       * D3DPRESENT_PARAMETERS *,DeviceContext const *,unsigned int
       *
       * What it does:
       * Builds one reset-parameter block for the requested head index.
       */
      D3DPRESENT_PARAMETERS* GetHeadParameters(
          D3DPRESENT_PARAMETERS* outParameters,
          const DeviceContext* context,
          unsigned int headIndex
      );

      /**
       * Address: 0x008E8F00 (FUN_008E8F00)
       *
       * D3DPRESENT_PARAMETERS *,DeviceContext const *
       *
       * What it does:
       * Writes reset-parameter blocks for all heads in the supplied context.
       */
      void GetDeviceParameters(D3DPRESENT_PARAMETERS* outParameters, const DeviceContext* context);

      /**
       * Address: 0x008EEB80 (FUN_008EEB80)
       *
       * What it does:
       * Recreates per-head backbuffer/depth wrappers after reset.
       */
      void CreateHeads();

      /**
       * Address: 0x008F2080 (FUN_008F2080)
       *
       * DeviceContext const *
       *
       * What it does:
       * Copies device-context capabilities, probes format/multisample support,
       * and updates shader/capability profile lanes.
       */
      int BuildDeviceCapabilities(const DeviceContext* context);

      /**
       * Address: 0x008F09A0 (FUN_008F09A0)
       *
       * What it does:
       * Compiles the context's source with its macros, creates the D3DX effect,
       * points it at the pipeline state's state manager, writes the compiled
       * bytes to the cache path when it can open it, and wraps the result in
       * an `EffectD3D9`.
       */
      boost::shared_ptr<Effect> CreateEffectFromSourceBuffer(const EffectContext& context);

      /**
       * Address: 0x008F0F90 (FUN_008F0F90)
       *
       * What it does:
       * Loads the compiled bytes from the context's cache path, creates the
       * D3DX effect from them, points it at the pipeline state's state manager
       * and wraps the result in an `EffectD3D9`.
       */
      boost::shared_ptr<Effect> CreateEffectFromCachedBinary(const EffectContext& context);

      /**
       * FAF addition, not in the shipped binary.
       *
       * What it does:
       * Reports whether vertex shaders on this device can read a texture of gal
       * format `textureFormat`: shader model 3 in both stages, hardware vertex
       * processing, and the format passing `D3DUSAGE_QUERY_VERTEXTEXTURE` on
       * the device's adapter.
       */
      [[nodiscard]] bool SupportsVertexTextureFormat(std::uint32_t textureFormat);

    public:
      int mCurThreadId = 0;                                    // +0x24 thread that ran Setup
      msvc8::vector<AdapterD3D9> mAdapters;                    // +0x28
      DeviceContext mDeviceContext{0};                         // +0x38 the context actually in force
      boost::shared_ptr<PipelineStateD3D9> mPipelineState;     // +0x6C
      IDirect3D9* mDirect3D = nullptr;                         // +0x74
      IDirect3DDevice9* mDevice = nullptr;                     // +0x78
      OutputContext* mHeads = nullptr;                         // +0x7C one per head, new[]'d by CreateHeads
      IDirect3DQuery9* mFrameEventQuery = nullptr;             // +0x80 D3DQUERYTYPE_EVENT
    };

    static_assert(offsetof(DeviceD3D9, mCurThreadId) == 0x24, "DeviceD3D9::mCurThreadId offset must be 0x24");
    static_assert(offsetof(DeviceD3D9, mAdapters) == 0x28, "DeviceD3D9::mAdapters offset must be 0x28");
    static_assert(offsetof(DeviceD3D9, mDeviceContext) == 0x38, "DeviceD3D9::mDeviceContext offset must be 0x38");
    static_assert(offsetof(DeviceD3D9, mPipelineState) == 0x6C, "DeviceD3D9::mPipelineState offset must be 0x6C");
    static_assert(offsetof(DeviceD3D9, mDirect3D) == 0x74, "DeviceD3D9::mDirect3D offset must be 0x74");
    static_assert(offsetof(DeviceD3D9, mDevice) == 0x78, "DeviceD3D9::mDevice offset must be 0x78");
    static_assert(offsetof(DeviceD3D9, mHeads) == 0x7C, "DeviceD3D9::mHeads offset must be 0x7C");
    static_assert(offsetof(DeviceD3D9, mFrameEventQuery) == 0x80, "DeviceD3D9::mFrameEventQuery offset must be 0x80");
    static_assert(sizeof(DeviceD3D9) == 0x84, "DeviceD3D9 size must be 0x84");
} // namespace gal
} // namespace gpg

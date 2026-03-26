// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"

namespace gpg {
namespace gal {
#if !defined(_D3D9TYPES_H_)
    struct _D3DPRESENT_PARAMETERS_;
#endif

    class Head;
    class DeviceContext;
    class Device;
    class CursorContext;
    class OutputContext;
    class CubeRenderTargetContext;
    class DepthStencilTargetContext;
    class IndexBufferContext;
    class RenderTargetContext;
    class TextureContext;
    class VertexBufferContext;
    class CubeRenderTargetD3D9;
    class DepthStencilTargetD3D9;
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
    class DeviceD3D9 {
    public:
      /**
       * Address: 0x008F37F0
       * Slot: 0
       * Demangled: sub_8F37F0
       */
      virtual void sub_8F37F0();
      /**
       * Address: 0x008E81D0 (FUN_008E81D0)
       * Slot: 1
       * Demangled: gpg::gal::DeviceD3D9::GetLog
       *
       * What it does:
       * Returns the global D3D9 log-storage lane used by this backend.
       */
      virtual void* GetLog();
      /**
       * Address: 0x008E81E0 (FUN_008E81E0)
       * Slot: 2
       * Demangled: gpg::gal::DeviceD3D9::GetDeviceContext
       *
       * What it does:
       * Dispatches `Func1` pre-hook and returns the embedded device-context lane.
       */
      virtual DeviceContext* GetDeviceContext();
      /**
       * Address: 0x008E81F0 (FUN_008E81F0)
       * Slot: 3
       * Demangled: gpg::gal::DeviceD3D9::GetCurThreadId
       *
       * What it does:
       * Returns the retained current thread-id lane at `this+0x24`.
       */
      virtual int GetCurThreadId();
      /**
       * Address: 0x008E8200 (FUN_008E8200)
       * Slot: 4
       * Demangled: gpg::gal::DeviceD3D9::Func1
       *
       * What it does:
       * Preserves the binary no-op virtual pre-hook slot.
       */
      virtual void Func1();
      /**
       * Address: 0x008F0170
       * Slot: 5
       * Demangled: gpg::gal::DeviceD3D9::GetModesForAdapter
       */
      virtual void GetModesForAdapter();
      /**
       * Address: 0x008EABF0 (FUN_008EABF0)
       * Slot: 6
       * Demangled: gpg::gal::DeviceD3D9::GetHead1
       *
       * What it does:
       * Validates one head index and returns the retained head lane pointer from
       * `this+0x7C` (`index * 0x20`).
       */
      virtual Head* GetHead1(unsigned int headIndex);
      /**
       * Address: 0x008EAB20 (FUN_008EAB20)
       * Slot: 7
       * Demangled: gpg::gal::DeviceD3D9::GetHead2
       *
       * What it does:
       * Validates one head index and returns the retained head lane pointer from
       * `this+0x7C` (`index * 0x20`).
       */
      virtual Head* GetHead2(unsigned int headIndex);
      /**
       * Address: 0x008E9B00 (FUN_008E9B00)
       * Slot: 8
       * Demangled: gpg::gal::DeviceD3D9::GetPipelineState
       *
       * What it does:
       * Dispatches `Func1` pre-hook and copies retained pipeline-state shared ownership.
       */
      virtual boost::shared_ptr<PipelineStateD3D9>* GetPipelineState(
          boost::shared_ptr<PipelineStateD3D9>* outPipelineState
       );
      /**
       * Address: 0x008F13D0
       * Slot: 9
       * Demangled: gpg::gal::DeviceD3D9::CreateEffect
       */
      virtual void CreateEffect();
      /**
       * Address: 0x008EACC0 (FUN_008EACC0)
       * Slot: 10
       * Demangled: gpg::gal::DeviceD3D9::CreateTexture
       *
       * What it does:
       * Creates one D3D9 texture from context source lanes and returns wrapped ownership.
       */
      virtual boost::shared_ptr<TextureD3D9>* CreateTexture(
          boost::shared_ptr<TextureD3D9>* outTexture,
          const TextureContext* context
       );
      /**
       * Address: 0x008EB610 (FUN_008EB610)
       * Slot: 11
       * Demangled: gpg::gal::DeviceD3D9::CreateVolumeTexture
       *
       * What it does:
       * Creates one D3D9 render-target texture wrapper from caller context lanes.
       */
      virtual boost::shared_ptr<RenderTargetD3D9>* CreateVolumeTexture(
          boost::shared_ptr<RenderTargetD3D9>* outRenderTarget,
          const RenderTargetContext* context
       );
      /**
       * Address: 0x008EB780 (FUN_008EB780)
       * Slot: 12
       * Demangled: gpg::gal::DeviceD3D9::CreateCubeRenderTarget
       *
       * What it does:
       * Creates one D3D9 cube-render-target wrapper from caller context lanes.
       */
      virtual boost::shared_ptr<CubeRenderTargetD3D9>* CreateCubeRenderTarget(
          boost::shared_ptr<CubeRenderTargetD3D9>* outCubeRenderTarget,
          const CubeRenderTargetContext* context
       );
      /**
       * Address: 0x008EB8E0 (FUN_008EB8E0)
       * Slot: 13
       * Demangled: gpg::gal::DeviceD3D9::CreateDepthStencilTarget
       *
       * What it does:
       * Creates one D3D9 depth-stencil surface wrapper from caller context lanes.
       */
      virtual boost::shared_ptr<DepthStencilTargetD3D9>* CreateDepthStencilTarget(
          boost::shared_ptr<DepthStencilTargetD3D9>* outDepthStencilTarget,
          const DepthStencilTargetContext* context
       );
      /**
       * Address: 0x008EBA50 (FUN_008EBA50)
       * Slot: 14
       * Demangled: gpg::gal::DeviceD3D9::CreateVertexFormat
       *
       * What it does:
       * Creates one D3D9 vertex declaration wrapper for the requested format token.
       */
      virtual boost::shared_ptr<VertexFormatD3D9>* CreateVertexFormat(
          boost::shared_ptr<VertexFormatD3D9>* outVertexFormat,
          std::uint32_t formatCode
       );
      /**
       * Address: 0x008EBBB0 (FUN_008EBBB0)
       * Slot: 15
       * Demangled: gpg::gal::DeviceD3D9::CreateVertexBuffer
       *
       * What it does:
       * Creates one D3D9 vertex buffer wrapper from caller context lanes.
       */
      virtual boost::shared_ptr<VertexBufferD3D9>* CreateVertexBuffer(
          boost::shared_ptr<VertexBufferD3D9>* outVertexBuffer,
          const VertexBufferContext* context
       );
      /**
       * Address: 0x008EBD30 (FUN_008EBD30)
       * Slot: 16
       * Demangled: gpg::gal::DeviceD3D9::CreateIndexBuffer
       *
       * What it does:
       * Creates one D3D9 index buffer wrapper from caller context lanes.
       */
      virtual boost::shared_ptr<IndexBufferD3D9>* CreateIndexBuffer(
          boost::shared_ptr<IndexBufferD3D9>* outIndexBuffer,
          const IndexBufferContext* context
       );
      /**
       * Address: 0x008EC440 (FUN_008EC440)
       * Slot: 17
       * Demangled: gpg::gal::DeviceD3D9::CreateRenderTarget
       *
       * What it does:
       * Validates source/destination handles and dispatches one native
       * `GetRenderTargetData` copy lane.
       */
      virtual void CreateRenderTarget(
          RenderTargetD3D9** sourceTexture,
          boost::shared_ptr<TextureD3D9>* destinationTexture
       );
      /**
       * Address: 0x008EC250 (FUN_008EC250)
       * Slot: 18
       * Demangled: gpg::gal::DeviceD3D9::StretchRect
       *
       * What it does:
       * Blits one source render surface into one destination render surface.
       */
      virtual void StretchRect(
          RenderTargetD3D9** sourceTexture,
          RenderTargetD3D9** destinationTexture,
          const void* sourceRect,
          const void* destinationRect
       );
      /**
       * Address: 0x008EBF70 (FUN_008EBF70)
       * Slot: 19
       * Demangled: gpg::gal::DeviceD3D9::UpdateSurface
       *
       * What it does:
       * Copies level-0 source texture surface data into the destination texture.
       */
      virtual void UpdateSurface(
          TextureD3D9** sourceTexture,
          TextureD3D9** destinationTexture,
          const void* sourceRect,
          const void* destinationRect
       );
      /**
       * Address: 0x008ECB50 (FUN_008ECB50)
       * Slot: 20
       * Demangled: gpg::gal::DeviceD3D9::Func3
       *
       * What it does:
       * Saves one cube texture lane to file as DDS.
       */
      virtual void Func3(TextureD3D9** texture, const msvc8::string& filePath);
      /**
       * Address: 0x008EC970 (FUN_008EC970)
       * Slot: 21
       * Demangled: gpg::gal::DeviceD3D9::Func4
       *
       * What it does:
       * Saves one render surface lane to file using the requested image format token.
       */
      virtual void Func4(RenderTargetD3D9** renderTarget, const msvc8::string& filePath, int fileFormatToken);
      /**
       * Address: 0x008EC6A0 (FUN_008EC6A0)
       * Slot: 22
       * Demangled: gpg::gal::DeviceD3D9::Func5
       *
       * What it does:
       * Saves one texture surface either to file or to caller memory buffer.
       */
      virtual void Func5(
          TextureD3D9** texture,
          const msvc8::string& filePath,
          int fileFormatToken,
          gpg::MemBuffer<char>* outBuffer
       );
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
       );
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
       );
      /**
       * Address: 0x008E8210 (FUN_008E8210)
       * Slot: 25
       * Demangled: gpg::gal::DeviceD3D9::Func8
       *
       * What it does:
       * Forwards the embedded device-context lane to slot-26 reset dispatch.
       */
      virtual int Func8();
      /**
       * Address: 0x008F3070 (FUN_008F3070)
       * Slot: 26
       * Demangled: gpg::gal::DeviceD3D9::Func9
       *
       * DeviceContext *
       *
       * What it does:
       * Resets the native D3D9 device using one context payload, then rebuilds
       * capabilities/head resources and recreates pipeline/query state.
       */
      virtual int Func9(DeviceContext* context);
      /**
       * Address: 0x008ED360 (FUN_008ED360)
       * Slot: 27
       * Demangled: gpg::gal::DeviceD3D9::TestCooperativeLevel
       *
       * What it does:
       * Probes native cooperative-level state and maps D3D9 result values into backend
       * status tokens (`0`, `1`, `2`).
       */
      virtual int TestCooperativeLevel();
      /**
       * Address: 0x008ED450 (FUN_008ED450)
       * Slot: 28
       * Demangled: gpg::gal::DeviceD3D9::BeginScene
       *
       * What it does:
       * Begins one native D3D9 scene and issues one begin marker on the retained frame
       * event query when available.
       */
      virtual int BeginScene();
      /**
       * Address: 0x008ED550 (FUN_008ED550)
       * Slot: 29
       * Demangled: gpg::gal::DeviceD3D9::EndScene
       *
       * What it does:
       * Ends one native D3D9 scene and throws on failing HRESULT.
       */
      virtual void EndScene();
      /**
       * Address: 0x008ED640 (FUN_008ED640)
       * Slot: 30
       * Demangled: gpg::gal::DeviceD3D9::Present
       *
       * What it does:
       * Flushes pending frame-event query data then presents the native swap chain.
       */
      virtual void Present();
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
      virtual void SetCursor(const CursorContext* context);
      /**
       * Address: 0x008E8220 (FUN_008E8220)
       * Slot: 32
       * Demangled: gpg::gal::DeviceD3D9::InitCursor
       *
       * What it does:
       * Preserves the binary no-op cursor-init slot body.
       */
      virtual void InitCursor();
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
      virtual int ShowCursor(bool show);
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
      virtual void SetViewport(const void* viewport);
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
      virtual void GetViewport(void* outViewport);
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
      virtual void ClearTarget(const OutputContext* context);
      /**
       * Address: 0x008E6810
       * Slot: 37
       * Demangled: gpg::gal::Device::GetContext
       */
      virtual void GetContext();
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
       );
      /**
       * Address: 0x008E8EE0 (FUN_008E8EE0)
       * Slot: 39
       * Demangled: gpg::gal::DeviceD3D9::ClearTextures
       *
       * What it does:
       * Dispatches `Func1` pre-hook then clears bound textures through pipeline-state helper.
       */
      virtual int ClearTextures();
      /**
       * Address: 0x008EDF70 (FUN_008EDF70)
       * Slot: 40
       * Demangled: gpg::gal::DeviceD3D9::SetVertexDeclaration
       *
       * boost::shared_ptr<gpg::gal::VertexFormatD3D9>
       *
       * What it does:
       * Binds one vertex declaration from caller-provided vertex-format ownership.
       */
      virtual void SetVertexDeclaration(boost::shared_ptr<VertexFormatD3D9> vertexFormat);
      /**
       * Address: 0x008EE0B0 (FUN_008EE0B0)
       * Slot: 41
       * Demangled: gpg::gal::DeviceD3D9::SetVertexBuffer
       *
       * std::uint32_t,boost::shared_ptr<gpg::gal::VertexBufferD3D9>,int,int
       *
       * What it does:
       * Binds one vertex-buffer stream and applies per-stream frequency token lanes.
       */
      virtual void SetVertexBuffer(
          std::uint32_t streamSlot,
          boost::shared_ptr<VertexBufferD3D9> vertexBuffer,
          int streamFrequencyToken,
          int streamOffsetMultiplier
       );
      /**
       * Address: 0x008EE2E0 (FUN_008EE2E0)
       * Slot: 42
       * Demangled: gpg::gal::DeviceD3D9::SetBufferIndices
       *
       * boost::shared_ptr<gpg::gal::IndexBufferD3D9>
       *
       * What it does:
       * Dispatches one native `SetIndices` bind from caller-owned index-buffer
       * shared ownership.
       */
      virtual void SetBufferIndices(boost::shared_ptr<IndexBufferD3D9> indexBuffer);
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
          const void* projection,
          float fogStart,
          float fogEnd,
          int fogColor
       );
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
      virtual int SetWireframeState(bool enabled);
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
      virtual int SetColorWriteState(bool arg1, bool arg2);
      /**
       * Address: 0x008EE850 (FUN_008EE850)
       * Slot: 46
       * Demangled: gpg::gal::DeviceD3D9::DrawIndexedPrimitive
       *
       * void const *
       *
       * What it does:
       * Validates indexed draw topology, binds native primitive type, and
       * dispatches one native indexed draw.
       */
      virtual int DrawIndexedPrimitive(const void* context);
      /**
       * Address: 0x008EE6B0 (FUN_008EE6B0)
       * Slot: 47
       * Demangled: gpg::gal::DeviceD3D9::DrawPrimitive
       *
       * void const *
       *
       * What it does:
       * Validates non-indexed draw topology, binds native primitive type, and
       * dispatches one native draw.
       */
      virtual int DrawPrimitive(const void* context);
      /**
       * Address: 0x008EEA00 (FUN_008EEA00)
       * Slot: 48
       * Demangled: gpg::gal::DeviceD3D9::BeginTechnique
       *
       * What it does:
       * Validates retained pipeline state then forwards begin-technique state
       * setup.
       */
      virtual void BeginTechnique();
      /**
       * Address: 0x008EEAC0 (FUN_008EEAC0)
       * Slot: 49
       * Demangled: gpg::gal::DeviceD3D9::EndTechnique
       *
       * What it does:
       * Validates retained pipeline state then forwards end-technique cleanup.
       */
      virtual void EndTechnique();

      /**
       * Address: 0x008E82B0 (FUN_008E82B0)
       *
       * D3DPRESENT_PARAMETERS *,DeviceContext const *,unsigned int
       *
       * What it does:
       * Builds one reset-parameter block for the requested head index.
       */
      _D3DPRESENT_PARAMETERS_* GetHeadParameters(
          _D3DPRESENT_PARAMETERS_* outParameters,
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
      void GetDeviceParameters(_D3DPRESENT_PARAMETERS_* outParameters, const DeviceContext* context);

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
    };

    /**
     * Address: 0x008EFD50 (FUN_008EFD50)
     *
     * What it does:
     * Allocates and initializes one D3D9 backend device object with recovered
     * default runtime lanes.
     */
    Device* CreateDeviceD3D9Backend();

    /**
     * Address context: 0x008F3320 (FUN_008F3320)
     *
     * What it does:
     * Initializes recovered startup-visible D3D9 runtime lanes from one caller
     * device-context payload.
     */
    void InitializeDeviceD3D9Backend(Device* device, const DeviceContext* context);
} // namespace gal
} // namespace gpg

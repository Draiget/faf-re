// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "legacy/containers/String.h"

namespace gpg {
namespace gal {
    class Device;
    class OutputContext;
    class CursorContext;
    class DeviceContext;
    class CubeRenderTargetContext;
    class DepthStencilTargetContext;
    class EffectContext;
    class IndexBufferContext;
    class RenderTargetContext;
    class TextureContext;
    class VertexBufferContext;
    class CubeRenderTargetD3D10;
    class DepthStencilTargetD3D10;
    class EffectD3D10;
    class PipelineStateD3D10;
    class IndexBufferD3D10;
    class RenderTargetD3D10;
    class TextureD3D10;
    class VertexBufferD3D10;
    class VertexFormatD3D10;

    struct WeakRefCountedToken
    {
        void** vtable = nullptr;          // +0x00
        volatile long strongCount;    // +0x04
        volatile long weakCount;      // +0x08
    };

    static_assert(sizeof(WeakRefCountedToken) == 0x0C, "WeakRefCountedToken size must be 0x0C");

    /**
     * VFTABLE: 0x00D4340C
     * COL:  0x00E50F78
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\DeviceD3D10.cpp
     * Log/code strings:
     *  - unknown error
     */
    class DeviceD3D10 {
    public:
      /**
       * Address: 0x009005E0
       * Slot: 0
       * Demangled: sub_9005E0
       */
      virtual void sub_9005E0();
      /**
       * Address: 0x008F86B0
       * Slot: 1
       * Demangled: gpg::gal::DeviceD3D10::GetLog
       *
       * What it does:
       * Returns the retained device log-storage lane at `this+0x50`.
       */
      virtual void* GetLog();
      /**
       * Address: 0x008F86C0
       * Slot: 2
       * Demangled: gpg::gal::DeviceD3D10::GetDeviceContext
       *
       * What it does:
       * Returns the retained device-context pointer lane at `this+0x60`.
       */
      virtual DeviceContext* GetDeviceContext();
      /**
       * Address: 0x008F86D0
       * Slot: 3
       * Demangled: gpg::gal::DeviceD3D10::GetCurThreadId
       *
       * What it does:
       * Returns the current thread-id lane stored at `this+0x4C`.
       */
      virtual int GetCurThreadId();
      /**
       * Address: 0x008F86E0
       * Slot: 4
       * Demangled: gpg::gal::DeviceD3D10::Func1
       *
       * What it does:
       * Preserves the binary no-op slot body.
       */
      virtual void Func1();
      /**
       * Address: 0x008F86F0
       * Slot: 5
       * Demangled: gpg::gal::DeviceD3D10::GetModesForAdapter
       *
       * What it does:
       * Preserves the binary no-op slot with `retn 8` calling-shape.
       */
      virtual void GetModesForAdapter(int arg1, int arg2);
      /**
       * Address: 0x008FAC50
       * Slot: 6
       * Demangled: gpg::gal::DeviceD3D10::GetHead1
       *
       * What it does:
       * Validates one head index and returns the retained head lane pointer from
       * the head-array base at `this+0x118`.
       */
      virtual void* GetHead1(unsigned int headIndex);
      /**
       * Address: 0x008FAB80
       * Slot: 7
       * Demangled: gpg::gal::DeviceD3D10::GetHead2
       *
       * What it does:
       * Validates one head index and returns the retained head lane pointer from
       * the head-array base at `this+0x118`.
       */
      virtual void* GetHead2(unsigned int headIndex);
      /**
       * Address: 0x008FA220
       * Slot: 8
       * Demangled: gpg::gal::DeviceD3D10::GetPipelineState
       *
       * What it does:
       * Copies the retained pipeline-state shared handle lane (`this+0xB4/+0xB8`)
       * into caller output.
       */
      virtual boost::shared_ptr<PipelineStateD3D10>* GetPipelineState(
          boost::shared_ptr<PipelineStateD3D10>* outPipelineState
      );
      /**
       * Address: 0x008FEA00 (FUN_008FEA00)
       * Slot: 9
       * Demangled: gpg::gal::DeviceD3D10::CreateEffect
       *
       * What it does:
       * Compiles one effect from source memory with recovered macro-injection lanes
       * and returns a wrapped D3D10 effect handle.
       */
      virtual boost::shared_ptr<EffectD3D10>* CreateEffect(
          boost::shared_ptr<EffectD3D10>* outEffect,
          EffectContext* context
      );
      /**
       * Address: 0x008FAD20 (FUN_008FAD20)
       * Slot: 10
       * Demangled: gpg::gal::DeviceD3D10::CreateTexture
       *
       * What it does:
       * Creates one texture resource from context source lanes and returns the wrapped
       * texture + shader-resource-view payload.
       */
      virtual boost::shared_ptr<TextureD3D10>* CreateTexture(
          boost::shared_ptr<TextureD3D10>* outTexture,
          const TextureContext* context
      );
      /**
       * Address: 0x008FB1D0 (FUN_008FB1D0)
       * Slot: 11
       * Demangled: gpg::gal::DeviceD3D10::CreateVolumeTexture
       *
       * What it does:
       * Creates one 2D render-target texture + RTV/SRV pair from caller context lanes.
       */
      virtual boost::shared_ptr<RenderTargetD3D10>* CreateVolumeTexture(
          boost::shared_ptr<RenderTargetD3D10>* outRenderTarget,
          const RenderTargetContext* context
      );
      /**
       * Address: 0x008FA6B0 (FUN_008FA6B0)
       * Slot: 12
       * Demangled: gpg::gal::DeviceD3D10::CreateCubeRenderTarget
       *
       * What it does:
       * Allocates one cube-render-target wrapper and returns it through caller shared output.
       */
      virtual boost::shared_ptr<CubeRenderTargetD3D10>* CreateCubeRenderTarget(
          boost::shared_ptr<CubeRenderTargetD3D10>* outCubeRenderTarget,
          const CubeRenderTargetContext* context
      );
      /**
       * Address: 0x008FB570 (FUN_008FB570)
       * Slot: 13
       * Demangled: gpg::gal::DeviceD3D10::CreateDepthStencilTarget
       *
       * What it does:
       * Creates one depth-stencil texture + DSV/SRV lane and returns wrapped ownership.
       */
      virtual boost::shared_ptr<DepthStencilTargetD3D10>* CreateDepthStencilTarget(
          boost::shared_ptr<DepthStencilTargetD3D10>* outDepthStencilTarget,
          const DepthStencilTargetContext* context
      );
      /**
       * Address: 0x008FE220 (FUN_008FE220)
       * Slot: 14
       * Demangled: gpg::gal::DeviceD3D10::CreateVertexFormat
       *
       * What it does:
       * Builds one input-layout declaration for the requested format token.
       */
      virtual boost::shared_ptr<VertexFormatD3D10>* CreateVertexFormat(
          boost::shared_ptr<VertexFormatD3D10>* outVertexFormat,
          std::uint32_t formatToken
      );
      /**
       * Address: 0x008FB8D0 (FUN_008FB8D0)
       * Slot: 15
       * Demangled: gpg::gal::DeviceD3D10::CreateVertexBuffer
       *
       * What it does:
       * Creates one GPU vertex buffer plus staging/upload lanes from caller context.
       */
      virtual boost::shared_ptr<VertexBufferD3D10>* CreateVertexBuffer(
          boost::shared_ptr<VertexBufferD3D10>* outVertexBuffer,
          const VertexBufferContext* context
      );
      /**
       * Address: 0x008FBB60 (FUN_008FBB60)
       * Slot: 16
       * Demangled: gpg::gal::DeviceD3D10::CreateIndexBuffer
       *
       * What it does:
       * Creates one GPU index buffer plus staging/upload lanes from caller context.
       */
      virtual boost::shared_ptr<IndexBufferD3D10>* CreateIndexBuffer(
          boost::shared_ptr<IndexBufferD3D10>* outIndexBuffer,
          const IndexBufferContext* context
      );
      /**
       * Address: 0x008FC540
       * Slot: 17
       * Demangled: gpg::gal::DeviceD3D10::CreateRenderTarget
       *
       * What it does:
       * Validates source/destination texture handles and dispatches one native
       * copy-resource lane on the retained D3D10 device.
       */
      virtual int CreateRenderTarget(
          RenderTargetD3D10** sourceTexture,
          TextureD3D10** destinationTexture
      );
      /**
       * Address: 0x008FC290
       * Slot: 18
       * Demangled: gpg::gal::DeviceD3D10::StretchRect
       *
       * What it does:
       * If source/destination contexts match, dispatches native subresource copy;
       * otherwise falls back to SRV->RTV blit helper path.
       */
      virtual void StretchRect(
          RenderTargetD3D10** sourceTexture,
          RenderTargetD3D10** destinationTexture,
          const void* sourceRect,
          const void* destinationPoint
      );
      /**
       * Address: 0x008FBDF0
       * Slot: 19
       * Demangled: gpg::gal::DeviceD3D10::UpdateSurface
       *
       * What it does:
       * If source/destination texture contexts match, dispatches native subresource
       * copy; otherwise performs readback+rebuild fallback copy path.
       */
      virtual void UpdateSurface(
          TextureD3D10** sourceTexture,
          TextureD3D10** destinationTexture,
          const void* sourceRect,
          const void* destinationPoint
      );
      /**
       * Address: 0x008F8700
       * Slot: 20
       * Demangled: gpg::gal::DeviceD3D10::Func3
       *
       * What it does:
       * Preserves the binary no-op slot with `retn 8` calling-shape.
       */
      virtual void Func3(int arg1, int arg2);
      /**
       * Address: 0x008FC9B0
       * Slot: 21
       * Demangled: gpg::gal::DeviceD3D10::Func4
       *
       * What it does:
       * Saves one texture to a file path using the recovered image-format token map.
       */
      virtual void Func4(
          RenderTargetD3D10** renderTarget,
          const msvc8::string& filePath,
          int fileFormatToken
      );
      /**
       * Address: 0x008FC6B0
       * Slot: 22
       * Demangled: gpg::gal::DeviceD3D10::Func5
       *
       * What it does:
       * Saves one texture either to caller memory buffer or to file path depending
       * on whether `outBuffer` is null.
       */
      virtual void Func5(
          TextureD3D10** texture,
          const msvc8::string& filePath,
          int fileFormatToken,
          gpg::MemBuffer<char>* outBuffer
      );
      /**
       * Address: 0x008FCAC0
       * Slot: 23
       * Demangled: gpg::gal::DeviceD3D10::GetTexture2D
       *
       * What it does:
       * Decodes one texture resource from in-memory bytes and exports mapped blocks
       * into caller `MemBuffer`, writing decoded width/height lanes.
       */
      virtual void GetTexture2D(
          const void* sourceData,
          std::uint32_t sourceBytes,
          gpg::MemBuffer<char>* outTextureData,
          std::uint32_t* outWidth,
          int* outHeight
      );
      /**
       * Address: 0x008FA260
       * Slot: 24
       * Demangled: gpg::gal::DeviceD3D10::Func7
       *
       * What it does:
       * Resets caller weak-handle output lane and consumes one temporary shared-handle
       * argument by value.
       */
      virtual boost::weak_ptr<void>* Func7(
          boost::weak_ptr<void>* outWeakHandle,
          boost::shared_ptr<void> temporarySharedHandle
      );
      /**
       * Address: 0x008F8720
       * Slot: 25
       * Demangled: gpg::gal::DeviceD3D10::Func8
       *
       * What it does:
       * Preserves the binary no-op slot body.
       */
      virtual void Func8();
      /**
       * Address: 0x008F8710
       * Slot: 26
       * Demangled: gpg::gal::DeviceD3D10::Func9
       *
       * What it does:
       * Preserves the binary no-op slot with `retn 4` calling-shape.
       */
      virtual void Func9(int arg1);
      /**
       * Address: 0x008F8730
       * Slot: 27
       * Demangled: gpg::gal::DeviceD3D10::TestCooperativeLevel
       */
      virtual int TestCooperativeLevel();
      /**
       * Address: 0x008F8740
       * Slot: 28
       * Demangled: gpg::gal::DeviceD3D10::BeginScene
       */
      virtual void BeginScene();
      /**
       * Address: 0x008F8750
       * Slot: 29
       * Demangled: gpg::gal::DeviceD3D10::EndScene
       */
      virtual void EndScene();
      /**
       * Address: 0x008FCEA0
       * Slot: 30
       * Demangled: gpg::gal::DeviceD3D10::Present
       *
       * What it does:
       * Presents each retained swapchain and throws on first failing HRESULT.
       */
      virtual void Present();
      /**
       * Address: 0x008F8760
       * Slot: 31
       * Demangled: gpg::gal::DeviceD3D10::SetCursor
       *
       * CursorContext const *
       *
       * What it does:
       * Delegates cursor rebuild/apply state to the retained `CursorD3D10` lane
       * at `this+0x11C`.
       */
      virtual void* SetCursor(const CursorContext* context);
      /**
       * Address: 0x008F8770
       * Slot: 32
       * Demangled: gpg::gal::DeviceD3D10::InitCursor
       *
       * What it does:
       * Delegates cursor initialization validation to the retained
       * `CursorD3D10` lane at `this+0x11C`.
       */
      virtual void* InitCursor();
      /**
       * Address: 0x008F8780
       * Slot: 33
       * Demangled: gpg::gal::DeviceD3D10::ShowCursor
       *
       * bool
       *
       * What it does:
       * Delegates native cursor show/hide loop control to the retained
       * `CursorD3D10` lane at `this+0x11C`.
       */
      virtual int ShowCursor(bool show);
      /**
       * Address: 0x008F8790
       * Slot: 34
       * Demangled: gpg::gal::DeviceD3D10::SetViewport
       *
       * What it does:
       * Binds one native viewport using caller-provided D3D10 viewport payload.
       */
      virtual int SetViewport(const void* viewport);
      /**
       * Address: 0x008F87F0
       * Slot: 35
       * Demangled: gpg::gal::DeviceD3D10::GetViewport
       *
       * What it does:
       * Reads one native viewport and copies it into caller-provided payload.
       */
      virtual void* GetViewport(void* outViewport);
      /**
       * Address: 0x008F94B0
       * Slot: 36
       * Demangled: gpg::gal::DeviceD3D10::ClearTarget
       *
       * What it does:
       * Copies the caller output-context into retained device state, resolves
       * render/depth target views, and dispatches native clear-target binding.
       */
      virtual int ClearTarget(const OutputContext* context);
      /**
       * Address: 0x008E6810
       * Slot: 37
       * Demangled: gpg::gal::Device::GetContext
       */
      virtual void GetContext();
      /**
       * Address: 0x008F9510
       * Slot: 38
       * Demangled: gpg::gal::DeviceD3D10::Clear
       *
       * bool,bool,bool,uint32_t,float,int
       *
       * What it does:
       * Clears color and/or depth-stencil lanes on retained active targets,
       * deriving clear-mask bits from depth/stencil booleans.
       */
      virtual int Clear(
          bool clearColor,
          bool clearDepth,
          bool clearStencil,
          std::uint32_t packedColor,
          float depth,
          int stencil
      );
      /**
       * Address: 0x008F95F0
       * Slot: 39
       * Demangled: gpg::gal::DeviceD3D10::ClearTextures
       *
       * What it does:
       * Clears shader-resource bindings for 128 texture slots on the retained
       * native D3D10 device lane.
       */
      virtual int ClearTextures();
      /**
       * Address: 0x008F9600
       * Slot: 40
       * Demangled: gpg::gal::DeviceD3D10::SetVertexDeclaration
       *
       * What it does:
       * Validates one vertex-format declaration handle, binds it on the native
       * device, then releases the previous weak-ref token when provided.
       */
      virtual int SetVertexDeclaration(VertexFormatD3D10* vertexFormat, WeakRefCountedToken* previousFormatRef);
      /**
       * Address: 0x008F9690
       * Slot: 41
       * Demangled: gpg::gal::DeviceD3D10::Func15
       *
       * What it does:
       * Binds one vertex-buffer stream on the native device and updates the
       * retained stream weak-ref lane.
       */
      virtual WeakRefCountedToken* Func15(
          std::uint32_t streamSlot,
          VertexBufferD3D10* vertexBuffer,
          WeakRefCountedToken* previousStreamRef,
          WeakRefCountedToken* currentStreamRef,
          int startVertexMultiplier
      );
      /**
       * Address: 0x008F9760
       * Slot: 42
       * Demangled: gpg::gal::DeviceD3D10::SetBufferIndices
       *
       * What it does:
       * Binds one index buffer on the native device with recovered format token
       * selection and releases the prior weak-ref token when provided.
       */
      virtual int SetBufferIndices(IndexBufferD3D10* indexBuffer, WeakRefCountedToken* previousIndexRef);
      /**
       * Address: 0x008FE6D0
       * Slot: 43
       * Demangled: gpg::gal::DeviceD3D10::SetFogState
       *
       * What it does:
       * Preserves the binary no-op fog-state slot.
       */
      virtual void SetFogState(int arg1, int arg2, int arg3, int arg4, int arg5);
      /**
       * Address: 0x008FE6E0
       * Slot: 44
       * Demangled: gpg::gal::DeviceD3D10::SetWireframeState
       *
       * What it does:
       * Preserves the binary no-op wireframe-state slot.
       */
      virtual void SetWireframeState(int arg1);
      /**
       * Address: 0x008FE6F0
       * Slot: 45
       * Demangled: gpg::gal::DeviceD3D10::SetColorWriteState
       *
       * What it does:
       * Preserves the binary no-op color-write-state slot.
       */
      virtual void SetColorWriteState(int arg1, int arg2);
      /**
       * Address: 0x008FD0A0
       * Slot: 46
       * Demangled: gpg::gal::DeviceD3D10::DrawIndexedPrimitive
       *
       * What it does:
       * Applies topology mapping and dispatches indexed draw or indexed-instanced draw.
       */
      virtual int DrawIndexedPrimitive(const void* context);
      /**
       * Address: 0x008FCF90
       * Slot: 47
       * Demangled: gpg::gal::DeviceD3D10::DrawPrimitive
       *
       * What it does:
       * Applies topology mapping and dispatches draw or draw-instanced.
       */
      virtual int DrawPrimitive(const void* context);
      /**
       * Address: 0x008F9810
       * Slot: 48
       * Demangled: gpg::gal::DeviceD3D10::BeginTechnique
       *
       * What it does:
       * Applies retained raster/depth/blend state lanes from the technique
       * binding runtime onto the native D3D10 device.
       */
      virtual int BeginTechnique();
      /**
       * Address: 0x008F9820
       * Slot: 49
       * Demangled: gpg::gal::DeviceD3D10::EndTechnique
       *
       * What it does:
       * For this binary lane, forwards to a no-op helper over the technique
       * binding runtime.
       */
      virtual int EndTechnique();

      /**
       * Address: 0x008FD2E0 (FUN_008FD2E0)
       *
       * What it does:
       * Dynamically resolves required D3D10/D3DX10/DXGI module exports used by
       * backend startup.
       */
      void DynamicLink();

      /**
       * Address: 0x00900A70 (FUN_00900A70)
       *
       * What it does:
       * Enumerates DXGI adapters, probes adapter output mode caches, and stores
       * valid adapters into the backend adapter list.
       */
      int SetupDXGIDevice();

      /**
       * Address: 0x008FDB80 (FUN_008FDB80)
       *
       * What it does:
       * Builds RTT helper effect/state resources (effect, technique, quad VB,
       * and input layout) used by stretch-rect paths.
       */
      void SetUpRTT();

      /**
       * Address: 0x008FF5B0 (FUN_008FF5B0)
       *
       * What it does:
       * Copies the requested device context into runtime, validates requested
       * head count, and populates per-head format/sample capability lanes.
       */
      std::uint32_t CheckAvailableFormats(DeviceContext* context);

      /**
       * Address: 0x008FD500 (FUN_008FD500)
       *
       * What it does:
       * Creates per-head backbuffer render/depth target wrappers and stores
       * them in the runtime output-context array.
       */
      void CreateRenderTargets();

      /**
       * Address: 0x00900B30 (FUN_00900B30)
       *
       * What it does:
       * Executes full D3D10 startup setup chain for one requested device
       * context (dynamic link, DXGI/device/swapchain/effects/state/capability
       * initialization).
       */
      void Setup(DeviceContext* context);
    };

    /**
     * Address: 0x008FE5D0 (FUN_008FE5D0)
     *
     * What it does:
     * Allocates and initializes one D3D10 backend object with recovered
     * constructor-default runtime lanes.
     */
    Device* CreateDeviceD3D10Backend();

    /**
     * Address context: 0x008E6B60 (func_CreateDeviceD3D)
     *
     * What it does:
     * Copies startup device-context payload into recovered D3D10 backend
     * context lanes and records the current thread id.
     */
    void InitializeDeviceD3D10Backend(Device* device, const DeviceContext* context);
} // namespace gal
} // namespace gpg

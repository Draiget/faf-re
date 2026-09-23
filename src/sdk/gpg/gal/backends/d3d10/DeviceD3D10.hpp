// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d10.h>
#include <dxgi.h>

#include "AdapterD3D10.hpp"
#include "CursorD3D10.hpp"
#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/Texture.hpp"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg {
namespace gal {
    class Device;
    class OutputContext;
    class CursorContext;
    class DeviceContext;
    class DrawContext;
    class DrawIndexedContext;
    class CubeRenderTargetContext;
    class DepthStencilTargetContext;
    class EffectContext;
    class IndexBufferContext;
    class RenderTargetContext;
    class TextureContext;
    class VertexBufferContext;
    class CubeRenderTargetD3D10;
    class DepthStencilTargetD3D10;
    class Effect;
    class EffectD3D10;
    class PipelineStateD3D10;
    class IndexBufferD3D10;
    class RenderTargetD3D10;
    class TextureD3D10;
    class VertexBufferD3D10;
    class VertexFormatD3D10;
    class IndexBuffer;
    class PipelineState;
    class VertexBuffer;
    class VertexFormat;

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
       * Address: 0x00900450 (FUN_00900450)
       * Address: 0x009005E0 (FUN_009005E0, slot 0: the scalar deleting destructor)
       *
       * What it does:
       * Releases the device objects and unloads the D3D10 modules, then
       * destroys the members.
       */
      virtual ~DeviceD3D10();
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
      virtual void Func1() const;
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
       * Address: 0x008FAB80
       * Slot: 7
       *
       * What it does:
       * Returns head `headIndex`'s output context from `mHeadOutputContexts`.
       */
      virtual OutputContext* GetHeadOutputContext(unsigned int headIndex);
      /**
       * Address: 0x008FAC50
       * Slot: 6
       *
       * What it does:
       * The const overload of slot 7.
       */
      virtual const OutputContext* GetHeadOutputContext(unsigned int headIndex) const;
      /**
       * Address: 0x008FA220
       * Slot: 8
       *
       * What it does:
       * Returns the device's pipeline state.
       */
      virtual boost::shared_ptr<PipelineState> GetPipelineState();
      /**
       * Address: 0x008FEA00 (FUN_008FEA00)
       * Slot: 9
       * Demangled: gpg::gal::DeviceD3D10::CreateEffect
       *
       * What it does:
       * Compiles the context's source with the D3D10 state macros added and
       * wraps the result in an `EffectD3D10`, constructed straight into the
       * caller's return slot.
       */
      virtual boost::shared_ptr<Effect> CreateEffect(const EffectContext& context);
      /**
       * Address: 0x008FAD20 (FUN_008FAD20)
       * Slot: 10
       *
       * What it does:
       * Creates one texture with its shader-resource view and wraps both in a
       * `TextureD3D10`.
       */
      virtual boost::shared_ptr<Texture> CreateTexture(const TextureContext* context);
      /**
       * Address: 0x008FB1D0 (FUN_008FB1D0)
       * Slot: 11
       *
       * What it does:
       * Creates one render-target texture with its RTV/SRV pair and wraps them
       * in a `RenderTargetD3D10`.
       */
      virtual boost::shared_ptr<RenderTarget> CreateRenderTarget(const RenderTargetContext* context);
      /**
       * Address: 0x008FA6B0 (FUN_008FA6B0)
       * Slot: 12
       *
       * What it does:
       * Returns an empty `CubeRenderTargetD3D10`; D3D10 has no cube targets.
       */
      virtual boost::shared_ptr<CubeRenderTarget> CreateCubeRenderTarget(const CubeRenderTargetContext* context);
      /**
       * Address: 0x008FB570 (FUN_008FB570)
       * Slot: 13
       *
       * What it does:
       * Creates one depth texture with its DSV (and SRV when sampleable) and
       * wraps them in a `DepthStencilTargetD3D10`.
       */
      virtual boost::shared_ptr<DepthStencilTarget> CreateDepthStencilTarget(const DepthStencilTargetContext* context);
      /**
       * Address: 0x008FE220 (FUN_008FE220)
       * Slot: 14
       *
       * What it does:
       * Builds the input layout for gal vertex format `formatToken`.
       */
      virtual boost::shared_ptr<VertexFormat> CreateVertexFormat(std::uint32_t formatToken);
      /**
       * Address: 0x008FB8D0 (FUN_008FB8D0)
       * Slot: 15
       *
       * What it does:
       * Creates one GPU vertex buffer and its staging buffer.
       */
      virtual boost::shared_ptr<VertexBuffer> CreateVertexBuffer(const VertexBufferContext* context);
      /**
       * Address: 0x008FBB60 (FUN_008FBB60)
       * Slot: 16
       *
       * What it does:
       * Creates one GPU index buffer and its staging buffer.
       */
      virtual boost::shared_ptr<IndexBuffer> CreateIndexBuffer(const IndexBufferContext* context);
      /**
       * Address: 0x008FC540
       * Slot: 17
       *
       * What it does:
       * Copies one colour target's texture into `destination` with a native
       * `CopyResource`.
       */
      virtual void GetRenderTargetData(
          const boost::shared_ptr<RenderTarget>& source,
          const boost::shared_ptr<Texture>& destination
      );
      /**
       * Address: 0x008FC290
       * Slot: 18
       *
       * What it does:
       * Copies directly when source and destination match in size and format;
       * otherwise draws the source into the destination through the RTT effect.
       */
      virtual void StretchRect(
          const boost::shared_ptr<RenderTarget>& source,
          const boost::shared_ptr<RenderTarget>& destination,
          const RECT* sourceRect,
          const RECT* destinationRect
      );
      /**
       * Address: 0x008FBDF0
       * Slot: 19
       *
       * What it does:
       * Copies directly when the two textures match in size and format;
       * otherwise round-trips the source through an encoded blob. Only the
       * destination rectangle's top-left corner is used.
       */
      virtual void UpdateSurface(
          const boost::shared_ptr<Texture>& source,
          const boost::shared_ptr<Texture>& destination,
          const RECT* sourceRect,
          const RECT* destinationRect
      );
      /**
       * Address: 0x008F8700
       * Slot: 20
       *
       * What it does:
       * D3D10 cannot save a cube target (`ret 8`).
       */
      virtual void SaveCubeRenderTarget(
          const boost::shared_ptr<CubeRenderTarget>& cubeTarget,
          const msvc8::string& filePath
      );
      /**
       * Address: 0x008FC9B0
       * Slot: 21
       *
       * What it does:
       * Writes one colour target's texture to `filePath` in image format
       * `fileFormat`.
       */
      virtual void SaveRenderTarget(
          const boost::shared_ptr<RenderTarget>& renderTarget,
          const msvc8::string& filePath,
          int fileFormat
      );
      /**
       * Address: 0x008FC6B0
       * Slot: 22
       *
       * What it does:
       * Encodes one texture to `filePath`, or into `outBuffer` when it is
       * non-null.
       */
      virtual void SaveTexture(
          const boost::shared_ptr<Texture>& texture,
          const msvc8::string& filePath,
          int fileFormat,
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
       *
       * What it does:
       * Binds `vertexFormat`'s input layout.
       */
      virtual void SetVertexDeclaration(boost::shared_ptr<VertexFormat> vertexFormat);
      /**
       * Address: 0x008F9690
       * Slot: 41
       *
       * What it does:
       * Binds one vertex stream and records its frequency.
       */
      virtual void SetVertexBuffer(
          std::uint32_t streamSlot,
          boost::shared_ptr<VertexBuffer> vertexBuffer,
          int streamFrequencyToken,
          int startVertex
      );
      /**
       * Address: 0x008F9760
       * Slot: 42
       *
       * What it does:
       * Binds `indexBuffer` as the index source.
       */
      virtual void SetBufferIndices(boost::shared_ptr<IndexBuffer> indexBuffer);
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
      virtual int DrawIndexedPrimitive(const DrawIndexedContext* context);
      /**
       * Address: 0x008FCF90
       * Slot: 47
       * Demangled: gpg::gal::DeviceD3D10::DrawPrimitive
       *
       * What it does:
       * Applies topology mapping and dispatches draw or draw-instanced.
       */
      virtual int DrawPrimitive(const DrawContext* context);
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

      /**
       * Address: 0x008FE5D0 (FUN_008FE5D0)
       *
       * What it does:
       * Builds the output context, zeroes the module/export/COM lanes, builds
       * the embedded device context with no heads and arms the cursor. The
       * member initializers below are that body; `func_CreateDeviceD3D`
       * (0x008E6B60) allocates 0x128 bytes and runs it.
       */
      DeviceD3D10();

      // Export signatures resolved by `DynamicLink`. The effect loader is the
      // early (Feb/Apr 2007) twelve-argument D3DX10 form: the call passes
      // 0x800 in the slot that later SDKs gave to `pProfile`, which only fits
      // `HLSLFlags` here.
      using D3D10CreateDeviceFn =
        HRESULT(__stdcall*)(IDXGIAdapter*, D3D10_DRIVER_TYPE, HMODULE, UINT, UINT, ID3D10Device**);
      using D3D10CreateBlobFn = HRESULT(__stdcall*)(std::uint32_t, void**);
      using D3DX10CreateEffectFromMemoryFn = HRESULT(__stdcall*)(
        const void*,
        std::size_t,
        const char*,
        const D3D10_SHADER_MACRO*,
        void*,
        unsigned int,
        unsigned int,
        ID3D10Device*,
        void*,
        void*,
        ID3D10Effect**,
        void**
      );
      using D3DX10CreateTextureFromMemoryFn =
        HRESULT(__stdcall*)(void*, const void*, std::uint32_t, const void*, void*, void**);
      using D3DX10SaveTextureToFileFn = HRESULT(__stdcall*)(void*, int, const char*);
      using D3DX10SaveTextureToMemoryFn = HRESULT(__stdcall*)(void*, int, void**);
      using CreateDXGIFactoryFn = HRESULT(__stdcall*)(const IID&, void**);

      // Layout recovered from the constructor at 0x008FE5D0 and the 0x128-byte
      // allocation in `func_CreateDeviceD3D`. Each lane is named for what the
      // code that fills it stores there, not for what an overlay called it.
      OutputContext mOutputContext{};                                 // +0x04
      HMODULE mD3D10Module = nullptr;                                 // +0x24  LoadLibraryA("d3d10.dll")
      HMODULE mD3DX10Module = nullptr;                                // +0x28  LoadLibraryA("d3dx10.dll")
      HMODULE mDXGIModule = nullptr;                                  // +0x2C  LoadLibraryA("dxgi.dll")
      D3D10CreateDeviceFn mD3D10CreateDevice = nullptr;               // +0x30
      D3D10CreateBlobFn mD3D10CreateBlob = nullptr;                   // +0x34
      D3DX10CreateEffectFromMemoryFn mD3DX10CreateEffectFromMemory = nullptr;   // +0x38
      D3DX10CreateTextureFromMemoryFn mD3DX10CreateTextureFromMemory = nullptr; // +0x3C
      D3DX10SaveTextureToFileFn mD3DX10SaveTextureToFileA = nullptr;  // +0x40
      D3DX10SaveTextureToMemoryFn mD3DX10SaveTextureToMemory = nullptr; // +0x44
      CreateDXGIFactoryFn mCreateDXGIFactory = nullptr;               // +0x48
      int mCurThreadId = 0;                                           // +0x4C
      msvc8::vector<msvc8::string> mLog{};                            // +0x50
      DeviceContext mDeviceContext{0};                                // +0x60
      msvc8::vector<AdapterD3D10> mAdapters{};                        // +0x94
      msvc8::vector<IDXGISwapChain*> mSwapChains{};                   // +0xA4
      boost::shared_ptr<PipelineStateD3D10> mPipelineState{};         // +0xB4
      IDXGIFactory* mDXGIFactory = nullptr;                           // +0xBC
      ID3D10Device* mDevice = nullptr;                                // +0xC0
      ID3D10Effect* mSignatureEffect = nullptr;                       // +0xC4  from kSignaturePreambleEffectSource
      ID3D10Effect* mRttEffect = nullptr;                             // +0xC8  from kRttEffectSource
      ID3D10EffectTechnique* mRttTechnique = nullptr;                 // +0xCC  GetTechniqueByName("RTT")
      ID3D10Buffer* mRttQuadVertexBuffer = nullptr;                   // +0xD0
      ID3D10InputLayout* mRttInputLayout = nullptr;                   // +0xD4
      // The frequency `SetVertexBuffer` was last given for each input slot;
      // the draws read slot 0's as the instance count. Not written by the
      // constructor (its stores skip +0xD8..+0x117); `Setup` clears all
      // sixteen before anything reads them.
      std::int32_t mStreamFrequencies[16];                            // +0xD8
      OutputContext* mHeadOutputContexts = nullptr;                   // +0x118 new[]'d, one per head
      CursorD3D10 mCursor{};                                          // +0x11C
    };

    static_assert(offsetof(DeviceD3D10, mOutputContext) == 0x04, "DeviceD3D10::mOutputContext offset must be 0x04");
    static_assert(offsetof(DeviceD3D10, mD3D10Module) == 0x24, "DeviceD3D10::mD3D10Module offset must be 0x24");
    static_assert(offsetof(DeviceD3D10, mCreateDXGIFactory) == 0x48, "DeviceD3D10::mCreateDXGIFactory offset must be 0x48");
    static_assert(offsetof(DeviceD3D10, mCurThreadId) == 0x4C, "DeviceD3D10::mCurThreadId offset must be 0x4C");
    static_assert(offsetof(DeviceD3D10, mLog) == 0x50, "DeviceD3D10::mLog offset must be 0x50");
    static_assert(offsetof(DeviceD3D10, mDeviceContext) == 0x60, "DeviceD3D10::mDeviceContext offset must be 0x60");
    static_assert(offsetof(DeviceD3D10, mAdapters) == 0x94, "DeviceD3D10::mAdapters offset must be 0x94");
    static_assert(offsetof(DeviceD3D10, mSwapChains) == 0xA4, "DeviceD3D10::mSwapChains offset must be 0xA4");
    static_assert(offsetof(DeviceD3D10, mPipelineState) == 0xB4, "DeviceD3D10::mPipelineState offset must be 0xB4");
    static_assert(offsetof(DeviceD3D10, mDXGIFactory) == 0xBC, "DeviceD3D10::mDXGIFactory offset must be 0xBC");
    static_assert(offsetof(DeviceD3D10, mDevice) == 0xC0, "DeviceD3D10::mDevice offset must be 0xC0");
    static_assert(offsetof(DeviceD3D10, mSignatureEffect) == 0xC4, "DeviceD3D10::mSignatureEffect offset must be 0xC4");
    static_assert(offsetof(DeviceD3D10, mRttInputLayout) == 0xD4, "DeviceD3D10::mRttInputLayout offset must be 0xD4");
    static_assert(offsetof(DeviceD3D10, mStreamFrequencies) == 0xD8, "DeviceD3D10::mStreamFrequencies offset must be 0xD8");
    static_assert(offsetof(DeviceD3D10, mHeadOutputContexts) == 0x118, "DeviceD3D10::mHeadOutputContexts offset must be 0x118");
    static_assert(offsetof(DeviceD3D10, mCursor) == 0x11C, "DeviceD3D10::mCursor offset must be 0x11C");
    static_assert(sizeof(DeviceD3D10) == 0x128, "DeviceD3D10 size must be 0x128");

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
    void InitializeDeviceD3D10Backend(Device* device, DeviceContext* context);
} // namespace gal
} // namespace gpg

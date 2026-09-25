#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/Matrix.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/Texture.hpp"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  class Device;
  class CubeRenderTargetContext;
  class DepthStencilTargetContext;
  class DeviceContext;
  class DrawContext;
  class DrawIndexedContext;
  class RenderTargetContext;
  class TextureContext;
  class Effect;
  class CursorContext;
  class EffectContext;
  class Head;
  struct HeadAdapterMode;
  class IndexBuffer;
  class IndexBufferContext;
  class PipelineState;
  class VertexBuffer;
  class VertexBufferContext;
  class VertexFormat;

  /**
   * Address: 0x0079CB10 (FUN_0079CB10, gpg::gal::WindowIsForeground)
   *
   * What it does:
   * Returns true when the OS foreground HWND matches any active GAL device
   * head window/handle lane.
   */
  [[nodiscard]] bool WindowIsForeground();

  /**
   * VFTABLE: 0x00D42224
   * COL:     0x00E5050C
   *
   * Every slot is pure in the binary except 36 (`ClearTarget`) and 37
   * (`GetContext`), and both backends override the other 48 at the same
   * indices (vtables 0x00D4273C and 0x00D4340C). Two pairs are overloads, which
   * MSVC lays out in reverse declaration order: `GetHeadOutputContext` (slots
   * 6/7) and `Reset` (25/26).
   */
  class Device
  {
  public:
    /**
     * Address: 0x008E6730 (FUN_008E6730)
     *
     * What it does:
     * Returns the global active device singleton pointer.
     */
    static Device* GetInstance();

    /**
     * Address family:
     * - used by 0x0042EA00 (FUN_0042EA00)
     * - used by 0x0042EA30 (FUN_0042EA30)
     * - used by 0x0042EAE0 (FUN_0042EAE0)
     *
     * What it does:
     * Returns true when the global active device singleton is available.
     */
    static bool IsReady();

    /**
     * Address: 0x008E6700 (FUN_008E6700, func_DeivceD3DDtr)
     *
     * What it does:
     * Destroys and clears the global active device singleton when present.
     */
    static void DestroyInstance();

    /**
     * Address: 0x008E6B60 (FUN_008E6B60, func_CreateDeviceD3D)
     *
     * What it does:
     * Replaces the active device with a new backend for
     * `context->mDeviceType` (`DeviceApi::Direct3D9` or `Direct3D10`; anything
     * else throws "unknown API requested"), brings it up for `context`, and
     * returns it.
     */
    static Device* Create(DeviceContext* context);

    /**
     * Address: 0x008E81B0 (FUN_008E81B0)
     *
     * What it does:
     * Installs the base vtable and builds the empty output context at +0x04.
     * Both backend constructors inline it.
     */
    Device();

    /**
     * Address: 0x008E81A0 (FUN_008E81A0)
     * Slot: 0 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Reinstalls the base vtable and destroys the output context. The slot
     * holds the scalar deleting destructor, which is what `DestroyInstance`
     * dispatches through.
     */
    virtual ~Device() = 0;
    /**
     * Slot: 1 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns the backend's log sink.
     */
    virtual void* GetLog() = 0;
    /**
     * Address context:
     * - 0x008D0E7C callsite in `CScApp::CreateDevice` (`FUN_008D0370`)
     *   dispatches slot-2 and ignores return value.
     *
     * What it does:
     * Returns the active device-context object for the backend device.
     */
    virtual DeviceContext* GetDeviceContext() = 0;
    /**
     * Slot: 3 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Returns the thread id the device was created on.
     */
    virtual int GetCurThreadId() = 0;
    /**
     * Slot: 4 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Per-call pre-hook every backend entry point runs first. It is `const`:
     * the const `GetHeadOutputContext` overload (slot 6, 0x008EABF0) calls it
     * too. Both shipped backends leave it empty.
     */
    virtual void Func1() const = 0;
    /**
     * Slot: 5 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Replaces `outModes` with the display modes of adapter `adapterIndex` as
     * `{width, height, refresh}` triples, the element `Head::adapterModes`
     * holds: the D3D9 body pushes 12-byte elements (0x008F0170) and the options
     * code that calls it walks the result at a 12-byte stride (0x008D2305). The
     * D3D10 backend leaves the slot empty (0x008F86F0, `ret 8`).
     */
    virtual void GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, int adapterIndex) = 0;
    /**
     * Slot: 7 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Returns the output context of head `headIndex` - its back-buffer colour
     * target and depth/stencil target - or throws "invalid head index
     * specified".
     *
     * Slots 6 and 7 are one overloaded name. MSVC lays overloaded virtuals out
     * in reverse declaration order, so the non-const overload, declared first,
     * lands in slot 7; `DeviceD3D9` defines it first too (its throw is
     * `DeviceD3D9.cpp` line 295, the const one's line 303). Moho calls slot 7
     * on a non-const `Device*` (0x0042E3BE in `CD3DDeviceSingleton::InitContext`,
     * 0x0042DD28 in `CD3DDevice::SetRenViewport`).
     */
    virtual OutputContext* GetHeadOutputContext(unsigned int headIndex) = 0;
    /**
     * Slot: 6 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * The const overload of slot 7; identical body.
     */
    virtual const OutputContext* GetHeadOutputContext(unsigned int headIndex) const = 0;
    /**
     * Slot: 8 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Returns the device's pipeline state (its fixed-function and default
     * render state). `EffectD3D9::OnReset` reaches it through this slot.
     */
    virtual boost::shared_ptr<PipelineState> GetPipelineState() = 0;
    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     *
     * What it does:
     * Builds the backend effect `context` describes. `Effect::Create`
     * (0x0093F5B0) forwards its own return slot to it, so the backend
     * constructs straight into the caller's `shared_ptr`.
     */
    virtual boost::shared_ptr<Effect> CreateEffect(const EffectContext& context) = 0;
    /**
     * Slot: 10 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one texture from `context` (in-memory file data, or an empty
     * texture of a given size and format). `Texture::Create` (0x008E7C50)
     * dispatches it.
     */
    virtual boost::shared_ptr<Texture> CreateTexture(const TextureContext* context) = 0;
    /**
     * Slot: 11 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one colour render target described by `context`.
     */
    virtual boost::shared_ptr<RenderTarget> CreateRenderTarget(const RenderTargetContext* context) = 0;
    /**
     * Slot: 12 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one six-face cube render target described by `context`.
     */
    virtual boost::shared_ptr<CubeRenderTarget> CreateCubeRenderTarget(const CubeRenderTargetContext* context) = 0;
    /**
     * Slot: 13 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one depth/stencil target described by `context`.
     */
    virtual boost::shared_ptr<DepthStencilTarget> CreateDepthStencilTarget(
      const DepthStencilTargetContext* context
    ) = 0;
    /**
     * Slot: 14 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates the vertex format for gal vertex-format code `formatCode`. The
     * hardware vertex formatters dispatch it as `[vtbl+0x38]` on the active
     * device (0x0094565C).
     */
    virtual boost::shared_ptr<VertexFormat> CreateVertexFormat(std::uint32_t formatCode) = 0;
    /**
     * Slot: 15 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one vertex buffer described by `context`.
     */
    virtual boost::shared_ptr<VertexBuffer> CreateVertexBuffer(const VertexBufferContext* context) = 0;
    /**
     * Slot: 16 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Creates one index buffer described by `context`.
     */
    virtual boost::shared_ptr<IndexBuffer> CreateIndexBuffer(const IndexBufferContext* context) = 0;
    /**
     * Slot: 17 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Reads one colour target back into a texture.
     */
    virtual void GetRenderTargetData(
      const boost::shared_ptr<RenderTarget>& source,
      const boost::shared_ptr<Texture>& destination
    ) = 0;
    /**
     * Slot: 18 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Copies (and scales) a rectangle of one colour target into another.
     * `CD3DDevice::SetViewRect` (0x0042FEB0) dispatches it as `[vtbl+0x48]`,
     * passing the addresses of the two `shared_ptr` temporaries its
     * `GetSurface` calls returned.
     */
    virtual void StretchRect(
      const boost::shared_ptr<RenderTarget>& source,
      const boost::shared_ptr<RenderTarget>& destination,
      const RECT* sourceRect,
      const RECT* destinationRect
    ) = 0;
    /**
     * Slot: 19 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Copies a rectangle of one texture's top level into another; null rects
     * mean the whole surface.
     */
    virtual void UpdateSurface(
      const boost::shared_ptr<Texture>& source,
      const boost::shared_ptr<Texture>& destination,
      const RECT* sourceRect,
      const RECT* destinationRect
    ) = 0;
    /**
     * Slot: 20 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Writes one cube render target to `filePath` as a DDS file.
     */
    virtual void SaveCubeRenderTarget(
      const boost::shared_ptr<CubeRenderTarget>& cubeTarget,
      const msvc8::string& filePath
    ) = 0;
    /**
     * Slot: 21 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Writes one colour target's surface to `filePath` in image format
     * `fileFormat`.
     */
    virtual void SaveRenderTarget(
      const boost::shared_ptr<RenderTarget>& renderTarget,
      const msvc8::string& filePath,
      int fileFormat
    ) = 0;
    /**
     * Slot: 22 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Encodes one texture in image format `fileFormat`, into `outBuffer`
     * when it is non-null and to `filePath` otherwise.
     */
    virtual void SaveTexture(
      const boost::shared_ptr<Texture>& texture,
      const msvc8::string& filePath,
      int fileFormat,
      gpg::MemBuffer<char>* outBuffer
    ) = 0;
    /**
     * Address: 0x00A82547 (_purecall in the base's own table)
     * Slot: 23
     *
     * What it does:
     * Decodes one texture payload from memory and exports the block-compressed
     * bytes plus its dimensions.
     *
     */
    virtual void GetTexture2D(
      const void* sourceData,
      std::uint32_t sourceBytes,
      gpg::MemBuffer<char>* outTextureData,
      std::uint32_t* outWidth,
      int* outHeight
    ) = 0;
    /**
     * Address: 0x00A82547 (_purecall in the base's own table)
     * Slot: 24
     *
     * What it does:
     * Takes one handle by value and returns an empty one: both backends leave
     * it unimplemented (0x008E9B40, 0x008FA260), and nothing in reach calls it,
     * so the handle types are not known.
     */
    virtual boost::weak_ptr<void>* Func7(
      boost::weak_ptr<void>* outWeakHandle,
      boost::shared_ptr<void> temporarySharedHandle
    ) = 0;
    /**
     * Slot: 26 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Resets the native device for `context` and rebuilds everything that
     * hangs off it (D3D9: 0x008F3070; D3D10 leaves it empty). Declared before
     * its no-argument overload, which MSVC therefore puts at slot 25.
     */
    virtual void Reset(DeviceContext* context) = 0;
    /**
     * Slot: 25 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Resets the device for the context it already has (D3D9 0x008E8210 is
     * `Reset(&mDeviceContext)`; D3D10 leaves it empty).
     */
    virtual void Reset() = 0;
    /**
     * Slot: 27 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Reports whether the device is usable, lost, or needs a reset.
     */
    virtual int TestCooperativeLevel() = 0;
    /**
     * Slot: 28 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Opens a scene.
     */
    virtual void BeginScene() = 0;
    /**
     * Slot: 29 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Closes the open scene.
     */
    virtual void EndScene() = 0;
    /**
     * Slot: 30 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Presents the back buffer.
     */
    virtual void Present() = 0;
    /**
     * Slot: 31 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Uploads the hardware cursor image.
     */
    virtual void SetCursor(const CursorContext* context) = 0;
    /**
     * Slot: 32 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Re-applies the hardware cursor. D3D9 leaves it empty (0x008E8220); D3D10
     * forwards to its cursor (0x008F8770). `D3D_InitCursor` (0x0042EAE0) calls
     * it for the viewport's WM_SETCURSOR.
     */
    virtual void InitCursor() = 0;
    /**
     * Slot: 33 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Shows or hides the hardware cursor.
     */
    virtual int ShowCursor(bool show) = 0;
    /**
     * Slot: 34 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Binds one viewport. The interface takes the D3D9 structure - the same way
     * slot 18 takes Win32 `RECT`s - and the D3D10 backend copies its six fields
     * into a `D3D10_VIEWPORT` (0x008F8790).
     */
    virtual void SetViewport(const D3DVIEWPORT9* viewport) = 0;
    /**
     * Slot: 35 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Reads the bound viewport back into `outViewport`.
     */
    virtual void GetViewport(D3DVIEWPORT9* outViewport) = 0;

    /**
     * Address: 0x008E6940 (FUN_008E6940)
     *
     * OutputContext const *
     *
     * What it does:
     * Copies the caller-provided output-target context into the device's active output context.
     */
    virtual void ClearTarget(const OutputContext* context);

    /**
     * Address: 0x008E6810 (FUN_008E6810)
     *
     * OutputContext *
     *
     * What it does:
     * Writes the device's active output-target context to the caller-provided context object.
     */
    virtual void GetContext(OutputContext* outContext);

    /**
     * Slot: 38 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Clears the bound target, depth and stencil.
     */
    virtual void Clear(
        bool clearTarget,
        bool clearZbuffer,
        bool clearStencil,
        std::uint32_t color,
        float depth,
        int stencil
    ) = 0;
    /**
     * Slot: 39 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Unbinds every texture stage. Both backends tail-call their pipeline
     * state's loop (0x008E8EEE, 0x008F95F6), and D3D10's ends in
     * `PSSetShaderResources`, which returns nothing.
     */
    virtual void ClearTextures() = 0;
    /**
     * Slot: 40 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Binds `vertexFormat` as the vertex declaration for the next draws.
     */
    virtual void SetVertexDeclaration(boost::shared_ptr<VertexFormat> vertexFormat) = 0;
    /**
     * Slot: 41 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Binds `vertexBuffer` on vertex stream `streamSlot`, starting
     * `startVertex` vertices in. `streamFrequencyToken` is the instance count
     * a geometry stream repeats for; per-instance streams advance once per
     * instance regardless.
     */
    virtual void SetVertexBuffer(
      std::uint32_t streamSlot,
      boost::shared_ptr<VertexBuffer> vertexBuffer,
      int streamFrequencyToken,
      int startVertex
    ) = 0;
    /**
     * Slot: 42 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224)
     *
     * What it does:
     * Binds `indexBuffer` as the index source for the next indexed draws.
     */
    virtual void SetBufferIndices(boost::shared_ptr<IndexBuffer> indexBuffer) = 0;
    /**
     * Slot: 43 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Sets the fixed-function fog parameters.
     */
    virtual void SetFogState(
        bool enable,
        const Matrix* projection,
        float fogStart,
        float fogEnd,
        int fogColor
    ) = 0;
    /**
     * Slot: 44 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Switches between filled and wireframe fill mode.
     */
    virtual void SetWireframeState(bool enabled) = 0;
    /**
     * Slot: 45 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Sets the colour-write mask.
     */
    virtual void SetColorWriteState(bool writeColor, bool writeAlpha) = 0;
    /**
     * Slot: 46 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Issues one indexed draw.
     */
    virtual int DrawIndexedPrimitive(const DrawIndexedContext* context) = 0;
    /**
     * Slot: 47 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Issues one non-indexed draw.
     */
    virtual int DrawPrimitive(const DrawContext* context) = 0;
    /**
     * Slot: 48 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Begins the selected effect technique.
     */
    virtual void BeginTechnique() = 0;
    /**
     * Slot: 49 (pure in ??_7Device@gal@gpg@@6B@ at 0x00D42224;
     * DeviceD3D9 overrides it at the same index)
     *
     * What it does:
     * Ends the active effect technique.
     */
    virtual void EndTechnique() = 0;

  protected:
    OutputContext outputContext_{}; // +0x04 the bound targets (`ClearTarget` / `GetContext`)
  };

  static_assert(sizeof(Device) == 0x24, "Device size must be 0x24");

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Asks the active backend whether vertex shaders can read a texture of gal
   * format `textureFormat` (the FAF skinning palette texture). The backends
   * answer through a member of their own rather than a `Device` slot, which
   * would change the binary's vtable. False without a device or before it is
   * set up.
   */
  [[nodiscard]] bool SupportsVertexTextureFormat(std::uint32_t textureFormat);
} // namespace gpg::gal


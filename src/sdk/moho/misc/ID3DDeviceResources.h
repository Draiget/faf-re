#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"

namespace gpg
{
  class Stream;
}

namespace gpg::gal
{
  class RenderTargetContext;
}

namespace moho
{
  class CD3DDynamicTextureSheet;
  class CD3DDepthStencil;
  class CD3DEffect;
  class CD3DIndexSheet;
  class ID3DRenderTarget;
  class CD3DRenderTarget;
  class CD3DVertexFormat;
  class CD3DVertexSheet;
  class CD3DVertexStream;
  class PrefetchData;
  class RD3DTextureResource;

  class ID3DDeviceResources
  {
  public:
    using RenderTargetHandle = boost::shared_ptr<CD3DRenderTarget>;
    using DepthStencilHandle = boost::shared_ptr<CD3DDepthStencil>;
    using DynamicTextureSheetHandle = boost::shared_ptr<CD3DDynamicTextureSheet>;
    using TextureResourceHandle = boost::shared_ptr<RD3DTextureResource>;
    using PrefetchDataHandle = boost::shared_ptr<PrefetchData>;
    using DynamicTextureSheetWeakHandle = boost::weak_ptr<CD3DDynamicTextureSheet>;

    /**
     * Address: 0x00440630 (FUN_00440630, sub_440630)
     *
     * What it does:
     * Initializes the base interface vftable lane for D3D device-resource wrappers.
     */
    ID3DDeviceResources();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Updates global mip-skip level and reloads tracked textures.
     */
    virtual void SetSkipMipLevels(int mipSkipLevels) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns current global mip-skip level.
     */
    virtual int GetSkipMipLevels() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one render-target wrapper from width/height/format.
     */
    virtual RenderTargetHandle&
      CreateRenderTarget(RenderTargetHandle& outTarget, int width, int height, int format) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Preserves one legacy render-target creation lane using a context payload.
     */
    virtual RenderTargetHandle&
      Func3(RenderTargetHandle& outTarget, const gpg::gal::RenderTargetContext& context) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one depth-stencil wrapper from width/height/format.
     */
    virtual DepthStencilHandle&
      CreateDepthStencil(DepthStencilHandle& outDepthStencil, int width, int height, int format) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns one cached vertex format for the requested format token.
     */
    virtual CD3DVertexFormat* GetVertexFormat(int formatToken) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one new vertex-sheet wrapper with internally owned streams.
     */
    virtual CD3DVertexSheet*
      NewVertexSheet(std::uint32_t streamUsageToken, int streamFrequencyToken, CD3DVertexFormat* vertexFormat) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one index-sheet wrapper.
     */
    virtual CD3DIndexSheet* CreateIndexSheet(bool dynamicUsage, int size) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one vertex-stream wrapper from requested format stride lanes.
     */
    virtual CD3DVertexStream*
      Func5(std::uint32_t width, int formatToken, int strideBytes, CD3DVertexFormat* vertexFormat) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one vertex-sheet wrapper from caller-provided stream array.
     */
    virtual CD3DVertexSheet* Func6(
      std::uint32_t streamUsageToken,
      int streamFrequencyToken,
      CD3DVertexFormat* vertexFormat,
      CD3DVertexStream** streams
    ) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Resolves one texture resource by path.
     */
    virtual TextureResourceHandle&
      GetTexture(TextureResourceHandle& outTexture, const char* path, int allowCreate, bool allowFallback) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Loads prefetch payload for the requested path.
     */
    virtual PrefetchDataHandle& LoadPrefetchData(PrefetchDataHandle& outPrefetchData, const char* path) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Preserves one legacy texture-load lane.
     */
    virtual TextureResourceHandle& Func7(TextureResourceHandle& outTexture, const char* path) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one texture resource from in-memory sheet payload.
     */
    virtual TextureResourceHandle&
      GetTextureSheet(TextureResourceHandle& outTexture, const char* location, void* data, std::size_t size) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one dynamic texture sheet and links it into dynamic-sheet list lane.
     */
    virtual DynamicTextureSheetHandle&
      CreateDynamicTextureSheet2(DynamicTextureSheetHandle& outSheet, int width, int height, int format) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one dynamic texture sheet with default usage lane.
     */
    virtual DynamicTextureSheetHandle&
      NewDynamicTextureSheet(DynamicTextureSheetHandle& outSheet, int width, int height, int format) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Creates one dynamic texture sheet in archive-mode lane.
     */
    virtual DynamicTextureSheetHandle&
      CreateDynamicTextureSheet(DynamicTextureSheetHandle& outSheet, int width, int height, int format) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Preserves one weak-handle release lane used by dynamic sheet dispatch.
     */
    virtual bool Func9(int arg1, int arg2, DynamicTextureSheetWeakHandle weakSheet) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Copies one render-target surface into a dynamic texture sheet, recreating
     * the destination texture when current dimensions mismatch.
     */
    virtual DynamicTextureSheetHandle& Func10(
      DynamicTextureSheetHandle& outSheet,
      ID3DRenderTarget* sourceRenderTarget,
      DynamicTextureSheetHandle currentSheet
    ) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Finds one compiled effect entry by name.
     */
    virtual CD3DEffect* FindEffect(const char* effectName) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Dumps preloaded texture usage lines to a stream.
     */
    virtual void DumpPreloadedTextures(gpg::Stream* stream) = 0;
  };

  static_assert(sizeof(ID3DDeviceResources) == 0x04, "ID3DDeviceResources size must be 0x04");
} // namespace moho

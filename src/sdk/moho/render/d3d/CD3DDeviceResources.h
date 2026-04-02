#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/misc/CDiskWatch.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/d3d/CD3DVertexFormat.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/d3d/CD3DVertexStream.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{
  class CD3DDevice;
  class CD3DEffect;
  class ID3DRenderTarget;

  /**
   * VFTABLE: 0x00E02864
   * COL:     0x00E5E8B0
   */
  class CD3DDeviceResources final : public ID3DDeviceResources, public CDiskWatchListener
  {
  public:
    /**
     * Address: 0x00440490 (FUN_00440490)
     *
     * What it does:
     * Initializes D3D resource-owner state, embedded list heads/wrappers, and
     * vertex/effect cache vectors.
     */
    CD3DDeviceResources();

    /**
     * Address: 0x00440660 (FUN_00440660, non-deleting body)
     *
     * What it does:
     * Releases embedded sheet/target wrappers and clears vector storage.
     */
    ~CD3DDeviceResources() override;

    /**
     * Address: 0x00440DC0 (FUN_00440DC0)
     *
     * What it does:
     * Stores one global mip-skip level and reloads all tracked texture resources.
     */
    void SetSkipMipLevels(int mipSkipLevels) override;

    /**
     * Address: 0x00440E00 (FUN_00440E00)
     *
     * What it does:
     * Returns the current global mip-skip level.
     */
    [[nodiscard]] int GetSkipMipLevels() const override;

    /**
     * Address: 0x00440E80 (FUN_00440E80)
     *
     * What it does:
     * Creates one render-target wrapper and links it into the render-target lane.
     */
    RenderTargetHandle&
      CreateRenderTarget(RenderTargetHandle& outTarget, int width, int height, int format) override;

    /**
     * Address: 0x00440E10 (FUN_00440E10)
     *
     * What it does:
     * Compatibility lane that forwards context payload into `CreateRenderTarget`.
     */
    RenderTargetHandle&
      Func3(RenderTargetHandle& outTarget, const gpg::gal::RenderTargetContext& context) override;

    /**
     * Address: 0x00440F80 (FUN_00440F80)
     *
     * What it does:
     * Creates one depth-stencil wrapper and links it into depth-stencil lane.
     */
    DepthStencilHandle&
      CreateDepthStencil(DepthStencilHandle& outDepthStencil, int width, int height, int format) override;

    /**
     * Address: 0x00441080 (FUN_00441080)
     *
     * What it does:
     * Returns cached vertex format by token or creates/stores one on miss.
     */
    CD3DVertexFormat* GetVertexFormat(int formatToken) override;

    /**
     * Address: 0x00441150 (FUN_00441150)
     *
     * What it does:
     * Creates one vertex sheet with internally-owned stream lanes and links it
     * into the matching availability list.
     */
    CD3DVertexSheet*
      NewVertexSheet(std::uint32_t streamUsageToken, int streamFrequencyToken, CD3DVertexFormat* vertexFormat) override;

    /**
     * Address: 0x004412E0 (FUN_004412E0)
     *
     * What it does:
     * Creates one index-sheet wrapper and links it into static/dynamic lane.
     */
    CD3DIndexSheet* CreateIndexSheet(bool dynamicUsage, int size) override;

    /**
     * Address: 0x004411D0 (FUN_004411D0)
     *
     * What it does:
     * Creates one vertex-stream wrapper from format lane metadata.
     */
    CD3DVertexStream*
      Func5(std::uint32_t dynamicUsageToken, int formatElementIndex, int streamWidth, CD3DVertexFormat* vertexFormat) override;

    /**
     * Address: 0x00441260 (FUN_00441260)
     *
     * What it does:
     * Creates one vertex sheet from caller-provided stream lanes and links it
     * into the matching availability list.
     */
    CD3DVertexSheet* Func6(
      std::uint32_t streamUsageToken,
      int streamFrequencyToken,
      CD3DVertexFormat* vertexFormat,
      CD3DVertexStream** streams
    ) override;

    /**
     * Address: 0x00441370 (FUN_00441370)
     *
     * What it does:
     * Loads one texture resource by path, with optional fallback, and moves the
     * resolved resource node to the tracked texture list head.
     */
    TextureResourceHandle&
      GetTexture(TextureResourceHandle& outTexture, const char* path, int allowCreate, bool allowFallback) override;

    /**
     * Address: 0x00441520 (FUN_00441520)
     *
     * What it does:
     * Resolves one prefetch payload for a texture path.
     */
    PrefetchDataHandle& LoadPrefetchData(PrefetchDataHandle& outPrefetchData, const char* path) override;

    /**
     * Address: 0x00441680 (FUN_00441680)
     *
     * What it does:
     * Legacy texture-load lane that performs fallback loading and list relink.
     */
    TextureResourceHandle& Func7(TextureResourceHandle& outTexture, const char* path) override;

    /**
     * Address: 0x00441810 (FUN_00441810)
     *
     * What it does:
     * Creates one in-memory texture resource wrapper from location+blob payload.
     */
    TextureResourceHandle&
      GetTextureSheet(TextureResourceHandle& outTexture, const char* location, void* data, std::size_t size) override;

    /**
     * Address: 0x00441900 (FUN_00441900)
     *
     * What it does:
     * Creates one dynamic texture sheet, links it into tracking list, and
     * recreates the backing texture.
     */
    DynamicTextureSheetHandle&
      CreateDynamicTextureSheet2(DynamicTextureSheetHandle& outSheet, int width, int height, int format) override;

    /**
     * Address: 0x00441AB0 (FUN_00441AB0)
     *
     * What it does:
     * Creates one non-archive dynamic texture sheet and recreates its texture.
     */
    DynamicTextureSheetHandle&
      NewDynamicTextureSheet(DynamicTextureSheetHandle& outSheet, int width, int height, int format) override;

    /**
     * Address: 0x00441BE0 (FUN_00441BE0)
     *
     * What it does:
     * Creates one archive-mode dynamic texture sheet and recreates its texture.
     */
    DynamicTextureSheetHandle&
      CreateDynamicTextureSheet(DynamicTextureSheetHandle& outSheet, int width, int height, int format) override;

    /**
     * Address: 0x00441D20 (FUN_00441D20)
     *
     * What it does:
     * Legacy weak-handle release lane for dynamic texture sheet callbacks.
     */
    bool Func9(int arg1, int arg2, DynamicTextureSheetWeakHandle weakSheet) override;

    /**
     * Address: 0x00441D60 (FUN_00441D60)
     *
     * What it does:
     * Copies one render-target surface into a dynamic texture sheet, allocating
     * a replacement sheet when dimensions do not match.
     */
    DynamicTextureSheetHandle& Func10(
      DynamicTextureSheetHandle& outSheet,
      ID3DRenderTarget* sourceRenderTarget,
      DynamicTextureSheetHandle currentSheet
    ) override;

    /**
     * Address: 0x004420A0 (FUN_004420A0)
     *
     * What it does:
     * Finds one compiled effect by exact name.
     */
    CD3DEffect* FindEffect(const char* effectName) override;

    /**
     * Address: 0x004427A0 (FUN_004427A0)
     *
     * What it does:
     * Emits one per-texture byte-usage report and total to the output stream.
     */
    void DumpPreloadedTextures(gpg::Stream* stream) override;

    /**
     * Address: 0x004421C0 (FUN_004421C0)
     *
     * What it does:
     * Reacts to watched file changes by hot-reloading effect/texture resources.
     */
    void OnDiskWatchEvent(const SDiskWatchEvent& event) override;

    /**
     * Address: 0x00430D29 (observed in FUN_00430C20 ctor tail)
     *
     * What it does:
     * Binds owning device pointer used by resource creation lanes.
     */
    void SetDevice(CD3DDevice* device);

    /**
     * Address: 0x00440790 (FUN_00440790, Moho::CD3DDeviceResources::InitResources)
     *
     * bool devInit
     *
     * What it does:
     * Recreates runtime D3D buffers/surfaces for tracked resources after one
     * device reset and either recompiles effects (`devInit=true`) or forwards
     * reset notifications to loaded effects (`devInit=false`).
     */
    bool InitResources(bool devInit);

    /**
     * Address: 0x00440BC0 (FUN_00440BC0, helper lane)
     *
     * What it does:
     * Deletes cached vertex-format wrappers and resets the active cache range.
     */
    void ClearCachedVertexFormats();

  private:
    /**
     * Address: 0x00440D00 (FUN_00440D00)
     *
     * What it does:
     * Moves one vertex-sheet node into the static/dynamic ownership lane.
     */
    void LinkVertexSheet(CD3DVertexSheet* vertexSheet);

    /**
     * Address: 0x00440D60 (FUN_00440D60)
     *
     * What it does:
     * Moves one index-sheet node into the static/dynamic ownership lane.
     */
    void LinkIndexSheet(CD3DIndexSheet* indexSheet);

    void TrackTextureResource(RD3DTextureResource* textureResource);

    /**
     * Address: 0x00442320 (FUN_00442320, sub_442320)
     *
     * What it does:
     * Rebuilds one effect from disk for hot-reload and replaces the previous
     * effect object in the active effect vector.
     */
    void ReloadEffectFile(const msvc8::string& effectPath);

    /**
     * Address: 0x004424A0 (FUN_004424A0, Moho::CD3DDeviceResources::DevResInitResources)
     *
     * What it does:
     * Clears existing effects and compiles all `/effects/*.fx` resources.
     */
    void DevResInitResources();

  public:
    std::int32_t mMipSkipLevels;                              // +0x34
    CD3DDevice* mDevice;                                      // +0x38
    CD3DVertexSheet mVertexSheet1;                            // +0x3C
    CD3DVertexSheet mVertexSheet2;                            // +0x7C
    CD3DIndexSheet mIndexSheet1;                              // +0xBC
    CD3DIndexSheet mIndexSheet2;                              // +0xE4
    CD3DRenderTarget mRenderTarget;                           // +0x10C
    CD3DDepthStencil mDepthStencil;                           // +0x134
    TDatListItem<RD3DTextureResource, void> mTextureList;     // +0x160
    CD3DDynamicTextureSheet mTextureSheet;                    // +0x168
    msvc8::vector<CD3DVertexFormat*> mVertexFormats;          // +0x1D8
    msvc8::vector<CD3DEffect*> mEffects;                      // +0x1E8
  };

  static_assert(offsetof(CD3DDeviceResources, mMipSkipLevels) == 0x34, "CD3DDeviceResources::mMipSkipLevels offset must be 0x34");
  static_assert(offsetof(CD3DDeviceResources, mDevice) == 0x38, "CD3DDeviceResources::mDevice offset must be 0x38");
  static_assert(offsetof(CD3DDeviceResources, mVertexSheet1) == 0x3C, "CD3DDeviceResources::mVertexSheet1 offset must be 0x3C");
  static_assert(offsetof(CD3DDeviceResources, mVertexSheet2) == 0x7C, "CD3DDeviceResources::mVertexSheet2 offset must be 0x7C");
  static_assert(offsetof(CD3DDeviceResources, mIndexSheet1) == 0xBC, "CD3DDeviceResources::mIndexSheet1 offset must be 0xBC");
  static_assert(offsetof(CD3DDeviceResources, mIndexSheet2) == 0xE4, "CD3DDeviceResources::mIndexSheet2 offset must be 0xE4");
  static_assert(offsetof(CD3DDeviceResources, mRenderTarget) == 0x10C, "CD3DDeviceResources::mRenderTarget offset must be 0x10C");
  static_assert(offsetof(CD3DDeviceResources, mDepthStencil) == 0x134, "CD3DDeviceResources::mDepthStencil offset must be 0x134");
  static_assert(offsetof(CD3DDeviceResources, mTextureList) == 0x160, "CD3DDeviceResources::mTextureList offset must be 0x160");
  static_assert(offsetof(CD3DDeviceResources, mTextureSheet) == 0x168, "CD3DDeviceResources::mTextureSheet offset must be 0x168");
  static_assert(offsetof(CD3DDeviceResources, mVertexFormats) == 0x1D8, "CD3DDeviceResources::mVertexFormats offset must be 0x1D8");
  static_assert(offsetof(CD3DDeviceResources, mEffects) == 0x1E8, "CD3DDeviceResources::mEffects offset must be 0x1E8");
  static_assert(sizeof(CD3DDeviceResources) == 0x1F8, "CD3DDeviceResources size must be 0x1F8");
} // namespace moho

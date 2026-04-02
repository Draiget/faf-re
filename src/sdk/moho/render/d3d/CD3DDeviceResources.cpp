#include "CD3DDeviceResources.h"

#include <Windows.h>

#include <cstring>
#include <string.h>
#include <stdexcept>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DTextureResourceFactory.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  namespace
  {
    constexpr const char* kTextureWatchPattern = "*.dds;*.tga;*.bmp;*.jpg;*.png;*.fx";
    constexpr const char* kFallbackTexturePath = "/textures/engine/b_fails_to_load.dds";
    constexpr const char* kEffectsDirectory = "/effects";
    constexpr const char* kEffectsPattern = "*.fx";
    constexpr std::uint32_t kIndexContextTypeStatic = 1u;
    constexpr std::uint32_t kTextureFormatRenderTarget = 2u;
    constexpr std::uint32_t kTextureUsageRenderTargetCopy = 3u;
    constexpr int kDiskActionAdded = 1;
    constexpr int kDiskActionModified = 3;
    constexpr int kDiskActionRenamedNewName = 5;

    void EnsureTextureTypeRegistered()
    {
      if (RD3DTextureResource::sType == nullptr) {
        RD3DTextureResource::sType = gpg::LookupRType(typeid(RD3DTextureResource));
      }
    }

    /**
     * Address: 0x00443800 (FUN_00443800)
     *
     * What it does:
     * Resolves RD3D texture RTTI on demand and registers the prefetch type key
     * used by the D3D texture resource pipeline.
     */
    void RegisterTexturePrefetchType()
    {
      gpg::RType* textureType = RD3DTextureResource::sType;
      if (textureType == nullptr) {
        textureType = gpg::LookupRType(typeid(RD3DTextureResource));
        RD3DTextureResource::sType = textureType;
      }
      RES_RegisterPrefetchType("d3d_textures", textureType);
    }

    CD3DTextureResourceFactory* GetTextureFactory()
    {
      return func_CreateTextureResourceFactory();
    }

    /**
     * Address: 0x004422F0 (FUN_004422F0, sub_4422F0)
     *
     * What it does:
     * Returns true when one effect's source file path equals the requested path.
     */
    [[nodiscard]] bool EffectFilePathMatches(const CD3DEffect* const effect, const msvc8::string& path)
    {
      return effect != nullptr && effect->mFile == path;
    }

    /**
     * Address: 0x00445620 (FUN_00445620, func_GetD3DTextureResource_fromPath)
     *
     * What it does:
     * Loads one `RD3DTextureResource` handle for a path through the active
     * texture factory lane.
     */
    CD3DDeviceResources::TextureResourceHandle& GetD3DTextureResourceFromPath(
      CD3DDeviceResources::TextureResourceHandle& outTexture,
      const char* const path,
      CD3DTextureResourceFactory* const textureFactory
    )
    {
      outTexture.reset();
      if (textureFactory != nullptr) {
        textureFactory->LoadImpl(outTexture, path);
      }
      return outTexture;
    }

    /**
     * Address: 0x00445700 (FUN_00445700, Moho::RES_LoadPrefetchData)
     *
     * What it does:
     * Resolves one texture prefetch payload by path and throws when the payload
     * cannot be resolved.
     */
    CD3DDeviceResources::PrefetchDataHandle& RES_LoadPrefetchData(
      CD3DDeviceResources::PrefetchDataHandle& outPrefetchData,
      const char* const path
    )
    {
      EnsureTextureTypeRegistered();

      outPrefetchData.reset();
      RES_PrefetchResource(&outPrefetchData, path, RD3DTextureResource::sType);

      if (!outPrefetchData) {
        const msvc8::string errorText = gpg::STR_Printf(
          "Prefetch couldn't find file %s",
          path != nullptr ? path : ""
        );
        throw std::runtime_error(errorText.c_str());
      }

      return outPrefetchData;
    }

    /**
     * Address: 0x00446220 (FUN_00446220, sub_446220)
     *
     * What it does:
     * Scans one contiguous `CD3DEffect*` iterator range and returns the first
     * iterator whose `mFile` path equals the requested path.
     */
    CD3DEffect*** FindEffectPathIteratorCore(
      CD3DEffect*** const outIteratorSlot,
      CD3DEffect** const begin,
      CD3DEffect** const end,
      const msvc8::string& path
    )
    {
      CD3DEffect** it = begin;
      while (it != end) {
        if (EffectFilePathMatches(*it, path)) {
          break;
        }
        ++it;
      }

      *outIteratorSlot = it;
      return outIteratorSlot;
    }

    /**
     * Address: 0x004458F0 (FUN_004458F0, sub_4458F0)
     *
     * What it does:
     * Materializes one local path-copy lane and forwards to the core effect-path
     * iterator search helper.
     */
    CD3DEffect*** FindEffectPathIterator(
      CD3DEffect*** const outIteratorSlot,
      CD3DEffect** const begin,
      CD3DEffect** const end,
      msvc8::string path
    )
    {
      msvc8::string localPath(path);
      return FindEffectPathIteratorCore(outIteratorSlot, begin, end, localPath);
    }

  } // namespace

  /**
   * Address: 0x00440490 (FUN_00440490)
   *
   * What it does:
   * Initializes D3D resource-owner state, embedded list heads/wrappers, and
   * vertex/effect cache vectors.
   */
  CD3DDeviceResources::CD3DDeviceResources()
    : CDiskWatchListener(kTextureWatchPattern)
    , mMipSkipLevels(0)
    , mDevice(nullptr)
    , mVertexSheet1(nullptr, nullptr, 0, 0, nullptr)
    , mVertexSheet2(nullptr, nullptr, 0, 0, nullptr)
    , mIndexSheet1(nullptr, 0, false)
    , mIndexSheet2(nullptr, 0, false)
    , mRenderTarget()
    , mDepthStencil()
    , mTextureList()
    , mTextureSheet(nullptr, false, 0, 0, 0, false)
    , mVertexFormats()
    , mEffects()
  {}

  /**
   * Address: 0x00440660 (FUN_00440660, non-deleting body)
   *
   * What it does:
   * Releases embedded sheet/target wrappers and clears vector storage.
   */
  CD3DDeviceResources::~CD3DDeviceResources() = default;

  /**
   * Address: 0x00440DC0 (FUN_00440DC0)
   *
   * What it does:
   * Stores one global mip-skip level and reloads all tracked texture resources.
   */
  void CD3DDeviceResources::SetSkipMipLevels(const int mipSkipLevels)
  {
    mMipSkipLevels = mipSkipLevels;

    using TextureResourceList = TDatList<RD3DTextureResource, void>;
    auto* node = mTextureList.mNext;
    while (node != &mTextureList) {
      auto* const next = node->mNext;
      auto* const textureResource = TextureResourceList::template owner_from_member<
        RD3DTextureResource,
        TDatListItem<RD3DTextureResource, void>,
        &RD3DTextureResource::mResources>(node);
      if (textureResource != nullptr) {
        textureResource->ReloadTexture();
      }
      node = next;
    }
  }

  /**
   * Address: 0x00440E00 (FUN_00440E00)
   *
   * What it does:
   * Returns the current global mip-skip level.
   */
  int CD3DDeviceResources::GetSkipMipLevels() const
  {
    return mMipSkipLevels;
  }

  /**
   * Address: 0x00440E80 (FUN_00440E80)
   *
   * What it does:
   * Creates one render-target wrapper and links it into the render-target lane.
   */
  CD3DDeviceResources::RenderTargetHandle&
  CD3DDeviceResources::CreateRenderTarget(
    RenderTargetHandle& outTarget,
    const int width,
    const int height,
    const int format
  )
  {
    outTarget.reset();

    CD3DRenderTarget* const renderTarget = new CD3DRenderTarget();
    if (renderTarget->ConfigureAndRecreate(mDevice, width, height, format)) {
      renderTarget->mLink.ListLinkAfter(&mRenderTarget.mLink);
      outTarget.reset(renderTarget);
      return outTarget;
    }

    delete renderTarget;
    return outTarget;
  }

  /**
   * Address: 0x00440E10 (FUN_00440E10)
   *
   * What it does:
   * Compatibility lane that forwards context payload into `CreateRenderTarget`.
   */
  CD3DDeviceResources::RenderTargetHandle&
  CD3DDeviceResources::Func3(
    RenderTargetHandle& outTarget,
    const gpg::gal::RenderTargetContext& context
  )
  {
    return CreateRenderTarget(
      outTarget,
      static_cast<int>(context.width_),
      static_cast<int>(context.height_),
      static_cast<int>(context.format_)
    );
  }

  /**
   * Address: 0x00440F80 (FUN_00440F80)
   *
   * What it does:
   * Creates one depth-stencil wrapper and links it into depth-stencil lane.
   */
  CD3DDeviceResources::DepthStencilHandle&
  CD3DDeviceResources::CreateDepthStencil(
    DepthStencilHandle& outDepthStencil,
    const int width,
    const int height,
    const int format
  )
  {
    outDepthStencil.reset();

    CD3DDepthStencil* const depthStencil = new CD3DDepthStencil();
    if (depthStencil->ConfigureAndRecreate(mDevice, width, height, format)) {
      depthStencil->mLink.ListLinkAfter(&mDepthStencil.mLink);
      outDepthStencil.reset(depthStencil);
      return outDepthStencil;
    }

    delete depthStencil;
    return outDepthStencil;
  }

  /**
   * Address: 0x00441080 (FUN_00441080)
   *
   * What it does:
   * Returns cached vertex format by token or creates/stores one on miss.
   */
  CD3DVertexFormat* CD3DDeviceResources::GetVertexFormat(const int formatToken)
  {
    const auto desiredFormat = static_cast<std::uint32_t>(formatToken);
    for (CD3DVertexFormat* const vertexFormat : mVertexFormats) {
      if (vertexFormat == nullptr) {
        continue;
      }

      const auto* const d3dVertexFormat = vertexFormat->mFormat.get();
      if (d3dVertexFormat != nullptr && d3dVertexFormat->formatCode_ == desiredFormat) {
        return vertexFormat;
      }
    }

    CD3DVertexFormat* const createdVertexFormat = new CD3DVertexFormat(desiredFormat);
    mVertexFormats.push_back(createdVertexFormat);
    return createdVertexFormat;
  }

  /**
   * Address: 0x00441150 (FUN_00441150)
   *
   * What it does:
   * Creates one vertex sheet with internally-owned stream lanes and links it
   * into the matching availability list.
   */
  CD3DVertexSheet* CD3DDeviceResources::NewVertexSheet(
    const std::uint32_t streamUsageToken,
    const int streamFrequencyToken,
    CD3DVertexFormat* const vertexFormat
  )
  {
    CD3DVertexSheet* const vertexSheet =
      new CD3DVertexSheet(vertexFormat, mDevice, streamFrequencyToken, streamUsageToken, nullptr);
    LinkVertexSheet(vertexSheet);
    return vertexSheet;
  }

  /**
   * Address: 0x004411D0 (FUN_004411D0)
   *
   * What it does:
   * Creates one vertex-stream wrapper from format lane metadata.
   */
  CD3DVertexStream* CD3DDeviceResources::Func5(
    const std::uint32_t dynamicUsageToken,
    const int formatElementIndex,
    const int streamWidth,
    CD3DVertexFormat* const vertexFormat
  )
  {
    std::uint32_t streamStrideToken = 0;
    if (vertexFormat != nullptr) {
      streamStrideToken = vertexFormat->GetElement(static_cast<std::uint32_t>(formatElementIndex));
    }

    CD3DVertexStream* const vertexStream = new CD3DVertexStream(
      mDevice,
      static_cast<std::uint32_t>(streamWidth),
      streamStrideToken,
      dynamicUsageToken != 0u
    );
    vertexStream->CreateBuffer();
    return vertexStream;
  }

  /**
   * Address: 0x00441260 (FUN_00441260)
   *
   * What it does:
   * Creates one vertex sheet from caller-provided stream lanes and links it
   * into the matching availability list.
   */
  CD3DVertexSheet* CD3DDeviceResources::Func6(
    const std::uint32_t streamUsageToken,
    const int streamFrequencyToken,
    CD3DVertexFormat* const vertexFormat,
    CD3DVertexStream** const streams
  )
  {
    CD3DVertexSheet* const vertexSheet =
      new CD3DVertexSheet(vertexFormat, mDevice, streamFrequencyToken, streamUsageToken, streams);
    LinkVertexSheet(vertexSheet);
    return vertexSheet;
  }

  /**
   * Address: 0x004412E0 (FUN_004412E0)
   *
   * What it does:
   * Creates one index-sheet wrapper and links it into static/dynamic lane.
   */
  CD3DIndexSheet* CD3DDeviceResources::CreateIndexSheet(const bool dynamicUsage, const int size)
  {
    CD3DIndexSheet* const indexSheet = new CD3DIndexSheet(mDevice, static_cast<std::uint32_t>(size), dynamicUsage);
    if (indexSheet == nullptr) {
      gpg::Die("CD3DDeviceResource: Unable to create index sheet");
    }

    LinkIndexSheet(indexSheet);
    return indexSheet;
  }

  /**
   * Address: 0x00441370 (FUN_00441370)
   *
   * What it does:
   * Loads one texture resource by path, with optional fallback, and moves the
   * resolved resource node to the tracked texture list head.
   */
  CD3DDeviceResources::TextureResourceHandle& CD3DDeviceResources::GetTexture(
    TextureResourceHandle& outTexture,
    const char* const path,
    const int allowCreate,
    const bool allowFallback
  )
  {
    (void)allowCreate;

    if (CD3DTextureResourceFactory* const textureFactory = GetTextureFactory(); textureFactory != nullptr) {
      GetD3DTextureResourceFromPath(outTexture, path, textureFactory);

      if (!outTexture && allowFallback) {
        gpg::Logf("Can't find texture \"%s\" -- trying fallback.", path != nullptr ? path : "");
        GetD3DTextureResourceFromPath(outTexture, kFallbackTexturePath, textureFactory);
      }
    } else {
      outTexture.reset();
    }

    TrackTextureResource(outTexture.get());
    return outTexture;
  }

  /**
   * Address: 0x00441520 (FUN_00441520)
   *
   * What it does:
   * Resolves one prefetch payload for a texture path.
   */
  CD3DDeviceResources::PrefetchDataHandle&
  CD3DDeviceResources::LoadPrefetchData(PrefetchDataHandle& outPrefetchData, const char* const path)
  {
    return RES_LoadPrefetchData(outPrefetchData, path);
  }

  /**
   * Address: 0x00441680 (FUN_00441680)
   *
   * What it does:
   * Legacy texture-load lane that performs fallback loading and list relink.
   */
  CD3DDeviceResources::TextureResourceHandle&
  CD3DDeviceResources::Func7(TextureResourceHandle& outTexture, const char* const path)
  {
    if (CD3DTextureResourceFactory* const textureFactory = GetTextureFactory(); textureFactory != nullptr) {
      GetD3DTextureResourceFromPath(outTexture, path, textureFactory);

      if (!outTexture) {
        gpg::Logf("Can't find texture \"%s\" -- trying fallback.", path != nullptr ? path : "");
        GetD3DTextureResourceFromPath(outTexture, kFallbackTexturePath, textureFactory);
      }
    } else {
      outTexture.reset();
    }

    TrackTextureResource(outTexture.get());
    return outTexture;
  }

  /**
   * Address: 0x00441810 (FUN_00441810)
   *
   * What it does:
   * Creates one in-memory texture resource wrapper from location+blob payload.
   */
  CD3DDeviceResources::TextureResourceHandle&
  CD3DDeviceResources::GetTextureSheet(
    TextureResourceHandle& outTexture,
    const char* const location,
    void* const data,
    const std::size_t size
  )
  {
    outTexture.reset(new RD3DTextureResource(location, data, size));
    return outTexture;
  }

  /**
   * Address: 0x00441900 (FUN_00441900)
   *
   * What it does:
   * Creates one dynamic texture sheet, links it into tracking list, and
   * recreates the backing texture.
   */
  CD3DDeviceResources::DynamicTextureSheetHandle& CD3DDeviceResources::CreateDynamicTextureSheet2(
    DynamicTextureSheetHandle& outSheet,
    const int width,
    const int height,
    const int format
  )
  {
    outSheet.reset(new CD3DDynamicTextureSheet(
      mDevice,
      false,
      static_cast<std::uint32_t>(width),
      static_cast<std::uint32_t>(height),
      static_cast<std::uint32_t>(format),
      true
    ));

    if (CD3DDynamicTextureSheet* const sheet = outSheet.get(); sheet != nullptr) {
      sheet->mLink.ListLinkAfter(&mTextureSheet.mLink);
      sheet->CreateTexture();
    }
    return outSheet;
  }

  /**
   * Address: 0x00441AB0 (FUN_00441AB0)
   *
   * What it does:
   * Creates one non-archive dynamic texture sheet and recreates its texture.
   */
  CD3DDeviceResources::DynamicTextureSheetHandle& CD3DDeviceResources::NewDynamicTextureSheet(
    DynamicTextureSheetHandle& outSheet,
    const int width,
    const int height,
    const int format
  )
  {
    outSheet.reset(new CD3DDynamicTextureSheet(
      mDevice,
      false,
      static_cast<std::uint32_t>(width),
      static_cast<std::uint32_t>(height),
      static_cast<std::uint32_t>(format),
      false
    ));

    if (CD3DDynamicTextureSheet* const sheet = outSheet.get(); sheet != nullptr) {
      sheet->CreateTexture();
    }
    return outSheet;
  }

  /**
   * Address: 0x00441BE0 (FUN_00441BE0)
   *
   * What it does:
   * Creates one archive-mode dynamic texture sheet and recreates its texture.
   */
  CD3DDeviceResources::DynamicTextureSheetHandle& CD3DDeviceResources::CreateDynamicTextureSheet(
    DynamicTextureSheetHandle& outSheet,
    const int width,
    const int height,
    const int format
  )
  {
    outSheet.reset(new CD3DDynamicTextureSheet(
      mDevice,
      true,
      static_cast<std::uint32_t>(width),
      static_cast<std::uint32_t>(height),
      static_cast<std::uint32_t>(format),
      false
    ));

    if (CD3DDynamicTextureSheet* const sheet = outSheet.get(); sheet != nullptr) {
      sheet->CreateTexture();
    }
    return outSheet;
  }

  /**
   * Address: 0x00441D20 (FUN_00441D20)
   *
   * What it does:
   * Legacy weak-handle release lane for dynamic texture sheet callbacks.
   */
  bool CD3DDeviceResources::Func9(const int arg1, const int arg2, DynamicTextureSheetWeakHandle weakSheet)
  {
    (void)arg1;
    (void)arg2;
    (void)weakSheet;
    return true;
  }

  /**
   * Address: 0x00441D60 (FUN_00441D60)
   *
   * What it does:
   * Copies one render-target surface into a dynamic texture sheet, allocating
   * a replacement sheet when current dimensions do not match.
   */
  CD3DDeviceResources::DynamicTextureSheetHandle& CD3DDeviceResources::Func10(
    DynamicTextureSheetHandle& outSheet,
    ID3DRenderTarget* const sourceRenderTarget,
    DynamicTextureSheetHandle currentSheet
  )
  {
    gpg::gal::RenderTargetContext sourceContext{};
    ID3DRenderTarget::SurfaceHandle sourceSurface{};
    sourceRenderTarget->GetSurface(sourceSurface);
    sourceContext = *sourceSurface->GetContext();

    CD3DDynamicTextureSheet* sheet = currentSheet.get();
    bool needsReplacement = sheet == nullptr;
    if (!needsReplacement) {
      CD3DDynamicTextureSheet::TextureHandle texture{};
      sheet->GetTexture(texture);
      const gpg::gal::TextureContext* const textureContext = texture->GetContext();
      needsReplacement =
        textureContext->width_ != sourceContext.width_ ||
        textureContext->height_ != sourceContext.height_;
    }

    if (needsReplacement) {
      CD3DDynamicTextureSheet* const replacementSheet = new CD3DDynamicTextureSheet(
        mDevice,
        false,
        sourceContext.width_,
        sourceContext.height_,
        kTextureFormatRenderTarget,
        false
      );
      boost::ResetSharedFromRaw(&currentSheet, replacementSheet);
      sheet = currentSheet.get();
      if (sheet != nullptr) {
        sheet->mContext.usage_ = kTextureUsageRenderTargetCopy;
        sheet->CreateTexture();
      }
    }

    if (sheet != nullptr) {
      gpg::gal::DeviceD3D9* const deviceD3D9 = mDevice->GetDeviceD3D9();
      if (deviceD3D9 != nullptr) {
        CD3DDynamicTextureSheet::TextureHandle destinationTexture{};
        sheet->GetTexture(destinationTexture);

        ID3DRenderTarget::SurfaceHandle sourceSurfaceForCopy{};
        sourceRenderTarget->GetSurface(sourceSurfaceForCopy);

        gpg::gal::RenderTargetD3D9* sourceTexture = sourceSurfaceForCopy.get();
        deviceD3D9->CreateRenderTarget(&sourceTexture, &destinationTexture);
      }
    }

    boost::CopySharedRetain(&outSheet, currentSheet);
    return outSheet;
  }

  /**
   * Address: 0x004420A0 (FUN_004420A0)
   *
   * What it does:
   * Finds one compiled effect by exact name.
   */
  CD3DEffect* CD3DDeviceResources::FindEffect(const char* const effectName)
  {
    if (effectName == nullptr) {
      return nullptr;
    }

    const msvc8::string query(effectName);
    for (CD3DEffect* const effect : mEffects) {
      if (effect != nullptr && effect->mName == query) {
        return effect;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x004421C0 (FUN_004421C0)
   *
   * What it does:
   * Reacts to watched file changes by hot-reloading effect/texture resources.
   */
  void CD3DDeviceResources::OnDiskWatchEvent(const SDiskWatchEvent& event)
  {
    if (event.mActionCode != kDiskActionAdded &&
        event.mActionCode != kDiskActionModified &&
        event.mActionCode != kDiskActionRenamedNewName) {
      return;
    }

    const char* const eventPath = event.mPath.c_str();
    const char* const extension = FILE_Ext(eventPath);
    if (extension != nullptr && _stricmp(extension, "fx") == 0) {
      gpg::Logf("Reloading shader: %s", eventPath);
      ReloadEffectFile(event.mPath);
      return;
    }

    using TextureResourceList = TDatList<RD3DTextureResource, void>;
    for (auto* node = mTextureList.mNext; node != &mTextureList; node = node->mNext) {
      auto* const textureResource = TextureResourceList::template owner_from_member<
        RD3DTextureResource,
        TDatListItem<RD3DTextureResource, void>,
        &RD3DTextureResource::mResources>(node);
      if (textureResource == nullptr) {
        continue;
      }

      if (_stricmp(eventPath, textureResource->mContext.location_.c_str()) == 0) {
        gpg::Logf("Reloading texture: %s", eventPath);
        textureResource->ReloadTexture();
      }
    }
  }

  /**
   * Address: 0x00442320 (FUN_00442320, sub_442320)
   *
   * What it does:
   * Rebuilds one effect from disk for hot-reload and replaces the previous
   * effect object in the active effect vector.
   */
  void CD3DDeviceResources::ReloadEffectFile(const msvc8::string& effectPath)
  {
    CD3DEffect** matchedEffect = mEffects.end();
    FindEffectPathIterator(&matchedEffect, mEffects.begin(), mEffects.end(), effectPath);

    if (matchedEffect == mEffects.end()) {
      return;
    }

    ::Sleep(100u);

    CD3DEffect* const replacementEffect = new CD3DEffect();
    if (!replacementEffect->InitEffectFromFile(effectPath.c_str())) {
      delete replacementEffect;
      return;
    }

    (void)mDevice->SetCurEffect(nullptr);

    if (*matchedEffect != nullptr) {
      delete *matchedEffect;
    }
    mEffects.erase(matchedEffect);
    mEffects.push_back(replacementEffect);
  }

  /**
   * Address: 0x004424A0 (FUN_004424A0, Moho::CD3DDeviceResources::DevResInitResources)
   *
   * What it does:
   * Clears existing effects and compiles all `/effects/*.fx` resources.
   */
  void CD3DDeviceResources::DevResInitResources()
  {
    for (CD3DEffect* const effect : mEffects) {
      delete effect;
    }
    mEffects.clear();

    (void)mDevice->SetCurEffect(nullptr);

    FILE_EnsureWaitHandleSet();
    FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      gpg::Die("Unable to load FX files at local store [/effects/*.fx]");
    }

    msvc8::vector<msvc8::string> effectPaths{};
    waitHandleSet->mHandle->EnumerateFiles(kEffectsDirectory, kEffectsPattern, true, &effectPaths);
    if (effectPaths.empty()) {
      gpg::Die("Unable to load FX files at local store [/effects/*.fx]");
    }

    for (const msvc8::string& effectPath : effectPaths) {
      CD3DEffect* const effect = new CD3DEffect();

      msvc8::string mountedPath{};
      waitHandleSet->mHandle->FindFile(&mountedPath, effectPath.c_str(), nullptr);
      if (!effect->InitEffectFromFile(mountedPath.c_str())) {
        delete effect;
        gpg::Die(
          "CD3DDeviceResources::DevResInitResources: Unable to load effect file %s",
          effectPath.c_str()
        );
      }

      gpg::Logf("Compiled shader: %s", effectPath.c_str());
      mEffects.push_back(effect);
    }

    gpg::Logf("SHADERS COMPILED");
  }

  /**
   * Address: 0x004427A0 (FUN_004427A0, Moho::CD3DDeviceResources::DumpPreloadedTextures)
   *
   * What it does:
   * Writes preloaded texture byte usage lines plus one total summary line.
   */
  void CD3DDeviceResources::DumpPreloadedTextures(gpg::Stream* const stream)
  {
    if (stream == nullptr) {
      return;
    }

    int totalBytes = 0;
    using TextureResourceList = TDatList<RD3DTextureResource, void>;

    for (auto* node = mTextureList.mNext; node != &mTextureList; node = node->mNext) {
      auto* const textureResource = TextureResourceList::template owner_from_member<
        RD3DTextureResource,
        TDatListItem<RD3DTextureResource, void>,
        &RD3DTextureResource::mResources>(node);
      if (textureResource == nullptr) {
        continue;
      }

      const int byteCount =
        static_cast<int>(textureResource->mContext.dataEnd_ - textureResource->mContext.dataBegin_);
      if (byteCount == 0) {
        continue;
      }

      const msvc8::string line = gpg::STR_Printf(
        "%12i: %s\n",
        byteCount,
        textureResource->mContext.location_.c_str()
      );
      stream->Write(line.c_str(), line.size());
      totalBytes += byteCount;
    }

    const msvc8::string summary = gpg::STR_Printf("\nTOTAL: %i\n", totalBytes);
    stream->Write(summary.c_str(), summary.size());
  }

  /**
   * Address: 0x00430D29 (observed in FUN_00430C20 ctor tail)
   *
   * What it does:
   * Binds owning device pointer used by resource creation lanes.
   */
  void CD3DDeviceResources::SetDevice(CD3DDevice* const device)
  {
    mDevice = device;
  }

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
  bool CD3DDeviceResources::InitResources(const bool devInit)
  {
    bool allCreated = true;

    using VertexSheetList = TDatList<CD3DVertexSheet, void>;
    using IndexSheetList = TDatList<CD3DIndexSheet, void>;
    using RenderTargetList = TDatList<CD3DRenderTarget, void>;
    using DepthStencilList = TDatList<CD3DDepthStencil, void>;
    using DynamicTextureSheetList = TDatList<CD3DDynamicTextureSheet, void>;

    for (auto* node = mVertexSheet2.mLink.mNext; node != &mVertexSheet2.mLink; node = node->mNext) {
      auto* const vertexSheet =
        VertexSheetList::template owner_from_member_node<CD3DVertexSheet, &CD3DVertexSheet::mLink>(node);
      if (vertexSheet == nullptr) {
        continue;
      }

      const std::uint32_t streamCount = static_cast<std::uint32_t>(vertexSheet->mStreams.size());
      for (std::uint32_t streamIndex = 0U; streamIndex < streamCount; ++streamIndex) {
        if (!vertexSheet->mOwnedStreamMask.TestBit(streamIndex)) {
          continue;
        }

        CD3DVertexStream* const stream = vertexSheet->mStreams[streamIndex];
        if (stream != nullptr && !stream->CreateBuffer()) {
          allCreated = false;
        }
      }
    }

    for (auto* node = mIndexSheet2.mLink.mNext; node != &mIndexSheet2.mLink; node = node->mNext) {
      auto* const indexSheet =
        IndexSheetList::template owner_from_member_node<CD3DIndexSheet, &CD3DIndexSheet::mLink>(node);
      if (indexSheet == nullptr) {
        continue;
      }

      if (indexSheet->mBuffer.get() == nullptr) {
        auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
        if (device != nullptr) {
          (void)device->CreateIndexBuffer(&indexSheet->mBuffer, &indexSheet->mContext);
        }
      }
    }

    for (auto* node = mRenderTarget.mLink.mNext; node != &mRenderTarget.mLink; node = node->mNext) {
      auto* const renderTarget =
        RenderTargetList::template owner_from_member_node<CD3DRenderTarget, &CD3DRenderTarget::mLink>(node);
      if (renderTarget != nullptr && !renderTarget->RecreateFromContext()) {
        allCreated = false;
      }
    }

    for (auto* node = mDepthStencil.mLink.mNext; node != &mDepthStencil.mLink; node = node->mNext) {
      auto* const depthStencil =
        DepthStencilList::template owner_from_member_node<CD3DDepthStencil, &CD3DDepthStencil::mLink>(node);
      if (depthStencil != nullptr && !depthStencil->RecreateFromContext()) {
        allCreated = false;
      }
    }

    for (auto* node = mTextureSheet.mLink.mNext; node != &mTextureSheet.mLink; node = node->mNext) {
      auto* const dynamicSheet = DynamicTextureSheetList::template owner_from_member_node<
        CD3DDynamicTextureSheet,
        &CD3DDynamicTextureSheet::mLink>(node);
      if (dynamicSheet != nullptr && !dynamicSheet->CreateTexture()) {
        allCreated = false;
      }
    }

    if (devInit) {
      DevResInitResources();
    } else {
      for (CD3DEffect* const effect : mEffects) {
        if (effect != nullptr && effect->mEffect.px != nullptr) {
          effect->mEffect.px->OnReset();
        }
      }
    }

    return allCreated;
  }

  /**
   * Address: 0x00440BC0 (FUN_00440BC0, helper lane)
   *
   * What it does:
   * Deletes cached vertex-format wrappers and resets the active cache range.
   */
  void CD3DDeviceResources::ClearCachedVertexFormats()
  {
    for (CD3DVertexFormat* const vertexFormat : mVertexFormats) {
      delete vertexFormat;
    }
    mVertexFormats.clear();
  }

  /**
   * Address: 0x00440D00 (FUN_00440D00)
   *
   * What it does:
   * Moves one vertex-sheet node into the static/dynamic ownership lane.
   */
  void CD3DDeviceResources::LinkVertexSheet(CD3DVertexSheet* const vertexSheet)
  {
    if (vertexSheet == nullptr) {
      return;
    }

    TDatListItem<CD3DVertexSheet, void>* const listHead =
      vertexSheet->HasVertexStreamAvailable() ? &mVertexSheet1.mLink : &mVertexSheet2.mLink;
    vertexSheet->mLink.ListLinkAfter(listHead);
  }

  /**
   * Address: 0x00440D60 (FUN_00440D60)
   *
   * What it does:
   * Moves one index-sheet node into the static/dynamic ownership lane.
   */
  void CD3DDeviceResources::LinkIndexSheet(CD3DIndexSheet* const indexSheet)
  {
    if (indexSheet == nullptr) {
      return;
    }

    TDatListItem<CD3DIndexSheet, void>* const listHead = indexSheet->mContext.type_ != kIndexContextTypeStatic
      ? &mIndexSheet2.mLink
      : &mIndexSheet1.mLink;
    indexSheet->mLink.ListLinkAfter(listHead);
  }

  void CD3DDeviceResources::TrackTextureResource(RD3DTextureResource* const textureResource)
  {
    if (textureResource == nullptr) {
      return;
    }
    textureResource->mResources.ListLinkAfter(&mTextureList);
  }
} // namespace moho

#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    /**
     * Address: 0x009033A0 (FUN_009033A0)
     *
     * What it does:
     * Converts DXGI texture-format tokens to GAL texture-format tokens through
     * the recovered 89-entry mapping table, with fallback format token `20`.
     */
    int MapDxgiToGalTextureFormat(const int dxgiFormat)
    {
      for (const DXGIFormatPair& pair : kTextureDxgiGalPairs) {
        if (pair.dxgi == dxgiFormat) {
          return pair.gal;
        }
      }

      return 20;
    }

    /**
     * Address: 0x008FD1B0 (FUN_008FD1B0)
     *
     * What it does:
     * Creates a staging texture copy (`usage=3`, `bind=0`, `cpuAccess=0x20000`) from
     * the source texture and issues a native D3D10 copy-resource from source to staging.
     */
    ID3D10Texture2D* CreateStagingTextureCopyOrThrow(Device* const device, ID3D10Texture2D* const sourceTexture)
    {
      D3D10_TEXTURE2D_DESC textureDesc{};
      sourceTexture->GetDesc(&textureDesc);
      textureDesc.Usage = D3D10_USAGE_STAGING;
      textureDesc.BindFlags = 0U;
      textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

      ID3D10Device* const nativeDevice = static_cast<DeviceD3D10*>(device)->mDevice;
      ID3D10Texture2D* stagingTexture = nullptr;
      const HRESULT createResult = nativeDevice->CreateTexture2D(&textureDesc, nullptr, &stagingTexture);
      if (createResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1635, createResult);
      }

      nativeDevice->CopyResource(stagingTexture, sourceTexture);
      return stagingTexture;
    }

    /**
     * Address: 0x00903E10 (FUN_00903E10)
     *
     * What it does:
     * Executes the recovered non-deleting destructor body lanes for `TextureD3D10`.
     */
    void DestroyTextureD3D10Body(TextureD3D10* const texture)
    {
      texture->DestroyState();
    }
}


  /**
   * Address: 0x00903310 (FUN_00903310)
   *
   * What it does:
   * Initializes vtable/context lanes and clears retained texture lock/state members.
   */
  TextureD3D10::TextureD3D10()
    : context_()
    , texture_(nullptr)
    , stagingTexture_(nullptr)
    , shaderResourceView_(nullptr)
    , lockActive_(false)
    , lockPadding_{}
    , lockLevel_(0)
    , lockHistory_(nullptr)
    , contextFormatBackup_(0)
  {}

  /**
   * Address: 0x00904050 (FUN_00904050)
   *
   * TextureContext const *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 texture wrapper from caller context + retained texture/SRV
   * handles, then rebuilds mip/format-dependent lock state.
   */
  TextureD3D10::TextureD3D10(
    const TextureContext* const context, ID3D10Texture2D* const texture, ID3D10ShaderResourceView* const shaderResourceView
  )
    : context_()
    , texture_(nullptr)
    , stagingTexture_(nullptr)
    , shaderResourceView_(nullptr)
    , lockActive_(false)
    , lockPadding_{}
    , lockLevel_(0)
    , lockHistory_(nullptr)
    , contextFormatBackup_(0)
  {
    InitializeState(context, texture, shaderResourceView);
  }

  /**
   * Address: 0x00904030 (FUN_00904030)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates body lanes to `FUN_00903E10`.
   */
  TextureD3D10::~TextureD3D10()
  {
    DestroyTextureD3D10Body(this);
  }

  /**
   * Address: 0x00903370 (FUN_00903370)
   *
   * What it does:
   * Returns the embedded texture-context lane at `this+0x04`.
   */
  TextureContext* TextureD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00903410 (FUN_00903410)
   *
   * What it does:
   * Maps one texture level and returns the mapping, also recorded in
   * `lockHistory_[level]`. D3D10 maps whole levels, so the rect is unused; a
   * read-only lock of a texture without CPU read access goes through a
   * staging copy.
   */
  TextureLockRect TextureD3D10::Lock(const int level, const RECT& rect, const int flags)
  {
    static_cast<void>(rect);

    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 59, "attempt to map invalid texture");
    }

    ID3D10Texture2D* const lockedTexture = texture_;

    if (level >= static_cast<int>(context_.mipmapLevels_)) {
      ThrowGalError("TextureD3D10.cpp", 60, "attempt to map invalid texture level");
    }

    if (lockActive_) {
      ThrowGalError("TextureD3D10.cpp", 61, "texture map/unmap mismatch");
    }

    if (stagingTexture_ != nullptr) {
      ThrowGalError("TextureD3D10.cpp", 62, "");
    }

    TextureLockRect lock{};
    lock.flags = flags;
    lock.level = level;

    D3D10_MAP mapMode = D3D10_MAP_WRITE_DISCARD;
    ID3D10Texture2D* mapTexture = lockedTexture;
    if (((flags & 1) == 0) && ((flags & 2) != 0)) {
      mapMode = D3D10_MAP_READ;

      D3D10_TEXTURE2D_DESC textureDesc{};
      lockedTexture->GetDesc(&textureDesc);
      if ((textureDesc.CPUAccessFlags & 0x20000U) == 0U) {
        Device* const device = Device::GetInstance();
        stagingTexture_ = CreateStagingTextureCopyOrThrow(device, lockedTexture);
        mapTexture = stagingTexture_;
      }
    }

    D3D10_MAPPED_TEXTURE2D mapped{};
    const HRESULT mapResult = mapTexture->Map(static_cast<UINT>(level), mapMode, 0U, &mapped);
    if (mapResult < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 96, mapResult);
    }

    lock.pitch = static_cast<int>(mapped.RowPitch);
    lock.bits = mapped.pData;
    lockHistory_[level] = lock;
    return lock;
  }

  /**
   * Address: 0x00903700 (FUN_00903700)
   *
   * What it does:
   * Unmaps one texture level and clears lock-tracking state lanes.
   */
  int TextureD3D10::Unlock(const int level)
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 137, "attempt to map invalid texture");
    }

    if (level >= static_cast<int>(context_.mipmapLevels_)) {
      ThrowGalError("TextureD3D10.cpp", 138, "attempt to map invalid texture level");
    }

    if (lockActive_) {
      ThrowGalError("TextureD3D10.cpp", 139, "texture map/unmap mismatch");
    }

    if (stagingTexture_ != nullptr) {
      stagingTexture_->Unmap(static_cast<UINT>(level));
    } else {
      texture_->Unmap(static_cast<UINT>(level));
    }

    // The binary returns what the staging copy's Release returned (or the null
    // pointer when there was none) and clears the lock state after it.
    int releaseResult = 0;
    if (stagingTexture_ != nullptr) {
      releaseResult = static_cast<int>(stagingTexture_->Release());
      stagingTexture_ = nullptr;
    }
    lockActive_ = false;
    lockLevel_ = 0;
    return releaseResult;
  }

  /**
   * Address: 0x00903390 (FUN_00903390)
   *
   * What it does:
   * Releases one mapping by unlocking its level - a virtual call to slot 3
   * (`mov eax,[ecx]; call [eax+0xC]`), `ret 0x10` for the by-value rect.
   */
  int TextureD3D10::Unlock(const TextureLockRect lock)
  {
    return Unlock(lock.level);
  }

  /**
   * Address: 0x009038D0 (FUN_009038D0)
   *
   * What it does:
   * Serializes texture bytes into the caller-provided memory buffer.
   */
  void TextureD3D10::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 172, "attempt to unlock invalid texture");
    }

    ID3D10Texture2D* const texture = texture_;

    auto* const device = static_cast<DeviceD3D10*>(Device::GetInstance());

    // An empty blob made first and released last; the encoded one below is
    // never released (the binary leaks it).
    ID3D10Blob* scratchBlob = nullptr;
    HRESULT result = device->CreateBlob(0U, &scratchBlob);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 177, result);
    }

    ID3D10Blob* encodedBlob = nullptr;
    result = device->SaveTextureToMemory(texture, D3DX10_IFF_DDS, &encodedBlob);
    if (result < 0) {
      ThrowGalErrorFromHresult("TextureD3D10.cpp", 178, result);
    }

    const unsigned int encodedSize = static_cast<unsigned int>(encodedBlob->GetBufferSize());
    if (outBuffer->Size() != encodedSize) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(encodedSize);
      *outBuffer = resizedBuffer;
    }

    // Raw encoded blob copy from the D3DX buffer.
    std::copy_n(static_cast<const char*>(encodedBlob->GetBufferPointer()), encodedSize, outBuffer->GetPtr(0U, 0U));

    SafeRelease(scratchBlob);
  }

  /**
   * Address: 0x00903BE0 (FUN_00903BE0)
   *
   * What it does:
   * Validates and returns the retained texture lane.
   */
  ID3D10Texture2D* TextureD3D10::GetTextureOrThrow()
  {
    if (texture_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 224, "invalid texture");
    }

    return texture_;
  }

  /**
   * Address: 0x00903CA0 (FUN_00903CA0)
   *
   * What it does:
   * Validates and returns the retained shader-resource-view lane.
   */
  ID3D10ShaderResourceView* TextureD3D10::GetShaderResourceViewOrThrow()
  {
    if (shaderResourceView_ == nullptr) {
      ThrowGalError("TextureD3D10.cpp", 230, "invalid shader resource view");
    }

    return shaderResourceView_;
  }

  /**
   * Address: 0x00903D60 (FUN_00903D60)
   *
   * What it does:
   * Releases retained texture/state resources and resets texture context lanes.
   */
  void TextureD3D10::DestroyState()
  {
    if (lockActive_) {
      static_cast<void>(Unlock(lockLevel_));
    }

    if (lockHistory_ != nullptr) {
      delete[] lockHistory_;
    }

    SafeRelease(texture_);
    SafeRelease(shaderResourceView_);

    const TextureContext resetContext{};
    context_.AssignFrom(resetContext);
  }

  /**
   * Address: 0x00903E70 (FUN_00903E70)
   *
   * TextureContext const *,void *,void *
   *
   * What it does:
   * Rebuilds texture wrapper state from caller context + texture/SRV handles and
   * allocates per-level lock-history storage.
   */
  void TextureD3D10::InitializeState(
    const TextureContext* const context, ID3D10Texture2D* const texture, ID3D10ShaderResourceView* const shaderResourceView
  )
  {
    DestroyState();
    context_.AssignFrom(*context);
    shaderResourceView_ = shaderResourceView;
    texture_ = texture;

    D3D10_TEXTURE2D_DESC textureDesc{};
    texture_->GetDesc(&textureDesc);
    context_.mipmapLevels_ = textureDesc.MipLevels;
    context_.width_ = textureDesc.Width;
    context_.height_ = textureDesc.Height;

    if (context_.mipmapLevels_ < 1U) {
      ThrowGalError("TextureD3D10.cpp", 205, "invalid texture");
    }

    context_.ClearDataBuffer();

    lockHistory_ = new TextureLockRect[context_.mipmapLevels_];
    contextFormatBackup_ = static_cast<int>(context_.format_);
    const int contextFormatBackupDxgi = MapGalTextureFormatToDxgi(contextFormatBackup_);
    static_cast<void>(contextFormatBackupDxgi);
    context_.format_ = static_cast<std::uint32_t>(MapDxgiToGalTextureFormat(static_cast<int>(textureDesc.Format)));
    const unsigned int formatBlockBytes = GetTextureFormatBlockBytes(context_.format_);
    static_cast<void>(formatBlockBytes);
    if (context_.format_ == 20U) {
      DestroyState();
      ThrowGalError("TextureD3D10.cpp", 213, "unsupported texture format");
    }
  }
}


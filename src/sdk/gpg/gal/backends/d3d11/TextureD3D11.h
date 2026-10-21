#pragma once

// FAF addition, not in the shipped binary: the Direct3D 11 counterpart of
// TextureD3D10.

#include <cstdint>
#include <vector>

#include <d3d11.h>
#include <wrl/client.h>

#include "gpg/gal/Texture.hpp"
#include "gpg/gal/TextureContext.h"

namespace gpg::gal
{
  /**
   * A 2D (or cube) texture and its shader-resource view.
   *
   * Locking follows D3D9's managed pool rather than D3D10's whole-level
   * WRITE_DISCARD map: each level the engine locks keeps a CPU copy, the lock
   * hands out that copy (at the rect's corner), and unlocking a writable lock
   * uploads the level with `UpdateSubresource`. Textures the engine created
   * empty start from a zeroed copy; textures loaded from a file read the
   * level back through a staging copy the first time it is locked.
   */
  class TextureD3D11 final : public Texture
  {
  public:
    TextureD3D11(
      const TextureContext& context,
      ID3D11Device* device,
      ID3D11DeviceContext* immediate,
      ID3D11Resource* resource,
      ID3D11ShaderResourceView* shaderResourceView,
      bool contentsFromEngine
    );
    ~TextureD3D11() override;

    TextureContext* GetContext() override;
    TextureLockRect Lock(int level, const RECT& rect, int flags) override;
    int Unlock(TextureLockRect lock) override;
    int Unlock(int level) override;
    void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) override;

    /** The texture's view; throws when there is none. */
    [[nodiscard]] ID3D11ShaderResourceView* GetShaderResourceView() const;
    /** The texture; throws when it is not 2D. */
    [[nodiscard]] ID3D11Texture2D* GetTexture2D() const;
    [[nodiscard]] ID3D11Resource* GetResource() const noexcept { return mResource.Get(); }
    [[nodiscard]] DXGI_FORMAT GetFormat() const noexcept { return mDesc.Format; }

    /**
     * The GPU copy changed behind the CPU one (a copy into this texture):
     * drop the CPU levels so the next lock reads the texture back.
     */
    void DiscardCpuCopy() noexcept;

  private:
    /** Fills `mLevels[level]` from the GPU copy through a staging texture. */
    void ReadBackLevel(std::uint32_t level);

    TextureContext mContext;
    Microsoft::WRL::ComPtr<ID3D11Device> mDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mImmediate;
    Microsoft::WRL::ComPtr<ID3D11Resource> mResource;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> mTexture2D;
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> mShaderResourceView;
    D3D11_TEXTURE2D_DESC mDesc{};
    std::vector<std::vector<std::uint8_t>> mLevels; // the CPU copy of each locked level
    bool mContentsFromEngine = false;
    bool mLocked = false;
    int mLockedLevel = 0;
    int mLockedFlags = 0;
  };
} // namespace gpg::gal

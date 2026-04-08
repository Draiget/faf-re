#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "moho/render/textures/CD3DRawBatchTexture.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E02AAC
   * COL: 0x00E5FAA8
   */
  class CD3DFileBatchTexture final : public CD3DRawBatchTexture
  {
  public:
    /**
     * Address: 0x004483E0 (FUN_004483E0, Moho::CD3DFileBatchTexture::CD3DFileBatchTexture)
     *
     * boost::shared_ptr<moho::SBatchTextureData>,unsigned int,std::string const &
     *
     * What it does:
     * Constructs one file-backed raw batch texture and stores the lookup filename.
     */
    CD3DFileBatchTexture(const DataHandle& data, std::uint32_t border, const msvc8::string& filename);

    /**
     * Address: 0x00448490 (FUN_00448490, Moho::CD3DFileBatchTexture::dtr)
     * Address: 0x004484D0 (FUN_004484D0, non-deleting helper lane)
     *
     * What it does:
     * Releases owned filename storage and runs base raw-batch-texture teardown.
     */
    ~CD3DFileBatchTexture() override;

    /**
     * Address: 0x00448450 (FUN_00448450)
     *
     * What it does:
     * Returns whether this file texture is currently marked for deferred delete.
     */
    [[nodiscard]] bool CanDelete() const;

    /**
     * Address: 0x00448460 (FUN_00448460)
     *
     * What it does:
     * Marks this texture as eligible for deferred delete on close.
     */
    void MarkCanDelete();

    /**
     * Address: 0x00448470 (FUN_00448470)
     *
     * What it does:
     * Clears deferred-delete mark so this texture can be reused.
     */
    void ClearCanDelete();

    /**
     * Address: 0x00448480 (FUN_00448480)
     *
     * What it does:
     * Returns the stored filename key used by the texture cache.
     */
    [[nodiscard]] const msvc8::string& GetFilename() const;

    /**
     * Address: 0x00448500 (FUN_00448500, Moho::CD3DFileBatchTexture::OnClose)
     *
     * What it does:
     * Custom shared-pointer close callback that either defers deletion into the
     * file-texture retain queue or finalizes destruction.
     */
    static void OnClose(CD3DFileBatchTexture* texture);

  public:
    msvc8::string mFilename; // +0x28
    bool mCanDelete = false; // +0x44
  };

  /**
   * Address: 0x00BC43A0 (FUN_00BC43A0, register_mTextureMap)
   *
   * What it does:
   * Startup thunk that materializes the global file-texture lookup map storage.
   */
  void register_mTextureMap();

  /**
   * Address: 0x00BC43E0 (FUN_00BC43E0, register_sFileTextures)
   *
   * What it does:
   * Startup thunk that materializes the global file-texture retain queue storage.
   */
  void register_sFileTextures();

  static_assert(offsetof(CD3DFileBatchTexture, mFilename) == 0x28, "CD3DFileBatchTexture::mFilename offset must be 0x28");
  static_assert(offsetof(CD3DFileBatchTexture, mCanDelete) == 0x44, "CD3DFileBatchTexture::mCanDelete offset must be 0x44");
  static_assert(sizeof(CD3DFileBatchTexture) == 0x48, "CD3DFileBatchTexture size must be 0x48");
} // namespace moho

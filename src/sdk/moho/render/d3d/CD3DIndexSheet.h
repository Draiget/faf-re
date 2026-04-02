#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DIndexSheet.h"

namespace moho
{
  class CD3DDevice;

  class CD3DIndexSheet : public ID3DIndexSheet
  {
  public:
    using BufferHandle = ID3DIndexSheet::BufferHandle;

    /**
     * Address: 0x0043F520 (FUN_0043F520)
     *
     * CD3DDevice *,int,bool
     *
     * What it does:
     * Initializes list links and index-buffer context metadata, then optionally
     * creates the backing gal index buffer when a device is present.
     */
    CD3DIndexSheet(CD3DDevice* device, std::uint32_t size, bool dynamicUsage);

    /**
     * Address: 0x0043F5B0 (FUN_0043F5B0, deleting thunk)
     * Address: 0x0043F620 (FUN_0043F620, non-deleting body)
     *
     * What it does:
     * Releases retained index-buffer ownership, destroys embedded context state,
     * and unlinks this node from its intrusive ring.
     */
    ~CD3DIndexSheet() override;

    /**
     * Address: 0x0043F870 (FUN_0043F870)
     *
     * What it does:
     * Deletes this wrapper instance through the virtual destructor path.
     */
    void Destroy() override;

    /**
     * Address: 0x0043F880 (FUN_0043F880)
     *
     * What it does:
     * Returns the owning D3D device wrapper lane.
     */
    CD3DDevice* GetDevice() override;

    /**
     * Address: 0x0043F890 (FUN_0043F890)
     *
     * What it does:
     * Returns true when retained index-buffer context type differs from token `1`.
     */
    bool Func3() override;

    /**
     * Address: 0x0043F8B0 (FUN_0043F8B0)
     *
     * boost::shared_ptr<gpg::gal::IndexBufferD3D9> &
     *
     * What it does:
     * Copies retained index-buffer ownership into caller storage.
     */
    BufferHandle& GetBuffer(BufferHandle& outBuffer) override;

    /**
     * Address: 0x0043F900 (FUN_0043F900)
     *
     * What it does:
     * Returns retained index count from the backing buffer context.
     */
    std::uint32_t GetSize() const override;

    /**
     * Address: 0x0043F910 (FUN_0043F910)
     *
     * std::uint32_t
     *
     * What it does:
     * Recreates the backing index buffer when the requested size differs.
     */
    bool SetSize(std::uint32_t size) override;

    /**
     * Address: 0x0043F950 (FUN_0043F950)
     *
     * std::uint32_t,std::uint32_t,bool,bool
     *
     * What it does:
     * Locks one index range in units of 16-bit indices and returns mapped data.
     */
    std::int16_t* Lock(std::uint32_t startIndex, std::uint32_t indexCount, bool readOnly, bool discard) override;

    /**
     * Address: 0x0043FA00 (FUN_0043FA00)
     *
     * What it does:
     * Unlocks the retained index buffer when present.
     */
    void Unlock() override;

    /**
     * Address: 0x0043FA10 (FUN_0043FA10)
     *
     * What it does:
     * Binds retained index-buffer ownership on the current D3D9 device lane.
     */
    void SetBufferIndices() override;

  private:
    /**
     * Address: 0x0043F850 (FUN_0043F850)
     *
     * What it does:
     * Returns true when retained index-buffer context type is the static token.
     */
    [[nodiscard]] bool IsStaticBufferType() const;

    /**
     * Address: 0x0043F700 (FUN_0043F700)
     *
     * What it does:
     * Creates one gal index-buffer wrapper from retained context metadata.
     */
    bool CreateBuffer();

    /**
     * Address: 0x0043F810 (FUN_0043F810)
     *
     * What it does:
     * Drops retained index-buffer ownership and clears handle state.
     */
    void DestroyBuffer();

  public:
    TDatListItem<CD3DIndexSheet, void> mLink; // +0x04
    CD3DDevice* mDevice;                       // +0x0C
    BufferHandle mBuffer;                      // +0x10
    gpg::gal::IndexBufferContext mContext;     // +0x18
  };

  static_assert(sizeof(CD3DIndexSheet::BufferHandle) == 0x08, "CD3DIndexSheet::BufferHandle size must be 0x08");
  static_assert(offsetof(CD3DIndexSheet, mLink) == 0x04, "CD3DIndexSheet::mLink offset must be 0x04");
  static_assert(offsetof(CD3DIndexSheet, mDevice) == 0x0C, "CD3DIndexSheet::mDevice offset must be 0x0C");
  static_assert(offsetof(CD3DIndexSheet, mBuffer) == 0x10, "CD3DIndexSheet::mBuffer offset must be 0x10");
  static_assert(offsetof(CD3DIndexSheet, mContext) == 0x18, "CD3DIndexSheet::mContext offset must be 0x18");
  static_assert(sizeof(CD3DIndexSheet) == 0x28, "CD3DIndexSheet size must be 0x28");
} // namespace moho

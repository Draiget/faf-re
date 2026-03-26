#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "platform/Platform.h"
#include "wm3/Vector2.h"
#include "wm3/Vector3.h"

#if defined(_WIN32)
#include <d3d9types.h>
#else
struct RECT
{
  long left;
  long top;
  long right;
  long bottom;
};

struct D3DLOCKED_RECT
{
  int Pitch;
  void* pBits;
};
#endif

namespace gpg
{
  class BinaryReader;
  class RType;
  class Stream;
}

namespace gpg::gal
{
  class TextureD3D9;
}

namespace moho
{
  class ID3DTextureSheet
  {
  public:
    using TextureHandle = boost::shared_ptr<gpg::gal::TextureD3D9>;
    static gpg::RType* sType;

    /**
     * Address: 0x0043CD80 (FUN_0043CD80, sub_43CD80)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DTextureSheet();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * Wm3::Vector3f *
     *
     * What it does:
     * Writes retained texture dimensions to caller output.
     */
    virtual Wm3::Vector3f* GetDimensions(Wm3::Vector3f* outDimensions) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * Wm3::Vector2i *
     *
     * What it does:
     * Writes retained original texture dimensions into caller output.
     */
    virtual Wm3::Vector2i* GetOriginalDimensions(Wm3::Vector2i* outDimensions) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns retained texture byte size from context metadata.
     */
    virtual int GetTextureSizeInBytes() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * boost::shared_ptr<gpg::gal::TextureD3D9> &
     *
     * What it does:
     * Copies retained texture ownership into caller storage.
     */
    virtual TextureHandle& GetTexture(TextureHandle& outTexture) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * std::uint32_t *,void **
     *
     * What it does:
     * Locks full texture level and returns mapped pitch + byte pointer.
     */
    virtual bool Lock(std::uint32_t* outPitch, void** outBits) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * RECT const *,std::uint32_t *,void **
     *
     * What it does:
     * Locks one caller-provided rectangle and returns mapped pitch + byte pointer.
     */
    virtual bool LockRect(const RECT* rect, std::uint32_t* outPitch, void** outBits) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Unlocks the current texture lock lane.
     */
    virtual bool Unlock() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * gpg::BinaryReader *
     *
     * What it does:
     * Loads texture bytes from archive stream and recreates retained texture.
     */
    virtual bool ReadFromArchive(gpg::BinaryReader* reader) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * gpg::Stream *,bool
     *
     * What it does:
     * Serializes retained texture bytes to stream, with optional byte-count prefix.
     */
    virtual bool SaveToArchive(gpg::Stream* stream, bool writeSizeHeader) = 0;
  };

  static_assert(sizeof(ID3DTextureSheet) == 0x04, "ID3DTextureSheet size must be 0x04");
} // namespace moho

#pragma once

#include <cstdint>

namespace moho
{
  class CD3DDevice;
  class ID3DVertexFormat;
  class ID3DVertexStream;

  class ID3DVertexSheet
  {
  public:
    /**
     * Address: 0x0043CD20 (FUN_0043CD20, sub_43CD20)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DVertexSheet();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Deletes this wrapper through the virtual destructor path.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the owning D3D device wrapper lane.
     */
    virtual CD3DDevice* GetDevice() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns one retained vertex-sheet mode token.
     */
    virtual std::uint32_t Func3() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the retained vertex-format wrapper lane.
     */
    virtual ID3DVertexFormat* GetFormat() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns one retained per-stream frequency token.
     */
    virtual int Func5() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * int
     *
     * What it does:
     * Applies one frequency token across all live owned vertex streams.
     */
    virtual bool Func6(int streamFrequencyToken) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the number of retained vertex-stream lanes.
     */
    virtual int GetStreamCount() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * std::uint32_t
     *
     * What it does:
     * Returns one retained vertex-stream lane by stream index.
     */
    virtual ID3DVertexStream* GetVertStream(std::uint32_t streamIndex) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Binds the retained format and each retained vertex stream on the active device.
     */
    virtual void Func9() = 0;
  };

  static_assert(sizeof(ID3DVertexSheet) == 0x04, "ID3DVertexSheet size must be 0x04");
} // namespace moho

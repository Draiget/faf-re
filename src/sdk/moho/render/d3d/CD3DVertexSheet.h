#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/containers/BitStorage32.h"
#include "moho/containers/TDatList.h"
#include "moho/render/ID3DVertexSheet.h"

namespace moho
{
  class CD3DDevice;
  class CD3DVertexFormat;
  class CD3DVertexStream;

  class CD3DVertexSheet : public ID3DVertexSheet
  {
  public:
    /**
     * Address: 0x0043FE60 (FUN_0043FE60, ??0CD3DVertexSheet@Moho@@QAE@@Z)
     *
     * CD3DVertexFormat *,CD3DDevice *,int,std::uint32_t,CD3DVertexStream **
     *
     * IDA signature:
     * Moho::CD3DVertexSheet *__userpurge CD3DVertexSheet@<eax>(CD3DVertexFormat *a1@<ebx>, CD3DVertexSheet *this, CD3DDevice *a3, int a4, int a5, CD3DVertexStream **a6);
     *
     * What it does:
     * Initializes list links and typed stream ownership storage, then wires one
     * stream per vertex-format element from supplied streams or newly allocated
     * `CD3DVertexStream` lanes.
     */
    CD3DVertexSheet(
      CD3DVertexFormat* vertexFormat,
      CD3DDevice* device,
      int streamFrequencyToken,
      std::uint32_t streamUsageToken,
      CD3DVertexStream** streams
    );

    /**
     * Address: 0x00440000 (FUN_00440000, deleting destructor thunk)
     * Address: 0x00440030 (FUN_00440030, non-deleting destructor body)
     *
     * IDA signature:
     * _DWORD *__stdcall sub_440030(Moho::CD3DVertexSheet *a1);
     *
     * What it does:
     * Closes retained stream buffers, destroys owned stream objects, releases
     * stream/mask storage, and unlinks this sheet from its intrusive list.
     */
    ~CD3DVertexSheet() override;

    /**
     * Address: 0x004402C0 (FUN_004402C0)
     *
     * IDA signature:
     * int __thiscall Moho::CD3DVertexSheet::Func1(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Deletes this wrapper through the virtual destructor path.
     */
    void Destroy() override;

    /**
     * Address: 0x004402D0 (FUN_004402D0)
     *
     * IDA signature:
     * Moho::CD3DDevice *__thiscall Moho::CD3DVertexSheet::GetDevice(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Returns the owning D3D device wrapper lane.
     */
    CD3DDevice* GetDevice() override;

    /**
     * Address: 0x004402E0 (FUN_004402E0)
     *
     * IDA signature:
     * int __thiscall Moho::CD3DVertexSheet::Func3(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Returns retained stream usage token.
     */
    std::uint32_t Func3() const override;

    /**
     * Address: 0x004402F0 (FUN_004402F0)
     *
     * IDA signature:
     * Moho::CD3DVertexFormat *__thiscall Moho::CD3DVertexSheet::GetFormat(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Returns retained vertex-format wrapper lane.
     */
    ID3DVertexFormat* GetFormat() override;

    /**
     * Address: 0x00440300 (FUN_00440300)
     *
     * IDA signature:
     * int __thiscall Moho::CD3DVertexSheet::Func5(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Returns retained stream-frequency token.
     */
    int Func5() const override;

    /**
     * Address: 0x00440310 (FUN_00440310)
     *
     * int
     *
     * IDA signature:
     * char __thiscall Moho::CD3DVertexSheet::Func6(Moho::CD3DVertexSheet *this, int a2);
     *
     * What it does:
     * Closes current owned stream buffers, applies one frequency token to every
     * owned stream context, then recreates owned stream buffers.
     */
    bool Func6(int streamFrequencyToken) override;

    /**
     * Address: 0x004403D0 (FUN_004403D0)
     *
     * IDA signature:
     * int __thiscall Moho::CD3DVertexSheet::GetStreamCount(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Returns retained stream pointer count.
     */
    int GetStreamCount() const override;

    /**
     * Address: 0x00440280 (FUN_00440280, Moho::CD3DVertexSheet::HasVertexStreamAvailable)
     *
     * What it does:
     * Returns true when every retained stream buffer is in static-usage mode.
     */
    bool HasVertexStreamAvailable();

    /**
     * Address: 0x004403F0 (FUN_004403F0)
     *
     * std::uint32_t
     *
     * IDA signature:
     * Moho::CD3DVertexStream *__thiscall Moho::CD3DVertexSheet::GetVertStream(Moho::CD3DVertexSheet *this, unsigned int a2);
     *
     * What it does:
     * Returns one retained stream by index when in range.
     */
    ID3DVertexStream* GetVertStream(std::uint32_t streamIndex) override;

    /**
     * Address: 0x00440420 (FUN_00440420)
     *
     * IDA signature:
     * void __thiscall Moho::CD3DVertexSheet::Func9(Moho::CD3DVertexSheet *this);
     *
     * What it does:
     * Binds retained vertex declaration and all retained stream buffers on the
     * active D3D9 gal device.
     */
    void Func9() override;

  private:
    /**
     * Address: 0x00440140 (FUN_00440140)
     *
     * IDA signature:
     * char __usercall sub_440140@<al>(Moho::CD3DVertexSheet *a1@<edi>);
     *
     * What it does:
     * Calls `CreateBuffer` for each owned stream and reports aggregate success.
     */
    bool CreateOwnedStreamBuffers();

    /**
     * Address: 0x004401C0 (FUN_004401C0)
     *
     * IDA signature:
     * void __usercall sub_4401C0(Moho::CD3DVertexSheet *a1@<ebx>);
     *
     * What it does:
     * Releases retained shared-buffer handles for each owned stream.
     */
    void Close();

    [[nodiscard]] bool IsStreamOwned(std::uint32_t streamIndex) const;
    void SetStreamOwned(std::uint32_t streamIndex, bool owned);

  public:
    TDatListItem<CD3DVertexSheet, void> mLink;   // +0x04
    CD3DDevice* mDevice;                         // +0x0C
    CD3DVertexFormat* mVertexFormat;             // +0x10
    int mStreamFrequencyToken;                   // +0x14
    std::uint32_t mStreamUsageToken;             // +0x18
    msvc8::vector<CD3DVertexStream*> mStreams;   // +0x1C
    SBitStorage32 mOwnedStreamMask;              // +0x2C
  };

  static_assert(offsetof(CD3DVertexSheet, mLink) == 0x04, "CD3DVertexSheet::mLink offset must be 0x04");
  static_assert(offsetof(CD3DVertexSheet, mDevice) == 0x0C, "CD3DVertexSheet::mDevice offset must be 0x0C");
  static_assert(offsetof(CD3DVertexSheet, mVertexFormat) == 0x10, "CD3DVertexSheet::mVertexFormat offset must be 0x10");
  static_assert(
    offsetof(CD3DVertexSheet, mStreamFrequencyToken) == 0x14,
    "CD3DVertexSheet::mStreamFrequencyToken offset must be 0x14"
  );
  static_assert(
    offsetof(CD3DVertexSheet, mStreamUsageToken) == 0x18,
    "CD3DVertexSheet::mStreamUsageToken offset must be 0x18"
  );
  static_assert(offsetof(CD3DVertexSheet, mStreams) == 0x1C, "CD3DVertexSheet::mStreams offset must be 0x1C");
  static_assert(
    offsetof(CD3DVertexSheet, mOwnedStreamMask) == 0x2C,
    "CD3DVertexSheet::mOwnedStreamMask offset must be 0x2C"
  );
  static_assert(sizeof(CD3DVertexSheet) == 0x40, "CD3DVertexSheet size must be 0x40");
} // namespace moho

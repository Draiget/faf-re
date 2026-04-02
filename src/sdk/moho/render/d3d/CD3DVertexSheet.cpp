#include "CD3DVertexSheet.h"

#include <new>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include "gpg/core/utils/Global.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/render/d3d/CD3DVertexFormat.h"
#include "moho/render/d3d/CD3DVertexStream.h"

namespace moho
{
  namespace
  {
    constexpr const char* kOwnedStreamAssertMessage = "Reached the supposably unreachable.";
    constexpr int kOwnedStreamAssertLine = 966;
    constexpr const char* kOwnedStreamAssertFile = "c:\\work\\rts\\main\\code\\src\\core\\D3DRes.cpp";
  } // namespace

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
  CD3DVertexSheet::CD3DVertexSheet(
    CD3DVertexFormat* const vertexFormat,
    CD3DDevice* const device,
    const int streamFrequencyToken,
    const std::uint32_t streamUsageToken,
    CD3DVertexStream** const streams
  )
    : mLink()
    , mDevice(device)
    , mVertexFormat(vertexFormat)
    , mStreamFrequencyToken(streamFrequencyToken)
    , mStreamUsageToken(streamUsageToken)
    , mStreams()
    , mOwnedStreamMask{}
  {
    if (mDevice == nullptr) {
      return;
    }

    const std::uint32_t streamCount = mVertexFormat->GetElementCount();
    mStreams.resize(streamCount, nullptr);
    mOwnedStreamMask.Resize(streamCount, false);

    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (streams != nullptr && streams[streamIndex] != nullptr) {
        mStreams[streamIndex] = streams[streamIndex];
        SetStreamOwned(streamIndex, false);
        continue;
      }

      auto* const stream = new (std::nothrow) CD3DVertexStream(
        mDevice,
        static_cast<std::uint32_t>(mStreamFrequencyToken),
        mVertexFormat->GetElement(streamIndex),
        mStreamUsageToken != 0u
      );
      mStreams[streamIndex] = stream;
      SetStreamOwned(streamIndex, true);
    }

    CreateOwnedStreamBuffers();
  }

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
  CD3DVertexSheet::~CD3DVertexSheet()
  {
    Close();

    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (!IsStreamOwned(streamIndex)) {
        continue;
      }

      if (CD3DVertexStream* const stream = mStreams[streamIndex]; stream != nullptr) {
        delete stream;
      }
    }

    mOwnedStreamMask.Reset();
    mStreams = msvc8::vector<CD3DVertexStream*>{};
    mLink.ListUnlink();
  }

  /**
   * Address: 0x004402C0 (FUN_004402C0)
   *
   * IDA signature:
   * int __thiscall Moho::CD3DVertexSheet::Func1(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Deletes this wrapper through the virtual destructor path.
   */
  void CD3DVertexSheet::Destroy()
  {
    delete this;
  }

  /**
   * Address: 0x004402D0 (FUN_004402D0)
   *
   * IDA signature:
   * Moho::CD3DDevice *__thiscall Moho::CD3DVertexSheet::GetDevice(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Returns the owning D3D device wrapper lane.
   */
  CD3DDevice* CD3DVertexSheet::GetDevice()
  {
    return mDevice;
  }

  /**
   * Address: 0x004402E0 (FUN_004402E0)
   *
   * IDA signature:
   * int __thiscall Moho::CD3DVertexSheet::Func3(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Returns retained stream usage token.
   */
  std::uint32_t CD3DVertexSheet::Func3() const
  {
    return mStreamUsageToken;
  }

  /**
   * Address: 0x004402F0 (FUN_004402F0)
   *
   * IDA signature:
   * Moho::CD3DVertexFormat *__thiscall Moho::CD3DVertexSheet::GetFormat(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Returns retained vertex-format wrapper lane.
   */
  ID3DVertexFormat* CD3DVertexSheet::GetFormat()
  {
    return mVertexFormat;
  }

  /**
   * Address: 0x00440300 (FUN_00440300)
   *
   * IDA signature:
   * int __thiscall Moho::CD3DVertexSheet::Func5(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Returns retained stream-frequency token.
   */
  int CD3DVertexSheet::Func5() const
  {
    return mStreamFrequencyToken;
  }

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
  bool CD3DVertexSheet::Func6(const int streamFrequencyToken)
  {
    if (streamFrequencyToken == mStreamFrequencyToken) {
      return true;
    }

    Close();
    mStreamFrequencyToken = streamFrequencyToken;

    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (!IsStreamOwned(streamIndex)) {
        gpg::HandleAssertFailure(kOwnedStreamAssertMessage, kOwnedStreamAssertLine, kOwnedStreamAssertFile);
#if defined(_MSC_VER)
        __debugbreak();
#endif
        return false;
      }

      mStreams[streamIndex]->mContext.width_ = static_cast<std::uint32_t>(streamFrequencyToken);
    }

    return CreateOwnedStreamBuffers();
  }

  /**
   * Address: 0x004403D0 (FUN_004403D0)
   *
   * IDA signature:
   * int __thiscall Moho::CD3DVertexSheet::GetStreamCount(Moho::CD3DVertexSheet *this);
   *
   * What it does:
   * Returns retained stream pointer count.
   */
  int CD3DVertexSheet::GetStreamCount() const
  {
    return static_cast<int>(mStreams.size());
  }

  /**
   * Address: 0x00440280 (FUN_00440280, Moho::CD3DVertexSheet::HasVertexStreamAvailable)
   */
  bool CD3DVertexSheet::HasVertexStreamAvailable()
  {
    constexpr std::uint32_t kStaticUsage = 1u;

    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (mStreams[streamIndex]->mBuffer.get()->GetContext()->usage_ != kStaticUsage) {
        return false;
      }
    }

    return true;
  }

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
  ID3DVertexStream* CD3DVertexSheet::GetVertStream(const std::uint32_t streamIndex)
  {
    if (streamIndex >= static_cast<std::uint32_t>(mStreams.size())) {
      return nullptr;
    }

    return mStreams[streamIndex];
  }

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
  void CD3DVertexSheet::Func9()
  {
    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    mVertexFormat->SetVertexDeclaration();

    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamSlot = 0; streamSlot < streamCount; ++streamSlot) {
      CD3DVertexStream::BufferHandle streamBuffer{};
      mStreams[streamSlot]->GetBuffer(streamBuffer);
      device->SetVertexBuffer(streamSlot, streamBuffer, 1, 0);
    }
  }

  /**
   * Address: 0x00440140 (FUN_00440140)
   *
   * IDA signature:
   * char __usercall sub_440140@<al>(Moho::CD3DVertexSheet *a1@<edi>);
   *
   * What it does:
   * Calls `CreateBuffer` for each owned stream and reports aggregate success.
   */
  bool CD3DVertexSheet::CreateOwnedStreamBuffers()
  {
    bool allCreated = true;

    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (!IsStreamOwned(streamIndex)) {
        continue;
      }

      if (!mStreams[streamIndex]->CreateBuffer()) {
        allCreated = false;
      }
    }

    return allCreated;
  }

  /**
   * Address: 0x004401C0 (FUN_004401C0)
   *
   * IDA signature:
   * void __usercall sub_4401C0(Moho::CD3DVertexSheet *a1@<ebx>);
   *
   * What it does:
   * Releases retained shared-buffer handles for each owned stream.
   */
  void CD3DVertexSheet::Close()
  {
    const std::uint32_t streamCount = static_cast<std::uint32_t>(mStreams.size());
    for (std::uint32_t streamIndex = 0; streamIndex < streamCount; ++streamIndex) {
      if (!IsStreamOwned(streamIndex)) {
        continue;
      }

      mStreams[streamIndex]->mBuffer.reset();
    }
  }

  bool CD3DVertexSheet::IsStreamOwned(const std::uint32_t streamIndex) const
  {
    return mOwnedStreamMask.TestBit(streamIndex);
  }

  void CD3DVertexSheet::SetStreamOwned(const std::uint32_t streamIndex, const bool owned)
  {
    mOwnedStreamMask.SetBit(streamIndex, owned);
  }
} // namespace moho

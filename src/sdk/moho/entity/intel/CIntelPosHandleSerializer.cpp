#include "moho/entity/intel/CIntelPosHandleSerializer.h"

#include <cstdlib>

#include "moho/entity/intel/CIntelPosHandle.h"

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::CIntelPosHandleSerializer;

  Serializer gCIntelPosHandleSerializer{};

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return &serializer.mHelperLinks;
  }

  template <class TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mNext = self;
    serializer.mHelperLinks.mPrev = self;
  }

  template <class TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    serializer.mHelperLinks.mNext->mPrev = serializer.mHelperLinks.mPrev;
    serializer.mHelperLinks.mPrev->mNext = serializer.mHelperLinks.mNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mPrev = self;
    serializer.mHelperLinks.mNext = self;
    return self;
  }

  void cleanup_CIntelPosHandleSerializer_atexit()
  {
    (void)moho::cleanup_CIntelPosHandleSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076F3D0 (FUN_0076F3D0, Moho::CIntelPosHandleSerializer::Deserialize)
   */
  void CIntelPosHandleSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const handle = reinterpret_cast<CIntelPosHandle*>(objectPtr);
    handle->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0076F3E0 (FUN_0076F3E0, Moho::CIntelPosHandleSerializer::Serialize)
   */
  void CIntelPosHandleSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const handle = reinterpret_cast<const CIntelPosHandle*>(objectPtr);
    handle->MemberSerialize(archive);
  }

  /**
   * Address: 0x0076FB00 (FUN_0076FB00, gpg::SerSaveLoadHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00C01ED0 (FUN_00C01ED0, cleanup_CIntelPosHandleSerializer)
   *
   * What it does:
   * Unlinks startup `CIntelPosHandleSerializer` helper links and rewires
   * a self-linked sentinel lane.
   */
  gpg::SerHelperBase* cleanup_CIntelPosHandleSerializer()
  {
    return UnlinkSerializerNode(gCIntelPosHandleSerializer);
  }

  /**
   * Address: 0x00BDCCF0 (FUN_00BDCCF0, register_CIntelPosHandleSerializer)
   *
   * What it does:
   * Initializes startup serializer helper lanes for `CIntelPosHandle` and
   * installs process-exit cleanup.
   */
  void register_CIntelPosHandleSerializer()
  {
    InitializeSerializerNode(gCIntelPosHandleSerializer);
    gCIntelPosHandleSerializer.mLoadCallback = &CIntelPosHandleSerializer::Deserialize;
    gCIntelPosHandleSerializer.mSaveCallback = &CIntelPosHandleSerializer::Serialize;
    (void)std::atexit(&cleanup_CIntelPosHandleSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct CIntelPosHandleSerializerBootstrap
  {
    CIntelPosHandleSerializerBootstrap()
    {
      moho::register_CIntelPosHandleSerializer();
    }
  };

  [[maybe_unused]] CIntelPosHandleSerializerBootstrap gCIntelPosHandleSerializerBootstrap;
} // namespace


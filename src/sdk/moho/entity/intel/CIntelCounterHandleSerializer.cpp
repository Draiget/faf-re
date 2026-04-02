#include "moho/entity/intel/CIntelCounterHandleSerializer.h"

#include <cstdlib>

#include "moho/entity/intel/CIntelCounterHandle.h"

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::CIntelCounterHandleSerializer;

  Serializer gCIntelCounterHandleSerializer{};

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

  void cleanup_CIntelCounterHandleSerializer_atexit()
  {
    (void)moho::cleanup_CIntelCounterHandleSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0076F990 (FUN_0076F990, Moho::CIntelCounterHandleSerializer::Deserialize)
   */
  void CIntelCounterHandleSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const handle = reinterpret_cast<CIntelCounterHandle*>(objectPtr);
    handle->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0076F9A0 (FUN_0076F9A0, Moho::CIntelCounterHandleSerializer::Serialize)
   */
  void CIntelCounterHandleSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const handle = reinterpret_cast<const CIntelCounterHandle*>(objectPtr);
    handle->MemberSerialize(archive);
  }

  /**
   * Address: 0x0076FC20 (FUN_0076FC20, gpg::SerSaveLoadHelper_CIntelCounterHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelCounterHandle RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelCounterHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CIntelCounterHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00C01F90 (FUN_00C01F90, cleanup_CIntelCounterHandleSerializer)
   *
   * What it does:
   * Unlinks startup `CIntelCounterHandleSerializer` helper links and rewires
   * a self-linked sentinel lane.
   */
  gpg::SerHelperBase* cleanup_CIntelCounterHandleSerializer()
  {
    return UnlinkSerializerNode(gCIntelCounterHandleSerializer);
  }

  /**
   * Address: 0x00BDCD90 (FUN_00BDCD90, register_CIntelCounterHandleSerializer)
   *
   * What it does:
   * Initializes startup serializer helper lanes for `CIntelCounterHandle` and
   * installs process-exit cleanup.
   */
  void register_CIntelCounterHandleSerializer()
  {
    InitializeSerializerNode(gCIntelCounterHandleSerializer);
    gCIntelCounterHandleSerializer.mLoadCallback = &CIntelCounterHandleSerializer::Deserialize;
    gCIntelCounterHandleSerializer.mSaveCallback = &CIntelCounterHandleSerializer::Serialize;
    (void)std::atexit(&cleanup_CIntelCounterHandleSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct CIntelCounterHandleSerializerBootstrap
  {
    CIntelCounterHandleSerializerBootstrap()
    {
      moho::register_CIntelCounterHandleSerializer();
    }
  };

  [[maybe_unused]] CIntelCounterHandleSerializerBootstrap gCIntelCounterHandleSerializerBootstrap;
} // namespace


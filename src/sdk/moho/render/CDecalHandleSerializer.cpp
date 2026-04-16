#include "moho/render/CDecalHandleSerializer.h"

#include <cstdint>

#include "moho/render/CDecalHandle.h"

namespace
{
  moho::CDecalHandleSerializer gCDecalHandleSerializer;

  [[nodiscard]] gpg::SerHelperBase* CDecalHandleSerializerSelfNode(moho::CDecalHandleSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeCDecalHandleSerializerLinks(moho::CDecalHandleSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = CDecalHandleSerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalHandleSerializerHelperNode(
    moho::CDecalHandleSerializer& serializer
  ) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = CDecalHandleSerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  struct CDecalHandleSerializerBootstrap
  {
    CDecalHandleSerializerBootstrap()
    {
      InitializeCDecalHandleSerializerLinks(gCDecalHandleSerializer);
      gCDecalHandleSerializer.mLoadCallback = nullptr;
      gCDecalHandleSerializer.mSaveCallback = nullptr;
    }
  };

  CDecalHandleSerializerBootstrap gCDecalHandleSerializerBootstrap;

  void DeserializeCDecalHandleSerializerLane(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const decalHandle = reinterpret_cast<moho::CDecalHandle*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (decalHandle != nullptr) {
      decalHandle->MemberDeserialize(archive);
    }
  }

  void SerializeCDecalHandleSerializerLane(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const decalHandle = reinterpret_cast<moho::CDecalHandle*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (decalHandle != nullptr) {
      decalHandle->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00779FD0 (FUN_00779FD0)
   *
   * What it does:
   * Initializes `CDecalHandleSerializer` helper links and binds archive
   * load/save callbacks for decal-handle payload lanes.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* InitializeCDecalHandleSerializerPrimary() noexcept
  {
    InitializeCDecalHandleSerializerLinks(gCDecalHandleSerializer);
    gCDecalHandleSerializer.mLoadCallback = &DeserializeCDecalHandleSerializerLane;
    gCDecalHandleSerializer.mSaveCallback = &SerializeCDecalHandleSerializerLane;
    return CDecalHandleSerializerSelfNode(gCDecalHandleSerializer);
  }

  /**
   * Address: 0x0077AB90 (FUN_0077AB90)
   *
   * What it does:
   * Secondary serializer-init lane that rebinds the same callback pair and
   * returns the helper-node self pointer.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* InitializeCDecalHandleSerializerSecondary() noexcept
  {
    return InitializeCDecalHandleSerializerPrimary();
  }

  /**
   * Address: 0x0077A000 (FUN_0077A000)
   *
   * What it does:
   * Unlinks `CDecalHandleSerializer` helper node from the intrusive helper
   * list, rewires self-links, and returns the helper self node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalHandleSerializerHelperPrimary() noexcept
  {
    return UnlinkCDecalHandleSerializerHelperNode(gCDecalHandleSerializer);
  }

  /**
   * Address: 0x0077A030 (FUN_0077A030)
   *
   * What it does:
   * Secondary entrypoint for the same `CDecalHandleSerializer` helper-node
   * intrusive unlink and self-link reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalHandleSerializerHelperSecondary() noexcept
  {
    return UnlinkCDecalHandleSerializerHelperNode(gCDecalHandleSerializer);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0077ABC0 (FUN_0077ABC0, gpg::SerSaveLoadHelper_CDecalHandle::Init)
   */
  void CDecalHandleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CDecalHandle::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

#include "moho/effects/rendering/CEfxBeamSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/effects/rendering/CEfxBeamTypeInfo.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/particles/SWorldBeam.h"

namespace
{
  using BeamSerializer = moho::CEfxBeamSerializer;

  BeamSerializer gCEfxBeamSerializer{};
  bool gCEfxBeamSerializerRegistered = false;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  template <typename TType>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cached)
  {
    if (!cached) {
      cached = gpg::LookupRType(typeid(TType));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveCEfxBeamType()
  {
    return ResolveCachedType<moho::CEfxBeam>(moho::CEfxBeam::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSEntAttachInfoType()
  {
    return ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamType()
  {
    return ResolveCachedType<moho::SWorldBeam>(moho::SWorldBeam::sType);
  }

  [[nodiscard]] gpg::RRef MakeOwnerRefOrNull(gpg::RRef* const ownerRef)
  {
    return ownerRef ? *ownerRef : gpg::RRef{};
  }

  void cleanup_CEfxBeamSerializer_atexit()
  {
    (void)moho::cleanup_CEfxBeamSerializer();
  }

  struct CEfxBeamSerializerBootstrap
  {
    CEfxBeamSerializerBootstrap()
    {
      (void)moho::register_CEfxBeamSerializer();
    }
  };

  [[maybe_unused]] CEfxBeamSerializerBootstrap gCEfxBeamSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00655FC0 (FUN_00655FC0)
   *
   * What it does:
   * Unlinks the global CEfxBeam serializer helper node and restores
   * self-links on the serializer node.
   */
  gpg::SerHelperBase* UnlinkCEfxBeamSerializerNodeVariantA()
  {
    return UnlinkSerializerNode(gCEfxBeamSerializer);
  }

  /**
   * Address: 0x00655FF0 (FUN_00655FF0)
   *
   * What it does:
   * Runs the duplicate CEfxBeam serializer helper-node unlink/reset lane.
   */
  gpg::SerHelperBase* UnlinkCEfxBeamSerializerNodeVariantB()
  {
    return UnlinkSerializerNode(gCEfxBeamSerializer);
  }

  /**
   * Address: 0x00657B80 (FUN_00657B80, gpg::SerSaveLoadHelper_CEfxBeam::Init)
   */
  void CEfxBeamSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveCEfxBeamType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00655F60 (FUN_00655F60, Moho::CEfxBeamSerializer::Deserialize)
   */
  void CEfxBeamSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CEfxBeam*>(static_cast<std::uintptr_t>(objectPtr));
    GPG_ASSERT(object != nullptr);

    const gpg::RRef owner = MakeOwnerRefOrNull(ownerRef);
    archive->Read(CEffectImpl::StaticGetClass(), object, owner);
    archive->ReadInt(&object->mBlendMode);
    archive->ReadBool(&object->mVisible);
    archive->ReadUInt(&object->mLastUpdate);
    archive->Read(ResolveSEntAttachInfoType(), &object->mEnd, owner);
    archive->Read(ResolveSWorldBeamType(), &object->mBeam, owner);
    archive->ReadBool(&object->mIsNew);
  }

  /**
   * Address: 0x00655F70 (FUN_00655F70, Moho::CEfxBeamSerializer::Serialize)
   */
  void CEfxBeamSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CEfxBeam*>(static_cast<std::uintptr_t>(objectPtr));
    GPG_ASSERT(object != nullptr);

    const gpg::RRef owner = MakeOwnerRefOrNull(ownerRef);
    archive->Write(CEffectImpl::StaticGetClass(), object, owner);
    archive->WriteInt(object->mBlendMode);
    archive->WriteBool(object->mVisible);
    archive->WriteUInt(object->mLastUpdate);
    archive->Write(ResolveSEntAttachInfoType(), &object->mEnd, owner);
    archive->Write(ResolveSWorldBeamType(), &object->mBeam, owner);
    archive->WriteBool(object->mIsNew);
  }

  /**
   * Address: 0x00BFB910 (FUN_00BFB910, cleanup_CEfxBeamSerializer)
   *
   * What it does:
   * Unlinks startup CEfxBeam serializer helper node and restores self-links.
   */
  void cleanup_CEfxBeamSerializer()
  {
    (void)UnlinkSerializerNode(gCEfxBeamSerializer);
  }

  /**
   * Address: 0x00BD3F50 (FUN_00BD3F50, register_CEfxBeamSerializer)
   *
   * What it does:
   * Initializes startup CEfxBeam serializer helper callbacks and installs
   * process-exit cleanup.
   */
  void register_CEfxBeamSerializer()
  {
    if (gCEfxBeamSerializerRegistered) {
      return;
    }

    (void)moho::register_CEfxBeamTypeInfo_AtExit();
    InitializeSerializerNode(gCEfxBeamSerializer);
    gCEfxBeamSerializer.mLoadCallback = &CEfxBeamSerializer::Deserialize;
    gCEfxBeamSerializer.mSaveCallback = &CEfxBeamSerializer::Serialize;
    gCEfxBeamSerializerRegistered = true;
    (void)std::atexit(&cleanup_CEfxBeamSerializer);
  }
} // namespace moho

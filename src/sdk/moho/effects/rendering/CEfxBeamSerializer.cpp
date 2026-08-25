#include "moho/effects/rendering/CEfxBeamSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEfxBeam.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/particles/SWorldBeam.h"

namespace
{
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

  // Address: 0x010B3A44 -- process-global `CEfxBeamSerializer` singleton.
  // Constructing it runs CEfxBeamSerializer::CEfxBeamSerializer()
  // (0x00BD3F50), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEfxBeamSerializer gCEfxBeamSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD3F50 (FUN_00BD3F50, register_CEfxBeamSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CEfxBeamSerializer::CEfxBeamSerializer()
    : mLoadCallback(&CEfxBeamSerializer::Deserialize)
    , mSaveCallback(&CEfxBeamSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFB910 (FUN_00BFB910, Moho::CEfxBeamSerializer::~CEfxBeamSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  CEfxBeamSerializer::~CEfxBeamSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00657B80 (FUN_00657B80, gpg::SerSaveLoadHelper_CEfxBeam::Init)
   */
  void CEfxBeamSerializer::Init()
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
} // namespace moho

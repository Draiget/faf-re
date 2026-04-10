#include "moho/effects/rendering/CEfxBeam.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEffectImpl.h"

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

  [[nodiscard]] gpg::RType* ResolveCEffectImplType()
  {
    return ResolveCachedType<moho::CEffectImpl>(moho::CEffectImpl::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSEntAttachInfoType()
  {
    return ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamType()
  {
    return ResolveCachedType<moho::SWorldBeam>(moho::SWorldBeam::sType);
  }
} // namespace

namespace moho
{
  gpg::RType* CEfxBeam::sType = nullptr;

  /**
   * Address: 0x006546F0 (FUN_006546F0, Moho::CEfxBeam::CEfxBeam)
   */
  CEfxBeam::CEfxBeam()
    : CEffectImpl()
    , mBlendMode(0)
    , mVisible(false)
    , mPad195{0}
    , mLastUpdate(0)
    , mEnd(SEntAttachInfo::MakeDetached())
    , mBeam{}
    , mIsNew(true)
    , mPad295{0}
  {}

  /**
   * Address: 0x00655B80 (FUN_00655B80, Moho::CEfxBeam::dtr)
   */
  CEfxBeam::~CEfxBeam()
  {
    mEnd.TargetWeakLink().UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00658A10 (FUN_00658A10, Moho::CEfxBeam::MemberDeserialize)
   */
  void CEfxBeam::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveCEffectImplType(), static_cast<CEffectImpl*>(this), nullOwner);
    archive->ReadInt(&mBlendMode);
    archive->ReadBool(&mVisible);
    archive->ReadUInt(&mLastUpdate);
    archive->Read(ResolveSEntAttachInfoType(), &mEnd, nullOwner);
    archive->Read(ResolveSWorldBeamType(), &mBeam, nullOwner);
    archive->ReadBool(&mIsNew);
  }

  /**
   * Address: 0x00658B10 (FUN_00658B10, Moho::CEfxBeam::MemberSerialize)
   */
  void CEfxBeam::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveCEffectImplType(), static_cast<const CEffectImpl*>(this), nullOwner);
    archive->WriteInt(mBlendMode);
    archive->WriteBool(mVisible);
    archive->WriteUInt(mLastUpdate);
    archive->Write(ResolveSEntAttachInfoType(), &mEnd, nullOwner);
    archive->Write(ResolveSWorldBeamType(), &mBeam, nullOwner);
    archive->WriteBool(mIsNew);
  }

  /**
   * Address: 0x006585D0 (FUN_006585D0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CEfxBeam deserialize thunk alias into
   * `CEfxBeam::MemberDeserialize`.
   */
  void DeserializeCEfxBeamThunkVariantA(CEfxBeam* const object, gpg::ReadArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00658780 (FUN_00658780, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEfxBeam deserialize thunk alias into
   * `CEfxBeam::MemberDeserialize`.
   */
  void DeserializeCEfxBeamThunkVariantB(CEfxBeam* const object, gpg::ReadArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006585E0 (FUN_006585E0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CEfxBeam serialize thunk alias into
   * `CEfxBeam::MemberSerialize`.
   */
  void SerializeCEfxBeamThunkVariantA(const CEfxBeam* const object, gpg::WriteArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00658790 (FUN_00658790, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEfxBeam serialize thunk alias into
   * `CEfxBeam::MemberSerialize`.
   */
  void SerializeCEfxBeamThunkVariantB(const CEfxBeam* const object, gpg::WriteArchive* const archive)
  {
    if (!object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * What it does:
   * Returns the cached reflection descriptor for `CEfxBeam`.
   */
  gpg::RType* CEfxBeam::StaticGetClass()
  {
    return ResolveCachedType<CEfxBeam>(sType);
  }
} // namespace moho

#include "moho/particles/SWorldBeam.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

namespace
{
  template <typename TType>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cached)
  {
    if (!cached) {
      cached = gpg::LookupRType(typeid(TType));
    }

    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveVTransformType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<moho::VTransform>(cached);
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<Wm3::Vector3<float>>(cached);
  }

  [[nodiscard]] gpg::RType* ResolveVector4fType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<moho::Vector4f>(cached);
  }

  [[nodiscard]] gpg::RType* ResolveParticleTextureCountedPtrType()
  {
    return ResolveCachedType<moho::CountedPtr_CParticleTexture>(moho::CountedPtr_CParticleTexture::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamBlendModeType()
  {
    return ResolveCachedType<moho::SWorldBeam::BlendMode>(moho::SWorldBeam::sBlendModeType);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00490000 (FUN_00490000, Moho::SWorldBeam::MemberDeserialize)
   */
  void SWorldBeam::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveVTransformType(), &mCurStart, nullOwner);
    archive->Read(ResolveVTransformType(), &mLastStart, nullOwner);
    archive->ReadBool(&mFromStart);
    archive->Read(ResolveVTransformType(), &mCurEnd, nullOwner);
    archive->Read(ResolveVTransformType(), &mLastEnd, nullOwner);
    archive->ReadFloat(&mLastInterpolation);
    archive->Read(ResolveVector3fType(), &mStart, nullOwner);
    archive->Read(ResolveVector3fType(), &mEnd, nullOwner);
    archive->ReadFloat(&mWidth);
    archive->Read(ResolveVector4fType(), &mStartColor, nullOwner);
    archive->Read(ResolveVector4fType(), &mEndColor, nullOwner);
    archive->Read(ResolveParticleTextureCountedPtrType(), &mTexture1, nullOwner);
    archive->Read(ResolveParticleTextureCountedPtrType(), &mTexture2, nullOwner);
    archive->ReadFloat(&mUShift);
    archive->ReadFloat(&mVShift);
    archive->Read(ResolveSWorldBeamBlendModeType(), &mBlendMode, nullOwner);
  }

  /**
   * Address: 0x004902B0 (FUN_004902B0, Moho::SWorldBeam::MemberSerialize)
   */
  void SWorldBeam::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveVTransformType(), &mCurStart, nullOwner);
    archive->Write(ResolveVTransformType(), &mLastStart, nullOwner);
    archive->WriteBool(mFromStart);
    archive->Write(ResolveVTransformType(), &mCurEnd, nullOwner);
    archive->Write(ResolveVTransformType(), &mLastEnd, nullOwner);
    archive->WriteFloat(mLastInterpolation);
    archive->Write(ResolveVector3fType(), &mStart, nullOwner);
    archive->Write(ResolveVector3fType(), &mEnd, nullOwner);
    archive->WriteFloat(mWidth);
    archive->Write(ResolveVector4fType(), &mStartColor, nullOwner);
    archive->Write(ResolveVector4fType(), &mEndColor, nullOwner);
    archive->Write(ResolveParticleTextureCountedPtrType(), &mTexture1, nullOwner);
    archive->Write(ResolveParticleTextureCountedPtrType(), &mTexture2, nullOwner);
    archive->WriteFloat(mUShift);
    archive->WriteFloat(mVShift);
    archive->Write(ResolveSWorldBeamBlendModeType(), &mBlendMode, nullOwner);
  }
} // namespace moho

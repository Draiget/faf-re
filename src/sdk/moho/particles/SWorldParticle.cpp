#include "moho/particles/SWorldParticle.h"

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

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<Wm3::Vector3<float>>(cached);
  }

  [[nodiscard]] gpg::RType* ResolveParticleTextureCountedPtrType()
  {
    return ResolveCachedType<moho::CountedPtr_CParticleTexture>(moho::CountedPtr_CParticleTexture::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldParticleBlendModeType()
  {
    return ResolveCachedType<moho::SWorldParticle::BlendMode>(moho::SWorldParticle::sBlendModeType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldParticleZModeType()
  {
    return ResolveCachedType<moho::SWorldParticle::ZMode>(moho::SWorldParticle::sZModeType);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0065B7F0 (FUN_0065B7F0, ??0SParticle@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one world-particle payload with default resistance, size,
   * blend/z modes, texture lanes, and army-index sentinel.
   */
  SWorldParticle::SWorldParticle()
    : mEnabled(false)
    , mPadding01{}
    , mResistance(0.07f)
    , mPos{0.0f, 0.0f, 0.0f}
    , mDir{0.0f, 0.0f, 0.0f}
    , mAccel{0.0f, 0.0f, 0.0f}
    , mInterop(0.0f)
    , mLifetime(0.0f)
    , mFramerate(0.0f)
    , mValue1(0.0f)
    , mTextureSelection(0.0f)
    , mValue3(0.0f)
    , mRampSelection(0.0f)
    , mBeginSize(1.0f)
    , mEndSize(1.0f)
    , mAngle(0.0f)
    , mRotationCurve(0.0f)
    , mReserved54(0.0f)
    , mTexture{}
    , mRampTexture{}
    , mTypeTag()
    , mArmyIndex(-1)
    , mBlendMode(BlendMode::Mode3)
    , mZMode(ZMode::Mode0)
  {}

  /**
   * Address: 0x00490570 (FUN_00490570, Moho::SWorldParticle::MemberDeserialize)
   */
  void SWorldParticle::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->ReadBool(&mEnabled);
    archive->ReadFloat(&mResistance);
    archive->Read(ResolveVector3fType(), &mPos, nullOwner);
    archive->Read(ResolveVector3fType(), &mDir, nullOwner);
    archive->Read(ResolveVector3fType(), &mAccel, nullOwner);
    archive->ReadFloat(&mInterop);
    archive->ReadFloat(&mLifetime);
    archive->ReadFloat(&mFramerate);
    archive->ReadFloat(&mValue1);
    archive->ReadFloat(&mTextureSelection);
    archive->ReadFloat(&mValue3);
    archive->ReadFloat(&mRampSelection);
    archive->ReadFloat(&mBeginSize);
    archive->ReadFloat(&mEndSize);
    archive->ReadFloat(&mAngle);
    archive->ReadFloat(&mRotationCurve);
    archive->ReadFloat(&mReserved54);
    archive->Read(ResolveParticleTextureCountedPtrType(), &mTexture, nullOwner);
    archive->Read(ResolveParticleTextureCountedPtrType(), &mRampTexture, nullOwner);
    archive->ReadString(&mTypeTag);
    archive->ReadInt(&mArmyIndex);
    archive->Read(ResolveSWorldParticleBlendModeType(), &mBlendMode, nullOwner);
    archive->Read(ResolveSWorldParticleZModeType(), &mZMode, nullOwner);
  }

  /**
   * Address: 0x004907D0 (FUN_004907D0, Moho::SWorldParticle::MemberSerialize)
   */
  void SWorldParticle::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->WriteBool(mEnabled);
    archive->WriteFloat(mResistance);
    archive->Write(ResolveVector3fType(), &mPos, nullOwner);
    archive->Write(ResolveVector3fType(), &mDir, nullOwner);
    archive->Write(ResolveVector3fType(), &mAccel, nullOwner);
    archive->WriteFloat(mInterop);
    archive->WriteFloat(mLifetime);
    archive->WriteFloat(mFramerate);
    archive->WriteFloat(mValue1);
    archive->WriteFloat(mTextureSelection);
    archive->WriteFloat(mValue3);
    archive->WriteFloat(mRampSelection);
    archive->WriteFloat(mBeginSize);
    archive->WriteFloat(mEndSize);
    archive->WriteFloat(mAngle);
    archive->WriteFloat(mRotationCurve);
    archive->WriteFloat(mReserved54);
    archive->Write(ResolveParticleTextureCountedPtrType(), &mTexture, nullOwner);
    archive->Write(ResolveParticleTextureCountedPtrType(), &mRampTexture, nullOwner);
    archive->WriteString(const_cast<msvc8::string*>(&mTypeTag));
    archive->WriteInt(mArmyIndex);
    archive->Write(ResolveSWorldParticleBlendModeType(), &mBlendMode, nullOwner);
    archive->Write(ResolveSWorldParticleZModeType(), &mZMode, nullOwner);
  }
} // namespace moho

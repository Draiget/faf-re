#include "moho/particles/SWorldBeam.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{

  [[nodiscard]] gpg::RType* ResolveSWorldBeamBlendModeType()
  {
    return gpg::CachedLookup<moho::SWorldBeam::BlendMode>(moho::SWorldBeam::sBlendModeType);
  }

  void InitializeIdentityBeamTransform(moho::VTransform& transform) noexcept
  {
    transform.orient_.w = 1.0f;
    transform.orient_.x = 0.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00655CC0 (FUN_00655CC0, Moho::SWorldBeam::SWorldBeam)
   */
  SWorldBeam::SWorldBeam()
  {
    InitializeIdentityBeamTransform(mCurStart);
    InitializeIdentityBeamTransform(mLastStart);
    InitializeIdentityBeamTransform(mCurEnd);
    InitializeIdentityBeamTransform(mLastEnd);

    mTexture1 = CountedPtr_CParticleTexture{};
    mTexture2 = CountedPtr_CParticleTexture{};
  }

  /**
   * Address: 0x00490000 (FUN_00490000, Moho::SWorldBeam::MemberDeserialize)
   */
  void SWorldBeam::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(gpg::RTypeOf<moho::VTransform>(), &mCurStart, nullOwner);
    archive->Read(gpg::RTypeOf<moho::VTransform>(), &mLastStart, nullOwner);
    archive->ReadBool(&mFromStart);
    archive->Read(gpg::RTypeOf<moho::VTransform>(), &mCurEnd, nullOwner);
    archive->Read(gpg::RTypeOf<moho::VTransform>(), &mLastEnd, nullOwner);
    archive->ReadFloat(&mLastInterpolation);
    archive->Read(gpg::RTypeOf<Wm3::Vector3<float>>(), &mStart, nullOwner);
    archive->Read(gpg::RTypeOf<Wm3::Vector3<float>>(), &mEnd, nullOwner);
    archive->ReadFloat(&mWidth);
    archive->Read(gpg::RTypeOf<moho::Vector4f>(), &mStartColor, nullOwner);
    archive->Read(gpg::RTypeOf<moho::Vector4f>(), &mEndColor, nullOwner);
    archive->Read(gpg::RTypeOf<moho::CountedPtr_CParticleTexture>(), &mTexture1, nullOwner);
    archive->Read(gpg::RTypeOf<moho::CountedPtr_CParticleTexture>(), &mTexture2, nullOwner);
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
    archive->Write(gpg::RTypeOf<moho::VTransform>(), &mCurStart, nullOwner);
    archive->Write(gpg::RTypeOf<moho::VTransform>(), &mLastStart, nullOwner);
    archive->WriteBool(mFromStart);
    archive->Write(gpg::RTypeOf<moho::VTransform>(), &mCurEnd, nullOwner);
    archive->Write(gpg::RTypeOf<moho::VTransform>(), &mLastEnd, nullOwner);
    archive->WriteFloat(mLastInterpolation);
    archive->Write(gpg::RTypeOf<Wm3::Vector3<float>>(), &mStart, nullOwner);
    archive->Write(gpg::RTypeOf<Wm3::Vector3<float>>(), &mEnd, nullOwner);
    archive->WriteFloat(mWidth);
    archive->Write(gpg::RTypeOf<moho::Vector4f>(), &mStartColor, nullOwner);
    archive->Write(gpg::RTypeOf<moho::Vector4f>(), &mEndColor, nullOwner);
    archive->Write(gpg::RTypeOf<moho::CountedPtr_CParticleTexture>(), &mTexture1, nullOwner);
    archive->Write(gpg::RTypeOf<moho::CountedPtr_CParticleTexture>(), &mTexture2, nullOwner);
    archive->WriteFloat(mUShift);
    archive->WriteFloat(mVShift);
    archive->Write(ResolveSWorldBeamBlendModeType(), &mBlendMode, nullOwner);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SWorldBeam>`, vtable 0x00E062F0.
   *
   * Address: 0x00BC5360 (FUN_00BC5360 -- constructs the global and registers its destructor.)
   * Address: 0x00BEFED0 (FUN_00BEFED0 -- the global's destructor.)
   * Address: 0x0048FB50 (FUN_0048FB50 -- `Init`.)
   * Address: 0x0048F480 (FUN_0048F480 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0048F490 (FUN_0048F490 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SWorldBeamSerializer : gpg::SerSaveLoadHelper<SWorldBeam>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A8010 -- process-global `SWorldBeamSerializer` singleton.
  moho::SWorldBeamSerializer gSWorldBeamSerializer;
} // namespace


#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/math/VMatrix4.h"
#include "moho/misc/CountedObject.h"
#include "moho/resource/CParticleTexture.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  gpg::RType* gFastVectorCountedParticleTextureType = nullptr;

  [[nodiscard]] gpg::RType* ResolveFastVectorCountedParticleTextureType()
  {
    return gpg::CachedLookup<gpg::fastvector<moho::CountedPtr<moho::CParticleTexture>>>(
      gFastVectorCountedParticleTextureType
    );
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x0065AFA0 (FUN_0065AFA0, CEffectImplSerializer::DeserializeCore)
   *
   * What it does:
   * Reads `CEffectImpl` base lane and member payload lanes into the object.
   */
  void CEffectImpl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    archive->Read(moho::IEffect::StaticGetClass(), this, gpg::RRef{});
    archive->Read(gpg::RTypeOf<gpg::fastvector<float>>(), &mParams, gpg::RRef{});
    archive->Read(ResolveFastVectorCountedParticleTextureType(), &mParticleTextures, gpg::RRef{});
    archive->Read(gpg::RTypeOf<gpg::fastvector<fa::string>>(), &mStrings, gpg::RRef{});
    archive->Read(
      gpg::CachedLookup<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType), &mEntityInfo, gpg::RRef{}
    );
    bool newAttachment = (mNewAttachment != 0);
    archive->ReadBool(&newAttachment);
    mNewAttachment = newAttachment ? 1u : 0u;
    archive->Read(gpg::CachedLookup<moho::VMatrix4>(moho::VMatrix4::sType), &mMatrix, gpg::RRef{});
  }

  /**
   * Address: 0x0065B110 (FUN_0065B110, CEffectImplSerializer::SerializeCore)
   *
   * What it does:
   * Writes `CEffectImpl` base lane and member payload lanes from the object.
   */
  void CEffectImpl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    archive->Write(moho::IEffect::StaticGetClass(), this, gpg::RRef{});
    archive->Write(gpg::RTypeOf<gpg::fastvector<float>>(), &mParams, gpg::RRef{});
    archive->Write(ResolveFastVectorCountedParticleTextureType(), &mParticleTextures, gpg::RRef{});
    archive->Write(gpg::RTypeOf<gpg::fastvector<fa::string>>(), &mStrings, gpg::RRef{});
    archive->Write(
      gpg::CachedLookup<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType), &mEntityInfo, gpg::RRef{}
    );
    archive->WriteBool(mNewAttachment != 0);
    archive->Write(gpg::CachedLookup<moho::VMatrix4>(moho::VMatrix4::sType), &mMatrix, gpg::RRef{});
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CEffectImpl>`, vtable 0x00E23E3C.
   *
   * Address: 0x00BD40E0 (FUN_00BD40E0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFBA20 (FUN_00BFBA20 -- the global's destructor.)
   * Address: 0x0065A2C0 (FUN_0065A2C0 -- `Init`.)
   * Address: 0x006598A0 (FUN_006598A0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006598B0 (FUN_006598B0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CEffectImplSerializer : gpg::SerSaveLoadHelper<CEffectImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B3ADC -- process-global `CEffectImplSerializer` singleton.
  moho::CEffectImplSerializer gCEffectImplSerializer;
} // namespace

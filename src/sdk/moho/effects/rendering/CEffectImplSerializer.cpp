#include "moho/effects/rendering/CEffectImplSerializer.h"

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

namespace
{
  gpg::RType* gFastVectorFloatType = nullptr;
  gpg::RType* gFastVectorCountedParticleTextureType = nullptr;
  gpg::RType* gFastVectorStringType = nullptr;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveFastVectorFloatType()
  {
    return ResolveCachedType<gpg::fastvector<float>>(gFastVectorFloatType);
  }

  [[nodiscard]] gpg::RType* ResolveFastVectorCountedParticleTextureType()
  {
    return ResolveCachedType<gpg::fastvector<moho::CountedPtr<moho::CParticleTexture>>>(
      gFastVectorCountedParticleTextureType
    );
  }

  [[nodiscard]] gpg::RType* ResolveFastVectorStringType()
  {
    return ResolveCachedType<gpg::fastvector<msvc8::string>>(gFastVectorStringType);
  }

  /**
   * Address: 0x0065AFA0 (FUN_0065AFA0, CEffectImplSerializer::DeserializeCore)
   *
   * What it does:
   * Reads `CEffectImpl` base lane and member payload lanes into the object.
   */
  void DeserializeCEffectImplCore(moho::CEffectImpl* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    archive->Read(moho::IEffect::StaticGetClass(), object, gpg::RRef{});
    archive->Read(ResolveFastVectorFloatType(), &object->mParams, gpg::RRef{});
    archive->Read(ResolveFastVectorCountedParticleTextureType(), &object->mParticleTextures, gpg::RRef{});
    archive->Read(ResolveFastVectorStringType(), &object->mStrings, gpg::RRef{});
    archive->Read(
      ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType), &object->mEntityInfo, gpg::RRef{}
    );
    bool newAttachment = (object->mNewAttachment != 0);
    archive->ReadBool(&newAttachment);
    object->mNewAttachment = newAttachment ? 1u : 0u;
    archive->Read(ResolveCachedType<moho::VMatrix4>(moho::VMatrix4::sType), &object->mMatrix, gpg::RRef{});
  }

  /**
   * Address: 0x0065B110 (FUN_0065B110, CEffectImplSerializer::SerializeCore)
   *
   * What it does:
   * Writes `CEffectImpl` base lane and member payload lanes from the object.
   */
  void SerializeCEffectImplCore(const moho::CEffectImpl* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    archive->Write(moho::IEffect::StaticGetClass(), object, gpg::RRef{});
    archive->Write(ResolveFastVectorFloatType(), &object->mParams, gpg::RRef{});
    archive->Write(ResolveFastVectorCountedParticleTextureType(), &object->mParticleTextures, gpg::RRef{});
    archive->Write(ResolveFastVectorStringType(), &object->mStrings, gpg::RRef{});
    archive->Write(
      ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType), &object->mEntityInfo, gpg::RRef{}
    );
    archive->WriteBool(object->mNewAttachment != 0);
    archive->Write(ResolveCachedType<moho::VMatrix4>(moho::VMatrix4::sType), &object->mMatrix, gpg::RRef{});
  }

  // Address: 0x010B3ADC -- process-global `CEffectImplSerializer` singleton.
  // Constructing it runs CEffectImplSerializer::CEffectImplSerializer()
  // (0x00BD40E0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::CEffectImplSerializer gCEffectImplSerializer;

  /**
   * Address: 0x00BFBA20 (FUN_00BFBA20, cleanup_CEffectImplSerializer)
   *
   * What it does:
   * Process-exit cleanup that unlinks the `CEffectImplSerializer` helper
   * node. The real ctor pushes this plain free function (not a mangled
   * destructor) as its atexit target.
   */
  void cleanup_CEffectImplSerializer()
  {
    gCEffectImplSerializer.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD40E0 (FUN_00BD40E0, register_CEffectImplSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields, then registers
   * `cleanup_CEffectImplSerializer` as the explicit atexit teardown.
   */
  CEffectImplSerializer::CEffectImplSerializer()
    : mLoadCallback(&CEffectImplSerializer::Deserialize)
    , mSaveCallback(&CEffectImplSerializer::Serialize)
  {
    (void)std::atexit(&cleanup_CEffectImplSerializer);
  }

  /**
   * Address: 0x006598A0 (FUN_006598A0, Moho::CEffectImplSerializer::Deserialize)
   */
  void CEffectImplSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CEffectImpl*>(static_cast<std::uintptr_t>(objectPtr));
    DeserializeCEffectImplCore(object, archive);
  }

  /**
   * Address: 0x006598B0 (FUN_006598B0, Moho::CEffectImplSerializer::Serialize)
   */
  void CEffectImplSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CEffectImpl*>(static_cast<std::uintptr_t>(objectPtr));
    SerializeCEffectImplCore(object, archive);
  }

  /**
   * Address: 0x0065A2C0 (FUN_0065A2C0, gpg::SerSaveLoadHelper_CEffectImpl::Init)
   */
  void CEffectImplSerializer::Init()
  {
    gpg::RType* const type = CEffectImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

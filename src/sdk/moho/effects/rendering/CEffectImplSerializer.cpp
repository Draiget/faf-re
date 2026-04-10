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
  moho::CEffectImplSerializer gCEffectImplSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

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
   * Address: 0x0065A7B0 (FUN_0065A7B0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CEffectImpl deserialize thunk alias into the shared
   * deserialize core body.
   */
  void DeserializeCEffectImplCoreThunkVariantA(
    moho::CEffectImpl* const object, gpg::ReadArchive* const archive, const gpg::RRef&
  )
  {
    DeserializeCEffectImplCore(object, archive);
  }

  /**
   * Address: 0x0065ADA0 (FUN_0065ADA0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEffectImpl deserialize thunk alias into the shared
   * deserialize core body.
   */
  void DeserializeCEffectImplCoreThunkVariantB(
    moho::CEffectImpl* const object, gpg::ReadArchive* const archive, const gpg::RRef&
  )
  {
    DeserializeCEffectImplCore(object, archive);
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

  /**
   * Address: 0x0065A7C0 (FUN_0065A7C0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CEffectImpl serialize thunk alias into the shared
   * serialize core body.
   */
  void SerializeCEffectImplCoreThunkVariantA(
    const moho::CEffectImpl* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeCEffectImplCore(object, archive);
  }

  /**
   * Address: 0x0065ADB0 (FUN_0065ADB0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CEffectImpl serialize thunk alias into the shared
   * serialize core body.
   */
  void SerializeCEffectImplCoreThunkVariantB(
    const moho::CEffectImpl* const object, gpg::WriteArchive* const archive
  )
  {
    SerializeCEffectImplCore(object, archive);
  }

  void cleanup_CEffectImplSerializer_atexit()
  {
    (void)moho::cleanup_CEffectImplSerializer();
  }
} // namespace

namespace moho
{
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
  void CEffectImplSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CEffectImpl::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BFBA20 (FUN_00BFBA20, cleanup_CEffectImplSerializer)
   *
   * What it does:
   * Unlinks startup CEffectImpl serializer helper node and restores self-links.
   */
  gpg::SerHelperBase* cleanup_CEffectImplSerializer()
  {
    return UnlinkHelperNode(gCEffectImplSerializer);
  }

  /**
   * Address: 0x00BD40E0 (FUN_00BD40E0, register_CEffectImplSerializer)
   *
   * What it does:
   * Initializes startup CEffectImpl serializer helper callbacks and installs
   * process-exit cleanup.
   */
  int register_CEffectImplSerializer()
  {
    InitializeHelperNode(gCEffectImplSerializer);
    gCEffectImplSerializer.mLoadCallback = &CEffectImplSerializer::Deserialize;
    gCEffectImplSerializer.mSaveCallback = &CEffectImplSerializer::Serialize;
    gCEffectImplSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_CEffectImplSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct CEffectImplSerializerBootstrap
  {
    CEffectImplSerializerBootstrap()
    {
      (void)moho::register_CEffectImplSerializer();
    }
  };

  [[maybe_unused]] CEffectImplSerializerBootstrap gCEffectImplSerializerBootstrap;
} // namespace

#include "moho/audio/ISoundManagerSerializer.h"

#include "moho/audio/AudioReflectionHelpers.h"

namespace
{
  moho::ISoundManagerSerializer gISoundManagerSerializer{};

  [[nodiscard]] gpg::SerHelperBase* ISoundManagerSerializerSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gISoundManagerSerializer.mHelperNext);
  }

  void InitializeISoundManagerSerializerNode() noexcept
  {
    gpg::SerHelperBase* const self = ISoundManagerSerializerSelfNode();
    gISoundManagerSerializer.mHelperNext = self;
    gISoundManagerSerializer.mHelperPrev = self;
  }

  /**
   * Address: 0x00760BF0 (FUN_00760BF0)
   *
   * What it does:
   * Initializes startup `ISoundManagerSerializer` helper links and callback lanes.
   */
  [[maybe_unused]] [[nodiscard]] moho::ISoundManagerSerializer* InitializeISoundManagerSerializerHelperStorage() noexcept
  {
    InitializeISoundManagerSerializerNode();
    gISoundManagerSerializer.mLoadCallback = &moho::ISoundManagerSerializer::Deserialize;
    gISoundManagerSerializer.mSaveCallback = &moho::ISoundManagerSerializer::Serialize;
    return &gISoundManagerSerializer;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkISoundManagerSerializerNode() noexcept
  {
    if (gISoundManagerSerializer.mHelperNext != nullptr && gISoundManagerSerializer.mHelperPrev != nullptr) {
      gISoundManagerSerializer.mHelperNext->mPrev = gISoundManagerSerializer.mHelperPrev;
      gISoundManagerSerializer.mHelperPrev->mNext = gISoundManagerSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = ISoundManagerSerializerSelfNode();
    gISoundManagerSerializer.mHelperPrev = self;
    gISoundManagerSerializer.mHelperNext = self;
    return self;
  }

  struct ISoundManagerSerializerNodeBootstrap
  {
    ISoundManagerSerializerNodeBootstrap()
    {
      (void)InitializeISoundManagerSerializerHelperStorage();
    }
  };

  ISoundManagerSerializerNodeBootstrap gISoundManagerSerializerNodeBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00760BD0 (FUN_00760BD0, Moho::ISoundManagerSerializer::Deserialize)
   */
  void ISoundManagerSerializer::Deserialize(gpg::ReadArchive*, int, int, gpg::RRef*)
  {
  }

  /**
   * Address: 0x00760BE0 (FUN_00760BE0, Moho::ISoundManagerSerializer::Serialize)
   */
  void ISoundManagerSerializer::Serialize(gpg::WriteArchive*, int, int, gpg::RRef*)
  {
  }

  /**
   * Address: 0x00761BE0 (FUN_00761BE0, gpg::SerSaveLoadHelper_ISoundManager::Init)
   *
   * What it does:
   * Resolves `ISoundManager` RTTI and installs load/save callbacks.
   */
  void ISoundManagerSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveISoundManagerType();
    audio_reflection::RegisterSerializeCallbacks(typeInfo, mLoadCallback, mSaveCallback);
  }

  /**
   * Address: 0x00760C20 (FUN_00760C20)
   *
   * What it does:
   * Duplicated teardown lane for `ISoundManagerSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_ISoundManagerSerializer_variant_primary()
  {
    return UnlinkISoundManagerSerializerNode();
  }

  /**
   * Address: 0x00760C50 (FUN_00760C50)
   *
   * What it does:
   * Secondary duplicated teardown lane for `ISoundManagerSerializer` helper
   * links.
   */
  gpg::SerHelperBase* cleanup_ISoundManagerSerializer_variant_secondary()
  {
    return UnlinkISoundManagerSerializerNode();
  }
} // namespace moho

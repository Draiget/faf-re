#include "moho/serialization/serializers/SWorldParticleSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldParticle.h"

#pragma init_seg(lib)

namespace
{
  using ParticleSerializer = moho::SWorldParticleSerializer;
  using ParticleBlendModePrimitiveSerializer = moho::SWorldParticleBlendModePrimitiveSerializer;
  using ParticleZModePrimitiveSerializer = moho::SWorldParticleZModePrimitiveSerializer;

  ParticleBlendModePrimitiveSerializer gSWorldParticleBlendModePrimitiveSerializer{};
  ParticleZModePrimitiveSerializer gSWorldParticleZModePrimitiveSerializer{};
  ParticleSerializer gSWorldParticleSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveSWorldParticleType()
  {
    return ResolveCachedType<moho::SWorldParticle>(moho::SWorldParticle::sType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldParticleBlendModeType()
  {
    return ResolveCachedType<moho::SWorldParticle::BlendMode>(moho::SWorldParticle::sBlendModeType);
  }

  [[nodiscard]] gpg::RType* ResolveSWorldParticleZModeType()
  {
    return ResolveCachedType<moho::SWorldParticle::ZMode>(moho::SWorldParticle::sZModeType);
  }

  /**
   * Address: 0x0048FE10 (SWorldParticle::BlendMode int read lane)
   *
   * What it does:
   * Reads one `int` from archive and stores it into `SWorldParticle::BlendMode`.
   */
  void DeserializeSWorldParticleBlendMode(
    gpg::ReadArchive* archive,
    moho::SWorldParticle::BlendMode* value
  )
  {
    int rawValue = 0;
    archive->ReadInt(&rawValue);
    *value = static_cast<moho::SWorldParticle::BlendMode>(rawValue);
  }

  /**
   * Address: 0x0048FE30 (SWorldParticle::BlendMode int write lane)
   *
   * What it does:
   * Writes one `SWorldParticle::BlendMode` value to archive as an `int`.
   */
  void SerializeSWorldParticleBlendMode(
    gpg::WriteArchive* archive,
    const moho::SWorldParticle::BlendMode* value
  )
  {
    archive->WriteInt(static_cast<int>(*value));
  }

  /**
   * Address: 0x0048FE80 (SWorldParticle::ZMode int read lane)
   *
   * What it does:
   * Reads one `int` from archive and stores it into `SWorldParticle::ZMode`.
   */
  void DeserializeSWorldParticleZMode(gpg::ReadArchive* archive, moho::SWorldParticle::ZMode* value)
  {
    int rawValue = 0;
    archive->ReadInt(&rawValue);
    *value = static_cast<moho::SWorldParticle::ZMode>(rawValue);
  }

  /**
   * Address: 0x0048FEA0 (SWorldParticle::ZMode int write lane)
   *
   * What it does:
   * Writes one `SWorldParticle::ZMode` value to archive as an `int`.
   */
  void SerializeSWorldParticleZMode(gpg::WriteArchive* archive, const moho::SWorldParticle::ZMode* value)
  {
    archive->WriteInt(static_cast<int>(*value));
  }

  void cleanup_SWorldParticleBlendModePrimitiveSerializer_atexit()
  {
    (void)moho::cleanup_SWorldParticleBlendModePrimitiveSerializer();
  }

  void cleanup_SWorldParticleZModePrimitiveSerializer_atexit()
  {
    (void)moho::cleanup_SWorldParticleZModePrimitiveSerializer();
  }

  void cleanup_SWorldParticleSerializer_atexit()
  {
    (void)moho::cleanup_SWorldParticleSerializer();
  }

  /**
   * Address: 0x0048F920 (FUN_0048F920)
   *
   * What it does:
   * Unlinks `SWorldParticleSerializer` from the intrusive helper list and
   * rewires it to a self-linked sentinel.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSWorldParticleSerializerNodeA()
  {
    return UnlinkSerializerNode(gSWorldParticleSerializer);
  }

  /**
   * Address: 0x0048F950 (FUN_0048F950)
   *
   * What it does:
   * Duplicate unlink lane for `SWorldParticleSerializer` with identical
   * self-link reset behavior.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSWorldParticleSerializerNodeB()
  {
    return UnlinkSerializerNode(gSWorldParticleSerializer);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0048F8D0 (Moho::SWorldParticleSerializer::Deserialize)
   */
  void SWorldParticleSerializer::Deserialize(
    gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<SWorldParticle*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0048F8E0 (Moho::SWorldParticleSerializer::Serialize)
   */
  void SWorldParticleSerializer::Serialize(
    gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
  )
  {
    const auto* const object = reinterpret_cast<const SWorldParticle*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x0048FD30 (Moho::SWorldParticleSerializer::Init)
   */
  void SWorldParticleSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSWorldParticleType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x0048FBF0 (gpg::PrimitiveSerHelper<Moho::SWorldParticle::BlendMode, int>::Init)
   */
  void SWorldParticleBlendModePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSWorldParticleBlendModeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BEFF10 (sub_BEFF10)
   */
  gpg::SerHelperBase* cleanup_SWorldParticleBlendModePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gSWorldParticleBlendModePrimitiveSerializer);
  }

  /**
   * Address: 0x00BC53C0 (sub_BC53C0)
   */
  int register_SWorldParticleBlendModePrimitiveSerializer()
  {
    InitializeSerializerNode(gSWorldParticleBlendModePrimitiveSerializer);
    gSWorldParticleBlendModePrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeSWorldParticleBlendMode);
    gSWorldParticleBlendModePrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeSWorldParticleBlendMode);
    return std::atexit(&cleanup_SWorldParticleBlendModePrimitiveSerializer_atexit);
  }

  /**
   * Address: 0x0048FC90 (gpg::PrimitiveSerHelper<Moho::SWorldParticle::ZMode, int>::Init)
   */
  void SWorldParticleZModePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSWorldParticleZModeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BEFF50 (sub_BEFF50)
   */
  gpg::SerHelperBase* cleanup_SWorldParticleZModePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gSWorldParticleZModePrimitiveSerializer);
  }

  /**
   * Address: 0x00BC5420 (sub_BC5420)
   */
  int register_SWorldParticleZModePrimitiveSerializer()
  {
    InitializeSerializerNode(gSWorldParticleZModePrimitiveSerializer);
    gSWorldParticleZModePrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeSWorldParticleZMode);
    gSWorldParticleZModePrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeSWorldParticleZMode);
    return std::atexit(&cleanup_SWorldParticleZModePrimitiveSerializer_atexit);
  }

  /**
   * Address: 0x00BEFFE0 (Moho::SWorldParticleSerializer::~SWorldParticleSerializer)
   */
  gpg::SerHelperBase* cleanup_SWorldParticleSerializer()
  {
    return UnlinkSWorldParticleSerializerNodeA();
  }

  /**
   * Address: 0x00BC5480 (register_SWorldParticleSerializer)
   */
  int register_SWorldParticleSerializer()
  {
    InitializeSerializerNode(gSWorldParticleSerializer);
    gSWorldParticleSerializer.mDeserialize = &SWorldParticleSerializer::Deserialize;
    gSWorldParticleSerializer.mSerialize = &SWorldParticleSerializer::Serialize;
    return std::atexit(&cleanup_SWorldParticleSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SWorldParticleSerializerBootstrap
  {
    SWorldParticleSerializerBootstrap()
    {
      (void)moho::register_SWorldParticleBlendModePrimitiveSerializer();
      (void)moho::register_SWorldParticleZModePrimitiveSerializer();
      (void)moho::register_SWorldParticleSerializer();
    }
  };

  [[maybe_unused]] SWorldParticleSerializerBootstrap gSWorldParticleSerializerBootstrap;
} // namespace

#include "moho/serialization/serializers/SWorldParticleSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldParticle.h"

namespace
{
  using ParticleSerializer = moho::SWorldParticleSerializer;

  ParticleSerializer gSWorldParticleSerializer{};

  /**
   * Address: 0x00BC53C0 (FUN_00BC53C0, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldParticle::BlendMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_SWorldParticleBlendModePrimitiveSerializer()` call from a
   * bootstrap struct to run its equivalent logic; the real binary never
   * does that -- the global's own dynamic initializer is the entire
   * registration.
   */
  moho::SWorldParticleBlendModePrimitiveSerializer gSWorldParticleBlendModePrimitiveSerializer;

  /**
   * Address: 0x00BC5420 (FUN_00BC5420, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldParticle::ZMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). Same "never actually registered
   * before this recovery" story as `SWorldParticle::BlendMode` above.
   */
  moho::SWorldParticleZModePrimitiveSerializer gSWorldParticleZModePrimitiveSerializer;

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
      (void)moho::register_SWorldParticleSerializer();
    }
  };

  [[maybe_unused]] SWorldParticleSerializerBootstrap gSWorldParticleSerializerBootstrap;
} // namespace

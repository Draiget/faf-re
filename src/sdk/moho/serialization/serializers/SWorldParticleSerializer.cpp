#include "moho/serialization/serializers/SWorldParticleSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldParticle.h"

namespace
{
  moho::SWorldParticleSerializer gSWorldParticleSerializer;

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
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC5480 (FUN_00BC5480, register_SWorldParticleSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SWorldParticleSerializer::SWorldParticleSerializer()
    : mDeserialize(&SWorldParticleSerializer::Deserialize)
    , mSerialize(&SWorldParticleSerializer::Serialize)
  {}

  /**
   * Address: 0x00BEFFE0 (FUN_00BEFFE0, Moho::SWorldParticleSerializer::~SWorldParticleSerializer)
   *
   * What it does:
   * Unlinks the `SWorldParticleSerializer` helper node and rewires
   * self-links.
   */
  SWorldParticleSerializer::~SWorldParticleSerializer()
  {
    ResetLinks();
  }

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
  void SWorldParticleSerializer::Init()
  {
    gpg::RType* const type = ResolveSWorldParticleType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

#include "moho/serialization/serializers/SWorldBeamSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldBeam.h"

namespace
{
  moho::SWorldBeamSerializer gSWorldBeamSerializer;

  /**
   * Address: 0x00BC5300 (FUN_00BC5300, dynamic initializer for the global
   * `PrimitiveSerHelper<SWorldBeam::BlendMode,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_SWorldBeamBlendModePrimitiveSerializer()` call from a
   * bootstrap struct to run its equivalent logic; the real binary never
   * does that -- the global's own dynamic initializer is the entire
   * registration.
   */
  moho::SWorldBeamBlendModePrimitiveSerializer gSWorldBeamBlendModePrimitiveSerializer;

  template <typename TType>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& cached)
  {
    if (!cached) {
      cached = gpg::LookupRType(typeid(TType));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* ResolveSWorldBeamType()
  {
    return ResolveCachedType<moho::SWorldBeam>(moho::SWorldBeam::sType);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC5360 (FUN_00BC5360, reigster_SWorldBeamSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SWorldBeamSerializer::SWorldBeamSerializer()
    : mDeserialize(&SWorldBeamSerializer::Deserialize)
    , mSerialize(&SWorldBeamSerializer::Serialize)
  {}

  /**
   * Address: 0x00BEFED0 (FUN_00BEFED0, Moho::SWorldBeamSerializer::~SWorldBeamSerializer)
   *
   * What it does:
   * Unlinks the `SWorldBeamSerializer` helper node and rewires self-links.
   */
  SWorldBeamSerializer::~SWorldBeamSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0048F480 (Moho::SWorldBeamSerializer::Deserialize)
   */
  void SWorldBeamSerializer::Deserialize(
    gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<SWorldBeam*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0048F490 (Moho::SWorldBeamSerializer::Serialize)
   */
  void SWorldBeamSerializer::Serialize(
    gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/
  )
  {
    const auto* const object = reinterpret_cast<const SWorldBeam*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x0048FB50 (gpg::SerSaveLoadHelper_SWorldBeam::Init)
   */
  void SWorldBeamSerializer::Init()
  {
    gpg::RType* const type = ResolveSWorldBeamType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

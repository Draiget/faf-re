#include "moho/serialization/serializers/SWorldBeamSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldBeam.h"

namespace
{
  using BeamSerializer = moho::SWorldBeamSerializer;

  BeamSerializer gSWorldBeamSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveSWorldBeamType()
  {
    return ResolveCachedType<moho::SWorldBeam>(moho::SWorldBeam::sType);
  }

  void cleanup_SWorldBeamSerializer_atexit()
  {
    (void)moho::cleanup_SWorldBeamSerializer();
  }
} // namespace

namespace moho
{
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
  void SWorldBeamSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSWorldBeamType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BEFED0 (Moho::SWorldBeamSerializer::~SWorldBeamSerializer)
   */
  gpg::SerHelperBase* cleanup_SWorldBeamSerializer()
  {
    return UnlinkSerializerNode(gSWorldBeamSerializer);
  }

  /**
   * Address: 0x00BC5360 (reigster_SWorldBeamSerializer)
   */
  int register_SWorldBeamSerializer()
  {
    InitializeSerializerNode(gSWorldBeamSerializer);
    gSWorldBeamSerializer.mDeserialize = &SWorldBeamSerializer::Deserialize;
    gSWorldBeamSerializer.mSerialize = &SWorldBeamSerializer::Serialize;
    return std::atexit(&cleanup_SWorldBeamSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SWorldBeamSerializerBootstrap
  {
    SWorldBeamSerializerBootstrap()
    {
      (void)moho::register_SWorldBeamSerializer();
    }
  };

  [[maybe_unused]] SWorldBeamSerializerBootstrap gSWorldBeamSerializerBootstrap;
} // namespace

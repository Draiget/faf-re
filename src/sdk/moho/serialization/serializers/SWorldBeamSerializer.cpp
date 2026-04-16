#include "moho/serialization/serializers/SWorldBeamSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/particles/SWorldBeam.h"

#pragma init_seg(lib)

namespace
{
  using BeamSerializer = moho::SWorldBeamSerializer;
  using BeamBlendModePrimitiveSerializer = moho::SWorldBeamBlendModePrimitiveSerializer;

  BeamBlendModePrimitiveSerializer gSWorldBeamBlendModePrimitiveSerializer{};
  BeamSerializer gSWorldBeamSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveSWorldBeamBlendModeType()
  {
    return ResolveCachedType<moho::SWorldBeam::BlendMode>(moho::SWorldBeam::sBlendModeType);
  }

  /**
   * Address: 0x0048FDA0 (SWorldBeam::BlendMode int read lane)
   *
   * What it does:
   * Reads one `int` from archive and stores it into `SWorldBeam::BlendMode`.
   */
  void DeserializeSWorldBeamBlendMode(gpg::ReadArchive* archive, moho::SWorldBeam::BlendMode* value)
  {
    int rawValue = 0;
    archive->ReadInt(&rawValue);
    *value = static_cast<moho::SWorldBeam::BlendMode>(rawValue);
  }

  /**
   * Address: 0x0048FDC0 (SWorldBeam::BlendMode int write lane)
   *
   * What it does:
   * Writes one `SWorldBeam::BlendMode` value to archive as an `int`.
   */
  void SerializeSWorldBeamBlendMode(gpg::WriteArchive* archive, const moho::SWorldBeam::BlendMode* value)
  {
    archive->WriteInt(static_cast<int>(*value));
  }

  void cleanup_SWorldBeamBlendModePrimitiveSerializer_atexit()
  {
    (void)moho::cleanup_SWorldBeamBlendModePrimitiveSerializer();
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
   * Address: 0x0048FAB0 (gpg::PrimitiveSerHelper<Moho::SWorldBeam::BlendMode, int>::Init)
   */
  void SWorldBeamBlendModePrimitiveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSWorldBeamBlendModeType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BEFE40 (sub_BEFE40)
   */
  gpg::SerHelperBase* cleanup_SWorldBeamBlendModePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gSWorldBeamBlendModePrimitiveSerializer);
  }

  /**
   * Address: 0x00BC5300 (sub_BC5300)
   */
  int register_SWorldBeamBlendModePrimitiveSerializer()
  {
    InitializeSerializerNode(gSWorldBeamBlendModePrimitiveSerializer);
    gSWorldBeamBlendModePrimitiveSerializer.mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeSWorldBeamBlendMode);
    gSWorldBeamBlendModePrimitiveSerializer.mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeSWorldBeamBlendMode);
    return std::atexit(&cleanup_SWorldBeamBlendModePrimitiveSerializer_atexit);
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
      (void)moho::register_SWorldBeamBlendModePrimitiveSerializer();
      (void)moho::register_SWorldBeamSerializer();
    }
  };

  [[maybe_unused]] SWorldBeamSerializerBootstrap gSWorldBeamSerializerBootstrap;
} // namespace

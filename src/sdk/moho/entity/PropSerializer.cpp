#include "moho/entity/PropSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Prop.h"

namespace
{
  moho::SPropPriorityInfoSerializer gSPropPriorityInfoSerializer;
  moho::PropSerializer gPropSerializer;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return &serializer.mHelperLinks;
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mNext = self;
    serializer.mHelperLinks.mPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperLinks.mNext != nullptr && serializer.mHelperLinks.mPrev != nullptr) {
      serializer.mHelperLinks.mNext->mPrev = serializer.mHelperLinks.mPrev;
      serializer.mHelperLinks.mPrev->mNext = serializer.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mPrev = self;
    serializer.mHelperLinks.mNext = self;
    return self;
  }

  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializerType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }

  void CleanupSPropPriorityInfoSerializerAtexit()
  {
    (void)moho::cleanup_SPropPriorityInfoSerializer();
  }

  void CleanupPropSerializerAtexit()
  {
    (void)moho::cleanup_PropSerializer();
  }

  struct PropSerializerBootstrap
  {
    PropSerializerBootstrap()
    {
      moho::register_SPropPriorityInfoSerializer();
      moho::register_PropSerializer();
    }
  };

  PropSerializerBootstrap gPropSerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x006F9BE0 (FUN_006F9BE0, Moho::SPropPriorityInfoSerializer::Deserialize)
   */
  void SPropPriorityInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<SPropPriorityInfo*>(objectPtr);
    if (archive == nullptr || info == nullptr) {
      return;
    }

    archive->ReadInt(&info->mPriority);
    archive->ReadInt(&info->mBoundedTick);
  }

  /**
   * Address: 0x006F9C10 (FUN_006F9C10, Moho::SPropPriorityInfoSerializer::Serialize)
   */
  void SPropPriorityInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const info = reinterpret_cast<const SPropPriorityInfo*>(objectPtr);
    if (archive == nullptr || info == nullptr) {
      return;
    }

    archive->WriteInt(info->mPriority);
    archive->WriteInt(info->mBoundedTick);
  }

  /**
   * Address: 0x006FA8C0 (FUN_006FA8C0, sub_6FA8C0)
   */
  void SPropPriorityInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSerializerType<SPropPriorityInfo>(SPropPriorityInfo::sType);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFF140 (FUN_00BFF140, sub_BFF140)
   */
  gpg::SerHelperBase* cleanup_SPropPriorityInfoSerializer()
  {
    return UnlinkSerializerNode(gSPropPriorityInfoSerializer);
  }

  /**
   * Address: 0x006F9C70 (FUN_006F9C70)
   *
   * What it does:
   * Duplicated teardown lane for `SPropPriorityInfoSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SPropPriorityInfoSerializer_variant_primary()
  {
    return UnlinkSerializerNode(gSPropPriorityInfoSerializer);
  }

  /**
   * Address: 0x006F9CA0 (FUN_006F9CA0)
   *
   * What it does:
   * Secondary duplicated teardown lane for
   * `SPropPriorityInfoSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SPropPriorityInfoSerializer_variant_secondary()
  {
    return UnlinkSerializerNode(gSPropPriorityInfoSerializer);
  }

  /**
   * Address: 0x00BD9840 (FUN_00BD9840, register_SPropPriorityInfoSerializer)
   */
  void register_SPropPriorityInfoSerializer()
  {
    InitializeSerializerNode(gSPropPriorityInfoSerializer);
    gSPropPriorityInfoSerializer.mDeserialize = &SPropPriorityInfoSerializer::Deserialize;
    gSPropPriorityInfoSerializer.mSerialize = &SPropPriorityInfoSerializer::Serialize;
    (void)std::atexit(&CleanupSPropPriorityInfoSerializerAtexit);
  }

  /**
   * Address: 0x006FA760 (FUN_006FA760, Moho::PropSerializer::Deserialize)
   */
  void PropSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<Prop*>(objectPtr);
    if (archive == nullptr || object == nullptr) {
      return;
    }

    object->MemberDeserialize(archive, version);
  }

  /**
   * Address: 0x006FA780 (FUN_006FA780, Moho::PropSerializer::Serialize)
   */
  void PropSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<Prop*>(objectPtr);
    if (archive == nullptr || object == nullptr) {
      return;
    }

    object->MemberSerialize(archive, version);
  }

  /**
   * Address: 0x006FAA60 (FUN_006FAA60, sub_6FAA60)
   */
  void PropSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSerializerType<Prop>(Prop::sType);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFF230 (FUN_00BFF230, Moho::PropSerializer::~PropSerializer)
   */
  gpg::SerHelperBase* cleanup_PropSerializer()
  {
    return UnlinkSerializerNode(gPropSerializer);
  }

  /**
   * Address: 0x006FA7D0 (FUN_006FA7D0)
   *
   * What it does:
   * Duplicated teardown lane for `PropSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_PropSerializer_variant_primary()
  {
    return UnlinkSerializerNode(gPropSerializer);
  }

  /**
   * Address: 0x006FA800 (FUN_006FA800)
   *
   * What it does:
   * Secondary duplicated teardown lane for `PropSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_PropSerializer_variant_secondary()
  {
    return UnlinkSerializerNode(gPropSerializer);
  }

  /**
   * Address: 0x00BD9910 (FUN_00BD9910, register_PropSerializer)
   */
  void register_PropSerializer()
  {
    InitializeSerializerNode(gPropSerializer);
    gPropSerializer.mDeserialize = &PropSerializer::Deserialize;
    gPropSerializer.mSerialize = &PropSerializer::Serialize;
    (void)std::atexit(&CleanupPropSerializerAtexit);
  }
} // namespace moho


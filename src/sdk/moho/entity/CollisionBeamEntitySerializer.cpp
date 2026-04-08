#include "moho/entity/CollisionBeamEntitySerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/CollisionBeamEntity.h"

#pragma init_seg(lib)

namespace
{
  moho::CollisionBeamEntitySerializer gCollisionBeamEntitySerializer{};

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return &serializer.mHelperLinks;
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperLinks.mPrev = self;
    serializer.mHelperLinks.mNext = self;
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

  void CleanupCollisionBeamEntitySerializerAtexit()
  {
    (void)moho::cleanup_CollisionBeamEntitySerializer();
  }

  struct CollisionBeamEntitySerializerBootstrap
  {
    CollisionBeamEntitySerializerBootstrap()
    {
      moho::register_CollisionBeamEntitySerializer();
    }
  };

  [[maybe_unused]] CollisionBeamEntitySerializerBootstrap gCollisionBeamEntitySerializerBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00673B00 (FUN_00673B00, Moho::CollisionBeamEntitySerializer::Deserialize)
   */
  void CollisionBeamEntitySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CollisionBeamEntity*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00673B10 (FUN_00673B10, Moho::CollisionBeamEntitySerializer::Serialize)
   */
  void CollisionBeamEntitySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CollisionBeamEntity*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00674FE0 (FUN_00674FE0, gpg::SerSaveLoadHelper_CollisionBeamEntity::Init)
   */
  void CollisionBeamEntitySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSerializerType<CollisionBeamEntity>(CollisionBeamEntity::sType);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00673B60 (FUN_00673B60, duplicate serializer helper unlink lane)
   *
   * What it does:
   * Runs the same helper-node unlink/self-link sequence as
   * `cleanup_CollisionBeamEntitySerializer`.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySerializerLinksA()
  {
    return UnlinkSerializerNode(gCollisionBeamEntitySerializer);
  }

  /**
   * Address: 0x00673B90 (FUN_00673B90, duplicate serializer helper unlink lane)
   *
   * What it does:
   * Runs the same helper-node unlink/self-link sequence as
   * `cleanup_CollisionBeamEntitySerializer`.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySerializerLinksB()
  {
    return UnlinkSerializerNode(gCollisionBeamEntitySerializer);
  }

  /**
   * Address: 0x00BFC3A0 (FUN_00BFC3A0, Moho::CollisionBeamEntitySerializer::~CollisionBeamEntitySerializer)
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySerializer()
  {
    return UnlinkSerializerNode(gCollisionBeamEntitySerializer);
  }

  /**
   * Address: 0x00BD4CD0 (FUN_00BD4CD0, register_CollisionBeamEntitySerializer)
   */
  void register_CollisionBeamEntitySerializer()
  {
    InitializeSerializerNode(gCollisionBeamEntitySerializer);
    gCollisionBeamEntitySerializer.mDeserialize = &CollisionBeamEntitySerializer::Deserialize;
    gCollisionBeamEntitySerializer.mSerialize = &CollisionBeamEntitySerializer::Serialize;
    (void)std::atexit(&CleanupCollisionBeamEntitySerializerAtexit);
  }
} // namespace moho

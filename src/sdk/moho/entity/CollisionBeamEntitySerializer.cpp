#include "moho/entity/CollisionBeamEntitySerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/CollisionBeamEntity.h"

namespace
{
  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializerType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }
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
   * Address: 0x00BD4CD0 (FUN_00BD4CD0, dynamic initializer for the global
   * `CollisionBeamEntitySerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CollisionBeamEntitySerializer::CollisionBeamEntitySerializer()
    : mDeserialize(&CollisionBeamEntitySerializer::Deserialize)
    , mSerialize(&CollisionBeamEntitySerializer::Serialize)
  {}

  /**
   * Address: 0x00BFC3A0 (FUN_00BFC3A0, Moho::CollisionBeamEntitySerializer::~CollisionBeamEntitySerializer)
   */
  CollisionBeamEntitySerializer::~CollisionBeamEntitySerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00674FE0 (FUN_00674FE0, gpg::SerSaveLoadHelper_CollisionBeamEntity::Init)
   */
  void CollisionBeamEntitySerializer::Init()
  {
    gpg::RType* const type = ResolveSerializerType<CollisionBeamEntity>(CollisionBeamEntity::sType);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  moho::CollisionBeamEntitySerializer gCollisionBeamEntitySerializer{};
} // namespace

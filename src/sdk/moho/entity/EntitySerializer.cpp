#include "moho/entity/EntitySerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"

using namespace moho;

namespace
{
  alignas(EntitySerializer) unsigned char gEntitySerializerStorage[sizeof(EntitySerializer)] = {};
  bool gEntitySerializerConstructed = false;

  [[nodiscard]] EntitySerializer* AcquireEntitySerializer()
  {
    if (!gEntitySerializerConstructed) {
      new (gEntitySerializerStorage) EntitySerializer();
      gEntitySerializerConstructed = true;
    }

    return reinterpret_cast<EntitySerializer*>(gEntitySerializerStorage);
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(EntitySerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(EntitySerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::RType* CachedEntityTypeForSerializer()
  {
    if (moho::Entity::sType == nullptr) {
      moho::Entity::sType = gpg::LookupRType(typeid(moho::Entity));
    }
    return moho::Entity::sType;
  }

  /**
   * Address: 0x00BFC870 (FUN_00BFC870, cleanup_EntitySerializer)
   *
   * What it does:
   * Unlinks the helper node from the intrusive serializer chain and re-points
   * both links at itself, leaving a valid one-element ring.
   */
  void cleanup_EntitySerializer()
  {
    if (!gEntitySerializerConstructed) {
      return;
    }

    EntitySerializer& serializer = *AcquireEntitySerializer();
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
  }

  struct EntitySerializerStartupBootstrap
  {
    EntitySerializerStartupBootstrap()
    {
      moho::register_EntitySerializer();
    }
  };

  [[maybe_unused]] EntitySerializerStartupBootstrap gEntitySerializerStartupBootstrap;
} // namespace

/**
 * Address: 0x0067B630 (FUN_0067B630, Moho::EntitySerializer::Deserialize)
 *
 * IDA signature:
 * void __cdecl Moho::EntitySerializer::Deserialize(gpg::ReadArchive* archive, int entity);
 */
void EntitySerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto* const entity = reinterpret_cast<Entity*>(static_cast<std::uintptr_t>(objectPtr));
  if (entity != nullptr) {
    entity->MemberDeserialize(archive);
  }
}

/**
 * Address: 0x0067B640 (FUN_0067B640, Moho::EntitySerializer::Serialize)
 * Address: 0x006807A0 (FUN_006807A0)
 * Address: 0x0067F640 (FUN_0067F640)
 */
void EntitySerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  const auto* const entity = reinterpret_cast<const Entity*>(static_cast<std::uintptr_t>(objectPtr));
  if (entity != nullptr) {
    entity->MemberSerialize(archive);
  }
}

/**
 * What it does:
 * Lazily resolves the `Entity` descriptor and installs this helper's load/save
 * callbacks into it.
 */
void EntitySerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedEntityTypeForSerializer();
  if (type == nullptr) {
    return;
  }

  type->serLoadFunc_ = mLoadCallback;
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BD5050 (FUN_00BD5050, register_EntitySerializer)
 *
 * What it does:
 * Initializes the global `Entity` serializer helper, binds its load/save
 * callbacks, and installs process-exit cleanup.
 */
void moho::register_EntitySerializer()
{
  EntitySerializer* const serializer = AcquireEntitySerializer();
  InitializeSerializerNode(*serializer);
  serializer->mLoadCallback = &EntitySerializer::Deserialize;
  serializer->mSaveCallback = &EntitySerializer::Serialize;
  (void)std::atexit(&cleanup_EntitySerializer);
}

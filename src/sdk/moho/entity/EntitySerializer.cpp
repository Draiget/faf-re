#include "moho/entity/EntitySerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"

using namespace moho;

namespace
{
  // Address: 0x010B43E4 -- process-global `EntitySerializer` singleton.
  EntitySerializer gEntitySerializer;
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
 * Address: 0x0067C600 (FUN_0067C600, gpg::SerSaveLoadHelper_Entity::Init)
 *
 * What it does:
 * Lazily resolves the `Entity` descriptor and installs this helper's load/save
 * callbacks into it.
 */
void EntitySerializer::Init()
{
  gpg::RType* type = moho::Entity::sType;
  if (type == nullptr) {
    type = gpg::LookupRType(typeid(moho::Entity));
    moho::Entity::sType = type;
  }

  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00BD5050 (FUN_00BD5050, dynamic initializer for the global
 * `EntitySerializer` singleton)
 */
EntitySerializer::EntitySerializer()
  : mLoadCallback(&EntitySerializer::Deserialize)
  , mSaveCallback(&EntitySerializer::Serialize)
{}

/**
 * Address: 0x00BFC870 (FUN_00BFC870, Moho::EntitySerializer::~EntitySerializer)
 */
EntitySerializer::~EntitySerializer()
{
  ResetLinks();
}

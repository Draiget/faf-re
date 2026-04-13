#include "moho/entity/SSTIEntityConstantData.h"

#include <cstdint>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(std::int32_t));
      }
    }
    return sType;
  }

  /**
   * Address: 0x00559A80 (FUN_00559A80)
   *
   * What it does:
   * Deserializes one reflected `EntId` value lane using lazy type lookup.
   */
  [[maybe_unused]] void DeserializeEntIdField(void* const valueStorage, gpg::ReadArchive* const archive)
  {
    if (archive == nullptr || valueStorage == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Read(entIdType, valueStorage, nullOwner);
  }

  /**
   * Address: 0x00559AC0 (FUN_00559AC0)
   *
   * What it does:
   * Serializes one reflected `EntId` value lane using lazy type lookup.
   */
  void SerializeEntIdField(const void* const valueStorage, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || valueStorage == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Write(entIdType, valueStorage, nullOwner);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00559A00 (FUN_00559A00, Moho::SSTIEntityConstantData::MemberSerialize)
   *
   * What it does:
   * Serializes entity id, unowned entity-blueprint pointer, and creation tick.
   */
  void SSTIEntityConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    SerializeEntIdField(&mEntityId, archive);

    gpg::RRef blueprintRef{};
    gpg::RRef_REntityBlueprint(&blueprintRef, mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->WriteUInt(mTickCreated);
  }
} // namespace moho

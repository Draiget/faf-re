#include "moho/command/SSTITarget.h"

#include <cstdint>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"

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

  [[nodiscard]] gpg::RType* ResolveTargetType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = ResolveTypeByAnyName(
        {"ESTITargetType", "Moho::ESTITargetType", "EAiTargetType", "Moho::EAiTargetType"}
      );
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::EAiTargetType));
      }
    }
    return sType;
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

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(Wm3::Vec3f));
    }
    return sType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0055B3A0 (FUN_0055B3A0, Moho::SSTITarget::MemberDeserialize)
   *
   * What it does:
   * Reads target-kind enum, then conditionally deserializes either entity-id
   * payload or ground-position payload.
   */
  void SSTITarget::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RType* const targetType = ResolveTargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Read(targetType, &mType, nullOwner);

    if (mType == EAiTargetType::AITARGET_Entity) {
      gpg::RType* const entIdType = ResolveEntIdType();
      GPG_ASSERT(entIdType != nullptr);
      archive->Read(entIdType, &mEntityId, nullOwner);
      return;
    }

    if (mType == EAiTargetType::AITARGET_Ground) {
      gpg::RType* const vec3Type = ResolveVector3fType();
      GPG_ASSERT(vec3Type != nullptr);
      archive->Read(vec3Type, &mPos, nullOwner);
    }
  }

  /**
   * Address: 0x0055B460 (FUN_0055B460, Moho::SSTITarget::MemberSerialize)
   *
   * What it does:
   * Writes target-kind enum, then conditionally serializes either entity-id
   * payload or ground-position payload.
   */
  void SSTITarget::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::RType* const targetType = ResolveTargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Write(targetType, &mType, nullOwner);

    if (mType == EAiTargetType::AITARGET_Entity) {
      gpg::RType* const entIdType = ResolveEntIdType();
      GPG_ASSERT(entIdType != nullptr);
      archive->Write(entIdType, &mEntityId, nullOwner);
      return;
    }

    if (mType == EAiTargetType::AITARGET_Ground) {
      gpg::RType* const vec3Type = ResolveVector3fType();
      GPG_ASSERT(vec3Type != nullptr);
      archive->Write(vec3Type, &mPos, nullOwner);
    }
  }
} // namespace moho

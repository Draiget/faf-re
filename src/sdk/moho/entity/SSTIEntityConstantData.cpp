#include "moho/entity/SSTIEntityConstantData.h"

#include <cstdint>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"

namespace
{
  class SSTIEntityConstantDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIEntityConstantData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIEntityConstantData);
      gpg::RType::Init();
      Finish();
    }
  };

  gpg::SerSaveLoadHelperListRuntime gSSTIEntityConstantDataSerializer{};

  /**
   * Address: 0x00558170 (FUN_00558170, SerSaveLoadHelper<SSTIEntityConstantData>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTIEntityConstantData` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityConstantDataSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTIEntityConstantDataSerializer);
  }

  /**
   * Address: 0x005581A0 (FUN_005581A0, SerSaveLoadHelper<SSTIEntityConstantData>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the
   * `SSTIEntityConstantData` serializer helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIEntityConstantDataSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTIEntityConstantDataSerializer);
  }

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
  void DeserializeEntIdField(void* const valueStorage, gpg::ReadArchive* const archive)
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
   * Address: 0x00557FC0 (FUN_00557FC0, preregister_SSTIEntityConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIEntityConstantData`.
   */
  gpg::RType* preregister_SSTIEntityConstantDataTypeInfo()
  {
    static SSTIEntityConstantDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIEntityConstantData), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00559990 (FUN_00559990, Moho::SSTIEntityConstantData::MemberDeserialize)
   *
   * What it does:
   * Deserializes entity id, unowned entity-blueprint pointer, and creation tick.
   */
  void SSTIEntityConstantData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    DeserializeEntIdField(&mEntityId, archive);
    archive->ReadPointer_REntityBlueprint(&mBlueprint, &nullOwner);
    archive->ReadUInt(&mTickCreated);
  }

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

  /**
   * Address: 0x005592C0 (FUN_005592C0)
   *
   * What it does:
   * Tail-thunk alias that forwards entity-constant save lanes into
   * `SSTIEntityConstantData::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeSSTIEntityConstantDataThunkA(
    const SSTIEntityConstantData* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x005596E0 (FUN_005596E0)
   * Address: 0x00672500 (FUN_00672500)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards entity-constant save lanes into
   * `SSTIEntityConstantData::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeSSTIEntityConstantDataThunkB(
    const SSTIEntityConstantData* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (object != nullptr) {
      object->MemberSerialize(archive);
    }
  }
} // namespace moho

namespace
{
  struct SSTIEntityConstantDataTypeInfoBootstrap
  {
    SSTIEntityConstantDataTypeInfoBootstrap()
    {
      (void)moho::preregister_SSTIEntityConstantDataTypeInfo();
    }
  };

  [[maybe_unused]] SSTIEntityConstantDataTypeInfoBootstrap gSSTIEntityConstantDataTypeInfoBootstrap;
} // namespace

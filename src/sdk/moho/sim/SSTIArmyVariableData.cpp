#include "SSTIArmyVariableData.h"

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] int PointerToArchiveInt(const void* ptr)
  {
    return static_cast<int>(reinterpret_cast<std::uintptr_t>(ptr));
  }

  [[nodiscard]] gpg::RType* FindRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::TypeMap& map = gpg::GetRTypeMap();
    for (const char* name : names) {
      if (!name || !*name) {
        continue;
      }

      const auto it = map.find(name);
      if (it != map.end()) {
        return it->second;
      }

      for (auto jt = map.begin(); jt != map.end(); ++jt) {
        const char* registeredName = jt->first;
        if (registeredName && std::strstr(registeredName, name) != nullptr) {
          return jt->second;
        }
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* RequireRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::RType* type = FindRTypeByNameAny(names);
    GPG_ASSERT(type != nullptr);
    return type;
  }

  void DeserializeObjectByRTypeName(
    gpg::ReadArchive* archive, void* object, const std::initializer_list<const char*>& typeNames, gpg::RRef* ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serLoadFunc_ != nullptr);
    type->serLoadFunc_(archive, PointerToArchiveInt(object), type->version_, ownerRef);
  }

  void SerializeObjectByRTypeName(
    gpg::WriteArchive* archive,
    const void* object,
    const std::initializer_list<const char*>& typeNames,
    gpg::RRef* ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serSaveFunc_ != nullptr);
    type->serSaveFunc_(archive, PointerToArchiveInt(object), type->version_, ownerRef);
  }

  /**
   * Address: 0x00550A00 (FUN_00550A00, Moho::SSTIArmyVariableDataSerializer::Deserialize callback)
   *
   * What it does:
   * Archive callback thunk that routes to SSTIArmyVariableData::SerializeLoadBody.
   */
  void SSTIArmyVariableDataSerializerLoadThunk(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const data = reinterpret_cast<moho::SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    data->SerializeLoadBody(archive, ownerRef);
  }

  /**
   * Address: 0x00550A10 (FUN_00550A10, Moho::SSTIArmyVariableDataSerializer::Serialize callback)
   *
   * What it does:
   * Archive callback thunk that routes to SSTIArmyVariableData::SerializeSaveBody.
   */
  void SSTIArmyVariableDataSerializerSaveThunk(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    const auto* const data = reinterpret_cast<const moho::SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    data->SerializeSaveBody(archive, ownerRef);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007011C0 (FUN_007011C0)
   */
  void SArmyVectorWithMeta::CopyWordPayloadFrom(const SArmyVectorWithMeta& source)
  {
    if (this == &source) {
      return;
    }

    mWords.assign(source.mWords.data(), source.mWords.size());
  }

  /**
   * Address: 0x00551270 (FUN_00551270, Moho::SSTIArmyVariableDataSerializer::Deserialize)
   */
  void SSTIArmyVariableData::SerializeLoadBody(gpg::ReadArchive* const archive, gpg::RRef* const ownerRef)
  {
    if (archive == nullptr) {
      return;
    }

    DeserializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, ownerRef);

    bool boolValue = false;
    archive->ReadBool(&boolValue);
    mIsResourceSharingEnabled = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    DeserializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    DeserializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->ReadBool(&boolValue);
    mIsAlly = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->ReadUInt(&mPlayerColorBgra);
    archive->ReadUInt(&mArmyColorBgra);
    archive->ReadString(&mArmyType);
    archive->ReadInt(&mFaction);

    archive->ReadBool(&boolValue);
    mUseWholeMap = boolValue ? 1u : 0u;

    archive->ReadBool(&boolValue);
    mShowScore = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(
      archive,
      &mCategoryFilterSet,
      {"BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "Moho::BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "BVSet<RBlueprint const *,EntityCategoryHelper>"},
      ownerRef
    );

    archive->ReadBool(&boolValue);
    mIsOutOfGame = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->ReadInt(&mNoRushTimer);
    archive->ReadFloat(&mNoRushRadius);
    DeserializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->ReadFloat(&mHandicapValue);
    archive->ReadFloat(&mHandicapExtra);
  }

  /**
   * Address: 0x00551500 (FUN_00551500, Moho::SSTIArmyVariableDataSerializer::Serialize)
   */
  void SSTIArmyVariableData::SerializeSaveBody(gpg::WriteArchive* const archive, gpg::RRef* const ownerRef) const
  {
    if (archive == nullptr) {
      return;
    }

    SerializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, ownerRef);
    archive->WriteBool(mIsResourceSharingEnabled != 0u);

    SerializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    SerializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);
    SerializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->WriteBool(mIsAlly != 0u);
    SerializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, ownerRef);

    archive->WriteUInt(mPlayerColorBgra);
    archive->WriteUInt(mArmyColorBgra);
    archive->WriteString(const_cast<msvc8::string*>(&mArmyType));
    archive->WriteInt(mFaction);
    archive->WriteBool(mUseWholeMap != 0u);
    archive->WriteBool(mShowScore != 0u);

    SerializeObjectByRTypeName(
      archive,
      &mCategoryFilterSet,
      {"BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "Moho::BVSet<Moho::RBlueprint const *,Moho::EntityCategoryHelper>",
       "BVSet<RBlueprint const *,EntityCategoryHelper>"},
      ownerRef
    );

    archive->WriteBool(mIsOutOfGame != 0u);
    SerializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->WriteInt(mNoRushTimer);
    archive->WriteFloat(mNoRushRadius);
    SerializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, ownerRef);
    archive->WriteFloat(mHandicapValue);
    archive->WriteFloat(mHandicapExtra);
  }

  /**
   * Address: 0x00550D90 (FUN_00550D90, sub_550D90)
   */
  void SSTIArmyVariableDataSerializer::RegisterSerializeFunctions()
  {
    if (mSerLoadFunc == nullptr) {
      mSerLoadFunc = &SSTIArmyVariableDataSerializerLoadThunk;
    }
    if (mSerSaveFunc == nullptr) {
      mSerSaveFunc = &SSTIArmyVariableDataSerializerSaveThunk;
    }

    gpg::RType* const type = gpg::LookupRType(typeid(SSTIArmyVariableData));
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00550950 (FUN_00550950, sub_550950)
   */
  SSTIArmyVariableDataTypeInfo::~SSTIArmyVariableDataTypeInfo() = default;

  /**
   * Address: 0x00550940 (FUN_00550940, sub_550940)
   */
  const char* SSTIArmyVariableDataTypeInfo::GetName() const
  {
    return "SSTIArmyVariableData";
  }

  /**
   * Address: 0x00550920 (FUN_00550920, sub_550920)
   */
  void SSTIArmyVariableDataTypeInfo::Init()
  {
    size_ = sizeof(SSTIArmyVariableData);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

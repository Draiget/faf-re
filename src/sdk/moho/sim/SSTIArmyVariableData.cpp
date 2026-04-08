#include "SSTIArmyVariableData.h"

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <new>
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

  alignas(moho::SSTIArmyVariableDataTypeInfo)
    unsigned char gSSTIArmyVariableDataTypeInfoStorage[sizeof(moho::SSTIArmyVariableDataTypeInfo)]{};
  bool gSSTIArmyVariableDataTypeInfoConstructed = false;

  [[nodiscard]] moho::SSTIArmyVariableDataTypeInfo& AcquireSSTIArmyVariableDataTypeInfo()
  {
    if (!gSSTIArmyVariableDataTypeInfoConstructed) {
      new (gSSTIArmyVariableDataTypeInfoStorage) moho::SSTIArmyVariableDataTypeInfo();
      gSSTIArmyVariableDataTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::SSTIArmyVariableDataTypeInfo*>(gSSTIArmyVariableDataTypeInfoStorage);
  }

  void CleanupSSTIArmyVariableDataTypeInfoAtexit()
  {
    if (!gSSTIArmyVariableDataTypeInfoConstructed) {
      return;
    }

    AcquireSSTIArmyVariableDataTypeInfo().~SSTIArmyVariableDataTypeInfo();
    gSSTIArmyVariableDataTypeInfoConstructed = false;
  }

  moho::SSTIArmyVariableDataSerializer gSSTIArmyVariableDataSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void CleanupSSTIArmyVariableDataSerializerAtexit()
  {
    (void)UnlinkHelperNode(gSSTIArmyVariableDataSerializer);
  }

  /**
   * Address: 0x00550F20 (FUN_00550F20, j_Moho::SSTIArmyVariableData::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `SSTIArmyVariableData::SerializeLoadBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberDeserializeThunk(
    moho::SSTIArmyVariableData* const data, gpg::ReadArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeLoadBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F30 (FUN_00550F30, j_Moho::SSTIArmyVariableData::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `SSTIArmyVariableData::SerializeSaveBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberSerializeThunk(
    const moho::SSTIArmyVariableData* const data, gpg::WriteArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeSaveBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F80 (FUN_00550F80, j_Moho::SSTIArmyVariableData::MemberDeserialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `SSTIArmyVariableData::SerializeLoadBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberDeserializeThunkSecondary(
    moho::SSTIArmyVariableData* const data, gpg::ReadArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeLoadBody(archive, nullptr);
  }

  /**
   * Address: 0x00550F90 (FUN_00550F90, j_Moho::SSTIArmyVariableData::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `SSTIArmyVariableData::SerializeSaveBody`.
   */
  [[maybe_unused]] void SSTIArmyVariableDataMemberSerializeThunkSecondary(
    const moho::SSTIArmyVariableData* const data, gpg::WriteArchive* const archive
  )
  {
    if (!data) {
      return;
    }

    data->SerializeSaveBody(archive, nullptr);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006FD390 (FUN_006FD390, Moho::SSTIArmyVariableData::SSTIArmyVariableData)
   *
   * What it does:
   * Seeds default runtime values for army variable state and constructs the
   * textual/default category lanes expected by serializer/copy callers.
   */
  SSTIArmyVariableData::SSTIArmyVariableData()
    : mIsResourceSharingEnabled(0u)
    , mIsAlly(1u)
    , mPlayerColorBgra(0u)
    , mArmyColorBgra(0u)
    , mArmyType("None")
    , mFaction(0)
    , mUseWholeMap(0u)
    , mShowScore(1u)
    , mIsOutOfGame(0u)
    , mNoRushTimer(0)
    , mNoRushRadius(100.0f)
    , mHandicapValue(1.0f)
    , mHandicapExtra(0.0f)
  {
    std::memset(&mEconomyTotals, 0, sizeof(mEconomyTotals));
    mRuntimeWordVectorWithMeta.mMetaWord = 0u;
    mCategoryFilterSet.ResetToEmpty(0u);
    mArmyStart = Wm3::Vector2f(0.0f, 0.0f);
    mNoRushOffset = Wm3::Vector2f(0.0f, 0.0f);
  }

  /**
   * Address: 0x0055FF80 (FUN_0055FF80, Moho::SSTIArmyVariableData::SSTIArmyVariableData copy-ctor)
   *
   * What it does:
   * Clones army-variable runtime payload lanes, including Set/category bitsets
   * and legacy vector/string state, from one source object.
   */
  SSTIArmyVariableData::SSTIArmyVariableData(const SSTIArmyVariableData& other)
    : mEconomyTotals(other.mEconomyTotals)
    , mIsResourceSharingEnabled(other.mIsResourceSharingEnabled)
    , mNeutrals(other.mNeutrals)
    , mAllies(other.mAllies)
    , mEnemies(other.mEnemies)
    , mIsAlly(other.mIsAlly)
    , mValidCommandSources(other.mValidCommandSources)
    , mPlayerColorBgra(other.mPlayerColorBgra)
    , mArmyColorBgra(other.mArmyColorBgra)
    , mArmyType(other.mArmyType)
    , mFaction(other.mFaction)
    , mUseWholeMap(other.mUseWholeMap)
    , mShowScore(other.mShowScore)
    , mCategoryFilterSet(other.mCategoryFilterSet)
    , mIsOutOfGame(other.mIsOutOfGame)
    , mArmyStart(other.mArmyStart)
    , mNoRushTimer(other.mNoRushTimer)
    , mNoRushRadius(other.mNoRushRadius)
    , mNoRushOffset(other.mNoRushOffset)
    , mHandicapValue(other.mHandicapValue)
    , mHandicapExtra(other.mHandicapExtra)
  {
    std::memcpy(mPad_0039_0040, other.mPad_0039_0040, sizeof(mPad_0039_0040));
    std::memcpy(mPad_00A1_00A8, other.mPad_00A1_00A8, sizeof(mPad_00A1_00A8));
    std::memcpy(mPad_00F1_00F4, other.mPad_00F1_00F4, sizeof(mPad_00F1_00F4));
    std::memcpy(mRuntimePad_0109_0110, other.mRuntimePad_0109_0110, sizeof(mRuntimePad_0109_0110));
    std::memcpy(mPad_0139_013C, other.mPad_0139_013C, sizeof(mPad_0139_013C));
    std::memcpy(mPad_015C_0160, other.mPad_015C_0160, sizeof(mPad_015C_0160));

    mRuntimeWordVectorWithMeta.CopyWordPayloadFrom(other.mRuntimeWordVectorWithMeta);
    mRuntimeWordVectorWithMeta.mMetaWord = other.mRuntimeWordVectorWithMeta.mMetaWord;
  }

  /**
   * Address: 0x0055FEA0 (FUN_0055FEA0, Moho::SSTIArmyVariableData::~SSTIArmyVariableData)
   *
   * What it does:
   * Tears down set/vector/string member lanes for one army-variable payload.
   */
  SSTIArmyVariableData::~SSTIArmyVariableData() = default;

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
   * Address: 0x00550A00 (FUN_00550A00, Moho::SSTIArmyVariableDataSerializer::Deserialize callback)
   *
   * What it does:
   * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeLoadBody`.
   */
  void SSTIArmyVariableDataSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const data = reinterpret_cast<SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    if (ownerRef != nullptr) {
      data->SerializeLoadBody(archive, ownerRef);
      return;
    }

    SSTIArmyVariableDataMemberDeserializeThunk(data, archive);
  }

  /**
   * Address: 0x00550A10 (FUN_00550A10, Moho::SSTIArmyVariableDataSerializer::Serialize callback)
   *
   * What it does:
   * Archive callback thunk forwarding into `SSTIArmyVariableData::SerializeSaveBody`.
   */
  void SSTIArmyVariableDataSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const data = reinterpret_cast<const SSTIArmyVariableData*>(objectPtr);
    GPG_ASSERT(data != nullptr);
    if (ownerRef != nullptr) {
      data->SerializeSaveBody(archive, ownerRef);
      return;
    }

    SSTIArmyVariableDataMemberSerializeThunk(data, archive);
  }

  /**
   * Address: 0x00550D90 (FUN_00550D90, sub_550D90)
   */
  void SSTIArmyVariableDataSerializer::RegisterSerializeFunctions()
  {
    if (mSerLoadFunc == nullptr) {
      mSerLoadFunc = &SSTIArmyVariableDataSerializer::Deserialize;
    }
    if (mSerSaveFunc == nullptr) {
      mSerSaveFunc = &SSTIArmyVariableDataSerializer::Serialize;
    }

    gpg::RType* const type = gpg::LookupRType(typeid(SSTIArmyVariableData));
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00BC9B10 (FUN_00BC9B10, register_SSTIArmyVariableDataSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for
   * `SSTIArmyVariableData` and schedules process-exit cleanup.
   */
  void register_SSTIArmyVariableDataSerializer()
  {
    InitializeHelperNode(gSSTIArmyVariableDataSerializer);
    gSSTIArmyVariableDataSerializer.mSerLoadFunc = &SSTIArmyVariableDataSerializer::Deserialize;
    gSSTIArmyVariableDataSerializer.mSerSaveFunc = &SSTIArmyVariableDataSerializer::Serialize;
    gSSTIArmyVariableDataSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupSSTIArmyVariableDataSerializerAtexit);
  }

  /**
   * Address: 0x005508C0 (FUN_005508C0, startup typeinfo constructor lane)
   */
  SSTIArmyVariableDataTypeInfo::SSTIArmyVariableDataTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SSTIArmyVariableData), this);
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

  /**
   * Address: 0x00BC9AF0 (FUN_00BC9AF0, register_SSTIArmyVariableDataTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `SSTIArmyVariableDataTypeInfo` storage and
   * registers process-exit teardown.
   */
  void register_SSTIArmyVariableDataTypeInfo()
  {
    (void)AcquireSSTIArmyVariableDataTypeInfo();
    (void)std::atexit(&CleanupSSTIArmyVariableDataTypeInfoAtexit);
  }
} // namespace moho

namespace
{
  struct SSTIArmyVariableDataTypeInfoBootstrap
  {
    SSTIArmyVariableDataTypeInfoBootstrap()
    {
      moho::register_SSTIArmyVariableDataTypeInfo();
    }
  };

  [[maybe_unused]] SSTIArmyVariableDataTypeInfoBootstrap gSSTIArmyVariableDataTypeInfoBootstrap;

  struct SSTIArmyVariableDataSerializerBootstrap
  {
    SSTIArmyVariableDataSerializerBootstrap()
    {
      moho::register_SSTIArmyVariableDataSerializer();
    }
  };

  [[maybe_unused]] SSTIArmyVariableDataSerializerBootstrap gSSTIArmyVariableDataSerializerBootstrap;
} // namespace

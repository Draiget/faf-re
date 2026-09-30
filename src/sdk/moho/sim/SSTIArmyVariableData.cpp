#include "SSTIArmyVariableData.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

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
   * Address: 0x00BF4810 (FUN_00BF4810, atexit destructor of the SSTIArmyVariableDataTypeInfo object)
   */
  [[nodiscard]] moho::SSTIArmyVariableDataTypeInfo& AcquireSSTIArmyVariableDataTypeInfo()
  {
    static moho::SSTIArmyVariableDataTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00704250 (FUN_00704250)
   *
   * What it does:
   * Copies one contiguous 32-bit range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the last written slot.
   */
  std::uint32_t* CopyWordRangeForward(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      *destination = *sourceBegin;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  struct SSTIArmyVariableDataOwnerSlotRuntime
  {
    std::uint8_t reserved00_7F[0x80]{};
    moho::SSTIArmyVariableData variableData;
  };
  static_assert(
    offsetof(SSTIArmyVariableDataOwnerSlotRuntime, variableData) == 0x80,
    "SSTIArmyVariableDataOwnerSlotRuntime::variableData offset must be 0x80"
  );

} // namespace

namespace moho
{
  gpg::RType* SSTIArmyVariableData::sType = nullptr;

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
    , mRuntimeWordVectorWithMeta(other.mRuntimeWordVectorWithMeta)
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

    mWords.resize(source.mWords.size());
    (void)CopyWordRangeForward(mWords.data(), source.mWords.data(), source.mWords.data() + source.mWords.size());
  }

  /**
   * Member-wise copy constructor. `mWords`' own copy constructor is what the
   * engine emitted at 0x00560A90; the body says nothing.
   */
  SArmyVectorWithMeta::SArmyVectorWithMeta(const SArmyVectorWithMeta& other)
    : mWords(other.mWords)
    , mMetaWord(other.mMetaWord)
  {
  }

  /**
   * Address: 0x00551270 (FUN_00551270, Moho::SSTIArmyVariableData::MemberDeserialize)
   */
  void SSTIArmyVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    DeserializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, nullptr);

    bool boolValue = false;
    archive->ReadBool(&boolValue);
    mIsResourceSharingEnabled = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, nullptr);
    DeserializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, nullptr);
    DeserializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, nullptr);

    archive->ReadBool(&boolValue);
    mIsAlly = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, nullptr);

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
      nullptr
    );

    archive->ReadBool(&boolValue);
    mIsOutOfGame = boolValue ? 1u : 0u;

    DeserializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, nullptr);
    archive->ReadInt(&mNoRushTimer);
    archive->ReadFloat(&mNoRushRadius);
    DeserializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, nullptr);
    archive->ReadFloat(&mHandicapValue);
    archive->ReadFloat(&mHandicapExtra);
  }

  /**
   * Address: 0x00551500 (FUN_00551500, Moho::SSTIArmyVariableData::MemberSerialize)
   */
  void SSTIArmyVariableData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    SerializeObjectByRTypeName(archive, &mEconomyTotals, {"SEconTotals", "Moho::SEconTotals"}, nullptr);
    archive->WriteBool(mIsResourceSharingEnabled != 0u);

    SerializeObjectByRTypeName(archive, &mNeutrals, {"BVIntSet", "Moho::BVIntSet"}, nullptr);
    SerializeObjectByRTypeName(archive, &mAllies, {"BVIntSet", "Moho::BVIntSet"}, nullptr);
    SerializeObjectByRTypeName(archive, &mEnemies, {"BVIntSet", "Moho::BVIntSet"}, nullptr);

    archive->WriteBool(mIsAlly != 0u);
    SerializeObjectByRTypeName(archive, &mValidCommandSources, {"BVIntSet", "Moho::BVIntSet"}, nullptr);

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
      nullptr
    );

    archive->WriteBool(mIsOutOfGame != 0u);
    SerializeObjectByRTypeName(archive, &mArmyStart, {"Vector2<float>", "Wm3::Vector2<float>"}, nullptr);
    archive->WriteInt(mNoRushTimer);
    archive->WriteFloat(mNoRushRadius);
    SerializeObjectByRTypeName(archive, &mNoRushOffset, {"Vector2<float>", "Wm3::Vector2<float>"}, nullptr);
    archive->WriteFloat(mHandicapValue);
    archive->WriteFloat(mHandicapExtra);
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
   * Constructs the startup `SSTIArmyVariableDataTypeInfo` object.
   */
  void register_SSTIArmyVariableDataTypeInfo()
  {
    (void)AcquireSSTIArmyVariableDataTypeInfo();
  }

  /**
   * Address: 0x00700280 (FUN_00700280, func_CopyArmyData)
   *
   * IDA signature:
   * Moho::SSTIArmyVariableData *callcnv_E3 func_CopyArmyData@<eax>(
   *     Moho::SSTIArmyVariableData *a1@<ebx>, Moho::SSTIArmyVariableData *a2);
   *
   * What it does:
   * Assigns one `SSTIArmyVariableData` payload from `source` into
   * `destination` and returns the destination pointer. Used by
   * `CArmyImpl::CopyArmyVariableData` to publish the sim army state, and by
   * `CWldSession::DoBeat` to fold each army update into its `UserArmy`.
   */
  SSTIArmyVariableData* AssignArmyVariableData(
    const SSTIArmyVariableData& source, SSTIArmyVariableData* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    *destination = source;
    return destination;
  }
} // namespace moho

namespace
{
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SSTIArmyVariableDataTypeInfo_275369, moho::register_SSTIArmyVariableDataTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTIArmyVariableData>`, vtable 0x00E17574.
   *
   * Address: 0x00BC9B10 (FUN_00BC9B10 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4870 (FUN_00BF4870 -- the global's destructor.)
   * Address: 0x00550F20 (FUN_00550F20 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x00550F80 (FUN_00550F80 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x00550F30 (FUN_00550F30 -- an unreferenced copy of `Serialize`.)
   * Address: 0x00550F90 (FUN_00550F90 -- an unreferenced copy of `Serialize`.)
   * Address: 0x00550D90 (FUN_00550D90 -- `Init`.)
   * Address: 0x00550A00 (FUN_00550A00 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00550A10 (FUN_00550A10 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SSTIArmyVariableDataSerializer : gpg::SerSaveLoadHelper<SSTIArmyVariableData>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AC350 -- process-global `SSTIArmyVariableDataSerializer` singleton.
  moho::SSTIArmyVariableDataSerializer gSSTIArmyVariableDataSerializer;
} // namespace

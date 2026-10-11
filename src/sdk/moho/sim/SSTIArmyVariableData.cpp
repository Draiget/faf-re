#include "SSTIArmyVariableData.h"
#include <algorithm>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
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

  struct SSTIArmyVariableDataOwnerSlot
  {
    std::uint8_t reserved00_7F[0x80]{};
    moho::SSTIArmyVariableData variableData;
  };
  static_assert(
    offsetof(SSTIArmyVariableDataOwnerSlot, variableData) == 0x80,
    "SSTIArmyVariableDataOwnerSlot::variableData offset must be 0x80"
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
    mWordVectorWithMeta.mMetaWord = 0u;
    mCategoryFilterSet.ResetToEmpty(EntityCategoryHelper{});
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
    , mWordVectorWithMeta(other.mWordVectorWithMeta)
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
    // Opaque layout pad bytes: preserved bit-for-bit, no typed meaning to copy.
    std::copy_n(other.mPad_0039_0040, std::size(other.mPad_0039_0040), mPad_0039_0040);
    std::copy_n(other.mPad_00A1_00A8, std::size(other.mPad_00A1_00A8), mPad_00A1_00A8);
    std::copy_n(other.mPad_00F1_00F4, std::size(other.mPad_00F1_00F4), mPad_00F1_00F4);
    std::copy_n(other.mRuntimePad_0109_0110, std::size(other.mRuntimePad_0109_0110), mRuntimePad_0109_0110);
    std::copy_n(other.mPad_0139_013C, std::size(other.mPad_0139_013C), mPad_0139_013C);
    std::copy_n(other.mPad_015C_0160, std::size(other.mPad_015C_0160), mPad_015C_0160);
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

    const gpg::RRef ownerRef{};

    archive->Read(gpg::RTypeOf<decltype(mEconomyTotals)>(), &mEconomyTotals, ownerRef);

    bool boolValue = false;
    archive->ReadBool(&boolValue);
    mIsResourceSharingEnabled = boolValue ? 1u : 0u;

    archive->Read(gpg::RTypeOf<decltype(mNeutrals)>(), &mNeutrals, ownerRef);
    archive->Read(gpg::RTypeOf<decltype(mAllies)>(), &mAllies, ownerRef);
    archive->Read(gpg::RTypeOf<decltype(mEnemies)>(), &mEnemies, ownerRef);

    archive->ReadBool(&boolValue);
    mIsAlly = boolValue ? 1u : 0u;

    archive->Read(gpg::RTypeOf<decltype(mValidCommandSources)>(), &mValidCommandSources, ownerRef);

    archive->ReadUInt(&mPlayerColorBgra);
    archive->ReadUInt(&mArmyColorBgra);
    archive->ReadString(&mArmyType);
    archive->ReadInt(&mFaction);

    archive->ReadBool(&boolValue);
    mUseWholeMap = boolValue ? 1u : 0u;

    archive->ReadBool(&boolValue);
    mShowScore = boolValue ? 1u : 0u;

    archive->Read(gpg::RTypeOf<decltype(mCategoryFilterSet)>(), &mCategoryFilterSet, ownerRef);

    archive->ReadBool(&boolValue);
    mIsOutOfGame = boolValue ? 1u : 0u;

    archive->Read(gpg::RTypeOf<decltype(mArmyStart)>(), &mArmyStart, ownerRef);
    archive->ReadInt(&mNoRushTimer);
    archive->ReadFloat(&mNoRushRadius);
    archive->Read(gpg::RTypeOf<decltype(mNoRushOffset)>(), &mNoRushOffset, ownerRef);
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

    const gpg::RRef ownerRef{};

    archive->Write(gpg::RTypeOf<decltype(mEconomyTotals)>(), &mEconomyTotals, ownerRef);
    archive->WriteBool(mIsResourceSharingEnabled != 0u);

    archive->Write(gpg::RTypeOf<decltype(mNeutrals)>(), &mNeutrals, ownerRef);
    archive->Write(gpg::RTypeOf<decltype(mAllies)>(), &mAllies, ownerRef);
    archive->Write(gpg::RTypeOf<decltype(mEnemies)>(), &mEnemies, ownerRef);

    archive->WriteBool(mIsAlly != 0u);
    archive->Write(gpg::RTypeOf<decltype(mValidCommandSources)>(), &mValidCommandSources, ownerRef);

    archive->WriteUInt(mPlayerColorBgra);
    archive->WriteUInt(mArmyColorBgra);
    archive->WriteString(const_cast<msvc8::string*>(&mArmyType));
    archive->WriteInt(mFaction);
    archive->WriteBool(mUseWholeMap != 0u);
    archive->WriteBool(mShowScore != 0u);

    archive->Write(gpg::RTypeOf<decltype(mCategoryFilterSet)>(), &mCategoryFilterSet, ownerRef);

    archive->WriteBool(mIsOutOfGame != 0u);
    archive->Write(gpg::RTypeOf<decltype(mArmyStart)>(), &mArmyStart, ownerRef);
    archive->WriteInt(mNoRushTimer);
    archive->WriteFloat(mNoRushRadius);
    archive->Write(gpg::RTypeOf<decltype(mNoRushOffset)>(), &mNoRushOffset, ownerRef);
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

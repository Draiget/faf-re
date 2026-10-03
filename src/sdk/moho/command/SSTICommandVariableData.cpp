#include "moho/command/SSTICommandVariableData.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/command/SSTICommandIssueData.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  class SSTICommandVariableDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTICommandVariableData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTICommandVariableData);
      gpg::RType::Init();
      Finish();
    }
  };

  gpg::RType* gEntIdVectorType = nullptr;
  gpg::RType* gUnitCommandType = nullptr;
  gpg::RType* gTargetType = nullptr;
  gpg::RType* gCellVectorType = nullptr;

  struct SSTICommandVariableDataSlot
  {
    std::uint32_t mHeaderWord0 = 0;                  // +0x00
    std::uint32_t mHeaderWord1 = 0;                  // +0x04
    moho::SSTICommandVariableData mVariableData{};   // +0x08
  };

  static_assert(
    offsetof(SSTICommandVariableDataSlot, mVariableData) == 0x08,
    "SSTICommandVariableDataSlot::mVariableData offset must be 0x08"
  );
  static_assert(
    sizeof(SSTICommandVariableDataSlot) >= (sizeof(moho::SSTICommandVariableData) + 0x08),
    "SSTICommandVariableDataSlot must include 8-byte slot header plus variable payload"
  );


  [[nodiscard]] gpg::RType* ResolveEntIdVectorType()
  {
    if (gEntIdVectorType == nullptr) {
      gEntIdVectorType = gpg::LookupRType(typeid(gpg::fastvector<moho::EntId>));
    }
    return gEntIdVectorType;
  }

  [[nodiscard]] gpg::RType* ResolveEUnitCommandType()
  {
    if (gUnitCommandType == nullptr) {
      gUnitCommandType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return gUnitCommandType;
  }

  [[nodiscard]] gpg::RType* ResolveSSTITargetType()
  {
    if (gTargetType == nullptr) {
      gTargetType = gpg::LookupRType(typeid(moho::SSTITarget));
    }
    return gTargetType;
  }

  [[nodiscard]] gpg::RType* ResolveSOCellPosVectorType()
  {
    if (gCellVectorType == nullptr) {
      gCellVectorType = gpg::LookupRType(typeid(gpg::fastvector<moho::SOCellPos>));
    }
    return gCellVectorType;
  }



  /**
   * Address: 0x005528C0 (FUN_005528C0, preregister_SSTICommandVariableDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandVariableData`.
   */
  gpg::RType* preregister_SSTICommandVariableDataTypeInfo()
  {
    static SSTICommandVariableDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(moho::SSTICommandVariableData), &typeInfo);
    return &typeInfo;
  }

} // namespace

namespace moho
{
  gpg::RType* SSTICommandVariableData::sType = nullptr;

  /**
   * Address: 0x00552A00 (FUN_00552A00, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Initializes variable-command payload lanes to an empty/default state
   * (`UNITCOMMAND_None`, no targets, empty vectors, and unset count limits).
   */
  SSTICommandVariableData::SSTICommandVariableData()
    : mEntIds{}
    , mCmdType(EUnitCommandType::UNITCOMMAND_None)
    , mTarget1{}
    , mTarget2{}
    , v14(0)
    , mCells{}
    , mMaxCount(-1)
    , mCount(-1)
    , v23(0)
  {
    mTarget1.mType = EAiTargetType::AITARGET_None;
    mTarget1.mEnt = static_cast<EntId>(0xF0000000u);
    mTarget1.mPos = Wm3::Vec3f::Zero();

    mTarget2.mType = EAiTargetType::AITARGET_None;
    mTarget2.mEnt = static_cast<EntId>(0xF0000000u);
    mTarget2.mPos = Wm3::Vec3f::Zero();
  }


  /**
   * Address: 0x006ECAD0 (FUN_006ECAD0, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Copy-constructs the full command-variable payload including target lanes
   * and variable cell vector storage.
   */
  SSTICommandVariableData::SSTICommandVariableData(const SSTICommandVariableData& other)
    : mEntIds(other.mEntIds)
    , mCmdType(other.mCmdType)
    , mTarget1(other.mTarget1)
    , mTarget2(other.mTarget2)
    , v14(other.v14)
    , mCells(other.mCells)
    , mMaxCount(other.mMaxCount)
    , mCount(other.mCount)
    , v23(other.v23)
  {
  }

  /**
   * Address: 0x00552A70 (FUN_00552A70, Moho::SSTICommandVariableData::SSTICommandVariableData)
   *
   * What it does:
   * Initializes variable command payload lanes from one issue payload lane.
   */
  SSTICommandVariableData::SSTICommandVariableData(const SSTICommandIssueData& issueData)
    : mEntIds{}
    , mCmdType(issueData.mCommandType)
    , mTarget1(issueData.mTarget)
    , mTarget2(issueData.mTarget2)
    , v14(issueData.unk38)
    , mCells{}
    , mMaxCount(issueData.unk70)
    , mCount(issueData.unk74)
    , v23(0)
  {
    mCells.clear();
    mCells.reserve(issueData.mCells.Size());
    for (std::size_t i = 0; i < issueData.mCells.Size(); ++i) {
      mCells.push_back(issueData.mCells[i]);
    }
  }

  /**
   * Address: 0x005603E0 (FUN_005603E0, Moho::SSTICommandVariableData::~SSTICommandVariableData)
   *
   * What it does:
   * Releases command payload vectors (`mCells`, `mEntIds`) and restores their
   * inline-storage lanes.
   */
  SSTICommandVariableData::~SSTICommandVariableData() = default;

  /**
   * Address: 0x00554760 (FUN_00554760, Moho::SSTICommandVariableData::MemberDeserialize)
   */
  void SSTICommandVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Read(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Read(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Read(targetType, &mTarget1, ownerRef);
    archive->Read(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Read(cellVectorType, &mCells, ownerRef);

    archive->ReadInt(&mMaxCount);
    archive->ReadInt(&mCount);
    archive->ReadUInt(&v23);
  }

  /**
   * Address: 0x005548A0 (FUN_005548A0, Moho::SSTICommandVariableData::MemberSerialize)
   */
  void SSTICommandVariableData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const entIdVectorType = ResolveEntIdVectorType();
    GPG_ASSERT(entIdVectorType != nullptr);
    archive->Write(entIdVectorType, &mEntIds, ownerRef);

    gpg::RType* const unitCommandType = ResolveEUnitCommandType();
    GPG_ASSERT(unitCommandType != nullptr);
    archive->Write(unitCommandType, &mCmdType, ownerRef);

    gpg::RType* const targetType = ResolveSSTITargetType();
    GPG_ASSERT(targetType != nullptr);
    archive->Write(targetType, &mTarget1, ownerRef);
    archive->Write(targetType, &mTarget2, ownerRef);

    gpg::RType* const cellVectorType = ResolveSOCellPosVectorType();
    GPG_ASSERT(cellVectorType != nullptr);
    archive->Write(cellVectorType, &mCells, ownerRef);

    archive->WriteInt(mMaxCount);
    archive->WriteInt(mCount);
    archive->WriteUInt(v23);
  }

  /**
   * Address: 0x00552C10 (FUN_00552C10, func_UnitStateIsBusy)
   *
   * What it does:
   * Returns whether `commandType` is one of the movement/engagement command
   * families that keep a unit's navigation busy (see the header). Called
   * out-of-line from `CAiFormationInstance::FindSlotFor` (0x0059AA20) and
   * `Unit::MotionTick`, and inlined into `CAiFormationInstance::Update`
   * (0x0059AE80, the seven-way command-type compare at 0x0059B3xx).
   */
  bool IsSpeedThroughBusyCommandType(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Guard:
        return true;
      default:
        return false;
    }
  }
} // namespace moho

namespace
{
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTICommandVariableDataTypeInfo_2a172c, moho::preregister_SSTICommandVariableDataTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTICommandVariableData>`, vtable 0x00E17B3C.
   *
   * Address: 0x00BC9D00 (FUN_00BC9D00 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4A80 (FUN_00BF4A80 -- the global's destructor.)
   * Address: 0x00553260 (FUN_00553260 -- `Init`.)
   * Address: 0x00552B20 (FUN_00552B20 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00552B30 (FUN_00552B30 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SSTICommandVariableDataSerializer : gpg::SerSaveLoadHelper<SSTICommandVariableData>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AC554 -- process-global `SSTICommandVariableDataSerializer` singleton.
  moho::SSTICommandVariableDataSerializer gSSTICommandVariableDataSerializer;
} // namespace

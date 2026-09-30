#include "moho/sim/IArmySerializer.h"

#include <cstdint>
#include <limits>
#include <typeinfo>

#include "moho/sim/IArmy.h"
#include "moho/sim/IArmyTypeInfo.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/SSTIArmyConstantData.h"
#include "moho/sim/SSTIArmyVariableData.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  class SSTIArmyConstantDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIArmyConstantData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIArmyConstantData);
      gpg::RType::Init();
      Finish();
    }
  };

  gpg::RType* gSSTIArmyConstantDataType = nullptr;
  gpg::RType* gSSTIArmyVariableDataType = nullptr;

  [[nodiscard]] gpg::RType* ResolveSSTIArmyConstantDataType()
  {
    if (!gSSTIArmyConstantDataType) {
      gSSTIArmyConstantDataType = gpg::LookupRType(typeid(moho::SSTIArmyConstantData));
      if (!gSSTIArmyConstantDataType) {
        gSSTIArmyConstantDataType = moho::preregister_SSTIArmyConstantDataTypeInfo();
      }
    }
    return gSSTIArmyConstantDataType;
  }

  [[nodiscard]] gpg::RType* ResolveSSTIArmyVariableDataType()
  {
    if (!gSSTIArmyVariableDataType) {
      gSSTIArmyVariableDataType = gpg::LookupRType(typeid(moho::SSTIArmyVariableData));
    }
    return gSSTIArmyVariableDataType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005506B0 (FUN_005506B0, preregister_SSTIArmyConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIArmyConstantData`.
   */
  gpg::RType* preregister_SSTIArmyConstantDataTypeInfo()
  {
    static SSTIArmyConstantDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIArmyConstantData), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x005517A0 (FUN_005517A0, Moho::IArmy::MemberDeserialize)
   */
  void IArmy::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RType* const constantType = ResolveSSTIArmyConstantDataType();
    const gpg::RType* const variableType = ResolveSSTIArmyVariableDataType();
    GPG_ASSERT(constantType != nullptr);
    GPG_ASSERT(variableType != nullptr);

    gpg::RRef constantOwnerRef{};
    archive->Read(constantType, &mConstDat, constantOwnerRef);

    gpg::RRef variableOwnerRef{};
    archive->Read(variableType, &mVarDat, variableOwnerRef);
  }

  /**
   * Address: 0x00551820 (FUN_00551820, Moho::IArmy::MemberSerialize)
   */
  void IArmy::MemberSerialize(gpg::WriteArchive* const archive) const{
    if (!archive) {
      return;
    }

    const gpg::RType* const constantType = ResolveSSTIArmyConstantDataType();
    const gpg::RType* const variableType = ResolveSSTIArmyVariableDataType();
    GPG_ASSERT(constantType != nullptr);
    GPG_ASSERT(variableType != nullptr);

    gpg::RRef constantOwnerRef{};
    archive->Write(constantType, &mConstDat, constantOwnerRef);

    gpg::RRef variableOwnerRef{};
    archive->Write(variableType, &mVarDat, variableOwnerRef);
  }

  /**
   * Address: 0x00579430 (FUN_00579430, Moho::IArmy::GetAllianceWith)
   *
   * What it does:
   * Resolves alliance relation against `other` using the neutral/ally/enemy
   * relation bitsets, defaulting to neutral.
   */
  EAlliance IArmy::GetAllianceWith(const IArmy* const other) const
  {
    if (!other) {
      return ALLIANCE_Neutral;
    }


    if (mConstDat.mArmyIndex == other->mConstDat.mArmyIndex) {
      return ALLIANCE_Ally;
    }

    const std::uint32_t otherArmyIndex = static_cast<std::uint32_t>(other->mConstDat.mArmyIndex);
    if (mVarDat.mNeutrals.Contains(otherArmyIndex)) {
      return ALLIANCE_Neutral;
    }
    if (mVarDat.mAllies.Contains(otherArmyIndex)) {
      return ALLIANCE_Ally;
    }
    if (mVarDat.mEnemies.Contains(otherArmyIndex)) {
      return ALLIANCE_Enemy;
    }

    return ALLIANCE_Neutral;
  }

  /**
   * Address: 0x005D5540 (FUN_005D5540, Moho::IArmy::IsEnemy)
   *
   * What it does:
   * Returns whether `armyIndex` is present in the enemy relation bitset.
   */
  bool IArmy::IsEnemy(const std::uint32_t armyIndex) const
  {
    if (armyIndex == std::numeric_limits<std::uint32_t>::max()) {
      return false;
    }

    return mVarDat.mEnemies.Contains(armyIndex);
  }

  /**
   * Address: 0x00707C40 (FUN_00707C40)
   */
  void IArmy::SetPlayerColorBgra(const std::uint32_t playerColorBgra)
  {
    mVarDat.mPlayerColorBgra = playerColorBgra;
  }

  /**
   * Address: 0x00707C50 (FUN_00707C50)
   */
  void IArmy::SetArmyColorBgra(const std::uint32_t armyColorBgra)
  {
    mVarDat.mArmyColorBgra = armyColorBgra;
  }

  /**
   * Address: 0x00707C60 (FUN_00707C60)
   */
  void IArmy::SetFactionIndex(const std::int32_t factionIndex)
  {
    mVarDat.mFaction = factionIndex;
  }

  /**
   * Address: 0x00707C90 (FUN_00707C90)
   */
  void IArmy::SetShowScoreFlag(const bool enabled)
  {
    mVarDat.mShowScore = enabled ? 1u : 0u;
  }

  /**
   * Address: 0x00707CA0 (FUN_00707CA0)
   */
  bool IArmy::IsCivilian() const
  {
    return mConstDat.mIsCivilian != 0u;
  }

  /**
   * Address: 0x00707CB0 (FUN_00707CB0)
   */
  bool IArmy::IsOutOfGame() const
  {
    return mVarDat.mIsOutOfGame != 0u;
  }

  /**
   * Address: 0x00707CD0 (FUN_00707CD0)
   */
  float IArmy::GetHandicap() const
  {
    if (mVarDat.mHandicapValue != 0.0f) {
      return mVarDat.mHandicapExtra;
    }
    return 0.0f;
  }

} // namespace moho

namespace
{
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTIArmyConstantDataTypeInfo_ce637e, moho::preregister_SSTIArmyConstantDataTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<IArmy>`, vtable 0x00E175B4.
   *
   * Address: 0x00BC9B70 (FUN_00BC9B70 -- constructs the global and registers its destructor.)
   * Address: 0x00BF4900 (FUN_00BF4900 -- the global's destructor.)
   * Address: 0x00550E30 (FUN_00550E30 -- `Init`.)
   * Address: 0x00550C00 (FUN_00550C00 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00550C10 (FUN_00550C10 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct IArmySerializer : gpg::SerSaveLoadHelper<IArmy>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AC364 -- process-global `IArmySerializer` singleton.
  moho::IArmySerializer gIArmySerializer;
} // namespace

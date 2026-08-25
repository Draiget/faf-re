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

  struct IArmySerializedView
  {
    moho::SSTIArmyConstantData mConstantData; // +0x000
    moho::SSTIArmyVariableData mVariableData; // +0x080
  };

  static_assert(
    offsetof(IArmySerializedView, mConstantData) == 0x000, "IArmySerializedView::mConstantData offset must be 0x000"
  );
  static_assert(
    offsetof(IArmySerializedView, mVariableData) == 0x080, "IArmySerializedView::mVariableData offset must be 0x080"
  );
  static_assert(sizeof(IArmySerializedView) == 0x1E0, "IArmySerializedView size must be 0x1E0");

  gpg::RType* gSSTIArmyConstantDataType = nullptr;
  gpg::RType* gSSTIArmyVariableDataType = nullptr;

  [[nodiscard]] gpg::RType* ResolveIArmyType()
  {
    gpg::RType* type = moho::IArmy::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IArmy));
      moho::IArmy::sType = type;
    }
    return type;
  }

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

    auto* const view = reinterpret_cast<IArmySerializedView*>(this);
    const gpg::RType* const constantType = ResolveSSTIArmyConstantDataType();
    const gpg::RType* const variableType = ResolveSSTIArmyVariableDataType();
    GPG_ASSERT(constantType != nullptr);
    GPG_ASSERT(variableType != nullptr);

    gpg::RRef constantOwnerRef{};
    archive->Read(constantType, &view->mConstantData, constantOwnerRef);

    gpg::RRef variableOwnerRef{};
    archive->Read(variableType, &view->mVariableData, variableOwnerRef);
  }

  /**
   * Address: 0x00551820 (FUN_00551820, Moho::IArmy::MemberSerialize)
   */
  void IArmy::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    const gpg::RType* const constantType = ResolveSSTIArmyConstantDataType();
    const gpg::RType* const variableType = ResolveSSTIArmyVariableDataType();
    GPG_ASSERT(constantType != nullptr);
    GPG_ASSERT(variableType != nullptr);

    gpg::RRef constantOwnerRef{};
    archive->Write(constantType, &view->mConstantData, constantOwnerRef);

    gpg::RRef variableOwnerRef{};
    archive->Write(variableType, &view->mVariableData, variableOwnerRef);
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

    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    const auto* const otherView = reinterpret_cast<const IArmySerializedView*>(other);

    if (view->mConstantData.mArmyIndex == otherView->mConstantData.mArmyIndex) {
      return ALLIANCE_Ally;
    }

    const std::uint32_t otherArmyIndex = static_cast<std::uint32_t>(otherView->mConstantData.mArmyIndex);
    if (view->mVariableData.mNeutrals.Contains(otherArmyIndex)) {
      return ALLIANCE_Neutral;
    }
    if (view->mVariableData.mAllies.Contains(otherArmyIndex)) {
      return ALLIANCE_Ally;
    }
    if (view->mVariableData.mEnemies.Contains(otherArmyIndex)) {
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

    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    return view->mVariableData.mEnemies.Contains(armyIndex);
  }

  /**
   * Address: 0x00707C40 (FUN_00707C40)
   */
  void IArmy::SetPlayerColorBgra(const std::uint32_t playerColorBgra)
  {
    auto* const view = reinterpret_cast<IArmySerializedView*>(this);
    view->mVariableData.mPlayerColorBgra = playerColorBgra;
  }

  /**
   * Address: 0x00707C50 (FUN_00707C50)
   */
  void IArmy::SetArmyColorBgra(const std::uint32_t armyColorBgra)
  {
    auto* const view = reinterpret_cast<IArmySerializedView*>(this);
    view->mVariableData.mArmyColorBgra = armyColorBgra;
  }

  /**
   * Address: 0x00707C60 (FUN_00707C60)
   */
  void IArmy::SetFactionIndex(const std::int32_t factionIndex)
  {
    auto* const view = reinterpret_cast<IArmySerializedView*>(this);
    view->mVariableData.mFaction = factionIndex;
  }

  /**
   * Address: 0x00707C90 (FUN_00707C90)
   */
  void IArmy::SetShowScoreFlag(const bool enabled)
  {
    auto* const view = reinterpret_cast<IArmySerializedView*>(this);
    view->mVariableData.mShowScore = enabled ? 1u : 0u;
  }

  /**
   * Address: 0x00707CA0 (FUN_00707CA0)
   */
  bool IArmy::IsCivilian() const
  {
    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    return view->mConstantData.mIsCivilian != 0u;
  }

  /**
   * Address: 0x00707CB0 (FUN_00707CB0)
   */
  bool IArmy::IsOutOfGame() const
  {
    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    return view->mVariableData.mIsOutOfGame != 0u;
  }

  /**
   * Address: 0x00707CD0 (FUN_00707CD0)
   */
  float IArmy::GetHandicap() const
  {
    const auto* const view = reinterpret_cast<const IArmySerializedView*>(this);
    if (view->mVariableData.mHandicapValue != 0.0f) {
      return view->mVariableData.mHandicapExtra;
    }
    return 0.0f;
  }

  /**
   * Address: 0x00BC9B70 (FUN_00BC9B70, dynamic initializer for the global
   * `IArmySerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  IArmySerializer::IArmySerializer()
    : mLoadCallback(&IArmySerializer::Deserialize)
    , mSaveCallback(&IArmySerializer::Serialize)
  {}

  IArmySerializer::~IArmySerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00550C00 (FUN_00550C00, Moho::IArmySerializer::Deserialize)
   */
  void IArmySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const army = reinterpret_cast<IArmy*>(static_cast<std::uintptr_t>(objectPtr));
    army->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00550C10 (FUN_00550C10, Moho::IArmySerializer::Serialize)
   */
  void IArmySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    auto* const army = reinterpret_cast<IArmy*>(static_cast<std::uintptr_t>(objectPtr));
    army->MemberSerialize(archive);
  }

  /**
   * Address: 0x00550E30 (FUN_00550E30, gpg::SerSaveLoadHelper_IArmy::Init)
   */
  void IArmySerializer::Init()
  {
    gpg::RType* const type = ResolveIArmyType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
    type->serLoadFunc_ = mLoadCallback;
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010AC364 -- process-global `IArmySerializer` singleton.
  moho::IArmySerializer gIArmySerializer;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTIArmyConstantDataTypeInfo_ce637e, moho::preregister_SSTIArmyConstantDataTypeInfo)

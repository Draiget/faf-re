#include "moho/serialization/SSavedGameHeader.h"

#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/RVectorTypestruct_Moho_SSavedGameArmyInfo.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/LaunchInfoBase.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  /**
   * Address: 0x008831C0 (FUN_008831C0)
   *
   * What it does:
   * Loads SSavedGameHeader payload fields and shared LaunchInfoBase pointer.
   */
  void LoadSavedGameHeader(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef*)
  {
    auto* const header = reinterpret_cast<moho::SSavedGameHeader*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(header != nullptr);
    if (!archive || !header) {
      return;
    }

    if (version < 3) {
      throw std::runtime_error("WrongVersion");
    }

    archive->ReadInt(&header->mVersion);
    archive->ReadString(&header->mMapName);
    archive->ReadInt(&header->mFocusArmy);
    archive->Read(gpg::ResolveSavedGameArmyInfoVectorType(), &header->mArmyInfo, NullOwnerRef());
    archive->ReadString(&header->mScenarioInfoText);
    gpg::ReadPointerShared_LaunchInfoBase(header->mLaunchInfo, archive, NullOwnerRef());
  }

  /**
   * Address: 0x00883280 (FUN_00883280)
   *
   * What it does:
   * Saves SSavedGameHeader payload fields and LaunchInfoBase shared pointer lane.
   */
  void SaveSavedGameHeader(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef*)
  {
    auto* const header = reinterpret_cast<const moho::SSavedGameHeader*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(header != nullptr);
    if (!archive || !header) {
      return;
    }

    if (version < 3) {
      throw std::runtime_error("WrongVersion");
    }

    archive->WriteInt(header->mVersion);
    archive->WriteString(const_cast<msvc8::string*>(&header->mMapName));
    archive->WriteInt(header->mFocusArmy);
    archive->Write(gpg::ResolveSavedGameArmyInfoVectorType(), &header->mArmyInfo, NullOwnerRef());
    archive->WriteString(const_cast<msvc8::string*>(&header->mScenarioInfoText));

    gpg::RRef launchInfoRef{};
    gpg::RRef_LaunchInfoBase(&launchInfoRef, header->mLaunchInfo.px);
    gpg::WriteRawPointer(archive, launchInfoRef, gpg::TrackedPointerState::Shared, NullOwnerRef());
  }

  moho::SSavedGameHeaderTypeInfo gSavedGameHeaderTypeInfo;
  moho::SSavedGameHeaderSerializer gSavedGameHeaderSerializer;

  void EnsureSavedGameHeaderRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(moho::SSavedGameHeader), &gSavedGameHeaderTypeInfo);
      gSavedGameHeaderSerializer.mNext = nullptr;
      gSavedGameHeaderSerializer.mPrev = nullptr;
      gSavedGameHeaderSerializer.mSerLoadFunc = &LoadSavedGameHeader;
      gSavedGameHeaderSerializer.mSerSaveFunc = &SaveSavedGameHeader;
      gSavedGameHeaderSerializer.RegisterSerializeFunctions();
      return true;
    }();

    (void)kRegistered;
  }
} // namespace

namespace moho
{
  gpg::RType* SSavedGameHeader::sType = nullptr;

  gpg::RType* SSavedGameHeader::StaticGetClass()
  {
    EnsureSavedGameHeaderRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(SSavedGameHeader));
    }
    return sType;
  }

  /**
   * Address: 0x00880580 (FUN_00880580)
   *
   * What it does:
   * Initializes header defaults (`mVersion = 0x14`) and clears payload fields.
   */
  SSavedGameHeader::SSavedGameHeader()
    : mVersion(0x14)
    , mMapName()
    , mFocusArmy(0)
    , mArmyInfo()
    , mScenarioInfoText()
    , mLaunchInfo()
  {
  }

  SSavedGameHeader::SSavedGameHeader(const SSavedGameHeader& other)
    : mVersion(other.mVersion)
    , mMapName(other.mMapName)
    , mFocusArmy(other.mFocusArmy)
    , mArmyInfo(other.mArmyInfo)
    , mScenarioInfoText(other.mScenarioInfoText)
    , mLaunchInfo()
  {
    mLaunchInfo.assign_retain(other.mLaunchInfo);
  }

  SSavedGameHeader& SSavedGameHeader::operator=(const SSavedGameHeader& other)
  {
    if (this == &other) {
      return *this;
    }

    mVersion = other.mVersion;
    mMapName = other.mMapName;
    mFocusArmy = other.mFocusArmy;
    mArmyInfo = other.mArmyInfo;
    mScenarioInfoText = other.mScenarioInfoText;
    mLaunchInfo.assign_retain(other.mLaunchInfo);
    return *this;
  }

  /**
   * Address: 0x008805E0 (FUN_008805E0)
   *
   * What it does:
   * Releases launch-info shared handle and clears owned fields.
   */
  SSavedGameHeader::~SSavedGameHeader()
  {
    mLaunchInfo.release();
  }

  /**
   * Address: 0x008801A0 (FUN_008801A0)
   */
  const char* SSavedGameHeaderTypeInfo::GetName() const
  {
    return "SSavedGameHeader";
  }

  /**
   * Address: 0x00880170 (FUN_00880170)
   */
  void SSavedGameHeaderTypeInfo::Init()
  {
    size_ = sizeof(SSavedGameHeader);
    gpg::RType::Init();
    gpg::RType::Version(3);
    Finish();
  }

  /**
   * Address: 0x00882330 (FUN_00882330)
   *
   * What it does:
   * Registers save/load callbacks for SSavedGameHeader.
   */
  void SSavedGameHeaderSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SSavedGameHeader::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

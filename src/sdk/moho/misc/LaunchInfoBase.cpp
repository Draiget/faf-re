#include "moho/misc/LaunchInfoBase.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/STIMap.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] gpg::RType* ResolveArmyLaunchInfoVectorType()
  {
    gpg::RType* type = gpg::REF_FindTypeNamed("vector<ArmyLaunchInfo>");
    if (!type) {
      type = gpg::REF_FindTypeNamed("vector<Moho::ArmyLaunchInfo>");
    }
    return type;
  }

  [[noreturn]] void ThrowSerializationError(const char* message)
  {
    throw gpg::SerializationError(message ? message : "");
  }

  /**
   * Address: 0x00544180 (FUN_00544180)
   *
   * What it does:
   * Loads LaunchInfoBase fields in archive order:
   * game-mods text, scenario-info text, army launch info, command-source
   * control lanes, language, and cheat flag.
   */
  void LoadLaunchInfoBase(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::LaunchInfoBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->ReadString(&info->mGameMods);
    archive->ReadString(&info->mScenarioInfo);

    gpg::RType* const vectorType = ResolveArmyLaunchInfoVectorType();
    if (!vectorType) {
      ThrowSerializationError(
        "Error detected in archive: missing reflection type \"vector<ArmyLaunchInfo>\" required by LaunchInfoBase."
      );
    }
    archive->Read(vectorType, &info->mArmyLaunchInfo, NullOwnerRef());

    archive->ReadInt(&info->mCommandSources.v4);
    archive->ReadInt(&info->mCommandSources.mOriginalSource);
    archive->ReadString(&info->mLanguage);
    archive->ReadBool(&info->mCheatsEnabled);
  }

  /**
   * Address: 0x00544220 (FUN_00544220)
   *
   * What it does:
   * Saves LaunchInfoBase fields in the same order as the load callback.
   */
  void SaveLaunchInfoBase(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::LaunchInfoBase*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->WriteString(&info->mGameMods);
    archive->WriteString(&info->mScenarioInfo);

    gpg::RType* const vectorType = ResolveArmyLaunchInfoVectorType();
    if (!vectorType) {
      ThrowSerializationError(
        "Error while creating archive: missing reflection type \"vector<ArmyLaunchInfo>\" required by LaunchInfoBase."
      );
    }
    archive->Write(vectorType, &info->mArmyLaunchInfo, NullOwnerRef());

    archive->WriteInt(info->mCommandSources.v4);
    archive->WriteInt(info->mCommandSources.mOriginalSource);
    archive->WriteString(&info->mLanguage);
    archive->WriteBool(info->mCheatsEnabled);
  }

  moho::LaunchInfoBaseTypeInfo gLaunchInfoBaseTypeInfo;
  moho::LaunchInfoBaseSerializer gLaunchInfoBaseSerializer;

  bool gLaunchInfoBaseTypeRegistered = false;

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

  void EnsureLaunchInfoBaseTypeRegistered()
  {
    if (gLaunchInfoBaseTypeRegistered) {
      return;
    }

    gpg::PreRegisterRType(typeid(moho::LaunchInfoBase), &gLaunchInfoBaseTypeInfo);
    gLaunchInfoBaseTypeRegistered = true;
  }

  void CleanupLaunchInfoBaseSerializerAtexit()
  {
    (void)UnlinkHelperNode(gLaunchInfoBaseSerializer);
  }

  struct LaunchInfoBaseSerializerBootstrap
  {
    LaunchInfoBaseSerializerBootstrap()
    {
      moho::register_LaunchInfoBaseSerializer();
    }
  };

  [[maybe_unused]] LaunchInfoBaseSerializerBootstrap gLaunchInfoBaseSerializerBootstrap;
} // namespace

namespace moho
{
  gpg::RType* LaunchInfoBase::sType = nullptr;

  gpg::RType* LaunchInfoBase::StaticGetClass()
  {
    EnsureLaunchInfoBaseTypeRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(LaunchInfoBase));
    }
    return sType;
  }

  /**
   * Address: 0x005423B0 (FUN_005423B0)
   *
   * What it does:
   * Initializes launch-info base runtime ownership and metadata lanes.
   */
  LaunchInfoBase::LaunchInfoBase()
    : mGameRules(nullptr)
    , mMap(nullptr)
    , mGameMods()
    , mScenarioInfo()
    , mArmyLaunchInfo()
    , mCommandSources()
    , mLanguage()
    , mCheatsEnabled(false)
    , pad_89{0, 0, 0}
  {
  }

  /**
   * Address: 0x00542440 (FUN_00542440, deleting dtor thunk)
   * Address: 0x00542460 (FUN_00542460, destructor core)
   */
  LaunchInfoBase::~LaunchInfoBase()
  {
    if (mMap != nullptr) {
      delete mMap;
      mMap = nullptr;
    }
  }

  /**
   * Address: 0x00541FB0 (FUN_00541FB0)
   *
   * What it does:
   * Base implementation returns no "new game" launch descriptor.
   */
  LaunchInfoNew* LaunchInfoBase::GetNew()
  {
    return nullptr;
  }

  /**
   * Address: 0x00541FC0 (FUN_00541FC0)
   *
   * What it does:
   * Base implementation returns no "load game" launch descriptor.
   */
  LaunchInfoLoad* LaunchInfoBase::GetLoad()
  {
    return nullptr;
  }

  /**
   * Address: 0x00542790 (FUN_00542790)
   *
   * What it does:
   * Initializes "new game" launch-info derived lanes.
   */
  LaunchInfoNew::LaunchInfoNew()
    : LaunchInfoBase()
    , mProps(nullptr)
    , mStrVec()
    , mInitSeed(0)
  {
  }

  /**
   * Address: 0x00542810 (FUN_00542810)
   */
  LaunchInfoNew::~LaunchInfoNew() = default;

  /**
   * Address: 0x00541FD0 (FUN_00541FD0)
   */
  LaunchInfoNew* LaunchInfoNew::GetNew()
  {
    return this;
  }

  /**
   * Address: 0x00542870 (FUN_00542870)
   *
   * What it does:
   * Allocates and populates a new LaunchInfoNew shared object from this source.
   */
  void LaunchInfoNew::Create(boost::SharedPtrRaw<void>& outCreated)
  {
    LaunchInfoNew* const createdInfo = new LaunchInfoNew();
    createdInfo->mGameMods = mGameMods;
    createdInfo->mScenarioInfo = mScenarioInfo;
    createdInfo->mArmyLaunchInfo = std::move(mArmyLaunchInfo);
    createdInfo->mCommandSources.v4 = mCommandSources.v4;
    createdInfo->mCommandSources.mOriginalSource = mCommandSources.mOriginalSource;
    createdInfo->mLanguage = mLanguage;
    createdInfo->mCheatsEnabled = mCheatsEnabled;
    createdInfo->mStrVec = std::move(mStrVec);
    createdInfo->mInitSeed = static_cast<std::int32_t>(gpg::time::GetSystemTimer().ElapsedCycles());

    outCreated.release();
    outCreated = boost::SharedPtrRaw<void>::with_deleter(static_cast<void*>(createdInfo), [](void* payload) {
      delete static_cast<LaunchInfoNew*>(payload);
    });
  }

  /**
   * Address: 0x00542AE0 (FUN_00542AE0)
   *
   * What it does:
   * Initializes "load game" launch-info derived lanes.
   */
  LaunchInfoLoad::LaunchInfoLoad()
    : LaunchInfoBase()
    , mReadArchive(nullptr)
    , mLoadSessionData()
    , mSharedLaunchInfo()
  {
  }

  /**
   * Address: 0x00542B80 (FUN_00542B80)
   *
   * What it does:
   * Releases shared session payload lanes and owned props object.
   */
  LaunchInfoLoad::~LaunchInfoLoad()
  {
    mSharedLaunchInfo.release();
    mLoadSessionData.release();
    delete mReadArchive;
    mReadArchive = nullptr;
  }

  /**
   * Address: 0x00541FE0 (FUN_00541FE0)
   */
  LaunchInfoLoad* LaunchInfoLoad::GetLoad()
  {
    return this;
  }

  /**
   * Address: 0x00541FF0 (FUN_00541FF0)
   *
   * What it does:
   * Returns retained shared payload lane for session creation.
   */
  void LaunchInfoLoad::Create(boost::SharedPtrRaw<void>& outCreated)
  {
    boost::SharedPtrRaw<void> sharedLaunchInfo{};
    sharedLaunchInfo.px = static_cast<void*>(mSharedLaunchInfo.px);
    sharedLaunchInfo.pi = mSharedLaunchInfo.pi;
    outCreated.assign_retain(sharedLaunchInfo);
  }

  /**
   * Address: 0x00542550 (FUN_00542550, Moho::LaunchInfoBaseSerializer::Deserialize)
   *
   * What it does:
   * Archive callback thunk forwarding into LaunchInfoBase load body.
   */
  void LaunchInfoBaseSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    LoadLaunchInfoBase(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00542560 (FUN_00542560, Moho::LaunchInfoBaseSerializer::Serialize)
   *
   * What it does:
   * Archive callback thunk forwarding into LaunchInfoBase save body.
   */
  void LaunchInfoBaseSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    SaveLaunchInfoBase(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00543190 (FUN_00543190, sub_543190)
   *
   * What it does:
   * Registers load/save callbacks into LaunchInfoBase RTTI.
   */
  void LaunchInfoBaseSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = LaunchInfoBase::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x00BC94C0 (FUN_00BC94C0, register_LaunchInfoBaseSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for `LaunchInfoBase`
   * and schedules process-exit cleanup.
   */
  void register_LaunchInfoBaseSerializer()
  {
    EnsureLaunchInfoBaseTypeRegistered();
    InitializeHelperNode(gLaunchInfoBaseSerializer);
    gLaunchInfoBaseSerializer.mSerLoadFunc = &LaunchInfoBaseSerializer::Deserialize;
    gLaunchInfoBaseSerializer.mSerSaveFunc = &LaunchInfoBaseSerializer::Serialize;
    gLaunchInfoBaseSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupLaunchInfoBaseSerializerAtexit);
  }

  /**
   * Address: 0x00542300 (FUN_00542300, deleting dtor thunk)
   */
  LaunchInfoBaseTypeInfo::~LaunchInfoBaseTypeInfo() = default;

  /**
   * Address: 0x005422F0 (FUN_005422F0)
   */
  const char* LaunchInfoBaseTypeInfo::GetName() const
  {
    return "LaunchInfoBase";
  }

  /**
   * Address: 0x005422D0 (FUN_005422D0)
   */
  void LaunchInfoBaseTypeInfo::Init()
  {
    size_ = sizeof(LaunchInfoBase);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00885170 (FUN_00885170)
   *
   * What it does:
   * Builds an `RRef` for `LaunchInfoBase*`, upcasting derived launch-info
   * objects to their complete-object pointer when needed.
   */
  RRef* RRef_LaunchInfoBase(RRef* outRef, moho::LaunchInfoBase* value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RType* const baseType = moho::LaunchInfoBase::StaticGetClass();
    outRef->mObj = value;
    outRef->mType = baseType;

    if (!value || !baseType) {
      return outRef;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*value));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      outRef->mObj = value;
      outRef->mType = dynamicType;
      return outRef;
    }

    outRef->mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
    outRef->mType = dynamicType;
    return outRef;
  }
} // namespace gpg

#include "CEconomy.h"

#include <cstdint>
#include <typeinfo>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  class SEconValueTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SEconValue";
    }

    void Init() override
    {
      size_ = sizeof(moho::SEconValue);
      gpg::RType::Init();
      Finish();
    }
  };

  class SEconTotalsTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SEconTotals";
    }

    void Init() override
    {
      size_ = sizeof(moho::SEconTotals);
      gpg::RType::Init();
      Finish();
    }
  };

  gpg::SerSaveLoadHelperListRuntime gSEconValueSerializer{};
  gpg::SerSaveLoadHelperListRuntime gSEconTotalsSerializer{};

  struct CEconomySerializerHelperRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
  static_assert(
    offsetof(CEconomySerializerHelperRuntime, mHelperNext) == 0x04,
    "CEconomySerializerHelperRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEconomySerializerHelperRuntime, mHelperPrev) == 0x08,
    "CEconomySerializerHelperRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEconomySerializerHelperRuntime, mLoadCallback) == 0x0C,
    "CEconomySerializerHelperRuntime::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconomySerializerHelperRuntime, mSaveCallback) == 0x10,
    "CEconomySerializerHelperRuntime::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconomySerializerHelperRuntime) == 0x14, "CEconomySerializerHelperRuntime size must be 0x14");

  CEconomySerializerHelperRuntime gCEconomySerializerHelper{};
  struct CEconomyConstructHelperRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CEconomyConstructHelperRuntime, mHelperNext) == 0x04,
    "CEconomyConstructHelperRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEconomyConstructHelperRuntime, mHelperPrev) == 0x08,
    "CEconomyConstructHelperRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEconomyConstructHelperRuntime, mConstructCallback) == 0x0C,
    "CEconomyConstructHelperRuntime::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEconomyConstructHelperRuntime, mDeleteCallback) == 0x10,
    "CEconomyConstructHelperRuntime::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CEconomyConstructHelperRuntime) == 0x14, "CEconomyConstructHelperRuntime size must be 0x14");

  CEconomyConstructHelperRuntime gCEconomyConstructHelper{};
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
  constexpr int kSerializationConstructLine = 231;

  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(CEconomySerializerHelperRuntime& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  void InitializeHelperNode(CEconomySerializerHelperRuntime& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(CEconomySerializerHelperRuntime& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00563CE0 (FUN_00563CE0, SerSaveLoadHelper<SEconValue>::unlink lane A)
   *
   * What it does:
   * Unlinks `SEconValue` serializer helper links and restores self-links for
   * intrusive-list sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSEconValueSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSEconValueSerializer);
  }

  /**
   * Address: 0x00563D10 (FUN_00563D10, SerSaveLoadHelper<SEconValue>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the `SEconValue` serializer
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSEconValueSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSEconValueSerializer);
  }

  /**
   * Address: 0x00563EE0 (FUN_00563EE0, SerSaveLoadHelper<SEconTotals>::unlink lane A)
   *
   * What it does:
   * Unlinks `SEconTotals` serializer helper links and restores self-links for
   * intrusive-list sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSEconTotalsSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSEconTotalsSerializer);
  }

  /**
   * Address: 0x00563F10 (FUN_00563F10, SerSaveLoadHelper<SEconTotals>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the `SEconTotals` serializer
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSEconTotalsSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSEconTotalsSerializer);
  }

  /**
   * Address: 0x007730D0 (FUN_007730D0)
   *
   * What it does:
   * Unlinks startup `CEconomySerializer` helper links and rewires the node
   * into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconomySerializerNodeVariantA() noexcept
  {
    return UnlinkHelperNode(gCEconomySerializerHelper);
  }

  /**
   * Address: 0x00773100 (FUN_00773100)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `CEconomySerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconomySerializerNodeVariantB() noexcept
  {
    return UnlinkHelperNode(gCEconomySerializerHelper);
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType) noexcept
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = staticType;
    return out;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (!moho::SEconValue::sType) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
      if (!moho::SEconValue::sType) {
        moho::SEconValue::sType = moho::preregister_SEconValueTypeInfo();
      }
    }
    return moho::SEconValue::sType;
  }

  [[nodiscard]] gpg::RType* CachedSEconTotalsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SEconTotals));
      if (!cached) {
        cached = moho::preregister_SEconTotalsTypeInfo();
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Sim));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      constexpr const char* kTypeNames[] = {"Moho::CEconStorage", "CEconStorage", "class Moho::CEconStorage"};
      for (const char* const typeName : kTypeNames) {
        cached = gpg::REF_FindTypeNamed(typeName);
        if (cached != nullptr) {
          break;
        }
      }
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCEconomyType()
  {
    if (moho::CEconomy::sType == nullptr) {
      moho::CEconomy::sType = gpg::LookupRType(typeid(moho::CEconomy));
    }
    return moho::CEconomy::sType;
  }

  [[nodiscard]] moho::CEconRequest* RequestFromNode(moho::TDatListItem<void, void>* const node) noexcept
  {
    return reinterpret_cast<moho::CEconRequest*>(node);
  }

  /**
   * Address: 0x00773C80 (FUN_00773C80, Moho::CEconomyConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Resolves `CEconomy` RTTI and installs startup construct/delete callbacks
   * from one construct-helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType::construct_func_t RegisterCEconomyConstructCallbacks(
    CEconomyConstructHelperRuntime* const helper
  )
  {
    gpg::RType* const type = CachedCEconomyType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }

    type->serConstructFunc_ = helper->mConstructCallback;
    type->deleteFunc_ = helper->mDeleteCallback;
    return helper->mConstructCallback;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00563B10 (FUN_00563B10, preregister_SEconValueTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconValue`.
   */
  gpg::RType* preregister_SEconValueTypeInfo()
  {
    static SEconValueTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SEconValue), &typeInfo);
    SEconValue::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x00563D40 (FUN_00563D40, preregister_SEconTotalsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconTotals`.
   */
  gpg::RType* preregister_SEconTotalsTypeInfo()
  {
    static SEconTotalsTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SEconTotals), &typeInfo);
    return &typeInfo;
  }

  gpg::RType* CEconomy::sType = nullptr;

  /**
   * Address: 0x00772FC0 (FUN_00772FC0)
   *
   * What it does:
   * Allocates one `CEconomy` object, initializes constructor-default lanes,
   * then returns it through `SerConstructResult` as an unowned reflected ref.
   */
  void ConstructCEconomyForSerializer(gpg::SerConstructResult* const result)
  {
    CEconomy* economy = static_cast<CEconomy*>(::operator new(sizeof(CEconomy), std::nothrow));
    if (economy != nullptr) {
      economy->mSim = nullptr;
      economy->mIndex = -1;
      economy->mResources = {};
      economy->mPendingResources = {};
      economy->mTotals = {};
      economy->mExtraStorage = nullptr;
      economy->mResourceSharing = 1u;
      economy->mPad55To57[0] = 0u;
      economy->mPad55To57[1] = 0u;
      economy->mPad55To57[2] = 0u;
      economy->mConsumptionData.mPrev = &economy->mConsumptionData;
      economy->mConsumptionData.mNext = &economy->mConsumptionData;
    }

    if (result != nullptr) {
      result->SetUnowned(MakeTypedRef(economy, CachedCEconomyType()), 0u);
    }
  }

  /**
   * Address: 0x00772FB0 (FUN_00772FB0)
   *
   * What it does:
   * Serializer construct-callback thunk that forwards to
   * `ConstructCEconomyForSerializer`.
   */
  [[maybe_unused]] void ConstructCEconomySerializerThunk(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    ConstructCEconomyForSerializer(result);
  }

  /**
   * Address: 0x00773080 (FUN_00773080, Moho::CEconomySerializer::Deserialize)
   *
   * What it does:
   * Forwards serializer-load callback lanes into `CEconomy::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEconomySerializerCallback(
    gpg::ReadArchive* const archive,
    CEconomy* const economy
  )
  {
    if (economy != nullptr) {
      economy->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00773090 (FUN_00773090, Moho::CEconomySerializer::Serialize)
   *
   * What it does:
   * Forwards serializer-save callback lanes into `CEconomy::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEconomySerializerCallback(
    gpg::WriteArchive* const archive,
    CEconomy* const economy
  )
  {
    if (economy != nullptr) {
      economy->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x007730A0 (FUN_007730A0)
   *
   * What it does:
   * Initializes startup `CEconomySerializer` helper links and binds
   * deserialize/serialize callback lanes.
   */
  [[nodiscard]] CEconomySerializerHelperRuntime* InitializeCEconomySerializerHelperStorage() noexcept
  {
    InitializeHelperNode(gCEconomySerializerHelper);
    gCEconomySerializerHelper.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&DeserializeCEconomySerializerCallback);
    gCEconomySerializerHelper.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&SerializeCEconomySerializerCallback);
    return &gCEconomySerializerHelper;
  }

  /**
   * Address: 0x007742A0 (FUN_007742A0)
   *
   * What it does:
   * Serializer delete-callback thunk that clears one `CEconomy` object when
   * the pointer lane is non-null.
   */
  [[maybe_unused]] void ClearCEconomyIfPresent(CEconomy* const economy)
  {
    if (economy != nullptr) {
      (void)economy->Clear();
    }
  }

  /**
   * Address: 0x00772F20 (FUN_00772F20)
   *
   * What it does:
   * Initializes startup `CEconomyConstruct` helper links and binds construct/
   * delete callback lanes for serializer-owned CEconomy objects.
   */
  [[nodiscard]] CEconomyConstructHelperRuntime* InitializeCEconomyConstructHelperStartup()
  {
    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&gCEconomyConstructHelper.mHelperNext);
    gCEconomyConstructHelper.mHelperNext = self;
    gCEconomyConstructHelper.mHelperPrev = self;
    gCEconomyConstructHelper.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCEconomySerializerThunk);
    gCEconomyConstructHelper.mDeleteCallback =
      reinterpret_cast<gpg::RType::delete_func_t>(&ClearCEconomyIfPresent);
    return &gCEconomyConstructHelper;
  }

  /**
   * Address: 0x007048F0 (FUN_007048F0, Moho::CEconomy::Clear)
   *
   * What it does:
   * Unlinks the consumption-request sentinel node, releases extra-storage
   * ownership (with max-storage rollback), then frees this economy object.
   */
  CEconomy* CEconomy::Clear()
  {
    mConsumptionData.mNext->mPrev = mConsumptionData.mPrev;
    mConsumptionData.mPrev->mNext = mConsumptionData.mNext;
    mConsumptionData.mPrev = &mConsumptionData;
    mConsumptionData.mNext = &mConsumptionData;

    CEconStorage* const extraStorage = mExtraStorage;
    if (extraStorage != nullptr) {
      if (extraStorage->mEconomy != nullptr) {
        (void)extraStorage->Chng(-1);
      }
      ::operator delete(extraStorage);
    }

    ::operator delete(this);
    return this;
  }

  /**
   * Address: 0x007731B0 (FUN_007731B0, Moho::CEconomy::SerializeRequests)
   *
   * What it does:
   * Writes economy-request intrusive-list pointers in reverse link order and
   * appends one null pointer terminator.
   */
void CEconomy::SerializeRequests(gpg::WriteArchive* const archive)
{
  if (archive == nullptr) {
    return;
    }

    const gpg::RRef nullOwner{};

    for (TDatListItem<void, void>* node = mConsumptionData.mPrev; node != &mConsumptionData; node = node->mPrev) {
      gpg::RRef requestRef{};
      gpg::RRef_CEconRequest(&requestRef, RequestFromNode(node));
      gpg::WriteRawPointer(archive, requestRef, gpg::TrackedPointerState::Unowned, nullOwner);
    }

  gpg::RRef endRef{};
  gpg::RRef_CEconRequest(&endRef, nullptr);
  gpg::WriteRawPointer(archive, endRef, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x00773130 (FUN_00773130, Moho::CEconomy::DeserializeRequests)
 *
 * What it does:
 * Reads CEconRequest intrusive nodes from archive and links each request into
 * `mConsumptionData` until one null terminator is encountered.
 */
void CEconomy::DeserializeRequests(gpg::ReadArchive* const archive)
{
  if (archive == nullptr) {
    return;
  }

  gpg::RRef ownerRef{};
  CEconRequest* request = nullptr;
  (void)archive->ReadPointer_CEconRequest(&request, &ownerRef);
  while (request != nullptr) {
    request->mNode.ListLinkAfter(&mConsumptionData);
    ownerRef = gpg::RRef{};
    (void)archive->ReadPointer_CEconRequest(&request, &ownerRef);
  }
}

  /**
   * Address: 0x00774730 (FUN_00774730, Moho::CEconomy::MemberDeserialize)
   *
   * What it does:
   * Deserializes Sim owner, index/value lanes, totals, owned extra-storage
   * pointer, sharing flag, and request list lanes from archive input.
   */
  void CEconomy::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_Sim(&mSim, &nullOwner);
    archive->ReadInt(&mIndex);
    archive->Read(CachedSEconValueType(), &mResources, nullOwner);
    archive->Read(CachedSEconValueType(), &mPendingResources, nullOwner);
    archive->Read(CachedSEconTotalsType(), &mTotals, nullOwner);

    // Canonical owned-pointer read (recovered from FUN_006B4F70): enforces
    // UNOWNED->OWNED transition and raises SerializationError on type mismatch.
    CEconStorage* loadedExtraStorage = nullptr;
    (void)archive->ReadPointerOwned_CEconStorage(&loadedExtraStorage, &nullOwner);

    CEconStorage* const previousExtraStorage = mExtraStorage;
    mExtraStorage = loadedExtraStorage;
    if (previousExtraStorage != nullptr) {
      if (previousExtraStorage->mEconomy != nullptr) {
        (void)previousExtraStorage->Chng(-1);
      }
      ::operator delete(previousExtraStorage);
    }

    bool sharingEnabled = (mResourceSharing != 0u);
    archive->ReadBool(&sharingEnabled);
    mResourceSharing = static_cast<std::uint8_t>(sharingEnabled ? 1u : 0u);

    DeserializeRequests(archive);
  }

  /**
   * Address: 0x007742F0 (FUN_007742F0)
   *
   * What it does:
   * Jump-thunk lane that forwards archive/object registers into
   * `CEconomy::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEconomyMemberThunkA(
    gpg::ReadArchive* const archive,
    CEconomy* const economy
  )
  {
    economy->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00774510 (FUN_00774510)
   *
   * What it does:
   * Secondary jump-thunk lane forwarding directly to
   * `CEconomy::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEconomyMemberThunkB(
    gpg::ReadArchive* const archive,
    CEconomy* const economy
  )
  {
    economy->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00774860 (FUN_00774860, Moho::CEconomy::MemberSerialize)
   *
   * What it does:
   * Serializes Sim owner, index/value lanes, totals, storage pointer ownership,
   * sharing flag, then emits the intrusive CEconRequest chain terminator.
   */
  void CEconomy::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    gpg::WriteRawPointer(
      archive,
      MakeTypedRef(mSim, CachedSimType()),
      gpg::TrackedPointerState::Unowned,
      nullOwner
    );

    archive->WriteInt(mIndex);
    archive->Write(CachedSEconValueType(), &mResources, nullOwner);
    archive->Write(CachedSEconValueType(), &mPendingResources, nullOwner);
    archive->Write(CachedSEconTotalsType(), &mTotals, nullOwner);

    gpg::WriteRawPointer(
      archive,
      MakeTypedRef(mExtraStorage, CachedCEconStorageType()),
      gpg::TrackedPointerState::Owned,
      nullOwner
    );

    archive->WriteBool(mResourceSharing != 0u);
    SerializeRequests(archive);
  }

  /**
   * Address: 0x005641F0 (FUN_005641F0, Moho::SEconTotals::MemberDeserialize)
   *
   * What it does:
   * Reads five `SEconPair` lanes through the reflected `SEconValue` type,
   * then reads `mMaxStorage` as two u64 lanes (`ENERGY`, `MASS`).
   */
  void SEconTotals::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    gpg::RType* const econValueType = CachedSEconValueType();
    archive->Read(econValueType, &mStored, nullOwner);
    archive->Read(econValueType, &mIncome, nullOwner);
    archive->Read(econValueType, &mReclaimed, nullOwner);
    archive->Read(econValueType, &mLastUseRequested, nullOwner);
    archive->Read(econValueType, &mLastUseActual, nullOwner);
    archive->ReadUInt64(&mMaxStorage.ENERGY);
    archive->ReadUInt64(&mMaxStorage.MASS);
  }

  /**
   * Address: 0x00564320 (FUN_00564320, Moho::SEconTotals::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::SEconTotals::MemberSerialize(BinaryWriteArchive *a1@<edi>, Moho::SEconTotals *a2@<esi>);
   *
   * What it does:
   * Writes the five SEconPair resource lanes (stored, income, reclaimed,
   * requested, actual) using the cached SEconValue RType, then emits the
   * u64 max-storage energy/mass fields through the archive's WriteUInt64
   * virtual slot. Mirrors the binary's lazy LookupRType caching sequence.
   */
  void SEconTotals::MemberSerialize(gpg::WriteArchive* const archive)
  {
    const gpg::RRef nullOwner{};

    gpg::RType* const econValueType = CachedSEconValueType();
    archive->Write(econValueType, &mStored, nullOwner);
    archive->Write(econValueType, &mIncome, nullOwner);
    archive->Write(econValueType, &mReclaimed, nullOwner);
    archive->Write(econValueType, &mLastUseRequested, nullOwner);
    archive->Write(econValueType, &mLastUseActual, nullOwner);

    archive->WriteUInt64(mMaxStorage.ENERGY);
    archive->WriteUInt64(mMaxStorage.MASS);
  }

  /**
   * Address: 0x00585920 (FUN_00585920, Moho::SEconTotals::MaxStorageOf)
   *
   * What it does:
   * Returns selected max-storage resource lane as a floating-point scalar.
   */
  double SEconTotals::MaxStorageOf(const EEconResource resource) const noexcept
  {
    const std::uint64_t* const maxStorageLanes = &mMaxStorage.ENERGY;
    return static_cast<double>(maxStorageLanes[static_cast<std::uint32_t>(resource)]);
  }
} // namespace moho

namespace
{
  struct CEconomyConstructHelperBootstrap
  {
    CEconomyConstructHelperBootstrap()
    {
      (void)moho::InitializeCEconomySerializerHelperStorage();
      (void)moho::InitializeCEconomyConstructHelperStartup();
    }
  };

  [[maybe_unused]] CEconomyConstructHelperBootstrap gCEconomyConstructHelperBootstrap;
} // namespace

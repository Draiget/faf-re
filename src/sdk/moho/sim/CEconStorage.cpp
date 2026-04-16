#include "moho/sim/CEconStorage.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CEconomy.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  gpg::RRef* RRef_CEconStorage(gpg::RRef* outRef, moho::CEconStorage* value);
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    if (moho::CEconStorage::sType == nullptr) {
      moho::CEconStorage::sType = gpg::LookupRType(typeid(moho::CEconStorage));
    }
    return moho::CEconStorage::sType;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (moho::SEconValue::sType == nullptr) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
  }

  struct SerHelperNodeRuntime
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
    gpg::RType::construct_func_t mConstructCallback = nullptr;
    gpg::RType::delete_func_t mDeleteCallback = nullptr;
  };
  static_assert(offsetof(SerHelperNodeRuntime, mNext) == 0x04, "SerHelperNodeRuntime::mNext offset must be 0x04");
  static_assert(offsetof(SerHelperNodeRuntime, mPrev) == 0x08, "SerHelperNodeRuntime::mPrev offset must be 0x08");
  static_assert(sizeof(SerHelperNodeRuntime) == 0x14, "SerHelperNodeRuntime size must be 0x14");

  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
  constexpr int kSerializationConstructLine = 231;

  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(SerHelperNodeRuntime& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  void InitializeHelperNode(SerHelperNodeRuntime& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(SerHelperNodeRuntime& helper) noexcept
  {
    helper.mNext->mPrev = helper.mPrev;
    helper.mPrev->mNext = helper.mNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  SerHelperNodeRuntime gCEconStorageConstructHelper{};
  SerHelperNodeRuntime gCEconStorageSerializerHelper{};

  /**
   * Address: 0x00773490 (FUN_00773490)
   *
   * What it does:
   * Unlinks startup `CEconStorageConstruct` helper links and rewires the node
   * into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconStorageConstructNodeVariantA() noexcept
  {
    return UnlinkHelperNode(gCEconStorageConstructHelper);
  }

  /**
   * Address: 0x007734C0 (FUN_007734C0)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `CEconStorageConstruct` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconStorageConstructNodeVariantB() noexcept
  {
    return UnlinkHelperNode(gCEconStorageConstructHelper);
  }

  /**
   * Address: 0x007735B0 (FUN_007735B0)
   *
   * What it does:
   * Unlinks startup `CEconStorageSerializer` helper links and rewires the node
   * into one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconStorageSerializerNodeVariantA() noexcept
  {
    return UnlinkHelperNode(gCEconStorageSerializerHelper);
  }

  /**
   * Address: 0x007735E0 (FUN_007735E0)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `CEconStorageSerializer` helper
   * links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCEconStorageSerializerNodeVariantB() noexcept
  {
    return UnlinkHelperNode(gCEconStorageSerializerHelper);
  }

  /**
   * Address: 0x00773DA0 (FUN_00773DA0, Moho::CEconStorageConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Resolves `CEconStorage` RTTI and installs startup construct/delete
   * callbacks from one construct-helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType::construct_func_t RegisterCEconStorageConstructCallbacks(
    SerHelperNodeRuntime* const helper
  )
  {
    gpg::RType* const type = CachedCEconStorageType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }

    type->serConstructFunc_ = helper->mConstructCallback;
    type->deleteFunc_ = helper->mDeleteCallback;
    return helper->mConstructCallback;
  }

  /**
   * Address: 0x007734F0 (FUN_007734F0, Moho::CEconStorageConstruct::Construct)
   *
   * What it does:
   * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
   * publishes the object as an unowned construct result.
   */
  [[maybe_unused]] void ConstructCEconStorageSerializerCallback(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    if (result == nullptr) {
      return;
    }

    auto* const storage = new (std::nothrow) moho::CEconStorage{};
    gpg::RRef storageRef{};
    gpg::RRef_CEconStorage(&storageRef, storage);
    result->SetUnowned(storageRef, 0u);
  }

  /**
   * Address: 0x00774350 (FUN_00774350, Moho::CEconStorageConstruct::Deconstruct)
   *
   * What it does:
   * Removes one storage contribution from owning economy totals when present,
   * then releases the storage object.
   */
  [[maybe_unused]] void DeconstructCEconStorageSerializerCallback(moho::CEconStorage* const storage)
  {
    if (storage == nullptr) {
      return;
    }

    if (storage->mEconomy != nullptr) {
      (void)storage->Chng(-1);
    }
    ::operator delete(storage);
  }

  /**
   * Address: 0x00773560 (FUN_00773560, Moho::CEconStorageSerializer::Deserialize)
   *
   * What it does:
   * Forwards serializer-load callback lanes into `CEconStorage::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCEconStorageSerializerCallback(
    gpg::ReadArchive* const archive,
    moho::CEconStorage* const storage
  )
  {
    if (storage != nullptr) {
      storage->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x00773570 (FUN_00773570, Moho::CEconStorageSerializer::Serialize)
   *
   * What it does:
   * Forwards serializer-save callback lanes into `CEconStorage::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEconStorageSerializerCallback(
    gpg::WriteArchive* const archive,
    moho::CEconStorage* const storage
  )
  {
    if (storage != nullptr) {
      storage->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00773460 (FUN_00773460)
   *
   * What it does:
   * Initializes startup `CEconStorageConstruct` helper links and binds
   * construct/deconstruct callback lanes.
   */
  [[nodiscard]] SerHelperNodeRuntime* InitializeCEconStorageConstructHelperStorage() noexcept
  {
    InitializeHelperNode(gCEconStorageConstructHelper);
    gCEconStorageConstructHelper.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCEconStorageSerializerCallback);
    gCEconStorageConstructHelper.mDeleteCallback =
      reinterpret_cast<gpg::RType::delete_func_t>(&DeconstructCEconStorageSerializerCallback);
    return &gCEconStorageConstructHelper;
  }

  /**
   * Address: 0x00773580 (FUN_00773580)
   *
   * What it does:
   * Initializes startup `CEconStorageSerializer` helper links and binds
   * deserialize/serialize callback lanes.
   */
  [[nodiscard]] SerHelperNodeRuntime* InitializeCEconStorageSerializerHelperStorage() noexcept
  {
    InitializeHelperNode(gCEconStorageSerializerHelper);
    gCEconStorageSerializerHelper.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&DeserializeCEconStorageSerializerCallback);
    gCEconStorageSerializerHelper.mDeleteCallback =
      reinterpret_cast<gpg::RType::delete_func_t>(&SerializeCEconStorageSerializerCallback);
    return &gCEconStorageSerializerHelper;
  }

  /**
   * Address: 0x00774B80 (FUN_00774B80)
   *
   * What it does:
   * Serializes one `CEconomy*` slot as an unowned tracked pointer and returns
   * the archive for callback chaining.
   */
  [[nodiscard]] gpg::WriteArchive*
  SerializeUnownedCEconomyPointer(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || economySlot == nullptr) {
      return archive;
    }

    gpg::RRef economyRef{};
    economyRef.mObj = *economySlot;
    economyRef.mType = gpg::LookupRType(typeid(moho::CEconomy));
    GPG_ASSERT(economyRef.mType != nullptr);
    gpg::WriteRawPointer(archive, economyRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    return archive;
  }

  /**
   * Address: 0x00774BC0 (FUN_00774BC0)
   *
   * What it does:
   * Binary-write callback variant of unowned `CEconomy*` slot serialization.
   */
  [[maybe_unused]] void
  SerializeUnownedCEconomyPointerBinary(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    (void)SerializeUnownedCEconomyPointer(economySlot, archive);
  }
} // namespace

namespace moho
{
  gpg::RType* CEconStorage::sType = nullptr;

  /**
   * Address: 0x00773270 (FUN_00773270)
   *
   * What it does:
   * Removes one storage contribution from owning economy max-storage totals
   * when this storage lane is currently bound to an economy.
   */
  [[maybe_unused]] [[nodiscard]] CEconStorage* RemoveCEconStorageContributionIfBound(CEconStorage* const storage)
  {
    if (storage->mEconomy != nullptr) {
      (void)storage->Chng(-1);
    }
    return storage;
  }

  /**
   * Address: 0x00773250 (FUN_00773250, Moho::CEconStorage::CEconStorage)
   *
   * What it does:
   * Binds one economy owner pointer, copies amount lanes, and applies this
   * storage lane into economy max-storage totals.
   */
  CEconStorage::CEconStorage(const SEconValue& amount, CEconomy* const economy)
  {
    mEconomy = economy;
    mAmt = amount;
    (void)Chng(1);
  }

  /**
   * Address: 0x00773280 (FUN_00773280, Moho::CEconStorage::ChangeAmt)
   *
   * What it does:
   * Removes previous amount contribution, copies new amount lanes, then
   * reapplies contribution to economy max-storage totals.
   */
  std::int64_t CEconStorage::ChangeAmt(const SEconValue& amount)
  {
    (void)Chng(-1);
    mAmt = amount;
    return Chng(1);
  }

  /**
   * Address: 0x00773500 (FUN_00773500, Moho::CEconStorage::MemberConstruct)
   *
   * What it does:
   * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
   * publishes the object as an unowned construct result.
   */
  void CEconStorage::MemberConstruct(
    gpg::ReadArchive&,
    const int,
    const gpg::RRef&,
    gpg::SerConstructResult& result
  )
  {
    auto* const storage = new (std::nothrow) CEconStorage{};

    gpg::RRef storageRef{};
    storageRef.mObj = storage;
    storageRef.mType = CachedCEconStorageType();
    result.SetUnowned(storageRef, 0u);
  }

  /**
   * Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
   *
   * What it does:
   * Applies this storage lane as a signed delta (`direction` is typically
   * `+1` or `-1`) into owning economy max-storage counters.
   */
  std::int64_t CEconStorage::Chng(const std::int32_t direction)
  {
    if (mEconomy == nullptr) {
      return 0;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    const float amounts[2] = {mAmt.energy, mAmt.mass};
    std::uint64_t* const totals[2] = {&mEconomy->mTotals.mMaxStorage.ENERGY, &mEconomy->mTotals.mMaxStorage.MASS};

    std::int64_t result = 0;
    for (int lane = 0; lane < 2; ++lane) {
      result = static_cast<std::int64_t>(amounts[lane]) * signedDirection;
      *totals[lane] += static_cast<std::uint64_t>(result);
    }
    return result;
  }

  /**
   * Address: 0x00774990 (FUN_00774990, Moho::CEconStorage::MemberDeserialize)
   *
   * What it does:
   * Deserializes referenced economy owner pointer, then reads one reflected
   * `SEconValue` payload lane.
   */
  void CEconStorage::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_CEconomy(&mEconomy, &nullOwner);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Read(econValueType, &mAmt, nullOwner);
  }

  /**
   * Address: 0x007749F0 (FUN_007749F0, Moho::CEconStorage::MemberSerialize)
   *
   * What it does:
   * Serializes referenced economy owner as an unowned pointer, then writes
   * one reflected `SEconValue` payload lane.
   */
  void CEconStorage::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)SerializeUnownedCEconomyPointer(&mEconomy, archive);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Write(econValueType, &mAmt, nullOwner);
  }

  /**
   * Address: 0x007743D0 (FUN_007743D0)
   *
   * What it does:
   * Tail-thunk alias that forwards econ-storage save lanes into
   * `CEconStorage::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEconStorageThunkA(
    CEconStorage* const storage,
    gpg::WriteArchive* const archive
  )
  {
    if (storage != nullptr) {
      storage->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x00774540 (FUN_00774540)
   *
   * What it does:
   * Secondary tail-thunk alias that forwards econ-storage save lanes into
   * `CEconStorage::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCEconStorageThunkB(
    CEconStorage* const storage,
    gpg::WriteArchive* const archive
  )
  {
    if (storage != nullptr) {
      storage->MemberSerialize(archive);
    }
  }
} // namespace moho

namespace
{
  struct CEconStorageHelperBootstrap
  {
    CEconStorageHelperBootstrap()
    {
      (void)InitializeCEconStorageConstructHelperStorage();
      (void)InitializeCEconStorageSerializerHelperStorage();
    }
  };

  [[maybe_unused]] CEconStorageHelperBootstrap gCEconStorageHelperBootstrap;
} // namespace

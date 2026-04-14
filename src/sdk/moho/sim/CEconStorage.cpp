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
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCEconStorageType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::CEconStorage));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (moho::SEconValue::sType == nullptr) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
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
} // namespace moho

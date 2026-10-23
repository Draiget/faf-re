#include "moho/sim/CEconStorage.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CEconomy.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (moho::SEconValue::sType == nullptr) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
  }
} // namespace

namespace moho
{
  gpg::RType* CEconStorage::sType = nullptr;

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
    Chng(1);
  }

  /**
   * Address: 0x00773280 (FUN_00773280, Moho::CEconStorage::ChangeAmt)
   *
   * What it does:
   * Removes previous amount contribution, copies new amount lanes, then
   * reapplies contribution to economy max-storage totals.
   */
  void CEconStorage::ChangeAmt(const SEconValue& amount)
  {
    Chng(-1);
    mAmt = amount;
    Chng(1);
  }

  /**
   * Address: 0x00773270 (FUN_00773270)
   */
  CEconStorage::~CEconStorage()
  {
    if (mEconomy != nullptr) {
      Chng(-1);
    }
  }

  /**
   * Address: 0x00773500 (FUN_00773500, Moho::CEconStorage::MemberConstruct)
   *
   * What it does:
   * Allocates one `CEconStorage`, zero-initializes owner/value lanes, and
   * publishes the object as an unowned construct result.
   */
  void CEconStorage::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CEconStorage()), 0u);
  }

  /**
   * Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
   *
   * What it does:
   * Applies this storage lane as a signed delta (`direction` is typically
   * `+1` or `-1`) into owning economy max-storage counters.
   */
  void CEconStorage::Chng(const std::int32_t direction)
  {
    SEconStoragePair& maxStorage = mEconomy->mTotals.mMaxStorage;
    maxStorage.ENERGY += static_cast<std::int64_t>(mAmt.energy) * direction;
    maxStorage.MASS += static_cast<std::int64_t>(mAmt.mass) * direction;
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

    (void)archive->ReadPointer(&mEconomy, &nullOwner);

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
  void CEconStorage::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    archive->WritePointer(mEconomy, gpg::TrackedPointerState::Unowned, nullOwner);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Write(econValueType, &mAmt, nullOwner);
  }

} // namespace moho

namespace moho
{
  /**
   * `gpg::SerConstructHelper<CEconStorage>`, vtable 0x00E36DF0.
   *
   * Address: 0x00BDD170 (FUN_00BDD170 -- constructs the global and registers its destructor.)
   * Address: 0x00C02310 (FUN_00C02310 -- the global's destructor.)
   * Address: 0x00773460 (FUN_00773460 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00773DA0 (FUN_00773DA0 -- `Init`.)
   * Address: 0x007734F0 (FUN_007734F0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x00774350 (FUN_00774350 -- `Delete`.)
   */
  struct CEconStorageConstruct : gpg::SerConstructHelper<CEconStorage>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CEconStorage>`, vtable 0x00E36E00.
   *
   * Address: 0x00BDD1B0 (FUN_00BDD1B0 -- constructs the global and registers its destructor.)
   * Address: 0x00C02340 (FUN_00C02340 -- the global's destructor.)
   * Address: 0x00773580 (FUN_00773580 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00773E20 (FUN_00773E20 -- `Init`.)
   * Address: 0x00773560 (FUN_00773560 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00773570 (FUN_00773570 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CEconStorageSerializer : gpg::SerSaveLoadHelper<CEconStorage>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BB914 -- process-global `CEconStorageConstruct` singleton.
  moho::CEconStorageConstruct gCEconStorageConstruct;

  // Address: 0x010BB7F4 -- process-global `CEconStorageSerializer` singleton.
  moho::CEconStorageSerializer gCEconStorageSerializer;
} // namespace

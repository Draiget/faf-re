#include "CEconomy.h"

#include <typeinfo>
#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/Sim.h"

namespace
{
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
    }
    return moho::SEconValue::sType;
  }

  [[nodiscard]] gpg::RType* CachedSEconTotalsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SEconTotals));
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

  [[nodiscard]] moho::CEconRequest* RequestFromNode(moho::TDatListItem<void, void>* const node) noexcept
  {
    return reinterpret_cast<moho::CEconRequest*>(node);
  }
} // namespace

namespace moho
{
  gpg::RType* CEconomy::sType = nullptr;

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
} // namespace moho

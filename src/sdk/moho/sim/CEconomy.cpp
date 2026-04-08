#include "CEconomy.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
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
} // namespace moho

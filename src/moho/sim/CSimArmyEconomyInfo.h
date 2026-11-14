#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconStorage;
  class Sim;
  enum EEconResource : std::int32_t;
  using IntrusiveNode = TDatListItem<void, void>;

  struct SEconPair
  {
    float ENERGY;
    float MASS;
  };

  struct SEconStoragePair
  {
    std::uint64_t ENERGY;
    std::uint64_t MASS;
  };

  struct SEconTotals
  {
    SEconPair mStored;
    SEconPair mIncome;
    SEconPair mReclaimed;
    SEconPair mLastUseRequested;
    SEconPair mLastUseActual;
    SEconStoragePair mMaxStorage;

    /**
     * Address: 0x005641F0 (FUN_005641F0, Moho::SEconTotals::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall Moho::SEconTotals::MemberDeserialize(ReadArchive *a1@<esi>, Moho::SEconTotals *a2@<eax>);
     *
     * What it does:
     * Reads the five `SEconPair` lanes via reflected `SEconValue` type data,
     * then reads max-storage `ENERGY`/`MASS` u64 lanes through `ReadUInt64`.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00564320 (FUN_00564320, Moho::SEconTotals::MemberSerialize)
     *
     * IDA signature:
     * void __usercall Moho::SEconTotals::MemberSerialize(BinaryWriteArchive *a1@<edi>, Moho::SEconTotals *a2@<esi>);
     *
     * What it does:
     * Writes the five SEconPair resource lanes via the reflected SEconValue
     * serializer, then emits the u64 energy/mass max-storage fields through
     * the archive's WriteUInt64 virtual slot.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00585920 (FUN_00585920, Moho::SEconTotals::MaxStorageOf)
     *
     * What it does:
     * Returns the max-storage lane (`ENERGY`/`MASS`) selected by one
     * `EEconResource` enum value as a floating-point scalar.
     */
    [[nodiscard]] double MaxStorageOf(EEconResource resource) const noexcept;
  };

  // The per-army economy object itself is `moho::CEconomy` (moho/sim/CEconomy.h):
  // `CArmyImpl` allocates one (ctor 0x00771880) and `GetEconomy()` (0x006FDCB0)
  // returns it. This header used to carry a second, field-for-field copy of
  // it named `CSimArmyEconomyInfo`; the binary has only the one type.

  static_assert(sizeof(IntrusiveNode) == 0x8, "IntrusiveNode size must be 0x8");
  static_assert(sizeof(SEconPair) == 0x8, "SEconPair size must be 0x8");
  static_assert(sizeof(SEconStoragePair) == 0x10, "SEconStoragePair size must be 0x10");
  static_assert(offsetof(SEconTotals, mMaxStorage) == 0x28, "SEconTotals::mMaxStorage offset must be 0x28");
  static_assert(sizeof(SEconTotals) == 0x38, "SEconTotals size must be 0x38");
} // namespace moho

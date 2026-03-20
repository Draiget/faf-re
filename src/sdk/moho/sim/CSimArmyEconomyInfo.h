#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"

namespace moho
{
  class CEconStorage;
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
  };

  class CSimArmyEconomyInfo
  {
  public:
    std::uint8_t _pad_00[0x18];
    SEconTotals economy;                   // +0x18
    CEconStorage* storageDelta;            // +0x50
    std::uint8_t isResourceSharingEnabled; // +0x54
    std::uint8_t _pad_55[3];
    IntrusiveNode registrationNode; // +0x58
  };

  static_assert(sizeof(IntrusiveNode) == 0x8, "IntrusiveNode size must be 0x8");
  static_assert(sizeof(SEconPair) == 0x8, "SEconPair size must be 0x8");
  static_assert(sizeof(SEconStoragePair) == 0x10, "SEconStoragePair size must be 0x10");
  static_assert(offsetof(SEconTotals, mMaxStorage) == 0x28, "SEconTotals::mMaxStorage offset must be 0x28");
  static_assert(sizeof(SEconTotals) == 0x38, "SEconTotals size must be 0x38");
  static_assert(offsetof(CSimArmyEconomyInfo, economy) == 0x18, "CSimArmyEconomyInfo::economy offset must be 0x18");
  static_assert(
    offsetof(CSimArmyEconomyInfo, storageDelta) == 0x50, "CSimArmyEconomyInfo::storageDelta offset must be 0x50"
  );
  static_assert(
    offsetof(CSimArmyEconomyInfo, isResourceSharingEnabled) == 0x54,
    "CSimArmyEconomyInfo::isResourceSharingEnabled offset must be 0x54"
  );
  static_assert(
    offsetof(CSimArmyEconomyInfo, registrationNode) == 0x58, "CSimArmyEconomyInfo::registrationNode offset must be 0x58"
  );
  static_assert(sizeof(CSimArmyEconomyInfo) == 0x60, "CSimArmyEconomyInfo size must be 0x60");
} // namespace moho

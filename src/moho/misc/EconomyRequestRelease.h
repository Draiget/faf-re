#pragma once

// Takes what an economy request was granted, and frees a request, for the tasks that hold one.

#include "moho/misc/CEconomyEvent.h"

namespace moho
{
  /**
   * Address: 0x00773740 (FUN_00773740, sub_773740)
   */
  [[nodiscard]] inline moho::SEconValue TakeGrantedResourcesAndReset(moho::CEconRequest* const request) noexcept
  {
    moho::SEconValue out{};
    out.energy = request->mGranted.energy;
    out.mass = request->mGranted.mass;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;
    return out;
  }

  /**
   * Address: 0x005CFA20 (sub_5CFA20)
   *
   * Alias of FUN_005CFA20 (non-canonical helper lane).
   */
  inline void DestroyEconomyRequestPointer(moho::CEconRequest*& request)
  {
    if (request == nullptr) {
      return;
    }

    request->mNode.ListUnlink();
    delete request;
    request = nullptr;
  }
} // namespace moho

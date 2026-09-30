#include "moho/ai/IAiFormationDB.h"

#include <new>

#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

/**
 * Address: 0x0059C360 (FUN_0059C360)
 */
IAiFormationDB::IAiFormationDB() = default;

/**
 * Address: 0x0059A3C0 (FUN_0059A3C0)
 *
 * What it does:
 * Alternate in-place constructor adapter for one IAiFormationDB interface
 * subobject lane.
 */
[[maybe_unused]] IAiFormationDB* InitializeIAiFormationDBInterfaceLane(
  IAiFormationDB* const objectStorage
) noexcept
{
  if (objectStorage == nullptr) {
    return nullptr;
  }

  return objectStorage;
}

/**
 * Address: 0x0059A3D0 (FUN_0059A3D0)
 */
IAiFormationDB::~IAiFormationDB() = default;

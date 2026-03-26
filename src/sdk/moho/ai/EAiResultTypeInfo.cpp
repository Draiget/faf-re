#include "moho/ai/EAiResultTypeInfo.h"

#include "moho/ai/EAiResult.h"

using namespace moho;

/**
 * Address: 0x00608C00 (FUN_00608C00, scalar deleting thunk)
 */
EAiResultTypeInfo::~EAiResultTypeInfo() = default;

/**
 * Address: 0x00608BF0 (FUN_00608BF0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiResult.
 */
const char* EAiResultTypeInfo::GetName() const
{
  return "EAiResult";
}

/**
 * Address: 0x00608BD0 (FUN_00608BD0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiResultTypeInfo::Init()
{
  size_ = sizeof(EAiResult);
  gpg::RType::Init();
  Finish();
}

#include "moho/render/EmitterTypeTypeInfo.h"

#include "moho/render/EmitterType.h"

using namespace moho;

/**
 * Address: 0x0065DF40 (FUN_0065DF40, scalar deleting thunk)
 */
EmitterTypeTypeInfo::~EmitterTypeTypeInfo() = default;

/**
 * Address: 0x0065DF30 (FUN_0065DF30)
 *
 * What it does:
 * Returns the reflection type name literal for EmitterType.
 */
const char* EmitterTypeTypeInfo::GetName() const
{
  return "EmitterType";
}

/**
 * Address: 0x0065DF10 (FUN_0065DF10)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EmitterTypeTypeInfo::Init()
{
  size_ = sizeof(EmitterType);
  gpg::RType::Init();
  Finish();
}

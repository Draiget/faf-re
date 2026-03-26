#include "moho/script/CUnitScriptTaskSerializer.h"

#include <typeinfo>

#include "moho/script/CUnitScriptTask.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    gpg::RType* type = CUnitScriptTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CUnitScriptTask));
      CUnitScriptTask::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x00623BB0 (FUN_00623BB0)
 */
void CUnitScriptTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCUnitScriptTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}


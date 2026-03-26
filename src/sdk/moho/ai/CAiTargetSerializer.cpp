#include "moho/ai/CAiTargetSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiTarget.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTarget));
      CAiTarget::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E3540 (FUN_005E3540)
 *
 * What it does:
 * Lazily resolves CAiTarget RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiTargetSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiTargetType();
  const gpg::RType::load_func_t loadCallback = mLoadCallback ? mLoadCallback : &CAiTarget::DeserializeFromArchive;
  const gpg::RType::save_func_t saveCallback = mSaveCallback ? mSaveCallback : &CAiTarget::SerializeToArchive;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = loadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = saveCallback;
}

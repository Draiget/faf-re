#include "gpg/core/containers/SerSaveLoadHelper_Box3f.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedBox3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Box3<float>));
    }
    return cached;
  }
} // namespace

namespace gpg
{
  /**
    * Alias of FUN_004756D0 (non-canonical helper lane).
   */
  void SerSaveLoadHelper_Box3f::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedBox3fType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace gpg


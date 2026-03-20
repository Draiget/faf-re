#include "CAniDefaultSkelConstruct.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/animation/CAniDefaultSkel.h"

namespace
{
  gpg::RType* CachedDefaultSkelType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAniDefaultSkel));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0054C550 (FUN_0054C550)
   *
   * What it does:
   * Binds construct/delete callbacks into `CAniDefaultSkel` RTTI.
   */
  void CAniDefaultSkelConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedDefaultSkelType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }
} // namespace moho

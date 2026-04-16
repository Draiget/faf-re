#include "CAniDefaultSkelSaveConstruct.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/animation/CAniDefaultSkel.h"

namespace
{
  gpg::RType* CachedDefaultSkelType()
  {
    gpg::RType* cached = moho::CAniDefaultSkel::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CAniDefaultSkel));
      moho::CAniDefaultSkel::sType = cached;
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0054C4D0 (FUN_0054C4D0)
   *
   * What it does:
   * Binds save-construct-args callback into `CAniDefaultSkel` RTTI.
   */
  void CAniDefaultSkelSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedDefaultSkelType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }
} // namespace moho

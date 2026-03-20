#include "RTrailBlueprintConstruct.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"

namespace
{
  gpg::RType* CachedTrailBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RTrailBlueprint));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510700 (FUN_00510700, sub_510700)
   *
   * What it does:
   * Binds construct/delete callbacks into RTrailBlueprint RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void RTrailBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedTrailBlueprintType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }
} // namespace moho

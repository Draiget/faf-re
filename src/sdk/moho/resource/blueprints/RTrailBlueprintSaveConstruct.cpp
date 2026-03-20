#include "RTrailBlueprintSaveConstruct.h"

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
   * Address: 0x00510680 (FUN_00510680, sub_510680)
   *
   * What it does:
   * Binds save-construct-args callback into RTrailBlueprint RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void RTrailBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedTrailBlueprintType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }
} // namespace moho

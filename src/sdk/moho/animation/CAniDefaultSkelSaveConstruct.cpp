#include "CAniDefaultSkelSaveConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/animation/CAniDefaultSkel.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int flags);
  };
} // namespace gpg

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

  /**
   * Address: 0x0054AAA0 (FUN_0054AAA0)
   *
   * What it does:
   * `CAniDefaultSkel` construction takes no per-instance archive data (it
   * always resolves the shared process-wide default skeleton), so this
   * save-construct-args callback only marks the result as owned.
   */
  void SaveDefaultSkelConstructArgsOwned(
    gpg::WriteArchive* const, const int, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    if (result != nullptr) {
      result->SetOwned(1u);
    }
  }

  // Address: 0x010AC334 -- process-global `CAniDefaultSkelSaveConstruct`
  // singleton. Constructing it runs CAniDefaultSkelSaveConstruct::
  // CAniDefaultSkelSaveConstruct() (0x00BC98D0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within
  // the first ReadArchive/WriteArchive construction.
  moho::CAniDefaultSkelSaveConstruct gCAniDefaultSkelSaveConstruct;

  /**
   * Address: 0x00BF4540 (FUN_00BF4540)
   *
   * What it does:
   * Unlinks the `CAniDefaultSkelSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC98D0) as the
   * global's `atexit` teardown. `FUN_0054AAB0` and `FUN_0054AAE0` are
   * duplicate-emission twins of this exact unlink/reset lane (same
   * `ResetLinks()` shape, folded to separate addresses); they have no
   * distinct source-level body of their own.
   */
  void CleanupCAniDefaultSkelSaveConstruct()
  {
    gCAniDefaultSkelSaveConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC98D0 (FUN_00BC98D0, dynamic initializer for the global
   * `CAniDefaultSkelSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  CAniDefaultSkelSaveConstruct::CAniDefaultSkelSaveConstruct()
    : mSerSaveConstructArgsFunc(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveDefaultSkelConstructArgsOwned)
      )
  {
    (void)std::atexit(&CleanupCAniDefaultSkelSaveConstruct);
  }

  /**
   * Address: 0x0054C4D0 (FUN_0054C4D0)
   *
   * What it does:
   * Binds save-construct-args callback into `CAniDefaultSkel` RTTI.
   */
  void CAniDefaultSkelSaveConstruct::Init()
  {
    gpg::RType* const type = CachedDefaultSkelType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }
} // namespace moho

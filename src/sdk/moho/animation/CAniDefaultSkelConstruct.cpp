#include "CAniDefaultSkelConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/animation/CAniDefaultSkel.h"

namespace gpg
{
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  void SetConstructResultSharedAniSkel(
    gpg::SerConstructResult* result, const boost::shared_ptr<const CAniSkel>& skeleton
  );
} // namespace moho

namespace
{
  struct ScalarDeleteVTable
  {
    using deleting_dtor_t = int(__thiscall*)(void* self, int deleteFlag);
    deleting_dtor_t mDeletingDtor;
  };

  struct ScalarDeleteObject
  {
    ScalarDeleteVTable* mVTable;
  };

  /**
   * Address: 0x0054CFC0 (FUN_0054CFC0)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `CAniDefaultSkel`.
   */
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
   * Address: 0x0054ABB0 (FUN_0054ABB0)
   *
   * What it does:
   * Publishes the process-wide default skeleton as a shared `CAniSkel`
   * construct-result payload.
   */
  void ConstructDefaultSkeletonSharedObject(
    gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result
  )
  {
    if (result == nullptr) {
      return;
    }

    const boost::shared_ptr<const moho::CAniSkel> skeleton = moho::CAniSkel::GetDefaultSkeleton();
    moho::SetConstructResultSharedAniSkel(result, skeleton);
  }

  /**
   * Address: 0x0054DE50 (FUN_0054DE50)
   *
   * What it does:
   * Invokes the scalar deleting-destructor lane for a default skeleton object.
   */
  void DeleteDefaultSkelObject(void* const object)
  {
    if (object == nullptr) {
      return;
    }

    auto* const scalarDeleteObject = static_cast<ScalarDeleteObject*>(object);
    scalarDeleteObject->mVTable->mDeletingDtor(object, 1);
  }

  // Address: 0x010AC254 -- process-global `CAniDefaultSkelConstruct`
  // singleton. Constructing it runs CAniDefaultSkelConstruct::
  // CAniDefaultSkelConstruct() (0x00BC9900), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction.
  moho::CAniDefaultSkelConstruct gCAniDefaultSkelConstruct;

  /**
   * Address: 0x00BF4570 (FUN_00BF4570)
   *
   * What it does:
   * Unlinks the `CAniDefaultSkelConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC9900) as the
   * global's `atexit` teardown.
   */
  void CleanupCAniDefaultSkelConstruct()
  {
    gCAniDefaultSkelConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC9900 (FUN_00BC9900, dynamic initializer for the global
   * `CAniDefaultSkelConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  CAniDefaultSkelConstruct::CAniDefaultSkelConstruct()
    : mSerConstructFunc(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructDefaultSkeletonSharedObject))
    , mDeleteFunc(&DeleteDefaultSkelObject)
  {
    (void)std::atexit(&CleanupCAniDefaultSkelConstruct);
  }

  /**
   * Address: 0x0054C550 (FUN_0054C550)
   *
   * What it does:
   * Binds construct/delete callbacks into `CAniDefaultSkel` RTTI.
   */
  void CAniDefaultSkelConstruct::Init()
  {
    gpg::RType* const type = CachedDefaultSkelType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }
} // namespace moho

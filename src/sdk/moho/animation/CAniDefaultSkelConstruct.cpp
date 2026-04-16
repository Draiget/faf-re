#include "CAniDefaultSkelConstruct.h"

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
  moho::CAniDefaultSkelConstruct gCAniDefaultSkelConstruct{};

  struct ScalarDeleteVTable
  {
    using deleting_dtor_t = int(__thiscall*)(void* self, int deleteFlag);
    deleting_dtor_t mDeletingDtor;
  };

  struct ScalarDeleteObject
  {
    ScalarDeleteVTable* mVTable;
  };

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

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
   * Address: 0x0054DE50 (FUN_0054DE50)
   *
   * What it does:
   * Invokes the scalar deleting-destructor lane for a default skeleton object.
   */
  [[maybe_unused]] void DeleteDefaultSkelObject(void* const object)
  {
    if (object == nullptr) {
      return;
    }

    auto* const scalarDeleteObject = static_cast<ScalarDeleteObject*>(object);
    scalarDeleteObject->mVTable->mDeletingDtor(object, 1);
  }

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
   * Address: 0x0054C520 (FUN_0054C520)
   *
   * What it does:
   * Reinitializes startup helper storage for `CAniDefaultSkel` construct lane
   * callbacks and restore self-linked helper node pointers.
   */
  [[maybe_unused]] [[nodiscard]] moho::CAniDefaultSkelConstruct* InitializeCAniDefaultSkelConstructHelperStartupThunk()
  {
    InitializeHelperNode(gCAniDefaultSkelConstruct);
    gCAniDefaultSkelConstruct.mSerConstructFunc =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructDefaultSkeletonSharedObject);
    gCAniDefaultSkelConstruct.mDeleteFunc = &DeleteDefaultSkelObject;
    return &gCAniDefaultSkelConstruct;
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

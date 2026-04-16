#include "moho/entity/CollisionBeamEntityConstruct.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int flags);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;
  gpg::RType* gCollisionBeamEntityType = nullptr;
  moho::CollisionBeamEntitySaveConstruct gCollisionBeamEntitySaveConstruct{};
  moho::CollisionBeamEntityConstruct gCollisionBeamEntityConstruct{};

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return &helper.mHelperLinks;
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mNext = self;
    helper.mHelperLinks.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    helper.mHelperLinks.mNext->mPrev = helper.mHelperLinks.mPrev;
    helper.mHelperLinks.mPrev->mNext = helper.mHelperLinks.mNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mPrev = self;
    helper.mHelperLinks.mNext = self;
    return self;
  }

  /**
   * Address: 0x006739D0 (FUN_006739D0)
   *
   * What it does:
   * Unlinks the global `CollisionBeamEntityConstruct` helper node from
   * the intrusive serializer-helper list, then resets the node to self-links.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCollisionBeamEntityConstructHelperNode() noexcept
  {
    gCollisionBeamEntityConstruct.mHelperLinks.mNext->mPrev = gCollisionBeamEntityConstruct.mHelperLinks.mPrev;
    gCollisionBeamEntityConstruct.mHelperLinks.mPrev->mNext = gCollisionBeamEntityConstruct.mHelperLinks.mNext;

    gpg::SerHelperBase* const self = &gCollisionBeamEntityConstruct.mHelperLinks;
    gCollisionBeamEntityConstruct.mHelperLinks.mPrev = self;
    gCollisionBeamEntityConstruct.mHelperLinks.mNext = self;
    return self;
  }

  void CleanupCollisionBeamEntityConstructAtexit()
  {
    (void)moho::cleanup_CollisionBeamEntityConstruct();
  }

  void CleanupCollisionBeamEntitySaveConstructAtexit()
  {
    (void)moho::cleanup_CollisionBeamEntitySaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006738A0 (FUN_006738A0, CollisionBeamEntity save-construct args callback)
   */
  void CollisionBeamEntitySaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<CollisionBeamEntity*>(static_cast<std::uintptr_t>(objectPtr));
    if (!archive || !object) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = object->SimulationRef;
    ownerRef.mType = object->SimulationRef ? ResolveCachedType<Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result != nullptr) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x00674EB0 (FUN_00674EB0, initialize_CollisionBeamEntitySaveConstruct)
   */
  gpg::SerHelperBase* initialize_CollisionBeamEntitySaveConstruct()
  {
    InitializeHelperNode(gCollisionBeamEntitySaveConstruct);
    gCollisionBeamEntitySaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CollisionBeamEntitySaveConstruct::SaveConstructArgs);
    return &gCollisionBeamEntitySaveConstruct.mHelperLinks;
  }

  /**
   * Address: 0x00674EE0 (FUN_00674EE0, gpg::SerSaveConstructHelper_CollisionBeamEntity::Init)
   */
  void CollisionBeamEntitySaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ResolveCachedType<CollisionBeamEntity>(gCollisionBeamEntityType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00675590 (FUN_00675590, construct callback adapter)
   *
   * What it does:
   * Adapts construct-callback calling convention lanes into
   * `CollisionBeamEntity::MemberConstruct`.
   */
  [[maybe_unused]] void ForwardCollisionBeamEntityMemberConstruct(
    gpg::ReadArchive& archive,
    const int version,
    const gpg::RRef& ownerRef,
    gpg::SerConstructResult& result
  )
  {
    CollisionBeamEntity::MemberConstruct(archive, version, ownerRef, result);
  }

  /**
   * Address: 0x00673A30 (FUN_00673A30, Moho::CollisionBeamEntityConstruct::Construct)
   */
  void CollisionBeamEntityConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    if (!archive || !result) {
      return;
    }

    gpg::RRef ownerRef{};
    ForwardCollisionBeamEntityMemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x00675570 (FUN_00675570, Moho::CollisionBeamEntityConstruct::Deconstruct)
   */
  void CollisionBeamEntityConstruct::Deconstruct(void* const objectPtr)
  {
    delete static_cast<CollisionBeamEntity*>(objectPtr);
  }

  /**
   * Address: 0x00674F60 (FUN_00674F60, gpg::SerConstructHelper_CollisionBeamEntity::Init)
   *
   * What it does:
   * Resolves `CollisionBeamEntity` RTTI and installs construct/delete callback
   * lanes into reflected type metadata.
   */
  void CollisionBeamEntityConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ResolveCachedType<CollisionBeamEntity>(gCollisionBeamEntityType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00673A00 (FUN_00673A00, cleanup_CollisionBeamEntityConstruct)
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntityConstruct()
  {
    return UnlinkCollisionBeamEntityConstructHelperNode();
  }

  /**
   * Address: 0x00BFC340 (FUN_00BFC340, cleanup_CollisionBeamEntitySaveConstruct)
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySaveConstruct()
  {
    return UnlinkHelperNode(gCollisionBeamEntitySaveConstruct);
  }

  /**
   * Address: 0x00BD4C60 (FUN_00BD4C60, register_CollisionBeamEntitySaveConstruct)
   */
  int register_CollisionBeamEntitySaveConstruct()
  {
    (void)initialize_CollisionBeamEntitySaveConstruct();
    return std::atexit(&CleanupCollisionBeamEntitySaveConstructAtexit);
  }

  /**
   * Address: 0x00BD4C90 (FUN_00BD4C90, register_CollisionBeamEntityConstruct)
   */
  void register_CollisionBeamEntityConstruct()
  {
    InitializeHelperNode(gCollisionBeamEntityConstruct);
    gCollisionBeamEntityConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&CollisionBeamEntityConstruct::Construct);
    gCollisionBeamEntityConstruct.mDeleteCallback = &CollisionBeamEntityConstruct::Deconstruct;
    gCollisionBeamEntityConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupCollisionBeamEntityConstructAtexit);
  }
} // namespace moho

namespace
{
  struct CollisionBeamEntityConstructBootstrap
  {
    CollisionBeamEntityConstructBootstrap()
    {
      (void)moho::register_CollisionBeamEntitySaveConstruct();
      moho::register_CollisionBeamEntityConstruct();
    }
  };

  [[maybe_unused]] CollisionBeamEntityConstructBootstrap gCollisionBeamEntityConstructBootstrap;
} // namespace

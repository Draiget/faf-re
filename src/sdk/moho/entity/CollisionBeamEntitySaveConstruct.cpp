#include "moho/entity/CollisionBeamEntitySaveConstruct.h"

#include <cstdlib>
#include <cstdint>
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
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;
  moho::CollisionBeamEntitySaveConstruct gCollisionBeamEntitySaveConstruct{};

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
    if (helper.mHelperLinks.mNext != nullptr && helper.mHelperLinks.mPrev != nullptr) {
      helper.mHelperLinks.mNext->mPrev = helper.mHelperLinks.mPrev;
      helper.mHelperLinks.mPrev->mNext = helper.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mPrev = self;
    helper.mHelperLinks.mNext = self;
    return self;
  }

  /**
    * Alias of FUN_006738A0 (non-canonical helper lane).
   *
   * What it does:
   * Writes one unowned `Sim*` owner pointer for a collision-beam object into
   * save-construct payload and marks result ownership flags as unowned.
   */
  void SaveConstructArgs_CollisionBeamEntity(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::CollisionBeamEntity*>(static_cast<std::uintptr_t>(objectPtr));
    if (!archive || !object) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = object->SimulationRef;
    ownerRef.mType = object->SimulationRef ? ResolveCachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
    * Alias of FUN_00674EB0 (non-canonical helper lane).
   *
   * What it does:
   * Initializes global save-construct helper links as a self-linked intrusive
   * node and installs callback lane for collision-beam save-construct payload.
   */
  gpg::SerHelperBase* InitializeCollisionBeamEntitySaveConstructHelper()
  {
    InitializeHelperNode(gCollisionBeamEntitySaveConstruct);
    gCollisionBeamEntitySaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_CollisionBeamEntity);
    return &gCollisionBeamEntitySaveConstruct.mHelperLinks;
  }

  void CleanupCollisionBeamEntitySaveConstructAtexit()
  {
    (void)moho::cleanup_CollisionBeamEntitySaveConstruct();
  }

  struct CollisionBeamEntitySaveConstructBootstrap
  {
    CollisionBeamEntitySaveConstructBootstrap()
    {
      (void)moho::register_CollisionBeamEntitySaveConstruct();
    }
  };

  [[maybe_unused]] CollisionBeamEntitySaveConstructBootstrap gCollisionBeamEntitySaveConstructBootstrap;
} // namespace

namespace moho
{
  /**
    * Alias of FUN_00674EE0 (non-canonical helper lane).
   */
  gpg::RType* CollisionBeamEntitySaveConstruct::Init()
  {
    gpg::RType* type = CollisionBeamEntity::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CollisionBeamEntity));
      CollisionBeamEntity::sType = type;
    }

    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
    return type;
  }

  /**
    * Alias of FUN_00BFC340 (non-canonical helper lane).
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySaveConstruct()
  {
    return UnlinkHelperNode(gCollisionBeamEntitySaveConstruct);
  }

  /**
    * Alias of FUN_00BD4C60 (non-canonical helper lane).
   */
  int register_CollisionBeamEntitySaveConstruct()
  {
    (void)InitializeCollisionBeamEntitySaveConstructHelper();
    (void)gCollisionBeamEntitySaveConstruct.Init();
    return std::atexit(&CleanupCollisionBeamEntitySaveConstructAtexit);
  }
} // namespace moho

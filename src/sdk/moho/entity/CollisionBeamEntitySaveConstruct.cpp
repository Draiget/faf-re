#include "moho/entity/CollisionBeamEntitySaveConstruct.h"

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
    void SetUnowned(unsigned int flags);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
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
   * Address: 0x00BD4C60 (FUN_00BD4C60, dynamic initializer for the global
   * `CollisionBeamEntitySaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  CollisionBeamEntitySaveConstruct::CollisionBeamEntitySaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CollisionBeamEntitySaveConstruct::SaveConstructArgs)
      )
  {}

  /**
   * Address: 0x00BFC340 (FUN_00BFC340, atexit target registered by the real
   * ctor above)
   */
  CollisionBeamEntitySaveConstruct::~CollisionBeamEntitySaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00674EE0 (FUN_00674EE0, gpg::SerSaveConstructHelper_CollisionBeamEntity::Init)
   *
   * What it does:
   * Resolves `CollisionBeamEntity` RTTI (caching into its own `sType`
   * static, matching the binary) and installs the save-construct-args
   * callback lane.
   */
  void CollisionBeamEntitySaveConstruct::Init()
  {
    gpg::RType* const type = ResolveCachedType<CollisionBeamEntity>(CollisionBeamEntity::sType);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B4240 -- process-global `CollisionBeamEntitySaveConstruct`
  // singleton. Constructing it runs CollisionBeamEntitySaveConstruct::
  // CollisionBeamEntitySaveConstruct() (0x00BD4C60), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; InitNewHelpers() later
  // dispatches Init() on it.
  moho::CollisionBeamEntitySaveConstruct gCollisionBeamEntitySaveConstruct{};
} // namespace

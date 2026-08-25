#include "moho/unit/core/UnitSaveConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

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
  gpg::RType* gUnitType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  /**
   * Address: 0x006AD210 (FUN_006AD210, SaveConstructArgs_Unit)
   *
   * What it does:
   * Serializes the owning `Sim` pointer for `Unit` as an unowned tracked
   * pointer and marks the save-construct args result as unowned.
   */
  void SaveConstructArgs_Unit(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const unit = reinterpret_cast<moho::Unit*>(objectPtr);

    gpg::RRef ownerRef{};
    ownerRef.mObj = unit->SimulationRef;
    ownerRef.mType = unit->SimulationRef ? ResolveCachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    result->SetUnowned(0u);
  }

  /**
   * Address: 0x00BD6AF0 (FUN_00BD6AF0, dynamic initializer for the global
   * `UnitSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field (vtable slot 0 `Init()` dispatched
   * later by `gpg::SerHelperBase::InitNewHelpers`). Confirmed via raw asm:
   * base-ctor call -> field-set -> vtable-install -> atexit, with no eager
   * `RegisterSaveConstructArgsFunction()` dispatch (the prior recovery
   * fabricated that eager call from `register_UnitSaveConstruct`).
   */
  moho::UnitSaveConstruct gUnitSaveConstruct;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD6AF0 (FUN_00BD6AF0, register_UnitSaveConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  UnitSaveConstruct::UnitSaveConstruct()
    : mSaveConstructArgsCallback(reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_Unit))
  {}

  /**
   * Address: 0x00BFD9D0 (FUN_00BFD9D0, cleanup_UnitSaveConstruct)
   */
  UnitSaveConstruct::~UnitSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006AE920 (FUN_006AE920, Moho::UnitSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * Binds the `moho::Unit` save-construct-args callback into RTTI using
   * `typeid(moho::Unit)`.
   */
  void UnitSaveConstruct::Init()
  {
    gpg::RType* const type = ResolveCachedType<moho::Unit>(gUnitType);

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

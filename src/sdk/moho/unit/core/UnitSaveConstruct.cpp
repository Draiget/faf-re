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
  moho::UnitSaveConstruct gUnitSaveConstruct;

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
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

  void CleanupSaveConstructAtexit()
  {
    (void)moho::cleanup_UnitSaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006AE920 (FUN_006AE920, Moho::UnitSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * Binds the `moho::Unit` save-construct-args callback into RTTI using
   * `typeid(moho::Unit)`.
   */
  void UnitSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ResolveCachedType<moho::Unit>(gUnitType);

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BFD9D0 (FUN_00BFD9D0, cleanup_UnitSaveConstruct)
   *
   * What it does:
   * Unlinks the `UnitSaveConstruct` helper node from the intrusive list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_UnitSaveConstruct()
  {
    return UnlinkHelperNode(gUnitSaveConstruct);
  }

  /**
   * Address: 0x00BD6AF0 (FUN_00BD6AF0, register_UnitSaveConstruct)
   *
   * What it does:
   * Initializes the `UnitSaveConstruct` helper node and registers its callback
   * lane during startup.
   */
  void register_UnitSaveConstruct()
  {
    InitializeHelperNode(gUnitSaveConstruct);
    gUnitSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_Unit);
    gUnitSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct UnitSaveConstructBootstrap
  {
    UnitSaveConstructBootstrap()
    {
      moho::register_UnitSaveConstruct();
    }
  };

  UnitSaveConstructBootstrap gUnitSaveConstructBootstrap;
} // namespace

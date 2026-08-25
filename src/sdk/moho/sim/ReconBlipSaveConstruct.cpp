#include "moho/sim/ReconBlipSaveConstruct.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/ReconBlip.h"
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
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gSimType = nullptr;

  /**
   * Address: 0x005BFA30 (FUN_005BFA30)
   *
   * What it does:
   * Writes owning `Sim*` pointer for `ReconBlip` save-construct arguments and
   * marks the serializer lane as unowned.
   */
  void SaveConstructArgs_ReconBlip(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::ReconBlip*>(static_cast<std::uintptr_t>(objectPtr));
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef simRef{};
    simRef.mObj = object->SimulationRef;
    simRef.mType = object->SimulationRef ? CachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00BCDC70 (FUN_00BCDC70, dynamic initializer for the global
   * `ReconBlipSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field. The ctor's atexit target
   * (0x00BF78D0) is a plain unlink thunk, not a mangled destructor, so it
   * is modeled as the compiler's implicit static-destructor registration
   * rather than an explicit call.
   */
  ReconBlipSaveConstruct::ReconBlipSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_ReconBlip)
      )
  {}

  ReconBlipSaveConstruct::~ReconBlipSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x005C42B0 (FUN_005C42B0, gpg::SerSaveConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs save-construct-args callback
   * from this helper into the type descriptor.
   */
  void ReconBlipSaveConstruct::Init()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010AFB44 -- process-global `ReconBlipSaveConstruct` singleton.
  moho::ReconBlipSaveConstruct gReconBlipSaveConstruct;
} // namespace

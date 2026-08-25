#include "moho/audio/CSimSoundManagerSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };

  // Declared locally: gpg::RRef_Sim (defined + address-cited in
  // src/sdk/gpg/core/containers/ArchiveSerialization.cpp) has external
  // linkage but is not yet exposed from a shared header.
  RRef* RRef_Sim(RRef* outRef, moho::Sim* value);
} // namespace gpg

namespace
{
  // Address: 0x010BAF7C -- process-global `CSimSoundManagerSaveConstruct`
  // singleton. Constructing it runs CSimSoundManagerSaveConstruct::
  // CSimSoundManagerSaveConstruct() (0x00BDC520), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the
  // first ReadArchive/WriteArchive construction.
  moho::CSimSoundManagerSaveConstruct gCSimSoundManagerSaveConstruct;

  /**
   * Address: 0x00C01560 (FUN_00C01560)
   *
   * What it does:
   * Unlinks the `CSimSoundManagerSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BDC520) as the
   * global's `atexit` teardown.
   */
  void CleanupCSimSoundManagerSaveConstruct()
  {
    gCSimSoundManagerSaveConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDC520 (FUN_00BDC520, dynamic initializer for the global
   * `CSimSoundManagerSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  CSimSoundManagerSaveConstruct::CSimSoundManagerSaveConstruct()
    : mSerSaveConstructArgsFunc(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CSimSoundManagerSaveConstruct::SaveConstructArgs)
      )
  {
    (void)std::atexit(&CleanupCSimSoundManagerSaveConstruct);
  }

  /**
   * Address: 0x007610B0 (FUN_007610B0)
   *
   * What it does:
   * Writes the owning `Sim*` (read from the `CSimSoundManager` object's
   * `mOwnerSim` field at +0x04) as an unowned tracked pointer.
   */
  void CSimSoundManagerSaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const soundManager = reinterpret_cast<CSimSoundManager*>(objectPtr);
    if (archive == nullptr || soundManager == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};
    gpg::RRef_Sim(&ownerRef, soundManager->mOwnerSim);
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result != nullptr) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x00761D90 (FUN_00761D90, gpg::SerSaveConstructHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs the save-construct-args
   * callback.
   */
  void CSimSoundManagerSaveConstruct::Init()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }
} // namespace moho

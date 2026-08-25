#include "moho/audio/CSimSoundManagerConstruct.h"

#include <cstdlib>
#include <new>

#include "gpg/core/containers/ReadArchive.h"
#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/ISoundManager.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  // Address: 0x010BAF40 -- process-global `CSimSoundManagerConstruct` singleton.
  // Constructing it runs CSimSoundManagerConstruct::CSimSoundManagerConstruct()
  // (0x00BDC550), which splices this helper into gpg::SerHelperBase::sNewHelpers;
  // gpg::SerHelperBase::InitNewHelpers() later dispatches Init()
  // on it from within the first ReadArchive/WriteArchive construction.
  moho::CSimSoundManagerConstruct gCSimSoundManagerConstruct;

  /**
   * Address: 0x00C01590 (FUN_00C01590)
   *
   * What it does:
   * Unlinks the `CSimSoundManagerConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BDC550) as the
   * global's `atexit` teardown.
   */
  void CleanupCSimSoundManagerConstruct()
  {
    gCSimSoundManagerConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDC550 (FUN_00BDC550, dynamic initializer for the global
   * `CSimSoundManagerConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  CSimSoundManagerConstruct::CSimSoundManagerConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CSimSoundManagerConstruct::Construct))
    , mDeleteCallback(&CSimSoundManagerConstruct::Deconstruct)
  {
    (void)std::atexit(&CleanupCSimSoundManagerConstruct);
  }

  /**
   * Address: 0x00761240 (FUN_00761240, Moho::CSimSoundManagerConstruct::Construct)
   *
   * What it does:
   * Reads the owning `Sim*`, allocates one `CSimSoundManager`, and returns it
   * through `SerConstructResult` as unowned payload.
   */
  void CSimSoundManagerConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    Sim* sim = nullptr;
    const gpg::RRef nullOwner{};
    (void)archive->ReadPointer_Sim(&sim, &nullOwner);

    CSimSoundManager* const object = new (std::nothrow) CSimSoundManager(sim);
    gpg::RRef objectRef{};
    gpg::RRef_ISoundManager(&objectRef, object);
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x007623F0 (FUN_007623F0)
   *
   * What it does:
   * Deleting-teardown callback: dispatches through `ISoundManager::Destroy`
   * (vtable slot 5) with the deleting flag set, when the object pointer is
   * non-null.
   */
  void CSimSoundManagerConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const soundManager = static_cast<ISoundManager*>(objectPtr);
    if (soundManager != nullptr) {
      (void)soundManager->Destroy(1u);
    }
  }

  /**
   * Address: 0x00761E10 (FUN_00761E10, gpg::SerConstructHelper_CSimSoundManager::Init)
   *
   * What it does:
   * Resolves `CSimSoundManager` RTTI and installs construct/delete callbacks.
   */
  void CSimSoundManagerConstruct::Init()
  {
    gpg::RType* const typeInfo = audio_reflection::ResolveCSimSoundManagerType();
    audio_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }
} // namespace moho

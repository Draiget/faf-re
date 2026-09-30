#include "moho/audio/CSimSoundManagerConstruct.h"

#include <cstdlib>
#include <new>

#include "gpg/core/containers/ReadArchive.h"
#include "moho/audio/AudioReflectionHelpers.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/ISoundManager.h"
#include "moho/sim/Sim.h"

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
  {}

  /**
   * Address: 0x00C01590 (FUN_00C01590, dynamic atexit destructor for `gCSimSoundManagerConstruct`)
   *
   * What it does:
   * Unlinks this helper node from the serializer-helper list (the
   * `TDatListItem` base destructor). The compiler registers it with
   * `atexit` from the global's dynamic initializer (0x00BDC550).
   * `FUN_007611E0` and `FUN_00761210` are
   * unreferenced out-of-line copies of the same body.
   */
  CSimSoundManagerConstruct::~CSimSoundManagerConstruct() = default;

  /**
   * Address: 0x00761240 (FUN_00761240, Moho::CSimSoundManagerConstruct::Construct)
   *
   * What it does:
   * Reads the owning `Sim*`, allocates one `CSimSoundManager`, and returns it
   * through `SerConstructResult` as unowned payload.
   */
  void CSimSoundManagerConstruct::Construct(
    gpg::ReadArchive* const archive, const int, gpg::RRef* const, gpg::SerConstructResult* const result
  )
  {
    Sim* sim = nullptr;
    const gpg::RRef nullOwner{};
    (void)archive->ReadPointer(&sim, &nullOwner);

    CSimSoundManager* const object = new (std::nothrow) CSimSoundManager(sim);
    gpg::RRef objectRef{};
    objectRef = gpg::MakeRRef<moho::ISoundManager>(object);
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x007623F0 (FUN_007623F0)
   *
   * What it does:
   * Deleting-teardown callback registered as the reflected type's
   * `deleteFunc_`: deletes the object through its `ISoundManager` base, which
   * is the vtable slot-5 dispatch the binary performs.
   */
  void CSimSoundManagerConstruct::Deconstruct(void* const objectPtr)
  {
    // Through the base pointer, so the `delete` dispatches slot 5 as the binary
    // does (`mov edx, [eax+0x14] / push 1 / call edx`) instead of binding the
    // final overrider directly; its own null test is the leading
    // `test ecx, ecx / je`.
    delete static_cast<ISoundManager*>(objectPtr);
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

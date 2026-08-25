#include "moho/ai/CAiBrainConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"

using namespace moho;

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
  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAiBrainRef(CAiBrain* const object)
  {
    gpg::RRef ref{};
    gpg::RRef_CAiBrain(&ref, object);
    return ref;
  }

  /**
   * Address: 0x00579D00 (FUN_00579D00)
   *
   * What it does:
   * Allocates one `CAiBrain`, wraps it in a reflected `RRef`, and publishes
   * that reference through `SerConstructResult::SetUnowned`.
   */
  void ConstructCAiBrainForResult(gpg::ReadArchive*, int, int, gpg::SerConstructResult* const result)
  {
    CAiBrain* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiBrain), std::nothrow);
    if (storage) {
      object = new (storage) CAiBrain();
    }

    result->SetUnowned(MakeCAiBrainRef(object), 0u);
  }

  /**
   * Address: 0x00579CF0 (FUN_00579CF0)
   *
   * What it does:
   * Forwards one serializer construct callback lane to
   * `ConstructCAiBrainForResult`.
   */
  void ConstructCAiBrainForResultThunk(
    gpg::ReadArchive* const archive,
    const int objectLane,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    ConstructCAiBrainForResult(archive, objectLane, version, result);
  }

  void DeleteConstructedCAiBrain(void* const objectPtr)
  {
    auto* const object = static_cast<CAiBrain*>(objectPtr);
    if (!object) {
      return;
    }

    delete object;
  }

  // Address: 0x010AD510 -- process-global `CAiBrainConstruct` singleton.
  // Constructing it runs CAiBrainConstruct::CAiBrainConstruct() (0x00BCB3F0),
  // which splices this helper into gpg::SerHelperBase::sNewHelpers;
  // gpg::SerHelperBase::InitNewHelpers() later dispatches Init() on it from
  // within the first ReadArchive/WriteArchive construction.
  CAiBrainConstruct gCAiBrainConstructStartupHelper;

  /**
   * Address: 0x00BF62C0 (FUN_00BF62C0)
   *
   * What it does:
   * Unlinks the `CAiBrainConstruct` helper node from whatever intrusive list
   * it currently sits in and restores a self-linked sentinel state.
   * Registered by the real dynamic initializer (0x00BCB3F0) as the global's
   * `atexit` teardown.
   */
  void CleanupCAiBrainConstructStartup()
  {
    gCAiBrainConstructStartupHelper.ResetLinks();
  }
} // namespace

/**
 * Address: 0x00BCB3F0 (FUN_00BCB3F0, dynamic initializer for the global
 * `CAiBrainConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiBrainConstruct::CAiBrainConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCAiBrainForResultThunk))
  , mDeleteCallback(&DeleteConstructedCAiBrain)
{
  (void)std::atexit(&CleanupCAiBrainConstructStartup);
}

/**
 * Address: 0x0057E3E0 (FUN_0057E3E0, gpg::SerConstructHelper_CAiBrain::Init)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs construct/delete callbacks from
 * this helper object into the type descriptor.
 */
void CAiBrainConstruct::Init()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

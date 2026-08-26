#include "moho/ai/CAiNavigatorAirConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

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
  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005A7F00 (FUN_005A7F00)
   *
   * What it does:
   * Populates one reflected `RRef` payload for a `CAiNavigatorAir` object.
   */
  [[nodiscard]] gpg::RRef* PopulateCAiNavigatorAirRef(gpg::RRef* const out, CAiNavigatorAir* const object)
  {
    gpg::RRef temp{};
    gpg::RRef_CAiNavigatorAir(&temp, object);
    *out = temp;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeCAiNavigatorAirRef(CAiNavigatorAir* const object)
  {
    gpg::RRef ref{};
    (void)PopulateCAiNavigatorAirRef(&ref, object);
    return ref;
  }

  /**
   * Address: 0x005A5640 (FUN_005A5640, construct body callback)
   *
   * What it does:
   * Allocates one `CAiNavigatorAir` and publishes it as unowned construct
   * result payload.
   */
  void ConstructAiNavigatorAirForResult(gpg::SerConstructResult* const result)
  {
    CAiNavigatorAir* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiNavigatorAir));
    if (storage) {
      object = new (storage) CAiNavigatorAir();
    }
    result->SetUnowned(MakeCAiNavigatorAirRef(object), 0u);
  }

  // Address: 0x010AE848 -- process-global `CAiNavigatorAirConstruct` singleton.
  // Constructing it runs CAiNavigatorAirConstruct::CAiNavigatorAirConstruct()
  // (0x00BCC840), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  CAiNavigatorAirConstruct gCAiNavigatorAirConstruct;

  /**
   * Address: 0x00BF6F40 (FUN_00BF6F40, cleanup_CAiNavigatorAirConstruct)
   *
   * What it does:
   * Unlinks the `CAiNavigatorAirConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BCC840) as the
   * global's `atexit` teardown. `FUN_005A5600` and `FUN_005A55D0` are
   * duplicate-emission twins of this exact unlink/reset lane (same
   * `ResetLinks()` shape, folded to separate addresses); they have no
   * distinct source-level body of their own.
   */
  void CleanupCAiNavigatorAirConstructStartup()
  {
    gCAiNavigatorAirConstruct.ResetLinks();
  }
} // namespace

/**
 * Alias of FUN_005A5630 (non-canonical helper lane).
 */
void CAiNavigatorAirConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }
  ConstructAiNavigatorAirForResult(result);
}

/**
 * Address: 0x005A7ED0 (FUN_005A7ED0, delete callback)
 */
void CAiNavigatorAirConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiNavigatorAir*>(object);
}

/**
 * Address: 0x00BCC840 (FUN_00BCC840, dynamic initializer for the global
 * `CAiNavigatorAirConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiNavigatorAirConstruct::CAiNavigatorAirConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiNavigatorAirConstruct::Construct))
  , mDeleteCallback(&CAiNavigatorAirConstruct::Deconstruct)
{
  (void)std::atexit(&CleanupCAiNavigatorAirConstructStartup);
}

/**
 * Address: 0x005A74D0 (FUN_005A74D0, gpg::SerConstructHelper_CAiNavigatorAir::Init)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorAirConstruct::Init()
{
  gpg::RType* const type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

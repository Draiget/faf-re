#include "moho/ai/CAiNavigatorLandConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

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
  [[nodiscard]] gpg::RType* CachedCAiNavigatorLandType()
  {
    gpg::RType* type = CAiNavigatorLand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorLand));
      CAiNavigatorLand::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005A7E20 (FUN_005A7E20)
   *
   * What it does:
   * Populates one reflected `RRef` payload for a `CAiNavigatorLand` object.
   */
  [[nodiscard]] gpg::RRef* PopulateCAiNavigatorLandRef(gpg::RRef* const out, CAiNavigatorLand* const object)
  {
    gpg::RRef temp{};
    gpg::RRef_CAiNavigatorLand(&temp, object);
    *out = temp;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeCAiNavigatorLandRef(CAiNavigatorLand* const object)
  {
    gpg::RRef ref{};
    (void)PopulateCAiNavigatorLandRef(&ref, object);
    return ref;
  }

  /**
   * Address: 0x005A4740 (FUN_005A4740, func_registerCAiNavigatorLandRType)
   *
   * What it does:
   * Allocates one `CAiNavigatorLand`, wraps it in a typed `gpg::RRef`, and
   * publishes it through `SerConstructResult::SetUnowned` as the construct
   * callback payload.
   */
  void ConstructAiNavigatorLandForResult(gpg::SerConstructResult* const result)
  {
    CAiNavigatorLand* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiNavigatorLand), std::nothrow);
    if (storage) {
      object = new (storage) CAiNavigatorLand();
    }
    result->SetUnowned(MakeCAiNavigatorLandRef(object), 0u);
  }

  // Address: 0x010AE85C -- process-global `CAiNavigatorLandConstruct` singleton.
  // Constructing it runs CAiNavigatorLandConstruct::CAiNavigatorLandConstruct()
  // (0x00BCC7A0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  CAiNavigatorLandConstruct gCAiNavigatorLandConstruct;

  /**
   * Address: 0x00BF6E80 (FUN_00BF6E80, cleanup_CAiNavigatorLandConstruct)
   *
   * What it does:
   * Unlinks the `CAiNavigatorLandConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BCC7A0) as the
   * global's `atexit` teardown.
   */
  void CleanupCAiNavigatorLandConstructStartup()
  {
    gCAiNavigatorLandConstruct.ResetLinks();
  }
} // namespace

/**
 * Address: 0x005A4730 (FUN_005A4730, CAiNavigatorLandConstruct::Construct)
 *
 * What it does:
 * Null-checks the construct-result payload and forwards to the typed
 * allocation helper.
 */
void CAiNavigatorLandConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }
  ConstructAiNavigatorLandForResult(result);
}

/**
 * Address: 0x005A7DF0 (FUN_005A7DF0, delete callback)
 */
void CAiNavigatorLandConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiNavigatorLand*>(object);
}

/**
 * Address: 0x00BCC7A0 (FUN_00BCC7A0, dynamic initializer for the global
 * `CAiNavigatorLandConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiNavigatorLandConstruct::CAiNavigatorLandConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiNavigatorLandConstruct::Construct))
  , mDeleteCallback(&CAiNavigatorLandConstruct::Deconstruct)
{
  (void)std::atexit(&CleanupCAiNavigatorLandConstructStartup);
}

/**
 * Address: 0x005A73B0 (FUN_005A73B0, gpg::SerConstructHelper_CAiNavigatorLand::Init)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorLandConstruct::Init()
{
  gpg::RType* const type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

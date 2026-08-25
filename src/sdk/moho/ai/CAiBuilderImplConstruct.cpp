#include "moho/ai/CAiBuilderImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBuilderImpl.h"

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
  [[nodiscard]] gpg::RType* CachedCAiBuilderImplType()
  {
    gpg::RType* type = CAiBuilderImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBuilderImpl));
      CAiBuilderImpl::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAiBuilderImplRef(CAiBuilderImpl* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCAiBuilderImplType();
    return ref;
  }

  /**
   * Address: 0x0059FD90 (FUN_0059FD90, construct helper)
   *
   * What it does:
   * Allocates one `CAiBuilderImpl` and stores an unowned reference into
   * serialization construct result output.
   */
  void ConstructAiBuilderImplForResult(gpg::SerConstructResult* const result)
  {
    CAiBuilderImpl* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiBuilderImpl), std::nothrow);
    if (storage) {
      object = new (storage) CAiBuilderImpl();
    }

    if (!result) {
      delete object;
      return;
    }
    result->SetUnowned(MakeCAiBuilderImplRef(object), 0u);
  }

  // Address: 0x010AE644 -- process-global `CAiBuilderImplConstruct` singleton.
  // Constructing it runs CAiBuilderImplConstruct::CAiBuilderImplConstruct()
  // (0x00BCC2E0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  CAiBuilderImplConstruct gCAiBuilderImplConstruct;

  /**
   * Address: 0x00BF6AC0 (FUN_00BF6AC0, cleanup_CAiBuilderImplConstruct)
   *
   * What it does:
   * Unlinks the `CAiBuilderImplConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BCC2E0) as the
   * global's `atexit` teardown.
   */
  void CleanupCAiBuilderImplConstructStartup()
  {
    gCAiBuilderImplConstruct.ResetLinks();
  }
} // namespace

/**
 * Address: 0x0059FD80 (FUN_0059FD80, construct callback)
 */
void CAiBuilderImplConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }

  ConstructAiBuilderImplForResult(result);
}

/**
 * Address: 0x005A1C80 (FUN_005A1C80, delete callback)
 */
void CAiBuilderImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiBuilderImpl*>(object);
}

/**
 * Address: 0x00BCC2E0 (FUN_00BCC2E0, dynamic initializer for the global
 * `CAiBuilderImplConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiBuilderImplConstruct::CAiBuilderImplConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiBuilderImplConstruct::Construct))
  , mDeleteCallback(&CAiBuilderImplConstruct::Deconstruct)
{
  (void)std::atexit(&CleanupCAiBuilderImplConstructStartup);
}

/**
 * Address: 0x005A0650 (FUN_005A0650, gpg::SerConstructHelper_CAiBuilderImpl::Init)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiBuilderImplConstruct::Init()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

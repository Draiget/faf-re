#include "moho/ai/CAiSiloBuildImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiSiloBuildImplType()
  {
    gpg::RType* type = CAiSiloBuildImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSiloBuildImpl));
      CAiSiloBuildImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010AFC34 -- process-global `CAiSiloBuildImplConstruct`
  // singleton. Constructing it runs CAiSiloBuildImplConstruct::
  // CAiSiloBuildImplConstruct() (0x00BCE110), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiSiloBuildImplConstruct,
  // 0x00BF7F30) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiSiloBuildImplConstruct gCAiSiloBuildImplConstruct;
} // namespace

/**
 * Address: 0x005CF840 (FUN_005CF840, Moho::CAiSiloBuildImplConstruct::Construct)
 */
void CAiSiloBuildImplConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result)
{
  if (!result) {
    return;
  }

  CAiSiloBuildImpl::MemberConstruct(result);
}

/**
 * Address: 0x005D0870 (FUN_005D0870, Moho::CAiSiloBuildImplConstruct::Deconstruct)
 */
void CAiSiloBuildImplConstruct::Deconstruct(void* const objectPtr)
{
  delete static_cast<CAiSiloBuildImpl*>(objectPtr);
}

/**
 * Address: 0x00BCE110 (FUN_00BCE110, dynamic initializer for the global
 * `CAiSiloBuildImplConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the construct/delete callback fields.
 */
CAiSiloBuildImplConstruct::CAiSiloBuildImplConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiSiloBuildImplConstruct::Construct))
  , mDeleteCallback(&CAiSiloBuildImplConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF7F30 (FUN_00BF7F30, Moho::CAiSiloBuildImplConstruct::~CAiSiloBuildImplConstruct)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiSiloBuildImplConstruct::~CAiSiloBuildImplConstruct()
{
  ResetLinks();
}

/**
 * Address: 0x005CFEB0 (FUN_005CFEB0, gpg::SerConstructHelper_CAiSiloBuildImpl::Init)
 *
 * What it does:
 * Lazily resolves CAiSiloBuildImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiSiloBuildImplConstruct::Init()
{
  gpg::RType* const type = CachedCAiSiloBuildImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x010AFC34 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiSiloBuildImplConstruct` singleton from an explicit registration
 * sequence. `gCAiSiloBuildImplConstruct` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_CAiSiloBuildImplConstruct()
{
  return 0;
}

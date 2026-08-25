#include "moho/ai/CAiTransportImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiTransportImplType()
  {
    gpg::RType* type = CAiTransportImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTransportImpl));
      CAiTransportImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010B087C -- process-global `CAiTransportImplConstruct`
  // singleton. Constructing it runs CAiTransportImplConstruct::
  // CAiTransportImplConstruct() (0x00BCEF10), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiTransportImplConstruct,
  // 0x00BF8C40) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiTransportImplConstruct gCAiTransportImplConstruct;
} // namespace

/**
 * Address: 0x005E84F0 (FUN_005E84F0, Moho::CAiTransportImplConstruct::Construct)
 *
 * What it does:
 * Forwards construct callback flow into `CAiTransportImpl::MemberConstruct`.
 */
void CAiTransportImplConstruct::Construct(gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result)
{
  if (!result) {
    return;
  }

  CAiTransportImpl::MemberConstruct(result);
}

/**
 * Address: 0x005EC380 (FUN_005EC380, Moho::CAiTransportImplConstruct::Deconstruct)
 *
 * What it does:
 * Deletes one constructed `CAiTransportImpl` object.
 */
void CAiTransportImplConstruct::Deconstruct(void* const objectPtr)
{
  delete static_cast<CAiTransportImpl*>(objectPtr);
}

/**
 * Address: 0x00BCEF10 (FUN_00BCEF10, dynamic initializer for the global
 * `CAiTransportImplConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the construct/delete callback fields.
 */
CAiTransportImplConstruct::CAiTransportImplConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiTransportImplConstruct::Construct))
  , mDeleteCallback(&CAiTransportImplConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF8C40 (FUN_00BF8C40, Moho::CAiTransportImplConstruct::~CAiTransportImplConstruct)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
CAiTransportImplConstruct::~CAiTransportImplConstruct()
{
  ResetLinks();
}

/**
 * Address: 0x005E9BB0 (FUN_005E9BB0, gpg::SerConstructHelper_CAiTransportImpl::Init)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiTransportImplConstruct::Init()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x010B087C caller lane (`IAiTransport.cpp`'s
 * `IAiTransportReflectionBootstrap` reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiTransportImplConstruct` singleton from an explicit registration
 * sequence. `gCAiTransportImplConstruct` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `IAiTransport.cpp`'s existing bootstrap
 * sequence does not need editing.
 */
void moho::register_CAiTransportImplConstruct()
{}

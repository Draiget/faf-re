#include "moho/ai/IAiCommandDispatchImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatchImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }

  // Address: 0x010AE404 -- process-global `IAiCommandDispatchImplConstruct`
  // singleton. Constructing it runs IAiCommandDispatchImplConstruct::
  // IAiCommandDispatchImplConstruct() (0x00BCBEC0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor
  // (~IAiCommandDispatchImplConstruct, 0x00BF66C0) runs at normal
  // static-duration teardown, matching the real binary's atexit
  // registration. Nothing outside this translation unit calls
  // `register_IAiCommandDispatchImplConstruct()` by name, so that
  // compatibility wrapper is not needed here (unlike
  // `CAiTransportImplConstruct`, whose equivalent is still called from
  // `IAiTransport.cpp`).
  IAiCommandDispatchImplConstruct gIAiCommandDispatchImplConstruct;
} // namespace

/**
 * Address: 0x00599320 (FUN_00599320, Moho::IAiCommandDispatchImplConstruct::Construct)
 */
void IAiCommandDispatchImplConstruct::Construct(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int version,
  gpg::SerConstructResult* const result
)
{
  IAiCommandDispatchImpl::MemberConstruct(archive, objectPtr, version, result);
}

/**
 * Address: 0x005999D0 (FUN_005999D0, Moho::IAiCommandDispatchImplConstruct::Deconstruct)
 */
void IAiCommandDispatchImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<IAiCommandDispatchImpl*>(object);
}

/**
 * Address: 0x00BCBEC0 (FUN_00BCBEC0, dynamic initializer for the global
 * `IAiCommandDispatchImplConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the construct/delete callback fields.
 */
IAiCommandDispatchImplConstruct::IAiCommandDispatchImplConstruct()
  : mConstructFunc(reinterpret_cast<gpg::RType::construct_func_t>(&IAiCommandDispatchImplConstruct::Construct))
  , mDeleteFunc(&IAiCommandDispatchImplConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF66C0 (FUN_00BF66C0, Moho::IAiCommandDispatchImplConstruct::~IAiCommandDispatchImplConstruct)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
IAiCommandDispatchImplConstruct::~IAiCommandDispatchImplConstruct()
{
  ResetLinks();
}

/**
 * Address: 0x00599650 (FUN_00599650, gpg::SerConstructHelper_IAiCommandDispatchImpl::Init)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs construct/delete
 * callbacks from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplConstruct::Init()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

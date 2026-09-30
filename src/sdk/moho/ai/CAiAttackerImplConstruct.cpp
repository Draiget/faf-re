#include "moho/ai/CAiAttackerImplConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"

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
  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    gpg::RType* cached = CAiAttackerImpl::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAiAttackerImpl));
      CAiAttackerImpl::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCAiAttackerImplRef(CAiAttackerImpl* const object)
  {
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CAiAttackerImpl>(object);
    return ref;
  }

  /**
   * Address: 0x005D83A0 (FUN_005D83A0)
   *
   * What it does:
   * Allocates one `CAiAttackerImpl`, wraps it in a typed reflected reference,
   * and publishes that payload through `SerConstructResult::SetUnowned`.
   */
  void ConstructCAiAttackerImplForResult(gpg::SerConstructResult* const result)
  {
    CAiAttackerImpl* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiAttackerImpl), std::nothrow);
    if (storage) {
      object = new (storage) CAiAttackerImpl();
    }

    result->SetUnowned(MakeCAiAttackerImplRef(object), 0u);
  }

  // Address: 0x010B028C -- process-global `CAiAttackerImplConstruct` singleton.
  // Constructing it runs CAiAttackerImplConstruct::CAiAttackerImplConstruct()
  // (0x00BCE890), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; the compiler registers its destructor with
  // `atexit`.
  moho::CAiAttackerImplConstruct gCAiAttackerImplConstruct;

} // namespace

/**
 * Address: 0x005D8390 (FUN_005D8390)
 *
 * What it does:
 * Construct-callback lane used by recovered `CAiAttackerImpl` reflection
 * helper registration. Forwards into the canonical helper body recovered at
 * `0x005D83A0`.
 */
void CAiAttackerImplConstruct::Construct(
  gpg::ReadArchive* const, const int, gpg::RRef* const, gpg::SerConstructResult* const result
)
{
  ConstructCAiAttackerImplForResult(result);
}

/**
 * Address: 0x005DEB50 (FUN_005DEB50)
 *
 * What it does:
 * Delete-callback lane used by recovered `CAiAttackerImpl` reflection helper
 * registration.
 */
void CAiAttackerImplConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiAttackerImpl*>(object);
}

/**
 * Address: 0x00BCE890 (FUN_00BCE890, dynamic initializer for the global
 * `CAiAttackerImplConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices into
 * `sNewHelpers`) and binds the construct/delete callback fields; the compiler
 * registers the destructor with `atexit`.
 */
CAiAttackerImplConstruct::CAiAttackerImplConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiAttackerImplConstruct::Construct))
  , mDeleteCallback(&CAiAttackerImplConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF8400 (FUN_00BF8400, dynamic atexit destructor for `gCAiAttackerImplConstruct`)
 *
 * What it does:
 * Unlinks this helper node from the serializer-helper list (the
 * `TDatListItem` base destructor). The compiler registers it with
 * `atexit` from the global's dynamic initializer (0x00BCE890).
 * `FUN_005D8330` and `FUN_005D8360` are
 * unreferenced out-of-line copies of the same body.
 */
CAiAttackerImplConstruct::~CAiAttackerImplConstruct() = default;

/**
 * Address: 0x005DC050 (FUN_005DC050)
 *
 * What it does:
 * Lazily resolves `CAiAttackerImpl` RTTI and installs construct/delete
 * callbacks from this helper object into the type descriptor.
 */
void CAiAttackerImplConstruct::Init()
{
  gpg::RType* const type = CachedCAiAttackerImplType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
  GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
  if (!type) {
    return;
  }

  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCE890 caller lane (`CAiAttackerImplTypeInfo.cpp`'s
 * reflection bootstrap sequence)
 *
 * What it does:
 * Historically forced construction of the (then lazily-constructed)
 * `CAiAttackerImplConstruct` singleton from an explicit registration
 * sequence. `gCAiAttackerImplConstruct` is now a genuine namespace-scope
 * global, so its constructor already runs unconditionally at static-init
 * time; this call is kept only so `CAiAttackerImplTypeInfo.cpp`'s existing
 * bootstrap sequence does not need editing.
 */
int moho::register_CAiAttackerImplConstruct()
{
  return 0;
}

#include "moho/sim/ReconBlipConstruct.h"

#include <cstdlib>

#include "moho/sim/ReconBlip.h"

namespace moho
{
  /**
   * Address: 0x00BCDCA0 (FUN_00BCDCA0, dynamic initializer for the global
   * `ReconBlipConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  ReconBlipConstruct::ReconBlipConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ReconBlipConstruct::Construct))
    , mDeleteCallback(&ReconBlipConstruct::DeleteConstructedObject)
  {}

  ReconBlipConstruct::~ReconBlipConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x005BFBC0 (FUN_005BFBC0, Moho::ReconBlipConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow into `ReconBlip::MemberConstruct`.
   */
  void ReconBlipConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int version, gpg::SerConstructResult* const result
  )
  {
    if (!archive || !result) {
      return;
    }

    const gpg::RRef ownerRef{};
    ReconBlip::MemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x005C9070 (FUN_005C9070, Moho::ReconBlipConstruct::Deconstruct)
   *
   * What it does:
   * Releases one constructed object through its deleting-destructor vtable
   * entry when the pointer is non-null.
   */
  void ReconBlipConstruct::DeleteConstructedObject(void* const objectPtr)
  {
    if (!objectPtr) {
      return;
    }
    delete static_cast<ReconBlip*>(objectPtr);
  }

  /**
   * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void ReconBlipConstruct::Init()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010AF7FC -- process-global `ReconBlipConstruct` singleton.
  moho::ReconBlipConstruct gReconBlipConstruct;
} // namespace

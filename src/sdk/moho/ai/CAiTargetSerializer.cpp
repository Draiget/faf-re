#include "moho/ai/CAiTargetSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTarget.h"

using namespace moho;

namespace
{
  // Address: 0x010B05B4 -- process-global `CAiTargetSerializer` singleton.
  // Constructing it runs CAiTargetSerializer::CAiTargetSerializer()
  // (0x00BCEC50), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiTargetSerializer,
  // 0x005E2E60) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiTargetSerializer gCAiTargetSerializer;

  /**
   * Address: 0x005E2E90 (FUN_005E2E90)
   *
   * What it does:
   * Secondary unlink/reset thunk for the global `CAiTargetSerializer` helper
   * node.
   */
  [[maybe_unused]] void cleanup_CAiTargetSerializerStartupThunkB()
  {
    gCAiTargetSerializer.ResetLinks();
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTarget));
      CAiTarget::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x00BCEC50 (FUN_00BCEC50, dynamic initializer for the global
 * `CAiTargetSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiTargetSerializer::CAiTargetSerializer()
  : mLoadCallback(&CAiTarget::DeserializeFromArchive)
  , mSaveCallback(&CAiTarget::SerializeToArchive)
{}

CAiTargetSerializer::~CAiTargetSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005E3540 (FUN_005E3540, gpg::SerSaveLoadHelper_CAiTarget::Init)
 *
 * What it does:
 * Lazily resolves CAiTarget RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiTargetSerializer::Init()
{
  gpg::RType* const type = CachedCAiTargetType();
  const gpg::RType::load_func_t loadCallback = mLoadCallback ? mLoadCallback : &CAiTarget::DeserializeFromArchive;
  const gpg::RType::save_func_t saveCallback = mSaveCallback ? mSaveCallback : &CAiTarget::SerializeToArchive;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = loadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = saveCallback;
}

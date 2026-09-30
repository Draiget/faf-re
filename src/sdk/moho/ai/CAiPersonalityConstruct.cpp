#include "moho/ai/CAiPersonalityConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiPersonality.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPersonalityType()
  {
    gpg::RType* type = CAiPersonality::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPersonality));
      CAiPersonality::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAiPersonalityRef(CAiPersonality* const personality)
  {
    gpg::RRef out{};
    out.mObj = personality;
    out.mType = CachedCAiPersonalityType();
    return out;
  }

  /**
   * Address: 0x005B69F0 (FUN_005B69F0, sub_5B69F0)
   *
   * What it does:
   * Allocates one `CAiPersonality`, wraps it as `gpg::RRef`, and stores it as
   * an unowned construct result payload.
   */
  void ConstructAiPersonalityForResult(gpg::SerConstructResult* const result)
  {
    CAiPersonality* personality = nullptr;
    void* const storage = ::operator new(sizeof(CAiPersonality), std::nothrow);
    if (storage) {
      personality = new (storage) CAiPersonality();
    }

    result->SetUnowned(MakeCAiPersonalityRef(personality), 0u);
  }

  // Address: 0x010AF130 -- process-global `CAiPersonalityConstruct` singleton.
  // Constructing it runs CAiPersonalityConstruct::CAiPersonalityConstruct()
  // (0x00BCD620), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  CAiPersonalityConstruct gCAiPersonalityConstruct;

} // namespace

/**
 * Address: 0x005B69E0 (FUN_005B69E0)
 *
 * What it does:
 * Construct-callback lane for `CAiPersonality` reflection loading.
 */
void CAiPersonalityConstruct::Construct(
  gpg::ReadArchive* const, const int, gpg::RRef* const, gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }
  ConstructAiPersonalityForResult(result);
}

/**
 * Address: 0x005B9580 (FUN_005B9580)
 *
 * What it does:
 * Delete-callback lane for `CAiPersonality` reflection loading.
 */
void CAiPersonalityConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiPersonality*>(object);
}

/**
 * Address: 0x00BCD620 (FUN_00BCD620, dynamic initializer for the global
 * `CAiPersonalityConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiPersonalityConstruct::CAiPersonalityConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CAiPersonalityConstruct::Construct))
  , mDeleteCallback(&CAiPersonalityConstruct::Deconstruct)
{}

/**
 * Address: 0x00BF7710 (FUN_00BF7710, dynamic atexit destructor for `gCAiPersonalityConstruct`)
 *
 * What it does:
 * Unlinks this helper node from the serializer-helper list (the
 * `TDatListItem` base destructor). The compiler registers it with
 * `atexit` from the global's dynamic initializer (0x00BCD620).
 * `FUN_005B6980` and `FUN_005B69B0` are
 * unreferenced out-of-line copies of the same body.
 */
CAiPersonalityConstruct::~CAiPersonalityConstruct() = default;

/**
 * Address: 0x005B92D0 (FUN_005B92D0, gpg::SerConstructHelper_CAiPersonality::Init)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiPersonalityConstruct::Init()
{
  gpg::RType* type = CachedCAiPersonalityType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

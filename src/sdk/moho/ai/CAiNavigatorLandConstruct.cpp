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
  alignas(CAiNavigatorLandConstruct) unsigned char gCAiNavigatorLandConstructStorage[sizeof(CAiNavigatorLandConstruct)] = {};
  bool gCAiNavigatorLandConstructConstructed = false;

  [[nodiscard]] gpg::SerHelperBase* HelperNode(CAiNavigatorLandConstruct& construct) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&construct.mHelperNext);
  }

  [[nodiscard]] CAiNavigatorLandConstruct* AcquireCAiNavigatorLandConstruct()
  {
    if (!gCAiNavigatorLandConstructConstructed) {
      new (gCAiNavigatorLandConstructStorage) CAiNavigatorLandConstruct();
      gCAiNavigatorLandConstructConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorLandConstruct*>(gCAiNavigatorLandConstructStorage);
  }

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

  /**
   * Address: 0x00BF6E80 (FUN_00BF6E80, cleanup_CAiNavigatorLandConstruct)
   *
   * What it does:
   * Unlinks recovered CAiNavigatorLand construct helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorLandConstruct()
  {
    if (!gCAiNavigatorLandConstructConstructed) {
      return nullptr;
    }

    CAiNavigatorLandConstruct* const construct = AcquireCAiNavigatorLandConstruct();
    gpg::SerHelperBase* const self = HelperNode(*construct);
    if (construct->mHelperNext != nullptr && construct->mHelperPrev != nullptr) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    construct->mHelperNext = self;
    construct->mHelperPrev = self;
    return self;
  }

  void cleanup_CAiNavigatorLandConstruct_atexit()
  {
    (void)cleanup_CAiNavigatorLandConstruct();
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
 * Address: 0x005A73B0 (FUN_005A73B0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorLandConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCC7A0 (FUN_00BCC7A0, register_CAiNavigatorLandConstruct)
 *
 * What it does:
 * Initializes the global CAiNavigatorLand construct helper callbacks and
 * installs process-exit cleanup.
 */
int moho::register_CAiNavigatorLandConstruct()
{
  CAiNavigatorLandConstruct* const construct = AcquireCAiNavigatorLandConstruct();
  gpg::SerHelperBase* const self = HelperNode(*construct);
  construct->mHelperNext = self;
  construct->mHelperPrev = self;
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiNavigatorLandConstruct::Construct);
  construct->mDeleteCallback = &CAiNavigatorLandConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&cleanup_CAiNavigatorLandConstruct_atexit);
}

namespace
{
  struct CAiNavigatorLandConstructBootstrap
  {
    CAiNavigatorLandConstructBootstrap()
    {
      (void)moho::register_CAiNavigatorLandConstruct();
    }
  };

  [[maybe_unused]] CAiNavigatorLandConstructBootstrap gCAiNavigatorLandConstructBootstrap;
} // namespace

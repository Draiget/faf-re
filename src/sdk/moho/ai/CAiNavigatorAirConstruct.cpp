#include "moho/ai/CAiNavigatorAirConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

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
  alignas(CAiNavigatorAirConstruct) unsigned char gCAiNavigatorAirConstructStorage[sizeof(CAiNavigatorAirConstruct)] = {};
  bool gCAiNavigatorAirConstructConstructed = false;

  [[nodiscard]] gpg::SerHelperBase* HelperNode(CAiNavigatorAirConstruct& construct) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&construct.mHelperNext);
  }

  [[nodiscard]] CAiNavigatorAirConstruct* AcquireCAiNavigatorAirConstruct()
  {
    if (!gCAiNavigatorAirConstructConstructed) {
      new (gCAiNavigatorAirConstructStorage) CAiNavigatorAirConstruct();
      gCAiNavigatorAirConstructConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorAirConstruct*>(gCAiNavigatorAirConstructStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005A7F00 (FUN_005A7F00)
   *
   * What it does:
   * Populates one reflected `RRef` payload for a `CAiNavigatorAir` object.
   */
  [[nodiscard]] gpg::RRef* PopulateCAiNavigatorAirRef(gpg::RRef* const out, CAiNavigatorAir* const object)
  {
    gpg::RRef temp{};
    gpg::RRef_CAiNavigatorAir(&temp, object);
    *out = temp;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeCAiNavigatorAirRef(CAiNavigatorAir* const object)
  {
    gpg::RRef ref{};
    (void)PopulateCAiNavigatorAirRef(&ref, object);
    return ref;
  }

  /**
   * Address: 0x005A5640 (FUN_005A5640, construct body callback)
   *
   * What it does:
   * Allocates one `CAiNavigatorAir` and publishes it as unowned construct
   * result payload.
   */
  void ConstructAiNavigatorAirForResult(gpg::SerConstructResult* const result)
  {
    CAiNavigatorAir* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiNavigatorAir));
    if (storage) {
      object = new (storage) CAiNavigatorAir();
    }
    result->SetUnowned(MakeCAiNavigatorAirRef(object), 0u);
  }

  /**
   * Address: 0x00BF6F40 (FUN_00BF6F40, cleanup_CAiNavigatorAirConstruct)
   *
   * What it does:
   * Unlinks recovered CAiNavigatorAir construct helper node from intrusive
   * serializer chain.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorAirConstruct()
  {
    if (!gCAiNavigatorAirConstructConstructed) {
      return nullptr;
    }

    CAiNavigatorAirConstruct* const construct = AcquireCAiNavigatorAirConstruct();
    gpg::SerHelperBase* const self = HelperNode(*construct);
    if (construct->mHelperNext != nullptr && construct->mHelperPrev != nullptr) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    construct->mHelperNext = self;
    construct->mHelperPrev = self;
    return self;
  }

  /**
   * Address: 0x005A5600 (FUN_005A5600)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks the global
   * `CAiNavigatorAirConstruct` helper node and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CAiNavigatorAirConstructStartupThunk()
  {
    return cleanup_CAiNavigatorAirConstruct();
  }

  void cleanup_CAiNavigatorAirConstruct_atexit()
  {
    (void)cleanup_CAiNavigatorAirConstruct();
  }
} // namespace

/**
  * Alias of FUN_005A5630 (non-canonical helper lane).
 */
void CAiNavigatorAirConstruct::Construct(
  gpg::ReadArchive* const,
  const int,
  const int,
  gpg::SerConstructResult* const result
)
{
  if (!result) {
    return;
  }
  ConstructAiNavigatorAirForResult(result);
}

/**
 * Address: 0x005A7ED0 (FUN_005A7ED0, delete callback)
 */
void CAiNavigatorAirConstruct::Deconstruct(void* const object)
{
  delete static_cast<CAiNavigatorAir*>(object);
}

/**
 * Address: 0x005A74D0 (FUN_005A74D0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorAirConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCC840 (FUN_00BCC840, register_CAiNavigatorAirConstruct)
 *
 * What it does:
 * Initializes the global CAiNavigatorAir construct helper callbacks and
 * installs process-exit cleanup.
 */
int moho::register_CAiNavigatorAirConstruct()
{
  CAiNavigatorAirConstruct* const construct = AcquireCAiNavigatorAirConstruct();
  gpg::SerHelperBase* const self = HelperNode(*construct);
  construct->mHelperNext = self;
  construct->mHelperPrev = self;
  construct->mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CAiNavigatorAirConstruct::Construct);
  construct->mDeleteCallback = &CAiNavigatorAirConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&cleanup_CAiNavigatorAirConstruct_atexit);
}

namespace
{
  struct CAiNavigatorAirConstructBootstrap
  {
    CAiNavigatorAirConstructBootstrap()
    {
      (void)moho::register_CAiNavigatorAirConstruct();
    }
  };

  [[maybe_unused]] CAiNavigatorAirConstructBootstrap gCAiNavigatorAirConstructBootstrap;
} // namespace


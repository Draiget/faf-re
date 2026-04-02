#include "moho/ai/CAiBrainConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"

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
  CAiBrainConstruct gCAiBrainConstructStartupHelper{};

  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(CAiBrainConstruct& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  void InitializeHelperNode(CAiBrainConstruct& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(CAiBrainConstruct& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void ConstructCAiBrainForSerializer(gpg::ReadArchive*, int, int, gpg::SerConstructResult* const result)
  {
    if (!result) {
      return;
    }

    CAiBrain* const object = new (std::nothrow) CAiBrain();
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = object ? object->GetClass() : nullptr;
    result->SetUnowned(objectRef, 0u);
  }

  void DeleteConstructedCAiBrain(void* const objectPtr)
  {
    auto* const object = static_cast<CAiBrain*>(objectPtr);
    if (!object) {
      return;
    }

    delete object;
  }

  [[nodiscard]] gpg::SerHelperBase* cleanup_CAiBrainConstructStartup()
  {
    return UnlinkHelperNode(gCAiBrainConstructStartupHelper);
  }

  void cleanup_CAiBrainConstructStartupAtExit()
  {
    (void)cleanup_CAiBrainConstructStartup();
  }

  struct CAiBrainConstructStartupBootstrap
  {
    CAiBrainConstructStartupBootstrap()
    {
      (void)moho::register_CAiBrainConstructStartup();
    }
  };

  CAiBrainConstructStartupBootstrap gCAiBrainConstructStartupBootstrap;
} // namespace

/**
 * Address: 0x0057E3E0 (FUN_0057E3E0)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs construct/delete callbacks from
 * this helper object into the type descriptor.
 */
void CAiBrainConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

/**
 * Address: 0x00BCB3F0 (FUN_00BCB3F0, sub_BCB3F0)
 *
 * What it does:
 * Initializes the startup `CAiBrainConstruct` serializer-helper node,
 * installs construct/delete callbacks, and schedules cleanup at exit.
 */
int moho::register_CAiBrainConstructStartup()
{
  InitializeHelperNode(gCAiBrainConstructStartupHelper);
  gCAiBrainConstructStartupHelper.mConstructCallback =
    reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCAiBrainForSerializer);
  gCAiBrainConstructStartupHelper.mDeleteCallback = &DeleteConstructedCAiBrain;
  gCAiBrainConstructStartupHelper.RegisterConstructFunction();
  return std::atexit(&cleanup_CAiBrainConstructStartupAtExit);
}

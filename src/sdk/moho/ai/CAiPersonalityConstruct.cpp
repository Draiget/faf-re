#include "moho/ai/CAiPersonalityConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiPersonality.h"

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
  alignas(CAiPersonalityConstruct) unsigned char gCAiPersonalityConstructStorage[sizeof(CAiPersonalityConstruct)];
  bool gCAiPersonalityConstructConstructed = false;

  [[nodiscard]] gpg::SerHelperBase* HelperNode(CAiPersonalityConstruct& construct) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&construct.mHelperNext);
  }

  [[nodiscard]] CAiPersonalityConstruct* AcquireCAiPersonalityConstruct()
  {
    if (!gCAiPersonalityConstructConstructed) {
      new (gCAiPersonalityConstructStorage) CAiPersonalityConstruct();
      gCAiPersonalityConstructConstructed = true;
    }

    return reinterpret_cast<CAiPersonalityConstruct*>(gCAiPersonalityConstructStorage);
  }

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

  /**
   * Address: 0x00BF7710 (FUN_00BF7710, cleanup_CAiPersonalityConstruct)
   *
   * What it does:
   * Unlinks the global construct helper node and restores self-links.
   */
  gpg::SerHelperBase* cleanup_CAiPersonalityConstruct()
  {
    if (!gCAiPersonalityConstructConstructed) {
      return nullptr;
    }

    CAiPersonalityConstruct* const construct = reinterpret_cast<CAiPersonalityConstruct*>(gCAiPersonalityConstructStorage);
    gpg::SerHelperBase* const selfNode = HelperNode(*construct);
    if (construct->mHelperNext != nullptr && construct->mHelperPrev != nullptr) {
      construct->mHelperNext->mPrev = construct->mHelperPrev;
      construct->mHelperPrev->mNext = construct->mHelperNext;
    }

    construct->mHelperNext = selfNode;
    construct->mHelperPrev = selfNode;
    return selfNode;
  }

  void CleanupCAiPersonalityConstructAtexit()
  {
    (void)cleanup_CAiPersonalityConstruct();
  }
} // namespace

/**
 * Address: 0x005B69E0 (FUN_005B69E0)
 *
 * What it does:
 * Construct-callback lane for `CAiPersonality` reflection loading.
 */
void CAiPersonalityConstruct::Construct(
  gpg::ReadArchive* const, const int, const int, gpg::SerConstructResult* const result
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
 * Address: 0x005B92D0 (FUN_005B92D0)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiPersonalityConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiPersonalityType();
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
 * Address: 0x00BCD620 (FUN_00BCD620, register_CAiPersonalityConstruct)
 *
 * What it does:
 * Initializes the global personality construct helper and installs
 * process-exit cleanup.
 */
int moho::register_CAiPersonalityConstruct()
{
  CAiPersonalityConstruct* const construct = AcquireCAiPersonalityConstruct();
  gpg::SerHelperBase* const selfNode = HelperNode(*construct);
  construct->mHelperNext = selfNode;
  construct->mHelperPrev = selfNode;
  construct->mConstructCallback =
    reinterpret_cast<gpg::RType::construct_func_t>(&CAiPersonalityConstruct::Construct);
  construct->mDeleteCallback = &CAiPersonalityConstruct::Deconstruct;
  construct->RegisterConstructFunction();
  return std::atexit(&CleanupCAiPersonalityConstructAtexit);
}

namespace
{
  struct CAiPersonalityConstructBootstrap
  {
    CAiPersonalityConstructBootstrap()
    {
      (void)moho::register_CAiPersonalityConstruct();
    }
  };

  [[maybe_unused]] CAiPersonalityConstructBootstrap gCAiPersonalityConstructBootstrap;
} // namespace

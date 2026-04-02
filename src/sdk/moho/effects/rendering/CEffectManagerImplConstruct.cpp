#include "moho/effects/rendering/CEffectManagerImplConstruct.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  gpg::SerHelperBase* cleanup_CEffectManagerImplConstruct();
} // namespace moho

namespace
{
  gpg::RType* gSimType = nullptr;
  moho::CEffectManagerImplConstruct gCEffectManagerImplConstruct;

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  [[nodiscard]] moho::Sim* ReadOwnerSim(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCachedType<moho::Sim>(gSimType));
    return static_cast<moho::Sim*>(upcast.mObj);
  }

  /**
   * Address: 0x0066BB40 (FUN_0066BB40, Construct_CEffectManagerImpl)
   *
   * What it does:
   * Reads owner `Sim` pointer from archive tracked-pointer payload, allocates a
   * `CEffectManagerImpl`, and returns it through `SerConstructResult`.
   */
  void Construct_CEffectManagerImpl(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    moho::Sim* const ownerSim = ReadOwnerSim(archive);
    (void)ownerSim;
    moho::CEffectManagerImpl* const object = nullptr;

    if (!result) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = moho::CEffectManagerImpl::StaticGetClass();
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x0066C280 (FUN_0066C280, Delete_CEffectManagerImpl)
   *
   * What it does:
   * Executes deleting-dtor semantics for one `CEffectManagerImpl` instance.
   */
  void Delete_CEffectManagerImpl(void* const objectPtr)
  {
    auto* const object = static_cast<moho::CEffectManagerImpl*>(objectPtr);
    delete object;
  }

  void cleanup_CEffectManagerImplConstruct_atexit()
  {
    (void)moho::cleanup_CEffectManagerImplConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0066C0E0 (FUN_0066C0E0, gpg::SerConstructHelper_CEffectManagerImpl::Init)
   *
   * IDA signature:
   * int __thiscall gpg::SerConstructHelper_CEffectManagerImpl::Init(void (__cdecl **this)(void *));
   */
  void CEffectManagerImplConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CEffectManagerImpl::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BFC030 (FUN_00BFC030, cleanup_CEffectManagerImplConstruct)
   *
   * What it does:
   * Unlinks startup `CEffectManagerImplConstruct` helper node and restores
   * self-linked sentinel state.
   */
  gpg::SerHelperBase* cleanup_CEffectManagerImplConstruct()
  {
    return UnlinkHelperNode(gCEffectManagerImplConstruct);
  }

  /**
   * Address: 0x00BD45C0 (FUN_00BD45C0, register_CEffectManagerImplConstruct)
   *
   * What it does:
   * Initializes startup construct helper callbacks for `CEffectManagerImpl`
   * and installs process-exit cleanup.
   */
  int register_CEffectManagerImplConstruct()
  {
    InitializeHelperNode(gCEffectManagerImplConstruct);
    gCEffectManagerImplConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CEffectManagerImpl);
    gCEffectManagerImplConstruct.mDeleteCallback = &Delete_CEffectManagerImpl;
    gCEffectManagerImplConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_CEffectManagerImplConstruct_atexit);
  }
} // namespace moho

namespace
{
  struct CEffectManagerImplConstructBootstrap
  {
    CEffectManagerImplConstructBootstrap()
    {
      (void)moho::register_CEffectManagerImplConstruct();
    }
  };

  [[maybe_unused]] CEffectManagerImplConstructBootstrap gCEffectManagerImplConstructBootstrap;
} // namespace

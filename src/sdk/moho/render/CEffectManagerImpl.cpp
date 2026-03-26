#include "moho/render/CEffectManagerImpl.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/render/IEffect.h"

namespace moho
{
  gpg::RType* CEffectManagerImpl::sType = nullptr;

  gpg::RType* CEffectManagerImpl::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CEffectManagerImpl));
    }
    return sType;
  }

  /**
   * Address: 0x0066B400 (FUN_0066B400, Moho::CEffectManagerImpl::dtr thunk)
   * Address: 0x0066B450 (FUN_0066B450, Moho::CEffectManagerImpl::~CEffectManagerImpl body)
   */
  CEffectManagerImpl::~CEffectManagerImpl()
  {
    // Preserve dtor behavior: migrate still-active effects into the pending
    // destroy list, then purge that list.
    while (!mActiveEffects.empty()) {
      TDatListItem<IEffect, void>* const node = mActiveEffects.pop_front();
      mDestroyedEffects.push_back(node);
    }

    PurgeDestroyedEffects();
  }

  /**
   * Address: 0x0066B220 (FUN_0066B220, Moho::CEffectManagerImpl::GetSim)
   */
  Sim* CEffectManagerImpl::GetSim() const
  {
    return mSim;
  }

  /**
   * Address: 0x0066B230 (FUN_0066B230, Moho::CEffectManagerImpl::DestroyEffect)
   */
  void CEffectManagerImpl::DestroyEffect(IEffect* const effect)
  {
    effect->mManagerListNode.ListLinkBefore(&mDestroyedEffects);
  }

  /**
   * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
   */
  void CEffectManagerImpl::Tick()
  {
    // Keep iteration semantics from the binary: capture next before invoking
    // effect code so list mutation during callback remains safe.
    TDatListItem<IEffect, void>* node = mActiveEffects.mNext;
    while (node != &mActiveEffects) {
      TDatListItem<IEffect, void>* const current = node;
      node = node->mNext;
      IEffect::ManagerList::owner_from_member<IEffect, IEffect::ManagerListNode, &IEffect::mManagerListNode>(current)
        ->OnTick();
    }
  }

  /**
   * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
   */
  void CEffectManagerImpl::PurgeDestroyedEffects()
  {
    while (!mDestroyedEffects.empty()) {
      IEffect* const effect = IEffect::ManagerList::owner_from_member<
        IEffect,
        IEffect::ManagerListNode,
        &IEffect::mManagerListNode>(mDestroyedEffects.mNext);
      delete effect;
    }
  }
} // namespace moho

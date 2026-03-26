#pragma once

#include <cstddef>

#include "moho/containers/TDatList.h"
#include "moho/render/IEffectManager.h"

namespace moho
{
  class CEffectManagerImpl : public IEffectManager
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]]
    static gpg::RType* StaticGetClass();

  public:
    /**
     * Address: 0x0066B400 (FUN_0066B400, Moho::CEffectManagerImpl::dtr thunk)
     * Address: 0x0066B450 (FUN_0066B450, Moho::CEffectManagerImpl::~CEffectManagerImpl body)
     */
    ~CEffectManagerImpl() override;

    /**
     * Address: 0x0066B220 (FUN_0066B220, Moho::CEffectManagerImpl::GetSim)
     */
    [[nodiscard]]
    Sim* GetSim() const override;

    /**
     * Address: 0x0066B230 (FUN_0066B230, Moho::CEffectManagerImpl::DestroyEffect)
     *
     * What it does:
     * Moves one effect instance from its current manager list to the pending-destroy list.
     */
    void DestroyEffect(IEffect* effect) override;

    /**
     * Address: 0x0066B4F0 (FUN_0066B4F0, Moho::CEffectManagerImpl::Tick)
     *
     * What it does:
     * Runs per-frame update for all active effect objects.
     */
    void Tick() override;

    /**
     * Address: 0x0066B570 (FUN_0066B570, Moho::CEffectManagerImpl::PurgeDestroyedEffects)
     *
     * What it does:
     * Deletes and removes all effects that were queued for destruction.
     */
    void PurgeDestroyedEffects() override;

  public:
    Sim* mSim;                              // +0x04
    TDatList<IEffect, void> mActiveEffects;   // +0x08
    TDatList<IEffect, void> mDestroyedEffects; // +0x10
  };

  static_assert(offsetof(CEffectManagerImpl, mSim) == 0x04, "CEffectManagerImpl::mSim offset must be 0x04");
  static_assert(
    offsetof(CEffectManagerImpl, mActiveEffects) == 0x08, "CEffectManagerImpl::mActiveEffects offset must be 0x08"
  );
  static_assert(
    offsetof(CEffectManagerImpl, mDestroyedEffects) == 0x10,
    "CEffectManagerImpl::mDestroyedEffects offset must be 0x10"
  );
  static_assert(sizeof(CEffectManagerImpl) == 0x18, "CEffectManagerImpl size must be 0x18");
} // namespace moho

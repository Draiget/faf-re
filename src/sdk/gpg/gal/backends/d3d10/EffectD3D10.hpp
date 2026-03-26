#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/EffectContext.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  class EffectTechniqueD3D10;
  class EffectVariableD3D10;

  /**
   * VFTABLE: 0x00D4885C
   * COL:  0x00E53810
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpggal\EffectD3D10.cpp
   */
  class EffectD3D10
  {
  public:
    /**
     * Address: 0x0094C070 (FUN_0094C070)
     *
     * What it does:
     * Initializes effect-context storage lanes, then binds caller context/effect handles.
     */
    EffectD3D10(EffectContext* context, void* dxEffect);

    /**
     * Address: 0x0094C050 (FUN_0094C050)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_0094BF80` body lanes.
     */
    virtual ~EffectD3D10();

    /**
     * Address: 0x0094B5D0 (FUN_0094B5D0)
     *
     * What it does:
     * Returns the embedded effect-context subobject at `this+0x04`.
     */
    virtual EffectContext* GetContext();

    /**
     * Address: 0x0094BC60 (FUN_0094BC60)
     *
     * What it does:
     * Enumerates valid effect techniques and appends wrapped D3D10 technique handles.
     */
    virtual void GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechniqueD3D10>>& outTechniques);

    /**
     * Address: 0x0094B8A0 (FUN_0094B8A0)
     *
     * What it does:
     * Looks up an effect variable by name and returns a wrapped variable handle.
     */
    virtual boost::shared_ptr<EffectVariableD3D10> SetMatrix(const char* variableName);

    /**
     * Address: 0x0094BA80 (FUN_0094BA80)
     *
     * What it does:
     * Looks up an effect technique by name and returns a wrapped technique handle.
     */
    virtual boost::shared_ptr<EffectTechniqueD3D10> SetTechnique(const char* techniqueName);

    /**
     * Address: 0x0094B5E0 (FUN_0094B5E0)
     *
     * What it does:
     * No-op D3D10 effect reset slot.
     */
    virtual void OnReset();

    /**
     * Address: 0x0094B5F0 (FUN_0094B5F0)
     *
     * What it does:
     * No-op D3D10 effect lost-device slot.
     */
    virtual void OnLost();

  public:
    EffectContext context_{};         // +0x04
    std::uint8_t contextPad_[0x60]{}; // +0x08 .. +0x67
    void* dxEffect_ = nullptr;        // +0x68
  };

  static_assert(offsetof(EffectD3D10, context_) == 0x04, "EffectD3D10::context_ offset must be 0x04");
  static_assert(offsetof(EffectD3D10, dxEffect_) == 0x68, "EffectD3D10::dxEffect_ offset must be 0x68");
  static_assert(sizeof(EffectD3D10) == 0x6C, "EffectD3D10 size must be 0x6C");
} // namespace gpg::gal

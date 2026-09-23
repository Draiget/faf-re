#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
  class EffectTechnique;
  class EffectVariable;

  /**
   * VFTABLE: 0x00D4885C
   * COL:  0x00E53810
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpggal\EffectD3D10.cpp
   *
   * Unlike `EffectD3D9` it has no weak-this: its techniques and variables
   * AddRef the native effect instead of referencing the wrapper.
   */
  class EffectD3D10 : public Effect
  {
  public:
    /**
     * Address: 0x0094C070 (FUN_0094C070)
     * Address: 0x0094B580 (FUN_0094B580 -- the default constructor: installs the
     * `Effect` then `EffectD3D10` vtables and builds an empty context. Zero callers,
     * unreachable; nothing in the binary constructs an `EffectD3D10` without a
     * context. It was once called from the body of this constructor as if it were
     * part of it, which constructed `context_` twice.)
     *
     * What it does:
     * Builds an empty context and a null effect handle (`EffectContext()` at
     * 0x0093FBE0, `mov [esi+0x68],0`), then adopts the caller's through
     * `SetEffect`. `DeviceD3D10::CreateEffect` constructs it (0x008FEF7A).
     */
    EffectD3D10(const EffectContext& context, void* dxEffect);

    /**
     * Address: 0x0094BF80 (FUN_0094BF80)
     * Address: 0x0094C050 (FUN_0094C050, the scalar deleting destructor)
     * Slot: 0
     *
     * What it does:
     * `Reset()`; `context_` is then destroyed as a member (0x0093F950), which
     * is the second and last call the binary body makes.
     */
    ~EffectD3D10() override;

    /**
     * Address: 0x0094B5D0 (FUN_0094B5D0)
     * Slot: 1
     *
     * What it does:
     * Returns the context the effect was built from.
     */
    EffectContext* GetContext() override;

    /**
     * Address: 0x0094BC60 (FUN_0094BC60)
     * Slot: 2
     *
     * What it does:
     * Walks the effect's techniques by index and appends a wrapper for every
     * valid one.
     */
    void GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques) override;

    /**
     * Address: 0x0094B8A0 (FUN_0094B8A0)
     * Slot: 3
     *
     * What it does:
     * Wraps the effect variable called `name`; throws when there is none.
     */
    boost::shared_ptr<EffectVariable> GetVariable(const char* name) override;

    /**
     * Address: 0x0094BA80 (FUN_0094BA80)
     * Slot: 4
     *
     * What it does:
     * Wraps the technique called `name`; throws when there is none.
     */
    boost::shared_ptr<EffectTechnique> GetTechnique(const char* name) override;

    /**
     * Address: 0x0094B5E0 (FUN_0094B5E0)
     * Slot: 5
     *
     * What it does:
     * Nothing: a D3D10 effect survives a device reset.
     */
    void OnReset() override;

    /**
     * Address: 0x0094B5F0 (FUN_0094B5F0)
     * Slot: 6
     *
     * What it does:
     * Nothing, for the same reason.
     */
    void OnLost() override;

    /**
     * Address: 0x0094BF10 (FUN_0094BF10)
     *
     * What it does:
     * Releases the native effect and assigns a fresh context over `context_`:
     * a temporary `EffectContext` (0x0093FBE0), `operator=` (0x00942CF0), and the
     * temporary's destructor (0x0093F950).
     */
    void Reset();

    /**
     * Address: 0x0094BFE0 (FUN_0094BFE0)
     *
     * What it does:
     * Resets, copies `context` into `context_`, adopts `dxEffect`, and empties the
     * copied source buffer -- the effect keeps the settings but not the bytes.
     */
    void SetEffect(const EffectContext& context, void* dxEffect);

  public:
    EffectContext context_;    // +0x04 .. +0x67
    void* dxEffect_ = nullptr; // +0x68
  };

  static_assert(offsetof(EffectD3D10, context_) == 0x04, "EffectD3D10::context_ offset must be 0x04");
  static_assert(offsetof(EffectD3D10, dxEffect_) == 0x68, "EffectD3D10::dxEffect_ offset must be 0x68");
  static_assert(sizeof(EffectD3D10) == 0x6C, "EffectD3D10 size must be 0x6C");
} // namespace gpg::gal

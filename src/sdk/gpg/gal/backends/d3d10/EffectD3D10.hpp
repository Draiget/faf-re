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
     * Address: 0x0094B580 (FUN_0094B580 -- the default constructor: installs the
     * `Effect` then `EffectD3D10` vtables and builds an empty context. Zero callers,
     * unreachable; nothing in the binary constructs an `EffectD3D10` without a
     * context. It was once called from the body of this constructor as if it were
     * part of it, which constructed `context_` twice.)
     *
     * What it does:
     * Builds an empty context and a null effect handle (`EffectContext()` at
     * 0x0093FBE0, `mov [esi+0x68],0`), then binds the caller's through `AssignState`.
     */
    EffectD3D10(EffectContext* context, void* dxEffect);

    /**
     * Address: 0x0094BF80 (FUN_0094BF80)
     * Address: 0x0094C050 (FUN_0094C050, the scalar deleting destructor)
     *
     * What it does:
     * Resets the state; `context_` is then destroyed as a member (0x0093F950),
     * which is the second and last call the binary body makes.
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

    /**
     * Address: 0x0094BF10 (FUN_0094BF10)
     *
     * What it does:
     * Releases the native effect and assigns a fresh context over `context_`:
     * a temporary `EffectContext` (0x0093FBE0), `operator=` (0x00942CF0), and the
     * temporary's destructor (0x0093F950).
     */
    void ResetState();

    /**
     * Address: 0x0094BFE0 (FUN_0094BFE0)
     *
     * What it does:
     * Resets, copies `source` into `context_`, adopts `dxEffect`, and empties the
     * copied source buffer -- the effect keeps the settings but not the bytes.
     */
    void AssignState(const EffectContext* source, void* dxEffect);

  public:
    EffectContext context_{};  // +0x04 .. +0x67
    void* dxEffect_ = nullptr; // +0x68
  };

  static_assert(offsetof(EffectD3D10, context_) == 0x04, "EffectD3D10::context_ offset must be 0x04");
  static_assert(offsetof(EffectD3D10, dxEffect_) == 0x68, "EffectD3D10::dxEffect_ offset must be 0x68");
  static_assert(sizeof(EffectD3D10) == 0x6C, "EffectD3D10 size must be 0x6C");
} // namespace gpg::gal

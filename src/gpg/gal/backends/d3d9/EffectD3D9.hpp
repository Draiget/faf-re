#pragma once

#include <cstddef>

#include <d3dx9effect.h>

#include "boost/enable_shared_from_this.h"
#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    class EffectTechnique;
    class EffectVariable;

    /**
     * VFTABLE: 0x00D47D6C
     * COL:  0x00E5331C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectD3D9.cpp
     *
     * `enable_shared_from_this` is the first declared base: both constructors
     * build its weak-this (+0x04) before the `Effect` subobject (unwind states
     * 0 and 1 at 0x00942EE0), and MSVC still places the polymorphic `Effect`
     * at +0x00. The techniques and variables it hands out hold it weakly
     * through `shared_from_this()` and lock it on every call.
     */
    class EffectD3D9 : public boost::enable_shared_from_this<EffectD3D9>, public Effect
    {
    public:
        /**
         * Address: 0x00942EE0 (FUN_00942EE0)
         * Address: 0x009419E0 (FUN_009419E0 -- the default constructor: the
         * same weak-this, vtable and empty-context setup with a null effect,
         * without the `SetEffect`. Zero callers, unreachable; nothing in the
         * binary builds an `EffectD3D9` without a context. It was once called
         * from this constructor as if it were part of it.)
         *
         * What it does:
         * Starts from an empty context and a null effect, then adopts `context`
         * and `effect` through `SetEffect`. `DeviceD3D9`'s two effect builders
         * construct it (0x008F0F22, 0x008F128E).
         */
        EffectD3D9(const EffectContext& context, ID3DXEffect* effect);

        /**
         * Address: 0x00942DD0 (FUN_00942DD0)
         * Address: 0x00942EC0 (FUN_00942EC0, the scalar deleting destructor)
         * Slot: 0
         *
         * What it does:
         * `Reset()`; the context, the `Effect` base and the weak-this then go
         * as a member and bases.
         */
        ~EffectD3D9() override;

        /**
         * Address: 0x009415B0 (FUN_009415B0)
         * Slot: 1
         *
         * What it does:
         * Returns the context the effect was built from.
         */
        EffectContext* GetContext() override;

        /**
         * Address: 0x00942920 (FUN_00942920)
         * Slot: 2
         *
         * What it does:
         * Walks the D3DX effect's valid techniques and appends a wrapper for
         * each to `outTechniques`.
         */
        void GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques) override;

        /**
         * Address: 0x00941D70 (FUN_00941D70)
         * Slot: 3
         *
         * What it does:
         * Wraps the effect parameter called `name`; throws when there is none.
         */
        boost::shared_ptr<EffectVariable> GetVariable(const char* name) override;

        /**
         * Address: 0x00941F60 (FUN_00941F60)
         * Slot: 4
         *
         * What it does:
         * Wraps the technique called `name`; throws when there is none.
         */
        boost::shared_ptr<EffectTechnique> GetTechnique(const char* name) override;

        /**
         * Address: 0x00942150 (FUN_00942150)
         * Slot: 5
         *
         * What it does:
         * Points the effect at the pipeline state's state manager again and
         * forwards the reset to D3DX.
         */
        void OnReset() override;

        /**
         * Address: 0x00942290 (FUN_00942290)
         * Slot: 6
         *
         * What it does:
         * Forwards the device loss to D3DX.
         */
        void OnLost() override;

        /**
         * Address: 0x00942350 (FUN_00942350)
         *
         * What it does:
         * Returns the D3DX effect; throws when there is none.
         */
        ID3DXEffect* GetDxEffect();

        /**
         * Address: 0x00942D60 (FUN_00942D60)
         *
         * What it does:
         * Releases the D3DX effect and assigns an empty context over the
         * current one.
         */
        void Reset();

        /**
         * Address: 0x00942E50 (FUN_00942E50)
         *
         * What it does:
         * Resets, copies `context`, adopts `effect`, then empties the copied
         * source buffer: the effect keeps the settings but not the bytes.
         */
        void SetEffect(const EffectContext& context, ID3DXEffect* effect);

    public:
        EffectContext effectContext_;      // +0x0C
        ID3DXEffect* dxEffect_ = nullptr;  // +0x70
    };

    static_assert(offsetof(EffectD3D9, effectContext_) == 0x0C, "EffectD3D9::effectContext_ offset must be 0x0C");
    static_assert(offsetof(EffectD3D9, dxEffect_) == 0x70, "EffectD3D9::dxEffect_ offset must be 0x70");
    static_assert(sizeof(EffectD3D9) == 0x74, "EffectD3D9 size must be 0x74");
} // namespace gpg::gal

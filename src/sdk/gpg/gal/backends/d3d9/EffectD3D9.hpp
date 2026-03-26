#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/EffectContext.hpp"
#include "legacy/containers/Vector.h"
#include "platform/Platform.h"

namespace gpg::gal
{
    class EffectTechniqueD3D9;
    class EffectVariableD3D9;

    /**
     * VFTABLE: 0x00D47D6C
     * COL:  0x00E5331C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectD3D9.cpp
     */
    class EffectD3D9
    {
    public:
        /**
         * Address: 0x00942EE0 (FUN_00942EE0)
         *
         * What it does:
         * Initializes weak-self/context/effect lanes and binds caller-provided context/effect state.
         */
        EffectD3D9(EffectContext* context, void* dxEffect);

        /**
         * Address: 0x00942EC0 (FUN_00942EC0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates teardown to `FUN_00942DD0`.
         */
        virtual ~EffectD3D9();

        /**
         * Address: 0x009415B0 (FUN_009415B0)
         *
         * What it does:
         * Returns the embedded effect-context subobject at `this+0x0C`.
         */
        virtual EffectContext* GetContext();

        /**
         * Address: 0x00942920 (FUN_00942920)
         *
         * What it does:
         * Enumerates valid techniques from the backing D3DX effect and appends wrappers.
         */
        virtual HRESULT GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechniqueD3D9>>& outTechniques);

        /**
         * Address: 0x00941D70 (FUN_00941D70)
         *
         * What it does:
         * Looks up an effect parameter by name and returns a wrapped variable handle.
         */
        virtual boost::shared_ptr<EffectVariableD3D9> SetMatrix(const char* variableName);

        /**
         * Address: 0x00941F60 (FUN_00941F60)
         *
         * What it does:
         * Looks up a technique by name and returns a shared wrapper bound to this effect.
         */
        virtual boost::shared_ptr<EffectTechniqueD3D9> SetTechnique(const char* techniqueName);

        /**
         * Address: 0x00942150 (FUN_00942150)
         *
         * What it does:
         * Rebinds effect state manager wiring and forwards reset notifications.
         */
        virtual void OnReset();

        /**
         * Address: 0x00942290 (FUN_00942290)
         *
         * What it does:
         * Forwards device-lost notifications to the retained D3DX effect.
         */
        virtual HRESULT OnLost();

        /**
         * Address: 0x00942350 (FUN_00942350)
         *
         * What it does:
         * Returns the backing D3DX effect handle and throws when it is missing.
         */
        void* GetDxEffect();

    public:
        boost::weak_ptr<EffectD3D9> selfWeak_{}; // +0x04 .. +0x0B
        EffectContext effectContext_{};         // +0x0C
        std::uint8_t effectContextPad_[0x60]{}; // +0x10 .. +0x6F (pending full EffectContext lift)
        void* dxEffect_ = nullptr;              // +0x70
    };

    static_assert(offsetof(EffectD3D9, selfWeak_) == 0x04, "EffectD3D9::selfWeak_ offset must be 0x04");
    static_assert(offsetof(EffectD3D9, effectContext_) == 0x0C, "EffectD3D9::effectContext_ offset must be 0x0C");
    static_assert(offsetof(EffectD3D9, dxEffect_) == 0x70, "EffectD3D9::dxEffect_ offset must be 0x70");
    static_assert(sizeof(EffectD3D9) == 0x74, "EffectD3D9 size must be 0x74");
}

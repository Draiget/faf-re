#include "Effect.hpp"
#include "EffectVariable.hpp"

#include "gpg/gal/Device.hpp"

namespace gpg::gal
{
    /**
     * Address: 0x009415A0 (FUN_009415A0)
     *
     * What it does:
     * Installs the abstract effect vtable.
     */
    Effect::Effect() = default;

    /**
     * Address: 0x00941590 (FUN_00941590)
     *
     * What it does:
     * Reinstalls the abstract effect vtable (`mov [ecx], 0x00D47D24; ret`).
     * Both backend destructors inline it; this out-of-line copy is what the
     * backend constructors' unwind funclets jump to (0x00B5DD8E, 0x00B5DF6A,
     * 0x00B5DF9E, 0x00B5E8F3, 0x00B5EA63, 0x00B5EA83).
     */
    Effect::~Effect() = default;

    /**
     * Address: 0x00942F70 (FUN_00942F70)
     *
     * What it does:
     * Installs the abstract effect-variable vtable.
     */
    EffectVariable::EffectVariable() = default;

    /**
     * Address: 0x00942F60 (FUN_00942F60)
     *
     * What it does:
     * Reinstalls the abstract effect-variable vtable (`mov [ecx], 0x00D47E44;
     * ret`). Both backend destructors inline it; this out-of-line copy is what
     * the backend constructors' unwind funclets jump to (0x00B5DFC3,
     * 0x00B5DFEE, 0x00B5EAA3, 0x00B5EAC6). Formerly an empty
     * `ApplyEffectVariableBaseVftableLane` in D3D9Interfaces.cpp.
     */
    EffectVariable::~EffectVariable() = default;

    /**
     * Address: 0x0093F5B0 (FUN_0093F5B0)
     * Mangled: ?Create@Effect@gal@gpg@@SA?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@ABVEffectContext@23@@Z
     *
     * What it does:
     * Has the active device build the effect: device slot 9, with this
     * call's own return slot forwarded as the callee's.
     */
    boost::shared_ptr<Effect> Effect::Create(const EffectContext& context)
    {
        return Device::GetInstance()->CreateEffect(context);
    }
} // namespace gpg::gal

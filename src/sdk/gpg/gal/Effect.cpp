#include "Effect.hpp"

#include "gpg/gal/Device.hpp"

namespace gpg::gal
{
    namespace
    {
        class DeviceCreateEffectSlotView
        {
        public:
            virtual void Slot0() = 0;
            virtual void Slot1() = 0;
            virtual void Slot2() = 0;
            virtual void Slot3() = 0;
            virtual void Slot4() = 0;
            virtual void Slot5() = 0;
            virtual void Slot6() = 0;
            virtual void Slot7() = 0;
            virtual void Slot8() = 0;
            virtual boost::shared_ptr<Effect>* CreateEffect(
                boost::shared_ptr<Effect>* outEffect,
                const EffectContext* context
            ) = 0;
        };
    }

    /**
     * Address: 0x0093F5B0 (FUN_0093F5B0)
     * Mangled: ?Create@Effect@gal@gpg@@SA?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@ABVEffectContext@23@@Z
     *
     * EffectContext const &
     *
     * IDA signature:
     * int __cdecl gpg::gal::Effect::Create(int a1, int a2);
     *
     * What it does:
     * Creates one backend effect instance by forwarding the output shared_ptr
     * lane and context payload to device virtual slot 9 (`CreateEffect`).
     */
    boost::shared_ptr<Effect> Effect::Create(const EffectContext& context)
    {
        boost::shared_ptr<Effect> createdEffect{};
        auto* const device = reinterpret_cast<DeviceCreateEffectSlotView*>(Device::GetInstance());
        (void)device->CreateEffect(&createdEffect, &context);
        return createdEffect;
    }
}

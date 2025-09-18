// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho
{
    /**
     * VFTABLE: 0x00E1E9CC
     * COL:  0x00E75AF8
     */
    class CAiAttackerImpl
    {
    public:
        /**
         * Address: 0x005D6A60
         * Slot: 0
         * Demangled: public: __thiscall Moho::CAiAttackerImpl::~CAiAttackerImpl()
         */
        virtual ~CAiAttackerImpl();

        /**
         * Address: 0x005D6D30
         * Slot: 1
         * Demangled: Moho::CAiAttackerImpl::WeaponsOnDestroy
         */
        virtual void WeaponsOnDestroy() = 0;

        /**
         * Address: 0x005D5D60
         * Slot: 2
         * Demangled: Moho::CAiAttackerImpl::GetUnit
         */
        virtual void GetUnit() = 0;

        /**
         * Address: 0x005D6D80
         * Slot: 3
         * Demangled: Moho::CAiAttackerImpl::WeaponsBusy
         */
        virtual void WeaponsBusy() = 0;

        /**
         * Address: 0x005D5D80
         * Slot: 4
         * Demangled: Moho::CAiAttackerImpl::GetTaskStage
         */
        virtual void GetTaskStage() = 0;

        /**
         * Address: 0x005D76E0
         * Slot: 5
         * Demangled: Moho::CAiAttackerImpl::CreateWeapon
         */
        virtual void CreateWeapon() = 0;

        /**
         * Address: 0x005D5D90
         * Slot: 6
         * Demangled: Moho::CAiAttackerImpl::GetWeaponCount
         */
        virtual void GetWeaponCount() = 0;

        /**
         * Address: 0x005D77D0
         * Slot: 7
         * Demangled: Moho::CAiAttackerImpl::GetWeapon
         */
        virtual void GetWeapon() = 0;

        /**
         * Address: 0x005D75B0
         * Slot: 8
         * Demangled: Moho::CAiAttackerImpl::SetDesiredTarget
         */
        virtual void SetDesiredTarget() = 0;

        /**
         * Address: 0x005D5D70
         * Slot: 9
         * Demangled: Moho::CAiAttackerImpl::GetDesiredTarget
         */
        virtual void GetDesiredTarget() = 0;

        /**
         * Address: 0x005D7570
         * Slot: 10
         * Demangled: Moho::CAiAttackerImpl::OnWeaponHaltFire
         */
        virtual void OnWeaponHaltFire() = 0;

        /**
         * Address: 0x005D6FA0
         * Slot: 11
         * Demangled: Moho::CAiAttackerImpl::CanAttackTarget
         */
        virtual void CanAttackTarget() = 0;

        /**
         * Address: 0x005D6F40
         * Slot: 12
         * Demangled: Moho::CAiAttackerImpl::PickTarget
         */
        virtual void PickTarget() = 0;

        /**
         * Address: 0x005D7A10
         * Slot: 13
         * Demangled: Moho::CAiAttackerImpl::FindBestEnemy
         */
        virtual void FindBestEnemy() = 0;

        /**
         * Address: 0x005D6DC0
         * Slot: 14
         * Demangled: Moho::CAiAttackerImpl::GetTargetWeapon
         */
        virtual void GetTargetWeapon() = 0;

        /**
         * Address: 0x005D6E30
         * Slot: 15
         * Demangled: Moho::CAiAttackerImpl::GetPrimaryWeapon
         */
        virtual void GetPrimaryWeapon() = 0;

        /**
         * Address: 0x005D6E80
         * Slot: 16
         * Demangled: Moho::CAiAttackerImpl::GetMaxWeaponRange
         */
        virtual void GetMaxWeaponRange() = 0;

        /**
         * Address: 0x005D7190
         * Slot: 17
         * Demangled: Moho::CAiAttackerImpl::VectorIsWithinWeaponAttackRange
         */
        virtual void VectorIsWithinWeaponAttackRange() = 0;

        /**
         * Address: 0x005D70E0
         * Slot: 18
         * Demangled: Moho::CAiAttackerImpl::VectorIsWithinAttackRange
         */
        virtual void VectorIsWithinAttackRange() = 0;

        /**
         * Address: 0x005D7090
         * Slot: 19
         * Demangled: Moho::CAiAttackerImpl::TargetIsWithinWeaponAttackRange
         */
        virtual void TargetIsWithinWeaponAttackRange() = 0;

        /**
         * Address: 0x005D7000
         * Slot: 20
         * Demangled: Moho::CAiAttackerImpl::TargetIsWithinAttackRange
         */
        virtual void TargetIsWithinAttackRange() = 0;

        /**
         * Address: 0x005D7210
         * Slot: 21
         * Demangled: Moho::CAiAttackerImpl::IsTooClose
         */
        virtual void IsTooClose() = 0;

        /**
         * Address: 0x005D7340
         * Slot: 22
         * Demangled: Moho::CAiAttackerImpl::IsTargetExempt
         */
        virtual void IsTargetExempt() = 0;

        /**
         * Address: 0x005D72B0
         * Slot: 23
         * Demangled: Moho::CAiAttackerImpl::HasSlavedTarget
         */
        virtual void HasSlavedTarget() = 0;

        /**
         * Address: 0x005D5DB0
         * Slot: 24
         * Demangled: Moho::CAiAttackerImpl::ResetReportingState
         */
        virtual void ResetReportingState() = 0;

        /**
         * Address: 0x005D7800
         * Slot: 25
         * Demangled: Moho::CAiAttackerImpl::TransmitProjectileImpactEvent
         */
        virtual void TransmitProjectileImpactEvent() = 0;

        /**
         * Address: 0x005D7870
         * Slot: 26
         * Demangled: Moho::CAiAttackerImpl::TransmitBeamImpactEvent
         */
        virtual void TransmitBeamImpactEvent() = 0;

        /**
         * Address: 0x005D8650
         * Slot: 27
         * Demangled: Moho::CAiAttackerImpl::ForceEngage
         */
        virtual void ForceEngage() = 0;

        /**
         * Address: 0x005D5DC0
         * Slot: 28
         * Demangled: Moho::CAiAttackerImpl::PushStack
         */
        virtual void PushStack() = 0;
    };

    /**
     * VFTABLE: 0x00E1EB3C
     * COL:  0x00E75600
     */
    class CAiAttackerImplGetUnit_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB44
     * COL:  0x00E755B0
     */
    class CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB4C
     * COL:  0x00E75560
     */
    class CAiAttackerImplGetWeaponCount_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB54
     * COL:  0x00E75510
     */
    class CAiAttackerImplSetDesiredTarget_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB5C
     * COL:  0x00E754C0
     */
    class CAiAttackerImplGetDesiredTarget_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB64
     * COL:  0x00E75470
     */
    class CAiAttackerImplStop_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB6C
     * COL:  0x00E75420
     */
    class CAiAttackerImplCanAttackTarget_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB74
     * COL:  0x00E753D0
     */
    class CAiAttackerImplFindBestEnemy_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB7C
     * COL:  0x00E75380
     */
    class CAiAttackerImplGetTargetWeapon_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB84
     * COL:  0x00E75330
     */
    class CAiAttackerImplGetPrimaryWeapon_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB8C
     * COL:  0x00E752E0
     */
    class CAiAttackerImplGetMaxWeaponRange_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB94
     * COL:  0x00E75290
     */
    class CAiAttackerImplIsWithinAttackRange_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EB9C
     * COL:  0x00E75240
     */
    class CAiAttackerImplIsTooClose_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EBA4
     * COL:  0x00E751F0
     */
    class CAiAttackerImplIsTargetExempt_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EBAC
     * COL:  0x00E751A0
     */
    class CAiAttackerImplHasSlavedTarget_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EBB4
     * COL:  0x00E75150
     */
    class CAiAttackerImplResetReportingState_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E1EBBC
     * COL:  0x00E75100
     */
    class CAiAttackerImplForceEngage_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

} // namespace moho

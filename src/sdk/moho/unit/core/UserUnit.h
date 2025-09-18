// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <cstdint>

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho {
    class SSTIEntityVariableData;
	class UserUnitWeapon;
} // forward decl

namespace moho {
    /**
     * VFTABLE: 0x00E4D93C
     * COL:  0x00E9F48C
     */
    class UserUnit
    {
    public:
        /**
         * Address: 0x008BF990
         * Slot: 0
         * Demangled: sub_8BF990
         */
        virtual void sub_8BF990() = 0;

        /**
         * Address: 0x008C0A30
         * Slot: 1
         * Demangled: moho::UserUnit::Tick
         */
        virtual void Tick() = 0;

        /**
         * Address: 0x008BF120
         * Slot: 2
         * Demangled: moho::UserUnit::IsUserUnit1
         */
        virtual void IsUserUnit1() = 0;

        /**
         * Address: 0x008BF110
         * Slot: 3
         * Demangled: moho::UserUnit::IsUserUnit2
         */
        virtual void IsUserUnit2() = 0;

        /**
         * Address: 0x008BF170
         * Slot: 4
         * Demangled: moho::UserUnit::GetUnitformScale
         */
        virtual void GetUnitformScale() = 0;

        /**
         * Address: 0x008BF150
         * Slot: 5
         * Demangled: moho::UserUnit::GetCommandQueue1
         */
        virtual void GetCommandQueue1() = 0;

        /**
         * Address: 0x008BF130
         * Slot: 6
         * Demangled: moho::UserUnit::GetCommandQueue2
         */
        virtual void GetCommandQueue2() = 0;

        /**
         * Address: 0x008BF160
         * Slot: 7
         * Demangled: moho::UserUnit::GetFactoryCommandQueue1
         */
        virtual void GetFactoryCommandQueue1() = 0;

        /**
         * Address: 0x008BF140
         * Slot: 8
         * Demangled: moho::UserUnit::GetFactoryCommandQueue2
         */
        virtual void GetFactoryCommandQueue2() = 0;

        /**
         * Address: 0x008B8EB0
         * Slot: 9
         * Demangled: public: virtual void __thiscall moho::UserEntity::UpdateEntityData(struct moho::SSTIEntityVariableData const near &)
         */
        virtual void UpdateEntityData(moho::SSTIEntityVariableData const&) = 0;

        /**
         * Address: 0x008C09B0
         * Slot: 10
         * Demangled: moho::UserUnit::UpdateVisibility
         */
        virtual void UpdateVisibility() = 0;

        /**
         * Address: 0x008B8530
         * Slot: 11
         * Demangled: public: virtual bool __thiscall moho::UserEntity::RequiresUIRefresh(void)const
         */
        virtual bool RequiresUIRefresh() const = 0;

        /**
         * Address: 0x008C0500
         * Slot: 12
         * Demangled: moho::UserUnit::Select
         */
        virtual void Select() = 0;

        /**
         * Address: 0x008BEFB0
         * Slot: 13
         * Demangled: moho::UserUnit::IsBeingBuilt
         */
        virtual void IsBeingBuilt() = 0;

        /**
         * Address: 0x008C1350
         * Slot: 14
         * Demangled: moho::UserUnit::NotifyFocusArmyUnitDamaged
         */
        virtual void NotifyFocusArmyUnitDamaged() = 0;

        /**
         * Address: 0x008C00E0
         * Slot: 15
         * Demangled: moho::UserUnit::CreateMeshInstance
         */
        virtual void CreateMeshInstance() = 0;

        /**
         * Address: 0x008C04D0
         * Slot: 16
         * Demangled: protected: virtual void __thiscall moho::UserEntity::DestroyMeshInstance(void)
         */
        virtual void DestroyMeshInstance() = 0;

        /**
         * Address: 0x008BFC50
         * Slot: 17
         * Demangled: moho::UserUnit::FindWeaponBy
         */
        virtual void FindWeaponBy() = 0;

        /**
         * Address: 0x008BFD70
         * Slot: 18
         * Demangled: moho::UserUnit::GetWaterIntel
         */
        virtual void GetWaterIntel() = 0;

        /**
         * Address: 0x008BFE50
         * Slot: 19
         * Demangled: moho::UserUnit::GetMaxCounterIntel
         */
        virtual void GetMaxCounterIntel() = 0;

        /**
         * Address: 0x008BEFD0
         * Slot: 20
         * Demangled: moho::UserUnit::GetAutoMode
         */
        virtual void GetAutoMode() = 0;

        /**
         * Address: 0x008BEFE0
         * Slot: 21
         * Demangled: moho::UserUnit::IsAutoSurfaceMode
         */
        virtual void IsAutoSurfaceMode() = 0;

        /**
         * Address: 0x008BEFF0
         * Slot: 22
         * Demangled: moho::UserUnit::Func1
         */
        virtual void Func1() = 0;

        /**
         * Address: 0x008BF000
         * Slot: 23
         * Demangled: moho::UserUnit::IsOverchargePaused
         */
        virtual void IsOverchargePaused() = 0;

        /**
         * Address: 0x008BF010
         * Slot: 24
         * Demangled: moho::UserUnit::GetCustomName
         */
        virtual void GetCustomName() = 0;

        /**
         * Address: 0x008BF060
         * Slot: 25
         * Demangled: moho::UserUnit::GetFuel
         */
        virtual void GetFuel() = 0;

        /**
         * Address: 0x008BF070
         * Slot: 26
         * Demangled: moho::UserUnit::GetShield
         */
        virtual void GetShield() = 0;

    public:
        // 0x148..0x1AF — unknown unit fields
        std::uint8_t  pad_0148_01B0[0x1B0 - 0x148]{};

        // 0x1B0
        bool          Paused;

        // 0x1B1..0x1BB — pad to float alignment
        std::uint8_t  pad_01B1_01BC[0x1BC - 0x1B1]{};

        // 0x1BC
        float         WorkProgress;                       // normalized work/build progress for UI

        // 0x1C0..0x1DB — unknown
        std::uint8_t  pad_01C0_01DC[0x1DC - 0x1C0]{};

        // 0x1DC
        char* customUnitName;                     // returns this+0x1DC in getter

        // 0x1E0..0x28F — unknown
        std::uint8_t  pad_01E0_0290[0x290 - 0x1E0]{};

        // 0x290
        UserUnitWeapon* weapons;                          // weapon table for GUI/range queries

        // 0x294..0x3E7 — tail not yet mapped
        std::uint8_t  pad_0294_03E8[0x3E8 - 0x294]{};
    };

    /**
     * VFTABLE: 0x00E4DA4C
     * COL:  0x00E9F3C4
     */
    class UserUnitCanAttackTarget_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA5C
     * COL:  0x00E9F328
     */
    class UserUnitGetFootPrintSize_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA64
     * COL:  0x00E9F2D8
     */
    class UserUnitGetUnitId_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA6C
     * COL:  0x00E9F288
     */
    class UserUnitGetEntityId_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA74
     * COL:  0x00E9F238
     */
    class UserUnitGetBlueprint_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA7C
     * COL:  0x00E9F1E8
     */
    class UserUnitHasUnloadCommandQueuedUp_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA84
     * COL:  0x00E9F198
     */
    class UserUnitProcessInfo_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA8C
     * COL:  0x00E9F148
     */
    class UserUnitIsAutoMode_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA94
     * COL:  0x00E9F0F8
     */
    class UserUnitIsAutoSurfaceMode_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DA9C
     * COL:  0x00E9F0A8
     */
    class UserUnitIsRepeatQueue_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAA4
     * COL:  0x00E9F058
     */
    class UserUnitIsInCategory_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAAC
     * COL:  0x00E9F008
     */
    class UserUnitGetStat_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAB4
     * COL:  0x00E9EFB8
     */
    class UserUnitIsStunned_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DABC
     * COL:  0x00E9EF68
     */
    class UserUnitSetCustomName_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAC4
     * COL:  0x00E9EF18
     */
    class UserUnitGetCustomName_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DACC
     * COL:  0x00E9EEC8
     */
    class UserUnitAddSelectionSet_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAD4
     * COL:  0x00E9EE78
     */
    class UserUnitRemoveSelectionSet_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DADC
     * COL:  0x00E9EE28
     */
    class UserUnitHasSelectionSet_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAE4
     * COL:  0x00E9EDD8
     */
    class UserUnitGetSelectionSets_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAEC
     * COL:  0x00E9ED88
     */
    class UserUnitGetHealth_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAF4
     * COL:  0x00E9ED38
     */
    class UserUnitGetMaxHealth_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DAFC
     * COL:  0x00E9ECE8
     */
    class UserUnitGetBuildRate_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB04
     * COL:  0x00E9EC98
     */
    class UserUnitIsOverchargePaused_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB0C
     * COL:  0x00E9EC48
     */
    class UserUnitIsDead_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB14
     * COL:  0x00E9EBF8
     */
    class UserUnitIsIdle_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB1C
     * COL:  0x00E9EBA8
     */
    class UserUnitGetFocus_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB24
     * COL:  0x00E9EB58
     */
    class UserUnitGetGuardedEntity_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB2C
     * COL:  0x00E9EB08
     */
    class UserUnitGetCreator_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB34
     * COL:  0x00E9EAB8
     */
    class UserUnitGetPosition_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB3C
     * COL:  0x00E9EA68
     */
    class UserUnitGetArmy_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB44
     * COL:  0x00E9EA18
     */
    class UserUnitGetFuelRatio_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB4C
     * COL:  0x00E9E9C8
     */
    class UserUnitGetShieldRatio_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB54
     * COL:  0x00E9E978
     */
    class UserUnitGetWorkProgress_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB5C
     * COL:  0x00E9E928
     */
    class UserUnitGetEconData_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB64
     * COL:  0x00E9E8D8
     */
    class UserUnitGetCommandQueue_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

    /**
     * VFTABLE: 0x00E4DB6C
     * COL:  0x00E9E888
     */
    class UserUnitGetMissileInfo_LuaFuncDef
    {
    public:
        /**
         * Address: 0x004CD3A0
         * Slot: 0
         * Demangled: protected: virtual void __thiscall moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
         */
        virtual void Run(LuaPlus::LuaState*) = 0;
    };

} // namespace moho

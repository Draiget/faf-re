// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <string>

#include "IUnit.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/entity/Entity.h"
#include "moho/math/Vector3f.h"

namespace LuaPlus { class LuaObject; class LuaState; } // forward decl

namespace moho { class EUnitState; class EntId; class RUnitBlueprint; class StatItem; class UnitAttributes; class UserUnit; class VTransform; } // forward decl
namespace Wm3 { class Vector3; } // forward decl
namespace gpg { class StrArg; } // forward decl

namespace moho
{
    /**
     * VFTABLE: 0x00E2A574
     * COL:  0x00E83CA4
     */
    class Unit : public IUnit, public Entity
    {
    public:
        /**
         * Address: 0x006A4BC0
         * Slot: 0
         * Demangled: public: virtual class moho::Unit const near * __thiscall moho::Unit::IsUnit(void)const
         */
        virtual Unit const* IsUnit() const = 0;

        /**
         * Address: 0x006A4BB0
         * Slot: 1
         * Demangled: public: virtual class moho::Unit near * __thiscall moho::Unit::IsUnit(void)
         */
        virtual Unit* IsUnit() = 0;

        /**
         * Address: 0x006A48E0
         * Slot: 2
         * Demangled: public: virtual class moho::UserUnit const near * __thiscall moho::IUnit::IsUserUnit(void)const
         */
        virtual UserUnit const* IsUserUnit() const = 0;

        /**
         * Address: 0x006A48D0
         * Slot: 3
         * Demangled: public: virtual class moho::UserUnit near * __thiscall moho::IUnit::IsUserUnit(void)
         */
        virtual UserUnit* IsUserUnit() = 0;

        /**
         * Address: 0x006A49A0
         * Slot: 4
         * Demangled: public: virtual class moho::EntId __thiscall moho::Unit::GetEntityId(void)const
         */
        virtual EntId GetEntityId() const = 0;

        /**
         * Address: 0x006A49B0
         * Slot: 5
         * Demangled: public: virtual class Wm3::Vec3f const near & __thiscall moho::Unit::GetPosition(void)const
         */
        virtual Wm3::Vec3f const& GetPosition() const = 0;

        /**
         * Address: 0x006A49C0
         * Slot: 6
         * Demangled: public: virtual class moho::VTransform const near & __thiscall moho::Unit::GetTransform(void)const
         */
        virtual VTransform const& GetTransform() const = 0;

        /**
         * Address: 0x006A8B20
         * Slot: 7
         * Demangled: public: virtual class moho::RUnitBlueprint const near * __thiscall moho::Unit::GetBlueprint(void)const
         */
        virtual RUnitBlueprint const* GetBlueprint() const = 0;

        /**
         * Address: 0x006A49D0
         * Slot: 8
         * Demangled: public: virtual class LuaPlus::LuaObject __thiscall moho::Unit::GetLuaObject(void)
         */
        virtual LuaPlus::LuaObject GetLuaObject() = 0;

        /**
         * Address: 0x006A8B30
         * Slot: 9
         * Demangled: public: virtual float __thiscall moho::Unit::CalcTransportLoadFactor(void)const
         */
        virtual float CalcTransportLoadFactor() const = 0;

        /**
         * Address: 0x006A49F0
         * Slot: 10
         * Demangled: public: virtual bool __thiscall moho::Unit::IsDead(void)const
         */
        virtual bool IsDead() const = 0;

        /**
         * Address: 0x006A4A00
         * Slot: 11
         * Demangled: public: virtual bool __thiscall moho::Unit::DestroyQueued(void)const
         */
        virtual bool DestroyQueued() const = 0;

        /**
         * Address: 0x006A4A10
         * Slot: 12
         * Demangled: public: virtual bool __thiscall moho::Unit::IsMobile(void)const
         */
        virtual bool IsMobile() const = 0;

        /**
         * Address: 0x006A4A20
         * Slot: 13
         * Demangled: public: virtual bool __thiscall moho::Unit::IsBeingBuilt(void)const
         */
        virtual bool IsBeingBuilt() const = 0;

        /**
         * Address: 0x006A7DC0
         * Slot: 14
         * Demangled: public: virtual bool __thiscall moho::Unit::IsNavigatorIdle(void)const
         */
        virtual bool IsNavigatorIdle() const = 0;

        /**
         * Address: 0x006A4AF0
         * Slot: 15
         * Demangled: public: virtual bool __thiscall moho::Unit::IsUnitState(enum moho::EUnitState)const
         */
        virtual bool IsUnitState(EUnitState) const = 0;

        /**
         * Address: 0x006A4990
         * Slot: 16
         * Demangled: public: virtual struct moho::UnitAttributes near & __thiscall moho::Unit::GetAttributes(void)
         */
        virtual UnitAttributes& GetAttributes() = 0;

        /**
         * Address: 0x006A4980
         * Slot: 17
         * Demangled: public: virtual struct moho::UnitAttributes const near & __thiscall moho::Unit::GetAttributes(void)const
         */
        virtual UnitAttributes const& GetAttributes() const = 0;

        /**
         * Address: 0x006A4B90
         * Slot: 18
         * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> const near &)
         */
        virtual StatItem* GetStat(gpg::StrArg, std::basic_string<char, std::char_traits<char>, std::allocator<char>> const&) = 0;

        /**
         * Address: 0x006A4B70
         * Slot: 19
         * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,float const near &)
         */
        virtual StatItem* GetStat(gpg::StrArg, float const&) = 0;

        /**
         * Address: 0x006A4B50
         * Slot: 20
         * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg,int const near &)
         */
        virtual StatItem* GetStat(gpg::StrArg, int const&) = 0;

        /**
         * Address: 0x006A4B30
         * Slot: 21
         * Demangled: public: virtual class moho::StatItem near * __thiscall moho::Unit::GetStat(class gpg::StrArg)
         */
        virtual StatItem* GetStat(gpg::StrArg) = 0;

        /**
         * Address: 0x006A73A0
         * Slot: 22
         * Demangled: public: virtual void __thiscall moho::Unit::SetAutoMode(bool)
         */
        virtual void SetAutoMode(bool) = 0;

        /**
         * Address: 0x006A73E0
         * Slot: 23
         * Demangled: public: virtual void __thiscall moho::Unit::SetAutoSurfaceMode(bool)
         */
        virtual void SetAutoSurfaceMode(bool) = 0;

        /**
         * Address: 0x006A4A30
         * Slot: 24
         * Demangled: public: virtual bool __thiscall moho::Unit::IsAutoMode(void)const
         */
        virtual bool IsAutoMode() const = 0;

        /**
         * Address: 0x006A4A40
         * Slot: 25
         * Demangled: public: virtual bool __thiscall moho::Unit::IsAutoSurfaceMode(void)const
         */
        virtual bool IsAutoSurfaceMode() const = 0;

        /**
         * Address: 0x006A4A50
         * Slot: 26
         * Demangled: public: virtual void __thiscall moho::Unit::SetCustomName(class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>>)
         */
        virtual void SetCustomName(std::basic_string<char, std::char_traits<char>, std::allocator<char>>) = 0;

        /**
         * Address: 0x006A4AB0
         * Slot: 27
         * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> __thiscall moho::Unit::GetCustomName(void)const
         */
        virtual std::basic_string<char, std::char_traits<char>, std::allocator<char>> GetCustomName() const = 0;

    public:
        class StatItem* Stats; //0x027C
        class StatsItem2* Stats2; //0x0280
        char pad_0284[16]; //0x0284
        float FuelRatio; //0x0294
        float ShieldRatio; //0x0298
        char pad_029C[4]; //0x029C
        bool IsPaused; //0x02A0
        char pad_02A1[11]; //0x02A1
        float BuildPercent; //0x02AC
        char pad_02B0[8]; //0x02B0
        int32_t BuildCurrentDefence; //0x02B8
        int32_t BuildCurrentAttack; //0x02BC
        int32_t BuildMaxDefence; //0x02C0
        int32_t BuildMaxAttack; //0x02C4
        char pad_02C8[72]; //0x02C8
        class CAniPose* AnimationPose; //0x0310
        char pad_0314[412]; //0x0314
        class CMotionEngine* MotionEngine; //0x04B0
        class N00001C07* CommandQueue; //0x04B4
        char pad_04B8[64]; //0x04B8
        class AiImplHolder* AiImplementations; //0x04F8
        char pad_04FC[72]; //0x04FC
        class CAiAttackerImpl* AiAttacker; //0x0544
        class IAiCommandDispatchImpl* AiCommandDispatch; //0x0548
        char pad_054C[12]; //0x054C
        CAiSiloBuildImpl* AiSiloBuild; //0x0558
        void* AiTransport; //0x055C
        char pad_0560[60]; //0x0560
        Vector3f N000008B5; //0x059C
        char pad_05A8[192]; //0x05A8
        int32_t TickCount2; //0x0668
        char pad_066C[20]; //0x066C
        class CReconBlip* ReconBlip; //0x0680
        char pad_0684[10]; //0x0684
        bool updWeaponRadius; //0x068E
        char pad_068F[111]; //0x068F
    };

    /**
     * VFTABLE: 0x00E1F4CC
     * COL:  0x00E76454
     */
    class UnitTransportDetachAllUnits_LuaFuncDef
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
     * VFTABLE: 0x00E2D3A8
     * COL:  0x00E86EC8
     */
    class UnitGetUnitId_LuaFuncDef
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
     * VFTABLE: 0x00E2D3B0
     * COL:  0x00E86E78
     */
    class UnitSetCreator_LuaFuncDef
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
     * VFTABLE: 0x00E2D3B8
     * COL:  0x00E86E28
     */
    class UnitGetCargo_LuaFuncDef
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
     * VFTABLE: 0x00E2D3C0
     * COL:  0x00E86DD8
     */
    class UnitAlterArmor_LuaFuncDef
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
     * VFTABLE: 0x00E2D3C8
     * COL:  0x00E86D88
     */
    class UnitGetArmorMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D3D0
     * COL:  0x00E86D38
     */
    class UnitClearFocusEntity_LuaFuncDef
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
     * VFTABLE: 0x00E2D3D8
     * COL:  0x00E86CE8
     */
    class UnitSetFocusEntity_LuaFuncDef
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
     * VFTABLE: 0x00E2D3E0
     * COL:  0x00E86C98
     */
    class UnitGetFocusUnit_LuaFuncDef
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
     * VFTABLE: 0x00E2D3E8
     * COL:  0x00E86C48
     */
    class UnitGetWeapon_LuaFuncDef
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
     * VFTABLE: 0x00E2D3F0
     * COL:  0x00E86BF8
     */
    class UnitGetWeaponCount_LuaFuncDef
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
     * VFTABLE: 0x00E2D3F8
     * COL:  0x00E86BA8
     */
    class UnitGetTargetEntity_LuaFuncDef
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
     * VFTABLE: 0x00E2D400
     * COL:  0x00E86B58
     */
    class UnitGetHealth_LuaFuncDef
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
     * VFTABLE: 0x00E2D408
     * COL:  0x00E86B08
     */
    class UnitGetAttacker_LuaFuncDef
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
     * VFTABLE: 0x00E2D410
     * COL:  0x00E86AB8
     */
    class UnitEnableManipulators_LuaFuncDef
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
     * VFTABLE: 0x00E2D418
     * COL:  0x00E86A68
     */
    class UnitKillManipulator_LuaFuncDef
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
     * VFTABLE: 0x00E2D420
     * COL:  0x00E86A18
     */
    class UnitKillManipulators_LuaFuncDef
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
     * VFTABLE: 0x00E2D428
     * COL:  0x00E869C8
     */
    class UnitScaleGetBuiltEmitter_LuaFuncDef
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
     * VFTABLE: 0x00E2D430
     * COL:  0x00E86978
     */
    class UnitSetStrategicUnderlay_LuaFuncDef
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
     * VFTABLE: 0x00E2D438
     * COL:  0x00E86928
     */
    class UnitIsUnitState_LuaFuncDef
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
     * VFTABLE: 0x00E2D440
     * COL:  0x00E868D8
     */
    class UnitIsIdleState_LuaFuncDef
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
     * VFTABLE: 0x00E2D448
     * COL:  0x00E86888
     */
    class UnitIsStunned_LuaFuncDef
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
     * VFTABLE: 0x00E2D450
     * COL:  0x00E86838
     */
    class UnitIsBeingBuilt_LuaFuncDef
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
     * VFTABLE: 0x00E2D458
     * COL:  0x00E867E8
     */
    class UnitIsPaused_LuaFuncDef
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
     * VFTABLE: 0x00E2D460
     * COL:  0x00E86798
     */
    class UnitSetPaused_LuaFuncDef
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
     * VFTABLE: 0x00E2D468
     * COL:  0x00E86748
     */
    class UnitSetConsumptionActive_LuaFuncDef
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
     * VFTABLE: 0x00E2D470
     * COL:  0x00E866F8
     */
    class UnitSetProductionActive_LuaFuncDef
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
     * VFTABLE: 0x00E2D478
     * COL:  0x00E866A8
     */
    class UnitSetBusy_LuaFuncDef
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
     * VFTABLE: 0x00E2D480
     * COL:  0x00E86658
     */
    class UnitSetBlockCommandQueue_LuaFuncDef
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
     * VFTABLE: 0x00E2D488
     * COL:  0x00E86608
     */
    class UnitSetImmobile_LuaFuncDef
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
     * VFTABLE: 0x00E2D490
     * COL:  0x00E865B8
     */
    class UnitSetStunned_LuaFuncDef
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
     * VFTABLE: 0x00E2D498
     * COL:  0x00E86568
     */
    class UnitSetUnSelectable_LuaFuncDef
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
     * VFTABLE: 0x00E2D4A0
     * COL:  0x00E86518
     */
    class UnitSetDoNotTarget_LuaFuncDef
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
     * VFTABLE: 0x00E2D4A8
     * COL:  0x00E864C8
     */
    class UnitSetUnitState_LuaFuncDef
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
     * VFTABLE: 0x00E2D4B0
     * COL:  0x00E86478
     */
    class UnitStopSiloBuild_LuaFuncDef
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
     * VFTABLE: 0x00E2D4B8
     * COL:  0x00E86428
     */
    class UnitSetIsValidTarget_LuaFuncDef
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
     * VFTABLE: 0x00E2D4C0
     * COL:  0x00E863D8
     */
    class UnitIsValidTarget_LuaFuncDef
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
     * VFTABLE: 0x00E2D4C8
     * COL:  0x00E86388
     */
    class UnitGetNumBuildOrders_LuaFuncDef
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
     * VFTABLE: 0x00E2D4D0
     * COL:  0x00E86338
     */
    class UnitCalculateWorldPositionFromRelative_LuaFuncDef
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
     * VFTABLE: 0x00E2D4D8
     * COL:  0x00E862E8
     */
    class UnitGetScriptBit_LuaFuncDef
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
     * VFTABLE: 0x00E2D4E0
     * COL:  0x00E86298
     */
    class UnitSetScriptBit_LuaFuncDef
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
     * VFTABLE: 0x00E2D4E8
     * COL:  0x00E86248
     */
    class UnitToggleScriptBit_LuaFuncDef
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
     * VFTABLE: 0x00E2D4F0
     * COL:  0x00E861F8
     */
    class UnitToggleFireState_LuaFuncDef
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
     * VFTABLE: 0x00E2D4F8
     * COL:  0x00E861A8
     */
    class UnitSetFireState_LuaFuncDef
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
     * VFTABLE: 0x00E2D500
     * COL:  0x00E86158
     */
    class UnitGetFireState_LuaFuncDef
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
     * VFTABLE: 0x00E2D508
     * COL:  0x00E86108
     */
    class UnitSetAutoMode_LuaFuncDef
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
     * VFTABLE: 0x00E2D510
     * COL:  0x00E860B8
     */
    class UnitAddBuildRestriction_LuaFuncDef
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
     * VFTABLE: 0x00E2D518
     * COL:  0x00E86068
     */
    class UnitRemoveBuildRestriction_LuaFuncDef
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
     * VFTABLE: 0x00E2D520
     * COL:  0x00E86018
     */
    class UnitRestoreBuildRestrictions_LuaFuncDef
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
     * VFTABLE: 0x00E2D528
     * COL:  0x00E85FC8
     */
    class UnitAddCommandCap_LuaFuncDef
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
     * VFTABLE: 0x00E2D530
     * COL:  0x00E85F78
     */
    class UnitRemoveCommandCap_LuaFuncDef
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
     * VFTABLE: 0x00E2D538
     * COL:  0x00E85F28
     */
    class UnitRestoreCommandCaps_LuaFuncDef
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
     * VFTABLE: 0x00E2D540
     * COL:  0x00E85ED8
     */
    class UnitTestCommandCaps_LuaFuncDef
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
     * VFTABLE: 0x00E2D548
     * COL:  0x00E85E88
     */
    class UnitAddToggleCap_LuaFuncDef
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
     * VFTABLE: 0x00E2D550
     * COL:  0x00E85E38
     */
    class UnitRemoveToggleCap_LuaFuncDef
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
     * VFTABLE: 0x00E2D558
     * COL:  0x00E85DE8
     */
    class UnitRestoreToggleCaps_LuaFuncDef
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
     * VFTABLE: 0x00E2D560
     * COL:  0x00E85D98
     */
    class UnitTestToggleCaps_LuaFuncDef
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
     * VFTABLE: 0x00E2D568
     * COL:  0x00E85D48
     */
    class UnitSetRegenRate_LuaFuncDef
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
     * VFTABLE: 0x00E2D570
     * COL:  0x00E85CF8
     */
    class UnitRevertRegenRate_LuaFuncDef
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
     * VFTABLE: 0x00E2D578
     * COL:  0x00E85CA8
     */
    class UnitSetReclaimable_LuaFuncDef
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
     * VFTABLE: 0x00E2D580
     * COL:  0x00E85C58
     */
    class UnitSetCapturable_LuaFuncDef
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
     * VFTABLE: 0x00E2D588
     * COL:  0x00E85C08
     */
    class UnitIsCapturable_LuaFuncDef
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
     * VFTABLE: 0x00E2D590
     * COL:  0x00E85BB8
     */
    class UnitSetOverchargePaused_LuaFuncDef
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
     * VFTABLE: 0x00E2D598
     * COL:  0x00E85B68
     */
    class UnitIsOverchargePaused_LuaFuncDef
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
     * VFTABLE: 0x00E2D5A0
     * COL:  0x00E85B18
     */
    class UnitSetBuildRate_LuaFuncDef
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
     * VFTABLE: 0x00E2D5A8
     * COL:  0x00E85AC8
     */
    class UnitGetBuildRate_LuaFuncDef
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
     * VFTABLE: 0x00E2D5B0
     * COL:  0x00E85A78
     */
    class UnitSetConsumptionPerSecondEnergy_LuaFuncDef
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
     * VFTABLE: 0x00E2D5B8
     * COL:  0x00E85A28
     */
    class UnitSetConsumptionPerSecondMass_LuaFuncDef
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
     * VFTABLE: 0x00E2D5C0
     * COL:  0x00E859D8
     */
    class UnitSetProductionPerSecondEnergy_LuaFuncDef
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
     * VFTABLE: 0x00E2D5C8
     * COL:  0x00E85988
     */
    class UnitSetProductionPerSecondMass_LuaFuncDef
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
     * VFTABLE: 0x00E2D5D0
     * COL:  0x00E85938
     */
    class UnitGetConsumptionPerSecondEnergy_LuaFuncDef
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
     * VFTABLE: 0x00E2D5D8
     * COL:  0x00E858E8
     */
    class UnitGetConsumptionPerSecondMass_LuaFuncDef
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
     * VFTABLE: 0x00E2D5E0
     * COL:  0x00E85898
     */
    class UnitGetProductionPerSecondEnergy_LuaFuncDef
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
     * VFTABLE: 0x00E2D5E8
     * COL:  0x00E85848
     */
    class UnitGetProductionPerSecondMass_LuaFuncDef
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
     * VFTABLE: 0x00E2D5F0
     * COL:  0x00E857F8
     */
    class UnitGetResourceConsumed_LuaFuncDef
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
     * VFTABLE: 0x00E2D5F8
     * COL:  0x00E857A8
     */
    class UnitSetElevation_LuaFuncDef
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
     * VFTABLE: 0x00E2D600
     * COL:  0x00E85758
     */
    class UnitRevertElevation_LuaFuncDef
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
     * VFTABLE: 0x00E2D608
     * COL:  0x00E85708
     */
    class UnitSetSpeedMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D610
     * COL:  0x00E856B8
     */
    class UnitSetAccMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D618
     * COL:  0x00E85668
     */
    class UnitSetTurnMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D620
     * COL:  0x00E85618
     */
    class UnitSetBreakOffTriggerMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D628
     * COL:  0x00E855C8
     */
    class UnitSetBreakOffDistanceMult_LuaFuncDef
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
     * VFTABLE: 0x00E2D630
     * COL:  0x00E85578
     */
    class UnitRevertCollisionShape_LuaFuncDef
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
     * VFTABLE: 0x00E2D638
     * COL:  0x00E85528
     */
    class UnitRecoilImpulse_LuaFuncDef
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
     * VFTABLE: 0x00E2D640
     * COL:  0x00E854D8
     */
    class UnitGetCurrentLayer_LuaFuncDef
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
     * VFTABLE: 0x00E2D648
     * COL:  0x00E85488
     */
    class UnitCanPathTo_LuaFuncDef
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
     * VFTABLE: 0x00E2D650
     * COL:  0x00E85438
     */
    class UnitCanPathToRect_LuaFuncDef
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
     * VFTABLE: 0x00E2D658
     * COL:  0x00E853E8
     */
    class UnitIsMobile_LuaFuncDef
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
     * VFTABLE: 0x00E2D660
     * COL:  0x00E85398
     */
    class UnitIsMoving_LuaFuncDef
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
     * VFTABLE: 0x00E2D668
     * COL:  0x00E85348
     */
    class UnitGetNavigator_LuaFuncDef
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
     * VFTABLE: 0x00E2D670
     * COL:  0x00E852F8
     */
    class UnitGetVelocity_LuaFuncDef
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
     * VFTABLE: 0x00E2D678
     * COL:  0x00E852A8
     */
    class UnitGetStat_LuaFuncDef
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
     * VFTABLE: 0x00E2D680
     * COL:  0x00E85258
     */
    class UnitSetStat_LuaFuncDef
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
     * VFTABLE: 0x00E2D688
     * COL:  0x00E85208
     */
    class UnitSetWorkProgress_LuaFuncDef
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
     * VFTABLE: 0x00E2D690
     * COL:  0x00E851B8
     */
    class UnitGetWorkProgress_LuaFuncDef
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
     * VFTABLE: 0x00E2D6A0
     * COL:  0x00E85118
     */
    class UnitGetGuardedUnit_LuaFuncDef
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
     * VFTABLE: 0x00E2D6A8
     * COL:  0x00E850C8
     */
    class UnitGetGuards_LuaFuncDef
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
     * VFTABLE: 0x00E2D6B0
     * COL:  0x00E85078
     */
    class UnitGetTransportFerryBeacon_LuaFuncDef
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
     * VFTABLE: 0x00E2D6B8
     * COL:  0x00E85028
     */
    class UnitHasValidTeleportDest_LuaFuncDef
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
     * VFTABLE: 0x00E2D6C0
     * COL:  0x00E84FD8
     */
    class UnitAddUnitToStorage_LuaFuncDef
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
     * VFTABLE: 0x00E2D6C8
     * COL:  0x00E84F88
     */
    class UnitSetCustomName_LuaFuncDef
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
     * VFTABLE: 0x00E2D6D0
     * COL:  0x00E84F38
     */
    class UnitHasMeleeSpaceAroundTarget_LuaFuncDef
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
     * VFTABLE: 0x00E2D6D8
     * COL:  0x00E84EE8
     */
    class UnitMeleeWarpAdjacentToTarget_LuaFuncDef
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
     * VFTABLE: 0x00E2D6E0
     * COL:  0x00E84E98
     */
    class UnitGetCommandQueue_LuaFuncDef
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
     * VFTABLE: 0x00E2D6E8
     * COL:  0x00E84E48
     */
    class UnitPrintCommandQueue_LuaFuncDef
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
     * VFTABLE: 0x00E2D6F0
     * COL:  0x00E84DF8
     */
    class UnitGetCurrentMoveLocation_LuaFuncDef
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
     * VFTABLE: 0x00E2D6F8
     * COL:  0x00E84DA8
     */
    class UnitGiveNukeSiloAmmo_LuaFuncDef
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
     * VFTABLE: 0x00E2D700
     * COL:  0x00E84D58
     */
    class UnitRemoveNukeSiloAmmo_LuaFuncDef
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
     * VFTABLE: 0x00E2D708
     * COL:  0x00E84D08
     */
    class UnitGetNukeSiloAmmoCount_LuaFuncDef
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
     * VFTABLE: 0x00E2D710
     * COL:  0x00E84CB8
     */
    class UnitGiveTacticalSiloAmmo_LuaFuncDef
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
     * VFTABLE: 0x00E2D718
     * COL:  0x00E84C68
     */
    class UnitRemoveTacticalSiloAmmo_LuaFuncDef
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
     * VFTABLE: 0x00E2D720
     * COL:  0x00E84C18
     */
    class UnitGetTacticalSiloAmmoCount_LuaFuncDef
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
     * VFTABLE: 0x00E2D740
     * COL:  0x00E84AD8
     */
    class UnitCanBuild_LuaFuncDef
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
     * VFTABLE: 0x00E2D748
     * COL:  0x00E84A88
     */
    class UnitGetRallyPoint_LuaFuncDef
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
     * VFTABLE: 0x00E2D750
     * COL:  0x00E84A38
     */
    class UnitGetFuelUseTime_LuaFuncDef
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
     * VFTABLE: 0x00E2D758
     * COL:  0x00E849E8
     */
    class UnitSetFuelUseTime_LuaFuncDef
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
     * VFTABLE: 0x00E2D760
     * COL:  0x00E84998
     */
    class UnitGetFuelRatio_LuaFuncDef
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
     * VFTABLE: 0x00E2D768
     * COL:  0x00E84948
     */
    class UnitSetFuelRatio_LuaFuncDef
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
     * VFTABLE: 0x00E2D770
     * COL:  0x00E848F8
     */
    class UnitSetShieldRatio_LuaFuncDef
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
     * VFTABLE: 0x00E2D778
     * COL:  0x00E848A8
     */
    class UnitGetShieldRatio_LuaFuncDef
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
     * VFTABLE: 0x00E2D780
     * COL:  0x00E84858
     */
    class UnitGetBlip_LuaFuncDef
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
     * VFTABLE: 0x00E2D788
     * COL:  0x00E84808
     */
    class UnitTransportHasSpaceFor_LuaFuncDef
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
     * VFTABLE: 0x00E2D790
     * COL:  0x00E847B8
     */
    class UnitTransportHasAvailableStorage_LuaFuncDef
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
     * VFTABLE: 0x00E2D798
     * COL:  0x00E84768
     */
    class UnitShowBone_LuaFuncDef
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
     * VFTABLE: 0x00E2D7A0
     * COL:  0x00E84718
     */
    class UnitHideBone_LuaFuncDef
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

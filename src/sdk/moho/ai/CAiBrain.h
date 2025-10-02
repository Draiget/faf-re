// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "legacy/containers/String.h"

namespace LuaPlus
{
	class LuaState;
}

namespace moho {
    /**
     * VFTABLE: 0x00E19900
     * COL:  0x00E6EA10
     */
    class CAiBrain {
    public:
        /**
         * Address: 0x00579590
         * Slot: 0
         * Demangled: Moho::CAiBrain::GetClass
         */
        virtual void GetClass() = 0;
        /**
         * Address: 0x005795B0
         * Slot: 1
         * Demangled: Moho::CAiBrain::GetDerivedObjectRef
         */
        virtual void GetDerivedObjectRef() = 0;
        /**
         * Address: 0x00579F30
         * Slot: 2
         * Demangled: sub_579F30
         */
        virtual void sub_579F30() = 0;
        /**
         * Address: 0x004C70A0
         * Slot: 3
         * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> __thiscall Moho::CScriptObject::GetErrorDescription(void)const
         */
        virtual msvc8::string GetErrorDescription() const = 0;
    };
} // namespace moho

/**
 * VFTABLE: 0x00E1AF5C
 * COL:  0x00E6FFD8
 */
class CAiBrainIsOpponentAIRunning_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF64
 * COL:  0x00E6FF88
 */
class CAiBrainGetArmyIndex_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF6C
 * COL:  0x00E6FF38
 */
class CAiBrainGetFactionIndex_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF74
 * COL:  0x00E6FEE8
 */
class CAiBrainSetCurrentPlan_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF7C
 * COL:  0x00E6FE98
 */
class CAiBrainGetPersonality_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF84
 * COL:  0x00E6FE48
 */
class CAiBrainSetCurrentEnemy_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF8C
 * COL:  0x00E6FDF8
 */
class CAiBrainGetCurrentEnemy_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF94
 * COL:  0x00E6FDA8
 */
class CAiBrainGetUnitBlueprint_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AF9C
 * COL:  0x00E6FD58
 */
class CAiBrainGetArmyStat_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFA4
 * COL:  0x00E6FD08
 */
class CAiBrainSetArmyStat_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFAC
 * COL:  0x00E6FCB8
 */
class CAiBrainAddArmyStat_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFB4
 * COL:  0x00E6FC68
 */
class CAiBrainSetGreaterOf_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFBC
 * COL:  0x00E6FC18
 */
class CAiBrainGetBlueprintStat_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFC4
 * COL:  0x00E6FBC8
 */
class CAiBrainGetCurrentUnits_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFCC
 * COL:  0x00E6FB78
 */
class CAiBrainGetListOfUnits_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFD4
 * COL:  0x00E6FB28
 */
class CAiBrainSetArmyStatsTrigger_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFDC
 * COL:  0x00E6FAD8
 */
class CAiBrainRemoveArmyStatsTrigger_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFE4
 * COL:  0x00E6FA88
 */
class CAiBrainGiveResource_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFEC
 * COL:  0x00E6FA38
 */
class CAiBrainGiveStorage_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFF4
 * COL:  0x00E6F9E8
 */
class CAiBrainTakeResource_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1AFFC
 * COL:  0x00E6F998
 */
class CAiBrainSetResourceSharing_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B004
 * COL:  0x00E6F948
 */
class CAiBrainFindUnit_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B00C
 * COL:  0x00E6F8F8
 */
class CAiBrainFindUpgradeBP_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B014
 * COL:  0x00E6F8A8
 */
class CAiBrainFindUnitToUpgrade_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B01C
 * COL:  0x00E6F858
 */
class CAiBrainDecideWhatToBuild_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B024
 * COL:  0x00E6F808
 */
class CAiBrainGetArmyStartPos_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B02C
 * COL:  0x00E6F7B8
 */
class CAiBrainCreateUnitNearSpot_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B034
 * COL:  0x00E6F768
 */
class CAiBrainCreateResourceBuildingNearest_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B03C
 * COL:  0x00E6F718
 */
class CAiBrainFindPlaceToBuild_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B044
 * COL:  0x00E6F6C8
 */
class CAiBrainCanBuildStructureAt_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B04C
 * COL:  0x00E6F678
 */
class CAiBrainBuildStructure_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B054
 * COL:  0x00E6F628
 */
class CAiBrainNumCurrentlyBuilding_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B05C
 * COL:  0x00E6F5D8
 */
class CAiBrainGetAvailableFactories_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B064
 * COL:  0x00E6F588
 */
class CAiBrainCanBuildPlatoon_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B06C
 * COL:  0x00E6F538
 */
class CAiBrainBuildPlatoon_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B074
 * COL:  0x00E6F4E8
 */
class CAiBrainBuildUnit_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B07C
 * COL:  0x00E6F498
 */
class CAiBrainIsAnyEngineerBuilding_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B084
 * COL:  0x00E6F448
 */
class CAiBrainGetNumPlatoonsWithAI_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B08C
 * COL:  0x00E6F3F8
 */
class CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B094
 * COL:  0x00E6F3A8
 */
class CAiBrainPlatoonExists_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B09C
 * COL:  0x00E6F358
 */
class CAiBrainGetPlatoonsList_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0A4
 * COL:  0x00E6F308
 */
class CAiBrainDisbandPlatoon_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0AC
 * COL:  0x00E6F2B8
 */
class CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0B4
 * COL:  0x00E6F268
 */
class CAiBrainMakePlatoon_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0BC
 * COL:  0x00E6F218
 */
class CAiBrainAssignUnitsToPlatoon_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0C4
 * COL:  0x00E6F1C8
 */
class CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0CC
 * COL:  0x00E6F178
 */
class CAiBrainGetNumUnitsAroundPoint_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0D4
 * COL:  0x00E6F128
 */
class CAiBrainGetUnitsAroundPoint_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0DC
 * COL:  0x00E6F0D8
 */
class CAiBrainFindClosestArmyWithBase_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0E4
 * COL:  0x00E6F088
 */
class CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0EC
 * COL:  0x00E6F038
 */
class CAiBrainGetAttackVectors_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0F4
 * COL:  0x00E6EFE8
 */
class CAiBrainPickBestAttackVector_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B0FC
 * COL:  0x00E6EF98
 */
class CAiBrainGetEconomyStored_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B104
 * COL:  0x00E6EF48
 */
class CAiBrainGetEconomyStoredRatio_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B10C
 * COL:  0x00E6EEF8
 */
class CAiBrainGetEconomyIncome_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B114
 * COL:  0x00E6EEA8
 */
class CAiBrainGetEconomyUsage_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B11C
 * COL:  0x00E6EE58
 */
class CAiBrainGetEconomyRequested_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B124
 * COL:  0x00E6EE08
 */
class CAiBrainGetEconomyTrend_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B12C
 * COL:  0x00E6EDB8
 */
class CAiBrainGetMapWaterRatio_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B134
 * COL:  0x00E6ED68
 */
class CAiBrainAssignThreatAtPosition_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B13C
 * COL:  0x00E6ED18
 */
class CAiBrainGetThreatAtPosition_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B144
 * COL:  0x00E6ECC8
 */
class CAiBrainGetThreatBetweenPositions_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B14C
 * COL:  0x00E6EC78
 */
class CAiBrainGetHighestThreatPosition_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B154
 * COL:  0x00E6EC28
 */
class CAiBrainGetThreatsAroundPosition_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B15C
 * COL:  0x00E6EBD8
 */
class CAiBrainCheckBlockingTerrain_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};

/**
 * VFTABLE: 0x00E1B164
 * COL:  0x00E6EB88
 */
class CAiBrainGetNoRushTicks_LuaFuncDef {
public:
    /**
     * Address: 0x004CD3A0
     * Slot: 0
     * Demangled: protected: virtual void __thiscall Moho::CScrLuaBinder::Run(class LuaPlus::LuaState near *)
     */
    virtual void Run(LuaPlus::LuaState*) = 0;
};


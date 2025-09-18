#pragma once

#include "../task/CTask.h"
#include "../script/CScriptObject.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Vector4f.h"
#include "moho/misc/TypeInfo.h"
#include "moho/sim/CArmyImpl.h"

namespace moho
{
	class Entity : public CScriptObject, public CTask
	{
		// Primary vftable (38 entries)
	public:
        /**
         * In binary: ctor?
         *
         * Address: 0x676C40
         * VFTable SLOT: 0
         */
        virtual type_info* GetTypeInfo() = 0;

        /**
         * In binary: PushToSmth?
         *
         * Address: 0x676C60
         * VFTable SLOT: 1
         */
        virtual void** sub_676C60(void** out) = 0;

        /**
         * In binary: dtor
         *
         * Address: 0x677C60
         * VFTable SLOT: 2
         */
        virtual ~Entity() = 0;

        virtual void sub_678D40() = 0; // 0x678D40 (slot 3)
        virtual void sub_5BDB10() = 0; // 0x5BDB10 (slot 4)
        virtual void sub_5BDB20() = 0; // 0x5BDB20 (slot 5)
        virtual void sub_5BDB30() = 0; // 0x5BDB30 (slot 6)
        virtual void sub_672BB0() = 0; // 0x672BB0 (slot 7)
        virtual void sub_5BDB40() = 0; // 0x5BDB40 (slot 8)
        virtual void sub_5BDB50() = 0; // 0x5BDB50 (slot 9)
        virtual void sub_678BB0() = 0; // 0x678BB0 (slot 10)
        virtual void sub_5BDB60() = 0; // 0x5BDB60 (slot 11)
        virtual void sub_67A0A0() = 0; // 0x67A0A0 (slot 12)

        /**
         * In binary: ResolveMeshFromBlueprint
         *
         * Address: 0x67A720
         * VFTable SLOT: 13
         */
        virtual void ResolveMeshFromBlueprint(msvc8::string& meshName, msvc8::string* explicitPlaceholder, int unknown) = 0;

        virtual void sub_5BDBD0() = 0; // 0x5BDBD0 (slot 14)
        virtual void sub_678DC0() = 0; // 0x678DC0 (slot 15)
        virtual void sub_5BDBF0() = 0; // 0x5BDBF0 (slot 16)
        virtual void sub_679210() = 0; // 0x679210 (slot 17)
        virtual void sub_679CE0() = 0; // 0x679CE0 (slot 18)
        virtual void sub_679E20() = 0; // 0x679E20 (slot 19)
        virtual void sub_679F70() = 0; // 0x679F70 (slot 20)
        virtual void sub_679FA0() = 0; // 0x679FA0 (slot 21)
        virtual void sub_5BDC10() = 0; // 0x5BDC10 (slot 22)
        virtual void sub_679550() = 0; // 0x679550 (slot 23)
        virtual void sub_6796F0() = 0; // 0x6796F0 (slot 24)
        virtual void sub_6797E0() = 0; // 0x6797E0 (slot 25)
        virtual void sub_679800() = 0; // 0x679800 (slot 26)
        virtual void sub_679820() = 0; // 0x679820 (slot 27)
        virtual void sub_679840() = 0; // 0x679840 (slot 28)
        virtual void sub_5BDC20() = 0; // 0x5BDC20 (slot 29)
        virtual void sub_679860() = 0; // 0x679860 (slot 30)
        virtual void sub_679A80() = 0; // 0x679A80 (slot 31)
        virtual void sub_679B80() = 0; // 0x679B80 (slot 32)
        virtual void sub_6791D0() = 0; // 0x6791D0 (slot 33)
        virtual void sub_67A220() = 0; // 0x67A220 (slot 34)
        virtual void sub_67A260() = 0; // 0x67A260 (slot 35)
        virtual void sub_67A290() = 0; // 0x67A290 (slot 36)
        virtual void sub_678A70() = 0; // 0x678A70 (slot 37)

	public:
        std::uint8_t _pad_38_5C[0x5C - 0x38];

        // 0x5C:
        std::uint32_t CategoryOrMask; // sub_67A290

        // 0x60
		char pad_0068[8]; //0x0068
		int32_t id_; //0x0070
		class RUnitBlueprint* BluePrint; //0x0074
		char pad_0078[12]; //0x0078
		class CAiSiloBuildImpl* Resources; //0x0084
		class RMeshBlueprint* MeshBluePrint; //0x0088
		float N000004CF; //0x008C
		char pad_0090[8]; //0x0090
		float Health; //0x0098
		float MaxHealth; //0x009C
		char pad_00A0[2]; //0x00A0
		uint8_t N00000075; //0x00A2
		char pad_00A3[1]; //0x00A3
		Vector4f Orientation; //0x00A4
		Vector3f Position; //0x00B4
		Vector4f PrevOrientation; //0x00C0
		Vector3f PrevPosition; //0x00D0
		float N0000007F; //0x00DC
		float FractionCompleted; //0x00E0
		char pad_00E4[52]; //0x00E4
		uint8_t Visibility; //0x0118
		char pad_0119[3]; //0x0119
		int32_t N00000094; //0x011C
		char pad_0120[48]; //0x0120
		Sim* SimulationRef; //0x0150
		CArmyImpl* ArmyRef; //0x0154
		char pad_0158[16]; //0x0158
		Vector3f PositionUnknown; //0x0168
		char pad_0174[4]; //0x0174
		float N000000AA; //0x0178
		int32_t TickCount1; //0x017C
        CColPrimitive<Box3f>* CollisionExtents; //0x0180
		msvc8::vector<void*> N000000AD; //0x0184
		char pad_0194[96]; //0x0194
		int32_t readinessFlags; //0x01F4
		char pad_01F8[16]; //0x01F8
		char* Name; //0x0208
		char pad_020C[60]; //0x020C
		Vector3f Position2; //0x0248
		Vector3f Position3; //0x0254
		char pad_0260[10]; //0x0260
	};

	static_assert(sizeof(Entity) == 0x270, "size of Entity == 0x270");
    ABI_SIZE_MUST_BE(Entity, 0x270);

    template<class T>
    class EntitySetTemplate
    {
	    
    };
}

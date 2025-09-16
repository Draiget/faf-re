#pragma once

#include "Entity.h"
#include "IUnit.h"

namespace moho
{
	class Unit : public IUnit, public Entity
	{
		// Primary vftable (28 entries)
	public:
        virtual void sub_6A4BC0() = 0; // 0x6A4BC0 (slot 0)
        virtual void sub_6A4BB0() = 0; // 0x6A4BB0 (slot 1)
        virtual void sub_6A48E0() = 0; // 0x6A48E0 (slot 2)
        virtual void sub_6A48D0() = 0; // 0x6A48D0 (slot 3)
        virtual void sub_6A49A0() = 0; // 0x6A49A0 (slot 4)
        virtual void sub_6A49B0() = 0; // 0x6A49B0 (slot 5)
        virtual void sub_6A49C0() = 0; // 0x6A49C0 (slot 6)
        virtual void sub_6A8B20() = 0; // 0x6A8B20 (slot 7)
        virtual void sub_6A49D0() = 0; // 0x6A49D0 (slot 8)
        virtual void sub_6A8B30() = 0; // 0x6A8B30 (slot 9)
        virtual void sub_6A49F0() = 0; // 0x6A49F0 (slot 10)
        virtual void sub_6A4A00() = 0; // 0x6A4A00 (slot 11)
        virtual void sub_6A4A10() = 0; // 0x6A4A10 (slot 12)
        virtual void sub_6A4A20() = 0; // 0x6A4A20 (slot 13)
        virtual void sub_6A7DC0() = 0; // 0x6A7DC0 (slot 14)
        virtual void sub_6A4AF0() = 0; // 0x6A4AF0 (slot 15)
        virtual void sub_6A4990() = 0; // 0x6A4990 (slot 16)
        virtual void sub_6A4980() = 0; // 0x6A4980 (slot 17)
        virtual void sub_6A4B90() = 0; // 0x6A4B90 (slot 18)
        virtual void sub_6A4B70() = 0; // 0x6A4B70 (slot 19)
        virtual void sub_6A4B50() = 0; // 0x6A4B50 (slot 20)
        virtual void sub_6A4B30() = 0; // 0x6A4B30 (slot 21)
        virtual void sub_6A73A0() = 0; // 0x6A73A0 (slot 22)
        virtual void sub_6A73E0() = 0; // 0x6A73E0 (slot 23)
        virtual void sub_6A4A30() = 0; // 0x6A4A30 (slot 24)
        virtual void sub_6A4A40() = 0; // 0x6A4A40 (slot 25)
        virtual void sub_6A4A50() = 0; // 0x6A4A50 (slot 26)
        virtual void sub_6A4AB0() = 0; // 0x6A4AB0 (slot 27)

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
}

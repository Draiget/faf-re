#pragma once
#include "UserEntity.h"

namespace moho
{
	class UserUnit : public UserEntity
	{
	public:
		// Primary vftable (27 entries)
        virtual void sub_8BF990() = 0; // 0x8BF990 (slot 0)
        virtual void sub_8C0A30() = 0; // 0x8C0A30 (slot 1)
        virtual void sub_8BF120() = 0; // 0x8BF120 (slot 2)
        virtual void sub_8BF110() = 0; // 0x8BF110 (slot 3)
        virtual void sub_8BF170() = 0; // 0x8BF170 (slot 4)
        virtual void sub_8BF150() = 0; // 0x8BF150 (slot 5)
        virtual void sub_8BF130() = 0; // 0x8BF130 (slot 6)
        virtual void sub_8BF160() = 0; // 0x8BF160 (slot 7)
        virtual void sub_8BF140() = 0; // 0x8BF140 (slot 8)
        virtual void sub_8B8EB0() = 0; // 0x8B8EB0 (slot 9)
        virtual void sub_8C09B0() = 0; // 0x8C09B0 (slot 10)
        virtual void sub_8B8530() = 0; // 0x8B8530 (slot 11)
        virtual void sub_8C0500() = 0; // 0x8C0500 (slot 12)
        virtual void sub_8BEFB0() = 0; // 0x8BEFB0 (slot 13)
        virtual void sub_8C1350() = 0; // 0x8C1350 (slot 14)
        virtual void sub_8C00E0() = 0; // 0x8C00E0 (slot 15)
        virtual void sub_8C04D0() = 0; // 0x8C04D0 (slot 16)
        virtual void sub_8BFC50() = 0; // 0x8BFC50 (slot 17)
        virtual void sub_8BFD70() = 0; // 0x8BFD70 (slot 18)
        virtual void sub_8BFE50() = 0; // 0x8BFE50 (slot 19)
        virtual void sub_8BEFD0() = 0; // 0x8BEFD0 (slot 20)
        virtual void sub_8BEFE0() = 0; // 0x8BEFE0 (slot 21)
        virtual void sub_8BEFF0() = 0; // 0x8BEFF0 (slot 22)
        virtual void sub_8BF000() = 0; // 0x8BF000 (slot 23)
        virtual void sub_8BF010() = 0; // 0x8BF010 (slot 24)
        virtual void sub_8BF060() = 0; // 0x8BF060 (slot 25)
        virtual void sub_8BF070() = 0; // 0x8BF070 (slot 26)
		// Secondary vftable at subobject offset 328 (22 entries)
        /*virtual*/ void vf_sub328_00(); // 0x6A48C0
        /*virtual*/ void vf_sub328_01(); // 0x6A48B0
        /*virtual*/ void vf_sub328_02(); // 0x8C6580
        /*virtual*/ void vf_sub328_03(); // 0x8C6590
        /*virtual*/ void vf_sub328_04(); // 0x8BEF00
        /*virtual*/ void vf_sub328_05(); // 0x8BEF10
        /*virtual*/ void vf_sub328_06(); // 0x8BEF20
        /*virtual*/ void vf_sub328_07(); // 0x8BEF30
        /*virtual*/ void vf_sub328_08(); // 0x8BEF60
        /*virtual*/ void vf_sub328_09(); // 0x8BEF80
        /*virtual*/ void vf_sub328_10(); // 0x8BEF90
        /*virtual*/ void vf_sub328_11(); // 0x8BEFA0
        /*virtual*/ void vf_sub328_12(); // 0x8C04E0
        /*virtual*/ void vf_sub328_13(); // 0x8C6570
        /*virtual*/ void vf_sub328_14(); // 0x8BEFC0
        /*virtual*/ void vf_sub328_15(); // 0x8BF020
        /*virtual*/ void vf_sub328_16(); // 0x8BEF50
        /*virtual*/ void vf_sub328_17(); // 0x8BEF40
        /*virtual*/ void vf_sub328_18(); // 0x8BF0C0
        /*virtual*/ void vf_sub328_19(); // 0x8BF0B0
        /*virtual*/ void vf_sub328_20(); // 0x8BF0A0
        /*virtual*/ void vf_sub328_21(); // 0x8BF080
        // Secondary vftable at subobject offset 336 (4 entries)
        /*virtual*/ void vf_sub336_00(); // 0x8BEEC0
        /*virtual*/ void vf_sub336_01(); // 0x8BEEE0
        /*virtual*/ void vf_sub336_02(); // 0x8C65A0
        /*virtual*/ void vf_sub336_03(); // 0x4C70A0

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
}

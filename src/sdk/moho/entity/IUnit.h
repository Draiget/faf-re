#pragma once

#include "../misc/WeakObject.h"

namespace moho
{
	class IUnit : public WeakObject
	{
        // Primary vftable (22 entries)
	public:
        virtual void sub_6A48C0() = 0; // 0x6A48C0 (slot 0)
        virtual void sub_6A48B0() = 0; // 0x6A48B0 (slot 1)
        virtual void sub_6A48E0() = 0; // 0x6A48E0 (slot 2)
        virtual void sub_6A48D0() = 0; // 0x6A48D0 (slot 3)
        virtual void sub_A82547() = 0; // 0xA82547 (slot 4)
        virtual void sub_A82547_1() = 0; // 0xA82547 (slot 5)
        virtual void sub_A82547_2() = 0; // 0xA82547 (slot 6)
        virtual void sub_A82547_3() = 0; // 0xA82547 (slot 7)
        virtual void sub_A82547_4() = 0; // 0xA82547 (slot 8)
        virtual void sub_A82547_5() = 0; // 0xA82547 (slot 9)
        virtual void sub_A82547_6() = 0; // 0xA82547 (slot 10)
        virtual void sub_A82547_7() = 0; // 0xA82547 (slot 11)
        virtual void sub_A82547_8() = 0; // 0xA82547 (slot 12)
        virtual void sub_A82547_9() = 0; // 0xA82547 (slot 13)
        virtual void sub_A82547_10() = 0; // 0xA82547 (slot 14)
        virtual void sub_A82547_11() = 0; // 0xA82547 (slot 15)
        virtual void sub_A82547_12() = 0; // 0xA82547 (slot 16)
        virtual void sub_A82547_13() = 0; // 0xA82547 (slot 17)
        virtual void sub_A82547_14() = 0; // 0xA82547 (slot 18)
        virtual void sub_A82547_15() = 0; // 0xA82547 (slot 19)
        virtual void sub_A82547_16() = 0; // 0xA82547 (slot 20)
        virtual void sub_A82547_17() = 0; // 0xA82547 (slot 21)
	};
	static_assert(sizeof(IUnit) == 0x08, "IUnit head must be 8 bytes");
}

#pragma once

namespace moho
{
	class IAiSiloBuild
	{
		// Primary vftable (12 entries)
	public:
        /**
         * In binary: dtor
         *
         * Address: 0x5CE860
         * VFTable SLOT: 0
         */
        virtual ~IAiSiloBuild() = default;

        virtual void sub_A82547() = 0;   // 0xA82547 (slot 1)
        virtual void sub_A82547_1() = 0; // 0xA82547 (slot 2)
        virtual void sub_A82547_2() = 0; // 0xA82547 (slot 3)
        virtual void sub_A82547_3() = 0; // 0xA82547 (slot 4)
        virtual void sub_A82547_4() = 0; // 0xA82547 (slot 5)
        virtual void sub_A82547_5() = 0; // 0xA82547 (slot 6)
        virtual void sub_A82547_6() = 0; // 0xA82547 (slot 7)
        virtual void sub_A82547_7() = 0; // 0xA82547 (slot 8)
        virtual void sub_A82547_8() = 0; // 0xA82547 (slot 9)
        virtual void sub_A82547_9() = 0; // 0xA82547 (slot 10)
        virtual void sub_A82547_10() = 0; // 0xA82547 (slot 11)
	};
}

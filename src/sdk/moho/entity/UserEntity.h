#pragma once
#include "../misc/WeakObject.h"
#include "../math/Vector4f.h"
#include "../math/Vector3f.h"

namespace moho
{
	class UserEntity : public WeakObject
	{
		// Primary vftable (17 entries)
	public:
        /**
         * In binary: dtor
         *
         * PDB address: 0x8B8760
         * VFTable SLOT: 0
         */
        virtual void ~UserEntity() = default;

        /**
         * In binary: nullsub
         *
         * PDB address: 0x8B8CD0
         * VFTable SLOT: 1
         */
        virtual void sub_8B8CD0() = 0; 

        /**
         * In binary:
         *
         * PDB address: 0x8B84D0
         * VFTable SLOT: 2
         */
        virtual int sub_8B84D0() {
            return 0;
        }

        virtual void sub_8B84C0() = 0; // 0x8B84C0 (slot 3)
        virtual void sub_8B84E0() = 0; // 0x8B84E0 (slot 4)
        virtual void sub_8B8510() = 0; // 0x8B8510 (slot 5)
        virtual void sub_8B84F0() = 0; // 0x8B84F0 (slot 6)
        virtual void sub_8B8520() = 0; // 0x8B8520 (slot 7)
        virtual void sub_8B8500() = 0; // 0x8B8500 (slot 8)
        virtual void sub_8B8EB0() = 0; // 0x8B8EB0 (slot 9)
        virtual void sub_8B9580() = 0; // 0x8B9580 (slot 10)
        virtual void sub_8B8530() = 0; // 0x8B8530 (slot 11)
        virtual void sub_8B8540() = 0; // 0x8B8540 (slot 12)
        virtual void sub_8B85C0() = 0; // 0x8B85C0 (slot 13)
        virtual void sub_8B85D0() = 0; // 0x8B85D0 (slot 14)
        virtual void sub_8B88D0() = 0; // 0x8B88D0 (slot 15)
        virtual void sub_8B8B10() = 0; // 0x8B8B10 (slot 16)

	public:
        // From +0x08 (after cookie) to +0x44 (entityID) we need 0x3C bytes of padding.
        std::uint8_t  pad_0008_0044[0x44 - 0x08]{};       // 0x08..0x43

        // 0x44
        int           entityID;                           // replicated id / low bits of packed key

        // 0x48
        class RPropBlueprint* blueprint;                        // for units: actually RUnitBlueprint*

        // 0x4C..0x57 — unknown (ctor zeroes several dwords)
        std::uint8_t  pad_004C_0058[0x58 - 0x4C]{};

        // 0x58
        class RMeshBlueprint* mesh;

        // 0x5C..0x67 — prev position cache etc. (engine uses in snapshot path)
        std::uint8_t  pad_005C_0068[0x68 - 0x5C]{};

        // 0x68 / 0x6C
        float         curHealth;
        float         maxHealth;

        // 0x70
        bool          isBeingBuilt;
        std::uint8_t  pad_0071_0074[0x74 - 0x71]{};

        // 0x74..0x8F
        Vector4f      rot1;                               // current rotation
        Vector3f      pos1;                               // current position

        // 0x90..0xAF
        Vector4f      rot2;                               // previous rotation
        Vector4f      pos2;                               // previous position as v4 (SIMD-friendly)

        // 0xB0
        float         fractionComplete;                   // build progress of this entity (0..1)

        // 0xB4..0xCF — scratch / normalization / proxy scalars
        std::uint8_t  pad_00B4_00D0[0xD0 - 0xB4]{};

        // 0xD0..0xDF — rectangle or extra floats (observed comment from guys)
        float         rect_x1{ 0 }, rect_y1{ 0 }, rect_x2{ 0 }, rect_y2{ 0 };

        // 0xE0..0xFF — more scratch
        std::uint8_t  pad_00E0_0100[0x100 - 0xE0]{};

        // 0x100..0x11F
        class UnitIntel     unitIntel;                          // replicated intel/visibility for UI

        // 0x120
        class UserArmy* owner;                              // resolved army pointer

        // 0x124..0x143 — extra transforms for FX / smoothing
        Vector4f      rot3;                               // working rotation for FX
        Vector4f      pos3;                               // working position for FX

        // 0x144..0x147 — tiny flags / alignment tail
        std::uint8_t  pad_0144_0148[0x148 - 0x144]{};
	};
}

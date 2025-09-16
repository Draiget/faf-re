#pragma once

#include "../command/ICommandSink.h"
#include "../resource/ISimResources.h"
#include "../../gpg/core/random/Random.h"
#include "../../legacy/containers/Vector.h"
#include "../../legacy/containers/String.h"

namespace moho
{
    class LuaState;
    class RRuleGameRules;
    class CSimResources;
    class STIMap;
    class SSTICommandSource;
    class SimArmy;
    class CEffectManagerImpl;
    class CSimSoundManager;

    struct SimRngState
	{
        gpg::core::Mt19937State core;  // mt[] + idx
        uint32_t     gaussBits; // @ +0x09C4 (optional cache)
        uint8_t      gaussHas;  // @ +0x09C8 (optional cache flag)
        uint8_t      _pad[3];
    };

    class Sim final : public ICommandSink
	{
    public:
        // Destruction through base is expected to be possible.
        // Implemented in .cpp (even if empty), because base dtor is pure.
        ~Sim() override;

    public:
        uint8_t  pad_0004[0x3C]; // 0x0004..0x003F

        uint8_t  verify_buf[8];  // 0x0040..0x0047 (used by sub_4B7D40(this+0x40))
        uint32_t verify_aux;     // 0x0048
        uint8_t  verify_active;  // 0x004C (set to 0 on mismatch)
        uint8_t  pad_004D[3];    // 0x004D..0x004F

        char     dynamicHash[16];     // 0x0050
        char     hashTrash[0x50];     // 0x0060
        char     simHashes[16 * 128]; // 0x00B0..0x08AF
        uint8_t  pad_08B0[0x10];      // 0x08B0..0x08BF

        CEffectManagerImpl* effectManager; // 0x08C0
        CSimSoundManager* soundManager;    // 0x08C4
        RRuleGameRules* rules;             // 0x08C8
        STIMap* stiMap;                    // 0x08CC

        boost::SharedPtrRaw<CSimResources> resources; // 0x08D0..0x08D7 (px, pi)

        LuaState*   LState;         // 0x08D8
        uint8_t     pad_08DC[0xA];  // 0x08DC..0x08E5
        bool        cheatsEnabled;  // 0x08E6  <-- this one
        uint8_t     pad_08E7[0x10]; // 0x08E7..0x08F6
        uint8_t     pad_08F7;       // 0x08F7
                                    
        uint32_t    beatCurrent;      // 0x08F8
        // 0x08FC is used at least as a byte flag: *(_BYTE*)(this+0x8FC) = 0
        // Keep a union to preserve raw 32-bit storage for other call-sites.
        union {
            uint32_t beatAuxRaw;    // 0x08FC - do not write blindly; low byte is used as a flag
            struct {
                uint8_t beatFlag;   // 0x08FC - cleared in sub_7474B0
                uint8_t pad_08FD[3];
            };
        };
        uint32_t    beatLastVerified; // 0x0900

        SimRngState* rng; // 0x0904

        // Footprint, obstruction context? Of what? Hm.
        void* unk3;           // 0x0908 (~0x68  bytes impl)

        msvc8::vector<SimArmy*> armies; // _Myproxy @0x090C, begin @0x0910 ... 0x091B
        msvc8::vector<SSTICommandSource> cmdSources; // _Myproxy @0x091C, begin @0x0920
        int32_t ourCmdSource;                               // 0x092C

        // 0x0930..0x097B
        uint8_t pad_0930[0x4C];

        // 0x097C..0x0983
        void**      unk4;              // ~0x30 impl
        // 0x0980..0x0983
        void*       CAiFormationDB;    // ~0x40 impl (shares area; keep as seen)
        // 0x0984..0x099B
        void*       Entities;          // 0x0984
        void*       unk5;              // 0x0988 (~0xCD0)
        uint8_t     pad_098C[0x10];    // 0x098C..0x099B

        // 0x099C..0x0A37
        void*   unk6;              // 0x099C (~0xCF0)
        uint8_t pad_09A0[0x98];

        // 0x0A38..0x0A87
        void*       unk7;              // 0x0A38 (~0x0C)
        uint8_t     pad_0A3C[0x4C];

        // 0x0A88..0x0AF7
        int32_t     focusArmyIndex;    // 0x0A88 (-1 == observer)
        uint8_t     pad_0A8C[0x6C];
    };
}

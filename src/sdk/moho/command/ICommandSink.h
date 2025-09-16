#pragma once
#include <cstdint>

namespace moho 
{
    using CommandSourceId = uint32_t;
    using BeatIndex = int32_t;

    struct CommandList;    // container of target entities/units (a2)
    struct CommandSpec;    // command descriptor (a3)

    /**
    * Abstract class, pure virtual functions (all are __purecall <-> sub_A82547)
    */
    class ICommandSink 
    {
        // Primary vftable (24 entries)
    public:
        // vtable slot 0 (deleting-dtor thunk in binary)
        virtual ~ICommandSink() = 0;

        /**
         * Padding to match the game's second dtor entry.
         * Exists only to align slots.
         *
         * VFTable SLOT: 1
         */
        virtual void __pad_dtor1() = 0;

        /**
         * In binary: 
         *
         * PDB name: sub_748650
         * VFTable SLOT: 2
         */
        virtual void SetCommandSource(CommandSourceId sourceId) = 0;

        /**
         * In binary:
         *
         * PDB name: sub_7486B0
         * VFTable SLOT: 3
         */
        virtual void OnCommandSourceTerminated() = 0;

        /**
         * In binary:
         *
         * PDB name: sub_7487C0
         * VFTable SLOT: 4
         */
        virtual void VerifyBeat(int channelOrFlags, BeatIndex beat) = 0;

        // slot 5
        virtual void Slot05() = 0;
        // slot 6
        virtual void Slot06() = 0;
        // slot 7
        virtual void Slot07() = 0;
        // slot 8
        virtual void Slot08() = 0;
        // slot 9
        virtual void Slot09() = 0;
        // slot 10
        virtual void Slot10() = 0;
        // slot 11
        virtual void Slot11() = 0;

        /**
         * In binary:
         * #STRs:
         *  "SetFireState", "SetAutoMode", "CustomName",
         *  "SetAutoSurfaceMode", "SetRepeatQueue", "SetPaused",
         *  "SiloBuildTactical", "SiloBuildNuke", "ToggleScriptBit",
         *  "false"
         *
         * PDB name: sub_748D50
         * VFTable SLOT: 12
         */
        virtual void Slot12() = 0;

        /**
         * In binary:
         *
         * PDB name: sub_749290
         * VFTable SLOT: 13
         */
        virtual void IssueCommand(
            const CommandList& targets,
            const CommandSpec& cmd,
            int queueFlags
        ) = 0;

        /**
         * In binary:
         *
         * PDB name: sub_7494B0
         * VFTable SLOT: 14
         */
        virtual void IssueFactoryCommand() = 0;

        // slot 15
        virtual void Slot15() = 0;
        // slot 16
        virtual void Slot16() = 0;
        // slot 17
        virtual void Slot17() = 0;
        // slot 18
        virtual void Slot18() = 0;
        // slot 19
        virtual void Slot19() = 0;
        // slot 20
        virtual void Slot20() = 0;

        /**
         * In binary:
         *
         * PDB name: sub_7494B0
         * VFTable SLOT: 21
         */
        virtual void RunGlobalLuaFunction() = 0;

        /**
         * In binary:
         *
         * PDB name: sub_749B60
         * VFTable SLOT: 22
         */
        virtual void DoLuaCallback() = 0;

        // slot 23
        virtual void Slot23() = 0;
    };
}

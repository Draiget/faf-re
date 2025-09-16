// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

namespace msvc8
{
	struct string;
}

namespace gpg {
    /**
     * VFTABLE: 0x00D48D14
     * COL:  0x00E53B84
     */
    class ReadArchive {
    public:
        /**
         * Address: 0x00953700
         * Slot: 0
         * Demangled: sub_953700
         */
        ~ReadArchive() = default;
        /**
         * Address: 0x00A82547
         * Slot: 1
         * Demangled: _purecall
         */
        virtual void ReadBytes(char*, size_t) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 2
         * Demangled: _purecall
         */
        virtual void ReadString(msvc8::string*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 3
         * Demangled: _purecall
         */
        virtual void ReadFloat(float*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual void ReadUInt64(unsigned __int64*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual void ReadInt64(__int64*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 6
         * Demangled: _purecall
         */
        virtual void ReadULong(unsigned long*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual void ReadLong(long*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void ReadUInt(unsigned int*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void ReadInt(int*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void ReadUShort(unsigned short*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void ReadShort(short*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual void ReadUByte(unsigned __int8*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 13
         * Demangled: _purecall
         */
        virtual void ReadByte(__int8*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 14
         * Demangled: _purecall
         */
        virtual void ReadBool(bool*) = 0;
        /**
         * Address: 0x00952BD0
         * Slot: 15
         * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
         */
        virtual void EndSection(bool) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 16
         * Demangled: _purecall
         */
        virtual int NextMarker() = 0;
    };
} // namespace gpg

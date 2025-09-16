// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <map>

namespace msvc8
{
	struct string;
}

namespace gpg {
    /**
     * VFTABLE: 0x00D48DDC
     * COL:  0x00E53B98
     * Log/code strings:
     *  - Error while creating archive: nobody claimed ownership of %s 0x%08x
     */
    class WriteArchive {
    public:
        /**
         * Address: 0x00953C80
         * Slot: 0
         * Demangled: sub_953C80
         */
        ~WriteArchive() = default;
        /**
         * Address: 0x00A82547
         * Slot: 1
         * Demangled: _purecall
         */
        virtual void WriteBytes(char*, size_t) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 2
         * Demangled: _purecall
         */
        virtual void WriteString(msvc8::string*) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 3
         * Demangled: _purecall
         */
        virtual void WriteFloat(float) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual void WriteUInt64(uint64_t) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual void WriteInt64(int64_t) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 6
         * Demangled: _purecall
         */
        virtual void WriteULong(unsigned long) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual void WriteLong(long) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void WriteUInt(unsigned int) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void WriteInt(int) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void WriteUShort(unsigned short) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void WriteShort(short) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual void WriteUByte(unsigned __int8) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 13
         * Demangled: _purecall
         */
        virtual void WriteByte(__int8) = 0;
        /**
         * Address: 0x00A82547
         * Slot: 14
         * Demangled: _purecall
         */
        virtual void WriteBool(bool) = 0;
        /**
         * Address: 0x009510B0
         * Slot: 15
         * Demangled: public: virtual void __thiscall gpg::WriteArchive::EndSection(bool)
         */
        virtual void EndSection(bool) = 0;
        /**
         * Address: 0x0094EA20
         * Slot: 16
         * Demangled: public: virtual void __thiscall gpg::WriteArchive::Close(void)
         */
        virtual void Close() = 0;
        /**
         * Address: 0x00A82547
         * Slot: 17
         * Demangled: _purecall
         */
        virtual void WriteMarker(int) = 0;

    public:
        std::map<void*, void*> mMap1;
        std::map<void*, void*> mMap2;
    };
} // namespace gpg

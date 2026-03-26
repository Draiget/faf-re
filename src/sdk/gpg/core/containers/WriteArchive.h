// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a reconstruction target; keep address docs in sync with recovered bodies.
#pragma once

#include <cstdio>
#include <cstdint>
#include <map>

#include "ArchiveSerialization.h"
#include "boost/shared_ptr.h"

namespace msvc8
{
    struct string;
}

namespace gpg
{
    class RRef;
    class RType;

    class WriteArchive
    {
    public:
        struct TrackedPointerRecord
        {
            RType* type = nullptr;
            int index = -1;
            TrackedPointerState ownership = TrackedPointerState::Reserved;
        };
        static_assert(sizeof(TrackedPointerRecord) == 0x0C, "TrackedPointerRecord size must be 0x0C");

    public:
        /**
         * Address: 0x00953C80 (FUN_00953C80)
         * Demangled: gpg::WriteArchive::dtr
         *
         * What it does:
         * Destroys write-archive bookkeeping state.
         */
        virtual ~WriteArchive();

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
         * Address: 0x009510B0 (FUN_009510B0)
         * Slot: 15
         * Demangled: public: virtual void __thiscall gpg::WriteArchive::EndSection(bool)
         *
         * What it does:
         * Finalizes section ownership checks and clears pointer/type bookkeeping.
         */
        virtual void EndSection(bool);

        /**
         * Address: 0x0094EA20 (FUN_0094EA20)
         * Slot: 16
         * Demangled: public: virtual void __thiscall gpg::WriteArchive::Close(void)
         *
         * What it does:
         * Closes active archive section by delegating to EndSection(false).
         */
        virtual void Close();

        /**
         * Address: 0x00A82547
         * Slot: 17
         * Demangled: _purecall
         */
        virtual void WriteMarker(int) = 0;

        /**
         * Address: 0x00953CA0 (FUN_00953CA0)
         * Demangled: public: void __thiscall gpg::WriteArchive::Write(class gpg::RType const *,void const *,class gpg::RRef const &)
         *
         * What it does:
         * Writes one typed object payload using reflection serializer callbacks.
         */
        void Write(const gpg::RType* type, const void* object, const gpg::RRef& ownerRef);

        /**
         * Address: 0x00953200 (FUN_00953200)
         * Demangled: gpg::WriteArchive::WriteRefCounts
         *
         * What it does:
         * Emits a type-handle table reference or introduces a new type handle.
         */
        void WriteRefCounts(const gpg::RType* type);

    protected:
        std::map<const RType*, int> mRefCounts;
        std::map<const void*, TrackedPointerRecord> mObjRefs;

        friend void WriteRawPointer(WriteArchive* archive, const RRef& objectRef, TrackedPointerState state, const RRef& ownerRef);
    };

    /**
     * Address: import thunk used at 0x008812DC callsite
     * (`?CreateBinaryWriteArchive@gpg@@YAPAVWriteArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z`)
     *
     * What it does:
     * Creates one file-backed concrete `WriteArchive` for save/load serializers.
     */
    WriteArchive* CreateBinaryWriteArchive(const boost::shared_ptr<std::FILE>& file);
} // namespace gpg

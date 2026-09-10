// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a reconstruction target; keep address docs in sync with recovered bodies.
#pragma once

#include <cstdio>
#include <cstdint>
#include <iosfwd>
#include <map>

#include "ArchiveSerialization.h"
#include "legacy/containers/Map.h"
#include "boost/shared_ptr.h"

namespace msvc8
{
    struct string;
}

struct lua_State;
struct TString;
struct Table;
struct LClosure;
struct Udata;
struct CClosure;

namespace gpg
{
    class RRef;
    class RType;

    class WriteArchive
    {
    public:
        /**
         * Address: 0x00953BE0 (FUN_00953BE0, ??0WriteArchive@gpg@@QAE@@Z)
         *
         * What it does:
         * Initializes archive reflection/type bookkeeping maps and refreshes
         * global serializer helper registrations for write flows.
         */
        WriteArchive();

        /**
         * The mapped half of one tracked-pointer entry. The type is not in
         * here: it is in the key, because the tree is keyed on the whole
         * `RRef` -- IDA names the instantiation `std::map_RRef_TrackedPointer`,
         * `_Lbound` (0x0094FA20) orders on `mType` first and `mObj` second,
         * and the insert guard (0x009512CC) gives `0x0AAAAAA9` =
         * `0xFFFFFFFF / 0x18 - 1`, so with an 0x08 key the record is 0x10.
         *
         * The trailing `{px, pn}` pair is the shared owner the write path
         * parks on an entry; it is modelled raw here, as `TrackedPointerInfo`
         * models the read side's, so no refcount moves with a copy. That gap
         * is the same one on both sides and wants one fix, not two.
         */
        struct TrackedPointerRecord
        {
            int index = -1;                                          // +0x00
            TrackedPointerState ownership = TrackedPointerState::Reserved; // +0x04
            void* sharedObject = nullptr;                            // +0x08
            boost::detail::sp_counted_base* sharedControl = nullptr;  // +0x0C
        };
        static_assert(sizeof(TrackedPointerRecord) == 0x10, "TrackedPointerRecord size must be 0x10");

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
         * Address: 0x009523F0 (FUN_009523F0)
         * Demangled: public: class gpg::WriteArchive & __thiscall gpg::WriteArchive::PreCreatedPtr(class gpg::RRef const &)
         *
         * What it does:
         * Registers one already-created object pointer in tracked-pointer state
         * so subsequent pointer writes reference it as an existing entry.
         */
        WriteArchive& PreCreatedPtr(const gpg::RRef& objectRef);

        /**
         * Address: 0x00953200 (FUN_00953200)
         * Demangled: gpg::WriteArchive::WriteRefCounts
         *
         * What it does:
         * Emits a type-handle table reference or introduces a new type handle.
         */
        void WriteRefCounts(const gpg::RType* type);

        /**
         * Address: 0x0040F970 (FUN_0040F970, gpg::WriteArchive::WriteValue)
         *
         * What it does:
         * Reads one numeric lane from a legacy value payload and forwards it to
         * `WriteFloat`.
         */
        WriteArchive* WriteValue(const void* valueLane, int unusedTag);

        /**
         * Address: 0x0090B380 (FUN_0090B380, gpg::WriteArchive::WriteTThread)
         *
         * What it does:
         * Wraps one Lua `lua_State*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteTThread(lua_State* threadState, const gpg::RRef& ownerRef);

        /**
         * Address: 0x00920870 (FUN_00920870, gpg::WriteArchive::WriteTString)
         *
         * What it does:
         * Wraps one Lua `TString*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteTString(TString* value, const gpg::RRef& ownerRef);

        /**
         * Address: 0x009208B0 (FUN_009208B0, gpg::WriteArchive::WriteTTable)
         *
         * What it does:
         * Wraps one Lua `Table*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteTTable(Table* table, const gpg::RRef& ownerRef);

        /**
         * Address: 0x009208F0 (FUN_009208F0, gpg::WriteArchive::WriteFunction)
         *
         * What it does:
         * Wraps one Lua `LClosure*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteFunction(LClosure* closure, const gpg::RRef& ownerRef);

        /**
         * Address: 0x00920930 (FUN_00920930, gpg::WriteArchive::WriteUserdata)
         *
         * What it does:
         * Wraps one Lua `Udata*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteUserdata(Udata* userdata, const gpg::RRef& ownerRef);

        /**
         * Address: 0x00921240 (FUN_00921240, gpg::WriteArchive::WriteCFunction)
         *
         * What it does:
         * Wraps one Lua `CClosure*` as an `RRef` and emits it as an unowned
         * tracked pointer lane using caller-provided owner context.
         */
        WriteArchive* WriteCFunction(CClosure* closure, const gpg::RRef& ownerRef);

    protected:
        /**
         * Both are the legacy 12-byte `{proxy, head, size}` map heads, not the
         * modern `std::map`. The ctor (0x00953BE0) constructs them at
         * `[this+4]` and `[this+10h]`, twelve bytes apart, and both derived
         * archives (0x00904740, 0x00939280) allocate 0x2C and start their own
         * state at +0x20 -- which only closes if each head is 0x0C and the
         * gap below it is one dword.
         *
         * `mObjRefs`'s node is 0x28 (allocator 0x009505D0) with colour/nil at
         * `+0x24`/`+0x25`, and its insert guard (0x009512CC) compares against
         * `0x0AAAAAA9` = `0xFFFFFFFF / 0x18 - 1`, so its `value_type` is 0x18.
         * IDA types that tree `std::map_RRef_TrackedPointer`, and `RRef` is
         * 0x08 -- so the key is the whole `RRef` and the record is 0x10.
         */
        msvc8::map<const RType*, int> mRefCounts;                  // +0x04
        msvc8::map<RRef, TrackedPointerRecord, RRefCompare> mObjRefs; // +0x10

        /**
         * One 4-byte slot at +0x1C that this class's own ctor and dtor never
         * touch, and which none of `Close`/`EndSection`/`PreCreatedPtr`/
         * `Write`/`WriteRawPointer` reads. Its existence is nonetheless
         * certain, from three independent readings of the binary:
         *
         *  - `gpg::WriteArchive::WriteArchive` (0x00953BE0) lays the two maps
         *    at `lea esi, [edi+4]` and `lea esi, [edi+10h]`, each spanning 12
         *    bytes, so the recovered members end at +0x1C;
         *  - `CreateBinaryWriteArchive` (0x00904740) allocates 0x2C and writes
         *    its shared owner at [esi+20h]/[esi+24h] and the duplicate handle
         *    at [esi+28h];
         *  - `CreateTextWriteArchive` (0x00939280) allocates 0x2C too and
         *    writes the same three offsets.
         *
         * Two unrelated derived classes both starting at +0x20 puts the gap in
         * the shared base, not in either of them. Named by the offset
         * convention for not-yet-identified fields rather than guessed at: the
         * layout is proven, the purpose is not.
         */
        std::uint32_t field_0x1C = 0;             // +0x1C

        friend void WriteRawPointer(WriteArchive* archive, const RRef& objectRef, TrackedPointerState state, const RRef& ownerRef);
    };

    // The size gate holds now. It could not while the two members were
    // `std::map`, whose size depends on the toolchain's iterator-debugging
    // level and so differs between the isolated-TU check and the full Debug
    // build; `msvc8::map` is the legacy 0x0C head in both, which is what the
    // binary has, so the 0x20 base the two derived archives imply is now
    // something the compiler can check.
    static_assert(sizeof(msvc8::map<const RType*, int>) == 0x0C, "the legacy map head must be 0x0C");
    static_assert(sizeof(WriteArchive) == 0x20, "gpg::WriteArchive size must be 0x20");

    /**
     * Address: import thunk used at 0x008812DC callsite
     * (`?CreateBinaryWriteArchive@gpg@@YAPAVWriteArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z`)
     *
     * What it does:
     * Creates one file-backed concrete `WriteArchive` for save/load serializers.
     */
    WriteArchive* CreateBinaryWriteArchive(const boost::shared_ptr<std::FILE>& file);

    /**
     * Address: 0x00939280 (FUN_00939280, ?CreateTextWriteArchive@gpg@@YAPAVWriteArchive@1@ABV?$shared_ptr@V?$basic_ostream@DU?$char_traits@D@std@@@std@@@boost@@@Z_0)
     *
     * What it does:
     * Creates one text-backed concrete `WriteArchive` bound to an output stream.
     */
    WriteArchive* CreateTextWriteArchive(const boost::shared_ptr<std::ostream>& stream);
} // namespace gpg

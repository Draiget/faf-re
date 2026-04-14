#include "WriteArchive.h"

#include <cstdint>
#include <cstdio>
#include <new>
#include <ostream>

#include "String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"

using namespace gpg;

namespace
{
struct LegacyValueFloatLane
{
    float number;
};

[[noreturn]] void ThrowSerializationError(const char* const message)
{
    throw SerializationError(message ? message : "");
}

[[noreturn]] void ThrowSerializationError(const msvc8::string& message)
{
    throw SerializationError(message.c_str());
}

const char* SafeTypeName(const RType* const type)
{
    return type ? type->GetName() : "null";
}

constexpr char kArchiveTokenBytes[] = {'}', 'N', '0', '*', '{'};

class TextWriteArchive final : public gpg::WriteArchive
{
public:
    explicit TextWriteArchive(const boost::shared_ptr<std::ostream>& stream)
        : mStreamRef(stream)
        , mStream(stream.get())
    {
    }

    /**
     * Address: 0x009391E0 (FUN_009391E0, ??1TextWriteArchive@@QAE@@Z)
     * Address: 0x00939260 (FUN_00939260, scalar deleting destructor thunk)
     *
     * What it does:
     * Releases stream shared-owner state and tears down `WriteArchive` base
     * bookkeeping.
     */
    ~TextWriteArchive() override = default;

    /**
     * Address: 0x0093E8E0 (FUN_0093E8E0, TextWriteArchive::WriteBytes)
     *
     * What it does:
     * Writes one byte span as grouped lowercase hex pairs (`32` bytes per line,
     * extra separator after every fourth byte).
     */
    void WriteBytes(char* bytes, size_t byteCount) override
    {
        if (byteCount == 0u) {
            return;
        }

        int lineColumn = 0;
        for (size_t i = 0; i < byteCount; ++i) {
            const unsigned char value = static_cast<unsigned char>(bytes[i]);
            const msvc8::string encodedByte = STR_Printf("%02x", static_cast<unsigned int>(value));
            (*mStream) << encodedByte.c_str();

            ++lineColumn;
            if (lineColumn == 32) {
                mStream->put('\n');
                lineColumn = 0;
                continue;
            }

            mStream->put(' ');
            if ((lineColumn & 3) == 0) {
                mStream->put(' ');
            }
        }

        if (lineColumn != 0) {
            mStream->put('\n');
        }
    }

    /**
     * Address: 0x0093EB60 (FUN_0093EB60, TextWriteArchive::WriteString)
     *
     * What it does:
     * Writes one quoted, escaped text lane (`\\n`, `\\t`, `\\\"`, `\\\\`, octal
     * escapes for non-printable bytes), then terminates the record with newline.
     */
    void WriteString(msvc8::string* const value) override
    {
        mStream->put('"');
        const char* const data = value->c_str();
        const size_t size = value->size();
        for (size_t i = 0; i < size; ++i) {
            const unsigned char c = static_cast<unsigned char>(data[i]);
            switch (c) {
            case '\n':
                (*mStream) << "\\n";
                break;
            case '\t':
                (*mStream) << "\\t";
                break;
            case '"':
                (*mStream) << "\\\"";
                break;
            case '\\':
                (*mStream) << "\\\\";
                break;
            default:
                if (c < 0x20u || c > 0x7Eu) {
                    const msvc8::string octalByte = STR_Printf("%03o", static_cast<unsigned int>(c));
                    (*mStream) << "\\" << octalByte.c_str();
                } else {
                    mStream->put(static_cast<char>(c));
                }
                break;
            }
        }
        mStream->put('"');
        mStream->put('\n');
    }

    /**
     * Address: 0x0093EB40 (FUN_0093EB40, TextWriteArchive::WriteFloat)
     */
    void WriteFloat(float value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EB20 (FUN_0093EB20, TextWriteArchive::WriteUInt64)
     */
    void WriteUInt64(uint64_t value) override
    {
        WriteScalarWithTrailingSpace(static_cast<unsigned long long>(value));
    }

    /**
     * Address: 0x0093EB00 (FUN_0093EB00, TextWriteArchive::WriteInt64)
     */
    void WriteInt64(int64_t value) override
    {
        WriteScalarWithTrailingSpace(static_cast<long long>(value));
    }

    /**
     * Address: 0x0093EAE0 (FUN_0093EAE0, TextWriteArchive::WriteULong)
     */
    void WriteULong(unsigned long value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EAC0 (FUN_0093EAC0, TextWriteArchive::WriteLong)
     */
    void WriteLong(long value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EAA0 (FUN_0093EAA0, TextWriteArchive::WriteUInt)
     */
    void WriteUInt(unsigned int value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EA80 (FUN_0093EA80, TextWriteArchive::WriteInt)
     */
    void WriteInt(int value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EA60 (FUN_0093EA60, TextWriteArchive::WriteUShort)
     */
    void WriteUShort(unsigned short value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EA40 (FUN_0093EA40, TextWriteArchive::WriteShort)
     */
    void WriteShort(short value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093EA20 (FUN_0093EA20, TextWriteArchive::WriteUByte)
     */
    void WriteUByte(unsigned __int8 value) override
    {
        WriteScalarWithTrailingSpace(static_cast<int>(value));
    }

    /**
     * Address: 0x0093EA00 (FUN_0093EA00, TextWriteArchive::WriteByte)
     */
    void WriteByte(__int8 value) override
    {
        WriteScalarWithTrailingSpace(static_cast<int>(value));
    }

    /**
     * Address: 0x0093E9E0 (FUN_0093E9E0, TextWriteArchive::WriteBool)
     */
    void WriteBool(bool value) override
    {
        WriteScalarWithTrailingSpace(value);
    }

    /**
     * Address: 0x0093B960 (FUN_0093B960, TextWriteArchive::WriteToken)
     *
     * What it does:
     * Writes one textual marker byte (`}N0*{`) and appends a separator space.
     */
    void WriteMarker(int marker) override
    {
        mStream->put(kArchiveTokenBytes[marker]);
        mStream->put(' ');
    }

private:
    template <typename T>
    void WriteScalarWithTrailingSpace(const T& value)
    {
        (*mStream) << value;
        mStream->put(' ');
    }

private:
    boost::shared_ptr<std::ostream> mStreamRef;
    std::ostream* mStream;
};

class BinaryWriteArchive final : public gpg::WriteArchive
{
public:
    explicit BinaryWriteArchive(const boost::shared_ptr<std::FILE>& file)
        : mFile(file)
    {
    }

    /**
     * Address: 0x00904A60 (FUN_00904A60, BinaryWriteArchive::WriteBytes)
     *
     * What it does:
     * Writes one raw byte lane (`fwrite(bytes, byteCount, 1, stream)`) and
     * throws `SerializationError("nowrite")` when the stream write fails.
     */
    void WriteBytes(char* bytes, size_t byteCount) override
    {
        if (std::fwrite(bytes, byteCount, 1u, mFile.get()) != 1u) {
            ThrowSerializationError("nowrite");
        }
    }

    /**
     * Address: 0x00905AC0 (FUN_00905AC0, BinaryWriteArchive::WriteString)
     *
     * What it does:
     * Writes one length-prefixed string lane to the archive stream and throws
     * `SerializationError("nowrite")` when either write fails.
     */
    void WriteString(msvc8::string* const value) override
    {
        std::FILE* const file = mFile.get();
        const std::uint32_t byteCount = static_cast<std::uint32_t>(value->size());

        if (!file || std::fwrite(&byteCount, sizeof(byteCount), 1u, file) != 1u) {
            ThrowSerializationError("nowrite");
        }

        if (byteCount != 0u && std::fwrite(value->raw_data_unsafe(), byteCount, 1u, file) != 1u) {
            ThrowSerializationError("nowrite");
        }
    }

    /**
     * Address: 0x00905A80 (FUN_00905A80, BinaryWriteArchive::WriteFloat)
     *
     * What it does:
     * Writes one 32-bit float lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteFloat(float value) override
    {
        WriteScalarNowrite(value, 4u);
    }

    /**
     * Address: 0x00905A40 (FUN_00905A40, BinaryWriteArchive::WriteUInt64)
     *
     * What it does:
     * Writes one 64-bit unsigned lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteUInt64(uint64_t value) override
    {
        WriteScalarNowrite(value, 8u);
    }

    /**
     * Address: 0x00905A00 (FUN_00905A00, BinaryWriteArchive::WriteInt64)
     *
     * What it does:
     * Writes one 64-bit signed lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteInt64(int64_t value) override
    {
        WriteScalarNowrite(value, 8u);
    }

    /**
     * Address: 0x009059C0 (FUN_009059C0, BinaryWriteArchive::WriteULong)
     *
     * What it does:
     * Writes one unsigned long lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteULong(unsigned long value) override
    {
        WriteScalarNowrite(value, 4u);
    }

    /**
     * Address: 0x00905980 (FUN_00905980, BinaryWriteArchive::WriteLong)
     *
     * What it does:
     * Writes one signed long lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteLong(long value) override
    {
        WriteScalarNowrite(value, 4u);
    }

    /**
     * Address: 0x00905940 (FUN_00905940, BinaryWriteArchive::WriteUInt)
     *
     * What it does:
     * Writes one 32-bit unsigned lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteUInt(unsigned int value) override
    {
        WriteScalarNowrite(value, 4u);
    }

    /**
     * Address: 0x00905900 (FUN_00905900, BinaryWriteArchive::WriteInt)
     *
     * What it does:
     * Writes one 32-bit signed lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteInt(int value) override
    {
        WriteScalarNowrite(value, 4u);
    }

    /**
     * Address: 0x009058C0 (FUN_009058C0, BinaryWriteArchive::WriteUShort)
     *
     * What it does:
     * Writes one unsigned 16-bit lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteUShort(unsigned short value) override
    {
        WriteScalarNowrite(value, 2u);
    }

    /**
     * Address: 0x00905880 (FUN_00905880, BinaryWriteArchive::WriteShort)
     *
     * What it does:
     * Writes one signed 16-bit lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteShort(short value) override
    {
        WriteScalarNowrite(value, 2u);
    }

    /**
     * Address: 0x00905840 (FUN_00905840, BinaryWriteArchive::WriteUByte)
     *
     * What it does:
     * Writes one unsigned byte lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteUByte(unsigned __int8 value) override
    {
        WriteScalarNowrite(value, 1u);
    }

    /**
     * Address: 0x00905800 (FUN_00905800, BinaryWriteArchive::WriteByte)
     *
     * What it does:
     * Writes one signed byte lane and throws `SerializationError("nowrite")`
     * when the stream write fails.
     */
    void WriteByte(__int8 value) override
    {
        WriteScalarNowrite(value, 1u);
    }

    /**
     * Address: 0x009057C0 (FUN_009057C0, BinaryWriteArchive::WriteBool)
     *
     * What it does:
     * Writes one boolean lane as one byte and throws
     * `SerializationError("nowrite")` when the stream write fails.
     */
    void WriteBool(bool value) override
    {
        WriteScalarNowrite(value, 1u);
    }

    /**
     * Address: 0x00905B60 (FUN_00905B60, BinaryWriteArchive::WriteToken)
     *
     * What it does:
     * Writes one lexical archive marker byte (`}N0*{`) mapped from one
     * runtime `ArchiveToken` ordinal lane and throws `SerializationError("nowrite")`
     * when the marker write fails.
     */
    void WriteMarker(int marker) override
    {
        std::FILE* const file = mFile.get();
        const char markerByte = kArchiveTokenBytes[marker];
        if (!file || std::fwrite(&markerByte, 1u, 1u, file) != 1u) {
            ThrowSerializationError("nowrite");
        }
    }

private:
    template <typename T>
    void WriteScalarNowrite(const T& value, std::size_t elementSize)
    {
        if (std::fwrite(&value, elementSize, 1u, mFile.get()) != 1u) {
            ThrowSerializationError("nowrite");
        }
    }

private:
    boost::shared_ptr<std::FILE> mFile;
};
} // namespace

/**
 * Address: 0x00953BE0 (FUN_00953BE0, ??0WriteArchive@gpg@@QAE@@Z)
 *
 * What it does:
 * Initializes write-archive map bookkeeping and refreshes global serializer
 * helper registrations used by reflection save lanes.
 */
WriteArchive::WriteArchive()
    : mRefCounts()
    , mObjRefs()
{
    SerHelperBase::InitNewHelpers();
}

/**
 * Address: 0x00953C80 (FUN_00953C80)
 * Demangled: gpg::WriteArchive::dtr
 *
 * What it does:
 * Destroys write-archive bookkeeping state.
 */
WriteArchive::~WriteArchive() = default;

/**
 * Address: 0x0040F970 (FUN_0040F970, gpg::WriteArchive::WriteValue)
 *
 * What it does:
 * Reads one numeric lane from a legacy value payload and forwards it to
 * `WriteFloat`.
 */
WriteArchive* WriteArchive::WriteValue(const void* const valueLane, const int /*unusedTag*/)
{
    const auto* const value = static_cast<const LegacyValueFloatLane*>(valueLane);
    WriteFloat(value->number);
    return this;
}

/**
 * Address: 0x00953200 (FUN_00953200)
 * Demangled: gpg::WriteArchive::WriteRefCounts
 *
 * What it does:
 * Emits a type-handle table reference or introduces a new type handle.
 */
void WriteArchive::WriteRefCounts(const RType* const type)
{
    if (!type) {
        ThrowSerializationError("Error while creating archive: null type descriptor.");
    }

    const std::map<const RType*, int>::iterator it = mRefCounts.find(type);
    if (it == mRefCounts.end()) {
        WriteInt(-1);
        msvc8::string typeName(type->GetName());
        WriteString(&typeName);
        WriteInt(type->version_);
        mRefCounts.insert(std::make_pair(type, static_cast<int>(mRefCounts.size())));
        return;
    }

    WriteInt(it->second);
}

/**
 * Address: 0x00953CA0 (FUN_00953CA0)
 * Demangled: public: void __thiscall gpg::WriteArchive::Write(class gpg::RType const *,void const *,class gpg::RRef const &)
 *
 * What it does:
 * Writes one typed object payload using reflection serializer callbacks.
 */
void WriteArchive::Write(const RType* const type, const void* const object, const RRef& ownerRef)
{
    if (!type) {
        ThrowSerializationError("Error while creating archive: null type descriptor.");
    }

    if (!type->serSaveFunc_) {
        const RIndexed* pointerType = type->IsPointer();
        if (pointerType) {
            const RRef pointerRef = pointerType->SubscriptIndex(const_cast<void*>(object), 0);
            WriteRawPointer(this, pointerRef, TrackedPointerState::Unowned, ownerRef);
            return;
        }

        ThrowSerializationError(STR_Printf(
            "Error while creating archive: encounted an object of type \"%s\", but we have no serializer for it.",
            SafeTypeName(type)
        ));
    }

    WriteMarker(static_cast<int>(ArchiveToken::ObjectStart));
    WriteRefCounts(type);
    type->serSaveFunc_(this, reinterpret_cast<int>(const_cast<void*>(object)), type->version_, const_cast<RRef*>(&ownerRef));
    WriteMarker(static_cast<int>(ArchiveToken::ObjectTerminator));
}

/**
 * Address: 0x009523F0 (FUN_009523F0)
 * Demangled: public: class gpg::WriteArchive & __thiscall gpg::WriteArchive::PreCreatedPtr(class gpg::RRef const &)
 *
 * What it does:
 * Pre-registers one non-null object pointer into the tracked-pointer map so
 * nested writes can emit `ExistingPointer` references to that object.
 */
WriteArchive& WriteArchive::PreCreatedPtr(const RRef& objectRef)
{
    if (!objectRef.mObj) {
        ThrowSerializationError("Error while creating archive: NULL pre-created pointers are not allowed.");
    }

    if (mObjRefs.find(objectRef.mObj) != mObjRefs.end()) {
        ThrowSerializationError(
            "Error while creating archive: can't register pre-created pointer because it has already been serialized."
        );
    }

    TrackedPointerRecord record{};
    record.type = objectRef.mType;
    record.index = static_cast<int>(mObjRefs.size());
    record.ownership = TrackedPointerState::Owned;
    mObjRefs.insert(std::make_pair(objectRef.mObj, record));
    return *this;
}

/**
 * Address: 0x009510B0 (FUN_009510B0)
 * Demangled: public: virtual void __thiscall gpg::WriteArchive::EndSection(bool)
 *
 * What it does:
 * Finalizes section ownership checks and clears pointer/type bookkeeping.
 */
void WriteArchive::EndSection(const bool skipOwnershipValidation)
{
    if (!skipOwnershipValidation) {
        for (std::map<const void*, TrackedPointerRecord>::const_iterator it = mObjRefs.begin(); it != mObjRefs.end();
             ++it) {
            const TrackedPointerRecord& ptr = it->second;
            if (ptr.ownership == TrackedPointerState::Unowned) {
                ThrowSerializationError(STR_Printf(
                    "Error while creating archive: nobody claimed ownership of %s 0x%08x",
                    SafeTypeName(ptr.type),
                    reinterpret_cast<unsigned int>(it->first)
                ));
            }
        }
    }

    mRefCounts.clear();
    mObjRefs.clear();
}

/**
 * Address: 0x0094EA20 (FUN_0094EA20)
 * Demangled: public: virtual void __thiscall gpg::WriteArchive::Close(void)
 *
 * What it does:
 * Closes active archive section by delegating to EndSection(false).
 */
void WriteArchive::Close()
{
    EndSection(false);
}

/**
 * Address: import thunk used at 0x008812DC callsite
 * (`?CreateBinaryWriteArchive@gpg@@YAPAVWriteArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z`)
 *
 * What it does:
 * Creates one file-backed concrete `WriteArchive` for save/load serializers.
 */
WriteArchive* gpg::CreateBinaryWriteArchive(const boost::shared_ptr<std::FILE>& file)
{
    if (!file.get()) {
        ThrowSerializationError("Error while creating archive: invalid output stream.");
    }
    return new BinaryWriteArchive(file);
}

/**
 * Address: 0x00939280 (FUN_00939280, ?CreateTextWriteArchive@gpg@@YAPAVWriteArchive@1@ABV?$shared_ptr@V?$basic_ostream@DU?$char_traits@D@std@@@std@@@boost@@@Z_0)
 *
 * What it does:
 * Creates one text-backed concrete `WriteArchive` bound to an output stream.
 */
WriteArchive* gpg::CreateTextWriteArchive(const boost::shared_ptr<std::ostream>& stream)
{
    return new (std::nothrow) TextWriteArchive(stream);
}

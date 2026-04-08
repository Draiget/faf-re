#include "WriteArchive.h"

#include <cstdint>
#include <cstdio>

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

class BinaryWriteArchive final : public gpg::WriteArchive
{
public:
    explicit BinaryWriteArchive(const boost::shared_ptr<std::FILE>& file)
        : mFile(file)
    {
    }

    void WriteBytes(char* bytes, size_t byteCount) override
    {
        WriteRaw(bytes, byteCount);
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

    void WriteFloat(float value) override
    {
        WritePod(value);
    }

    void WriteUInt64(uint64_t value) override
    {
        WritePod(value);
    }

    void WriteInt64(int64_t value) override
    {
        WritePod(value);
    }

    void WriteULong(unsigned long value) override
    {
        WritePod(value);
    }

    void WriteLong(long value) override
    {
        WritePod(value);
    }

    void WriteUInt(unsigned int value) override
    {
        WritePod(value);
    }

    void WriteInt(int value) override
    {
        WritePod(value);
    }

    void WriteUShort(unsigned short value) override
    {
        WritePod(value);
    }

    void WriteShort(short value) override
    {
        WritePod(value);
    }

    void WriteUByte(unsigned __int8 value) override
    {
        WritePod(value);
    }

    void WriteByte(__int8 value) override
    {
        WritePod(value);
    }

    void WriteBool(bool value) override
    {
        WritePod(value);
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
    void WritePod(const T& value)
    {
        WriteRaw(&value, sizeof(value));
    }

    void WriteRaw(const void* bytes, size_t byteCount)
    {
        std::FILE* const file = mFile.get();
        if (!file) {
            ThrowSerializationError("Error while creating archive: invalid output stream.");
        }

        if (byteCount == 0) {
            return;
        }

        if (std::fwrite(bytes, byteCount, 1, file) != 1) {
            ThrowSerializationError("Error while creating archive: unable to write stream bytes.");
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

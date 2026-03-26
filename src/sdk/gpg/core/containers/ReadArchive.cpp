#include "ReadArchive.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "String.h"

using namespace gpg;

namespace
{
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

  [[noreturn]] void ThrowReadFailure(std::FILE* const file)
  {
    if (file != nullptr && std::feof(file) != 0) {
      ThrowSerializationError("eof");
    }
    ThrowSerializationError("noread");
  }

  class BinaryReadArchive final : public gpg::ReadArchive
  {
  public:
    explicit BinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
      : mFile(file)
    {
    }

    void ReadBytes(char* const bytes, const size_t byteCount) override
    {
      if (!bytes && byteCount != 0) {
        ThrowSerializationError("noread");
      }

      std::FILE* const file = mFile.get();
      if (!file) {
        ThrowSerializationError("noread");
      }

      if (byteCount == 0) {
        return;
      }

      if (std::fread(bytes, byteCount, 1, file) != 1) {
        ThrowReadFailure(file);
      }
    }

    void ReadString(msvc8::string* const out) override
    {
      if (!out) {
        ThrowSerializationError("noread");
      }

      std::string value{};
      while (true) {
        char nextByte = '\0';
        ReadBytes(&nextByte, 1);
        if (nextByte == '\0') {
          out->assign_owned(value);
          return;
        }
        value.push_back(nextByte);
      }
    }

    void ReadFloat(float* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadUInt64(unsigned __int64* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadInt64(__int64* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadULong(unsigned long* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadLong(long* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadUInt(unsigned int* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadInt(int* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadUShort(unsigned short* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadShort(short* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadUByte(unsigned __int8* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadByte(__int8* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    void ReadBool(bool* const value) override
    {
      ReadBytes(reinterpret_cast<char*>(value), sizeof(*value));
    }

    int NextMarker() override
    {
      int marker = 0;
      ReadInt(&marker);
      return marker;
    }

  private:
    boost::shared_ptr<std::FILE> mFile;
  };
} // namespace

/**
 * Address: 0x00953700 (FUN_00953700)
 * Demangled: gpg::ReadArchive::dtr
 *
 * What it does:
 * Destroys read-archive bookkeeping state.
 */
ReadArchive::~ReadArchive() = default;

/**
 * Address: 0x00952F10 (FUN_00952F10)
 * Demangled: gpg::ReadArchive::ReadTypeHandle
 *
 * What it does:
 * Reads or resolves reflected type/version handle from archive token stream.
 */
TypeHandle ReadArchive::ReadTypeHandle()
{
  int index = 0;
  ReadInt(&index);

  if (index == -1) {
    msvc8::string typeName;
    ReadString(&typeName);

    RType* type = REF_FindTypeNamed(typeName.c_str());
    if (!type) {
      ThrowSerializationError(STR_Printf("No type named \"%s\"", typeName.c_str()));
    }

    int version = 0;
    ReadInt(&version);

    TypeHandle handle{};
    handle.type = type;
    handle.version = version;
    mTypeHandles.push_back(handle);
    return handle;
  }

  if (index < 0 || static_cast<size_t>(index) >= mTypeHandles.size()) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found a reference to type index %d, but only %d types have been mentioned.",
      index,
      static_cast<int>(mTypeHandles.size())
    ));
  }

  return mTypeHandles[static_cast<size_t>(index)];
}

/**
 * Address: 0x00953DA0 (FUN_00953DA0)
 * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const &)
 *
 * What it does:
 * Reads one typed object payload using reflection serializer callbacks.
 */
void ReadArchive::Read(const RType* const type, void* const object, const RRef& ownerRef)
{
  if (!type) {
    ThrowSerializationError("Error detected in archive: null type descriptor.");
  }

  if (!type->serLoadFunc_) {
    const RIndexed* pointerType = type->IsPointer();
    if (pointerType) {
      const TrackedPointerInfo tracked = ReadRawPointer(this, ownerRef);
      RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      pointerType->AssignPointer(object, source);
      return;
    }

    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
      SafeTypeName(type)
    ));
  }

  const int marker = NextMarker();
  if (marker != static_cast<int>(ArchiveToken::ObjectStart)) {
    ArchiveToken tokenCopy = static_cast<ArchiveToken>(marker);
    const RRef tokenRef = RRef_ArchiveToken(&tokenCopy);
    const msvc8::string tokenLexical = tokenRef.mType ? tokenRef.GetLexical() : STR_Printf("%d", marker);
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: expected an OBJECT_START token marking the beginning of a \"%s\", but got a %s "
      "instead.",
      SafeTypeName(type),
      tokenLexical.c_str()
    ));
  }

  const TypeHandle handle = ReadTypeHandle();
  if (handle.type != type) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: found an object of type \"%s\", but expected one of \"%s\".",
      SafeTypeName(handle.type),
      SafeTypeName(type)
    ));
  }

  type->serLoadFunc_(this, reinterpret_cast<int>(object), handle.version, const_cast<RRef*>(&ownerRef));

  if (NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.", SafeTypeName(type)
    ));
  }
}

/**
 * Address: 0x00952BD0 (FUN_00952BD0)
 * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
 *
 * What it does:
 * Releases tracked pointer/type-handle section state, including releasing
 * shared control blocks for tracked shared-pointer lanes.
 */
void ReadArchive::EndSection(const bool)
{
  for (size_t i = 0; i < mTrackedPtrs.size(); ++i) {
    TrackedPointerInfo& tracked = mTrackedPtrs[i];
    if (tracked.state == TrackedPointerState::Owned && tracked.object && tracked.type) {
      RRef ref{};
      ref.mObj = tracked.object;
      ref.mType = tracked.type;
      ref.Delete();
    } else if (tracked.state == TrackedPointerState::Shared && tracked.sharedControl) {
      tracked.sharedControl->release();
      tracked.sharedControl = nullptr;
      tracked.sharedObject = nullptr;
    }
  }

  mTypeHandles.clear();
  mTrackedPtrs.clear();
  mNullTrackedPointer = {};
}

/**
 * Address: 0x009048B0 (FUN_009048B0)
 * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
 *
 * What it does:
 * Creates one file-backed concrete `ReadArchive` for save/load serializers.
 */
ReadArchive* gpg::CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file)
{
  if (!file.get()) {
    ThrowSerializationError("noread");
  }
  return new BinaryReadArchive(file);
}

#include "ReadArchive.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "boost/shared_ptr.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "String.h"
#include "lua/LuaObject.h"

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

  [[nodiscard]] RType* CachedLuaStateType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaState));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (moho::Sim::sType == nullptr) {
      moho::Sim::sType = gpg::LookupRType(typeid(moho::Sim));
    }
    return moho::Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Unit));
    }
    return cached;
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
 * Address: 0x004C1520 (FUN_004C1520, gpg::ReadArchive::ReadPointer_LuaState)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `LuaPlus::LuaState`,
 * raising `SerializationError` when the pointer is not LuaState-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_LuaState(LuaPlus::LuaState** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  LuaPlus::LuaState* const asState = source.CastLuaState();
  *outValue = asState;
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedLuaStateType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "LuaState",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00584FB0 (FUN_00584FB0, gpg::ReadArchive::ReadPointer_Sim)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::Sim`,
 * raising `SerializationError` when the pointer is not Sim-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Sim(moho::Sim** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSimType());
  *outValue = static_cast<moho::Sim*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedSimType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Sim",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x005A2900 (FUN_005A2900, gpg::ReadArchive::ReadPointer_Unit)
 *
 * What it does:
 * Reads one tracked pointer lane and upcasts it to `moho::Unit`,
 * raising `SerializationError` when the pointer is not Unit-compatible.
 */
ReadArchive* ReadArchive::ReadPointer_Unit(moho::Unit** const outValue, const RRef* const ownerRef)
{
  if (!outValue) {
    return this;
  }

  const RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  const TrackedPointerInfo& tracked = gpg::ReadRawPointer(this, owner);

  RRef source{};
  source.mObj = tracked.object;
  source.mType = tracked.type;

  if (!source.mObj) {
    *outValue = nullptr;
    return this;
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitType());
  *outValue = static_cast<moho::Unit*>(upcast.mObj);
  if (*outValue) {
    return this;
  }

  const char* const expectedName = SafeTypeName(CachedUnitType());
  const char* const actualName = source.GetTypeName();
  ThrowSerializationError(STR_Printf(
    "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
    "instead",
    expectedName ? expectedName : "Unit",
    actualName ? actualName : "null"
  ));
  return this;
}

/**
 * Address: 0x00953B30 (FUN_00953B30)
 * Demangled: public: class gpg::ReadArchive & __thiscall gpg::ReadArchive::TrackPointer(class gpg::RRef const &)
 *
 * What it does:
 * Appends one tracked-pointer table lane for an object that already exists
 * at the time its serializer starts reading nested payload.
 */
ReadArchive& ReadArchive::TrackPointer(const RRef& objectRef)
{
  TrackedPointerInfo tracked{};
  tracked.object = objectRef.mObj;
  tracked.type = objectRef.mType;
  tracked.state = TrackedPointerState::Owned;
  tracked.sharedObject = nullptr;
  tracked.sharedControl = nullptr;
  mTrackedPtrs.push_back(tracked);
  return *this;
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

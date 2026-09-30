#include "lua/LuaRuntimeTypeInfo.h"

#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"

/**
 * Address: 0x00923280 (FUN_00923280, TStringTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `TStringTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyTStringTypeInfoDeleting(
  TStringTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923300 (FUN_00923300, TableTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `TableTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyTableTypeInfoDeleting(
  TableTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009233D0 (FUN_009233D0, LClosureTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `LClosureTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyLClosureTypeInfoDeleting(
  LClosureTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923460 (FUN_00923460, UpValTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `UpValTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyUpValTypeInfoDeleting(
  UpValTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009234C0 (FUN_009234C0, ProtoTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `ProtoTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyProtoTypeInfoDeleting(
  ProtoTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923550 (FUN_00923550, lua_StateTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `lua_StateTypeInfo` descriptor via `gpg::RType` base teardown
 * and conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyLuaStateTypeInfoDeleting(
  lua_StateTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x00923600 (FUN_00923600, UdataTypeInfo deleting-dtor thunk)
 *
 * What it does:
 * Tears down one `UdataTypeInfo` descriptor via `gpg::RType` base teardown and
 * conditionally frees storage when `deleteFlag & 1`.
 */
[[maybe_unused]] gpg::RType* DestroyUdataTypeInfoDeleting(
  UdataTypeInfo* const typeInfo,
  const unsigned char deleteFlag
)
{
  typeInfo->gpg::RType::~RType();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(typeInfo));
  }
  return typeInfo;
}

/**
 * Address: 0x009220B0 (FUN_009220B0, TableTypeInfo::TableTypeInfo)
 *
 * What it does:
 * Constructs the table runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Table)`.
 */
TableTypeInfo::TableTypeInfo()
{
  gpg::PreRegisterRType(typeid(Table), this);
}

/**
 * Address: 0x00921FD0 (FUN_00921FD0, TStringTypeInfo::TStringTypeInfo)
 *
 * What it does:
 * Constructs the TString runtime type descriptor and preregisters it with
 * reflection registry using `typeid(TString)`.
 */
TStringTypeInfo::TStringTypeInfo()
{
  gpg::PreRegisterRType(typeid(TString), this);
}

/**
 * Address: 0x00922020 (FUN_00922020, TStringTypeInfo::GetName)
 */
const char* TStringTypeInfo::GetName() const
{
  return "TStr";
}

/**
 * Address: 0x00922030 (FUN_00922030, TStringTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `TString`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void TStringTypeInfo::Init()
{
  // The registered size is the string header -- the character payload `str`
  // begins at +0x14 (see LuaRuntimeTypes.h), not at sizeof(TString).
  static_assert(offsetof(TString, str) == 0x14, "TString header is 0x14 bytes on x86");
  size_ = offsetof(TString, str);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922100 (FUN_00922100, TableTypeInfo::GetName)
 */
const char* TableTypeInfo::GetName() const
{
  return "Table";
}

/**
 * Address: 0x00922110 (FUN_00922110, TableTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Table`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void TableTypeInfo::Init()
{
  static_assert(sizeof(Table) == 0x24, "Table is 0x24 bytes on x86");
  size_ = sizeof(Table);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x009222D0 (FUN_009222D0, LClosureTypeInfo::LClosureTypeInfo)
 *
 * What it does:
 * Constructs the closure runtime type descriptor and preregisters it with
 * reflection registry using `typeid(LClosure)`.
 */
LClosureTypeInfo::LClosureTypeInfo()
{
  gpg::PreRegisterRType(typeid(LClosure), this);
}

/**
 * Address: 0x00922320 (FUN_00922320, LClosureTypeInfo::GetName)
 */
const char* LClosureTypeInfo::GetName() const
{
  return "LClosure";
}

/**
 * Address: 0x00922330 (FUN_00922330, LClosureTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `LClosure`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void LClosureTypeInfo::Init()
{
  static_assert(sizeof(LClosure) == 0x20, "LClosure is 0x20 bytes on x86");
  size_ = sizeof(LClosure);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x009223A0 (FUN_009223A0, UpValTypeInfo::UpValTypeInfo)
 *
 * What it does:
 * Constructs the upvalue runtime type descriptor and preregisters it with
 * reflection registry using `typeid(UpVal)`.
 */
UpValTypeInfo::UpValTypeInfo()
{
  gpg::PreRegisterRType(typeid(UpVal), this);
}

/**
 * Address: 0x009223F0 (FUN_009223F0, UpValTypeInfo::GetName)
 */
const char* UpValTypeInfo::GetName() const
{
  return "UpVal";
}

/**
 * Address: 0x00922400 (FUN_00922400, UpValTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `UpVal`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void UpValTypeInfo::Init()
{
  static_assert(sizeof(UpVal) == 0x14, "UpVal is 0x14 bytes on x86");
  size_ = sizeof(UpVal);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922470 (FUN_00922470, ProtoTypeInfo::ProtoTypeInfo)
 *
 * What it does:
 * Constructs the proto runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Proto)`.
 */
ProtoTypeInfo::ProtoTypeInfo()
{
  gpg::PreRegisterRType(typeid(Proto), this);
}

/**
 * Address: 0x009224C0 (FUN_009224C0, ProtoTypeInfo::GetName)
 */
const char* ProtoTypeInfo::GetName() const
{
  return "Proto";
}

/**
 * Address: 0x009224D0 (FUN_009224D0, ProtoTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Proto`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void ProtoTypeInfo::Init()
{
  static_assert(sizeof(Proto) == 0x70, "Proto is 0x70 bytes on x86");
  size_ = sizeof(Proto);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922540 (FUN_00922540, lua_StateTypeInfo::lua_StateTypeInfo)
 *
 * What it does:
 * Constructs the C lua_State runtime type descriptor and preregisters it with
 * reflection registry using `typeid(lua_State)`.
 */
lua_StateTypeInfo::lua_StateTypeInfo()
{
  gpg::PreRegisterRType(typeid(lua_State), this);
}

/**
 * Address: 0x00922590 (FUN_00922590, lua_StateTypeInfo::GetName)
 */
const char* lua_StateTypeInfo::GetName() const
{
  return "lua_State";
}

/**
 * Address: 0x009225A0 (FUN_009225A0, lua_StateTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for C `lua_State`, initializes base RType
 * state, and finalizes field/base descriptors.
 */
void lua_StateTypeInfo::Init()
{
  static_assert(sizeof(lua_State) == 0x48, "lua_State is 0x48 bytes on x86");
  size_ = sizeof(lua_State);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00922620 (FUN_00922620, UdataTypeInfo::UdataTypeInfo)
 *
 * What it does:
 * Constructs the Udata runtime type descriptor and preregisters it with
 * reflection registry using `typeid(Udata)`.
 */
UdataTypeInfo::UdataTypeInfo()
{
  gpg::PreRegisterRType(typeid(Udata), this);
}

/**
 * Address: 0x00922670 (FUN_00922670, UdataTypeInfo::GetName)
 */
const char* UdataTypeInfo::GetName() const
{
  return "Udata";
}

/**
 * Address: 0x00922680 (FUN_00922680, UdataTypeInfo::Init)
 *
 * What it does:
 * Sets reflected runtime size for `Udata`, initializes base RType state,
 * and finalizes field/base descriptors.
 */
void UdataTypeInfo::Init()
{
  static_assert(sizeof(Udata) == 0x10, "Udata is 0x10 bytes on x86");
  size_ = sizeof(Udata);
  gpg::RType::Init();
  Finish();
}

// ---------------------------------------------------------------------------
// Startup registration
//
// Each descriptor registers its typeid from its constructor, so the descriptor
// only enters the reflection map if something constructs it. The binary does
// that from its CRT initializer table; these are the equivalent entries.
// ---------------------------------------------------------------------------

namespace
{
  struct LuaRuntimeTypeInfoBootstrap
  {
    LuaRuntimeTypeInfoBootstrap()
    {
      register_TStringTypeInfoStartup();
      register_TableTypeInfoStartup();
      register_LClosureTypeInfoStartup();
      register_UpValTypeInfoStartup();
      register_ProtoTypeInfoStartup();
      register_lua_StateTypeInfoStartup();
      register_UdataTypeInfoStartup();
    }
  };

  LuaRuntimeTypeInfoBootstrap gLuaRuntimeTypeInfoBootstrap;
}

/**
 * Address: 0x00BEA1A0 (register_TStringTypeInfo)
 * Address: 0x00C09E80 (FUN_00C09E80, atexit destructor of the TStringTypeInfo object)
 */
void register_TStringTypeInfoStartup()
{
  static TStringTypeInfo sInstance;
}

/**
 * Address: 0x00BEA2B0 (register_TableTypeInfo)
 * Address: 0x00C09EE0 (FUN_00C09EE0, atexit destructor of the TableTypeInfo object)
 */
void register_TableTypeInfoStartup()
{
  static TableTypeInfo sInstance;
}

/**
 * Address: 0x00BEA3C0 (register_LClosureTypeInfo)
 * Address: 0x00C09F40 (FUN_00C09F40, atexit destructor of the LClosureTypeInfo object)
 */
void register_LClosureTypeInfoStartup()
{
  static LClosureTypeInfo sInstance;
}

/**
 * Address: 0x00BEA4D0 (register_UpValTypeInfo)
 * Address: 0x00C09FA0 (FUN_00C09FA0, atexit destructor of the UpValTypeInfo object)
 */
void register_UpValTypeInfoStartup()
{
  static UpValTypeInfo sInstance;
}

/**
 * Address: 0x00BEA5E0 (register_ProtoTypeInfo)
 * Address: 0x00C0A000 (FUN_00C0A000, atexit destructor of the ProtoTypeInfo object)
 */
void register_ProtoTypeInfoStartup()
{
  static ProtoTypeInfo sInstance;
}

/**
 * Address: 0x00BEA6F0 (register_lua_StateTypeInfo)
 * Address: 0x00C0A060 (FUN_00C0A060, atexit destructor of the lua_StateTypeInfo object)
 */
void register_lua_StateTypeInfoStartup()
{
  static lua_StateTypeInfo sInstance;
}

/**
 * Address: 0x00BEA800 (register_UdataTypeInfo)
 * Address: 0x00C0A0C0 (FUN_00C0A0C0, atexit destructor of the UdataTypeInfo object)
 */
void register_UdataTypeInfoStartup()
{
  static UdataTypeInfo sInstance;
}



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_TStringTypeInfoStartup_8f60e9, register_TStringTypeInfoStartup)
GPG_PREREGISTER_INIT(register_TableTypeInfoStartup_8f60e9, register_TableTypeInfoStartup)
GPG_PREREGISTER_INIT(register_LClosureTypeInfoStartup_8f60e9, register_LClosureTypeInfoStartup)
GPG_PREREGISTER_INIT(register_UpValTypeInfoStartup_8f60e9, register_UpValTypeInfoStartup)
GPG_PREREGISTER_INIT(register_ProtoTypeInfoStartup_8f60e9, register_ProtoTypeInfoStartup)
GPG_PREREGISTER_INIT(register_lua_StateTypeInfoStartup_8f60e9, register_lua_StateTypeInfoStartup)
GPG_PREREGISTER_INIT(register_UdataTypeInfoStartup_8f60e9, register_UdataTypeInfoStartup)

extern "C"
{
	TString* luaS_newlstr(lua_State* L, const char* str, std::size_t len);
	Udata* luaS_newudata(lua_State* L, gpg::RType* type);
	Table* luaH_new(lua_State* L, int narray, int lnhash);
	const LuaPlus::TObject* luaH_getstr(Table* t, TString* key);
	Closure* luaF_newLclosure(lua_State* L, int nelems, const LuaPlus::TObject* environment);
	UpVal* luaF_newupval(lua_State* L);
	Proto* luaF_newproto(lua_State* L);
	lua_State* luaE_newthread(lua_State* L);
	extern const LuaPlus::TObject luaO_nilobject;
}

TString* ResolveSerializedNameForLuaObject(lua_State* const state, LuaPlus::Value value);

void TString::MemberConstruct(
	gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();
	msvc8::string characters;
	archive.ReadString(&characters);
	result.SetOwned(gpg::MakeRRef(luaS_newlstr(state, characters.c_str(), characters.size())), 0u);
}

/**
 * Address: 0x00921500 (FUN_00921500)
 */
void TString::MemberSaveConstructArgs(
	gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
	msvc8::string characters(str, len);
	archive.WriteString(&characters);
	result.SetOwned(0u);
}

void Table::MemberConstruct(
	gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();

	bool savedByName = false;
	archive.ReadBool(&savedByName);
	if (savedByName) {
		TString* name = nullptr;
		archive.ReadPointer(&name, &ownerRef);

		const LuaPlus::TObject* const objectsByName =
			luaH_getstr(static_cast<Table*>(state->_gt.value.p), luaS_newlstr(state, "__serialize_object_for_name", 0x1Bu));
		const LuaPlus::TObject* const named = (objectsByName->tt == LUA_TTABLE)
			? luaH_getstr(static_cast<Table*>(objectsByName->value.p), name)
			: &luaO_nilobject;
		if (named->tt == LUA_TNIL) {
			throw gpg::SerializationError("Named script object not found");
		}
		if (named->tt != LUA_TTABLE) {
			throw gpg::SerializationError("Named script object was a table on save but isn't on load.");
		}

		result.SetOwned(gpg::MakeRRef(static_cast<Table*>(named->value.p)), 1u);
		return;
	}

	int arraySize = 0;
	archive.ReadInt(&arraySize);
	lu_byte hashSizeLog2 = 0u;
	archive.ReadUByte(&hashSizeLog2);
	result.SetOwned(gpg::MakeRRef(luaH_new(state, arraySize, hashSizeLog2)), 0u);
}

/**
 * Address: 0x00921590 (FUN_00921590)
 */
void Table::MemberSaveConstructArgs(
	gpg::WriteArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();

	LuaPlus::Value self{};
	self.p = this;
	if (TString* const name = ResolveSerializedNameForLuaObject(state, self)) {
		archive.WriteBool(true);
		archive.WritePointer(name, gpg::TrackedPointerState::Unowned, ownerRef);
		result.SetOwned(1u);
		return;
	}

	archive.WriteBool(false);
	archive.WriteInt(sizearray);
	archive.WriteUByte(lsizenode);
	result.SetOwned(0u);
}

void LClosure::MemberConstruct(
	gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();
	lu_byte upvalueCount = 0u;
	archive.ReadUByte(&upvalueCount);
	Closure* const closure = luaF_newLclosure(state, upvalueCount, &state->_gt);
	result.SetOwned(gpg::MakeRRef(&closure->l), 0u);
}

void LClosure::MemberSaveConstructArgs(
	gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
	archive.WriteUByte(nupvalues);
	result.SetOwned(0u);
}

void UpVal::MemberConstruct(
	gpg::ReadArchive&, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	result.SetOwned(gpg::MakeRRef(luaF_newupval(ownerRef.TryUpcastLuaThreadState())), 0u);
}

void UpVal::MemberSaveConstructArgs(
	gpg::WriteArchive&, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
	result.SetOwned(0u);
}

void UpVal::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
{
	archive->Read(gpg::RTypeOf<LuaPlus::TObject>(), v, ownerRef);
}

void UpVal::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef) const
{
	archive->Write(gpg::RTypeOf<LuaPlus::TObject>(), v, ownerRef);
}

void Proto::MemberConstruct(
	gpg::ReadArchive&, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	result.SetOwned(gpg::MakeRRef(luaF_newproto(ownerRef.TryUpcastLuaThreadState())), 0u);
}

void Proto::MemberSaveConstructArgs(
	gpg::WriteArchive&, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
	result.SetOwned(0u);
}

void lua_State::MemberConstruct(
	gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();
	bool isMainThread = false;
	archive.ReadBool(&isMainThread);
	if (isMainThread) {
		result.SetUnowned(gpg::MakeRRef(state), 1u);
		return;
	}
	result.SetOwned(gpg::MakeRRef(luaE_newthread(state)), 0u);
}

/**
 * Address: 0x00921630 (FUN_00921630)
 */
void lua_State::MemberSaveConstructArgs(
	gpg::WriteArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();
	if (l_G->mainthread != state) {
		throw gpg::SerializationError("Consistency check failed: value.l_G->mainthread == &state");
	}

	const bool isMainThread = (this == state);
	archive.WriteBool(isMainThread);
	if (isMainThread) {
		result.SetUnowned(1u);
		return;
	}

	if (nCcalls != 0u) {
		throw gpg::SerializationError("cannot save a Lua thread with active C calls");
	}
	result.SetOwned(0u);
}

void Udata::MemberConstruct(
	gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
	lua_State* const state = ownerRef.TryUpcastLuaThreadState();
	const gpg::TypeHandle payloadType = archive.ReadTypeHandle();
	result.SetOwned(gpg::MakeRRef(luaS_newudata(state, payloadType.type)), 0u);
}

void Udata::MemberSaveConstructArgs(
	gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
)
{
	archive.WriteRefCounts(reinterpret_cast<const gpg::RType*>(len));
	result.SetOwned(0u);
}

/**
 * `gpg::SerSaveConstructHelper<TString>`, vtable 0x00D47018.
 *
 * Address: 0x00BEA200 (FUN_00BEA200 -- constructs the global and registers its destructor.)
 * Address: 0x00C09A00 (FUN_00C09A00 -- the global's destructor.)
 * Address: 0x0091F930 (FUN_0091F930 -- `Init`.)
 * Address: 0x009220A0 (FUN_009220A0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
 */
struct TStringSaveConstruct : gpg::SerSaveConstructHelper<TString>
{};

/**
 * `gpg::SerConstructHelper<TString>`, vtable 0x00D46AB8.
 *
 * Address: 0x00BEA230 (FUN_00BEA230 -- constructs the global and registers its destructor.)
 * Address: 0x00C09A30 (FUN_00C09A30 -- the global's destructor.)
 * Address: 0x0091F9B0 (FUN_0091F9B0 -- `Init`.)
 * Address: 0x00921280 (FUN_00921280 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E3C0 (FUN_0091E3C0 -- `Delete`.)
 */
struct TStringConstruct : gpg::SerConstructHelper<TString>
{};

/**
 * `gpg::SerSaveConstructHelper<Table>`, vtable 0x00D47020.
 *
 * Address: 0x00BEA310 (FUN_00BEA310 -- constructs the global and registers its destructor.)
 * Address: 0x00C09A90 (FUN_00C09A90 -- the global's destructor.)
 * Address: 0x0091FAC0 (FUN_0091FAC0 -- `Init`.)
 * Address: 0x00922180 (FUN_00922180 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
 */
struct TableSaveConstruct : gpg::SerSaveConstructHelper<Table>
{};

/**
 * `gpg::SerConstructHelper<Table>`, vtable 0x00D47028.
 *
 * Address: 0x00BEA340 (FUN_00BEA340 -- constructs the global and registers its destructor.)
 * Address: 0x00C09AC0 (FUN_00C09AC0 -- the global's destructor.)
 * Address: 0x0091FB40 (FUN_0091FB40 -- `Init`.)
 * Address: 0x00922190 (FUN_00922190 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E3F0 (FUN_0091E3F0 -- `Delete`.)
 */
struct TableConstruct : gpg::SerConstructHelper<Table>
{};

/**
 * `gpg::SerSaveConstructHelper<LClosure>`, vtable 0x00D46A68.
 *
 * Address: 0x00BEA420 (FUN_00BEA420 -- constructs the global and registers its destructor.)
 * Address: 0x00C09B20 (FUN_00C09B20 -- the global's destructor.)
 * Address: 0x0091FC50 (FUN_0091FC50 -- `Init`.)
 * Address: 0x0091F490 (FUN_0091F490 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
 */
struct LClosureSaveConstruct : gpg::SerSaveConstructHelper<LClosure>
{};

/**
 * `gpg::SerConstructHelper<LClosure>`, vtable 0x00D46A90.
 *
 * Address: 0x00BEA450 (FUN_00BEA450 -- constructs the global and registers its destructor.)
 * Address: 0x00C09B50 (FUN_00C09B50 -- the global's destructor.)
 * Address: 0x0091FCD0 (FUN_0091FCD0 -- `Init`.)
 * Address: 0x00920A80 (FUN_00920A80 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E400 (FUN_0091E400 -- `Delete`.)
 */
struct LClosureConstruct : gpg::SerConstructHelper<LClosure>
{};

/**
 * `gpg::SerSaveConstructHelper<UpVal>`, vtable 0x00D46A70.
 *
 * Address: 0x00BEA530 (FUN_00BEA530 -- constructs the global and registers its destructor.)
 * Address: 0x00C09BB0 (FUN_00C09BB0 -- the global's destructor.)
 * Address: 0x0091FDE0 (FUN_0091FDE0 -- `Init`.)
 * Address: 0x0091E510 (FUN_0091E510 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
 */
struct UpValSaveConstruct : gpg::SerSaveConstructHelper<UpVal>
{};

/**
 * `gpg::SerConstructHelper<UpVal>`, vtable 0x00D46A98.
 *
 * Address: 0x00BEA560 (FUN_00BEA560 -- constructs the global and registers its destructor.)
 * Address: 0x00C09BE0 (FUN_00C09BE0 -- the global's destructor.)
 * Address: 0x0091FE60 (FUN_0091FE60 -- `Init`.)
 * Address: 0x00920B10 (FUN_00920B10 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E410 (FUN_0091E410 -- `Delete`.)
 */
struct UpValConstruct : gpg::SerConstructHelper<UpVal>
{};

/**
 * `gpg::SerSaveLoadHelper<UpVal>`, vtable 0x00D46A78.
 *
 * Address: 0x00BEA5A0 (FUN_00BEA5A0 -- constructs the global and registers its destructor.)
 * Address: 0x00C09C10 (FUN_00C09C10 -- the global's destructor.)
 * Address: 0x0091FEE0 (FUN_0091FEE0 -- `Init`.)
 * Address: 0x00920B60 (FUN_00920B60 -- `Deserialize`, `MemberDeserialize` inlined.)
 * Address: 0x00920BA0 (FUN_00920BA0 -- `Serialize`, `MemberSerialize` inlined.)
 */
struct UpValSerializer : gpg::SerSaveLoadHelper<UpVal>
{};

/**
 * `gpg::SerSaveConstructHelper<Proto>`, vtable 0x00D46A80.
 *
 * Address: 0x00BEA640 (FUN_00BEA640 -- constructs the global and registers its destructor.)
 * Address: 0x00C09C40 (FUN_00C09C40 -- the global's destructor.)
 * Address: 0x0091FF70 (FUN_0091FF70 -- `Init`.)
 * Address: 0x0091E520 (FUN_0091E520 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
 */
struct ProtoSaveConstruct : gpg::SerSaveConstructHelper<Proto>
{};

/**
 * `gpg::SerConstructHelper<Proto>`, vtable 0x00D46AA0.
 *
 * Address: 0x00BEA670 (FUN_00BEA670 -- constructs the global and registers its destructor.)
 * Address: 0x00C09C70 (FUN_00C09C70 -- the global's destructor.)
 * Address: 0x0091FFF0 (FUN_0091FFF0 -- `Init`.)
 * Address: 0x00920C20 (FUN_00920C20 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E420 (FUN_0091E420 -- `Delete`.)
 */
struct ProtoConstruct : gpg::SerConstructHelper<Proto>
{};

/**
 * `gpg::SerSaveConstructHelper<lua_State>`, vtable 0x00D47048.
 *
 * Address: 0x00BEA750 (FUN_00BEA750 -- constructs the global and registers its destructor.)
 * Address: 0x00C09CD0 (FUN_00C09CD0 -- the global's destructor.)
 * Address: 0x00920100 (FUN_00920100 -- `Init`.)
 * Address: 0x00922610 (FUN_00922610 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
 */
struct lua_StateSaveConstruct : gpg::SerSaveConstructHelper<lua_State>
{};

/**
 * `gpg::SerConstructHelper<lua_State>`, vtable 0x00D46AA8.
 *
 * Address: 0x00BEA780 (FUN_00BEA780 -- constructs the global and registers its destructor.)
 * Address: 0x00C09D00 (FUN_00C09D00 -- the global's destructor.)
 * Address: 0x00920180 (FUN_00920180 -- `Init`.)
 * Address: 0x00920C70 (FUN_00920C70 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E430 (FUN_0091E430 -- `Delete`.)
 */
struct lua_StateConstruct : gpg::SerConstructHelper<lua_State>
{};

/**
 * `gpg::SerSaveConstructHelper<Udata>`, vtable 0x00D46A88.
 *
 * Address: 0x00BEA860 (FUN_00BEA860 -- constructs the global and registers its destructor.)
 * Address: 0x00C09D60 (FUN_00C09D60 -- the global's destructor.)
 * Address: 0x00920290 (FUN_00920290 -- `Init`.)
 * Address: 0x0091E530 (FUN_0091E530 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
 */
struct UdataSaveConstruct : gpg::SerSaveConstructHelper<Udata>
{};

/**
 * `gpg::SerConstructHelper<Udata>`, vtable 0x00D46AB0.
 *
 * Address: 0x00BEA890 (FUN_00BEA890 -- constructs the global and registers its destructor.)
 * Address: 0x00C09D90 (FUN_00C09D90 -- the global's destructor.)
 * Address: 0x00920310 (FUN_00920310 -- `Init`.)
 * Address: 0x00920D30 (FUN_00920D30 -- `Construct`, `MemberConstruct` inlined.)
 * Address: 0x0091E440 (FUN_0091E440 -- `Delete`.)
 */
struct UdataConstruct : gpg::SerConstructHelper<Udata>
{};

namespace
{
	// Address: 0x00F8E89C -- process-global `TStringSaveConstruct` singleton.
	TStringSaveConstruct gTStringSaveConstruct;

	// Address: 0x00F8E704 -- process-global `TStringConstruct` singleton.
	TStringConstruct gTStringConstruct;

	// Address: 0x00F8E87C -- process-global `TableSaveConstruct` singleton.
	TableSaveConstruct gTableSaveConstruct;

	// Address: 0x00F8E9AC -- process-global `TableConstruct` singleton.
	TableConstruct gTableConstruct;

	// Address: 0x00F8E88C -- process-global `LClosureSaveConstruct` singleton.
	LClosureSaveConstruct gLClosureSaveConstruct;

	// Address: 0x00F8EB24 -- process-global `LClosureConstruct` singleton.
	LClosureConstruct gLClosureConstruct;

	// Address: 0x00F8E924 -- process-global `UpValSaveConstruct` singleton.
	UpValSaveConstruct gUpValSaveConstruct;

	// Address: 0x00F8E7F4 -- process-global `UpValConstruct` singleton.
	UpValConstruct gUpValConstruct;

	// Address: 0x00F8EA34 -- process-global `UpValSerializer` singleton.
	UpValSerializer gUpValSerializer;

	// Address: 0x00F8EA24 -- process-global `ProtoSaveConstruct` singleton.
	ProtoSaveConstruct gProtoSaveConstruct;

	// Address: 0x00F8E740 -- process-global `ProtoConstruct` singleton.
	ProtoConstruct gProtoConstruct;

	// Address: 0x00F8E6E0 -- process-global `lua_StateSaveConstruct` singleton.
	lua_StateSaveConstruct glua_StateSaveConstruct;

	// Address: 0x00F8E754 -- process-global `lua_StateConstruct` singleton.
	lua_StateConstruct glua_StateConstruct;

	// Address: 0x00F8E86C -- process-global `UdataSaveConstruct` singleton.
	UdataSaveConstruct gUdataSaveConstruct;

	// Address: 0x00F8E718 -- process-global `UdataConstruct` singleton.
	UdataConstruct gUdataConstruct;
} // namespace

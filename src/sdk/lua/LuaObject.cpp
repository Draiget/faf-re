#include "LuaObject.h"

#include <Windows.h>

#include <array>
#include <cerrno>
#include <cctype>
#include <clocale>
#include <cstddef>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <io.h>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>

#include "LuaAssertion.h"
#include "LuaError.h"
#include "LuaTableIterator.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace LuaPlus;

extern "C" void __cdecl _free_crt(void* ptr);
extern "C" int luaG_checkcode(const Proto* f);

/**
 * Legacy CRT `_free_crt` compat thunk. NOT a recovered binary function - this
 * is build-side glue, so it carries no `Address:` block. (It previously
 * claimed 0x004F2730, which is really
 * `?WIN_CopyToClipboard@Moho@@YA_NVStrArgW@gpg@@@Z`, recovered in
 * moho/app/WinApp.cpp.)
 *
 * What it does:
 * Forwards to `std::free`. Provides the legacy `_free_crt` symbol expected by
 * recovered code that allocates via the legacy CRT free path. Defined here
 * because `legacy_stdio_definitions.lib` does not export this thunk on UCRT.
 */
extern "C" void __cdecl _free_crt(void* const ptr)
{
	std::free(ptr);
}

/**
 * Legacy CRT `_iob[]` global array shim.
 *
 * The old MSVCRT exported `_iob` as `FILE _iob[_IOB_ENTRIES]` via
 * `__imp___iob`. UCRT removed the global in favor of `__acrt_iob_func()`,
 * but third-party .lib files compiled against the old CRT (e.g. LuaPlus's
 * `lauxlib.obj`, `lbaselib.obj`, `liolib.obj`) still reference
 * `__imp___iob`. Provide a private backing array so the link resolves; the
 * streams are not functional — callers that actually use them will route
 * through `__iob_func()` above which dispatches to UCRT at runtime.
 */
extern "C" __declspec(selectany) std::FILE _iob[20]{};

/**
 * Legacy CRT errno-mapping thunk.
 *
 * Maps a Win32 error code to a POSIX `errno` value. The old MSVCRT exported
 * `_dosmaperr` (single underscore C, `__dosmaperr` with the linker's extra
 * underscore decoration); UCRT still provides the mapping through internal
 * helpers but not under this exact symbol when /MDd is combined with legacy
 * obj files. No-op here since callers only use it to propagate errors.
 */
extern "C" void __cdecl _dosmaperr(unsigned long) {}

/**
 * Address: 0x00A89E54 (legacy CRT compat thunk)
 *
 * What it does:
 * Returns the base of the legacy `_iob[]` array. On UCRT, dispatches to
 * `__acrt_iob_func(0)` from `ucrtbase.dll` (the modern replacement) and
 * falls back to a static placeholder array if the symbol is unavailable.
 * Provided here because UCRT does not export `__iob_func` directly.
 */
extern "C" std::FILE* __cdecl __iob_func(void)
{
	using AcrtIobFunc = std::FILE* (__cdecl*)(unsigned int);
	static AcrtIobFunc sAcrtIobFunc = []() noexcept -> AcrtIobFunc {
		HMODULE const ucrtModule = ::GetModuleHandleA("ucrtbase.dll");
		if (ucrtModule == nullptr) {
			return nullptr;
		}
		return reinterpret_cast<AcrtIobFunc>(
			reinterpret_cast<void(*)()>(::GetProcAddress(ucrtModule, "__acrt_iob_func"))
		);
	}();

	if (sAcrtIobFunc != nullptr) {
		return sAcrtIobFunc(0u);
	}

	static std::FILE sLegacyIobFallback[20]{};
	return sLegacyIobFallback;
}

// FUN_00923F20 / FUN_00923F40 are recovered once, further down this file, as
// the `extern "C"` pair that `luaHelper_Realloc` / `luaHelper_Free` point at.
// A second copy used to live here with the same two addresses and the wrong
// allocator - `std::realloc` and the CRT's `_free_crt` rather than the
// engine's `realloc_0` / `free_crt`. It was unreferenced, but it is exactly
// the pairing Global.cpp warns about, so it is gone rather than dormant.

class TableSerializer
{
public:
	/**
	 * Address: 0x009233B0 (FUN_009233B0, init_TableSerializer)
	 *
	 * What it does:
	 * Initializes one table serializer helper runtime object by wiring intrusive
	 * helper links and binding table deserialize/serialize callback lanes.
	 */
	static TableSerializer* Initialize(TableSerializer* serializer);

	/**
	 * Address: 0x009233A0 (FUN_009233A0, TableSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one serialized table payload into `Table::MemberDeserialize`
	 * using caller-provided owner reference lane.
	 */
	static void Deserialize(gpg::ReadArchive* archive, Table* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00920A50 (FUN_00920A50, TableSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one table serialization payload into `Table::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, Table* object, int version, gpg::RRef* ownerRef);

	virtual void RegisterSerializeFunctions();

	gpg::SerHelperBase* mHelperNext;
	gpg::SerHelperBase* mHelperPrev;
	gpg::RType::load_func_t mDeserialize;
	gpg::RType::save_func_t mSerialize;
};

static_assert(offsetof(TableSerializer, mHelperNext) == 0x04, "TableSerializer::mHelperNext offset must be 0x04");
static_assert(offsetof(TableSerializer, mHelperPrev) == 0x08, "TableSerializer::mHelperPrev offset must be 0x08");
static_assert(offsetof(TableSerializer, mDeserialize) == 0x0C, "TableSerializer::mDeserialize offset must be 0x0C");
static_assert(offsetof(TableSerializer, mSerialize) == 0x10, "TableSerializer::mSerialize offset must be 0x10");
static_assert(sizeof(TableSerializer) == 0x14, "TableSerializer size must be 0x14");

/**
 * Address: 0x009233B0 (FUN_009233B0, init_TableSerializer)
 *
 * What it does:
 * Initializes one table serializer helper runtime object by wiring intrusive
 * helper links and binding table deserialize/serialize callback lanes.
 */
TableSerializer* TableSerializer::Initialize(TableSerializer* serializer)
{
	if (serializer == nullptr) {
		return nullptr;
	}
	serializer = new (serializer) TableSerializer();

	auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&serializer->mHelperNext);
	serializer->mHelperNext = self;
	serializer->mHelperPrev = self;
	serializer->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&TableSerializer::Deserialize);
	serializer->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&TableSerializer::Serialize);
	return serializer;
}

void TableSerializer::RegisterSerializeFunctions() {}

/**
 * Address: 0x009233A0 (FUN_009233A0, TableSerializer::Deserialize)
 *
 * What it does:
 * Forwards one serialized table payload into `Table::MemberDeserialize`.
 */
void TableSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	Table* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Table::MemberDeserialize(archive, object, version, *ownerRef);
}

/**
 * Address: 0x00920A50 (FUN_00920A50, TableSerializer::Serialize)
 *
 * What it does:
 * Forwards one table serialization payload into `Table::MemberSerialize`.
 */
void TableSerializer::Serialize(
	gpg::WriteArchive* const archive,
	Table* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Table::MemberSerialize(archive, object, version, ownerRef);
}

class LClosureSerializer
{
public:
	/**
	 * Address: 0x00921370 (FUN_00921370, LClosureSerializer::Serialize)
	 * Address: 0x0098FF80 (FUN_0098FF80)
	 *
	 * What it does:
	 * Forwards one closure save lane into `LClosure::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, LClosure* object, int version, const gpg::RRef* ownerRef);

	/**
	 * Address: 0x00923430 (FUN_00923430, LClosureSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one serialized closure payload into `LClosure::MemberDeserialize`
	 * using the provided archive owner reference lane.
	 */
	static void Deserialize(gpg::ReadArchive* archive, LClosure* object, int version, gpg::RRef* ownerRef);
};

class ProtoSerializer
{
public:
	/**
	 * Address: 0x00923530 (FUN_00923530, ProtoSerializer::ProtoSerializer)
	 *
	 * What it does:
	 * Initializes one proto serializer helper node by self-linking intrusive
	 * helper lanes and wiring deserialize/serialize callback slots.
	 */
	ProtoSerializer();

	/**
	 * Address: 0x00923520 (FUN_00923520, ProtoSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one proto load lane into `Proto::MemberDeserialize`.
	 */
	static void Deserialize(gpg::ReadArchive* archive, Proto* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x009213C0 (FUN_009213C0, ProtoSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one proto save lane into `Proto::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, Proto* object, int version, gpg::RRef* ownerRef);

	virtual void RegisterSerializeFunctions();

	gpg::SerHelperBase* mHelperNext;
	gpg::SerHelperBase* mHelperPrev;
	gpg::RType::load_func_t mDeserialize;
	gpg::RType::save_func_t mSerialize;
};

static_assert(offsetof(ProtoSerializer, mHelperNext) == 0x04, "ProtoSerializer::mHelperNext offset must be 0x04");
static_assert(offsetof(ProtoSerializer, mHelperPrev) == 0x08, "ProtoSerializer::mHelperPrev offset must be 0x08");
static_assert(offsetof(ProtoSerializer, mDeserialize) == 0x0C, "ProtoSerializer::mDeserialize offset must be 0x0C");
static_assert(offsetof(ProtoSerializer, mSerialize) == 0x10, "ProtoSerializer::mSerialize offset must be 0x10");
static_assert(sizeof(ProtoSerializer) == 0x14, "ProtoSerializer size must be 0x14");

class lua_StateSerializer
{
public:
	/**
	 * Address: 0x009235D0 (FUN_009235D0, lua_StateSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one Lua thread load lane into `lua_State::MemberDeserialize`.
	 */
	static void Deserialize(gpg::ReadArchive* archive, lua_State* state, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x009213F0 (FUN_009213F0, lua_StateSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one Lua thread save lane into `lua_State::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, lua_State* state, int version, const gpg::RRef* ownerRef);
};

class TObjectSerializer
{
public:
	/**
	 * Address: 0x00921FC0 (FUN_00921FC0, TObjectSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one tagged Lua value save lane into `TObject::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00923250 (FUN_00923250, TObjectSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one tagged Lua value load lane into `TObject::MemberDeserialize`.
	 */
	static void Deserialize(gpg::ReadArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);
};

class UdataSerializer
{
public:
	/**
	 * Address: 0x00923660 (FUN_00923660)
	 *
	 * What it does:
	 * Forwards one userdata load lane into `Udata::MemberDeserialize`.
	 */
	static void Deserialize(gpg::ReadArchive* archive, Udata* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00920D90 (FUN_00920D90)
	 *
	 * What it does:
	 * Forwards one userdata save lane into `Udata::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, Udata* object, int version, gpg::RRef* ownerRef);
};

namespace
{
	struct SerializerHelperRuntimeView
	{
		void* vftable;
		gpg::SerHelperBase* mNext;
		gpg::SerHelperBase* mPrev;
		gpg::RType::load_func_t mDeserialize;
		gpg::RType::save_func_t mSerialize;
	};

	static_assert(sizeof(SerializerHelperRuntimeView) == 0x14, "SerializerHelperRuntimeView size must be 0x14");

	/**
	 * Address: 0x00923260 (FUN_00923260)
	 *
	 * What it does:
	 * Initializes one serializer-helper lane for `TObject` load/save callbacks.
	 */
	SerializerHelperRuntimeView* InitializeTObjectSerializerHelper(
		SerializerHelperRuntimeView* const helper
	) noexcept
	{
		if (helper == nullptr) {
			return nullptr;
		}

		helper->vftable = nullptr;
		gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper->mNext);
		helper->mNext = self;
		helper->mPrev = self;
		helper->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&TObjectSerializer::Deserialize);
		helper->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&TObjectSerializer::Serialize);
		return helper;
	}

	/**
	 * Address: 0x00923440 (FUN_00923440)
	 *
	 * What it does:
	 * Initializes one serializer-helper lane for `LClosure` load/save callbacks.
	 */
	SerializerHelperRuntimeView* InitializeLClosureSerializerHelper(
		SerializerHelperRuntimeView* const helper
	) noexcept
	{
		if (helper == nullptr) {
			return nullptr;
		}

		helper->vftable = nullptr;
		gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper->mNext);
		helper->mNext = self;
		helper->mPrev = self;
		helper->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&LClosureSerializer::Deserialize);
		helper->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&LClosureSerializer::Serialize);
		return helper;
	}

	/**
	 * Address: 0x00923670 (FUN_00923670)
	 *
	 * What it does:
	 * Initializes one serializer-helper lane for userdata load/save callbacks.
	 */
	SerializerHelperRuntimeView* InitializeUdataSerializerHelper(
		SerializerHelperRuntimeView* const helper
	) noexcept
	{
		if (helper == nullptr) {
			return nullptr;
		}

		helper->vftable = nullptr;
		gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper->mNext);
		helper->mNext = self;
		helper->mPrev = self;
		helper->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&UdataSerializer::Deserialize);
		helper->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&UdataSerializer::Serialize);
		return helper;
	}

	/**
	 * Address: 0x00BEA7C0 (register_lua_StateSerializer)
	 *
	 * IDA signature:
	 * void __cdecl register_lua_StateSerializer();
	 *
	 * What it does:
	 * Initializes one serializer-helper lane for Lua thread load/save callbacks.
	 * The binary runs SerHelperBase::SerHelperBase to self-link the ring, binds
	 * both callbacks, stores the vftable and registers the destructor with
	 * atexit; the ring self-link plus callback binding is the observable part.
	 */
	SerializerHelperRuntimeView* InitializeLuaStateSerializerHelper(
		SerializerHelperRuntimeView* const helper
	) noexcept
	{
		if (helper == nullptr) {
			return nullptr;
		}

		helper->vftable = nullptr;
		gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper->mNext);
		helper->mNext = self;
		helper->mPrev = self;
		helper->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&lua_StateSerializer::Deserialize);
		helper->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&lua_StateSerializer::Serialize);
		return helper;
	}

	/**
	 * Address: 0x00BEA160 (register_TObjectSerializer)
	 * Address: 0x00BEA490 (register_LClosureSerializer)
	 * Address: 0x00BEA8D0 (register_UdataSerializer)
	 *
	 * What it does:
	 * Brings the Lua serializer helper lanes into existence. Each helper links
	 * itself into its own intrusive ring and binds its load/save callbacks; the
	 * binary drives all three from its CRT initializer table. Without this the
	 * Initialize* lanes above are never called and no Lua value has a serializer.
	 */
	SerializerHelperRuntimeView gTObjectSerializerHelper{};
	SerializerHelperRuntimeView gLClosureSerializerHelper{};
	SerializerHelperRuntimeView gUdataSerializerHelper{};
	SerializerHelperRuntimeView gLuaStateSerializerHelper{};

	struct LuaSerializerHelperBootstrap
	{
		LuaSerializerHelperBootstrap()
		{
			(void)InitializeTObjectSerializerHelper(&gTObjectSerializerHelper);
			(void)InitializeLClosureSerializerHelper(&gLClosureSerializerHelper);
			(void)InitializeUdataSerializerHelper(&gUdataSerializerHelper);
			(void)InitializeLuaStateSerializerHelper(&gLuaStateSerializerHelper);
		}
	};

	LuaSerializerHelperBootstrap gLuaSerializerHelperBootstrap;
}

/**
 * Address: 0x00921370 (FUN_00921370, LClosureSerializer::Serialize)
 *
 * What it does:
 * Forwards one closure save lane into `LClosure::MemberSerialize`.
 */
void LClosureSerializer::Serialize(
	gpg::WriteArchive* const archive,
	LClosure* const object,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	LClosure::MemberSerialize(archive, object, version, ownerRef);
}

void LClosureSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	LClosure* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	const gpg::RRef nullOwner{};
	LClosure::MemberDeserialize(archive, object, version, ownerRef != nullptr ? *ownerRef : nullOwner);
}

/**
 * Address: 0x00923530 (FUN_00923530, ProtoSerializer::ProtoSerializer)
 *
 * What it does:
 * Initializes one proto serializer helper node by self-linking intrusive
 * helper lanes and wiring deserialize/serialize callback slots.
 */
ProtoSerializer::ProtoSerializer()
{
	auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&mHelperNext);
	mHelperNext = self;
	mHelperPrev = self;
	mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&ProtoSerializer::Deserialize);
	mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&ProtoSerializer::Serialize);
}

void ProtoSerializer::RegisterSerializeFunctions() {}

namespace
{
	/**
	 * Address: 0x00BEA380 (register_TableSerializer)
	 * Address: 0x00BEA6B0 (register_ProtoSerializer)
	 *
	 * What it does:
	 * Brings both serializer helpers into existence. Each self-links into its own
	 * intrusive helper ring and binds its load/save callbacks - TableSerializer
	 * through its Initialize lane, ProtoSerializer through its constructor - so
	 * neither takes effect until something creates one. The binary drives both
	 * from its CRT initializer table.
	 */
	alignas(TableSerializer) unsigned char gTableSerializerStorage[sizeof(TableSerializer)];

	struct LuaValueSerializerBootstrap
	{
		LuaValueSerializerBootstrap()
		{
			(void)TableSerializer::Initialize(
				reinterpret_cast<TableSerializer*>(gTableSerializerStorage));
		}
	};

	LuaValueSerializerBootstrap gLuaValueSerializerBootstrap;
	ProtoSerializer gProtoSerializer;
}

/**
 * Address: 0x00923520 (FUN_00923520, ProtoSerializer::Deserialize)
 *
 * What it does:
 * Forwards one proto load lane into `Proto::MemberDeserialize`.
 */
void ProtoSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	Proto* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Proto::MemberDeserialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x009213C0 (FUN_009213C0, ProtoSerializer::Serialize)
 *
 * What it does:
 * Forwards one proto save lane into `Proto::MemberSerialize`.
 */
void ProtoSerializer::Serialize(
	gpg::WriteArchive* const archive,
	Proto* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Proto::MemberSerialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x009235D0 (FUN_009235D0, lua_StateSerializer::Deserialize)
 *
 * What it does:
 * Forwards one Lua thread load lane into `lua_State::MemberDeserialize`.
 */
void lua_StateSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	lua_State* const state,
	const int version,
	gpg::RRef* const ownerRef
)
{
	lua_State::MemberDeserialize(archive, state, version, ownerRef);
}

/**
 * Address: 0x009213F0 (FUN_009213F0, lua_StateSerializer::Serialize)
 *
 * What it does:
 * Forwards one Lua thread save lane into `lua_State::MemberSerialize`.
 */
void lua_StateSerializer::Serialize(
	gpg::WriteArchive* const archive,
	lua_State* const state,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	lua_State::MemberSerialize(archive, state, version, ownerRef);
}

/**
 * Address: 0x00921FC0 (FUN_00921FC0, TObjectSerializer::Serialize)
 *
 * What it does:
 * Forwards one tagged Lua value save lane into `TObject::MemberSerialize`.
 */
void TObjectSerializer::Serialize(
	gpg::WriteArchive* const archive,
	TObject* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	TObject::MemberSerialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x00923250 (FUN_00923250, TObjectSerializer::Deserialize)
 *
 * What it does:
 * Forwards one tagged Lua value load lane into `TObject::MemberDeserialize`.
 */
void TObjectSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	TObject* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	TObject::MemberDeserialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x00923660 (FUN_00923660)
 *
 * What it does:
 * Forwards one userdata load lane into `Udata::MemberDeserialize`.
 */
void UdataSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	Udata* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	const gpg::RRef nullOwner{};
	Udata::MemberDeserialize(archive, object, version, ownerRef != nullptr ? *ownerRef : nullOwner);
}

/**
 * Address: 0x00920D90 (FUN_00920D90)
 *
 * What it does:
 * Forwards one userdata save lane into `Udata::MemberSerialize`.
 */
void UdataSerializer::Serialize(
	gpg::WriteArchive* const archive,
	Udata* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Udata::MemberSerialize(archive, object, version, ownerRef);
}

namespace
{
	/**
	 * The metatable every fresh userdata starts with.
	 *
	 * `luaS_newudata` (0x00924A10) reads it as `mov edx, [ecx+118h]` off the
	 * `global_State`, and 0x118 is `_defaultmetatypes[LUA_TUSERDATA].value`:
	 * the array sits at G+0xD4 with an 8-byte stride (`lea eax, [ecx+eax*8+0D4h]`
	 * in `luaT_gettmbyobj`, 0x00928450), and `TObject` is `{int tt; Value value;}`
	 * - tt first - so slot 8's value half lands at 0xD4 + 8*8 + 4 = 0x118.
	 */
	[[nodiscard]] inline Table* DefaultUserdataMetatable(global_State* const globalState) noexcept
	{
		return static_cast<Table*>(globalState->_defaultmetatypes[LUA_TUSERDATA].value.p);
	}
	static_assert(
		offsetof(global_State, _defaultmetatypes) + LUA_TUSERDATA * sizeof(LuaPlus::TObject)
			+ offsetof(LuaPlus::TObject, value) == 0x118,
		"default userdata metatable must live at global_State+0x118"
	);
	static_assert(offsetof(global_State, rootudata) == 0x14, "global_State::rootudata must be at +0x14");

	struct LuaFuncStateCodegenRuntimeView
	{
		Proto* functionProto;
		std::uint8_t reserved04To0B[0x08];
		void* lexState;
		std::uint8_t reserved10To23[0x14];
		int freeRegister;
	};

	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, functionProto) == 0x00,
		"LuaFuncStateCodegenRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, lexState) == 0x0C,
		"LuaFuncStateCodegenRuntimeView::lexState offset must be 0x0C"
	);
	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, freeRegister) == 0x24,
		"LuaFuncStateCodegenRuntimeView::freeRegister offset must be 0x24"
	);

	struct LuaFuncStateConstantRuntimeView
	{
		Proto* functionProto;      // +0x00
		Table* constantLookupTable; // +0x04
		std::uint8_t reserved08To0F[0x08];
		lua_State* state;          // +0x10
		std::uint8_t reserved14To27[0x14];
		int constantCount;         // +0x28
	};

	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, functionProto) == 0x00,
		"LuaFuncStateConstantRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, constantLookupTable) == 0x04,
		"LuaFuncStateConstantRuntimeView::constantLookupTable offset must be 0x04"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, state) == 0x10,
		"LuaFuncStateConstantRuntimeView::state offset must be 0x10"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, constantCount) == 0x28,
		"LuaFuncStateConstantRuntimeView::constantCount offset must be 0x28"
	);

	struct LuaExpDescCodegenRuntimeView
	{
		int kind;
		int info;
		int aux;
		int t;
		int f;
	};

	static_assert(offsetof(LuaExpDescCodegenRuntimeView, kind) == 0x00, "LuaExpDescCodegenRuntimeView::kind offset must be 0x00");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, info) == 0x04, "LuaExpDescCodegenRuntimeView::info offset must be 0x04");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, aux) == 0x08, "LuaExpDescCodegenRuntimeView::aux offset must be 0x08");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, t) == 0x0C, "LuaExpDescCodegenRuntimeView::t offset must be 0x0C");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, f) == 0x10, "LuaExpDescCodegenRuntimeView::f offset must be 0x10");

	struct LuaFuncStateUpvalueRuntimeView
	{
		Proto* functionProto;
		std::uint8_t reserved04To0B[0x08];
		void* lexState;
		lua_State* state;
		std::uint8_t reserved14To37[0x24];
		LuaExpDescCodegenRuntimeView upvalues[0x20];
	};

	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, functionProto) == 0x00,
		"LuaFuncStateUpvalueRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, lexState) == 0x0C,
		"LuaFuncStateUpvalueRuntimeView::lexState offset must be 0x0C"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, state) == 0x10,
		"LuaFuncStateUpvalueRuntimeView::state offset must be 0x10"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, upvalues) == 0x38,
		"LuaFuncStateUpvalueRuntimeView::upvalues offset must be 0x38"
	);

#if INTPTR_MAX == INT32_MAX
	// Table's own offsets are asserted at its definition in LuaRuntimeTypes.h,
	// where each one cites the instruction it was read from. They used to be
	// asserted here as 0x0D/0x14/0x18/0x24, which matched the struct as written
	// rather than the binary.
	static_assert(sizeof(Node) == 0x14, "Node size must be 0x14 (x86)");
#endif

	[[nodiscard]] constexpr std::uint32_t LuaHashMask(const Table* const table)
	{
		return (1u << table->lsizenode) - 1u;
	}

	[[nodiscard]] constexpr std::uint32_t LuaHashOddModulus(const Table* const table)
	{
		return LuaHashMask(table) | 1u;
	}

	[[nodiscard]] std::uint32_t LuaFloatBitPattern(const float value)
	{
		std::uint32_t bits = 0u;
		std::memcpy(&bits, &value, sizeof(bits));
		return bits;
	}

	[[nodiscard]] constexpr int LuaInstructionSignedOffset(const Instruction instruction)
	{
		return static_cast<int>((instruction >> 6) & 0x3FFFFu) - 0x1FFFF;
	}

	struct LuaGlobalStateTableAllocRuntimeView
	{
		std::uint8_t reserved00[0x100];
		Table* defaultTableMetatable;
		std::uint8_t reserved104To14F[0x4C];
		std::uint8_t allocationTrackingEnabled;
	};
#if INTPTR_MAX == INT32_MAX
	static_assert(
		offsetof(LuaGlobalStateTableAllocRuntimeView, defaultTableMetatable) == 0x100,
		"LuaGlobalStateTableAllocRuntimeView::defaultTableMetatable offset must be 0x100 (x86)"
	);
	static_assert(
		offsetof(LuaGlobalStateTableAllocRuntimeView, allocationTrackingEnabled) == 0x150,
		"LuaGlobalStateTableAllocRuntimeView::allocationTrackingEnabled offset must be 0x150 (x86)"
	);
#endif

	Table* LuaDebugGetSizesTable(lua_State* const state);
}

struct FuncState;
struct expdesc;

extern "C"
{
	void luaC_collectgarbage(lua_State* L);
	void luaC_link(lua_State* L, GCObject* object, int typeTag);
	int luaC_sweep(lua_State* L, int all);
	void luaF_close(lua_State* L, StkId level);
	Closure* luaF_newCclosure(lua_State* L, int nelems);
	lua_State* luaE_newthread(lua_State* L);
	void luaD_growstack(lua_State* L, int n);
	void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
	void luaS_freeall(lua_State* L);
	void* luaM_growaux(lua_State* L, void* block, int* size, int sizeElem, int limit, const char* what);
	const char* luaO_pushvfstring(lua_State* L, const char* fmt, va_list argp);
	int _errorfb(lua_State* L, int level);
	void luaG_runerror(lua_State* L, const char* format, ...);
	void luaV_concat(lua_State* L, int total, int last);
	int luaV_tostring(lua_State* L, TObject* obj);
	int luaV_equalval(lua_State* L, const TObject* left, const TObject* right);
	int luaV_lessthan(lua_State* L, const TObject* left, const TObject* right);
	Proto* luaF_newproto(lua_State* L);
	void discharge2reg(expdesc* e, int reg, FuncState* fs);
	int luaK_code(FuncState* fs, Instruction i, int line);
	int luaK_codeABC(FuncState* fs, int o, int a, int b, int c);
	void luaK_dischargevars(FuncState* fs, expdesc* e);
	void luaK_nil(FuncState* fs, int from, int n);
	void luaX_checklimit(void* ls, int v, int l, const char* what);
	void luaX_syntaxerror(void* ls, const char* msg);
	TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
	// Lua nil sentinel TObject. The Lua VM core that originally owned this
	// global is not part of the recovered link set, so it is defined here with
	// external linkage (extern + initializer). A default-constructed TObject is
	// the nil value (tt == LUA_TNIL, value.p == nullptr).
	extern const TObject luaO_nilobject{};
	int luaO_rawequalObj(const TObject* t1, const TObject* t2);
	Node* luaH_mainposition(const Table* t, const TObject* key);
	const TObject* luaH_getany(const TObject* key, Table* t);
	const TObject* luaH_get(Table* t, const TObject* key);
	const TObject* luaH_getstr(Table* t, TString* key);
	const TObject* luaH_getnum(Table* t, int key);
	int luaO_log2(unsigned int x);
	const TObject* luaT_gettm(Table* events, int event, TString* ename);
	void luaD_reallocstack(lua_State* L, int newsize);
	TObject* newkey(lua_State* L, Table* t, const TObject* key);
	void luaK_fixjump(int to, int from, FuncState* fs);
	TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
	TObject* luaH_setnum(lua_State* L, Table* t, int key);
	TObject* negindex(lua_State* L, int idx);
	Table* luaH_new(lua_State* L, int narray, int lnhash);
	Table* luaT_getmetatable(lua_State* L, const TObject* o);
	const TObject* luaV_tonumber(const TObject* obj, TObject* outNumber);
	int luaV_lessthan(lua_State* L, const TObject* l, const TObject* r);
	int luaH_next(lua_State* L, Table* table, TObject* key);
	void luaG_errormsg(lua_State* L);

	/**
	 * Address: 0x00D474D8 (luaT_typenames)
	 *
	 * What it does:
	 * Names each type tag for `lua_typename` and the `luaG_*error` messages.
	 * Read straight out of the shipped image: twelve entries, ending where
	 * luaT_eventname begins at 0x00D47508. The fork's split of "cfunction"
	 * from "function" and its trailing proto/upval lanes are why this cannot
	 * be left to resolve into the prebuilt LuaPlus lib, whose stock array is
	 * both shorter and differently ordered.
	 */
	extern const char* luaT_typenames[]{
		"nil",       // LUA_TNIL            0
		"boolean",   // LUA_TBOOLEAN        1
		"userdata",  // LUA_TLIGHTUSERDATA  2
		"number",    // LUA_TNUMBER         3
		"string",    // LUA_TSTRING         4
		"table",     // LUA_TTABLE          5
		"cfunction", // LUA_CFUNCTION       6
		"function",  // LUA_TFUNCTION       7
		"userdata",  // LUA_TUSERDATA       8
		"thread",    // LUA_TTHREAD         9
		"proto",     // LUA_TPROTO         10
		"upval",     // LUA_TUPVALUE       11
	};

	// Sizes of the three interned-name tables the bootstrap walks, each taken
	// from the loop bound in the function that fills it.
	constexpr int kLuaTypeTagCount = 12;      // luaC_init:  0xA4 -> 0xD4 step 4
	constexpr int kLuaTagMethodCount = 18;    // luaT_init:  0x5C -> 0xA4 step 4
	constexpr int kLuaReservedWordCount = 22; // luaX_init:  "cmp ebx, 16h"

	// GC mark bit that pins a string against collection; every interned name
	// laid down during bootstrap gets it ("or byte ptr [eax+5], 10h").
	constexpr lu_byte kLuaFixedStringMark = 0x10;

	// Bucket count the string table opens with ("push 20h" -> luaS_resize).
	constexpr int kLuaInitialStringTableSize = 32;

	/**
	 * `luaC_checkGC` was a macro in the 2007 sources, so the binary emits it
	 * inline at every allocating API entry point rather than as a call. Kept
	 * as one internal-linkage helper here so the gate is written once.
	 */
	static void luaC_checkGC(lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		if (globalState->nblocks >= globalState->GCthreshold && globalState->gcTraversalLockDepth == 0) {
			luaC_collectgarbage(state);
		}
	}

	/**
	 * `api_incr_top`, likewise a macro: publish one freshly written stack slot,
	 * growing the stack first when this frame has run out of room.
	 */
	static void api_incr_top(lua_State* const state)
	{
		if (state->top >= state->ci->top && state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
	}
	/**
	 * Address: 0x009240C0 (FUN_009240C0, lua_stack_init)
	 *
	 * What it does:
	 * Allocates one fresh Lua thread stack and call-info array, initializes the
	 * first call frame, and seeds default stack/base/top lanes for execution.
	 */
	static void lua_stack_init(lua_State* const allocatorState, lua_State* const threadState)
	{
		constexpr int kInitialStackSlots = 45;
		constexpr int kStackGuardTailSlots = 6;
		constexpr int kInitialCallInfoSlots = 8;
		constexpr int kInitialCallFrameTopSpan = 20;

		TObject* const stackBase = static_cast<TObject*>(luaM_realloc(
			allocatorState,
			nullptr,
			0u,
			static_cast<lu_mem>(sizeof(TObject) * kInitialStackSlots)
		));
		threadState->stack = stackBase;
		threadState->top = stackBase;
		threadState->stacksize = kInitialStackSlots;
		threadState->stack_last = stackBase + (kInitialStackSlots - kStackGuardTailSlots);

		CallInfo* const callInfoBase = static_cast<CallInfo*>(luaM_realloc(
			allocatorState,
			nullptr,
			0u,
			static_cast<lu_mem>(sizeof(CallInfo) * kInitialCallInfoSlots)
		));
		threadState->ci = callInfoBase;
		threadState->base_ci = callInfoBase;
		callInfoBase->state = 5;
		callInfoBase->savedpc = nullptr;
		callInfoBase->tailcalls = 0;
		callInfoBase->pc = nullptr;
		callInfoBase->reserved0 = 0;
		callInfoBase->reserved1 = 0;
		callInfoBase->reserved2 = 0;

		threadState->top->tt = LUA_TNIL;
		CallInfo* const ci = threadState->ci;
		ci->base = ++threadState->top;
		threadState->base = ci->base;
		ci->top = threadState->top + kInitialCallFrameTopSpan;
		threadState->size_ci = static_cast<std::uint16_t>(kInitialCallInfoSlots);
		threadState->end_ci = threadState->base_ci + kInitialCallInfoSlots;
	}

	/**
	 * Address: 0x00924210 (FUN_00924210, close_state)
	 *
	 * What it does:
	 * Closes pending Lua upvalues, sweeps/frees GC and scratch-buffer lanes,
	 * releases callinfo+stack arrays, then frees global and thread state using
	 * allocator callbacks captured from `global_State`.
	 */
	static void close_state(lua_State* const state)
	{
		luaF_close(state, state->stack);

		global_State* const globalState = state->l_G;
		lua_State allocatorState{};
		global_State allocatorGlobal{};
		allocatorState.l_G = &allocatorGlobal;
		allocatorGlobal.memData = globalState->memData;
		allocatorGlobal.reallocFunc = globalState->reallocFunc;
		allocatorGlobal.freeFunc = globalState->freeFunc;

		if (globalState != nullptr) {
			(void)luaC_sweep(state, 1);
			luaS_freeall(state);
			globalState->buff.buffer = static_cast<char*>(luaM_realloc(
				state,
				globalState->buff.buffer,
				static_cast<lu_mem>(globalState->buff.buffsize),
				0u
			));
			globalState->buff.buffsize = 0u;
		}

		(void)luaM_realloc(
			state,
			state->base_ci,
			static_cast<lu_mem>(sizeof(CallInfo) * state->size_ci),
			0u
		);
		(void)luaM_realloc(
			state,
			state->stack,
			static_cast<lu_mem>(sizeof(TObject) * state->stacksize),
			0u
		);

		if (globalState != nullptr) {
			(void)luaM_realloc(&allocatorState, globalState, static_cast<lu_mem>(0x160u), 0u);
		}
		(void)luaM_realloc(&allocatorState, state, static_cast<lu_mem>(0x48u), 0u);
	}

	/**
	 * Address: 0x00924080 (FUN_00924080, lua_setusergcfunction)
	 *
	 * What it does:
	 * Stores one engine GC callback pointer in the shared global-state lane.
	 */
	void lua_setusergcfunction(lua_State* const state, void(__cdecl* userGCFunction)(void*))
	{
		state->l_G->userGCFunction = reinterpret_cast<void(__cdecl*)(GCState*)>(userGCFunction);
	}

	/**
	 * Address: 0x009240B0 (FUN_009240B0, lua_setstateuserdata)
	 *
	 * What it does:
	 * Stores one LuaPlus wrapper pointer in `lua_State::stateUserData`.
	 */
	void lua_setstateuserdata(lua_State* const state, void* const stateUserData)
	{
		state->stateUserData = static_cast<LuaState*>(stateUserData);
	}

	/**
	 * Address: 0x00924060 (FUN_00924060, lua_setglobaluserdata)
	 *
	 * What it does:
	 * Stores engine global userdata pointer into `global_State::globalUserData`.
	 */
	void lua_setglobaluserdata(lua_State* const state, void* const globalUserData)
	{
		state->l_G->globalUserData = static_cast<moho::Sim*>(globalUserData);
	}

	/**
	 * Address: 0x00924050 (FUN_00924050, lua_getglobaluserdata)
	 *
	 * IDA signature:
	 * Moho::Sim *__usercall lua_getglobaluserdata@<eax>(lua_State *L);
	 *
	 * What it does:
	 * Reads back what lua_setglobaluserdata stored - the Sim every sim-side
	 * Lua binding starts from.
	 *
	 * The setter above was recovered but this half never was, so it resolved
	 * to the prebuilt LuaPlus library's copy, which reads the field at stock
	 * global_State's offset rather than this fork's +0x148. Every binding that
	 * asked for the Sim got a null back, and the first one to do so - the
	 * initial-unit spawn - reported the ACU blueprint as unknown.
	 */
// LuaPrimitives.h macros the name onto the typed inline wrapper for call
// sites; the definition itself has to be spelled without it.
#undef lua_getglobaluserdata
	void* lua_getglobaluserdata(lua_State* const state)
	{
		return state->l_G->globalUserData;
	}
#define lua_getglobaluserdata lua_getglobaluserdata_typed

	/**
	 * Address: 0x009240A0 (FUN_009240A0, lua_getstateuserdata)
	 *
	 * What it does:
	 * Returns LuaPlus state wrapper pointer stored in `lua_State::stateUserData`.
	 */
	void* lua_getstateuserdata(lua_State* const state)
	{
		return state->stateUserData;
	}

	/**
	 * Address: 0x0090C530 (FUN_0090C530, lua_newthread)
	 *
	 * What it does:
	 * Runs the Lua GC-threshold gate, creates one new coroutine state, pushes
	 * that thread object to stack top, and preserves Lua stack growth guard.
	 */
	lua_State* lua_newthread(lua_State* const state)
	{
		luaC_checkGC(state);

		lua_State* const newThread = luaE_newthread(state);
		auto* const threadObject = reinterpret_cast<GCObject*>(newThread);
		TObject* const top = state->top;
		top->tt = static_cast<int>(threadObject->gch.tt);
		top->value.p = threadObject;

		if (top >= state->ci->top && state->stack_last - top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return newThread;
	}

	/**
	 * Address: 0x0090C900 (FUN_0090C900, lua_equal)
	 *
	 * What it does:
	 * Resolves two Lua API stack indices, validates same-type operands, then
	 * performs one Lua semantic equality test via `luaV_equalval`.
	 */
	int lua_equal(lua_State* const state, const int leftIndex, const int rightIndex)
	{
		TObject* leftObject = nullptr;
		if (leftIndex > 0) {
			TObject* const candidate = state->base + leftIndex - 1;
			if (candidate < state->top) {
				leftObject = candidate;
			}
		} else {
			leftObject = negindex(state, leftIndex);
		}

		TObject* rightObject = nullptr;
		if (rightIndex > 0) {
			TObject* const candidate = state->base + rightIndex - 1;
			if (candidate < state->top) {
				rightObject = candidate;
			}
		} else {
			rightObject = negindex(state, rightIndex);
		}

		return leftObject != nullptr
			&& rightObject != nullptr
			&& leftObject->tt == rightObject->tt
			&& luaV_equalval(state, leftObject, rightObject) != 0;
	}

	/**
	 * Address: 0x0090C3D0 (FUN_0090C3D0, luaA_index)
	 *
	 * What it does:
	 * Resolves one Lua stack index to its `TObject*` slot. Positive indices are
	 * relative to the current call's base; non-positive indices route through
	 * `negindex` (registry, globals, upvalues, or negative stack offsets).
	 */
	TObject* luaA_index(lua_State* const state, const int stackIndex)
	{
		if (stackIndex > 0) {
			return &state->base[stackIndex - 1];
		}
		return negindex(state, stackIndex);
	}

	/**
	 * What it does:
	 * Resolves one stack index the way every read-only lua_* accessor does:
	 * like `luaA_index`, except a positive index past the top yields nothing
	 * instead of a slot nobody pushed. The binary open-codes this three-line
	 * test at the head of each accessor rather than calling a helper.
	 */
	[[nodiscard]] TObject* luaA_indexAcceptable(lua_State* const state, const int stackIndex)
	{
		if (stackIndex <= 0) {
			return negindex(state, stackIndex);
		}

		TObject* const candidate = &state->base[stackIndex - 1];
		return candidate < state->top ? candidate : nullptr;
	}

	/**
	 * Address: 0x0090C340 (FUN_0090C340, negindex)
	 *
	 * IDA signature:
	 * TObject *__usercall negindex@<eax>(lua_State *L, int idx);
	 *
	 * What it does:
	 * Resolves a non-positive stack index to its slot. Ordinary negative
	 * indices count back from the top; below those sit the pseudo-indices -
	 * this fork adds a registry-by-integer range beneath the usual
	 * globals/registry pair, and anything lower still is an upvalue of the
	 * running C closure (null when the closure has no such upvalue).
	 *
	 * The thresholds are the literals in the disassembly, not the decompiler's
	 * symbol substitution:
	 *   0x0090C344  cmp edx, 0FFFFD8F0h   -10000  LUA_REGISTRYINDEX
	 *   0x0090C357  cmp edx, 0FFFF63C0h   -40000  kRegistryIntegerIndexBase
	 *   0x0090C37D  cmp edx, 0FFFFD8EFh   -10001  LUA_GLOBALSINDEX
	 */
	TObject* negindex(lua_State* const L, const int idx)
	{
		// Registry slots addressed by integer, a LuaPlus extension below the
		// stock pseudo-index pair.
		constexpr int kRegistryIntegerIndexBase = -40000;

		if (idx > LUA_REGISTRYINDEX) {
			return &L->top[idx];
		}

		if (idx < kRegistryIntegerIndexBase) {
			auto* const registry = static_cast<Table*>(L->l_G->_registry.value.p);
			return const_cast<TObject*>(luaH_getnum(registry, kRegistryIntegerIndexBase - idx));
		}

		if (idx == LUA_GLOBALSINDEX) {
			return &L->_gt;
		}

		if (idx == LUA_REGISTRYINDEX) {
			return &L->l_G->_registry;
		}

		// Upvalue of the running C closure, counted down from the globals
		// pseudo-index. `upvalue_m1` is the one-before-first lane the binary
		// indexes, so the subscript is used directly.
		GCObject* const closure = static_cast<GCObject*>(L->base[-1].value.p);
		const int upvalueIndex = LUA_GLOBALSINDEX - idx;
		if (upvalueIndex > closure->cl.c.nupvalues) {
			return nullptr;
		}

		return &closure->cl.c.upvalue_m1[upvalueIndex];
	}

	/**
	 * Address: 0x0090C420 (FUN_0090C420, luaA_pushobject)
	 *
	 * What it does:
	 * Copies one `TObject` lane to stack top, grows stack when the guard lane
	 * reaches one slot, then advances top.
	 */
	void luaA_pushobject(lua_State* const state, const TObject* const object)
	{
		*state->top = *object;
		if ((state->stack_last - state->top) <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
	}

	/**
	 * Address: 0x0090C740 (FUN_0090C740, lua_type)
	 *
	 * IDA signature:
	 * int __cdecl lua_type(lua_State *L, int idx);
	 *
	 * What it does:
	 * Returns the type tag at `idx`, or LUA_TNONE for an index that addresses
	 * nothing: past the live top for a positive index, or a pseudo-index with
	 * no slot (an upvalue the running closure does not have).
	 */
	int lua_type(lua_State* const state, const int idx)
	{
		const TObject* slot = nullptr;
		if (idx > 0) {
			slot = &state->base[idx - 1];
			if (slot >= state->top) {
				return LUA_TNONE;
			}
		} else {
			slot = negindex(state, idx);
			if (slot == nullptr) {
				return LUA_TNONE;
			}
		}

		return slot->tt;
	}

	/**
	 * Address: 0x0090C780 (FUN_0090C780, lua_typename)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_typename(lua_State *L, int t);
	 *
	 * What it does:
	 * Names one type tag. The state argument is unused - the table is global.
	 */
	const char* lua_typename([[maybe_unused]] lua_State* const state, const int t)
	{
		if (t == LUA_TNONE) {
			return "no value";
		}

		return luaT_typenames[t];
	}

	/**
	 * Address: 0x0090C6E0 (FUN_0090C6E0, lua_pushvalue)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushvalue(lua_State *L, int idx);
	 *
	 * What it does:
	 * Copies the value at `idx` onto the top of the stack.
	 */
	void lua_pushvalue(lua_State* const state, const int idx)
	{
		*state->top = *luaA_index(state, idx);
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090C5F0 (FUN_0090C5F0, lua_remove)
	 *
	 * IDA signature:
	 * void __cdecl lua_remove(lua_State *L, int idx);
	 *
	 * What it does:
	 * Deletes the value at `idx`, shifting everything above it down one slot.
	 */
	void lua_remove(lua_State* const state, const int idx)
	{
		TObject* slot = luaA_index(state, idx);
		for (++slot; slot < state->top; ++slot) {
			slot[-1] = *slot;
		}

		--state->top;
	}

	/**
	 * Address: 0x0090C640 (FUN_0090C640, lua_insert)
	 *
	 * IDA signature:
	 * void __cdecl lua_insert(lua_State *L, int idx);
	 *
	 * What it does:
	 * Moves the top value down to `idx`, shifting everything from `idx` up one
	 * slot to make room. The stack height is unchanged.
	 */
	void lua_insert(lua_State* const state, const int idx)
	{
		TObject* const destination = luaA_index(state, idx);
		for (TObject* slot = state->top; slot > destination; --slot) {
			*slot = slot[-1];
		}

		*destination = *state->top;
	}

	/**
	 * Address: 0x0090C690 (FUN_0090C690, lua_replace)
	 *
	 * IDA signature:
	 * void __cdecl lua_replace(lua_State *L, int idx);
	 *
	 * What it does:
	 * Pops the top value and stores it into `idx`.
	 */
	void lua_replace(lua_State* const state, const int idx)
	{
		const TObject* const source = state->top - 1;
		*luaA_index(state, idx) = *source;
		--state->top;
	}

	/**
	 * Address: 0x0090CD80 (FUN_0090CD80, lua_pushlstring)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushlstring(lua_State *L, const char *s, size_t len);
	 *
	 * What it does:
	 * Interns `len` bytes as a Lua string and pushes it, running the GC gate
	 * first because the intern may allocate.
	 */
	void lua_pushlstring(lua_State* const state, const char* const s, const size_t len)
	{
		luaC_checkGC(state);

		TString* const interned = luaS_newlstr(state, s, len);
		TObject* const top = state->top;
		top->tt = static_cast<int>(interned->tt);
		top->value.p = interned;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D110 (FUN_0090D110, lua_newtable)
	 *
	 * IDA signature:
	 * void __cdecl lua_newtable(lua_State *L);
	 *
	 * What it does:
	 * Creates one empty table and pushes it, running the GC gate first because
	 * the table allocates.
	 */
	void lua_newtable(lua_State* const state)
	{
		luaC_checkGC(state);

		Table* const table = luaH_new(state, 0, 0);
		TObject* const top = state->top;
		top->tt = static_cast<int>(table->tt);
		top->value.p = table;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090C590 (FUN_0090C590, lua_gettop)
	 * Mangled: ?lua_gettop@@YAHPAUlua_State@@@Z
	 *
	 * IDA signature:
	 * int __cdecl lua_gettop(lua_State *L);
	 *
	 * What it does:
	 * Returns the number of values on the current frame's stack.
	 */
	int lua_gettop(lua_State* const state)
	{
		return static_cast<int>(state->top - state->base);
	}

	/**
	 * Address: 0x0090C5A0 (FUN_0090C5A0, lua_settop)
	 * Mangled: ?lua_settop@@YAXPAUlua_State@@H@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_settop(lua_State *L, int idx);
	 *
	 * What it does:
	 * Sets the stack height. A non-negative `idx` is an absolute height, and
	 * any slots opened up by growing are niled - only the tag is written, the
	 * value half is left as it was. A negative `idx` is relative to the
	 * current top, so -1 leaves the stack unchanged.
	 */
	void lua_settop(lua_State* const state, const int idx)
	{
		if (idx >= 0) {
			TObject* const target = state->base + idx;
			for (; state->top < target; ++state->top) {
				state->top->tt = LUA_TNIL;
			}

			state->top = target;
		} else {
			state->top += idx + 1;
		}
	}

	/**
	 * Address: 0x0090CD00 (FUN_0090CD00, lua_pushnil)
	 * Mangled: ?lua_pushnil@@YAXPAUlua_State@@@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushnil(lua_State *L);
	 *
	 * What it does:
	 * Pushes nil. Only the tag is written - the value half keeps whatever the
	 * slot held before.
	 */
	void lua_pushnil(lua_State* const state)
	{
		state->top->tt = LUA_TNIL;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CD40 (FUN_0090CD40, lua_pushnumber)
	 * Mangled: ?lua_pushnumber@@YAXPAUlua_State@@M@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushnumber(lua_State *L, float n);
	 *
	 * What it does:
	 * Pushes a number. The binary takes a 4-byte float ("movss xmm0,[esp+n]")
	 * because this fork's Value::n is float - that is what makes TObject 8
	 * bytes instead of 12. The parameter stays lua_Number here because
	 * src/sdk/main.vcxproj never defines LUA_NUMBER, so every existing caller
	 * passes a double; the narrowing on store is what the binary's callers do
	 * at their own call sites. Defining LUA_NUMBER=float project-wide would
	 * remove the conversion, and is worth doing separately.
	 */
	void lua_pushnumber(lua_State* const state, const lua_Number n)
	{
		TObject* const top = state->top;
		top->value.n = static_cast<float>(n);
		top->tt = LUA_TNUMBER;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CF80 (FUN_0090CF80, lua_pushboolean)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushboolean(lua_State *L, int b);
	 *
	 * What it does:
	 * Pushes a boolean, normalising any non-zero input to 1.
	 */
	void lua_pushboolean(lua_State* const state, const int b)
	{
		TObject* const top = state->top;
		top->tt = LUA_TBOOLEAN;
		top->value.b = (b != 0) ? 1 : 0;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CFC0 (FUN_0090CFC0, lua_pushlightuserdata)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushlightuserdata(lua_State *L, void *p);
	 *
	 * What it does:
	 * Pushes a raw pointer the collector does not own.
	 */
	void lua_pushlightuserdata(lua_State* const state, void* const p)
	{
		TObject* const top = state->top;
		top->tt = LUA_TLIGHTUSERDATA;
		top->value.p = p;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CDF0 (FUN_0090CDF0, lua_pushstring)
	 * Mangled: ?lua_pushstring@@YAXPAUlua_State@@PBD@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushstring(lua_State *L, const char *s);
	 *
	 * What it does:
	 * Pushes a NUL-terminated string, or nil when `s` is null.
	 */
	void lua_pushstring(lua_State* const state, const char* const s)
	{
		if (s == nullptr) {
			state->top->tt = LUA_TNIL;
			api_incr_top(state);
			return;
		}

		lua_pushlstring(state, s, std::strlen(s));
	}

	/**
	 * Address: 0x0090CED0 (FUN_0090CED0, lua_pushcclosure)
	 *
	 * What it does:
	 * Allocates one C closure with `n` upvalues from stack top, runs the
	 * GC-threshold check lane, then pushes closure object back onto the stack.
	 */
	void lua_pushcclosure(lua_State* const state, lua_CFunction fn, int n)
	{
		luaC_checkGC(state);

		Closure* const closure = luaF_newCclosure(state, n);
		closure->c.f = fn;
		state->top -= n;

		for (int upvalueIndex = n - 1; upvalueIndex >= 0; --upvalueIndex) {
			closure->c.upvalue[upvalueIndex] = state->top[upvalueIndex];
		}

		TObject* const top = state->top;
		top->tt = static_cast<int>(closure->c.tt);
		top->value.p = closure;

		if (top >= state->ci->top && state->stack_last - top <= 1) {
			luaD_growstack(state, 1);
		}

		state->top += 1;
	}

	/**
	 * Address: 0x0090AD00 (FUN_0090AD00, lua_setdefaultmetatable)
	 *
	 * IDA signature:
	 * void __cdecl lua_setdefaultmetatable(lua_State *L, int type);
	 *
	 * What it does:
	 * Pops one value from stack top and, when that value is a table, writes it
	 * into the default-metatable slot for `type`.
	 */
	void lua_setdefaultmetatable(lua_State* const state, const int type)
	{
		TObject* const topValue = state->top - 1;
		if (topValue->tt == LUA_TTABLE) {
			state->l_G->_defaultmetatypes[type] = *topValue;
		}
		--state->top;
	}

	/**
	 * Address: 0x0090D650 (FUN_0090D650, lua_getgcthreshold)
	 *
	 * What it does:
	 * Returns the current GC threshold in KiB units.
	 */
	int lua_getgcthreshold(lua_State* const state)
	{
		return static_cast<int>(static_cast<std::uint32_t>(state->l_G->GCthreshold) >> 10);
	}

	/**
	 * Address: 0x0090D660 (FUN_0090D660, lua_getgccount)
	 *
	 * What it does:
	 * Returns the current allocated-block count in KiB units.
	 */
	int lua_getgccount(lua_State* const state)
	{
		return static_cast<int>(static_cast<std::uint32_t>(state->l_G->nblocks) >> 10);
	}

	/**
	 * Address: 0x0090D670 (FUN_0090D670, lua_setgcthreshold)
	 *
	 * What it does:
	 * Sets the GC threshold in KiB units (saturating to max on overflow) and
	 * runs one GC cycle when allocated bytes already cross the new limit.
	 */
	void lua_setgcthreshold(lua_State* const state, const int newThreshold)
	{
		global_State* const globalState = state->l_G;
		if (static_cast<std::uint32_t>(newThreshold) <= 0x3FFFFFu) {
			globalState->GCthreshold = static_cast<std::uint32_t>(newThreshold) << 10;
		} else {
			globalState->GCthreshold = 0xFFFFFFFFu;
		}

		luaC_checkGC(state);
	}

	/**
	 * Address: 0x0090D740 (FUN_0090D740, lua_concat)
	 *
	 * What it does:
	 * Concatenates `n` values at stack top through VM concat, pushes empty
	 * string when `n == 0`, and preserves Lua stack-growth guard behavior.
	 */
	void lua_concat(lua_State* const state, const int n)
	{
		luaC_checkGC(state);

		if (n >= 2) {
			const int last = static_cast<int>(state->top - state->base) - 1;
			luaV_concat(state, n, last);
			state->top += 1 - n;
			return;
		}

		if (n == 0) {
			TObject* const top = state->top;
			TString* const emptyString = luaS_newlstr(state, nullptr, 0u);
			top->tt = static_cast<int>(emptyString->tt);
			top->value.p = emptyString;

			if (top >= state->ci->top && state->stack_last - top <= 1) {
				luaD_growstack(state, 1);
			}

			state->top += 1;
		}
	}

	/**
	 * Address: 0x0090D8E0 (FUN_0090D8E0, lua_pushupvalues)
	 *
	 * What it does:
	 * Pushes all upvalue lanes from the current closure (`base[-1]`) onto the
	 * Lua stack, preserving the original growth guard (`nup + 20` slots).
	 */
	extern "C" int lua_pushupvalues(lua_State* const state)
	{
		const auto* const closure = static_cast<const Closure*>(state->base[-1].value.p);
		const int upvalueCount = static_cast<int>(closure->c.nupvalues);
		const int requiredStackSlots = upvalueCount + 20;

		if ((state->stack_last - state->top) <= requiredStackSlots) {
			luaD_growstack(state, requiredStackSlots);
		}

		const TObject* sourceUpvalue = &closure->c.upvalue[0];
		for (int upvalueIndex = 0; upvalueIndex < upvalueCount; ++upvalueIndex, ++sourceUpvalue) {
			TObject* const stackTop = state->top;
			*stackTop = *sourceUpvalue;
			state->top = stackTop + 1;
		}

		return upvalueCount;
	}

	/**
	 * Address: 0x0090D940 (FUN_0090D940, aux_upvalue)
	 *
	 * What it does:
	 * Resolves one upvalue pointer/name pair for either C closures
	 * (`upvalue_m1[n]`) or Lua closures (`upvals[n-1]` + `proto->upvalues[n-1]`)
	 * and returns null on type/index mismatch.
	 */
	const char* aux_upvalue(
		lua_State* const state,
		const int functionIndex,
		TObject** const outValueSlot,
		const int upvalueIndex
	)
	{
		TObject* functionObject = nullptr;
		if (functionIndex <= 0) {
			functionObject = negindex(state, functionIndex);
		} else {
			functionObject = &state->base[functionIndex - 1];
		}

		if (functionObject->tt == LUA_CFUNCTION) {
			auto* const cClosure = static_cast<CClosure*>(functionObject->value.p);
			if (upvalueIndex <= static_cast<int>(cClosure->nupvalues)) {
				*outValueSlot = &cClosure->upvalue_m1[upvalueIndex];
				return "";
			}
			return nullptr;
		}

		if (functionObject->tt == LUA_TFUNCTION) {
			auto* const lClosure = static_cast<LClosure*>(functionObject->value.p);
			Proto* const prototype = lClosure->p;
			if (upvalueIndex <= prototype->sizeupvalues) {
				*outValueSlot = lClosure->upvals[upvalueIndex - 1]->v;
				return prototype->upvalues[upvalueIndex - 1]->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x0090E330 (FUN_0090E330, luaL_pushresult)
	 *
	 * What it does:
	 * Flushes pending buffer bytes as one Lua string lane, then concatenates
	 * all buffered segments and resets buffer nesting level to one.
	 */
	void luaL_pushresult(luaL_Buffer* const buffer)
	{
		const auto bufferedLength = buffer->p - buffer->buffer;
		if (bufferedLength != 0) {
			lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(bufferedLength));
			++buffer->lvl;
			buffer->p = buffer->buffer;
		}

		lua_concat(buffer->L, buffer->lvl);
		buffer->lvl = 1;
	}

	/**
	 * Address: 0x0090CB10 (FUN_0090CB10, lua_strlen)
	 *
	 * What it does:
	 * Resolves one stack lane by positive or negative index, converts it to a
	 * string when needed, and returns the resulting byte length.
	 */
	[[nodiscard]] size_t lua_strlen(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			// `negindex`, not `top + idx` (0x0090CB31 calls it). Anything at or
			// below LUA_REGISTRYINDEX is a pseudo-index - the registry, the globals
			// table, or a C closure upvalue - and top-relative arithmetic sends
			// those far below the stack base, where the guard below answers 0.
			// `string.gfind` measures its subject through `lua_upvalueindex(1)`, so
			// every iterator built by it saw a zero-length subject, matched
			// nothing, and yielded no words at all: `WrapText` returned no lines
			// and every wrapped string in the UI - dialog bodies, tooltips - came
			// out blank.
			object = negindex(state, idx);
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return 0;
			}
		}

		if (object == nullptr) {
			return 0;
		}

		if (object->tt == LUA_TSTRING) {
			return static_cast<TString*>(object->value.p)->len;
		}

		if (luaV_tostring(state, object) == 0) {
			return 0;
		}

		return static_cast<TString*>(object->value.p)->len;
	}

	/**
	 * Address: 0x0090E9E0 (FUN_0090E9E0, tag_error)
	 *
	 * What it does:
	 * Formats one Lua type-mismatch message (`"%s expected, got %s"`) and raises
	 * argument error for the offending stack index.
	 */
	static int tag_error(const int expectedTag, const int argumentIndex, lua_State* const state)
	{
		const char* const expectedName = lua_typename(state, expectedTag);
		const int gotTag = lua_type(state, argumentIndex);
		const char* const gotName = lua_typename(state, gotTag);
		const char* const message = lua_pushfstring(state, "%s expected, got %s", expectedName, gotName);
		return luaL_argerror(state, argumentIndex, message);
	}

	// ---------------------------------------------------------------------
	// Public C API accessors that were still resolving to the prebuilt
	// LuaPlus library.
	//
	// Every one of these reads the lua_State and global_State this tree
	// builds, and the library's copies read them at stock offsets - so each
	// was a live fault waiting for the first script that touched it.
	// lua_getmetatable was the one that fired: tostring(ClientVersion) in
	// init_faf.lua reached luaL_callmeta, and the library's copy compared
	// against a defaultmeta it found at the wrong place and pushed a table
	// that was not one.
	// ---------------------------------------------------------------------

	/**
	 * Address: 0x0090D180 (FUN_0090D180, lua_getmetatable)
	 *
	 * IDA signature:
	 * int __cdecl lua_getmetatable(lua_State *L, int objindex);
	 *
	 * What it does:
	 * Pushes the metatable governing one value and always reports success.
	 * That is a fork change: stock Lua returns 0 and pushes nothing when the
	 * value has no metatable of its own, whereas here every type has one -
	 * tables and userdata carry theirs, everything else shares the per-type
	 * default - so `luaT_getmetatable` always has something to hand back.
	 */
	int lua_getmetatable(lua_State* const state, const int objindex)
	{
		const TObject* const object = luaA_indexAcceptable(state, objindex);
		Table* const metatable = luaT_getmetatable(state, object);

		state->top->tt = static_cast<int>(metatable->tt);
		state->top->value.p = metatable;
		api_incr_top(state);
		return 1;
	}

	/**
	 * What it does:
	 * Returns the raw pointer behind a userdata slot: the payload for a full
	 * userdata, the stored pointer for a light one.
	 *
	 * The shipped binary has no lua_touserdata - every site that wants this
	 * open-codes it, as func_GetRRefFromUserdata does at 0x0090CBB0 - but this
	 * tree calls it from eight places, so it needs a body here. Without one it
	 * resolved to the prebuilt LuaPlus copy, which tests stock's LUA_TUSERDATA
	 * of 7; this fork numbers cfunction 6, function 7, full userdata 8. Every
	 * one of those eight calls was therefore answering null.
	 */
	void* lua_touserdata(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return nullptr;
		}

		switch (object->tt) {
			case LUA_TUSERDATA:
				return reinterpret_cast<std::uint8_t*>(object->value.p) + sizeof(Udata);
			case LUA_TLIGHTUSERDATA:
				return object->value.p;
			default:
				return nullptr;
		}
	}

	/**
	 * Address: 0x0090C9F0 (FUN_0090C9F0, lua_tonumber)
	 *
	 * What it does:
	 * Reads one stack slot as a number, parsing a numeric string on the way
	 * through a scratch slot. Anything else reads as zero.
	 */
	lua_Number lua_tonumber(lua_State* const state, const int idx)
	{
		const TObject* object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return 0.0f;
		}

		TObject scratch{};
		if (object->tt != LUA_TNUMBER) {
			object = luaV_tonumber(object, &scratch);
			if (object == nullptr) {
				return 0.0f;
			}
		}

		return object->value.n;
	}

	/**
	 * Address: 0x0090C7A0 (FUN_0090C7A0, lua_isnumber)
	 *
	 * What it does:
	 * Reports whether one stack slot is a number or a string that parses as
	 * one.
	 */
	int lua_isnumber(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return 0;
		}

		TObject scratch{};
		return (object->tt == LUA_TNUMBER || luaV_tonumber(object, &scratch) != nullptr) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C800 (FUN_0090C800, lua_isstring)
	 *
	 * What it does:
	 * Reports whether one stack slot holds a string. Note this fork does not
	 * accept a number here the way stock Lua does - the tag test is exact.
	 */
	int lua_isstring(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		return (object != nullptr && object->tt == LUA_TSTRING) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C890 (FUN_0090C890, lua_rawequal)
	 *
	 * What it does:
	 * Compares two stack slots by identity, without consulting `__eq`.
	 */
	int lua_rawequal(lua_State* const state, const int index1, const int index2)
	{
		const TObject* const left = luaA_indexAcceptable(state, index1);
		const TObject* const right = luaA_indexAcceptable(state, index2);
		return (left != nullptr && right != nullptr && luaO_rawequalObj(left, right) != 0) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C980 (FUN_0090C980, lua_lessthan)
	 *
	 * What it does:
	 * Orders two stack slots with full `__lt` semantics.
	 */
	int lua_lessthan(lua_State* const state, const int index1, const int index2)
	{
		const TObject* const left = luaA_indexAcceptable(state, index1);
		const TObject* const right = luaA_indexAcceptable(state, index2);
		if (left == nullptr || right == nullptr) {
			return 0;
		}

		return luaV_lessthan(state, left, right);
	}

	/**
	 * Address: 0x0090CC90 (FUN_0090CC90, lua_topointer)
	 *
	 * What it does:
	 * Returns an identity pointer for the collectable value at one index -
	 * the payload itself for userdata, the object for everything else, and
	 * nothing for values that are not collectable.
	 */
	const void* lua_topointer(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return nullptr;
		}

		switch (object->tt) {
			case LUA_TLIGHTUSERDATA:
			case LUA_TTABLE:
			case LUA_CFUNCTION:
			case LUA_TFUNCTION:
			case LUA_TTHREAD:
				return object->value.p;
			case LUA_TUSERDATA:
				// Full userdata identifies by its payload, which starts one
				// header past the object - `add eax, 10h`.
				return reinterpret_cast<const std::uint8_t*>(object->value.p) + sizeof(Udata);
			default:
				return nullptr;
		}
	}

	/**
	 * Address: 0x0090CC50 (FUN_0090CC50, lua_tothread)
	 *
	 * What it does:
	 * Returns the coroutine at one index, or nothing when the slot holds
	 * something else.
	 */
	lua_State* lua_tothread(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr || object->tt != LUA_TTHREAD) {
			return nullptr;
		}

		return static_cast<lua_State*>(object->value.p);
	}

	/**
	 * Address: 0x0090C4C0 (FUN_0090C4C0, lua_xmove)
	 *
	 * What it does:
	 * Moves `n` values off one thread's stack and onto another's, in order.
	 * Both threads share a global_State, so the values are copied as they are.
	 *
	 * `add [ebx+8], eax` with eax = -n*8 is the source pop; the loop then reads
	 * `[ecx+edi*8]` and its +4 half, which is one 8-byte TObject per step.
	 */
	void lua_xmove(lua_State* const from, lua_State* const to, const int n)
	{
		from->top -= n;
		for (int index = 0; index < n; ++index) {
			*to->top = from->top[index];
			api_incr_top(to);
		}
	}

	/**
	 * Address: 0x0090C460 (FUN_0090C460, lua_checkstack)
	 *
	 * What it does:
	 * Makes room for `size` more slots, growing the stack and widening the
	 * current frame's ceiling if that is what it takes. Reports failure only
	 * when the request would push the frame past the API stack limit.
	 */
	int lua_checkstack(lua_State* const state, const int size)
	{
		constexpr int kMaxApiStackSlots = 0x800; // "cmp edx, 800h" at 0x0090C476

		if (size + (state->top - state->base) > kMaxApiStackSlots) {
			return 0;
		}

		if (state->stack_last - state->top <= size) {
			luaD_growstack(state, size);
		}

		StkId const requiredTop = state->top + size;
		if (state->ci->top < requiredTop) {
			state->ci->top = requiredTop;
		}

		return 1;
	}

	/**
	 * Address: 0x0090EA70 (FUN_0090EA70, luaL_checkany)
	 *
	 * What it does:
	 * Requires that an argument slot exists at all. The decompile shows it
	 * returning lua_type's result, but that is just the value left in EAX by
	 * the tail call - the declared shape is void, as in stock Lua.
	 */
	void luaL_checkany(lua_State* const state, const int narg)
	{
		if (lua_type(state, narg) == LUA_TNONE) {
			(void)luaL_argerror(state, narg, "value expected");
		}
	}

	/**
	 * Address: 0x0090EA20 (FUN_0090EA20, luaL_checktype)
	 *
	 * What it does:
	 * Requires that an argument slot holds exactly type `t`.
	 */
	void luaL_checktype(lua_State* const state, const int narg, const int t)
	{
		if (lua_type(state, narg) != t) {
			(void)tag_error(t, narg, state);
		}
	}

	/**
	 * Address: 0x0090EAA0 (FUN_0090EAA0, luaL_checklstring)
	 *
	 * What it does:
	 * Requires that an argument slot reads as a string, optionally reporting
	 * its length.
	 */
	const char* luaL_checklstring(lua_State* const state, const int narg, size_t* const len)
	{
		const char* const text = lua_tostring(state, narg);
		if (text == nullptr) {
			(void)tag_error(LUA_TSTRING, narg, state);
		}

		if (len != nullptr) {
			*len = lua_strlen(state, narg);
		}

		return text;
	}

	/**
	 * Address: 0x0090EB10 (FUN_0090EB10, luaL_optlstring)
	 *
	 * What it does:
	 * Same as `luaL_checklstring`, except an absent or nil argument yields
	 * the caller's default.
	 */
	const char* luaL_optlstring(
		lua_State* const state,
		const int narg,
		const char* const def,
		size_t* const len
	)
	{
		if (lua_type(state, narg) > LUA_TNIL) {
			return luaL_checklstring(state, narg, len);
		}

		if (len != nullptr) {
			*len = (def != nullptr) ? std::strlen(def) : 0u;
		}

		return def;
	}

	/**
	 * Address: 0x0090EB70 (FUN_0090EB70, luaL_checknumber)
	 *
	 * What it does:
	 * Requires that an argument slot reads as a number. Zero is ambiguous -
	 * lua_tonumber returns it both for the number zero and for anything
	 * unconvertible - so that one case is re-tested with lua_isnumber.
	 */
	lua_Number luaL_checknumber(lua_State* const state, const int narg)
	{
		const lua_Number value = lua_tonumber(state, narg);
		if (value == 0.0f && lua_isnumber(state, narg) == 0) {
			(void)tag_error(LUA_TNUMBER, narg, state);
		}

		return value;
	}

	/**
	 * Address: 0x0090D6D0 (FUN_0090D6D0, lua_next)
	 *
	 * What it does:
	 * Advances one table traversal: takes the key on top, replaces it with the
	 * next key and pushes that key's value. On reaching the end it pops the key
	 * and reports 0.
	 *
	 * Note the index resolution here is `luaA_index`, not the acceptable-index
	 * form the read-only accessors use - a positive index past the top is not
	 * defended against, because a caller that has no table there is already
	 * wrong.
	 */
	int lua_next(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		const int hasMore = luaH_next(state, static_cast<Table*>(table->value.p), state->top - 1);

		if (hasMore == 0) {
			--state->top; // traversal finished: drop the key
			return 0;
		}

		api_incr_top(state); // key was replaced in place; publish its value
		return hasMore;
	}

	/**
	 * Address: 0x0090D0A0 (FUN_0090D0A0, lua_rawgeti)
	 *
	 * What it does:
	 * Pushes `t[n]` for an integer key without consulting `__index`.
	 */
	void lua_rawgeti(lua_State* const state, const int idx, const int n)
	{
		const TObject* const table = luaA_index(state, idx);
		*state->top = *luaH_getnum(static_cast<Table*>(table->value.p), n);
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D6C0 (FUN_0090D6C0, lua_error)
	 *
	 * What it does:
	 * Raises the value on top of the stack as an error. The binary's body is a
	 * bare tail call to luaG_errormsg with no return value, because this fork
	 * throws rather than longjmps and control never comes back; the int here is
	 * only what the API declaration asks for.
	 */
	int lua_error(lua_State* const state)
	{
		luaG_errormsg(state);
		return 0; // unreachable
	}

	/**
	 * Address: 0x0090D1F0 (FUN_0090D1F0, lua_getfenv)
	 *
	 * What it does:
	 * Pushes the environment of the function at `idx`; anything that is not a
	 * Lua closure answers with the running thread's globals.
	 */
	void lua_getfenv(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_index(state, idx);
		const TObject* const environment = (object->tt == LUA_TFUNCTION)
			? &static_cast<GCObject*>(object->value.p)->cl.l.g
			: &state->_gt;

		*state->top = *environment;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D3B0 (FUN_0090D3B0, lua_setfenv)
	 *
	 * What it does:
	 * Pops a value and installs it as the environment of the Lua closure at
	 * `idx`. The value is consumed either way; only the assignment is
	 * conditional.
	 */
	int lua_setfenv(lua_State* const state, const int idx)
	{
		TObject* const object = luaA_index(state, idx);
		--state->top;

		if (object->tt != LUA_TFUNCTION) {
			return 0;
		}

		static_cast<GCObject*>(object->value.p)->cl.l.g = *state->top;
		return 1;
	}

	/**
	 * Address: 0x0090AD30 (FUN_0090AD30, lua_getn)
	 *
	 * What it does:
	 * Answers a table's length the way this fork defines it: an `n` field wins
	 * outright; otherwise it is the larger of the array part's last non-nil
	 * index and the largest numeric key in the hash part.
	 */
	int lua_getn(lua_State* const state, const int index)
	{
		const TObject* const object = luaA_index(state, index);
		Table* const table = static_cast<Table*>(object->value.p);

		TString* const nField = luaS_newlstr(state, "n", 1u);
		const TObject* const recorded = luaH_getstr(table, nField);
		if (recorded->tt == LUA_TNUMBER) {
			return static_cast<int>(recorded->value.n);
		}

		// Walk the array part back to its last non-nil slot. An empty or
		// all-nil array leaves the index at -1, so the count comes out zero.
		int lastArrayIndex = table->sizearray - 1;
		for (; lastArrayIndex >= 0; --lastArrayIndex) {
			if (table->array[lastArrayIndex].tt != LUA_TNIL) {
				break;
			}
		}

		auto largest = static_cast<float>(lastArrayIndex + 1);

		const Node* node = table->node;
		for (int remaining = 1 << table->lsizenode; remaining != 0; --remaining, ++node) {
			if (node->i_key.tt == LUA_TNUMBER && node->i_val.tt != LUA_TNIL && node->i_key.value.n > largest) {
				largest = node->i_key.value.n;
			}
		}

		return static_cast<int>(largest);
	}

	/**
	 * Address: 0x0090CC10 (FUN_0090CC10, lua_tolightuserdata)
	 *
	 * What it does:
	 * Returns light-userdata pointer for one stack index (`nullptr` for
	 * out-of-range/non-lightuserdata lanes).
	 */
	[[nodiscard]] void* lua_tolightuserdata(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = negindex(state, idx);
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return nullptr;
			}
		}

		if (object == nullptr || object->tt != LUA_TLIGHTUSERDATA) {
			return nullptr;
		}

		return object->value.p;
	}

	/**
	 * Address: 0x0090ADE0 (FUN_0090ADE0)
	 *
	 * What it does:
	 * Loads one light-userdata function pointer from pseudo-index `-10002` and
	 * invokes that callback with the current Lua state.
	 */
	int lua_calllightuserdata(lua_State* const state)
	{
		using LuaRegistryStdCall = int(__stdcall*)(lua_State*);
		auto* const callback = reinterpret_cast<LuaRegistryStdCall>(lua_tolightuserdata(state, -10002));
		return callback(state);
	}

	/**
	 * Address: 0x0090AE30 (FUN_0090AE30)
	 *
	 * What it does:
	 * Copies one Lua string value (including trailing `\0`) from stack index
	 * `idx` into caller-provided destination storage.
	 */
	char* lua_copystring_to_buffer(lua_State* const state, const int idx, void* const destination)
	{
		char* const source = const_cast<char*>(lua_tostring(state, idx));
		const size_t length = lua_strlen(state, idx);
		return static_cast<char*>(std::memcpy(destination, source, length + 1u));
	}

	/**
	 * Address: 0x0090E1E0 (FUN_0090E1E0, adjuststack)
	 *
	 * What it does:
	 * Chooses one suffix of stacked Lua string fragments to concatenate,
	 * balancing total top-fragment length against fragment count.
	 */
	void adjuststack(luaL_Buffer* const buffer)
	{
		int fragmentsToConcat = 1;
		if (buffer->lvl <= 1) {
			return;
		}

		lua_State* const state = buffer->L;
		size_t topLength = lua_strlen(state, -1);
		int relativeIndex = -2;

		while (fragmentsToConcat < buffer->lvl) {
			const size_t currentLength = lua_strlen(state, relativeIndex);
			const int remainingFragments = buffer->lvl - fragmentsToConcat + 1;
			if (remainingFragments < 10 && topLength <= currentLength) {
				break;
			}

			topLength += currentLength;
			++fragmentsToConcat;
			--relativeIndex;
		}

		lua_concat(state, fragmentsToConcat);
		buffer->lvl += 1 - fragmentsToConcat;
	}

	/**
	 * Address: 0x00926170 (FUN_00926170, luaI_addquoted)
	 *
	 * What it does:
	 * Writes one quoted Lua string literal into the buffer, escaping embedded
	 * NUL, newline, quote, and backslash bytes with the legacy Lua escape lane.
	 */
	void luaI_addquoted(lua_State* const state, const int argumentIndex, luaL_Buffer* const buffer)
	{
		char* const bufferEnd = reinterpret_cast<char*>(&buffer[1]);
		size_t remainingLength = 0;
		const char* source = luaL_checklstring(state, argumentIndex, &remainingLength);

		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';
		for (; remainingLength != 0; ++source) {
			--remainingLength;

			switch (*source) {
			case '\0':
				luaL_addlstring(buffer, "\\000", 4u);
				break;

			case '\n':
			case '"':
			case '\\':
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p++ = '\\';
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p = *source;
				++buffer->p;
				break;

			default:
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p = *source;
				++buffer->p;
				break;
			}
		}

		--remainingLength;
		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';
	}

	/**
	 * Address: 0x0091A570 (FUN_0091A570, luaO_rawequalObj)
	 *
	 * What it does:
	 * Compares two tagged Lua values with raw-equality semantics (no
	 * metamethod dispatch), including exact-number and pointer-lane equality.
	 */
	int luaO_rawequalObj(const TObject* const t1, const TObject* const t2)
	{
		if (t1->tt != t2->tt) {
			return 0;
		}

		switch (t1->tt) {
		case LUA_TNIL:
			return 1;
		case LUA_TNUMBER:
			return (t1->value.n == t2->value.n) ? 1 : 0;
		default:
			return (t1->value.p == t2->value.p) ? 1 : 0;
		}
	}

	/**
	 * Address: 0x0091A8D0 (FUN_0091A8D0, luaO_pushfstring)
	 *
	 * What it does:
	 * Starts one varargs lane for `format`, forwards to `luaO_pushvfstring`,
	 * then returns that pushed Lua string pointer.
	 */
	const char* luaO_pushfstring(lua_State* const state, const char* const format, ...)
	{
		va_list argp;
		va_start(argp, format);
		const char* const pushedString = luaO_pushvfstring(state, format, argp);
		va_end(argp);
		return pushedString;
	}

	/**
	 * Address: 0x00913810 (FUN_00913810)
	 *
	 * What it does:
	 * Interns one C-string, writes that tagged string object into caller-chosen
	 * stack slot `slot`, and moves `L->top` to one-past that slot.
	 */
	TString* PushLuaStringAtStackSlot(
		lua_State* const L,
		TObject* const slot,
		const char* const source
	)
	{
		TString* const stringObject = luaS_newlstr(L, source, std::strlen(source));
		slot->tt = stringObject->tt;
		slot->value.p = stringObject;
		L->top = slot + 1;
		return stringObject;
	}

	/**
	 * Address: 0x0091A640 (FUN_0091A640, pushstr)
	 *
	 * What it does:
	 * Interns one Lua string, writes the tagged string object into the current
	 * stack slot, and grows the stack if only one slot of headroom remains.
	 */
	TString* pushstr(lua_State* const state, const char* const source)
	{
		TObject* const top = state->top;
		TString* const stringObject = luaS_newlstr(state, source, std::strlen(source));
		top->tt = stringObject->tt;
		top->value.p = stringObject;

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return stringObject;
	}

	/**
	 * Address: 0x009247C0 (FUN_009247C0, luaS_resize)
	 *
	 * What it does:
	 * Rebuilds the Lua interned-string hash table to `newsize`, rehashing all
	 * existing `TString` nodes and releasing the previous bucket array.
	 */
	void luaS_resize(lua_State* const state, const int newsize)
	{
		GCObject** const newHash = static_cast<GCObject**>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(GCObject*) * newsize))
		);
		global_State* const globalState = state->l_G;
		if (newsize > 0) {
			std::memset(newHash, 0, static_cast<std::size_t>(sizeof(GCObject*) * newsize));
		}

		for (int bucketIndex = 0; bucketIndex < globalState->strt.size; ++bucketIndex) {
			GCObject* node = globalState->strt.hash[bucketIndex];
			while (node != nullptr) {
				GCObject* const next = node->gch.next;
				const int newBucket = static_cast<int>(node->ts.hash & static_cast<lu_hash>(newsize - 1));
				node->gch.next = newHash[newBucket];
				newHash[newBucket] = node;
				node = next;
			}
		}

		luaM_realloc(
			state,
			globalState->strt.hash,
			static_cast<lu_mem>(sizeof(GCObject*) * globalState->strt.size),
			0u
		);
		globalState->strt.hash = newHash;
		globalState->strt.size = newsize;
	}

	/**
	 * Address: 0x00924860 (FUN_00924860, newlstr)
	 *
	 * What it does:
	 * Allocates one `TString`, copies payload bytes plus terminating NUL, links
	 * it into the string-table bucket chain, and triggers table growth when
	 * string usage exceeds bucket count.
	 */
	[[nodiscard]] static TString* newlstr(
		const lu_hash hashValue,
		lua_State* const state,
		const char* const source,
		const std::size_t length
	)
	{
		constexpr std::size_t kTStringHeaderWithTerminator = offsetof(TString, str) + 1u;
		constexpr int kLuaStringTableMaxGrowth = 0x3FFFFFFE;

		GCObject* const object = static_cast<GCObject*>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(length + kTStringHeaderWithTerminator))
		);
		TString* const stringObject = &object->ts;
		stringObject->len = length;
		stringObject->hash = hashValue;
		stringObject->marked = 0u;
		stringObject->tt = LUA_TSTRING;
		stringObject->reserved = 0;

		if (length != 0 && source != nullptr) {
			std::memcpy(stringObject->str, source, length);
		}
		stringObject->str[length] = '\0';

		global_State* const globalState = state->l_G;
		const int bucket = static_cast<int>(hashValue & static_cast<lu_hash>(globalState->strt.size - 1));
		object->gch.next = globalState->strt.hash[bucket];
		globalState->strt.hash[bucket] = object;

		const int stringUseCount = ++globalState->strt.nuse;
		const int bucketCount = globalState->strt.size;
		if (stringUseCount > bucketCount && bucketCount <= kLuaStringTableMaxGrowth) {
			luaS_resize(state, bucketCount * 2);
		}

		return stringObject;
	}

	/**
	 * Address: 0x009248E0 (FUN_009248E0, luaS_newlstr)
	 *
	 * What it does:
	 * Computes Lua string hash, probes interned-string bucket chain for an exact
	 * byte match, and returns existing interned object or allocates a new one.
	 */
	TString* luaS_newlstr(lua_State* const state, const char* const source, const std::size_t length)
	{
		const std::size_t hashStep = (length >> 5u) + 1u;
		lu_hash hashValue = static_cast<lu_hash>(length);
		for (std::size_t probeIndex = length; probeIndex >= hashStep; probeIndex -= hashStep) {
			const lu_hash byteValue = static_cast<unsigned char>(source[probeIndex - 1u]);
			hashValue ^= (hashValue << 5u) + (hashValue >> 2u) + byteValue;
		}

		global_State* const globalState = state->l_G;
		const int bucket = static_cast<int>(hashValue & static_cast<lu_hash>(globalState->strt.size - 1));
		for (GCObject* object = globalState->strt.hash[bucket]; object != nullptr; object = object->gch.next) {
			TString* const candidate = &object->ts;
			if (candidate->tt == LUA_TSTRING && candidate->len == length) {
				if (length == 0u || (source != nullptr && std::memcmp(source, candidate->str, length) == 0)) {
					return candidate;
				}
			}
		}

		return newlstr(hashValue, state, source, length);
	}

	/**
	 * Address: 0x00925A20 (FUN_00925A20, push_onecapture)
	 *
	 * What it does:
	 * Pushes one pattern-capture result to Lua stack (error for unfinished
	 * capture, numeric position for position captures, or captured substring).
	 */
	struct CaptureRuntimeView
	{
		const char* init;
		int len;
	};
	struct MatchStateRuntimeView
	{
		const char* srcInit;
		const char* srcEnd;
		lua_State* state;
		int level;
		CaptureRuntimeView captures[32];
	};
	static_assert(offsetof(CaptureRuntimeView, init) == 0x0, "CaptureRuntimeView::init offset must be 0x0");
	static_assert(offsetof(CaptureRuntimeView, len) == 0x4, "CaptureRuntimeView::len offset must be 0x4");
	static_assert(sizeof(CaptureRuntimeView) == 0x8, "CaptureRuntimeView size must be 0x8");
	static_assert(offsetof(MatchStateRuntimeView, srcInit) == 0x0, "MatchStateRuntimeView::srcInit offset must be 0x0");
	static_assert(offsetof(MatchStateRuntimeView, srcEnd) == 0x4, "MatchStateRuntimeView::srcEnd offset must be 0x4");
	static_assert(offsetof(MatchStateRuntimeView, state) == 0x8, "MatchStateRuntimeView::state offset must be 0x8");
	static_assert(offsetof(MatchStateRuntimeView, level) == 0xC, "MatchStateRuntimeView::level offset must be 0xC");
	static_assert(
		offsetof(MatchStateRuntimeView, captures) == 0x10,
		"MatchStateRuntimeView::captures offset must be 0x10"
	);
	static_assert(sizeof(MatchStateRuntimeView) == 0x110, "MatchStateRuntimeView size must be 0x110");

	[[nodiscard]] const char* luaI_classend(const char* p, MatchStateRuntimeView* ms);
	[[nodiscard]] int match_class(int c1, int cl1);
	[[nodiscard]] int matchbracketclass(const char* p, int c, const char* ec);
	[[nodiscard]] int luaI_singlematch(int c, const char* p, const char* ep);
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchStateRuntimeView* ms);
	[[nodiscard]] const char* match_capture(int l, MatchStateRuntimeView* ms, const char* s);
	[[nodiscard]] const char* max_expand(MatchStateRuntimeView* ms, const char* s, const char* p, const char* ep);
	[[nodiscard]] const char* min_expand(const char* s, MatchStateRuntimeView* ms, const char* p, const char* ep);
	[[nodiscard]] const char* start_capture(const char* s, MatchStateRuntimeView* ms, const char* p, int what);
	[[nodiscard]] const char* end_capture(const char* s, MatchStateRuntimeView* ms, const char* p);
	[[nodiscard]] const char* match(MatchStateRuntimeView* ms, const char* s, const char* p);

	/**
	 * Address: 0x00925920 (FUN_00925920, lmemfind)
	 *
	 * What it does:
	 * Searches one bounded source span for the first occurrence of a bounded
	 * pattern span and returns the match pointer or null when not found.
	 */
	[[nodiscard]] const char* lmemfind(
		const size_t patternLength,
		const char* const sourceText,
		const size_t sourceLength,
		const char* const patternText
	)
	{
		if (patternLength == 0u) {
			return sourceText;
		}

		if (patternLength > sourceLength) {
			return nullptr;
		}

		const size_t tailLength = patternLength - 1u;
		size_t remainingSearch = sourceLength - tailLength;
		if (remainingSearch == 0u) {
			return nullptr;
		}

		const char firstPatternByte = patternText[0];
		const char* searchCursor = sourceText;
		while (true) {
			const void* const found = std::memchr(searchCursor, firstPatternByte, remainingSearch);
			if (found == nullptr) {
				return nullptr;
			}

			const char* const candidate = static_cast<const char*>(found);
			if (tailLength == 0u
				|| std::memcmp(candidate + 1, patternText + 1, tailLength) == 0) {
				return candidate;
			}

			const char* const nextCursor = candidate + 1;
			if (nextCursor <= searchCursor) {
				return nullptr;
			}

			const size_t consumed = static_cast<size_t>(nextCursor - searchCursor);
			if (consumed >= remainingSearch) {
				return nullptr;
			}

			searchCursor = nextCursor;
			remainingSearch -= consumed;
		}
	}

	void push_onecapture(const int captureIndex, MatchStateRuntimeView* const matchState)
	{
		CaptureRuntimeView& capture = matchState->captures[captureIndex];
		const int captureLength = capture.len;
		if (captureLength == -1) {
			luaL_error(matchState->state, "unfinished capture");
			return;
		}

		if (captureLength == -2) {
			const int capturePosition = static_cast<int>(capture.init - matchState->srcInit + 1);
			lua_pushnumber(matchState->state, static_cast<float>(capturePosition));
			return;
		}

		lua_pushlstring(matchState->state, capture.init, static_cast<size_t>(captureLength));
	}

	/**
	 * Address: 0x00925A80 (FUN_00925A80, push_captures)
	 *
	 * What it does:
	 * Pushes all current pattern captures to Lua stack (or the full match slice
	 * when there are no captures) and returns pushed value count.
	 */
	[[nodiscard]] int push_captures(const char* const sourceStart, const char* const sourceEnd, MatchStateRuntimeView* const ms)
	{
		luaL_checkstack(ms->state, ms->level, "too many captures");
		if (ms->level == 0 && sourceStart != nullptr) {
			lua_pushlstring(ms->state, sourceStart, static_cast<size_t>(sourceEnd - sourceStart));
			return 1;
		}

		for (int captureIndex = 0; captureIndex < ms->level; ++captureIndex) {
			push_onecapture(captureIndex, ms);
		}

		return ms->level;
	}

	/**
	 * Address: 0x009250B0 (FUN_009250B0, luaI_classend)
	 *
	 * What it does:
	 * Advances a pattern pointer to the end of the current class/range token,
	 * raising Lua pattern syntax errors for truncated `%` or `[...]` forms.
	 */
	[[nodiscard]] const char* luaI_classend(const char* p, MatchStateRuntimeView* const ms)
	{
		const char token = *p++;
		if (token == '%') {
			if (*p == '\0') {
				luaL_error(ms->state, "malformed pattern (ends with `%%')");
				return nullptr;
			}
			return p + 1;
		}

		if (token == '[') {
			if (*p == '^') {
				++p;
			}

			do {
				if (*p == '\0') {
					luaL_error(ms->state, "malformed pattern (missing `]')");
					return nullptr;
				}

				const char next = *p++;
				if (next == '%' && *p != '\0') {
					++p;
				}
			} while (*p != ']');

			return p + 1;
		}

		return p;
	}

	/**
	 * Address: 0x00925120 (FUN_00925120, match_class)
	 *
	 * What it does:
	 * Evaluates one Lua character class against `c1`, honoring the legacy
	 * uppercase-negation convention for class letters.
	 */
	[[nodiscard]] int match_class(const int c1, const int cl1)
	{
		const unsigned char ch = static_cast<unsigned char>(c1);
		const unsigned char classChar = static_cast<unsigned char>(cl1);
		int result = 0;

		switch (std::tolower(classChar)) {
		case 'a':
			result = std::isalpha(ch) != 0;
			break;
		case 'c':
			result = std::iscntrl(ch) != 0;
			break;
		case 'd':
			result = std::isdigit(ch) != 0;
			break;
		case 'l':
			result = std::islower(ch) != 0;
			break;
		case 'p':
			result = std::ispunct(ch) != 0;
			break;
		case 's':
			result = std::isspace(ch) != 0;
			break;
		case 'u':
			result = std::isupper(ch) != 0;
			break;
		case 'w':
			result = std::isalnum(ch) != 0;
			break;
		case 'x':
			result = std::isxdigit(ch) != 0;
			break;
		case 'z':
			result = (ch == 0);
			break;
		default:
			return c1 == cl1;
		}

		if (std::islower(classChar) == 0) {
			result = (result == 0);
		}

		return result;
	}

	/**
	 * Address: 0x00925230 (FUN_00925230, matchbracketclass)
	 *
	 * What it does:
	 * Evaluates a bracket class or range list against one character and honors
	 * `^` negation, character ranges, and embedded `%` class escapes.
	 */
	[[nodiscard]] int matchbracketclass(const char* p, const int c, const char* ec)
	{
		int positive = 1;
		if (p[1] == '^') {
			positive = 0;
			++p;
		}

		++p;
		if (p < ec) {
			const char* cursor = p + 2;
			do {
				if (*p == '%') {
					const int classChar = static_cast<unsigned char>(*++p);
					++cursor;
					if (match_class(c, classChar)) {
						return positive;
					}
				} else if (p[1] == '-' && cursor < ec) {
					const int first = static_cast<unsigned char>(*p);
					p += 2;
					cursor += 2;
					if (first <= c && c <= static_cast<unsigned char>(*p)) {
						return positive;
					}
				} else if (static_cast<unsigned char>(*p) == c) {
					return positive;
				}

				++p;
				++cursor;
			} while (p < ec);
		}

		return positive == 0;
	}

	/**
	 * Address: 0x009252D0 (FUN_009252D0, luaI_singlematch)
	 *
	 * What it does:
	 * Performs one pattern atom test at a single character position.
	 */
	[[nodiscard]] int luaI_singlematch(const int c, const char* const p, const char* const ep)
	{
		const unsigned char patternChar = static_cast<unsigned char>(*p);
		if (patternChar == '%') {
			return match_class(c, p[1]);
		}

		if (patternChar == '.') {
			return 1;
		}

		if (patternChar == '[') {
			return matchbracketclass(p, c, ep - 1);
		}

		return patternChar == c;
	}

	/**
	 * Address: 0x00925320 (FUN_00925320, matchbalance)
	 *
	 * What it does:
	 * Matches one balanced-pair pattern lane and advances to the matching
	 * closing delimiter when nesting depth returns to zero.
	 */
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchStateRuntimeView* const ms)
	{
		if (*p == '\0' || p[1] == '\0') {
			luaL_error(ms->state, "unbalanced pattern");
			return nullptr;
		}

		const char openChar = *p;
		if (*s != openChar) {
			return nullptr;
		}

		const char* const srcEnd = ms->srcEnd;
		const char closeChar = p[1];
		int depth = 1;
		++s;
		for (const int openValue = openChar; s < srcEnd; ++s) {
			const int current = static_cast<unsigned char>(*s);
			if (current == closeChar) {
				if (--depth == 0) {
					return s + 1;
				}
			} else if (current == openValue) {
				++depth;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x00925390 (FUN_00925390, max_expand)
	 *
	 * What it does:
	 * Greedily consumes the largest possible prefix matching the current
	 * pattern atom, then backtracks until the tail pattern succeeds.
	 */
	[[nodiscard]] const char* max_expand(
		MatchStateRuntimeView* const ms,
		const char* s,
		const char* p,
		const char* ep
	)
	{
		const char* current = s;
		int matchedCount = 0;

		if (s < ms->srcEnd) {
			while (true) {
				const unsigned char patternChar = static_cast<unsigned char>(*p);
				const unsigned char currentChar = static_cast<unsigned char>(*current);

				bool matched = false;
				if (patternChar == '%') {
					matched = match_class(currentChar, p[1]) != 0;
				} else if (patternChar == '.') {
					matched = true;
				} else if (patternChar == '[') {
					matched = matchbracketclass(p, currentChar, ep - 1) != 0;
				} else {
					matched = patternChar == currentChar;
				}

				if (matched == false) {
					break;
				}

				++current;
				++matchedCount;
				if (current >= ms->srcEnd) {
					break;
				}
			}
		}

		while (true) {
			const char* const result = match(ms, s + matchedCount, ep + 1);
			if (result != nullptr) {
				return result;
			}

			--matchedCount;
			if (matchedCount < 0) {
				return nullptr;
			}
		}
	}

	/**
	 * Address: 0x00925430 (FUN_00925430, min_expand)
	 *
	 * What it does:
	 * Tries the tail pattern at the current source position first and only
	 * advances while the current atom still matches.
	 */
	[[nodiscard]] const char* min_expand(
		const char* s,
		MatchStateRuntimeView* const ms,
		const char* p,
		const char* ep
	)
	{
		const char* current = s;
		while (true) {
			const char* const result = match(ms, current, ep + 1);
			if (result != nullptr) {
				return result;
			}

			if (current >= ms->srcEnd) {
				return nullptr;
			}

			const unsigned char patternChar = static_cast<unsigned char>(*p);
			const unsigned char sourceChar = static_cast<unsigned char>(*current);
			const bool matched =
				(patternChar == '%')
					? (match_class(sourceChar, p[1]) != 0)
					: (patternChar == '.'
						? true
						: (patternChar == '[' ? (matchbracketclass(p, sourceChar, ep - 1) != 0)
											   : (patternChar == sourceChar)));
			if (matched == false) {
				return nullptr;
			}

			++current;
		}
	}

	/**
	 * Address: 0x00925580 (FUN_00925580, match_capture)
	 *
	 * What it does:
	 * Compares a captured substring lane against the current source lane and
	 * advances when they match byte-for-byte.
	 */
	[[nodiscard]] const char* match_capture(const int l, MatchStateRuntimeView* const ms, const char* const s)
	{
		const int captureIndex = l - '1';
		if (captureIndex < 0 || captureIndex >= ms->level || ms->captures[captureIndex].len == -1) {
			luaL_error(ms->state, "invalid capture index");
			return nullptr;
		}

		const int captureLength = ms->captures[captureIndex].len;
		if (ms->srcEnd - s < captureLength) {
			return nullptr;
		}

		if (std::memcmp(ms->captures[captureIndex].init, s, static_cast<size_t>(captureLength)) != 0) {
			return nullptr;
		}

		return s + captureLength;
	}

	/**
	 * Address: 0x009254D0 (FUN_009254D0, start_capture)
	 *
	 * What it does:
	 * Starts one new capture lane, advances nested pattern matching, and rolls
	 * back the capture depth when the tail pattern fails.
	 */
	[[nodiscard]] const char* start_capture(
		const char* s,
		MatchStateRuntimeView* const ms,
		const char* p,
		const int what
	)
	{
		const int level = ms->level;
		if (level >= 32) {
			luaL_error(ms->state, "too many captures");
			return nullptr;
		}

		ms->captures[level].init = s;
		ms->captures[level].len = what;
		ms->level = level + 1;
		const char* const result = match(ms, s, p);
		if (result == nullptr) {
			--ms->level;
		}
		return result;
	}

	/**
	 * Address: 0x00925520 (FUN_00925520, end_capture)
	 *
	 * What it does:
	 * Completes the most recent open capture lane, then re-enters matching and
	 * rolls the capture back open if the tail fails.
	 */
	[[nodiscard]] const char* end_capture(const char* s, MatchStateRuntimeView* const ms, const char* p)
	{
		int level = ms->level - 1;
		if (level < 0) {
			luaL_error(ms->state, "invalid pattern capture");
			return nullptr;
		}

		while (ms->captures[level].len != -1) {
			--level;
			if (level < 0) {
				luaL_error(ms->state, "invalid pattern capture");
				return nullptr;
			}
		}

		ms->captures[level].len = static_cast<int>(s - ms->captures[level].init);
		const char* const result = match(ms, s, p);
		if (result == nullptr) {
			ms->captures[level].len = -1;
		}
		return result;
	}

	/**
	 * Address: 0x00925650 (FUN_00925650, match)
	 *
	 * What it does:
	 * Evaluates one Lua pattern atom against the current source lane, handling
	 * anchors, captures, frontier checks, balanced pairs, and quantifiers.
	 */
	[[nodiscard]] const char* match(MatchStateRuntimeView* const ms, const char* s, const char* p)
	{
		while (true) {
			switch (*p) {
			case '\0':
				return s;

			case '$':
				if (p[1] != '\0') {
					goto default_case;
				}
				return s != ms->srcEnd ? nullptr : s;

			case '%': {
				const unsigned char p1 = static_cast<unsigned char>(p[1]);
				if (p1 == 'b') {
					s = matchbalance(p + 2, s, ms);
					if (s == nullptr) {
						return nullptr;
					}
					p += 4;
					continue;
				}
				if (p1 != 'f') {
					if (std::isdigit(p1) == 0) {
						goto default_case;
					}
					s = match_capture(p1, ms, s);
					if (s == nullptr) {
						return nullptr;
					}
					p += 2;
					continue;
				}

				p += 2;
				if (*p != '[') {
					luaL_error(ms->state, "missing `[' after `%%f' in pattern");
					return nullptr;
				}

				const char* const classEnd = luaI_classend(p, ms);
				const char* const classEndMinusOne = classEnd - 1;
				const unsigned char previous = (s == ms->srcInit) ? 0 : static_cast<unsigned char>(*(s - 1));
				if (!matchbracketclass(p, previous, classEndMinusOne)
					&& matchbracketclass(p, static_cast<unsigned char>(*s), classEndMinusOne)) {
					p = classEnd;
					continue;
				}
				return nullptr;
			}

			case '(':
				if (p[1] == ')') {
					return start_capture(s, ms, p + 2, -2);
				}
				return start_capture(s, ms, p + 1, -1);

			case ')':
				return end_capture(s, ms, p + 1);

			default:
			default_case:
				break;
			}

			const char* const ep = luaI_classend(p, ms);
			int matched = 0;
			if (s < ms->srcEnd) {
				const unsigned char patternChar = static_cast<unsigned char>(*p);
				const unsigned char sourceChar = static_cast<unsigned char>(*s);
				if (patternChar == '%') {
					matched = match_class(sourceChar, p[1]);
				} else if (patternChar == '.') {
					matched = 1;
				} else if (patternChar == '[') {
					matched = matchbracketclass(p, sourceChar, ep - 1);
				} else {
					matched = patternChar == sourceChar;
				}
			}

			switch (*ep) {
			case '*':
				return max_expand(ms, s, p, ep);

			case '+':
				if (matched == 0) {
					return nullptr;
				}
				return max_expand(ms, s + 1, p, ep);

			case '-':
				return min_expand(s, ms, p, ep);

			case '?':
				if (matched != 0) {
					const char* const result = match(ms, s + 1, ep + 1);
					if (result != nullptr) {
						return result;
					}
				}
				p = ep + 1;
				continue;

			default:
				if (matched == 0) {
					return nullptr;
				}
				++s;
				p = ep;
				continue;
			}
		}
	}

	/**
	 * Address: 0x00926F70 (FUN_00926F70, luaH_mainposition)
	 *
	 * What it does:
	 * Computes the canonical main hash-bucket node for one table key by key
	 * tag (boolean/lightuserdata/number/string/default pointer lane).
	 */
	Node* luaH_mainposition(const Table* const t, const TObject* const key)
	{
		const std::uint32_t hashMask = LuaHashMask(t);
		const std::uint32_t oddModulus = LuaHashOddModulus(t);

		switch (key->tt) {
		case LUA_TBOOLEAN:
			return &t->node[static_cast<std::uint32_t>(key->value.b) & hashMask];
		case LUA_TLIGHTUSERDATA: {
			const std::uint32_t raw = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(key->value.p));
			return &t->node[raw % oddModulus];
		}
		case LUA_TNUMBER: {
			const std::uint32_t hash = LuaFloatBitPattern(key->value.n + 1.0f);
			return &t->node[hash % oddModulus];
		}
		case LUA_TSTRING: {
			auto* const stringKey = static_cast<TString*>(key->value.p);
			return &t->node[stringKey->hash & hashMask];
		}
		default: {
			const std::uint32_t raw = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(key->value.p));
			return &t->node[raw % oddModulus];
		}
		}
	}

	/**
	 * Address: 0x00927400 (FUN_00927400, luaH_getany)
	 *
	 * What it does:
	 * Performs hash-table lookup for arbitrary key tags and returns the slot
	 * value lane or `luaO_nilobject` when the key is not present.
	 */
	const TObject* luaH_getany(const TObject* const key, Table* const t)
	{
		if (key->tt == LUA_TNIL) {
			return &luaO_nilobject;
		}

		Node* node = luaH_mainposition(t, key);
		while (luaO_rawequalObj(&node->i_key, key) == 0) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x00927450 (FUN_00927450, luaH_getnum)
	 *
	 * What it does:
	 * Looks up one integer key in table array-part first, then in hash chains
	 * using Lua's numeric-key hash lane and nilobject-on-miss semantics.
	 */
	const TObject* luaH_getnum(Table* const t, const int key)
	{
		if (key >= 1 && key <= t->sizearray) {
			return &t->array[key - 1];
		}

		const float floatKey = static_cast<float>(key);
		const std::uint32_t bucket = LuaFloatBitPattern(floatKey + 1.0f) % LuaHashOddModulus(t);
		Node* node = &t->node[bucket];
		while (node->i_key.tt != LUA_TNUMBER || node->i_key.value.n != floatKey) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x009274D0 (FUN_009274D0, luaH_getstr)
	 *
	 * What it does:
	 * Looks up one interned string key in table hash chains and returns either
	 * the value lane or the shared Lua nil object on miss.
	 */
	const TObject* luaH_getstr(Table* const t, TString* const key)
	{
		Node* node = &t->node[key->hash & LuaHashMask(t)];
		while (node->i_key.tt != LUA_TSTRING || static_cast<TString*>(node->i_key.value.p) != key) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x00928420 (FUN_00928420, luaT_gettm)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaT_gettm(Table *events, char event, TString *ename);
	 *
	 * What it does:
	 * Fetches one tag method from a metatable by name. On a miss it records the
	 * absence in the metatable's `flags` cache - setting bit `event` so later
	 * lookups for the same event can skip the table entirely - and returns null
	 * rather than the shared nil object, which is what lets callers distinguish
	 * "no such tag method" from "a tag method whose value is nil".
	 */
	const TObject* luaT_gettm(Table* const events, const int event, TString* const ename)
	{
		const TObject* const tagMethod = luaH_getstr(events, ename);
		if (tagMethod->tt == LUA_TNIL) {
			events->flags |= static_cast<int8_t>(1 << event);
			return nullptr;
		}

		return tagMethod;
	}

	/**
	 * Address: 0x00928450 (FUN_00928450, luaT_gettmbyobj)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaT_gettmbyobj(lua_State *L, const TObject *o, int event);
	 *
	 * What it does:
	 * Resolves one tag method for an arbitrary value. Tables and userdata each
	 * carry their own metatable, so the event name is looked up there. Every
	 * other tag shares the per-type default metatable this fork keeps in
	 * `global_State::_defaultmetatypes` - unlike stock Lua 5.0, which returns
	 * the nil sentinel for those tags - so the slot is handed back directly and
	 * the caller sees nil only when no default has been installed for the type.
	 */
	const TObject* luaT_gettmbyobj(lua_State* const state, const TObject* const object, const int event)
	{
		global_State* const globalState = state->l_G;
		TString* const eventName = globalState->tmname[event];

		switch (object->tt) {
			case LUA_TTABLE:
				return luaH_getstr(static_cast<Table*>(object->value.p)->metatable, eventName);
			case LUA_TUSERDATA:
				return luaH_getstr(static_cast<Udata*>(object->value.p)->metatable, eventName);
			default:
				return &globalState->_defaultmetatypes[object->tt];
		}
	}

	/**
	 * Address: 0x00927510 (FUN_00927510, luaH_get)
	 *
	 * What it does:
	 * Dispatches table get by key tag, including integer-fast-path for number
	 * keys and string-fast-path for interned string keys.
	 */
	const TObject* luaH_get(Table* const t, const TObject* const key)
	{
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				return luaH_getnum(t, integerKey);
			}
		} else if (key->tt == LUA_TSTRING) {
			return luaH_getstr(t, static_cast<TString*>(key->value.p));
		}

		return luaH_getany(key, t);
	}

	/**
	 * Address: 0x00927610 (FUN_00927610, luaH_index)
	 *
	 * What it does:
	 * Resolves the linear iteration index used by `next`, validating incoming
	 * key shape and mapping hash-node value-lane pointers back to node indices.
	 */
	int luaH_index(lua_State* const state, Table* const table, const TObject* const key)
	{
		if (key->tt == LUA_TNIL) {
			return -1;
		}

		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey && integerKey >= 1) {
				const int zeroBased = integerKey - 1;
				if ((zeroBased & 0xFF000000) == 0 && integerKey <= table->sizearray) {
					return zeroBased;
				}
			}
		}

		const TObject* const slot = luaH_get(table, key);
		if (slot == &luaO_nilobject) {
			luaG_runerror(state, "invalid key for `next'");
		}

		const auto nodeBase = reinterpret_cast<std::uintptr_t>(table->node);
		const auto slotAddress = reinterpret_cast<std::uintptr_t>(slot);
		const std::uintptr_t valueLaneOffset = offsetof(Node, i_val);
		const int nodeIndex =
			static_cast<int>((slotAddress - nodeBase - valueLaneOffset) / static_cast<std::uintptr_t>(sizeof(Node)));
		return table->sizearray + nodeIndex;
	}

	/**
	 * Address: 0x009276A0 (FUN_009276A0, luaH_next)
	 *
	 * What it does:
	 * Advances Lua table iteration from `key` to the next occupied array/hash
	 * slot and writes both next-key and next-value lanes into caller storage.
	 */
	int luaH_next(lua_State* const state, Table* const table, TObject* const key)
	{
		int index = luaH_index(state, table, key) + 1;
		const int sizearray = table->sizearray;
		if (index < sizearray) {
			TObject* arraySlot = &table->array[index];
			while (arraySlot->tt == LUA_TNIL) {
				++index;
				++arraySlot;
				if (index >= sizearray) {
					break;
				}
			}

			if (index < sizearray) {
				key->tt = LUA_TNUMBER;
				key->value.n = static_cast<float>(index + 1);
				key[1] = table->array[index];
				return 1;
			}
		}

		int nodeIndex = index - sizearray;
		const int nodeCount = 1 << table->lsizenode;
		if (nodeIndex >= nodeCount) {
			return 0;
		}

		Node* const nodeBase = table->node;
		TObject* valueSlot = &nodeBase[nodeIndex].i_val;
		while (valueSlot->tt == LUA_TNIL) {
			++nodeIndex;
			valueSlot = reinterpret_cast<TObject*>(reinterpret_cast<std::uint8_t*>(valueSlot) + sizeof(Node));
			if (nodeIndex >= nodeCount) {
				return 0;
			}
		}

		key[0] = nodeBase[nodeIndex].i_key;
		key[1] = nodeBase[nodeIndex].i_val;
		return 1;
	}

	/**
	 * Address: 0x0090A6B0 (FUN_0090A6B0, LuaPlusH_next)
	 *
	 * What it does:
	 * Advances Lua table iteration using LuaPlus object wrappers, returning the
	 * next key/value pair in `key` and `value` and `0` when exhausted.
	 */
	extern "C" int LuaPlusH_next(
		LuaState* const state,
		LuaObject* const table,
		LuaObject* const key,
		LuaObject* const value
	)
	{
		if (state == nullptr || state->m_state == nullptr || table == nullptr || key == nullptr || value == nullptr) {
			return 0;
		}

		auto* const tableObject = static_cast<Table*>(table->m_object.value.p);
		if (tableObject == nullptr) {
			return 0;
		}

		int nextIndex = luaH_index(state->m_state, tableObject, &key->m_object) + 1;
		const int arraySize = tableObject->sizearray;

		if (nextIndex < arraySize) {
			TObject* arrayValue = &tableObject->array[nextIndex];
			while (arrayValue->tt == LUA_TNIL) {
				++nextIndex;
				++arrayValue;
				if (nextIndex >= arraySize) {
					break;
				}
			}

			if (nextIndex < arraySize) {
				key->AssignInteger(state, nextIndex + 1);
				value->AssignTObject(state, arrayValue);
				return 1;
			}
		}

		int nodeIndex = nextIndex - arraySize;
		const int nodeCount = 1 << tableObject->lsizenode;
		if (nodeIndex >= nodeCount) {
			return 0;
		}

		Node* const nodeBase = tableObject->node;
		TObject* valueSlot = &nodeBase[nodeIndex].i_val;
		while (valueSlot->tt == LUA_TNIL) {
			++nodeIndex;
			if (nodeIndex >= nodeCount) {
				return 0;
			}
			valueSlot = &nodeBase[nodeIndex].i_val;
		}

		key->AssignTObject(state, &nodeBase[nodeIndex].i_key);
		value->AssignTObject(state, &nodeBase[nodeIndex].i_val);
		return 1;
	}

	/**
	 * Address: 0x00910010 (FUN_00910010, fixjump)
	 *
	 * IDA signature:
	 * void __usercall fixjump(int dest@<eax>, int pc@<ecx>, FuncState *fs@<ebx>);
	 *
	 * What it does:
	 * Patches the sBx field of one jump instruction in `fs->f->code[from]` to
	 * encode the signed offset `to - (from + 1)`, raising a syntax error when
	 * the offset exceeds the 18-bit signed range. Recovered as a free function
	 * here because `luaK_concat` (recovered into LuaObject.cpp) calls it.
	 */
	extern "C" void luaK_fixjump(const int to, const int from, FuncState* const fs)
	{
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateCodegenRuntimeView*>(fs);
		Instruction* const jmp = &fsRuntime->functionProto->code[from];
		const int offset = to - (from + 1);
		constexpr int kMaxArgSBx = 0x1FFFF;
		if (offset > kMaxArgSBx || offset < -kMaxArgSBx) {
			luaX_syntaxerror(fsRuntime->lexState, "control structure too long");
		}
		*jmp = (*jmp & ~(static_cast<Instruction>(0x3FFFFu) << 6))
			| ((static_cast<Instruction>(offset) + kMaxArgSBx) << 6);
	}

	/**
	 * Address: 0x009102F0 (FUN_009102F0, luaK_concat)
	 *
	 * What it does:
	 * Concatenates two jump lists for Lua codegen: appends `l2` to `*l1`,
	 * walking terminal jump links in generated bytecode before patching.
	 */
	void luaK_concat(FuncState* const fs, int* const l1, const int l2)
	{
		if (l2 == LUA_MULTRET) {
			return;
		}

		int list = *l1;
		if (list == LUA_MULTRET) {
			*l1 = l2;
			return;
		}

		const auto* const fsRuntime = reinterpret_cast<const LuaFuncStateCodegenRuntimeView*>(fs);
		const Instruction* const code = fsRuntime->functionProto->code;
		while (true) {
			const int signedOffset = LuaInstructionSignedOffset(code[list]);
			if (signedOffset == LUA_MULTRET) {
				break;
			}

			const int next = list + signedOffset + 1;
			if (next == LUA_MULTRET) {
				break;
			}

			list = next;
		}

		luaK_fixjump(l2, list, fs);
	}

	/**
	 * Address: 0x00910400 (FUN_00910400, addk)
	 *
	 * What it does:
	 * Interns one constant value/key pair into `FuncState` constant tracking
	 * (`h` + `Proto::k`) and returns the resulting constant index.
	 */
	int addk(TObject* const valueObject, FuncState* const functionState, TObject* const keyObject)
	{
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateConstantRuntimeView*>(functionState);
		const TObject* const lookupSlot = luaH_get(fsRuntime->constantLookupTable, keyObject);
		if (lookupSlot->tt == LUA_TNUMBER) {
			return static_cast<int>(lookupSlot->value.n);
		}

		Proto* const functionProto = fsRuntime->functionProto;
		if (fsRuntime->constantCount + 1 > functionProto->sizek) {
			functionProto->k = static_cast<TObject*>(luaM_growaux(
				fsRuntime->state,
				functionProto->k,
				&functionProto->sizek,
				static_cast<int>(sizeof(TObject)),
				0x3FFFF,
				"constant table overflow"
			));
		}

		functionProto->k[fsRuntime->constantCount] = *valueObject;

		TObject* const insertedSlot = luaH_set(fsRuntime->state, fsRuntime->constantLookupTable, keyObject);
		insertedSlot->value.n = static_cast<float>(fsRuntime->constantCount);
		insertedSlot->tt = LUA_TNUMBER;

		const int constantIndex = fsRuntime->constantCount;
		fsRuntime->constantCount = constantIndex + 1;
		return constantIndex;
	}

	/**
	 * Address: 0x00910500 (FUN_00910500, nil_constant)
	 *
	 * What it does:
	 * Interns one shared nil constant key lane (using `FuncState::h` table
	 * identity as key) and returns its constant-table index.
	 */
	int nil_constant(FuncState* const functionState)
	{
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateConstantRuntimeView*>(functionState);

		TObject nilValue{};
		nilValue.tt = LUA_TNIL;

		TObject keyObject{};
		keyObject.value.p = fsRuntime->constantLookupTable;
		keyObject.tt = static_cast<int>(fsRuntime->constantLookupTable->tt);

		return addk(&nilValue, functionState, &keyObject);
	}

	struct LuaDischargeExpdescRuntimeView
	{
		int k;
		int info;
		int aux;
		int t;
		int f;
	};

	struct LuaDischargeLexStateRuntimeView
	{
		int current;
		int linenumber;
		int lastline;
	};

	static_assert(offsetof(LuaDischargeExpdescRuntimeView, k) == 0x00, "LuaDischargeExpdescRuntimeView::k offset must be 0x00");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, info) == 0x04, "LuaDischargeExpdescRuntimeView::info offset must be 0x04");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, aux) == 0x08, "LuaDischargeExpdescRuntimeView::aux offset must be 0x08");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, t) == 0x0C, "LuaDischargeExpdescRuntimeView::t offset must be 0x0C");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, f) == 0x10, "LuaDischargeExpdescRuntimeView::f offset must be 0x10");
	static_assert(sizeof(LuaDischargeExpdescRuntimeView) == 0x14, "LuaDischargeExpdescRuntimeView size must be 0x14");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, current) == 0x00, "LuaDischargeLexStateRuntimeView::current offset must be 0x00");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, linenumber) == 0x04, "LuaDischargeLexStateRuntimeView::linenumber offset must be 0x04");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, lastline) == 0x08, "LuaDischargeLexStateRuntimeView::lastline offset must be 0x08");
	static_assert(sizeof(LuaDischargeLexStateRuntimeView) == 0x0C, "LuaDischargeLexStateRuntimeView size must be 0x0C");

	/**
	 * Address: 0x00910970 (FUN_00910970, discharge2reg)
	 *
	 * What it does:
	 * Forces one expression into a destination register, rewriting the
	 * expression lane or emitting a move/load opcode as needed.
	 */
	extern "C" void discharge2reg(expdesc* const e, const int reg, FuncState* const fs)
	{
		constexpr int kExpKindNil = 1;
		constexpr int kExpKindTrue = 2;
		constexpr int kExpKindFalse = 3;
		constexpr int kExpKindConstant = 4;
		constexpr int kExpKindRelocatable = 10;
		constexpr int kExpKindNonReloc = 11;
		constexpr int kLuaOpMove = 0;
		constexpr int kLuaOpLoadBool = 2;

		auto* const expr = reinterpret_cast<LuaDischargeExpdescRuntimeView*>(e);
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateCodegenRuntimeView*>(fs);

		luaK_dischargevars(fs, e);

		switch (expr->k) {
		case kExpKindNil:
			luaK_nil(fs, reg, 1);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindTrue:
		case kExpKindFalse:
			luaK_codeABC(fs, kLuaOpLoadBool, reg, expr->k == kExpKindTrue ? 1 : 0, 0);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindConstant:
			luaK_code(
				fs,
				static_cast<Instruction>(((expr->info | (reg << 18)) << 6) | 1),
				static_cast<int>(reinterpret_cast<LuaDischargeLexStateRuntimeView*>(fsRuntime->lexState)->lastline)
			);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindRelocatable:
			fsRuntime->functionProto->code[expr->info] =
				(reg << 24) | (static_cast<unsigned int>(fsRuntime->functionProto->code[expr->info]) & 0x00FFFFFFu);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindNonReloc: {
			const int info = expr->info;
			if (reg != info) {
				luaK_codeABC(fs, kLuaOpMove, reg, info, 0);
			}
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;
		}

		default:
			return;
		}
	}

	/**
	 * Address: 0x0090DB80 (FUN_0090DB80, luaL_where)
	 *
	 * What it does:
	 * Pushes one `source(line): ` prefix when a valid debug frame exists;
	 * otherwise pushes an empty prefix string.
	 */
	void luaL_where(lua_State* const state, const int level)
	{
		lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) != 0) {
			lua_getinfo(state, "Snl", &activationRecord);
			if (activationRecord.currentline > 0) {
				lua_pushfstring(state, "%s(%d): ", activationRecord.short_src, activationRecord.currentline);
				return;
			}
		}

	lua_pushlstring(state, "", 0u);
	}

	/**
	 * Address: 0x0090DD40 (FUN_0090DD40, luaL_getmetafield)
	 *
	 * What it does:
	 * Looks up one named metafield on the object's metatable, leaving the
	 * metatable stack slot consumed on success and restoring the stack on miss.
	 */
	int luaL_getmetafield(lua_State* const state, const int obj, const char* const event)
	{
		if (lua_getmetatable(state, obj) == 0) {
			return 0;
		}

		lua_pushstring(state, event);
		lua_rawget(state, -2);
		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -3);
			return 0;
		}

		lua_remove(state, -2);
		return 1;
	}

	/**
	 * Address: 0x0090DE00 (FUN_0090DE00, luaL_openlib)
	 *
	 * What it does:
	 * Opens/creates one globals table slot for `libname`, binds every
	 * `luaL_reg` entry as a closure capturing `nup` upvalues, and restores
	 * stack height by dropping the upvalue copies and destination table.
	 */
	void luaL_openlib(lua_State* const state, const char* const libname, const luaL_reg* registration, const int nup)
	{
		if (libname != nullptr) {
			lua_pushstring(state, libname);
			lua_gettable(state, LUA_GLOBALSINDEX);
			if (lua_type(state, -1) == LUA_TNIL) {
				lua_settop(state, -2);
				lua_newtable(state);
				lua_pushstring(state, libname);
				lua_pushvalue(state, -2);
				lua_settable(state, LUA_GLOBALSINDEX);
			}
			lua_insert(state, -1 - nup);
		}

		const int destinationTableIndex = -3 - nup;
		while (registration != nullptr && registration->name != nullptr) {
			lua_pushstring(state, registration->name);
			for (int upvalueIndex = 0; upvalueIndex < nup; ++upvalueIndex) {
				lua_pushvalue(state, -1 - nup);
			}
			lua_pushcclosure(state, registration->func, nup);
			lua_settable(state, destinationTableIndex);
			++registration;
		}

		lua_settop(state, -1 - nup);
	}

	/**
	 * Address: 0x0090EBF0 (FUN_0090EBF0, luaL_optnumber)
	 *
	 * What it does:
	 * Returns `luaL_checknumber` for present non-nil argument lanes, otherwise
	 * returns caller-provided default numeric value.
	 */
	lua_Number luaL_optnumber(lua_State* const state, const int index, const lua_Number defaultValue)
	{
		if (lua_type(state, index) > LUA_TNIL) {
			return luaL_checknumber(state, index);
		}

		return defaultValue;
	}

	/**
	 * Address: 0x00927090 (FUN_00927090, computesizes)
	 *
	 * What it does:
	 * Chooses optimal array/hash split from bucketed integer-key usage counts
	 * and writes resulting dense-array size plus hash-entry count.
	 */
	void computesizes(
		const int totalUsedEntries,
		int* const narray,
		int* const nhash,
		const int* const nums
	)
	{
		int accumulatedArrayUse = nums[0];
		int bestLog = (accumulatedArrayUse != 0) ? 0 : -1;
		int bestArrayUse = accumulatedArrayUse;
		if (accumulatedArrayUse < *narray) {
			int log = 0;
			const int* numsLane = nums + 1;
			while (accumulatedArrayUse < *narray) {
				const int bucketUpperBound = 1 << log;
				if (*narray < bucketUpperBound) {
					break;
				}

				if (*numsLane > 0) {
					accumulatedArrayUse += *numsLane;
					if (accumulatedArrayUse >= bucketUpperBound) {
						bestLog = log + 1;
						bestArrayUse = accumulatedArrayUse;
					}
				}

				++numsLane;
				++log;
			}
		}

		*nhash = totalUsedEntries - bestArrayUse;
		*narray = (bestLog == -1) ? 0 : (1 << bestLog);
	}

	/**
	 * Address: 0x00927110 (FUN_00927110, numuse)
	 *
	 * What it does:
	 * Counts live Lua table entries by dense-array power-of-two buckets and
	 * hash-node lanes, then derives resize targets for array/hash partitions.
	 */
	void numuse(Table* const table, int* const narray, int* const nhash)
	{
		constexpr int kLuaTableMaxBits = 0x18;
		constexpr int kLuaBucketCount = kLuaTableMaxBits + 1;

		int totalUse = 0;
		int nums[kLuaBucketCount]{};

		int i = 0;
		int lg = 0;
		const int sizearray = table->sizearray;
		while (lg <= kLuaTableMaxBits) {
			int bucketEnd = 1 << lg;
			if (bucketEnd > sizearray) {
				bucketEnd = sizearray;
				if (i >= sizearray) {
					break;
				}
			}

			nums[lg] = 0;
			while (i < bucketEnd) {
				if (table->array[i].tt != LUA_TNIL) {
					++nums[lg];
					++totalUse;
				}
				++i;
			}

			++lg;
		}

		for (; lg < kLuaBucketCount; ++lg) {
			nums[lg] = 0;
		}

		*narray = totalUse;
		const int nodeCount = 1 << table->lsizenode;
		for (int index = nodeCount - 1; index >= 0; --index) {
			const Node& node = table->node[index];
			if (node.i_val.tt == LUA_TNIL) {
				continue;
			}

			if (node.i_key.tt == LUA_TNUMBER) {
				const float numericKey = node.i_key.value.n;
				const int integerKey = static_cast<int>(numericKey);
				if (static_cast<float>(integerKey) == numericKey && integerKey >= 1
					&& ((integerKey - 1) & 0xFF000000) == 0) {
					const int logIndex = luaO_log2(static_cast<unsigned int>(integerKey - 1));
					++nums[logIndex + 1];
					++(*narray);
				}
			}

			++totalUse;
		}

		computesizes(totalUse, narray, nhash, nums);
	}

	/**
	 * Address: 0x00927240 (FUN_00927240, setarrayvector)
	 *
	 * What it does:
	 * Resizes one table dense-array lane, nil-tags newly exposed slots, and
	 * updates `Table::sizearray`.
	 */
	int setarrayvector(const int size, Table* const table, lua_State* const state)
	{
		const lu_mem oldBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(table->sizearray);
		const lu_mem newBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(size);
		table->array = static_cast<TObject*>(luaM_realloc(state, table->array, oldBytes, newBytes));

		int index = table->sizearray;
		while (index < size) {
			table->array[index].tt = LUA_TNIL;
			++index;
		}

		table->sizearray = size;
		return index;
	}

	/**
	 * Address: 0x00927290 (FUN_00927290, setnodevector)
	 *
	 * What it does:
	 * Allocates or binds one table hash-node lane, nil-tags every hash slot key
	 * and value tag, then refreshes `lsizenode` and `firstfree`.
	 */
	Node* setnodevector(lua_State* const state, Table* const table, const int lsize)
	{
		constexpr int kLuaTableMaxHashBits = 0x18;
		if (lsize > kLuaTableMaxHashBits) {
			luaG_runerror(state, "table overflow");
		}

		const int size = 1 << lsize;
		if (lsize != 0) {
			const lu_mem nodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(size);
			table->node = static_cast<Node*>(luaM_realloc(state, nullptr, 0u, nodeBytes));

			for (int index = 0; index < size; ++index) {
				Node& node = table->node[index];
				node.next = nullptr;
				node.i_key.tt = LUA_TNIL;
				node.i_val.tt = LUA_TNIL;
			}
		} else {
			table->node = state->l_G->dummynode;
		}

		table->lsizenode = static_cast<lu_byte>(lsize);
		Node* const firstFree = &table->node[size - 1];
		table->firstfree = firstFree;
		return firstFree;
	}

	/**
	 * Address: 0x009136F0 (FUN_009136F0, sub_9136F0)
	 *
	 * What it does:
	 * Records one newly-created table type entry in Lua debug allocation-size
	 * map while temporarily disabling recursive allocation tracking.
	 */
	void LuaDebugTrackNewTableAllocation(lua_State* const state, Table* const table)
	{
		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;
		globalState->allocationTrackingEnabled = 0;

		TObject* const top = state->top;
		top->tt = static_cast<int>(table->tt);
		top->value.p = table;
		state->top = top + 1;

		Table* const sizesTable = LuaDebugGetSizesTable(state);
		TObject* const destination = luaH_set(state, sizesTable, state->top - 1);

		lua_pushstring(state, lua_typename(state, table->tt));
		(void)_errorfb(state, 0);

		*destination = *(state->top - 1);
		state->top -= 2;

		globalState->allocationTrackingEnabled = 1;
		--globalState->gcTraversalLockDepth;
	}

	/**
	 * Address: 0x00927320 (FUN_00927320, luaH_new)
	 *
	 * What it does:
	 * Allocates and initializes one Lua table object, links it into GC lists,
	 * allocates array/hash lanes, and applies debug allocation tracking hook.
	 */
	Table* luaH_new(lua_State* const state, const int narray, const int lnhash)
	{
		Table* const table = static_cast<Table*>(luaM_realloc(state, nullptr, 0u, sizeof(Table)));
		luaC_link(state, reinterpret_cast<GCObject*>(table), LUA_TTABLE);

		auto* const globalStateView = reinterpret_cast<LuaGlobalStateTableAllocRuntimeView*>(state->l_G);
		table->metatable = globalStateView->defaultTableMetatable;
		table->flags = static_cast<std::int8_t>(-1);
		table->array = nullptr;
		table->sizearray = 0;
		table->lsizenode = 0;
		table->node = nullptr;

		(void)setarrayvector(narray, table, state);
		(void)setnodevector(state, table, lnhash);

		if (globalStateView->allocationTrackingEnabled != 0) {
			LuaDebugTrackNewTableAllocation(state, table);
		}

		return table;
	}

	/**
	 * Address: 0x009273A0 (FUN_009273A0, luaH_free)
	 *
	 * What it does:
	 * Releases one Lua table's hash-node and array storage, then frees the
	 * table object itself through Lua allocator callbacks.
	 */
	void luaH_free(lua_State* const state, Table* const table)
	{
		if (table->lsizenode != 0) {
			const lu_mem nodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(1u << table->lsizenode);
			(void)luaM_realloc(state, table->node, nodeBytes, 0u);
		}

		const lu_mem arrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(table->sizearray);
		(void)luaM_realloc(state, table->array, arrayBytes, 0u);
		(void)luaM_realloc(state, table, static_cast<lu_mem>(sizeof(Table)), 0u);
	}

	/**
	 * Address: 0x00927780 (FUN_00927780, resize)
	 *
	 * What it does:
	 * Rebuilds one Lua table's array/hash storage to new capacities, migrates
	 * live entries across resized lanes, and frees old hash storage when
	 * applicable.
	 */
	int resize(Table* const table, const int newArraySize, lua_State* const state, const int newHashBits)
	{
		const int oldArraySize = table->sizearray;
		const int oldHashBits = table->lsizenode;
		Node* oldNodeArray = table->node;

		Node copiedDummyNode{};
		if (oldHashBits == 0) {
			copiedDummyNode = *oldNodeArray;
			oldNodeArray = &copiedDummyNode;
			state->l_G->dummynode[0].i_key.tt = LUA_TNIL;
			state->l_G->dummynode[0].i_val.tt = LUA_TNIL;
		}

		if (newArraySize > oldArraySize) {
			setarrayvector(newArraySize, table, state);
		}
		setnodevector(state, table, newHashBits);

		if (newArraySize < oldArraySize) {
			table->sizearray = newArraySize;
			for (int index = newArraySize; index < oldArraySize; ++index) {
				TObject* const arraySlot = &table->array[index];
				if (arraySlot->tt == LUA_TNIL) {
					continue;
				}

				const int oneBasedKey = index + 1;
				TObject* destinationSlot = const_cast<TObject*>(luaH_getnum(table, oneBasedKey));
				if (destinationSlot->tt == LUA_TNIL) {
					destinationSlot = luaH_setnum(state, table, oneBasedKey);
				}
				*destinationSlot = *arraySlot;
			}

			const lu_mem oldArrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(oldArraySize);
			const lu_mem newArrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(newArraySize);
			table->array = static_cast<TObject*>(luaM_realloc(state, table->array, oldArrayBytes, newArrayBytes));
		}

		const int oldNodeCount = 1 << oldHashBits;
		for (int index = oldNodeCount - 1; index >= 0; --index) {
			const Node& oldNode = oldNodeArray[index];
			if (oldNode.i_val.tt == LUA_TNIL) {
				continue;
			}

			TObject* const destinationSlot = luaH_set(state, table, &oldNode.i_key);
			*destinationSlot = oldNode.i_val;
		}

		if (oldHashBits != 0) {
			const lu_mem oldNodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(oldNodeCount);
			return static_cast<int>(reinterpret_cast<std::uintptr_t>(luaM_realloc(state, oldNodeArray, oldNodeBytes, 0u)));
		}

		return oldNodeCount;
	}

	/**
	 * Address: 0x00927930 (FUN_00927930, sub_927930)
	 *
	 * What it does:
	 * Recomputes Lua table array/hash resize targets from current occupancy and
	 * applies one resize pass with the derived hash-bit count.
	 */
	int RehashTableFromUsage(Table* const table, lua_State* const state)
	{
		int narray = 0;
		int nhash = 0;
		numuse(table, &narray, &nhash);
		const int hashBits = luaO_log2(static_cast<unsigned int>(nhash)) + 1;
		return resize(table, narray, state, hashBits);
	}

	/**
	 * Address: 0x00927970 (FUN_00927970, newkey)
	 *
	 * What it does:
	 * Inserts one missing key into Lua table storage, relocating collided nodes
	 * through `firstfree` chains and triggering table resize when hash lanes
	 * are exhausted.
	 */
	TObject* newkey(lua_State* const state, Table* const table, const TObject* const key)
	{
		Node* mainPosition = luaH_mainposition(table, key);
		if (mainPosition->i_val.tt != LUA_TNIL) {
			Node* const collidingMainPosition = luaH_mainposition(table, &mainPosition->i_key);
			Node* const firstFree = table->firstfree;
			if (collidingMainPosition == mainPosition) {
				firstFree->next = mainPosition->next;
				mainPosition->next = firstFree;
				mainPosition = firstFree;
			} else {
				Node* collisionPrev = collidingMainPosition;
				while (collisionPrev->next != mainPosition) {
					collisionPrev = collisionPrev->next;
				}

				collisionPrev->next = firstFree;
				firstFree->i_key = mainPosition->i_key;
				firstFree->i_val = mainPosition->i_val;
				firstFree->next = mainPosition->next;
				mainPosition->next = nullptr;
				mainPosition->i_val.tt = LUA_TNIL;
			}
		}

		mainPosition->i_key = *key;
		if (table->firstfree->i_key.tt == LUA_TNIL) {
			return &mainPosition->i_val;
		}

		const Node* const nodeStart = table->node;
		for (;;) {
			Node* const currentFirstFree = table->firstfree;
			if (currentFirstFree == nodeStart) {
				break;
			}

			Node* const previousNode = currentFirstFree - 1;
			table->firstfree = previousNode;
			if (previousNode->i_key.tt == LUA_TNIL) {
				return &mainPosition->i_val;
			}
		}

		mainPosition->i_val.tt = LUA_TBOOLEAN;
		mainPosition->i_val.value.b = 0;
		(void)RehashTableFromUsage(table, state);

		TObject* valueSlot = nullptr;
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				valueSlot = const_cast<TObject*>(luaH_getnum(table, integerKey));
			}
		} else if (key->tt == LUA_TSTRING) {
			valueSlot = const_cast<TObject*>(luaH_getstr(table, static_cast<TString*>(key->value.p)));
		}

		if (valueSlot == nullptr) {
			valueSlot = const_cast<TObject*>(luaH_getany(key, table));
		}

		valueSlot->tt = LUA_TNIL;
		return valueSlot;
	}

	/**
	 * Address: 0x00927560 (FUN_00927560, luaH_set)
	 *
	 * What it does:
	 * Resolves mutable slot for one table key (with integer/string fast-paths),
	 * resets table metamethod-cache flags, and inserts missing keys via `newkey`.
	 */
	TObject* luaH_set(lua_State* const state, Table* const table, const TObject* const key)
	{
		const TObject* slot = nullptr;
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				slot = luaH_getnum(table, integerKey);
			}
		} else if (key->tt == LUA_TSTRING) {
			slot = luaH_getstr(table, static_cast<TString*>(key->value.p));
		}

		if (slot == nullptr) {
			slot = luaH_getany(key, table);
		}

		table->flags = 0;
		if (slot == &luaO_nilobject) {
			if (key->tt == LUA_TNIL) {
				luaG_runerror(state, "table index is nil");
			} else if (key->tt == LUA_TNUMBER) {
				const float numericKey = key->value.n;
				if (numericKey != numericKey) {
					luaG_runerror(state, "table index is NaN");
				}
			}

			return newkey(state, table, key);
		}

		return const_cast<TObject*>(slot);
	}

	/**
	 * Address: 0x00927AC0 (FUN_00927AC0, luaH_setnum)
	 *
	 * What it does:
	 * Resolves or inserts one integer-key table slot and returns the mutable
	 * value lane for callers to assign payload data.
	 */
	TObject* luaH_setnum(lua_State* const state, Table* const table, const int key)
	{
		const TObject* slot = luaH_getnum(table, key);
		if (slot == &luaO_nilobject) {
			TObject numericKey{};
			numericKey.tt = LUA_TNUMBER;
			numericKey.value.n = static_cast<float>(key);
			return newkey(state, table, &numericKey);
		}

		return const_cast<TObject*>(slot);
	}

	/**
	 * Address: 0x00927EF0 (FUN_00927EF0, sub_927EF0)
	 *
	 * What it does:
	 * Compares two stack lanes for table-sort partitioning, using custom
	 * comparator at stack index 2 when present and falling back to
	 * `lua_lessthan` when comparator is absent.
	 */
	[[nodiscard]] int LuaSortLessThanWithOptionalComparator(
		const int leftStackIndex,
		const int rightStackIndex,
		lua_State* const state
	)
	{
		if (lua_type(state, 2) == LUA_TNONE) {
			return lua_lessthan(state, rightStackIndex, leftStackIndex);
		}

		lua_pushvalue(state, 2);
		lua_pushvalue(state, rightStackIndex - 1);
		lua_pushvalue(state, leftStackIndex - 2);
		lua_call(state, 2, 1);
		const int lessThan = lua_toboolean(state, -1);
		lua_settop(state, -2);
		return lessThan;
	}

	/**
	 * Address: 0x00910A70 (FUN_00910A70, discharge2anyreg)
	 *
	 * What it does:
	 * Ensures one expression is materialized in a register lane, grows
	 * `Proto::maxstacksize` when needed, and throws parser syntax errors when
	 * register usage exceeds Lua's function complexity cap.
	 */
	void discharge2anyreg(FuncState* const fs, expdesc* const e)
	{
		constexpr int kExpKindNonReloc = 0x0B;
		constexpr int kLuaMaxFunctionRegisterSlots = 0xFA;

		auto* const fsView = reinterpret_cast<LuaFuncStateCodegenRuntimeView*>(fs);
		const auto* const expView = reinterpret_cast<const LuaExpDescCodegenRuntimeView*>(e);
		if (expView->kind == kExpKindNonReloc) {
			return;
		}

		const int requiredRegisterCount = fsView->freeRegister + 1;
		if (requiredRegisterCount > static_cast<int>(fsView->functionProto->maxstacksize)) {
			if (requiredRegisterCount >= kLuaMaxFunctionRegisterSlots) {
				luaX_syntaxerror(fsView->lexState, "function or expression too complex");
			}
			fsView->functionProto->maxstacksize = static_cast<lu_byte>(requiredRegisterCount);
		}

		discharge2reg(e, fsView->freeRegister++, fs);
	}

	/**
	 * Address: 0x0091AE90 (FUN_0091AE90, indexupvalue)
	 *
	 * What it does:
	 * Finds or appends one parser upvalue entry matching expression
	 * kind/info lanes, grows proto upvalue-name storage when needed, and
	 * returns resolved upvalue index.
	 */
	int indexupvalue(FuncState* const fs, expdesc* const value, TString* const name)
	{
		constexpr int kLuaMaxUpvalues = 0x20;
		constexpr int kLuaIntMaxMinusTwo = 0x7FFFFFFD;
		constexpr int kUpvalueNameEntrySizeBytes = 4;

		auto* const fsView = reinterpret_cast<LuaFuncStateUpvalueRuntimeView*>(fs);
		Proto* const proto = fsView->functionProto;
		const auto* const valueView = reinterpret_cast<const LuaExpDescCodegenRuntimeView*>(value);

		int index = 0;
		const int existingUpvalueCount = static_cast<int>(proto->nups);
		while (index < existingUpvalueCount) {
			const LuaExpDescCodegenRuntimeView& slot = fsView->upvalues[index];
			if (slot.kind == valueView->kind && slot.info == valueView->info) {
				return index;
			}
			++index;
		}

		luaX_checklimit(fsView->lexState, existingUpvalueCount + 1, kLuaMaxUpvalues, "upvalues");
		int& upvalueCapacity = proto->sizeupvalues;
		if (existingUpvalueCount + 1 > upvalueCapacity) {
			proto->upvalues = static_cast<TString**>(
				luaM_growaux(
					fsView->state,
					proto->upvalues,
					&upvalueCapacity,
					kUpvalueNameEntrySizeBytes,
					kLuaIntMaxMinusTwo,
					"upvalues"
				)
			);
		}

		proto->upvalues[existingUpvalueCount] = name;
		fsView->upvalues[existingUpvalueCount] = *valueView;
		proto->nups = static_cast<lu_byte>(existingUpvalueCount + 1);
		return existingUpvalueCount;
	}

} // extern "C"

namespace LuaPlus
{
	// Runtime views for the Lua binary-bytecode loader (lundump). Kept in the
	// engine `LuaPlus` namespace (external linkage) so both the sub-loader
	// definitions here in LuaObject.cpp and `luaU_undump` in LuaParser.cpp name
	// the same layout. Field offsets mirror the original `ZIO` / `LoadState`
	// structs as observed in FUN_009285C0 / FUN_00928ED0 / FUN_009290F0.
	// The reader hands back a whole block at a time; `remainingBytes`/`cursor`
	// walk it, and the tail three fields are what luaZ_init (FUN_0092BA10)
	// writes: "mov [eax+8], ecx" (reader), "mov [eax+0Ch], edx" (data),
	// "mov [eax+10h], ecx" (name), then zeroes +0x00 and +0x04.
	// End-of-stream sentinel the reader lane returns (stock Lua's EOZ).
	constexpr int kLuaEndOfStream = -1;

	struct LuaZioRuntimeView
	{
		int remainingBytes;    // ZIO::n     +0x00
		const char* cursor;    // ZIO::p     +0x04
		lua_Chunkreader reader; // ZIO::reader +0x08
		void* readerData;      // ZIO::data  +0x0C
		const char* chunkName; // ZIO::name  +0x10
	};
	static_assert(offsetof(LuaZioRuntimeView, remainingBytes) == 0x0, "LuaZioRuntimeView::remainingBytes offset must be 0x0");
	static_assert(offsetof(LuaZioRuntimeView, cursor) == 0x4, "LuaZioRuntimeView::cursor offset must be 0x4");
	static_assert(offsetof(LuaZioRuntimeView, reader) == 0x8, "LuaZioRuntimeView::reader offset must be 0x8");
	static_assert(offsetof(LuaZioRuntimeView, readerData) == 0xC, "LuaZioRuntimeView::readerData offset must be 0xC");
	static_assert(offsetof(LuaZioRuntimeView, chunkName) == 0x10, "LuaZioRuntimeView::chunkName offset must be 0x10");

	struct LuaLoadStateRuntimeView
	{
		lua_State* state;        // LoadState::L   (+0x0)
		LuaZioRuntimeView* stream; // LoadState::Z (+0x4)
		Mbuffer* scratchBuffer;  // LoadState::b   (+0x8)
		int swapBytes;           // LoadState::swap(+0xC)
		const char* chunkName;   // LoadState::name(+0x10)
	};
	static_assert(offsetof(LuaLoadStateRuntimeView, state) == 0x0, "LuaLoadStateRuntimeView::state offset must be 0x0");
	static_assert(offsetof(LuaLoadStateRuntimeView, stream) == 0x4, "LuaLoadStateRuntimeView::stream offset must be 0x4");
	static_assert(offsetof(LuaLoadStateRuntimeView, scratchBuffer) == 0x8, "LuaLoadStateRuntimeView::scratchBuffer offset must be 0x8");
	static_assert(offsetof(LuaLoadStateRuntimeView, swapBytes) == 0xC, "LuaLoadStateRuntimeView::swapBytes offset must be 0xC");
	static_assert(offsetof(LuaLoadStateRuntimeView, chunkName) == 0x10, "LuaLoadStateRuntimeView::chunkName offset must be 0x10");
	static_assert(sizeof(LuaLoadStateRuntimeView) == 0x14, "LuaLoadStateRuntimeView size must be 0x14");

	// Binary-chunk loader entry points, recovered in LuaObject.cpp alongside the
	// file-private sub-loaders. External linkage so LuaParser.cpp's luaU_undump
	// can invoke them by name.
	void LuaLoadChunkHeader(LuaLoadStateRuntimeView* loadState);
	Proto* LuaLoadProtoObject(LuaLoadStateRuntimeView* loadState, TString* fallbackSource);
}

namespace
{
	using LuaPlus::LuaZioRuntimeView;

	extern "C"
	{
		const TObject* luaH_get(Table* t, const TObject* key);
		const TObject* luaH_getnum(Table* t, int key);
		const TObject* luaH_getstr(Table* t, TString* key);
		TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
		TObject* luaH_setnum(lua_State* L, Table* t, int key);
		TObject* luaA_index(lua_State* L, int index);
		Table* luaH_new(lua_State* L, int narray, int nhash);
		TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
		const char* luaF_getlocalname(const Proto* func, int local_number, int pc);
		Table* luaT_getmetatable(lua_State* L, const TObject* o);
		int luaO_log2(unsigned int x);
		const TObject* luaV_gettable(lua_State* L, const TObject* t, const TObject* key, int loop);
		void luaV_settable(lua_State* L, const TObject* t, TObject* key, StkId val);
		const TObject* luaV_tonumber(const TObject* obj, TObject* outNumber);
		int luaO_str2d(const char* s, float* result);
		int luaV_tostring(lua_State* L, TObject* obj);
		const char* getobjname(int stackPos, CallInfo* callInfo, const char** nameOut);
		void luaG_runerror(lua_State* L, const char* format, ...);
		int luaZ_fill(LuaZioRuntimeView* stream);
		size_t luaZ_read(LuaZioRuntimeView* stream, void* buffer, size_t size);
		char* luaZ_openspace(lua_State* L, Mbuffer* buff, size_t n);
		std::FILE* __cdecl __iob_func(void);
		void luaO_chunkid(char* out, const char* source, int bufflen);
		void luaA_pushobject(lua_State* L, const TObject* o);
		int luaopen_serialize(lua_State* L);
		void reallymarkobject(GCState* gcState, GCObject* object);
		int luaD_call(lua_State* L, StkId func, int nResults);
		LuaPlus::StkId luaD_precall(lua_State* L, StkId func);
		void luaD_callhook(lua_State* L, int event, int line);
		void luaD_poscall(lua_State* L, int wanted, StkId firstResult);
		void luaD_reallocCI(lua_State* L, int newsize);
		void luaD_growstack(lua_State* L, int n);
		StkId luaV_execute(lua_State* L);
		void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
		void correctstack(lua_State* L, TObject* oldstack);
	}
	constexpr std::uint16_t kLuaMaxCallInfoFrames = 0x1000u;

	// Defined below; both are the fork's own userdata builders.
	[[nodiscard]] Udata* CreateDefaultConstructedUserdata(lua_State* state, gpg::RType* type);
	[[nodiscard]] gpg::RRef BuildRefFromUserdata(Udata* userdata);

	/**
	 * Address: 0x00924B90 shape (the fork's three-argument `lua_newuserdata`).
	 *
	 * What it does:
	 * Builds one reflected userdata of `type`, pushes it on the stack, and hands
	 * the caller a ref to its payload through `outRef`.
	 *
	 * The three-argument shape is the binary's, not stock Lua's: `newfile`
	 * 0x00917190 calls `lua_newuserdata(&rt, L, WrapFile::RType)` and then
	 * upcasts `rt`, so the ref goes out through the argument rather than the
	 * return value. This used to take a source ref in that first slot and return
	 * the new one, which left both callers upcasting a ref nothing had filled -
	 * `NewFileUserdata` threw BadRefCast on it the moment the recovered
	 * `luaopen_io` first ran.
	 *
	 * A null type is `newproxy`'s case: stock Lua makes a userdata of no size,
	 * which here is one carrying no RType in `len` and so no constructor to run.
	 */
	gpg::RRef* lua_newuserdata_ref(
		gpg::RRef* const outRef,
		lua_State* const state,
		gpg::RType* const type
	)
	{
		Udata* userdata = nullptr;
		if (type != nullptr) {
			userdata = CreateDefaultConstructedUserdata(state, type);
		} else {
			userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, sizeof(Udata)));
			userdata->len = 0u;
			userdata->tt = LUA_TUSERDATA;
			userdata->marked = 0u;

			global_State* const globalState = state->l_G;
			userdata->metatable = DefaultUserdataMetatable(globalState);
			userdata->next = globalState->rootudata;
			globalState->rootudata = reinterpret_cast<GCObject*>(userdata);
		}

		state->top->tt = static_cast<int>(userdata->tt);
		state->top->value.p = userdata;
		api_incr_top(state);

		if (outRef != nullptr) {
			*outRef = BuildRefFromUserdata(userdata);
		}
		return outRef;
	}

	/**
	 * Address: 0x00924A10 (FUN_00924A10, luaS_newudata)
	 *
	 * What it does:
	 * Allocates one reflected userdata payload for `type`, default-constructs
	 * the payload through the registered `ctorRefFunc_`, and links userdata into
	 * the root userdata list.
	 */
	[[nodiscard]] Udata* CreateDefaultConstructedUserdata(lua_State* const state, gpg::RType* const type)
	{
		if (type->ctorRefFunc_ == nullptr) {
			luaG_runerror(state, "type %s is not default constructible", type->GetName());
		}

		const std::size_t userdataSize = sizeof(Udata) + static_cast<std::size_t>(type->size_);
		Udata* const userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, userdataSize));

		try {
			void* const payload = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
			(void)type->ctorRefFunc_(payload);
		} catch (...) {
			(void)luaM_realloc(state, userdata, userdataSize, 0u);
			throw;
		}

		userdata->len = reinterpret_cast<std::size_t>(type);
		userdata->tt = LUA_TUSERDATA;
		userdata->marked = (type->dtrFunc_ != nullptr) ? 2u : 0u;

		global_State* const globalState = state->l_G;
		userdata->metatable = DefaultUserdataMetatable(globalState);
		userdata->next = globalState->rootudata;
		globalState->rootudata = reinterpret_cast<GCObject*>(userdata);
		return userdata;
	}

	/**
	 * Address: 0x00924AF0 (FUN_00924AF0, luaS_newudata2)
	 *
	 * What it does:
	 * Allocates one reflected userdata payload for `sourceRef`, move-constructs
	 * it through the source type handler, and links it into root userdata lanes.
	 */
	[[nodiscard]] Udata* CreateRefUserdata(lua_State* const state, gpg::RRef* const sourceRef)
	{
		gpg::RType* const sourceType = sourceRef->mType;
		if (sourceType->movRefFunc_ == nullptr) {
			luaG_runerror(state, "type %s is not copy constructible", sourceType->GetName());
		}

		const std::size_t userdataSize = sizeof(Udata) + static_cast<std::size_t>(sourceType->size_);
		Udata* const userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, userdataSize));

		try {
			void* const payload = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
			(void)sourceType->movRefFunc_(payload, sourceRef);
		} catch (...) {
			(void)luaM_realloc(state, userdata, userdataSize, 0u);
			throw;
		}

		userdata->len = reinterpret_cast<std::size_t>(sourceType);
		userdata->tt = LUA_TUSERDATA;
		userdata->marked = (sourceType->dtrFunc_ != nullptr) ? 2u : 0u;

		global_State* const globalState = state->l_G;
		userdata->metatable = DefaultUserdataMetatable(globalState);
		userdata->next = globalState->rootudata;
		globalState->rootudata = reinterpret_cast<GCObject*>(userdata);
		return userdata;
	}

	[[nodiscard]] gpg::RRef BuildRefFromUserdata(Udata* const userdata)
	{
		gpg::RRef out{};
		out.mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
		out.mType = reinterpret_cast<gpg::RType*>(userdata->len);
		return out;
	}

	/**
	 * Address: 0x00912D30 (FUN_00912D30, kname)
	 *
	 * What it does:
	 * Resolves one proto constant-table slot name from a stack/register index
	 * by subtracting `MAXSTACK`; returns `"?"` when slot is out of range or not
	 * a Lua string constant.
	 */
	const char* kname(const int stackSlotIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		constexpr const char* kUnknownName = "?";

		const int constantIndex = stackSlotIndex - kLuaParserMaxStackSlots;
		if (constantIndex < 0 || proto == nullptr || proto->k == nullptr) {
			return kUnknownName;
		}

		const LuaPlus::TObject& constant = proto->k[constantIndex];
		if (constant.tt != LUA_TSTRING || constant.value.p == nullptr) {
			return kUnknownName;
		}

		return static_cast<const TString*>(constant.value.p)->str;
	}

	/**
	 * Address: 0x009127F0 (FUN_009127F0, travglobals)
	 *
	 * What it does:
	 * Scans the global table hash nodes for a value equal to `object` and
	 * returns the associated string-key name when found.
	 */
	const char* travglobals(lua_State* const state, const TObject* const object)
	{
		auto* const globalsTable = static_cast<Table*>(state->_gt.value.p);
		int remaining = 1 << globalsTable->lsizenode;
		if (remaining == 0) {
			return nullptr;
		}

		int nodeIndex = remaining;
		while (remaining > 0) {
			Node* const node = &globalsTable->node[--nodeIndex];
			--remaining;

			if (luaO_rawequalObj(object, &node->i_val) != 0 && node->i_key.tt == LUA_TSTRING) {
				return static_cast<const TString*>(node->i_key.value.p)->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x009128D0 (FUN_009128D0, checkopenop)
	 *
	 * What it does:
	 * Checks whether instruction `pc + 1` is an "open" opcode lane for
	 * symbolic execution (`OP_CALL`..`OP_RETURN` with open-result flag cleared,
	 * or `OP_SETLIST`).
	 */
	bool checkopenop(const Proto* const proto, const int pc)
	{
		constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
		constexpr unsigned int kLuaOpenOperandMask = 0x00FF8000u;
		constexpr unsigned int kOpCall = 0x1Du;
		constexpr unsigned int kOpReturn = 0x1Fu;
		constexpr unsigned int kOpSetList = 0x24u;

		const Instruction instruction = proto->code[pc + 1];
		const unsigned int opcode = static_cast<unsigned int>(instruction) & kLuaOpcodeMask;
		if (opcode >= kOpCall) {
			if (opcode <= kOpReturn) {
				return (static_cast<unsigned int>(instruction) & kLuaOpenOperandMask) == 0u;
			}

			if (opcode == kOpSetList) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Address: 0x00912530 (FUN_00912530, currentline)
	 *
	 * What it does:
	 * Returns one active source line for the current frame when `savedpc` maps
	 * into Lua bytecode; returns `-1` for non-Lua frames and `0` when lineinfo
	 * is absent.
	 */
	int currentline(CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		if (ci->state >= kCiSavedPc) {
			return -1;
		}

		const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
		const Proto* const proto = closure->l.p;
		const int instructionIndex = static_cast<int>(ci->savedpc - proto->code);
		if (instructionIndex < 0) {
			return -1;
		}

		if (proto->lineinfo != nullptr) {
			return proto->lineinfo[instructionIndex];
		}

		return 0;
	}

	/**
	 * Address: 0x00912910 (FUN_00912910, checkRK)
	 *
	 * What it does:
	 * Validates one RK operand lane against either register space
	 * (`< maxstacksize`) or constant-table space (`MAXSTACK + k`).
	 */
	bool checkRK(const int rkIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		return rkIndex < static_cast<int>(proto->maxstacksize)
			|| (rkIndex >= kLuaParserMaxStackSlots
				&& (rkIndex - kLuaParserMaxStackSlots) < proto->sizek);
	}

	/**
	 * Address: 0x00912E90 (FUN_00912E90, getfuncname)
	 *
	 * What it does:
	 * Resolves callee object-name metadata for call/tailcall opcodes in the
	 * previous Lua frame and returns the object-class string from `getobjname`.
	 */
	const char* getfuncname(const char** const nameOut, CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		constexpr int kOpCall = 29;
		constexpr int kOpTailCall = 30;

		if ((ci->state < kCiSavedPc && ci->tailcalls > 0) || (ci - 1)->state >= kCiSavedPc) {
			return nullptr;
		}

		CallInfo* const callerFrame = ci - 1;
		const auto* const callerClosure = static_cast<const Closure*>(callerFrame->base[-1].value.p);
		const Proto* const callerProto = callerClosure->l.p;

		int instructionIndex = -1;
		if (callerFrame->state < kCiSavedPc) {
			instructionIndex = static_cast<int>(callerFrame->savedpc - callerProto->code);
		}

		const Instruction instruction = callerProto->code[instructionIndex];
		const int opcode = static_cast<int>(instruction & 0x3Fu);
		if (opcode != kOpCall && opcode != kOpTailCall) {
			return nullptr;
		}

		return getobjname(static_cast<int>(instruction >> 24u), callerFrame, nameOut);
	}

	// ---- Lua 5.0 (LuaPlus 1081) bytecode instruction layout + opcode modes ----
	//
	// Field positions for the packed 32-bit Instruction word and the operand
	// range limits used by the symbolic executor below. Values match the
	// LuaPlus 1081 VM this build links.
	constexpr int kLuaMaxStack = 250;                 // MAXSTACK
	constexpr int kLuaNoReg = 255;                    // NO_REG (== MAXARG_A)
	constexpr unsigned kLuaMaxArgB = 0x1FFu;          // MAXARG_B / MAXARG_C
	constexpr unsigned kLuaMaxArgBx = 0x3FFFFu;       // MAXARG_Bx
	constexpr int kLuaMaxArgSBx = 0x1FFFF;            // MAXARG_sBx bias
	constexpr unsigned kLuaFieldsPerFlushM1 = 0x1Fu;  // LFIELDS_PER_FLUSH - 1
	constexpr unsigned kLuaOpJmp = 0x18u;             // OP_JMP opcode (24)
	constexpr unsigned kLuaOpReturn = 0x1Fu;          // OP_RETURN opcode (31)

	// Bits of a `luaP_opmodes` entry: (T<<7)|(A<<6)|(B<<4)|(C<<2)|opmode.
	enum LuaOpModeBits : unsigned char {
		kLuaOpModeMask = 0x03,   // low 2 bits: iABC=0 / iABx=1 / iAsBx=2
		kLuaOpModeBreg = 0x04,   // B is a register
		kLuaOpModeBrk  = 0x08,   // B is register-or-constant (RK)
		kLuaOpModeCrk  = 0x10,   // C is register-or-constant (RK)
		kLuaOpModeSetA = 0x20,   // instruction assigns register A
		kLuaOpModeK    = 0x40,   // Bx is a constant index
	};
	enum LuaOpMode : unsigned char { kLuaIABC = 0, kLuaIABx = 1, kLuaIAsBx = 2 };

	// luaP_opmodes[op] for LuaPlus 1081 — byte-verified from ForgedAlliance.exe
	// .rdata at VA 0x00D466F4. Do NOT edit; matches the shipped binary exactly.
	constexpr unsigned char kLuaOpModes[39] = {
		0x24, 0x61, 0x20, 0x24, 0x20, 0x61, 0x34, 0x41, 0x00, 0x18,
		0x20, 0x34, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
		0x38, 0x24, 0x24, 0x34, 0x02, 0x98, 0x98, 0x98, 0xA4, 0x00,
		0x00, 0x00, 0x02, 0x80, 0x02, 0x01, 0x01, 0x00, 0x21,
	};

	/**
	 * Address: 0x00912940 (FUN_00912940, luaG_symbexec)
	 *
	 * IDA signature:
	 * Instruction __usercall luaG_symbexec@<eax>(const Proto *pt, int lastpc, int reg);
	 *
	 * What it does:
	 * Symbolically executes proto bytecode from pc 0 up to `lastpc`, validating
	 * every instruction's operands against the register window, constant table,
	 * upvalue count and nested-proto lanes, and returns the last instruction that
	 * assigned register `reg` (or 0 when `reg` is never written or the bytecode is
	 * malformed). File-local in the original ldebug.c; used by `getobjname` (name
	 * resolution) and `luaG_checkcode` (load-time verification).
	 *
	 * The exact early-return lattice and forward-jump tracking are preserved 1:1
	 * from the binary; a fully structured rewrite would obscure that lattice.
	 */
	Instruction luaG_symbexec(const Proto* const pt, const int lastpc, const int reg)
	{
		int last = pt->sizecode - 1;
		if (pt->maxstacksize > static_cast<unsigned char>(kLuaMaxStack)) {
			return 0;
		}
		if (pt->sizelineinfo != pt->sizecode && pt->sizelineinfo != 0) {
			return 0;
		}

		const Instruction* const code = pt->code;
		if ((code[pt->sizecode - 1] & 0x3Fu) != kLuaOpReturn) {
			return 0;
		}
		if (lastpc <= 0) {
			return code[last];
		}

		const int maxstack = pt->maxstacksize;
		int pc = 0;
		for (;;) {
			const Instruction instr = code[pc];
			const int op = static_cast<int>(instr & 0x3Fu);
			const int a = static_cast<int>((instr >> 24) & 0xFFu);
			int b = 0;
			int c = 0;
			if (a >= maxstack) {
				return 0;
			}

			const signed char mode = static_cast<signed char>(kLuaOpModes[op]);
			const int opmode = mode & kLuaOpModeMask;
			if (opmode == kLuaIABx) {
				b = static_cast<int>((instr >> 6) & kLuaMaxArgBx);
				if ((mode & kLuaOpModeK) != 0 && !(b < pt->sizek)) {
					return 0;
				}
			} else if (opmode == kLuaIAsBx) {
				b = static_cast<int>((instr >> 6) & kLuaMaxArgBx) - kLuaMaxArgSBx;
			} else {  // iABC: decode + validate B/C operands
				b = static_cast<int>((instr >> 15) & kLuaMaxArgB);
				c = static_cast<int>((instr >> 6) & kLuaMaxArgB);
				if ((mode & kLuaOpModeBreg) != 0) {
					if (b >= maxstack) {
						return 0;
					}
				} else if ((mode & kLuaOpModeBrk) != 0 && !checkRK(b, pt)) {
					return 0;
				}
				if ((mode & kLuaOpModeCrk) != 0 && c >= maxstack) {
					if (c < kLuaMaxStack) {
						return 0;
					}
					if (!((c - kLuaMaxStack) < pt->sizek)) {
						return 0;
					}
				}
			}

			if ((mode & kLuaOpModeSetA) != 0 && a == reg) {
				last = pc;
			}

			// A test operator must be immediately followed by an OP_JMP; any
			// other operator (mode >= 0, i.e. test bit clear) runs unconditionally.
			if (mode >= 0 ||
				(pc + 2 < pt->sizecode && (code[pc + 1] & 0x3Fu) == kLuaOpJmp)) {
				switch (op) {
				case 2:  // OP_LOADBOOL: skip-next requires a following instruction
					if (c != 0 && pc + 2 >= pt->sizecode) {
						return 0;
					}
					break;
				case 3:  // OP_LOADNIL: clears R(a..b)
					if (a <= reg && reg <= b) {
						last = pc;
					}
					break;
				case 4:  // OP_GETUPVAL
				case 8:  // OP_SETUPVAL
					if (b >= pt->nups) {
						return 0;
					}
					break;
				case 5:  // OP_GETGLOBAL
				case 7:  // OP_SETGLOBAL: Bx must name a string constant
					if (pt->k[b].tt != LUA_TSTRING) {
						return 0;
					}
					break;
				case 11:  // OP_SELF: writes R(a) and R(a+1)
					if (a + 1 >= maxstack) {
						return 0;
					}
					if (reg == a + 1) {
						last = pc;
					}
					break;
				case 23:  // OP_CONCAT: R(b..c)
					if (c >= kLuaMaxStack || b >= c) {
						return 0;
					}
					break;
				case 29:  // OP_CALL
				case 30:  // OP_TAILCALL
					if (b != 0 && b + a - 1 >= maxstack) {
						return 0;
					}
					if (--c == -1) {
						if (!checkopenop(pt, pc)) {
							return 0;
						}
					} else if (c != 0 && a + c - 1 >= maxstack) {
						return 0;
					}
					if (reg >= a) {
						last = pc;
					}
					break;
				case 31:  // OP_RETURN
					if (--b > 0 && b + a - 1 >= maxstack) {
						return 0;
					}
					break;
				case 35:  // OP_SETLIST
					if (static_cast<int>(b & kLuaFieldsPerFlushM1) + a + 1 >= maxstack) {
						return 0;
					}
					break;
				case 38:  // OP_CLOSURE: preceding MOVE/GETUPVAL pseudo-ops per upvalue
					if (b >= pt->sizep) {
						return 0;
					}
					{
						int upvalues = pt->p[b]->nups;
						if (upvalues + pc >= pt->sizecode) {
							return 0;
						}
						if (upvalues != 0) {
							const Instruction* pseudo = &code[upvalues + pc];
							for (;;) {
								const int pseudoOp = static_cast<int>(*pseudo & 0x3Fu);
								if (pseudoOp != 4 && pseudoOp != 0) {  // GETUPVAL / MOVE only
									return 0;
								}
								--upvalues;
								--pseudo;
								if (upvalues <= 0) {
									break;
								}
							}
						}
					}
					break;
				case 33:  // OP_TFORLOOP: writes control + loop vars, then falls to jump
					if (a + c + 5 >= maxstack) {
						return 0;
					}
					if (reg >= a) {
						last = pc;
					}
					[[fallthrough]];
				case 32:  // OP_FORLOOP: writes R(a+2), then falls to jump
					if (a + 2 >= maxstack) {
						return 0;
					}
					[[fallthrough]];
				case 24: {  // OP_JMP: validate/optionally follow the forward jump
					const int dest = b + pc + 1;
					if (dest < 0 || dest >= pt->sizecode) {
						return 0;
					}
					if (reg != kLuaNoReg && pc < dest && dest <= lastpc) {
						pc += b;
					}
					break;
				}
				default:
					break;
				}
			} else {
				return 0;
			}

			if (++pc >= lastpc) {
				return code[last];
			}
		}
	}

	/**
	 * Address: 0x00912D50 (FUN_00912D50, getobjname)
	 *
	 * IDA signature:
	 * const char* __usercall getobjname@<eax>(Instruction stackpos@<eax>, CallInfo *ci, const char **name);
	 *
	 * What it does:
	 * Resolves a human-readable name (and its kind: "local"/"upval"/"global"/
	 * "field"/"method") for the value in register `stackPos`, to enrich runtime
	 * error messages. First tries an active local name via `luaF_getlocalname`
	 * (skipping compiler-internal "(...)" names); otherwise symbolically executes
	 * the proto bytecode (`luaG_symbexec`) up to the current pc to find the
	 * producing opcode, following OP_MOVE chains to their source register.
	 */
	extern "C" const char* getobjname(int stackPos, CallInfo* const callInfo, const char** const nameOut)
	{
		constexpr int kCiSavedPc = 3;
		if (callInfo->state >= kCiSavedPc) {
			return nullptr;
		}

		for (;;) {
			const auto* const closure = static_cast<const Closure*>(callInfo->base[-1].value.p);
			const Proto* const proto = closure->l.p;
			const int instructionIndex = static_cast<int>(callInfo->savedpc - proto->code);

			// Prefer an active local-variable name. Compiler-internal locals begin
			// with '(' (e.g. "(for index)") and are skipped, matching the original.
			const char* const localName = luaF_getlocalname(proto, stackPos + 1, instructionIndex);
			*nameOut = localName;
			if (localName != nullptr && *localName != '(') {
				return "local";
			}

			// Otherwise symbolically execute up to this pc to find the instruction
			// that produced the value in register `stackPos`, and name it from that
			// opcode (global/field/method/upvalue) or follow a MOVE chain.
			const Instruction producer = luaG_symbexec(proto, instructionIndex, stackPos);
			switch (producer & 0x3Fu) {
			case 0:  // OP_MOVE: trace back to the source register, then re-resolve
				if (static_cast<int>((producer >> 15) & 0x1FFu) >=
					static_cast<int>((producer >> 24) & 0xFFu)) {
					return nullptr;
				}
				stackPos = static_cast<int>((producer >> 15) & 0x1FFu);
				if (callInfo->state >= kCiSavedPc) {
					return nullptr;
				}
				continue;
			case 4:  // OP_GETUPVAL
				*nameOut = proto->upvalues[(producer >> 15) & 0x1FFu]->str;
				return "upval";
			case 5:  // OP_GETGLOBAL
				*nameOut = static_cast<const TString*>(proto->k[(producer >> 6) & 0x3FFFFu].value.p)->str;
				return "global";
			case 6:  // OP_GETTABLE with a constant key
				*nameOut = kname(static_cast<int>((producer >> 6) & 0x1FFu), proto);
				return "field";
			case 11:  // OP_SELF (method-call sugar)
				*nameOut = kname(static_cast<int>((producer >> 6) & 0x1FFu), proto);
				return "method";
			default:
				return nullptr;
			}
		}
	}

	/**
	 * Address: 0x00912F30 (FUN_00912F30, addinfo)
	 *
	 * What it does:
	 * Prefixes one Lua error message with `chunk(line): ` when the active call
	 * frame is a Lua function and returns the formatted string lane.
	 */
	const char* addinfo(lua_State* const state, const char* const msg)
	{
		char buff[60]{};
		CallInfo* const ci = state->ci;
		if (ci->state < 3) {
			const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
			const Proto* const proto = closure->l.p;
			const int line = currentline(ci);
			luaO_chunkid(buff, proto->source->str, static_cast<int>(sizeof(buff)));
			return luaO_pushfstring(state, "%s(%d): %s", buff, line, msg);
		}

		return msg;
	}

	/**
	 * Address: 0x009133A0 (FUN_009133A0, luaG_typeerror)
	 *
	 * What it does:
	 * Resolves Lua operand provenance/name when possible and raises a typed
	 * operation error matching Lua's runtime wording.
	 */
	void luaG_typeerror(lua_State* const state, const TObject* const object, const char* const operation)
	{
		const char* const valueType = luaT_typenames[object->tt];
		CallInfo* const callInfo = state->ci;
		const char* objectName = nullptr;
		TObject* stackSlot = callInfo->base;
		const TObject* const stackTop = callInfo->top;

		while (stackSlot < stackTop) {
			if (stackSlot == object) {
				const int stackIndex = static_cast<int>(object - state->base);
				const char* const objectClass = getobjname(stackIndex, callInfo, &objectName);
				if (objectClass != nullptr) {
					luaG_runerror(
						state, "attempt to %s %s `%s' (a %s value)", operation, objectClass, objectName, valueType
					);
				}
				break;
			}
			++stackSlot;
		}

		luaG_runerror(state, "%s expected but got %s", operation, valueType);
	}

	/**
	 * Address: 0x00913420 (FUN_00913420, luaV_concat type-error helper)
	 *
	 * What it does:
	 * Selects the non-string operand lane from two concat candidates and raises
	 * `luaG_typeerror(..., "concatenate")`.
	 */
	[[noreturn]] void luaV_concat_raise_typeerror(
		lua_State* const state,
		TObject* const leftCandidate,
		TObject* const rightCandidate
	)
	{
		TObject* errorOperand = leftCandidate;
		if (leftCandidate != nullptr && leftCandidate->tt == LUA_TSTRING) {
			errorOperand = rightCandidate;
		}

		luaG_typeerror(state, errorOperand, "concatenate");
		std::abort();
	}

	/**
	 * Address: 0x00913440 (FUN_00913440, luaG_aritherror)
	 *
	 * What it does:
	 * Selects the non-numeric arithmetic operand (when present) and raises
	 * `luaG_typeerror(..., "perform arithmetic on")`.
	 */
	[[noreturn]] void luaG_aritherror(
		lua_State* const state,
		TObject* const leftOperand,
		TObject* const rightOperand
	)
	{
		TObject* errorOperand = leftOperand;
		if (leftOperand != nullptr && leftOperand->tt == LUA_TNUMBER) {
			errorOperand = rightOperand;
		}

		luaG_typeerror(state, errorOperand, "perform arithmetic on");
		std::abort();
	}

	/**
	 * Address: 0x00914240 (FUN_00914240, luaD_growCI)
	 *
	 * What it does:
	 * Doubles call-info capacity and raises runtime overflow errors for
	 * recursive error handling and post-growth stack-limit overrun.
	 */
	void luaD_growCI(lua_State* const state)
	{
		const std::uint16_t currentFrameCapacity = state->size_ci;
		if (currentFrameCapacity > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "error in Lua error handling");
		}

		luaD_reallocCI(state, static_cast<int>(currentFrameCapacity) * 2);
		if (state->size_ci > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "stack overflow");
		}
	}

	/**
	 * Address: 0x00914080 (FUN_00914080)
	 *
	 * What it does:
	 * Refreshes `stack_last` from the current stack allocation and clamps an
	 * oversized call-info arena back to `kLuaMaxCallInfoFrames` when active
	 * frames fit below that threshold.
	 */
	extern "C" TObject* luaD_refreshstacklimit(lua_State* const state)
	{
		TObject* const stackLast = &state->stack[state->stacksize - 1];
		state->stack_last = stackLast;

		if (state->size_ci > kLuaMaxCallInfoFrames) {
			const auto activeFrameCount = (state->ci - state->base_ci) + 1;
			if (activeFrameCount < static_cast<decltype(activeFrameCount)>(kLuaMaxCallInfoFrames)) {
				luaD_reallocCI(state, static_cast<int>(kLuaMaxCallInfoFrames));
			}
		}

		return stackLast;
	}

	/**
	 * Address: 0x00913850 (FUN_00913850, correctstack)
	 *
	 * What it does:
	 * Rebases stack-relative `top/base/callinfo/open-upvalue` pointers after one
	 * Lua stack reallocation from `oldStackBase` to `state->stack`.
	 */
	extern "C" void correctstack(lua_State* const state, TObject* const oldStackBase)
	{
		TObject* const newStackBase = state->stack;
		state->top = &newStackBase[state->top - oldStackBase];

		for (GCObject* openUpvalue = state->openupval; openUpvalue != nullptr; openUpvalue = openUpvalue->gch.next) {
			UpVal* const upvalue = &openUpvalue->uv;
			upvalue->v = &newStackBase[upvalue->v - oldStackBase];
		}

		for (CallInfo* frame = state->base_ci; frame <= state->ci; ++frame) {
			frame->top = &newStackBase[frame->top - oldStackBase];
			frame->base = &newStackBase[frame->base - oldStackBase];
		}

		state->base = state->ci->base;
	}

	/**
	 * Address: 0x00913990 (FUN_00913990, luaD_growstack)
	 *
	 * What it does:
	 * Reallocates Lua stack storage, grows by either `2x` or `n + EXTRA_STACK`,
	 * then rewrites stack-relative pointers through `correctstack`.
	 */
	extern "C" void luaD_growstack(lua_State* const state, const int n)
	{
		constexpr int kLuaExtraStackSlots = 5;
		const int currentStackSize = state->stacksize;
		TObject* const oldStackBase = state->stack;
		const int newStackSize =
			(n > currentStackSize) ? (currentStackSize + n + kLuaExtraStackSlots) : (currentStackSize * 2);
		TObject* const newStackBase = static_cast<TObject*>(luaM_realloc(
			state,
			oldStackBase,
			static_cast<lu_mem>(sizeof(TObject) * currentStackSize),
			static_cast<lu_mem>(sizeof(TObject) * newStackSize)
		));
		state->stack = newStackBase;
		state->stacksize = newStackSize;
		state->stack_last = &newStackBase[newStackSize - 6];
		correctstack(state, oldStackBase);
	}

	/**
	 * Address: 0x009292F0 (FUN_009292F0, callTM)
	 *
	 * What it does:
	 * Pushes one metamethod + three operands, performs a no-result Lua call,
	 * and preserves stack-growth behavior.
	 */
	void callTM(
		const TObject* const firstOperand,
		const TObject* const secondOperand,
		const TObject* const thirdOperand,
		lua_State* const state,
		const TObject* const metamethodFunction
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *firstOperand;
		top[2] = *secondOperand;
		top[3] = *thirdOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 32) {
			luaD_growstack(state, 4);
		}

		state->top += 4;
		(void)luaD_call(state, state->top - 4, 0);
	}

	/**
	 * Address: 0x009295A0 (FUN_009295A0, get_compTM)
	 *
	 * What it does:
	 * Resolves one comparison metamethod from both metatables and returns it
	 * only when both sides expose the same metamethod function.
	 */
	const TObject* get_compTM(
		Table* const leftMetatable,
		const int event,
		lua_State* const state,
		Table* const rightMetatable
	)
	{
		const lu_byte eventMask = static_cast<lu_byte>(1u << static_cast<unsigned int>(event));
		if ((leftMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const leftTagMethod = luaT_gettm(leftMetatable, event, state->l_G->tmname[event]);
		if (leftTagMethod == nullptr) {
			return nullptr;
		}

		if (leftMetatable == rightMetatable) {
			return leftTagMethod;
		}

		if ((rightMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const rightTagMethod = luaT_gettm(rightMetatable, event, state->l_G->tmname[event]);
		if (rightTagMethod == nullptr) {
			return nullptr;
		}

		return (luaO_rawequalObj(leftTagMethod, rightTagMethod) != 0) ? leftTagMethod : nullptr;
	}

	/**
	 * Address: 0x00929280 (FUN_00929280, callTMres)
	 *
	 * What it does:
	 * Pushes one metamethod function + two operands, executes one Lua call with
	 * a single expected result, then pops that result slot from the Lua stack.
	 */
	int callTMres(
		const TObject* const metamethodFunction,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		lua_State* const state
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *leftOperand;
		top[2] = *rightOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 24) {
			luaD_growstack(state, 3);
		}

		state->top += 3;
		const int callResult = luaD_call(state, state->top - 3, 1);
		--state->top;
		return callResult;
	}

	/**
	 * Address: 0x00929530 (FUN_00929530)
	 *
	 * What it does:
	 * Resolves one binary-operation metamethod across both operands, executes it
	 * when callable, and writes the result back to caller-selected stack slot.
	 */
	int call_binTM(
		lua_State* const state,
		const TObject* const firstOperand,
		const TObject* const secondOperand,
		StkId const resultSlot,
		const int event
	)
	{
		const auto resultStackOffset = resultSlot - state->stack;
		const TObject* metamethodFunction = luaT_gettmbyobj(state, firstOperand, event);
		if (metamethodFunction->tt == LUA_TNIL) {
			metamethodFunction = luaT_gettmbyobj(state, secondOperand, event);
		}

		if ((metamethodFunction->tt | 1) != 7) {
			return 0;
		}

		(void)callTMres(metamethodFunction, firstOperand, secondOperand, state);
		state->stack[resultStackOffset] = *state->top;
		return 1;
	}

	/**
	 * Address: 0x00929B90 (FUN_00929B90)
	 *
	 * What it does:
	 * Attempts one binary-arithmetic metamethod dispatch, then raises one
	 * arithmetic type error when no metamethod resolves.
	 */
	int CallBinTmOrRaiseArithmeticTypeError(
		const int event,
		TObject* const leftOperand,
		lua_State* const state,
		TObject* const rightOperand,
		const StkId resultSlot
	)
	{
		const int result = call_binTM(state, leftOperand, rightOperand, resultSlot, event);
		if (result == 0) {
			luaG_aritherror(state, leftOperand, rightOperand);
		}
		return result;
	}

	/**
	 * Address: 0x00929610 (FUN_00929610, call_orderTM)
	 *
	 * What it does:
	 * Resolves order metamethod on both operands, executes one shared metamethod
	 * call when both sides match, and returns Lua-truthiness of result.
	 */
	int call_orderTM(
		lua_State* const state,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		const int event
	)
	{
		const TObject* const rightMetamethod = luaT_gettmbyobj(state, rightOperand, event);
		if (rightMetamethod->tt == LUA_TNIL) {
			return -1;
		}

		const TObject* const leftMetamethod = luaT_gettmbyobj(state, leftOperand, event);
		if (luaO_rawequalObj(rightMetamethod, leftMetamethod) == 0) {
			return -1;
		}

		(void)callTMres(rightMetamethod, leftOperand, rightOperand, state);
		const TObject* const result = state->top;
		return (result->tt != LUA_TNIL && (result->tt != LUA_TBOOLEAN || result->value.b != 0)) ? 1 : 0;
	}

	/**
	 * Address: 0x00913AD0 (FUN_00913AD0, adjust_varargs)
	 *
	 * What it does:
	 * Pads missing fixed args with nil, collects extra args into one vararg
	 * table (`1..n` plus string key `"n"`), and pushes that table.
	 */
	void adjust_varargs(lua_State* const state, int fixedArgCount, StkId base)
	{
		int actualArgCount = static_cast<int>(state->top - base);
		if (actualArgCount < fixedArgCount) {
			int missingArgCount = fixedArgCount - actualArgCount;
			if ((state->stack_last - state->top) <= missingArgCount) {
				luaD_growstack(state, missingArgCount);
			}

			actualArgCount = fixedArgCount;
			while (missingArgCount-- > 0) {
				state->top->tt = LUA_TNIL;
				++state->top;
			}
		}

		actualArgCount -= fixedArgCount;
		Table* const varargTable = luaH_new(state, actualArgCount, 1);
		for (int index = 0; index < actualArgCount; ++index) {
			const TObject* const sourceSlot = state->top - actualArgCount + index;
			*luaH_setnum(state, varargTable, index + 1) = *sourceSlot;
		}

		TString* const internedCountKey = luaS_newlstr(state, "n", 1u);
		TObject keyN{};
		keyN.tt = static_cast<int>(internedCountKey->tt);
		keyN.value.p = internedCountKey;

		TObject* const countSlot = luaH_set(state, varargTable, &keyN);
		countSlot->tt = LUA_TNUMBER;
		countSlot->value.n = static_cast<float>(actualArgCount);

		state->top -= actualArgCount;
		state->top->tt = static_cast<int>(varargTable->tt);
		state->top->value.p = varargTable;

		if ((state->stack_last - state->top) <= 1) {
			const int currentStackSize = state->stacksize;
			TObject* const oldStackBase = state->stack;
			int newStackSize = currentStackSize * 2;
			if (currentStackSize < 1) {
				newStackSize = currentStackSize + 6;
			}

			TObject* const newStackBase = static_cast<TObject*>(luaM_realloc(
				state,
				oldStackBase,
				static_cast<lu_mem>(sizeof(TObject) * currentStackSize),
				static_cast<lu_mem>(sizeof(TObject) * newStackSize)
			));
			state->stack = newStackBase;
			state->stack_last = &newStackBase[newStackSize - 6];
			state->stacksize = newStackSize;
			correctstack(state, oldStackBase);
		}

		++state->top;
	}

	[[noreturn]] void LuaAssertFail(const char* message)
	{
		throw std::runtime_error(message ? message : "Lua assertion failed");
	}

	void Ensure(bool cond, const char* message)
	{
		if (!cond) {
			LuaAssertFail(message);
		}
	}

	/**
	 * Address: 0x00924020 (FUN_00924020, defaultFatalErrorFunc)
	 *
	 * What it does:
	 * Handles unrecoverable Lua VM fatal-error fallback by terminating the
	 * process with exit code `1`.
	 */
	[[noreturn]] void defaultFatalErrorFunc()
	{
		std::exit(1);
	}

	template <class TObjectType>
	[[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
	{
		if (slot == nullptr) {
			slot = gpg::LookupRType(typeid(TObjectType));
		}
		return slot;
	}

	gpg::RType* gLuaTObjectType = nullptr;
	gpg::RType* gWrapFileType = nullptr;

	struct WrapFile
	{
		std::FILE* stream;
		std::uint8_t closeEnabled;
		std::uint8_t reserved[3];
	};
	static_assert(sizeof(WrapFile) == 0x8, "WrapFile size must be 0x8");
	static_assert(offsetof(WrapFile, stream) == 0x0, "WrapFile::stream offset must be 0x0");
	static_assert(offsetof(WrapFile, closeEnabled) == 0x4, "WrapFile::closeEnabled offset must be 0x4");

	struct WrapFileRuntimeView
	{
		std::FILE* stream;
		std::uint8_t closeEnabled;
		std::uint8_t reserved[3];
	};
	static_assert(offsetof(WrapFileRuntimeView, closeEnabled) == 0x4, "WrapFileRuntimeView::closeEnabled offset must be 0x4");
	static_assert(sizeof(WrapFileRuntimeView) == sizeof(WrapFile), "WrapFileRuntimeView size must match WrapFile");

	class WrapFileTypeInfo final : public gpg::RType
	{
	public:
		/**
		 * Address: 0x00917F80 (FUN_00917F80, WrapFileTypeInfo::WrapFileTypeInfo)
		 *
		 * What it does:
		 * Constructs the WrapFile runtime type descriptor and preregisters it
		 * with reflection registry using `typeid(WrapFile)`.
		 */
		WrapFileTypeInfo();

		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00917FE0 (FUN_00917FE0, WrapFileTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes WrapFile reflection size/callback lanes and finalizes the
		 * descriptor.
		 */
		void Init() override;
	};

	class TObjectTypeInfo final : public gpg::RType
	{
	public:
		/**
		 * Address: 0x00921EF0 (FUN_00921EF0, TObjectTypeInfo::TObjectTypeInfo)
		 *
		 * What it does:
		 * Constructs the TObject runtime type descriptor and preregisters it with
		 * reflection registry using `typeid(TObject)`.
		 */
		TObjectTypeInfo();

		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00921F50 (FUN_00921F50, TObjectTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes TObject reflection size lane and finalizes the descriptor.
		 */
		void Init() override;
	};

	// The binary-bytecode loader state views (`LuaZioRuntimeView` /
	// `LuaLoadStateRuntimeView`) live in `namespace LuaPlus` so the lundump
	// entry points (`LuaLoadChunkHeader` / `LuaLoadProtoObject`) can share the
	// exact same type with `luaU_undump` in LuaParser.cpp without duplicating
	// the layout. Re-expose them unqualified for the file-private sub-loaders
	// below that already reference them by simple name.
	using LuaPlus::LuaZioRuntimeView;
	using LuaPlus::LuaLoadStateRuntimeView;

	constexpr int kLuaRefUserdataTypeTag = LUA_TUSERDATA;
	constexpr int kLuaIoUpvalueEnvIndex = lua_upvalueindex(1);
	// The line-iterator closure carries three upvalues, and both places that
	// build it push them in the same order: the "FILE*" metatable first (held
	// only to keep it alive), then the file, then the close-on-eof flag. The
	// binary reads the file at -10003 and the flag at -10004, which is upvalues
	// 2 and 3 - reading them as 1 and 2 handed the metatable to
	// TryUpcast_WrapFile, and `for line in handle:lines()` threw BadRefCast
	// "can't convert null to WrapFile" on the first iteration.
	constexpr int kLuaIoReadlineFileUpvalueIndex = lua_upvalueindex(2);
	constexpr int kLuaIoReadlineCloseOnEofUpvalueIndex = lua_upvalueindex(3);
	constexpr std::size_t kLuaIoReadChunkSize = 0x200;
	constexpr const char* kLuaDebugHookRegistryKey = "h";
	constexpr const char* kLuaDebugExternalHookLabel = "external hook";
	constexpr const char* kLuaDebugPrompt = "lua_debug> ";
	constexpr const char* kLuaDebugContinueToken = "cont\n";
	constexpr int kLuaDebugInputBufferSize = 0xFC;
	constexpr int kLuaDebugReadLineLimit = 0xFA;
	constexpr int kLuaRegistryAllocationSizesKey = 3;
	constexpr const char* const kLuaDebugHookEventNames[] = {
		"call",
		"return",
		"line",
		"count",
		"tail return"
	};
	static_assert(
		(sizeof(kLuaDebugHookEventNames) / sizeof(kLuaDebugHookEventNames[0])) == 5,
		"kLuaDebugHookEventNames must match Lua hook event count"
	);

	/**
	 * Address: 0x0090CBB0 (FUN_0090CBB0, func_GetRRefFromUserdata)
	 *
	 * What it does:
	 * Reads one userdata stack lane, then materializes `{payload, rtype}` into
	 * a reflected `gpg::RRef`; non-userdata/out-of-range lanes return null ref.
	 */
	void GetRRefFromUserdata(gpg::RRef* const out, lua_State* const state, const int index)
	{
		if (out == nullptr) {
			return;
		}

		// The binary reads the slot itself rather than going through
		// lua_touserdata - `dest->mType = p->u.rtype` at +0x0C and
		// `dest->mObj = &p->th.l_G` at +0x10, which is the payload. Routing it
		// through lua_touserdata was worse than a detour: that function is not
		// defined anywhere in this tree, so it resolved to the prebuilt
		// LuaPlus copy, whose tag test is stock's LUA_TUSERDATA of 7 while this
		// fork numbers full userdata 8. It answered null for every reflected
		// object, and `handle:lines()` threw BadRefCast on the first call.
		const TObject* const object = luaA_indexAcceptable(state, index);
		if (object == nullptr || object->tt != kLuaRefUserdataTypeTag) {
			out->mObj = nullptr;
			out->mType = nullptr;
			return;
		}

		auto* const userdata = static_cast<Udata*>(object->value.p);
		out->mType = reinterpret_cast<gpg::RType*>(userdata->len);
		out->mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
	}

	bool IsWrapFileTypeName(const char* const typeName)
	{
		return typeName != nullptr && std::strstr(typeName, "WrapFile") != nullptr;
	}

	/**
	 * Address: 0x00917060 (FUN_00917060, gpg::RRef::TryUpcast_WrapFile)
	 *
	 * What it does:
	 * Validates reflected userdata carries one WrapFile-compatible type lane,
	 * then returns the wrapped file payload pointer; throws `BadRefCast` on
	 * mismatch to match runtime cast-failure behavior.
	 */
	WrapFileRuntimeView* TryUpcastWrapFile(gpg::RRef* const reference)
	{
		const char* sourceTypeName = "null";
		if (reference != nullptr && reference->mType != nullptr) {
			const char* const runtimeTypeName = reference->mType->GetName();
			sourceTypeName = runtimeTypeName != nullptr ? runtimeTypeName : "null";
		}

		if (reference == nullptr || reference->mObj == nullptr || !IsWrapFileTypeName(sourceTypeName)) {
			throw gpg::BadRefCast(nullptr, sourceTypeName, "WrapFile");
		}

		return static_cast<WrapFileRuntimeView*>(reference->mObj);
	}

	/**
	 * Address: 0x00917240 (FUN_00917240, aux_close)
	 *
	 * What it does:
	 * Closes one wrapped FILE lane only when close-enabled; prefers `_pclose`
	 * and falls back through `fclose` error path exactly as original control
	 * flow, then nulls the stored stream pointer.
	 */
	int AuxClose(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->closeEnabled == 0 || wrapFile->stream == nullptr) {
			return 0;
		}

		if (::_pclose(wrapFile->stream) == -1 && std::fclose(wrapFile->stream) != 0) {
			wrapFile->stream = nullptr;
			return 0;
		}

		wrapFile->stream = nullptr;
		return 1;
	}

	/**
	 * Address: 0x009172B0 (FUN_009172B0, lua::io_close)
	 *
	 * What it does:
	 * Resolves default `_output` file handle from io upvalue when arg-1 is
	 * missing, attempts wrapped close, and pushes Lua `(true)` or
	 * `(nil, strerror(errno), errno-number)` result lanes.
	 */
	int LuaIoClose(lua_State* const state)
	{
		if (lua_type(state, 1) == LUA_TNONE && lua_type(state, kLuaIoUpvalueEnvIndex) == LUA_TTABLE) {
			lua_pushstring(state, "_output");
			lua_rawget(state, kLuaIoUpvalueEnvIndex);
		}

		if (AuxClose(state)) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00917B10 (FUN_00917B10, lua::f_flush)
	 *
	 * What it does:
	 * Flushes one reflected wrapped FILE handle, raising Lua closed-file error
	 * for null stream lane and returning standard io-library `(true)` or
	 * `(nil, strerror(errno), errno-number)` result tuples.
	 */
	int LuaFileFlush(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		if (std::fflush(wrapFile->stream) == 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00915F60 (FUN_00915F60, lua::io_dir)
	 *
	 * What it does:
	 * Expands one wildcard expression through CRT find-first/find-next and
	 * returns one Lua table of 1-based filename entries.
	 */
	int LuaIoDir(lua_State* const state)
	{
		const char* const wildcard = lua_tostring(state, 1);
		lua_newtable(state);

		__finddata64_t findData{};
		const intptr_t findHandle = ::_findfirst64(wildcard, &findData);
		if (findHandle != -1) {
			int index = 1;
			lua_pushnumber(state, static_cast<lua_Number>(index));
			lua_pushstring(state, findData.name);
			lua_settable(state, -3);

			while (::_findnext64(findHandle, &findData) == 0) {
				++index;
				lua_pushnumber(state, static_cast<lua_Number>(index));
				lua_pushstring(state, findData.name);
				lua_settable(state, -3);
			}

			(void)::_findclose(findHandle);
		}

		return 1;
	}

	bool ReadLine(std::FILE* const stream, lua_State* const state);
	gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFileRuntimeView* const wrapFile);

	/**
	 * Address: 0x00916020 (FUN_00916020, read_number)
	 *
	 * What it does:
	 * Reads one floating-point value from `FILE*` and pushes it as Lua number;
	 * returns zero on scan failure.
	 */
	int ReadNumberFromFile(std::FILE* const stream, lua_State* const state)
	{
		double value = 0.0;
		if (std::fscanf(stream, "%lf", &value) != 1) {
			return 0;
		}

		lua_pushnumber(state, static_cast<lua_Number>(value));
		return 1;
	}

	/**
	 * Address: 0x00916160 (FUN_00916160, read_chars)
	 *
	 * What it does:
	 * Reads up to `count` bytes from `FILE*` into one Lua buffer string and
	 * returns success when full count was read or at least one byte was pushed.
	 */
	bool ReadCharsFromFile(std::size_t count, std::FILE* const stream, lua_State* const state)
	{
		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);

		std::size_t chunkSize = kLuaIoReadChunkSize;
		std::size_t readCount = 0u;
		do {
			char* const writeBuffer = luaL_prepbuffer(&buffer);
			if (chunkSize > count) {
				chunkSize = count;
			}

			readCount = std::fread(writeBuffer, 1u, chunkSize, stream);
			buffer.p += readCount;
			count -= readCount;
		} while (count != 0u && readCount == chunkSize);

		luaL_pushresult(&buffer);
		return count == 0u || lua_strlen(state, -1) > 0u;
	}

	/**
	 * Address: 0x009161F0 (FUN_009161F0, g_read)
	 *
	 * What it does:
	 * Implements Lua IO read options (`number`, `*l`, `*n`, `*a`) over one
	 * wrapped `FILE*`, preserving nil-on-failure stack/result semantics.
	 */
	int LuaReadFromFile(
		std::FILE* const stream,
		lua_State* const state,
		const int firstArgumentIndex
	)
	{
		int argumentIndex = firstArgumentIndex;
		int readSucceeded = 1;
		int remainingOptions = lua_gettop(state) - 1;

		if (remainingOptions == 0) {
			readSucceeded = ReadLine(stream, state) ? 1 : 0;
			argumentIndex = firstArgumentIndex + 1;
		} else {
			luaL_checkstack(state, remainingOptions + 20, "too many arguments");
			while (remainingOptions > 0) {
				--remainingOptions;
				if (readSucceeded == 0) {
					break;
				}

				if (lua_type(state, argumentIndex) == LUA_TNUMBER) {
					const int requestedCount = static_cast<int>(lua_tonumber(state, argumentIndex));
					if (requestedCount != 0) {
						readSucceeded = ReadCharsFromFile(
							static_cast<std::size_t>(static_cast<unsigned int>(requestedCount)), stream, state
						)
							? 1
							: 0;
					} else {
						const int nextChar = std::getc(stream);
						std::ungetc(nextChar, stream);
						lua_pushlstring(state, nullptr, 0u);
						readSucceeded = nextChar != EOF ? 1 : 0;
					}
				} else if (lua_type(state, argumentIndex) == LUA_TSTRING) {
					const char* const option = lua_tostring(state, argumentIndex);
					if (option == nullptr || option[0] != '*') {
						luaL_argerror(state, argumentIndex, "invalid option");
					}

					switch (option[1]) {
					case 'a':
						(void)ReadCharsFromFile(
							static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()), stream, state
						);
						readSucceeded = 1;
						break;
					case 'l':
						readSucceeded = ReadLine(stream, state) ? 1 : 0;
						break;
					case 'n':
						readSucceeded = ReadNumberFromFile(stream, state);
						break;
					case 'w':
						luaL_error(state, "obsolete option `*w' to 'read'");
						break;
					default:
						luaL_argerror(state, argumentIndex, "invalid format");
						break;
					}
				}

				++argumentIndex;
			}
		}

		if (readSucceeded == 0) {
			lua_settop(state, -2);
			lua_pushnil(state);
		}

		return argumentIndex - firstArgumentIndex;
	}

	/**
	 * Address: 0x00916090 (FUN_00916090, read_line)
	 *
	 * What it does:
	 * Reads one text line from a wrapped `FILE*`, strips the trailing newline
	 * when present, pushes the line as Lua string, and returns non-empty status.
	 */
	bool ReadLine(std::FILE* const stream, lua_State* const state)
	{
		std::string line{};
		char chunk[512]{};

		while (std::fgets(chunk, static_cast<int>(sizeof(chunk)), stream) != nullptr) {
			const size_t chunkLength = std::strlen(chunk);
			if (chunkLength == 0) {
				continue;
			}

			if (chunk[chunkLength - 1] == '\n') {
				line.append(chunk, chunkLength - 1);
				lua_pushlstring(state, line.c_str(), line.size());
				return true;
			}

			line.append(chunk, chunkLength);
		}

		lua_pushlstring(state, line.c_str(), line.size());
		return !line.empty();
	}

	/**
	 * Address: 0x009177E0 (FUN_009177E0, io_readline)
	 *
	 * What it does:
	 * Reads one line from the wrapped file upvalue, optionally auto-closes on
	 * EOF depending on the boolean close-flag upvalue, and returns Lua iterator
	 * success status (`1` for value pushed, `0` for EOF).
	 */
	int LuaIoReadline(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, kLuaIoReadlineFileUpvalueIndex);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		std::FILE* const stream = wrapFile->stream;
		if (stream == nullptr) {
			luaL_error(state, "file is already closed");
		}

		if (ReadLine(stream, state)) {
			return 1;
		}

		if (lua_toboolean(state, kLuaIoReadlineCloseOnEofUpvalueIndex) != 0) {
			lua_settop(state, 0);
			lua_pushvalue(state, kLuaIoReadlineFileUpvalueIndex);
			(void)AuxClose(state);
		}

		return 0;
	}

	/**
	 * Address: 0x00917DC0 (FUN_00917DC0, lua::aux_lines)
	 *
	 * What it does:
	 * Creates one line-iterator closure for a wrapped file handle with
	 * upvalues `{FILE* metatable, file userdata, closeOnEof=false}`.
	 */
	int LuaAuxLines(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		lua_pushlstring(state, "FILE*", 5u);
		lua_rawget(state, LUA_REGISTRYINDEX);
		lua_pushvalue(state, 1);
		lua_pushboolean(state, 0);
		lua_pushcclosure(state, LuaIoReadline, 3);
		return 1;
	}

	/**
	 * Address: 0x00917190 (FUN_00917190, newfile)
	 *
	 * What it does:
	 * Allocates one WrapFile userdata lane, binds `FILE*` metatable, and sets
	 * the close-enabled byte according to caller intent.
	 */
	WrapFileRuntimeView* NewFileUserdata(lua_State* const state, const bool closeEnabled)
	{
		gpg::RRef reference{};
		lua_newuserdata_ref(&reference, state, CachedType<WrapFile>(gWrapFileType));
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		luaL_getmetatable(state, "FILE*");
		lua_setmetatable(state, -2);
		wrapFile->closeEnabled = closeEnabled ? 1u : 0u;
		return wrapFile;
	}

	/**
	 * Address: 0x00917000 (FUN_00917000, sub_917000)
	 *
	 * What it does:
	 * Destroys one heap-allocated WrapFile storage lane, conditionally closing
	 * the stream when close-enabled, then frees the payload block.
	 */
	void DestroyWrapFileStorage(WrapFileRuntimeView* const wrapFile)
	{
		if (wrapFile == nullptr) {
			return;
		}

		if (wrapFile->stream != nullptr && wrapFile->closeEnabled != 0u) {
			std::fclose(wrapFile->stream);
		}

		wrapFile->stream = nullptr;
		::operator delete(wrapFile);
	}

	/**
	 * Address: 0x00917030 (FUN_00917030, sub_917030)
	 *
	 * What it does:
	 * Performs WrapFile close-on-destruct semantics in-place and clears the
	 * stream lane, returning the raw x86 `EAX` result payload.
	 */
	std::intptr_t FinalizeWrapFileStorage(WrapFileRuntimeView* const wrapFile)
	{
		std::intptr_t result = reinterpret_cast<std::intptr_t>(wrapFile->stream);
		if (wrapFile->stream != nullptr && wrapFile->closeEnabled != 0u) {
			result = static_cast<std::intptr_t>(std::fclose(wrapFile->stream));
		}

		wrapFile->stream = nullptr;
		return result;
	}

	/**
	 * Address: 0x00917D00 (FUN_00917D00, sub_917D00)
	 *
	 * What it does:
	 * Allocates one heap WrapFile storage payload and returns it as reflected
	 * `gpg::RRef` with close-enabled default state.
	 */
	gpg::RRef* NewWrapFileStorageRef(gpg::RRef* const out)
	{
		auto* const wrapFile = static_cast<WrapFileRuntimeView*>(::operator new(sizeof(WrapFileRuntimeView), std::nothrow));
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		return BuildWrapFileRef(out, wrapFile);
	}

	/**
	 * Address: 0x00917D40 (FUN_00917D40, sub_917D40)
	 *
	 * What it does:
	 * Initializes caller-owned WrapFile storage and returns the reflected
	 * `gpg::RRef` view of that payload.
	 */
	gpg::RRef* ConstructWrapFileStorageRef(
		gpg::RRef* const out,
		WrapFileRuntimeView* const wrapFile
	)
	{
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		return BuildWrapFileRef(out, wrapFile);
	}

	/**
	 * Address: 0x00917F80 (FUN_00917F80, WrapFileTypeInfo::WrapFileTypeInfo)
	 *
	 * What it does:
	 * Constructs the WrapFile runtime type descriptor and preregisters it with
	 * reflection registry using `typeid(WrapFile)`.
	 */
	WrapFileTypeInfo::WrapFileTypeInfo()
	{
		gpg::PreRegisterRType(typeid(WrapFile), this);
	}

	const char* WrapFileTypeInfo::GetName() const
	{
		return "WrapFile";
	}

	/**
	 * Address: 0x00917FE0 (FUN_00917FE0, WrapFileTypeInfo::Init)
	 *
	 * What it does:
	 * Initializes WrapFile reflection size/callback lanes and finalizes the
	 * descriptor.
	 */
	void WrapFileTypeInfo::Init()
	{
		size_ = sizeof(WrapFile);
		gpg::RType::Init();
		newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		Finish();
	}

	/**
	 * Address: 0x00918070 (FUN_00918070, WrapFileTypeInfo deleting-dtor thunk)
	 *
	 * What it does:
	 * Tears down one `WrapFileTypeInfo` descriptor via `gpg::RType` base
	 * teardown and conditionally frees storage when `deleteFlag & 1`.
	 */
	gpg::RType* DestroyWrapFileTypeInfoDeleting(
		WrapFileTypeInfo* const typeInfo,
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
	 * Address: 0x009231F0 (FUN_009231F0, TObjectTypeInfo deleting-dtor thunk)
	 *
	 * What it does:
	 * Tears down one `TObjectTypeInfo` descriptor via `gpg::RType` base teardown
	 * and conditionally frees storage when `deleteFlag & 1`.
	 */
	gpg::RType* DestroyTObjectTypeInfoDeleting(
		TObjectTypeInfo* const typeInfo,
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
	 * Address: 0x00921EF0 (FUN_00921EF0, TObjectTypeInfo::TObjectTypeInfo)
	 *
	 * What it does:
	 * Constructs the TObject runtime type descriptor and preregisters it with
	 * reflection registry using `typeid(TObject)`.
	 */
	TObjectTypeInfo::TObjectTypeInfo()
	{
		gpg::PreRegisterRType(typeid(TObject), this);
	}

	const char* TObjectTypeInfo::GetName() const
	{
		return "TObject";
	}

	/**
	 * Address: 0x00921F50 (FUN_00921F50, TObjectTypeInfo::Init)
	 *
	 * What it does:
	 * Initializes TObject reflection size lane and finalizes the descriptor.
	 */
	void TObjectTypeInfo::Init()
	{
		size_ = sizeof(TObject);
		gpg::RType::Init();
		Finish();
	}

	/**
	 * Address: 0x00BEA0A0 (register_WrapFileTypeInfo)
	 * Address: 0x00BEA100 (register_TObjectTypeInfo)
	 *
	 * What it does:
	 * Constructs the two descriptors so their constructors can pre-register
	 * `typeid(WrapFile)` and `typeid(TObject)`. Both register from their ctor,
	 * so without an instance neither typeid ever reaches the reflection map.
	 * The binary drives both from its CRT initializer table.
	 */
	alignas(WrapFileTypeInfo) unsigned char gWrapFileTypeInfoStorage[sizeof(WrapFileTypeInfo)];
	alignas(TObjectTypeInfo) unsigned char gTObjectTypeInfoStorage[sizeof(TObjectTypeInfo)];
	bool gWrapFileTypeInfoConstructed = false;
	bool gTObjectTypeInfoConstructed = false;

	void CleanupWrapFileTypeInfo()
	{
		if (!gWrapFileTypeInfoConstructed) {
			return;
		}
		auto& ti = *reinterpret_cast<WrapFileTypeInfo*>(gWrapFileTypeInfoStorage);
		ti.fields_ = msvc8::vector<gpg::RField>{};
		ti.bases_ = msvc8::vector<gpg::RField>{};
	}

	void CleanupTObjectTypeInfo()
	{
		if (!gTObjectTypeInfoConstructed) {
			return;
		}
		auto& ti = *reinterpret_cast<TObjectTypeInfo*>(gTObjectTypeInfoStorage);
		ti.fields_ = msvc8::vector<gpg::RField>{};
		ti.bases_ = msvc8::vector<gpg::RField>{};
	}

	struct LuaObjectTypeInfoBootstrap
	{
		LuaObjectTypeInfoBootstrap()
		{
			new (gWrapFileTypeInfoStorage) WrapFileTypeInfo();
			gWrapFileTypeInfoConstructed = true;
			(void)std::atexit(&CleanupWrapFileTypeInfo);

			new (gTObjectTypeInfoStorage) TObjectTypeInfo();
			gTObjectTypeInfoConstructed = true;
			(void)std::atexit(&CleanupTObjectTypeInfo);
		}
	};

	LuaObjectTypeInfoBootstrap gLuaObjectTypeInfoBootstrap;

	/**
	 * Address: 0x00917CE0 (FUN_00917CE0, sub_917CE0)
	 *
	 * What it does:
	 * Binds WrapFile cleanup callbacks (`delete`, `destruct`) onto one
	 * reflection type descriptor lane.
	 */
	gpg::RType* ConfigureWrapFileCleanupCallbacks(gpg::RType* const type)
	{
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		return type;
	}

	/**
	 * Address: 0x00917F10 (FUN_00917F10, sub_917F10)
	 *
	 * What it does:
	 * Binds WrapFile `new-ref` and `construct-ref` callbacks onto one
	 * reflection type descriptor lane.
	 */
	gpg::RType* ConfigureWrapFileRefCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		type->ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		return type;
	}

	/**
	 * Address: 0x00917F30 (FUN_00917F30, sub_917F30)
	 *
	 * What it does:
	 * Binds full WrapFile callback suite (`new/construct/delete/destruct`) onto
	 * one reflection type descriptor lane.
	 */
	gpg::RType* ConfigureWrapFileAllCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		type->ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		return type;
	}

	/**
	 * Address: 0x00917F60 (FUN_00917F60, sub_917F60)
	 *
	 * What it does:
	 * Binds the full WrapFile callback suite directly onto one reflection type
	 * descriptor lane without returning the descriptor.
	 */
	void ConfigureWrapFileAllCallbacksInPlace(gpg::RType* const type)
	{
		type->newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		type->ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
	}

	/**
	 * Address: 0x00917100 (FUN_00917100, sub_917100)
	 *
	 * What it does:
	 * Pack entry: builds one temporary `gpg::RRef` by routing through
	 * `gpg::RRef_WrapFile` and copies the `(mObj, mType)` pair into
	 * caller-provided storage. The canonical reflection-reference body lives
	 * in `gpg::RRef_WrapFile` at 0x00916E60 (non-polymorphic WrapFile ⇒ the
	 * derived-type cache branch is dead and the effective behavior is the
	 * direct field assignment below).
	 */
	gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFileRuntimeView* const wrapFile)
	{
		out->mObj = wrapFile;
		out->mType = CachedType<WrapFile>(gWrapFileType);
		return out;
	}

	/**
	 * Address: 0x00916E60 (FUN_00916E60, gpg::RRef_WrapFile)
	 *
	 * IDA signature:
	 * gpg::RRef *__cdecl gpg::RRef_WrapFile(gpg::RRef *out, char *object);
	 *
	 * What it does:
	 * Builds a reflected reference for a `WrapFile` payload using the cached
	 * RTTI lookup and a 3-slot TLS derived-type normalization helper,
	 * matching the binary's TLS-cached `IsDerivedFrom` adjustment chain.
	 * `WrapFile` is a non-polymorphic struct so the runtime-type
	 * compare-equal fast path always fires and the derived-type TLS-cache
	 * lanes are dead code in this instantiation; the effective behavior is
	 * the same `(out->mObj = object; out->mType = CachedType<WrapFile>())`
	 * assignment as the caller-pack entry at 0x00917100.
	 */
	gpg::RRef* RRefWrapFileImpl(gpg::RRef* const out, WrapFileRuntimeView* const object)
	{
		if (out == nullptr) {
			return nullptr;
		}

		out->mObj = object;
		out->mType = CachedType<WrapFile>(gWrapFileType);
		return out;
	}

	/**
	 * Address: 0x00917130 (FUN_00917130, sub_917130)
	 *
	 * What it does:
	 * Validates that one userdata stack lane resolves to a WrapFile payload.
	 */
	void ValidateWrapFileUserdataAt(lua_State* const state, const int index)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, index);
		(void)TryUpcastWrapFile(&reference);
	}

	/**
	 * Address: 0x00917150 (FUN_00917150, tofile)
	 *
	 * What it does:
	 * Resolves one wrapped file userdata and returns `FILE*`, raising Lua's
	 * closed-file error when stream lane is null.
	 */
	std::FILE* ToFile(lua_State* const state, const int index)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, index);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		return wrapFile->stream;
	}

	/**
	 * Address: 0x009175B0 (FUN_009175B0, sub_9175B0)
	 *
	 * What it does:
	 * Looks up global io handle by key (`_input`/`_output`) and returns wrapped
	 * `FILE*`, raising Lua closed-file error when stream lane is null.
	 */
	std::FILE* GetIoFileFromGlobal(lua_State* const state, const char* const globalKey)
	{
		lua_pushstring(state, globalKey);
		lua_rawget(state, LUA_GLOBALSINDEX);

		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, -1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		return wrapFile->stream;
	}

	/**
	 * Address: 0x00917540 (FUN_00917540, lua::io_tmpfile)
	 *
	 * What it does:
	 * Creates one temporary `FILE*` wrapped userdata and returns either the
	 * handle or standard Lua io `(nil, strerror(errno), errno)` error tuple.
	 */
	int LuaIoTmpFile(lua_State* const state)
	{
		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = std::tmpfile();
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00916C80 (FUN_00916C80, io_difftime)
	 *
	 * What it does:
	 * Converts the first two numeric arguments to a time span and pushes the
	 * `difftime` result as one Lua number.
	 */
	int io_difftime(lua_State* const state)
	{
		const std::time_t right = static_cast<std::time_t>(luaL_optnumber(state, 2, 0.0f));
		const std::time_t left = static_cast<std::time_t>(luaL_checknumber(state, 1));
		lua_pushnumber(state, static_cast<lua_Number>(std::difftime(left, right)));
		return 1;
	}

	constexpr int kLuaLocaleCategories[] = {
		LC_ALL,
		LC_COLLATE,
		LC_CTYPE,
		LC_MONETARY,
		LC_NUMERIC,
		LC_TIME
	};

	constexpr const char* const kLuaLocaleCategoryNames[] = {
		"all",
		"collate",
		"ctype",
		"monetary",
		"numeric",
		"time",
		nullptr
	};

	/**
	 * Address: 0x00916CD0 (FUN_00916CD0, io_setloc)
	 *
	 * What it does:
	 * Applies/query one locale category from optional arg-2 selector and pushes
	 * the CRT `setlocale` result string.
	 */
	int io_setloc(lua_State* const state)
	{
		const char* const locale = lua_tostring(state, 1);
		const char* const categoryName = luaL_optlstring(state, 2, "all", nullptr);
		const int categoryIndex = luaL_findstring(categoryName, kLuaLocaleCategoryNames);

		if (locale == nullptr) {
			if (lua_type(state, 1) > LUA_TNONE) {
				luaL_argerror(state, 1, "string expected");
			}
		}
		if (categoryIndex == -1) {
			luaL_argerror(state, 2, "invalid option");
		}

		const char* const localeResult = std::setlocale(kLuaLocaleCategories[categoryIndex], locale);
		lua_pushstring(state, localeResult);
		return 1;
	}

	/**
	 * Address: 0x00917350 (FUN_00917350, lua::io_tostring)
	 *
	 * What it does:
	 * Formats one wrapped file userdata lane as `file (%p)` when open, or
	 * `file (closed)` when the underlying stream lane is null.
	 */
	int LuaIoToString(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		char description[128]{};
		if (wrapFile->stream != nullptr) {
			std::sprintf(description, "%p", static_cast<void*>(wrapFile));
		} else {
			std::strcpy(description, "closed");
		}

		lua_pushfstring(state, "file (%s)", description);
		return 1;
	}

	int PushIoOpenFailure(lua_State* const state, const char* const path)
	{
		lua_pushnil(state);
		const int errorCode = *_errno();
		const char* const errorText = std::strerror(errorCode);
		if (path != nullptr) {
			lua_pushfstring(state, "%s: %s", path, errorText);
		} else {
			lua_pushfstring(state, "%s", errorText);
		}
		lua_pushnumber(state, static_cast<lua_Number>(*_errno()));
		return 3;
	}

	/**
	 * Address: 0x00915EE0 (FUN_00915EE0, pushresult)
	 *
	 * What it does:
	 * Pushes io-library success boolean for successful operations, or the
	 * standard `(nil, strerror(errno), errno)` tuple (with optional path prefix)
	 * for failures.
	 */
	int pushresult(const char* const path, lua_State* const state, const bool success)
	{
		if (success) {
			lua_pushboolean(state, 1);
			return 1;
		}

		return PushIoOpenFailure(state, path);
	}

	/**
	 * Address: 0x009173E0 (FUN_009173E0, lua::io_open)
	 *
	 * What it does:
	 * Opens one file path with optional mode and returns either wrapped file
	 * userdata or the standard Lua io error tuple.
	 */
	int LuaIoOpen(lua_State* const state)
	{
		const char* const filePath = luaL_checklstring(state, 1, nullptr);
		const char* const mode = luaL_optlstring(state, 2, "r", nullptr);

		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = std::fopen(filePath, mode);
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		return PushIoOpenFailure(state, filePath);
	}

	/**
	 * Address: 0x00917490 (FUN_00917490, lua::io_popen)
	 *
	 * What it does:
	 * Opens one process pipe with optional mode and returns either wrapped file
	 * userdata or the standard Lua io error tuple.
	 */
	int LuaIoPopen(lua_State* const state)
	{
		const char* const command = luaL_checklstring(state, 1, nullptr);
		const char* const mode = luaL_optlstring(state, 2, "r", nullptr);

		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = ::_popen(command, mode);
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		return PushIoOpenFailure(state, command);
	}

	/**
	 * Address: 0x00916500 (FUN_00916500, io_execute)
	 *
	 * What it does:
	 * Executes one shell command from arg-1 and returns process exit code as a
	 * single Lua numeric result.
	 */
	int io_execute(lua_State* const state)
	{
		const char* const command = luaL_checklstring(state, 1, nullptr);
		const int resultCode = std::system(command);
		lua_pushnumber(state, static_cast<lua_Number>(resultCode));
		return 1;
	}

	/**
	 * Address: 0x00916540 (FUN_00916540, io_remove)
	 *
	 * What it does:
	 * Removes one filesystem path from Lua arg-1 and returns standard
	 * io-library success/error tuple via `pushresult`.
	 */
	int io_remove(lua_State* const state)
	{
		const char* const path = luaL_checklstring(state, 1, nullptr);
		const int removeResult = std::remove(path);
		return pushresult(path, state, removeResult == 0);
	}

	/**
	 * Address: 0x00916570 (FUN_00916570, io_rename)
	 *
	 * What it does:
	 * Renames one filesystem path pair from Lua args 1/2 and returns standard
	 * io-library success/error tuple via `pushresult`.
	 */
	int io_rename(lua_State* const state)
	{
		const char* const sourcePath = luaL_checklstring(state, 1, nullptr);
		const char* const destinationPath = luaL_checklstring(state, 2, nullptr);
		const int renameResult = std::rename(sourcePath, destinationPath);
		return pushresult(sourcePath, state, renameResult == 0);
	}

	/**
	 * Address: 0x009165B0 (FUN_009165B0, io_tmpname)
	 *
	 * What it does:
	 * Produces one temporary filename string through `tmpnam`; raises Lua error
	 * when the CRT cannot provide a unique path.
	 */
	int io_tmpname(lua_State* const state)
	{
		char tempName[16]{};
		if (std::tmpnam(tempName) != tempName) {
			return luaL_error(state, "unable to generate a unique filename in `tmpname'");
		}

		lua_pushstring(state, tempName);
		return 1;
	}

	/**
	 * Address: 0x00916600 (FUN_00916600, io_getenv)
	 *
	 * What it does:
	 * Reads one environment-variable name from arg-1, pushes its value as Lua
	 * string (or nil when not found), and returns one result.
	 */
	int io_getenv(lua_State* const state)
	{
		const char* const variableName = luaL_checklstring(state, 1, nullptr);
		const char* const variableValue = std::getenv(variableName);
		lua_pushstring(state, variableValue);
		return 1;
	}

	/**
	 * Address: 0x00916630 (FUN_00916630, io_clock)
	 *
	 * What it does:
	 * Samples CRT `clock()` ticks and returns elapsed seconds as one Lua number.
	 */
	int io_clock(lua_State* const state)
	{
		const int tickCount = std::clock();
		lua_pushnumber(state, static_cast<lua_Number>(static_cast<float>(tickCount) * 0.001f));
		return 1;
	}

	/**
	 * Address: 0x00916D60 (FUN_00916D60, io_exit)
	 *
	 * What it does:
	 * Reads one optional numeric exit code from arg-1 (default zero), converts
	 * it to process exit status, and terminates the host process.
	 */
	[[noreturn]] int io_exit(lua_State* const state)
	{
		const int exitCode = static_cast<int>(luaL_optnumber(state, 1, 0.0f));
		std::exit(exitCode);
	}

	/**
	 * Address: 0x009163C0 (FUN_009163C0, g_write)
	 *
	 * What it does:
	 * Writes Lua string/number arguments to one `FILE*` lane and returns
	 * standard io-library success or `(nil, strerror(errno), errno)` tuple.
	 */
	int LuaWriteToFile(
		int firstArgumentIndex,
		lua_State* const state,
		std::FILE* const stream
	)
	{
		int remainingArguments = lua_gettop(state) - 1;
		int writeSucceeded = 1;
		if (remainingArguments == 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		do {
			--remainingArguments;
			if (lua_type(state, firstArgumentIndex) == LUA_TNUMBER) {
				if (writeSucceeded != 0) {
					const double value = lua_tonumber(state, firstArgumentIndex);
					writeSucceeded = std::fprintf(stream, "%.14g", value) > 0 ? 1 : 0;
				}
			} else if (lua_type(state, firstArgumentIndex) == LUA_TSTRING) {
				std::size_t elementCount = 0u;
				const char* const text = luaL_checklstring(state, firstArgumentIndex, &elementCount);
				if (writeSucceeded == 0 || std::fwrite(text, 1u, elementCount, stream) != elementCount) {
					writeSucceeded = 0;
				} else {
					writeSucceeded = 1;
				}
			}

			++firstArgumentIndex;
		} while (remainingArguments != 0);

		if (writeSucceeded != 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(*_errno()));
		return 3;
	}

	/**
	 * Address: 0x00917600 (FUN_00917600, g_iofile)
	 *
	 * What it does:
	 * Updates global io default handle (`_input`/`_output`) from path-or-file
	 * arg-1 and returns the resolved current default handle.
	 */
	int LuaIoFile(lua_State* const state, const char* const globalKey, const char* const mode)
	{
		if (lua_type(state, 1) > LUA_TNONE) {
			const char* const argument = lua_tostring(state, 1);
			lua_pushstring(state, globalKey);

			if (argument != nullptr) {
				WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
				wrapFile->stream = std::fopen(argument, mode);
				if (wrapFile->stream == nullptr) {
					const int errorCode = *_errno();
					lua_pushfstring(state, "%s: %s", argument, std::strerror(errorCode));
					luaL_argerror(state, 1, lua_tostring(state, -1));
				}
			} else {
				(void)ToFile(state, 1);
				lua_pushvalue(state, 1);
			}

			lua_rawset(state, LUA_ENVIRONINDEX);
		}

		lua_pushstring(state, globalKey);
		lua_rawget(state, LUA_ENVIRONINDEX);
		return 1;
	}

	/**
	 * Address: 0x009176F0 (FUN_009176F0, lua::io_input)
	 *
	 * What it does:
	 * Gets/sets Lua io default `_input` handle lane via `g_iofile`.
	 */
	int LuaIoInput(lua_State* const state)
	{
		return LuaIoFile(state, "_input", "r");
	}

	/**
	 * Address: 0x00917710 (FUN_00917710, lua::io_output)
	 *
	 * What it does:
	 * Gets/sets Lua io default `_output` handle lane via `g_iofile`.
	 */
	int LuaIoOutput(lua_State* const state)
	{
		return LuaIoFile(state, "_output", "w");
	}

	/**
	 * Address: 0x00917730 (FUN_00917730, lua::io_read)
	 *
	 * What it does:
	 * Reads from global `_input` file handle using Lua io option semantics.
	 */
	int LuaIoRead(lua_State* const state)
	{
		std::FILE* const stream = GetIoFileFromGlobal(state, "_input");
		return LuaReadFromFile(stream, state, 1);
	}

	/**
	 * Address: 0x00917790 (FUN_00917790, lua::f_read)
	 *
	 * What it does:
	 * Reads from userdata-bound file handle using Lua io option semantics.
	 */
	int LuaFileRead(lua_State* const state)
	{
		return LuaReadFromFile(ToFile(state, 1), state, 2);
	}

	/**
	 * `setfield`, likewise inlined at every use.
	 *
	 * Writes one integer field into the date table being built on the stack
	 * top. Numbers go out as this fork's float lua_Number.
	 */
	void SetDateTableField(lua_State* const state, const char* const key, const int value)
	{
		lua_pushstring(state, key);
		lua_pushnumber(state, static_cast<lua_Number>(value));
		lua_rawset(state, -3);
	}

	/**
	 * Address: 0x00916740 (FUN_00916740, lua::os_date)
	 *
	 * IDA signature:
	 * int __cdecl io_date(lua_State *L);
	 *
	 * What it does:
	 * Lua `os.date([format [, time]])`. Formats a time - the current one
	 * unless given - through strftime, defaulting to "%c". A leading `!` asks
	 * for UTC and is stripped before the format is used. The format "*t"
	 * instead returns the broken-down table that os.time reads back, with
	 * month, weekday and yearday moved to Lua's 1-based counting and the year
	 * made absolute. A time the C library will not break down comes back as
	 * nil, and a result that will not fit 256 bytes raises.
	 */
	int LuaOsDate(lua_State* const state)
	{
		const char* format = luaL_optlstring(state, 1, "%c", nullptr);

		__time64_t when = static_cast<__time64_t>(luaL_optnumber(state, 2, static_cast<lua_Number>(-1)));
		if (when == static_cast<__time64_t>(-1)) {
			when = _time64(nullptr);
		}

		std::tm* brokenDown = nullptr;
		if (*format == '!') {
			brokenDown = _gmtime64(&when);
			++format;
		} else {
			brokenDown = _localtime64(&when);
		}

		if (brokenDown == nullptr) {
			lua_pushnil(state);
			return 1;
		}

		if (std::strcmp(format, "*t") == 0) {
			lua_newtable(state);
			SetDateTableField(state, "sec", brokenDown->tm_sec);
			SetDateTableField(state, "min", brokenDown->tm_min);
			SetDateTableField(state, "hour", brokenDown->tm_hour);
			SetDateTableField(state, "day", brokenDown->tm_mday);
			SetDateTableField(state, "month", brokenDown->tm_mon + 1);
			SetDateTableField(state, "year", brokenDown->tm_year + 1900);
			SetDateTableField(state, "wday", brokenDown->tm_wday + 1);
			SetDateTableField(state, "yday", brokenDown->tm_yday + 1);
			lua_pushstring(state, "isdst");
			lua_pushboolean(state, brokenDown->tm_isdst);
			lua_rawset(state, -3);
			return 1;
		}

		char formatted[256];
		if (std::strftime(formatted, sizeof(formatted), format, brokenDown) == 0) {
			luaL_error(state, "`date' format too long");
		}

		lua_pushstring(state, formatted);
		return 1;
	}

	/**
	 * `getfield`, inlined at every use in the binary.
	 *
	 * Reads one integer field off the date table on the stack top. A negative
	 * default marks the field as required, which is how day, month and year
	 * are spelled: absent, they raise rather than defaulting.
	 */
	int GetDateTableField(lua_State* const state, const char* const key, const int defaultValue)
	{
		lua_pushstring(state, key);
		lua_gettable(state, -2);

		int value = defaultValue;
		if (lua_isnumber(state, -1)) {
			value = static_cast<int>(lua_tonumber(state, -1));
		} else if (defaultValue < 0) {
			luaL_error(state, "field `%s' missing in date table", key);
		}

		lua_settop(state, -2);
		return value;
	}

	/**
	 * Address: 0x009169E0 (FUN_009169E0, lua::os_time)
	 *
	 * IDA signature:
	 * int __cdecl io_time(lua_State *L);
	 *
	 * What it does:
	 * Lua `os.time([table])`. With no table it answers the current time. With
	 * one it reads the broken-down fields back out and runs them through
	 * mktime: seconds and minutes default to zero, the hour to noon, and day,
	 * month and year are required. Month and year carry the C offsets - one
	 * less, and 1900 less - and isdst is read as a plain truth value. A time
	 * mktime cannot represent comes back as nil rather than an error.
	 */
	int LuaOsTime(lua_State* const state)
	{
		__time64_t when = 0;

		if (lua_type(state, 1) <= LUA_TNIL) {
			when = _time64(nullptr);
		} else {
			luaL_checktype(state, 1, LUA_TTABLE);
			lua_settop(state, 1);

			std::tm brokenDown{};
			brokenDown.tm_sec = GetDateTableField(state, "sec", 0);
			brokenDown.tm_min = GetDateTableField(state, "min", 0);
			brokenDown.tm_hour = GetDateTableField(state, "hour", 12);
			brokenDown.tm_mday = GetDateTableField(state, "day", -1);
			brokenDown.tm_mon = GetDateTableField(state, "month", -1) - 1;
			brokenDown.tm_year = GetDateTableField(state, "year", -1) - 1900;

			lua_pushstring(state, "isdst");
			lua_gettable(state, -2);
			brokenDown.tm_isdst = lua_toboolean(state, -1);
			lua_settop(state, -2);

			when = _mktime64(&brokenDown);
			if (when == static_cast<__time64_t>(-1)) {
				lua_pushnil(state);
				return 1;
			}
		}

		lua_pushnumber(state, static_cast<lua_Number>(static_cast<double>(when)));
		return 1;
	}

	/**
	 * Address: 0x00917E40 (FUN_00917E40, lua::io_lines)
	 *
	 * IDA signature:
	 * int __cdecl lua::io_lines(lua_State *L);
	 *
	 * What it does:
	 * Lua `io.lines([filename])`. Given a filename it opens that file for
	 * reading and hands back an iterator closed over three upvalues - the
	 * "FILE*" metatable out of the registry, the new file userdata, and a
	 * true flag marking the file as one the iterator owns and should close
	 * when it runs out. A failed open is reported against argument 1 rather
	 * than as a return value, so the caller sees the CRT text. Given nothing
	 * it iterates the file bound to the global `_input` instead, which is
	 * the shared path with `file:lines()`.
	 */
	int LuaIoLines(lua_State* const state)
	{
		if (lua_type(state, 1) <= LUA_TNIL) {
			lua_pushstring(state, "_input");
			lua_rawget(state, LUA_GLOBALSINDEX);
			return LuaAuxLines(state);
		}

		const char* const fileName = luaL_checklstring(state, 1, nullptr);
		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = std::fopen(fileName, "r");
		if (wrapFile->stream == nullptr) {
			luaL_argerror(state, 1, std::strerror(errno));
		}

		const int fileIndex = lua_gettop(state);
		lua_pushlstring(state, "FILE*", 5u);
		lua_rawget(state, LUA_REGISTRYINDEX);
		lua_pushvalue(state, fileIndex);
		lua_pushboolean(state, 1);
		lua_pushcclosure(state, LuaIoReadline, 3);
		return 1;
	}

	/**
	 * Address: 0x00917A50 (FUN_00917A50, lua::io_flush)
	 *
	 * IDA signature:
	 * int __cdecl lua::io_flush(lua_State *L);
	 *
	 * What it does:
	 * Lua `io.flush()`. Flushes the file currently bound to the global
	 * `_output`, raising the closed-file error when that handle has no stream,
	 * and answers with the io library's usual pair of shapes: `true` when the
	 * flush succeeded, or the `(nil, strerror(errno), errno)` tuple when it did
	 * not. No path is named in the failure, so the message carries only the
	 * CRT's own text.
	 */
	int LuaIoFlush(lua_State* const state)
	{
		std::FILE* const stream = GetIoFileFromGlobal(state, "_output");
		return pushresult(nullptr, state, std::fflush(stream) == 0);
	}

	/**
	 * Address: 0x00917880 (FUN_00917880, lua::io_write)
	 *
	 * What it does:
	 * Writes Lua args to global `_output` file handle with io tuple semantics.
	 */
	int LuaIoWrite(lua_State* const state)
	{
		std::FILE* const stream = GetIoFileFromGlobal(state, "_output");
		return LuaWriteToFile(1, state, stream);
	}

	/**
	 * Address: 0x009178F0 (FUN_009178F0, lua::f_write)
	 *
	 * What it does:
	 * Writes Lua args to userdata-bound file handle with io tuple semantics.
	 */
	int LuaFileWrite(lua_State* const state)
	{
		return LuaWriteToFile(2, state, ToFile(state, 1));
	}

	constexpr int kLuaFileSeekModes[] = {SEEK_SET, SEEK_CUR, SEEK_END};

	constexpr const char* const kLuaFileSeekModeNames[] = {
		"set",
		"cur",
		"end",
		nullptr
	};

	/**
	 * Address: 0x00917940 (FUN_00917940, lua::f_seek)
	 *
	 * IDA signature:
	 * int __cdecl lua::f_seek(lua_State *L);
	 *
	 * What it does:
	 * Lua `file:seek([whence [, offset]])`. Resolves the wrapped file userdata
	 * (raising the closed-file error when its stream lane is null), maps the
	 * optional whence selector (`"set"`/`"cur"`/`"end"`, defaulting to `"cur"`)
	 * onto the CRT `SEEK_*` constants, and seeks by the optional offset
	 * (defaulting to 0). On success it pushes the new `ftell` position and
	 * returns 1; on failure it pushes the inline `pushresult` failure tuple
	 * (nil, `strerror(errno)`, errno) and returns 3.
	 */
	int LuaFileSeek(lua_State* const state)
	{
		std::FILE* const stream = ToFile(state, 1);
		const char* const whenceName = luaL_optlstring(state, 2, "cur", nullptr);
		const int whenceIndex = luaL_findstring(whenceName, kLuaFileSeekModeNames);
		const long offset = static_cast<long>(luaL_optnumber(state, 3, 0.0f));

		if (whenceIndex == -1) {
			luaL_argerror(state, 2, "invalid mode");
		}

		if (std::fseek(stream, offset, kLuaFileSeekModes[whenceIndex]) != 0) {
			lua_pushnil(state);
			const int errorCode = *_errno();
			lua_pushfstring(state, "%s", std::strerror(errorCode));
			lua_pushnumber(state, static_cast<lua_Number>(*_errno()));
			return 3;
		}

		lua_pushnumber(state, static_cast<lua_Number>(static_cast<int>(std::ftell(stream))));
		return 1;
	}

	/**
	 * Address: 0x00D45C80 (`flib` registration table)
	 *
	 * What it does:
	 * The `liolib` file-method registration table: the methods installed onto
	 * the wrapped-`FILE` userdata metatable. Reconstructed from the binary's
	 * `luaL_reg` array, whose function lanes sit at 0x00D45C84 (`f_flush`),
	 * 0x00D45C8C (`f_read`), 0x00D45C94 (`aux_lines`), 0x00D45C9C (`f_seek`),
	 * 0x00D45CA4 (`f_write`), 0x00D45CAC (`io_close`) and 0x00D45CB4
	 * (`io_tostring`) -- seven consecutive 8-byte entries, so this build carries
	 * no `__gc` lane between `close` and `__tostring`.
	 *
	 * This table is the source-level invocation for all seven file methods:
	 * `luaL_openlib` installs them by address from here.
	 */
	const luaL_reg kLuaFileMethods[] = {
		{"flush", &LuaFileFlush},
		{"read", &LuaFileRead},
		{"lines", &LuaAuxLines},
		{"seek", &LuaFileSeek},
		{"write", &LuaFileWrite},
		{"close", &LuaIoClose},
		{"__tostring", &LuaIoToString},
		{nullptr, nullptr}
	};

	/**
	 * Publishes the recovered `flib` file-method table so the registration lane
	 * stays addressable from this TU, mirroring how the binary's `liolib`
	 * open path hands the array to `luaL_openlib`.
	 */
	[[nodiscard]] const luaL_reg* ResolveLuaFileMethodRegistrations() noexcept
	{
		return kLuaFileMethods;
	}

	/**
	 * The `iolib` registration table, head at 0x00D45C20.
	 *
	 * Order is the binary's. `dir` is this engine's own addition - stock Lua
	 * 5.0 has no such entry - and sits last, after the ten it kept.
	 */
	const luaL_reg kLuaIoLibrary[] = {
		{"input", &LuaIoInput},
		{"output", &LuaIoOutput},
		{"lines", &LuaIoLines},
		{"close", &LuaIoClose},
		{"flush", &LuaIoFlush},
		{"open", &LuaIoOpen},
		{"popen", &LuaIoPopen},
		{"read", &LuaIoRead},
		{"tmpfile", &LuaIoTmpFile},
		{"write", &LuaIoWrite},
		{"dir", &LuaIoDir},
		{nullptr, nullptr}
	};

	/**
	 * The `syslib` registration table, head at 0x00D45CC0.
	 *
	 * Registered under the name "os" - the libname the decompiler shows as a
	 * pointer at 0x00D45F28 is not one: those four bytes are the string
	 * itself.
	 */
	const luaL_reg kLuaOsLibrary[] = {
		{"clock", &io_clock},
		{"date", &LuaOsDate},
		{"difftime", &io_difftime},
		{"execute", &io_execute},
		{"exit", &io_exit},
		{"getenv", &io_getenv},
		{"remove", &io_remove},
		{"rename", &io_rename},
		{"setlocale", &io_setloc},
		{"time", &LuaOsTime},
		{"tmpname", &io_tmpname},
		{nullptr, nullptr}
	};

	/**
	 * Address: 0x00917BC0 (FUN_00917BC0, luaopen_io)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_io(lua_State *L);
	 *
	 * What it does:
	 * Opens both libraries this Lua exposes over files - "os" from syslib and
	 * "io" from iolib - and builds the shared "FILE*" metatable between them.
	 *
	 * The metatable is its own `__index`, so file methods resolve through it,
	 * and the file-method table goes in with a null library name so it lands
	 * on that metatable rather than a global. The io table is then opened with
	 * one upvalue - the metatable itself - which is how its functions reach
	 * the type without a registry lookup on every call.
	 *
	 * Finally the three standard streams are wrapped and installed: stdin and
	 * stdout are also bound to the globals `_input` and `_output`, which is
	 * what io.read, io.write and io.flush answer to, while stderr is only
	 * reachable as io.stderr. None of the three is marked closeable, so
	 * file:close() on them cannot take the process's own streams down.
	 */
	int LuaOpenIo(lua_State* const state)
	{
		luaL_openlib(state, "os", kLuaOsLibrary, 0);

		luaL_newmetatable(state, "FILE*");
		lua_pushlstring(state, "__index", 7u);
		lua_pushvalue(state, -2);
		lua_rawset(state, -3);
		luaL_openlib(state, nullptr, kLuaFileMethods, 0);

		lua_pushvalue(state, -1);
		luaL_openlib(state, "io", kLuaIoLibrary, 1);

		lua_pushstring(state, "stdin");
		NewFileUserdata(state, false)->stream = stdin;
		lua_pushstring(state, "_input");
		lua_pushvalue(state, -2);
		lua_settable(state, -6);
		lua_settable(state, -3);

		lua_pushstring(state, "stdout");
		NewFileUserdata(state, false)->stream = stdout;
		lua_pushstring(state, "_output");
		lua_pushvalue(state, -2);
		lua_settable(state, -6);
		lua_settable(state, -3);

		lua_pushstring(state, "stderr");
		NewFileUserdata(state, false)->stream = stderr;
		lua_settable(state, -3);

		return 1;
	}

	int ReadZioByte(LuaZioRuntimeView* const stream)
	{
		const int available = stream->remainingBytes;
		stream->remainingBytes = available - 1;
		if (available <= 0) {
			return luaZ_fill(stream);
		}

		const unsigned char value = static_cast<unsigned char>(*stream->cursor);
		++stream->cursor;
		return static_cast<int>(value);
	}

	/**
	 * Address: 0x009285C0 (FUN_009285C0, LoadBlock)
	 *
	 * What it does:
	 * Loads one raw byte block from Lua chunk stream; when byte-swap mode is
	 * enabled it reads byte-by-byte in reverse order, otherwise bulk-reads.
	 */
	void LuaLoadBlock(
		const size_t size,
		void* const destination,
		LuaLoadStateRuntimeView* const loadState
	)
	{
		if (loadState->swapBytes != 0) {
			auto* writeCursor = static_cast<std::uint8_t*>(destination) + size;
			for (size_t index = 0; index < size; ++index) {
				--writeCursor;
				const int byteValue = ReadZioByte(loadState->stream);
				if (byteValue == -1) {
					luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
				}
				*writeCursor = static_cast<std::uint8_t>(byteValue);
			}
			return;
		}

		if (luaZ_read(loadState->stream, destination, size) != 0) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x00928650 (FUN_00928650, sub_928650)
	 *
	 * What it does:
	 * Loads one element array from chunk stream; byte-swap mode reverses each
	 * element lane byte order, otherwise it bulk-reads contiguous bytes.
	 */
	void LuaLoadElementArray(
		char* const destination,
		LuaLoadStateRuntimeView* const loadState,
		int elementCount,
		const int elementSize
	)
	{
		if (loadState->swapBytes != 0) {
			if (elementCount != 0) {
				int bytesRemainingInLane = elementSize;
				char* writeCursor = destination + static_cast<std::ptrdiff_t>(elementSize) - 1;
				char* laneTail = writeCursor;
				do {
					--elementCount;
					if (bytesRemainingInLane != 0) {
						do {
							--bytesRemainingInLane;
							const int byteValue = ReadZioByte(loadState->stream);
							if (byteValue == -1) {
								luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
							}
							*writeCursor-- = static_cast<char>(byteValue);
						} while (bytesRemainingInLane != 0);
						bytesRemainingInLane = elementSize;
					}

					writeCursor = laneTail + bytesRemainingInLane;
					laneTail += bytesRemainingInLane;
				} while (elementCount != 0);
			}
			return;
		}

		const int byteCount = elementSize * elementCount;
		if (luaZ_read(loadState->stream, destination, static_cast<size_t>(byteCount)) != 0) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x009287A0 (FUN_009287A0, sub_9287A0)
	 *
	 * What it does:
	 * Reads one size-prefixed Lua chunk string payload and interns it (without
	 * trailing NUL) into the owner Lua state string table.
	 */
	[[nodiscard]] TString* LuaLoadTString(LuaLoadStateRuntimeView* const loadState)
	{
		std::uint32_t byteCount = 0u;
		LuaLoadBlock(4u, &byteCount, loadState);
		if (byteCount == 0u) {
			return nullptr;
		}

		char* const scratch = luaZ_openspace(loadState->state, loadState->scratchBuffer, byteCount);
		if (luaZ_read(loadState->stream, scratch, byteCount) != 0) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}

		return luaS_newlstr(loadState->state, scratch, static_cast<size_t>(byteCount - 1u));
	}

	/**
	 * Address: 0x00928810 (FUN_00928810, sub_928810)
	 *
	 * What it does:
	 * Reads proto bytecode instruction count, allocates `Proto::code`, and
	 * loads one contiguous instruction vector from chunk stream.
	 */
	void LuaLoadProtoCode(LuaLoadStateRuntimeView* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->code = static_cast<Instruction*>(luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(4 * count)));
		proto->sizecode = count;
		LuaLoadElementArray(reinterpret_cast<char*>(proto->code), loadState, count, 4);
	}

	/**
	 * Address: 0x00928960 (FUN_00928960, sub_928960)
	 *
	 * What it does:
	 * Reads proto line-info count, allocates `Proto::lineinfo`, and loads one
	 * contiguous source-line map vector from chunk stream.
	 */
	void LuaLoadProtoLineInfo(LuaLoadStateRuntimeView* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->lineinfo = static_cast<int*>(luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(4 * count)));
		proto->sizelineinfo = count;
		LuaLoadElementArray(reinterpret_cast<char*>(proto->lineinfo), loadState, count, 4);
	}

	[[nodiscard]] int LuaReadChunkByteOrThrow(LuaLoadStateRuntimeView* const loadState)
	{
		const int byteValue = ReadZioByte(loadState->stream);
		if (byteValue == -1) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}
		return byteValue;
	}

	// The recursive nested-proto loader has external linkage (defined in the
	// LuaPlus block below so LuaParser.cpp's luaU_undump can call it). Re-expose
	// it here so the constant/child-proto reader can recurse by simple name.
	using LuaPlus::LuaLoadProtoObject;

	/**
	 * Address: 0x00928870 (FUN_00928870, sub_928870)
	 *
	 * What it does:
	 * Reads local-variable debug lane count and fills one `Proto::locvars`
	 * array with `{name,startpc,endpc}` entries.
	 */
	void LuaLoadProtoLocalVariableDebugInfo(
		LuaLoadStateRuntimeView* const loadState,
		Proto* const proto
	)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->locvars = static_cast<LocVar*>(
			luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(static_cast<int>(sizeof(LocVar)) * count))
		);
		proto->sizelocvars = count;

		if (count <= 0) {
			return;
		}

		for (int index = 0; index < count; ++index) {
			LocVar& lane = proto->locvars[index];
			lane.varname = LuaLoadTString(loadState);

			int startPc = 0;
			LuaLoadBlock(4u, &startPc, loadState);
			if (startPc < 0) {
				luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
			}
			lane.startpc = startPc;

			int endPc = 0;
			LuaLoadBlock(4u, &endPc, loadState);
			if (endPc < 0) {
				luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
			}
			lane.endpc = endPc;
		}
	}

	/**
	 * Address: 0x009289C0 (FUN_009289C0, sub_9289C0)
	 *
	 * What it does:
	 * Reads upvalue-name count, validates it against `Proto::nups`, and fills
	 * one `Proto::upvalues` string-pointer lane array.
	 */
	void LuaLoadProtoUpvalueNames(LuaLoadStateRuntimeView* const loadState, Proto* const proto)
	{
		int count = 0;
		LuaLoadBlock(4u, &count, loadState);
		if (count < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		if (count != 0 && count != static_cast<int>(proto->nups)) {
			luaG_runerror(
				loadState->state,
				"bad nupvalues in %s: read %d; expected %d",
				loadState->chunkName,
				count,
				static_cast<int>(proto->nups)
			);
		}

		proto->upvalues = static_cast<TString**>(
			luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(4 * count))
		);
		proto->sizeupvalues = count;

		for (int index = 0; index < count; ++index) {
			proto->upvalues[index] = LuaLoadTString(loadState);
		}
	}

	/**
	 * Address: 0x00928A60 (FUN_00928A60, sub_928A60)
	 *
	 * What it does:
	 * Loads one proto constant table lane (`Proto::k`) followed by nested child
	 * proto pointers (`Proto::p`) from the chunk stream.
	 */
	void LuaLoadProtoConstantsAndNestedProtos(
		LuaLoadStateRuntimeView* const loadState,
		Proto* const proto
	)
	{
		int constantCount = 0;
		LuaLoadBlock(4u, &constantCount, loadState);
		if (constantCount < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->k = static_cast<LuaPlus::TObject*>(
			luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(8 * constantCount))
		);
		proto->sizek = constantCount;

		for (int index = 0; index < constantCount; ++index) {
			LuaPlus::TObject& constantLane = proto->k[index];
			const int constantType = LuaReadChunkByteOrThrow(loadState);
			const unsigned int typeTag = static_cast<unsigned int>(static_cast<unsigned char>(constantType));

			if (typeTag == LUA_TNIL) {
				constantLane.tt = LUA_TNIL;
				continue;
			}

			if (typeTag == LUA_TNUMBER) {
				float numberValue = 0.0f;
				LuaLoadBlock(4u, &numberValue, loadState);
				constantLane.tt = LUA_TNUMBER;
				constantLane.value.n = numberValue;
				continue;
			}

			if (typeTag == LUA_TSTRING) {
				TString* const stringValue = LuaLoadTString(loadState);
				constantLane.tt = static_cast<int>(stringValue->tt);
				constantLane.value.p = stringValue;
				continue;
			}

			luaG_runerror(loadState->state, "bad constant type (%d) in %s", static_cast<int>(typeTag), loadState->chunkName);
		}

		int childCount = 0;
		LuaLoadBlock(4u, &childCount, loadState);
		if (childCount < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}

		proto->p = static_cast<Proto**>(luaM_realloc(loadState->state, nullptr, 0u, static_cast<lu_mem>(4 * childCount)));
		proto->sizep = childCount;

		for (int index = 0; index < childCount; ++index) {
			proto->p[index] = LuaLoadProtoObject(loadState, proto->source);
		}
	}

	/**
	 * Address: 0x0090A780 (FUN_0090A780, LuaPlusGCFunction)
	 *
	 * What it does:
	 * Marks root-state live LuaObject payload GC nodes during Lua GC callback,
	 * skipping already-marked or non-GC-tag payload lanes.
	 */
	void LuaPlusGCFunction(GCState* const gcState)
	{
		if (gcState == nullptr || gcState->L == nullptr) {
			return;
		}

		auto* const state = static_cast<LuaState*>(gcState->L->stateUserData);
		if (state == nullptr || state != state->m_rootState) {
			return;
		}

		LuaObject* node = state->m_headObject.m_next;
		LuaObject* const tail = reinterpret_cast<LuaObject*>(&state->m_tailObject);
		while (node != tail) {
			if (node->m_object.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(node->m_object.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(gcState, object);
				}
			}
			node = node->m_next;
		}
	}

	/**
	 * Address: 0x009151E0 (FUN_009151E0, reallymarkobject)
	 *
	 * What it does:
	 * Marks one collectable GC object and links it into the appropriate gray
	 * propagation lane.
	 */
	extern "C" void reallymarkobject(GCState* const st, GCObject* const object)
	{
		GCObject* current = object;
		current->gch.marked |= 1u;

		while (true) {
			switch (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE)) {
			case 0:
				current->h.gclist = st->tmark;
				st->tmark = current;
				return;

			case 1:
			case 2:
				current->cl.c.gclist = st->tmark;
				st->tmark = current;
				return;

			case 3:
				current = reinterpret_cast<GCObject*>(current->u.metatable);
				if (current != nullptr && (current->gch.marked & 0x11u) == 0u) {
					current->gch.marked |= 1u;
					if (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE) <= 5u) {
						continue;
					}
				}
				return;

			case 4:
				current->th.gclist = st->tmark;
				st->tmark = current;
				return;

			case 5:
				current->p.gclist = st->tmark;
				st->tmark = current;
				return;

			default:
				return;
			}
		}
	}

	/**
	 * Address: 0x00915320 (FUN_00915320, traversetable)
	 *
	 * What it does:
	 * Marks the metatable, resolves weak-table mode, and traverses array/hash
	 * lanes while preserving weak key/value semantics.
	 */
	extern "C" void traversetable(GCState* const st, Table* const h)
	{
		// __mode is slot 2, not 3: luaT_init (FUN_009283C0) interns
		// luaT_eventname (0x00D47508) in the order __index, __newindex,
		// __mode, __eq, ..., and traversetable's own call site is
		// "mov edx,[ecx+64h]" / "push 2" - byte offset 0x64 into tmname at
		// 0x5C. The old value read the same byte offset only because tmname
		// was mismodelled as starting at 0x58.
		constexpr int kLuaTagMethodMode = 2;

		auto markCollectable = [st](TObject& slot) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		};

		auto condMarkCollectable = [&markCollectable](TObject& slot, const bool shouldMark) {
			if (shouldMark) {
				markCollectable(slot);
			}
		};

		Table* const metatable = h->metatable;
		bool weakkey = false;
		bool weakvalue = false;
		if ((metatable->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(metatable));
		}

		if ((metatable->flags & 4) == 0) {
			const TObject* const mode = luaT_gettm(metatable, kLuaTagMethodMode, st->g->tmname[kLuaTagMethodMode]);
			if (mode != nullptr && mode->tt == LUA_TSTRING) {
				const char* const modeText = static_cast<TString*>(mode->value.p)->str;
				weakkey = std::strchr(modeText, 'k') != nullptr;
				weakvalue = std::strchr(modeText, 'v') != nullptr;
			}
		}

		if (weakkey || weakvalue) {
			h->marked &= static_cast<lu_byte>(~0x6u);
			if (weakkey) {
				h->marked |= 0x2u;
			}
			if (weakvalue) {
				h->marked |= 0x4u;
			}

			GCObject** const weaklist = weakkey ? (weakvalue ? &st->wkv : &st->wk) : &st->wv;
			h->gclist = *weaklist;
			*weaklist = reinterpret_cast<GCObject*>(h);
		}

		if (!weakvalue) {
			for (int index = h->sizearray; index != 0; --index) {
				markCollectable(h->array[index - 1]);
			}
		}

		for (int index = 1 << h->lsizenode; index != 0; --index) {
			Node* const node = &h->node[index - 1];
			if (node->i_val.tt != LUA_TNIL) {
				condMarkCollectable(node->i_key, !weakkey);
				condMarkCollectable(node->i_val, !weakvalue);
			}
		}
	}

	/**
	 * Address: 0x009154A0 (FUN_009154A0, traverseproto)
	 *
	 * What it does:
	 * Marks one prototype's strings, upvalue names, nested protos, and local
	 * variable names.
	 */
	extern "C" void traverseproto(GCState* const st, Proto* const f)
	{
		f->source->marked |= 1u;
		for (int index = 0; index < f->sizek; ++index) {
			TObject& constant = f->k[index];
			if (constant.tt == LUA_TSTRING) {
				static_cast<TString*>(constant.value.p)->marked |= 1u;
			}
		}

		for (int index = 0; index < f->sizeupvalues; ++index) {
			f->upvalues[index]->marked |= 1u;
		}

		for (int index = 0; index < f->sizep; ++index) {
			Proto* const nested = f->p[index];
			if ((nested->marked & 0x11u) == 0u) {
				reallymarkobject(st, reinterpret_cast<GCObject*>(nested));
			}
		}

		for (int index = 0; index < f->sizelocvars; ++index) {
			f->locvars[index].varname->marked |= 1u;
		}
	}

	/**
	 * Address: 0x00915540 (FUN_00915540, traversecclosure)
	 *
	 * What it does:
	 * Marks one C closure's collectable upvalue lanes.
	 */
	extern "C" void traversecclosure(GCState* const st, CClosure* const cl)
	{
		for (int index = 0; index < cl->nupvalues; ++index) {
			TObject& upvalue = cl->upvalue[index];
			if (upvalue.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(upvalue.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}
	}

	/**
	 * Address: 0x00915580 (FUN_00915580, traverselclosure)
	 *
	 * What it does:
	 * Marks one Lua closure's environment, prototype, and nested upvalues.
	 */
	extern "C" void traverselclosure(GCState* const st, LClosure* const cl)
	{
		if (cl->g.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(cl->g.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		if (cl->p != nullptr && (cl->p->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(cl->p));
		}

		for (int index = 0; index < cl->nupvalues; ++index) {
			UpVal* const upvalue = cl->upvals[index];
			if (upvalue != nullptr && upvalue->marked == 0) {
				if (upvalue->value.tt >= LUA_TSTRING) {
					auto* const object = static_cast<GCObject*>(upvalue->value.value.p);
					if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
						reallymarkobject(st, object);
					}
				}
				upvalue->marked = 1u;
			}
		}
	}

	/**
	 * Address: 0x00915600 (FUN_00915600)
	 *
	 * What it does:
	 * Shrinks call-info and stack allocations when the live usage window is
	 * sparse enough to satisfy the legacy Lua GC compaction thresholds.
	 */
	void ShrinkThreadRuntimeStacksIfSparse(
		TObject* const liveStackLimit,
		lua_State* const state
	)
	{
		const unsigned __int16 callInfoCapacity = state->size_ci;
		if (4 * (state->ci - state->base_ci) < callInfoCapacity && callInfoCapacity > 0x10u) {
			luaD_reallocCI(state, callInfoCapacity >> 1);
		}

		const int stackCapacity = state->stacksize;
		if (4 * (liveStackLimit - state->stack) < stackCapacity && stackCapacity > 90) {
			luaD_reallocstack(state, stackCapacity / 2);
		}
	}

	/**
	 * Address: 0x00915670 (FUN_00915670, traversestack)
	 *
	 * What it does:
	 * Marks the thread global table and live stack lanes, clears the unused tail
	 * to nil, then trims overgrown stack and call-info allocations.
	 */
	extern "C" void traversestack(lua_State* const L1, GCState* const st)
	{
		if (L1->_gt.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(L1->_gt.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		CallInfo* const baseCi = L1->base_ci;
		CallInfo* const currentCi = L1->ci;
		TObject* lim = L1->top;
		for (CallInfo* ci = baseCi; ci <= currentCi; ++ci) {
			if (lim < ci->top) {
				lim = ci->top;
			}
		}

		for (TObject* object = L1->stack; object < L1->top; ++object) {
			if (object->tt >= LUA_TSTRING) {
				auto* const gcObject = static_cast<GCObject*>(object->value.p);
				if (gcObject != nullptr && (gcObject->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, gcObject);
				}
			}
		}

		for (TObject* object = L1->top; object <= lim; ++object) {
			object->tt = LUA_TNIL;
			object->value.p = nullptr;
		}

		ShrinkThreadRuntimeStacksIfSparse(lim, L1);
	}

	/**
	 * Address: 0x00915840 (FUN_00915840, cleartablekeys)
	 *
	 * What it does:
	 * Walks weak-key tables and clears hash nodes whose keys are collectable
	 * but were not marked alive in the current propagation pass.
	 */
	extern "C" void cleartablekeys(GCObject* tableList)
	{
		auto markStringKey = [](LuaPlus::TObject& keySlot) {
			if (keySlot.tt == LUA_TSTRING && keySlot.value.p != nullptr) {
				static_cast<TString*>(keySlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(table->gclist)) {
			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				LuaPlus::TObject& keySlot = node.i_key;
				markStringKey(keySlot);

				if (keySlot.tt >= LUA_TSTRING) {
					auto* const keyObject = static_cast<GCObject*>(keySlot.value.p);
					if (keyObject != nullptr && (keyObject->gch.marked & 1u) == 0u) {
						node.i_val.tt = LUA_TNIL;
						keySlot.tt = LUA_TNONE;
					}
				}
			}
		}
	}

	/**
	 * Address: 0x009158A0 (FUN_009158A0, cleartablevalues)
	 *
	 * What it does:
	 * Walks weak-value tables and clears array/hash value lanes whose
	 * collectable payloads were not marked alive in the current GC pass.
	 */
	extern "C" void cleartablevalues(GCObject* tableList)
	{
		auto markStringValue = [](LuaPlus::TObject& valueSlot) {
			if (valueSlot.tt == LUA_TSTRING && valueSlot.value.p != nullptr) {
				static_cast<TString*>(valueSlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(table->gclist)) {
			for (int arrayIndex = table->sizearray; arrayIndex != 0; --arrayIndex) {
				LuaPlus::TObject& valueSlot = table->array[arrayIndex - 1];
				markStringValue(valueSlot);
				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						valueSlot.tt = LUA_TNIL;
					}
				}
			}

			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				LuaPlus::TObject& valueSlot = node.i_val;
				markStringValue(valueSlot);

				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						const bool hasCollectableKey = node.i_key.tt >= LUA_TSTRING;
						valueSlot.tt = LUA_TNIL;
						if (hasCollectableKey) {
							node.i_key.tt = LUA_TNONE;
						}
					}
				}
			}
		}
	}

	extern "C" void freeobj(GCObject* object, lua_State* state);
	extern "C" void luaF_freeproto(lua_State* L, Proto* proto);
	extern "C" void luaF_freeclosure(lua_State* L, Closure* closure);
	extern "C" void luaE_freethread(lua_State* L, lua_State* thread);

	/**
	 * Address: 0x00915530 (lgc.c::freeobj, file-local in original Lua)
	 *
	 * What it does:
	 * Dispatches one dead GC object to its type-specific free function:
	 * `LUA_TPROTO`/`LUA_TFUNCTION`/`LUA_TTABLE`/`LUA_TTHREAD` route to the
	 * corresponding `luaF_free*` / `luaH_free` / `luaE_freethread` helper;
	 * `LUA_TUPVALUE`/`LUA_TSTRING`/`LUA_TUSERDATA` are released through
	 * `luaM_realloc(..., 0)` with the appropriate variable-length size.
	 * Recovered as a free function here because `sweeplist` (recovered above)
	 * calls it across translation-unit boundaries.
	 */
	extern "C" void freeobj(GCObject* const object, lua_State* const state)
	{
		switch (object->gch.tt) {
			case LUA_TPROTO:
				luaF_freeproto(state, reinterpret_cast<Proto*>(object));
				break;
			case LUA_TFUNCTION:
				luaF_freeclosure(state, reinterpret_cast<Closure*>(object));
				break;
			case LUA_TUPVALUE:
				(void)luaM_realloc(state, object, static_cast<lu_mem>(sizeof(UpVal)), 0u);
				break;
			case LUA_TTABLE:
				luaH_free(state, reinterpret_cast<Table*>(object));
				break;
			case LUA_TTHREAD:
				luaE_freethread(state, reinterpret_cast<lua_State*>(object));
				break;
			case LUA_TSTRING: {
				// `len + 21` in the binary (0x00915950), which is exactly what
				// `newlstr` asks for: a 20-byte header plus the NUL. Charging
				// `sizeof(TString)` instead adds the four bytes C++ pads the
				// `char str[1]` tail to, so every string free refunded four
				// bytes that were never allocated and `nblocks` drifted below
				// the true total - eventually underflowing and leaving the
				// collector running against a bogus threshold.
				const auto* const ts = reinterpret_cast<const TString*>(object);
				const lu_mem stringByteSize =
					static_cast<lu_mem>(offsetof(TString, str) + (ts->len + 1u) * sizeof(char));
				(void)luaM_realloc(state, object, stringByteSize, 0u);
				break;
			}
			case LUA_TUSERDATA: {
				// `Udata::len` carries the object's `gpg::RType*` in this fork, not a
				// byte count, so the payload size is the type's. Charging `ud->len`
				// refunded a pointer value - tens of megabytes - on every userdata
				// free, which underflowed `nblocks` and left it permanently above
				// `GCthreshold`, so `luaC_checkGC` ran a full collection on every
				// single allocation from then on. Must mirror the allocation in
				// `CreateDefaultConstructedUserdata` exactly.
				const auto* const ud = reinterpret_cast<const Udata*>(object);
				const auto* const type = reinterpret_cast<const gpg::RType*>(ud->len);
				const lu_mem udataByteSize = static_cast<lu_mem>(sizeof(Udata) + type->size_);
				(void)luaM_realloc(state, object, udataByteSize, 0u);
				break;
			}
			default:
				break;
		}
	}

	/**
	 * Address: 0x00915A00 (FUN_00915A00, sweeplist)
	 *
	 * What it does:
	 * Walks one intrusive GC list lane until `tail`, keeping live nodes in-place
	 * (while clearing their dead-white bit) and unlinking/freeing dead nodes up
	 * to `limit`, returning the reclaimed object count.
	 */
	extern "C" int sweeplist(
		GCObject** const listHeadLink,
		GCObject* const tail,
		lua_State* const state,
		const int limit
	)
	{
		GCObject** currentLink = listHeadLink;
		GCObject* current = *currentLink;
		int reclaimedCount = 0;

		while (current != tail) {
			const lu_byte markByte = current->gch.marked;
			// The whole byte, unmasked. Stock 5.0 clears the two weak-table bits
			// before this comparison, but the shipped sweeplist does not - it is
			// `mov cl, [eax+5]; movzx edx, cl; cmp edx, limit` at 0x00915A11 with
			// nothing in between. Carrying stock's mask over (as `& 0xF9`) cleared
			// bits 1 and 2, so any object marked only in those bits compared equal
			// to zero and was freed while still live.
			const int colorClass = static_cast<int>(markByte);

			if (colorClass > limit) {
				current->gch.marked = static_cast<lu_byte>(markByte & 0xFEu);
				currentLink = &current->gch.next;
			} else {
				*currentLink = current->gch.next;
				++reclaimedCount;
				freeobj(current, state);
			}

			current = *currentLink;
		}

		return reclaimedCount;
	}

	/**
	 * Address: 0x00915A50 (FUN_00915A50, sweepstrings)
	 *
	 * What it does:
	 * Sweeps every string-table bucket and decrements `nuse` by each bucket's
	 * reclaimed string count.
	 */
	void sweepstrings(lua_State* const state, const int all)
	{
		global_State* const globalState = state->l_G;
		for (int index = 0; index < globalState->strt.size; ++index) {
			globalState->strt.nuse -= sweeplist(&globalState->strt.hash[index], nullptr, state, all);
		}
	}

	/**
	 * Address: 0x00915AA0 (FUN_00915AA0, checkSizes)
	 *
	 * What it does:
	 * Shrinks oversized string/hash scratch storage and recomputes the next GC
	 * threshold after the current mark/sweep dead-memory estimate.
	 */
	void checkSizes(lua_State* const state, const size_t deadmem)
	{
		global_State* const globalState = state->l_G;
		if (globalState->strt.nuse < globalState->strt.size / 4) {
			const int stringTableSize = globalState->strt.size;
			if (stringTableSize > 64) {
				luaS_resize(state, stringTableSize / 2);
			}
		}

		if (globalState->buff.buffsize > 64u) {
			const lu_mem oldBufferSize = globalState->buff.buffsize;
			const lu_mem newBufferSize = oldBufferSize >> 1;
			globalState->buff.buffer =
				static_cast<char*>(luaM_realloc(state, globalState->buff.buffer, oldBufferSize, newBufferSize));
			globalState->buff.buffsize = newBufferSize;
		}

		const int nblocks = static_cast<int>(globalState->nblocks);
		int thresholdBase = nblocks + nblocks;
		if (nblocks >= 0x40000000) {
			thresholdBase = nblocks + 0x10000000;
		}

		const std::uint32_t adjustedThreshold =
			static_cast<std::uint32_t>(thresholdBase) - static_cast<std::uint32_t>(deadmem);
		globalState->GCthreshold = static_cast<lu_mem>(adjustedThreshold);
	}

	/**
	 * Address: 0x00915BF0 (FUN_00915BF0, markroot)
	 *
	 * What it does:
	 * Marks Lua GC roots for default metatable lanes, registry, and thread
	 * roots, then dispatches the optional engine GC callback hook.
	 */
	void markroot(GCState* const st, lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		global_State* const gcGlobals = st->g;

		if (globalState->_defaultmeta.tt >= LUA_TSTRING) {
			auto* const defaultMetaObject = static_cast<GCObject*>(globalState->_defaultmeta.value.p);
			if ((defaultMetaObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, defaultMetaObject);
			}
		}

		for (TObject& slot : globalState->_defaultmetatypes) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if ((object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}

		if (globalState->_registry.tt >= LUA_TSTRING) {
			auto* const registryObject = static_cast<GCObject*>(globalState->_registry.value.p);
			if ((registryObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, registryObject);
			}
		}

		traversestack(gcGlobals->mainthread, st);
		if (state != gcGlobals->mainthread && (state->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(state));
		}

		if (globalState->userGCFunction != nullptr) {
			st->L = gcGlobals->mainthread;
			globalState->userGCFunction(st);
		}
	}

	/**
	 * Address: 0x00915750 (FUN_00915750, propagatemarks)
	 *
	 * What it does:
	 * Drains the gray list by dispatching tables, closures, threads, and proto
	 * nodes through their specialized traversal lanes.
	 */
	extern "C" void propagatemarks(GCState* const st)
	{
		while (st->tmark != nullptr) {
			GCObject* const current = st->tmark;
			switch (current->gch.tt) {
			case LUA_TTABLE:
				st->tmark = current->h.gclist;
				traversetable(st, &current->h);
				break;

			case LUA_CFUNCTION:
				st->tmark = current->cl.c.gclist;
				traversecclosure(st, &current->cl.c);
				break;

			case LUA_TFUNCTION:
				st->tmark = current->cl.c.gclist;
				traverselclosure(st, &current->cl.l);
				break;

			case LUA_TTHREAD:
				st->tmark = current->th.gclist;
				traversestack(&current->th, st);
				if (current->th.l_G->userGCFunction != nullptr) {
					st->L = &current->th;
					current->th.l_G->userGCFunction(st);
				}
				break;

			case LUA_TPROTO:
				st->tmark = current->p.gclist;
				traverseproto(st, &current->p);
				break;

			default:
				break;
			}
		}
	}

	constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
	constexpr unsigned int kLuaOpcodeModeMask = 0x3u;
	constexpr unsigned int kLuaInstructionAFieldShift = 24u;
	constexpr unsigned int kLuaInstructionBFieldShift = 15u;
	constexpr unsigned int kLuaInstructionCFieldShift = 6u;
	constexpr unsigned int kLuaInstructionABxMask = 0x3FFFFu;
	constexpr unsigned int kLuaInstructionBOrCMask = 0x1FFu;
	constexpr int kLuaInstructionSignedBxBias = 0x1FFFF;

	constexpr unsigned char kLuaOpcodeModes[] = {
		0, 1, 0, 0, 0, 1, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
		0, 0, 2, 0, 2, 1, 1, 0, 1
	};

	constexpr const char* const kLuaOpcodeNames[] = {
		"MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL",
		"GETGLOBAL", "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE",
		"NEWTABLE", "SELF", "ADD", "SUB", "MUL",
		"DIV", "BAND", "BOR", "BSHL", "BSHR",
		"XOR", "UNM", "NOT", "CONCAT", "JMP",
		"EQ", "LT", "LE", "TEST", "CALL",
		"TAILCALL", "RETURN", "FORLOOP", "TFORLOOP", "TFORPREP",
		"SETLIST", "SETLISTO", "CLOSE", "CLOSURE"
	};
	static_assert(
		(sizeof(kLuaOpcodeModes) / sizeof(kLuaOpcodeModes[0]))
		== (sizeof(kLuaOpcodeNames) / sizeof(kLuaOpcodeNames[0])),
		"Lua opcode mode/name table sizes must match"
	);
	constexpr const char* kLuaDebugLevelOutOfRange = "level out of range";
	constexpr const char* kLuaDebugFunctionOrLevelExpected = "function or level expected";
	constexpr const char* kLuaDebugInvalidOption = "invalid option";

	/**
	 * Address: 0x009116B0 (FUN_009116B0, getinfo)
	 *
	 * What it does:
	 * Resolves debug info for either stack level arg-1 or function arg-1 and
	 * returns one table populated by requested option mask (`flnSu` by default).
	 */
	int LuaDebugGetInfo(lua_State* const state)
	{
		const char* optionMask = luaL_optlstring(state, 2, "flnSu", nullptr);
		::lua_Debug activationRecord{};

		if (lua_isnumber(state, 1) != 0) {
			const int level = static_cast<int>(lua_tonumber(state, 1));
			if (lua_getstack(state, level, &activationRecord) == 0) {
				lua_pushnil(state);
				return 1;
			}
		} else {
			const int firstArgumentType = lua_type(state, 1);
			if ((firstArgumentType | 1) != LUA_TFUNCTION) {
				luaL_argerror(state, 1, kLuaDebugFunctionOrLevelExpected);
			}

			lua_pushfstring(state, ">%s", optionMask);
			optionMask = lua_tostring(state, -1);
			lua_pushvalue(state, 1);
		}

		if (lua_getinfo(state, optionMask, &activationRecord) == 0) {
			return luaL_argerror(state, 2, kLuaDebugInvalidOption);
		}

		lua_newtable(state);
		for (const char* option = optionMask; *option != '\0'; ++option) {
			switch (*option) {
				case 'S':
					lua_pushstring(state, "source");
					lua_pushstring(state, activationRecord.source);
					lua_rawset(state, -3);

					lua_pushstring(state, "short_src");
					lua_pushstring(state, activationRecord.short_src);
					lua_rawset(state, -3);

					lua_pushstring(state, "linedefined");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.linedefined));
					lua_rawset(state, -3);

					lua_pushstring(state, "what");
					lua_pushstring(state, activationRecord.what);
					lua_rawset(state, -3);
					break;

				case 'f':
					lua_pushlstring(state, "func", 4);
					lua_pushvalue(state, -3);
					lua_rawset(state, -3);
					break;

				case 'l':
					lua_pushstring(state, "currentline");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.currentline));
					lua_rawset(state, -3);
					break;

				case 'n':
					lua_pushstring(state, "name");
					lua_pushstring(state, activationRecord.name);
					lua_rawset(state, -3);

					lua_pushstring(state, "namewhat");
					lua_pushstring(state, activationRecord.namewhat);
					lua_rawset(state, -3);
					break;

				case 'u':
					lua_pushstring(state, "nups");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.nups));
					lua_rawset(state, -3);
					break;

				default:
					break;
			}
		}

		return 1;
	}

	/**
	 * Address: 0x00911940 (FUN_00911940, getlocal)
	 *
	 * What it does:
	 * Returns local variable name/value pair for stack level arg-1 and local
	 * index arg-2; returns `nil` when local index is unavailable.
	 */
	int LuaDebugGetLocal(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_checknumber(state, 1));
		::lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) == 0) {
			return luaL_argerror(state, 1, kLuaDebugLevelOutOfRange);
		}

		const int localIndex = static_cast<int>(luaL_checknumber(state, 2));
		const char* const localName = lua_getlocal(state, &activationRecord, localIndex);
		if (localName != nullptr) {
			lua_pushstring(state, localName);
			lua_pushvalue(state, -2);
			return 2;
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x009119D0 (FUN_009119D0, setlocal)
	 *
	 * What it does:
	 * Sets one local variable for stack level arg-1/local index arg-2 using
	 * stack arg-3 and returns assigned local name (or nil).
	 */
	int LuaDebugSetLocal(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_checknumber(state, 1));
		::lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) == 0) {
			return luaL_argerror(state, 1, kLuaDebugLevelOutOfRange);
		}

		luaL_checkany(state, 3);
		const int localIndex = static_cast<int>(luaL_checknumber(state, 2));
		lua_pushstring(state, lua_setlocal(state, &activationRecord, localIndex));
		return 1;
	}

	/**
	 * Address: 0x00911AB0 (FUN_00911AB0, getupvalue)
	 *
	 * What it does:
	 * Returns upvalue name+value for function arg-1 and upvalue index arg-2;
	 * returns 0 when index is out of range.
	 */
	int LuaDebugGetUpvalue(lua_State* const state)
	{
		const int upvalueIndex = static_cast<int>(luaL_checknumber(state, 2));
		luaL_checktype(state, 1, LUA_TFUNCTION);

		const char* const upvalueName = lua_getupvalue(state, 1, upvalueIndex);
		if (upvalueName != nullptr) {
			lua_pushstring(state, upvalueName);
			lua_insert(state, -2);
			return 2;
		}

		return 0;
	}

	/**
	 * Address: 0x00911B00 (FUN_00911B00, setupvalue)
	 *
	 * What it does:
	 * Writes function upvalue from stack arg-3 for function arg-1/index arg-2
	 * and returns upvalue name when the write succeeds.
	 */
	int LuaDebugSetUpvalue(lua_State* const state)
	{
		luaL_checkany(state, 3);
		const int upvalueIndex = static_cast<int>(luaL_checknumber(state, 2));
		luaL_checktype(state, 1, LUA_TFUNCTION);

		const char* const upvalueName = lua_setupvalue(state, 1, upvalueIndex);
		if (upvalueName != nullptr) {
			lua_pushstring(state, upvalueName);
			lua_insert(state, -1);
			return 1;
		}

		return 0;
	}

	/**
	 * Address: 0x00911B60 (FUN_00911B60, hookf)
	 *
	 * What it does:
	 * Dispatches one debug-hook event to the registry-stored `h` callback,
	 * passing event-name + current line (`nil` when line < 0).
	 */
	void LuaDebugHookCallback(lua_State* const state, ::lua_Debug* const activationRecord)
	{
		lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
		lua_rawget(state, LUA_REGISTRYINDEX);
		if ((lua_type(state, -1) | 1) == LUA_TFUNCTION) {
			lua_pushstring(state, kLuaDebugHookEventNames[activationRecord->event]);

			const int currentLine = activationRecord->currentline;
			if (currentLine < 0) {
				lua_pushnil(state);
			} else {
				lua_pushnumber(state, static_cast<lua_Number>(currentLine));
			}

			lua_call(state, 2, 0);
		} else {
			lua_settop(state, -2);
		}
	}

	/**
	 * Address: 0x00911C00 (FUN_00911C00, makemask)
	 *
	 * What it does:
	 * Parses textual hook mask (`c`,`r`,`l`) plus count gate and returns packed
	 * Lua hook mask bits.
	 */
	int LuaDebugBuildHookMask(const char* const maskSpec, const int count)
	{
		int mask = (std::strchr(maskSpec, 'c') != nullptr) ? LUA_MASKCALL : 0;
		if (std::strchr(maskSpec, 'r') != nullptr) {
			mask |= LUA_MASKRET;
		}
		if (std::strchr(maskSpec, 'l') != nullptr) {
			mask |= LUA_MASKLINE;
		}
		if (count > 0) {
			mask |= LUA_MASKCOUNT;
		}
		return mask;
	}

	/**
	 * Address: 0x00911C80 (FUN_00911C80, sethook)
	 *
	 * What it does:
	 * Sets or clears the active debug hook based on arg-1 (`nil` clears),
	 * then stores callback object in registry key `h`.
	 */
	int LuaDebugSetHook(lua_State* const state)
	{
		if (lua_type(state, 1) > LUA_TNIL) {
			const char* const maskSpec = luaL_checklstring(state, 2, nullptr);
			const int count = static_cast<int>(luaL_optnumber(state, 3, 0.0));
			const int mask = LuaDebugBuildHookMask(maskSpec, count);
			lua_sethook(state, &LuaDebugHookCallback, mask, count);
		} else {
			lua_settop(state, 1);
			lua_sethook(state, nullptr, 0, 0);
		}

		lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
		lua_pushvalue(state, 1);
		lua_rawset(state, LUA_REGISTRYINDEX);
		return 0;
	}

	/**
	 * Address: 0x00911D20 (FUN_00911D20, gethook)
	 *
	 * What it does:
	 * Returns the current hook callback object (`h` or `"external hook"`),
	 * active hook mask string, and hook count.
	 */
	int LuaDebugGetHook(lua_State* const state)
	{
		const int mask = lua_gethookmask(state);
		const auto hook = lua_gethook(state);
		const auto localHook = &LuaDebugHookCallback;
		if (hook == nullptr || hook == localHook) {
			lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
			lua_rawget(state, LUA_REGISTRYINDEX);
		} else {
			lua_pushlstring(state, kLuaDebugExternalHookLabel, std::strlen(kLuaDebugExternalHookLabel));
		}

		char maskString[8]{};
		int writeIndex = 0;
		if ((mask & LUA_MASKCALL) != 0) {
			maskString[writeIndex++] = 'c';
		}
		if ((mask & LUA_MASKRET) != 0) {
			maskString[writeIndex++] = 'r';
		}
		if ((mask & LUA_MASKLINE) != 0) {
			maskString[writeIndex++] = 'l';
		}

		maskString[writeIndex] = '\0';
		lua_pushstring(state, maskString);
		lua_pushnumber(state, static_cast<lua_Number>(lua_gethookcount(state)));
		return 3;
	}

	/**
	 * Address: 0x00911DE0 (FUN_00911DE0, luaD_debug)
	 *
	 * What it does:
	 * Runs one interactive debug REPL on stdin/stderr until EOF or `cont\\n`,
	 * executing each entered line with `lua_dostring`.
	 */
	int LuaDebugConsole(lua_State* const state)
	{
		char inputBuffer[kLuaDebugInputBufferSize]{};

		std::FILE* ioBase = __iob_func();
		std::fputs(kLuaDebugPrompt, &ioBase[2]);

		ioBase = __iob_func();
		if (std::fgets(inputBuffer, kLuaDebugReadLineLimit, &ioBase[0]) == nullptr) {
			return 0;
		}

		do {
			if (std::strcmp(inputBuffer, kLuaDebugContinueToken) == 0) {
				break;
			}

			lua_dostring(state, inputBuffer);
			lua_settop(state, 0);

			ioBase = __iob_func();
			std::fputs(kLuaDebugPrompt, &ioBase[2]);
			ioBase = __iob_func();
		} while (std::fgets(inputBuffer, kLuaDebugReadLineLimit, &ioBase[0]) != nullptr);

		return 0;
	}

	/**
	 * Address: 0x00912780 (FUN_00912780, funcinfo)
	 *
	 * What it does:
	 * Populates one `lua_Debug` function-source lane from function object type:
	 * C closure (`=[C]`) or Lua prototype-backed closure info.
	 */
	void LuaDebugPopulateFuncInfo(
		::lua_Debug* const activationRecord,
		TObject* const functionObject
	)
	{
		if (functionObject->tt == LUA_CFUNCTION) {
			activationRecord->source = "=[C]";
			activationRecord->linedefined = -1;
			activationRecord->what = "C";
			luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
			return;
		}

		const auto* const closure = static_cast<const Closure*>(functionObject->value.p);
		const Proto* const proto = closure->l.p;
		activationRecord->source = proto->source->str;
		activationRecord->linedefined = proto->lineDefined;
		activationRecord->what = (proto->lineDefined == 0) ? "main" : "Lua";
		luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
	}

	/**
	 * Address: 0x00912850 (FUN_00912850, info_tailcall)
	 *
	 * What it does:
	 * Fills one activation record for a frame that only exists as a tail call,
	 * where there is no function object left to describe, and pushes a nil in
	 * place of the function `lua_getinfo` would otherwise have left behind.
	 */
	void info_tailcall(::lua_Debug* const activationRecord, lua_State* const state)
	{
		activationRecord->namewhat = "";
		activationRecord->name = "";
		activationRecord->currentline = -1;
		activationRecord->linedefined = -1;
		activationRecord->what = "tail";
		activationRecord->source = "=(tail call)";
		luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
		activationRecord->nups = 0;
		state->top->tt = LUA_TNIL;
	}

	/**
	 * Address: 0x00913020 (FUN_00913020, auxgetinfo)
	 *
	 * IDA signature:
	 * int __usercall auxgetinfo(const char *what@<eax>, TObject *f@<edi>,
	 *     lua_Debug *ar@<esi>, lua_State *L, CallInfo *ci);
	 *
	 * What it does:
	 * Fills the activation record for one frame, a field per option letter.
	 * An unrecognised letter leaves the record alone and makes the whole call
	 * report failure, but the rest of the string is still processed.
	 */
	int auxgetinfo(
		const char* what,
		TObject* const functionObject,
		::lua_Debug* const activationRecord,
		lua_State* const state,
		CallInfo* const ci
	)
	{
		int status = 1;

		for (; *what != '\0'; ++what) {
			switch (*what) {
				case 'S':
					LuaDebugPopulateFuncInfo(activationRecord, functionObject);
					break;

				case 'f':
					// Parked at the top for lua_getinfo to publish once it has
					// seen an 'f' in the option string.
					*state->top = *functionObject;
					break;

				case 'l':
					activationRecord->currentline = (ci != nullptr) ? currentline(ci) : -1;
					break;

				case 'n': {
					const char* nameWhat = (ci != nullptr) ? getfuncname(&activationRecord->name, ci) : nullptr;
					activationRecord->namewhat = nameWhat;
					if (nameWhat == nullptr) {
						// Not resolvable from the call site, so fall back to
						// whatever global happens to hold this function.
						const char* const globalName = travglobals(state, functionObject);
						activationRecord->name = globalName;
						activationRecord->namewhat = (globalName != nullptr) ? "global" : "";
					}
					break;
				}

				case 'u':
					activationRecord->nups = static_cast<const Closure*>(functionObject->value.p)->c.nupvalues;
					break;

				default:
					status = 0;
					break;
			}
		}

		return status;
	}

	/**
	 * Address: 0x00911EC0 (FUN_00911EC0, listcode_buildop)
	 *
	 * What it does:
	 * Formats one Lua bytecode instruction into a debug line with source line,
	 * instruction index, opcode mnemonic, and decoded operand lane values.
	 */
	const char* LuaDebugBuildOpcodeText(
		const Proto* const proto,
		const int instructionIndex,
		char* const outputBuffer
	)
	{
		const Instruction instruction = proto->code[instructionIndex];
		const auto opcode = static_cast<unsigned int>(instruction) & kLuaOpcodeMask;
		const int sourceLine = proto->lineinfo != nullptr ? proto->lineinfo[instructionIndex] : 0;
		std::sprintf(outputBuffer, "(%4d) %4d - ", sourceLine, instructionIndex);

		char* const writeCursor = outputBuffer + std::strlen(outputBuffer);
		const auto mode = kLuaOpcodeModes[opcode] & kLuaOpcodeModeMask;
		const auto registerA = static_cast<unsigned int>(instruction) >> kLuaInstructionAFieldShift;

		if (mode == 0) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4u %4u",
				kLuaOpcodeNames[opcode],
				registerA,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionBFieldShift) & kLuaInstructionBOrCMask,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionBOrCMask
			);
		} else if (mode == 1) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4u",
				kLuaOpcodeNames[opcode],
				registerA,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionABxMask
			);
		} else if (mode == 2) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4d",
				kLuaOpcodeNames[opcode],
				registerA,
				static_cast<int>(
					((static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionABxMask)
				) - kLuaInstructionSignedBxBias
			);
		}

		return outputBuffer;
	}

	/**
	 * Address: 0x00911FC0 (FUN_00911FC0, debug_listcode)
	 *
	 * What it does:
	 * Builds one Lua table describing function bytecode: fixed fields
	 * (`maxstack`, `numparams`) plus formatted per-instruction listing lines.
	 */
	int LuaDebugListCode(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const stackValueObject = static_cast<GCObject*>(state->ci->base->value.p);
		Proto* const proto = stackValueObject->cl.l.p;

		lua_newtable(state);

		lua_pushstring(state, "maxstack");
		lua_pushnumber(state, static_cast<lua_Number>(proto->maxstacksize));
		lua_rawset(state, -3);

		lua_pushstring(state, "numparams");
		lua_pushnumber(state, static_cast<lua_Number>(proto->numparams));
		lua_rawset(state, -3);

		char opcodeText[100]{};
		for (int instructionIndex = 0; instructionIndex < proto->sizecode; ++instructionIndex) {
			lua_pushnumber(state, static_cast<lua_Number>(instructionIndex + 1));
			lua_pushstring(state, LuaDebugBuildOpcodeText(proto, instructionIndex, opcodeText));
			lua_settable(state, -3);
		}

		return 1;
	}

	/**
	 * Address: 0x009120B0 (FUN_009120B0, func_listk)
	 *
	 * What it does:
	 * Returns one table containing function constant slots (`proto->k`) indexed
	 * from 1..sizek for Lua function arg-1.
	 */
	int LuaDebugListConstants(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const closureObject = static_cast<GCObject*>(state->ci->base->value.p);
		Proto* const proto = closureObject->cl.l.p;

		lua_newtable(state);
		for (int constantIndex = 0; constantIndex < proto->sizek; ++constantIndex) {
			lua_pushnumber(state, static_cast<lua_Number>(constantIndex + 1));
			luaA_pushobject(state, &proto->k[constantIndex]);
			lua_settable(state, -3);
		}
		return 1;
	}

	/**
	 * Address: 0x00912130 (FUN_00912130, func_listlocals)
	 *
	 * What it does:
	 * Pushes all local variable names visible at the requested pc lane (arg-2)
	 * for function arg-1 and returns pushed name count.
	 */
	int LuaDebugListLocals(lua_State* const state)
	{
		const int pc = static_cast<int>(luaL_checknumber(state, 2)) - 1;

		const int functionType = lua_type(state, 1);
		if ((functionType | 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const closureObject = static_cast<GCObject*>(state->ci->base->value.p);
		const Proto* const proto = closureObject->cl.l.p;

		int localNumber = 1;
		for (const char* localName = luaF_getlocalname(proto, 1, pc);
			localName != nullptr;
			localName = luaF_getlocalname(proto, localNumber, pc)) {
			lua_pushstring(state, localName);
			++localNumber;
		}
		return localNumber - 1;
	}

	[[nodiscard]] std::size_t AlignSizeToEight(const std::size_t value)
	{
		return (value + 7u) & ~static_cast<std::size_t>(7u);
	}

	struct LuaTableSizeRuntimeView
	{
		std::uint8_t reserved00[0x9];
		lu_byte lsizenode;
		std::uint8_t reserved0A[0x16];
		int32_t sizearray;
	};
	static_assert(
		offsetof(LuaTableSizeRuntimeView, lsizenode) == 0x9,
		"LuaTableSizeRuntimeView::lsizenode offset must be 0x9"
	);
	static_assert(
		offsetof(LuaTableSizeRuntimeView, sizearray) == 0x20,
		"LuaTableSizeRuntimeView::sizearray offset must be 0x20"
	);

	struct LuaThreadSizeRuntimeView
	{
		std::uint8_t reserved00[0x20];
		std::uint32_t lane20;
		std::uint32_t lane24;
		std::uint32_t lane28;
	};
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane20) == 0x20,
		"LuaThreadSizeRuntimeView::lane20 offset must be 0x20"
	);
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane24) == 0x24,
		"LuaThreadSizeRuntimeView::lane24 offset must be 0x24"
	);
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane28) == 0x28,
		"LuaThreadSizeRuntimeView::lane28 offset must be 0x28"
	);

	void LuaDebugAppendGcObject(lua_State* const state, Table* const outputTable, int& nextIndex, GCObject* const object)
	{
		TObject* const slot = luaH_setnum(state, outputTable, ++nextIndex);
		slot->tt = static_cast<int>(object->gch.tt);
		slot->value.p = object;
	}

	void LuaDebugAppendNumber(
		lua_State* const state,
		Table* const outputTable,
		int& nextIndex,
		const float number
	)
	{
		TObject* const slot = luaH_setnum(state, outputTable, ++nextIndex);
		slot->tt = LUA_TNUMBER;
		slot->value.n = number;
	}

	/**
	 * Address: 0x00912FA0 (FUN_00912FA0, lua::getsizes)
	 *
	 * What it does:
	 * Returns (and lazily initializes) the registry weak-key table at numeric
	 * key `3` used by Lua debug allocation-size bookkeeping.
	 */
	Table* LuaDebugGetSizesTable(lua_State* const state)
	{
		Table* const registryTable = static_cast<Table*>(state->l_G->_registry.value.p);
		TObject* const sizesSlot = luaH_setnum(state, registryTable, kLuaRegistryAllocationSizesKey);
		if (sizesSlot->tt != LUA_TTABLE) {
			lua_newtable(state);
			lua_newtable(state);
			lua_pushlstring(state, "__mode", 6u);
			lua_pushlstring(state, "k", 1u);
			lua_rawset(state, -3);
			lua_setmetatable(state, -2);
			*sizesSlot = *(state->top - 1);
			--state->top;
		}

		return static_cast<Table*>(sizesSlot->value.p);
	}

	/**
	 * Address: 0x009121C0 (FUN_009121C0, func_allobjects)
	 *
	 * What it does:
	 * Builds and returns a flat debug table with every tracked GC object from
	 * root GC lists and interned-string buckets.
	 */
	int LuaDebugAllObjects(lua_State* const state)
	{
		lua_newtable(state);
		auto* const outputTable = static_cast<Table*>((state->top - 1)->value.p);
		int objectIndex = 0;
		lua_setgcthreshold(state, 0);

		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;

		for (GCObject* object = globalState->rootgc; object != nullptr; object = object->gch.next) {
			if (object != reinterpret_cast<GCObject*>(outputTable)) {
				LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
			}
		}

		for (GCObject* object = globalState->rootgc1; object != nullptr; object = object->gch.next) {
			LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
		}

		for (GCObject* object = globalState->rootudata; object != nullptr; object = object->gch.next) {
			LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
		}

		const stringtable& stringTable = globalState->strt;
		if (stringTable.hash != nullptr) {
			for (int bucketWalk = 0; bucketWalk < stringTable.size; ++bucketWalk) {
				for (GCObject* object = stringTable.hash[bucketWalk]; object != nullptr; object = object->gch.next) {
					LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
				}
			}
		}

		--globalState->gcTraversalLockDepth;
		return 1;
	}

	/**
	 * Address: 0x009122F0 (FUN_009122F0, func_allocinfo)
	 *
	 * What it does:
	 * Pushes the debug allocation-info table returned by `lua::getsizes` onto
	 * the Lua stack as a raw internal `TObject`.
	 */
	int LuaDebugAllocInfo(lua_State* const state)
	{
		lua_setgcthreshold(state, 0);
		Table* const sizesTable = LuaDebugGetSizesTable(state);

		TObject* const top = state->top;
		top->tt = static_cast<int>(sizesTable->tt);
		top->value.p = sizesTable;
		state->top = top + 1;
		return 1;
	}

	/**
	 * Address: 0x00912320 (FUN_00912320, func_trackallocations)
	 *
	 * What it does:
	 * Toggles global allocation tracking gate from boolean arg-1.
	 */
	int LuaDebugTrackAllocations(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TBOOLEAN) {
			luaL_argerror(state, 1, "boolean expected");
		}

		state->l_G->allocationTrackingEnabled = static_cast<lu_byte>(lua_toboolean(state, 1));
		return 0;
	}

	struct LuaClosureHeaderRuntimeView
	{
		std::uint8_t reserved00[0x8];
		std::uint8_t upvalueCount;
	};
	static_assert(
		offsetof(LuaClosureHeaderRuntimeView, upvalueCount) == 0x8,
		"LuaClosureHeaderRuntimeView::upvalueCount offset must be 0x8"
	);

	struct LuaUserdataTypeInfoRuntimeView
	{
		std::uint8_t reserved00[0x8];
		std::uint32_t payloadSize;
	};
	static_assert(
		offsetof(LuaUserdataTypeInfoRuntimeView, payloadSize) == 0x8,
		"LuaUserdataTypeInfoRuntimeView::payloadSize offset must be 0x8"
	);

	struct LuaUserdataRuntimeView
	{
		std::uint8_t reserved00[0x0C];
		LuaUserdataTypeInfoRuntimeView* typeInfo;
	};
	static_assert(
		offsetof(LuaUserdataRuntimeView, typeInfo) == 0x0C,
		"LuaUserdataRuntimeView::typeInfo offset must be 0x0C"
	);

	/**
	 * Address: 0x00912360 (FUN_00912360, func_GetTObjectSize)
	 *
	 * What it does:
	 * Returns aligned byte size for one Lua `TObject` payload by exact runtime
	 * type tag rules used by debug allocation helpers.
	 */
	std::size_t LuaDebugGetTObjectSize(const TObject* const object)
	{
		if (object == nullptr) {
			return 0;
		}

		switch (object->tt) {
		case LUA_TSTRING: {
			const auto* const stringObject = static_cast<const TString*>(object->value.p);
			if (stringObject == nullptr) {
				return 0;
			}
			return AlignSizeToEight(stringObject->len + 0x15u);
		}
		case LUA_TTABLE: {
			const auto* const tableObject = static_cast<const LuaTableSizeRuntimeView*>(object->value.p);
			if (tableObject == nullptr) {
				return 0;
			}

			const std::size_t hashBytes
				= tableObject->lsizenode != 0u ? (static_cast<std::size_t>(20u) << tableObject->lsizenode) : 0u;
			const std::size_t arrayBytes = static_cast<std::size_t>(tableObject->sizearray) * sizeof(TObject);
			return AlignSizeToEight(hashBytes + arrayBytes + 0x24u);
		}
		case LUA_CFUNCTION: {
			const auto* const closureHeader = static_cast<const LuaClosureHeaderRuntimeView*>(object->value.p);
			if (closureHeader == nullptr) {
				return 0;
			}
			return AlignSizeToEight(static_cast<std::size_t>(0x40u + (8u * closureHeader->upvalueCount)));
		}
		case LUA_TFUNCTION: {
			const auto* const closureHeader = static_cast<const LuaClosureHeaderRuntimeView*>(object->value.p);
			if (closureHeader == nullptr) {
				return 0;
			}
			return AlignSizeToEight(static_cast<std::size_t>(0x1Cu + (4u * closureHeader->upvalueCount)));
		}
		case LUA_TUSERDATA: {
			const auto* const userData = static_cast<const LuaUserdataRuntimeView*>(object->value.p);
			if (userData == nullptr || userData->typeInfo == nullptr) {
				return 0;
			}

			return AlignSizeToEight(static_cast<std::size_t>(userData->typeInfo->payloadSize + 0x10u));
		}
		case LUA_TTHREAD: {
			const auto* const threadState = static_cast<const LuaThreadSizeRuntimeView*>(object->value.p);
			if (threadState == nullptr) {
				return 0;
			}

			// Keep x86 lane arithmetic shape from FUN_00912360 exactly.
			std::uint32_t rawSize = 0x48u + (threadState->lane20 * 8u);
			rawSize -= threadState->lane28;
			rawSize += threadState->lane24;
			return AlignSizeToEight(static_cast<std::size_t>(rawSize));
		}
		case LUA_TPROTO: {
			const auto* const proto = static_cast<const Proto*>(object->value.p);
			if (proto == nullptr) {
				return 0;
			}

			const std::size_t scalarCount = static_cast<std::size_t>(
				proto->sizeupvalues
				+ proto->sizecode
				+ proto->sizelineinfo
				+ proto->sizep
				+ (proto->sizelocvars * 3)
				+ (proto->sizek * 2)
				+ 28
			);
			return AlignSizeToEight(scalarCount * sizeof(std::int32_t));
		}
		case LUA_TUPVALUE:
			return AlignSizeToEight(0x14u);
		default:
			return 0;
		}
	}

	/**
	 * Address: 0x00912470 (FUN_00912470, func_allocatedsize)
	 *
	 * What it does:
	 * Replaces each stack argument with a number containing its aligned object
	 * allocation size and returns the converted argument count.
	 */
	int LuaDebugAllocatedSize(lua_State* const state)
	{
		const int argumentCount = lua_gettop(state);
		for (int argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
			TObject* const object = &state->base[argumentIndex];
			object->value.n = static_cast<float>(LuaDebugGetTObjectSize(object));
			object->tt = LUA_TNUMBER;
		}
		return argumentCount;
	}

	struct LuaProfileCountersRuntimeView
	{
		std::uint32_t sampleCount;
		std::uint32_t sampleCountAux;
		std::uint8_t reserved08[0x18];
		std::int64_t totalBytes;
	};
	static_assert(
		offsetof(LuaProfileCountersRuntimeView, totalBytes) == 0x20,
		"LuaProfileCountersRuntimeView::totalBytes offset must be 0x20"
	);

	[[nodiscard]] const LuaProfileCountersRuntimeView* LuaDebugGetProfileCounters(const GCObject* const object)
	{
		if (object->gch.tt == LUA_CFUNCTION) {
			return reinterpret_cast<const LuaProfileCountersRuntimeView*>(
				reinterpret_cast<const std::uint8_t*>(object) + 0x18u
			);
		}
		if (object->gch.tt == LUA_TPROTO) {
			return reinterpret_cast<const LuaProfileCountersRuntimeView*>(
				reinterpret_cast<const std::uint8_t*>(object) + 0x48u
			);
		}

		return nullptr;
	}

	/**
	 * Address: 0x0091E080 (FUN_0091E080, func_profiledata)
	 *
	 * What it does:
	 * Builds a flat profile table for GC proto/C-closure nodes that carry
	 * allocation counters, emitting per-node tuple lanes with total byte tally.
	 */
	int LuaDebugProfileData(lua_State* const state)
	{
		lua_newtable(state);
		auto* const outputTable = static_cast<Table*>((state->top - 1)->value.p);

		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;

		for (GCObject* secondary = globalState->rootgc1; secondary != nullptr; secondary = secondary->gch.next) {
		}

		int outputIndex = 0;
		for (GCObject* object = globalState->rootgc; object != nullptr; object = object->gch.next) {
			const LuaProfileCountersRuntimeView* const counters = LuaDebugGetProfileCounters(object);
			if (counters == nullptr || (counters->sampleCount | counters->sampleCountAux) == 0u) {
				continue;
			}

			LuaDebugAppendGcObject(state, outputTable, outputIndex, object);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, static_cast<float>(counters->totalBytes));
		}

		--globalState->gcTraversalLockDepth;
		return 1;
	}

	/**
	 * Address: 0x0090E790 (FUN_0090E790, callalert)
	 *
	 * What it does:
	 * Handles Lua chunk-call failures by dispatching to global `_ALERT` when it
	 * is callable, otherwise prints the pending Lua error text to stderr and
	 * drops helper/error stack lanes.
	 */
	void LuaCallAlert(lua_State* const state, const int status)
	{
		if (status == 0) {
			return;
		}

		lua_pushstring(state, "_ALERT");
		lua_gettable(state, LUA_GLOBALSINDEX);

		const int alertType = lua_type(state, -1);
		if ((alertType | 1) == LUA_TFUNCTION) {
			lua_insert(state, -2);
			lua_call(state, 1, 0);
			return;
		}

		const char* const alertText = lua_tostring(state, -2);
		std::fprintf(stderr, "%s\n", alertText);
		lua_settop(state, -3);
	}

	/**
	 * Address: 0x0090E830 (FUN_0090E830, lua_dofile)
	 *
	 * What it does:
	 * Loads one Lua chunk from `filename`, executes it when load succeeds,
	 * then routes any error status through `callalert`.
	 */
	extern "C" int lua_dofile(lua_State* const state, const char* const filename)
	{
		int status = ::luaL_loadfile(state, filename);
		if (status == 0) {
			status = lua_call(state, 0, LUA_MULTRET);
		}

		LuaCallAlert(state, status);
		return status;
	}

	/**
	 * Address: 0x0090E870 (FUN_0090E870, lua_dobuffer)
	 *
	 * What it does:
	 * Loads one source buffer as a Lua chunk, executes it when load succeeds,
	 * then routes any error status through `callalert`.
	 */
	int lua_dobuffer(
		lua_State* const state,
		const char* const buffer,
		const int size,
		const char* const name
	)
	{
		int status = ::luaL_loadbuffer(state, buffer, static_cast<size_t>(size), name);
		if (status == 0) {
			status = lua_call(state, 0, LUA_MULTRET);
		}

		LuaCallAlert(state, status);
		return status;
	}

	/**
	 * Address: 0x0090E8D0 (FUN_0090E8D0, lua_dostring)
	 *
	 * What it does:
	 * Executes one null-terminated source string by forwarding to `lua_dobuffer`.
	 */
	int lua_dostring(lua_State* const state, const char* const source)
	{
		return lua_dobuffer(state, source, static_cast<int>(std::strlen(source)), source);
	}

	/**
	 * Address: 0x0090D6B0 (FUN_0090D6B0, lua_version)
	 *
	 * What it does:
	 * Returns the embedded Lua runtime version string literal.
	 */
	extern "C" const char* lua_version()
	{
		return "Lua 5.0.1";
	}

	/**
	 * Address: 0x00924BE0 (FUN_00924BE0, str_len)
	 *
	 * What it does:
	 * Returns the byte length of arg-1 string as one Lua number result.
	 */
	int str_len(lua_State* const state)
	{
		size_t textLength = 0u;
		(void)luaL_checklstring(state, 1, &textLength);
		lua_pushnumber(state, static_cast<float>(textLength));
		return 1;
	}

	/**
	 * Address: 0x00924CE0 (FUN_00924CE0, str_lower)
	 *
	 * What it does:
	 * Lowercases each byte from the first Lua string argument and pushes the
	 * transformed buffer result.
	 */
	int str_lower(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		char* const bufferEnd = reinterpret_cast<char*>(&buffer) + sizeof(buffer);
		for (size_t index = 0; index < textLength; ++index) {
			if (buffer.p >= bufferEnd) {
				luaL_prepbuffer(&buffer);
			}
			*buffer.p++ = static_cast<char>(std::tolower(static_cast<unsigned char>(text[index])));
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924C30 (FUN_00924C30, str_sub)
	 *
	 * What it does:
	 * Returns the substring slice selected by arg-2 and arg-3, honoring Lua's
	 * 1-based negative-index conventions and empty-slice behavior.
	 */
	int str_sub(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		int start = static_cast<int>(luaL_checknumber(state, 2));
		if (start < 0) {
			start += static_cast<int>(textLength) + 1;
		}

		int end = static_cast<int>(luaL_optnumber(state, 3, -1.0f));
		if (end < 0) {
			end += static_cast<int>(textLength) + 1;
		}

		if (start < 1) {
			start = 1;
		}
		if (end > static_cast<int>(textLength)) {
			end = static_cast<int>(textLength);
		}

		if (start > end) {
			lua_pushlstring(state, "", 0u);
		} else {
			lua_pushlstring(state, text + (start - 1), static_cast<size_t>(end - start + 1));
		}
		return 1;
	}

	/**
	 * Address: 0x00924D80 (FUN_00924D80, str_upper)
	 *
	 * What it does:
	 * Uppercases each byte from the first Lua string argument and pushes the
	 * transformed buffer result.
	 */
	int str_upper(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		char* const bufferEnd = reinterpret_cast<char*>(&buffer) + sizeof(buffer);
		for (size_t index = 0; index < textLength; ++index) {
			if (buffer.p >= bufferEnd) {
				luaL_prepbuffer(&buffer);
			}
			*buffer.p++ = static_cast<char>(std::toupper(static_cast<unsigned char>(text[index])));
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924E20 (FUN_00924E20, str_rep)
	 *
	 * What it does:
	 * Repeats arg-1 string arg-2 times and pushes the concatenated result.
	 */
	int str_rep(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);
		const int repeatCount = static_cast<int>(luaL_checknumber(state, 2));

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		for (int repeatIndex = 0; repeatIndex < repeatCount; ++repeatIndex) {
			luaL_addlstring(&buffer, text, textLength);
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924FB0 (FUN_00924FB0, writer)
	 *
	 * What it does:
	 * Appends one Lua bytecode dump chunk into a `luaL_Buffer` sink and returns
	 * success (`1`) to the dump producer.
	 *
	 * Signature is `lua_Chunkwriter`'s, which is how `str_dump` hands it to
	 * `lua_dump`; the sink arrives as the opaque user-data lane.
	 */
	int writer(
		lua_State* const,
		const void* const chunk,
		const size_t chunkSize,
		void* const sink
	)
	{
		luaL_addlstring(static_cast<luaL_Buffer*>(sink), static_cast<const char*>(chunk), chunkSize);
		return 1;
	}

	/**
	 * Address: 0x00924EA0 (FUN_00924EA0, str_byte)
	 *
	 * What it does:
	 * Returns one byte value from arg-1 at optional arg-2 position, honoring
	 * Lua's negative-index adjustment and out-of-range empty-result behavior.
	 */
	int str_byte(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		int position = static_cast<int>(luaL_optnumber(state, 2, 1.0f));
		if (position < 0) {
			position += static_cast<int>(textLength) + 1;
		}

		if (position <= 0 || static_cast<size_t>(position) > textLength) {
			return 0;
		}

		lua_pushnumber(state, static_cast<float>(static_cast<unsigned char>(text[position - 1])));
		return 1;
	}

	/**
	 * Address: 0x00925B30 (FUN_00925B30, str_find)
	 *
	 * What it does:
	 * Finds one pattern in source text with optional plain/anchored modes and
	 * returns `(start,end,captures...)` or `nil` when no match exists.
	 */
	int str_find(lua_State* const state)
	{
		size_t sourceLength = 0u;
		const char* const sourceText = luaL_checklstring(state, 1, &sourceLength);
		size_t patternLength = 0u;
		const char* pattern = luaL_checklstring(state, 2, &patternLength);

		int startIndex = static_cast<int>(luaL_optnumber(state, 3, 1.0f));
		if (startIndex < 0) {
			startIndex += static_cast<int>(sourceLength) + 1;
		}

		std::size_t init = 0u;
		if (startIndex - 1 >= 0) {
			init = static_cast<std::size_t>(startIndex - 1);
			if (init > sourceLength) {
				init = sourceLength;
			}
		}

		if (lua_toboolean(state, 4) != 0 || std::strpbrk(pattern, "^$*+?.([%-") == nullptr) {
			const char* const found = lmemfind(patternLength, sourceText + init, sourceLength - init, pattern);
			if (found != nullptr) {
				const std::size_t matchStart = static_cast<std::size_t>(found - sourceText);
				lua_pushnumber(state, static_cast<float>(matchStart + 1u));
				lua_pushnumber(state, static_cast<float>(matchStart + patternLength));
				return 2;
			}

			lua_pushnil(state);
			return 1;
		}

		int anchor = 0;
		if (*pattern == '^') {
			++pattern;
			anchor = 1;
		}

		const char* searchCursor = sourceText + init;
		MatchStateRuntimeView matchState{};
		matchState.state = state;
		matchState.srcInit = sourceText;
		matchState.srcEnd = sourceText + sourceLength;

		while (true) {
			matchState.level = 0;
			const char* const matchEnd = match(&matchState, searchCursor, pattern);
			if (matchEnd != nullptr) {
				lua_pushnumber(state, static_cast<float>(searchCursor - sourceText + 1));
				lua_pushnumber(state, static_cast<float>(matchEnd - sourceText));
				return push_captures(nullptr, nullptr, &matchState) + 2;
			}

			const char* const priorCursor = searchCursor++;
			if (priorCursor >= matchState.srcEnd || anchor != 0) {
				lua_pushnil(state);
				return 1;
			}
		}
	}

	/**
	 * Address: 0x00925D00 (FUN_00925D00, gfind_aux)
	 *
	 * What it does:
	 * Advances legacy `%gfind` iterator state over source/pattern upvalues and
	 * returns next capture tuple while updating closure start offset.
	 */
	int gfind_aux(lua_State* const state)
	{
		const char* const sourceText = lua_tostring(state, lua_upvalueindex(1));
		const size_t sourceLength = lua_strlen(state, lua_upvalueindex(1));
		const char* const pattern = lua_tostring(state, lua_upvalueindex(2));

		MatchStateRuntimeView matchState{};
		matchState.state = state;
		matchState.srcInit = sourceText;
		matchState.srcEnd = sourceText + sourceLength;

		const int startOffset = static_cast<int>(lua_tonumber(state, lua_upvalueindex(3)));
		const char* sourceCursor = sourceText + startOffset;
		if (sourceCursor > matchState.srcEnd) {
			return 0;
		}

		const char* matchEnd = nullptr;
		while (true) {
			matchState.level = 0;
			matchEnd = match(&matchState, sourceCursor, pattern);
			if (matchEnd != nullptr) {
				break;
			}

			++sourceCursor;
			if (sourceCursor > matchState.srcEnd) {
				return 0;
			}
		}

		int newStart = static_cast<int>(matchEnd - sourceText);
		if (matchEnd == sourceCursor) {
			++newStart;
		}

		lua_pushnumber(state, static_cast<float>(newStart));
		lua_replace(state, lua_upvalueindex(3));
		return push_captures(sourceCursor, matchEnd, &matchState);
	}

	/**
	 * Address: 0x00925E00 (FUN_00925E00, gfind)
	 *
	 * What it does:
	 * Validates source/pattern string arguments and returns one closure iterator
	 * with `(source, pattern, startIndex)` captured upvalues.
	 */
	int gfind(lua_State* const state)
	{
		luaL_checklstring(state, 1, nullptr);
		luaL_checklstring(state, 2, nullptr);
		lua_settop(state, 2);
		lua_pushnumber(state, 0.0f);
		lua_pushcclosure(state, gfind_aux, 3);
		return 1;
	}

	/**
	 * Address: 0x00925E50 (FUN_00925E50, add_s)
	 *
	 * What it does:
	 * Builds one replacement segment for `%gsub`: either expands replacement
	 * string capture escapes (`%1`..`%9`) or calls replacement function/value.
	 */
	void add_s(
		MatchStateRuntimeView* const matchState,
		luaL_Buffer* const buffer,
		const char* const sourceStart,
		const char* const sourceEnd
	)
	{
		lua_State* const state = matchState->state;
		if (lua_isstring(state, 3) != 0) {
			const char* const replacement = lua_tostring(state, 3);
			const size_t replacementLength = lua_strlen(state, 3);
			for (size_t replacementIndex = 0; replacementIndex < replacementLength; ++replacementIndex) {
				if (replacement[replacementIndex] == '%') {
					const unsigned char replacementChar =
						static_cast<unsigned char>(replacement[++replacementIndex]);
					if (std::isdigit(replacementChar) != 0) {
						const int captureIndex = static_cast<int>(replacement[replacementIndex] - '1');
						if (captureIndex < 0 || captureIndex >= matchState->level
							|| matchState->captures[captureIndex].len == -1) {
							luaL_error(matchState->state, "invalid capture index");
						}

						push_onecapture(captureIndex, matchState);
						luaL_addvalue(buffer);
					} else {
						if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
							luaL_prepbuffer(buffer);
						}
						*buffer->p++ = replacement[replacementIndex];
					}
				} else {
					if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
						luaL_prepbuffer(buffer);
					}
					*buffer->p++ = replacement[replacementIndex];
				}
			}
			return;
		}

		lua_pushvalue(state, 3);
		const int captureCount = push_captures(sourceStart, sourceEnd, matchState);
		lua_call(state, captureCount, 1);
		if (lua_isstring(state, -1) != 0) {
			luaL_addvalue(buffer);
			return;
		}

		lua_settop(state, -2);
	}

	/**
	 * Address: 0x00925FA0 (FUN_00925FA0, str_gsub)
	 *
	 * IDA signature:
	 * int __cdecl str_gsub(lua_State *L);
	 *
	 * What it does:
	 * Replaces up to `n` matches of a pattern in the subject, driving `add_s`
	 * for each one, and returns the rebuilt string plus the substitution count.
	 *
	 * The arg-3 check is the one that surfaces as
	 * "bad argument #3 to `gsub' (string or function expected)": it accepts a
	 * string, or a value whose tag `(t | 1)` is LUA_TFUNCTION - this fork keeps
	 * C and Lua functions on adjacent tags 6 and 7, so that single test covers
	 * both.
	 */
	int str_gsub(lua_State* const state)
	{
		size_t sourceLength = 0u;
		const char* sourceCursor = luaL_checklstring(state, 1, &sourceLength);
		const char* pattern = luaL_checklstring(state, 2, nullptr);

		const int maxSubstitutions =
			static_cast<int>(luaL_optnumber(state, 4, static_cast<lua_Number>(sourceLength + 1u)));

		int anchor = 0;
		if (*pattern == '^') {
			++pattern;
			anchor = 1;
		}

		int substitutionCount = 0;
		if (lua_gettop(state) < 3
			|| (lua_isstring(state, 3) == 0
				&& (lua_type(state, 3) | 1) != LUA_TFUNCTION)) {
			luaL_argerror(state, 3, "string or function expected");
		}

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);

		MatchStateRuntimeView matchState{};
		matchState.state = state;
		matchState.srcInit = sourceCursor;
		matchState.srcEnd = sourceCursor + sourceLength;

		if (maxSubstitutions > 0) {
			do {
				matchState.level = 0;
				const char* const matchEnd = match(&matchState, sourceCursor, pattern);
				if (matchEnd != nullptr) {
					++substitutionCount;
					add_s(&matchState, &buffer, sourceCursor, matchEnd);
				}

				if (matchEnd != nullptr && matchEnd > sourceCursor) {
					sourceCursor = matchEnd;
				} else {
					// An empty match, or none: copy one byte across and step
					// past it, so the scan cannot stall on a zero-width hit.
					if (sourceCursor >= matchState.srcEnd) {
						break;
					}

					if (buffer.p >= reinterpret_cast<char*>(&buffer + 1)) {
						luaL_prepbuffer(&buffer);
					}

					*buffer.p++ = *sourceCursor++;
				}
			} while (anchor == 0 && substitutionCount < maxSubstitutions);
		}

		luaL_addlstring(
			&buffer, sourceCursor, static_cast<size_t>(matchState.srcEnd - sourceCursor));
		luaL_pushresult(&buffer);
		lua_pushnumber(state, static_cast<lua_Number>(substitutionCount));
		return 2;
	}

	/**
	 * Address: 0x00924F10 (FUN_00924F10, str_char)
	 *
	 * IDA signature:
	 * int __cdecl str_char(lua_State *L);
	 *
	 * What it does:
	 * Builds a string from its numeric arguments, one byte each, rejecting any
	 * value that does not survive a round trip through `unsigned char`.
	 */
	int str_char(lua_State* const state)
	{
		const int argumentCount = lua_gettop(state);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);

		for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
			const int value = static_cast<int>(luaL_checknumber(state, argumentIndex));
			if (static_cast<int>(static_cast<unsigned char>(value)) != value) {
				luaL_argerror(state, argumentIndex, "invalid value");
			}

			if (buffer.p >= reinterpret_cast<char*>(&buffer + 1)) {
				luaL_prepbuffer(&buffer);
			}

			*buffer.p++ = static_cast<char>(value);
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924FD0 (FUN_00924FD0, str_dump)
	 *
	 * IDA signature:
	 * int __cdecl str_dump(lua_State *L);
	 *
	 * What it does:
	 * Serializes a Lua function to a bytecode string by driving `lua_dump`
	 * through `writer`, which appends each chunk into the buffer.
	 */
	int str_dump(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TFUNCTION);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		if (lua_dump(state, writer, &buffer) == 0) {
			luaL_error(state, "unable to dump given function");
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x009262C0 (FUN_009262C0, luaI_addquotedbinary)
	 *
	 * IDA signature:
	 * void __usercall luaI_addquotedbinary(lua_State *L@<edx>, int arg@<ecx>,
	 *                                      luaL_Buffer *b@<esi>);
	 *
	 * What it does:
	 * The `%Q` quoter - this engine's addition next to stock `%q`. Where `%q`
	 * emits `\000`-style decimal escapes and passes every other byte through,
	 * this one uses the named C escapes for the seven control characters that
	 * have them and `\xNN` for anything else `isprint` rejects, so the result
	 * survives a round trip through a byte-exact source reader.
	 */
	void luaI_addquotedbinary(lua_State* const state, const int argumentIndex, luaL_Buffer* const buffer)
	{
		char* const bufferEnd = reinterpret_cast<char*>(&buffer[1]);
		size_t remainingLength = 0u;
		const char* source = luaL_checklstring(state, argumentIndex, &remainingLength);

		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';

		// Emits one backslash plus `escaped`, prepping the buffer before each
		// byte exactly as the binary does - the two-step check is what keeps a
		// pair from straddling a buffer boundary.
		const auto addEscapePair = [buffer, bufferEnd](const char escaped) {
			if (buffer->p >= bufferEnd) {
				luaL_prepbuffer(buffer);
			}

			*buffer->p++ = '\\';
			if (buffer->p >= bufferEnd) {
				luaL_prepbuffer(buffer);
			}

			*buffer->p++ = escaped;
		};

		for (; remainingLength != 0u; ++source) {
			--remainingLength;

			switch (*source) {
			case '\a': addEscapePair('a'); break;
			case '\b': addEscapePair('b'); break;
			case '\t': addEscapePair('t'); break;
			case '\n': addEscapePair('n'); break;
			case '\v': addEscapePair('v'); break;
			case '\f': addEscapePair('f'); break;
			case '\r': addEscapePair('r'); break;

			case '"':
			case '\\':
				addEscapePair(*source);
				break;

			default:
				if (std::isprint(static_cast<unsigned char>(*source)) != 0) {
					if (buffer->p >= bufferEnd) {
						luaL_prepbuffer(buffer);
					}

					*buffer->p++ = *source;
				} else {
					char hexEscape[12]{};
					std::sprintf(hexEscape, "\\x%02x", static_cast<unsigned char>(*source));
					luaL_addstring(buffer, hexEscape);
				}
				break;
			}
		}

		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';
	}

	/// Longest `%`-directive this build will assemble, including the leading
	/// `%` and the trailing NUL: `scanformat`'s own bound at 0x009265F9.
	constexpr int kMaxFormatSpecifier = 20;

	/// Largest single formatted item `str_format_helper` will `sprintf`, taken
	/// from its 0x200-byte scratch buffer at 0x00926690.
	constexpr int kMaxFormatItem = 512;

	/**
	 * Address: 0x00926590 (FUN_00926590, scanformat)
	 *
	 * IDA signature:
	 * const char *__usercall scanformat@<eax>(const char *strfrmt@<ebx>,
	 *     lua_State *L, char *form, int *hasprecision);
	 *
	 * What it does:
	 * Consumes one `%`-directive's flags, width and precision, copies them into
	 * `form` with the `%` restored, and returns the cursor left on the
	 * conversion character. Width and precision are capped at two digits each,
	 * which is what makes the total fit `kMaxFormatSpecifier`.
	 */
	const char* scanformat(
		const char* const specifier,
		lua_State* const state,
		char* const form,
		int* const hasPrecision
	)
	{
		static constexpr const char* kFormatFlags = "-+ #0";

		const char* cursor = specifier;
		if (std::strchr(kFormatFlags, *cursor) != nullptr) {
			do {
				++cursor;
			} while (std::strchr(kFormatFlags, *cursor) != nullptr);
		}

		if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
			++cursor;
		}

		if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
			++cursor;
		}

		if (*cursor == '.') {
			++cursor;
			*hasPrecision = 1;
			if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
				++cursor;
			}

			if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
				++cursor;
			}
		}

		if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
			luaL_error(state, "invalid format (width or precision too long)");
		}

		const int scannedLength = static_cast<int>(cursor - specifier);
		if (scannedLength + 2 > kMaxFormatSpecifier) {
			luaL_error(state, "invalid format (too long)");
		}

		form[0] = '%';
		std::strncpy(form + 1, specifier, static_cast<size_t>(scannedLength) + 1u);
		form[scannedLength + 2] = '\0';
		return cursor;
	}

	/**
	 * Address: 0x00926690 (FUN_00926690, str_format_helper)
	 *
	 * IDA signature:
	 * int __cdecl str_format_helper(luaL_Buffer *b, lua_State *L, int arg);
	 *
	 * What it does:
	 * The body of `string.format`, split out so callers can supply their own
	 * buffer and first-argument index.
	 *
	 * Beyond stock Lua 5.0 this build adds two conversions:
	 *   - `%Q`, the binary-safe quoter above, and
	 *   - `%b<T>`, which appends the argument as raw little-endian bytes with
	 *     `T` picking the width: `F` double (8), `f` float (4), `d` int32 (4),
	 *     `w` int16 (2), `b` byte (1). An unrecognized `T` appends nothing.
	 *     The pack path writes into the scratch buffer and then clears its
	 *     first byte, so the shared `strlen`-based tail contributes nothing on
	 *     top of the exact-width append it already made.
	 */
	int str_format_helper(luaL_Buffer* const buffer, lua_State* const state, int argumentIndex)
	{
		size_t specifierLength = 0u;
		const char* specifier = luaL_checklstring(state, argumentIndex, &specifierLength);
		const char* const specifierEnd = specifier + specifierLength;

		luaL_buffinit(state, buffer);
		while (specifier < specifierEnd) {
			if (*specifier != '%') {
				if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p++ = *specifier++;
				continue;
			}

			++specifier;
			if (*specifier == '%') {
				if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p++ = *specifier++;
				continue;
			}

			int hasPrecision = 0;
			if (std::isdigit(static_cast<unsigned char>(*specifier)) != 0 && specifier[1] == '$') {
				luaL_error(state, "obsolete option (d$) to `format'");
			}

			++argumentIndex;

			char form[kMaxFormatSpecifier]{};
			char item[kMaxFormatItem]{};
			specifier = scanformat(specifier, state, form, &hasPrecision);

			const char conversion = *specifier++;
			switch (conversion) {
			case 'c':
			case 'd':
			case 'i':
				std::sprintf(item, form, static_cast<int>(luaL_checknumber(state, argumentIndex)));
				break;

			case 'o':
			case 'u':
			case 'x':
			case 'X':
				std::sprintf(
					item,
					form,
					static_cast<unsigned int>(static_cast<std::int64_t>(luaL_checknumber(state, argumentIndex)))
				);
				break;

			case 'e':
			case 'E':
			case 'f':
			case 'g':
			case 'G':
				std::sprintf(item, form, static_cast<double>(luaL_checknumber(state, argumentIndex)));
				break;

			case 'q':
				luaI_addquoted(state, argumentIndex, buffer);
				continue;

			case 'Q':
				luaI_addquotedbinary(state, argumentIndex, buffer);
				continue;

			case 'b': {
				// The pack scratch: eight bytes cleared up front, the widest
				// operand written over them, then item[0] zeroed by the shared
				// tail so `strlen` adds nothing more.
				std::memset(item + 1, 0, 8u);

				const char packWidth = *specifier++;
				switch (packWidth) {
				case 'F': {
					const double packed = static_cast<double>(luaL_checknumber(state, argumentIndex));
					std::memcpy(item, &packed, sizeof(packed));
					luaL_addlstring(buffer, item, sizeof(packed));
					break;
				}

				case 'f': {
					const float packed = static_cast<float>(luaL_checknumber(state, argumentIndex));
					std::memcpy(item, &packed, sizeof(packed));
					luaL_addlstring(buffer, item, sizeof(packed));
					break;
				}

				case 'd': {
					const std::int32_t packed =
						static_cast<std::int32_t>(static_cast<std::int64_t>(luaL_checknumber(state, argumentIndex)));
					std::memcpy(item, &packed, sizeof(packed));
					luaL_addlstring(buffer, item, sizeof(packed));
					break;
				}

				case 'w': {
					const std::int16_t packed =
						static_cast<std::int16_t>(static_cast<int>(luaL_checknumber(state, argumentIndex)));
					std::memcpy(item, &packed, sizeof(packed));
					luaL_addlstring(buffer, item, sizeof(packed));
					break;
				}

				case 'b': {
					const char packed = static_cast<char>(static_cast<int>(luaL_checknumber(state, argumentIndex)));
					item[0] = packed;
					luaL_addlstring(buffer, item, 1u);
					break;
				}

				default:
					break;
				}

				item[0] = '\0';
				break;
			}

			case 's': {
				size_t textLength = 0u;
				const char* const text = luaL_checklstring(state, argumentIndex, &textLength);
				if (hasPrecision == 0 && textLength >= 100u) {
					// Too long to survive the scratch buffer, and with no
					// precision to trim it there is nothing to format: push the
					// value itself instead.
					lua_pushvalue(state, argumentIndex);
					luaL_addvalue(buffer);
					continue;
				}

				std::sprintf(item, form, text);
				break;
			}

			default:
				luaL_error(state, "invalid option to `format'");
				return 0;
			}

			luaL_addlstring(buffer, item, std::strlen(item));
		}

		return 1;
	}

	/**
	 * Address: 0x00926EB0 (FUN_00926EB0, str_format)
	 *
	 * IDA signature:
	 * int __cdecl str_format(lua_State *L);
	 *
	 * What it does:
	 * `string.format`: runs the shared helper over a local buffer starting at
	 * argument 1 and pushes the result.
	 */
	int str_format(lua_State* const state)
	{
		luaL_Buffer buffer{};
		const int status = str_format_helper(&buffer, state, 1);
		if (status == 0) {
			return status;
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00926AE0 (FUN_00926AE0, str_lualex)
	 *
	 * IDA signature:
	 * int __cdecl str_lualex(lua_State *L);
	 *
	 * What it does:
	 * `string.lualex`, this engine's own entry: resolves the backslash escapes
	 * a Lua source lexer would, so a string that arrived with its escapes still
	 * literal (from a data file, say) can be turned into the bytes it denotes.
	 *
	 * Two deviations from the lexer it imitates are the binary's, kept as-is:
	 *   - `\xNN` appends *two* bytes, the accumulator's low byte and its second
	 *     byte, rather than the one byte a lexer would emit; and
	 *   - the hex digits are accumulated from the *start of the subject*
	 *     (index 0) instead of from just past the `x`, so the value only comes
	 *     out right for an escape at the very beginning of the string.
	 * Both are reproduced deliberately - see the reconstruction note.
	 */
	int str_lualex(lua_State* const state)
	{
		size_t sourceLength = 0u;
		const char* const source = luaL_checklstring(state, 1, &sourceLength);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);

		char* const bufferEnd = reinterpret_cast<char*>(&buffer + 1);
		const auto prepIfFull = [&buffer, bufferEnd]() {
			if (buffer.p >= bufferEnd) {
				luaL_prepbuffer(&buffer);
			}
		};

		for (size_t index = 0u; index < sourceLength; ++index) {
			if (source[index] != '\\') {
				prepIfFull();
				*buffer.p++ = source[index];
				continue;
			}

			switch (source[++index]) {
			case 'a': prepIfFull(); *buffer.p++ = '\a'; break;
			case 'b': prepIfFull(); *buffer.p++ = '\b'; break;
			case 'f': prepIfFull(); *buffer.p++ = '\f'; break;
			case 'n': prepIfFull(); *buffer.p++ = '\n'; break;
			case 'r': prepIfFull(); *buffer.p++ = '\r'; break;
			case 't': prepIfFull(); *buffer.p++ = '\t'; break;
			case 'v': prepIfFull(); *buffer.p++ = '\v'; break;

			case 'x': {
				const int firstHex = std::tolower(static_cast<unsigned char>(source[++index]));
				if (std::isdigit(firstHex) == 0 && (firstHex < 'a' || firstHex > 'f')) {
					// Not an escape after all: back up and pass the `x` through.
					--index;
					prepIfFull();
					*buffer.p++ = 'x';
					break;
				}

				int hexValue = 0;
				int hexCursor = 0;
				int lookahead = 0;
				do {
					const int digit = std::tolower(static_cast<unsigned char>(source[hexCursor]));
					if (std::isdigit(digit) != 0) {
						hexValue = 16 * hexValue + (digit - '0');
					} else if (static_cast<unsigned int>(digit - 'a') <= 5u) {
						hexValue = 16 * hexValue + (digit - 'a' + 10);
					}

					lookahead = std::tolower(static_cast<unsigned char>(source[hexCursor + 1]));
					hexCursor += 2;
				} while ((hexCursor < 2 && std::isdigit(lookahead) != 0)
					|| (lookahead >= 'a' && lookahead <= 'f'));

				prepIfFull();
				*buffer.p++ = static_cast<char>(hexValue);
				prepIfFull();
				*buffer.p++ = static_cast<char>(hexValue >> 8);
				break;
			}

			default:
				if (std::isdigit(static_cast<unsigned char>(source[index])) != 0) {
					int decimalValue = 0;
					int digitCount = 0;
					do {
						decimalValue = 10 * decimalValue + (source[index] - '0');
						++digitCount;
						++index;
					} while (digitCount < 3 && std::isdigit(static_cast<unsigned char>(source[index])) != 0);

					prepIfFull();
					*buffer.p++ = static_cast<char>(decimalValue);
				} else {
					prepIfFull();
					*buffer.p++ = source[index];
				}
				break;
			}
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00D47158 (`strlib` registration table)
	 *
	 * What it does:
	 * The `lstrlib` registration table, read out of the image at 0x00D47158:
	 * thirteen entries whose name pointers run down through 0x00D47150 and
	 * whose function lanes are the addresses recovered above, terminated by the
	 * null row at 0x00D471C0.
	 *
	 * Twelve are stock Lua 5.0; `lualex` is this engine's, and sits last.
	 * `gmatch` is absent, as it should be for 5.0.
	 *
	 * This table is the source-level invocation for every function in it -
	 * `luaopen_string` hands it to `luaL_openlib`, which installs them by
	 * address.
	 */
	const luaL_reg kLuaStringLibrary[] = {
		{"len", &str_len},
		{"sub", &str_sub},
		{"lower", &str_lower},
		{"upper", &str_upper},
		{"char", &str_char},
		{"rep", &str_rep},
		{"byte", &str_byte},
		{"format", &str_format},
		{"dump", &str_dump},
		{"find", &str_find},
		{"gfind", &gfind},
		{"gsub", &str_gsub},
		{"lualex", &str_lualex},
		{nullptr, nullptr}
	};

	/**
	 * Address: 0x00927B10 (FUN_00927B10, luaB_foreachi)
	 *
	 * IDA signature:
	 * int __cdecl luaB_foreachi(lua_State *L);
	 *
	 * What it does:
	 * Calls f(i, t[i]) for 1..getn(t), stopping at and returning the first
	 * non-nil result.
	 */
	int LuaTableForEachIndexed(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int count = luaL_getn(state, 1);

		for (int index = 1; index <= count; ++index) {
			lua_pushvalue(state, 2);
			lua_pushnumber(state, static_cast<lua_Number>(index));
			lua_rawgeti(state, 1, index);
			LuaCallUnprotected(state, 2, 1);
			if (lua_type(state, -1) != LUA_TNIL) {
				return 1;
			}
			lua_settop(state, -2);
		}

		return 0;
	}

	/**
	 * Address: 0x00927BA0 (FUN_00927BA0, luaB_foreach)
	 *
	 * IDA signature:
	 * int __cdecl luaB_foreach(lua_State *L);
	 *
	 * What it does:
	 * Calls f(k, v) for every pair, stopping at and returning the first non-nil
	 * result.
	 */
	int LuaTableForEach(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);

		lua_pushnil(state);
		while (lua_next(state, 1) != 0) {
			lua_pushvalue(state, 2);
			lua_pushvalue(state, -3);
			lua_pushvalue(state, -3);
			LuaCallUnprotected(state, 2, 1);
			if (lua_type(state, -1) != LUA_TNIL) {
				return 1;
			}
			lua_settop(state, -3);
		}

		return 0;
	}

	/**
	 * Address: 0x00927C20 (FUN_00927C20, luaB_getn)
	 *
	 * IDA signature:
	 * int __cdecl luaB_getn(lua_State *L);
	 */
	int LuaTableGetN(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		lua_pushnumber(state, static_cast<lua_Number>(luaL_getn(state, 1)));
		return 1;
	}

	/**
	 * Address: 0x00927C60 (FUN_00927C60, luaB_setn)
	 *
	 * IDA signature:
	 * int __cdecl luaB_setn(lua_State *L);
	 */
	int LuaTableSetN(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const auto count = static_cast<int>(luaL_checknumber(state, 2));
		luaL_setn(state, 1, count);
		return 0;
	}

	/**
	 * Address: 0x00927C90 (FUN_00927C90, luaB_tinsert)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tinsert(lua_State *L);
	 *
	 * What it does:
	 * table.insert(t, v) appends; table.insert(t, pos, v) shifts everything from
	 * pos up one and writes v there. Inserting past the end grows n to the given
	 * position.
	 */
	int LuaTableInsert(lua_State* const state)
	{
		int valueIndex = lua_gettop(state);
		luaL_checktype(state, 1, LUA_TTABLE);

		const int currentCount = luaL_getn(state, 1);
		int newCount = currentCount + 1;
		int position = 0;

		if (valueIndex == 2) {
			position = currentCount + 1;
		} else {
			position = static_cast<int>(luaL_checknumber(state, 2));
			if (position > newCount) {
				newCount = position;
			}
			valueIndex = 3;
		}

		luaL_setn(state, 1, newCount);
		for (int slot = newCount - 1; slot >= position; --slot) {
			lua_rawgeti(state, 1, slot);
			lua_rawseti(state, 1, slot + 1);
		}

		lua_pushvalue(state, valueIndex);
		lua_rawseti(state, 1, position);
		return 0;
	}

	/**
	 * Address: 0x00927D30 (FUN_00927D30, luaB_tremove)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tremove(lua_State *L);
	 *
	 * What it does:
	 * Removes t[pos] (default n), shifts the tail down, and returns the removed
	 * value. An empty table returns nothing at all.
	 */
	int LuaTableRemove(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);

		const int count = luaL_getn(state, 1);
		const auto position = static_cast<int>(luaL_optnumber(state, 2, static_cast<lua_Number>(count)));
		if (count <= 0) {
			return 0;
		}

		luaL_setn(state, 1, count - 1);
		lua_rawgeti(state, 1, position);
		for (int slot = position; slot < count; ++slot) {
			lua_rawgeti(state, 1, slot + 1);
			lua_rawseti(state, 1, slot);
		}

		lua_pushnil(state);
		lua_rawseti(state, 1, count);
		return 1;
	}

	/**
	 * Address: 0x00927DD0 (FUN_00927DD0, str_concat)
	 *
	 * IDA signature:
	 * int __cdecl str_concat(lua_State *L);
	 *
	 * What it does:
	 * table.concat(t, sep, i, j) - joins t[i..j] with sep, defaulting to the
	 * whole array part and an empty separator.
	 */
	int LuaTableConcat(lua_State* const state)
	{
		std::size_t separatorLength = 0;
		const char* const separator = luaL_optlstring(state, 2, "", &separatorLength);
		int first = static_cast<int>(luaL_optnumber(state, 3, 1.0));
		int last = static_cast<int>(luaL_optnumber(state, 4, 0.0));

		luaL_checktype(state, 1, LUA_TTABLE);
		if (last == 0) {
			last = luaL_getn(state, 1);
		}

		luaL_Buffer buffer;
		luaL_buffinit(state, &buffer);
		for (; first <= last; ++first) {
			lua_rawgeti(state, 1, first);
			if (lua_isstring(state, -1) == 0) {
				luaL_argerror(state, 1, "table contains non-strings");
			}
			luaL_addvalue(&buffer);
			if (first != last) {
				luaL_addlstring(&buffer, separator, separatorLength);
			}
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Compares two stack slots the way the sort was asked to: through the
	 * comparator parked at index 2 when there is one, and with lua_lessthan when
	 * index 2 is nil. The comparator path pushes the function first, so the two
	 * operand indices shift by one and two respectively.
	 */
	[[nodiscard]] bool LuaSortCompare(lua_State* const state, const int leftIndex, const int rightIndex)
	{
		if (lua_type(state, 2) == LUA_TNIL) {
			return lua_lessthan(state, leftIndex, rightIndex) != 0;
		}

		lua_pushvalue(state, 2);
		lua_pushvalue(state, leftIndex < 0 ? leftIndex - 1 : leftIndex);
		lua_pushvalue(state, rightIndex < 0 ? rightIndex - 2 : rightIndex);
		LuaCallUnprotected(state, 2, 1);
		const bool result = lua_toboolean(state, -1) != 0;
		lua_settop(state, -2);
		return result;
	}

	/**
	 * Writes the two values on top of the stack into t[i] and t[j].
	 */
	void LuaSortSet2(lua_State* const state, const int i, const int j)
	{
		lua_rawseti(state, 1, i);
		lua_rawseti(state, 1, j);
	}

	/**
	 * Address: 0x00927F60 (FUN_00927F60, auxsort)
	 *
	 * IDA signature:
	 * void __cdecl auxsort(lua_State *L, int l, int u);
	 *
	 * What it does:
	 * Quicksort over t[l..u]: orders the ends, medians the middle into u-1 as the
	 * pivot, partitions around it, then recurses into the smaller half and loops
	 * on the larger one. A comparator that never settles walks an index off the
	 * range, which is the "invalid order function for sorting" case.
	 */
	void LuaTableAuxSort(lua_State* const state, int lower, int upper)
	{
		while (lower < upper) {
			lua_rawgeti(state, 1, lower);
			lua_rawgeti(state, 1, upper);
			if (LuaSortCompare(state, -1, -2)) {
				LuaSortSet2(state, lower, upper);
			} else {
				lua_settop(state, -3);
			}

			if (upper - lower == 1) {
				break;
			}

			const int middle = (lower + upper) / 2;
			lua_rawgeti(state, 1, middle);
			lua_rawgeti(state, 1, lower);
			if (LuaSortCompare(state, -2, -1)) {
				LuaSortSet2(state, middle, lower);
			} else {
				lua_settop(state, -2);
				lua_rawgeti(state, 1, upper);
				if (LuaSortCompare(state, -1, -2)) {
					LuaSortSet2(state, middle, upper);
				} else {
					lua_settop(state, -3);
				}
			}

			if (upper - lower == 2) {
				break;
			}

			lua_rawgeti(state, 1, middle);
			lua_pushvalue(state, -1);
			const int pivotSlot = upper - 1;
			lua_rawgeti(state, 1, pivotSlot);
			LuaSortSet2(state, middle, pivotSlot);

			int i = lower;
			int j = pivotSlot;
			for (;;) {
				lua_rawgeti(state, 1, ++i);
				while (LuaSortCompare(state, -1, -2)) {
					if (i > upper) {
						luaL_error(state, "invalid order function for sorting");
					}
					lua_settop(state, -2);
					lua_rawgeti(state, 1, ++i);
				}

				lua_rawgeti(state, 1, --j);
				while (LuaSortCompare(state, -3, -1)) {
					if (j < lower) {
						luaL_error(state, "invalid order function for sorting");
					}
					lua_settop(state, -2);
					lua_rawgeti(state, 1, --j);
				}

				if (j < i) {
					break;
				}
				LuaSortSet2(state, i, j);
			}

			lua_settop(state, -4);
			lua_rawgeti(state, 1, pivotSlot);
			lua_rawgeti(state, 1, i);
			LuaSortSet2(state, pivotSlot, i);

			int recurseLower = 0;
			int recurseUpper = 0;
			if (i - lower >= upper - i) {
				recurseLower = i + 1;
				recurseUpper = upper;
				upper = i - 1;
			} else {
				recurseLower = lower;
				recurseUpper = i - 1;
				lower = i + 1;
			}
			LuaTableAuxSort(state, recurseLower, recurseUpper);
		}
	}

	/**
	 * Address: 0x00928360 (FUN_00928360, luaB_sort)
	 *
	 * IDA signature:
	 * int __cdecl luaB_sort(lua_State *L);
	 *
	 * What it does:
	 * table.sort(t [, comp]). Note there is no type check on the comparator: the
	 * fork accepts any callable and LuaSortCompare only asks whether index 2 is
	 * nil. Stock ltablib checks it against LUA_TFUNCTION, which is 6 in stock
	 * numbering but the *C* function tag in this fork, so the vendored copy of
	 * this function rejects every Lua comparator with "cfunction expected, got
	 * function".
	 */
	int LuaTableSort(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int count = luaL_getn(state, 1);
		luaL_checkstack(state, 40, "");
		lua_settop(state, 2);
		LuaTableAuxSort(state, 1, count);
		return 0;
	}

	/**
	 * Address: 0x00D47418 (tab_funcs)
	 *
	 * The "table" library registration array, read out of the shipped image:
	 * eight rows in this order, terminated by the null row. This table is the
	 * source-level invocation for every function in it.
	 */
	const luaL_reg kLuaTableLibrary[] = {
		{"concat", &LuaTableConcat},
		{"foreach", &LuaTableForEach},
		{"foreachi", &LuaTableForEachIndexed},
		{"getn", &LuaTableGetN},
		{"setn", &LuaTableSetN},
		{"sort", &LuaTableSort},
		{"insert", &LuaTableInsert},
		{"remove", &LuaTableRemove},
		{nullptr, nullptr}
	};

	/**
	 * Address: 0x009283A0 (FUN_009283A0, luaopen_table)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_table(lua_State *L);
	 *
	 * What it does:
	 * Opens the "table" library.
	 *
	 * Named apart from the binary's symbol for the same reason LuaOpenString is:
	 * the prebuilt LuaPlus library exports its own luaopen_table, and that copy
	 * was compiled against stock tag numbering.
	 */
	int LuaOpenTable(lua_State* const state)
	{
		luaL_openlib(state, "table", kLuaTableLibrary, 0);
		return 1;
	}

	/**
	 * Address: 0x00926EF0 (FUN_00926EF0, luaopen_string)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_string(lua_State *L);
	 *
	 * What it does:
	 * Opens the "string" library and then makes that same table the default
	 * metatable for every string value, which is what lets `("x"):upper()` and
	 * `s:sub(1,2)` resolve without a per-string metatable.
	 *
	 * The type argument to `lua_setdefaultmetatable` is 4 - LUA_TSTRING in this
	 * fork's tag numbering.
	 *
	 * Named apart from the binary's symbol for the same reason `LuaOpenIo` is:
	 * the prebuilt LuaPlus library exports its own `luaopen_string`, and while
	 * that one is what currently answers, it walks a `lua_State` this tree
	 * lays out differently and misreads its arguments - `string.gsub` in
	 * particular rejects every replacement as neither string nor function.
	 */
	int LuaOpenString(lua_State* const state)
	{
		luaL_openlib(state, "string", kLuaStringLibrary, 0);
		lua_pushstring(state, "string");
		lua_gettable(state, LUA_GLOBALSINDEX);
		lua_setdefaultmetatable(state, LUA_TSTRING);
		return 1;
	}

	/**
	 * Address: 0x00919930 (FUN_00919930)
	 *
	 * What it does:
	 * Bridges one Lua numeric value into `frexp` mantissa/exponent extraction
	 * and returns the mantissa lane as `double`.
	 */
	double LuaFrexpMantissaBridgeA(const lua_Number value, int* const exponentOut)
	{
		if (exponentOut == nullptr) {
			errno = EINVAL;
			return 0.0;
		}

		return std::frexp(static_cast<double>(value), exponentOut);
	}

	/**
	 * Address: 0x00919950 (FUN_00919950)
	 *
	 * What it does:
	 * Bridges one Lua numeric value plus exponent lane into `ldexp`.
	 */
	double LuaLdexpBridgeA(const lua_Number value, const int exponent)
	{
		return std::ldexp(static_cast<double>(value), exponent);
	}

	/**
	 * Address: 0x009199F0 (FUN_009199F0)
	 *
	 * What it does:
	 * Secondary dispatch lane into the Lua `frexp` bridge helper.
	 */
	double LuaFrexpMantissaBridgeB(const lua_Number value, int* const exponentOut)
	{
		return LuaFrexpMantissaBridgeA(value, exponentOut);
	}

	/**
	 * Address: 0x00919A10 (FUN_00919A10)
	 *
	 * What it does:
	 * Secondary dispatch lane into the Lua `ldexp` bridge helper.
	 */
	double LuaLdexpBridgeB(const lua_Number value, const int exponent)
	{
		return LuaLdexpBridgeA(value, exponent);
	}

	/**
	 * Address: 0x009199B0 (FUN_009199B0)
	 *
	 * What it does:
	 * Promotes one Lua numeric value to `double`, applies `ceil`, and returns
	 * the x87-compatible double-precision result lane.
	 */
	double LuaCeilBridge(const lua_Number value)
	{
		return std::ceil(static_cast<double>(value));
	}

	/**
	 * Address: 0x00919A50 (FUN_00919A50, math_abs)
	 *
	 * What it does:
	 * Computes `abs(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_abs(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::fabs(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919A80 (FUN_00919A80, math_sin)
	 *
	 * What it does:
	 * Computes `sin(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_sin(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::sin(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919AB0 (FUN_00919AB0, math_cos)
	 *
	 * What it does:
	 * Computes `cos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_cos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::cos(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919AE0 (FUN_00919AE0, math_tan)
	 *
	 * What it does:
	 * Computes `tan(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_tan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::tan(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919B40 (FUN_00919B40, math_acos)
	 *
	 * What it does:
	 * Computes `acos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_acos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::acos(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919B70 (FUN_00919B70, math_atan)
	 *
	 * What it does:
	 * Computes `atan(arg1)` (x87 `fpatan` lane with denominator `1.0`) and
	 * pushes one Lua numeric result.
	 */
	int math_atan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::atan2(static_cast<double>(value), 1.0))
		);
		return 1;
	}

	/**
	 * Address: 0x00919BA0 (FUN_00919BA0, math_atan2)
	 *
	 * What it does:
	 * Computes `atan2(arg1, arg2)` with Lua numeric argument validation and
	 * pushes one Lua numeric result.
	 */
	int math_atan2(lua_State* const state)
	{
		const lua_Number numerator = luaL_checknumber(state, 1);
		const lua_Number denominator = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::atan2(static_cast<double>(numerator), static_cast<double>(denominator)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919BE0 (FUN_00919BE0, math_ceil)
	 *
	 * What it does:
	 * Computes `ceil(arg1)` with Lua numeric argument validation and pushes one
	 * resulting Lua number.
	 */
	int math_ceil(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(LuaCeilBridge(value)));
		return 1;
	}

	/**
	 * Address: 0x00919C10 (FUN_00919C10, math_floor)
	 *
	 * What it does:
	 * Computes `floor(arg1)` with Lua numeric argument validation and pushes
	 * one resulting Lua number.
	 */
	int math_floor(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::floor(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919C40 (FUN_00919C40, math_mod)
	 *
	 * What it does:
	 * Computes `fmod(arg1, arg2)` with Lua numeric argument checks and pushes
	 * one Lua numeric result.
	 */
	int math_mod(lua_State* const state)
	{
		const lua_Number left = luaL_checknumber(state, 1);
		const lua_Number right = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::fmod(static_cast<double>(left), static_cast<double>(right)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919C80 (FUN_00919C80, math_sqrt)
	 *
	 * What it does:
	 * Computes `sqrt(arg1)` with Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_sqrt(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::sqrt(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919CB0 (FUN_00919CB0, math_pow)
	 *
	 * What it does:
	 * Computes `pow(arg1, arg2)` with Lua numeric argument checks and pushes
	 * one Lua numeric result.
	 */
	int math_pow(lua_State* const state)
	{
		const lua_Number base = luaL_checknumber(state, 1);
		const lua_Number exponent = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::pow(static_cast<double>(base), static_cast<double>(exponent)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919CF0 (FUN_00919CF0, math_log)
	 *
	 * What it does:
	 * Computes natural logarithm for arg-1 (`ln`) and pushes one Lua numeric
	 * result.
	 */
	int math_log(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::log(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D20 (FUN_00919D20, math_log10)
	 *
	 * What it does:
	 * Computes base-10 logarithm for arg-1 and pushes one Lua numeric result.
	 */
	int math_log10(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::log10(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D50 (FUN_00919D50, math_exp)
	 *
	 * What it does:
	 * Computes exponential (`e^arg1`) and pushes one Lua numeric result.
	 */
	int math_exp(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::exp(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D90 (FUN_00919D90, math_deg)
	 *
	 * What it does:
	 * Converts radians (arg-1) to degrees and pushes one Lua numeric result.
	 */
	int math_deg(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, value * static_cast<lua_Number>(57.29578f));
		return 1;
	}

	/**
	 * Address: 0x00919DC0 (FUN_00919DC0, math_rad)
	 *
	 * What it does:
	 * Converts degrees (arg-1) to radians and pushes one Lua numeric result.
	 */
	int math_rad(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, value * static_cast<lua_Number>(0.017453292f));
		return 1;
	}

	/**
	 * Address: 0x00919DF0 (FUN_00919DF0, math_frexp)
	 *
	 * What it does:
	 * Computes `frexp(arg1, &exp)` and pushes both mantissa and exponent as Lua
	 * numeric results.
	 */
	int math_frexp(lua_State* const state)
	{
		int exponent = 0;
		const lua_Number value = luaL_checknumber(state, 1);
		const lua_Number mantissa = static_cast<lua_Number>(LuaFrexpMantissaBridgeB(value, &exponent));
		lua_pushnumber(state, mantissa);
		lua_pushnumber(state, static_cast<lua_Number>(exponent));
		return 2;
	}

	/**
	 * Address: 0x00919E40 (FUN_00919E40, math_ldexp)
	 *
	 * What it does:
	 * Computes `ldexp(arg1, int(arg2))` with Lua numeric argument checks and
	 * returns the result as one Lua number.
	 */
	int math_ldexp(lua_State* const state)
	{
		const int exponent = static_cast<int>(luaL_checknumber(state, 2));
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(LuaLdexpBridgeB(value, exponent)));
		return 1;
	}

	/**
	 * Address: 0x00919E90 (FUN_00919E90, math_min)
	 *
	 * What it does:
	 * Returns the minimum numeric value across all Lua arguments.
	 */
	int math_min(lua_State* const state)
	{
		const int valueCount = lua_gettop(state);
		lua_Number currentMinimum = luaL_checknumber(state, 1);

		for (int index = 2; index <= valueCount; ++index) {
			const lua_Number value = luaL_checknumber(state, index);
			if (currentMinimum > value) {
				currentMinimum = value;
			}
		}

		lua_pushnumber(state, currentMinimum);
		return 1;
	}

	/**
	 * Address: 0x00919F10 (FUN_00919F10, math_max)
	 *
	 * What it does:
	 * Returns the maximum numeric value across all Lua arguments.
	 */
	int math_max(lua_State* const state)
	{
		const int valueCount = lua_gettop(state);
		lua_Number currentMaximum = luaL_checknumber(state, 1);

		for (int index = 2; index <= valueCount; ++index) {
			const lua_Number value = luaL_checknumber(state, index);
			if (value > currentMaximum) {
				currentMaximum = value;
			}
		}

		lua_pushnumber(state, currentMaximum);
		return 1;
	}

	/**
	 * Address: 0x0091A0D0 (FUN_0091A0D0, math_randomseed)
	 *
	 * What it does:
	 * Reads one numeric seed argument, truncates it to integer seed lane, and
	 * re-seeds the C runtime RNG.
	 */
	int math_randomseed(lua_State* const state)
	{
		const auto seed = static_cast<unsigned int>(luaL_checknumber(state, 1));
		std::srand(seed);
		return 0;
	}

	/**
	 * Address: 0x00919B10 (FUN_00919B10, math_asin)
	 *
	 * What it does:
	 * Computes `asin(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_asin(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::asin(static_cast<double>(value))));
		return 1;
	}

	/**
	 * The scale the engine applies to `rand()` to reach [0,1).
	 *
	 * This is 0x38000100, which is NOT 1/32768 (that would be 0x38000000) - the
	 * fork's constant is a hair larger. Kept bit-exact rather than "corrected",
	 * because `math.random` feeds simulation code and any drift here desyncs.
	 */
	constexpr float kLuaRandomScale = 3.0518509447574615e-05f;

	/**
	 * Address: 0x00919F90 (FUN_00919F90, math_random)
	 *
	 * IDA signature:
	 * int __usercall math_random@<eax>(__m128i a1@<xmm0>, lua_State *L);
	 *
	 * What it does:
	 * Lua's three-form `math.random`: no argument yields the raw [0,1) sample,
	 * one argument `u` yields an integer in [1,u], and two arguments `l,u` yield
	 * an integer in [l,u]. The sample is drawn once up front, before the
	 * argument count is even read, so the RNG advances on every call regardless
	 * of form.
	 */
	int math_random(lua_State* const state)
	{
		const float sample = static_cast<float>(std::rand() % 0x7FFF) * kLuaRandomScale;

		const int argumentCount = lua_gettop(state);
		if (argumentCount == 0) {
			lua_pushnumber(state, sample);
			return 1;
		}

		if (argumentCount == 1) {
			const int upper = static_cast<int>(luaL_checknumber(state, 1));
			if (upper < 1) {
				luaL_argerror(state, 1, "interval is empty");
			}
			lua_pushnumber(
				state, static_cast<lua_Number>(std::floor(sample * static_cast<double>(upper)) + 1.0)
			);
			return 1;
		}

		if (argumentCount != 2) {
			luaL_error(state, "wrong number of arguments");
		}

		const int lower = static_cast<int>(luaL_checknumber(state, 1));
		const int upper = static_cast<int>(luaL_checknumber(state, 2));
		if (lower > upper) {
			luaL_argerror(state, 2, "interval is empty");
		}
		lua_pushnumber(
			state,
			static_cast<lua_Number>(
				std::floor(sample * static_cast<double>(upper - lower + 1)) + static_cast<double>(lower)
			)
		);
		return 1;
	}

	/**
	 * The `math` library registration table at 0x00D46278.
	 *
	 * Order is taken from the binary's .rdata, not from stock Lua 5.0: this fork
	 * lists `pow` between `deg` and `rad` rather than after `randomseed`.
	 */
	const luaL_reg kLuaMathLib[] = {
		{"abs", math_abs},          {"sin", math_sin},     {"cos", math_cos},
		{"tan", math_tan},          {"asin", math_asin},   {"acos", math_acos},
		{"atan", math_atan},        {"atan2", math_atan2}, {"ceil", math_ceil},
		{"floor", math_floor},      {"mod", math_mod},     {"frexp", math_frexp},
		{"ldexp", math_ldexp},      {"sqrt", math_sqrt},   {"min", math_min},
		{"max", math_max},          {"log", math_log},     {"log10", math_log10},
		{"exp", math_exp},          {"deg", math_deg},     {"pow", math_pow},
		{"rad", math_rad},          {"random", math_random},
		{"randomseed", math_randomseed},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x0091A110 (FUN_0091A110, luaopen_math)
	 *
	 * What it does:
	 * Registers the `math` library, then adds two entries the registration table
	 * cannot express: the `pi` constant, and `__pow` installed into the *globals*
	 * table rather than into `math`, which is what makes the `^` operator work.
	 *
	 * The `__pow` write targets pseudo-index -10001 (LUA_GLOBALSINDEX); only the
	 * `pi` write lands on the `math` table left on the stack by luaL_openlib.
	 */
	int LuaOpenMath(lua_State* const state)
	{
		luaL_openlib(state, "math", kLuaMathLib, 0);

		lua_pushlstring(state, "pi", 2u);
		lua_pushnumber(state, 3.1415927410125732f);
		lua_settable(state, -3);

		lua_pushlstring(state, "__pow", 5u);
		lua_pushcclosure(state, math_pow, 0);
		lua_settable(state, LUA_GLOBALSINDEX);
		return 1;
	}

	/**
	 * Address: 0x0090EE20 (FUN_0090EE20, luaB_error)
	 *
	 * What it does:
	 * Raises a Lua error from arg-1 and optionally prefixes source/line
	 * context using arg-2 stack level.
	 */
	int luaB_error(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_optnumber(state, 2, 1.0f));
		luaL_checkany(state, 1);
		if (lua_isstring(state, 1) != 0 && level != 0) {
			luaL_where(state, level);
			lua_pushvalue(state, 1);
			lua_concat(state, 2);
			return lua_error(state);
		}

		lua_pushvalue(state, 1);
		return lua_error(state);
	}

	/**
	 * Address: 0x0091A3B0 (FUN_0091A3B0, sub_91A3B0)
	 *
	 * What it does:
	 * Pushes the last Win32 error as a Lua string. Falls back to a formatted
	 * numeric message when FormatMessage itself fails, so the caller always ends
	 * up with exactly one string on the stack.
	 */
	void PushLastSystemError(lua_State* const state)
	{
		const DWORD lastError = ::GetLastError();
		CHAR buffer[128];
		if (::FormatMessageA(
				FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, lastError, 0, buffer,
				static_cast<DWORD>(sizeof(buffer)), nullptr
			) != 0) {
			lua_pushstring(state, buffer);
		} else {
			lua_pushfstring(state, "system error %d\n", lastError);
		}
	}

	/**
	 * Address: 0x0091A410 (FUN_0091A410, loadlib)
	 *
	 * What it does:
	 * `loadlib(path, symbol)` - loads a DLL and wraps the named export as a Lua
	 * C closure carrying the module handle as its one upvalue, so the module
	 * stays alive as long as the closure does.
	 *
	 * On failure it returns three values (nil, message, "open"/"init") rather
	 * than raising, and it frees the library when the load succeeded but the
	 * symbol did not resolve.
	 */
	int LuaLoadLib(lua_State* const state)
	{
		const char* const path = luaL_checklstring(state, 1, nullptr);
		const char* const symbol = luaL_checklstring(state, 2, nullptr);

		const HMODULE module = ::LoadLibraryA(path);
		if (module != nullptr) {
			if (auto* const entry =
					reinterpret_cast<lua_CFunction>(::GetProcAddress(module, symbol));
				entry != nullptr) {
				lua_pushlightuserdata(state, module);
				lua_pushcclosure(state, entry, 1);
				return 1;
			}
		}

		lua_pushnil(state);
		PushLastSystemError(state);
		lua_pushstring(state, (module != nullptr) ? "init" : "open");
		if (module != nullptr) {
			::FreeLibrary(module);
		}
		return 3;
	}

	/**
	 * Address: 0x0091A4B0 (FUN_0091A4B0, luaopen_loadlib)
	 *
	 * What it does:
	 * Installs `loadlib` straight into the globals table. Unlike the other
	 * openers there is no library table and no return value - it pushes nothing
	 * and reports zero results.
	 */
	int LuaOpenLoadLib(lua_State* const state)
	{
		lua_pushstring(state, "loadlib");
		lua_pushcclosure(state, LuaLoadLib, 0);
		lua_settable(state, LUA_GLOBALSINDEX);
		return 0;
	}

	/**
	 * Address: 0x0090EEA0 (FUN_0090EEA0, luaB_getmetatable)
	 *
	 * What it does:
	 * Returns arg-1 metatable when present; if protected `__metatable` exists,
	 * returns that field instead.
	 */
	int luaB_getmetatable(lua_State* const state)
	{
		luaL_checkany(state, 1);
		if (lua_getmetatable(state, 1) == 0) {
			lua_pushnil(state);
			return 1;
		}

		(void)luaL_getmetafield(state, 1, "__metatable");
		return 1;
	}

	void getfunc(lua_State* const state)
	{
		if (lua_isfunction(state, 1) != 0) {
			lua_pushvalue(state, 1);
			return;
		}

		::lua_Debug activationRecord{};
		const int level = static_cast<int>(luaL_optnumber(state, 1, 1.0f));
		if (level < 0) {
			luaL_argerror(state, 1, "level must be non-negative");
		}
		if (lua_getstack(state, level, &activationRecord) == 0) {
			luaL_argerror(state, 1, "invalid level");
		}

		lua_getinfo(state, "f", &activationRecord);
		if (lua_isnil(state, -1) != 0) {
			luaL_error(state, "no function environment for tail call at level %d", level);
		}
	}

	/**
	 * Address: 0x0090F050 (FUN_0090F050, luaB_getfenv)
	 *
	 * What it does:
	 * Resolves target function (object or stack level), then returns its
	 * effective environment (`__fenv` override when present).
	 */
	int luaB_getfenv(lua_State* const state)
	{
		getfunc(state);
		lua_getfenv(state, -1);
		lua_pushlstring(state, "__fenv", 6u);
		lua_rawget(state, -2);
		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -2);
		}
		return 1;
	}

	/**
	 * Address: 0x0090F160 (FUN_0090F160, luaB_rawequal)
	 *
	 * What it does:
	 * Requires two arguments, compares them with raw-equality semantics, and
	 * pushes one boolean result.
	 */
	int luaB_rawequal(lua_State* const state)
	{
		luaL_checkany(state, 1);
		luaL_checkany(state, 2);
		lua_pushboolean(state, lua_rawequal(state, 1, 2));
		return 1;
	}

	/**
	 * Address: 0x0090F190 (FUN_0090F190, luaB_rawget)
	 *
	 * What it does:
	 * Requires table + key arguments, performs one raw table lookup, and
	 * returns the retrieved value.
	 */
	int luaB_rawget(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		luaL_checkany(state, 2);
		lua_rawget(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F1C0 (FUN_0090F1C0, luaB_rawset)
	 *
	 * What it does:
	 * Requires table/key/value arguments, performs one raw table write, and
	 * returns the table lane.
	 */
	int luaB_rawset(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		luaL_checkany(state, 2);
		luaL_checkany(state, 3);
		lua_rawset(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F200 (FUN_0090F200, luaB_gcinfo)
	 *
	 * What it does:
	 * Pushes current GC count and threshold as numeric values.
	 */
	int luaB_gcinfo(lua_State* const state)
	{
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgccount(state)));
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgcthreshold(state)));
		return 2;
	}

	/**
	 * Address: 0x0090F240 (FUN_0090F240, luaB_collectgarbage)
	 *
	 * What it does:
	 * Optionally sets GC threshold from arg-1 and returns no values.
	 */
	int luaB_collectgarbage(lua_State* const state)
	{
		const lua_Number threshold = luaL_optnumber(state, 1, 0.0f);
		lua_setgcthreshold(state, static_cast<int>(threshold));
		return 0;
	}

	/**
	 * Address: 0x0090F270 (FUN_0090F270, luaB_type)
	 *
	 * What it does:
	 * Replaces arg-1 with the interned type-name string lane from
	 * `global_State::typenames` and returns it.
	 */
	int luaB_type(lua_State* const state)
	{
		luaL_checkany(state, 1);

		TObject* const top = state->top;
		const int valueTypeTag = (top - 1)->tt;
		TString* const typeName = state->l_G->typenames[valueTypeTag];
		(top - 1)->tt = static_cast<int>(typeName->tt);
		(top - 1)->value.p = typeName;
		return 1;
	}

	/**
	 * Address: 0x0090F2B0 (FUN_0090F2B0, luaB_next)
	 *
	 * What it does:
	 * Iterates one table lane with `lua_next`; returns key/value pair when
	 * available, otherwise pushes nil and returns one value.
	 */
	int luaB_next(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		lua_settop(state, 2);
		if (lua_next(state, 1) != 0) {
			return 2;
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x0090F2F0 (FUN_0090F2F0, luaB_pairs)
	 *
	 * What it does:
	 * Returns the canonical Lua `pairs` iterator triple:
	 * (`next`, table, nil).
	 */
	int luaB_pairs(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		lua_pushlstring(state, "next", 4u);
		lua_rawget(state, LUA_GLOBALSINDEX);
		lua_pushvalue(state, 1);
		lua_pushnil(state);
		return 3;
	}

	/**
	 * Address: 0x0090F330 (FUN_0090F330, luaB_ipairs)
	 *
	 * What it does:
	 * Implements the legacy Lua `ipairs` iterator lane: bootstrap call returns
	 * (`ipairs`, table, 0), subsequent calls increment numeric index and fetch
	 * array slot with `lua_rawgeti`.
	 */
	int luaB_ipairs(lua_State* const state)
	{
		const float indexValue = lua_tonumber(state, 2);
		luaL_checktype(state, 1, LUA_TTABLE);

		if (indexValue == 0.0f && lua_type(state, 2) == LUA_TNONE) {
			lua_pushlstring(state, "ipairs", 6u);
			lua_rawget(state, LUA_GLOBALSINDEX);
			lua_pushvalue(state, 1);
			lua_pushnumber(state, 0.0f);
			return 3;
		}

		const float nextIndex = indexValue + 1.0f;
		lua_pushnumber(state, nextIndex);
		lua_rawgeti(state, 1, static_cast<int>(nextIndex));
		return lua_type(state, -1) != LUA_TNIL ? 2 : 0;
	}

	/**
	 * Address: 0x0090F420 (FUN_0090F420, luaB_loadstring)
	 *
	 * What it does:
	 * Loads one Lua chunk from string input and returns either compiled
	 * function (success) or `(nil, error)` on failure.
	 */
	int luaB_loadstring(lua_State* const state)
	{
		size_t chunkLength = 0u;
		const char* const chunkText = luaL_checklstring(state, 1, &chunkLength);
		const char* const chunkName = luaL_optlstring(state, 2, chunkText, nullptr);
		if (::luaL_loadbuffer(state, chunkText, chunkLength, chunkName) == 0) {
			return 1;
		}

		lua_pushnil(state);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090F480 (FUN_0090F480, luaB_loadfile)
	 *
	 * What it does:
	 * Loads one Lua chunk from optional file path and returns either compiled
	 * function (success) or `(nil, error)` on failure.
	 */
	int luaB_loadfile(lua_State* const state)
	{
		const char* const fileName = luaL_optlstring(state, 1, nullptr, nullptr);
		if (luaL_loadfile(state, fileName) == 0) {
			return 1;
		}

		lua_pushnil(state);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090F4C0 (FUN_0090F4C0, luaB_dofile)
	 *
	 * What it does:
	 * Loads an optional file path, executes the chunk, and returns all chunk
	 * results currently on stack.
	 */
	int luaB_dofile(lua_State* const state)
	{
		const char* const fileName = luaL_optlstring(state, 1, nullptr, nullptr);
		const int baseTop = lua_gettop(state);
		if (luaL_loadfile(state, fileName) != 0) {
			lua_error(state);
		}

		lua_call(state, 0, LUA_MULTRET);
		return lua_gettop(state) - baseTop;
	}

	/**
	 * Address: 0x0090F560 (FUN_0090F560, luaB_unpack)
	 *
	 * What it does:
	 * Expands table arg-1 array part into multiple return values.
	 */
	int luaB_unpack(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int elementCount = luaL_getn(state, 1);
		luaL_checkstack(state, elementCount, "table too big to unpack");
		for (int index = 1; index <= elementCount; ++index) {
			lua_rawgeti(state, 1, index);
		}
		return elementCount;
	}

	/**
	 * Address: 0x0090F5B0 (FUN_0090F5B0, luaB_pcall)
	 *
	 * What it does:
	 * Executes protected call on arg-1 function using remaining stack args, then
	 * prepends boolean success flag to returned value lanes.
	 */
	int luaB_pcall(lua_State* const state)
	{
		luaL_checkany(state, 1);
		const int status = lua_call(state, lua_gettop(state) - 1, LUA_MULTRET);
		lua_pushboolean(state, status == 0 ? 1 : 0);
		lua_insert(state, 1);
		return lua_gettop(state);
	}

	/**
	 * Address: 0x0090F780 (FUN_0090F780, pushcomposename)
	 *
	 * What it does:
	 * Expands each '?' placeholder in the module path component using arg-1,
	 * then concatenates all generated fragments into one composed name.
	 */
	void pushcomposename(lua_State* const state)
	{
		const char* path = lua_tostring(state, -1);
		int segmentCount = 1;
		const char* wildcard = std::strchr(path, '?');
		while (wildcard != nullptr) {
			luaL_checkstack(state, 3, "too many marks in a path component");
			lua_pushlstring(state, path, static_cast<size_t>(wildcard - path));
			lua_pushvalue(state, 1);
			path = wildcard + 1;
			segmentCount += 2;
			wildcard = std::strchr(path, '?');
		}

		lua_pushstring(state, path);
		lua_concat(state, segmentCount);
	}

	/**
	 * Address: 0x0090FB60 (FUN_0090FB60, luaB_cocreate)
	 *
	 * What it does:
	 * Creates one new coroutine thread and moves arg-1 Lua function onto the
	 * new thread stack as its entry lane.
	 */
	int luaB_cocreate(lua_State* const state)
	{
		lua_State* const newThread = lua_newthread(state);
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		lua_pushvalue(state, 1);
		lua_xmove(state, newThread, 1);
		return 1;
	}

	/**
	 * Address: 0x0090FC10 (FUN_0090FC10, luaB_yield)
	 *
	 * What it does:
	 * Yields current coroutine with all values currently present on stack.
	 */
	int luaB_yield(lua_State* const state)
	{
		return lua_yield(state, lua_gettop(state));
	}

	/**
	 * Address: 0x00914580 (FUN_00914580, resume)
	 *
	 * What it does:
	 * Applies one coroutine resume step: restores pending frame state when
	 * resuming after yield, executes VM, then finalizes any immediate return.
	 */
	void resume(int* const userData, lua_State* const state)
	{
		const int argumentCount = *userData;
		CallInfo* const currentFrame = state->ci;

		if (currentFrame == state->base_ci) {
			(void)luaD_precall(state, &state->top[-argumentCount - 1]);
		} else if (currentFrame->state == 4) {
			CallInfo* const previousFrame = currentFrame - 1;
			const std::uint32_t instruction = static_cast<std::uint32_t>(*(previousFrame->savedpc - 1));
			previousFrame->state = 0;

			const int wantedResults = static_cast<int>((instruction >> 6u) & 0x1FFu) - 1;
			(void)luaD_poscall(state, wantedResults, &state->top[-argumentCount]);
			if (wantedResults >= 0) {
				state->top = state->ci->top;
			}
		} else {
			currentFrame->state = 0;
		}

		StkId firstResult = luaV_execute(state);
		if (firstResult != nullptr) {
			(void)luaD_poscall(state, -1, firstResult);
		}
	}

	/**
	 * Address: 0x00913CF0 (FUN_00913CF0, callrethooks)
	 *
	 * What it does:
	 * Emits return and tail-return debug hook events for one completed frame and
	 * remaps `firstResult` to the current stack base after hook side effects.
	 */
	StkId callrethooks(StkId firstResult, lua_State* const state)
	{
		constexpr int kCiSavedPc = 3;

		const std::ptrdiff_t resultOffset = firstResult - state->stack;
		luaD_callhook(state, LUA_HOOKRET, -1);

		CallInfo* const currentFrame = state->ci;
		if (currentFrame->state < kCiSavedPc) {
			if (currentFrame->tailcalls != 0) {
				do {
					--state->ci->tailcalls;
					luaD_callhook(state, LUA_HOOKTAILRET, -1);
				} while (state->ci->tailcalls != 0);
			}
			--state->ci->tailcalls;
		}

		return state->stack + resultOffset;
	}

	/**
	 * Address: 0x00913DC0 (FUN_00913DC0, resume_error)
	 *
	 * What it does:
	 * Pushes one interned error string into the coroutine base slot, grows the
	 * stack when needed, and returns a single Lua result lane.
	 */
	int resume_error(lua_State* const state, const char* const message)
	{
		TObject* const base = state->ci->base;
		state->top = base;

		TString* const errorString = luaS_newlstr(state, message, std::strlen(message));
		base->tt = errorString->tt;
		base->value.p = errorString;

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return 1;
	}

	/**
	 * A `CallInfo::state` of 4 marks a frame that yielded; 2 marks one that is
	 * still inside a C function. Only those two can be resumed.
	 */
	constexpr int kCallInfoStateYielded = 4;
	constexpr int kCallInfoStateInC = 2;

	/**
	 * The threshold `lua_yield` tests: a frame at 3 or above is running Lua code
	 * and yields for real, anything below has not started and is only marked as
	 * being in C.
	 */
	constexpr int kCallInfoStateRunningLuaFrame = 3;

	/** Argument C of an instruction: bits 6..14. */
	[[nodiscard]] constexpr int GetInstructionArgC(const Instruction instruction)
	{
		return static_cast<int>((instruction >> 6) & 0x1FFu);
	}

	/**
	 * Address: 0x00914580 (FUN_00914580, resume)
	 *
	 * IDA signature:
	 * void __usercall resume(int *ud@<eax>, lua_State *L@<edi>);
	 *
	 * What it does:
	 * The body `lua_resume` runs inside its protected region. Either starts the
	 * coroutine's function, or picks the suspended frame back up - a frame that
	 * yielded finishes the call that yielded first, using the result count of
	 * the instruction that issued it - and then runs the interpreter.
	 */
	void resume(lua_State* const state, const int nargs)
	{
		CallInfo* const ci = state->ci;

		if (ci == state->base_ci) {
			// First resume: start the coroutine body itself.
			luaD_precall(state, state->top - (nargs + 1));
		} else if (ci->state == kCallInfoStateYielded) {
			// Finish the call that yielded. Its result count comes from argument
			// C of the CALL instruction that issued it, which sits one word
			// behind the saved program counter of the caller's frame.
			const int nresults = GetInstructionArgC(ci[-1].savedpc[-1]) - 1;
			ci[-1].state = 0;

			luaD_poscall(state, nresults, state->top - nargs);
			if (nresults >= 0) {
				state->top = state->ci->top;
			}
		} else {
			ci->state = 0;
		}

		StkId const firstResult = luaV_execute(state);
		if (firstResult != nullptr) {
			luaD_poscall(state, -1, firstResult);
		}
	}

	/**
	 * Unwinds a coroutine back to its base frame after `resume` threw, leaving
	 * the error text as the single value on its stack.
	 */
	void RestoreCoroutineAfterError(
		lua_State* const state, const char* const errorText, const lu_byte savedAllowHook
	)
	{
		state->ci = state->base_ci;
		state->base = state->ci->base;
		state->nCcalls = 0;

		luaF_close(state, state->base);
		(void)PushLuaStringAtStackSlot(state, state->base, errorText);

		state->l_G->allowhook = savedAllowHook;
		(void)luaD_refreshstacklimit(state);
	}

	/**
	 * Address: 0x00913E40 (FUN_00913E40, lua_yield)
	 *
	 * IDA signature:
	 * int __cdecl lua_yield(lua_State *L, int nresults);
	 *
	 * What it does:
	 * Suspends the running coroutine. A frame that has not started executing Lua
	 * yet (`state < 3`) is only marked as sitting in C; a live Lua frame first
	 * refuses to yield across a C function, then slides its `nresults` return
	 * values down to the frame base, trims the stack to them, and marks itself
	 * yielded. Always returns -1, which `luaD_precall` reads as "this frame did
	 * not produce results here".
	 *
	 * The two state values are the whole point, and the binary spells them out:
	 *
	 *   0x00913EF0: mov dword ptr [edi+8], 2   ; state < 3  -> in-C
	 *   0x00913EE2: mov dword ptr [edi+8], 4   ; otherwise  -> yielded
	 *
	 * which are exactly the two values `lua_resume` accepts. Until this was
	 * recovered the call resolved to the prebuilt LuaPlus library instead, and
	 * that build writes stock Lua 5.0 `CI_*` bitmask flags into the same field.
	 * Our `lua_resume` then compared them against this fork's enum, found
	 * neither 4 nor 2, and rejected every resume with "cannot resume
	 * non-suspended coroutine" - which killed the script driving the intro
	 * movies.
	 */
	extern "C" int lua_yield(lua_State* const state, const int nresults)
	{
		CallInfo* const ci = state->ci;

		if (state->nCcalls != 0) {
			luaG_runerror(state, "attempt to yield across metamethod/C-call boundary");
		}

		if (ci->state < kCallInfoStateRunningLuaFrame) {
			ci->state = kCallInfoStateInC;
			return -1;
		}

		if (ci[-1].state != 0) {
			luaG_runerror(state, "cannot yield a C function");
		}

		// Only move anything when the results are not already sitting at the
		// frame base; the binary guards the whole block on this comparison.
		if (&state->top[-nresults] > state->base) {
			for (int i = 0; i < nresults; ++i) {
				state->base[i] = state->top[i - nresults];
			}
			state->top = &state->base[nresults];
		}

		ci->state = kCallInfoStateYielded;
		return -1;
	}

	/**
	 * Address: 0x00914610 (FUN_00914610, lua_resume)
	 *
	 * IDA signature:
	 * int __cdecl lua_resume(lua_State *L, int nargs);
	 *
	 * What it does:
	 * Resumes a coroutine: rejects one that is dead or not suspended, then runs
	 * `resume` protected. On the way out of an error it rewinds to the base
	 * frame, closes pending upvalues, replaces the stack with the error text
	 * and restores the hook flag, returning the raised lua::lua_Error's own
	 * code (or LUA_ERRRUN for anything else that escapes).
	 *
	 * Like lua_call this fork protects with a C++ try rather than a setjmp, so
	 * the two handlers at 0x009146BF and 0x00914728 are the EH funclets the
	 * decompiler elides - `luaD_rawrunprotected` does not exist here.
	 *
	 * Recovering this matters beyond fidelity: while it resolved to the
	 * prebuilt LuaPlus library, resume walked our coroutine at stock Lua
	 * offsets and wrote 12-byte TObjects onto an 8-byte stack, so every script
	 * error came back as a garbage value - "<non-string lua error>".
	 */
	extern "C" int lua_resume(lua_State* const state, const int nargs)
	{
		CallInfo* const ci = state->ci;

		if (ci == state->base_ci) {
			if (nargs >= state->top - state->base) {
				return resume_error(state, "cannot resume dead coroutine");
			}
		} else if (ci->state != kCallInfoStateYielded && ci->state != kCallInfoStateInC) {
			return resume_error(state, "cannot resume non-suspended coroutine");
		}

		const lu_byte savedAllowHook = state->l_G->allowhook;

		try {
			resume(state, nargs);
		} catch (const lua::lua_Error& error) {
			RestoreCoroutineAfterError(state, error.what(), savedAllowHook);
			return error.code;
		} catch (const std::exception& error) {
			RestoreCoroutineAfterError(state, error.what(), savedAllowHook);
			return LUA_ERRRUN;
		}

		return 0;
	}

	/**
	 * Address: 0x0090FA00 (FUN_0090FA00, auxresume)
	 *
	 * What it does:
	 * Moves resume arguments into target coroutine, executes one resume, then
	 * moves either one error object or all yielded/returned values back.
	 */
	int auxresume(const int argumentCount, lua_State* const callerState, lua_State* const coroutineState)
	{
		if (lua_checkstack(coroutineState, argumentCount) == 0) {
			luaL_error(callerState, "too many arguments to resume");
		}

		lua_xmove(callerState, coroutineState, argumentCount);
		if (lua_resume(coroutineState, argumentCount) != 0) {
			lua_xmove(coroutineState, callerState, 1);
			return -1;
		}

		const int resultCount = lua_gettop(coroutineState);
		if (lua_checkstack(callerState, resultCount) == 0) {
			luaL_error(callerState, "too many results to resume");
		}

		lua_xmove(coroutineState, callerState, resultCount);
		return resultCount;
	}

	/**
	 * Address: 0x0090FA80 (FUN_0090FA80, luaB_coresume)
	 *
	 * What it does:
	 * Resumes coroutine from arg-1 using remaining args, returning status boolean
	 * plus coroutine results (or status false + error object).
	 */
	int luaB_coresume(lua_State* const state)
	{
		lua_State* const coroutineState = lua_tothread(state, 1);
		if (coroutineState == nullptr) {
			luaL_argerror(state, 1, "coroutine expected");
		}

		const int resumeResultCount = auxresume(lua_gettop(state) - 1, state, coroutineState);
		if (resumeResultCount >= 0) {
			lua_pushboolean(state, 1);
			lua_insert(state, -1 - resumeResultCount);
			return resumeResultCount + 1;
		}

		lua_pushboolean(state, 0);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090FB00 (FUN_0090FB00, luaB_auxwrap)
	 *
	 * What it does:
	 * Upvalue-bound coroutine wrapper: resumes coroutine with call args and
	 * propagates errors with traceback context.
	 */
	int luaB_auxwrap(lua_State* const state)
	{
		lua_State* const coroutineState = lua_tothread(state, lua_upvalueindex(1));
		const int resultCount = auxresume(lua_gettop(state), state, coroutineState);
		if (resultCount < 0) {
			if (lua_isstring(state, -1) != 0) {
				luaL_where(state, 1);
				lua_insert(state, -2);
				lua_concat(state, 2);
			}
			lua_error(state);
		}
		return resultCount;
	}

	/**
	 * Address: 0x0090FBB0 (FUN_0090FBB0, luaB_cowrap)
	 *
	 * What it does:
	 * Creates one coroutine from arg-1 Lua function and returns one closure that
	 * resumes it through `luaB_auxwrap`.
	 */
	int luaB_cowrap(lua_State* const state)
	{
		lua_State* const newThread = lua_newthread(state);
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		lua_pushvalue(state, 1);
		lua_xmove(state, newThread, 1);
		lua_pushcclosure(state, luaB_auxwrap, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F510 (FUN_0090F510, luaB_assert)
	 *
	 * What it does:
	 * Validates arg-1 presence/truthiness, raises Lua assertion error with
	 * optional arg-2 message, and returns arg-1 as the only result on success.
	 */
	int luaB_assert(lua_State* const state)
	{
		luaL_checkany(state, 1);
		if (lua_toboolean(state, 1) == 0) {
			const char* const message = luaL_optlstring(state, 2, "assertion failed!", nullptr);
			luaL_error(state, "%s", message);
		}

		lua_settop(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090EEF0 (FUN_0090EEF0, luaB_setmetatable)
	 *
	 * What it does:
	 * Sets one table metatable after validating arg-2 type (`nil|table`) and
	 * rejecting protected `__metatable` lanes.
	 */
	int luaB_setmetatable(lua_State* const state)
	{
		const int metatableType = lua_type(state, 2);
		luaL_checktype(state, 1, LUA_TTABLE);

		if (metatableType != LUA_TNIL && metatableType != LUA_TTABLE) {
			luaL_argerror(state, 2, "nil or table expected");
		}

		if (luaL_getmetafield(state, 1, "__metatable") != 0) {
			luaL_error(state, "cannot change a protected metatable");
		}

		lua_settop(state, 2);
		lua_setmetatable(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F600 (FUN_0090F600, luaB_newproxy)
	 *
	 * What it does:
	 * Creates one proxy userdata lane and optionally binds/validates its
	 * metatable against the base-lib proxy registry upvalue.
	 */
	int luaB_newproxy(lua_State* const state)
	{
		lua_settop(state, 1);

		gpg::RRef proxyRef{};
		(void)lua_newuserdata_ref(&proxyRef, state, nullptr);

		if (lua_toboolean(state, 1) == 0) {
			return 1;
		}

		if (lua_type(state, 1) == LUA_TBOOLEAN) {
			lua_newtable(state);
			lua_pushvalue(state, -1);
			lua_pushboolean(state, 1);
			lua_rawset(state, lua_upvalueindex(1));
		} else {
			const bool hasMetaTable = (lua_getmetatable(state, 1) != 0);
			bool isKnownProxy = false;
			if (hasMetaTable) {
				lua_rawget(state, lua_upvalueindex(1));
				isKnownProxy = (lua_toboolean(state, -1) != 0);
				lua_settop(state, -2);
			}

			if (!hasMetaTable || !isKnownProxy) {
				luaL_argerror(state, 1, "boolean or proxy expected");
			}

			(void)lua_getmetatable(state, 1);
		}

		lua_setmetatable(state, 2);
		return 1;
	}

	/**
	 * Address: 0x0090A8C0 (FUN_0090A8C0, LS_LOG)
	 *
	 * What it does:
	 * Implements Lua `LOG`/`_ALERT` by applying `tostring` to each argument,
	 * joining with tab separators, and forwarding the final text to gpg logging.
	 */
	int LS_LOG(lua_State* const state)
	{
		Ensure(state != nullptr, "state");

		const int argumentCount = lua_gettop(state);
		lua_pushstring(state, "tostring");
		lua_gettable(state, LUA_GLOBALSINDEX);

		std::ostringstream messageBuilder{};
		for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
			lua_pushvalue(state, -1);
			lua_pushvalue(state, argumentIndex);
			lua_call(state, 1, 1);

			const char* const convertedText = lua_tostring(state, -1);
			if (convertedText == nullptr) {
				luaL_error(state, "`tostring' must return a string to `print'");
				return 0;
			}

			if (argumentIndex > 1) {
				messageBuilder << '\t';
			}
			messageBuilder << convertedText;

			lua_settop(state, -2);
		}

		msvc8::string message{};
		message.assign_owned(messageBuilder.str());
		gpg::LogMessage(gpg::LogSeverity::Info, message);
		return 0;
	}

	/**
	 * Address: 0x0090AF50 (FUN_0090AF50)
	 *
	 * What it does:
	 * Writes one dumped Lua chunk block into an output FILE stream and reports
	 * boolean success expected by this build's `lua_dump` path.
	 */
	int LS_dump_FileChunkWriter(
		lua_State* const,
		const void* const buffer,
		const size_t elementSize,
		void* const streamUserData
	)
	{
		std::FILE* const output = static_cast<std::FILE*>(streamUserData);
		return (output != nullptr && std::fwrite(buffer, elementSize, 1u, output) == 1u) ? 1 : 0;
	}

	/**
	 * Address: 0x0090AF80 (FUN_0090AF80, LS_import)
	 *
	 * What it does:
	 * Implements legacy `import` fallback for this runtime lane by returning
	 * false on the Lua stack.
	 */
	int LS_import(lua_State* const state)
	{
		Ensure(state != nullptr, "state");
		Ensure(state->stateUserData != nullptr, "state->stateUserData");

		lua_State* const cstate = state->stateUserData->m_state;
		lua_pushboolean(cstate, 0);
		(void)lua_gettop(cstate);
		return 1;
	}

	/**
	 * Address: 0x0090AFB0 (FUN_0090AFB0, LS_dump)
	 *
	 * What it does:
	 * Loads one Lua source file, dumps the compiled chunk to output file path,
	 * and returns success/failure boolean on the Lua stack.
	 */
	int LS_dump(lua_State* const state)
	{
		Ensure(state != nullptr, "state");
		Ensure(state->stateUserData != nullptr, "state->stateUserData");

		LuaState* const luaState = state->stateUserData;
		lua_State* const cstate = luaState->m_state;

		LuaStackObject sourcePathArg(luaState, 1);
		const char* const sourcePath = lua_tostring(cstate, 1);
		if (sourcePath == nullptr) {
			LuaStackObject::TypeError(&sourcePathArg, "string");
		}

		LuaStackObject outputPathArg(luaState, 2);
		const char* const outputPath = lua_tostring(cstate, 2);
		if (outputPath == nullptr) {
			LuaStackObject::TypeError(&outputPathArg, "string");
		}

		if (luaL_loadfile(cstate, sourcePath) != 0) {
			lua_pushboolean(cstate, 0);
			(void)lua_gettop(cstate);
			return 1;
		}

		std::FILE* const output = std::fopen(outputPath, "wb");
		if (output != nullptr) {
			(void)lua_dump(cstate, LS_dump_FileChunkWriter, output);
			std::fclose(output);
			lua_pushboolean(cstate, 1);
			(void)lua_gettop(cstate);
		} else {
			lua_pushboolean(cstate, 0);
			(void)lua_gettop(cstate);
		}
		return 1;
	}

	/**
	 * Address: 0x0090B0D0 (FUN_0090B0D0, ScriptFunctionsRegister)
	 *
	 * What it does:
	 * Registers script-global helper lanes (`import`, `LuaDumpBinary`) on the
	 * active Lua globals table.
	 */
	void ScriptFunctionsRegister(LuaState* const state)
	{
		Ensure(state != nullptr, "state");
		LuaObject globals = state->GetGlobals();
		globals.Register("import", LS_import, 0);
		globals.Register("LuaDumpBinary", LS_dump, 0);
	}

	unsigned int HashLuaString(const char* key, const unsigned int length)
	{
		unsigned int hash = length;
		const unsigned int step = (hash >> 5U) + 1U;
		for (unsigned int i = length; i >= step; i -= step) {
			hash ^= (hash >> 2U) + (hash << 5U) + static_cast<unsigned char>(key[i - 1U]);
		}
		return hash;
	}

	const TString* FindInternedString(lua_State* state, const char* key)
	{
		Ensure(state != nullptr && state->l_G != nullptr, "state != nullptr && state->l_G != nullptr");
		Ensure(key != nullptr, "key");

		const stringtable& strings = state->l_G->strt;
		if (strings.hash == nullptr || strings.size <= 0) {
			return nullptr;
		}

		const unsigned int keyLength = static_cast<unsigned int>(std::strlen(key));
		const unsigned int hash = HashLuaString(key, keyLength);
		GCObject* current = strings.hash[hash & static_cast<unsigned int>(strings.size - 1)];
		while (current != nullptr) {
			if (current->gch.tt == LUA_TSTRING) {
				const auto* candidate = reinterpret_cast<const TString*>(current);
				if (candidate->len == static_cast<size_t>(keyLength)
					&& std::memcmp(candidate->str, key, static_cast<size_t>(keyLength)) == 0) {
					return candidate;
				}
			}
			current = current->gch.next;
		}

		return nullptr;
	}

	TObject CaptureStackValue(lua_State* state, const int index)
	{
		lua_pushvalue(state, index);
		const TObject value = *(state->top - 1);
		lua_pop(state, 1);
		return value;
	}

	struct LuaCallFrameRuntimeView
	{
		LuaState* state = nullptr;              // +0x00 (root-main-thread LuaState*)
		LuaObject function{};                   // +0x04 (callable LuaObject, tracked on list)
		int argumentCount = 0;                  // +0x18
		int nextTopIndex = 0;                   // +0x1C
	};
	static_assert(offsetof(LuaCallFrameRuntimeView, state) == 0x00, "LuaCallFrameRuntimeView::state offset must be 0x00");
	static_assert(offsetof(LuaCallFrameRuntimeView, function) == 0x04, "LuaCallFrameRuntimeView::function offset must be 0x04");
	static_assert(offsetof(LuaCallFrameRuntimeView, argumentCount) == 0x18, "LuaCallFrameRuntimeView::argumentCount offset must be 0x18");
	static_assert(offsetof(LuaCallFrameRuntimeView, nextTopIndex) == 0x1C, "LuaCallFrameRuntimeView::nextTopIndex offset must be 0x1C");
	static_assert(sizeof(LuaCallFrameRuntimeView) == 0x20, "LuaCallFrameRuntimeView size must be 0x20");

	/**
	 * Address: 0x00909A00 (FUN_00909A00)
	 *
	 * IDA signature:
	 * int __thiscall sub_909A00(LuaCallFrameRuntimeView *this@<ecx>, const LuaObject *functionObject);
	 *
	 * What it does:
	 * Constructs one Lua call-frame view from a caller-supplied function
	 * `LuaObject`: default-initializes the embedded function lane, links it
	 * onto the source object's root-state live-object intrusive list with the
	 * same tagged value via `AddToUsedObjectList`, captures the root
	 * main-thread `LuaPlus::LuaState*` wrapper into `state`, asserts the
	 * function slot is bound (`m_state` non-null), raises a Lua type error
	 * when the payload is not callable (`tt | 1 != 7` ⇒ not `LUA_TFUNCTION`),
	 * and records the current root stack top `+ 1` as `nextTopIndex` while
	 * pushing the function onto that stack as the first call-frame slot.
	 */
	LuaCallFrameRuntimeView* ConstructLuaCallFrame(
		LuaCallFrameRuntimeView* const frame,
		LuaObject* const functionObject
	)
	{
		frame->function.m_next = nullptr;
		frame->function.m_prev = nullptr;
		frame->function.m_state = nullptr;
		frame->function.m_object.tt = 0;
		frame->function.m_object.value.p = nullptr;

		LuaState* const sourceState = functionObject->m_state;
		if (sourceState != nullptr) {
			frame->function.AddToUsedObjectList(sourceState, &functionObject->m_object);
		}

		frame->argumentCount = 0;
		LuaState* const boundState = frame->function.m_state;
		frame->state = boundState->m_state->l_G->mainthread->stateUserData;

		if (frame->function.m_state == nullptr) {
			throw LuaAssertion("m_state");
		}

		constexpr std::uint32_t kFunctionTagMask = 1u;
		if ((static_cast<std::uint32_t>(frame->function.m_object.tt) | kFunctionTagMask) != 7u) {
			luaG_typeerror(
				frame->function.m_state->m_state->l_G->mainthread,
				&frame->function.m_object,
				"call"
			);
		}

		lua_State* const rootLuaState = frame->state->m_state;
		const int currentTop = lua_gettop(rootLuaState);
		frame->nextTopIndex = currentTop + 1;

		(void)frame->function.PushStack(frame->state);
		return frame;
	}

	/**
	 * Address: 0x00907270 (FUN_00907270)
	 *
	 * What it does:
	 * Runs one prepared Lua call frame using retained argument-count lanes, then
	 * materializes one stack-object view for the top result slot.
	 */
	LuaStackObject* InvokeLuaCallFrame(
		LuaCallFrameRuntimeView* const frame,
		LuaStackObject* const outResult,
		const int* const resultCount
	)
	{
		lua_call(frame->state->m_state, frame->argumentCount, *resultCount);
		outResult->m_state = frame->state;
		outResult->m_stackIndex = frame->nextTopIndex - 1;
		return outResult;
	}

	/**
	 * Address: 0x00907480 (FUN_00907480)
	 *
	 * What it does:
	 * Copies one tagged Lua value to `state->top`, grows stack when needed, and
	 * advances top by one slot.
	 */
	StkId PushRawLuaObjectToStack(const TObject* const object, lua_State* const state)
	{
		StkId const top = state->top;
		*top = *object;
		if (top >= state->ci->top) {
			(void)lua_checkstack(state, 1);
		}

		state->top = top + 1;
		return top;
	}

	/**
	 * Address: 0x00908940 (FUN_00908940)
	 *
	 * What it does:
	 * Pushes one LuaObject argument onto a prepared Lua call frame and bumps the
	 * retained argument-count lane.
	 */
	LuaCallFrameRuntimeView* PushLuaObjectArgumentToCallFrame(
		LuaCallFrameRuntimeView* const frame,
		LuaObject* const argument
	)
	{
		const StkId pushed = argument->PushStack(frame->state);
		(void)pushed;
		++frame->argumentCount;
		return frame;
	}

	void PushTObject(lua_State* state, const TObject& object)
	{
		switch (object.tt) {
			case LUA_TNIL:
				lua_pushnil(state);
				return;
			case LUA_TBOOLEAN:
				lua_pushboolean(state, object.value.b ? 1 : 0);
				return;
			case LUA_TNUMBER:
				lua_pushnumber(state, object.value.n);
				return;
			case LUA_TSTRING: {
				const auto* str = static_cast<const TString*>(object.value.p);
				lua_pushstring(state, str ? str->str : "");
				return;
			}
			default:
				break;
		}

		*state->top = object;
		if (state->top >= state->ci->top) {
			lua_checkstack(state, 1);
		}
		state->top += 1;
	}

	void RebindToState(LuaObject& object, LuaState* state)
	{
		Ensure(state != nullptr, "state");
		const LuaState* root = state->m_rootState ? state->m_rootState : state;
		if (root == object.m_state) {
			return;
		}

		if (object.m_state) {
			*object.m_prev = object.m_next;
			object.m_next->m_prev = object.m_prev;
			object.m_object.tt = LUA_TNIL;
		}

		object.AddToUsedList(state);
	}
}

/**
 * Address: 0x009125E0 (FUN_009125E0, lua_getstack)
 *
 * What it does:
 * Walks `level` frames down from the current one and records which
 * CallInfo that landed on, so `lua_getinfo` can describe it. Tail calls
 * collapsed into a Lua frame each count as a level of their own, which is
 * why a frame's `tailcalls` comes off the counter. Reports failure once the
 * walk reaches the base frame with levels still to go.
 */
int lua_getstack(lua_State* const state, const int level, ::lua_Debug* const activationRecord)
{
	constexpr int kFrameCFunction = 3;

	int remaining = level;
	CallInfo* ci = state->ci;

	if (level > 0) {
		bool landed = false;
		while (ci > state->base_ci) {
			--remaining;
			if (ci->state < kFrameCFunction) {
				remaining -= ci->tailcalls;
			}
			// Step down first, then check: level 1 has to end up on the
			// caller of the running function, not on the running function
			// itself. Testing before the step made every level report one
			// frame too shallow, so debug.getinfo(1) described the C
			// function it was called from instead of the Lua one that
			// called it.
			--ci;
			if (remaining <= 0) {
				landed = true;
				break;
			}
		}

		if (!landed && remaining > 0) {
			return 0;
		}
	}

	if (ci == state->base_ci) {
		return 0;
	}

	// A negative remainder means the level landed inside a run of tail
	// calls rather than on a real frame; i_ci = 0 marks that for
	// lua_getinfo, which then answers from info_tailcall.
	activationRecord->i_ci = (remaining >= 0) ? static_cast<int>(ci - state->base_ci) : 0;
	return 1;
}

/**
 * Address: 0x009132F0 (FUN_009132F0, lua_getinfo)
 *
 * What it does:
 * Describes either the function on top of the stack (`what` starting with
 * '>') or the frame `lua_getstack` recorded. When the option string asks
 * for 'f', the function object auxgetinfo parked at the top is published.
 */
int lua_getinfo(lua_State* const state, const char* what, ::lua_Debug* const activationRecord)
{
	int status = 1;

	if (*what == '>') {
		StkId const functionSlot = state->top - 1;
		// `or eax, 1 / cmp eax, 7` - the two function tags differ only in the
		// low bit, so this is one test for "callable".
		if ((functionSlot->tt | 1) != LUA_TFUNCTION) {
			luaG_runerror(state, "value for `lua_getinfo' is not a function");
		}

		status = auxgetinfo(what + 1, functionSlot, activationRecord, state, nullptr);
		--state->top; // the function was an argument; consume it
	} else if (activationRecord->i_ci != 0) {
		CallInfo* const ci = state->base_ci + activationRecord->i_ci;
		status = auxgetinfo(what, ci->base - 1, activationRecord, state, ci);
	} else {
		info_tailcall(activationRecord, state);
	}

	if (std::strchr(what, 'f') != nullptr) {
		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}
		++state->top;
	}

	return status;
}

namespace LuaPlus
{
	/**
	 * Address: 0x00928DD0 (FUN_00928DD0, LoadSignature)
	 * IDA signature:
	 * void __usercall LoadSignature(LoadState *S@<esi>);
	 *
	 * What it does:
	 * Reads and validates the `"\x1BLua"` chunk signature byte-by-byte from the
	 * load stream; raises "unexpected end of file" on EOF and "bad signature" on
	 * the first mismatching byte.
	 */
	void LuaLoadSignature(LuaLoadStateRuntimeView* const loadState)
	{
		const char* expected = "\x1BLua";
		for (;;) {
			const int byteValue = LuaReadChunkByteOrThrow(loadState);
			if (byteValue != static_cast<unsigned char>(*expected)) {
				break;
			}
			if (*++expected == '\0') {
				return;
			}
		}

		if (*expected != '\0') {
			luaG_runerror(loadState->state, "bad signature in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x00928E50 (FUN_00928E50, TestSize)
	 * IDA signature:
	 * void __usercall TestSize(int s@<edi>, LoadState *S@<esi>, const char *tname);
	 *
	 * What it does:
	 * Reads one size byte from the load stream and verifies it equals the
	 * expected `sizeof(<tname>)`; raises "virtual machine mismatch" on a size
	 * disagreement (and "unexpected end of file" on EOF).
	 */
	void LuaTestTypeSize(const int expectedSize, LuaLoadStateRuntimeView* const loadState, const char* const typeName)
	{
		const int readSize = LuaReadChunkByteOrThrow(loadState);
		if (static_cast<unsigned char>(readSize) != expectedSize) {
			luaG_runerror(
				loadState->state,
				"virtual machine mismatch in %s: size of %s is %d but read %d",
				loadState->chunkName,
				typeName,
				expectedSize,
				static_cast<unsigned char>(readSize)
			);
		}
	}

	/**
	 * Address: 0x00928ED0 (FUN_00928ED0, LoadChunk)
	 * IDA signature:
	 * void __usercall LoadChunk(LoadState *S@<eax>);
	 *
	 * What it does:
	 * Validates the full binary chunk header: signature, combined
	 * version/format word (must equal 0x0501), endianness/byte-swap flag, the
	 * eight type-size bytes (int/size_t/Instruction/OP/A/B/C/number), and the
	 * `lua_Number` self-test value (must truncate to 31415926).
	 */
	void LuaLoadChunkHeader(LuaLoadStateRuntimeView* const loadState)
	{
		LuaLoadSignature(loadState);

		const int versionByte = LuaReadChunkByteOrThrow(loadState);
		const int formatByte = LuaReadChunkByteOrThrow(loadState);
		const int versionWord = static_cast<unsigned char>(formatByte)
			| (static_cast<unsigned char>(versionByte) << 8);
		if (versionWord > 0x0501) {
			luaG_runerror(
				loadState->state,
				"%s too new: read version %d.%d; expected at most %d.%d",
				loadState->chunkName,
				versionWord / 16,
				versionWord & 0xF,
				80,
				1
			);
		}
		if (versionWord < 0x0501) {
			luaG_runerror(
				loadState->state,
				"%s too old: read version %d.%d; expected at least %d.%d",
				loadState->chunkName,
				versionWord / 16,
				versionWord % 16,
				80,
				1
			);
		}

		const int endiannessByte = LuaReadChunkByteOrThrow(loadState);
		loadState->swapBytes = (static_cast<std::uint8_t>(endiannessByte) != 1) ? 1 : 0;

		LuaTestTypeSize(4, loadState, "int");
		LuaTestTypeSize(4, loadState, "size_t");
		LuaTestTypeSize(4, loadState, "Instruction");
		LuaTestTypeSize(6, loadState, "OP");
		LuaTestTypeSize(8, loadState, "A");
		LuaTestTypeSize(9, loadState, "B");
		LuaTestTypeSize(9, loadState, "C");
		LuaTestTypeSize(4, loadState, "number");

		float numberFormat = 0.0f;
		LuaLoadBlock(4u, &numberFormat, loadState);
		if (static_cast<int>(numberFormat) != 31415926) {
			luaG_runerror(loadState->state, "unknown number format in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x00928C10 (FUN_00928C10, LoadFunction)
	 * IDA signature:
	 * Proto *__cdecl LoadFunction(LoadState *S, TString *parentSource);
	 *
	 * What it does:
	 * Recursively reads one `Proto` from the chunk stream: source string (falling
	 * back to the parent chunk name), line-defined, upvalue/param counts,
	 * vararg/stack-size flags, then the line-info, local-variable, upvalue-name,
	 * constant + nested-proto, and bytecode lanes via the sub-loaders. Validates
	 * decoded bytecode with `luaG_checkcode`.
	 */
	Proto* LuaLoadProtoObject(LuaLoadStateRuntimeView* const loadState, TString* const fallbackSource)
	{
		Proto* const proto = luaF_newproto(loadState->state);

		TString* const loadedSource = LuaLoadTString(loadState);
		proto->source = (loadedSource != nullptr) ? loadedSource : fallbackSource;

		int lineDefined = 0;
		LuaLoadBlock(4u, &lineDefined, loadState);
		if (lineDefined < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}
		proto->lineDefined = lineDefined;

		proto->nups = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->numparams = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->is_vararg = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->maxstacksize = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));

		LuaLoadProtoLineInfo(loadState, proto);
		LuaLoadProtoLocalVariableDebugInfo(loadState, proto);
		LuaLoadProtoUpvalueNames(loadState, proto);
		LuaLoadProtoConstantsAndNestedProtos(loadState, proto);
		LuaLoadProtoCode(loadState, proto);

		if (luaG_checkcode(proto) == 0) {
			luaG_runerror(loadState->state, "bad code in %s", loadState->chunkName);
		}

		return proto;
	}
}

extern "C"
{
	/**
	 * Address: 0x0090D260 (FUN_0090D260, lua_settable)
	 *
	 * What it does:
	 * Resolves one Lua API table target at `idx`, performs one table write
	 * using top-2 key/value stack lanes, then pops those two lanes.
	 */
	void lua_settable(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = luaA_index(state, idx);
		} else {
			object = &state->base[idx - 1];
		}

		luaV_settable(state, object, state->top - 2, state->top - 1);
		state->top -= 2;
	}
}

namespace
{
	// LUA_CFUNCTION (6) and LUA_TFUNCTION (7) are adjacent tags differing only
	// in the low bit, which is how the binary tests "is this callable" in one
	// instruction pair: `or eax, 1` / `cmp eax, 7`.
	[[nodiscard]] constexpr bool IsCallableTag(const int tag) noexcept
	{
		return (tag | 1) == LUA_TFUNCTION;
	}
}

/**
 * Address: 0x00929450 (FUN_00929450, luaV_settable)
 *
 * IDA signature:
 * void __cdecl luaV_settable(lua_State *L, const TObject *t, TObject *key, StkId val);
 *
 * What it does:
 * Performs one `t[key] = val` with full `__newindex` semantics. The raw table
 * store wins in three cases: the slot already holds a non-nil value, the
 * metatable carries the cached "no __newindex here" flag, or the metatable
 * genuinely has no `__newindex`. Otherwise the handler is invoked when it is
 * callable, and re-indexed into when it is another container - bounded to 100
 * hops before raising "loop in settable".
 *
 * Defined with C linkage at namespace scope on purpose: the prebuilt
 * LuaPlus lib carries its own `_luaV_settable` built against a different
 * TObject/Table layout, and letting that one win is what corrupted every
 * table written through `luaL_openlib` during startup.
 */
extern "C" void luaV_settable(
	lua_State* const state,
	const TObject* target,
	TObject* const key,
	TObject* const val
)
{
	constexpr int kTagMethodNewIndex = 1;
	constexpr int kNoNewIndexTagMethodFlag = 1 << kTagMethodNewIndex;
	constexpr int kMaxTagMethodChain = 100;

	for (int hop = 0; hop <= kMaxTagMethodChain; ++hop) {
		const TObject* handler = nullptr;

		if (target->tt == LUA_TTABLE) {
			auto* const table = static_cast<Table*>(target->value.p);
			TObject* const slot = luaH_set(state, table, key);

			if (slot->tt != LUA_TNIL) {
				*slot = *val;
				return;
			}

			Table* const metatable = table->metatable;
			if ((metatable->flags & kNoNewIndexTagMethodFlag) != 0) {
				*slot = *val;
				return;
			}

			handler = luaT_gettm(metatable, kTagMethodNewIndex, state->l_G->tmname[kTagMethodNewIndex]);
			if (handler == nullptr) {
				*slot = *val;
				return;
			}
		} else {
			handler = luaT_gettmbyobj(state, target, kTagMethodNewIndex);
			if (handler->tt == LUA_TNIL) {
				luaG_typeerror(state, target, "index");
			}
		}

		if (IsCallableTag(handler->tt)) {
			callTM(target, key, val, state, handler);
			return;
		}

		target = handler;
	}

	luaG_runerror(state, "loop in settable");
}

// ---------------------------------------------------------------------------
// Lua state construction.
//
// This block is the bootstrap the prebuilt LuaPlus lib used to own. Because
// lua_open and f_luaopen were never recovered, the lib allocated and
// initialised the whole lua_State + global_State pair at *its* field offsets,
// and every recovered function above then read that object at ours - which is
// why L->_gt came back as 0xCD debug fill no matter how much of the API was
// correct. Everything here is defined with C linkage at namespace scope so it
// displaces the lib's copies at link time.
// ---------------------------------------------------------------------------

// luaM_realloc, f_luaopen and lua_open all raise lua_MemError on allocation
// failure, exactly as the binary does through _CxxThrowException. The project
// compiles with /EHc, under which the compiler assumes an extern "C" function
// never throws and warns (C4297) when one does. The assumption is wrong for
// these three; switching the project to /EHs would express that globally, so
// the suppression is scoped to this block rather than papered over per-call.
#pragma warning(push)
#pragma warning(disable : 4297)
extern "C"
{
	// Both hooks reach the engine's small-block allocator, which is what the
	// binary does: FUN_00923F20 tail-calls realloc at FUN_00957B00 and
	// FUN_00923F40 tail-calls _free_crt at FUN_00957AF0, and both of those are
	// engine code, not CRT. Naming matters here - the project links the DLL
	// CRT, so writing `realloc` would bind to `__imp__realloc` and allocate on
	// the CRT heap while `free_crt` released it against the engine's page map.
	void* __cdecl realloc_0(void* pblock, std::size_t newsize);
	void __cdecl free_crt(void* ptr);

	/**
	 * Address: 0x00923F20 (FUN_00923F20, luaHelper_ReallocFunction)
	 *
	 * IDA signature:
	 * void *__cdecl luaHelper_ReallocFunction(void *ptr, int oldsize, int size,
	 *     void *data, const char *allocName, unsigned int flags);
	 *
	 * What it does:
	 * Resizes one Lua block on the CRT heap. Only `ptr` and `size` reach the
	 * call - the bookkeeping arguments exist for allocator instrumentation
	 * this build never installs.
	 */
	void* __cdecl luaHelper_ReallocFunction(
		void* const ptr,
		const int oldsize,
		const int size,
		void* const data,
		const char* const allocName,
		const unsigned int flags
	)
	{
		return realloc_0(ptr, static_cast<std::size_t>(size));
	}

	/**
	 * Address: 0x00923F40 (FUN_00923F40, luaHelper_FreeFunction)
	 *
	 * IDA signature:
	 * void __cdecl luaHelper_FreeFunction(void *ptr, int oldsize, void *data);
	 *
	 * What it does:
	 * Releases one Lua block back to the CRT heap.
	 */
	void __cdecl luaHelper_FreeFunction(
		void* const ptr,
		const int oldsize,
		void* const data
	)
	{
		free_crt(ptr);
	}

	// Allocator hooks and tuning knobs, read out of .data in the shipped image:
	//   luaHelper_Realloc     0x00F32120 -> 0x00923F20
	//   luaHelper_Free        0x00F32124 -> 0x00923F40
	//   luaHelper_memData     0x00F8EB9C -> zero-initialised
	//   lua_minimumnumstrings 0x00F32128 -> 0x1F
	//   lua_minimumauxspace   0x00F8EBA0 -> zero-initialised
	ReallocFunction luaHelper_Realloc = &luaHelper_ReallocFunction;
	FreeFunction luaHelper_Free = &luaHelper_FreeFunction;
	void* luaHelper_memData = nullptr;
	int lua_minimumnumstrings = 0x1F;
	int lua_minimumauxspace = 0;

	/**
	 * Address: 0x0091A240 (FUN_0091A240, luaM_realloc)
	 *
	 * IDA signature:
	 * void *__cdecl luaM_realloc(lua_State *L, void *block, lu_mem oldsize, lu_mem size);
	 *
	 * What it does:
	 * The VM's single allocation choke point. A zero `size` frees, anything
	 * else resizes through the global_State's realloc hook, and either way the
	 * allocated-byte counter is adjusted by the same delta. Note the counter
	 * update runs even on the error paths - that is the binary's behaviour,
	 * not an oversight here.
	 */
	// noexcept(false) is load-bearing: /EHc makes the compiler assume an
	// extern "C" function cannot throw, and this one does - the binary raises
	// lua_MemError through _CxxThrowException on allocation failure.
	void* luaM_realloc(lua_State* const state, void* const block, const lu_mem oldsize, const lu_mem size)
	{
		// The largest block the allocator will attempt; anything at or above
		// this is reported rather than passed on ("cmp ebx, 0FFFFFFFDh").
		constexpr lu_mem kMaxBlockSize = 0xFFFFFFFDu;

		void* result = nullptr;

		if (size == 0) {
			if (block == nullptr) {
				return nullptr;
			}

			global_State* const globalState = state->l_G;
			globalState->freeFunc(block, static_cast<int>(oldsize), globalState->memData);
		} else if (size >= kMaxBlockSize) {
			luaG_runerror(state, "memory allocation error: block too big");
			result = block;
		} else {
			global_State* const globalState = state->l_G;
			result = globalState->reallocFunc(
				block,
				static_cast<int>(oldsize),
				static_cast<int>(size),
				globalState->memData,
				nullptr,
				state->allocFlags
			);

			if (result == nullptr) {
				throw lua_MemError(lua::lua_Error(state, LUA_ERRMEM, "out of memory"));
			}
		}

		if (state != nullptr) {
			state->l_G->nblocks -= oldsize;
			state->l_G->nblocks += size;
		}

		return result;
	}

	/**
	 * Address: 0x0091A310 (FUN_0091A310, luaM_growaux)
	 *
	 * IDA signature:
	 * void *__cdecl luaM_growaux(lua_State *L, void *block, int *size, int size_elems, int limit, char *what);
	 *
	 * What it does:
	 * Doubles an array's element count (starting from `MINSIZEARRAY` = 4 when it
	 * was empty), clamped to `limit`, and reallocates the backing block through
	 * `luaM_realloc`. If the array is already past half of `limit` it grows only
	 * to `limit` itself; if it is already at `limit - MINSIZEARRAY` or beyond,
	 * growing further would not make room for a useful batch of new elements, so
	 * it reports `what` as a fixed overflow message instead of growing.
	 */
	void* luaM_growaux(
		lua_State* const state, void* const block, int* const size, const int sizeElems, const int limit,
		const char* const what
	)
	{
		constexpr int kMinSizeArray = 4;

		int newSize = *size * 2;
		if (newSize < kMinSizeArray) {
			newSize = kMinSizeArray;
		} else if (*size >= limit / 2) {
			if (*size >= limit - kMinSizeArray) {
				luaG_runerror(state, what);
			}
			newSize = limit;
		}

		void* const newBlock = luaM_realloc(
			state, block, static_cast<lu_mem>(sizeElems * *size), static_cast<lu_mem>(sizeElems * newSize)
		);
		*size = newSize;
		return newBlock;
	}

	/**
	 * Address: 0x0090EC20 (FUN_0090EC20, luaB_print)
	 *
	 * IDA signature:
	 * int __cdecl luaB_print(lua_State *L);
	 *
	 * What it does:
	 * Writes each argument to stdout, tab-separated, newline-terminated. Each
	 * value is rendered by calling the *global* `tostring` - looked up once up
	 * front - so a script that replaces it changes what print produces.
	 */
	int luaB_print(lua_State* const state)
	{
		const int argumentCount = lua_gettop(state);

		lua_pushstring(state, "tostring");
		lua_gettable(state, LUA_GLOBALSINDEX);

		for (int argument = 1; argument <= argumentCount; ++argument) {
			lua_pushvalue(state, -1);
			lua_pushvalue(state, argument);
			lua_call(state, 1, 1);

			const char* const text = lua_tostring(state, -1);
			if (text == nullptr) {
				return luaL_error(state, "`tostring' must return a string to `print'");
			}

			if (argument > 1) {
				std::fputs("\t", stdout);
			}

			std::fputs(text, stdout);
			lua_settop(state, -2);
		}

		std::fputs("\n", stdout);
		return 0;
	}

	/**
	 * Address: 0x0090FC30 (FUN_0090FC30, luaB_costatus)
	 *
	 * IDA signature:
	 * int __cdecl luaB_costatus(lua_State *L);
	 *
	 * What it does:
	 * Reports a coroutine as "running" when it is the calling thread,
	 * "suspended" while it still has a frame or stack to resume into, and
	 * "dead" once it has neither.
	 */
	int luaB_costatus(lua_State* const state)
	{
		lua_State* const coroutine = lua_tothread(state, 1);
		if (coroutine == nullptr) {
			luaL_argerror(state, 1, "coroutine expected");
		}

		if (state == coroutine) {
			lua_pushlstring(state, "running", 7u);
			return 1;
		}

		lua_Debug frame{};
		if (lua_getstack(coroutine, 0, &frame) != 0 || lua_gettop(coroutine) != 0) {
			lua_pushlstring(state, "suspended", 9u);
			return 1;
		}

		lua_pushlstring(state, "dead", 4u);
		return 1;
	}

	/**
	 * Address: 0x0090ECF0 (FUN_0090ECF0, luaB_tonumber)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tonumber(lua_State *L);
	 *
	 * What it does:
	 * Converts argument 1 to a number. Base 10 accepts anything Lua already
	 * considers numeric; any other base parses a string with `strtoul` and
	 * requires the whole remainder to be blank. Returns nil on failure.
	 */
	int luaB_tonumber(lua_State* const state)
	{
		constexpr int kDecimalBase = 10;
		constexpr int kMinBase = 2;
		constexpr int kMaxBase = 36;

		const int base = static_cast<int>(luaL_optnumber(state, 2, static_cast<lua_Number>(kDecimalBase)));

		if (base == kDecimalBase) {
			luaL_checkany(state, 1);
			if (lua_isnumber(state, 1) != 0) {
				lua_pushnumber(state, lua_tonumber(state, 1));
				return 1;
			}
		} else {
			const char* const text = luaL_checklstring(state, 1, nullptr);
			if (base < kMinBase || base > kMaxBase) {
				luaL_argerror(state, 2, "base out of range");
			}

			char* end = nullptr;
			const unsigned long value = std::strtoul(text, &end, base);
			if (text != end) {
				while (std::isspace(static_cast<unsigned char>(*end)) != 0) {
					++end;
				}

				if (*end == '\0') {
					lua_pushnumber(state, static_cast<lua_Number>(value));
					return 1;
				}
			}
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x0090F6D0 (FUN_0090F6D0, lua::getpath)
	 *
	 * IDA signature:
	 * const char *__usercall lua::getpath(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Resolves the package search path: the global `LUA_PATH` wins, then the
	 * environment variable of the same name, and failing both a built-in
	 * "current directory" pattern.
	 */
	static const char* getpath(lua_State* const state)
	{
		lua_pushstring(state, "LUA_PATH");
		lua_gettable(state, LUA_GLOBALSINDEX);
		const char* const scriptPath = lua_tostring(state, -1);
		lua_settop(state, -2);

		if (scriptPath != nullptr) {
			return scriptPath;
		}

		const char* const environmentPath = std::getenv("LUA_PATH");
		if (environmentPath == nullptr) {
			return "?;?.lua";
		}

		return environmentPath;
	}

	/**
	 * Address: 0x0090F0A0 (FUN_0090F0A0, luaB_setfenv)
	 *
	 * IDA signature:
	 * int __cdecl luaB_setfenv(lua_State *L);
	 *
	 * What it does:
	 * Installs a new environment table on a function. A `__fenv` key in the
	 * current environment marks it protected and refuses the change. Level 0
	 * targets the running thread's own globals rather than a function.
	 */
	int luaB_setfenv(lua_State* const state)
	{
		luaL_checktype(state, 2, LUA_TTABLE);
		getfunc(state);

		lua_getfenv(state, -1);
		lua_pushlstring(state, "__fenv", 6u);
		lua_rawget(state, -2);
		if (lua_type(state, -1) != LUA_TNIL) {
			luaL_error(state, "`setfenv' cannot change a protected environment");
		}

		lua_settop(state, -3);
		lua_pushvalue(state, 2);

		if (lua_isnumber(state, 1) != 0 && lua_tonumber(state, 1) == 0.0) {
			lua_replace(state, LUA_GLOBALSINDEX);
			return 0;
		}

		if (lua_setfenv(state, -2) == 0) {
			luaL_error(state, "`setfenv' cannot change environment of given function");
		}

		return 0;
	}

	/**
	 * Address: 0x0090FDE0 (FUN_0090FDE0, luaB_tostring)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tostring(lua_State *L);
	 *
	 * What it does:
	 * Renders argument 1 as a string. A `__tostring` metamethod wins outright;
	 * otherwise each tag gets its own form, and userdata is described through
	 * the reflection system - type name, address and lexical value - which is
	 * this fork's departure from stock Lua's bare "userdata: %p".
	 */
	int luaB_tostring(lua_State* const state)
	{
		constexpr std::size_t kRenderBufferSize = 512;

		luaL_checkany(state, 1);
		if (luaL_callmeta(state, 1, "__tostring") != 0) {
			return 1;
		}

		char rendered[kRenderBufferSize];

		switch (lua_type(state, 1)) {
			case LUA_TNIL:
				lua_pushlstring(state, "nil", 3u);
				return 1;
			case LUA_TBOOLEAN:
				lua_pushstring(state, lua_toboolean(state, 1) ? "true" : "false");
				return 1;
			case LUA_TNUMBER:
				lua_pushstring(state, lua_tostring(state, 1));
				return 1;
			case LUA_TSTRING:
				lua_pushvalue(state, 1);
				return 1;
			case LUA_TUPVALUE:
				lua_pushlstring(state, "upval", 5u);
				return 1;
			case LUA_TLIGHTUSERDATA:
				std::sprintf(rendered, "pointer: %p", lua_tolightuserdata(state, 1));
				break;
			case LUA_TTABLE:
				std::sprintf(rendered, "table: %p", lua_topointer(state, 1));
				break;
			case LUA_CFUNCTION:
				std::sprintf(rendered, "cfunction: %p", lua_topointer(state, 1));
				break;
			case LUA_TFUNCTION:
				std::sprintf(rendered, "function: %p", lua_topointer(state, 1));
				break;
			case LUA_TTHREAD:
				std::sprintf(rendered, "thread: %p", static_cast<void*>(lua_tothread(state, 1)));
				break;
			case LUA_TUSERDATA: {
				gpg::RRef reference{};
				GetRRefFromUserdata(&reference, state, 1);
				const msvc8::string lexical = reference.GetLexical();
				std::sprintf(
					rendered,
					"userdata: %.80s at %p = %.80s",
					reference.GetName(),
					reference.mObj,
					lexical.c_str()
				);
				break;
			}
			case LUA_TPROTO: {
				const Proto* const proto = static_cast<const Proto*>(state->base->value.p);
				std::sprintf(rendered, "code: %.200s(%d)", proto->source->str, proto->lineDefined);
				break;
			}
			default:
				rendered[0] = '\0';
				break;
		}

		lua_pushstring(state, rendered);
		return 1;
	}

	/**
	 * Address: 0x0090F7F0 (FUN_0090F7F0, luaB_require)
	 *
	 * IDA signature:
	 * int __cdecl luaB_require(lua_State *L);
	 *
	 * What it does:
	 * Loads a package once. Already-loaded names come straight back out of
	 * `_LOADED`; otherwise each ';'-separated template in the search path is
	 * tried in turn until one loads. The chunk runs with `_REQUIREDNAME` set to
	 * the requested name, and whatever it returns - or `true` if it returns
	 * nothing - is cached under that name.
	 */
	int luaB_require(lua_State* const state)
	{
		constexpr int kFileNotFound = 2;

		int status = kFileNotFound;

		luaL_checklstring(state, 1, nullptr);
		lua_settop(state, 1);
		lua_pushstring(state, "_LOADED");
		lua_gettable(state, LUA_GLOBALSINDEX);
		if (lua_type(state, 2) != LUA_TTABLE) {
			luaL_error(state, "`_LOADED' is not a table");
		}

		const char* path = getpath(state);
		lua_pushvalue(state, 1);
		lua_rawget(state, 2);

		if (!lua_toboolean(state, -1)) {
			while (status == kFileNotFound) {
				lua_settop(state, 3);
				if (*path == '\0') {
					break;
				}

				const char* component = path;
				if (*component == ';') {
					++component;
				}

				const char* end = std::strchr(component, ';');
				if (end == nullptr) {
					end = component + std::strlen(component);
				}

				lua_pushlstring(state, component, static_cast<size_t>(end - component));
				if (end == nullptr) {
					break;
				}

				path = end;
				pushcomposename(state);
				status = luaL_loadfile(state, lua_tostring(state, -1));
			}

			if (status != 0) {
				if (status != kFileNotFound) {
					const char* const reason = lua_tostring(state, -1);
					luaL_error(state, "error loading package `%s' (%s)", lua_tostring(state, 1), reason);
				}

				const char* const searched = getpath(state);
				luaL_error(state, "could not load package `%s' from path `%s'", lua_tostring(state, 1), searched);
			}

			lua_pushstring(state, "_REQUIREDNAME");
			lua_gettable(state, LUA_GLOBALSINDEX);
			lua_insert(state, -2);
			lua_pushvalue(state, 1);
			lua_pushstring(state, "_REQUIREDNAME");
			lua_insert(state, -2);
			lua_settable(state, LUA_GLOBALSINDEX);

			lua_call(state, 0, 1);

			lua_insert(state, -2);
			lua_pushstring(state, "_REQUIREDNAME");
			lua_insert(state, -2);
			lua_settable(state, LUA_GLOBALSINDEX);

			if (lua_type(state, -1) == LUA_TNIL) {
				lua_pushboolean(state, 1);
				lua_replace(state, -2);
			}

			lua_pushvalue(state, 1);
			lua_pushvalue(state, -2);
			lua_rawset(state, 2);
		}

		return 1;
	}

	/**
	 * Address: 0x00D45170 (base_funcs)
	 *
	 * What it does:
	 * The global functions `base_open` registers straight into the globals
	 * table. Read out of the shipped image in this exact order.
	 */
	const luaL_reg base_funcs[]{
		{"error", luaB_error},
		{"getmetatable", luaB_getmetatable},
		{"setmetatable", luaB_setmetatable},
		{"getfenv", luaB_getfenv},
		{"setfenv", luaB_setfenv},
		{"next", luaB_next},
		{"ipairs", luaB_ipairs},
		{"pairs", luaB_pairs},
		{"print", luaB_print},
		{"tonumber", luaB_tonumber},
		{"tostring", luaB_tostring},
		{"type", luaB_type},
		{"assert", luaB_assert},
		{"unpack", luaB_unpack},
		{"rawequal", luaB_rawequal},
		{"rawget", luaB_rawget},
		{"rawset", luaB_rawset},
		{"pcall", luaB_pcall},
		{"collectgarbage", luaB_collectgarbage},
		{"gcinfo", luaB_gcinfo},
		{"loadfile", luaB_loadfile},
		{"dofile", luaB_dofile},
		{"loadstring", luaB_loadstring},
		{"require", luaB_require},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x00D45238 (co_funcs)
	 *
	 * What it does:
	 * The `coroutine` table's contents.
	 */
	const luaL_reg co_funcs[]{
		{"create", luaB_cocreate},
		{"wrap", luaB_cowrap},
		{"resume", luaB_coresume},
		{"yield", luaB_yield},
		{"status", luaB_costatus},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x0090FCD0 (FUN_0090FCD0, base_open)
	 *
	 * IDA signature:
	 * void __usercall base_open(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Opens the base library into the globals table itself - `_G` names it,
	 * `_VERSION` records the dialect - and installs `newproxy`, whose upvalue
	 * is a weak-keyed table remembering which proxies it created.
	 */
	static void base_open(lua_State* const state)
	{
		lua_pushlstring(state, "_G", 2u);
		lua_pushvalue(state, LUA_GLOBALSINDEX);
		luaL_openlib(state, nullptr, base_funcs, 0);

		lua_pushlstring(state, "_VERSION", 8u);
		lua_pushlstring(state, "Lua 5.0.1", 9u);
		lua_rawset(state, -3);

		lua_pushlstring(state, "newproxy", 8u);
		lua_newtable(state);
		lua_pushvalue(state, -1);
		lua_setmetatable(state, -2);
		lua_pushlstring(state, "__mode", 6u);
		lua_pushlstring(state, "k", 1u);
		lua_rawset(state, -3);
		lua_pushcclosure(state, luaB_newproxy, 1);
		lua_rawset(state, -3);

		lua_rawset(state, -1);
	}

	/**
	 * Address: 0x0090FD90 (FUN_0090FD90, luaopen_base)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_base(lua_State *L);
	 *
	 * What it does:
	 * Opens the base library and the `coroutine` table, then seeds `_LOADED`.
	 * Note what it does *not* do: the prebuilt LuaPlus asks for a default
	 * metatable here through lua_getdefaultmetatable, a function the shipped
	 * binary does not contain at all - which is why the lib's copy of this
	 * function asserted against our global_State.
	 */
	int luaopen_base(lua_State* const state)
	{
		base_open(state);
		luaL_openlib(state, "coroutine", co_funcs, 0);

		lua_newtable(state);
		lua_pushstring(state, "_LOADED");
		lua_insert(state, -2);
		lua_settable(state, LUA_REGISTRYINDEX);
		return 0;
	}

	// luaV_gettable and the two paths below are mutually recursive: a metatable
	// whose __index is itself a table sends the lookup back around.
	const TObject* luaV_getnotable(lua_State* state, const TObject* t, const TObject* key, int loop);
	const TObject* luaV_index(lua_State* state, const TObject* t, const TObject* key, int loop);

	/**
	 * Address: 0x0090E400 (FUN_0090E400, luaL_buffinit)
	 *
	 * IDA signature:
	 * void __cdecl luaL_buffinit(lua_State *L, luaL_Buffer *B);
	 *
	 * What it does:
	 * Starts an empty string buffer. `lvl` counts the partial strings parked
	 * on the Lua stack, which is how the buffer grows past its fixed array.
	 */
	void luaL_buffinit(lua_State* const state, luaL_Buffer* const buffer)
	{
		buffer->L = state;
		buffer->p = buffer->buffer;
		buffer->lvl = 0;
	}

	/**
	 * Address: 0x0090E260 (FUN_0090E260, luaL_prepbuffer)
	 *
	 * IDA signature:
	 * char *__usercall luaL_prepbuffer(luaL_Buffer *B);
	 *
	 * What it does:
	 * Flushes whatever the array holds onto the Lua stack and hands it back
	 * empty. An already-empty buffer is left alone, so no zero-length string
	 * is pushed.
	 */
	char* luaL_prepbuffer(luaL_Buffer* const buffer)
	{
		if (buffer->p != buffer->buffer) {
			lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
			++buffer->lvl;
			buffer->p = buffer->buffer;
			adjuststack(buffer);
		}

		return buffer->buffer;
	}

	/**
	 * Address: 0x0090E2A0 (FUN_0090E2A0, luaL_addlstring)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addlstring(luaL_Buffer *B, const char *s, size_t l);
	 *
	 * What it does:
	 * Appends `l` bytes, flushing whenever the array fills. The binary tests
	 * and copies one byte at a time rather than in runs, which matters for a
	 * source string that overlaps the buffer.
	 */
	void luaL_addlstring(luaL_Buffer* const buffer, const char* s, size_t l)
	{
		for (; l != 0u; --l, ++s) {
			if (buffer->p >= reinterpret_cast<char*>(buffer + 1) && buffer->p != buffer->buffer) {
				lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
				++buffer->lvl;
				buffer->p = buffer->buffer;
				adjuststack(buffer);
			}

			*buffer->p++ = *s;
		}
	}

	/**
	 * Address: 0x0090E300 (FUN_0090E300, luaL_addstring)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addstring(luaL_Buffer *B, const char *s);
	 *
	 * What it does:
	 * Appends a NUL-terminated string.
	 */
	void luaL_addstring(luaL_Buffer* const buffer, const char* const s)
	{
		luaL_addlstring(buffer, s, std::strlen(s));
	}

	/**
	 * Address: 0x0090E370 (FUN_0090E370, luaL_addvalue)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addvalue(luaL_Buffer *B);
	 *
	 * What it does:
	 * Appends the value on top of the Lua stack. One that fits is copied into
	 * the array; one that does not is left on the stack as its own level, with
	 * any pending array contents pushed underneath it first so the pieces stay
	 * in order.
	 */
	void luaL_addvalue(luaL_Buffer* const buffer)
	{
		lua_State* const state = buffer->L;
		const size_t valueLength = lua_strlen(state, -1);
		const size_t freeSpace = sizeof(buffer->buffer) - static_cast<size_t>(buffer->p - buffer->buffer);

		if (valueLength > freeSpace) {
			if (buffer->p != buffer->buffer) {
				lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
				++buffer->lvl;
				buffer->p = buffer->buffer;
				// Slide the flushed piece below the value being added.
				lua_insert(state, -2);
			}

			++buffer->lvl;
			adjuststack(buffer);
			return;
		}

		std::memcpy(buffer->p, lua_tostring(state, -1), valueLength);
		buffer->p += valueLength;
		lua_settop(state, -2);
	}

	/**
	 * Address: 0x0090DC20 (FUN_0090DC20, luaL_findstring)
	 *
	 * IDA signature:
	 * int __cdecl luaL_findstring(const char *name, const char *const *list);
	 *
	 * What it does:
	 * Returns the index of `name` in a NULL-terminated list, or -1.
	 */
	int luaL_findstring(const char* const name, const char* const* const list)
	{
		for (int index = 0; list[index] != nullptr; ++index) {
			if (std::strcmp(list[index], name) == 0) {
				return index;
			}
		}

		return -1;
	}

	/**
	 * Address: 0x0090DC70 (FUN_0090DC70, luaL_newmetatable)
	 *
	 * IDA signature:
	 * int __cdecl luaL_newmetatable(lua_State *L, const char *tname);
	 *
	 * What it does:
	 * Creates a metatable registered under `tname` and leaves it on the stack,
	 * or returns 0 with the existing one if the name is taken. The registry
	 * gets both directions - name to table and table to name - so a userdata's
	 * type can be recovered from its metatable.
	 */
	int luaL_newmetatable(lua_State* const state, const char* const tname)
	{
		lua_pushstring(state, tname);
		lua_rawget(state, LUA_REGISTRYINDEX);
		if (lua_type(state, -1) != LUA_TNIL) {
			return 0;
		}

		lua_settop(state, -2);
		lua_newtable(state);

		lua_pushstring(state, tname);
		lua_pushvalue(state, -2);
		lua_rawset(state, LUA_REGISTRYINDEX);

		lua_pushvalue(state, -1);
		lua_pushstring(state, tname);
		lua_rawset(state, LUA_REGISTRYINDEX);
		return 1;
	}

	/**
	 * Address: 0x0090DDA0 (FUN_0090DDA0, luaL_callmeta)
	 *
	 * IDA signature:
	 * int __cdecl luaL_callmeta(lua_State *L, int obj, const char *event);
	 *
	 * What it does:
	 * Calls a metamethod with the object as its only argument, leaving the one
	 * result. Returns 0 untouched when there is no such metamethod.
	 */
	int luaL_callmeta(lua_State* const state, int obj, const char* const event)
	{
		if (static_cast<unsigned int>(obj) >= 0xFFFFD8F1u || obj == 0) {
			obj += lua_gettop(state) + 1;
		}

		const int found = luaL_getmetafield(state, obj, event);
		if (found == 0) {
			return found;
		}

		lua_pushvalue(state, obj);
		lua_call(state, 1, 1);
		return 1;
	}

	/**
	 * Address: 0x0090E900 (FUN_0090E900, luaL_argerror)
	 *
	 * IDA signature:
	 * int __usercall luaL_argerror(lua_State *L, int narg, const char *extramsg);
	 *
	 * What it does:
	 * Raises a bad-argument error naming the offending position and function.
	 * A method call shifts the numbering, because `self` is argument one - so
	 * a complaint about it is reported as bad self rather than argument 0.
	 */
	int luaL_argerror(lua_State* const state, int narg, const char* const extramsg)
	{
		lua_Debug ar{};
		(void)lua_getstack(state, 0, &ar);
		(void)lua_getinfo(state, "n", &ar);

		if (std::strcmp(ar.namewhat, "method") == 0 && --narg == 0) {
			luaL_error(state, "calling `%s' on bad self (%s)", ar.name, extramsg);
		}

		if (ar.name == nullptr) {
			ar.name = "?";
		}

		return luaL_error(state, "bad argument #%d to `%s' (%s)", narg, ar.name, extramsg);
	}

	/**
	 * Address: 0x0090E9A0 (FUN_0090E9A0, luaL_typerror)
	 *
	 * IDA signature:
	 * int __cdecl luaL_typerror(lua_State *L, int narg, const char *tname);
	 *
	 * What it does:
	 * Raises "expected X, got Y" for an argument of the wrong type.
	 */
	int luaL_typerror(lua_State* const state, const int narg, const char* const tname)
	{
		const char* const actual = lua_typename(state, lua_type(state, narg));
		const char* const message = lua_pushfstring(state, "%s expected, got %s", tname, actual);
		return luaL_argerror(state, narg, message);
	}

	/**
	 * Address: 0x0090E420 (FUN_0090E420, luaL_ref)
	 *
	 * IDA signature:
	 * int __cdecl luaL_ref(lua_State *L, int t);
	 *
	 * What it does:
	 * Stores the value on top of the stack in table `t` and returns an integer
	 * key for it. Slot 1 heads a free list threaded through the table itself,
	 * so released references are reused before the table grows. A nil value
	 * consumes nothing and returns -1.
	 */
	int luaL_ref(lua_State* const state, int t)
	{
		constexpr int kFreeListSlot = 1;
		constexpr int kFirstReference = 3;
		constexpr int kRefNil = -1;

		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -2);
			return kRefNil;
		}

		lua_rawgeti(state, t, kFreeListSlot);
		const int recycled = static_cast<int>(lua_tonumber(state, -1));
		lua_settop(state, -2);

		if (recycled != 0) {
			// Pop the head of the free list and re-point slot 1 at its successor.
			lua_rawgeti(state, t, recycled);
			lua_rawseti(state, t, kFreeListSlot);
			lua_rawseti(state, t, recycled);
			return recycled;
		}

		int next = luaL_getn(state, t);
		if (next < kFirstReference) {
			next = kFirstReference;
		}

		++next;
		luaL_setn(state, t, next);
		lua_rawseti(state, t, next);
		return next;
	}

	/**
	 * Address: 0x0090E4F0 (FUN_0090E4F0, luaL_unref)
	 *
	 * IDA signature:
	 * void __cdecl luaL_unref(lua_State *L, int t, int ref);
	 *
	 * What it does:
	 * Releases a reference by pushing its slot onto the free list headed at
	 * slot 1. Negative references - LUA_REFNIL and LUA_NOREF - are ignored.
	 */
	void luaL_unref(lua_State* const state, int t, const int ref)
	{
		constexpr int kFreeListSlot = 1;

		if (ref < 0) {
			return;
		}

		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_rawgeti(state, t, kFreeListSlot);
		lua_rawseti(state, t, ref);
		lua_pushnumber(state, static_cast<lua_Number>(ref));
		lua_rawseti(state, t, kFreeListSlot);
	}

	/**
	 * Address: 0x00915190 (FUN_00915190, luaF_getlocalname)
	 *
	 * IDA signature:
	 * const char *__cdecl luaF_getlocalname(const Proto *f, int local_number, int pc);
	 *
	 * What it does:
	 * Names the `local_number`-th local that is live at `pc`. Locals are stored
	 * in the order they come into scope, so the walk stops as soon as one
	 * starts after `pc`.
	 */
	const char* luaF_getlocalname(const Proto* const proto, int local_number, const int pc)
	{
		for (int index = 0; index < proto->sizelocvars; ++index) {
			const LocVar& local = proto->locvars[index];
			if (local.startpc > pc) {
				break;
			}

			if (pc < local.endpc && --local_number == 0) {
				return local.varname->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x00924300 (FUN_00924300, luaE_newthread)
	 *
	 * IDA signature:
	 * lua_State *__usercall luaE_newthread(lua_State *L);
	 *
	 * What it does:
	 * Creates a coroutine sharing the parent's global state and globals table,
	 * with its own stack. It goes on the secondary GC root list, not the main
	 * one.
	 */
	lua_State* luaE_newthread(lua_State* const state)
	{
		auto* const thread = static_cast<lua_State*>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(lua_State)))
		);

		thread->next = state->l_G->rootgc1;
		state->l_G->rootgc1 = reinterpret_cast<GCObject*>(thread);

		thread->marked = 0;
		thread->stack = nullptr;
		thread->stacksize = 0;
		thread->openupval = nullptr;
		thread->size_ci = 0;
		thread->nCcalls = 0;
		thread->ci = nullptr;
		thread->base_ci = nullptr;
		thread->stateUserData = nullptr;
		thread->_gt.tt = LUA_TNIL;
		thread->tt = LUA_TTHREAD;
		thread->l_G = state->l_G;

		lua_stack_init(state, thread);
		thread->_gt = state->_gt;
		return thread;
	}

	/**
	 * Address: 0x00924370 (FUN_00924370, luaE_freethread)
	 *
	 * IDA signature:
	 * void __usercall luaE_freethread(lua_State *L, lua_State *L1);
	 *
	 * What it does:
	 * Destroys a coroutine: closes its upvalues, then releases its call-info
	 * array, its stack, and the thread object, all charged to the parent.
	 */
	void luaE_freethread(lua_State* const state, lua_State* const thread)
	{
		// `lstate` names the currently-executing thread and is only ever the
		// main thread or one that is live: `luaV_execute` sets it on entry and
		// puts the previous one back on exit. Collecting the thread it happens
		// to name breaks that, and every later `GetActiveCState()` then hands
		// out a freed `lua_State` whose `top` points into whatever the
		// allocator did with the block - the observed fault was a push through
		// a `top` sitting in the uncommitted tail of a heap segment. The binary
		// does not need this because it cannot reach here with `lstate` stale;
		// dropping back to the main thread restores its invariant.
		global_State* const globalState = state->l_G;
		if (globalState != nullptr && globalState->lstate == thread) {
			globalState->lstate = globalState->mainthread;
		}

		luaF_close(thread, thread->stack);
		(void)luaM_realloc(state, thread->base_ci, sizeof(CallInfo) * thread->size_ci, 0u);
		(void)luaM_realloc(state, thread->stack, sizeof(TObject) * thread->stacksize, 0u);
		(void)luaM_realloc(state, thread, static_cast<lu_mem>(sizeof(lua_State)), 0u);
	}

	/**
	 * Address: 0x0092BA10 (FUN_0092BA10, luaZ_init)
	 *
	 * IDA signature:
	 * void __cdecl luaZ_init(ZIO *z, lua_Chunkreader reader, void *data, const char *name);
	 *
	 * What it does:
	 * Binds a stream to its reader. The buffer starts empty, so the first read
	 * pulls a block.
	 */
	void luaZ_init(LuaZioRuntimeView* const stream, const lua_Chunkreader reader, void* const data, const char* const name)
	{
		stream->reader = reader;
		stream->readerData = data;
		stream->chunkName = name;
		stream->remainingBytes = 0;
		stream->cursor = nullptr;
	}

	/**
	 * Address: 0x0092B970 (FUN_0092B970, luaZ_fill)
	 *
	 * IDA signature:
	 * int __cdecl luaZ_fill(ZIO *z);
	 *
	 * What it does:
	 * Pulls the next block from the reader and returns its first byte, already
	 * consumed. An empty or absent block is end of stream.
	 */
	int luaZ_fill(LuaZioRuntimeView* const stream)
	{
		size_t available = 0;
		const char* const block = reinterpret_cast<const char*>(
			stream->reader(nullptr, stream->readerData, &available)
		);

		if (block == nullptr || available == 0u) {
			return kLuaEndOfStream;
		}

		stream->remainingBytes = static_cast<int>(available - 1u);
		stream->cursor = block + 1;
		return static_cast<unsigned char>(*block);
	}

	/**
	 * Address: 0x0092B9B0 (FUN_0092B9B0, luaZ_lookahead)
	 *
	 * IDA signature:
	 * int __cdecl luaZ_lookahead(ZIO *z);
	 *
	 * What it does:
	 * Peeks the next byte without consuming it. Refilling consumes one, so it
	 * is pushed back - the binary inlines luaZ_fill here and open-codes that
	 * same adjustment.
	 */
	int luaZ_lookahead(LuaZioRuntimeView* const stream)
	{
		if (stream->remainingBytes == 0) {
			if (luaZ_fill(stream) == kLuaEndOfStream) {
				return kLuaEndOfStream;
			}

			++stream->remainingBytes;
			--stream->cursor;
		}

		return static_cast<unsigned char>(*stream->cursor);
	}
	/**
	 * Address: 0x0090CE50 (FUN_0090CE50, lua_pushvfstring)
	 *
	 * What it does:
	 * Formats a string onto the Lua stack. The API entry gives the collector a
	 * chance to run first, which the internal luaO_pushvfstring does not.
	 */
	const char* lua_pushvfstring(lua_State* const state, const char* const fmt, va_list argp)
	{
		luaC_checkGC(state);
		return luaO_pushvfstring(state, fmt, argp);
	}

	/**
	 * Address: 0x0090CE90 (FUN_0090CE90, lua_pushfstring)
	 *
	 * What it does:
	 * The varargs form of lua_pushvfstring.
	 */
	const char* lua_pushfstring(lua_State* const state, const char* const fmt, ...)
	{
		va_list argp;
		va_start(argp, fmt);
		luaC_checkGC(state);
		const char* const result = luaO_pushvfstring(state, fmt, argp);
		va_end(argp);
		return result;
	}

	/**
	 * Address: 0x0090CA90 (FUN_0090CA90, lua_tostring)
	 *
	 * IDA signature:
	 * const char *__usercall lua_tostring@<eax>(lua_State *L, int idx);
	 *
	 * What it does:
	 * Reads a stack slot as a string, converting a number in place if that is
	 * what is there. The conversion allocates, so the collector gets a chance
	 * to run before returning - which is also why the returned pointer is only
	 * good until the slot changes.
	 */
	const char* lua_tostring(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = negindex(state, idx);
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return nullptr;
			}
		}

		if (object == nullptr) {
			return nullptr;
		}

		if (object->tt == LUA_TSTRING) {
			return static_cast<const TString*>(object->value.p)->str;
		}

		const char* result = nullptr;
		if (luaV_tostring(state, object) != 0) {
			result = static_cast<const TString*>(object->value.p)->str;
		}

		luaC_checkGC(state);
		return result;
	}

	// Defined in LuaParser.cpp, alongside f_parser and SParser.
	int luaD_protectedparser(lua_State* L, LuaZioRuntimeView* z, int bin);

	/**
	 * Address: 0x0090D5C0 (FUN_0090D5C0, lua_load)
	 *
	 * IDA signature:
	 * int __cdecl lua_load(lua_State *L, lua_Chunkreader reader, void *data, const char *chunkname);
	 *
	 * What it does:
	 * Compiles a chunk pulled from `reader`. One byte of lookahead decides
	 * whether it is precompiled - a leading ESC marks a binary chunk - so
	 * source and bytecode load through the same entry point.
	 */
	int lua_load(lua_State* const state, const lua_Chunkreader reader, void* const data, const char* chunkname)
	{
		constexpr int kLuaSignatureFirstByte = 0x1B; // ESC, the binary-chunk marker

		if (chunkname == nullptr) {
			chunkname = "?";
		}

		LuaZioRuntimeView stream;
		luaZ_init(&stream, reader, data, chunkname);
		const int first = luaZ_lookahead(&stream);
		return luaD_protectedparser(state, &stream, first == kLuaSignatureFirstByte);
	}

	// One block of a file being loaded. luaL_loadfile keeps this on its own
	// stack and hands it to lua_load as the reader's state.
	struct LuaLoadFileState
	{
		FILE* f;
		char buff[512];
	};

	// The whole of a string being loaded, handed over in one go.
	struct LuaLoadStringState
	{
		const char* s;
		size_t size;
	};

	/**
	 * Address: 0x0090E550 (FUN_0090E550, getWF)
	 *
	 * What it does:
	 * Reader for luaL_loadfile: hands over one buffer's worth at a time.
	 */
	const char* getWF(lua_State* const state, void* const data, size_t* const size)
	{
		(void)state;
		auto* const lf = static_cast<LuaLoadFileState*>(data);
		if (std::feof(lf->f) != 0) {
			return nullptr;
		}

		*size = std::fread(lf->buff, 1u, sizeof(lf->buff), lf->f);
		return (*size > 0u) ? lf->buff : nullptr;
	}

	/**
	 * Address: 0x0090E740 (FUN_0090E740, getS)
	 *
	 * What it does:
	 * Reader for luaL_loadbuffer: the whole string once, then end of stream.
	 */
	const char* getS(lua_State* const state, void* const data, size_t* const size)
	{
		(void)state;
		auto* const ls = static_cast<LuaLoadStringState*>(data);
		if (ls->size == 0u) {
			return nullptr;
		}

		*size = ls->size;
		ls->size = 0u;
		return ls->s;
	}

	/**
	 * Address: 0x0090E590 (FUN_0090E590, errfile)
	 *
	 * IDA signature:
	 * int __usercall errfile@<eax>(int fnameindex@<ebx>, lua_State *L@<edi>);
	 *
	 * What it does:
	 * Replaces the pushed chunk name with "cannot read <file>: <reason>" and
	 * reports it as a file error. The name is skipped past its `@` marker.
	 */
	int errfile(lua_State* const state, const int fnameindex)
	{
		const char* const filename = lua_tostring(state, fnameindex) + 1;
		lua_pushfstring(state, "cannot read %s: %s", filename, std::strerror(errno));
		lua_remove(state, fnameindex);
		return LUA_ERRFILE;
	}

	/**
	 * Address: 0x0090E5D0 (FUN_0090E5D0, luaL_loadfile)
	 *
	 * IDA signature:
	 * int __cdecl luaL_loadfile(lua_State *L, const char *filename);
	 *
	 * What it does:
	 * Loads a chunk from a file, or from stdin when `filename` is null. The
	 * chunk name is pushed first so an error can name the file even if opening
	 * it failed. If the first byte is neither printable nor whitespace the file
	 * is reopened in binary mode, which is how a precompiled chunk survives the
	 * text-mode line-ending translation.
	 */
	int luaL_loadfile(lua_State* const state, const char* const filename)
	{
		const int fnameindex = lua_gettop(state) + 1; // where the chunk name lands

		LuaLoadFileState lf;
		if (filename != nullptr) {
			lua_pushfstring(state, "@%s", filename);
			lf.f = std::fopen(filename, "r");
		} else {
			lua_pushlstring(state, "=stdin", 6u);
			lf.f = stdin;
		}

		if (lf.f == nullptr) {
			return errfile(state, fnameindex);
		}

		const int first = std::getc(lf.f);
		/**
		 * Address: 0x00A868BB (FUN_00A868BB, `ungetc` -- IDA FLIRT-identified
		 * by its real CRT symbol name, not `FUN_`/`sub_` prefixed)
		 * Address: 0x00A8679D (FUN_00A8679D, `_ungetc_nolock`-equivalent
		 * internal body `ungetc` calls into)
		 *
		 * `std::ungetc(first, lf.f)` below compiles to these two out-of-line
		 * MSVC8 CRT stdio bodies. Confirmed against 0x00A8679D's own `.c`:
		 * text-mode `ioinfo`/`_badioinfo` validation via `_fileno`, then
		 * direct `FILE::_flag`/`_base`/`_ptr`/`_cnt` manipulation and
		 * `getbuf`/`_invalid_parameter` calls -- textbook MSVC CRT
		 * `ungetc`/`_ungetc_nolock`, not engine code. Reached from this call
		 * site (the classic `luaL_loadfile` shebang-line peek: read one
		 * byte, push it back, then decide text- vs binary-mode reopen) and
		 * from the `io.read(0)`-style peek at `LuaObject.cpp` ~line 6112.
		 * Both `FUN_00A868BB`/`FUN_00A8679D` were mass-mis-attributed to
		 * `CrtRuntimeHelpers.cpp` by the 2026-08-24 DB-integrity bulk pass
		 * (address not present in that file); classified
		 * `external_dependency` here with a real citation instead.
		 */
		std::ungetc(first, lf.f);
		if (std::isspace(first) == 0 && std::isprint(first) == 0 && lf.f != stdin) {
			std::fclose(lf.f);
			lf.f = std::fopen(filename, "rb");
			if (lf.f == nullptr) {
				return errfile(state, fnameindex);
			}
		}

		const int status =
			lua_load(state, reinterpret_cast<lua_Chunkreader>(getWF), &lf, lua_tostring(state, -1));

		const int readstatus = std::ferror(lf.f);
		if (lf.f != stdin) {
			std::fclose(lf.f);
		}
		if (readstatus != 0) {
			lua_settop(state, fnameindex); // drop whatever the load left behind
			return errfile(state, fnameindex);
		}

		lua_remove(state, fnameindex);
		return status;
	}

	/**
	 * Address: 0x0090E760 (FUN_0090E760, luaL_loadbuffer)
	 *
	 * What it does:
	 * Loads a chunk from memory.
	 */
	int luaL_loadbuffer(
		lua_State* const state,
		const char* const buff,
		const size_t size,
		const char* const name
	)
	{
		LuaLoadStringState ls;
		ls.s = buff;
		ls.size = size;
		return lua_load(state, reinterpret_cast<lua_Chunkreader>(getS), &ls, name);
	}


	/**
	 * Address: 0x0092BA40 (FUN_0092BA40, luaZ_read)
	 *
	 * IDA signature:
	 * size_t __cdecl luaZ_read(ZIO *z, void *b, size_t n);
	 *
	 * What it does:
	 * Copies `n` bytes out of the stream, pulling blocks as needed. Returns 0
	 * on success, or how many bytes were still wanted when the stream ended -
	 * so a non-zero result is a short read, not a count.
	 */
	size_t luaZ_read(LuaZioRuntimeView* const stream, void* buffer, size_t n)
	{
		while (n != 0u) {
			if (stream->remainingBytes == 0) {
				if (luaZ_fill(stream) == kLuaEndOfStream) {
					return n;
				}

				++stream->remainingBytes;
				--stream->cursor;
			}

			const size_t chunk =
				(n <= static_cast<size_t>(stream->remainingBytes)) ? n : static_cast<size_t>(stream->remainingBytes);
			std::memcpy(buffer, stream->cursor, chunk);

			stream->remainingBytes -= static_cast<int>(chunk);
			stream->cursor += chunk;
			buffer = static_cast<char*>(buffer) + chunk;
			n -= chunk;
		}

		return 0u;
	}

	/**
	 * Address: 0x0090DD10 (FUN_0090DD10, luaL_checkstack)
	 *
	 * IDA signature:
	 * void __cdecl luaL_checkstack(lua_State *L, int space, const char *mes);
	 *
	 * What it does:
	 * Reserves stack room or raises "stack overflow", naming what wanted it.
	 */
	void luaL_checkstack(lua_State* const state, const int space, const char* const message)
	{
		if (lua_checkstack(state, space) == 0) {
			luaL_error(state, "stack overflow (%s)", message);
		}
	}

	/**
	 * Address: 0x0090DCF0 (FUN_0090DCF0, luaL_getmetatable)
	 *
	 * IDA signature:
	 * void __cdecl luaL_getmetatable(lua_State *L, const char *tname);
	 *
	 * What it does:
	 * Pushes the registry entry a named metatable was registered under.
	 */
	void luaL_getmetatable(lua_State* const state, const char* const tname)
	{
		lua_pushstring(state, tname);
		lua_rawget(state, LUA_REGISTRYINDEX);
	}

	/**
	 * Address: 0x00914EF0 (FUN_00914EF0, luaF_newLclosure)
	 *
	 * IDA signature:
	 * Closure *__usercall luaF_newLclosure(lua_State *L, int nelems, TObject *e);
	 *
	 * What it does:
	 * Allocates a Lua closure sized for `nelems` upvalues, links it for
	 * collection, and captures the environment it was created in. The
	 * prototype and the upvalue array are filled in by the caller.
	 */
	Closure* luaF_newLclosure(lua_State* const state, const int nelems, const TObject* const environment)
	{
		auto* const closure = static_cast<Closure*>(luaM_realloc(
			state,
			nullptr,
			0u,
			static_cast<lu_mem>(offsetof(LClosure, upvals) + sizeof(UpVal*) * nelems)
		));

		luaC_link(state, reinterpret_cast<GCObject*>(closure), LUA_TFUNCTION);

		closure->l.g = *environment;
		closure->l.nupvalues = static_cast<lu_byte>(nelems);
		return closure;
	}

	/**
	 * Address: 0x009138D0 (FUN_009138D0, luaD_reallocstack)
	 *
	 * IDA signature:
	 * void __cdecl luaD_reallocstack(lua_State *L, int newsize);
	 *
	 * What it does:
	 * Resizes the value stack and re-points everything that held a slot into
	 * the old block. `stack_last` is kept six slots short of the end, which is
	 * the headroom the API relies on for pushes that do not check first.
	 */
	void luaD_reallocstack(lua_State* const state, const int newsize)
	{
		constexpr int kStackHeadroom = 6;

		StkId const oldStack = state->stack;
		auto* const newStack = static_cast<StkId>(luaM_realloc(
			state,
			oldStack,
			static_cast<lu_mem>(sizeof(TObject) * state->stacksize),
			static_cast<lu_mem>(sizeof(TObject) * newsize)
		));

		state->stack_last = &newStack[newsize - kStackHeadroom];
		state->stack = newStack;
		state->stacksize = newsize;
		correctstack(state, oldStack);
	}

	/**
	 * Address: 0x00913920 (FUN_00913920, luaD_reallocCI)
	 *
	 * IDA signature:
	 * CallInfo *__cdecl luaD_reallocCI(lua_State *L, int newsize);
	 *
	 * What it does:
	 * Resizes the call-info array, rebasing the current frame pointer onto the
	 * new block. Note the frame count is truncated to 16 bits when end_ci is
	 * computed, matching size_ci's width.
	 */
	void luaD_reallocCI(lua_State* const state, const int newsize)
	{
		CallInfo* const oldBase = state->base_ci;
		const ptrdiff_t activeFrame = state->ci - oldBase;

		auto* const newBase = static_cast<CallInfo*>(luaM_realloc(
			state,
			oldBase,
			static_cast<lu_mem>(sizeof(CallInfo) * state->size_ci),
			static_cast<lu_mem>(sizeof(CallInfo) * newsize)
		));

		state->ci = &newBase[activeFrame];
		state->size_ci = static_cast<std::uint16_t>(newsize);
		state->base_ci = newBase;
		state->end_ci = &newBase[static_cast<std::uint16_t>(newsize)];
	}

	/**
	 * Address: 0x0090DF30 (FUN_0090DF30, getsizes)
	 *
	 * IDA signature:
	 * void __usercall getsizes(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Pushes the registry's weak-keyed table of array sizes, creating it on
	 * first use. Weak keys mean a table recorded here does not keep itself
	 * alive just by having had its length cached.
	 */
	static void getsizes(lua_State* const state)
	{
		constexpr int kRegistrySizesKey = 2;

		lua_rawgeti(state, LUA_REGISTRYINDEX, kRegistrySizesKey);
		if (lua_type(state, -1) != LUA_TNIL) {
			return;
		}

		lua_settop(state, -2);
		lua_newtable(state);
		lua_pushvalue(state, -1);
		(void)lua_setmetatable(state, -2);
		lua_pushlstring(state, "__mode", 6u);
		lua_pushlstring(state, "k", 1u);
		lua_rawset(state, -3);
		lua_pushvalue(state, -1);
		lua_rawseti(state, LUA_REGISTRYINDEX, kRegistrySizesKey);
	}

	/**
	 * Address: 0x0090DFB0 (FUN_0090DFB0, luaL_setn)
	 *
	 * IDA signature:
	 * void __cdecl luaL_setn(lua_State *L, int t, int n);
	 *
	 * What it does:
	 * Records a table's length. A table that already carries an `n` field keeps
	 * using it; otherwise the size goes in the weak side table, so the table
	 * itself is left unmodified.
	 */
	void luaL_setn(lua_State* const state, int t, const int n)
	{
		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_pushlstring(state, "n", 1u);
		lua_rawget(state, t);

		int recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -2);

		if (recorded < 0) {
			getsizes(state);
			lua_pushvalue(state, t);
			lua_pushnumber(state, static_cast<lua_Number>(n));
			lua_rawset(state, -3);
			lua_settop(state, -2);
			return;
		}

		lua_pushlstring(state, "n", 1u);
		lua_pushnumber(state, static_cast<lua_Number>(n));
		lua_rawset(state, t);
	}

	/**
	 * Address: 0x0090E090 (FUN_0090E090, luaL_getn)
	 *
	 * IDA signature:
	 * int __cdecl luaL_getn(lua_State *L, int t);
	 *
	 * What it does:
	 * Reports a table's length, in the order the `n` field, then the weak side
	 * table, then an actual count from index 1 up to the first nil.
	 */
	int luaL_getn(lua_State* const state, int t)
	{
		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_pushlstring(state, "n", 1u);
		lua_rawget(state, t);

		int recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -2);
		if (recorded >= 0) {
			return recorded;
		}

		getsizes(state);
		lua_pushvalue(state, t);
		lua_rawget(state, -2);

		recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -3);
		if (recorded >= 0) {
			return recorded;
		}

		int index = 1;
		lua_rawgeti(state, t, index);
		while (lua_type(state, -1) != LUA_TNIL) {
			lua_settop(state, -2);
			lua_rawgeti(state, t, ++index);
		}

		lua_settop(state, -2);
		return index - 1;
	}

	/**
	 * Address: 0x00915090 (FUN_00915090, luaF_freeproto)
	 *
	 * IDA signature:
	 * void __cdecl luaF_freeproto(lua_State *L, Proto *f);
	 *
	 * What it does:
	 * Releases a prototype and every array hanging off it, the prototype
	 * itself last.
	 */
	void luaF_freeproto(lua_State* const state, Proto* const proto)
	{
		(void)luaM_realloc(state, proto->code, sizeof(Instruction) * proto->sizecode, 0u);
		(void)luaM_realloc(state, proto->p, sizeof(Proto*) * proto->sizep, 0u);
		(void)luaM_realloc(state, proto->k, sizeof(TObject) * proto->sizek, 0u);
		(void)luaM_realloc(state, proto->lineinfo, sizeof(int) * proto->sizelineinfo, 0u);
		(void)luaM_realloc(state, proto->locvars, sizeof(LocVar) * proto->sizelocvars, 0u);
		(void)luaM_realloc(state, proto->upvalues, sizeof(TString*) * proto->sizeupvalues, 0u);
		(void)luaM_realloc(state, proto, static_cast<lu_mem>(sizeof(Proto)), 0u);
	}

	/**
	 * Address: 0x00929680 (FUN_00929680, luaV_strcmp)
	 *
	 * IDA signature:
	 * int __usercall luaV_strcmp(const TString *ls@<ecx>, const TString *rs@<eax>);
	 *
	 * What it does:
	 * Orders two Lua strings by locale. They may contain embedded NULs, so a
	 * single strcoll is not enough: when the compared runs tie, whichever
	 * string ends at that NUL sorts first, and if neither does the comparison
	 * resumes past it.
	 */
	static int luaV_strcmp(const TString* const ls, const TString* const rs)
	{
		const char* left = ls->str;
		const char* right = rs->str;
		size_t leftRemaining = ls->len;
		size_t rightRemaining = rs->len;

		for (;;) {
			const int ordering = std::strcoll(left, right);
			if (ordering != 0) {
				return ordering;
			}

			// Equal up to a NUL: whoever ran out is the smaller string.
			const size_t run = std::strlen(left);
			if (run == rightRemaining) {
				return (run == leftRemaining) ? 0 : 1;
			}

			if (run == leftRemaining) {
				return -1;
			}

			const size_t consumed = run + 1u;
			left += consumed;
			right += consumed;
			leftRemaining -= consumed;
			rightRemaining -= consumed;
		}
	}

	/**
	 * Address: 0x00913460 (FUN_00913460, luaG_ordererror)
	 *
	 * IDA signature:
	 * void __cdecl luaG_ordererror(lua_State *L, const TObject *p1, const TObject *p2);
	 *
	 * What it does:
	 * Reports two values that cannot be ordered. The binary distinguishes
	 * "two %s values" from "%s with %s" by comparing the third character of
	 * the two type names, which is enough to separate every pair in
	 * luaT_typenames.
	 */
	void luaG_ordererror(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		const char* const leftName = luaT_typenames[left->tt];
		const char* const rightName = luaT_typenames[right->tt];

		if (leftName[2] == rightName[2]) {
			luaG_runerror(state, "attempt to compare two %s values", leftName);
		}

		luaG_runerror(state, "attempt to compare %s with %s", leftName, rightName);
	}

	/**
	 * Address: 0x009296F0 (FUN_009296F0, luaV_lessthan)
	 *
	 * IDA signature:
	 * int __cdecl luaV_lessthan(lua_State *L, const TObject *l, const TObject *r);
	 *
	 * What it does:
	 * Evaluates `l < r`. Values of different tags order by tag alone; numbers
	 * and strings compare directly; anything else goes to `__lt`.
	 */
	int luaV_lessthan(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodLess = 14;

		if (left->tt != right->tt) {
			return left->tt < right->tt;
		}

		if (left->tt == LUA_TNUMBER) {
			return right->value.n > left->value.n;
		}

		if (left->tt == LUA_TSTRING) {
			return luaV_strcmp(
				static_cast<const TString*>(left->value.p),
				static_cast<const TString*>(right->value.p)
			) < 0;
		}

		const int viaTagMethod = call_orderTM(state, left, right, kTagMethodLess);
		if (viaTagMethod == -1) {
			luaG_ordererror(state, left, right);
		}

		return viaTagMethod;
	}

	/**
	 * Address: 0x00929770 (FUN_00929770, luaV_lessequal)
	 *
	 * IDA signature:
	 * int __usercall luaV_lessequal(const TObject *l@<edi>, const TObject *r@<esi>, lua_State *L);
	 *
	 * What it does:
	 * Evaluates `l <= r`. With no `__le` it falls back to `not (r < l)`, which
	 * is what makes a type that only defines `__lt` still usable with `<=`.
	 */
	int luaV_lessequal(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodLess = 14;
		constexpr int kTagMethodLessEqual = 15;

		if (left->tt != right->tt) {
			return left->tt < right->tt;
		}

		if (left->tt == LUA_TNUMBER) {
			return right->value.n >= left->value.n;
		}

		if (left->tt == LUA_TSTRING) {
			return luaV_strcmp(
				static_cast<const TString*>(left->value.p),
				static_cast<const TString*>(right->value.p)
			) <= 0;
		}

		const int viaLessEqual = call_orderTM(state, left, right, kTagMethodLessEqual);
		if (viaLessEqual != -1) {
			return viaLessEqual;
		}

		const int viaLess = call_orderTM(state, right, left, kTagMethodLess);
		if (viaLess == -1) {
			luaG_ordererror(state, left, right);
		}

		return viaLess == 0;
	}

	/**
	 * Address: 0x00929810 (FUN_00929810, luaV_equalval)
	 *
	 * IDA signature:
	 * int __cdecl luaV_equalval(lua_State *L, const TObject *l, const TObject *r);
	 *
	 * What it does:
	 * Compares two values already known to share a tag. Primitives compare by
	 * payload; tables and userdata are equal when they are the same object, and
	 * otherwise consult `__eq` - which only applies when both sides carry the
	 * same handler.
	 */
	int luaV_equalval(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodEqual = 3;

		Table* leftMetatable = nullptr;
		Table* rightMetatable = nullptr;

		switch (left->tt) {
			case LUA_TNIL:
				return 1;
			case LUA_TBOOLEAN:
				return left->value.b == right->value.b;
			case LUA_TNUMBER:
				return left->value.n == right->value.n;
			case LUA_TTABLE: {
				auto* const leftTable = static_cast<Table*>(left->value.p);
				auto* const rightTable = static_cast<Table*>(right->value.p);
				if (leftTable == rightTable) {
					return 1;
				}
				leftMetatable = leftTable->metatable;
				rightMetatable = rightTable->metatable;
				break;
			}
			case LUA_TUSERDATA: {
				auto* const leftUdata = static_cast<Udata*>(left->value.p);
				auto* const rightUdata = static_cast<Udata*>(right->value.p);
				if (leftUdata == rightUdata) {
					return 1;
				}
				leftMetatable = leftUdata->metatable;
				rightMetatable = rightUdata->metatable;
				break;
			}
			default:
				return left->value.b == right->value.b;
		}

		const TObject* const handler = get_compTM(leftMetatable, kTagMethodEqual, state, rightMetatable);
		if (handler == nullptr) {
			return 0;
		}

		(void)callTMres(handler, left, right, state);

		const TObject* const result = state->top;
		if (result->tt == LUA_TNIL) {
			return 0;
		}

		if (result->tt != LUA_TBOOLEAN) {
			return 1;
		}

		return result->value.b != 0;
	}

	/**
	 * Address: 0x00915010 (FUN_00915010, luaF_newproto)
	 *
	 * IDA signature:
	 * Proto *__cdecl luaF_newproto(lua_State *L);
	 *
	 * What it does:
	 * Allocates an empty function prototype and links it for collection. Every
	 * lane is cleared except gclist, which luaC_link has just written.
	 */
	Proto* luaF_newproto(lua_State* const state)
	{
		auto* const proto = static_cast<Proto*>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(Proto)))
		);
		luaC_link(state, reinterpret_cast<GCObject*>(proto), LUA_TPROTO);

		proto->k = nullptr;
		proto->code = nullptr;
		proto->p = nullptr;
		proto->lineinfo = nullptr;
		proto->locvars = nullptr;
		proto->upvalues = nullptr;
		proto->source = nullptr;
		proto->sizeupvalues = 0;
		proto->sizek = 0;
		proto->sizecode = 0;
		proto->sizelineinfo = 0;
		proto->sizep = 0;
		proto->sizelocvars = 0;
		proto->lineDefined = 0;
		proto->nups = 0;
		proto->numparams = 0;
		proto->is_vararg = 0;
		proto->maxstacksize = 0;
		proto->reserved0 = 0;
		proto->reserved1 = 0;
		proto->reserved2 = 0;
		proto->reserved3 = 0;
		proto->reserved4 = 0;
		proto->reserved5 = 0;
		proto->reserved6 = 0;
		proto->reserved7 = 0;
		proto->reserved8 = 0;
		return proto;
	}

	/**
	 * Address: 0x00915160 (FUN_00915160, luaF_freeclosure)
	 *
	 * IDA signature:
	 * void __cdecl luaF_freeclosure(lua_State *L, Closure *c);
	 *
	 * What it does:
	 * Releases a closure. The size is computed from the upvalue count with the
	 * Lua-closure formula, which is what the binary does for either kind.
	 */
	void luaF_freeclosure(lua_State* const state, Closure* const closure)
	{
		constexpr size_t kClosureHeaderSize = 28u;

		(void)luaM_realloc(
			state,
			closure,
			static_cast<lu_mem>(kClosureHeaderSize + 4u * closure->c.nupvalues),
			0u
		);
	}

	/**
	 * Address: 0x00914F70 (FUN_00914F70, luaF_findupval)
	 *
	 * IDA signature:
	 * UpVal *__usercall luaF_findupval(lua_State *L, StkId level);
	 *
	 * What it does:
	 * Returns the upvalue already pointing at `level`, or makes one and splices
	 * it into the thread's open list. The list runs from higher stack slots
	 * down, so the walk stops as soon as it passes the target.
	 */
	UpVal* luaF_findupval(lua_State* const state, StkId const level)
	{
		GCObject** link = &state->openupval;

		for (GCObject* candidate = state->openupval; candidate != nullptr; candidate = candidate->gch.next) {
			TObject* const referenced = candidate->uv.v;
			if (referenced < level) {
				break;
			}

			if (referenced == level) {
				return &candidate->uv;
			}

			link = &candidate->gch.next;
		}

		auto* const upvalue = static_cast<UpVal*>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(UpVal)))
		);
		upvalue->tt = LUA_TUPVALUE;
		upvalue->marked = 1;
		upvalue->v = level;
		upvalue->next = *link;
		*link = reinterpret_cast<GCObject*>(upvalue);
		return upvalue;
	}

	/**
	 * Address: 0x009139F0 (FUN_009139F0, luaD_callhook)
	 *
	 * IDA signature:
	 * void __cdecl luaD_callhook(lua_State *L, int event, int line);
	 *
	 * What it does:
	 * Invokes the installed debug hook for one event. Stack positions are
	 * saved as offsets rather than pointers because the hook may grow the
	 * stack and move it, and the hook is disabled for its own duration so it
	 * cannot re-enter. A tail return has no frame of its own, so it reports
	 * i_ci 0.
	 */
	void luaD_callhook(lua_State* const state, const int event, const int line)
	{
		constexpr int kMinCStackSlots = 20;

		global_State* const globalState = state->l_G;
		const Hook hook = globalState->hook;
		if (hook == nullptr || globalState->allowhook == 0) {
			return;
		}

		const ptrdiff_t savedTop = state->top - state->stack;
		const ptrdiff_t savedFrameTop = state->ci->top - state->stack;

		lua_Debug ar{};
		ar.event = event;
		ar.currentline = line;
		ar.i_ci = (event == LUA_HOOKTAILRET) ? 0 : static_cast<int>(state->ci - state->base_ci);

		if (state->stack_last - state->top <= kMinCStackSlots) {
			luaD_growstack(state, kMinCStackSlots);
		}

		state->ci->top = state->top + kMinCStackSlots;
		state->l_G->allowhook = 0;
		hook(state, &ar);
		state->l_G->allowhook = 1;

		state->ci->top = state->stack + savedFrameTop;
		state->top = state->stack + savedTop;
	}

	/**
	 * Address: 0x009131B0 (FUN_009131B0, luaG_errormsg)
	 *
	 * IDA signature:
	 * void __cdecl luaG_errormsg(lua_State *L);
	 *
	 * What it does:
	 * Delivers a pending error. If the globals table defines `_TRACEBACK`, it
	 * is called with the message and whatever it returns replaces it - that is
	 * how a stack trace gets attached. Either way the result is thrown as a
	 * lua_RuntimeError carrying the top-of-stack string.
	 */
	void luaG_errormsg(lua_State* const state)
	{
		TString* const key = luaS_newlstr(state, "_TRACEBACK", 10u);
		state->top->tt = static_cast<int>(key->tt);
		state->top->value.p = key;
		api_incr_top(state);

		const TObject* const handler = luaV_gettable(state, &state->_gt, state->top - 1, 0);
		if (IsCallableTag(handler->tt)) {
			// Stack holds [message, "_TRACEBACK"]; turn it into
			// [handler, message] and call it.
			state->top[-1] = state->top[-2];
			state->top[-2] = *handler;
			(void)luaD_call(state, state->top - 2, 1);
		} else {
			--state->top;
		}

		throw lua_RuntimeError(lua::lua_Error(state, LUA_ERRRUN));
	}

	/**
	 * Address: 0x00929150 (FUN_00929150, luaV_tonumber)
	 *
	 * IDA signature:
	 * const TObject *__usercall luaV_tonumber@<eax>(const TObject *obj, TObject *n);
	 *
	 * What it does:
	 * Views a value as a number. Numbers are returned as they are; a string is
	 * parsed into the caller's scratch slot and that is returned instead.
	 * Anything else - or a string that does not parse - gives null, which is
	 * what makes arithmetic on it fall through to a tag method.
	 */
	const TObject* luaV_tonumber(const TObject* const obj, TObject* const n)
	{
		if (obj->tt == LUA_TNUMBER) {
			return obj;
		}

		if (obj->tt == LUA_TSTRING) {
			float parsed = 0.0f;
			if (luaO_str2d(static_cast<const TString*>(obj->value.p)->str, &parsed) != 0) {
				n->value.n = parsed;
				n->tt = LUA_TNUMBER;
				return n;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x009291A0 (FUN_009291A0, luaV_tostring)
	 *
	 * IDA signature:
	 * int __cdecl luaV_tostring(lua_State *L, TObject *obj);
	 *
	 * What it does:
	 * Converts a number in place to its string form, leaving anything else
	 * alone. Returns whether the slot now holds a string.
	 */
	int luaV_tostring(lua_State* const state, TObject* const object)
	{
		if (object->tt != LUA_TNUMBER) {
			return 0;
		}

		char rendered[32];
		std::sprintf(rendered, "%.14g", static_cast<double>(object->value.n));

		TString* const interned = luaS_newlstr(state, rendered, std::strlen(rendered));
		object->value.p = interned;
		object->tt = static_cast<int>(interned->tt);
		return 1;
	}

	/**
	 * Address: 0x00929910 (FUN_00929910, luaV_concat)
	 *
	 * IDA signature:
	 * void __cdecl luaV_concat(lua_State *L, int total, int last);
	 *
	 * What it does:
	 * Folds `total` stack values ending at `last` into one string. Each pass
	 * takes the longest run of strings and numbers it can reach and joins them
	 * through the shared scratch buffer in a single allocation, so `a..b..c`
	 * does not build an intermediate. A pair that is not concatenable falls
	 * back to `__concat`, which handles one pair at a time - hence the outer
	 * loop.
	 */
	// Lua's own `tostring` macro, and the shape the binary open-codes at each of
	// the three sites below: `if (slot->tt != LUA_TSTRING) { convert or fail }`.
	//
	// `luaV_tostring` alone is NOT this test - it reports 0 for a value that is
	// already a string, because its job is only the number-to-string conversion.
	// Calling it bare on the right-hand operand made every string-to-string
	// concatenation take the __concat path and raise "concatenate expected but
	// got string". Since luaO_pushvfstring builds every Lua error message with
	// exactly that concatenation, each error raised a fresh error while
	// formatting itself, and the first one to occur overflowed the stack.
	[[nodiscard]] static bool CoerceToStringInPlace(lua_State* const state, StkId const slot)
	{
		return slot->tt == LUA_TSTRING || luaV_tostring(state, slot) != 0;
	}

	void luaV_concat(lua_State* const state, int total, int last)
	{
		constexpr int kTagMethodConcat = 16;
		constexpr size_t kMaxStringSize = 0xFFFFFFFDu;

		do {
			StkId const top = state->base + last + 1;
			int handled = 2;

			if (!CoerceToStringInPlace(state, top - 2) || !CoerceToStringInPlace(state, top - 1)) {
				const TObject* handler = luaT_gettmbyobj(state, top - 2, kTagMethodConcat);
				if (handler->tt == LUA_TNIL) {
					handler = luaT_gettmbyobj(state, top - 1, kTagMethodConcat);
				}

				if (!IsCallableTag(handler->tt)) {
					luaV_concat_raise_typeerror(state, top - 2, top - 1);
				}

				const ptrdiff_t resultOffset =
					reinterpret_cast<char*>(top - 2) - reinterpret_cast<char*>(state->stack);
				(void)callTMres(handler, top - 2, top - 1, state);
				*reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + resultOffset) = *state->top;
			} else if (static_cast<TString*>(top[-1].value.p)->len > 0u) {
				// Two strings at least. Reach back over as many more as are
				// convertible so the whole run costs one allocation.
				size_t joinedLength = static_cast<TString*>(top[-1].value.p)->len
					+ static_cast<TString*>(top[-2].value.p)->len;

				while (handled < total && CoerceToStringInPlace(state, top - handled - 1)) {
					joinedLength += static_cast<TString*>(top[-handled - 1].value.p)->len;
					++handled;
				}

				if (joinedLength > kMaxStringSize) {
					luaG_runerror(state, "string size overflow");
				}

				char* const buffer = luaZ_openspace(state, &state->l_G->buff, joinedLength);

				size_t written = 0;
				for (int index = handled; index > 0; --index) {
					const TString* const piece = static_cast<TString*>(top[-index].value.p);
					std::memcpy(buffer + written, piece->str, piece->len);
					written += piece->len;
				}

				TString* const joined = luaS_newlstr(state, buffer, written);
				top[-handled].tt = static_cast<int>(joined->tt);
				top[-handled].value.p = joined;
			}

			total -= handled - 1;
			last -= handled - 1;
		} while (total > 1);
	}
	// -----------------------------------------------------------------------
	// lvm.c - the interpreter loop.
	// -----------------------------------------------------------------------

	// Instruction field positions. The operand range limits and MAXSTACK
	// already sit above with the symbolic executor's tables; only the field
	// offsets are new here.
	constexpr int kLuaSizeOp = 6;
	constexpr int kLuaSizeC = 9;
	constexpr int kLuaSizeB = 9;
	constexpr int kLuaPosC = kLuaSizeOp;
	constexpr int kLuaPosBx = kLuaPosC;
	constexpr int kLuaPosB = kLuaPosC + kLuaSizeC;
	constexpr int kLuaPosA = kLuaPosB + kLuaSizeB;



	// Opcodes. Stock Lua 5.0.2 with this fork's four extra bit operators
	// spliced in after OP_DIV, which shifts everything from there up by four.
	enum LuaOpcode : int
	{
		kOpMove = 0, kOpLoadK, kOpLoadBool, kOpLoadNil, kOpGetUpval,
		kOpGetGlobal, kOpGetTable, kOpSetGlobal, kOpSetUpval, kOpSetTable,
		kOpNewTable, kOpSelf,
		kOpAdd, kOpSub, kOpMul, kOpDiv,
		kOpBAnd, kOpBOr, kOpBShl, kOpBShr, kOpBXor,
		kOpUnm, kOpNot, kOpConcat,
		kOpJmp, kOpEq, kOpLt, kOpLe, kOpTest,
		kOpCall, kOpTailCall, kOpReturn,
		kOpForLoop, kOpTForLoop, kOpTForPrep,
		kOpSetList, kOpSetListO, kOpClose, kOpClosure
	};

	// Tag-method slots. This fork has no TM_MODE and adds one per bit
	// operator, so TM_EQ lands at 3 and the arithmetic block runs 4..13 -
	// which is what global_State::tmname[18] is sized for.
	enum LuaTagMethod : int
	{
		kTmIndex = 0, kTmNewIndex, kTmGc, kTmEq,
		kTmAdd, kTmSub, kTmMul, kTmDiv,
		kTmBAnd, kTmBOr, kTmBShl, kTmBShr, kTmBXor,
		kTmUnm, kTmLt, kTmLe, kTmConcat, kTmCall
	};

	// CallInfo::state. Not the bit flags stock Lua uses - this fork stores a
	// small enumeration, read back from how luaV_execute and luaD_precall
	// write it.
	constexpr int kFrameRunning = 0;   // a Lua frame executing here
	constexpr int kFrameCalling = 1;   // its callee's frame sits on top
	constexpr int kFrameSuspended = 2; // unwind out to the C caller

	// Hook masks and event codes.
	constexpr int kHookMaskCall = 1;
	constexpr int kHookMaskLine = 4;
	constexpr int kHookMaskCount = 8;
	constexpr int kHookEventCall = 0;
	constexpr int kHookEventLine = 2;
	constexpr int kHookEventCount = 3;

	[[nodiscard]] static constexpr int LuaGetOpcode(const Instruction i) noexcept
	{
		return static_cast<int>(i & ((1u << kLuaSizeOp) - 1u));
	}

	[[nodiscard]] static constexpr int LuaGetArgA(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosA) & 0xFFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgB(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosB) & 0x1FFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgC(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosC) & 0x1FFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgBx(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosBx) & kLuaMaxArgBx);
	}

	[[nodiscard]] static constexpr int LuaGetArgSBx(const Instruction i) noexcept
	{
		return LuaGetArgBx(i) - kLuaMaxArgSBx;
	}

	[[nodiscard]] static constexpr bool LuaIsFalse(const TObject* const o) noexcept
	{
		return o->tt == LUA_TNIL || (o->tt == LUA_TBOOLEAN && o->value.b == 0);
	}

	// The bit operators work on the 32-bit truncation of their operands and
	// hand the result back as a number. A negative result is re-read as
	// unsigned first, so `-1 >> 0` is 4294967295 rather than -1 - the binary
	// adds 2^32 (the constant at 0x00E4F710) whenever the sign bit is set.
	[[nodiscard]] static inline float LuaBitwiseResult(const std::int32_t value) noexcept
	{
		float result = static_cast<float>(value);
		if (value < 0) {
			result += 4294967296.0f;
		}
		return result;
	}

	[[nodiscard]] static inline std::int32_t LuaToBitwiseOperand(const float value) noexcept
	{
		return static_cast<std::int32_t>(value);
	}

	/**
	 * Address: 0x00929C60 (FUN_00929C60, luaV_execute)
	 *
	 * IDA signature:
	 * TObject *__cdecl luaV_execute(lua_State *L);
	 *
	 * What it does:
	 * Runs Lua bytecode. Returns the first result of the frame that finished
	 * when control has to go back to whatever C code called in, or null when the
	 * interpreter was unwound by a yield.
	 *
	 * The loop is entered twice over: `callentry` for a fresh call, which fires
	 * the call hook first, and `retentry` for resuming a caller whose callee has
	 * just returned. A Lua-to-Lua call therefore never recurses into this
	 * function - OP_CALL jumps back to the top with the new frame in place, and
	 * OP_RETURN jumps back with the old one restored.
	 */
	TObject* luaV_execute(lua_State* L)
	{
		global_State* const G = L->l_G;
		lua_State* const previousActiveThread = G->lstate;

		// The binary restores `lstate` at each of its returns (FUN_00929C60
		// saves it at +0x44 on entry and writes it back before every exit). It
		// has no way to restore on the error path because errors there are a
		// longjmp; ours are C++ exceptions, and an unwind past this frame would
		// leave `lstate` pointing at the thread that raised - typically a
		// coroutine, whose `stateUserData` is null by construction
		// (`luaE_newthread`). Every later `LuaObject::GetActiveState()` then
		// hands back null, and the first UI event to build a Lua event table
		// dies on it. A guard keeps the binary's intent on all exits.
		struct ActiveThreadGuard
		{
			global_State* g;
			lua_State* previous;
			~ActiveThreadGuard() { g->lstate = previous; }
		} const activeThreadGuard{G, previousActiveThread};

		G->lstate = L;

		LClosure* cl = nullptr;
		const Instruction* pc = nullptr;
		TObject* k = nullptr;
		int oldline = -1;

	callentry: // a fresh call: the call hook sees it before the first instruction
		if ((G->hookmask & kHookMaskCall) != 0) {
			luaD_callhook(L, kHookEventCall, -1);
		}

	retentry: // resuming: the frame is already set up
		cl = &static_cast<GCObject*>(L->base[-1].value.p)->cl.l;
		pc = L->ci->savedpc;
		k = cl->p->k;
		oldline = -1;

		for (;;) {
			const Instruction i = *pc++;

			if ((G->hookmask & (kHookMaskLine | kHookMaskCount)) != 0) {
				--G->hookcount;
				if (G->hookcount == 0 || (G->hookmask & kHookMaskLine) != 0) {
					L->ci->savedpc = pc - 1;

					if ((G->hookmask & kHookMaskCount) != 0 && G->hookcount == 0) {
						G->hookcount = G->basehookcount;
						luaD_callhook(L, kHookEventCount, -1);
					} else if ((G->hookmask & kHookMaskLine) != 0) {
						// Only report a line once, however many instructions it
						// covers.
						const CallInfo* const ci = L->ci;
						const Proto* const p = static_cast<GCObject*>(ci->base[-1].value.p)->cl.l.p;
						const int line = (p->lineinfo != nullptr)
							? p->lineinfo[ci->savedpc - p->code]
							: 0;
						if (line != oldline) {
							oldline = line;
							luaD_callhook(L, kHookEventLine, line);
						}
					}

					if (L->ci->state == kFrameSuspended) { // did the hook yield?
						G->lstate = previousActiveThread;
						return nullptr;
					}
				}
			}

			StkId const base = L->base;
			StkId const ra = base + LuaGetArgA(i);

			// Operand accessors. RKB/RKC pick a constant instead of a register
			// once the index passes MAXSTACK.
			const auto rb = [&]() -> StkId { return base + LuaGetArgB(i); };
			const auto rkb = [&]() -> TObject* {
				const int index = LuaGetArgB(i);
				return (index >= kLuaMaxStack) ? &k[index - kLuaMaxStack] : &base[index];
			};
			const auto rkc = [&]() -> TObject* {
				const int index = LuaGetArgC(i);
				return (index >= kLuaMaxStack) ? &k[index - kLuaMaxStack] : &base[index];
			};

			switch (LuaGetOpcode(i)) {
			case kOpMove:
				*ra = *rb();
				break;

			case kOpLoadK:
				*ra = k[LuaGetArgBx(i)];
				break;

			case kOpLoadBool:
				ra->value.b = LuaGetArgB(i);
				ra->tt = LUA_TBOOLEAN;
				if (LuaGetArgC(i) != 0) {
					++pc; // C says skip the next instruction
				}
				break;

			case kOpLoadNil: {
				StkId slot = rb();
				do {
					slot->tt = LUA_TNIL;
					--slot;
				} while (slot >= ra);
				break;
			}

			case kOpGetUpval:
				*ra = *cl->upvals[LuaGetArgB(i)]->v;
				break;

			case kOpGetGlobal: {
				const TObject* const key = &k[LuaGetArgBx(i)];
				const TObject* value = luaH_getstr(
					static_cast<Table*>(cl->g.value.p),
					static_cast<TString*>(key->value.p)
				);
				if (value->tt == LUA_TNIL) {
					value = luaV_index(L, &cl->g, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpGetTable: {
				StkId const table = rb();
				const TObject* const key = rkc();
				const TObject* value = nullptr;
				if (table->tt == LUA_TTABLE) {
					value = luaH_get(static_cast<Table*>(table->value.p), key);
					if (value->tt == LUA_TNIL) {
						value = luaV_index(L, table, key, 0);
					}
				} else {
					value = luaV_getnotable(L, table, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpSetGlobal:
				luaV_settable(L, &cl->g, &k[LuaGetArgBx(i)], ra);
				break;

			case kOpSetUpval:
				*cl->upvals[LuaGetArgB(i)]->v = *ra;
				break;

			case kOpSetTable:
				luaV_settable(L, ra, rkb(), rkc());
				break;

			case kOpNewTable: {
				// B is a floating byte: three mantissa bits and an exponent, as
				// packed by luaO_int2fb.
				const int sizeHint = LuaGetArgB(i);
				Table* const table = luaH_new(L, (sizeHint & 7) << (sizeHint >> 3), LuaGetArgC(i));
				ra->tt = static_cast<int>(table->tt);
				ra->value.p = table;
				luaC_checkGC(L);
				break;
			}

			case kOpSelf: {
				StkId const object = rb();
				const TObject* const key = rkc();
				if (key->tt != LUA_TSTRING) {
					// The code generator only ever emits OP_SELF with a string
					// key; a chunk that says otherwise is not one this
					// interpreter can run.
					G->lstate = previousActiveThread;
					return nullptr;
				}

				ra[1] = *object;
				const TObject* value = nullptr;
				if (object->tt == LUA_TTABLE) {
					value = luaH_getstr(
						static_cast<Table*>(object->value.p),
						static_cast<TString*>(key->value.p)
					);
					if (value->tt != LUA_TNIL) {
						*ra = *value;
						break;
					}
					value = luaV_index(L, object, key, 0);
				} else {
					value = luaV_getnotable(L, object, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpAdd: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = c->value.n + b->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					// Note there is no string coercion here: unlike stock Lua,
					// this fork goes straight to the tag method.
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmAdd, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpSub: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = b->value.n - c->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmSub, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpMul: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = c->value.n * b->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmMul, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpDiv: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = b->value.n / c->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmDiv, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpBAnd:
			case kOpBOr:
			case kOpBShl:
			case kOpBShr:
			case kOpBXor: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					const std::int32_t left = LuaToBitwiseOperand(b->value.n);
					const std::int32_t right = LuaToBitwiseOperand(c->value.n);
					std::int32_t result = 0;
					switch (LuaGetOpcode(i)) {
					case kOpBAnd: result = left & right; break;
					case kOpBOr:  result = left | right; break;
					case kOpBShl: result = left << right; break;
					case kOpBShr: result = static_cast<std::int32_t>(
						static_cast<std::uint32_t>(left) >> right); break;
					default:      result = left ^ right; break; // kOpBXor
					}
					ra->value.n = LuaBitwiseResult(result);
					ra->tt = LUA_TNUMBER;
				} else {
					const int event = kTmBAnd + (LuaGetOpcode(i) - kOpBAnd);
					(void)CallBinTmOrRaiseArithmeticTypeError(
						event, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpUnm: {
				const TObject* operand = rb();
				TObject coerced{};
				if (operand->tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (operand->tt == LUA_TSTRING
						&& luaO_str2d(static_cast<const TString*>(operand->value.p)->str, &parsed) != 0) {
						// Unary minus is the one arithmetic operator here that
						// still coerces a numeric string.
						coerced.value.n = parsed;
						coerced.tt = LUA_TNUMBER;
						operand = &coerced;
					} else {
						TObject secondOperand{};
						secondOperand.tt = LUA_TNIL;
						(void)CallBinTmOrRaiseArithmeticTypeError(
							kTmUnm, const_cast<TObject*>(operand), L, &secondOperand, ra);
						break;
					}
				}
				ra->value.n = -0.0f - operand->value.n;
				ra->tt = LUA_TNUMBER;
				break;
			}

			case kOpNot:
				ra->value.b = LuaIsFalse(rb()) ? 1 : 0;
				ra->tt = LUA_TBOOLEAN;
				break;

			case kOpConcat: {
				const int b = LuaGetArgB(i);
				const int c = LuaGetArgC(i);
				luaV_concat(L, c - b + 1, c); // may change the stack
				*(L->base + LuaGetArgA(i)) = *(L->base + b);
				luaC_checkGC(L);
				break;
			}

			case kOpJmp:
				pc += LuaGetArgSBx(i);
				break;

			case kOpEq: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				int equal = 0;
				if (b->tt == c->tt) {
					equal = luaV_equalval(L, rkb(), rkc()) ? 1 : 0;
				}
				if (equal == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc; // skip the jump that follows
				}
				break;
			}

			case kOpLt:
				if (luaV_lessthan(L, rkb(), rkc()) == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc;
				}
				break;

			case kOpLe:
				if (luaV_lessequal(L, rkb(), rkc()) == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc;
				}
				break;

			case kOpTest: {
				StkId const value = rb();
				if ((LuaIsFalse(value) ? 1 : 0) == LuaGetArgC(i)) {
					++pc;
				} else {
					*ra = *value;
					pc += LuaGetArgSBx(*pc) + 1;
				}
				break;
			}

			case kOpCall:
			case kOpTailCall: {
				if (LuaGetArgB(i) != 0) {
					L->top = ra + LuaGetArgB(i);
				}
				const int nresults = LuaGetArgC(i) - 1;

				StkId const firstResult = luaD_precall(L, ra);
				if (firstResult == nullptr) { // a Lua function: run it here
					if (LuaGetOpcode(i) == kOpCall) {
						L->ci[-1].state = kFrameCalling;
						L->ci[-1].savedpc = pc - 1; // points at this OP_CALL
					} else {
						// Tail call: slide the new frame down over the caller's,
						// so the two share one stack level.
						StkId const callerBase = L->ci[-1].base;
						StkId const source = callerBase + LuaGetArgA(i);
						if (L->openupval != nullptr) {
							luaF_close(L, callerBase);
						}

						int moved = 0;
						while (source + moved < L->top) {
							callerBase[moved - 1] = source[moved];
							++moved;
						}

						L->top = callerBase + moved;
						L->ci[-1].top = L->top;
						L->ci[-1].savedpc = L->ci->savedpc;
						++L->ci[-1].tailcalls; // one more call lost to the trace
						--L->ci;
						L->base = L->ci->base;
					}
					goto callentry;
				}

				if (firstResult > L->top) { // the C function yielded
					L->ci[-1].state = kFrameSuspended;
					L->ci[-1].savedpc = pc;
					G->lstate = previousActiveThread;
					return nullptr;
				}

				luaD_poscall(L, nresults, firstResult);
				if (nresults >= 0) {
					L->top = L->ci->top;
				}
				break;
			}

			case kOpReturn: {
				CallInfo* const caller = &L->ci[-1];
				const int b = LuaGetArgB(i);
				if (b != 0) {
					L->top = ra + b - 1;
				}
				if (L->openupval != nullptr) {
					luaF_close(L, base);
				}
				L->ci->savedpc = pc;

				if (caller->state != kFrameCalling) {
					// Whoever called in was C code, so hand the results back.
					G->lstate = previousActiveThread;
					return ra;
				}

				// The caller is Lua and is waiting at its OP_CALL: finish the
				// call and resume it without leaving this function.
				const int nresults = LuaGetArgC(*caller->savedpc) - 1;
				luaD_poscall(L, nresults, ra);
				if (nresults >= 0) {
					L->top = L->ci->top;
				}
				L->ci->state = kFrameRunning;
				++L->ci->savedpc; // step past the OP_CALL
				goto retentry;
			}

			case kOpForLoop: {
				if (ra->tt != LUA_TNUMBER) {
					luaG_runerror(L, "`for' initial value must be a number");
				}
				if (ra[1].tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (ra[1].tt != LUA_TSTRING
						|| luaO_str2d(static_cast<const TString*>(ra[1].value.p)->str, &parsed) == 0) {
						luaG_runerror(L, "`for' limit must be a number");
					}
					ra[1].value.n = parsed;
					ra[1].tt = LUA_TNUMBER;
				}
				if (ra[2].tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (ra[2].tt != LUA_TSTRING
						|| luaO_str2d(static_cast<const TString*>(ra[2].value.p)->str, &parsed) == 0) {
						luaG_runerror(L, "`for' step must be a number");
					}
					ra[2].value.n = parsed;
					ra[2].tt = LUA_TNUMBER;
				}

				const float step = ra[2].value.n;
				const float limit = ra[1].value.n;
				const float index = ra->value.n + step;
				if ((step > 0.0f) ? (index <= limit) : (index >= limit)) {
					pc += LuaGetArgSBx(i); // jump back to the body
					ra->value.n = index;
				}
				break;
			}

			case kOpTForLoop: {
				const int nvar = LuaGetArgC(i) + 1;
				StkId callBase = ra + nvar + 2;
				callBase[0] = ra[0];
				callBase[1] = ra[1];
				callBase[2] = ra[2];
				L->top = callBase + 3; // iterator + state + control
				(void)luaD_call(L, callBase, nvar);

				L->top = L->ci->top;
				// the call may have moved the stack, so find the slots again
				callBase = L->base + LuaGetArgA(i) + 2;
				for (int slot = nvar - 1; slot >= 0; --slot) {
					callBase[slot] = callBase[slot + nvar];
				}

				if (callBase->tt != LUA_TNIL) {
					pc += LuaGetArgSBx(*pc) + 1; // go round again
				} else {
					++pc; // control variable is nil: leave the loop
				}
				break;
			}

			case kOpTForPrep: {
				if (ra->tt == LUA_TTABLE) {
					// `for x in t' is shorthand for `for x in next, t'.
					ra[1].tt = LUA_TTABLE;
					ra[1].value.p = ra->value.p;
					TString* const nextName = luaS_newlstr(L, "next", 4u);
					*ra = *luaH_getstr(static_cast<Table*>(L->_gt.value.p), nextName);
				} else if (!IsCallableTag(ra->tt)) {
					L->ci->savedpc = pc - 1;
					luaG_typeerror(L, ra, "loop over");
				}
				pc += LuaGetArgSBx(i);
				break;
			}

			case kOpSetList:
			case kOpSetListO: {
				if (ra->tt != LUA_TTABLE) {
					// Only a table constructor emits these, so a chunk that
					// reaches here with anything else is not runnable.
					G->lstate = previousActiveThread;
					return nullptr;
				}

				Table* const table = static_cast<Table*>(ra->value.p);
				const int bc = LuaGetArgBx(i);
				int n = 0;
				if (LuaGetOpcode(i) == kOpSetList) {
					n = (bc & static_cast<int>(kLuaFieldsPerFlushM1)) + 1;
				} else {
					n = static_cast<int>(L->top - ra) - 1; // the open call's results
					L->top = L->ci->top;
				}

				const int batchBase = bc & ~static_cast<int>(kLuaFieldsPerFlushM1);
				for (; n > 0; --n) {
					*luaH_setnum(L, table, batchBase + n) = ra[n];
				}
				break;
			}

			case kOpClose:
				luaF_close(L, ra);
				break;

			case kOpClosure: {
				Proto* const proto = cl->p->p[LuaGetArgBx(i)];
				const int nups = proto->nups;
				Closure* const closure = luaF_newLclosure(L, nups, &cl->g);
				closure->l.p = proto;

				// Each upvalue is described by one pseudo-instruction following
				// the OP_CLOSURE: either GETUPVAL to share the enclosing
				// closure's, or MOVE to capture a local.
				for (int up = 0; up < nups; ++up, ++pc) {
					const int index = LuaGetArgB(*pc);
					closure->l.upvals[up] = (LuaGetOpcode(*pc) == kOpGetUpval)
						? cl->upvals[index]
						: luaF_findupval(L, base + index);
				}

				ra->tt = static_cast<int>(closure->l.tt);
				ra->value.p = closure;
				luaC_checkGC(L);
				break;
			}

			default:
				break;
			}

			L->ci->savedpc = pc;
		}
	}


	/**
	 * Address: 0x0091A690 (FUN_0091A690, luaO_pushvfstring)
	 *
	 * IDA signature:
	 * const char *__cdecl luaO_pushvfstring(lua_State *L, const char *fmt, va_list argp);
	 *
	 * What it does:
	 * Formats a message onto the Lua stack. Each literal run and each
	 * conversion is pushed as its own value and the lot is concatenated at the
	 * end, which is how the result becomes a collectable Lua string rather
	 * than something the caller has to free. Only %%, %c, %d, %f and %s are
	 * understood - anything else is dropped, as in the binary.
	 */
	void luaG_errormsg(lua_State* L);

	const char* luaO_pushvfstring(lua_State* const state, const char* fmt, va_list argp)
	{
		int pushed = 1;
		pushstr(state, "");

		const char* conversion = std::strchr(fmt, '%');
		while (conversion != nullptr) {
			TString* const literal = luaS_newlstr(state, fmt, static_cast<size_t>(conversion - fmt));
			TObject* top = state->top;
			top->tt = static_cast<int>(literal->tt);
			top->value.p = literal;
			api_incr_top(state);

			top = state->top;
			switch (conversion[1]) {
				case '%':
					pushstr(state, "%");
					break;
				case 'c': {
					char one[2];
					one[0] = static_cast<char>(va_arg(argp, int));
					one[1] = '\0';
					pushstr(state, one);
					break;
				}
				case 'd':
					top->value.n = static_cast<float>(va_arg(argp, int));
					top->tt = LUA_TNUMBER;
					api_incr_top(state);
					break;
				case 'f':
					top->value.n = static_cast<float>(va_arg(argp, double));
					top->tt = LUA_TNUMBER;
					api_incr_top(state);
					break;
				case 's':
					pushstr(state, va_arg(argp, const char*));
					break;
				default:
					break;
			}

			pushed += 2;
			fmt = conversion + 2;
			conversion = std::strchr(fmt, '%');
		}

		pushstr(state, fmt);
		luaV_concat(state, pushed + 1, static_cast<int>(state->top - state->base) - 1);
		state->top -= pushed;
		return static_cast<TString*>(state->top[-1].value.p)->str;
	}

	/**
	 * Address: 0x00913270 (FUN_00913270, luaG_runerror)
	 *
	 * IDA signature:
	 * void __cdecl luaG_runerror(lua_State *L, const char *fmt, ...);
	 *
	 * What it does:
	 * Raises a runtime error: formats the message onto the stack, tags it with
	 * the chunk and line it came from, and hands it to the error machinery.
	 * Never returns.
	 */
	void luaG_runerror(lua_State* const state, const char* const format, ...)
	{
		va_list arguments;
		va_start(arguments, format);
		const char* const message = luaO_pushvfstring(state, format, arguments);
		va_end(arguments);

		addinfo(state, message);
		luaG_errormsg(state);
	}

	/**
	 * Address: 0x0091A510 (FUN_0091A510, luaO_log2)
	 *
	 * IDA signature:
	 * int __cdecl luaO_log2(unsigned int x);
	 *
	 * What it does:
	 * Returns floor(log2(x)), or -1 for zero. Works a byte at a time off a
	 * 256-entry lookup table, so the answer costs one table read plus a
	 * constant.
	 */
	int luaO_log2(const unsigned int x)
	{
		// The binary carries this as 256 literal bytes at 0x00D46407; every
		// entry from 1 up is floor(log2(i)), which is cheaper to state than to
		// transcribe. Entry 0 is 0 there and unreachable here either way.
		static constexpr auto kLog2Byte = [] {
			std::array<unsigned char, 256> table{};
			for (unsigned int i = 2; i < 256; ++i) {
				table[i] = static_cast<unsigned char>(table[i / 2] + 1);
			}
			return table;
		}();

		if (x >= 0x10000u) {
			return (x >= 0x1000000u)
				? kLog2Byte[x >> 24] + 24
				: kLog2Byte[(x >> 16) & 0xFFu] + 16;
		}
		if (x >= 0x100u) {
			return kLog2Byte[(x >> 8) & 0xFFu] + 8;
		}
		return (x != 0u) ? kLog2Byte[x] : -1;
	}

	/**
	 * Address: 0x0091A5D0 (FUN_0091A5D0, luaO_str2d)
	 *
	 * IDA signature:
	 * int __usercall luaO_str2d@<eax>(const char *s, Number *result);
	 *
	 * What it does:
	 * Converts a numeric literal, accepting it only when the whole string is
	 * consumed apart from trailing space. Returns 0 on anything else, which is
	 * what makes `tonumber("1x")` nil.
	 */
	int luaO_str2d(const char* const s, float* const result)
	{
		char* end = nullptr;
		const float value = static_cast<float>(std::strtod(s, &end));
		if (end == s) {
			return 0; // nothing converted
		}

		while (std::isspace(static_cast<unsigned char>(*end)) != 0) {
			++end; // trailing space is fine
		}
		if (*end != '\0') {
			return 0; // but nothing else is
		}

		*result = value;
		return 1;
	}

	/**
	 * Address: 0x0091A4E0 (FUN_0091A4E0, luaO_int2fb)
	 *
	 * IDA signature:
	 * unsigned int __cdecl luaO_int2fb(unsigned int x);
	 *
	 * What it does:
	 * Packs a size into Lua's "floating byte" form - three mantissa bits and an
	 * exponent - so that a table's array-part hint fits one instruction field.
	 * Values under 8 pass through unchanged.
	 */
	unsigned int luaO_int2fb(const unsigned int x)
	{
		unsigned int mantissa = x;
		int exponent = 0;
		while (mantissa >= 8u) {
			mantissa = (mantissa + 1u) >> 1;
			++exponent;
		}
		return mantissa | (static_cast<unsigned int>(exponent) << 3);
	}

	/**
	 * Address: 0x0091A8F0 (FUN_0091A8F0, luaO_chunkid)
	 *
	 * IDA signature:
	 * void __cdecl luaO_chunkid(char *out, const char *source, int bufflen);
	 *
	 * What it does:
	 * Renders a chunk name for an error message, in the three forms Lua's
	 * loader tags sources with. `=name` is used verbatim, `@file` is a file
	 * path shown from the tail with a leading ellipsis when it does not fit,
	 * and anything else is source text quoted as `[string "..."]`, truncated
	 * at the first newline or at the buffer limit.
	 */
	void luaO_chunkid(char* const out, const char* const source, const int bufflen)
	{
		if (*source == '=') {
			std::strncpy(out, source + 1, static_cast<size_t>(bufflen));
			out[bufflen - 1] = '\0';
			return;
		}

		if (*source == '@') {
			// File name: keep the tail, which is the part that identifies it.
			constexpr int kEllipsisReserve = 8;

			const char* path = source + 1;
			const int length = static_cast<int>(std::strlen(path));
			*out = '\0';

			if (length > bufflen - kEllipsisReserve) {
				path += length - (bufflen - kEllipsisReserve);
				std::strcat(out, "...");
			}

			std::strcat(out, path);
			return;
		}

		// Source text: show the first line, quoted.
		constexpr int kQuotingReserve = 17;

		int length = static_cast<int>(std::strcspn(source, "\n"));
		if (length > bufflen - kQuotingReserve) {
			length = bufflen - kQuotingReserve;
		}

		std::strcpy(out, "[string \"");
		if (source[length] != '\0') {
			std::strncat(out, source, static_cast<size_t>(length));
			std::strcat(out, "...");
		} else {
			std::strcat(out, source);
		}

		std::strcat(out, "\"]");
	}

	/**
	 * Address: 0x00912F30 (FUN_00912F30, addinfo)
	 *
	 * IDA signature:
	 * const char *__usercall addinfo(lua_State *L@<edi>, const char *msg);
	 *
	 * What it does:
	 * Prefixes an error message with the chunk name and line it came from,
	 * turning "attempt to call a nil value" into
	 * "script.lua(42): attempt to call a nil value". Only frames still running
	 * Lua bytecode carry that position, so a C frame is left unannotated.
	 */
	[[maybe_unused]] static void addinfo(lua_State* const state, const char* const msg)
	{
		constexpr int kChunkIdBufferSize = 60;
		constexpr int kCallInfoStateRunningLua = 3;

		CallInfo* const ci = state->ci;
		if (ci->state >= kCallInfoStateRunningLua) {
			return;
		}

		const Proto* const proto = static_cast<GCObject*>(ci->base[-1].value.p)->cl.l.p;
		const ptrdiff_t pc = ci->savedpc - proto->code;

		int line = -1;
		if (pc >= 0) {
			line = (proto->lineinfo != nullptr) ? proto->lineinfo[pc] : 0;
		}

		char chunkId[kChunkIdBufferSize];
		luaO_chunkid(chunkId, proto->source->str, kChunkIdBufferSize);
		(void)luaO_pushfstring(state, "%s(%d): %s", chunkId, line, msg);
	}

	/**
	 * Address: 0x0090D430 (FUN_0090D430, lua_call)
	 *
	 * IDA signature:
	 * int __cdecl lua_call(lua_State *L, int nargs, int nresults);
	 *
	 * What it does:
	 * Calls the function sitting `nargs` slots below the top, leaving
	 * `nresults` values in its place, and reports whether it got there: 0 on
	 * success, the raised lua::lua_Error's own code otherwise, or LUA_ERRRUN
	 * for anything else that escapes.
	 *
	 * This is the fork's only protected-call entry point - it has no
	 * lua_pcall, no luaD_pcall and no luaD_rawrunprotected, because the C++
	 * exceptions it raises need a try rather than a setjmp. The body is one EH
	 * region around luaD_call with two handlers, at 0x0090D48D (reads `code`
	 * from the error at +0x28 and returns it) and 0x0090D4B0 (returns 1).
	 *
	 * It used to be recovered as a void passthrough on the assumption that
	 * "lua_pcall catches them", so callers reached for the prebuilt LuaPlus
	 * lua_pcall instead - which walks this state at stock offsets, writes an
	 * errfunc field past the end of our 0x48-byte lua_State, and cannot catch a
	 * C++ throw through its setjmp anyway. A script error consequently unwound
	 * past every protected boundary and out of WinMain.
	 */
	int LuaCallProtected(lua_State* const state, const int nargs, const int nresults)
	{
		StkId const func = state->top - (nargs + 1);
		try {
			(void)luaD_call(state, func, nresults);
		} catch (const lua::lua_Error& error) {
			return error.code;
		} catch (...) {
			return LUA_ERRRUN;
		}
		return 0;
	}

	/**
	 * Address: 0x0090D400 (FUN_0090D400, lua_call)
	 * Mangled: ?lua_call@@YAXPAUlua_State@@HH@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_call(lua_State *L, int nargs, int nresults);
	 *
	 * What it does:
	 * Calls with no handler, so an error unwinds to the caller's own protected
	 * boundary instead of being turned into a status nobody reads.
	 */
	void LuaCallUnprotected(lua_State* const state, const int nargs, const int nresults)
	{
		(void)luaD_call(state, state->top - (nargs + 1), nresults);
	}

	/**
	 * Address: 0x00913C30 (FUN_00913C30, tryFuncTM)
	 *
	 * IDA signature:
	 * StkId __usercall tryFuncTM(TObject *func@<eax>, lua_State *L@<esi>);
	 *
	 * What it does:
	 * Handles a call on something that is not a function. The value's `__call`
	 * tag method becomes the callee and the original value is shifted up to
	 * become its first argument, so `t(x)` turns into `mt.__call(t, x)`.
	 */
	static StkId tryFuncTM(StkId func, lua_State* const state)
	{
		constexpr int kTagMethodCall = 17;

		const TObject* const handler = luaT_gettmbyobj(state, func, kTagMethodCall);
		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		if (!IsCallableTag(handler->tt)) {
			luaG_typeerror(state, func, "call");
		}

		// Open a slot at `func` by sliding everything above it up one.
		for (StkId slot = state->top; slot > func; --slot) {
			slot[0] = slot[-1];
		}

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;

		StkId const target = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset);
		target->tt = handler->tt;
		target->value.p = handler->value.p;
		return target;
	}

	/**
	 * Address: 0x00913D40 (FUN_00913D40, luaD_poscall)
	 *
	 * IDA signature:
	 * void __cdecl luaD_poscall(lua_State *L, int wanted, StkId firstResult);
	 *
	 * What it does:
	 * Tears the finished frame down: pops the CallInfo, restores `base`, then
	 * slides the results down over the callee and its arguments, padding with
	 * nil when fewer were produced than the caller asked for.
	 */
	void luaD_poscall(lua_State* const state, int wanted, StkId firstResult)
	{
		constexpr lu_byte kHookMaskReturn = 1 << 1;

		if ((state->l_G->hookmask & kHookMaskReturn) != 0) {
			firstResult = callrethooks(firstResult, state);
		}

		--state->ci;
		StkId result = state->base - 1;
		state->base = state->ci->base;

		for (; wanted != 0 && firstResult < state->top; --wanted) {
			*result++ = *firstResult++;
		}

		for (; wanted > 0; --wanted) {
			(result++)->tt = LUA_TNIL;
		}

		state->top = result;
	}

	/**
	 * Address: 0x009142A0 (FUN_009142A0, luaD_precall)
	 *
	 * IDA signature:
	 * StkId __cdecl luaD_precall(lua_State *L, StkId func);
	 *
	 * What it does:
	 * Opens a call frame. A Lua closure gets its stack reserved and returns
	 * null, telling the caller to run the interpreter; a C closure is invoked
	 * here and its first result returned. Anything else is routed through
	 * `__call` first.
	 */
	StkId luaD_precall(lua_State* const state, StkId func)
	{
		constexpr int kMinCStackSlots = 20;
		constexpr lu_byte kHookMaskCall = 1 << 0;

		// This fork's CallInfo::state is a small enum, not stock Lua's bitmask:
		// 0 is a Lua frame running here, 1 is a frame whose callee sits on top,
		// 2 is one unwinding out to its C caller, and 3 is a C function's own
		// frame - `mov dword ptr [eax+8], 3` at 0x009143D3.
		//
		// Writing 1 here instead marked every C frame "calling", so when a
		// chunk invoked from C returned, OP_RETURN took the resume path and
		// dereferenced the null savedpc that belongs to a C frame. Any script
		// loaded through dofile faulted the moment it finished.
		constexpr int kFrameCFunction = 3;

		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		if (!IsCallableTag(func->tt)) {
			func = tryFuncTM(func, state);
		}

		if (&state->ci[1] == state->end_ci) {
			luaD_growCI(state);
		}

		if (func->tt == LUA_TFUNCTION) {
			// Lua closure: reserve its registers and hand back to the caller,
			// which runs luaV_execute over the frame we just opened.
			Proto* const proto = static_cast<GCObject*>(func->value.p)->cl.l.p;

			if (proto->is_vararg != 0) {
				adjust_varargs(state, proto->numparams, func + 1);
			}

			if (state->stack_last - state->top <= proto->maxstacksize) {
				luaD_growstack(state, proto->maxstacksize);
			}

			CallInfo* const ci = ++state->ci;
			ci->base = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset) + 1;
			state->base = ci->base;
			ci->top = state->base + proto->maxstacksize;
			ci->savedpc = proto->code;
			ci->tailcalls = 0;
			ci->state = 0;
			ci->pc = nullptr;
			ci->reserved0 = 0;
			ci->reserved1 = 0;
			ci->reserved2 = 0;

			for (; state->top < ci->top; ++state->top) {
				state->top->tt = LUA_TNIL;
			}

			state->top = ci->top;
			// Per-proto invocation counter at Proto+0x68 (reserved8). The binary
			// bumps only the low dword - "add dword ptr [edi+68h], 1" with no
			// carry - so this is a 32-bit increment, not a 64-bit one.
			reinterpret_cast<std::uint32_t&>(proto->reserved8) += 1u;
			return nullptr;
		}

		if (state->stack_last - state->top <= kMinCStackSlots) {
			luaD_growstack(state, kMinCStackSlots);
		}

		CallInfo* const ci = ++state->ci;
		ci->base = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset) + 1;
		state->base = ci->base;
		ci->top = state->top + kMinCStackSlots;
		ci->state = kFrameCFunction;
		ci->savedpc = nullptr;
		ci->tailcalls = 0;
		ci->pc = nullptr;
		ci->reserved0 = 0;
		ci->reserved1 = 0;
		ci->reserved2 = 0;

		if ((state->l_G->hookmask & kHookMaskCall) != 0) {
			luaD_callhook(state, LUA_HOOKCALL, -1);
		}

		Closure* const closure = static_cast<Closure*>(state->base[-1].value.p);

		// The two words at upvalue_m1[0] are one 64-bit invocation counter this
		// fork keeps per C closure - the binary increments the low half and
		// carries into the high half.
		std::uint32_t& invocationsLow = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].tt);
		std::uint32_t& invocationsHigh = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].value.b);
		const std::uint32_t previousLow = invocationsLow++;
		if (invocationsLow < previousLow) {
			++invocationsHigh;
		}

		const int produced = closure->c.f(state);
		return state->top - produced;
	}

	/**
	 * Address: 0x00914430 (FUN_00914430, luaD_call)
	 *
	 * IDA signature:
	 * void __cdecl luaD_call(lua_State *L, StkId func, int nResults);
	 *
	 * What it does:
	 * Calls `func` and leaves `nResults` values behind it. Guards the C stack
	 * against runaway recursion, and on any error unwinds this frame back to
	 * the depth it started at - closing upvalues, planting the message where
	 * the caller expects it, and restoring the hook gate - before letting the
	 * error continue outward.
	 */
	int luaD_call(lua_State* const state, StkId func, const int nResults)
	{
		constexpr unsigned int kMaxCCalls = 200;
		constexpr unsigned int kMaxCCallsHandling = kMaxCCalls + (kMaxCCalls >> 3);

		const ptrdiff_t frameOffset =
			reinterpret_cast<char*>(state->ci) - reinterpret_cast<char*>(state->base_ci);
		const std::uint16_t savedNestedCalls = state->nCcalls;
		const lu_byte savedAllowHook = state->l_G->allowhook;
		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		if (++state->nCcalls >= kMaxCCalls) {
			if (state->nCcalls == kMaxCCalls) {
				luaG_runerror(state, "C stack overflow");
			} else if (state->nCcalls >= kMaxCCallsHandling) {
				throw lua_ErrorError(lua::lua_Error(state, LUA_ERRERR, "error in Lua error handling"));
			}
		}

		try {
			StkId firstResult = luaD_precall(state, func);
			if (firstResult == nullptr) {
				firstResult = luaV_execute(state);
			}

			luaD_poscall(state, nResults, firstResult);
		} catch (const std::exception& error) {
			StkId const errorSlot =
				reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset);
			luaF_close(state, errorSlot);
			(void)PushLuaStringAtStackSlot(state, errorSlot, error.what());

			state->ci = reinterpret_cast<CallInfo*>(
				reinterpret_cast<char*>(state->base_ci) + frameOffset
			);
			state->base = state->ci->base;
			state->nCcalls = savedNestedCalls;
			state->l_G->allowhook = savedAllowHook;
			(void)luaD_refreshstacklimit(state);
			throw;
		}

		--state->nCcalls;
		luaC_checkGC(state);
		return 0;
	}

	/**
	 * Address: 0x00915290 (FUN_00915290, luaC_separateudata)
	 *
	 * IDA signature:
	 * size_t __usercall luaC_separateudata(lua_State *L);
	 *
	 * What it does:
	 * Moves every unreachable userdata that still wants finalising off the
	 * live list and onto `tmudata`, returning the total bytes they occupy so
	 * the collector can charge them against the allocation counter before the
	 * finalisers have actually run.
	 */
	static size_t luaC_separateudata(lua_State* const state)
	{
		constexpr lu_byte kReachableMask = 0x11;
		constexpr lu_byte kWantsFinaliserMask = 0x02;

		global_State* const globalState = state->l_G;
		GCObject** survivor = &globalState->rootudata;
		GCObject* collected = nullptr;
		GCObject** lastCollected = &collected;
		size_t deadmem = 0;

		for (GCObject* current = *survivor; current != nullptr; current = *survivor) {
			const lu_byte marked = current->gch.marked;
			if ((marked & kReachableMask) != 0 || (marked & kWantsFinaliserMask) == 0) {
				survivor = &current->gch.next;
				continue;
			}

			deadmem += static_cast<size_t>(reinterpret_cast<gpg::RType*>(current->u.len)->size_);
			*survivor = current->gch.next;
			current->gch.next = nullptr;
			*lastCollected = current;
			lastCollected = &current->gch.next;
		}

		*lastCollected = state->l_G->tmudata;
		state->l_G->tmudata = collected;
		return deadmem;
	}

	/**
	 * Address: 0x00915B20 (FUN_00915B20, luaC_callGCTM)
	 *
	 * IDA signature:
	 * void __cdecl luaC_callGCTM(lua_State *L);
	 *
	 * What it does:
	 * Runs the finaliser for every userdata `luaC_separateudata` set aside,
	 * returning each one to the live list first so a finaliser that resurrects
	 * its object finds it intact. Hooks stay disabled for the duration. Unlike
	 * stock Lua this does not look up a `__gc` metamethod - the fork calls the
	 * reflected destructor recorded on the userdata's RType instead, which is
	 * why the payload pointer rather than a Lua value is what gets passed.
	 */
	static void luaC_callGCTM(lua_State* const state)
	{
		constexpr lu_byte kClearFinaliserBits = 0xFC;

		global_State* const globalState = state->l_G;
		const lu_byte savedAllowHook = globalState->allowhook;
		globalState->allowhook = 0;

		// One reserved slot holds the userdata across the finaliser call.
		++state->top;

		while (state->l_G->tmudata != nullptr) {
			GCObject* const udata = state->l_G->tmudata;

			state->l_G->tmudata = udata->gch.next;
			udata->gch.next = state->l_G->rootudata;
			state->l_G->rootudata = udata;

			TObject* const slot = state->top - 1;
			slot->value.p = udata;
			slot->tt = static_cast<int>(udata->gch.tt);

			udata->gch.marked &= kClearFinaliserBits;

			auto* const type = reinterpret_cast<gpg::RType*>(udata->u.len);
			type->dtrFunc_(static_cast<void*>(&udata->u + 1));
		}

		--state->top;
		state->l_G->allowhook = savedAllowHook;
	}

	/**
	 * Address: 0x00915CC0 (FUN_00915CC0, mark)
	 *
	 * IDA signature:
	 * size_t __usercall mark(lua_State *L@<eax>);
	 *
	 * What it does:
	 * The mark half of one collection cycle. Roots are marked and propagated,
	 * then weak-valued tables are cleared before userdata pending finalisation
	 * are separated out and re-marked - they and anything they reach have to
	 * survive long enough for their finalisers to run. A second propagation
	 * covers that resurrection, after which the weak tables are cleared for
	 * real. Returns the bytes owed by the separated userdata.
	 */
	static size_t mark(lua_State* const state)
	{
		constexpr lu_byte kMarkedBit = 0x01;

		GCState st{};
		st.g = state->l_G;
		st.L = state;

		markroot(&st, state);
		propagatemarks(&st);

		cleartablevalues(st.wkv);
		cleartablevalues(st.wv);

		GCObject* const weakKeyValueTables = st.wkv;
		st.wkv = nullptr;
		st.wv = nullptr;

		const size_t deadmem = luaC_separateudata(state);

		for (GCObject* udata = st.g->tmudata; udata != nullptr; udata = udata->gch.next) {
			udata->gch.marked &= static_cast<lu_byte>(~kMarkedBit);
			reallymarkobject(&st, udata);
		}

		propagatemarks(&st);

		cleartablekeys(weakKeyValueTables);
		cleartablekeys(st.wk);
		cleartablevalues(st.wv);
		cleartablekeys(st.wkv);
		cleartablevalues(st.wkv);

		return deadmem;
	}

	/**
	 * Address: 0x00915D90 (FUN_00915D90, luaC_collectgarbage)
	 *
	 * IDA signature:
	 * void __cdecl luaC_collectgarbage(lua_State *L);
	 *
	 * What it does:
	 * One full stop-the-world cycle: mark, sweep the four collectable lanes,
	 * resize the string table and recompute the threshold, then run the
	 * finalisers that the mark phase deferred.
	 */
	void luaC_collectgarbage(lua_State* const state)
	{
		const size_t deadmem = mark(state);

		(void)sweeplist(&state->l_G->rootudata, nullptr, state, 0);
		sweepstrings(state, 0);
		(void)sweeplist(&state->l_G->rootgc1, nullptr, state, 0);
		(void)sweeplist(&state->l_G->rootgc, nullptr, state, 0);

		checkSizes(state, deadmem);
		luaC_callGCTM(state);
	}

	/**
	 * Address: 0x009284A0 (FUN_009284A0, luaT_getmetatable)
	 *
	 * IDA signature:
	 * Table *__cdecl luaT_getmetatable(lua_State *L, const TObject *o);
	 *
	 * What it does:
	 * Returns the metatable governing one value: tables and userdata carry
	 * their own, everything else shares the per-type default.
	 */
	Table* luaT_getmetatable(lua_State* const state, const TObject* const object)
	{
		switch (object->tt) {
			case LUA_TTABLE:
				return static_cast<Table*>(object->value.p)->metatable;
			case LUA_TUSERDATA:
				return static_cast<Udata*>(object->value.p)->metatable;
			default:
				return static_cast<Table*>(state->l_G->_defaultmetatypes[object->tt].value.p);
		}
	}

	/**
	 * Address: 0x009293E0 (FUN_009293E0, luaV_gettable)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaV_gettable(lua_State *L, const TObject *t, const TObject *key, int loop);
	 *
	 * What it does:
	 * Reads `t[key]` with full `__index` semantics. A raw hit on a real table
	 * returns immediately; a miss, or a non-table subject, continues down the
	 * metatable chain. `loop` counts the hops taken so far and trips the
	 * "loop in gettable" error past 100.
	 */
	const TObject* luaV_gettable(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kMaxTagMethodChain = 100;

		if (loop > kMaxTagMethodChain) {
			luaG_runerror(state, "loop in gettable");
		}

		if (t->tt != LUA_TTABLE) {
			return luaV_getnotable(state, t, key, loop + 1);
		}

		const TObject* const value = luaH_get(static_cast<Table*>(t->value.p), key);
		if (value->tt != LUA_TNIL) {
			return value;
		}

		return luaV_index(state, t, key, loop + 1);
	}

	/**
	 * Address: 0x00929BF0 (FUN_00929BF0, luaV_index)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaV_index(lua_State *L, const TObject *t, const TObject *key, int loop);
	 *
	 * What it does:
	 * Handles a raw miss on a real table. The metatable's cached "no __index
	 * here" flag short-circuits to nil without touching the table at all;
	 * otherwise a callable handler is invoked and anything else is re-indexed.
	 */
	const TObject* luaV_index(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kTagMethodIndex = 0;
		constexpr int kNoIndexTagMethodFlag = 1 << kTagMethodIndex;

		Table* const metatable = static_cast<Table*>(t->value.p)->metatable;
		if ((metatable->flags & kNoIndexTagMethodFlag) != 0) {
			return &luaO_nilobject;
		}

		const TObject* const handler =
			luaT_gettm(metatable, kTagMethodIndex, state->l_G->tmname[kTagMethodIndex]);
		if (handler == nullptr) {
			return &luaO_nilobject;
		}

		if (IsCallableTag(handler->tt)) {
			(void)callTMres(handler, t, key, state);
			return state->top;
		}

		return luaV_gettable(state, handler, key, loop);
	}

	/**
	 * Address: 0x00929370 (FUN_00929370, luaV_getnotable)
	 *
	 * IDA signature:
	 * const TObject *__usercall luaV_getnotable(lua_State *L@<eax>, const TObject *t@<edi>,
	 *     const TObject *key@<ebx>, int loop);
	 *
	 * What it does:
	 * Handles indexing a value that is not a table. The per-type `__index` tag
	 * method wins if there is one; failing that the value's whole metatable
	 * stands in as the handler, so `("x").upper` resolves through the string
	 * metatable.
	 */
	const TObject* luaV_getnotable(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kTagMethodIndex = 0;

		const TObject* handler = luaT_gettmbyobj(state, t, kTagMethodIndex);

		TObject metatableAsHandler{};
		if (handler->tt == LUA_TNIL) {
			Table* const metatable = luaT_getmetatable(state, t);
			metatableAsHandler.tt = static_cast<int>(metatable->tt);
			metatableAsHandler.value.p = metatable;
			handler = &metatableAsHandler;
		}

		if (IsCallableTag(handler->tt)) {
			(void)callTMres(handler, t, key, state);
			return state->top;
		}

		return luaV_gettable(state, handler, key, loop);
	}

	/**
	 * Address: 0x0090D000 (FUN_0090D000, lua_gettable)
	 * Mangled: ?lua_gettable@@YAXPAUlua_State@@H@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_gettable(lua_State *L, int idx);
	 *
	 * What it does:
	 * Replaces the key on top of the stack with `t[key]`, honouring metatables.
	 */
	void lua_gettable(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 1;
		*key = *luaV_gettable(state, table, key, 0);
	}

	/**
	 * Address: 0x0090D050 (FUN_0090D050, lua_rawget)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawget(lua_State *L, int idx);
	 *
	 * What it does:
	 * Replaces the key on top of the stack with `t[key]`, without consulting
	 * any metatable.
	 */
	void lua_rawget(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 1;
		*key = *luaH_get(static_cast<Table*>(table->value.p), key);
	}

	/**
	 * Address: 0x0090D2A0 (FUN_0090D2A0, lua_rawset)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawset(lua_State *L, int idx);
	 *
	 * What it does:
	 * Stores `t[key] = value` from the top two stack slots and pops both,
	 * bypassing metatables.
	 */
	void lua_rawset(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 2;
		*luaH_set(state, static_cast<Table*>(table->value.p), key) = *(state->top - 1);
		state->top -= 2;
	}

	/**
	 * Address: 0x0090D2F0 (FUN_0090D2F0, lua_rawseti)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawseti(lua_State *L, int idx, int n);
	 *
	 * What it does:
	 * Stores `t[n] = value` from the top stack slot and pops it, bypassing
	 * metatables.
	 */
	void lua_rawseti(lua_State* const state, const int idx, const int n)
	{
		const TObject* const table = luaA_index(state, idx);
		*luaH_setnum(state, static_cast<Table*>(table->value.p), n) = *(state->top - 1);
		--state->top;
	}

	/**
	 * Address: 0x0090D340 (FUN_0090D340, lua_setmetatable)
	 *
	 * IDA signature:
	 * int __cdecl lua_setmetatable(lua_State *L, int objindex);
	 *
	 * What it does:
	 * Pops a metatable off the stack and installs it on the value at
	 * `objindex`. A nil on top means "no metatable of its own", which this
	 * fork expresses by installing the shared default metatable rather than a
	 * null pointer - so a table's metatable lane is never empty. Returns 1
	 * when the target can carry one, 0 for tags that cannot.
	 */
	int lua_setmetatable(lua_State* const state, const int objindex)
	{
		const TObject* const object = luaA_index(state, objindex);

		const TObject* metatable = state->top - 1;
		if (metatable->tt == LUA_TNIL) {
			metatable = &state->l_G->_defaultmeta;
		}

		int applied = 1;
		switch (object->tt) {
			case LUA_TTABLE:
				static_cast<Table*>(object->value.p)->metatable = static_cast<Table*>(metatable->value.p);
				break;
			case LUA_TUSERDATA:
				static_cast<Udata*>(object->value.p)->metatable = static_cast<Table*>(metatable->value.p);
				break;
			default:
				applied = 0;
				break;
		}

		--state->top;
		return applied;
	}

	/**
	 * Address: 0x00915DF0 (FUN_00915DF0, luaC_link)
	 *
	 * IDA signature:
	 * void __cdecl luaC_link(lua_State *L, GCObject *o, lu_byte tt);
	 *
	 * What it does:
	 * Pushes one fresh collectable onto the head of the main GC root list and
	 * stamps its tag, clearing the mark bits so the next sweep sees it white.
	 */
	void luaC_link(lua_State* const state, GCObject* const object, const int typeTag)
	{
		global_State* const globalState = state->l_G;
		object->gch.next = globalState->rootgc;
		globalState->rootgc = object;
		object->gch.marked = 0;
		object->gch.tt = static_cast<lu_byte>(typeTag);
	}

	/**
	 * Address: 0x00914E90 (FUN_00914E90, luaF_newCclosure)
	 *
	 * IDA signature:
	 * Closure *__cdecl luaF_newCclosure(lua_State *L, int nelems);
	 *
	 * What it does:
	 * Allocates a C closure sized for `nelems` upvalues, links it for
	 * collection, and records the upvalue count. The function pointer itself
	 * is filled in by the caller.
	 */
	Closure* luaF_newCclosure(lua_State* const state, const int nelems)
	{
		auto* const closure = static_cast<Closure*>(luaM_realloc(
			state,
			nullptr,
			0u,
			static_cast<lu_mem>(offsetof(CClosure, upvalue) + sizeof(LuaPlus::TObject) * nelems)
		));

		luaC_link(state, reinterpret_cast<GCObject*>(closure), LUA_CFUNCTION);

		// The binary clears 0x18 through 0x40 - the tail of the reserved span
		// whose fields are not named yet, plus the one-before-first upvalue
		// lane - and deliberately leaves the dword at 0x14 as the allocator
		// returned it.
		constexpr std::size_t kUnclearedReservedPrefix = 4;
		std::memset(
			&closure->c.reservedTail[kUnclearedReservedPrefix],
			0,
			sizeof(closure->c.reservedTail) - kUnclearedReservedPrefix
		);
		closure->c.upvalue_m1[0].tt = LUA_TNIL;
		closure->c.upvalue_m1[0].value.p = nullptr;

		closure->c.nupvalues = static_cast<lu_byte>(nelems);
		return closure;
	}

	/**
	 * Address: 0x0092BAD0 (FUN_0092BAD0, luaZ_openspace)
	 *
	 * IDA signature:
	 * char *__cdecl luaZ_openspace(lua_State *L, Mbuffer *buff, size_t n);
	 *
	 * What it does:
	 * Grows the shared scratch buffer to at least `n` bytes, never below the
	 * 32-byte floor. The allocator flag lane is forced to 1 across the resize
	 * and restored afterwards, which is how this build tags scratch growth
	 * apart from ordinary VM allocation.
	 */
	char* luaZ_openspace(lua_State* const state, Mbuffer* const buff, const size_t n)
	{
		constexpr size_t kMinBuffer = 32u;

		if (n > buff->buffsize) {
			const size_t newSize = n < kMinBuffer ? kMinBuffer : n;

			const unsigned int savedAllocFlags = state->allocFlags;
			state->allocFlags = 1u;
			buff->buffer = static_cast<char*>(
				luaM_realloc(state, buff->buffer, static_cast<lu_mem>(buff->buffsize), static_cast<lu_mem>(newSize))
			);
			state->allocFlags = savedAllocFlags;

			buff->buffsize = newSize;
		}

		return buff->buffer;
	}

	/**
	 * Address: 0x00D47508 (luaT_eventname)
	 *
	 * What it does:
	 * Source text for the tag-method names `luaT_init` interns into
	 * `global_State::tmname`. Eighteen entries, read out of the shipped image;
	 * the array ends where unrelated data begins, and the count matches
	 * luaT_init's own loop bound (esi = 0x5C stepping 4 while below 0xA4).
	 */
	const char* luaT_eventname[]{
		"__index",    // 0
		"__newindex", // 1
		"__mode",     // 2
		"__eq",       // 3
		"__add",      // 4
		"__sub",      // 5
		"__mul",      // 6
		"__div",      // 7
		"__band",     // 8
		"__bor",      // 9
		"__bshl",     // 10
		"__bshr",     // 11
		"__pow",      // 12
		"__unm",      // 13
		"__lt",       // 14
		"__le",       // 15
		"__concat",   // 16
		"__call",     // 17
	};

	/**
	 * Address: 0x00D46010 (token2string)
	 *
	 * What it does:
	 * The reserved words, in token order. `luaX_init` interns these and stamps
	 * each one's `reserved` lane with its index + 1, which is how the lexer
	 * recognises a keyword by pointer identity instead of strcmp. Entry 22 in
	 * the image starts the non-reserved token names, so the reserved run is
	 * exactly the 22 below - matching luaX_init's "cmp ebx, 16h".
	 */
	const char* token2string[]{
		"and",   "break", "continue", "do",   "else", "elseif",
		"end",   "false", "for",      "function", "if", "in",
		"local", "nil",   "not",      "or",   "repeat", "return",
		"then",  "true",  "until",    "while",
	};

	/**
	 * Address: 0x009241A0 (FUN_009241A0, luaC_init)
	 *
	 * IDA signature:
	 * void __usercall luaC_init(lua_State *L@<edi>);
	 *
	 * What it does:
	 * Despite the luaC_ prefix this is not GC setup - it interns the twelve
	 * type names into `global_State::typenames` and pins each against
	 * collection. The loop walks g+0xA4 through g+0xD4 in four-byte steps,
	 * which is where that array lives.
	 */
	void luaC_init(lua_State* const state)
	{
		for (int typeTag = 0; typeTag < kLuaTypeTagCount; ++typeTag) {
			const char* const name = luaT_typenames[typeTag];
			TString* const interned = luaS_newlstr(state, name, std::strlen(name));
			state->l_G->typenames[typeTag] = interned;
			state->l_G->typenames[typeTag]->marked |= kLuaFixedStringMark;
		}
	}

	/**
	 * Address: 0x009283C0 (FUN_009283C0, luaT_init)
	 *
	 * IDA signature:
	 * void __cdecl luaT_init(lua_State *L);
	 *
	 * What it does:
	 * Interns the tag-method names into `global_State::tmname` and pins each
	 * against collection, so `luaT_gettm` can look a metamethod up by
	 * pre-interned key.
	 */
	void luaT_init(lua_State* const state)
	{
		for (int event = 0; event < kLuaTagMethodCount; ++event) {
			const char* const name = luaT_eventname[event];
			TString* const interned = luaS_newlstr(state, name, std::strlen(name));
			state->l_G->tmname[event] = interned;
			state->l_G->tmname[event]->marked |= kLuaFixedStringMark;
		}
	}

	/**
	 * Address: 0x009180D0 (FUN_009180D0, luaX_init)
	 *
	 * IDA signature:
	 * void __cdecl luaX_init(lua_State *L);
	 *
	 * What it does:
	 * Interns the reserved words, pins them, and stamps each with its token
	 * index + 1. The binary writes only the low byte of the `reserved` lane
	 * ("mov [eax+8], cl"); the indices are all under 256, so storing the whole
	 * field is equivalent for a freshly interned string.
	 */
	void luaX_init(lua_State* const state)
	{
		for (int token = 0; token < kLuaReservedWordCount; ++token) {
			const char* const word = token2string[token];
			TString* const interned = luaS_newlstr(state, word, std::strlen(word));
			interned->marked |= kLuaFixedStringMark;
			interned->reserved = token + 1;
		}
	}

	/**
	 * Address: 0x009247A0 (FUN_009247A0, luaS_freeall)
	 *
	 * IDA signature:
	 * void __cdecl luaS_freeall(lua_State *L);
	 *
	 * What it does:
	 * Releases the string table's bucket array. The strings themselves are
	 * already gone by this point - close_state sweeps before calling here.
	 */
	void luaS_freeall(lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		(void)luaM_realloc(
			state,
			globalState->strt.hash,
			static_cast<lu_mem>(sizeof(GCObject*) * globalState->strt.size),
			0u
		);
	}

	/**
	 * Address: 0x00915BA0 (FUN_00915BA0, luaC_sweep)
	 *
	 * IDA signature:
	 * int __cdecl luaC_sweep(lua_State *L, int all);
	 *
	 * What it does:
	 * Sweeps the four collectable lanes in the order userdata, strings,
	 * secondary root list, main root list. `all` selects the mark limit: 0
	 * keeps anything reachable, 0x100 is above every real mark bit and so
	 * collects everything, which is what close_state passes.
	 */
	int luaC_sweep(lua_State* const state, const int all)
	{
		constexpr int kSweepEverythingLimit = 0x100;

		const int limit = all != 0 ? kSweepEverythingLimit : 0;

		(void)sweeplist(&state->l_G->rootudata, nullptr, state, limit);
		sweepstrings(state, limit);
		(void)sweeplist(&state->l_G->rootgc1, nullptr, state, limit);
		return sweeplist(&state->l_G->rootgc, nullptr, state, limit);
	}

	/**
	 * Address: 0x00914FC0 (FUN_00914FC0, luaF_close)
	 *
	 * IDA signature:
	 * void __cdecl luaF_close(lua_State *L, StkId level);
	 *
	 * What it does:
	 * Closes every open upvalue at or above `level`: the referenced stack slot
	 * is copied into the upvalue's own storage, the pointer is retargeted at
	 * that copy, and the object moves off the thread's open list onto the GC
	 * list. Open upvalues are ordered by descending stack slot, so the walk
	 * stops at the first one below `level`.
	 */
	void luaF_close(lua_State* const state, const StkId level)
	{
		for (GCObject* upvalObject = state->openupval; upvalObject != nullptr;
			 upvalObject = state->openupval) {
			UpVal* const upval = &upvalObject->uv;
			if (upval->v < level) {
				return;
			}

			upval->value = *upval->v;
			upval->v = &upval->value;
			state->openupval = upvalObject->gch.next;
			luaC_link(state, upvalObject, LUA_TUPVALUE);
		}
	}

	/**
	 * Address: 0x00924470 (FUN_00924470, f_luaopen)
	 *
	 * IDA signature:
	 * void __usercall f_luaopen(lua_State *L@<eax>);
	 *
	 * What it does:
	 * Builds the shared global_State for a brand-new thread. The chicken-and-
	 * egg problem - the allocator lives in the global_State being allocated -
	 * is solved with a throwaway lua_State/global_State pair on the stack
	 * carrying just the allocator hooks, which is what the real object is
	 * allocated through. After that it seeds the string table, the registry
	 * (whose metatable is itself), a default metatable per type tag, the
	 * thread's globals table, the interned name tables, and the scratch
	 * buffer.
	 */
	void f_luaopen(lua_State* const state)
	{
		// The binary leaves this bootstrap pair uninitialised apart from the
		// five fields below, so luaM_realloc reads whatever the stack held for
		// allocFlags. Value-initialising is the one deliberate deviation here:
		// reading indeterminate storage is undefined behaviour in C++, and
		// zero is the flag value every other caller uses (luaZ_openspace saves
		// and restores it precisely because 1 is the exception).
		lua_State bootstrapState{};
		global_State bootstrapGlobals{};
		bootstrapState.l_G = &bootstrapGlobals;
		bootstrapGlobals.reallocFunc = luaHelper_Realloc;
		bootstrapGlobals.freeFunc = luaHelper_Free;
		bootstrapGlobals.memData = luaHelper_memData;
		bootstrapGlobals.nblocks = static_cast<lu_mem>(sizeof(lua_State) + sizeof(global_State));

		auto* const globalState = static_cast<global_State*>(
			luaM_realloc(&bootstrapState, nullptr, 0u, static_cast<lu_mem>(sizeof(global_State)))
		);
		if (globalState == nullptr) {
			throw lua_MemError(lua::lua_Error(state, LUA_ERRMEM, "out of memory"));
		}

		state->l_G = globalState;

		globalState->strt.hash = nullptr;
		globalState->strt.nuse = 0;
		globalState->strt.size = 0;
		globalState->rootgc = nullptr;
		globalState->rootgc1 = nullptr;
		globalState->rootudata = nullptr;
		globalState->tmudata = nullptr;
		globalState->buff.buffer = nullptr;
		globalState->buff.buffsize = 0u;
		globalState->GCthreshold = 0u;
		globalState->gcTraversalLockDepth = 0;
		globalState->nblocks = static_cast<lu_mem>(sizeof(lua_State) + sizeof(global_State));
		globalState->_defaultmeta.tt = LUA_TNIL;
		globalState->_registry.tt = LUA_TNIL;
		globalState->mainthread = state;
		globalState->lstate = state;
		globalState->dummynode[0].i_key.tt = LUA_TNIL;
		globalState->dummynode[0].i_val.tt = LUA_TNIL;
		globalState->dummynode[0].next = nullptr;
		globalState->fatalErrorFunc = &defaultFatalErrorFunc;
		globalState->memData = luaHelper_memData;
		globalState->reallocFunc = luaHelper_Realloc;
		globalState->freeFunc = luaHelper_Free;
		globalState->globalUserData = nullptr;
		globalState->userGCFunction = nullptr;
		globalState->allocationTrackingEnabled = 0;
		globalState->hookmask = 0;
		globalState->allowhook = 1;
		globalState->basehookcount = 0;
		globalState->hookcount = 0;
		globalState->hook = nullptr;

		lua_stack_init(state, state);

		for (TObject& slot : globalState->_defaultmetatypes) {
			slot.value.p = nullptr;
		}

		// The slot starts life as the number 0 before being replaced by its
		// table - the binary really does write LUA_TNUMBER here first.
		globalState->_defaultmeta.tt = LUA_TNUMBER;
		globalState->_defaultmeta.value.p = nullptr;

		// The shared default metatable is its own metatable, which is what
		// terminates metatable chains for values that have none of their own.
		Table* const defaultMeta = luaH_new(state, 0, 0);
		globalState->_defaultmeta.tt = static_cast<int>(defaultMeta->tt);
		globalState->_defaultmeta.value.p = defaultMeta;
		static_cast<Table*>(globalState->_defaultmeta.value.p)->metatable =
			static_cast<Table*>(globalState->_defaultmeta.value.p);

		for (TObject& slot : globalState->_defaultmetatypes) {
			Table* const typeMeta = luaH_new(state, 0, 0);
			slot.tt = static_cast<int>(typeMeta->tt);
			slot.value.p = typeMeta;
			static_cast<Table*>(slot.value.p)->metatable =
				static_cast<Table*>(globalState->_defaultmeta.value.p);
		}

		Table* const globals = luaH_new(state, 0, 4);
		state->_gt.tt = static_cast<int>(globals->tt);
		state->_gt.value.p = globals;

		Table* const registry = luaH_new(state, 4, 4);
		globalState->_registry.value.p = registry;
		globalState->_registry.tt = static_cast<int>(registry->tt);
		globalState->minimumstrings = lua_minimumnumstrings;

		luaS_resize(state, kLuaInitialStringTableSize);
		luaC_init(state);
		luaT_init(state);
		luaX_init(state);

		TString* const outOfMemory = luaS_newlstr(state, "not enough memory", 17u);
		outOfMemory->marked |= kLuaFixedStringMark;

		globalState->GCthreshold = 4u * globalState->nblocks;
		(void)luaZ_openspace(state, &globalState->buff, static_cast<size_t>(lua_minimumauxspace));
	}

	/**
	 * Address: 0x009246D0 (FUN_009246D0, lua_open)
	 * Mangled: ?lua_open@@YAPAUlua_State@@XZ
	 *
	 * IDA signature:
	 * lua_State *__cdecl lua_open(void);
	 *
	 * What it does:
	 * Allocates the main thread through the same throwaway allocator state
	 * f_luaopen uses, blanks it, and hands it to f_luaopen to acquire the
	 * shared global_State. If that throws part-way the half-built state is
	 * closed before the exception continues out - the binary expresses this
	 * with an SEH frame around the f_luaopen call.
	 */
	lua_State* lua_open(void)
	{
		lua_State bootstrapState{};
		global_State bootstrapGlobals{};
		bootstrapState.l_G = &bootstrapGlobals;
		bootstrapGlobals.reallocFunc = luaHelper_Realloc;
		bootstrapGlobals.freeFunc = luaHelper_Free;
		bootstrapGlobals.memData = luaHelper_memData;
		bootstrapGlobals.nblocks = static_cast<lu_mem>(sizeof(lua_State) + sizeof(global_State));

		auto* const state = static_cast<lua_State*>(
			luaM_realloc(&bootstrapState, nullptr, 0u, static_cast<lu_mem>(sizeof(lua_State)))
		);
		if (state == nullptr) {
			return nullptr;
		}

		state->next = nullptr;
		state->tt = LUA_TTHREAD;
		state->marked = 0;
		state->l_G = nullptr;
		state->ci = nullptr;
		state->stack = nullptr;
		state->stacksize = 0;
		state->base_ci = nullptr;
		state->size_ci = 0;
		state->nCcalls = 0;
		state->_gt.tt = LUA_TNIL;
		state->openupval = nullptr;
		state->gclist = nullptr;
		state->stateUserData = nullptr;
		// Not written by the binary, which leaves the freshly allocated bytes
		// in place and lets luaM_realloc read them. Zeroed here for the same
		// reason as the bootstrap pair above: the allocator hook ignores the
		// flag lane, so the observable behaviour is identical without the
		// indeterminate read.
		state->allocFlags = 0u;

		try {
			f_luaopen(state);
		} catch (...) {
			close_state(state);
			throw;
		}

		return state;
	}

	/**
	 * Address: 0x009243E0 (FUN_009243E0, lua_close)
	 *
	 * IDA signature:
	 * void __cdecl lua_close(lua_State *L);
	 *
	 * What it does:
	 * Tears the whole VM down through its main thread: open upvalues are closed,
	 * every userdata still owing a finaliser is moved onto `tmudata`, and those
	 * finalisers then run on a stack rewound to the base frame. A finaliser that
	 * throws only costs itself - `luaC_callGCTM` unlinks each userdata before
	 * calling it - so the rewind-and-run is simply repeated until one pass gets
	 * through. That retry is how the binary spells stock Lua's
	 * `do { ... } while (luaD_rawrunprotected(L, callallgcTM, NULL) != 0)`: the
	 * fork raises C++ exceptions, so the loop is an EH region whose handler at
	 * 0x00924463 reloads the main thread and jumps back to the rewind at
	 * 0x00924420. `close_state` then releases the arrays and both state objects.
	 *
	 * Recovered because the prebuilt LuaPlus copy reads this state at stock
	 * offsets and so walked garbage from its very first line:
	 * `global_State::mainthread` is at +0x40 here, and `rootudata`/`tmudata` sit
	 * at +0x14/+0x18 rather than the stock +0x10/+0x14 because the fork carries
	 * a second GC lane.
	 */
	void lua_close(lua_State* const state)
	{
		lua_State* const mainThread = state->l_G->mainthread;

		luaF_close(mainThread, mainThread->stack);
		(void)luaC_separateudata(mainThread);

		for (bool finalisersFinished = false; !finalisersFinished;) {
			mainThread->ci = mainThread->base_ci;
			mainThread->top = mainThread->base_ci->base;
			mainThread->base = mainThread->top;
			mainThread->nCcalls = 0u;

			try {
				luaC_callGCTM(mainThread);
				finalisersFinished = true;
			} catch (...) {
				// Whatever threw is already off `tmudata`; rewind and run the
				// rest, which is all the binary's catch funclet does.
			}
		}

		close_state(mainThread);
	}
}
#pragma warning(pop)

extern "C"
{
	int _errorfb(lua_State* L, int level);
}

/**
 * Address: 0x00911DD0 (ldblib.c::errorfb core, recovered)
 *
 * What it does:
 * Walks the active Lua call stack starting at `level + 1`, pushing one
 * `"stack traceback:"` header followed by a `\n\t<chunk>:<line>: in
 * function <name>` line for each frame. Compresses the middle of very deep
 * stacks with a single ellipsis (`LEVELS1=12`, `LEVELS2=10`). Concatenates
 * the result into one string at top-of-stack and returns 1. Recovered as a
 * free function here because callers (e.g. `errorfb`, `lua_traceback`) live
 * in our recovered LuaObject.cpp.
 */
extern "C" int _errorfb(lua_State* const state, int level)
{
	constexpr int kLevels1 = 12;
	constexpr int kLevels2 = 10;
	int firstpart = 1;
	lua_Debug ar;

	if (lua_gettop(state) == 0) {
		lua_pushlstring(state, "", 0);
	} else if (!lua_isstring(state, 1)) {
		return 1;
	} else {
		lua_pushlstring(state, "\n", 1);
	}

	lua_pushlstring(state, "stack traceback:", 16);
	++level;
	while (lua_getstack(state, level++, &ar)) {
		if (level > kLevels1 && firstpart) {
			if (!lua_getstack(state, level + kLevels2, &ar)) {
				--level;
			} else {
				lua_pushlstring(state, "\n\t...", 5);
				while (lua_getstack(state, level + kLevels2, &ar)) {
					++level;
				}
			}
			firstpart = 0;
			continue;
		}

		lua_pushlstring(state, "\n\t", 2);
		lua_getinfo(state, "Snl", &ar);
		lua_pushfstring(state, "%s:", ar.short_src);
		if (ar.currentline > 0) {
			lua_pushfstring(state, "%d:", ar.currentline);
		}

		switch (*ar.namewhat) {
			case 'g':
			case 'l':
			case 'f':
			case 'm':
				lua_pushfstring(state, " in function `%s'", ar.name);
				break;
			default:
				if (*ar.what == 'm') {
					lua_pushfstring(state, " in main chunk");
				} else if (*ar.what == 'C' || *ar.what == 't') {
					lua_pushlstring(state, " ?", 2);
				} else {
					lua_pushfstring(state, " in function <%s:%d>", ar.short_src, ar.linedefined);
				}
		}

		lua_concat(state, lua_gettop(state));
	}

	lua_concat(state, lua_gettop(state));
	return 1;
}

/**
 * Address: 0x00911E90 (FUN_00911E90, errorfb)
 *
 * What it does:
 * Calls core traceback formatter with default skip level 1.
 */
extern "C" int errorfb(lua_State* const state)
{
	return _errorfb(state, 1);
}

/**
 * Address: 0x00911EA0 (FUN_00911EA0, lua_traceback)
 *
 * What it does:
 * Pushes message text and then runs core traceback formatter at given level.
 */
extern "C" int lua_traceback(lua_State* const state, const char* const message, const int level)
{
	lua_pushstring(state, message);
	return _errorfb(state, level);
}

namespace
{
	const luaL_reg kLuaDebugLibrary[] = {
		{"getinfo", &LuaDebugGetInfo},
		{"getlocal", &LuaDebugGetLocal},
		{"setlocal", &LuaDebugSetLocal},
		{"getupvalue", &LuaDebugGetUpvalue},
		{"setupvalue", &LuaDebugSetUpvalue},
		{"sethook", &LuaDebugSetHook},
		{"gethook", &LuaDebugGetHook},
		{"debug", &LuaDebugConsole},
		{"traceback", &errorfb},
		{"listcode", &LuaDebugListCode},
		{"listk", &LuaDebugListConstants},
		{"listlocals", &LuaDebugListLocals},
		{"allobjects", &LuaDebugAllObjects},
		{"allocinfo", &LuaDebugAllocInfo},
		{"trackallocations", &LuaDebugTrackAllocations},
		{"allocatedsize", &LuaDebugAllocatedSize},
		{"profiledata", &LuaDebugProfileData},
		{nullptr, nullptr}
	};
}

/**
 * Address: 0x00923690 (FUN_00923690, luaopen_serialize)
 *
 * What it does:
 * Opens the LuaPlus `serialize` library table with the two functions the
 * binary registers through `serializelib` at 0x00D47068. Table contents read
 * out of the shipped image:
 *   0x00D47068 -> "tostring"   / 0x00D4706C -> 0x00923AC0 LuaSerializeToString
 *   0x00D47070 -> "fromstring" / 0x00D47074 -> 0x00923D20 LuaSerializeFromString
 *   0x00D47078 -> { nullptr, nullptr } sentinel
 * Both bodies live in `gpg/core/containers/ArchiveSerialization.cpp`; naming
 * them here is what keeps them in the link, and what makes runtime
 * `serialize.tostring` / `serialize.fromstring` resolve instead of returning
 * nil.
 */
extern "C" int luaopen_serialize(lua_State* const state)
{
	static const luaL_reg kSerializeLibrary[] = {
		{"tostring", &LuaSerializeToString},
		{"fromstring", &LuaSerializeFromString},
		{nullptr, nullptr}
	};
	luaL_openlib(state, "serialize", kSerializeLibrary, 0);
	return 1;
}

/**
 * Address: 0x009124C0 (FUN_009124C0, luaopen_debug)
 *
 * What it does:
 * Opens the Lua debug library table, installs `_TRACEBACK` in globals, and
 * binds it to the recovered `errorfb` traceback helper.
 */
int luaopen_debug(lua_State* const state)
{
	luaL_openlib(state, "debug", kLuaDebugLibrary, 0);
	lua_pushlstring(state, "_TRACEBACK", 10u);
	lua_pushcclosure(state, errorfb, 0);
	lua_settable(state, LUA_GLOBALSINDEX);
	return 1;
}

/**
 * Address: 0x00912560 (FUN_00912560, lua_sethook)
 *
 * What it does:
 * Installs or clears VM debug hook callback/mask/count lanes in `global_State`.
 */
int lua_sethook(lua_State* const state, lua_Hook hook, int mask, const int count)
{
	if (hook == nullptr || mask == 0) {
		mask = 0;
		hook = nullptr;
	}

	global_State* const globalState = state->l_G;
	globalState->hook = hook;
	globalState->basehookcount = count;
	globalState->hookcount = globalState->basehookcount;
	globalState->hookmask = static_cast<lu_byte>(mask);
	return 1;
}

/**
 * Address: 0x009125B0 (FUN_009125B0, lua_gethook)
 *
 * What it does:
 * Returns currently installed VM debug hook callback pointer.
 */
lua_Hook lua_gethook(lua_State* const state)
{
	return state->l_G->hook;
}

/**
 * Address: 0x009125C0 (FUN_009125C0, lua_gethookmask)
 *
 * What it does:
 * Returns active VM debug hook mask bitfield.
 */
int lua_gethookmask(lua_State* const state)
{
	return state->l_G->hookmask;
}

/**
 * Address: 0x009125D0 (FUN_009125D0, lua_gethookcount)
 *
 * What it does:
 * Returns base hook countdown reload value.
 */
int lua_gethookcount(lua_State* const state)
{
	return state->l_G->basehookcount;
}

/**
 * Address: 0x009072A0 (FUN_009072A0, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty LuaObject with null list links/state and NIL payload.
 */
LuaObject::LuaObject()
	: m_next(nullptr),
	  m_prev(nullptr),
	  m_state(nullptr),
	  m_object()
{
}

/**
 * Address: 0x005280D0 (FUN_005280D0, ??0LuaObject@LuaPlus@@QAE@@Z)
 *
 * What it does:
 * Casts one raw C Lua state pointer to the owning `LuaState` wrapper and
 * forwards construction to the stack-lane constructor with index `-1`.
 */
LuaObject::LuaObject(lua_State* const state)
	: LuaObject(LuaState::CastState(state), -1)
{
}

LuaObject::LuaObject(LuaState* state)
	: LuaObject()
{
	AddToUsedList(state);
	m_object.tt = LUA_TNIL;
}

LuaObject::LuaObject(LuaState* state, const int32_t stackIndex)
	: LuaObject()
{
	Ensure(state != nullptr, "state");
	const TObject stackObject = CaptureStackValue(state->GetCState(), stackIndex);
	AddToUsedObjectList(state, const_cast<TObject*>(&stackObject));
}

/**
 * Address: 0x009089F0 (FUN_009089F0, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Binds this object to one caller-provided raw `TObject` lane and inserts it
 * into the owning root-state used-object list.
 */
LuaObject::LuaObject(LuaState* state, TObject* obj)
	: LuaObject()
{
	Ensure(obj != nullptr, "obj");
	AddToUsedObjectList(state, obj);
}

/**
 * Address: 0x00908A70 (FUN_00908A70, ??0LuaObject@LuaPlus@@QAE@ABVLuaStackObject@1@@Z)
 *
 * What it does:
 * Initializes this object from one stack slot and links it into the root
 * used-object list of the source stack-object state.
 */
LuaObject::LuaObject(const LuaStackObject& stackObject)
{
	m_object.tt = LUA_TNIL;
	TObject* const stackValue = luaA_index(stackObject.m_state->m_state, stackObject.m_stackIndex);
	AddToUsedObjectList(stackObject.m_state, stackValue);
}

/**
 * Address: 0x00908A40 (FUN_00908A40, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty object, then mirrors the source LuaObject by
 * linking into the same root-state used-object list when bound.
 */
LuaObject::LuaObject(const LuaObject& other)
	: LuaObject()
{
	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	}
}

/**
 * Address: 0x00908AB0 (FUN_00908AB0, LuaPlus::LuaObject::operator=)
 *
 * What it does:
 * Unlinks current state-list ownership (when bound), then binds to `other`
 * by re-inserting this object into the source state's used-object list.
 */
LuaObject& LuaObject::operator=(const LuaObject& other)
{
	if (this == &other) {
		return *this;
	}

	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}

	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	} else {
		m_state = nullptr;
		m_next = nullptr;
		m_prev = nullptr;
	}
	return *this;
}

namespace
{
	struct LuaObjectAssignmentLaneOwnerRuntimeView
	{
		std::uint8_t lane00_77[0x78]{};
		LuaObject embeddedLuaObject; // +0x78
	};
	static_assert(
		offsetof(LuaObjectAssignmentLaneOwnerRuntimeView, embeddedLuaObject) == 0x78,
		"LuaObjectAssignmentLaneOwnerRuntimeView::embeddedLuaObject offset must be 0x78"
	);
}

/**
 * Address: 0x006ED960 (FUN_006ED960)
 *
 * What it does:
 * Resolves one embedded LuaObject lane at owner offset `+0x78`, assigns from
 * one source object lane, and returns the owner runtime pointer.
 */
LuaObjectAssignmentLaneOwnerRuntimeView* AssignEmbeddedLuaObjectAtOffset78(
	LuaObjectAssignmentLaneOwnerRuntimeView* const ownerRuntime,
	const LuaObject& sourceObject
)
{
	ownerRuntime->embeddedLuaObject = sourceObject;
	return ownerRuntime;
}

/**
 * Address: 0x00908B00 (FUN_00908B00, LuaPlus::LuaObject::operator=)
 *
 * What it does:
 * Unlinks current state-list ownership (when bound), resolves one stack slot
 * TValue lane from `stackObject`, then re-links this object into that state's
 * used-object list.
 */
LuaObject& LuaObject::operator=(const LuaStackObject& stackObject)
{
	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}

	TObject* const stackValue = luaA_index(stackObject.m_state->m_state, stackObject.m_stackIndex);
	AddToUsedObjectList(stackObject.m_state, stackValue);
	return *this;
}

/**
 * Address: 0x009075D0 (FUN_009075D0, LuaPlus::LuaObject::~LuaObject)
 * Address: 0x005790D0 (FUN_005790D0, LuaObject::j_Dtr_3 thunk)
 * Address: 0x005791A0 (FUN_005791A0, LuaObject::j_Dtr_4 thunk)
 * Address: 0x005D0A90 (FUN_005D0A90, LuaObject::j_Dtr_6 thunk)
 * Address: 0x00624120 (FUN_00624120, LuaObject::j_Dtr_7 thunk)
 * Address: 0x00BA2E8B (FUN_00BA2E8B, LuaObject::j_Dtr_9 thunk)
 *
 * What it does:
 * Unlinks this object from the owning state's intrusive used-object list
 * when bound and clears the tagged value to nil.
 */
LuaObject::~LuaObject()
{
	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}
}

/**
  * Alias of FUN_005790D0 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk3(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_005791A0 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk4(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_005D0A90 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk6(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_00624120 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk7(LuaObject* const object)
{
	object->~LuaObject();
}

/**
 * Address: 0x0090AC10 (FUN_0090AC10, LuaPlus::LuaState::LuaState)
 *
 * What it does:
 * Initializes root-state ownership lanes, creates a fresh C `lua_State`,
 * binds userdata/GC callbacks, and runs standard-library init.
 */
LuaState::LuaState(const StandardLibraries initStandardLibrary)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_pad9{0, 0, 0},
	  m_threadObj(),
	  m_rootState(this),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{
	m_state = lua_open();
	m_ownState = 1;
	lua_setusergcfunction(m_state, reinterpret_cast<void(__cdecl*)(void*)>(&LuaPlusGCFunction));
	lua_setstateuserdata(m_state, this);

	m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
	m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
	m_headObject.m_prev = nullptr;
	m_tailObject.m_next = nullptr;
	m_luaTask = nullptr;

	Init(initStandardLibrary);
}

/**
 * Address: 0x0090AAD0 (FUN_0090AAD0, LuaPlus::LuaState::Init)
 *
 * What it does:
 * Initializes selected standard libraries and script helper globals, then
 * always registers `LOG` and `_ALERT` on the global table.
 */
void LuaState::Init(const StandardLibraries initStandardLibrary)
{
	if (initStandardLibrary != LIB_NONE) {
		lua_State* const state = m_state;
		const int previousTop = lua_gettop(state);

		luaopen_base(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo below. The
		// vendored ltablib was compiled with stock tag numbering, where
		// LUA_TFUNCTION is 6; in this fork 6 is the C-function tag, so its
		// table.sort turned away every Lua comparator with "cfunction
		// expected, got function".
		LuaOpenTable(state);
		if (initStandardLibrary == LIB_OSIO) {
			// Ours, not the prebuilt lib's. The vendored liolib walks a
			// lua_State this tree builds and asserts in its debug
			// lua_newuserdata; this one is the binary's own 0x00917BC0.
			LuaOpenIo(state);
		}
		luaopen_serialize(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
		LuaOpenString(state);
		// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
		LuaOpenMath(state);
		luaopen_debug(state);
		if (initStandardLibrary == LIB_OSIO) {
			// Ours, not the prebuilt lib's - same reason as LuaOpenIo above.
			LuaOpenLoadLib(state);
		}

		ScriptFunctionsRegister(this);
		lua_settop(state, previousTop);
	}

	LuaObject globals = GetGlobals();
	globals.Register("LOG", LS_LOG, 0);

	LuaObject alertGlobals = GetGlobals();
	alertGlobals.Register("_ALERT", LS_LOG, 0);
}

/**
 * Address: 0x0090A520 (FUN_0090A520, LuaPlus::LuaState::LuaState)
 *
 * What it does:
 * Creates one coroutine thread state under the provided root wrapper, captures
 * the pushed thread object into `m_threadObj`, then binds `stateUserData`.
 */
LuaState::LuaState(LuaState* const parentState)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_pad9{0, 0, 0},
	  m_threadObj(),
	  m_rootState(parentState ? parentState->m_rootState : nullptr),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{
	Ensure(parentState != nullptr, "parentState");
	Ensure(m_rootState != nullptr, "parentState->m_rootState");
	Ensure(m_rootState->m_state != nullptr, "parentState->m_rootState->m_state");

	m_state = lua_newthread(m_rootState->m_state);
	Ensure(m_state != nullptr, "lua_newthread");

	const LuaStackObject threadStackObject(m_rootState, lua_gettop(m_rootState->m_state));
	m_threadObj = LuaObject(threadStackObject);
	lua_settop(m_rootState->m_state, -2);

	m_state->stateUserData = this;
}

/**
 * Address: 0x0090A600 (FUN_0090A600, LuaPlus::LuaState::~LuaState)
 *
 * What it does:
 * Clears root-owned live objects, detaches Lua state userdata, closes owned
 * C-state when required, then lets member destructors run.
 */
LuaState::~LuaState()
{
	if (m_rootState == this) {
		const auto* const tail = reinterpret_cast<const LuaObject*>(&m_tailObject);
		while (m_headObject.m_next != tail) {
			LuaObject* const live = m_headObject.m_next;
			Ensure(live != nullptr, "live");
			live->Reset();
		}
	}

	if (m_state != nullptr) {
		m_state->stateUserData = nullptr;
		if (m_ownState != 0) {
			lua_close(m_state);
		}
	}
}

/**
 * Address: 0x004C99B0 (FUN_004C99B0, LuaState scalar deleting destructor thunk)
 *
 * What it does:
 * Runs `LuaState` non-deleting destruction, then conditionally releases the
 * object storage when the scalar-delete flag bit is set.
 */
LuaState* DestroyLuaStateWithDeleteFlag(LuaState* const state, const std::uint8_t deleteFlag)
{
	state->~LuaState();
	if ((deleteFlag & 1u) != 0u) {
		::operator delete(state);
	}
	return state;
}

/**
 * Address: 0x0090A7D0 (FUN_0090A7D0, LuaPlus::LuaState::SetState)
 *
 * What it does:
 * Binds this wrapper to an existing C `lua_State`, sets root thread/sentinel
 * ownership for main-thread lanes, and updates `stateUserData`.
 */
void LuaState::SetState(lua_State* const state)
{
	if (m_state != nullptr || m_rootState != nullptr) {
		throw LuaAssertion("m_state==NULL && m_rootState==NULL");
	}

	if (state->stateUserData != nullptr) {
		throw LuaAssertion("L->stateUserData == NULL");
	}

	lua_State* const mainThread = state->l_G->mainthread;
	if (mainThread == state) {
		m_rootState = this;
		m_state = state;
		m_ownState = 1;
		m_headObject.m_prev = nullptr;
		m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
		m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
		m_tailObject.m_next = nullptr;
		m_state->l_G->userGCFunction = &LuaPlusGCFunction;
		m_state->stateUserData = this;
		return;
	}

	m_rootState = mainThread->stateUserData;
	if (m_rootState == nullptr) {
		throw LuaAssertion("m_rootState");
	}

	m_state = state;
	m_threadObj.AssignThread(this);
	m_state->stateUserData = this;
}

/**
 * Address: 0x00921050 (FUN_00921050, lua_State::MemberSerialize)
 *
 * What it does:
 * Serializes raw lua_State stack/callframe/global/upvalue lanes for archive
 * persistence.
 */
/**
 * Address: 0x00921480 (FUN_00921480, func_SerializeNameLuaObject)
 *
 * What it does:
 * Resolves optional object-name indirection from global table
 * `"__serialize_name_for_object"` and returns a TString pointer when present.
 */
[[nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* state, TString* key);

[[nodiscard]] TString* ResolveSerializedNameForLuaObject(lua_State* const state, const Value value)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_name_for_object", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt != LUA_TTABLE) {
		return nullptr;
	}

	const auto* const gcObject = static_cast<const GCObject*>(value.p);
	if (gcObject == nullptr) {
		return nullptr;
	}

	TObject lookupKey{};
	lookupKey.tt = static_cast<int>(gcObject->gch.tt);
	lookupKey.value = value;

	const TObject* const lookupResult = luaH_get(static_cast<Table*>(serializeMapObject->value.p), &lookupKey);
	if (lookupResult->tt == LUA_TNIL) {
		return nullptr;
	}

	if (lookupResult->tt != LUA_TSTRING) {
		throw gpg::SerializationError("__serialize_name_for_object table must contain only string values");
	}

	return static_cast<TString*>(lookupResult->value.p);
}

/**
 * Address: 0x009216D0 (FUN_009216D0, TObject::MemberSerialize)
 *
 * What it does:
 * Serializes one tagged Lua value lane with optional named-object indirection
 * and type-specific payload dispatch.
 */
void TObject::MemberSerialize(
	gpg::WriteArchive* const archive,
	TObject* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	if (object->tt > LUA_TSTRING) {
		lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
		if (TString* const serializedName = ResolveSerializedNameForLuaObject(ownerState, object->value);
			serializedName != nullptr) {
			archive->WriteInt(-2);
			archive->WriteTString(serializedName, *ownerRef);
			return;
		}
	}

	archive->WriteInt(object->tt);
	switch (object->tt) {
	case LUA_TBOOLEAN:
		archive->WriteInt(object->value.b);
		return;
	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");
	case LUA_TNUMBER:
		archive->WriteValue(&object->value, 0);
		return;
	case LUA_TSTRING:
		archive->WriteTString(static_cast<TString*>(object->value.p), *ownerRef);
		return;
	case LUA_TTABLE:
		archive->WriteTTable(static_cast<Table*>(object->value.p), *ownerRef);
		return;
	case LUA_CFUNCTION:
		archive->WriteCFunction(static_cast<CClosure*>(object->value.p), *ownerRef);
		return;
	case LUA_TFUNCTION:
		archive->WriteFunction(static_cast<LClosure*>(object->value.p), *ownerRef);
		return;
	case LUA_TUSERDATA:
		archive->WriteUserdata(static_cast<Udata*>(object->value.p), *ownerRef);
		return;
	case LUA_TTHREAD:
		archive->WriteTThread(static_cast<lua_State*>(object->value.p), *ownerRef);
		return;
	default:
		return;
	}
}

/**
 * Address: 0x009226F0 (FUN_009226F0, TObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes one tagged Lua value lane with named-object lookup support and
 * type-specific payload dispatch.
 */
void TObject::MemberDeserialize(
	gpg::ReadArchive* const archive,
	TObject* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	int typeCode = LUA_TNIL;
	archive->ReadInt(&typeCode);
	switch (typeCode) {
	case -2: {
		lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
		TString* serializedName = nullptr;
		(void)archive->ReadPointer_TString(&serializedName, ownerRef);

		const TObject* const resolvedObject = ResolveSerializedObjectNameEntry(ownerState, serializedName);
		if (resolvedObject->tt == LUA_TNIL) {
			throw gpg::SerializationError("Named script object not found");
		}

		*object = *resolvedObject;
		return;
	}

	case LUA_TNONE:
	case LUA_TNIL:
		object->tt = typeCode;
		object->value.p = nullptr;
		return;

	case LUA_TBOOLEAN: {
		int boolValue = 0;
		archive->ReadInt(&boolValue);
		object->tt = LUA_TBOOLEAN;
		object->value.b = boolValue;
		return;
	}

	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");

	case LUA_TNUMBER: {
		float numberValue = 0.0f;
		archive->ReadFloat(&numberValue);
		object->tt = LUA_TNUMBER;
		object->value.n = numberValue;
		return;
	}

	case LUA_TSTRING: {
		TString* stringValue = nullptr;
		(void)archive->ReadPointer_TString(&stringValue, ownerRef);
		object->tt = LUA_TSTRING;
		object->value.p = stringValue;
		return;
	}

	case LUA_TTABLE: {
		Table* tableValue = nullptr;
		(void)archive->ReadPointer_Table(&tableValue, ownerRef);
		object->tt = LUA_TTABLE;
		object->value.p = tableValue;
		return;
	}

	case LUA_CFUNCTION:
		throw gpg::SerializationError("C functions must be saved by name, not value");

	case LUA_TFUNCTION: {
		LClosure* functionValue = nullptr;
		(void)archive->ReadPointer_LClosure(&functionValue, ownerRef);
		object->tt = LUA_TFUNCTION;
		object->value.p = functionValue;
		return;
	}

	case LUA_TUSERDATA: {
		Udata* userdataValue = nullptr;
		(void)archive->ReadPointer_Udata(&userdataValue, ownerRef);
		object->tt = LUA_TUSERDATA;
		object->value.p = userdataValue;
		return;
	}

	case LUA_TTHREAD: {
		lua_State* threadValue = nullptr;
		(void)archive->ReadPointer_lua_State(&threadValue, ownerRef);
		object->tt = LUA_TTHREAD;
		object->value.p = threadValue;
		return;
	}

	default:
		throw gpg::SerializationError("Unknown type code for lua value");
	}
}

/**
 * Address: 0x00920DA0 (FUN_00920DA0, LClosure::MemberSerialize)
 *
 * What it does:
 * Serializes one closure's proto pointer, global-object lane, and upvalue
 * pointer array lanes.
 */
void LClosure::MemberSerialize(
	gpg::WriteArchive* const archive,
	LClosure* const object,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	gpg::RRef protoRef{};
	(void)gpg::RRef_Proto(&protoRef, object->p);
	gpg::WriteRawPointer(archive, protoRef, gpg::TrackedPointerState::Unowned, owner);

	archive->Write(CachedType<TObject>(gLuaTObjectType), &object->g, owner);

	for (std::uint8_t upvalueIndex = 0; upvalueIndex < object->nupvalues; ++upvalueIndex) {
		gpg::RRef upvalueRef{};
		(void)gpg::RRef_UpVal(&upvalueRef, object->upvals[upvalueIndex]);
		gpg::WriteRawPointer(archive, upvalueRef, gpg::TrackedPointerState::Unowned, owner);
	}
}

/**
 * Address: 0x00920E40 (FUN_00920E40, Proto::MemberSerialize)
 *
 * What it does:
 * Serializes proto scalar metadata, constants/code/nested-proto lanes, and
 * debug name/source pointer lanes.
 */
void Proto::MemberSerialize(
	gpg::WriteArchive* const archive,
	Proto* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	archive->WriteInt(object->sizeupvalues);
	archive->WriteInt(object->sizek);
	archive->WriteInt(object->sizecode);
	archive->WriteInt(object->sizelineinfo);
	archive->WriteInt(object->sizep);
	archive->WriteInt(object->sizelocvars);
	archive->WriteInt(object->lineDefined);
	archive->WriteUByte(object->nups);
	archive->WriteUByte(object->numparams);
	archive->WriteUByte(object->is_vararg);
	archive->WriteUByte(object->maxstacksize);

	for (int index = 0; index < object->sizek; ++index) {
		archive->Write(CachedType<TObject>(gLuaTObjectType), &object->k[index], owner);
	}

	archive->WriteBytes(reinterpret_cast<char*>(object->code), sizeof(Instruction) * static_cast<std::size_t>(object->sizecode));

	for (int index = 0; index < object->sizep; ++index) {
		gpg::RRef protoRef{};
		(void)gpg::RRef_Proto(&protoRef, object->p[index]);
		gpg::WriteRawPointer(archive, protoRef, gpg::TrackedPointerState::Unowned, owner);
	}

	for (int index = 0; index < object->sizelineinfo; ++index) {
		archive->WriteInt(object->lineinfo[index]);
	}

	for (int index = 0; index < object->sizelocvars; ++index) {
		gpg::RRef localNameRef{};
		(void)gpg::RRef_TString(&localNameRef, object->locvars[index].varname);
		gpg::WriteRawPointer(archive, localNameRef, gpg::TrackedPointerState::Unowned, owner);
		archive->WriteInt(object->locvars[index].startpc);
		archive->WriteInt(object->locvars[index].endpc);
	}

	for (int index = 0; index < object->nups; ++index) {
		gpg::RRef upvalueNameRef{};
		(void)gpg::RRef_TString(&upvalueNameRef, object->upvalues[index]);
		gpg::WriteRawPointer(archive, upvalueNameRef, gpg::TrackedPointerState::Unowned, owner);
	}

	gpg::RRef sourceRef{};
	(void)gpg::RRef_TString(&sourceRef, object->source);
	gpg::WriteRawPointer(archive, sourceRef, gpg::TrackedPointerState::Unowned, owner);
}

/**
 * Address: 0x00922B20 (FUN_00922B20, Proto::MemberDeserialize)
 *
 * What it does:
 * Deserializes proto scalar metadata, constants/code/nested-proto lanes, and
 * debug name/source pointer lanes, then validates bytecode consistency.
 */
void Proto::MemberDeserialize(
	gpg::ReadArchive* const archive,
	Proto* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");

	archive->ReadInt(&object->sizeupvalues);
	archive->ReadInt(&object->sizek);
	archive->ReadInt(&object->sizecode);
	archive->ReadInt(&object->sizelineinfo);
	archive->ReadInt(&object->sizep);
	archive->ReadInt(&object->sizelocvars);
	archive->ReadInt(&object->lineDefined);
	archive->ReadUByte(&object->nups);
	archive->ReadUByte(&object->numparams);
	archive->ReadUByte(&object->is_vararg);
	archive->ReadUByte(&object->maxstacksize);

	const gpg::RRef& owner = *ownerRef;
	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);

	object->k = static_cast<TObject*>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(TObject) * static_cast<std::size_t>(object->sizek))
	));
	for (int index = 0; index < object->sizek; ++index) {
		archive->Read(tObjectType, &object->k[index], owner);
	}

	object->code = static_cast<Instruction*>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(Instruction) * static_cast<std::size_t>(object->sizecode))
	));
	archive->ReadBytes(
		reinterpret_cast<char*>(object->code),
		sizeof(Instruction) * static_cast<std::size_t>(object->sizecode)
	);

	object->p = static_cast<Proto**>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(Proto*) * static_cast<std::size_t>(object->sizep))
	));
	for (int index = 0; index < object->sizep; ++index) {
		archive->ReadPointer_Proto(&object->p[index], ownerRef);
	}

	object->lineinfo = static_cast<int*>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(int) * static_cast<std::size_t>(object->sizelineinfo))
	));
	for (int index = 0; index < object->sizelineinfo; ++index) {
		archive->ReadInt(&object->lineinfo[index]);
	}

	object->locvars = static_cast<LocVar*>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(LocVar) * static_cast<std::size_t>(object->sizelocvars))
	));
	for (int index = 0; index < object->sizelocvars; ++index) {
		archive->ReadPointer_TString(&object->locvars[index].varname, ownerRef);
		archive->ReadInt(&object->locvars[index].startpc);
		archive->ReadInt(&object->locvars[index].endpc);
	}

	object->upvalues = static_cast<TString**>(luaM_realloc(
		ownerState,
		nullptr,
		0u,
		static_cast<lu_mem>(sizeof(TString*) * static_cast<std::size_t>(object->nups))
	));
	for (int index = 0; index < object->nups; ++index) {
		archive->ReadPointer_TString(&object->upvalues[index], ownerRef);
	}

	archive->ReadPointer_TString(&object->source, ownerRef);
	if (!luaG_checkcode(object)) {
		throw gpg::SerializationError("Consistency check failed: luaG_checkcode(&value)");
	}
}

/**
 * Address: 0x00920530 (FUN_00920530, Table::MemberSerialize)
 *
 * What it does:
 * Serializes table metatable pointer lane, dense array payload lanes, and
 * non-empty hash key/value lanes.
 */
void Table::MemberSerialize(
	gpg::WriteArchive* const archive,
	Table* const object,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	gpg::RRef metatableRef{};
	(void)gpg::RRef_Table(&metatableRef, object->metatable);
	gpg::WriteRawPointer(archive, metatableRef, gpg::TrackedPointerState::Unowned, *ownerRef);

	const int hashNodeCount = 1 << object->lsizenode;
	int nonEmptyHashCount = 0;
	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		if (object->node[hashIndex].i_val.tt != LUA_TNIL) {
			++nonEmptyHashCount;
		}
	}
	archive->WriteInt(nonEmptyHashCount);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int arrayIndex = 0; arrayIndex < object->sizearray; ++arrayIndex) {
		archive->Write(tObjectType, &object->array[arrayIndex], *ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		Node* const node = &object->node[hashIndex];
		if (node->i_val.tt == LUA_TNIL) {
			continue;
		}

		archive->Write(tObjectType, &node->i_key, *ownerRef);
		archive->Write(tObjectType, &node->i_val, *ownerRef);
	}
}

/**
 * Address: 0x00922950 (FUN_00922950, Table::MemberDeserialize)
 *
 * What it does:
 * Deserializes table metatable pointer lane, dense-array element lanes, and
 * hashed key/value lanes under owner GC traversal lock.
 */
void Table::MemberDeserialize(
	gpg::ReadArchive* const archive,
	Table* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	(void)archive->ReadPointer_Table(&object->metatable, &ownerRef);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	int hashEntryCount = 0;
	archive->ReadInt(&hashEntryCount);

	for (int arrayIndex = 1; arrayIndex <= object->sizearray; ++arrayIndex) {
		TObject* const destinationSlot = luaH_setnum(ownerState, object, arrayIndex);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashEntryCount; ++hashIndex) {
		TObject key{};
		archive->Read(tObjectType, &key, ownerRef);
		TObject* const destinationSlot = luaH_set(ownerState, object, &key);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}
}

/**
 * Address: 0x009207E0 (FUN_009207E0, Udata::MemberSerialize)
 *
 * What it does:
 * Uses the owner Lua-thread lane as serialization context, writes userdata
 * metatable pointer as unowned tracked reference, then serializes userdata
 * payload through the stored runtime `RType`.
 */
void Udata::MemberSerialize(
	gpg::WriteArchive* const archive,
	Udata* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	gpg::RRef metatableRef{};
	(void)gpg::RRef_Table(&metatableRef, object->metatable);
	gpg::WriteRawPointer(archive, metatableRef, gpg::TrackedPointerState::Unowned, *ownerRef);

	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(object->len);
	const void* const payload = reinterpret_cast<const std::uint8_t*>(object) + sizeof(Udata);
	archive->Write(payloadType, payload, *ownerRef);
}

/**
 * Address: 0x00923170 (FUN_00923170, Udata::MemberDeserialize)
 *
 * What it does:
 * Deserializes userdata metatable pointer lane and typed payload bytes using
 * one owning Lua thread traversal lock lane from `ownerRef`.
 */
void Udata::MemberDeserialize(
	gpg::ReadArchive* const archive,
	Udata* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	(void)archive->ReadPointer_Table(&object->metatable, &ownerRef);
	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(object->len);
	void* const payload = reinterpret_cast<std::uint8_t*>(object) + sizeof(Udata);
	archive->Read(payloadType, payload, ownerRef);
}

/**
 * Address: 0x00922AB0 (FUN_00922AB0, LClosure::MemberDeserialize)
 *
 * What it does:
 * Deserializes prototype/global-object/upvalue pointer lanes for one Lua
 * closure object.
 */
void LClosure::MemberDeserialize(
	gpg::ReadArchive* const archive,
	LClosure* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	archive->ReadPointer_Proto(&object->p, &ownerRef);
	archive->Read(CachedType<TObject>(gLuaTObjectType), &object->g, ownerRef);

	UpVal** upvalueLane = object->upvals;
	for (std::uint8_t upvalueIndex = 0; upvalueIndex < object->nupvalues; ++upvalueIndex, ++upvalueLane) {
		archive->ReadPointer_UpVal(upvalueLane, &ownerRef);
	}
}

/**
 * Address: 0x00922DD0 (FUN_00922DD0, lua_State::MemberDeserialize)
 *
 * What it does:
 * Restores one Lua thread stack/callframe/global/upvalue lane set from a
 * serialized archive payload.
 */
void lua_State::MemberDeserialize(
	gpg::ReadArchive* const archive,
	lua_State* const state,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(state != nullptr, "state");

	int stackSize = 0;
	int topIndex = 0;
	int baseIndex = 0;
	archive->ReadInt(&stackSize);
	archive->ReadInt(&topIndex);
	archive->ReadInt(&baseIndex);

	if (baseIndex < 0 || baseIndex > topIndex || topIndex > stackSize) {
		throw gpg::SerializationError("Consistency check failed: 0 <= ibase && ibase <= itop && itop <= stacksize");
	}

	luaD_reallocstack(state, stackSize);

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;
	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int stackIndex = 0; stackIndex < topIndex; ++stackIndex) {
		archive->Read(tObjectType, &state->stack[stackIndex], owner);
	}

	TObject* const stackBase = state->stack;
	state->base = &stackBase[baseIndex];
	state->top = &stackBase[topIndex];

	std::uint16_t callInfoCapacity = 0u;
	archive->ReadUShort(&callInfoCapacity);
	luaD_reallocCI(state, static_cast<int>(callInfoCapacity));

	std::uint16_t currentCallInfoIndex = 0u;
	archive->ReadUShort(&currentCallInfoIndex);
	if (currentCallInfoIndex >= callInfoCapacity) {
		throw gpg::SerializationError("Consistency check failed: ici < size_ci");
	}

	state->ci = &state->base_ci[currentCallInfoIndex];

	for (std::uint16_t callInfoIndex = 0; callInfoIndex <= currentCallInfoIndex; ++callInfoIndex) {
		CallInfo* const callInfo = state->base_ci + callInfoIndex;

		int ciBaseByteOffset = 0;
		int ciTopByteOffset = 0;
		archive->ReadInt(&ciBaseByteOffset);
		archive->ReadInt(&ciTopByteOffset);

		if (ciBaseByteOffset < 0) {
			throw gpg::SerializationError("Consistency check failed: 0 <= cibase");
		}
		if (ciBaseByteOffset > ciTopByteOffset) {
			throw gpg::SerializationError("Consistency check failed: cibase <= citop");
		}
		if (ciTopByteOffset > static_cast<int>(sizeof(TObject) * static_cast<std::size_t>(state->stacksize))) {
			throw gpg::SerializationError("Consistency check failed: citop <= (int)(value.stacksize*sizeof(TObject))");
		}

		auto* const stackBytes = reinterpret_cast<std::uint8_t*>(state->stack);
		callInfo->base = reinterpret_cast<TObject*>(stackBytes + ciBaseByteOffset);
		callInfo->top = reinterpret_cast<TObject*>(stackBytes + ciTopByteOffset);

		archive->ReadInt(&callInfo->state);
		archive->ReadInt(&callInfo->tailcalls);

		if (callInfo->state < 3) {
			int savedProgramCounterIndex = 0;
			archive->ReadInt(&savedProgramCounterIndex);

			const TObject* const functionSlot = callInfo->base - 1;
			const auto* const closure = static_cast<const Closure*>(functionSlot->value.p);
			const Instruction* const codeBase = closure->l.p->code;
			callInfo->savedpc = codeBase + savedProgramCounterIndex;
		} else {
			callInfo->savedpc = nullptr;
		}
	}

	archive->Read(tObjectType, &state->_gt, owner);

	int upvalueLastStackIndex = topIndex;
	GCObject** openUpvalueInsert = &state->openupval;

	int upvalueStackIndex = -1;
	archive->ReadInt(&upvalueStackIndex);
	while (upvalueStackIndex != -1) {
		if (upvalueStackIndex < 0 || upvalueStackIndex >= upvalueLastStackIndex) {
			throw gpg::SerializationError("Consistency check failed: 0 <= stackindex && stackindex < upval_last_stackindex");
		}

		UpVal* upvalue = nullptr;
		archive->ReadPointer_UpVal(&upvalue, &owner);
		if (upvalue == nullptr) {
			throw gpg::SerializationError("Consistency check failed: u");
		}
		if (upvalue->v != &upvalue->value) {
			throw gpg::SerializationError("Consistency check failed: u->v == &u->value");
		}

		auto* const upvalueObject = reinterpret_cast<GCObject*>(upvalue);
		GCObject** link = &state->openupval;
		while (*link != nullptr && *link != upvalueObject) {
			link = &(*link)->gch.next;
		}
		if (*link == upvalueObject) {
			*link = upvalueObject->gch.next;
			upvalueObject->gch.next = nullptr;
		}

		upvalue->v = &state->stack[upvalueStackIndex];
		*openUpvalueInsert = upvalueObject;
		openUpvalueInsert = &upvalueObject->gch.next;

		upvalueLastStackIndex = upvalueStackIndex;
		archive->ReadInt(&upvalueStackIndex);
	}
}

void lua_State::MemberSerialize(
	gpg::WriteArchive* const archive,
	lua_State* const state,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(state != nullptr, "state");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	TObject* const stackBase = state->stack;
	const int baseIndex = static_cast<int>(state->base - stackBase);
	const int topIndex = static_cast<int>(state->top - stackBase);

	archive->WriteInt(state->stacksize);
	archive->WriteInt(baseIndex);
	archive->WriteInt(topIndex);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int index = 0; index < topIndex; ++index) {
		archive->Write(tObjectType, &stackBase[index], owner);
	}

	archive->WriteUShort(state->size_ci);
	const std::uint16_t currentCallInfoIndex = static_cast<std::uint16_t>(state->ci - state->base_ci);
	archive->WriteUShort(currentCallInfoIndex);

	for (std::uint16_t callInfoIndex = 0; callInfoIndex <= currentCallInfoIndex; ++callInfoIndex) {
		CallInfo* const callInfo = state->base_ci + callInfoIndex;

		const int callInfoBaseByteOffset = static_cast<int>(
			reinterpret_cast<const std::uint8_t*>(callInfo->base) - reinterpret_cast<const std::uint8_t*>(stackBase)
		);
		const int callInfoTopByteOffset = static_cast<int>(
			reinterpret_cast<const std::uint8_t*>(callInfo->top) - reinterpret_cast<const std::uint8_t*>(stackBase)
		);

		archive->WriteInt(callInfoBaseByteOffset);
		archive->WriteInt(callInfoTopByteOffset);
		archive->WriteInt(callInfo->state);
		archive->WriteInt(callInfo->tailcalls);

		if (callInfo->state < 3) {
			const TObject* const functionSlot = callInfo->base - 1;
			const auto* const closure = static_cast<const Closure*>(functionSlot->value.p);
			const Instruction* const codeBase = closure->l.p->code;
			archive->WriteInt(static_cast<int>(callInfo->savedpc - codeBase));
		}
	}

	archive->Write(tObjectType, &state->_gt, owner);

	for (GCObject* openUpval = state->openupval; openUpval != nullptr; openUpval = openUpval->gch.next) {
		UpVal* const upvalue = &openUpval->uv;
		archive->WriteInt(static_cast<int>(upvalue->v - stackBase));

		gpg::RRef upvalueRef{};
		(void)gpg::RRef_UpVal(&upvalueRef, upvalue);
		gpg::WriteRawPointer(archive, upvalueRef, gpg::TrackedPointerState::Unowned, owner);
	}

	archive->WriteInt(-1);
}

/**
 * Address: 0x0090B8F0 (FUN_0090B8F0, LuaPlus::LuaState::MemberSerialize)
 *
 * What it does:
 * Serializes root/current LuaState pointer lanes for archive ownership
 * restoration.
 */
void LuaState::MemberSerialize(gpg::WriteArchive* const archive, LuaState* const state)
{
	Ensure(archive != nullptr, "archive");
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");

	gpg::RRef rootStateRef{};
	(void)gpg::RRef_LuaState(&rootStateRef, state->m_rootState);
	gpg::WriteRawPointer(archive, rootStateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

	gpg::RRef currentStateRef{};
	(void)gpg::RRef_lua_State(&currentStateRef, state->m_state);
	gpg::WriteRawPointer(archive, currentStateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
}

LuaState* LuaState::GetActiveState()
{
	if (!m_state || !m_state->l_G || !m_state->l_G->lstate) {
		return nullptr;
	}
	return m_state->l_G->lstate->stateUserData;
}

lua_State* LuaState::GetActiveCState()
{
	if (!m_state || !m_state->l_G) {
		return nullptr;
	}
	return m_state->l_G->lstate;
}

lua_State* LuaState::GetCState() const
{
	return m_state;
}

/**
 * Address: 0x1000A4A0 (?GetGlobals@LuaState@LuaPlus@@QAE?AVLuaObject@2@XZ)
 */
LuaObject LuaState::GetGlobals()
{
	if (!m_state) {
		return {};
	}

	return LuaObject(this, LUA_GLOBALSINDEX);
}

/**
 * Address: 0x0090A510 (FUN_0090A510, LuaPlus::LuaState::CastState)
 *
 * What it does:
 * Returns the C++ wrapper pointer stored in `lua_State::stateUserData`.
 */
LuaState* LuaState::CastState(lua_State* const state)
{
	return state->stateUserData;
}

/**
 * Address: 0x10008F20 (?GetGlobal@LuaState@LuaPlus@@QAE?AVLuaObject@2@PBD@Z)
 */
LuaObject LuaState::GetGlobal(const char* name)
{
	LuaObject globals = GetGlobals();
	return globals[name ? name : ""];
}

LuaState* LuaState::GetRootState()
{
	return m_rootState;
}

const LuaState* LuaState::GetRootState() const
{
	return m_rootState;
}

const LuaObject* LuaState::GetThreadObject() const
{
	return &m_threadObj;
}

/**
 * Address: 0x004CCA70 (FUN_004CCA70)
 *
 * What it does:
 * Bridges one `lua_State*` slot in `ECX` into `lua_call(L, nargs, nresults)`,
 * preserving the original thiscall adapter stack shape.
 */
__declspec(naked) void __stdcall LuaStateSlotCallBridge(
	const int /*nargs*/,
	const int /*nresults*/
)
{
	__asm
	{
		mov     eax, [esp+8]
		mov     edx, [esp+4]
		push    eax
		mov     eax, [ecx]
		push    edx
		push    eax
		call    lua_call
		add     esp, 0Ch
		retn    8
	}
}

/**
 * Address: 0x004CCA90 (FUN_004CCA90)
 *
 * What it does:
 * Bridges register/stack lanes into `luaL_loadbuffer(*slot, buff, size, name)`
 * using the original stdcall adapter sequence.
 */
__declspec(naked) void __stdcall LuaStateSlotLoadBufferBridge(lua_State** /*stateSlot*/)
{
	__asm
	{
		push    eax
		mov     eax, [esp+8]
		push    ecx
		mov     ecx, [eax]
		push    edx
		push    ecx
		call    luaL_loadbuffer
		add     esp, 10h
		retn    4
	}
}

/**
 * Address: 0x004CCAB0 (FUN_004CCAB0)
 *
 * What it does:
 * Pops one value from a Lua stack slot by rebasing top to `-2`.
 */
[[maybe_unused]] static void LuaStateSlotPopOne(lua_State** const stateSlot)
{
	lua_settop(*stateSlot, -2);
}

/**
 * Address: 0x004CCA10 (FUN_004CCA10, LuaPlus::LuaState::PushNil)
 *
 * What it does:
 * Pushes nil to this state's Lua stack and returns a stack-object view for
 * the pushed value.
 */
LuaStackObject LuaState::PushNil()
{
	lua_pushnil(m_state);
	return LuaStackObject(this, lua_gettop(m_state));
}

/**
 * Address: 0x004CCA30 (FUN_004CCA30, LuaPlus::LuaState::PushNumber)
 *
 * What it does:
 * Pushes one numeric value to this state's Lua stack and returns a stack view
 * for the pushed value.
 */
LuaStackObject LuaState::PushNumber(const float n)
{
	lua_pushnumber(m_state, n);
	return LuaStackObject(this, lua_gettop(m_state));
}

LuaStackObject LuaState::Stack(const int32_t index)
{
	return LuaStackObject(this, index);
}

/**
 * Address: 0x0090BFB0 (FUN_0090BFB0, LuaPlus::LuaState::CheckString)
 *
 * What it does:
 * Validates stack slot `index` as string/coercible and returns Lua's internal
 * string pointer + optional byte length.
 */
const char* LuaState::CheckString(const int32_t index, size_t* const lengthOut)
{
	return luaL_checklstring(m_state, index, lengthOut);
}

/**
 * Address: 0x0090C170 (FUN_0090C170, LuaPlus::LuaState::CheckAny)
 *
 * What it does:
 * Raises a Lua argument error when stack slot `index` is missing.
 */
void LuaState::CheckAny(const int32_t index)
{
	luaL_checkany(m_state, index);
}

/**
 * Address: 0x0090BF90 (FUN_0090BF90)
 *
 * What it does:
 * Raises one Lua argument error for argument lane `narg`.
 */
int LuaState::ArgError(const int narg, char* const extraMessage)
{
	return luaL_argerror(m_state, narg, extraMessage);
}

/**
 * Address: 0x0090BFD0 (FUN_0090BFD0)
 *
 * What it does:
 * Returns optional string argument `narg` or `defaultValue`, and writes string
 * byte length when `lengthOut` is non-null.
 */
const char* LuaState::OptString(const int narg, char* const defaultValue, size_t* const lengthOut)
{
	return luaL_optlstring(m_state, narg, defaultValue, lengthOut);
}

/**
 * Address: 0x0090BFF0 (FUN_0090BFF0)
 *
 * What it does:
 * Validates numeric argument `index` and returns its number lane.
 */
lua_Number LuaState::CheckNumber(const int index)
{
	return luaL_checknumber(m_state, index);
}

/**
 * Address: 0x0090C010 (FUN_0090C010)
 *
 * What it does:
 * Returns optional numeric argument `index` or `defaultValue`.
 */
lua_Number LuaState::OptNumber(const int index, const lua_Number defaultValue)
{
	return luaL_optnumber(m_state, index, defaultValue);
}

int32_t LuaState::GetTop() const
{
	return m_state ? lua_gettop(m_state) : 0;
}

bool LuaState::IsRootState() const
{
	return m_rootState == this;
}

bool LuaState::IsSuspended() const
{
	// lua_suspended() is not surfaced in this SDK build yet.
	return false;
}

/**
 * Address: 0x0090C1D0 (FUN_0090C1D0, ?Error@LuaState@LuaPlus@@QAAHPBDZZ)
 *
 * What it does:
 * Formats one varargs error string on the Lua stack and raises `lua_error`.
 */
void LuaState::Error(LuaState* const state, const char* const format, ...)
{
	va_list args;
	va_start(args, format);
	lua_pushvfstring(state->m_state, format, args);
	va_end(args);
	lua_error(state->m_state);
}

/**
 * Address: 0x00415490 (FUN_00415490, LuaPlus::LuaStackObject::LuaStackObject)
 */
LuaStackObject::LuaStackObject(LuaState* state, const int32_t stackIndex)
	: m_state(state),
	  m_stackIndex(stackIndex)
{
}

/**
 * Address: 0x00456AE0 (FUN_00456AE0, sub_456AE0)
 *
 * LuaState *,char const *
 *
 * What it does:
 * Pushes one C-string onto the Lua state stack and returns a stack-object
 * view for the pushed slot.
 */
LuaStackObject LuaPlus::PushStringAndCaptureStackObject(LuaState* const state, const char* const value)
{
	lua_pushstring(state->m_state, value);
	return LuaStackObject(state, lua_gettop(state->m_state));
}

bool LuaStackObject::IsNil() const
{
	return !m_state || !m_state->GetCState() || lua_type(m_state->GetCState(), m_stackIndex) == LUA_TNIL;
}

/**
 * Address: 0x004154B0 (FUN_004154B0, LuaPlus::LuaStackObject::TypeError)
 *
 * What it does:
 * Raises the standard Lua bad-argument error for the current stack slot.
 */
void LuaStackObject::TypeError(const char* const expectedType) const
{
	luaL_argerror(m_state->GetCState(), m_stackIndex, expectedType ? expectedType : "value");
}

void LuaStackObject::TypeError(const char* const expectedType, const int32_t) const
{
	TypeError(expectedType);
}

void LuaStackObject::TypeError(LuaStackObject* const self, const char* const expectedType)
{
	if (self != nullptr) {
		self->TypeError(expectedType);
	}
}

/**
 * Address: 0x00415530 (FUN_00415530, LuaPlus::LuaStackObject::GetString)
 *
 * What it does:
 * Returns the string view for the current stack slot, coercing via Lua and
 * raising a type error when conversion fails.
 */
const char* LuaStackObject::GetString() const
{
	const char* const str = lua_tostring(m_state->GetCState(), m_stackIndex);
	if (!str) {
		TypeError("string");
	}
	return str;
}

/**
 * Address: 0x0041B520 (FUN_0041B520, LuaPlus::LuaStackObject::GetInteger)
 *
 * What it does:
 * Reads one integer lane from the current Lua stack slot and raises a type
 * error when the slot is not numeric.
 */
int32_t LuaStackObject::GetInteger() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("integer");
	}
	return static_cast<int32_t>(lua_tonumber(cState, m_stackIndex));
}

/**
 * Address: 0x004CCB00 (FUN_004CCB00, LuaPlus::LuaStackObject::ToNumber)
 *
 * What it does:
 * Validates that the current stack lane is numeric and returns one Lua number
 * payload; raises `TypeError(\"number\")` for non-numeric values.
 */
double LuaStackObject::ToNumber() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("number");
	}
	return lua_tonumber(cState, m_stackIndex);
}

/**
 * Address: 0x00415560 (FUN_00415560, LuaPlus::LuaStackObject::GetBoolean)
 *
 * What it does:
 * Reads the current stack slot as a Lua boolean, allowing nil as false and
 * raising a type error for other non-boolean values.
 */
bool LuaStackObject::GetBoolean() const
{
	const int type = lua_type(m_state->GetCState(), m_stackIndex);
	if (type != LUA_TBOOLEAN && type != LUA_TNIL) {
		TypeError("boolean");
	}
	return lua_toboolean(m_state->GetCState(), m_stackIndex) != 0;
}

/**
 * Address: 0x00528140 (FUN_00528140, LuaPlus::LuaStackObject::GetByName)
 *
 * What it does:
 * Pushes `name`, performs one raw lookup against this stack slot, and returns
 * a stack-object view of the lookup result.
 */
LuaStackObject LuaStackObject::GetByName(const char* const name) const
{
	lua_State* const cState = m_state->GetCState();
	lua_pushstring(cState, name);
	lua_rawget(cState, m_stackIndex);
	return LuaStackObject(m_state, lua_gettop(cState));
}

/**
 * Address: 0x005280F0 (FUN_005280F0)
 *
 * What it does:
 * Reads one Lua stack-object lane pair `(state, stackIndex)` and returns the
 * legacy `lua_getn` length for that stack slot.
 */
int32_t GetLuaStackObjectLengthLegacy(const LuaStackObject* const stackObject)
{
	return lua_getn(stackObject->m_state->GetCState(), stackObject->m_stackIndex);
}

namespace
{
	class VirtualLaneDispatchTarget
	{
	public:
		virtual std::uint32_t DispatchLane0() = 0;
		virtual std::uint32_t DispatchLane1() = 0;
		virtual std::uint32_t DispatchLane2() = 0;
		virtual std::uint32_t DispatchLane3() = 0;
		virtual std::uint32_t DispatchLane4() = 0;
		virtual std::uint32_t DispatchMainLane() = 0;
	};

	struct VirtualLaneDispatchSlotView
	{
		VirtualLaneDispatchTarget* mTarget;
	};

	struct AuxiliaryWordRuntimeView
	{
		std::uint8_t mOpaquePrefix[0x5C];
		std::uint32_t mAuxiliaryWord;
	};

	struct InlineOrHeapStringView
	{
		std::uint8_t mOpaquePrefix[0x0C];

		union Storage
		{
			const char* mHeapData;
			char mInlineData[16];
		} mStorage;

		std::uint32_t mCapacityOrFlags;
		std::uint32_t mLength;
	};

	struct PointerWordSourceView
	{
		std::uint32_t mOpaquePrefix;
		std::uint32_t* mWordPointer;
	};

	static_assert(offsetof(VirtualLaneDispatchSlotView, mTarget) == 0x00, "VirtualLaneDispatchSlotView::mTarget offset must be 0x00");
	static_assert(sizeof(VirtualLaneDispatchSlotView) == 0x04, "VirtualLaneDispatchSlotView size must be 0x04");
	static_assert(offsetof(AuxiliaryWordRuntimeView, mAuxiliaryWord) == 0x5C, "AuxiliaryWordRuntimeView::mAuxiliaryWord offset must be 0x5C");
	static_assert(offsetof(InlineOrHeapStringView, mStorage) == 0x0C, "InlineOrHeapStringView::mStorage offset must be 0x0C");
	static_assert(offsetof(InlineOrHeapStringView, mLength) == 0x20, "InlineOrHeapStringView::mLength offset must be 0x20");
	static_assert(offsetof(PointerWordSourceView, mWordPointer) == 0x04, "PointerWordSourceView::mWordPointer offset must be 0x04");
}

/**
 * Address: 0x005280B0 (FUN_005280B0)
 *
 * What it does:
 * Loads one object pointer from the dispatch slot and tail-calls its sixth
 * virtual lane.
 */
std::uint32_t InvokeMainVirtualLaneFromSlot(VirtualLaneDispatchSlotView* const slot)
{
	return slot->mTarget->DispatchMainLane();
}

/**
 * Address: 0x005281C0 (FUN_005281C0)
 *
 * What it does:
 * Returns one cached auxiliary 32-bit lane from the runtime view.
 */
std::uint32_t ReadAuxiliaryRuntimeWord(const AuxiliaryWordRuntimeView* const view)
{
	return view->mAuxiliaryWord;
}

/**
 * Address: 0x005281D0 (FUN_005281D0)
 *
 * What it does:
 * Returns inline string storage for short payloads and heap storage for long
 * payloads.
 */
const char* ResolveInlineOrHeapStringData(const InlineOrHeapStringView* const view)
{
	if (view->mLength < 0x10u) {
		return view->mStorage.mInlineData;
	}
	return view->mStorage.mHeapData;
}

/**
 * Address: 0x005281E0 (FUN_005281E0)
 *
 * What it does:
 * Stores one dereferenced 32-bit lane from the source pointer slot into
 * `outValue`.
 */
std::uint32_t* StoreIndirectWordFromPointerSlot(
	std::uint32_t* const outValue,
	const PointerWordSourceView* const source
)
{
	*outValue = *source->mWordPointer;
	return outValue;
}

/**
 * Address: 0x005281F0 (FUN_005281F0)
 *
 * What it does:
 * Stores one pointer-slot address lane into `outValue`.
 */
std::uint32_t* StorePointerSlotAddressWord(
	std::uint32_t* const outValue,
	const PointerWordSourceView* const source
)
{
	*outValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(source->mWordPointer));
	return outValue;
}

/**
 * Address: 0x009072B0 (FUN_009072B0, LuaPlus::LuaObject::GetActiveState)
 *
 * What it does:
 * Returns the active Lua wrapper state (`stateUserData`) from this object's
 * bound root C-state lane.
 */
LuaState* LuaObject::GetActiveState() const
{
	return m_state->m_state->l_G->lstate->stateUserData;
}

/**
 * Address: 0x009072C0 (FUN_009072C0, LuaPlus::LuaObject::GetActiveCState)
 *
 * What it does:
 * Returns the active C-state pointer through this object's bound root
 * wrapper lane.
 */
lua_State* LuaObject::GetActiveCState() const
{
	return m_state->m_state->l_G->lstate;
}

/**
 * Address: 0x0091E200 (FUN_0091E200, func_SerializeLuaObjectName)
 *
 * What it does:
 * Resolves one serialized-name lookup lane from globals key
 * `"__serialize_object_for_name"` and returns the matching table entry for
 * `key`, or Lua's canonical nil object lane when the globals slot is not a
 * table.
 */
[[maybe_unused, nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* const state, TString* const key)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_object_for_name", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt == LUA_TTABLE) {
		return luaH_getstr(static_cast<Table*>(serializeMapObject->value.p), key);
	}

	return &luaO_nilobject;
}

/**
 * Address: 0x0090B990 (FUN_0090B990, LuaPlus::LuaObject::MemberSerialize)
 *
 * What it does:
 * Serializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberSerialize(gpg::WriteArchive* const archive, LuaObject* const object)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	gpg::RRef stateRef{};
	(void)gpg::RRef_LuaState(&stateRef, object->m_state);
	gpg::WriteRawPointer(archive, stateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

	if (object->m_state != nullptr) {
		gpg::RRef ownerRef{};
		(void)gpg::RRef_lua_State(&ownerRef, object->m_state->m_state);
		archive->Write(CachedType<TObject>(gLuaTObjectType), &object->m_object, ownerRef);
	}
}

/**
 * Address: 0x0090BDD0 (FUN_0090BDD0, LuaPlus::LuaObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberDeserialize(
	gpg::ReadArchive* const archive,
	LuaObject* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	LuaState* state = nullptr;
	(void)archive->ReadPointer_LuaState(&state, &ownerRef);
	if (state != nullptr) {
		object->AssignNil(state);

		gpg::RRef stateOwner{};
		(void)gpg::RRef_lua_State(&stateOwner, object->m_state->m_state);
		archive->Read(CachedType<TObject>(gLuaTObjectType), &object->m_object, stateOwner);
		return;
	}

	*object = LuaObject{};
}

/**
 * Address: 0x009088E0 (FUN_009088E0, LuaPlus::LuaObject::AddToUsedObjectList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state` and
 * copies the caller-provided raw payload into `m_object`.
 */
void LuaObject::AddToUsedObjectList(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");
	Ensure(object != nullptr, "obj");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
	m_object = *object;
}

/**
 * Address: 0x009099B0 (FUN_009099B0, LuaPlus::LuaObject::AssignTObject)
 *
 * What it does:
 * Rebinds this object to the target root list only when the owner root
 * changes, then copies one caller-provided raw `TObject` payload.
 */
void LuaObject::AssignTObject(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");
	Ensure(object != nullptr, "obj");

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object = *object;
}

/**
 * Address: 0x00908890 (FUN_00908890, LuaPlus::LuaObject::AddToUsedList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state`,
 * preserving the current payload lane.
 */
void LuaObject::AddToUsedList(LuaState* state)
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
}

/**
 * Address: 0x009096F0 (FUN_009096F0, LuaPlus::LuaObject::AssignThread)
 *
 * What it does:
 * Rebinds this object to one thread `lua_State` payload and enforces root
 * ownership transition semantics for the intrusive used-object list.
 */
void LuaObject::AssignThread(LuaState* const state)
{
	if (state->m_rootState == state) {
		LuaState* const activeState = state->GetActiveState();
		luaG_runerror(activeState->m_state, "attempt to use main lua state as a thread");
	}

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.p = state->m_state;
	m_object.tt = state->m_state->tt;
}

/**
 * Address: 0x009075F0 (FUN_009075F0, LuaPlus::LuaObject::Reset)
 *
 * What it does:
 * Unlinks this object from the owning state intrusive list (when bound),
 * resets the tagged value to nil, and clears state ownership.
 */
void LuaObject::Reset()
{
	if (!m_state) {
		return;
	}

	if (m_prev && m_next) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
	}
	m_object.tt = LUA_TNIL;
	m_state = nullptr;
	m_next = nullptr;
	m_prev = nullptr;
}

/**
 * Address: 0x00907440 (FUN_00907440, LuaPlus::LuaObject::operator bool)
 *
 * What it does:
 * Applies Lua truthiness rules for this bound object:
 * nil is false, booleans return stored value, everything else is true.
 */
LuaObject::operator bool() const noexcept
{
	if (!m_state) {
		return false;
	}

	if (m_object.tt == LUA_TNIL) {
		return false;
	}

	if (m_object.tt == LUA_TBOOLEAN) {
		return m_object.value.b != 0;
	}

	return true;
}

/**
 * Address: 0x0090BF00 (FUN_0090BF00)
 *
 * What it does:
 * Performs Lua semantic equality on this value and `other` after matching
 * type tags.
 */
bool LuaObject::operator==(const LuaObject& other) const
{
	if (m_object.tt != other.m_object.tt) {
		return false;
	}

	return luaV_equalval(m_state->m_state, &m_object, &other.m_object) != 0;
}

/**
 * Address: 0x0090BF40 (FUN_0090BF40)
 *
 * What it does:
 * Performs Lua semantic less-than comparison between this value and `other`.
 */
bool LuaObject::operator<(const LuaObject& other) const
{
	return luaV_lessthan(m_state->m_state, &m_object, &other.m_object) != 0;
}

/**
 * Address: 0x009072F0 (FUN_009072F0, LuaPlus::LuaObject::IsNil)
 *
 * What it does:
 * Returns true only for state-bound objects tagged as nil.
 */
bool LuaObject::IsNil() const noexcept
{
	return m_state != nullptr && m_object.tt == LUA_TNIL;
}

/**
 * Address: 0x00907850 (FUN_00907850, LuaPlus::LuaObject::IsNone)
 *
 * What it does:
 * Asserts state binding and returns whether this object carries Lua's
 * `LUA_TNONE` sentinel tag.
 */
bool LuaObject::IsNone() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TNONE;
}

/**
 * Address: 0x009078D0 (FUN_009078D0, LuaPlus::LuaObject::IsBoolean)
 *
 * What it does:
 * Asserts state binding and returns whether this value is a boolean tag.
 */
bool LuaObject::IsBoolean() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TBOOLEAN;
}

/**
 * Address: 0x00907350 (FUN_00907350, LuaPlus::LuaObject::IsNumber)
 *
 * What it does:
 * Returns whether this value carries a numeric Lua tag.
 */
bool LuaObject::IsNumber() const noexcept
{
	return m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x0077F680 (FUN_0077F680, LuaObject::j_IsNumber2 thunk)
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::IsNumber`.
 */
bool LuaObjectIsNumberThunk2(const LuaObject* const object)
{
	return object->IsNumber();
}

/**
 * Address: 0x00907370 (FUN_00907370, LuaPlus::LuaObject::IsString)
 *
 * What it does:
 * Returns whether this value carries a string Lua tag.
 */
bool LuaObject::IsString() const noexcept
{
	return m_object.tt == LUA_TSTRING;
}

/**
 * Address: 0x00907890 (FUN_00907890, LuaPlus::LuaObject::IsLightUserData)
 *
 * What it does:
 * Asserts state binding and returns whether this value carries a light-
 * userdata tag.
 */
bool LuaObject::IsLightUserData() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TLIGHTUSERDATA;
}

/**
 * Address: 0x00907320 (FUN_00907320, LuaPlus::LuaObject::IsUserData)
 *
 * What it does:
 * Returns true for both full userdata and light userdata tags.
 */
bool LuaObject::IsUserData() const noexcept
{
	return m_object.tt == LUA_TUSERDATA || m_object.tt == LUA_TLIGHTUSERDATA;
}

/**
 * Address: 0x00907BC0 (FUN_00907BC0, LuaPlus::LuaObject::GetUserData)
 * Mangled: ?GetUserData@LuaObject@LuaPlus@@QBE?AVRRef@gpg@@XZ
 *
 * IDA signature:
 * gpg::RRef *__thiscall LuaPlus::LuaObject::GetUserData(
 *     LuaPlus::LuaObject *this, gpg::RRef *dest);
 *
 * What it does:
 * Builds the reflection reference a full userdata stands for.
 *
 * Only the full-userdata tag is accepted here - the light-userdata one that
 * `IsUserData` also answers to has no header to read a type out of, so it
 * takes the type-error path.
 *
 * The two loads are the whole contract, and they are worth stating because
 * both hand-rolled copies of this in the tree had them wrong:
 *
 *     lea edx, [ecx+10h]   ; mObj  = the object, laid out after the header
 *     mov ecx, [ecx+0Ch]   ; mType = Udata::len, reinterpreted as RType*
 *
 * This fork reuses `Udata::len` to carry the `gpg::RType*` rather than a
 * byte count, so the reference is assembled from the header and the payload
 * pointer. It is not a `gpg::RRef` stored inside the payload, and the type
 * does not sit inside the payload either.
 */
gpg::RRef LuaObject::GetUserData() const
{
	Ensure(m_state != nullptr, "m_state");

	if (m_object.tt != LUA_TUSERDATA) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as UserData");
	}

	auto* const userdata = static_cast<Udata*>(m_object.value.p);

	gpg::RRef out{};
	out.mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
	out.mType = reinterpret_cast<gpg::RType*>(userdata->len);
	return out;
}

/**
 * Address: 0x00907810 (FUN_00907810, LuaPlus::LuaObject::IsFunction)
 *
 * What it does:
 * Validates state ownership, then treats both Lua closure and C-function
 * tags as callable by checking `(tt | 1) == LUA_TFUNCTION`.
 */
bool LuaObject::IsFunction() const
{
	if (m_state == nullptr) {
		throw LuaAssertion("m_state");
	}

	return (m_object.tt | 1) == LUA_TFUNCTION;
}

/**
 * Address: 0x00907700 (FUN_00907700, LuaPlus::LuaObject::IsConvertibleToInteger)
 *
 * What it does:
 * Returns true when this value is already numeric or can be converted to one
 * via `luaV_tonumber`.
 */
bool LuaObject::IsConvertibleToInteger() const
{
	Ensure(m_state != nullptr, "m_state");

	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER) {
		return true;
	}

	return luaV_tonumber(&m_object, &numericValue) != 0;
}

/**
 * Address: 0x00907760 (FUN_00907760, LuaPlus::LuaObject::IsConvertibleToNumber)
 *
 * What it does:
 * Returns true when this value is already numeric or can be converted to one
 * via `luaV_tonumber`.
 */
bool LuaObject::IsConvertibleToNumber() const
{
	Ensure(m_state != nullptr, "m_state");

	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER) {
		return true;
	}

	return luaV_tonumber(&m_object, &numericValue) != 0;
}

/**
 * Address: 0x009077C0 (FUN_009077C0, LuaPlus::LuaObject::IsConvertibleToString)
 *
 * What it does:
 * Returns true when this value is already string or numeric.
 */
bool LuaObject::IsConvertibleToString() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TSTRING || m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
 *
 * What it does:
 * Raises one Lua-object operation type error for the current tagged value.
 */
void LuaObject::TypeError(const char* const operation) const
{
	lua_State* const cState = GetActiveCState();
	const char* const valueType = cState != nullptr ? lua_typename(cState, m_object.tt) : "unknown";
	const char* const opText = operation != nullptr ? operation : "operate on";

	std::string message("attempt to ");
	message += opText;
	message += " a ";
	message += valueType != nullptr ? valueType : "unknown";
	message += " value";
	throw std::runtime_error(message);
}

/**
 * Address: 0x009076D0 (FUN_009076D0, LuaPlus::LuaObject::Type)
 *
 * What it does:
 * Returns this object's raw Lua type tag.
 */
int LuaObject::Type() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt;
}

/**
 * Address: 0x00908B50 (FUN_00908B50, LuaPlus::LuaObject::TypeName)
 *
 * What it does:
 * Returns `"no value"` for `LUA_TNONE`; otherwise returns Lua's typename for
 * this object's current type tag.
 */
const char* LuaObject::TypeName() const
{
	Ensure(m_state != nullptr, "m_state");

	const int type = m_object.tt;
	if (type == LUA_TNONE) {
		return "no value";
	}
	return luaT_typenames[type];
}

void LuaObject::SetTableHelper(const char* key, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	PushTObject(lstate, *object);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00907510 (FUN_00907510)
 *
 * What it does:
 * Builds one numeric-key TValue and writes `valueSlot` into this object's
 * table lane using `luaV_settable`.
 */
void LuaObject::SetTableHelperRaw(const int32_t index, const StkId valueSlot)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(valueSlot != nullptr, "valueSlot");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);
	luaV_settable(lstate, &m_object, &key, valueSlot);
}

/**
 * Address: 0x00907550 (FUN_00907550)
 *
 * What it does:
 * Writes one table entry by Lua-object key through `luaV_settable` using one
 * caller-provided value slot.
 */
void LuaObject::SetTableHelperRaw(const LuaObject& key, const StkId valueSlot)
{
	lua_State* const lstate = GetActiveCState();
	luaV_settable(lstate, &m_object, const_cast<TObject*>(&key.m_object), valueSlot);
}

void LuaObject::SetTableHelper(const int32_t index, TObject* object)
{
	SetTableHelperRaw(index, object);
}

/**
 * Address: 0x00907ED0 (FUN_00907ED0, LuaPlus::LuaObject::SetN)
 *
 * What it does:
 * Writes Lua array-length metadata (`n`) for this table object.
 */
void LuaObject::SetN(const int32_t n)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	luaL_setn(lstate, -1, n);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00907D10 (FUN_00907D10)
 * Mangled: ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z
 *
 * What it does:
 * Validates that both objects share the same Lua global-state root, pushes this
 * object's raw `TObject` payload onto `state->top`, extends stack space when
 * needed, then advances the stack top by one slot.
 */
StkId LuaObject::PushStack(lua_State* state) const
{
	if (state == nullptr || m_state == nullptr || m_state->m_state == nullptr) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}
	if (state->l_G != m_state->m_state->l_G) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}

	return PushRawLuaObjectToStack(&m_object, state);
}

// Convenience overload with no counterpart in the binary, which exports only
// ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z (0x00907D10). That one
// guards on the two objects sharing a `global_State` and nothing more, so this
// forwarder must not add a stricter test: demanding the same *root* LuaState
// rejects pushes between the sim and UI roots, which are distinct roots over
// one global_State, and that rejection is what was failing every
// cfunc_GetPreference call at startup.
StkId LuaObject::PushStack(LuaState* state) const
{
	Ensure(state != nullptr, "state");
	return PushStack(state->GetCState());
}

void LuaObject::AssignNewTable(LuaState* state, const int32_t nArray, const uint32_t lnHash)
{
	RebindToState(*this, state);

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	// Address: 0x00909940 (FUN_00909940)
	// Binary path creates a table directly via luaH_new using requested array/hash sizing.
	const int hashBits = luaO_log2(lnHash);
	Table* const table = luaH_new(lstate, nArray, hashBits + 1);
	Ensure(table != nullptr, "luaH_new returned null");
	m_object.tt = table->tt;
	m_object.value.p = table;
}

/**
 * Address: 0x00909900 (FUN_00909900, LuaPlus::LuaObject::AssignObject)
 *
 * What it does:
 * Copies one source LuaObject tagged payload into this object after enforcing
 * shared-state ownership.
 */
void LuaObject::AssignObject(
	LuaState* const state,
	const LuaObject& value
)
{
	(void)state;
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	m_object.tt = value.m_object.tt;
	m_object.value = value.m_object.value;
}

/**
 * Address: 0x00909650 (FUN_00909650, LuaPlus::LuaObject::AssignInteger)
 *
 * What it does:
 * Rebinds this object to `state` root ownership lane when needed, then stores
 * one integer payload converted to Lua number format.
 */
void LuaObject::AssignInteger(LuaState* state, const int32_t value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.n = static_cast<float>(value);
	m_object.tt = LUA_TNUMBER;
}

/**
 * Address: 0x009096A0 (FUN_009096A0, LuaPlus::LuaObject::AssignNumber)
 *
 * What it does:
 * Rebinds this object to `state` root ownership (when needed) and stores one
 * numeric payload lane.
 */
void LuaObject::AssignNumber(LuaState* state, const double number)
{
	RebindToState(*this, state);
	m_object.value.n = static_cast<float>(number);
	m_object.tt = LUA_TNUMBER;
}

/**
 * Address: 0x009095C0 (FUN_009095C0, LuaPlus::LuaObject::AssignNil)
 *
 * IDA signature:
 * void __thiscall LuaPlus::LuaObject::AssignNil(
 *     LuaPlus::LuaObject *this, LuaPlus::LuaState *state);
 *
 * What it does:
 * Rebinds this object to `state` and sets its payload to nil. The unlink from
 * the previous state's used-object chain lives in RebindToState, which is what
 * the binary open-codes here before writing the tag.
 */
void LuaObject::AssignNil(LuaState* state)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TNIL;
	m_object.value.p = nullptr;
}

/**
 * Address: 0x00909600 (FUN_00909600, LuaPlus::LuaObject::AssignBoolean)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * boolean payload lane (`LUA_TBOOLEAN`).
 */
void LuaObject::AssignBoolean(LuaState* state, const bool value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object.value.b = value ? 1u : 0u;
	*reinterpret_cast<std::uint32_t*>(&m_object.tt) = LUA_TBOOLEAN;
}

/**
 * Address: 0x00909750 (FUN_00909750, LuaPlus::LuaObject::AssignString)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * interned string payload or marks this object as `LUA_TNIL` for null input.
 */
void LuaObject::AssignString(LuaState* state, const char* value)
{
	RebindToState(*this, state);
	if (value == nullptr) {
		m_object.tt = LUA_TNIL;
		return;
	}

	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
	m_object.tt = interned->tt;
	m_object.value.p = interned;
}

void LuaObject::AssignLightUserData(LuaState* state, void* value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TLIGHTUSERDATA;
	m_object.value.p = value;
}

/**
 * Address: 0x009097D0 (FUN_009097D0, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, allocates one default-
 * constructed userdata payload for `type`, and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RType* type)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	Ensure(type != nullptr, "type");

	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = CreateDefaultConstructedUserdata(lstate, const_cast<gpg::RType*>(type));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x00909840 (FUN_00909840, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, then materializes one
 * reflected userdata lane from `value` and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RRef& value)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = CreateRefUserdata(lstate, const_cast<gpg::RRef*>(&value));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x009084E0 (FUN_009084E0, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by integer index using a string-or-nil payload.
 */
void LuaObject::SetString(const int32_t index, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	TObject keyObject{};
	keyObject.value.n = static_cast<float>(index);
	keyObject.tt = LUA_TNUMBER;
	luaV_settable(lstate, &m_object, &keyObject, &valueObject);
}

/**
 * Address: 0x00908450 (FUN_00908450, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by string key using a string-or-nil payload.
 */
void LuaObject::SetString(const char* key, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	SetTableHelper(key, &valueObject);
}

/**
 * Address: 0x00908590 (FUN_00908590, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by LuaObject key using a string-or-nil payload after
 * enforcing shared-state ownership with `key`.
 */
void LuaObject::SetString(const LuaObject& key, const char* value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
	}

	SetTableHelperRaw(key, &valueObject);
}

/**
 * Address: 0x00908630 (FUN_00908630, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by string key.
 */
void LuaObject::SetLightUserData(const char* const key, void* const value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TLIGHTUSERDATA;
	object.value.p = value;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908680 (FUN_00908680, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by integer key.
 */
void LuaObject::SetLightUserData(const int32_t index, void* const value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject val{};
	val.value.p = value;
	val.tt = LUA_TLIGHTUSERDATA;

	TObject key{};
	key.value.n = static_cast<float>(index);
	key.tt = LUA_TNUMBER;

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009086F0 (FUN_009086F0, LuaPlus::LuaObject::SetLightUserData)
 *
 * What it does:
 * Writes one light-userdata payload into this table by LuaObject key after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetLightUserData(const LuaObject& key, void* const value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.value.p = value;
	val.tt = LUA_TLIGHTUSERDATA;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00907FF0 (FUN_00907FF0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by string key.
 */
void LuaObject::SetNil(const char* const key)
{
	Ensure(m_state != nullptr, "m_state");

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;
	SetTableHelper(key, &nilObject);
}

/**
 * Address: 0x00907FA0 (FUN_00907FA0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by integer key.
 */
void LuaObject::SetNil(const int32_t index)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;

	luaV_settable(lstate, &m_object, &keyObject, &nilObject);
}

/**
 * Address: 0x00908060 (FUN_00908060, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes one nil payload to this table by LuaObject key after validating
 * shared-state ownership with `key`.
 */
void LuaObject::SetNil(const LuaObject& key)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;

	SetTableHelperRaw(key, &nilObject);
}

/**
 * Address: 0x00908320 (FUN_00908320, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by string key using a numeric payload.
 */
void LuaObject::SetNumber(const char* key, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TNUMBER;
	object.value.n = value;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908370 (FUN_00908370, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by integer key using a numeric payload.
 */
void LuaObject::SetNumber(const int32_t index, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = value;

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009083E0 (FUN_009083E0, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by LuaObject key using a numeric payload after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetNumber(const LuaObject& key, const float value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = value;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00908240 (FUN_00908240, ?SetInteger@LuaObject@LuaPlus@@QBEXHH@Z)
 *
 * What it does:
 * Writes one table entry by integer key using an integer payload.
 */
void LuaObject::SetInteger(const int32_t index, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = static_cast<float>(value);

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009081F0 (FUN_009081F0, ?SetInteger@LuaObject@LuaPlus@@QBEXPBDH@Z)
 *
 * What it does:
 * Writes one table entry by string key using an integer payload lane.
 */
void LuaObject::SetInteger(const char* key, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TNUMBER;
	object.value.n = static_cast<float>(value);
	SetTableHelper(key, &object);
}

/**
 * Address: 0x009082B0 (FUN_009082B0, LuaPlus::LuaObject::SetInteger)
 *
 * What it does:
 * Writes one table entry by LuaObject key using an integer payload lane after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetInteger(const LuaObject& key, const int32_t value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = static_cast<float>(value);

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x009080C0 (FUN_009080C0, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by string key.
 */
void LuaObject::SetBoolean(const char* key, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TBOOLEAN;
	object.value.b = value ? 1 : 0;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908110 (FUN_00908110, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by integer key.
 */
void LuaObject::SetBoolean(const int32_t index, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject val{};
	val.value.b = value ? 1 : 0;
	val.tt = LUA_TBOOLEAN;

	TObject key{};
	key.value.n = static_cast<float>(index);
	key.tt = LUA_TNUMBER;

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x00908180 (FUN_00908180, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by LuaObject key after
 * validating shared-state ownership with `key`.
 */
void LuaObject::SetBoolean(const LuaObject& key, const bool value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	TObject val{};
	val.value.b = value ? 1 : 0;
	val.tt = LUA_TBOOLEAN;

	SetTableHelperRaw(key, &val);
}

/**
 * Address: 0x00908760 (FUN_00908760, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table field by string key after enforcing shared-state ownership
 * with the source Lua object value.
 */
void LuaObject::SetObject(const char* key, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(key, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const char* key, LuaObject* value)
{
	if (value) {
		SetObject(key, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(key, &nilValue);
}

/**
 * Address: 0x00908810 (FUN_00908810, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table entry by LuaObject key/value lanes after validating shared
 * state ownership.
 */
void LuaObject::SetObject(const LuaObject& key, const LuaObject& value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");
	Ensure(m_state == value.m_state, "m_state == value.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	SetTableHelperRaw(key, const_cast<TObject*>(&value.m_object));
}

/**
 * Address: 0x009087A0 (FUN_009087A0, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one object value into this table by integer key after enforcing
 * shared Lua-state ownership with `value`.
 */
void LuaObject::SetObject(const int32_t index, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(index, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const int32_t index, LuaObject* value)
{
	if (value) {
		SetObject(index, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(index, &nilValue);
}

namespace
{
	/**
	 * Address: 0x00915E20 (FUN_00915E20)
	 *
	 * What it does:
	 * Unlinks one `UpVal` node from `lua_State::openupval` forward chain and
	 * clears the removed node's `next` link lane.
	 */
	GCObject** UnlinkOpenUpvalueFromState(
		lua_State* const state,
		GCObject* const upvalue
	)
	{
		if (state == nullptr || upvalue == nullptr) {
			return nullptr;
		}

		GCObject** link = &state->openupval;
		while (*link != nullptr && *link != upvalue) {
			link = &(*link)->gch.next;
		}

		if (*link == upvalue) {
			*link = upvalue->gch.next;
			upvalue->gch.next = nullptr;
		}

		return link;
	}

	struct OwnerWordLaneAt68Runtime
	{
		std::byte pad00[68];
		std::uint32_t lane44;
	};
	static_assert(offsetof(OwnerWordLaneAt68Runtime, lane44) == 68, "OwnerWordLaneAt68Runtime::lane44 offset must be 68");

	struct OwnerWordWritePairRuntime
	{
		OwnerWordLaneAt68Runtime* owner;
		std::uint32_t value;
	};
	static_assert(sizeof(OwnerWordWritePairRuntime) == 0x08, "OwnerWordWritePairRuntime size must be 0x08");

	/**
	 * Address: 0x00929BE0 (FUN_00929BE0)
	 *
	 * What it does:
	 * Stores one 32-bit value into owner field `+0x44` (`+0x68` bytes) and
	 * returns the owner pointer lane.
	 */
	OwnerWordLaneAt68Runtime* StoreOwnerWordLaneAt68(
		OwnerWordWritePairRuntime* const writePair
	)
	{
		if (writePair == nullptr || writePair->owner == nullptr) {
			return nullptr;
		}

		writePair->owner->lane44 = writePair->value;
		return writePair->owner;
	}

	/**
	 * Address: 0x009284D0 (FUN_009284D0)
	 *
	 * IDA signature:
	 * void __cdecl sub_9284D0(lua_State *L, TObject *o, GCObject *mt);
	 *
	 * What it does:
	 * Assigns one metatable object to a tagged Lua value:
	 * table/userdata instances store direct metatable pointers while all other
	 * tag lanes update `global_State::_defaultmetatypes[tt]`. The binary
	 * dispatches on the tag alone - it validates neither the pointers nor the
	 * tag range, so neither does this.
	 */
	void AssignMetatableByTaggedValueType(
		lua_State* const state,
		LuaPlus::TObject* const object,
		GCObject* const metatableObject
	)
	{
		if (object->tt == LUA_TTABLE) {
			static_cast<Table*>(object->value.p)->metatable = reinterpret_cast<Table*>(metatableObject);
			return;
		}

		if (object->tt == LUA_TUSERDATA) {
			static_cast<Udata*>(object->value.p)->metatable = reinterpret_cast<Table*>(metatableObject);
			return;
		}

		TObject& slot = state->l_G->_defaultmetatypes[object->tt];
		slot.tt = static_cast<int>(metatableObject->gch.tt);
		slot.value.p = metatableObject;
	}
}

/**
 * Address: 0x00907E00 (FUN_00907E00, LuaPlus::LuaObject::SetMetaTable)
 *
 * What it does:
 * Validates that both objects share one Lua state and applies `valueObj` as
 * this object's runtime metatable.
 */
void LuaObject::SetMetaTable(const LuaObject& valueObj)
{
	Ensure(m_state && m_state == valueObj.m_state, "m_state && m_state == valueObj.m_state");

	AssignMetatableByTaggedValueType(
		m_state->GetCState(),
		&m_object,
		static_cast<GCObject*>(valueObj.m_object.value.p)
	);
}

/**
 * Address: 0x00908BA0 (FUN_00908BA0, LuaPlus::LuaObject::GetMetaTable)
 *
 * What it does:
 * Fetches this object's runtime metatable and returns it as a bound LuaObject.
 */
LuaObject LuaObject::GetMetaTable() const
{
	Ensure(m_state != nullptr, "m_state");

	Table* const metatable = luaT_getmetatable(m_state->m_state, &m_object);

	LuaObject out(m_state);
	out.m_object.value.p = metatable;
	out.m_object.tt = metatable->tt;
	return out;
}

/**
 * Address: 0x00908C10 (FUN_00908C10, LuaPlus::LuaObject::CreateTable)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at string key `key`.
 */
LuaObject LuaObject::CreateTable(const char* const key, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;
	SetTableHelper(key, &out.m_object);
	return out;
}

/**
 * Address: 0x00908CA0 (FUN_00908CA0, LuaPlus::LuaObject::CreateTable_Array)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at integer key
 * `index`.
 */
LuaObject LuaObject::CreateTable(const int32_t index, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);
	luaV_settable(lstate, &m_object, &keyObject, &out.m_object);
	return out;
}

/**
 * Address: 0x00908D50 (FUN_00908D50, LuaPlus::LuaObject::CreateTable)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table under LuaObject key
 * `key`.
 */
LuaObject LuaObject::CreateTable(
	const LuaObject& key,
	const int32_t narray,
	const int32_t lnhash
)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.tt = table->tt;
	out.m_object.value.p = table;

	SetTableHelperRaw(key, &out.m_object);
	return out;
}

// Reopen the same unnamed namespace that houses LuaCallFrameRuntimeView and the
// three recovered frame primitives so we can build a typed `table.method()`
// driver on top of them without duplicating their layout.
namespace
{
	// Intent-first typed frame wrapper used by LuaObject::Insert / Remove / Sort.
	// Delegates to the recovered 2007 primitives from earlier in this TU:
	//   ConstructLuaCallFrame            (0x00909A00, FUN_00909A00)
	//   InvokeLuaCallFrame               (0x00907270, FUN_00907270)
	//   PushLuaObjectArgumentToCallFrame (0x00908940, FUN_00908940)
	void RunLuaTableMethodCallFrame(
		LuaState* const activeState,
		LuaObject& methodFunction,
		LuaObject* const arg0 = nullptr,
		const bool pushNumericArg = false,
		const lua_Number numericArg = 0.0,
		LuaObject* const arg2 = nullptr
	)
	{
		LuaCallFrameRuntimeView frame{};
		(void)ConstructLuaCallFrame(&frame, &methodFunction);

		if (arg0 != nullptr) {
			(void)PushLuaObjectArgumentToCallFrame(&frame, arg0);
		}

		if (pushNumericArg) {
			lua_pushnumber(activeState->m_state, numericArg);
			++frame.argumentCount;
		}

		if (arg2 != nullptr) {
			(void)PushLuaObjectArgumentToCallFrame(&frame, arg2);
		}

		LuaStackObject result(activeState, 0);
		const int multret = LUA_MULTRET;
		(void)InvokeLuaCallFrame(&frame, &result, &multret);
	}
} // namespace

/**
 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Runs `table.insert(this, key, obj)` by constructing one Lua call-frame
 * view (FUN_00909A00) over the resolved `table.insert` function, pushing
 * `this`, the numeric key, and the value `obj` as arguments onto it,
 * invoking the frame, and restoring the original Lua stack top.
 */
void LuaObject::Insert(const int32_t key, const LuaObject& obj) const
{
	if (m_state != obj.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject insertFunction = tableObject["insert"];

		LuaObject thisCopy(*this);
		LuaObject objCopy(obj);
		RunLuaTableMethodCallFrame(
			activeState,
			insertFunction,
			&thisCopy,
			true,
			static_cast<lua_Number>(key),
			&objCopy
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00909AF0 (FUN_00909AF0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Runs `table.insert(this, obj)` (no explicit index -- appends at the end)
 * by constructing one Lua call-frame view (FUN_00909A00) over the resolved
 * `table.insert` function, pushing `this` and the value `obj` as arguments
 * onto it, invoking the frame, and restoring the original Lua stack top.
 * Same shape as the two-argument overload above with the numeric-key push
 * omitted.
 */
void LuaObject::Insert(const LuaObject& obj) const
{
	if (m_state != obj.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject insertFunction = tableObject["insert"];

		LuaObject thisCopy(*this);
		LuaObject objCopy(obj);
		RunLuaTableMethodCallFrame(
			activeState,
			insertFunction,
			&thisCopy,
			false,
			0.0,
			&objCopy
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00909EB0 (FUN_00909EB0, LuaPlus::LuaObject::Remove)
 *
 * What it does:
 * Runs `table.remove(this, index)` by constructing one Lua call-frame view
 * (FUN_00909A00) over `table.remove`, pushing `this` and the numeric index
 * as arguments, invoking the frame, and restoring the original Lua stack
 * top.
 */
void LuaObject::Remove(const int32_t index) const
{
	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject removeFunction = tableObject["remove"];

		LuaObject thisCopy(*this);
		RunLuaTableMethodCallFrame(
			activeState,
			removeFunction,
			&thisCopy,
			true,
			static_cast<lua_Number>(index),
			nullptr
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x0090A020 (FUN_0090A020, LuaPlus::LuaObject::Sort)
 *
 * What it does:
 * Runs `table.sort(this)` by constructing one Lua call-frame view
 * (FUN_00909A00) over `table.sort`, pushing `this` as the single argument,
 * invoking the frame, and restoring the original Lua stack top.
 */
void LuaObject::Sort() const
{
	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject sortFunction = tableObject["sort"];

		LuaObject thisCopy(*this);
		RunLuaTableMethodCallFrame(
			activeState,
			sortFunction,
			&thisCopy,
			false,
			0.0,
			nullptr
		);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 * Address: 0x00908DF0 (FUN_00908DF0, __imp_?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 *
 * IDA signature:
 * LuaPlus::LuaObject *__thiscall GetByIndex(LuaObject *this, LuaObject *dest, int index);
 *
 * What it does:
 * Reads one entry out of this object's own tagged value by numeric key. The
 * lookup runs straight through `luaV_gettable` on `m_object` - the sibling of
 * `GetByObject` - and the resolved slot is bound into a fresh LuaObject on the
 * same root state.
 *
 * The Lua stack is deliberately not involved. Routing this through
 * `PushStack`/`lua_gettable` and then reading slot -1 back through a
 * `LuaStackObject` bound to `m_state` mixes two different threads: the push
 * lands on `l_G->lstate` (whichever coroutine is running) while the read
 * indexes `m_state->m_state` (the root). Inside a sim coroutine those are
 * different stacks, so every lookup returned whatever the root happened to
 * have on top - typically a stale error string. That is how class metatables
 * fetched out of `__factory_objects` turned into `TString`s.
 */
LuaObject LuaObject::GetByIndex(const int32_t index) const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();

	TObject key{};
	key.value.n = static_cast<lua_Number>(index);
	key.tt = LUA_TNUMBER;

	const TObject* const rawValue = luaV_gettable(lstate, &m_object, &key, 0);
	return LuaObject(m_state, const_cast<TObject*>(rawValue));
}

/**
 * Address: 0x00908E70 (FUN_00908E70, LuaPlus::LuaObject::GetByObject)
 *
 * What it does:
 * Looks up this table using a LuaObject key and returns the raw slot value.
 */
LuaObject LuaObject::GetByObject(const LuaObject& key) const
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const TObject* const rawValue = luaV_gettable(lstate, &m_object, &key.m_object, 0);
	LuaObject out;
	out.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return out;
}

/**
 * Address: 0x00908EE0 (FUN_00908EE0, LuaPlus::LuaObject::GetByObject)
 *
 * What it does:
 * Looks up this table using one `LuaStackObject` key lane and returns the
 * resolved raw slot value as a bound LuaObject.
 */
LuaObject LuaObject::GetByObject(const LuaStackObject& obj) const
{
	Ensure(m_state == obj.m_state->m_rootState, "m_state == obj.m_state->m_rootState");

	lua_State* const lstate = GetActiveCState();
	TObject* const keyObject = luaA_index(lstate, obj.m_stackIndex);
	const TObject* const rawValue = luaV_gettable(lstate, &m_object, keyObject, 0);
	return LuaObject(m_state, const_cast<TObject*>(rawValue));
}

/**
 * Address: 0x0090A160 (FUN_0090A160, LuaPlus::LuaObject::GetByName)
 * Mangled: ?GetByName@LuaObject@LuaPlus@@QBE?AV12@PBD@Z
 *
 * IDA signature:
 * LuaPlus::LuaObject *__userpurge LuaPlus::LuaObject::GetByName@<eax>(
 *     LuaPlus::LuaObject *this@<ecx>, LuaPlus::LuaObject *dest, const char *name);
 *
 * What it does:
 * Forwards straight to operator[](const char*), which reads the table slot
 * with luaH_get. The lookup is therefore raw: no __index metamethod runs, and
 * a key the table does not hold itself comes back nil rather than escalating
 * to whatever the module's environment chain would do with it.
 */
LuaObject LuaObject::GetByName(const char* name) const
{
	return (*this)[name];
}

/**
 * Address: 0x00908F60 (FUN_00908F60, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates table indexing, resolves an already-interned string key from the
 * VM string table, and returns the raw table slot value.
 */
LuaObject LuaObject::operator[](const char* const name) const
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(name != nullptr, "name");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	const TString* const internedKey = FindInternedString(lstate, name);
	if (internedKey == nullptr) {
		LuaObject nilValue;
		nilValue.AddToUsedList(m_state);
		nilValue.m_object.tt = LUA_TNIL;
		return nilValue;
	}

	TObject keyObject;
	keyObject.tt = internedKey->tt;
	keyObject.value.p = const_cast<TString*>(internedKey);

	const TObject* const rawValue = luaH_get(reinterpret_cast<Table*>(m_object.value.p), &keyObject);
	Ensure(rawValue != nullptr, "obj");

	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x00909280 (FUN_00909280, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates state + table type for LuaObject-key indexing, then fetches the
 * raw keyed slot directly from Lua's table storage.
 */
LuaObject LuaObject::operator[](const LuaObject& key) const
{
	if (m_state != key.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	const TObject* const rawValue = luaH_get(reinterpret_cast<Table*>(m_object.value.p), &key.m_object);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009091E0 (FUN_009091E0, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates state + table type for integer indexing, then fetches the raw
 * numeric-key slot directly from Lua's table storage.
 */
LuaObject LuaObject::operator[](const int32_t index) const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
		if (m_object.tt != LUA_TTABLE) {
			throw LuaAssertion("(((o)->tt) == LUA_TTABLE)");
		}
	}

	const TObject* const rawValue = luaH_getnum(reinterpret_cast<Table*>(m_object.value.p), index);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x00909310 (FUN_00909310, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates root-state compatibility for LuaStackObject-key indexing, then
 * resolves the stack key and fetches the raw keyed table slot.
 */
LuaObject LuaObject::operator[](const LuaStackObject& key) const
{
	const LuaState* const rootState = m_state;
	const LuaState* const keyRootState = (key.m_state != nullptr) ? key.m_state->m_rootState : nullptr;
	if (rootState != keyRootState) {
		throw LuaAssertion("m_state == obj.m_state->m_rootState");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	TObject* const stackKey = luaA_index(lstate, key.m_stackIndex);
	const TObject* const rawValue = luaH_get(reinterpret_cast<Table*>(m_object.value.p), stackKey);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009093B0 (FUN_009093B0, LuaPlus::LuaObject::Lookup)
 *
 * What it does:
 * Traverses a dotted path and alternates string-key vs numeric-index lookup
 * based on each segment's parse result.
 */
LuaObject LuaObject::Lookup(const char* const path) const
{
	if (path == nullptr || *path == '\0') {
		return *this;
	}

	auto tryParseIndex = [](const char* const text, int32_t* const outIndex) -> bool
	{
		if (text == nullptr || *text == '\0' || outIndex == nullptr) {
			return false;
		}

		char* parseEnd = nullptr;
		const double parsedValue = std::strtod(text, &parseEnd);
		if (parseEnd == text || parseEnd == nullptr || *parseEnd != '\0') {
			return false;
		}

		const double minValue = static_cast<double>(std::numeric_limits<int32_t>::min());
		const double maxValue = static_cast<double>(std::numeric_limits<int32_t>::max());
		if (parsedValue < minValue || parsedValue > maxValue) {
			return false;
		}

		*outIndex = static_cast<int32_t>(parsedValue);
		return true;
	};

	LuaObject current = *this;
	std::string mutablePath(path);
	char* segment = mutablePath.data();
	char* dot = std::strchr(segment, '.');

	while (dot != nullptr) {
		*dot = '\0';
		if (*segment == '\0') {
			return {};
		}

		int32_t numericIndex = 0;
		current = tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
		if (current.IsNil()) {
			return current;
		}

		segment = dot + 1;
		dot = std::strchr(segment, '.');
	}

	if (*segment == '\0') {
		return {};
	}

	int32_t numericIndex = 0;
	return tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
}

int32_t LuaObject::GetN() const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
#if defined(lua_rawlen)
	const int32_t count = static_cast<int32_t>(lua_rawlen(lstate, -1));
#elif defined(lua_objlen)
	const int32_t count = static_cast<int32_t>(lua_objlen(lstate, -1));
#else
	const int32_t count = luaL_getn(lstate, -1);
#endif
	lua_settop(lstate, oldTop);
	return count;
}

/**
 * Address: 0x00907F50 (FUN_00907F50, LuaPlus::LuaObject::GetCount)
 *
 * What it does:
 * Pushes this object to the active Lua stack, reads Lua table length via
 * `lua_getn`, then restores stack top and returns that element count.
 */
int32_t LuaObject::GetCount() const
{
	Ensure(m_state != nullptr, "m_state");

	LuaState* const activeState = GetActiveState();
	Ensure(activeState != nullptr, "active state");
	Ensure(activeState->m_state != nullptr, "active lua state");

	const int oldTop = lua_gettop(activeState->m_state);
	const_cast<LuaObject*>(this)->PushStack(activeState);
	const int stackIndex = lua_gettop(activeState->m_state);
	const int32_t count = static_cast<int32_t>(lua_getn(activeState->m_state, stackIndex));
	lua_settop(activeState->m_state, oldTop);
	return count;
}

/**
 * Address: 0x0090A410 (FUN_0090A410, LuaPlus::LuaObject::GetTableCount)
 *
 * What it does:
 * Iterates all table entries and returns the number of key/value pairs.
 */
int32_t LuaObject::GetTableCount() const
{
	int32_t count = 0;
	LuaTableIterator iter(*this, 1);
	while (!iter.m_isDone) {
		++count;
		iter.Next();
	}
	return count;
}

/**
 * Address: 0x00907630 (FUN_00907630, LuaPlus::LuaObject::Register)
 *
 * What it does:
 * Creates one C closure with `tagMethod` upvalues from the Lua root-state
 * stack, then assigns it into this table object under `key`.
 */
void LuaObject::Register(const char* const key, CFunction const value, const int32_t tagMethod)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state->m_state != nullptr, "lua state");
	Ensure(m_state->m_state->l_G != nullptr, "lua global state");
	Ensure(key != nullptr, "key");
	Ensure(value != nullptr, "value");

	lua_State* const closureState = m_state->m_state->l_G->lstate;
	Ensure(closureState != nullptr, "closure state");

	Closure* const closure = luaF_newCclosure(closureState, tagMethod);
	closure->c.f = value;
	closureState->top -= tagMethod;

	for (int upvalueIndex = tagMethod - 1; upvalueIndex >= 0; --upvalueIndex) {
		closure->c.upvalue[upvalueIndex] = closureState->top[upvalueIndex];
		closureState->top[upvalueIndex].tt = 0;
	}

	TObject closureObject{};
	closureObject.value.p = closure;
	closureObject.tt = static_cast<int>(closure->c.tt);
	SetTableHelper(key, &closureObject);
}

namespace
{
	// Wire tags of the SCR byte-stream format, written by LuaObject::ToByteStream.
	constexpr int8_t kScrTagNumber = 0;
	constexpr int8_t kScrTagString = 1;
	constexpr int8_t kScrTagNil = 2;
	constexpr int8_t kScrTagBoolean = 3;
	constexpr int8_t kScrTagTableBegin = 4;
	constexpr int8_t kScrTagTableEnd = 5;
} // namespace

/**
 * Address: 0x004D2A40 (FUN_004D2A40, Moho::SCR_FromByteStream)
 *
 * What it does:
 * Deserializes one tagged Lua payload from a binary stream and recursively
 * rebuilds nested table key/value pairs.
 */
void LuaObject::SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader)
{
	Ensure(state != nullptr, "state");
	Ensure(reader != nullptr, "reader");

	LuaObject result;
	int8_t luaType = 0;
	reader->ReadExact(luaType);

	switch (luaType) {
		case kScrTagNumber: {
			float number = 0.0f;
			reader->ReadExact(number);
			result.AssignNumber(state, number);
			break;
		}
		case kScrTagString: {
			msvc8::string string;
			reader->ReadString(&string);
			result.AssignString(state, string.c_str());
			break;
		}
		case kScrTagNil:
			result.AssignNil(state);
			break;
		case kScrTagBoolean: {
			int8_t byteValue = 0;
			reader->ReadExact(byteValue);
			result.AssignBoolean(state, byteValue != 0);
			break;
		}
		case kScrTagTableBegin: {
			result.AssignNewTable(state, 0, 0);

			// Peek the next tag through Stream::CheckByte: it reads one byte and
			// rewinds the read window by one. Reaching for the virtual unget
			// directly instead skips that rewind, and MemBufferStream's override
			// throws unconditionally - which made every table fail to load.
			gpg::Stream& stream = *const_cast<gpg::Stream*>(reader->stream());
			while (stream.CheckByte() != kScrTagTableEnd) {
				LuaObject key;
				SCR_FromByteStream(key, state, reader);
				if (key.IsNil()) {
					gpg::Die("Deserialized nil table key.");
				}

				LuaObject value;
				SCR_FromByteStream(value, state, reader);
				if (value.IsNil()) {
					gpg::Die("Deserialized nil table value.");
				}

				result.SetObject(key, value);
			}

			// Consume the end-of-table tag the peek left in place.
			(void)reader->ReadChar();
			break;
		}
		case kScrTagTableEnd:
			gpg::Warnf("Error deseralizing lua object: unexpected end-of-table marker encountered.");
			result.AssignNil(state);
			break;
		default:
			gpg::Warnf("Attempt to deserialize unknown lua data.");
			result.AssignNil(state);
			break;
	}

	out = result;
}

/**
 * Address: 0x00907C90 (FUN_00907C90, LuaPlus::LuaObject::GetBoolean)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-nil/non-boolean values, and returns Lua truthiness for boolean lanes.
 */
bool LuaObject::GetBoolean() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TNIL && m_object.tt != LUA_TBOOLEAN) {
		luaG_typeerror(lstate, &m_object, "get as boolean");
	}

	return m_object.tt != LUA_TNIL && (m_object.tt != LUA_TBOOLEAN || m_object.value.b != 0);
}

/**
 * Address: 0x00907A90 (FUN_00907A90, LuaPlus::LuaObject::GetString)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-string values, and returns the underlying interned string buffer.
 */
const char* LuaObject::GetString() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TSTRING) {
		luaG_typeerror(lstate, &m_object, "get as string");
	}

	const auto* ts = static_cast<const TString*>(m_object.value.p);
	return ts->str;
}

/**
 * Address: 0x00907410 (FUN_00907410, LuaPlus::LuaObject::ToStrLen)
 *
 * What it does:
 * Returns current string length when already string, otherwise tries Lua's
 * number-to-string conversion and returns resulting length on success.
 */
int32_t LuaObject::ToStrLen()
{
	if (m_object.tt == LUA_TSTRING) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	if (luaV_tostring(m_state->m_state, &m_object) != 0) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	return 0;
}

/**
 * Address: 0x00907380 (FUN_00907380)
 *
 * What it does:
 * Returns one integer truncation of this value when numeric/coercible,
 * otherwise returns `0`.
 */
int32_t LuaObject::ToInteger() const
{
	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER || luaV_tonumber(&m_object, &numericValue) != 0) {
		return static_cast<int32_t>(m_object.value.n);
	}
	return 0;
}

/**
 * Address: 0x009073B0 (FUN_009073B0, LuaPlus::LuaObject::ToNumber)
 *
 * What it does:
 * Returns numeric payload when already numeric, otherwise attempts Lua numeric
 * coercion and returns `0` on conversion failure.
 */
double LuaObject::ToNumber() const
{
	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER || luaV_tonumber(&m_object, &numericValue) != 0) {
		return static_cast<double>(m_object.value.n);
	}
	return 0.0;
}

/**
 * Address: 0x009073E0 (FUN_009073E0, LuaPlus::LuaObject::ToString)
 *
 * What it does:
 * Returns the current interned string buffer when this object is already a
 * string, otherwise attempts in-place Lua coercion via `luaV_tostring` and
 * returns `nullptr` when conversion fails.
 */
const char* LuaObject::ToString() const
{
	if (m_object.tt == LUA_TSTRING) {
		return static_cast<const GCObject*>(m_object.value.p)->ts.str;
	}

	TObject* const object = const_cast<TObject*>(&m_object);
	if (luaV_tostring(m_state->m_state, object) != 0) {
		return static_cast<const GCObject*>(object->value.p)->ts.str;
	}

	return nullptr;
}

/**
 * Address: 0x00907970 (FUN_00907970, LuaPlus::LuaObject::GetNumber)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns numeric payload.
 */
double LuaObject::GetNumber() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as number");
	}
	return static_cast<double>(m_object.value.n);
}

/**
 * Address: 0x009079D0 (FUN_009079D0)
 *
 * What it does:
 * Validates LuaObject state/type and returns the numeric payload as one float
 * lane (`Value::n`), raising Lua's type-error lane for non-numeric values.
 */
float LuaObjectGetNumberAsFloat(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as number");
	}
	return object->m_object.value.n;
}

/**
 * Address: 0x00907AF0 (FUN_00907AF0)
 *
 * What it does:
 * Validates LuaObject state/type and returns one interned Lua string buffer,
 * raising Lua's typed-operation error lane on non-string values.
 */
const char* LuaObjectGetStringChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TSTRING) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "string");
	}

	const auto* const text = static_cast<const TString*>(object->m_object.value.p);
	return text->str;
}

/**
 * Address: 0x00907B50 (FUN_00907B50)
 *
 * What it does:
 * Validates LuaObject state/type for function access and returns one C closure
 * entrypoint pointer, or `nullptr` if Lua still reports a non-function lane.
 */
CFunction LuaObjectGetCFunctionChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");

	bool isFunctionType = object->m_object.tt == LUA_TFUNCTION;
	if (!isFunctionType) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as C function");
		isFunctionType = object->m_object.tt == LUA_TFUNCTION;
	}

	if (!isFunctionType) {
		return nullptr;
	}

	const auto* const closure = static_cast<const CClosure*>(object->m_object.value.p);
	return closure != nullptr ? closure->f : nullptr;
}

/**
 * Address: 0x00907C30 (FUN_00907C30)
 *
 * What it does:
 * Validates LuaObject state/type and returns the raw light-userdata pointer
 * payload (`Value::p`) from this tagged object.
 */
void* LuaObjectGetLightUserDataChecked(const LuaObject* const object)
{
	Ensure(object != nullptr, "object");
	Ensure(object->m_state != nullptr, "m_state");
	if (object->m_object.tt != LUA_TLIGHTUSERDATA) {
		luaG_typeerror(object->m_state->m_state->l_G->lstate, &object->m_object, "get as light userdata");
	}

	return object->m_object.value.p;
}

/**
 * Address: 0x009166B0 (FUN_009166B0)
 *
 * What it does:
 * Fetches one boolean field from the date-table lane at stack index `-2` and
 * returns the converted truth-value while restoring the original stack top.
 */
bool LuaDateGetBooleanField(
	const char* const fieldName,
	lua_State* const  state
)
{
	Ensure(state != nullptr, "state");
	Ensure(fieldName != nullptr, "fieldName");

	lua_pushstring(state, fieldName);
	lua_gettable(state, -2);
	const bool value = lua_toboolean(state, -1) != 0;
	lua_settop(state, -2);
	return value;
}

/**
 * Address: 0x009166E0 (FUN_009166E0)
 *
 * What it does:
 * Fetches one numeric field from the date-table lane at stack index `-2`;
 * returns `defaultValue` on non-number fields and raises when required.
 */
int LuaDateGetNumericFieldOrDefault(
	int               defaultValue,
	const char* const fieldName,
	lua_State* const  state
)
{
	Ensure(state != nullptr, "state");
	Ensure(fieldName != nullptr, "fieldName");

	lua_pushstring(state, fieldName);
	lua_gettable(state, -2);

	if (lua_isnumber(state, -1)) {
		defaultValue = static_cast<int>(lua_tonumber(state, -1));
	} else if (defaultValue == -2) {
		luaL_error(state, "field `%s' missing in date table", fieldName);
	}

	lua_settop(state, -2);
	return defaultValue;
}

/**
 * Address: 0x0077F660 (FUN_0077F660, LuaObject::j_GetNumber2 thunk)
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::GetNumber`.
 */
double LuaObjectGetNumberThunk2(const LuaObject* const object)
{
	return object->GetNumber();
}

/**
 * Address: 0x00907910 (FUN_00907910, LuaPlus::LuaObject::GetInteger)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns int-truncated payload.
 */
int32_t LuaObject::GetInteger() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as int");
	}
	return static_cast<int32_t>(m_object.value.n);
}

/**
 * Address: 0x004D2C80 (FUN_004D2C80, ?SCR_ToByteStream@Moho@@YA_NABVLuaObject@LuaPlus@@AAVStream@gpg@@@Z)
 *
 * What it does:
 * Encodes one LuaObject value into the SCR tagged stream format and recursively
 * serializes table keys/values while warning on userdata/unsupported lanes.
 */
bool LuaObject::ToByteStream(gpg::Stream& stream)
{
	char typeTag;
	bool success = true;

	if (!m_state || IsNil()) {
		typeTag = 2;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsBoolean()) {
		typeTag = 3;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}

		const bool boolValue = GetBoolean();
		typeTag = boolValue ? 1 : 0;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsNumber()) {
		typeTag = 0;
		stream.Write(typeTag);
		const float number = static_cast<float>(GetNumber());
		stream.Write(number);
		return true;
	}

	if (IsString()) {
		typeTag = 1;
		stream.Write(typeTag);
		const char* str = GetString();
		stream.Write(str ? str : "");
		return true;
	}

	if (IsTable()) {
		typeTag = 4;
		stream.Write(typeTag);

		LuaTableIterator iter(*this, 1);
		while (!iter.m_isDone) {
			LuaObject key = iter.GetKey();
			if (!key.ToByteStream(stream)) {
				success = false;
			}

			LuaObject value = iter.GetValue();
			if (!value.ToByteStream(stream)) {
				success = false;
			}

			iter.Next();
		}

		typeTag = 5;
		stream.Write(typeTag);
		return success;
	}

	if (IsUserData()) {
		gpg::Warnf("Attempt to serialize lua user data.");
		typeTag = 2;
		stream.Write(typeTag);
		return false;
	}

	gpg::Warnf("Attempt to serialize unsupported lua value.");
	typeTag = 2;
	stream.Write(typeTag);
	return false;
}

namespace LuaPlus
{
	struct LuaObjectEmbeddedRecord24
	{
		std::uint32_t reserved00 = 0; // +0x00
		LuaPlus::LuaObject object{};  // +0x04
	};
	static_assert(sizeof(LuaObjectEmbeddedRecord24) == 0x18, "LuaObjectEmbeddedRecord24 size must be 0x18");
	static_assert(
		offsetof(LuaObjectEmbeddedRecord24, object) == 0x04,
		"LuaObjectEmbeddedRecord24::object offset must be 0x04"
	);

	/**
	 * Address: 0x00578960 (FUN_00578960)
	 *
	 * What it does:
	 * Destroys every live `LuaObject` in one contiguous range
	 * `[beginObject, endObject)`.
	 */
	void DestroyLuaObjectRangeForward(
		LuaPlus::LuaObject* const beginObject,
		LuaPlus::LuaObject* const endObject
	)
	{
		for (LuaPlus::LuaObject* cursor = beginObject; cursor != endObject; ++cursor) {
			cursor->~LuaObject();
		}
	}

	/**
	 * Address: 0x007CA2E0 (FUN_007CA2E0)
	 *
	 * What it does:
	 * Destroys embedded `LuaObject` subobjects that live at `+0x04` inside one
	 * 24-byte record range and returns the original record-begin lane.
	 */
	LuaPlus::LuaObject* DestroyEmbeddedLuaObjectRangeIn24ByteRecords(
		LuaPlus::LuaObject* const recordBegin,
		LuaPlus::LuaObject* const recordEnd
	)
	{
		auto* cursor = reinterpret_cast<LuaObjectEmbeddedRecord24*>(recordBegin);
		auto* const end = reinterpret_cast<LuaObjectEmbeddedRecord24*>(recordEnd);
		while (cursor != end) {
			cursor->object.~LuaObject();
			++cursor;
		}

		return recordBegin;
	}

	/**
	 * Address: 0x005788E0 (FUN_005788E0)
	 *
	 * What it does:
	 * Copy-constructs `count` consecutive destination lanes from one source
	 * `LuaObject` and returns destination end.
	 */
	LuaPlus::LuaObject* CopyConstructLuaObjectCountAndReturnEnd(
		const LuaPlus::LuaObject* const source,
		LuaPlus::LuaObject* destination,
		const int count
	)
	{
		for (int remaining = count; remaining > 0; --remaining) {
			if (destination != nullptr) {
				::new (destination) LuaPlus::LuaObject(*source);
			}
			++destination;
		}

		return destination;
	}

	/**
	 * Address: 0x00578ED0 (FUN_00578ED0)
	 *
	 * What it does:
	 * Assigns one source `LuaObject` value into each destination lane in
	 * `[destinationBegin, destinationEnd)` and returns the pointer returned by
	 * the final assignment call (or `destinationBegin` when the range is empty).
	 */
	LuaPlus::LuaObject* AssignLuaObjectRangeForward(
		LuaPlus::LuaObject* const destinationBegin,
		const LuaPlus::LuaObject* const source,
		LuaPlus::LuaObject* const destinationEnd
	)
	{
		LuaPlus::LuaObject* lastAssigned = destinationBegin;
		for (LuaPlus::LuaObject* cursor = destinationBegin; cursor != destinationEnd; ++cursor) {
			lastAssigned = &((*cursor) = *source);
		}

		return lastAssigned;
	}

	/**
	 * Address: 0x00578EF0 (FUN_00578EF0)
	 *
	 * What it does:
	 * Reverse-assigns one source range `[sourceBegin, sourceEnd)` into
	 * destination lanes ending at `destinationEnd`, returning destination begin.
	 */
	LuaPlus::LuaObject* AssignLuaObjectRangeBackward(
		LuaPlus::LuaObject* sourceEnd,
		LuaPlus::LuaObject* destinationEnd,
		LuaPlus::LuaObject* const sourceBegin
	)
	{
		while (sourceEnd != sourceBegin) {
			--sourceEnd;
			--destinationEnd;
			*destinationEnd = *sourceEnd;
		}

		return destinationEnd;
	}

	/**
	 * Address: 0x004C7C70 (FUN_004C7C70, gpg::fastvector_LuaObject::clear)
	 *
	 * IDA signature:
	 * LuaPlus::LuaObject *__usercall std::vector_LuaObject::clear@<eax>(
	 *   gpg::fastvector_LuaObject *this@<edi>);
	 *
	 * What it does:
	 * Destroys every live `LuaPlus::LuaObject` element in one
	 * fastvector runtime view, then either keeps inline storage (when
	 * the active buffer matches the saved inline-origin pointer) or
	 * frees the active heap buffer and rebinds the view back to its
	 * inline lane, reading the saved inline-capacity sentinel from the
	 * first pointer slot of the inline buffer.
	 */
	void ClearAndResetLuaObjectFastVector(gpg::fastvector_runtime_view<LuaPlus::LuaObject>& view) noexcept
	{
		for (LuaPlus::LuaObject* it = view.begin; it != view.end; ++it) {
			it->~LuaObject();
		}

		gpg::FastVectorRuntimeResetToInline(view);
	}
}

namespace gpg
{
	/**
	 * Address: 0x00916E60 (FUN_00916E60, gpg::RRef_WrapFile)
	 *
	 * IDA signature:
	 * gpg::RRef *__cdecl gpg::RRef_WrapFile(gpg::RRef *out, char *object);
	 *
	 * What it does:
	 * Builds a reflected reference for one `WrapFile` payload (internal
	 * LuaObject.cpp userdata type) using the cached RTTI lookup and the
	 * 3-slot TLS derived-type normalization helper. `WrapFile` is a
	 * non-polymorphic struct so the runtime-type compare-equal fast path
	 * always fires and the derived-type TLS-cache lanes are dead code in
	 * this instantiation; the effective behavior is
	 * `(out->mObj = object; out->mType = CachedType<WrapFile>())`.
	 */
	gpg::RRef* RRef_WrapFile(gpg::RRef* const out, void* const object)
	{
		return RRefWrapFileImpl(out, static_cast<WrapFileRuntimeView*>(object));
	}
}

// Part of LuaObject.cpp, included there: the io library (liolib).

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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);

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
	 *
	 * Engine addition (dedicated-server plan WPL.15): the names are sorted in
	 * NTFS's order (`gpg::STR_FileNameOrderLess`) before they go into the
	 * table, the order the shipped game gets them in on NTFS, on every platform
	 * and file system. Init scripts mount what this lists in this order.
	 */
	int LuaIoDir(lua_State* const state)
	{
		const char* const wildcard = lua_tostring(state, 1);
		lua_newtable(state);

		std::vector<std::string> names{};
		__finddata64_t findData{};
		const intptr_t findHandle = ::_findfirst64(wildcard, &findData);
		if (findHandle != -1) {
			do {
				names.emplace_back(findData.name);
			} while (::_findnext64(findHandle, &findData) == 0);
			(void)::_findclose(findHandle);
		}
		// Engine addition (dedicated-server plan WPR.22): res_EnumOrderFuzz shuffles them first.
		moho::DISK_FuzzEnumerationOrder(names.begin(), names.end(), [](const std::string& name) { return name.c_str(); });
		std::sort(names.begin(), names.end(), [](const std::string& lhs, const std::string& rhs) {
			return gpg::STR_FileNameOrderLess(lhs.c_str(), rhs.c_str());
		});

		int index = 1;
		for (const std::string& name : names) {
			lua_pushnumber(state, static_cast<lua_Number>(index));
			lua_pushstring(state, name.c_str());
			lua_settable(state, -3);
			++index;
		}

		return 1;
	}

	bool ReadLine(std::FILE* const stream, lua_State* const state);
	gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFile* const wrapFile);

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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);

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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);
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
	WrapFile* NewFileUserdata(lua_State* const state, const bool closeEnabled)
	{
		gpg::RRef reference{};
		lua_newuserdata_ref(&reference, state, CachedType<WrapFile>(gWrapFileType));
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);

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
	void DestroyWrapFileStorage(WrapFile* const wrapFile)
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
	std::intptr_t FinalizeWrapFileStorage(WrapFile* const wrapFile)
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
	gpg::RRef NewWrapFileStorageRef()
	{
		auto* const wrapFile = static_cast<WrapFile*>(::operator new(sizeof(WrapFile), std::nothrow));
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		// Returned by value, as `RType::new_ref_func_t` declares it: each ABI then passes the
		// result as its callers expect (MSVC through a hidden pointer, System V x64 in
		// registers); a `RRef*(RRef*)` body cast to that type only matches the first.
		gpg::RRef out{};
		(void)BuildWrapFileRef(&out, wrapFile);
		return out;
	}

	/**
	 * Address: 0x00917D40 (FUN_00917D40, sub_917D40)
	 *
	 * What it does:
	 * Initializes caller-owned WrapFile storage and returns the reflected
	 * `gpg::RRef` view of that payload.
	 */
	gpg::RRef ConstructWrapFileStorageRef(void* const storage)
	{
		auto* const wrapFile = static_cast<WrapFile*>(storage);
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		// By value, as `RType::ctor_ref_func_t` declares it (see NewWrapFileStorageRef).
		gpg::RRef out{};
		(void)BuildWrapFileRef(&out, wrapFile);
		return out;
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
		newRefFunc_ = &NewWrapFileStorageRef;
		ctorRefFunc_ = &ConstructWrapFileStorageRef;
		deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(reinterpret_cast<void (*)()>(&FinalizeWrapFileStorage));
		Finish();
	}

	/**
	 * Address: 0x00918070 (FUN_00918070, WrapFileTypeInfo deleting-dtor thunk)
	 *
	 * What it does:
	 * Tears down one `WrapFileTypeInfo` descriptor via `gpg::RType` base
	 * teardown and conditionally frees storage when `deleteFlag & 1`.
	 */
	[[maybe_unused]] gpg::RType* DestroyWrapFileTypeInfoDeleting(
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
	[[maybe_unused]] gpg::RType* DestroyTObjectTypeInfoDeleting(
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
	 * reflection registry using `typeid(LuaPlus::TObject)`.
	 */
	TObjectTypeInfo::TObjectTypeInfo()
	{
		gpg::PreRegisterRType(typeid(LuaPlus::TObject), this);
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
		size_ = sizeof(LuaPlus::TObject);
		gpg::RType::Init();
		Finish();
	}

	/**
	 * Address: 0x00C099A0 (FUN_00C099A0, atexit destructor of the WrapFileTypeInfo object)
	 */
	[[nodiscard]] WrapFileTypeInfo& AcquireWrapFileTypeInfo()
	{
		static WrapFileTypeInfo sInstance;
		return sInstance;
	}

	/**
	 * Address: 0x00C09E20 (FUN_00C09E20, atexit destructor of the TObjectTypeInfo object)
	 */
	[[nodiscard]] TObjectTypeInfo& AcquireTObjectTypeInfo()
	{
		static TObjectTypeInfo sInstance;
		return sInstance;
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
	struct LuaObjectTypeInfoBootstrap
	{
		LuaObjectTypeInfoBootstrap()
		{
			(void)AcquireWrapFileTypeInfo();
			(void)AcquireTObjectTypeInfo();
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
	[[maybe_unused]] gpg::RType* ConfigureWrapFileCleanupCallbacks(gpg::RType* const type)
	{
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(reinterpret_cast<void (*)()>(&FinalizeWrapFileStorage));
		return type;
	}

	/**
	 * Address: 0x00917F10 (FUN_00917F10, sub_917F10)
	 *
	 * What it does:
	 * Binds WrapFile `new-ref` and `construct-ref` callbacks onto one
	 * reflection type descriptor lane.
	 */
	[[maybe_unused]] gpg::RType* ConfigureWrapFileRefCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = &NewWrapFileStorageRef;
		type->ctorRefFunc_ = &ConstructWrapFileStorageRef;
		return type;
	}

	/**
	 * Address: 0x00917F30 (FUN_00917F30, sub_917F30)
	 *
	 * What it does:
	 * Binds full WrapFile callback suite (`new/construct/delete/destruct`) onto
	 * one reflection type descriptor lane.
	 */
	[[maybe_unused]] gpg::RType* ConfigureWrapFileAllCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = &NewWrapFileStorageRef;
		type->ctorRefFunc_ = &ConstructWrapFileStorageRef;
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(reinterpret_cast<void (*)()>(&FinalizeWrapFileStorage));
		return type;
	}

	/**
	 * Address: 0x00917F60 (FUN_00917F60, sub_917F60)
	 *
	 * What it does:
	 * Binds the full WrapFile callback suite directly onto one reflection type
	 * descriptor lane without returning the descriptor.
	 */
	[[maybe_unused]] void ConfigureWrapFileAllCallbacksInPlace(gpg::RType* const type)
	{
		type->newRefFunc_ = &NewWrapFileStorageRef;
		type->ctorRefFunc_ = &ConstructWrapFileStorageRef;
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(reinterpret_cast<void (*)()>(&FinalizeWrapFileStorage));
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
	gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFile* const wrapFile)
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
	gpg::RRef* RRefWrapFileImpl(gpg::RRef* const out, WrapFile* const object)
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
	[[maybe_unused]] void ValidateWrapFileUserdataAt(lua_State* const state, const int index)
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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);
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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);
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
		WrapFile* const wrapFile = NewFileUserdata(state, true);
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
		WrapFile* const wrapFile = TryUpcastWrapFile(&reference);

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

		WrapFile* const wrapFile = NewFileUserdata(state, true);
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

		WrapFile* const wrapFile = NewFileUserdata(state, true);
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
		moho::DISK_InvalidateFileLookups(); // engine addition (res_CacheFileLookups)
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
		moho::DISK_InvalidateFileLookups(); // engine addition (res_CacheFileLookups)
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
					// Plan WPL.17: the Windows CRT's NaN text (LuaNumberText.h).
					char rendered[64];
					(void)lua::FormatNumberLikeWindowsCrt(rendered, "%.14g", value);
					writeSucceeded = std::fputs(rendered, stream) >= 0 ? 1 : 0;
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
				WrapFile* const wrapFile = NewFileUserdata(state, true);
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
		WrapFile* const wrapFile = NewFileUserdata(state, true);
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

	int ReadZioByte(ZIO* const stream)
	{
		const std::size_t available = stream->remainingBytes;
		stream->remainingBytes = available - 1u;
		if (available == 0u) {
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
		LoadState* const loadState
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
		LoadState* const loadState,
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

#pragma once

#include <string>
#include <type_traits>
#include "lua/LuaRuntimeTypes.h"

namespace gpg
{
	class RType;
}

namespace LuaPlus
{
#pragma pack(push, 4)

	class LuaObject
	{
	public:
		inline static gpg::RType* sType = nullptr;

		class MiniLuaObject
		{
		public:
			LuaObject* m_next;   // Forward link in root-state owned LuaObject list.
			LuaObject** m_prev;  // Back-link as pointer-to-link for O(1) unlink.
		};

		/**
		 * Address: 0x009072A0 (FUN_009072A0, LuaPlus::LuaObject::LuaObject)
		 *
		 * What it does:
		 * Initializes an empty LuaObject with null state/list links and NIL type.
		 */
		LuaObject();
		explicit LuaObject(LuaState* state);
		LuaObject(LuaState* state, int32_t stackIndex);
		explicit LuaObject(const LuaStackObject& stackObject);

		/**
		 * Address: 0x00908A40 (FUN_00908A40, LuaPlus::LuaObject::LuaObject)
		 *
		 * What it does:
		 * Copy-constructs a LuaObject by linking to the source object's state list
		 * and copying its tagged value payload when a state is present.
		 */
		LuaObject(const LuaObject& other);

		/**
		 * Address: 0x00908AB0 (FUN_00908AB0, LuaPlus::LuaObject::operator=)
		 *
		 * What it does:
		 * Rebinds this object to the source object's Lua state/value and preserves
		 * intrusive used-list ownership semantics.
		 */
		LuaObject& operator=(const LuaObject& other);
		~LuaObject();

		/**
		 * Address: 0x009072B0 (FUN_009072B0, LuaPlus::LuaObject::GetActiveState)
		 *
		 * What it does:
		 * Returns the active `LuaState` wrapper (`stateUserData`) from this
		 * object's root C-state lane.
		 */
		LuaState* GetActiveState() const;

		/**
		 * Address: 0x009072C0 (FUN_009072C0, LuaPlus::LuaObject::GetActiveCState)
		 *
		 * What it does:
		 * Returns the active C Lua state pointer for this object's root state.
		 */
		lua_State* GetActiveCState() const;

		/**
		 * Address: 0x009088E0
		 * @param state 
		 * @param obj 
		 */
		void AddToUsedObjectList(LuaState* state, TObject* obj);

		/**
		 * Address: 0x00908890
		 *
		 * @param state 
		 */
		void AddToUsedList(LuaState* state);
		void Reset();

		/**
		 * Address: 0x009072B0
		 *
		 * Rules:
		 * - false if no state (m_state == nullptr)
		 * - false if type is NIL (tt == 0)
		 * - if type is BOOLEAN, return underlying boolean value
		 * - true for any other non-NIL type
		 */
		explicit operator bool() const noexcept;

		/**
		 * Address: 0x009074B0
		 *
		 * @param key 
		 * @param obj 
		 */
		void SetTableHelper(const char* key, TObject* obj);
		void SetTableHelper(int32_t index, TObject* obj);

		/**
		 * Address: 0x00907D10 (FUN_00907D10)
		 * Mangled: ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z
		 *
		 * Pushes this object's `TObject` payload into `state->top`, validates root-state
		 * ownership, extends stack space when needed, and returns the pre-increment slot.
		 */
		StkId PushStack(lua_State* state) const;
		StkId PushStack(LuaState* state) const;

		/**
		 * Address: 0x00909940
		 *
		 * @param state 
		 * @param nArray 
		 * @param lnHash 
		 */
		void AssignNewTable(LuaState* state, int32_t nArray, uint32_t lnHash);

		/**
		 * Address: 0x009096A0
		 *
		 * @param state 
		 * @param number 
		 */
		void AssignNumber(LuaState* state, double number);
		void AssignInteger(LuaState* state, int32_t value)
		{
			AssignNumber(state, static_cast<double>(value));
		}
		void AssignNil(LuaState* state);
		void AssignBoolean(LuaState* state, bool value);
		void AssignString(LuaState* state, const char* value);
		void AssignLightUserData(LuaState* state, void* value);
		gpg::RRef AssignNewUserData(LuaState* state, const gpg::RRef& value);

		/**
		 * Address: 0x009084E0
		 *
		 * @param index 
		 * @param value 
		 */
		void SetString(int32_t index, const char* value);

		/**
		 * Address: 0x00908450
		 *
		 * @param key 
		 * @param value 
		 */
		void SetString(const char* key, const char* value);

		/**
		 * Address: 0x00908320
		 *
		 * @param key 
		 * @param value 
		 */
		void SetNumber(int32_t index, float value);
		void SetNumber(const char* key, float value);
		void SetInteger(const char* key, int32_t value);
		void SetBoolean(const char* key, bool value);

		/**
		 * Address: 0x00908760
		 *
		 * @param key 
		 * @param value 
		 */
		void SetObject(const char* key, const LuaObject& value);
		void SetObject(const char* key, LuaObject* value);
		void SetObject(const LuaObject& key, const LuaObject& value);

		/**
		 * Address: 0x009087A0
		 *
		 * @param index 
		 * @param value 
		 */
		void SetObject(int32_t index, const LuaObject& value);
		void SetObject(int32_t index, LuaObject* value);
		void SetMetaTable(const LuaObject& valueObj);

		/**
		 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
		 *
		 * What it does:
		 * Calls Lua `table.insert(this, key, obj)` using the active state and
		 * restores the caller's original Lua stack top.
		 */
		void Insert(int32_t key, const LuaObject& obj) const;

		/**
		 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
		 *
		 * @param index
		 * @return
		 */
		[[nodiscard]]
		LuaObject GetByIndex(int32_t index) const;

		[[nodiscard]]
		LuaObject GetByName(const char* name) const;

		/**
		 * Address: 0x00908F60 (FUN_00908F60, LuaPlus::LuaObject::operator[])
		 *
		 * What it does:
		 * Looks up a string key in a table object using the VM's interned-string
		 * table path, then returns the raw table slot value as a LuaObject.
		 */
		[[nodiscard]]
		LuaObject operator[](const char* name) const;

		/**
		 * Address: 0x009091E0 (FUN_009091E0, LuaPlus::LuaObject::operator[])
		 *
		 * What it does:
		 * Validates integer indexing on a table object and returns the raw table
		 * slot value for the numeric key.
		 */
		[[nodiscard]]
		LuaObject operator[](int32_t index) const;

		[[nodiscard]]
		LuaObject Lookup(const char* path) const;

		[[nodiscard]]
		int32_t GetN() const;

		[[nodiscard]] int32_t GetCount() const
		{
			return GetN();
		}

		[[nodiscard]] const char* ToString() const;

		/**
		 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
		 *
		 * What it does:
		 * Raises one typed-operation error for this object value.
		 */
		void TypeError(const char* operation) const;

		void Register(const char* key, CFunction value, int32_t tagMethod);

		/**
		 * Address: 0x004D2A40 (FUN_004D2A40, Moho::SCR_FromByteStream)
		 *
		 * What it does:
		 * Deserializes one tagged Lua payload from the binary stream into `out`.
		 * Table payloads are decoded recursively and reject nil keys/values.
		 */
		void SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader);

		/**
		 * Address: 0x004D2C80 (FUN_004D2C80, ?SCR_ToByteStream@Moho@@YA_NABVLuaObject@LuaPlus@@AAVStream@gpg@@@Z)
		 *
		 * What it does:
		 * Serializes one Lua value into the SCR tagged byte-stream format
		 * (nil/boolean/number/string/table) with recursive table key/value emission.
		 */
		bool ToByteStream(gpg::Stream& stream);

		/**
		 * Type checking methods
		 */
		template <int kTypeTag>
		[[nodiscard]] bool IsTaggedType() const noexcept
		{
			return m_state && m_object.tt == kTypeTag;
		}

		[[nodiscard]] bool IsNil() const noexcept { return !m_state || m_object.tt == LUA_TNIL; }
		[[nodiscard]] bool IsBoolean() const noexcept { return IsTaggedType<LUA_TBOOLEAN>(); }
		[[nodiscard]] bool IsNumber() const noexcept { return IsTaggedType<LUA_TNUMBER>(); }
		[[nodiscard]] bool IsString() const noexcept { return IsTaggedType<LUA_TSTRING>(); }

		/**
		 * Address: 0x00907310 (FUN_00907310, LuaPlus::LuaObject::IsTable)
		 *
		 * What it does:
		 * Returns whether this tagged Lua value is a table.
		 */
		[[nodiscard]] bool IsTable() const noexcept { return m_object.tt == LUA_TTABLE; }

		/**
		 * Address: 0x0128BF90 (FUN_0128BF90, LuaPlus::LuaObject::IsFunction)
		 *
		 * What it does:
		 * Asserts the object is bound to a Lua state, then reports whether the
		 * wrapped tagged value is a Lua function.
		 */
		[[nodiscard]] bool IsFunction() const;

		[[nodiscard]] bool IsUserData() const noexcept { return m_state && (m_object.tt == LUA_TUSERDATA || m_object.tt == LUA_TLIGHTUSERDATA); }

		/**
		 * Value getters
		 */
		[[nodiscard]] bool GetBoolean() const noexcept { return m_object.value.b != 0; }
		[[nodiscard]] double GetNumber() const noexcept { return static_cast<double>(m_object.value.n); }
		[[nodiscard]] int32_t GetInteger() const noexcept;

		/**
		 * Address: 0x00907A90 (FUN_00907A90, LuaPlus::LuaObject::GetString)
		 *
		 * What it does:
		 * Asserts this object is bound to a Lua state, raises Lua's typed-operation
		 * error when the value is not a string, and returns the underlying
		 * interned-string character buffer.
		 */
		[[nodiscard]] const char* GetString() const;

	public:
		LuaObject* m_next; // Intrusive list node next (managed by LuaState root).
		LuaObject** m_prev; // Intrusive list back-link (pointer-to-owner-link).
		LuaState* m_state; // Owning root LuaState wrapper.
		TObject m_object;  // Cached tagged Lua value payload.
	};
	static_assert(sizeof(LuaObject) == 0x14, "LuaObject must be 0x14");

	class LuaStackObject
	{
	public:
		LuaStackObject()
			: m_state(nullptr)
			, m_stackIndex(0)
		{
		}

		/**
		 * Address: 0x00415490 (FUN_00415490, LuaPlus::LuaStackObject::LuaStackObject)
		 *
		 * What it does:
		 * Captures a `(LuaState*, stackIndex)` pair for deferred stack-value access.
		 */
		LuaStackObject(LuaState* state, int32_t stackIndex);
		[[nodiscard]] bool IsNil() const;

		/**
		 * Address: 0x004154B0 (FUN_004154B0, LuaPlus::LuaStackObject::TypeError)
		 *
		 * What it does:
		 * Raises a Lua argument type error for the current stack slot.
		 */
		void TypeError(const char* expectedType) const;
		void TypeError(const char* expectedType, int32_t) const;
		static void TypeError(LuaStackObject* self, const char* expectedType);

		/**
		 * Address: 0x00415530 (FUN_00415530, LuaPlus::LuaStackObject::GetString)
		 *
		 * What it does:
		 * Reads the current stack slot as a string, raising a type error when
		 * Lua cannot coerce the value.
		 */
		[[nodiscard]] const char* GetString() const;

		/**
		 * Address: 0x0041B520 (FUN_0041B520, LuaPlus::LuaStackObject::GetInteger)
		 *
		 * What it does:
		 * Reads the current stack slot as an integer number and raises a type
		 * error when the Lua value is not numeric.
		 */
		[[nodiscard]] int32_t GetInteger() const;

		[[nodiscard]] double ToNumber() const;

		/**
		 * Address: 0x00415560 (FUN_00415560, LuaPlus::LuaStackObject::GetBoolean)
		 *
		 * What it does:
		 * Reads the current stack slot as a boolean, allowing nil as false.
		 */
		[[nodiscard]] bool GetBoolean() const;
		[[nodiscard]] static bool GetBoolean(const LuaStackObject* self)
		{
			return self != nullptr ? self->GetBoolean() : false;
		}

	public:
		LuaState* m_state;     // Wrapper state that owns the stack view.
		int32_t m_stackIndex;  // Lua stack index captured by this view.
	};
	static_assert(sizeof(LuaStackObject) == 0x08, "LuaStackObject must be 0x08");

	class LuaState
	{
	public:
		LuaState() = default;

		/**
		 * Address: 0x0090A520 (FUN_0090A520, LuaPlus::LuaState::LuaState)
		 *
		 * What it does:
		 * Creates a coroutine thread state rooted in `parentState->m_rootState`,
		 * captures the new thread object from the root stack, and binds
		 * `stateUserData` back to this wrapper.
		 */
		explicit LuaState(LuaState* parentState);

		/**
		 * Address: 0x0090A600 (FUN_0090A600, LuaPlus::LuaState::~LuaState)
		 *
		 * What it does:
		 * Clears root-owned live LuaObject lanes, detaches state userdata,
		 * optionally closes owned lua_State, then destroys `m_threadObj`.
		 */
		~LuaState();

		lua_State* GetCState() const;

		/**
		 * Address: 0x10008F20 (?GetGlobal@LuaState@LuaPlus@@QAE?AVLuaObject@2@PBD@Z)
		 */
		[[nodiscard]]
		LuaObject GetGlobal(const char* name);

		/**
		 * Address: 0x1000A4A0 (?GetGlobals@LuaState@LuaPlus@@QAE?AVLuaObject@2@XZ)
		 */
		[[nodiscard]]
		LuaObject GetGlobals();

		LuaState* GetRootState();
		const LuaState* GetRootState() const;
		LuaState* GetActiveState();
		lua_State* GetActiveCState();
		const LuaObject* GetThreadObject() const;
		LuaStackObject Stack(int32_t index);
		int32_t GetTop() const;
		bool IsRootState() const;
		bool IsSuspended() const;
		static void Error(LuaState* state, const char* format, ...);

	public:
		lua_State* m_state;                    // Underlying C lua_State*.
		moho::CLuaTask* m_luaTask;             // Engine CLuaTask owner (if any).
		uint8_t m_ownState;                    // 1 when wrapper owns/destroys lua_State.
		uint8_t m_pad9[3];
		LuaObject m_threadObj;                 // LuaObject representing this thread in parent/root state.
		LuaState* m_rootState;                 // Root wrapper for shared LuaObject tracking.
		LuaObject::MiniLuaObject m_headObject; // Sentinel head for live LuaObject intrusive list.
		LuaObject::MiniLuaObject m_tailObject; // Sentinel tail for live LuaObject intrusive list.
	};
	static_assert(sizeof(LuaState) == 0x34, "LuaState must be 0x34");

	/**
	 * Address: 0x00456AE0 (FUN_00456AE0, sub_456AE0)
	 *
	 * LuaState *,char const *
	 *
	 * What it does:
	 * Pushes one C-string to the Lua stack and returns a stack-object view for
	 * the pushed slot.
	 */
	[[nodiscard]] LuaStackObject PushStringAndCaptureStackObject(LuaState* state, const char* value);

	inline void LuaPush(lua_State* L, LuaPlus::LuaObject& obj)
	{
		obj.PushStack(L);
	}

	inline void LuaPush(lua_State* L, const LuaPlus::LuaObject& obj)
	{
		const_cast<LuaPlus::LuaObject&>(obj).PushStack(L);
	}

	inline void LuaPush(lua_State* L, LuaPlus::LuaObject* obj)
	{
		if (obj) {
			obj->PushStack(L);
		} else {
			lua_pushnil(L);
		}
	}

	inline void LuaPush(lua_State* L, const LuaPlus::LuaObject* obj)
	{
		if (obj) {
			const_cast<LuaPlus::LuaObject*>(obj)->PushStack(L);
		} else {
			lua_pushnil(L);
		}
	}

	inline void LuaPush(lua_State* L, const char* s)
	{
		lua_pushstring(L, s ? s : "");
	}

	inline void LuaPush(lua_State* L, char* s)
	{
		lua_pushstring(L, s ? s : "");
	}

	inline void LuaPush(lua_State* L, const msvc8::string& s)
	{
		lua_pushlstring(L, s.c_str(), static_cast<size_t>(s.size()));
	}

	inline void LuaPush(lua_State* L, const std::string& s)
	{
		lua_pushlstring(L, s.c_str(), static_cast<size_t>(s.size()));
	}

	inline void LuaPush(lua_State* L, bool v)
	{
		lua_pushboolean(L, v ? 1 : 0);
	}

	inline void LuaPush(lua_State* L, int v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	inline void LuaPush(lua_State* L, unsigned int v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	inline void LuaPush(lua_State* L, long v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	inline void LuaPush(lua_State* L, unsigned long v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	inline void LuaPush(lua_State* L, float v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	inline void LuaPush(lua_State* L, double v)
	{
		lua_pushnumber(L, static_cast<lua_Number>(v));
	}

	template<class Ret = void>
	class LuaFunction : public LuaObject
	{
	public:
		/**
		 * Address: 0x0041F910 (FUN_0041F910, ??0LuaFunction@LuaPlus@@QAE@@Z_0)
		 *
		 * What it does:
		 * Wraps a Lua object as callable function and throws a Lua type error
		 * when the source object is not a function.
		 */
		explicit LuaFunction(const LuaObject& obj)
			: LuaObject(obj) {
			if (!IsFunction()) {
				TypeError("call");
			}
		}

		template<class... Ts>
		Ret operator()(const Ts&... args) const {
			LuaState* st = GetActiveState();
			if (!st) {
				if constexpr (std::is_void_v<Ret>) {
					return;
				} else {
					return Ret{};
				}
			}

			lua_State* L = st->GetCState();
			const int savedTop = lua_gettop(L);
			PushStack(L);
			(LuaPush(L, args), ...);

			constexpr int kResultCount = std::is_void_v<Ret> ? 0 : 1;
			lua_call(L, sizeof...(Ts), kResultCount);

			if constexpr (std::is_void_v<Ret>) {
				lua_settop(L, savedTop);
				return;
			} else if constexpr (std::is_same_v<Ret, LuaObject>) {
				Ret result{ LuaStackObject(st, -1) };
				lua_settop(L, savedTop);
				return result;
			} else {
				lua_settop(L, savedTop);
				return Ret{};
			}
		}

		void Call(LuaObject& obj, const char* s, const char* a4, const char* a5) const {
			(void)(*this)(obj, s, a4, a5);
		}

		void Call(LuaObject& obj, const char* arg0) const {
			(void)(*this)(obj, arg0);
		}
	};

	template<>
	class LuaFunction<const char*> : public LuaObject
	{
	public:
		/**
		 * Address: 0x004798B0 (FUN_004798B0, LuaPlus::LuaFunction::LuaFunction)
		 *
		 * What it does:
		 * Wraps a Lua object as callable function and raises type error for
		 * non-function values.
		 */
		explicit LuaFunction(const LuaObject& obj)
			: LuaObject(obj) {
			if (!IsFunction()) {
				TypeError("call");
			}
		}

		/**
		 * Address: 0x00479910 (FUN_00479910, LuaPlus::LuaFunction::operator())
		 *
		 * What it does:
		 * Calls Lua function with one string argument and returns Lua string result.
		 */
		[[nodiscard]] const char* operator()(const char* s) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, s);
			lua_call(activeState, 1, 1);
			const char* const result = lua_tostring(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}
	};

	inline LuaState*& g_ConsoleLuaState()
	{
		// Base image has no ASLR in this build.
		static auto** pp = reinterpret_cast<LuaState**>(0x010A6478);
		return *pp;
	}
#pragma pack(pop)
}

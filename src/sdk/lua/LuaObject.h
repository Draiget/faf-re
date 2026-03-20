#pragma once

#include <string>
#include <type_traits>
#include "lua/LuaRuntimeTypes.h"

namespace LuaPlus
{
#pragma pack(push, 4)

	class LuaObject
	{
	public:
		class MiniLuaObject
		{
		public:
			LuaObject* m_next;   // Forward link in root-state owned LuaObject list.
			LuaObject** m_prev;  // Back-link as pointer-to-link for O(1) unlink.
		};

		LuaObject();
		explicit LuaObject(LuaState* state);
		LuaObject(LuaState* state, int32_t stackIndex);
		explicit LuaObject(const LuaStackObject& stackObject);
		LuaObject(const LuaObject& other);
		LuaObject& operator=(const LuaObject& other);
		~LuaObject();

		/**
		 * Address: 0x009072B0
		 * @return 
		 */
		LuaState* GetActiveState() const;
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
		 * Address: 0x00907D10
		 *
		 * Push this object's value onto the given lua_State stack and return the slot used.
		 * Preconditions:
		 * - Both states must share the same global state (state->l_G == m_state->m_state->l_G).
		 * Behavior:
		 * - Writes m_object into *state->top, returns the address of that slot (old top),
		 *   ensures at least one extra slot (lua_checkstack) if top reached ci->top,
		 *   then increments state->top.
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
		 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
		 *
		 * @param index
		 * @return
		 */
		[[nodiscard]]
		LuaObject GetByIndex(int32_t index) const;

		[[nodiscard]]
		LuaObject GetByName(const char* name) const;

		[[nodiscard]]
		int32_t GetN() const;

		void Register(const char* key, CFunction value, int32_t tagMethod);

		/**
		 * Address: 0x004D2A40
		 *
		 * @param state 
		 * @param reader 
		 * @return 
		 */
		void SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader);

		/**
		 * Address: 0x004D2C80
		 *
		 * @param stream 
		 */
		bool ToByteStream(gpg::Stream& stream);

		/**
		 * Type checking methods
		 */
		[[nodiscard]] bool IsNil() const noexcept { return !m_state || m_object.tt == LUA_TNIL; }
		[[nodiscard]] bool IsBoolean() const noexcept { return m_state && m_object.tt == LUA_TBOOLEAN; }
		[[nodiscard]] bool IsNumber() const noexcept { return m_state && m_object.tt == LUA_TNUMBER; }
		[[nodiscard]] bool IsString() const noexcept { return m_state && m_object.tt == LUA_TSTRING; }
		[[nodiscard]] bool IsTable() const noexcept { return m_state && m_object.tt == LUA_TTABLE; }
		[[nodiscard]] bool IsUserData() const noexcept { return m_state && (m_object.tt == LUA_TUSERDATA || m_object.tt == LUA_TLIGHTUSERDATA); }

		/**
		 * Value getters
		 */
		[[nodiscard]] bool GetBoolean() const noexcept { return m_object.value.b != 0; }
		[[nodiscard]] double GetNumber() const noexcept { return static_cast<double>(m_object.value.n); }
		[[nodiscard]] const char* GetString() const noexcept;

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
		LuaStackObject(LuaState* state, int32_t stackIndex);
		[[nodiscard]] bool IsNil() const;
		[[nodiscard]] const char* GetString() const;

	public:
		LuaState* m_state;     // Wrapper state that owns the stack view.
		int32_t m_stackIndex;  // Lua stack index captured by this view.
	};
	static_assert(sizeof(LuaStackObject) == 0x08, "LuaStackObject must be 0x08");

	class LuaState
	{
	public:
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
		explicit LuaFunction(const LuaObject& obj)
			: LuaObject(obj) {
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

	inline LuaState*& g_ConsoleLuaState()
	{
		// Base image has no ASLR in this build.
		static auto** pp = reinterpret_cast<LuaState**>(0x010A6478);
		return *pp;
	}
#pragma pack(pop)
}

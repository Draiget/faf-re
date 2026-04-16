#pragma once

#include <string>
#include <type_traits>
#include "lua/LuaRuntimeTypes.h"

namespace gpg
{
	class ReadArchive;
	class RType;
	class WriteArchive;
	class RRef;
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

		/**
		 * Address: 0x005280D0 (FUN_005280D0, ??0LuaObject@LuaPlus@@QAE@@Z)
		 *
		 * What it does:
		 * Casts one raw C Lua state pointer to the owning `LuaState` wrapper and
		 * forwards construction to the stack-lane constructor with index `-1`.
		 */
		explicit LuaObject(lua_State* state);
		explicit LuaObject(LuaState* state);
		LuaObject(LuaState* state, int32_t stackIndex);

		/**
		 * Address: 0x009089F0 (FUN_009089F0, LuaPlus::LuaObject::LuaObject)
		 *
		 * What it does:
		 * Binds this object to one caller-provided raw `TObject` lane and inserts
		 * it into the owning root-state used-object list.
		 */
		LuaObject(LuaState* state, TObject* obj);

		/**
		 * Address: 0x00908A70 (FUN_00908A70, ??0LuaObject@LuaPlus@@QAE@ABVLuaStackObject@1@@Z)
		 *
		 * What it does:
		 * Binds this object to one stack-value lane from `stackObject` and inserts
		 * it into the owning root-state used-object list.
		 */
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

		/**
		 * Address: 0x00908B00 (FUN_00908B00, LuaPlus::LuaObject::operator=)
		 *
		 * What it does:
		 * Rebinds this object to one `LuaStackObject` slot by unlinking current
		 * list ownership and linking to the resolved stack TValue lane.
		 */
		LuaObject& operator=(const LuaStackObject& stackObject);

		/**
		 * Address: 0x009075D0 (FUN_009075D0, LuaPlus::LuaObject::~LuaObject)
		   * Address: 0x005790D0 (FUN_005790D0)
		   * Address: 0x005791A0 (FUN_005791A0)
		   * Address: 0x005D0A90 (FUN_005D0A90)
		   * Address: 0x00624120 (FUN_00624120)
		 * Address: 0x00BA2E8B (FUN_00BA2E8B, LuaObject::j_Dtr_9 thunk)
		 *
		 * What it does:
		 * Unlinks this object from the owning state's intrusive used-object list
		 * when bound and clears the tagged value to nil.
		 */
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
		 * Address: 0x0090B990 (FUN_0090B990, LuaPlus::LuaObject::MemberSerialize)
		 *
		 * What it does:
		 * Serializes LuaObject state binding and tagged payload into archive.
		 */
		static void MemberSerialize(gpg::WriteArchive* archive, LuaObject* object);

		/**
		 * Address: 0x0090BDD0 (FUN_0090BDD0, LuaPlus::LuaObject::MemberDeserialize)
		 *
		 * What it does:
		 * Deserializes LuaObject state binding and tagged payload from archive.
		 */
		static void MemberDeserialize(gpg::ReadArchive* archive, LuaObject* object, int version, const gpg::RRef& ownerRef);

		/**
		 * Address: 0x009072C0 (FUN_009072C0, LuaPlus::LuaObject::GetActiveCState)
		 *
		 * What it does:
		 * Returns the active C Lua state pointer for this object's root state.
		 */
		lua_State* GetActiveCState() const;

		/**
		 * Address: 0x009088E0 (FUN_009088E0, LuaPlus::LuaObject::AddToUsedObjectList)
		 *
		 * What it does:
		 * Rebinds this object to `state`'s root used-object intrusive list and
		 * copies one caller-provided raw `TObject` payload into `m_object`.
		 */
		void AddToUsedObjectList(LuaState* state, TObject* obj);

		/**
		 * Address: 0x009099B0 (FUN_009099B0, LuaPlus::LuaObject::AssignTObject)
		 *
		 * What it does:
		 * Rebinds this object to `state`'s root used-object intrusive list only
		 * when root ownership changes, then copies one raw `TObject` payload.
		 */
		void AssignTObject(LuaState* state, TObject* obj);

		/**
		 * Address: 0x00908890 (FUN_00908890, LuaPlus::LuaObject::AddToUsedList)
		 *
		 * What it does:
		 * Rebinds this object to `state`'s root used-object intrusive list and
		 * leaves the current `m_object` payload unchanged.
		 */
		void AddToUsedList(LuaState* state);

		/**
		 * Address: 0x009075F0 (FUN_009075F0, LuaPlus::LuaObject::Reset)
		 *
		 * What it does:
		 * Unlinks this object from the used-object list and clears its Lua state
		 * and object payload back to nil.
		 */
		void Reset();

		/**
		 * Address: 0x00907440 (FUN_00907440, LuaPlus::LuaObject::operator bool)
		 *
		 * Rules:
		 * - false if no state (m_state == nullptr)
		 * - false if type is NIL (tt == 0)
		 * - if type is BOOLEAN, return underlying boolean value
		 * - true for any other non-NIL type
		 */
		explicit operator bool() const noexcept;

		/**
		 * Address: 0x0090BF00 (FUN_0090BF00)
		 *
		 * What it does:
		 * Performs Lua semantic equality on this value and `other` after matching
		 * type tags.
		 */
		[[nodiscard]] bool operator==(const LuaObject& other) const;

		/**
		 * Address: 0x0090BF40 (FUN_0090BF40)
		 *
		 * What it does:
		 * Performs Lua semantic less-than comparison between this value and
		 * `other`.
		 */
		[[nodiscard]] bool operator<(const LuaObject& other) const;

		/**
		 * Address: 0x009074B0
		 *
		 * @param key 
		 * @param obj 
		 */
		void SetTableHelper(const char* key, TObject* obj);
		void SetTableHelper(int32_t index, TObject* obj);

		/**
		 * Address: 0x00907510 (FUN_00907510)
		 *
		 * What it does:
		 * Writes one table entry by integer key directly through `luaV_settable`
		 * using a caller-provided value slot.
		 */
		void SetTableHelperRaw(int32_t index, StkId valueSlot);

		/**
		 * Address: 0x00907550 (FUN_00907550)
		 *
		 * What it does:
		 * Writes one table entry by Lua-object key through `luaV_settable` using
		 * a caller-provided value slot.
		 */
		void SetTableHelperRaw(const LuaObject& key, StkId valueSlot);

		/**
		 * Address: 0x00907ED0 (FUN_00907ED0, LuaPlus::LuaObject::SetN)
		 *
		 * What it does:
		 * Sets Lua array-length metadata for this table object.
		 */
		void SetN(int32_t n);

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
		 * Address: 0x009096A0 (FUN_009096A0, LuaPlus::LuaObject::AssignNumber)
		 *
		 * What it does:
		 * Rebinds to `state` root ownership when needed, then stores one numeric
		 * Lua payload lane (`LUA_TNUMBER`).
		 */
		void AssignNumber(LuaState* state, double number);

		/**
		 * Address: 0x00909650 (FUN_00909650, LuaPlus::LuaObject::AssignInteger)
		 *
		 * What it does:
		 * Rebinds to `state` root ownership when needed, then stores one integer
		 * payload converted to Lua number lane (`LUA_TNUMBER`).
		 */
		void AssignInteger(LuaState* state, int32_t value);
		void AssignNil(LuaState* state);

		/**
		 * Address: 0x00909600 (FUN_00909600, LuaPlus::LuaObject::AssignBoolean)
		 *
		 * What it does:
		 * Rebinds to `state` root ownership when needed, then stores one boolean
		 * payload lane (`LUA_TBOOLEAN`).
		 */
		void AssignBoolean(LuaState* state, bool value);

		/**
		 * Address: 0x00909750 (FUN_00909750, LuaPlus::LuaObject::AssignString)
		 *
		 * What it does:
		 * Rebinds root-state ownership when needed and stores one interned
		 * string payload (or `LUA_TNIL` for a null source pointer).
		 */
		void AssignString(LuaState* state, const char* value);
		void AssignLightUserData(LuaState* state, void* value);

		/**
		 * Address: 0x009097D0 (FUN_009097D0, LuaPlus::LuaObject::AssignNewUserData)
		 *
		 * What it does:
		 * Rebinds this object to `state` root ownership and stores one
		 * default-constructed reflected userdata payload of `type`.
		 */
		gpg::RRef AssignNewUserData(LuaState* state, const gpg::RType* type);

		/**
		 * Address: 0x00909840 (FUN_00909840, LuaPlus::LuaObject::AssignNewUserData)
		 *
		 * What it does:
		 * Rebinds this object to `state` root ownership and stores one reflected
		 * userdata payload built from `value`.
		 */
		gpg::RRef AssignNewUserData(LuaState* state, const gpg::RRef& value);

		/**
		 * Address: 0x009096F0 (FUN_009096F0, LuaPlus::LuaObject::AssignThread)
		 *
		 * What it does:
		 * Binds this object to one thread-state lane and updates root used-list
		 * ownership if the thread root differs from current ownership.
		 */
		void AssignThread(LuaState* state);

		/**
		 * Address: 0x00909900 (FUN_00909900, LuaPlus::LuaObject::AssignObject)
		 *
		 * What it does:
		 * Copies one source `LuaObject` payload into this object after validating
		 * shared root-state ownership.
		 *
		 * Notes:
		 * The binary keeps the `state` argument lane for ABI compatibility but
		 * does not read it in this implementation.
		 */
		void AssignObject(LuaState* state, const LuaObject& value);

		/**
		 * Address: 0x009084E0 (FUN_009084E0, LuaPlus::LuaObject::SetString)
		 *
		 * What it does:
		 * Writes one table entry by numeric index using a string-or-nil payload.
		 */
		void SetString(int32_t index, const char* value);

		/**
		 * Address: 0x00908450 (FUN_00908450, LuaPlus::LuaObject::SetString)
		 *
		 * What it does:
		 * Writes one table entry by string key using a string-or-nil payload.
		 */
		void SetString(const char* key, const char* value);

		/**
		 * Address: 0x00908590 (FUN_00908590, LuaPlus::LuaObject::SetString)
		 *
		 * What it does:
		 * Writes one table entry by LuaObject key using a string-or-nil payload
		 * after validating shared-state ownership with `key`.
		 */
		void SetString(const LuaObject& key, const char* value);

		/**
		 * Address: 0x00907FF0 (FUN_00907FF0, LuaPlus::LuaObject::SetNil)
		 *
		 * What it does:
		 * Writes one nil payload to a table field addressed by string key.
		 */
		void SetNil(const char* key);

		/**
		 * Address: 0x00907FA0 (FUN_00907FA0, LuaPlus::LuaObject::SetNil)
		 *
		 * What it does:
		 * Writes one nil payload to a table slot addressed by integer key.
		 */
		void SetNil(int32_t index);

		/**
		 * Address: 0x00908060 (FUN_00908060, LuaPlus::LuaObject::SetNil)
		 *
		 * What it does:
		 * Writes one nil payload to a table field addressed by LuaObject key
		 * after validating shared-state ownership with `key`.
		 */
		void SetNil(const LuaObject& key);

		/**
		 * Address: 0x00908370 (FUN_00908370, LuaPlus::LuaObject::SetNumber)
		 *
		 * What it does:
		 * Writes one table entry by numeric index using a numeric payload.
		 */
		void SetNumber(int32_t index, float value);

		/**
		 * Address: 0x00908320 (FUN_00908320, LuaPlus::LuaObject::SetNumber)
		 *
		 * What it does:
		 * Writes one table entry by string key using a numeric payload.
		 */
		void SetNumber(const char* key, float value);

		/**
		 * Address: 0x009083E0 (FUN_009083E0, LuaPlus::LuaObject::SetNumber)
		 *
		 * What it does:
		 * Writes one table entry by LuaObject key using a numeric payload after
		 * validating shared-state ownership with `key`.
		 */
		void SetNumber(const LuaObject& key, float value);

		/**
		 * Address: 0x00908240 (FUN_00908240, ?SetInteger@LuaObject@LuaPlus@@QBEXHH@Z)
		 *
		 * What it does:
		 * Writes one table entry by integer key using an integer payload lane.
		 */
		void SetInteger(int32_t index, int32_t value);

		/**
		 * Address: 0x009081F0 (FUN_009081F0, ?SetInteger@LuaObject@LuaPlus@@QBEXPBDH@Z)
		 *
		 * What it does:
		 * Writes one table entry by string key using an integer payload lane.
		 */
		void SetInteger(const char* key, int32_t value);

		/**
		 * Address: 0x009082B0 (FUN_009082B0, LuaPlus::LuaObject::SetInteger)
		 *
		 * What it does:
		 * Writes one table entry by LuaObject key using an integer payload lane
		 * after validating shared-state ownership with `key`.
		 */
		void SetInteger(const LuaObject& key, int32_t value);

		/**
		 * Address: 0x009080C0 (FUN_009080C0, LuaPlus::LuaObject::SetBoolean)
		 *
		 * What it does:
		 * Writes one boolean payload into this table by string key.
		 */
		void SetBoolean(const char* key, bool value);

		/**
		 * Address: 0x00908110 (FUN_00908110, LuaPlus::LuaObject::SetBoolean)
		 *
		 * What it does:
		 * Writes one boolean payload into this table by numeric index.
		 */
		void SetBoolean(int32_t index, bool value);

		/**
		 * Address: 0x00908180 (FUN_00908180, LuaPlus::LuaObject::SetBoolean)
		 *
		 * What it does:
		 * Writes one boolean payload into this table by LuaObject key after
		 * validating shared-state ownership with `key`.
		 */
		void SetBoolean(const LuaObject& key, bool value);

		/**
		 * Address: 0x00908680 (FUN_00908680, LuaPlus::LuaObject::SetLightUserData)
		 *
		 * What it does:
		 * Writes one light-userdata payload into this table by numeric index.
		 */
		void SetLightUserData(int32_t index, void* value);

		/**
		 * Address: 0x00908630 (FUN_00908630, LuaPlus::LuaObject::SetLightUserData)
		 *
		 * What it does:
		 * Writes one light-userdata payload into this table by string key.
		 */
		void SetLightUserData(const char* key, void* value);

		/**
		 * Address: 0x009086F0 (FUN_009086F0, LuaPlus::LuaObject::SetLightUserData)
		 *
		 * What it does:
		 * Writes one light-userdata payload into this table by LuaObject key after
		 * validating shared-state ownership with `key`.
		 */
		void SetLightUserData(const LuaObject& key, void* value);

		/**
		 * Address: 0x00908760 (FUN_00908760, LuaPlus::LuaObject::SetObject)
		 *
		 * What it does:
		 * Writes one table field by string key after validating that both
		 * objects share the same owning Lua state.
		 */
		void SetObject(const char* key, const LuaObject& value);
		void SetObject(const char* key, LuaObject* value);

		/**
		 * Address: 0x00908810 (FUN_00908810, LuaPlus::LuaObject::SetObject)
		 *
		 * What it does:
		 * Writes one table entry by LuaObject key/value lanes after validating
		 * shared-state ownership.
		 */
		void SetObject(const LuaObject& key, const LuaObject& value);

		/**
		 * Address: 0x009087A0
		 *
		 * @param index 
		 * @param value 
		 */
		void SetObject(int32_t index, const LuaObject& value);
		void SetObject(int32_t index, LuaObject* value);
		/**
		 * Address: 0x00907E00 (FUN_00907E00, LuaPlus::LuaObject::SetMetaTable)
		 *
		 * What it does:
		 * Assigns `valueObj` as metatable for this object after validating shared
		 * Lua-state ownership.
		 */
		void SetMetaTable(const LuaObject& valueObj);

		/**
		 * Address: 0x00908BA0 (FUN_00908BA0, LuaPlus::LuaObject::GetMetaTable)
		 *
		 * What it does:
		 * Returns this object's runtime metatable as a bound LuaObject.
		 */
		[[nodiscard]] LuaObject GetMetaTable() const;

		/**
		 * Address: 0x00908C10 (FUN_00908C10, LuaPlus::LuaObject::CreateTable)
		 *
		 * What it does:
		 * Creates one new Lua table and stores it under string key `key`.
		 */
		[[nodiscard]] LuaObject CreateTable(const char* key, int32_t narray, int32_t lnhash);

		/**
		 * Address: 0x00908CA0 (FUN_00908CA0, LuaPlus::LuaObject::CreateTable_Array)
		 *
		 * What it does:
		 * Creates one new Lua table and stores it under integer key `index`.
		 */
		[[nodiscard]] LuaObject CreateTable(int32_t index, int32_t narray, int32_t lnhash);

		/**
		 * Address: 0x00908D50 (FUN_00908D50, LuaPlus::LuaObject::CreateTable)
		 *
		 * What it does:
		 * Creates one new Lua table and stores it under LuaObject key `key`.
		 */
		[[nodiscard]] LuaObject CreateTable(const LuaObject& key, int32_t narray, int32_t lnhash);

		/**
		 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
		 *
		 * What it does:
		 * Calls Lua `table.insert(this, key, obj)` using the active state and
		 * restores the caller's original Lua stack top.
		 */
		void Insert(int32_t key, const LuaObject& obj) const;

		/**
		 * Address: 0x00909EB0 (FUN_00909EB0, LuaPlus::LuaObject::Remove)
		 *
		 * What it does:
		 * Calls Lua `table.remove(this, index)` using the active state and
		 * restores the caller's original Lua stack top.
		 */
		void Remove(int32_t index) const;

		/**
		 * Address: 0x0090A020 (FUN_0090A020, LuaPlus::LuaObject::Sort)
		 *
		 * What it does:
		 * Calls Lua `table.sort(this)` using the active state and restores the
		 * caller's original Lua stack top.
		 */
		void Sort() const;

		/**
		 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
		 *
		 * @param index
		 * @return
		 */
		[[nodiscard]]
		LuaObject GetByIndex(int32_t index) const;

		/**
		 * Address: 0x00908E70 (FUN_00908E70, LuaPlus::LuaObject::GetByObject)
		 *
		 * What it does:
		 * Looks up this table with a LuaObject key and returns the raw value.
		 */
		[[nodiscard]] LuaObject GetByObject(const LuaObject& key) const;

		/**
		 * Address: 0x00908EE0 (FUN_00908EE0, LuaPlus::LuaObject::GetByObject)
		 *
		 * What it does:
		 * Looks up this table with one Lua stack key lane and returns the raw
		 * value as a bound LuaObject.
		 */
		[[nodiscard]] LuaObject GetByObject(const LuaStackObject& obj) const;

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
		 * Address: 0x00909280 (FUN_00909280, LuaPlus::LuaObject::operator[])
		 *
		 * What it does:
		 * Validates object-state compatibility for table indexing with one
		 * LuaObject key and returns the raw table slot value.
		 */
		[[nodiscard]]
		LuaObject operator[](const LuaObject& key) const;

		/**
		 * Address: 0x009091E0 (FUN_009091E0, LuaPlus::LuaObject::operator[])
		 *
		 * What it does:
		 * Validates integer indexing on a table object and returns the raw table
		 * slot value for the numeric key.
		 */
		[[nodiscard]]
		LuaObject operator[](int32_t index) const;

		/**
		 * Address: 0x00909310 (FUN_00909310, LuaPlus::LuaObject::operator[])
		 *
		 * What it does:
		 * Validates root-state compatibility for table indexing with one
		 * LuaStackObject key and returns the raw table slot value.
		 */
		[[nodiscard]]
		LuaObject operator[](const LuaStackObject& key) const;

		/**
		 * Address: 0x009093B0 (FUN_009093B0, LuaPlus::LuaObject::Lookup)
		 *
		 * What it does:
		 * Traverses a dotted lookup path segment-by-segment; each segment is
		 * treated as numeric index when parseable, otherwise as string key.
		 */
		[[nodiscard]]
		LuaObject Lookup(const char* path) const;

		[[nodiscard]]
		int32_t GetN() const;

		/**
		 * Address: 0x00907F50 (FUN_00907F50, LuaPlus::LuaObject::GetCount)
		 *
		 * What it does:
		 * Pushes this object to the active Lua stack, reads Lua table length via
		 * `lua_getn`, then restores stack top and returns that element count.
		 */
		[[nodiscard]] int32_t GetCount() const;

		/**
		 * Address: 0x0090A410 (FUN_0090A410, LuaPlus::LuaObject::GetTableCount)
		 *
		 * What it does:
		 * Iterates all key/value pairs and returns total table-entry count.
		 */
		[[nodiscard]] int32_t GetTableCount() const;

		/**
		 * Address: 0x009073E0 (FUN_009073E0, LuaPlus::LuaObject::ToString)
		 *
		 * What it does:
		 * Returns the current interned string buffer when already string-typed;
		 * otherwise runs Lua's in-place `luaV_tostring` coercion and returns
		 * `nullptr` when conversion fails.
		 */
		[[nodiscard]] const char* ToString() const;

		/**
		 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
		 *
		 * What it does:
		 * Raises one typed-operation error for this object value.
		 */
		void TypeError(const char* operation) const;

		/**
		 * Address: 0x009076D0 (FUN_009076D0, LuaPlus::LuaObject::Type)
		 *
		 * What it does:
		 * Returns the raw Lua type tag for this object value.
		 */
		[[nodiscard]] int Type() const;

		/**
		 * Address: 0x00908B50 (FUN_00908B50, LuaPlus::LuaObject::TypeName)
		 *
		 * What it does:
		 * Returns the runtime Lua typename string for this object value.
		 */
		[[nodiscard]] const char* TypeName() const;

		/**
		 * Address: 0x00907630 (FUN_00907630, LuaPlus::LuaObject::Register)
		 *
		 * What it does:
		 * Creates one C closure using `tagMethod` stack upvalues and stores it in
		 * this table object at `key`.
		 */
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

		/**
		 * Address: 0x009072F0 (FUN_009072F0, LuaPlus::LuaObject::IsNil)
		 *
		 * What it does:
		 * Returns true only for state-bound objects tagged as nil.
		 */
		[[nodiscard]] bool IsNil() const noexcept;

		/**
		 * Address: 0x00907850 (FUN_00907850, LuaPlus::LuaObject::IsNone)
		 *
		 * What it does:
		 * Asserts state binding and returns whether this object carries the
		 * `LUA_TNONE` sentinel tag.
		 */
		[[nodiscard]] bool IsNone() const;

		/**
		 * Address: 0x009078D0 (FUN_009078D0, LuaPlus::LuaObject::IsBoolean)
		 *
		 * What it does:
		 * Asserts state binding and returns whether this value is a boolean tag.
		 */
		[[nodiscard]] bool IsBoolean() const;

		/**
		 * Address: 0x00907360 (FUN_00907360, LuaPlus::LuaObject::IsNumber)
		 *
		 * What it does:
		 * Returns whether this value carries a numeric Lua tag.
		 */
		[[nodiscard]] bool IsNumber() const noexcept;

		/**
		 * Address: 0x00907370 (FUN_00907370, LuaPlus::LuaObject::IsString)
		 *
		 * What it does:
		 * Returns whether this value carries a string Lua tag.
		 */
		[[nodiscard]] bool IsString() const noexcept;

		/**
		 * Address: 0x00907890 (FUN_00907890, LuaPlus::LuaObject::IsLightUserData)
		 *
		 * What it does:
		 * Asserts state binding and returns whether this value carries a light-
		 * userdata tag.
		 */
		[[nodiscard]] bool IsLightUserData() const;

		/**
		 * Address: 0x00907310 (FUN_00907310, LuaPlus::LuaObject::IsTable)
		 *
		 * What it does:
		 * Returns whether this tagged Lua value is a table.
		 */
		[[nodiscard]] bool IsTable() const noexcept { return m_object.tt == LUA_TTABLE; }

		/**
		 * Address: 0x00907810 (FUN_00907810, LuaPlus::LuaObject::IsFunction)
		 *
		 * What it does:
		 * Asserts this object is state-bound, then accepts both Lua C-function
		 * and Lua closure tags via `(tt | 1) == LUA_TFUNCTION`.
		 */
		[[nodiscard]] bool IsFunction() const;

		/**
		 * Address: 0x00907700 (FUN_00907700, LuaPlus::LuaObject::IsConvertibleToInteger)
		 *
		 * What it does:
		 * Returns true when this value is already numeric or can be coerced to a
		 * numeric lane via `luaV_tonumber`.
		 */
		[[nodiscard]] bool IsConvertibleToInteger() const;

		/**
		 * Address: 0x00907760 (FUN_00907760, LuaPlus::LuaObject::IsConvertibleToNumber)
		 *
		 * What it does:
		 * Returns true when this value is already numeric or can be coerced to a
		 * numeric lane via `luaV_tonumber`.
		 */
		[[nodiscard]] bool IsConvertibleToNumber() const;

		/**
		 * Address: 0x009077C0 (FUN_009077C0, LuaPlus::LuaObject::IsConvertibleToString)
		 *
		 * What it does:
		 * Returns true when this value is already string or number typed.
		 */
		[[nodiscard]] bool IsConvertibleToString() const;

		/**
		 * Address: 0x00907320 (FUN_00907320, LuaPlus::LuaObject::IsUserData)
		 *
		 * What it does:
		 * Returns true for both full userdata and light userdata tags.
		 */
		[[nodiscard]] bool IsUserData() const noexcept;

		/**
		 * Value getters
		 */
		/**
		 * Address: 0x00907C90 (FUN_00907C90, LuaPlus::LuaObject::GetBoolean)
		 *
		 * What it does:
		 * Validates bound state ownership, raises Lua type error for non-nil/non-boolean
		 * lanes, and returns Lua truthiness for nil/boolean payloads.
		 */
		[[nodiscard]] bool GetBoolean() const;
		/**
		 * Address: 0x00907970 (FUN_00907970, LuaPlus::LuaObject::GetNumber)
		 *
		 * What it does:
		 * Asserts state binding, enforces numeric type, and returns numeric payload.
		 */
		[[nodiscard]] double GetNumber() const;

		/**
		 * Address: 0x00907910 (FUN_00907910, LuaPlus::LuaObject::GetInteger)
		 *
		 * What it does:
		 * Asserts state binding, enforces numeric type, and returns int-truncated payload.
		 */
		[[nodiscard]] int32_t GetInteger() const;

		/**
		 * Address: 0x00907A90 (FUN_00907A90, LuaPlus::LuaObject::GetString)
		 *
		 * What it does:
		 * Asserts this object is bound to a Lua state, raises Lua's typed-operation
		 * error when the value is not a string, and returns the underlying
		 * interned-string character buffer.
		 */
		[[nodiscard]] const char* GetString() const;

		/**
		 * Address: 0x00907410 (FUN_00907410, LuaPlus::LuaObject::ToStrLen)
		 *
		 * What it does:
		 * Converts numeric values to string in-place when needed and returns the
		 * current string length; returns zero when conversion fails.
		 */
		[[nodiscard]] int32_t ToStrLen();

		/**
		 * Address: 0x009073B0 (FUN_009073B0, LuaPlus::LuaObject::ToNumber)
		 *
		 * What it does:
		 * Returns numeric payload when already numeric, otherwise attempts Lua
		 * numeric coercion and returns `0` on conversion failure.
		 */
		[[nodiscard]] double ToNumber() const;

		/**
		 * Address: 0x00907380 (FUN_00907380)
		 *
		 * What it does:
		 * Returns one integer truncation of this value when numeric/coercible,
		 * otherwise returns `0`.
		 */
		[[nodiscard]] int32_t ToInteger() const;

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

		/**
		 * Address: 0x004CCB00 (FUN_004CCB00, LuaPlus::LuaStackObject::ToNumber)
		 *
		 * What it does:
		 * Validates numeric stack type and returns one numeric payload from the
		 * current Lua stack slot.
		 */
		[[nodiscard]] double ToNumber() const;
		[[nodiscard]] double GetNumber() const { return ToNumber(); }

		/**
		 * Address: 0x00415560 (FUN_00415560, LuaPlus::LuaStackObject::GetBoolean)
		 *
		 * What it does:
		 * Reads the current stack slot as a boolean, allowing nil as false.
		 */
		[[nodiscard]] bool GetBoolean() const;

		/**
		 * Address: 0x00528140 (FUN_00528140, LuaPlus::LuaStackObject::GetByName)
		 *
		 * What it does:
		 * Pushes one string key and performs a raw table lookup against this
		 * stack slot, returning a stack-object view for the fetched value.
		 */
		[[nodiscard]] LuaStackObject GetByName(const char* name) const;
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
		enum StandardLibraries : int32_t
		{
			LIB_NONE = 0,
			LIB_BASE = 1,
			LIB_OSIO = 2,
		};

		LuaState() = default;

		/**
		 * Address: 0x0090AC10 (FUN_0090AC10, LuaPlus::LuaState::LuaState)
		 *
		 * What it does:
		 * Initializes a root-owned Lua state wrapper, creates a fresh `lua_State`,
		 * installs userdata/GC callbacks, and runs standard-library init lane.
		 */
		explicit LuaState(StandardLibraries initStandardLibrary);

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

		/**
		 * Address: 0x0090A7D0 (FUN_0090A7D0, LuaPlus::LuaState::SetState)
		 *
		 * What it does:
		 * Binds this wrapper to one existing C lua_State lane, initializes root
		 * sentinel links for main-thread ownership, and updates state userdata.
		 */
		void SetState(lua_State* state);

		/**
		 * Address: 0x0090B8F0 (FUN_0090B8F0, LuaPlus::LuaState::MemberSerialize)
		 *
		 * What it does:
		 * Serializes root/current Lua state pointer bindings into archive.
		 */
		static void MemberSerialize(gpg::WriteArchive* archive, LuaState* state);

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

		/**
		 * Address: 0x0090A510 (FUN_0090A510, LuaPlus::LuaState::CastState)
		 *
		 * What it does:
		 * Returns the C++ wrapper pointer stored in `lua_State::stateUserData`.
		 */
		[[nodiscard]] static LuaState* CastState(lua_State* state);

		LuaState* GetRootState();
		const LuaState* GetRootState() const;
		LuaState* GetActiveState();
		lua_State* GetActiveCState();
		const LuaObject* GetThreadObject() const;

		/**
		 * Address: 0x004CCA10 (FUN_004CCA10, LuaPlus::LuaState::PushNil)
		 *
		 * What it does:
		 * Pushes nil to this state's Lua stack and returns the pushed stack view.
		 */
		[[nodiscard]] LuaStackObject PushNil();

		/**
		 * Address: 0x004CCA30 (FUN_004CCA30, LuaPlus::LuaState::PushNumber)
		 *
		 * What it does:
		 * Pushes one numeric value to this state's Lua stack and returns it as a
		 * stack-object view.
		 */
		[[nodiscard]] LuaStackObject PushNumber(float n);

		LuaStackObject Stack(int32_t index);

		/**
		 * Address: 0x0090BFB0 (FUN_0090BFB0, LuaPlus::LuaState::CheckString)
		 *
		 * What it does:
		 * Validates that stack slot `index` is coercible to string and returns
		 * its char pointer + optional byte length.
		 */
		[[nodiscard]] const char* CheckString(int32_t index, size_t* lengthOut);

		/**
		 * Address: 0x0090C170 (FUN_0090C170, LuaPlus::LuaState::CheckAny)
		 *
		 * What it does:
		 * Raises a Lua argument error when stack slot `index` is missing.
		 */
		void CheckAny(int32_t index);

		/**
		 * Address: 0x0090BF90 (FUN_0090BF90)
		 *
		 * What it does:
		 * Raises one Lua argument error for argument lane `narg`.
		 */
		int ArgError(int narg, char* extraMessage);

		/**
		 * Address: 0x0090BFD0 (FUN_0090BFD0)
		 *
		 * What it does:
		 * Returns optional string argument `narg` or `defaultValue`, and writes
		 * string byte length when `lengthOut` is non-null.
		 */
		[[nodiscard]] const char* OptString(int narg, char* defaultValue, size_t* lengthOut);

		/**
		 * Address: 0x0090BFF0 (FUN_0090BFF0)
		 *
		 * What it does:
		 * Validates numeric argument `index` and returns its number lane.
		 */
		[[nodiscard]] lua_Number CheckNumber(int index);

		/**
		 * Address: 0x0090C010 (FUN_0090C010)
		 *
		 * What it does:
		 * Returns optional numeric argument `index` or `defaultValue`.
		 */
		[[nodiscard]] lua_Number OptNumber(int index, lua_Number defaultValue);

		int32_t GetTop() const;
		bool IsRootState() const;
		bool IsSuspended() const;

		/**
		 * Address: 0x0090C1D0 (FUN_0090C1D0, ?Error@LuaState@LuaPlus@@QAAHPBDZZ)
		 *
		 * What it does:
		 * Formats one Lua error message and raises it through `lua_error`.
		 */
		static void Error(LuaState* state, const char* format, ...);

	private:
		/**
		 * Address: 0x0090AAD0 (FUN_0090AAD0, LuaPlus::LuaState::Init)
		 *
		 * What it does:
		 * Initializes selected Lua standard libraries, script helper globals,
		 * and always registers `LOG` / `_ALERT` on globals table.
		 */
		void Init(StandardLibraries initStandardLibrary);

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
		 * Address: 0x0052C950 (FUN_0052C950, ??0LuaFunction@LuaPlus@@QAE@@Z_2)
		 * Address: 0x0057E950 (FUN_0057E950, ??0LuaFunction@LuaPlus@@QAE@@Z_4)
		 * Address: 0x005D0B60 (FUN_005D0B60, ??0LuaFunction@LuaPlus@@QAE@@Z_3)
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

		/**
		 * Address: 0x0074CEC0 (FUN_0074CEC0, LuaPlus::LuaFunction::Call)
		 *
		 * What it does:
		 * Executes this Lua function with no arguments, expecting one return
		 * value, and restores the caller stack top afterward.
		 */
		void Call() const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_call(activeState, 0, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0074D0D0 (FUN_0074D0D0, LuaPlus::LuaFunction::Call_x_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with zero arguments and returns one boolean
		 * result while restoring caller stack top.
		 */
		[[nodiscard]] bool Call_x_Bool() const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_call(activeState, 0, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00830CB0 (FUN_00830CB0, LuaPlus::LuaFunction::Call_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with one boolean argument and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Bool(const bool value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushboolean(activeState, value ? 1 : 0);
			lua_call(activeState, 1, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007BC9E0 (FUN_007BC9E0, LuaPlus::LuaFunction::Call_Int)
		 *
		 * What it does:
		 * Executes this Lua function with one integer argument and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Int(const int value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value));
			lua_call(activeState, 1, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00582DD0 (FUN_00582DD0, LuaPlus::LuaFunction::Call_Object)
		 *
		 * What it does:
		 * Executes this Lua function with one Lua object argument and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Object(const LuaObject& value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			value.PushStack(activeState);
			lua_call(activeState, 1, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007512A0 (FUN_007512A0, LuaPlus::LuaFunction::Call_Int2)
		 *
		 * What it does:
		 * Executes this Lua function with two integer arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Int2(const int value0, const int value1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value0));
			lua_pushnumber(activeState, static_cast<lua_Number>(value1));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007B5B90 (FUN_007B5B90, LuaPlus::LuaFunction::Call_Num2)
		 *
		 * What it does:
		 * Executes this Lua function with two numeric arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Num2(const float value0, const float value1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value0));
			lua_pushnumber(activeState, static_cast<lua_Number>(value1));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007BC940 (FUN_007BC940, LuaPlus::LuaFunction::Call_Str3)
		 *
		 * What it does:
		 * Executes this Lua function with three string arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Str3(const char* value0, const char* value1, const char* value2) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, value0);
			lua_pushstring(activeState, value1);
			lua_pushstring(activeState, value2);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00830D70 (FUN_00830D70, LuaPlus::LuaFunction::Call_Int_Num)
		 *
		 * What it does:
		 * Executes this Lua function with one integer argument and returns one
		 * numeric result while restoring caller stack top.
		 */
		[[nodiscard]] lua_Number Call_Int_Num(const int value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value));
			lua_call(activeState, 1, 1);
			const lua_Number result = lua_tonumber(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00835BE0 (FUN_00835BE0, LuaPlus::LuaFunction::Call_IntStr)
		 *
		 * What it does:
		 * Executes this Lua function with integer + string arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_IntStr(const int value, const char* text) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value));
			lua_pushstring(activeState, text);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008835A0 (FUN_008835A0, LuaPlus::LuaFunction::Call_FalseStr)
		 *
		 * What it does:
		 * Executes this Lua function with fixed `false` + string arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_FalseStr(const char* text) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushboolean(activeState, 0);
			lua_pushstring(activeState, text);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005FDAB0 (FUN_005FDAB0, LuaPlus::LuaFunction::Call_ObjectStr)
		 *
		 * What it does:
		 * Executes this Lua function with object + string arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_ObjectStr(const LuaObject& objectArg, const char* textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0069FD40 (FUN_0069FD40, LuaPlus::LuaFunction::Call_ObjectBool)
		 *
		 * What it does:
		 * Executes this Lua function with object + boolean arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectBool(const LuaObject& objectArg, const bool boolArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007BC8A0 (FUN_007BC8A0, LuaPlus::LuaFunction::Call_StrFalseStr2)
		 *
		 * What it does:
		 * Executes this Lua function with string + false + two strings and
		 * restores caller stack top after a one-result call.
		 */
		void Call_StrFalseStr2(const char* value0, const char* value1, const char* value2) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, value0);
			lua_pushboolean(activeState, 0);
			lua_pushstring(activeState, value1);
			lua_pushstring(activeState, value2);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x004D4BA0 (FUN_004D4BA0, LuaPlus::LuaFunction::Call_Object_Str)
		 *
		 * What it does:
		 * Executes this Lua function with one object argument, returns one string
		 * result, and restores caller stack top.
		 */
		[[nodiscard]] const char* Call_Object_Str(const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_call(activeState, 1, 1);
			const char* const result = lua_tostring(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x005F4B70 (FUN_005F4B70, LuaPlus::LuaFunction::Call_Object_bool)
		 *
		 * What it does:
		 * Executes this Lua function with one object argument, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_Object_bool(const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_call(activeState, 1, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00775DD0 (FUN_00775DD0, LuaPlus::LuaFunction::Call_ObjectNum)
		 *
		 * What it does:
		 * Executes this Lua function with object + numeric arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_ObjectNum(const LuaObject& objectArg, const lua_Number numberArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, numberArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0084A0A0 (FUN_0084A0A0, LuaPlus::LuaFunction::Call_StrObject)
		 *
		 * What it does:
		 * Executes this Lua function with string + object arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_StrObject(const char* textArg, const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, textArg);
			objectArg.PushStack(activeState);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00831230 (FUN_00831230, LuaPlus::LuaFunction::Call_Uint_Num)
		 *
		 * What it does:
		 * Executes this Lua function with one unsigned integer argument, returns
		 * one numeric result, and restores caller stack top.
		 */
		[[nodiscard]] lua_Number Call_Uint_Num(const unsigned int value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(value));
			lua_call(activeState, 1, 1);
			const lua_Number result = lua_tonumber(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x005D0D00 (FUN_005D0D00, LuaPlus::LuaFunction::Call_Obj_Num)
		 *
		 * What it does:
		 * Executes this Lua function with one object argument, returns one
		 * numeric result, and restores caller stack top.
		 */
		[[nodiscard]] lua_Number Call_Obj_Num(const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_call(activeState, 1, 1);
			const lua_Number result = lua_tonumber(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x006B1B10 (FUN_006B1B10, LuaPlus::LuaFunction::Call_ObjectChar)
		 *
		 * What it does:
		 * Executes this Lua function with object + numeric-char arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectChar(const LuaObject& objectArg, const int charValue) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(charValue));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006241B0 (FUN_006241B0, LuaPlus::LuaFunction::Call_Object_Int)
		 *
		 * What it does:
		 * Executes this Lua function with one object argument, converts the one
		 * numeric return value to integer, and restores caller stack top.
		 */
		[[nodiscard]] int Call_Object_Int(const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_call(activeState, 1, 1);
			const int result = static_cast<int>(lua_tonumber(activeState, -1));
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00849F20 (FUN_00849F20, LuaPlus::LuaFunction::Call_IntObject)
		 *
		 * What it does:
		 * Executes this Lua function with integer + object arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_IntObject(const int intArg, const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			objectArg.PushStack(activeState);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00680530 (FUN_00680530, LuaPlus::LuaFunction::Call_ObjectStr2)
		 *
		 * What it does:
		 * Executes this Lua function with object + two-string arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectStr2(const LuaObject& objectArg, const char* text0, const char* text1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, text0);
			lua_pushstring(activeState, text1);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006803D0 (FUN_006803D0, LuaPlus::LuaFunction::Call_ObjectEnt)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional entity Lua object
		 * arguments and restores caller stack top after a one-result call.
		 */
		void Call_ObjectEnt(const LuaObject& objectArg, const LuaObject* entityLuaObject) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			if (entityLuaObject) {
				entityLuaObject->PushStack(activeState);
			} else {
				lua_pushnil(activeState);
			}
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008C7240 (FUN_008C7240, LuaPlus::LuaFunction::Call_True_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with fixed `true`, returns one Lua object
		 * result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_True_Obj() const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushboolean(activeState, 1);
			lua_call(activeState, 1, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00582D20 (FUN_00582D20, LuaPlus::LuaFunction::Call_Obj2)
		 *
		 * What it does:
		 * Executes this Lua function with two object arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Obj2(const LuaObject& objectArg0, const LuaObject& objectArg1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0052C9B0 (FUN_0052C9B0, LuaPlus::LuaFunction::Call_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with zero arguments, returns one Lua object
		 * result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_Obj() const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_call(activeState, 0, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x0078B1C0 (FUN_0078B1C0, LuaPlus::LuaFunction::Call_ObjectStr_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + string arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjectStr_Bool(const LuaObject& objectArg, const char* textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00835B30 (FUN_00835B30, LuaPlus::LuaFunction::Call_String)
		 *
		 * What it does:
		 * Executes this Lua function with one string argument and restores
		 * caller stack top after a one-result call.
		 */
		void Call_String(const std::string& textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 1, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0078AF70 (FUN_0078AF70, LuaPlus::LuaFunction::Call_ObjectBool_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + boolean arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjectBool_Bool(const LuaObject& objectArg, const bool boolArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x008C7190 (FUN_008C7190, LuaPlus::LuaFunction::Call_Str_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with one string argument, returns one Lua
		 * object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_Str_Obj(const char* textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 1, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x0078B270 (FUN_0078B270, LuaPlus::LuaFunction::Call_ObjectStrNum)
		 *
		 * What it does:
		 * Executes this Lua function with object + string + number arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectStrNum(const LuaObject& objectArg, const char* textArg, const lua_Number numberArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_pushnumber(activeState, numberArg);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005CB2B0 (FUN_005CB2B0, LuaPlus::LuaFunction::Call_ObjectInt)
		 *
		 * What it does:
		 * Executes this Lua function with object + unsigned integer arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectInt(const LuaObject& objectArg, const unsigned int intArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00680480 (FUN_00680480, LuaPlus::LuaFunction::Call_ObjectNum2)
		 *
		 * What it does:
		 * Executes this Lua function with object + two numeric arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectNum2(
			const LuaObject& objectArg,
			const lua_Number numberArg0,
			const lua_Number numberArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, numberArg0);
			lua_pushnumber(activeState, numberArg1);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007958F0 (FUN_007958F0, LuaPlus::LuaFunction::Call_ObjectInt_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + integer arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjectInt_Bool(const LuaObject& objectArg, const int intArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x007CC980 (FUN_007CC980, LuaPlus::LuaFunction::Call_ObjectStr3)
		 *
		 * What it does:
		 * Executes this Lua function with object + three string arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectStr3(
			const LuaObject& objectArg,
			const char* text0,
			const char* text1,
			const char* text2
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, text0);
			lua_pushstring(activeState, text1);
			lua_pushstring(activeState, text2);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006B1A50 (FUN_006B1A50, LuaPlus::LuaFunction::Call_Object2Str)
		 *
		 * What it does:
		 * Executes this Lua function with two object arguments plus one string
		 * argument and restores caller stack top after a one-result call.
		 */
		void Call_Object2Str(const LuaObject& objectArg0, const LuaObject& objectArg1, const char* textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00849E60 (FUN_00849E60, LuaPlus::LuaFunction::Call_StrIntStr3)
		 *
		 * What it does:
		 * Executes this Lua function with one string + integer + three strings
		 * and restores caller stack top after a one-result call.
		 */
		void Call_StrIntStr3(
			const char* protocol,
			const int port,
			const char* playerName,
			const char* gameName,
			const char* mapName
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, protocol);
			lua_pushnumber(activeState, static_cast<lua_Number>(port));
			lua_pushstring(activeState, playerName);
			lua_pushstring(activeState, gameName);
			lua_pushstring(activeState, mapName);
			lua_call(activeState, 5, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008739B0 (FUN_008739B0, LuaPlus::LuaFunction::Call_StringBool)
		 *
		 * What it does:
		 * Executes this Lua function with one string + one boolean argument and
		 * restores caller stack top after a one-result call.
		 */
		void Call_StringBool(const std::string& textArg, const bool boolArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0060C850 (FUN_0060C850, LuaPlus::LuaFunction::Call_Obj2_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with two object arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_Obj2_Bool(const LuaObject& objectArg0, const LuaObject& objectArg1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00751510 (FUN_00751510, LuaPlus::LuaFunction::Call_StrObject2)
		 *
		 * What it does:
		 * Executes this Lua function with one string + two object arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_StrObject2(const char* textArg, const LuaObject& objectArg0, const LuaObject& objectArg1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, textArg);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008D6CE0 (FUN_008D6CE0, LuaPlus::LuaFunction::Call_StrBool_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with string + boolean arguments, returns one
		 * Lua object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_StrBool_Obj(const char* textArg, const bool boolArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 2, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x0069FDE0 (FUN_0069FDE0, LuaPlus::LuaFunction::Call_ObjScrobj_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional script-object Lua
		 * argument, returns one boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjScrobj_Bool(const LuaObject& objectArg, const LuaObject* scriptObjectLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			if (scriptObjectLuaArg) {
				scriptObjectLuaArg->PushStack(activeState);
			} else {
				lua_pushnil(activeState);
			}
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x008834E0 (FUN_008834E0, LuaPlus::LuaFunction::Call_BoolString)
		 *
		 * What it does:
		 * Executes this Lua function with one boolean + one string argument and
		 * restores caller stack top after a one-result call.
		 */
		void Call_BoolString(const bool boolArg, const std::string& textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007CC8C0 (FUN_007CC8C0, LuaPlus::LuaFunction::Call_Object_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with one object argument, returns one Lua
		 * object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_Object_Obj(const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_call(activeState, 1, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00795830 (FUN_00795830, LuaPlus::LuaFunction::Call_ObjectIntObject)
		 *
		 * What it does:
		 * Executes this Lua function with object + integer + object arguments and
		 * restores caller stack top after a one-result call.
		 */
		void Call_ObjectIntObject(
			const LuaObject& objectArg0,
			const int intArg,
			const LuaObject& objectArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			objectArg1.PushStack(activeState);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00581C00 (FUN_00581C00, LuaPlus::LuaFunction::Call_Num4_bool)
		 *
		 * What it does:
		 * Executes this Lua function with four numeric arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_Num4_bool(
			const lua_Number value0,
			const lua_Number value1,
			const lua_Number value2,
			const lua_Number value3
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, value0);
			lua_pushnumber(activeState, value1);
			lua_pushnumber(activeState, value2);
			lua_pushnumber(activeState, value3);
			lua_call(activeState, 4, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x006B1E30 (FUN_006B1E30, LuaPlus::LuaFunction::Call_Object3)
		 *
		 * What it does:
		 * Executes this Lua function with three object arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_Object3(
			const LuaObject& objectArg0,
			const LuaObject& objectArg1,
			const LuaObject& objectArg2
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			objectArg2.PushStack(activeState);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00633470 (FUN_00633470, LuaPlus::LuaFunction::Call_ObjectString)
		 *
		 * What it does:
		 * Executes this Lua function with object + string arguments and restores
		 * caller stack top after a one-result call.
		 */
		void Call_ObjectString(const LuaObject& objectArg, const std::string& textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00849FD0 (FUN_00849FD0, LuaPlus::LuaFunction::Call_Int3)
		 *
		 * What it does:
		 * Executes this Lua function with three integer lanes and restores caller
		 * stack top after a one-result call.
		 */
		void Call_Int3(const int arg0, const unsigned int arg1, const unsigned int arg2) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(arg0));
			lua_pushnumber(activeState, static_cast<lua_Number>(arg1));
			lua_pushnumber(activeState, static_cast<lua_Number>(arg2));
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005D0DB0 (FUN_005D0DB0, LuaPlus::LuaFunction::Call_ObjectWeap)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weapon-Lua-object
		 * arguments and restores caller stack top after a one-result call.
		 */
		void Call_ObjectWeap(const LuaObject& objectArg, const LuaObject* weaponLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weaponLuaArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005EDA40 (FUN_005EDA40, LuaPlus::LuaFunction::Call_ObjectUnit)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional unit-Lua-object
		 * arguments and restores caller stack top after a one-result call.
		 */
		void Call_ObjectUnit(const LuaObject& objectArg, const LuaObject* unitLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005ED8A0 (FUN_005ED8A0, LuaPlus::LuaFunction::Call_Unit_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional unit-Lua-object
		 * arguments, returns one boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_Unit_Bool(const LuaObject& objectArg, const LuaObject* unitLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg);
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x006DE6E0 (FUN_006DE6E0, LuaPlus::LuaFunction::Call_ObjectWeap_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weapon-Lua-object
		 * arguments, returns one boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjectWeap_Bool(const LuaObject& objectArg, const LuaObject* weaponLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weaponLuaArg);
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x005FD9B0 (FUN_005FD9B0, LuaPlus::LuaFunction::Call_ObjectUnitNum2)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional unit-Lua-object +
		 * two numeric arguments and restores caller stack top.
		 */
		void Call_ObjectUnitNum2(
			const LuaObject& objectArg,
			const LuaObject* unitLuaArg,
			const lua_Number numberArg0,
			const lua_Number numberArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg);
			lua_pushnumber(activeState, numberArg0);
			lua_pushnumber(activeState, numberArg1);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006DE600 (FUN_006DE600, LuaPlus::LuaFunction::Call_Obj2_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with two object arguments, returns one Lua
		 * object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_Obj2_Obj(const LuaObject& objectArg0, const LuaObject& objectArg1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_call(activeState, 2, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x006057D0 (FUN_006057D0, LuaPlus::LuaFunction::Call_ObjectWeakent)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-entity Lua
		 * object arguments and restores caller stack top after a one-result call.
		 */
		void Call_ObjectWeakent(const LuaObject& objectArg, const LuaObject* weakEntityLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakEntityLuaArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006B1970 (FUN_006B1970, LuaPlus::LuaFunction::Call_ObjectUnit2)
		 *
		 * What it does:
		 * Executes this Lua function with object + two optional unit-Lua-object
		 * arguments and restores caller stack top after a one-result call.
		 */
		void Call_ObjectUnit2(const LuaObject& objectArg, const LuaObject* unitLuaArg0, const LuaObject* unitLuaArg1) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg0);
			LuaPush(activeState, unitLuaArg1);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007BC810 (FUN_007BC810, LuaPlus::LuaFunction::Call_GPGNetGame)
		 *
		 * What it does:
		 * Executes this Lua function with fixed selector `"GPGNetGame"` plus one
		 * caller string argument and restores caller stack top.
		 */
		void Call_GPGNetGame(const char* value) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, "GPGNetGame");
			lua_pushstring(activeState, value);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006B1BC0 (FUN_006B1BC0, LuaPlus::LuaFunction::Call_ObjectEntStrNum)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional entity-Lua-object +
		 * string + numeric arguments and restores caller stack top.
		 */
		void Call_ObjectEntStrNum(
			const LuaObject& objectArg,
			const LuaObject* entityLuaArg,
			const char* textArg,
			const lua_Number numberArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, entityLuaArg);
			lua_pushstring(activeState, textArg);
			lua_pushnumber(activeState, numberArg);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006FAE50 (FUN_006FAE50, LuaPlus::LuaFunction::Call_ObjectPropStrNum)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional prop-Lua-object +
		 * string + numeric arguments and restores caller stack top.
		 */
		void Call_ObjectPropStrNum(
			const LuaObject& objectArg,
			const LuaObject* propLuaArg,
			const char* textArg,
			const lua_Number numberArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, propLuaArg);
			lua_pushstring(activeState, textArg);
			lua_pushnumber(activeState, numberArg);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x007510E0 (FUN_007510E0, LuaPlus::LuaFunction::Call_IntBrainStr2)
		 *
		 * What it does:
		 * Executes this Lua function with unsigned-int + optional brain-Lua-object
		 * + two string arguments and restores caller stack top.
		 */
		void Call_IntBrainStr2(
			const unsigned int arg0,
			const LuaObject* brainLuaArg,
			const char* textArg0,
			const char* textArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, static_cast<lua_Number>(arg0));
			LuaPush(activeState, brainLuaArg);
			lua_pushstring(activeState, textArg0);
			lua_pushstring(activeState, textArg1);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00830E30 (FUN_00830E30, LuaPlus::LuaFunction::Call_UserunitObject_Num)
		 *
		 * What it does:
		 * Executes this Lua function with optional userunit-Lua-object + object
		 * arguments, returns one numeric result, and restores caller stack top.
		 */
		[[nodiscard]] lua_Number Call_UserunitObject_Num(const LuaObject* userUnitLuaArg, const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			LuaPush(activeState, userUnitLuaArg);
			objectArg.PushStack(activeState);
			lua_call(activeState, 2, 1);
			const lua_Number result = lua_tonumber(activeState, -1);
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x006209E0 (FUN_006209E0, LuaPlus::LuaFunction::Call_ObjectNum_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with object + numeric arguments, returns one
		 * Lua object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_ObjectNum_Obj(const LuaObject& objectArg, const lua_Number numberArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, numberArg);
			lua_call(activeState, 2, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x00638C40 (FUN_00638C40, LuaPlus::LuaFunction::Call_ObjectStrNum3)
		 *
		 * What it does:
		 * Executes this Lua function with object + string + three numeric
		 * arguments and restores caller stack top.
		 */
		void Call_ObjectStrNum3(
			const LuaObject& objectArg,
			const char* textArg,
			const lua_Number numberArg0,
			const lua_Number numberArg1,
			const lua_Number numberArg2
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushstring(activeState, textArg);
			lua_pushnumber(activeState, numberArg0);
			lua_pushnumber(activeState, numberArg1);
			lua_pushnumber(activeState, numberArg2);
			lua_call(activeState, 5, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00795750 (FUN_00795750, LuaPlus::LuaFunction::Call_ObjectString_Bool)
		 *
		 * What it does:
		 * Executes this Lua function with object + string arguments, returns one
		 * boolean result, and restores caller stack top.
		 */
		[[nodiscard]] bool Call_ObjectString_Bool(const LuaObject& objectArg, const std::string& textArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 2, 1);
			const bool result = lua_toboolean(activeState, -1) != 0;
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x005FD7C0 (FUN_005FD7C0, LuaPlus::LuaFunction::Call_ObjectUnitString)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional unit-Lua-object +
		 * string arguments and restores caller stack top.
		 */
		void Call_ObjectUnitString(
			const LuaObject& objectArg,
			const LuaObject* unitLuaArg,
			const std::string& textArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00603080 (FUN_00603080, LuaPlus::LuaFunction::Call_ObjectIntWeakunit)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-unit Lua object +
		 * integer arguments and restores caller stack top.
		 */
		void Call_ObjectIntWeakunit(const LuaObject& objectArg, const int intArg, const LuaObject* weakUnitLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakUnitLuaArg);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00598870 (FUN_00598870, LuaPlus::LuaFunction::Call_ObjectObjNum4)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional Lua object + four
		 * numeric arguments and restores caller stack top.
		 */
		void Call_ObjectObjNum4(
			const LuaObject& objectArg,
			const LuaObject* objectLuaArg,
			const lua_Number num0,
			const lua_Number num1,
			const lua_Number num2,
			const lua_Number num3
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, objectLuaArg);
			lua_pushnumber(activeState, num0);
			lua_pushnumber(activeState, num1);
			lua_pushnumber(activeState, num2);
			lua_pushnumber(activeState, num3);
			lua_call(activeState, 6, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005FD8B0 (FUN_005FD8B0, LuaPlus::LuaFunction::Call_ObjectWeakunitNum2)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-unit Lua object +
		 * two numeric arguments and restores caller stack top.
		 */
		void Call_ObjectWeakunitNum2(
			const LuaObject& objectArg,
			const lua_Number num0,
			const lua_Number num1,
			const LuaObject* weakUnitLuaArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakUnitLuaArg);
			lua_pushnumber(activeState, num0);
			lua_pushnumber(activeState, num1);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x00795640 (FUN_00795640, LuaPlus::LuaFunction::Call_ObjectString2)
		 *
		 * What it does:
		 * Executes this Lua function with object + two string arguments and
		 * restores caller stack top.
		 */
		void Call_ObjectString2(
			const LuaObject& objectArg,
			const std::string& textArg0,
			const std::string& textArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			lua_pushlstring(activeState, textArg0.c_str(), static_cast<size_t>(textArg0.size()));
			lua_pushlstring(activeState, textArg1.c_str(), static_cast<size_t>(textArg1.size()));
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005FD6B0 (FUN_005FD6B0, LuaPlus::LuaFunction::Call_ObjectStringWeakunit)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-unit Lua object +
		 * string arguments and restores caller stack top.
		 */
		void Call_ObjectStringWeakunit(
			const LuaObject& objectArg,
			const std::string& textArg,
			const LuaObject* weakUnitLuaArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakUnitLuaArg);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0084A1A0 (FUN_0084A1A0, LuaPlus::LuaFunction::Call_Num2StrObjectNumBool)
		 *
		 * What it does:
		 * Executes this Lua function with two numbers + string + object + number
		 * + boolean arguments and restores caller stack top.
		 */
		void Call_Num2StrObjectNumBool(
			const lua_Number num0,
			const lua_Number num1,
			const char* textArg,
			const LuaObject& objectArg,
			const lua_Number num2,
			const bool boolArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushnumber(activeState, num0);
			lua_pushnumber(activeState, num1);
			lua_pushstring(activeState, textArg);
			objectArg.PushStack(activeState);
			lua_pushnumber(activeState, num2);
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 6, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005FDB70 (FUN_005FDB70, LuaPlus::LuaFunction::Call_ObjectWeakunit)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-unit Lua object
		 * arguments and restores caller stack top.
		 */
		void Call_ObjectWeakunit(const LuaObject& objectArg, const LuaObject* weakUnitLuaArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakUnitLuaArg);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x0060C9B0 (FUN_0060C9B0, LuaPlus::LuaFunction::Call_Object4)
		 *
		 * What it does:
		 * Executes this Lua function with four object arguments and restores
		 * caller stack top.
		 */
		void Call_Object4(
			const LuaObject& objectArg0,
			const LuaObject& objectArg1,
			const LuaObject& objectArg2,
			const LuaObject& objectArg3
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			objectArg2.PushStack(activeState);
			objectArg3.PushStack(activeState);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008C6140 (FUN_008C6140, LuaPlus::LuaFunction::Call_StringObject)
		 *
		 * What it does:
		 * Executes this Lua function with string + object arguments and restores
		 * caller stack top.
		 */
		void Call_StringObject(const std::string& textArg, const LuaObject& objectArg) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			objectArg.PushStack(activeState);
			lua_call(activeState, 2, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x005ED960 (FUN_005ED960, LuaPlus::LuaFunction::Call_ObjectUnitIntBoolStr)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional unit-Lua-object +
		 * integer + boolean + string arguments and restores caller stack top.
		 */
		void Call_ObjectUnitIntBoolStr(
			const LuaObject& objectArg,
			const LuaObject* unitLuaArg,
			const int intArg,
			const bool boolArg,
			const char* textArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, unitLuaArg);
			lua_pushnumber(activeState, static_cast<lua_Number>(intArg));
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 5, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x008C72F0 (FUN_008C72F0, LuaPlus::LuaFunction::Call_StrObject2_Obj)
		 *
		 * What it does:
		 * Executes this Lua function with string + two object arguments, returns
		 * one Lua object result, and restores caller stack top.
		 */
		[[nodiscard]] LuaObject Call_StrObject2_Obj(
			const char* textArg,
			const LuaObject& objectArg0,
			const LuaObject& objectArg1
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			lua_pushstring(activeState, textArg);
			objectArg0.PushStack(activeState);
			objectArg1.PushStack(activeState);
			lua_call(activeState, 3, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
		}

		/**
		 * Address: 0x005CB1C0 (FUN_005CB1C0, LuaPlus::LuaFunction::Call_Obj2StrBool)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional Lua object + string +
		 * boolean arguments and restores caller stack top.
		 */
		void Call_Obj2StrBool(
			const LuaObject& objectArg0,
			const LuaObject* objectArg1,
			const std::string& textArg,
			const bool boolArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg0.PushStack(activeState);
			LuaPush(activeState, objectArg1);
			lua_pushlstring(activeState, textArg.c_str(), static_cast<size_t>(textArg.size()));
			lua_pushboolean(activeState, boolArg ? 1 : 0);
			lua_call(activeState, 4, 1);
			lua_settop(activeState, savedTop);
		}

		/**
		 * Address: 0x006B1F00 (FUN_006B1F00, LuaPlus::LuaFunction::Call_ObjectWeakunitStr)
		 *
		 * What it does:
		 * Executes this Lua function with object + optional weak-unit Lua object +
		 * string arguments and restores caller stack top.
		 */
		void Call_ObjectWeakunitStr(
			const LuaObject& objectArg,
			const char* textArg,
			const LuaObject* weakUnitLuaArg
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);
			objectArg.PushStack(activeState);
			LuaPush(activeState, weakUnitLuaArg);
			lua_pushstring(activeState, textArg);
			lua_call(activeState, 3, 1);
			lua_settop(activeState, savedTop);
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

		/**
		 * Address: 0x007BC6B0 (FUN_007BC6B0, LuaPlus::LuaFunction::Call_UDP)
		 *
		 * What it does:
		 * Calls the Lua lobby factory with the fixed UDP signature and returns
		 * the created lobby object while restoring the caller stack top.
		 */
		[[nodiscard]] LuaObject
		Call_UDP(
			const bool useUdp,
			const int localPort,
			const msvc8::string& playerName,
			const char* playerUidText,
			const LuaObject* natTraversalObject,
			const int natPort
		) const {
			lua_State* const activeState = GetActiveCState();
			const int savedTop = lua_gettop(activeState);
			PushStack(activeState);

			lua_pushboolean(activeState, useUdp ? 1 : 0);
			lua_pushstring(activeState, "UDP");
			lua_pushnumber(activeState, static_cast<lua_Number>(localPort));
			lua_pushlstring(activeState, playerName.c_str(), static_cast<size_t>(playerName.size()));
			lua_pushstring(activeState, playerUidText ? playerUidText : "");
			if (natTraversalObject) {
				natTraversalObject->PushStack(activeState);
			} else {
				lua_pushnil(activeState);
			}
			lua_pushnumber(activeState, static_cast<lua_Number>(natPort));

			lua_call(activeState, 7, 1);
			LuaObject result{LuaStackObject(GetActiveState(), -1)};
			lua_settop(activeState, savedTop);
			return result;
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

/**
 * Address: 0x0090A6B0 (FUN_0090A6B0, LuaPlusH_next)
 *
 * What it does:
 * Advances one Lua table iterator lane and returns non-zero while a next
 * `(key, value)` pair exists.
 */
extern "C" int LuaPlusH_next(
	LuaPlus::LuaState* state,
	LuaPlus::LuaObject* table,
	LuaPlus::LuaObject* key,
	LuaPlus::LuaObject* value
);

namespace gpg::core
{
	template <class T>
	struct fastvector_runtime_view;
}

namespace LuaPlus
{
	/**
	 * Address: 0x004C7C70 (FUN_004C7C70, gpg::fastvector_LuaObject::clear)
	 *
	 * Destroys every live element in one fastvector runtime view over
	 * `LuaPlus::LuaObject`, then rebinds storage back to the inline
	 * lane, freeing the active heap buffer when present.
	 */
	void ClearAndResetLuaObjectFastVector(gpg::core::fastvector_runtime_view<LuaPlus::LuaObject>& view) noexcept;
}

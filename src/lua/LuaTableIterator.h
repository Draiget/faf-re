#pragma once

#include <cstddef>
#include <cstdint>

#include "LuaObject.h"

namespace LuaPlus
{
	class LuaTableIterator
	{
	public:
		LuaObject* m_tableObj;   // +0x00
		LuaObject m_keyObj;      // +0x04
		LuaObject m_valueObj;    // +0x18
		bool m_isDone;           // +0x2C
		std::uint8_t m_pad2D[3]; // +0x2D

		/**
		 * Address: 0x00457A40 (FUN_00457A40, ??0LuaTableIterator@LuaPlus@@QAE@Z)
		 *
		 * LuaPlus::LuaObject *,char
		 *
		 * What it does:
		 * Binds one table-object iterator view, initializes key/value lane
		 * wrappers, and optionally resets to the first `(key, value)` pair.
		 */
		LuaTableIterator(LuaObject* tableObj, int doReset);
		LuaTableIterator(LuaObject& tableObj, int doReset)
			: LuaTableIterator(&tableObj, doReset)
		{
		}
		LuaTableIterator(const LuaObject& tableObj, int doReset)
			: LuaTableIterator(const_cast<LuaObject*>(&tableObj), doReset)
		{
		}

		/**
		 * Address: 0x00457B10 (FUN_00457B10, ??1LuaTableIterator@LuaPlus@@QAE@@Z)
		 *
		 * What it does:
		 * Destroys iterator-owned key/value object wrappers.
		 */
		~LuaTableIterator();

		/**
		 * Address: 0x00457B60 (FUN_00457B60, sub_457B60)
		 *
		 * What it does:
		 * Resets iteration to the first table entry and updates `m_isDone`.
		 */
		bool Reset();

		/**
		 * Address: 0x00457C00 (FUN_00457C00, sub_457C00)
		 *
		 * What it does:
		 * Reports whether the iterator currently references a live entry.
		 */
		[[nodiscard]]
		bool IsValid() const;

		/**
		 * Address: 0x00457C20 (FUN_00457C20, sub_457C20)
		 *
		 * What it does:
		 * Boolean validity conversion for iterator loops.
		 */
		explicit operator bool() const;

		/**
		 * Address: 0x00457BA0 (FUN_00457BA0, LuaPlus::LuaTableIterator::Next)
		 *
		 * What it does:
		 * Advances to the next table entry and updates done-state when exhausted.
		 */
		bool Next();

		/**
		 * Address: 0x00457C10 (FUN_00457C10, sub_457C10)
		 *
		 * What it does:
		 * Advances to the next table entry and returns this iterator.
		 */
		LuaTableIterator& operator++();

		/**
		 * Address: 0x004A4F30 (FUN_004A4F30, LuaPlus::LuaTableIterator::GetKey)
		 *
		 * What it does:
		 * Returns the current key object; throws when iteration is exhausted.
		 */
		[[nodiscard]]
		LuaObject& GetKey();

		/**
		 * Address: 0x00457C30 (FUN_00457C30, LuaPlus::LuaTableIterator::GetValue)
		 *
		 * What it does:
		 * Returns the current value object; throws when iteration is exhausted.
		 */
		[[nodiscard]]
		LuaObject& GetValue();
	};

	static_assert(offsetof(LuaTableIterator, m_tableObj) == 0x00, "LuaTableIterator::m_tableObj offset must be 0x00");
	static_assert(offsetof(LuaTableIterator, m_keyObj) == 0x04, "LuaTableIterator::m_keyObj offset must be 0x04");
	static_assert(offsetof(LuaTableIterator, m_valueObj) == 0x18, "LuaTableIterator::m_valueObj offset must be 0x18");
	static_assert(offsetof(LuaTableIterator, m_isDone) == 0x2C, "LuaTableIterator::m_isDone offset must be 0x2C");
	static_assert(sizeof(LuaTableIterator) == 0x30, "LuaTableIterator size must be 0x30");
}

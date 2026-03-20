#include "LuaTableIterator.h"

#include "LuaObject.h"
using namespace LuaPlus;

LuaTableIterator::LuaTableIterator(LuaObject* table, int reset) {
	m_table = table;
	m_isDone = false;

	if (!table || !table->m_state || !table->IsTable()) {
		m_isDone = true;
		m_L = nullptr;
		m_tableIndex = 0;
		return;
	}

	LuaState* state = table->m_state;
	m_L = state->m_state;

	// Push table onto stack
	table->PushStack(m_L);
	m_tableIndex = lua_gettop(m_L);

	// Push nil to start iteration
	lua_pushnil(m_L);

	// Try to get first key-value pair
	if (lua_next(m_L, m_tableIndex) == 0) {
		m_isDone = true;
	}
}

LuaTableIterator::~LuaTableIterator() {
	if (m_L && m_tableIndex > 0) {
		// Clean up: if we're not done, pop the value and key
		if (!m_isDone) {
			lua_pop(m_L, 2); // pop value and key
		}
		// Pop the table
		lua_settop(m_L, m_tableIndex - 1);
	}
}

LuaObject LuaTableIterator::GetKey() const {
	if (m_isDone || !m_L) {
		return {};
	}

	// Key is at stack index -2 (relative to top)
	LuaObject key;
	key.m_state = m_table->m_state;
	// Access TObject directly from the stack
	const StkId keySlot = m_L->top - 2;
	key.m_object = *keySlot;
	return key;
}

LuaObject LuaTableIterator::GetValue() const {
	if (m_isDone || !m_L) {
		return {};
	}

	// Value is at stack index -1 (top of stack)
	LuaObject value;
	value.m_state = m_table->m_state;
	// Access TObject directly from the stack
	const StkId valueSlot = m_L->top - 1;
	value.m_object = *valueSlot;
	return value;
}

void LuaTableIterator::Next() {
	if (m_isDone || !m_L) {
		return;
	}

	// Pop the value, keep the key for lua_next
	lua_pop(m_L, 1);

	// Get next key-value pair
	if (lua_next(m_L, m_tableIndex) == 0) {
		m_isDone = true;
	}
}

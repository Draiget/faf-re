#include "LuaTableIterator.h"

#include "LuaAssertion.h"

using namespace LuaPlus;

namespace
{
	[[nodiscard]]
	bool LuaTableIteratorNext(
		LuaState* const state,
		LuaObject* const tableObj,
		LuaObject* const keyObj,
		LuaObject* const valueObj)
	{
		if (state == nullptr || tableObj == nullptr || keyObj == nullptr || valueObj == nullptr) {
			return false;
		}

		lua_State* const cState = state->GetCState();
		if (cState == nullptr) {
			return false;
		}

		const int32_t oldTop = lua_gettop(cState);
		tableObj->PushStack(cState);
		keyObj->PushStack(cState);
		if (lua_next(cState, -2) == 0) {
			lua_settop(cState, oldTop);
			return false;
		}

		keyObj->m_object = *(cState->top - 2);
		valueObj->m_object = *(cState->top - 1);
		lua_settop(cState, oldTop);
		return true;
	}

	[[noreturn]]
	void ThrowInvalidIteratorState()
	{
		throw LuaAssertion("IsValid()");
	}
}

/**
 * Address: 0x00457A40 (FUN_00457A40)
 */
LuaTableIterator::LuaTableIterator(LuaObject* const tableObj, const int doReset)
	: m_tableObj(tableObj),
	  m_keyObj(tableObj != nullptr ? tableObj->m_state : nullptr),
	  m_valueObj(tableObj != nullptr ? tableObj->m_state : nullptr),
	  m_isDone(false),
	  m_pad2D{ 0, 0, 0 }
{
	if (m_tableObj == nullptr || !m_tableObj->IsTable()) {
		if (m_tableObj != nullptr) {
			m_tableObj->TypeError("iterate");
		}
		m_isDone = true;
		return;
	}

	if (doReset != 0) {
		m_keyObj.AssignNil(m_tableObj->m_state);
		if (!LuaTableIteratorNext(m_tableObj->m_state, m_tableObj, &m_keyObj, &m_valueObj)) {
			m_isDone = true;
		}
	}
}

/**
 * Address: 0x00457B10 (FUN_00457B10)
 */
LuaTableIterator::~LuaTableIterator() = default;

/**
 * Address: 0x00457B60 (FUN_00457B60)
 */
bool LuaTableIterator::Reset()
{
	if (m_tableObj == nullptr || m_tableObj->m_state == nullptr) {
		m_isDone = true;
		return false;
	}

	m_keyObj.AssignNil(m_tableObj->m_state);
	const bool hasNext = LuaTableIteratorNext(m_tableObj->m_state, m_tableObj, &m_keyObj, &m_valueObj);
	m_isDone = !hasNext;
	return hasNext;
}

/**
 * Address: 0x00457BA0 (FUN_00457BA0)
 */
bool LuaTableIterator::Next()
{
	if (m_isDone) {
		ThrowInvalidIteratorState();
	}

	if (LuaTableIteratorNext(m_tableObj->m_state, m_tableObj, &m_keyObj, &m_valueObj)) {
		return true;
	}

	m_isDone = true;
	return false;
}

/**
 * Address: 0x00457C00 (FUN_00457C00)
 */
bool LuaTableIterator::IsValid() const
{
	return !m_isDone;
}

/**
 * Address: 0x00457C20 (FUN_00457C20)
 */
LuaTableIterator::operator bool() const
{
	return !m_isDone;
}

/**
 * Address: 0x00457C10 (FUN_00457C10)
 */
LuaTableIterator& LuaTableIterator::operator++()
{
	Next();
	return *this;
}

/**
 * Address: 0x004A4F30 (FUN_004A4F30)
 */
LuaObject& LuaTableIterator::GetKey()
{
	if (m_isDone) {
		ThrowInvalidIteratorState();
	}
	return m_keyObj;
}

/**
 * Address: 0x00457C30 (FUN_00457C30)
 */
LuaObject& LuaTableIterator::GetValue()
{
	if (m_isDone) {
		ThrowInvalidIteratorState();
	}
	return m_valueObj;
}

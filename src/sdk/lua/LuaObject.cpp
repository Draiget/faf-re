#include "LuaObject.h"

#include <exception>

#include "gpg/core/streams/BinaryReader.h"
using namespace LuaPlus;

LuaState* LuaObject::GetActiveState() {
	//return m_state->m_state->l_G->lstate->stateUserData;
	return nullptr;
}

void LuaObject::AddToUsedObjectList(LuaState* state, TObject* obj) {
	if (state == nullptr) {
		// TODO: Implement LuaPlus::LuaAssertion ?
		// throw LuaAssertion("state");
		return;
	}

	//
	// We don't know what is this field are:
	// m_rootState = (LuaPlus::LuaState *)((char *)m_rootState + 36);
	// TODO: Look at LuaPlus::LuaState more.
	//
	// // Root state holds the global intrusive list of live LuaObject wrappers.
	// LuaState* root = state->m_rootState;
	// m_state = root;
	// 
	// // Head (sentinel) node is an embedded LuaObject inside LuaState.
	// auto* head = &root->m_headObject;
	// 
	// // Insert `this` right after head (push_front in doubly-linked intrusive list).
	// // head: [H] <-> ...
	// // becomes: [H] <-> [this] <-> ...
	// m_next = head->m_next;  // link forward to old first
	// m_prev = head;          // link back to head
	// head->m_next->m_prev = this;  // old first points back to this
	// head->m_next = this;          // head points forward to this
	// 
	// // Copy the actual Lua value being wrapped.
	// m_object = *obj;
}

void LuaObject::AddToUsedList(LuaState* state) {
}

LuaObject::operator bool() const noexcept
{
	// No state -> falsy
	if (!m_state)
		return false;

	const auto tt = m_object.tt; // enum tag from TObject

	// NIL (0) -> falsy
	if (tt == 0) // LUA_TNIL in Lua 5.0/5.1
		return false;

	// Boolean: use actual boolean value
	// (original checked: tt != LUA_TBOOLEAN || value.b)
#ifdef LUA_TBOOLEAN
	if (tt == LUA_TBOOLEAN)
		return m_object.value.b != 0;
#else
// Fallback if LUA_TBOOLEAN isn't visible: in Lua 5.0/5.1 it's 1
	if (tt == 1)
		return m_object.value.b != 0;
#endif

	// Any other non-NIL type is truthy
	return true;
}

StkId LuaObject::PushStack(lua_State* state) {
	if (!state || !m_state || !m_state->m_state) {
		// Match original behavior of throwing when preconditions are violated.
		throw std::runtime_error("LuaObject::PushStack: null state");
	}

	// Assert same global state (matches: if (state->l_G != m_state->m_state->l_G) throw).
	if (state->l_G != m_state->m_state->l_G) {
		throw std::runtime_error("state->l_G == m_state->m_state->l_G");
	}

	// Write TValue at current top and remember the slot.
	*state->top = m_object;
	StkId slot = state->top;

	// Ensure there is space for the increment (matches: if (slot >= state->ci->top) lua_checkstack(state, 1)).
	if (slot >= state->ci->top) {
		lua_checkstack(state, 1);
	}

	// Advance top and return the slot where we stored the value.
	++state->top;
	return slot;
}

void LuaObject::AssignNewTable(LuaState* state, int32_t nArray, uint32_t lnHash) {
}

void LuaObject::AssignNumber(LuaState* state, const double number) {
	const auto prevState = m_state;
	if (state->m_rootState != prevState) {
		if (prevState) {
			m_prev->m_next = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}
	m_object.value.n = number;
	m_object.tt = LUA_TNUMBER;
}

void LuaObject::SetString(int32_t index, const char* value) {
}

void LuaObject::SetString(const char* name, const char* value) {
}

// 0x004D2A40
void LuaObject::SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader) {
	int8_t luaType;
	reader->ReadExact(luaType);

	out = {};

	switch (luaType) {
		case 0: {
			double number;
			reader->ReadExact(number);
			out.AssignNumber(state, number);
		}
	}
}

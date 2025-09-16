#pragma once

#include "LuaState.h"

namespace LuaPlus
{
	typedef union {
		void* p;
		float n;
		int b;
	} Value;

	// lua.org/source/5.0/lobject.h.html#TObject
	struct TObject {
		int tt;
		Value value;

		TObject(int value) : tt{ LUA_TNUMBER } { this->value.n = value; }
		TObject(float value) : tt{ LUA_TNUMBER } { this->value.n = value; }
		TObject(bool value) : tt{ LUA_TBOOLEAN } { this->value.b = value; }
		TObject() : tt{ LUA_TNIL } {}
	};

	class LuaObject
	{
	public:
		LuaObject* m_next;
		LuaObject* m_prev;
		LuaState* m_state;
		TObject m_object;
	};
	static_assert(sizeof(LuaObject) == 0x14, "LuaObject must be 0x14");
}

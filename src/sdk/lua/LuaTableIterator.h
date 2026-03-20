#pragma once

#include "LuaObject.h"

namespace LuaPlus
{
	class LuaTableIterator
	{
	public:
		bool m_isDone;
		LuaObject* m_table;
		lua_State* m_L;
		int m_tableIndex;

		LuaTableIterator(LuaObject* table, int reset);

		~LuaTableIterator();

		LuaObject GetKey() const;

		LuaObject GetValue() const;

		void Next();
	};

}

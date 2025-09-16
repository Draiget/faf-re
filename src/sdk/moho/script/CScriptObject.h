#pragma once

#include "lua/LuaObject.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakObject.h"

namespace moho
{
	class CScriptObject : public gpg::RObject, WeakObject
	{
		// Primary vftable (4 entries)
	public:
		virtual void sub_A82547() = 0; // 0xA82547 (slot 0)
		virtual void sub_A82547_1() = 0; // 0xA82547 (slot 1)
		virtual ~CScriptObject() = default; // 0x4C6FF0 (slot 2)
		virtual void sub_4C70A0() = 0; // 0x4C70A0 (slot 3)

	public:
		void* ll;					  // +0x08
		LuaPlus::LuaObject UserData;  // +0x0C  (0x14)
		LuaPlus::LuaObject Table;     // +0x20  (0x14)
	};

	static_assert(sizeof(CScriptObject) == 0x34, "CScriptObject must be 0x34");
}

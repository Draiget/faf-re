#pragma once

enum
{
	LUA_IDSIZE = 60
};

namespace LuaPlus
{
	struct lua_Debug {
		int event;
		const char* name;           // (n)
		const char* namewhat;       // (n) 'global', 'local', 'field', 'method'
		const char* what;           // (S) 'Lua', 'C', 'main', 'tail'
		const char* source;         // (S)
		int currentline;            // (l)
		int nups;                   // (u) number of upvalues
		int linedefined;            // (S)
		char short_src[LUA_IDSIZE]; // (S)
		/* private part */
		int i_ci; // active function
	};
}

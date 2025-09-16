#pragma once
#include <cstdint>

#define LUA_MULTRET (-1)

#define LUA_REGISTRYINDEX (-10000)
#define LUA_GLOBALSINDEX (-10001)
#define lua_upvalueindex(i) (LUA_GLOBALSINDEX - (i))

#define LUA_OK 0
#define LUA_ERRRUN 1
#define LUA_ERRFILE 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5

#define LUA_TNONE (-1)
#define LUA_TNIL 0
#define LUA_TBOOLEAN 1
#define LUA_TLIGHTUSERDATA 2
#define LUA_TNUMBER 3
#define LUA_TSTRING 4
#define LUA_TTABLE 5
#define LUA_CFUNCTION 6
#define LUA_TFUNCTION 7
#define LUA_TUSERDATA 8
#define LUA_TTHREAD 9
#define LUA_TPROTO 10
#define LUA_TUPVALUE 11

#define LUA_HOOKCALL 0
#define LUA_HOOKRET 1
#define LUA_HOOKLINE 2
#define LUA_HOOKCOUNT 3
#define LUA_HOOKTAILRET 4

#define LUA_MASKCALL (1 << LUA_HOOKCALL)
#define LUA_MASKRET (1 << LUA_HOOKRET)
#define LUA_MASKLINE (1 << LUA_HOOKLINE)
#define LUA_MASKCOUNT (1 << LUA_HOOKCOUNT)

#define LUA_NOREF (-2)
#define LUA_REFNIL (-1)

namespace LuaPlus
{
    // Keep 4-byte alignment to mirror MSVC x86 layout
#pragma pack(push, 4)

	/** GC header used by Lua 5.0 objects (x86/MSVC layout). */
    struct GCheader {
        void* next;    // 0x00
        uint8_t tt;      // 0x04
        uint8_t marked;  // 0x05
        uint16_t _pad;   // 0x06 (align to 4)
    };


    /** First 0x44 bytes of lua_State in Lua 5.0 (32-bit). */
    struct Lua50_StateHead {
        GCheader gch;            // 0x00..0x07
        uint8_t  status;         // 0x08
        uint8_t  _padA[3];       // 0x09..0x0B (align)
        void* top;            // 0x0C  (StkId)
        void* l_G;            // 0x10  (global_State*)
        void* ci;             // 0x14  (CallInfo*)
        const void* savedpc;     // 0x18  (Instruction*)
        void* stack_last;     // 0x1C  (StkId)
        void* stack;          // 0x20  (StkId)
        void* end_ci;         // 0x24  (CallInfo*)
        void* base_ci;        // 0x28  (CallInfo*)
        int32_t  stacksize;      // 0x2C
        int32_t  size_ci;        // 0x30
        uint16_t nCcalls;        // 0x34
        uint16_t baseCcalls;     // 0x36
        uint8_t  hookmask;       // 0x38
        uint8_t  allowhook;      // 0x39
        uint16_t _padB;          // 0x3A (align to 4)
        int32_t  basehookcount;  // 0x3C
        int32_t  hookcount;      // 0x40
    };                           // == 0x44

    static_assert(sizeof(Lua50_StateHead) == 0x44, "Lua50_StateHead must be 0x44");

	class LuaState;

	struct lua_State {
        Lua50_StateHead head;
		LuaState* owner;
	};

    static_assert(offsetof(lua_State, owner) == 0x44, "owner must be at 0x44");

    class LuaState {
    public:
        /** Returns raw lua_State* (C API). */
        virtual lua_State* GetCState() const = 0;

        /** Optional: human-readable typename for diagnostics. */
        virtual const char* TypeName() const = 0;

        virtual ~LuaState() = default;

        // Fields are unknown; actual layout is not inferred yet.
        // Keep interface-only wrapper until offsets are proven at runtime.
    };

    inline LuaState*& g_ConsoleLuaState()
    {
        // Base image has no ASLR in this build.
        static auto** pp = reinterpret_cast<LuaState**>(0x010A6478);
        return *pp;
    }
#pragma pack(pop)
}

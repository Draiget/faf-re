#pragma once

struct lua_State;

namespace moho
{
    /**
	 * Minimal generic stats interface.
	 * Exactly one virtual function to keep 1-slot vtable shape in derived classes.
	 * Non-virtual (protected) destructor prevents accidental delete via base.
	 */
    template <class T>
    class Stats {
    public:
        using item_type = T;

        /** Push container data to Lua (derived class defines the table shape) */
        virtual void PushLua(lua_State* L) const = 0;

    protected:
        ~Stats() = default; // non-virtual on purpose (matches 1-slot vtable in derived)
    };
}

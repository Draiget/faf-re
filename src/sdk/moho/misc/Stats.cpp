#include "Stats.h"
using namespace moho;

// Provide an out-of-class definition for the pure virtual to act as key function.
// This forces vftable/typeinfo emission for the template specializations on MSVC,
// yet does NOT add extra slots (still exactly one virtual in the interface).
template <class TItem>
void Stats<TItem>::PushLua(lua_State* /*L*/) const {
	/* no body needed */
}

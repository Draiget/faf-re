#pragma once
#include <cstdint>

namespace moho
{
    // Intrusive tree base used by Moho. The template param is the *final* type.
	// Layout is inferred; use as a view. No virtuals here (StatItem vtable has only 2 slots).
    template <class T>
    struct TDatTreeItem {
        // NOTE: In the real binary this base sits right after the most-derived vptr.
        // Offsets below are relative to the *most-derived* object base (ECX).

        // 0x04..0x23 - eight dwords; most plausible mapping for an intrusive tree:
        T* parent;      // 0x04
        T* firstChild;  // 0x08
        T* lastChild;   // 0x0C
        T* nextSibling; // 0x10
        T* prevSibling; // 0x14
        int32_t  childCount;  // 0x18
        int32_t  flags;       // 0x1C   // unknown bitfield (visibility/sort/etc.)
        int32_t  userData;    // 0x20   // unknown (often an index/order/id)

        // After this base, your StatItem-specific fields continue, e.g.:
        // 0x24: int/float storage (interpreted by getters)
        // 0x78: MSVC8 std::string Name (SSO < 16)
        // 0x90: uint32_t valueType (0=float,1=int,2=string)
        // 0x94: uint32_t useCurrent (==1)
        // 0x98: void* criticalSection
        // 0x9C: uint8_t lockMode
    };
}

#pragma once

#include <cstdio>
#include <cstdlib>
#include <utility>

// Engine addition: the C++23 counterpart of GPG_UNREACHABLE (gpg/core/utils/Global.h), for a point no input can
// reach, such as the end of a switch that returns for every value of an enum the engine produces itself.
// GPG_UNREACHABLE reports and carries on, as the binary does (the die handler may return); this one tells the
// compiler the point is never reached (std::unreachable), so release builds drop the dead path. Builds without
// NDEBUG print where it was reached and abort. Never use it where the value can come from a replay, the network,
// Lua or a file. It has its own header with no dependencies, so any target can use it (Global.h's x86 layout
// asserts fail in targets that don't switch them off on x64).
#if defined(NDEBUG)
#define FAF_UNREACHABLE(...) std::unreachable()
#else
#define FAF_UNREACHABLE(...)                                                                                           \
  (std::fprintf(stderr, "Reached the unreachable: %s(%d)\n", __FILE__, __LINE__), std::abort())
#endif

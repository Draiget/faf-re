#pragma once

#include <cstddef>

// Checks the size of a type at compile time; clang prints both values on a mismatch.
#define EXPECT_SIZE(T, EXPECTED) static_assert(sizeof(T) == (EXPECTED), "sizeof(" #T ") != " #EXPECTED)

// Checks the offset of a field at compile time.
#define EXPECT_OFFSET(T, FIELD, EXPECTED)                                                                              \
  static_assert(offsetof(T, FIELD) == (EXPECTED), "offsetof(" #T ", " #FIELD ") != " #EXPECTED)

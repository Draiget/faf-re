#pragma once

// Primary template is undefined: triggers error when sizes differ.
template<size_t Actual, size_t Expected>
struct SizeIs;

// Specialization exists only when sizes match.
template<size_t N>
struct SizeIs<N, N> {};

#define ABI_SIZE_MUST_BE(T, N) \
    using T##_AbiSizeCheck = ::SizeIs<sizeof(T), (N)>


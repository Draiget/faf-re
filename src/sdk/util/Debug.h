#pragma once

#include <cstddef>

namespace moho_detail {

    // "Требую равенства": определён только для случая Actual == Expected.
    template<std::size_t Actual, std::size_t Expected>
    struct require_size_equal;                 // первичка — неполная (ошибка при неравенстве)

    template<std::size_t N>
    struct require_size_equal<N, N> {};       // спец. для равенства — пустой тип (Ок)

    template<std::size_t Actual, std::size_t Expected>
    struct require_offset_equal;               // аналогично для смещений

    template<std::size_t N>
    struct require_offset_equal<N, N> {};
}

// Склейка для уникальных имён
#define MOHO_CONCAT2(a,b) a##b
#define MOHO_CONCAT(a,b)  MOHO_CONCAT2(a,b)

// Проверка размера типа. При несовпадении MSVC напечатает:
// "use of undefined type 'moho_detail::require_size_equal<8,4>'"
#define EXPECT_SIZE(T, EXPECTED) \
    typedef moho_detail::require_size_equal< sizeof(T), (EXPECTED) > \
        MOHO_CONCAT(_expect_size_line_, __LINE__)

// Проверка смещения поля
#define EXPECT_OFFSET(T, FIELD, EXPECTED) \
    typedef moho_detail::require_offset_equal< offsetof(T, FIELD), (EXPECTED) > \
        MOHO_CONCAT(_expect_offs_line_, __LINE__)

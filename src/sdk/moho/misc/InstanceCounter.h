#pragma once
#include <atomic>

namespace moho
{
    template<class T>
    struct InstanceCounter {
        InstanceCounter() noexcept { ++s_count; }
        InstanceCounter(const InstanceCounter&) noexcept { ++s_count; }
        ~InstanceCounter() noexcept { --s_count; }
        InstanceCounter& operator=(const InstanceCounter&) = delete;

        static std::atomic<int> s_count;
    };
    template<class T>
    std::atomic<int> InstanceCounter<T>::s_count{ 0 };
}

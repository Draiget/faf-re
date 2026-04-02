#pragma once

#include <algorithm>
#include <type_traits>
#include <utility>

namespace moho::detail
{
  template<typename Container>
  [[nodiscard]] constexpr auto ContainerBegin(Container& container) noexcept(noexcept(container.begin())) -> decltype(container.begin())
  {
    return container.begin();
  }

  template<typename Container>
  [[nodiscard]] constexpr auto ContainerBegin(const Container& container) noexcept(noexcept(container.begin())) -> decltype(container.begin())
  {
    return container.begin();
  }

  template<typename Container>
  [[nodiscard]] constexpr auto ContainerEnd(Container& container) noexcept(noexcept(container.end())) -> decltype(container.end())
  {
    return container.end();
  }

  template<typename Container>
  [[nodiscard]] constexpr auto ContainerEnd(const Container& container) noexcept(noexcept(container.end())) -> decltype(container.end())
  {
    return container.end();
  }

  template<typename Container, typename Iterator>
  [[nodiscard]] constexpr auto EraseIterator(Container& container, Iterator iterator) -> decltype(container.erase(iterator))
  {
    return container.erase(iterator);
  }

  template<typename Map, typename Key>
  [[nodiscard]] constexpr auto MapFind(Map& map, const Key& key) noexcept(noexcept(map.find(key))) -> decltype(map.find(key))
  {
    return map.find(key);
  }

  template<typename Map, typename Key>
  [[nodiscard]] constexpr auto MapFind(const Map& map, const Key& key) noexcept(noexcept(map.find(key))) -> decltype(map.find(key))
  {
    return map.find(key);
  }

  template<typename Map, typename Key>
  [[nodiscard]] constexpr auto MapLowerBound(Map& map, const Key& key) noexcept(noexcept(map.lower_bound(key))) -> decltype(map.lower_bound(key))
  {
    return map.lower_bound(key);
  }

  template<typename Map, typename Key>
  [[nodiscard]] constexpr auto MapLowerBound(const Map& map, const Key& key) noexcept(noexcept(map.lower_bound(key))) -> decltype(map.lower_bound(key))
  {
    return map.lower_bound(key);
  }

  template<typename Map, typename Iterator, typename Value>
  [[nodiscard]] constexpr auto MapInsertAtHint(Map& map, Iterator hint, Value&& value)
    -> decltype(map.insert(hint, std::forward<Value>(value)))
  {
    return map.insert(hint, std::forward<Value>(value));
  }

  template<typename Container, typename Value>
  [[nodiscard]] constexpr auto InsertAtBegin(Container& container, Value&& value)
    -> decltype(container.insert(container.begin(), std::forward<Value>(value)))
  {
    return container.insert(container.begin(), std::forward<Value>(value));
  }

  template<typename Container>
  constexpr void AdvanceIterator(Container& container, typename Container::iterator& iterator)
  {
    if (iterator != container.end()) {
      ++iterator;
    }
  }

  template<typename Container>
  constexpr void RetreatIterator(Container& container, typename Container::iterator& iterator)
  {
    if (container.empty()) {
      iterator = container.end();
      return;
    }

    if (iterator == container.end()) {
      iterator = container.end();
      --iterator;
      return;
    }

    if (iterator == container.begin()) {
      iterator = container.end();
      return;
    }

    --iterator;
  }

  template<typename T>
  [[nodiscard]] constexpr T CopyResult(const T& value) noexcept(std::is_nothrow_copy_constructible_v<T>)
  {
    return value;
  }

  template<typename InputIt, typename OutputIt>
  constexpr OutputIt CopyRange(InputIt first, InputIt last, OutputIt destination)
  {
    return std::copy(first, last, destination);
  }

  template<typename BidirIt1, typename BidirIt2>
  constexpr BidirIt2 CopyRangeBackward(BidirIt1 first, BidirIt1 last, BidirIt2 destinationEnd)
  {
    return std::copy_backward(first, last, destinationEnd);
  }
} // namespace moho::detail

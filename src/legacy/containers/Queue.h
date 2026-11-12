#pragma once
#include <cstddef>
#include <memory>
#include <utility>

#ifndef MSVC8_QUEUE_NOEXCEPT
#define MSVC8_QUEUE_NOEXCEPT noexcept
#endif

#pragma pack(push, 4)

namespace fa
{
  // Forward declare list so queue can use it as default
  template <class T, class Alloc>
  class list;

  template <class T, class Container = fa::list<T, std::allocator<T>>>
  class queue
  {
  public:
    typedef Container container_type;
    typedef typename Container::value_type value_type;
    typedef typename Container::size_type size_type;
    typedef typename Container::reference reference;
    typedef typename Container::const_reference const_reference;

  protected:
    // Single data member, like in MSVC8: underlying container
    container_type _Mycont;

  public:
    // ----- ctors -----

    queue()
      : _Mycont()
    {}

    explicit queue(
      const container_type& cont
    )
      : _Mycont(cont)
    {}

    // Copy and assignment are trivial and don't change the layout
    queue(
      const queue& other
    )
      : _Mycont(other._Mycont)
    {}

    queue& operator=(
      const queue& other
    )
    {
      if (this != &other)
        _Mycont = other._Mycont;
      return *this;
    }

    // Move operations for C++11 and later (they don't touch the layout)
    queue(
      queue&& other
    ) MSVC8_QUEUE_NOEXCEPT :
      _Mycont(
        std::move(other._Mycont)
      )
    {}

    queue& operator=(
      queue&& other
    ) MSVC8_QUEUE_NOEXCEPT
    {
      if (this != &other)
        _Mycont = std::move(other._Mycont);
      return *this;
    }

    // ----- basic properties -----

    bool empty() const MSVC8_QUEUE_NOEXCEPT
    {
      return _Mycont.empty();
    }

    size_type size() const MSVC8_QUEUE_NOEXCEPT
    {
      return _Mycont.size();
    }

    // ----- element access -----

    reference front()
    {
      return _Mycont.front();
    }

    const_reference front() const
    {
      return _Mycont.front();
    }

    reference back()
    {
      return _Mycont.back();
    }

    const_reference back() const
    {
      return _Mycont.back();
    }

    // ----- modifiers -----

    void push(
      const value_type& value
    )
    {
      // Queue semantics: push at back
      _Mycont.push_back(value);
    }

    // Move push for C++11 and later
    void push(
      value_type&& value
    )
    {
      _Mycont.push_back(std::move(value));
    }

    void pop()
    {
      // Queue semantics: pop from front
      _Mycont.pop_front();
    }

    void swap(
      queue& other
    ) MSVC8_QUEUE_NOEXCEPT
    {
      using std::swap;
      swap(_Mycont, other._Mycont);
    }

    // Access to the underlying container, mirroring the STL
    container_type& _Get_container()
    {
      return _Mycont;
    }

    const container_type& _Get_container() const
    {
      return _Mycont;
    }
  };

  // Free swap function, as in the STL
  template <class T, class C>
  inline void swap(
    queue<T, C>& a,
    queue<T, C>& b
  ) MSVC8_QUEUE_NOEXCEPT
  {
    a.swap(b);
  }

} // namespace fa

#pragma pack(pop)

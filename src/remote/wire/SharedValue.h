#pragma once

#include <memory>
#include <utility>

// Engine addition, server mode: a value shared between copies until one of them is changed.

namespace faf::remote::wire
{
  /**
   * A `T` held by a shared pointer: copying is a pointer copy, `Edit` copies the value first when
   * another holder shares it, and equality is pointer equality or else the values'. The frames
   * a server builds and a client decodes are mostly the previous frame's records unchanged, so
   * their bulky parts (a unit's stats and detail) are shared rather than copied every beat.
   */
  template <class T>
  class TSharedValue
  {
  public:
    TSharedValue()
      : mValue(Default())
    {}

    explicit TSharedValue(T value)
      : mValue(std::make_shared<const T>(std::move(value)))
    {}

    [[nodiscard]] const T& operator*() const noexcept { return *mValue; }
    [[nodiscard]] const T* operator->() const noexcept { return mValue.get(); }

    /** The value to change, no longer shared with any other holder. */
    [[nodiscard]] T& Edit()
    {
      if (mValue.use_count() != 1) {
        mValue = std::make_shared<const T>(*mValue);
      }
      // The object was made non-const by `make_shared`; only the pointer's type is const.
      return const_cast<T&>(*mValue);
    }

    /** Replaces the value unless it is equal already (keeping the sharing). */
    void Assign(const T& value)
    {
      if (!(*mValue == value)) {
        mValue = std::make_shared<const T>(value);
      }
    }

    [[nodiscard]] bool operator==(const TSharedValue& other) const noexcept
    {
      return mValue == other.mValue || *mValue == *other.mValue;
    }

  private:
    /** One default value every default-made holder shares. */
    [[nodiscard]] static const std::shared_ptr<const T>& Default()
    {
      static const std::shared_ptr<const T> value = std::make_shared<const T>();
      return value;
    }

    std::shared_ptr<const T> mValue; // never null
  };
} // namespace faf::remote::wire

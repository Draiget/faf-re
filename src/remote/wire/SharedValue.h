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
    TSharedValue() = default;

    explicit TSharedValue(T value)
      : mValue(std::make_shared<const T>(std::move(value)))
    {}

    [[nodiscard]] const T& operator*() const noexcept { return mValue ? *mValue : Default(); }
    [[nodiscard]] const T* operator->() const noexcept { return &**this; }

    /** The value to change, no longer shared with any other holder. */
    [[nodiscard]] T& Edit()
    {
      if (mValue.use_count() != 1) {
        mValue = std::make_shared<const T>(**this);
      }
      // The object was made non-const by `make_shared`; only the pointer's type is const.
      return const_cast<T&>(*mValue);
    }

    /** Replaces the value unless it is equal already (keeping the sharing); whether it did. */
    bool Assign(const T& value)
    {
      if (**this == value) {
        return false;
      }
      mValue = std::make_shared<const T>(value);
      return true;
    }

    /**
     * Holds `other`'s value, sharing its pointer, so the next call with the same pointer compares nothing;
     * whether the value differed.
     */
    bool Share(const TSharedValue& other)
    {
      if (mValue == other.mValue) {
        return false;
      }
      const bool changed = !(**this == *other);
      mValue = other.mValue;
      return changed;
    }
    [[nodiscard]] bool operator==(const TSharedValue& other) const noexcept
    {
      return mValue == other.mValue || **this == *other;
    }

  private:
    /**
     * The value of a holder with no pointer. A pointer to a shared default would be counted on one
     * cache line by every record copied on every sim worker (plan WPR.35).
     */
    [[nodiscard]] static const T& Default()
    {
      static const T value{};
      return value;
    }

    std::shared_ptr<const T> mValue; // null: the default value
  };
} // namespace faf::remote::wire

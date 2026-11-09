#pragma once

#include <cassert>
#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

namespace gpg::core
{
  /**
   * Engine addition: a vector for many large elements, kept in fixed-size chunks. Growing adds a
   * chunk: nothing is copied or moved, an element keeps its address, and at most one chunk is
   * unused, where a doubling vector can leave half its memory unused and needs old and new at
   * once while it grows. `clear` keeps the chunks and their elements' storage for reuse; an
   * element still holds its old value until it is assigned again.
   */
  template <class T, std::size_t kChunkLog2 = 8>
  class ChunkedVector
  {
  public:
    static constexpr std::size_t kChunkSize = std::size_t{1} << kChunkLog2;

    [[nodiscard]] std::size_t size() const noexcept { return mSize; }

    [[nodiscard]] T& operator[](const std::size_t index) noexcept
    {
      assert(index < mSize);
      return mChunks[index >> kChunkLog2][index & (kChunkSize - 1u)];
    }

    [[nodiscard]] const T& operator[](const std::size_t index) const noexcept
    {
      assert(index < mSize);
      return mChunks[index >> kChunkLog2][index & (kChunkSize - 1u)];
    }

    /** Grows to `size` elements; it never shrinks. New elements are default-made. */
    void grow_to(const std::size_t size)
    {
      while (mChunks.size() * kChunkSize < size) {
        mChunks.push_back(std::make_unique<T[]>(kChunkSize));
      }
      if (size > mSize) {
        mSize = size;
      }
    }

    template <class U>
    T& push_back(U&& value)
    {
      grow_to(mSize + 1u);
      T& element = (*this)[mSize - 1u];
      element = std::forward<U>(value);
      return element;
    }

    void clear() noexcept { mSize = 0u; }

  private:
    std::vector<std::unique_ptr<T[]>> mChunks;
    std::size_t mSize = 0;
  };
} // namespace gpg::core

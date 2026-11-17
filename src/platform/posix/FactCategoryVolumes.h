#pragma once

// XACT's category volumes on FAudio's FACT, for XactOverFact.cpp. No engine or FAudio headers, so a test can run it
// against FACT directly.
//
// XACT: a category plays at its authored volume times the value set on it and on every category above it, so the
// master volume (Global) scales every sound once. FACT's `FACTAudioEngine_SetVolume` (FAudio 26.10 FACT.c) sets the
// category to its authored volume times the value, but then multiplies each category below it by that category's own
// authored volume again, on every call, and never by the new value: each step of the master volume slider made world
// sounds about 2 dB louder until they clipped, while interface and unit sounds faded.
//
// So the values are kept here, and FACT is called for the category and then for each category below it, parents
// first, with the product of the values on its chain: each call sets its own category right, and every later call
// overwrites what it multiplied below. Each category ends at its own authored volume times the values on its chain,
// the level FACT gives the category it is called for. Whether XACT also multiplies in the parents' authored volumes is
// not known (with FA's SupCom.xgs it would make every sound about 7 dB louder).

#include <cstddef>
#include <cstdint>
#include <vector>

namespace platform::posix
{
  class FactCategoryVolumes
  {
  public:
    /**
     * Reads each category's parent from the global settings file (SupCom.xgs) where FAudio 26.10's
     * `FACT_INTERNAL_ParseAudioEngine` reads it: the category count at byte 19, the category table's offset at byte
     * 33, 10 bytes per category with the parent's index at +6. No file: FACT's built-in Global, Default and Music, the
     * last two under Global. A file too short for its table: no categories known, and `Set` passes values through.
     */
    void Reset(
      const void* const buffer,
      const std::uint32_t size
    )
    {
      mParents.clear();
      if (buffer == nullptr) {
        mParents = {-1, 0, 0};
      } else if (size >= 37u) {
        const auto* const bytes = static_cast<const std::uint8_t*>(buffer);
        const std::uint32_t magic =
          bytes[0] | (bytes[1] << 8u) | (bytes[2] << 16u) | (static_cast<std::uint32_t>(bytes[3]) << 24u);
        const bool swapped = magic == 0x58475346u; // a big-endian (Xbox) file
        const auto u16At = [&](const std::uint32_t at) {
          return static_cast<std::uint16_t>(
            swapped ? (bytes[at] << 8u) | bytes[at + 1u] : bytes[at] | (bytes[at + 1u] << 8u)
          );
        };
        const auto u32At = [&](const std::uint32_t at) {
          return swapped ? (static_cast<std::uint32_t>(u16At(at)) << 16u) | u16At(at + 2u)
                         : u16At(at) | (static_cast<std::uint32_t>(u16At(at + 2u)) << 16u);
        };
        const std::uint32_t count = u16At(19u);
        const std::uint32_t table = u32At(33u);
        if (table <= size && count <= (size - table) / 10u) {
          mParents.resize(count);
          for (std::uint32_t i = 0; i < count; ++i) {
            mParents[i] = static_cast<std::int16_t>(u16At(table + i * 10u + 6u));
          }
        }
      }
      mValues.assign(mParents.size(), 1.0f);
    }

    /**
     * Records `value` for `category` and calls `apply(index, chainValue)` (FACT's SetVolume) for it and every
     * category below it, parents first. Returns what `apply` returned for `category`. A category the file doesn't
     * list goes to `apply` as it is.
     */
    template <class Apply>
    std::uint32_t Set(
      const std::uint16_t category,
      const float value,
      Apply&& apply
    )
    {
      const std::size_t count = mParents.size();
      if (category >= count) {
        return apply(category, value);
      }
      mValues[category] = value;

      // Depth below `category` of each category in its subtree, -1 outside it.
      std::vector<int> depth(count, -1);
      int deepest = 0;
      for (std::size_t i = 0; i < count; ++i) {
        std::size_t at = i;
        for (int steps = 0; steps <= static_cast<int>(count); ++steps) {
          if (at == category) {
            depth[i] = steps;
            if (steps > deepest) {
              deepest = steps;
            }
            break;
          }
          if (!Parent(at, at)) {
            break;
          }
        }
      }

      std::uint32_t result = 0u;
      for (int level = 0; level <= deepest; ++level) {
        for (std::size_t i = 0; i < count; ++i) {
          if (depth[i] != level) {
            continue;
          }
          const std::uint32_t one = apply(static_cast<std::uint16_t>(i), ChainValue(i));
          if (i == category) {
            result = one;
          }
        }
      }
      return result;
    }

  private:
    // The parent of `at` into `out`; false for a root or a parent the table doesn't have.
    [[nodiscard]] bool Parent(
      const std::size_t at,
      std::size_t& out
    ) const
    {
      const std::int16_t parent = mParents[at];
      if (parent < 0 || static_cast<std::size_t>(parent) >= mParents.size()) {
        return false;
      }
      out = static_cast<std::size_t>(parent);
      return true;
    }

    // The product of the values set on `i` and every category above it. A chain longer than the table (a parent loop
    // in a bad file) stops there.
    [[nodiscard]] float ChainValue(
      std::size_t i
    ) const
    {
      float value = 1.0f;
      for (std::size_t steps = 0; steps <= mParents.size(); ++steps) {
        value *= mValues[i];
        if (!Parent(i, i)) {
          break;
        }
      }
      return value;
    }

    std::vector<std::int16_t> mParents; // -1 for none
    std::vector<float> mValues;         // what was set on each category, 1 until then
  };
} // namespace platform::posix

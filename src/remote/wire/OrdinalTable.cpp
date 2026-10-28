#include "remote/wire/OrdinalTable.h"

#include <algorithm>

// Engine addition, server mode: see OrdinalTable.h.

namespace faf::remote::wire
{
  namespace
  {
    constexpr std::uint64_t kFnvOffset = 0xCBF29CE484222325ull;
    constexpr std::uint64_t kFnvPrime = 0x100000001B3ull;

    void HashBytes(std::uint64_t& hash, const void* const data, const std::size_t size) noexcept
    {
      const auto* const bytes = static_cast<const std::uint8_t*>(data);
      for (std::size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= kFnvPrime;
      }
    }

    void HashU64(std::uint64_t& hash, const std::uint64_t value) noexcept
    {
      std::uint8_t bytes[8];
      for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
      }
      HashBytes(hash, bytes, sizeof(bytes));
    }
  } // namespace

  std::string NormalizeContentName(const std::string_view name)
  {
    std::string normalized(name);
    for (char& c : normalized) {
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      }
    }
    return normalized;
  }

  COrdinalTable COrdinalTable::Build(const std::span<const std::string> names)
  {
    COrdinalTable table;
    table.mNames.reserve(names.size());
    for (const std::string& name : names) {
      table.mNames.push_back(NormalizeContentName(name));
    }
    std::sort(table.mNames.begin(), table.mNames.end());
    table.mNames.erase(std::unique(table.mNames.begin(), table.mNames.end()), table.mNames.end());

    table.mHash = kFnvOffset;
    HashU64(table.mHash, table.mNames.size());
    for (std::uint32_t ordinal = 0; ordinal < table.mNames.size(); ++ordinal) {
      const std::string& name = table.mNames[ordinal];
      HashBytes(table.mHash, name.c_str(), name.size() + 1u);
      table.mIndex.emplace(name, ordinal);
    }
    return table;
  }

  std::uint32_t COrdinalTable::Ordinal(const std::string_view name) const
  {
    const auto it = mIndex.find(NormalizeContentName(name));
    return it != mIndex.end() ? it->second : kNone;
  }

  std::string_view COrdinalTable::Name(const std::uint32_t ordinal) const noexcept
  {
    return ordinal < mNames.size() ? std::string_view(mNames[ordinal]) : std::string_view{};
  }

  std::uint64_t SContentTables::Hash() const noexcept
  {
    std::uint64_t hash = kFnvOffset;
    HashU64(hash, blueprints.Hash());
    HashU64(hash, meshes.Hash());
    HashU64(hash, sounds.Hash());
    return hash;
  }
} // namespace faf::remote::wire

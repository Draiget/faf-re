#pragma once

#include <filesystem>
#include <string>

namespace faf::editor
{
  /** A path from UTF-8 text (std::filesystem::u8path, deprecated in C++20). */
  [[nodiscard]] inline std::filesystem::path PathFromUtf8(const std::string& text)
  {
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
  }
} // namespace faf::editor

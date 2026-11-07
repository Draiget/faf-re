#pragma once

#include <cstdint>
#include <string>

namespace gpg
{
  /**
   * Engine addition: the directory the engine keeps its caches in (compiled shaders, translated
   * effects, compiled scripts): FAF_SHADER_CACHE_DIR, else %LOCALAPPDATA%\FAForever\ShaderCache,
   * with a trailing separator; created on first use, empty when it cannot be.
   */
  [[nodiscard]] const std::string& LocalCacheDirectory();

  /** Engine addition: this executable's size and last write time, hashed, so a rebuild gets cache entries of its own. */
  [[nodiscard]] std::uint64_t ExecutableIdentity();
} // namespace gpg

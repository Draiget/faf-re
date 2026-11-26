#pragma once

/**
 * Engine addition (in-game launcher plan, WP1): secrets kept on disk sealed for the current OS user, one interface with
 * one implementation per platform. Used for FAF sign-in tokens.
 *
 * - Windows (src/platform/windows/SecretStoreWindows.cpp): DPAPI, as the map editor kept its login before WP1.
 * - POSIX: not written yet (the system keyring, with the Linux and macOS clients).
 */

#include <expected>
#include <string>
#include <string_view>

namespace platform::secret
{
  /** `plain` sealed so that only this OS user can open it; `description` is kept with it in clear. */
  [[nodiscard]] std::expected<std::string, std::string> Seal(std::string_view plain, std::string_view description);
  /** What Seal sealed; the error for a blob of another user or a broken one. */
  [[nodiscard]] std::expected<std::string, std::string> Open(std::string_view sealed);
} // namespace platform::secret

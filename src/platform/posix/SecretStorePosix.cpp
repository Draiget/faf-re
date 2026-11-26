// Engine addition (in-game launcher plan, WP1): platform::secret on POSIX (src/platform/SecretStore.h).
//
// Not encrypted yet: the "sealed" text is the secret behind a marker line, and what keeps it to this user is the
// file's owner-only permissions, which FafAuth sets (0600). That is how the official FAF client keeps its refresh
// token on every system (client.prefs). The system keyring (libsecret, the macOS Keychain) is the later step.

#include "platform/SecretStore.h"

namespace platform::secret
{
  namespace
  {
    constexpr std::string_view kMarker = "faf-re secret v1 (file permissions only)\n";
  } // namespace

  std::expected<std::string, std::string> Seal(
    const std::string_view plain,
    const std::string_view description
  )
  {
    (void)description;
    std::string sealed(kMarker);
    sealed += plain;
    return sealed;
  }

  std::expected<std::string, std::string> Open(
    const std::string_view sealed
  )
  {
    if (!sealed.starts_with(kMarker)) {
      return std::unexpected("not a secret this program kept");
    }
    return std::string(sealed.substr(kMarker.size()));
  }
} // namespace platform::secret

// Engine addition (in-game launcher plan, WP1): platform::secret on DPAPI (src/platform/SecretStore.h).

#include "platform/SecretStore.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dpapi.h>

namespace platform::secret
{
  std::expected<std::string, std::string> Seal(
    const std::string_view plain,
    const std::string_view description
  )
  {
    std::wstring wideDescription;
    if (!description.empty()) {
      const int count =
        ::MultiByteToWideChar(CP_UTF8, 0, description.data(), static_cast<int>(description.size()), nullptr, 0);
      wideDescription.assign(static_cast<std::size_t>(count), L'\0');
      (void)::MultiByteToWideChar(
        CP_UTF8, 0, description.data(), static_cast<int>(description.size()), wideDescription.data(), count
      );
    }
    DATA_BLOB input{static_cast<DWORD>(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))};
    DATA_BLOB output{};
    if (!::CryptProtectData(&input, wideDescription.c_str(), nullptr, nullptr, nullptr, 0, &output)) {
      return std::unexpected("sealing failed (error " + std::to_string(::GetLastError()) + ")");
    }
    std::string sealed(reinterpret_cast<const char*>(output.pbData), output.cbData);
    ::LocalFree(output.pbData);
    return sealed;
  }

  std::expected<std::string, std::string> Open(
    const std::string_view sealed
  )
  {
    DATA_BLOB input{static_cast<DWORD>(sealed.size()), reinterpret_cast<BYTE*>(const_cast<char*>(sealed.data()))};
    DATA_BLOB output{};
    if (!::CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
      return std::unexpected("opening failed (error " + std::to_string(::GetLastError()) + ")");
    }
    std::string plain(reinterpret_cast<const char*>(output.pbData), output.cbData);
    ::LocalFree(output.pbData);
    return plain;
  }
} // namespace platform::secret

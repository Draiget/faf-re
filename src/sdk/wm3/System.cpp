#include "wm3/System.h"

#include <cstring>

namespace Wm3
{
/**
 * Address: 0x00A48F30 (FUN_00A48F30, Wm3::System::Memcpy)
 *
 * What it does:
 * Calls secure memcpy and returns destination pointer on success, else `nullptr`.
 */
void* System::Memcpy(
  void* const destination,
  const std::size_t destinationSize,
  const void* const source,
  const std::size_t sourceSize
) noexcept
{
#if defined(_MSC_VER)
  return ::memcpy_s(destination, destinationSize, source, sourceSize) == 0 ? destination : nullptr;
#else
  if (destination == nullptr || source == nullptr || sourceSize > destinationSize) {
    return nullptr;
  }

  return std::memcpy(destination, source, sourceSize);
#endif
}
} // namespace Wm3

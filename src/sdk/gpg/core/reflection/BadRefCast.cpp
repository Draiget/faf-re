#include "BadRefCast.h"

#include <string>

using namespace gpg;

namespace
{
  /**
   * Address: 0x008DD220 (FUN_008DD220)
   *
   * What it does:
   * Builds one `std::runtime_error` payload from
   * `prefix_or_default("type error: ") + detail`.
   */
  [[maybe_unused]] std::runtime_error* BuildRuntimeTypeErrorWithPrefix(
    std::runtime_error* const outError,
    const char* const prefix,
    const char* const detail
  )
  {
    const char* const resolvedPrefix = prefix ? prefix : "type error: ";
    std::string message(resolvedPrefix);
    message += (detail != nullptr) ? detail : "";
    return new (outError) std::runtime_error(message);
  }

  [[nodiscard]] std::string BuildBadRefCastMessage(
    const char* const prefix, const char* const fromType, const char* const toType
  )
  {
    const char* const resolvedPrefix = prefix ? prefix : "type error: can't convert ";

    std::string message(resolvedPrefix);
    message += fromType ? fromType : "";
    message += " to ";
    message += toType ? toType : "";
    return message;
  }
} // namespace

/**
 * Address: 0x004089D0 (FUN_004089D0)
 * Mangled: ??0BadRefCast@gpg@@Z
 *
 * What it does:
 * Builds the bad-reference-cast exception payload from a C-string message.
 */
BadRefCast::BadRefCast(const char* const message)
    : std::runtime_error(message)
{
}

/**
 * Address: 0x008DD300 (FUN_008DD300, ??0BadRefCast@gpg@@QAE@@Z)
 *
 * What it does:
 * Builds one formatted cast failure payload:
 * `prefix_or_default + fromType + " to " + toType`.
 */
BadRefCast::BadRefCast(const char* const prefix, const char* const fromType, const char* const toType)
    : std::runtime_error(BuildBadRefCastMessage(prefix, fromType, toType))
{
}

/**
 * Address: 0x0040CC30 (FUN_0040CC30)
 * Mangled: ??0BadRefCast@gpg@@QAE@ABVruntime_error@std@@@Z
 *
 * What it does:
 * Clones a runtime_error payload into BadRefCast and restores BadRefCast vftable.
 */
BadRefCast::BadRefCast(const std::runtime_error& error)
    : std::runtime_error(error)
{
}

/**
 * Address: 0x00408A70 (FUN_00408A70)
 * Mangled: ??1BadRefCast@gpg@@UAE@XZ
 *
 * What it does:
 * Destroys the bad-reference-cast runtime_error payload.
 */
BadRefCast::~BadRefCast() noexcept = default;

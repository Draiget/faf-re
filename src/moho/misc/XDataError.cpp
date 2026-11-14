#include "XDataError.h"

namespace
{
} // namespace

using namespace moho;

/**
 * Address: 0x004B2B00 (FUN_004B2B00)
 *
 * What it does:
 * Constructs one data-error object from a message payload.
 */
XDataError::XDataError(
  const char* const message
)
  : XException(message)
{}

/**
 * Address: 0x004B2E40 (FUN_004B2E40)
 *
 * What it does:
 * Copy-constructs data-error payload and inherited exception lanes.
 */
XDataError::XDataError(
  const XDataError& other
)
  : XException(other)
{}

/**
 * Address: 0x004B2B20 (FUN_004B2B20)
 *
 * What it does:
 * Destroys data-error payload and inherited exception state.
 */
XDataError::~XDataError() noexcept = default;

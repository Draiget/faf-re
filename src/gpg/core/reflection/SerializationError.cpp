#include "SerializationError.h"

using namespace gpg;

/**
 * Address: 0x004066B0 (FUN_004066B0)
 * Mangled: ??0SerializationError@gpg@@Z
 *
 * What it does:
 * Builds the serialization exception payload from a C-string message.
 */
SerializationError::SerializationError(const char* const message)
    : std::runtime_error(message)
{
}

/**
 * Address: 0x00406770 (FUN_00406770)
 * Demangled: gpg::SerializationError::dtr
 *
 * What it does:
 * Destroys runtime_error-backed serialization exception state.
 */
SerializationError::~SerializationError() noexcept = default;

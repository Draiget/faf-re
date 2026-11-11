// Dependency-free raw DEFLATE (RFC 1951) decoder for the map container (no zlib/gzip wrapper).
// Standard library only, so tools, tests and the engine behave identically.
#pragma once

#include <cstddef>
#include <cstdint>

namespace moho::mapformat {

/// Inflates a raw DEFLATE stream (stored, fixed and dynamic blocks) into `out`.
///
/// Succeeds only when the stream is well formed AND produces exactly `outSize` bytes: a stream that ends early,
/// produces more, uses an invalid code, an over-subscribed / incomplete code set, or a distance reaching before the start
/// of the output fails. Never reads outside `in[0, inSize)` and never writes outside `out[0, outSize)`.
/// It enforces nothing about the expansion ratio: the caller checks `outSize` against its limits first, because `outSize`
/// is what the caller allocates.
///
/// `consumed` (optional) receives the number of input bytes the stream occupies (a last partial byte counts) on success
/// and 0 on failure. `error` (optional) receives a static message on failure and nullptr on success.
bool Inflate(const std::uint8_t* in, std::size_t inSize, std::uint8_t* out, std::size_t outSize, std::size_t* consumed,
             const char** error = nullptr);

} // namespace moho::mapformat

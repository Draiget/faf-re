#include "moho/misc/ScrActivation.h"

#include <new>

namespace
{
  /**
   * Address: 0x004AFF20 (FUN_004AFF20, nullsub_745)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk() noexcept {}

} // namespace

/**
 * Address: 0x004B8FB0 (FUN_004B8FB0, Moho::ScrActivation::ScrActivation)
 *
 * Moho::ScrActivation const &
 *
 * What it does:
 * Copy-constructs one script activation entry from another activation lane.
 */
moho::ScrActivation::ScrActivation(const ScrActivation& other)
  : file(),
    name(),
    line(0)
{
  file.assign(other.file, 0U, msvc8::string::npos);
  name.assign(other.name, 0U, msvc8::string::npos);
  line = other.line;
}

/**
 * Address: 0x004AFF80 (FUN_004AFF80, Moho::ScrActivation::ScrActivation)
 *
 * msvc8::string const &,msvc8::string const &,int
 *
 * What it does:
 * Initializes one script activation entry from file/name string lanes and
 * stores the associated source line.
 */
moho::ScrActivation::ScrActivation(
  const msvc8::string& filePath,
  const msvc8::string& activationName,
  const int lineNumber
)
  : file(),
    name(),
    line(0)
{
  file.assign(filePath, 0U, msvc8::string::npos);
  name.assign(activationName, 0U, msvc8::string::npos);
  line = lineNumber;
}

/**
 * Address: 0x004B0000 (FUN_004B0000, Moho::ScrActivation::~ScrActivation)
 * Also emitted at: 0x004AFF60 -- the scalar deleting destructor MSVC
 * generates for any polymorphic class with a virtual destructor (this class
 * declares `virtual ~ScrActivation()`, no other base). No source line maps
 * to that emission; a standalone `DestructScrActivationDeleting` free
 * function previously modelled it as if it needed its own source-level
 * caller, but nothing ever called it (removed).
 *
 * What it does:
 * Resets script activation string lanes and releases heap-backed storage.
 */
moho::ScrActivation::~ScrActivation()
{
  name.tidy(true, 0U);
  file.tidy(true, 0U);
}

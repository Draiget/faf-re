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

  /**
   * Address: 0x004AFF60 (FUN_004AFF60)
   *
   * What it does:
   * Executes one deleting-destructor thunk lane for `ScrActivation` by
   * running object teardown and conditionally freeing storage.
   */
  [[maybe_unused]] moho::ScrActivation* DestructScrActivationDeleting(
    moho::ScrActivation* const self,
    const unsigned char deleteFlag
  ) noexcept
  {
    self->~ScrActivation();
    if ((deleteFlag & 1U) != 0U) {
      ::operator delete(static_cast<void*>(self));
    }
    return self;
  }
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
 *
 * What it does:
 * Resets script activation string lanes and releases heap-backed storage.
 */
moho::ScrActivation::~ScrActivation()
{
  name.tidy(true, 0U);
  file.tidy(true, 0U);
}

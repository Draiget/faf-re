#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace moho
{
  class ScrActivation
  {
  public:
    /**
     * Address: 0x004B8FB0 (FUN_004B8FB0, Moho::ScrActivation::ScrActivation)
     *
     * Moho::ScrActivation const &
     *
     * What it does:
     * Copy-constructs one script activation entry from another activation lane.
     */
    ScrActivation(const ScrActivation& other);

    /**
     * Address: 0x004AFF80 (FUN_004AFF80, Moho::ScrActivation::ScrActivation)
     *
     * msvc8::string const &,msvc8::string const &,int
     *
     * What it does:
     * Initializes one script activation entry from file/name string lanes and
     * stores the associated source line.
     */
    ScrActivation(const msvc8::string& filePath, const msvc8::string& activationName, int lineNumber);

    /**
     * Address: 0x004B0000 (FUN_004B0000, Moho::ScrActivation::~ScrActivation)
     *
     * What it does:
     * Resets script activation string lanes and releases heap-backed storage.
     */
    virtual ~ScrActivation();

  public:
    msvc8::string file; // +0x04
    msvc8::string name; // +0x20
    int line;           // +0x3C
  };

  static_assert(offsetof(ScrActivation, file) == 0x04, "ScrActivation::file offset must be 0x04");
  static_assert(offsetof(ScrActivation, name) == 0x20, "ScrActivation::name offset must be 0x20");
  static_assert(offsetof(ScrActivation, line) == 0x3C, "ScrActivation::line offset must be 0x3C");
  static_assert(sizeof(ScrActivation) == 0x40, "ScrActivation size must be 0x40");
} // namespace moho

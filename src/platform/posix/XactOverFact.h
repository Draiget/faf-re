#pragma once

// Engine addition (issue #258): the Linux client's XACT engine, built on FAudio's FACT. See
// XactOverFact.cpp.

namespace platform::posix
{
  /**
   * Creates an engine that implements moho::IXACTEngine with FACT and stores it in *outEngine,
   * as CoCreateInstance does for XACT's COM class on Windows. Returns 0 (S_OK) or FACT's error.
   */
  int CreateXactEngineOverFact(void** outEngine);
} // namespace platform::posix

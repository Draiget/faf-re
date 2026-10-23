#include "moho/misc/IConOutputHandler.h"

namespace
{
  /**
   * Address: 0x00BC38A0 (FUN_00BC38A0, dynamic initializer for `gConsoleOutputHandlers`)
   * Address: 0x00BEEB40 (FUN_00BEEB40, dynamic atexit destructor for `gConsoleOutputHandlers`)
   *
   * What it does:
   * Process-wide intrusive list head for console output handlers
   * (`sConsoleOutputHandlers` in the binary).
   */
  moho::ConOutputHandlerList gConsoleOutputHandlers;
}

/**
 * Address: 0x0041E8F0 (FUN_0041E8F0)
 *
 * What it does:
 * Sets up the base console-output handler as a singleton-style intrusive list node.
 */
moho::IConOutputHandler::IConOutputHandler() noexcept = default;

/**
 * Address: 0x00F58F44 (consoleoutputhandlers)
 *
 * What it does:
 * Returns the process-wide intrusive list head for console output handlers.
 */
moho::ConOutputHandlerList& moho::CON_GetOutputHandlers()
{
  return gConsoleOutputHandlers;
}

#include "moho/misc/IConOutputHandler.h"

#include <cstdlib>

namespace
{
  moho::ConOutputHandlerList gConsoleOutputHandlers;

  /**
   * Address: 0x00BEEB40 (FUN_00BEEB40, ??1sConsoleOutputHandlers@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for the global console-output-handler list.
   */
  void cleanup_sConsoleOutputHandlers()
  {
    gConsoleOutputHandlers.clear();
  }
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

/**
 * Address: 0x00BC38A0 (FUN_00BC38A0, register_sConsoleOutputHandlers)
 *
 * What it does:
 * Registers process-exit teardown for the global console-output-handler list.
 */
void moho::register_sConsoleOutputHandlers()
{
  (void)std::atexit(&cleanup_sConsoleOutputHandlers);
}

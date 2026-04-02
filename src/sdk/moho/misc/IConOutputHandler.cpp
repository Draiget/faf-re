#include "moho/misc/IConOutputHandler.h"

namespace
{
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

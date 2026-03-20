#include "moho/misc/IConOutputHandler.h"

namespace
{
  moho::ConOutputHandlerList gConsoleOutputHandlers;
}

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

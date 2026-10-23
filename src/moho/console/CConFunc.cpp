#include "moho/console/CConFunc.h"

/**
 * Address: 0x0041E5C0 (FUN_0041E5C0, ??0CConFunc@Moho@@QAE@PBD0@Z)
 *
 * const char* name, const char* description, Callback callback
 *
 * What it does:
 * Initializes base command metadata/registration, then stores the handler.
 */
moho::CConFunc::CConFunc(const char* const name, const char* const description, const Callback callback) noexcept
  : CConCommand(name, description)
  , mFunc(callback)
{}

/**
 * Address: 0x1001DC00 (MohoEngine.dll, FUN_1001DC00)
 * Address: 0x0041E5F0 (ForgedAlliance.exe, FUN_0041E5F0)
 *
 * What it does:
 * Invokes the stored handler with the command args.
 */
void moho::CConFunc::Handle(const msvc8::vector<msvc8::string>& args)
{
  mFunc(args);
}

#include "moho/console/CConFunc.h"

moho::CConFunc::CConFunc() noexcept
{
  mName = nullptr;
  mDescription = nullptr;
  mHandlerOrValue = 0u;
}

/**
 * Address: 0x0041E5C0 (FUN_0041E5C0, ??0CConFunc@Moho@@QAE@PBD0@Z)
 *
 * const char* name, const char* description, Callback callback
 *
 * What it does:
 * Initializes base command metadata/registration, then stores callback.
 */
moho::CConFunc::CConFunc(const char* const name, const char* const description, const Callback callback) noexcept
  : CConCommand(name, description)
{
  mHandlerOrValue = reinterpret_cast<std::uintptr_t>(callback);
}

void moho::CConFunc::InitializeRecovered(const char* description, const char* name, Callback callback) noexcept
{
  mName = name;
  mDescription = description;
  mHandlerOrValue = reinterpret_cast<std::uintptr_t>(callback);

  if (mName != nullptr) {
    RegisterConCommand(*this);
  }
}

/**
 * Address: 0x1001DC00 (MohoEngine.dll, FUN_1001DC00)
 * Address: 0x0041E5F0 (ForgedAlliance.exe, FUN_0041E5F0)
 *
 * What it does:
 * Loads callback pointer from +0x0C payload storage and invokes it with command args.
 */
void moho::CConFunc::Handle(void* commandArgs)
{
  if (const Callback callback = GetCallback(); callback != nullptr) {
    callback(commandArgs);
  }
}

moho::CConFunc::Callback moho::CConFunc::GetCallback() const noexcept
{
  return reinterpret_cast<Callback>(mHandlerOrValue);
}

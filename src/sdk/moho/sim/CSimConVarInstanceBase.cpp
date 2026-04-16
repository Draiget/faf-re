#include "CSimConVarInstanceBase.h"

#include <cstdlib>
#include <new>

#include "moho/console/CConCommand.h"

using namespace moho;

namespace
{
  struct ConVarInstanceBaseRuntimeView
  {
    void* vftable;
    const char* name;
  };

  class ConVarInstanceBaseVtableProbe final : public moho::CSimConVarInstanceBase
  {
  public:
    int HandleConsoleCommand(void*) override
    {
      return 0;
    }

    void* GetValueStorage() override
    {
      return nullptr;
    }

    gpg::RRef* GetValueRef(gpg::RRef* const outRef) override
    {
      return outRef;
    }
  };

  [[nodiscard]] void* ConVarInstanceBaseVtable() noexcept
  {
    static ConVarInstanceBaseVtableProbe probe;
    return *reinterpret_cast<void**>(&probe);
  }

  void ResetConVarInstanceBaseVtableLane(moho::CSimConVarInstanceBase* const instance) noexcept
  {
    if (instance == nullptr) {
      return;
    }

    auto* const runtime = reinterpret_cast<ConVarInstanceBaseRuntimeView*>(instance);
    runtime->vftable = ConVarInstanceBaseVtable();
  }

  [[nodiscard]] const std::string*
  GetArgToken(const moho::CSimConCommand::ParsedCommandArgs& args, const std::size_t index) noexcept
  {
    if (index >= args.size()) {
      return nullptr;
    }
    return &args[index];
  }

  [[nodiscard]] float ParseFloatArg(const std::string* const token) noexcept
  {
    if (token == nullptr) {
      return 0.0f;
    }
    return static_cast<float>(std::atof(token->c_str()));
  }

  [[nodiscard]] bool TokenEq(const std::string* const token, const char* const text) noexcept
  {
    return token != nullptr && text != nullptr && *token == text;
  }

  [[nodiscard]] bool TokenEqNoCase(const std::string* const token, const char* const text) noexcept
  {
    return token != nullptr && text != nullptr && gpg::STR_EqualsNoCase(token->c_str(), text);
  }

  [[nodiscard]] int ParseIntArg(const std::string* const token) noexcept
  {
    return std::atoi(token != nullptr ? token->c_str() : "");
  }

  template <typename TValue>
  void ApplyIntegralSimConVarArgs(const moho::CSimConCommand::ParsedCommandArgs& args, TValue* const value) noexcept
  {
    if (value == nullptr) {
      return;
    }

    const std::string* const op = GetArgToken(args, 1u);
    const std::string* const rhs = GetArgToken(args, 2u);

    if (TokenEq(op, "=") && rhs != nullptr) {
      *value = static_cast<TValue>(ParseIntArg(rhs));
      return;
    }
    if (TokenEq(op, "+=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value + static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "-=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value - static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "*=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value * static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "/=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value / static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "%=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value % static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "&=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value & static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "|=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value | static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }
    if (TokenEq(op, "^=") && rhs != nullptr) {
      *value = static_cast<TValue>(*value ^ static_cast<TValue>(ParseIntArg(rhs)));
      return;
    }

    if (TokenEqNoCase(op, "on") || TokenEqNoCase(op, "true")) {
      *value = static_cast<TValue>(1);
      return;
    }
    if (TokenEqNoCase(op, "off") || TokenEqNoCase(op, "false")) {
      *value = static_cast<TValue>(0);
      return;
    }
    if (TokenEqNoCase(op, "tog")) {
      *value = static_cast<TValue>((*value == static_cast<TValue>(0)) ? 1 : 0);
      return;
    }

    if (op != nullptr) {
      *value = static_cast<TValue>(ParseIntArg(op));
    }
  }

  void ApplyIntSimConVarArgs(const moho::CSimConCommand::ParsedCommandArgs& args, int* const value) noexcept
  {
    ApplyIntegralSimConVarArgs<int>(args, value);
  }

  void ApplyUInt8SimConVarArgs(const moho::CSimConCommand::ParsedCommandArgs& args, std::uint8_t* const value) noexcept
  {
    ApplyIntegralSimConVarArgs<std::uint8_t>(args, value);
  }

  [[nodiscard]] int HandleBoolSimConVarArgs(
    const moho::CSimConCommand::ParsedCommandArgs& args,
    const char* const name,
    bool* const value
  ) noexcept
  {
    if (value == nullptr) {
      return 0;
    }

    if (args.size() < 2u) {
      *value = !*value;
      CON_Printf("toggled %s is now %s", name ? name : "", *value ? "on" : "off");
      return 0;
    }

    const std::string* const op = GetArgToken(args, 1u);
    const std::string* const rhs = GetArgToken(args, 2u);

    if (TokenEq(op, "=") && rhs != nullptr) {
      const int parsed = ParseIntArg(rhs);
      *value = parsed != 0;
      return parsed;
    }
    if (TokenEqNoCase(op, "on") || TokenEqNoCase(op, "true")) {
      *value = true;
      return 0;
    }
    if (TokenEqNoCase(op, "off") || TokenEqNoCase(op, "false")) {
      *value = false;
      return 0;
    }
    if (TokenEqNoCase(op, "show")) {
      CON_Printf("bool %s is %s", name ? name : "", *value ? "on" : "off");
      return 0;
    }
    if (TokenEqNoCase(op, "tog")) {
      *value = !*value;
      return 0;
    }

    const int parsed = ParseIntArg(op);
    *value = parsed != 0;
    return *value ? 1 : 0;
  }

  [[nodiscard]] int HandleStringSimConVarArgs(
    const moho::CSimConCommand::ParsedCommandArgs& args,
    const char* const name,
    msvc8::string* const value
  )
  {
    if (value == nullptr) {
      return 0;
    }

    if (args.size() >= 2u) {
      const std::string* const op = GetArgToken(args, 1u);
      const std::string* const rhs = GetArgToken(args, 2u);

      if (TokenEq(op, "=") && rhs != nullptr) {
        value->assign_owned(rhs->c_str());
      } else if (op != nullptr) {
        value->assign_owned(op->c_str());
      }
      return 1;
    }

    CON_Printf("string %s == %s", name ? name : "", value->c_str());
    return 0;
  }

  void ApplyFloatSimConVarArgs(const moho::CSimConCommand::ParsedCommandArgs& args, float* const value) noexcept
  {
    if (value == nullptr) {
      return;
    }

    const std::string* const op = GetArgToken(args, 1u);
    const std::string* const rhs = GetArgToken(args, 2u);

    if (op == nullptr) {
      return;
    }

    if (*op == "=" && rhs != nullptr) {
      *value = ParseFloatArg(rhs);
      return;
    }
    if (*op == "+=" && rhs != nullptr) {
      *value += ParseFloatArg(rhs);
      return;
    }
    if (*op == "-=" && rhs != nullptr) {
      *value -= ParseFloatArg(rhs);
      return;
    }
    if (*op == "*=" && rhs != nullptr) {
      *value *= ParseFloatArg(rhs);
      return;
    }
    if (*op == "/=" && rhs != nullptr) {
      *value /= ParseFloatArg(rhs);
      return;
    }

    *value = ParseFloatArg(op);
  }
} // namespace

/**
 * Address: 0x00579720 (FUN_00579720, sub_579720)
 *
 * What it does:
 * Base constructor lane that installs the abstract convar-instance vtable and
 * binds the command-name lane.
 */
CSimConVarInstanceBase::CSimConVarInstanceBase(const char* const name)
  : mName(name)
{
}

/**
 * Address: 0x00579730 (FUN_00579730, sub_579730)
 * Address: 0x005D4260 (FUN_005D4260)
 *
 * What it does:
 * Base constructor lane that initializes the abstract convar-instance vtable;
 * the second constructor lane is an equivalent alias.
 */
CSimConVarInstanceBase::CSimConVarInstanceBase() = default;

/**
 * Address: 0x00579740 (FUN_00579740, sub_579740)
 *
 * What it does:
 * Base convar-instance destructor body; deleting behavior is provided by
 * compiler-generated scalar-deleting thunk in the original binary.
 */
CSimConVarInstanceBase::~CSimConVarInstanceBase() = default;

/**
 * Address: 0x0057FC40 (FUN_0057FC40)
 *
 * What it does:
 * Constructs one `TSimConVarInstance<bool>` in-place from `(name, value)`.
 */
[[maybe_unused]] moho::TSimConVarInstance<bool>* ConstructTSimConVarInstanceBool(
  moho::TSimConVarInstance<bool>* const instance,
  const char* const name,
  const bool value
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  ::new (static_cast<void*>(instance)) moho::TSimConVarInstance<bool>();
  instance->mName = name;
  instance->mValue = value;
  return instance;
}

/**
 * Address: 0x0057FCB0 (FUN_0057FCB0)
 *
 * What it does:
 * Constructs one `TSimConVarInstance<int>` in-place from `(name, value)`.
 */
[[maybe_unused]] moho::TSimConVarInstance<int>* ConstructTSimConVarInstanceInt(
  moho::TSimConVarInstance<int>* const instance,
  const char* const name,
  const int value
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  ::new (static_cast<void*>(instance)) moho::TSimConVarInstance<int>();
  instance->mName = name;
  instance->mValue = value;
  return instance;
}

/**
 * Address: 0x00735980 (FUN_00735980, Moho::TSimConVarInstance_uint8::TSimConVarInstance_uint8)
 *
 * What it does:
 * Constructs one `TSimConVarInstance<std::uint8_t>` in-place from
 * `(name, value)`.
 */
[[maybe_unused]] moho::TSimConVarInstance<std::uint8_t>* ConstructTSimConVarInstanceUInt8(
  moho::TSimConVarInstance<std::uint8_t>* const instance,
  const std::uint8_t value,
  const char* const name
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  ::new (static_cast<void*>(instance)) moho::TSimConVarInstance<std::uint8_t>();
  instance->mName = name;
  instance->mValue = value;
  return instance;
}

/**
 * Address: 0x0057FDC0 (FUN_0057FDC0)
 *
 * What it does:
 * Restores the base `CSimConVarInstanceBase` vtable lane on one
 * bool-instance storage block.
 */
[[maybe_unused]] moho::CSimConVarInstanceBase* ResetConVarInstanceBaseVtableFromBool(
  moho::TSimConVarInstance<bool>* const instance
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  auto* const base = static_cast<moho::CSimConVarInstanceBase*>(instance);
  ResetConVarInstanceBaseVtableLane(base);
  return base;
}

/**
 * Address: 0x0057FDD0 (FUN_0057FDD0)
 *
 * What it does:
 * Restores the base `CSimConVarInstanceBase` vtable lane on one int-instance
 * storage block.
 */
[[maybe_unused]] moho::CSimConVarInstanceBase* ResetConVarInstanceBaseVtableFromInt(
  moho::TSimConVarInstance<int>* const instance
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  auto* const base = static_cast<moho::CSimConVarInstanceBase*>(instance);
  ResetConVarInstanceBaseVtableLane(base);
  return base;
}

/**
 * Address: 0x00735B70 (FUN_00735B70)
 *
 * What it does:
 * Restores the base `CSimConVarInstanceBase` vtable lane on one convar
 * instance storage block.
 */
[[maybe_unused]] moho::CSimConVarInstanceBase* ResetConVarInstanceBaseVtableLaneAlias(
  moho::CSimConVarInstanceBase* const instance
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  ResetConVarInstanceBaseVtableLane(instance);
  return instance;
}

/**
 * Address: 0x00735B10 (FUN_00735B10, Moho::TSimConVarInstance_uint8::scalar deleting dtr)
 *
 * What it does:
 * Runs one scalar-deleting destructor thunk for
 * `TSimConVarInstance<std::uint8_t>`.
 */
[[maybe_unused]] moho::TSimConVarInstance<std::uint8_t>* DestroyTSimConVarInstanceUInt8(
  moho::TSimConVarInstance<std::uint8_t>* const instance,
  const unsigned char deleteFlag
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  instance->~TSimConVarInstance<std::uint8_t>();
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(instance));
  }
  return instance;
}

/**
 * Address: 0x00735B80 (FUN_00735B80, Moho::TSimConVarInstance_string non-deleting dtor body)
 *
 * What it does:
 * Tears down one `TSimConVarInstance<msvc8::string>` object in-place by
 * releasing the embedded legacy string lane and then running the base
 * `CSimConVarInstanceBase` destructor lane.
 */
[[maybe_unused]] int DestroyTSimConVarInstanceStringInPlace(
  moho::TSimConVarInstance<msvc8::string>* const instance
) noexcept
{
  if (instance == nullptr) {
    return 0;
  }

  instance->mValue.tidy(true, 0U);
  static_cast<moho::CSimConVarInstanceBase*>(instance)->~CSimConVarInstanceBase();
  return 0;
}

/**
 * Address: 0x00735B30 (FUN_00735B30, Moho::TSimConVarInstance_string::scalar deleting dtr)
 *
 * What it does:
 * Runs one scalar-deleting destructor thunk for
 * `TSimConVarInstance<msvc8::string>`.
 */
[[maybe_unused]] moho::TSimConVarInstance<msvc8::string>* DestroyTSimConVarInstanceString(
  moho::TSimConVarInstance<msvc8::string>* const instance,
  const unsigned char deleteFlag
) noexcept
{
  if (instance == nullptr) {
    return nullptr;
  }

  (void)DestroyTSimConVarInstanceStringInPlace(instance);
  if ((deleteFlag & 1u) != 0u) {
    ::operator delete(static_cast<void*>(instance));
  }
  return instance;
}

/**
 * Address: 0x0057FCC0 (FUN_0057FCC0, Moho::TSimConVarInstance_int::OnCall)
 *
 * What it does:
 * Handles int sim-convar command arguments and prints current value when no
 * RHS token is provided.
 */
template <>
int moho::TSimConVarInstance<int>::HandleConsoleCommand(void* commandArgs)
{
  auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
  if (args != nullptr && args->size() >= 2u) {
    ApplyIntSimConVarArgs(*args, &mValue);
    return 1;
  }

  CON_Printf("int %s == %d", mName ? mName : "", mValue);
  return 0;
}

/**
 * Address: 0x0057FC50 (FUN_0057FC50, Moho::TSimConVarInstance_bool::OnCall)
 *
 * What it does:
 * Handles bool sim-convar command arguments using legacy bool parser
 * semantics (`=`, on/off/true/false/show/tog, numeric fallback).
 */
template <>
int moho::TSimConVarInstance<bool>::HandleConsoleCommand(void* commandArgs)
{
  auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
  return args != nullptr ? HandleBoolSimConVarArgs(*args, mName, &mValue) : HandleBoolSimConVarArgs({}, mName, &mValue);
}

/**
 * Address: 0x00735990 (FUN_00735990, Moho::TSimConVarInstance_uint8::OnCall)
 *
 * What it does:
 * Handles uint8 sim-convar command arguments and prints current value when no
 * RHS token is provided.
 */
template <>
int moho::TSimConVarInstance<std::uint8_t>::HandleConsoleCommand(void* commandArgs)
{
  auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
  if (args != nullptr && args->size() >= 2u) {
    ApplyUInt8SimConVarArgs(*args, &mValue);
    return 1;
  }

  CON_Printf("uint8 %s == %d", mName ? mName : "", static_cast<int>(mValue));
  return 0;
}

/**
 * Address: 0x005D41E0 (FUN_005D41E0, Moho::TSimConVarInstance_float::GetPtr)
 *
 * What it does:
 * Returns pointer to the float value lane stored at offset +0x08.
 */
template <>
void* moho::TSimConVarInstance<float>::GetValueStorage()
{
  return &mValue;
}

/**
 * Address: 0x0057FC70 (FUN_0057FC70, Moho::TSimConVarInstance_bool::GetPtr)
 *
 * What it does:
 * Returns pointer to the bool value lane stored at offset +0x08.
 */
template <>
void* moho::TSimConVarInstance<bool>::GetValueStorage()
{
  return &mValue;
}

/**
 * Address: 0x0057FD20 (FUN_0057FD20, Moho::TSimConVarInstance_int::GetPtr)
 *
 * What it does:
 * Returns pointer to the int value lane stored at offset +0x08.
 */
template <>
void* moho::TSimConVarInstance<int>::GetValueStorage()
{
  return &mValue;
}

/**
 * Address: 0x0057FD30 (FUN_0057FD30, Moho::TSimConVarInstance_int::GetRRef)
 *
 * What it does:
 * Builds one reflected int reference for this convar value and copies it into
 * `outRef`.
 */
template <>
gpg::RRef* moho::TSimConVarInstance<int>::GetValueRef(gpg::RRef* const outRef)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RRef intValueRef{};
  gpg::RRef_int(&intValueRef, &mValue);
  outRef->mObj = intValueRef.mObj;
  outRef->mType = intValueRef.mType;
  return outRef;
}

/**
 * Address: 0x0057FC80 (FUN_0057FC80, Moho::TSimConVarInstance_bool::GetRRef)
 *
 * What it does:
 * Builds one reflected bool reference for this convar value and copies it
 * into `outRef`.
 */
template <>
gpg::RRef* moho::TSimConVarInstance<bool>::GetValueRef(gpg::RRef* const outRef)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RRef boolValueRef{};
  gpg::RRef_bool(&boolValueRef, &mValue);
  outRef->mObj = boolValueRef.mObj;
  outRef->mType = boolValueRef.mType;
  return outRef;
}

/**
 * Address: 0x00735A00 (FUN_00735A00, Moho::TSimConVarInstance_uint8::GetRRef)
 *
 * What it does:
 * Builds one reflected uint8 reference for this convar value and copies it
 * into `outRef`.
 */
template <>
gpg::RRef* moho::TSimConVarInstance<std::uint8_t>::GetValueRef(gpg::RRef* const outRef)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RRef uint8ValueRef{};
  gpg::RRef_uchar(&uint8ValueRef, &mValue);
  outRef->mObj = uint8ValueRef.mObj;
  outRef->mType = uint8ValueRef.mType;
  return outRef;
}

/**
 * Address: 0x00735AE0 (FUN_00735AE0, Moho::TSimConVarInstance_string::GetRRef)
 *
 * What it does:
 * Builds one reflected string reference for this convar value and copies it
 * into `outRef`.
 */
template <>
gpg::RRef* moho::TSimConVarInstance<msvc8::string>::GetValueRef(gpg::RRef* const outRef)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RRef stringValueRef{};
  gpg::RRef_string(&stringValueRef, &mValue);
  outRef->mObj = stringValueRef.mObj;
  outRef->mType = stringValueRef.mType;
  return outRef;
}

/**
 * Address: 0x00735AB0 (FUN_00735AB0, Moho::TSimConVarInstance_string::OnCall)
 *
 * What it does:
 * Handles string sim-convar command arguments (`= value` or direct
 * assignment); prints current value when no RHS argument is provided.
 */
template <>
int moho::TSimConVarInstance<msvc8::string>::HandleConsoleCommand(void* commandArgs)
{
  auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
  return args != nullptr ? HandleStringSimConVarArgs(*args, mName, &mValue) : HandleStringSimConVarArgs({}, mName, &mValue);
}

/**
 * Address: 0x005D41F0 (FUN_005D41F0, Moho::TSimConVarInstance_float::GetRRef)
 *
 * What it does:
 * Builds one reflected float reference for this convar value and copies it
 * into `outRef`.
 */
template <>
gpg::RRef* moho::TSimConVarInstance<float>::GetValueRef(gpg::RRef* const outRef)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  gpg::RRef floatValueRef{};
  gpg::RRef_float(&floatValueRef, &mValue);
  outRef->mObj = floatValueRef.mObj;
  outRef->mType = floatValueRef.mType;
  return outRef;
}

/**
 * Address: 0x005D4180 (FUN_005D4180, Moho::TSimConVarInstance_float::OnCall)
 *
 * What it does:
 * Handles float sim-convar command arguments and prints current value when no
 * RHS token is provided.
 */
template <>
int moho::TSimConVarInstance<float>::HandleConsoleCommand(void* commandArgs)
{
  auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
  if (args != nullptr && args->size() >= 2u) {
    ApplyFloatSimConVarArgs(*args, &mValue);
    return 1;
  }

  CON_Printf("float %s == %.4f", mName ? mName : "", mValue);
  return 0;
}

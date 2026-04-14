#include "CSimConVarInstanceBase.h"

#include <cstdlib>

#include "moho/console/CConCommand.h"

using namespace moho;

namespace
{
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
 * Address: 0x00579740 (FUN_00579740, sub_579740)
 *
 * What it does:
 * Base convar-instance destructor body; deleting behavior is provided by
 * compiler-generated scalar-deleting thunk in the original binary.
 */
CSimConVarInstanceBase::~CSimConVarInstanceBase() = default;

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

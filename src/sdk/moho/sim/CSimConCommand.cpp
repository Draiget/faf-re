#include "moho/sim/CSimConCommand.h"

#include <algorithm>
#include <map>
#include <string>

#include "gpg/core/containers/String.h"

namespace
{
  struct SimConCommandNameLess
  {
    [[nodiscard]]
    bool operator()(const std::string& lhs, const std::string& rhs) const noexcept
    {
      return gpg::STR_CompareNoCase(lhs.c_str(), rhs.c_str()) < 0;
    }
  };

  using SimConCommandRegistry = std::map<std::string, moho::CSimConCommand*, SimConCommandNameLess>;

  [[nodiscard]] SimConCommandRegistry& GetSimConCommandRegistry()
  {
    static SimConCommandRegistry sRegistry;
    return sRegistry;
  }
} // namespace

namespace moho
{
  CSimConCommand::CSimConCommand() noexcept
    : mName(nullptr)
    , mRequiresCheat(0u)
    , mPad09{0u, 0u, 0u}
  {
  }

  /**
   * Address: 0x00734630 (FUN_00734630, ??0CSimConCommand@Moho@@QAE@EPBD@Z)
   */
  CSimConCommand::CSimConCommand(const bool requiresCheat, const char* const name)
    : mName(name)
    , mRequiresCheat(requiresCheat ? 1u : 0u)
    , mPad09{0u, 0u, 0u}
  {
    if (mName == nullptr || *mName == '\0') {
      return;
    }

    GetSimConCommandRegistry()[mName] = this;
  }

  /**
   * Address: 0x00734760 (FUN_00734760, ??1CSimConCommand@Moho@@UAE@XZ)
   */
  CSimConCommand::~CSimConCommand()
  {
    if (mName == nullptr || *mName == '\0') {
      return;
    }

    auto& registry = GetSimConCommandRegistry();
    const auto it = registry.find(mName);
    if (it != registry.end() && it->second == this) {
      registry.erase(it);
    }
  }

  /**
   * Address: 0x005BE350 (FUN_005BE350, sub_5BE350)
   */
  CSimConCommand* CSimConCommand::Identity()
  {
    return this;
  }

  CSimConCommand* FindRegisteredSimConCommand(const std::string& commandName)
  {
    if (commandName.empty()) {
      return nullptr;
    }

    auto& registry = GetSimConCommandRegistry();
    const auto it = registry.find(commandName);
    if (it == registry.end()) {
      return nullptr;
    }

    return it->second;
  }
} // namespace moho

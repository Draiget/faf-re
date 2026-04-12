#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Wm3Vector3.h"

namespace moho
{
  class Sim;
  class CArmyImpl;
  struct SEntitySetTemplateUnit;

  /**
   * VFTABLE: 0x00E32B1C
   * COL:     0x00E8D658
   */
  class CSimConCommand
  {
  public:
    using ParsedCommandArgs = std::vector<std::string>;

    CSimConCommand() noexcept;

    /**
     * Address: 0x00734630 (FUN_00734630, ??0CSimConCommand@Moho@@QAE@EPBD@Z)
     *
     * What it does:
     * Initializes command metadata and registers this command in the
     * case-insensitive global sim-command registry by name.
     */
    CSimConCommand(bool requiresCheat, const char* name);

    /**
     * Address: 0x00734760 (FUN_00734760, ??1CSimConCommand@Moho@@UAE@XZ)
     *
     * What it does:
     * Unregisters this command name from the global sim-command registry.
     */
    virtual ~CSimConCommand();

    /**
     * Address: 0x00A82547 (_purecall in base CSimConCommand vtable)
     *
     * IDA signature:
     * int __thiscall Moho::CSimConCommand::Run(
     *   Moho::Sim* sim,
     *   std::vector<std::string>* commandArgs,
     *   Wm3::Vector3<float>* worldPos,
     *   Moho::CArmyImpl* focusArmy,
     *   Moho::SEntitySetTemplateUnit* selectedUnits);
     *
     * What it does:
     * Executes one parsed sim-console command payload.
     */
    virtual int Run(
      Sim* sim,
      ParsedCommandArgs* commandArgs,
      Wm3::Vector3f* worldPos,
      CArmyImpl* focusArmy,
      SEntitySetTemplateUnit* selectedUnits
    ) = 0;

    /**
     * Address: 0x005BE350 (FUN_005BE350, sub_5BE350)
     *
     * What it does:
     * Base identity virtual for CSimConCommand-family objects.
     */
    virtual CSimConCommand* Identity();

  public:
    const char* mName;           // +0x04
    std::uint8_t mRequiresCheat; // +0x08
    std::uint8_t mPad09[3];      // +0x09
  };

  static_assert(sizeof(CSimConCommand) == 0x0C, "CSimConCommand size must be 0x0C");
  static_assert(offsetof(CSimConCommand, mName) == 0x04, "CSimConCommand::mName offset must be 0x04");
  static_assert(offsetof(CSimConCommand, mRequiresCheat) == 0x08, "CSimConCommand::mRequiresCheat offset must be 0x08");

  /**
   * Address: 0x00735110/FUN_00735110-family lookup path.
   *
   * What it does:
   * Resolves one registered sim command by case-insensitive name.
   */
  [[nodiscard]] CSimConCommand* FindRegisteredSimConCommand(const std::string& commandName);
} // namespace moho

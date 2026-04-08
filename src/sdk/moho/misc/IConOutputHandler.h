#pragma once

#include "gpg/core/containers/DList.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E01718
   * COL:     0x00E5E1D4
   */
  class IConOutputHandler : public gpg::DListItem<IConOutputHandler, void>
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall)
     *
     * VFTable SLOT: 0
     *
     * What it does:
     * Receives one formatted console output line.
     */
    virtual void Handle(const char* text) = 0;

  protected:
    /**
     * Address: 0x0041E8F0 (FUN_0041E8F0)
     *
     * What it does:
     * Initializes the intrusive-list base node for one output handler object.
     */
    IConOutputHandler() noexcept;

    ~IConOutputHandler() = default;
  };

  using ConOutputHandlerList = gpg::DList<IConOutputHandler, void>;

  /**
   * Address: 0x00F58F44 (consoleoutputhandlers)
   *
   * What it does:
   * Returns the process-wide intrusive list head for console output handlers.
   */
  ConOutputHandlerList& CON_GetOutputHandlers();

  /**
   * Address: 0x00BC38A0 (FUN_00BC38A0, register_sConsoleOutputHandlers)
   *
   * What it does:
   * Registers process-exit teardown for the global console-output-handler list.
   */
  void register_sConsoleOutputHandlers();

  static_assert(sizeof(IConOutputHandler) == 0x0C, "IConOutputHandler size must be 0x0C");
  static_assert(sizeof(ConOutputHandlerList) == 0x08, "ConOutputHandlerList size must be 0x08");
} // namespace moho

#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace moho
{
  struct ConCommandArgsView
  {
    const msvc8::string* begin = nullptr;
    const msvc8::string* end = nullptr;

    [[nodiscard]] std::size_t Count() const noexcept;
    [[nodiscard]] const msvc8::string* At(std::size_t index) const noexcept;
  };

  /**
   * VFTABLE: 0x00E01700
   * COL:     0x00E5E318
   */
  class CConCommand
  {
  public:
    /**
     * Address: 0x00A82547 (_purecall in base CConCommand vtable)
     *
     * What it does:
     * Type-specific console command handler entry point.
     */
    virtual void Handle(void* commandArgs) = 0;

    const char* mName;              // 0x04
    const char* mDescription;       // 0x08
    std::uintptr_t mHandlerOrValue; // 0x0C (callback pointer / typed value pointer)
  };

  static_assert(sizeof(CConCommand) == 0x10, "CConCommand size must be 0x10");
  static_assert(offsetof(CConCommand, mName) == 0x04, "CConCommand::mName offset must be 0x04");
  static_assert(offsetof(CConCommand, mDescription) == 0x08, "CConCommand::mDescription offset must be 0x08");
  static_assert(offsetof(CConCommand, mHandlerOrValue) == 0x0C, "CConCommand::mHandlerOrValue offset must be 0x0C");

  /**
   * Address: 0x0041E390 (FUN_0041E390)
   *
   * What it does:
   * Registers command definition in the process-global console command table by command name.
   */
  void RegisterConCommand(CConCommand& command);

  /**
   * Address: 0x0041E4E0 (FUN_0041E4E0)
   *
   * What it does:
   * Unregisters command definition from the process-global console command table by command name.
   */
  void UnregisterConCommand(CConCommand& command);

  /**
   * Address: 0x0041E5A0 (FUN_0041E5A0)
   *
   * What it does:
   * Base unwind/teardown helper that removes command registration when name is set.
   */
  void TeardownConCommandRegistration(CConCommand& command);

  /**
   * Address: 0x0041CC90 (FUN_0041CC90)
   *
   * What it does:
   * Tokenizes and executes a single console command text line through the global registry.
   */
  void ExecuteConsoleCommandText(const char* commandText);

  /**
   * Address: <shared helper for recovered handlers>
   *
   * What it does:
   * Adapts wire-format command argument payload into begin/end token view.
   */
  [[nodiscard]] ConCommandArgsView GetConCommandArgsView(const void* commandArgs) noexcept;

  template <typename T>
  class TConVar final : public CConCommand
  {
  public:
    TConVar(const char* name, const char* description, T* value) noexcept
    {
      mName = name;
      mDescription = description;
      mHandlerOrValue = reinterpret_cast<std::uintptr_t>(value);
    }

    void Handle(void* commandArgs) override;

    [[nodiscard]]
    T* ValuePtr() const noexcept
    {
      return reinterpret_cast<T*>(mHandlerOrValue);
    }
  };

  /**
   * Address: <synthetic generic fallback>
   *
   * What it does:
   * Generic handler fallback; real binary behavior is provided via explicit
   * specializations below.
   */
  template <typename T>
  inline void TConVar<T>::Handle(void* commandArgs)
  {
    (void)commandArgs;
  }

  /**
   * Address: 0x1001ED50 (FUN_1001ED50)
   *
   * What it does:
   * Handles bool console-convar commands.
   */
  template <>
  void TConVar<bool>::Handle(void* commandArgs);

  /**
   * Address: 0x1001EDB0 (FUN_1001EDB0)
   *
   * What it does:
   * Handles int console-convar commands.
   */
  template <>
  void TConVar<int>::Handle(void* commandArgs);

  /**
   * Address: 0x1001EE50 (FUN_1001EE50)
   *
   * What it does:
   * Handles uint8 console-convar commands.
   */
  template <>
  void TConVar<std::uint8_t>::Handle(void* commandArgs);

  /**
   * Address: 0x1001EEF0 (FUN_1001EEF0)
   *
   * What it does:
   * Handles float console-convar commands.
   */
  template <>
  void TConVar<float>::Handle(void* commandArgs);

  /**
   * Address: 0x103C8880 (FUN_103C8880)
   *
   * What it does:
   * Handles uint32 console-convar commands.
   */
  template <>
  void TConVar<std::uint32_t>::Handle(void* commandArgs);

  /**
   * Address: 0x1001EF90 (FUN_1001EF90)
   *
   * What it does:
   * Handles string console-convar commands.
   */
  template <>
  void TConVar<msvc8::string>::Handle(void* commandArgs);

  static_assert(sizeof(TConVar<bool>) == 0x10, "TConVar<bool> size must be 0x10");
  static_assert(sizeof(TConVar<int>) == 0x10, "TConVar<int> size must be 0x10");
  static_assert(sizeof(TConVar<std::uint8_t>) == 0x10, "TConVar<uint8_t> size must be 0x10");
  static_assert(sizeof(TConVar<float>) == 0x10, "TConVar<float> size must be 0x10");
  static_assert(sizeof(TConVar<std::uint32_t>) == 0x10, "TConVar<uint32_t> size must be 0x10");
  static_assert(sizeof(TConVar<msvc8::string>) == 0x10, "TConVar<string> size must be 0x10");
} // namespace moho

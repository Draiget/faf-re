#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "moho/sim/CSimConCommand.h"

namespace moho
{
  namespace detail
  {
    [[nodiscard]] inline bool ParseBoolToken(const std::string_view token, bool& outValue) noexcept
    {
      const char* const text = token.data();
      if (
        token == "1" || gpg::STR_EqualsNoCase(text, "true") || gpg::STR_EqualsNoCase(text, "on")
        || gpg::STR_EqualsNoCase(text, "yes")
      ) {
        outValue = true;
        return true;
      }
      if (
        token == "0" || gpg::STR_EqualsNoCase(text, "false") || gpg::STR_EqualsNoCase(text, "off")
        || gpg::STR_EqualsNoCase(text, "no")
      ) {
        outValue = false;
        return true;
      }

      return false;
    }

    template <typename T>
    [[nodiscard]] bool ParseSimConValue(const std::string& token, T& outValue)
    {
      if constexpr (std::is_same_v<T, bool>) {
        bool parsed = false;
        if (!ParseBoolToken(token, parsed)) {
          return false;
        }
        outValue = parsed;
        return true;
      } else if constexpr (std::is_same_v<T, int>) {
        char* endPtr = nullptr;
        errno = 0;
        const long parsed = std::strtol(token.c_str(), &endPtr, 10);
        if (endPtr == token.c_str() || (endPtr && *endPtr != '\0') || errno == ERANGE) {
          return false;
        }
        if (parsed < static_cast<long>(std::numeric_limits<int>::min()) ||
            parsed > static_cast<long>(std::numeric_limits<int>::max())) {
          return false;
        }
        outValue = static_cast<int>(parsed);
        return true;
      } else if constexpr (std::is_same_v<T, float>) {
        char* endPtr = nullptr;
        errno = 0;
        const float parsed = std::strtof(token.c_str(), &endPtr);
        if (endPtr == token.c_str() || (endPtr && *endPtr != '\0') || errno == ERANGE) {
          return false;
        }
        outValue = parsed;
        return true;
      } else if constexpr (std::is_same_v<T, std::uint8_t>) {
        int parsed = 0;
        if (!ParseSimConValue<int>(token, parsed)) {
          return false;
        }
        if (parsed < 0 || parsed > 255) {
          return false;
        }
        outValue = static_cast<std::uint8_t>(parsed);
        return true;
      } else if constexpr (std::is_same_v<T, msvc8::string>) {
        outValue.assign_owned(token.c_str());
        return true;
      } else {
        return false;
      }
    }

    template <typename T>
    void LogSimConValue(const char* const name, const T& value)
    {
      if constexpr (std::is_same_v<T, bool>) {
        gpg::Logf("bool %s == %s", name ? name : "", value ? "on" : "off");
      } else if constexpr (std::is_same_v<T, int>) {
        gpg::Logf("int %s == %d", name ? name : "", value);
      } else if constexpr (std::is_same_v<T, float>) {
        gpg::Logf("float %s == %.4f", name ? name : "", value);
      } else if constexpr (std::is_same_v<T, std::uint8_t>) {
        gpg::Logf("uint8 %s == %d", name ? name : "", static_cast<int>(value));
      } else if constexpr (std::is_same_v<T, msvc8::string>) {
        gpg::Logf("string %s == %s", name ? name : "", value.c_str());
      }
    }

    template <typename T>
    [[nodiscard]] gpg::RType* CachedRType()
    {
      static gpg::RType* sType = nullptr;
      if (!sType) {
        sType = gpg::LookupRType(typeid(T));
      }
      return sType;
    }
  } // namespace detail

  /**
   * VFTABLE: 0x00E198EC
   * COL:		0x00E6EAC0
   */
  class CSimConVarInstanceBase
  {
  public:
    /**
     * Address: 0x00579720 (FUN_00579720, sub_579720)
     *
     * What it does:
     * Initializes one base sim-convar instance object with a bound command
     * name lane.
     */
    explicit CSimConVarInstanceBase(const char* name);

    /**
     * Address: 0x00579730 (FUN_00579730, sub_579730)
     * Address: 0x005D4260 (FUN_005D4260)
     *
     * What it does:
     * Initializes one base sim-convar instance object and installs the
     * `CSimConVarInstanceBase` vtable lane; the second constructor lane is an
     * equivalent alias.
     */
    CSimConVarInstanceBase();

    /**
     * Address: 0x00579740 (FUN_00579740, sub_579740)
     *
     * IDA signature:
     * _DWORD *__thiscall sub_579740(_DWORD *this, char a2);
     *
     * What it does:
     * Scalar-deleting destructor for base convar-instance objects.
     */
    virtual ~CSimConVarInstanceBase();

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Handles console command args for this typed convar instance.
     */
    virtual int HandleConsoleCommand(void* commandArgs) = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Returns pointer to underlying typed value storage used by Sim convar readers.
     */
    virtual void* GetValueStorage() = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Exports the typed value as a reflection `gpg::RRef`.
     */
    virtual gpg::RRef* GetValueRef(gpg::RRef* outRef) = 0;

  public:
    const char* mName; // 0x04
  };

  static_assert(sizeof(CSimConVarInstanceBase) == 0x08, "CSimConVarInstanceBase size must be 0x08");
  static_assert(offsetof(CSimConVarInstanceBase, mName) == 0x04, "CSimConVarInstanceBase::mName offset must be 0x04");

  template <typename T>
  class TSimConVarInstance : public CSimConVarInstanceBase
  {
  public:
    int HandleConsoleCommand(void* commandArgs) override
    {
      auto* const args = static_cast<CSimConCommand::ParsedCommandArgs*>(commandArgs);
      if (args != nullptr && args->size() >= 2u) {
        T parsed{};
        if (detail::ParseSimConValue<T>((*args)[1], parsed)) {
          mValue = parsed;
          return 1;
        }
      }

      detail::LogSimConValue<T>(mName, mValue);
      return 0;
    }

    void* GetValueStorage() override
    {
      return &mValue;
    }

    gpg::RRef* GetValueRef(gpg::RRef* outRef) override
    {
      if (!outRef) {
        return nullptr;
      }

      outRef->mObj = &mValue;
      outRef->mType = detail::CachedRType<T>();
      return outRef;
    }

  public:
    T mValue; // +0x08
  };

  /**
   * Address: 0x0057FCC0 (FUN_0057FCC0, Moho::TSimConVarInstance_int::OnCall)
   *
   * What it does:
   * Handles int sim-convar command arguments via the shared int parser helper;
   * prints current value when fewer than two tokens are provided.
   */
  template <>
  int TSimConVarInstance<int>::HandleConsoleCommand(void* commandArgs);

  /**
   * Address: 0x0057FC50 (FUN_0057FC50, Moho::TSimConVarInstance_bool::OnCall)
   *
   * What it does:
   * Handles bool sim-convar command arguments using legacy bool parsing
   * semantics (`=`, on/off/true/false/show/tog, numeric fallback).
   */
  template <>
  int TSimConVarInstance<bool>::HandleConsoleCommand(void* commandArgs);

  /**
   * Address: 0x00735990 (FUN_00735990, Moho::TSimConVarInstance_uint8::OnCall)
   *
   * What it does:
   * Handles uint8 sim-convar command arguments via the shared uint8 parser
   * helper; prints current value when fewer than two tokens are provided.
   */
  template <>
  int TSimConVarInstance<std::uint8_t>::HandleConsoleCommand(void* commandArgs);

  /**
   * Address: 0x00735AB0 (FUN_00735AB0, Moho::TSimConVarInstance_string::OnCall)
   *
   * What it does:
   * Handles string sim-convar command arguments (`= value` or direct
   * assignment); prints current value when fewer than two tokens are provided.
   */
  template <>
  int TSimConVarInstance<msvc8::string>::HandleConsoleCommand(void* commandArgs);

  /**
   * Address: 0x005D4180 (FUN_005D4180, Moho::TSimConVarInstance_float::OnCall)
   *
   * What it does:
   * Handles float sim-convar command arguments using the float command parser
   * semantics (`=`, `+=`, `-=`, `*=`, `/=`, direct value); prints current value
   * when no RHS token is provided.
   */
  template <>
  int TSimConVarInstance<float>::HandleConsoleCommand(void* commandArgs);

  /**
   * Address: 0x005D41E0 (FUN_005D41E0, Moho::TSimConVarInstance_float::GetPtr)
   *
   * What it does:
   * Returns pointer to the float value lane stored at offset +0x08.
   */
  template <>
  void* TSimConVarInstance<float>::GetValueStorage();

  /**
   * Address: 0x0057FC70 (FUN_0057FC70, Moho::TSimConVarInstance_bool::GetPtr)
   *
   * What it does:
   * Returns pointer to the bool value lane stored at offset +0x08.
   */
  template <>
  void* TSimConVarInstance<bool>::GetValueStorage();

  /**
   * Address: 0x0057FD20 (FUN_0057FD20, Moho::TSimConVarInstance_int::GetPtr)
   *
   * What it does:
   * Returns pointer to the int value lane stored at offset +0x08.
   */
  template <>
  void* TSimConVarInstance<int>::GetValueStorage();

  /**
   * Address: 0x0057FC80 (FUN_0057FC80, Moho::TSimConVarInstance_bool::GetRRef)
   *
   * What it does:
   * Builds one reflected bool reference for this convar value and copies it
   * into `outRef`.
   */
  template <>
  gpg::RRef* TSimConVarInstance<bool>::GetValueRef(gpg::RRef* outRef);

  /**
   * Address: 0x0057FD30 (FUN_0057FD30, Moho::TSimConVarInstance_int::GetRRef)
   *
   * What it does:
   * Builds one reflected int reference for this convar value and copies it
   * into `outRef`.
   */
  template <>
  gpg::RRef* TSimConVarInstance<int>::GetValueRef(gpg::RRef* outRef);

  /**
   * Address: 0x00735A00 (FUN_00735A00, Moho::TSimConVarInstance_uint8::GetRRef)
   *
   * What it does:
   * Builds one reflected uint8 reference for this convar value and copies it
   * into `outRef`.
   */
  template <>
  gpg::RRef* TSimConVarInstance<std::uint8_t>::GetValueRef(gpg::RRef* outRef);

  /**
   * Address: 0x00735AE0 (FUN_00735AE0, Moho::TSimConVarInstance_string::GetRRef)
   *
   * What it does:
   * Builds one reflected string reference for this convar value and copies it
   * into `outRef`.
   */
  template <>
  gpg::RRef* TSimConVarInstance<msvc8::string>::GetValueRef(gpg::RRef* outRef);

  /**
   * Address: 0x005D41F0 (FUN_005D41F0, Moho::TSimConVarInstance_float::GetRRef)
   *
   * What it does:
   * Builds one reflected float reference for this convar value and copies it
   * into `outRef`.
   */
  template <>
  gpg::RRef* TSimConVarInstance<float>::GetValueRef(gpg::RRef* outRef);

  static_assert(
    offsetof(TSimConVarInstance<bool>, mValue) == 0x08, "TSimConVarInstance<bool>::mValue offset must be 0x08"
  );
  static_assert(offsetof(TSimConVarInstance<int>, mValue) == 0x08, "TSimConVarInstance<int>::mValue offset must be 0x08");
  static_assert(
    offsetof(TSimConVarInstance<float>, mValue) == 0x08, "TSimConVarInstance<float>::mValue offset must be 0x08"
  );
  static_assert(
    offsetof(TSimConVarInstance<std::uint8_t>, mValue) == 0x08,
    "TSimConVarInstance<uint8_t>::mValue offset must be 0x08"
  );
  static_assert(
    offsetof(TSimConVarInstance<msvc8::string>, mValue) == 0x08,
    "TSimConVarInstance<string>::mValue offset must be 0x08"
  );
  static_assert(sizeof(TSimConVarInstance<bool>) == 0x0C, "TSimConVarInstance<bool> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<int>) == 0x0C, "TSimConVarInstance<int> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<float>) == 0x0C, "TSimConVarInstance<float> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<std::uint8_t>) == 0x0C, "TSimConVarInstance<uint8_t> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<msvc8::string>) == 0x24, "TSimConVarInstance<string> size must be 0x24");
} // namespace moho
